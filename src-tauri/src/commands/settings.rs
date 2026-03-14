//! Settings commands
//!
//! Handles user preferences and application settings.
//! FIX-1-7: Settings files are HMAC-protected to detect tampering.
//! A random HMAC key is stored in Windows Credential Manager.

use hmac::{Hmac, Mac};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

type HmacSha256 = Hmac<Sha256>;

const SETTINGS_HMAC_SERVICE: &str = "BirdoVPN";
const SETTINGS_HMAC_KEY_NAME: &str = "settings_hmac_key";

/// Wrapper that stores settings alongside an HMAC for integrity verification
#[derive(Debug, Serialize, Deserialize)]
struct SignedSettings {
    settings: AppSettings,
    hmac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppSettings {
    /// Start Birdo VPN when Windows starts
    pub autostart: bool,
    /// Start minimized to system tray
    pub start_minimized: bool,
    /// Enable kill switch (block all traffic if VPN disconnects)
    pub killswitch_enabled: bool,
    /// Show notifications for connection events
    pub notifications_enabled: bool,
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Preferred server ID for auto-connect (None = best server)
    pub preferred_server_id: Option<String>,
    /// Enable split tunneling
    pub split_tunneling_enabled: bool,
    /// Apps to exclude from VPN (split tunneling)
    pub split_tunnel_apps: Vec<String>,
    /// DNS servers to use while connected (None = use VPN's DNS)
    pub custom_dns: Option<Vec<String>>,
    /// Protocol preference
    pub protocol: Protocol,
    /// Allow LAN access while connected (printers, NAS, etc.)
    #[serde(default)]
    pub local_network_sharing: bool,
    /// WireGuard port: "auto", "51820", "53", or custom port number
    #[serde(default = "default_wireguard_port")]
    pub wireguard_port: String,
    /// WireGuard MTU: 0 = automatic (server default), 1280-1500 = custom
    #[serde(default)]
    pub wireguard_mtu: u16,
}

fn default_wireguard_port() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Wireguard,
}

fn get_settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app.path()
        .app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {}", e))?
        .join("settings.json"))
}

/// Get or generate the HMAC key from Windows Credential Manager
fn get_hmac_key() -> Result<Vec<u8>, String> {
    let entry = Entry::new(SETTINGS_HMAC_SERVICE, SETTINGS_HMAC_KEY_NAME)
        .map_err(|e| format!("Failed to create HMAC key entry: {}", e))?;
    
    match entry.get_password() {
        Ok(key_hex) => {
            hex::decode(&key_hex).map_err(|e| format!("Corrupted HMAC key: {}", e))
        }
        Err(keyring::Error::NoEntry) => {
            // First run — generate a random 32-byte key
            use rand::Rng;
            let key: [u8; 32] = rand::thread_rng().gen();
            let key_hex = hex::encode(&key);
            entry.set_password(&key_hex)
                .map_err(|e| format!("Failed to store HMAC key: {}", e))?;
            tracing::info!("Generated new settings HMAC key");
            Ok(key.to_vec())
        }
        Err(e) => {
            Err(format!("Cannot access HMAC key from credential store: {}", e))
        }
    }
}

/// Compute HMAC-SHA256 over serialized settings JSON
fn compute_hmac(settings_json: &str, key: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(settings_json.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verify HMAC of settings using constant-time comparison
/// PROD-HARDENING: Use hmac::Mac::verify() for timing-safe comparison
/// instead of plain string equality which leaks information via timing.
fn verify_hmac(settings_json: &str, expected_hmac: &str, key: &[u8]) -> bool {
    let Ok(expected_bytes) = hex::decode(expected_hmac) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(settings_json.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok()
}

/// Get current application settings
#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<AppSettings, String> {
    let path = get_settings_path(&app)?;

    if !path.exists() {
        return Ok(AppSettings::default());
    }

    let content = fs::read_to_string(&path).map_err(|e| format!("Failed to read settings: {}", e))?;

    // Try to parse as signed settings (new format)
    if let Ok(signed) = serde_json::from_str::<SignedSettings>(&content) {
        // Verify HMAC
        match get_hmac_key() {
            Ok(key) => {
                let settings_json = serde_json::to_string(&signed.settings)
                    .map_err(|e| format!("Failed to re-serialize settings: {}", e))?;
                if verify_hmac(&settings_json, &signed.hmac, &key) {
                    return Ok(signed.settings);
                } else {
                    tracing::warn!("Settings HMAC verification failed — possible tampering. Resetting to defaults.");
                    return Ok(AppSettings::default());
                }
            }
            Err(e) => {
                tracing::error!("HMAC key unavailable ({}). Resetting to secure defaults to prevent tampered settings from loading.", e);
                return Ok(AppSettings::default());
            }
        }
    }

    // Legacy format (unsigned) — migrate by parsing and re-saving with HMAC
    match serde_json::from_str::<AppSettings>(&content) {
        Ok(settings) => {
            tracing::info!("Migrating unsigned settings to HMAC-protected format");
            // Re-save with HMAC (best effort)
            let _ = save_settings_inner(&app, &settings);
            Ok(settings)
        }
        Err(e) => Err(format!("Failed to parse settings: {}", e)),
    }
}

/// Internal save function used by both save_settings command and migration
fn save_settings_inner(app: &AppHandle, settings: &AppSettings) -> Result<(), String> {
    let path = get_settings_path(app)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {}", e))?;
    }

    let settings_json = serde_json::to_string(settings)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    let hmac_key = get_hmac_key()?;
    let hmac = compute_hmac(&settings_json, &hmac_key)?;

    let signed = SignedSettings {
        settings: settings.clone(),
        hmac,
    };

    let content = serde_json::to_string_pretty(&signed)
        .map_err(|e| format!("Failed to serialize signed settings: {}", e))?;

    // FIX-2-6: Atomic write — write to temp file then rename.
    // Prevents corruption if process crashes or power is lost mid-write.
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, &content)
        .map_err(|e| format!("Failed to write temp settings: {}", e))?;
    fs::rename(&tmp_path, &path)
        .map_err(|e| {
            // Clean up temp file on rename failure
            let _ = fs::remove_file(&tmp_path);
            format!("Failed to atomically replace settings file: {}", e)
        })?;
    Ok(())
}

/// Save application settings
#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: AppSettings) -> Result<bool, String> {
    save_settings_inner(&app, &settings)?;
    tracing::info!("Settings saved successfully");
    Ok(true)
}

/// Enable or disable autostart
#[tauri::command]
pub async fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;

    let autostart = app.autolaunch();

    if enabled {
        autostart
            .enable()
            .map_err(|e| format!("Failed to enable autostart: {}", e))?;
    } else {
        autostart
            .disable()
            .map_err(|e| format!("Failed to disable autostart: {}", e))?;
    }

    // Also update settings file
    let mut settings = get_settings(app.clone()).await?;
    settings.autostart = enabled;
    save_settings(app, settings).await?;

    Ok(true)
}
