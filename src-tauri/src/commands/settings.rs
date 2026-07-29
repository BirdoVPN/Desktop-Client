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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Start Birdo VPN when Windows starts
    pub autostart: bool,
    /// Start minimized to system tray
    pub start_minimized: bool,
    /// Enable kill switch (block all traffic if VPN disconnects).
    /// User preference — defaults ON (serde default_true + Default), but the user
    /// may turn it OFF in VPN Settings. When OFF, connect does not arm the
    /// firewall block and an unexpected drop is NOT failed closed.
    #[serde(default = "default_true")]
    pub killswitch_enabled: bool,
    /// Show notifications for connection events
    pub notifications_enabled: bool,
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Preferred server ID for auto-connect (None = best server)
    pub preferred_server_id: Option<String>,
    /// Enable kill-switch exceptions (field keeps the historical
    /// split-tunnel name for settings-file/HMAC compat)
    pub split_tunneling_enabled: bool,
    /// Apps exempt from the kill-switch block (WFP permits — traffic still
    /// routes through the VPN while connected; see wfp.rs)
    pub split_tunnel_apps: Vec<String>,
    /// DNS servers to use while connected (None = use VPN's DNS)
    pub custom_dns: Option<Vec<String>>,
    /// Protocol preference. `#[serde(default)]` is REQUIRED: the frontend's
    /// settingsToRust() has never sent this field, so without a default every
    /// save_settings() call fails deserialization at the command boundary with
    /// "missing field `protocol`" — silently breaking ALL persistence (custom
    /// port, MTU, split-tunnel apps never reached the connect path). Protocol has
    /// a single Wireguard variant (`#[default]`), so a missing value is correct.
    #[serde(default)]
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
    /// Enable Xray Reality stealth tunnel (bypass DPI/censorship)
    #[serde(default)]
    pub stealth_mode: bool,
    /// Enable Rosenpass post-quantum key exchange. ON by default for all users
    /// (available on every plan, negligible overhead).
    #[serde(default = "default_true")]
    pub quantum_protection: bool,
    /// LOCKDOWN: always-on kill switch (Mullvad-style). When true the WFP
    /// block-all stays active the entire time the tunnel is up, permitting
    /// tunneled traffic by interface so there is ZERO leak window — including
    /// across reconnects.
    ///
    /// ON by default. The reactive (block-only-during-reconnect-gap) mode holds
    /// traffic in the tunnel with ROUTING alone during steady-state Connected,
    /// which is decloakable by TunnelVision (CVE-2024-3661): a rogue DHCP
    /// server pushing option-121 classless routes installs more-specific routes
    /// on the physical NIC that win longest-prefix-match and steer traffic
    /// around the tunnel below the WireGuard layer — WITHOUT dropping the
    /// tunnel, so the reactive switch never triggers. The always-on interface-
    /// scoped WFP block cannot be bypassed that way (option-121 routes can't move
    /// traffic past a block keyed on the physical interface). Fail-safe:
    /// activate_blocking() refuses to install a block-all when the tunnel LUID is
    /// unknown (wfp.rs), and arm() disarms + the connect is best-effort on any
    /// activation error, so lockdown can never brick or block a connect — worst
    /// case it degrades to the reactive behavior. Trade-off: LAN devices on the
    /// physical NIC are blocked unless local_network_sharing is enabled.
    #[serde(default = "default_true")]
    pub lockdown_mode: bool,
    /// Multi-hop (double VPN) armed state. The frontend has always sent these
    /// three fields (helpers.ts settingsToRust) — before they existed here,
    /// serde silently dropped them, so the user's multi-hop arm + entry/exit
    /// selection was wiped on every settings round-trip/restart.
    #[serde(default)]
    pub multi_hop_enabled: bool,
    /// Entry node ID for multi-hop (None = not selected)
    #[serde(default)]
    pub multi_hop_entry_node_id: Option<String>,
    /// Exit node ID for multi-hop (None = not selected)
    #[serde(default)]
    pub multi_hop_exit_node_id: Option<String>,
}

/// The exact `AppSettings` shape (fields + order + serde attributes) BEFORE the
/// multi-hop fields were added. Used ONLY as an HMAC-verification fallback:
/// `get_settings` verifies the HMAC over a RE-serialization of the parsed
/// struct, so a settings file signed by an older build re-serializes with the
/// new fields included and fails the primary check. Without this fallback,
/// every existing install would silently reset to defaults on upgrade (losing
/// split-tunnel apps, autostart, DNS, …). When fields are added to
/// `AppSettings` again, snapshot the pre-change shape here the same way.
#[derive(Debug, Serialize, Deserialize)]
struct LegacyAppSettingsV1 {
    autostart: bool,
    start_minimized: bool,
    #[serde(default = "default_true")]
    killswitch_enabled: bool,
    notifications_enabled: bool,
    auto_connect: bool,
    preferred_server_id: Option<String>,
    split_tunneling_enabled: bool,
    split_tunnel_apps: Vec<String>,
    custom_dns: Option<Vec<String>>,
    protocol: Protocol,
    #[serde(default)]
    local_network_sharing: bool,
    #[serde(default = "default_wireguard_port")]
    wireguard_port: String,
    #[serde(default)]
    wireguard_mtu: u16,
    #[serde(default)]
    stealth_mode: bool,
    #[serde(default = "default_true")]
    quantum_protection: bool,
    #[serde(default)]
    lockdown_mode: bool,
}

impl From<LegacyAppSettingsV1> for AppSettings {
    fn from(l: LegacyAppSettingsV1) -> Self {
        Self {
            autostart: l.autostart,
            start_minimized: l.start_minimized,
            killswitch_enabled: l.killswitch_enabled,
            notifications_enabled: l.notifications_enabled,
            auto_connect: l.auto_connect,
            preferred_server_id: l.preferred_server_id,
            split_tunneling_enabled: l.split_tunneling_enabled,
            split_tunnel_apps: l.split_tunnel_apps,
            custom_dns: l.custom_dns,
            protocol: l.protocol,
            local_network_sharing: l.local_network_sharing,
            wireguard_port: l.wireguard_port,
            wireguard_mtu: l.wireguard_mtu,
            stealth_mode: l.stealth_mode,
            quantum_protection: l.quantum_protection,
            lockdown_mode: l.lockdown_mode,
            multi_hop_enabled: false,
            multi_hop_entry_node_id: None,
            multi_hop_exit_node_id: None,
        }
    }
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            autostart: false,
            start_minimized: false,
            killswitch_enabled: true, // always-on protection
            notifications_enabled: false,
            auto_connect: false,
            preferred_server_id: None,
            split_tunneling_enabled: false,
            split_tunnel_apps: Vec::new(),
            custom_dns: None,
            protocol: Protocol::default(),
            local_network_sharing: false,
            wireguard_port: default_wireguard_port(),
            wireguard_mtu: 0,
            stealth_mode: false,      // premium — off by default
            quantum_protection: true, // post-quantum on by default
            // Always-on kill switch. ON by default where it is REAL (Windows),
            // OFF elsewhere — because on macOS and Linux `is_lockdown_mode()`
            // returns a hard-coded `false` (killswitch.rs), so nothing ever
            // installs a steady-state block. Defaulting it to `true` there made
            // the stored settings, and the UI reading them, claim a protection
            // that did not exist: a user could see "always-on" enabled while the
            // only containment was split-default routing — exactly the
            // configuration TunnelVision (CVE-2024-3661) defeats.
            //
            // This is the honesty half of the fix. The protection half (wiring
            // lockdown through on Unix) is deliberately NOT done here: it must
            // come after routes reliably capture traffic and after the kill
            // switch permits our own control plane, or an always-on block locks
            // users out with no reconnect path.
            #[cfg(target_os = "windows")]
            lockdown_mode: true,
            #[cfg(not(target_os = "windows"))]
            lockdown_mode: false,
            multi_hop_enabled: false,
            multi_hop_entry_node_id: None,
            multi_hop_exit_node_id: None,
        }
    }
}

fn default_wireguard_port() -> String {
    "auto".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Wireguard,
}

fn get_settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {}", e))?
        .join("settings.json"))
}

/// Get or generate the HMAC key from Windows Credential Manager
fn get_hmac_key() -> Result<Vec<u8>, String> {
    let entry = Entry::new(SETTINGS_HMAC_SERVICE, SETTINGS_HMAC_KEY_NAME)
        .map_err(|e| format!("Failed to create HMAC key entry: {}", e))?;

    match entry.get_password() {
        Ok(key_hex) => hex::decode(&key_hex).map_err(|e| format!("Corrupted HMAC key: {}", e)),
        Err(keyring::Error::NoEntry) => {
            // First run — generate a random 32-byte key
            use rand::Rng;
            let key: [u8; 32] = rand::thread_rng().gen();
            let key_hex = hex::encode(key);
            entry
                .set_password(&key_hex)
                .map_err(|e| format!("Failed to store HMAC key: {}", e))?;
            tracing::info!("Generated new settings HMAC key");
            Ok(key.to_vec())
        }
        Err(e) => Err(format!(
            "Cannot access HMAC key from credential store: {}",
            e
        )),
    }
}

/// Compute HMAC-SHA256 over serialized settings JSON
fn compute_hmac(settings_json: &str, key: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC key error: {}", e))?;
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

/// Normalize settings loaded from disk to enforce non-negotiable invariants.
///
/// The kill switch defaults ON (via the `default_true` serde default when the
/// field is absent) but is user-toggleable, so a persisted `false` is honored
/// here — unlike before, when it was force-reset to `true`. Kept as the single
/// choke-point for both the signed and legacy load paths so any future
/// invariants stay in lock-step and remain unit-testable without a Tauri
/// `AppHandle`/filesystem.
fn normalize_loaded_settings(settings: AppSettings) -> AppSettings {
    settings
}

/// Get current application settings
#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<AppSettings, String> {
    load_settings_sync(&app)
}

/// Synchronous settings loader shared by the `get_settings` command and Rust
/// callers that need settings before the frontend is up (e.g. main.rs setup
/// honoring `start_minimized`).
pub fn load_settings_sync(app: &AppHandle) -> Result<AppSettings, String> {
    let path = get_settings_path(app)?;

    if !path.exists() {
        return Ok(AppSettings::default());
    }

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read settings: {}", e))?;

    // Try to parse as signed settings (new format)
    if let Ok(signed) = serde_json::from_str::<SignedSettings>(&content) {
        // Verify HMAC
        match get_hmac_key() {
            Ok(key) => {
                let settings_json = serde_json::to_string(&signed.settings)
                    .map_err(|e| format!("Failed to re-serialize settings: {}", e))?;
                if verify_hmac(&settings_json, &signed.hmac, &key) {
                    return Ok(normalize_loaded_settings(signed.settings));
                }

                // Fallback: the file may have been signed by a build whose
                // AppSettings predates newer fields — the HMAC covers the OLD
                // shape's serialization, which the primary check (serialized
                // with the new fields present) can never reproduce. Re-verify
                // against the legacy shape before declaring tampering, else
                // every upgrade would silently reset user settings.
                if let Ok(legacy) = serde_json::to_value(&signed.settings)
                    .and_then(serde_json::from_value::<LegacyAppSettingsV1>)
                {
                    let legacy_json = serde_json::to_string(&legacy)
                        .map_err(|e| format!("Failed to serialize legacy settings: {}", e))?;
                    if verify_hmac(&legacy_json, &signed.hmac, &key) {
                        tracing::info!(
                            "Settings verified against pre-multi-hop shape — migrating signature"
                        );
                        let settings = normalize_loaded_settings(AppSettings::from(legacy));
                        if let Err(e) = save_settings_inner(app, &settings) {
                            tracing::warn!(
                                "Failed to re-sign migrated settings: {} (will retry next load)",
                                e
                            );
                        }
                        return Ok(settings);
                    }
                }

                tracing::warn!("Settings HMAC verification failed — possible tampering. Resetting to defaults.");
                return Ok(AppSettings::default());
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
            let settings = normalize_loaded_settings(settings);
            // Re-save with HMAC (best effort). Log on failure so a persistent
            // failure to upgrade (disk full, permissions, credential store down)
            // is observable rather than silently leaving settings unprotected.
            if let Err(e) = save_settings_inner(app, &settings) {
                tracing::warn!(
                    "Failed to migrate settings to HMAC-protected format: {}. Settings remain unsigned and will be retried on next load.",
                    e
                );
            }
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

    let settings_json =
        serde_json::to_string(settings).map_err(|e| format!("Failed to serialize: {}", e))?;

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
    fs::write(&tmp_path, &content).map_err(|e| {
        // Clean up partial temp file on write failure
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to write temp settings: {}", e)
    })?;
    fs::rename(&tmp_path, &path).map_err(|e| {
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
    #[cfg(windows)]
    set_autostart_windows(&app, enabled)?;

    #[cfg(not(windows))]
    {
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
    }

    // Also update settings file
    let mut settings = get_settings(app.clone()).await?;
    settings.autostart = enabled;
    save_settings(app, settings).await?;

    Ok(true)
}

/// Windows launch-at-login via a logon-triggered Scheduled Task.
///
/// The exe manifest is `requireAdministrator`, and Windows never launches an
/// elevated binary from the HKCU Run key (where tauri-plugin-autostart writes)
/// — the entry is silently skipped with ERROR_ELEVATION_REQUIRED, so the
/// toggle appeared to work but the app never started. A Scheduled Task with
/// `/RL HIGHEST` is the supported way to autostart elevated without a UAC
/// prompt; creating one needs admin, which this process always has.
#[cfg(windows)]
fn set_autostart_windows(app: &AppHandle, enabled: bool) -> Result<(), String> {
    const TASK_NAME: &str = "BirdoVPN Launch At Login";

    // Older builds wrote the useless Run-key entry; clear it on either toggle
    // so it stops logging an elevation failure at every logon.
    {
        use tauri_plugin_autostart::ManagerExt;
        let _ = app.autolaunch().disable();
    }

    let run = |args: &[&str]| -> Result<std::process::Output, String> {
        crate::utils::hidden_cmd("schtasks")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run schtasks: {}", e))
    };

    if enabled {
        let exe = std::env::current_exe()
            .map_err(|e| format!("Failed to resolve the app path: {}", e))?;
        // Quote the action ourselves — Task Scheduler splits an unquoted
        // "C:\Program Files\…" at the first space.
        let action = format!("\"{}\"", exe.display());
        let out = run(&[
            "/Create", "/F", "/TN", TASK_NAME, "/TR", &action, "/SC", "ONLOGON", "/RL", "HIGHEST",
        ])?;
        if !out.status.success() {
            return Err(format!(
                "Failed to register the launch-at-login task: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        tracing::info!("Registered elevated launch-at-login task");
    } else {
        // schtasks error text is localized, so probe existence by exit code
        // instead of parsing "cannot find" out of /Delete's stderr.
        let exists = run(&["/Query", "/TN", TASK_NAME])?.status.success();
        if exists {
            let out = run(&["/Delete", "/F", "/TN", TASK_NAME])?;
            if !out.status.success() {
                return Err(format!(
                    "Failed to remove the launch-at-login task: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            tracing::info!("Removed launch-at-login task");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A settings file signed by a pre-multi-hop build must still verify via
    /// the legacy-shape fallback — otherwise every upgrade silently resets
    /// user settings (the primary check re-serializes with the new fields
    /// present, which can never reproduce the old signed JSON).
    #[test]
    fn legacy_signed_settings_verify_via_fallback_after_field_additions() {
        let key: &[u8] = b"unit-test-hmac-key-32-bytes-pad!";
        // What an old build serialized and signed (no multi_hop_* fields).
        let legacy = LegacyAppSettingsV1 {
            autostart: true,
            start_minimized: true,
            killswitch_enabled: true,
            notifications_enabled: true,
            auto_connect: false,
            preferred_server_id: Some("node-7".into()),
            split_tunneling_enabled: true,
            split_tunnel_apps: vec!["C:\\games\\x.exe".into()],
            custom_dns: None,
            protocol: Protocol::Wireguard,
            local_network_sharing: false,
            wireguard_port: "auto".into(),
            wireguard_mtu: 0,
            stealth_mode: false,
            quantum_protection: true,
            lockdown_mode: false,
        };
        let legacy_json = serde_json::to_string(&legacy).unwrap();
        let hmac = compute_hmac(&legacy_json, key).unwrap();

        // The new build parses the same stored JSON into the CURRENT struct.
        let current: AppSettings = serde_json::from_str(&legacy_json).unwrap();

        // Primary verification fails (re-serialization now includes new fields)…
        let current_json = serde_json::to_string(&current).unwrap();
        assert!(
            !verify_hmac(&current_json, &hmac, key),
            "primary check should fail for a legacy-signed file (this test guards the fallback's reason to exist)"
        );

        // …but the legacy-shape fallback reproduces the signed JSON exactly.
        let roundtrip: LegacyAppSettingsV1 = serde_json::to_value(&current)
            .and_then(serde_json::from_value)
            .unwrap();
        let roundtrip_json = serde_json::to_string(&roundtrip).unwrap();
        assert!(
            verify_hmac(&roundtrip_json, &hmac, key),
            "legacy fallback must verify a pre-multi-hop signed settings file"
        );
        // And the migrated settings keep the user's values.
        assert!(current.autostart && current.start_minimized);
        assert_eq!(current.preferred_server_id.as_deref(), Some("node-7"));
        assert!(!current.multi_hop_enabled);
    }

    /// The two non-negotiable defaults shipped in v1.3.30/31: kill switch and
    /// post-quantum protection are both ON for a brand-new install.
    #[test]
    fn default_settings_enforce_killswitch_and_pq_on() {
        let d = AppSettings::default();
        assert!(d.killswitch_enabled, "kill switch must default ON");
        assert!(d.quantum_protection, "post-quantum must default ON");
        assert!(!d.stealth_mode, "stealth (premium) stays off by default");
    }

    /// An older settings file that predates these fields must still load with
    /// kill switch + post-quantum ON, via the `default_true` serde defaults —
    /// so upgrading users inherit the protection without re-saving.
    #[test]
    fn serde_defaults_killswitch_and_pq_true_when_absent() {
        // JSON omits `killswitch_enabled` and `quantum_protection` entirely.
        let json = r#"{
            "autostart": false,
            "start_minimized": false,
            "notifications_enabled": false,
            "auto_connect": false,
            "preferred_server_id": null,
            "split_tunneling_enabled": false,
            "split_tunnel_apps": [],
            "custom_dns": null,
            "protocol": "wireguard"
        }"#;
        let s: AppSettings =
            serde_json::from_str(json).expect("legacy settings should deserialize");
        assert!(s.killswitch_enabled, "absent kill switch must default ON");
        assert!(s.quantum_protection, "absent post-quantum must default ON");
        // TunnelVision fix: a stored config predating lockdown_mode must upgrade
        // to the always-on kill switch, not the routing-only reactive default.
        assert!(s.lockdown_mode, "absent lockdown_mode must default ON");
    }

    /// REGRESSION: the frontend's settingsToRust() payload omits `protocol`
    /// entirely. Without `#[serde(default)]` on the field this fails to
    /// deserialize at the save_settings command boundary ("missing field
    /// protocol"), silently breaking ALL persistence — the exact split-tunnel /
    /// custom-port save failures reported on a fresh install. This asserts the
    /// real frontend shape (no protocol) round-trips.
    #[test]
    fn deserializes_frontend_payload_without_protocol() {
        // Mirrors src/utils/helpers.ts settingsToRust() — note: no `protocol`.
        let json = r#"{
            "killswitch_enabled": true,
            "auto_connect": false,
            "autostart": false,
            "start_minimized": false,
            "notifications_enabled": true,
            "preferred_server_id": null,
            "split_tunneling_enabled": true,
            "split_tunnel_apps": ["chrome.exe"],
            "custom_dns": null,
            "local_network_sharing": false,
            "wireguard_port": "51820",
            "wireguard_mtu": 0,
            "multi_hop_enabled": false,
            "multi_hop_entry_node_id": null,
            "multi_hop_exit_node_id": null,
            "stealth_mode": false,
            "quantum_protection": true
        }"#;
        let s: AppSettings = serde_json::from_str(json)
            .expect("frontend settings payload (no protocol) must deserialize");
        assert!(matches!(s.protocol, Protocol::Wireguard));
        assert!(s.split_tunneling_enabled);
        assert_eq!(s.wireguard_port, "51820");
    }

    /// The kill switch is now a real user preference: a persisted `false` must
    /// be HONORED on load (not force-reset to true), while every other pref also
    /// passes through untouched. Default remains ON (see the two tests above).
    #[test]
    fn normalize_loaded_settings_honors_persisted_killswitch_off() {
        let stored = AppSettings {
            killswitch_enabled: false, // user turned it off — must be respected
            quantum_protection: false, // user opted out of PQ — respected
            stealth_mode: true,
            ..AppSettings::default()
        };
        let loaded = normalize_loaded_settings(stored);
        assert!(
            !loaded.killswitch_enabled,
            "kill switch is a user preference — a persisted OFF must be honored"
        );
        assert!(
            !loaded.quantum_protection,
            "PQ is a real preference — normalize must not flip it"
        );
        assert!(loaded.stealth_mode, "other prefs pass through untouched");
    }
}
