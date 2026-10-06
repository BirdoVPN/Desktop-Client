//! Settings commands
//!
//! Handles user preferences and application settings.
//! FIX-1-7: Settings files are HMAC-protected to detect tampering.
//! A random HMAC key is stored in Windows Credential Manager.

// digest 0.11 moved `new_from_slice` off the `Mac` trait and onto `KeyInit`,
// so the constructor needs its own import now.
use hmac::{Hmac, KeyInit, Mac};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

use crate::commands::ipc_error::{IpcError, IpcErrorCode};

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
    /// WireGuard port: "auto" or "51820" (the relays accept no other). "53"
    /// and custom numbers from earlier builds are migrated to "auto" on load
    /// (`migrate_wireguard_port`).
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
    /// BirdoShield (OPEN-WORK D18): ask the server to resolve this device's
    /// DNS through the fleet's filtering resolver (ads, trackers, malware
    /// domains). OFF by default, available on every plan, sent as the
    /// per-device `dnsFiltering` connect flag on both dial paths — absent
    /// when off, so a body from a user who never touched it is byte-identical
    /// to 1.4.42's. Applies on the next connect (same semantics as stealth).
    ///
    /// `skip_serializing_if = is_false` is what keeps every existing install's
    /// HMAC valid across this upgrade: `load_settings_sync` verifies the
    /// signature over a RE-serialization of the parsed struct, so a field
    /// that always serializes would turn every 1.4.42-signed settings.json
    /// (multi-hop fields present, no `dns_filtering`) into a "tampering"
    /// quarantine + reset — the `LegacyAppSettingsV1` fallback cannot save it
    /// either, since that shape predates multi-hop. Omitting the key while it
    /// holds its default reproduces the old bytes exactly; only a file that
    /// was signed WITH the field (by this build, value true) carries it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dns_filtering: bool,
    /// Send crash reports to Sentry. OPT-IN: false for a new install AND for
    /// every install upgrading from a build that reported unconditionally
    /// (audit 2026-09-29, C-3 / D-12). Driven by the consent-screen toggle and
    /// Settings › Privacy; applied by `utils::crash_report::set_opted_in` at
    /// startup and on every save.
    ///
    /// `skip_serializing_if = is_false` for the same HMAC reason as
    /// `dns_filtering`: an existing settings.json (no such key) must
    /// re-serialize byte-identically, or every upgrade would be quarantined as
    /// tampering and reset.
    #[serde(default, skip_serializing_if = "is_false")]
    pub crash_reports_enabled: bool,
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
            dns_filtering: false,
            crash_reports_enabled: false,
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
            stealth_mode: false,          // premium — off by default
            quantum_protection: true,     // post-quantum on by default
            dns_filtering: false,         // BirdoShield — opt-in (D18)
            crash_reports_enabled: false, // crash reports — opt-in (C-3)
            // LOCKDOWN mode. ON by default where it is REAL (Windows), OFF
            // elsewhere — on macOS and Linux `is_lockdown_mode()` returns a
            // hard-coded `false` (killswitch.rs), so this flag does nothing
            // there and defaulting it `true` would make the stored settings,
            // and the UI reading them, claim semantics that do not exist.
            //
            // Note the distinction: macOS/Linux DO now hold a steady-state
            // block for the whole Connected session whenever the kill switch
            // is enabled (killswitch::holds_block_while_connected — the
            // P1-ks-reactive-detection-window fix), so a silent tunnel death
            // fails closed. What they do NOT have is lockdown's
            // keep-blocked-after-give-up semantics, which is what this flag
            // governs: on Unix the give-up/offline-cap branches still release
            // the block so a dead session cannot strand the machine.
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

/// `skip_serializing_if` predicate for default-false preferences whose key
/// must stay OUT of the signed JSON while unset (see `dns_filtering`).
fn is_false(v: &bool) -> bool {
    !*v
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

/// Get or generate the key used to sign `settings.json`.
///
/// The OS credential store is tried FIRST, so existing installs keep the key
/// (and therefore the signature) they already have.
///
/// It then FALLS BACK to a 0600 file beside settings.json, which macOS needs:
/// every VPN operation requires euid 0 (`is_elevated()`), but keyring's
/// apple-native backend addresses the keychain of the EFFECTIVE user, and root's
/// login keychain is normally absent or locked with no Aqua session to unlock
/// it. `get_password()` therefore failed on essentially every load, and the
/// caller turned that failure into `Ok(AppSettings::default())` — so the user's
/// custom DNS, MTU, port, local-network-sharing and kill-switch preference were
/// silently discarded on EVERY launch, and the next save wrote those defaults
/// over settings.json permanently. It also produced the stream of "HMAC key
/// unavailable" errors in Console.
///
/// This key only has to make local tampering DETECTABLE. It is not a secret from
/// root, and settings.json already lives in the same root-owned directory, so a
/// sibling 0600 file is exactly as strong as the keychain was pretending to be
/// here.
/// P1-dk-hmac-key-source-drift: the key source used to be keystore-first with
/// a silent (debug-logged) fallback that MINTED a fresh key file whenever the
/// store was merely unreachable — a locked GNOME Secret Service at login, or
/// root on macOS. Settings signed with the store's key then failed
/// verification against the freshly minted file key, and the "tampering" path
/// reset every preference to defaults (including `multi_hop_enabled`,
/// `lockdown_mode` and `killswitch_enabled`) permanently. The rework:
/// - loads verify against EVERY readable key (both sources) and never mint;
/// - the winning key is mirrored into BOTH sources so they converge and a
///   later outage of either source can no longer strand the signature;
/// - fallbacks log at warn/error, not debug.
fn get_hmac_key(settings_path: &Path) -> Result<Vec<u8>, String> {
    // Deterministic order: credential store first (existing installs keep the
    // key — and therefore the signature — they already have), then the sibling
    // key file (an install that has been signing with the file key stays on
    // it, even once the store becomes writable again).
    match read_keystore_key() {
        Ok(Some(key)) => {
            sync_hmac_key_sources(settings_path, &key);
            return Ok(key);
        }
        Ok(None) => {} // store reachable, no key stored — check the file
        Err(e) => {
            tracing::warn!(
                "Credential store unavailable for the settings HMAC key ({}); using the key file",
                e
            );
        }
    }
    if let Some(key) = read_file_key(settings_path) {
        sync_hmac_key_sources(settings_path, &key);
        return Ok(key);
    }

    // Neither source holds a key — first run. Mint one and persist it to BOTH
    // sources. The file write is the hard requirement (it is the source that
    // is always reachable); the store mirror is best-effort.
    use rand::Rng;
    let key: [u8; 32] = rand::thread_rng().gen();
    write_key_file(settings_path, &key)?;
    sync_hmac_key_sources(settings_path, &key);
    tracing::info!("Generated new settings HMAC key");
    Ok(key.to_vec())
}

/// Read the settings HMAC key from the OS credential store, WITHOUT ever
/// creating one. `Ok(None)` means the store answered "no such entry";
/// `Err` means the store could not answer (locked, no session, absent) — which
/// is indistinguishable from "temporarily locked", so callers must never treat
/// it as proof that no key exists.
fn read_keystore_key() -> Result<Option<Vec<u8>>, String> {
    let entry = Entry::new(SETTINGS_HMAC_SERVICE, SETTINGS_HMAC_KEY_NAME)
        .map_err(|e| format!("credential store: {}", e))?;
    match entry.get_password() {
        Ok(key_hex) => hex::decode(&key_hex)
            .map(Some)
            .map_err(|e| format!("corrupted HMAC key in the credential store: {}", e)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("credential store: {}", e)),
    }
}

/// Read the sibling 0600 key file, WITHOUT ever creating one. `None` means
/// absent, empty, unreadable or non-hex.
fn read_file_key(settings_path: &Path) -> Option<Vec<u8>> {
    match read_key_file(settings_path) {
        KeyFile::Key(key) => Some(key),
        KeyFile::Missing | KeyFile::Unreadable => None,
    }
}

/// What the key file beside settings.json holds right now.
#[derive(Debug, PartialEq)]
enum KeyFile {
    Key(Vec<u8>),
    /// No file, or one that is not a key (empty, not hex): no key to find.
    Missing,
    /// There, and unreadable right now (a scanner holding it, permissions):
    /// the key may well be in it.
    Unreadable,
}

fn read_key_file(settings_path: &Path) -> KeyFile {
    let key_path = settings_path.with_file_name("settings_hmac.key");
    let existing = match fs::read_to_string(&key_path) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return KeyFile::Missing,
        Err(e) => {
            tracing::warn!("Settings HMAC key file unreadable ({}); not using it", e);
            return KeyFile::Unreadable;
        }
    };
    let trimmed = existing.trim();
    if trimmed.is_empty() {
        return KeyFile::Missing;
    }
    match hex::decode(trimmed) {
        Ok(key) => KeyFile::Key(key),
        Err(e) => {
            tracing::warn!("Corrupted settings HMAC key file ({}); ignoring it", e);
            KeyFile::Missing
        }
    }
}

/// Write the 0600 HMAC key file that sits beside settings.json.
fn write_key_file(settings_path: &Path, key: &[u8]) -> Result<(), String> {
    let key_path = settings_path.with_file_name("settings_hmac.key");
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {}", e))?;
    }
    fs::write(&key_path, hex::encode(key))
        .map_err(|e| format!("Failed to write HMAC key file: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: the directory is already root-owned, so a failure here
        // does not widen access beyond what settings.json itself has.
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Mirror the canonical key into both sources (best-effort) so a transient
/// outage of either one can never strand the settings signature again. This
/// key only makes local tampering DETECTABLE (see `get_hmac_key`'s history) —
/// duplicating it into the sibling 0600 file does not widen access beyond
/// what settings.json itself already has.
fn sync_hmac_key_sources(settings_path: &Path, key: &[u8]) {
    let key_hex = hex::encode(key);

    if let Ok(entry) = Entry::new(SETTINGS_HMAC_SERVICE, SETTINGS_HMAC_KEY_NAME) {
        let already = matches!(entry.get_password(), Ok(existing) if existing == key_hex);
        if !already && entry.set_password(&key_hex).is_err() {
            // Expected wherever the store is unwritable (root on macOS); the
            // key file below is the source that keeps working there.
            tracing::debug!("Could not mirror the settings HMAC key into the credential store");
        }
    }

    let key_path = settings_path.with_file_name("settings_hmac.key");
    let already = fs::read_to_string(&key_path)
        .map(|s| s.trim() == key_hex)
        .unwrap_or(false);
    if !already {
        if let Err(e) = write_key_file(settings_path, key) {
            tracing::warn!(
                "Could not mirror the settings HMAC key into the key file: {}",
                e
            );
        }
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
fn normalize_loaded_settings(mut settings: AppSettings) -> AppSettings {
    migrate_wireguard_port(&mut settings);
    settings
}

/// WIN-FIX-3: the relays accept WireGuard on UDP 51820 only (vpn-a3, all
/// ten: no DNAT, nothing on a public 53). The "53" preset and the custom port
/// that earlier builds offered failed the handshake on every relay, so a
/// saved value of either becomes "auto" — the same rule as Android. Returns
/// whether it changed anything, so a signed file is re-saved once.
fn migrate_wireguard_port(settings: &mut AppSettings) -> bool {
    if matches!(settings.wireguard_port.as_str(), "auto" | "51820") {
        return false;
    }
    settings.wireguard_port = default_wireguard_port();
    true
}

/// Get current application settings
#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<AppSettings, IpcError> {
    off_the_runtime(move || load_settings_sync(&app).map_err(IpcError::unknown)).await
}

/// Run a settings command's synchronous work on the blocking pool.
///
/// P1-dk-blocking-io-on-async-runtime: these are async IPC commands, and a
/// load or a save reads and writes settings.json, reads the signing key from
/// the OS credential store (a Secret Service prompt on Linux can wait on the
/// user; Windows Credential Manager calls are RPCs) and, for autostart, runs
/// `schtasks`. Done inline, each parked a runtime worker for as long as that
/// took — the same workers the status choke point, the reconnect loop and
/// every other command need. `biometric.rs` moved its keystore calls the same
/// way.
///
/// The commands answer an `IpcError` (whose message is always redacted), so
/// a refusal can carry its own code: `settings_unverified`.
async fn off_the_runtime<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, IpcError> + Send + 'static,
) -> Result<T, IpcError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| IpcError::unknown(format!("Settings task failed: {e}")))?
}

/// Synchronous settings loader shared by the `get_settings` command and Rust
/// callers that need settings before the frontend is up (e.g. main.rs setup
/// honoring `start_minimized`).
pub fn load_settings_sync(app: &AppHandle) -> Result<AppSettings, String> {
    load_settings(app)
        .map(Loaded::settings)
        .map_err(String::from)
}

/// [`load_settings_sync`] on the blocking pool, for async Rust callers such as
/// the kill switch's `arm` (review of #222): the load is file and
/// credential-store I/O, and must not park a runtime worker.
pub(crate) async fn load_settings_off_runtime(app: &AppHandle) -> Result<AppSettings, String> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || load_settings_sync(&app))
        .await
        .map_err(|e| format!("Settings task failed: {e}"))?
}

/// Why a load produced no settings at all.
#[derive(Debug, PartialEq)]
enum LoadError {
    /// The file is there and could not be read: a scanner or a backup agent
    /// holding it open, permissions. What it holds is unknown, and may well
    /// be the user's settings.
    Unreadable(String),
    /// The file was read and is not settings in any format this build knows.
    Unparseable(String),
    /// Anything else (no config directory, a serializer failure).
    Other(String),
}

/// What a failed read of settings.json means. Bytes that are not UTF-8 are
/// a file that does not parse — nothing a save could lose, and saving is the
/// way out of it — not one that could not be read (round 3 of the review of
/// #222: mapped to Unreadable, such a file could never be saved again, and no
/// reset was offered). Every other read error is Unreadable.
fn read_error(e: std::io::Error) -> LoadError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        LoadError::Unparseable(format!("Failed to parse settings (not UTF-8): {}", e))
    } else {
        LoadError::Unreadable(format!("Failed to read settings: {}", e))
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Unreadable(e) | LoadError::Unparseable(e) | LoadError::Other(e) => {
                f.write_str(e)
            }
        }
    }
}

impl From<LoadError> for String {
    fn from(error: LoadError) -> Self {
        error.to_string()
    }
}

impl From<LoadError> for IpcError {
    fn from(error: LoadError) -> Self {
        IpcError::unknown(error.to_string())
    }
}

/// What a load found (WIN3-010).
enum Loaded {
    /// What is saved: the verified file — or the defaults where there is no
    /// file to lose (none yet).
    Saved(AppSettings),
    /// Defaults served for this session because the file could not be
    /// verified right now (its signing key is unreadable). The file is left
    /// as it is, and nothing may be saved from these: that would replace
    /// every real preference with its default.
    Unverified(AppSettings),
    /// The file was verified by no key, for good, and THIS load quarantined
    /// it ([`no_verifying_key`]): the defaults are what is saved now, and a
    /// save may go ahead. Kept apart from `Saved` so a reset whose re-check
    /// did the quarantine reports a reset (round 4 of the review of #222).
    Quarantined(AppSettings),
}

impl Loaded {
    fn settings(self) -> AppSettings {
        match self {
            Loaded::Saved(settings)
            | Loaded::Unverified(settings)
            | Loaded::Quarantined(settings) => settings,
        }
    }
}

/// [`load_settings_sync`], saying whether the settings may be saved back.
///
/// The whole load holds [`SETTINGS_WRITE`] (WIN3-010): the migrations below
/// save what they read, and a save that landed between their read and their
/// write was lost.
fn load_settings(app: &AppHandle) -> Result<Loaded, LoadError> {
    let _write = SETTINGS_WRITE.lock();
    let path = get_settings_path(app).map_err(LoadError::Other)?;

    if !path.exists() {
        return Ok(Loaded::Saved(AppSettings::default()));
    }

    let content = fs::read_to_string(&path).map_err(read_error)?;

    // Try to parse as signed settings (new format)
    if let Ok(signed) = serde_json::from_str::<SignedSettings>(&content) {
        // P1-dk-hmac-key-source-drift: collect every key the two sources hold
        // right now, WITHOUT minting one — minting during load is what used to
        // turn a transient credential-store outage into a permanent signature
        // mismatch. A signature made by EITHER source's key is accepted, and
        // the winning key is then mirrored into both sources so they converge.
        let keystore = read_keystore_key();
        let key_file = read_key_file(&path);
        let key_may_still_exist = key_may_still_exist(&keystore, &key_file);
        let mut candidates: Vec<Vec<u8>> = Vec::new();
        match keystore {
            Ok(Some(key)) => candidates.push(key),
            Ok(None) => {}
            Err(e) => tracing::warn!(
                "Credential store unavailable while verifying settings ({}); trying the key file",
                e
            ),
        }
        if let KeyFile::Key(key) = key_file {
            if !candidates.contains(&key) {
                candidates.push(key);
            }
        }

        let settings_json = serde_json::to_string(&signed.settings)
            .map_err(|e| LoadError::Other(format!("Failed to re-serialize settings: {}", e)))?;
        for key in &candidates {
            if verify_hmac(&settings_json, &signed.hmac, key) {
                sync_hmac_key_sources(&path, key);
                let port_before = signed.settings.wireguard_port.clone();
                let settings = normalize_loaded_settings(signed.settings);
                // Persist a migration once rather than redo it on every load.
                if settings.wireguard_port != port_before {
                    if let Err(e) = save_settings_inner(app, &settings) {
                        tracing::warn!(
                            "Failed to save migrated settings: {} (will retry next load)",
                            e
                        );
                    }
                }
                return Ok(Loaded::Saved(settings));
            }
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
            let legacy_json = serde_json::to_string(&legacy).map_err(|e| {
                LoadError::Other(format!("Failed to serialize legacy settings: {}", e))
            })?;
            for key in &candidates {
                if verify_hmac(&legacy_json, &signed.hmac, key) {
                    tracing::info!(
                        "Settings verified against pre-multi-hop shape — migrating signature"
                    );
                    sync_hmac_key_sources(&path, key);
                    let settings = normalize_loaded_settings(AppSettings::from(legacy));
                    if let Err(e) = save_settings_inner(app, &settings) {
                        tracing::warn!(
                            "Failed to re-sign migrated settings: {} (will retry next load)",
                            e
                        );
                    }
                    return Ok(Loaded::Saved(settings));
                }
            }
        }

        return Ok(no_verifying_key(&path, key_may_still_exist));
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
            Ok(Loaded::Saved(settings))
        }
        Err(e) => Err(LoadError::Unparseable(format!(
            "Failed to parse settings: {}",
            e
        ))),
    }
}

/// Whether a key that could verify settings.json may exist and be unreadable
/// right now: the credential store could not answer, or the key file is there
/// and could not be read. A store that answered "no key" beside a key file
/// that is missing or not a key is an answer: that key is gone.
fn key_may_still_exist(keystore: &Result<Option<Vec<u8>>, String>, key_file: &KeyFile) -> bool {
    keystore.is_err() || *key_file == KeyFile::Unreadable
}

/// The end of a load whose signed file no readable key verifies.
///
/// While a key may still exist ([`key_may_still_exist`]) the file may be
/// signed by exactly the key that cannot be read: transient, not tampering.
/// Defaults are served for this session (`Unverified`), nothing is minted and
/// nothing is touched, and the next load retries.
///
/// Otherwise every source answered and none verifies: a genuine mismatch, or
/// the key is gone for good (the store holds none, the key file is missing or
/// not a key). Review of #222 (P2): the second case used to count as "cannot
/// be read right now" too, so the file stayed unverified on every load and
/// every save was refused, with no way out. Both now quarantine the file
/// (settings.json.tampered-…, [`aside_path`]) instead of leaving it for a save to silently
/// overwrite — the user's data stays recoverable and the reset is visible on
/// disk — and the defaults load as what is saved.
fn no_verifying_key(path: &Path, key_may_still_exist: bool) -> Loaded {
    if key_may_still_exist {
        tracing::error!(
            "Settings signature matches no readable key while a key source is unreadable — using defaults for this session without resetting"
        );
        return Loaded::Unverified(AppSettings::default());
    }
    tracing::warn!(
        "Settings HMAC verification failed — tampered, or its key is gone. Resetting to defaults."
    );
    if let Err(e) = fs::rename(path, aside_path(path, "tampered")) {
        tracing::warn!("Could not preserve the unverified settings file: {}", e);
    }
    Loaded::Quarantined(AppSettings::default())
}

/// Internal save function used by both save_settings command and migration
fn save_settings_inner(app: &AppHandle, settings: &AppSettings) -> Result<(), String> {
    let path = get_settings_path(app)?;
    write_signed_settings(&path, settings, |json| {
        compute_hmac(json, &get_hmac_key(&path)?)
    })
}

/// Serialises every settings write in this process (REVIEW-WIN-006).
///
/// `save_settings` is an async command, so two saves run in parallel on the
/// runtime, and since the UI mirrors the chosen server into
/// `preferred_server_id` with no user action, a background save racing a
/// toggle is ordinary. Both used to write the SAME `settings.json.tmp` and
/// rename it: one truncated the file the other was writing, one renamed a
/// partial file into place (which then failed its HMAC on the next load and
/// was quarantined, resetting every preference), or the second rename found
/// nothing and the UI rolled the user's change back with "Couldn't save".
/// The lock also covers the key read, so two first-run saves cannot mint two
/// different signing keys.
///
/// Re-entrant, so a read-modify-write can hold it across the load — whose
/// legacy-format migrations save — and the save (REVIEW-WIN2-023, see
/// `clear_account_choices`).
static SETTINGS_WRITE: parking_lot::ReentrantMutex<()> = parking_lot::const_reentrant_mutex(());

/// Sign `settings` with `sign` and write them to `path`, the whole save under
/// [`SETTINGS_WRITE`]. `sign` is a parameter so a test can sign without the
/// OS credential store.
fn write_signed_settings(
    path: &Path,
    settings: &AppSettings,
    sign: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    let _write = SETTINGS_WRITE.lock();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {}", e))?;
    }

    let settings_json =
        serde_json::to_string(settings).map_err(|e| format!("Failed to serialize: {}", e))?;
    let signed = SignedSettings {
        settings: settings.clone(),
        hmac: sign(&settings_json)?,
    };
    let content = serde_json::to_string_pretty(&signed)
        .map_err(|e| format!("Failed to serialize signed settings: {}", e))?;
    write_atomically(path, &content)
}

/// FIX-2-6: write to a temp file, then rename over `path`, so a crash or a
/// power cut mid-write never leaves a torn settings file. The temp name is
/// unique to this write (process id + a counter): a fixed name is shared by
/// every writer, which is half of REVIEW-WIN-006.
fn write_atomically(path: &Path, content: &str) -> Result<(), String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = path.with_extension(format!("json.{}.{n}.tmp", std::process::id()));
    fs::write(&tmp_path, content).map_err(|e| {
        // Clean up partial temp file on write failure
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to write temp settings: {}", e)
    })?;
    fs::rename(&tmp_path, path).map_err(|e| {
        // Clean up temp file on rename failure
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to atomically replace settings file: {}", e)
    })?;
    Ok(())
}

/// Save application settings
#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: AppSettings) -> Result<bool, IpcError> {
    off_the_runtime(move || save_settings_blocking(&app, &settings)).await
}

/// The whole-object save behind `save_settings`. Holds the settings lock
/// across the check and the write, so a file cannot turn unverifiable in
/// between.
fn save_settings_blocking(app: &AppHandle, settings: &AppSettings) -> Result<bool, IpcError> {
    let _write = SETTINGS_WRITE.lock();
    may_save_over(load_settings(app))?;
    save_settings_inner(app, settings).map_err(IpcError::unknown)?;
    // Keep the live crash-reporting gate equal to what is on disk, whichever
    // screen saved.
    crate::utils::crash_report::set_opted_in(settings.crash_reports_enabled);
    tracing::info!("Settings saved successfully");
    Ok(true)
}

/// Settings are per MACHINE, but the server a session dials is one ACCOUNT's
/// choice: the UI mirrors the user's server into `preferred_server_id`, and
/// the armed Multi-Hop route, so tray Quick Connect dials what the Connect
/// button would. Left behind, the next account to sign in on this machine had
/// its first tray Quick Connect dial the previous user's server
/// (REVIEW-WIN-007) — or the previous user's Multi-Hop pair, which the first
/// fix left out (REVIEW-WIN2-023). Returns whether anything changed.
pub(crate) fn forget_account_choices(settings: &mut AppSettings) -> bool {
    let server = settings.preferred_server_id.take().is_some();
    let entry = settings.multi_hop_entry_node_id.take().is_some();
    let exit = settings.multi_hop_exit_node_id.take().is_some();
    let armed = std::mem::take(&mut settings.multi_hop_enabled);
    server || entry || exit || armed
}

/// [`forget_account_choices`] on the settings file, at every account boundary
/// (sign-out, deletion, an expired session). Best effort: a sign-out must not
/// fail over it. Writes only when there was something to forget, so settings
/// served as defaults (an unreadable signing key) are never written over the
/// real file. The whole read-modify-write holds the settings lock, so a
/// concurrent save (the UI's preferred-server mirror) cannot land between the
/// read and the write and put the old server back (REVIEW-WIN2-023).
///
/// On the blocking pool (review of #222): it is file and credential-store
/// I/O, and every caller is an async command (sign-out, account deletion, an
/// expired session).
pub(crate) async fn clear_account_choices(app: &AppHandle) {
    let app = app.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || forget_saved_account_choices(&app)).await {
        tracing::warn!("Could not clear the account's server: {}", e);
    }
}

fn forget_saved_account_choices(app: &AppHandle) {
    let _write = SETTINGS_WRITE.lock();
    match load_settings_sync(app) {
        Ok(mut settings) => {
            if forget_account_choices(&mut settings) {
                if let Err(e) = save_settings_inner(app, &settings) {
                    tracing::warn!("Could not clear the signed-out account's server: {}", e);
                }
            }
        }
        Err(e) => tracing::warn!(
            "Could not read settings to clear the account's server: {}",
            e
        ),
    }
}

/// Put the tunnel-shaping settings of `good` back over what is saved now, and
/// save: the revert of a settings change the live session could not apply
/// (WIN-FIX-3, `vpn::reapply_vpn_settings`). Returns what was saved. On the
/// blocking pool, like the commands (review of #222).
pub(crate) async fn restore_tunnel_settings(
    app: &AppHandle,
    good: &AppSettings,
) -> Result<AppSettings, String> {
    let (app, good) = (app.clone(), good.clone());
    tokio::task::spawn_blocking(move || restore_tunnel_settings_now(&app, &good))
        .await
        .map_err(|e| format!("Settings task failed: {e}"))?
}

fn restore_tunnel_settings_now(app: &AppHandle, good: &AppSettings) -> Result<AppSettings, String> {
    let _write = SETTINGS_WRITE.lock();
    let restored = restored_over(load_settings(app)?, good)?;
    save_settings_inner(app, &restored)?;
    Ok(restored)
}

/// What the revert saves, over what was `loaded` (WIN3-010). Never over the
/// defaults a load serves while it cannot verify the file: saved, they
/// replaced the user's kill switch, lockdown, autostart, server and every
/// other preference with defaults. The revert then fails, and the error the
/// reapply met stands.
fn restored_over(loaded: Loaded, good: &AppSettings) -> Result<AppSettings, String> {
    verified(loaded)
        .map(|current| with_tunnel_settings_of(current, good))
        .map_err(|refusal| refusal.message)
}

/// What is saved, for a change made on top of it — or a refusal when the
/// load could only serve defaults because it cannot verify the file
/// (WIN3-010). Those are not the user's settings: written back, they replace
/// every preference, and the save may mint a new signing key the old file
/// never verifies against again.
///
/// The refusal has its own code, `settings_unverified` (review of #222): the
/// UI offers a reset with it (`reset_settings`), the way out when the key
/// source stays unreadable.
fn verified(loaded: Loaded) -> Result<AppSettings, IpcError> {
    match loaded {
        Loaded::Saved(settings) | Loaded::Quarantined(settings) => Ok(settings),
        Loaded::Unverified(_) => Err(IpcError::new(
            IpcErrorCode::SettingsUnverified,
            "the settings file could not be verified, so it was left as it is",
        )),
    }
}

/// Whether a whole-object save may replace what is on disk (MR-692).
///
/// `save_settings` writes the object the UI sends, and the UI's copy came from
/// `get_settings` — which, while the signing key is unreadable, serves
/// defaults. The revert already refused to save over such a file; the save
/// itself did not, so the next toggle wrote those defaults over the user's
/// real file. Now it is refused while the file cannot be verified (the UI puts
/// the toggle back and says the save failed) and goes ahead once it can.
///
/// A file that was read and does not parse at all has nothing a save could
/// lose, and saving stays the way out of it. One that could not be READ is
/// not that (review of #222): an antivirus sharing violation looks the same
/// to the caller, and the file behind it is usually the user's own. The save
/// is refused, and the next one, once the file is readable again, goes ahead.
fn may_save_over(loaded: Result<Loaded, LoadError>) -> Result<(), IpcError> {
    match loaded {
        Ok(loaded) => verified(loaded).map(drop),
        Err(LoadError::Unparseable(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// `current` with every setting a live reapply rebuilds the tunnel for taken
/// from `good`. Only those: anything else changed since (a notification
/// toggle, the server the user picked) is not part of the revert.
fn with_tunnel_settings_of(current: AppSettings, good: &AppSettings) -> AppSettings {
    AppSettings {
        custom_dns: good.custom_dns.clone(),
        local_network_sharing: good.local_network_sharing,
        wireguard_port: good.wireguard_port.clone(),
        wireguard_mtu: good.wireguard_mtu,
        stealth_mode: good.stealth_mode,
        quantum_protection: good.quantum_protection,
        dns_filtering: good.dns_filtering,
        split_tunneling_enabled: good.split_tunneling_enabled,
        split_tunnel_apps: good.split_tunnel_apps.clone(),
        ..current
    }
}

/// Turn crash reporting on or off (consent screen and Settings › Privacy).
///
/// A dedicated command rather than a full-object `save_settings`, because the
/// consent screen runs before anything has hydrated the frontend store from
/// Rust: saving the store's view there could overwrite a settings.json the
/// store has never read. This reads the file, changes the one field and
/// writes it back. Takes effect immediately in both directions (see
/// `utils::crash_report`), so no restart is needed.
#[tauri::command]
pub async fn set_crash_reports_enabled(app: AppHandle, enabled: bool) -> Result<bool, IpcError> {
    off_the_runtime(move || {
        // MR-692: one field over what is saved — never over the defaults a
        // load serves while it cannot verify the file.
        let _write = SETTINGS_WRITE.lock();
        let mut settings = verified(load_settings(&app)?)?;
        settings.crash_reports_enabled = enabled;
        save_settings_inner(&app, &settings).map_err(IpcError::unknown)?;
        crate::utils::crash_report::set_opted_in(enabled);
        Ok(enabled)
    })
    .await
}

/// Put the settings back to their defaults: the way out of a file that cannot
/// be verified (`settings_unverified`) when its key source stays unreadable.
/// The UI asks the user to confirm first, and this re-checks under the
/// settings lock ([`resettable`]): only a file that STILL cannot be verified
/// is reset. `Ok(false)`: it verifies again (the key came back), and nothing
/// was touched.
///
/// The file is set aside under a timestamped name (`settings.json.unverified-…`,
/// [`aside_path`]), not deleted — but for manual recovery only: nothing in the
/// app reads it again. The defaults are signed like any save, which with the
/// credential store unreachable mints a new key in the key file; once the
/// store answers again, `sync_hmac_key_sources` writes that new key over the
/// old one there, after which the set-aside file cannot be verified by the
/// app at all. The OS launch-at-login entry is set to the defaults' autostart,
/// so the two agree; the UI then re-reads the settings and rebuilds a live
/// session on them.
#[tauri::command]
pub async fn reset_settings(app: AppHandle) -> Result<bool, IpcError> {
    off_the_runtime(move || {
        let _write = SETTINGS_WRITE.lock();
        let loaded = load_settings(&app);
        let quarantined = matches!(loaded, Ok(Loaded::Quarantined(_)));
        if !resettable(loaded)? {
            tracing::info!("Settings verify again — nothing to reset");
            return Ok(false);
        }
        let path = get_settings_path(&app).map_err(IpcError::unknown)?;
        let defaults = AppSettings::default();
        reset_over(&path, quarantined, || save_settings_inner(&app, &defaults))?;
        crate::utils::crash_report::set_opted_in(defaults.crash_reports_enabled);
        if let Err(e) = apply_autostart(&app, defaults.autostart) {
            tracing::warn!("Settings reset, but launch-at-login was not updated: {}", e);
        }
        tracing::warn!("Settings reset to their defaults at the user's request");
        Ok(true)
    })
    .await
}

/// Whether a reset may go ahead over what a load found: only over a file that
/// still cannot be verified. One that verifies again is left alone
/// (`Ok(false)`), and a load that failed outright is reported. One that the
/// re-check's own load just quarantined (its key gone for good) is a reset
/// already: it goes ahead — there is nothing left to set aside, and the
/// defaults are saved — and is reported as one (round 4 of the review; it
/// used to read as "nothing was reset").
fn resettable(loaded: Result<Loaded, LoadError>) -> Result<bool, IpcError> {
    match loaded? {
        Loaded::Unverified(_) | Loaded::Quarantined(_) => Ok(true),
        Loaded::Saved(_) => Ok(false),
    }
}

/// Set settings.json aside and save the defaults with `save`. If the save
/// fails, the file is put back, so a failed reset leaves things as they were
/// (round 4 of the review: it stayed set aside, with nothing saved and the
/// user told only that the reset failed). If even that rename fails, the
/// error says the file is still set aside. `quarantined`: the re-check's own
/// load already set the file aside as tampered ([`no_verifying_key`]), so
/// there is nothing here to put back, and the error says where it went
/// (round 5 of the review: it said "not reset").
fn reset_over(
    path: &Path,
    quarantined: bool,
    save: impl FnOnce() -> Result<(), String>,
) -> Result<(), IpcError> {
    let aside = set_aside(path, "unverified")?;
    let Err(e) = save() else {
        return Ok(());
    };
    Err(IpcError::unknown(
        match aside.map(|aside| fs::rename(aside, path)) {
            Some(Err(back)) => format!(
                "The defaults could not be saved ({e}), and the settings file stays set aside \
                 (settings.json.unverified-…): {back}"
            ),
            None if quarantined => format!(
                "The settings file was set aside (settings.json.tampered-…), but the defaults \
                 could not be saved: {e}"
            ),
            _ => format!("The defaults could not be saved, so the settings were not reset: {e}"),
        },
    ))
}

/// Where to move settings.json aside to: `settings.json.<tag>-<UTC time>`,
/// with a counter when that name is taken. A fixed name was replaced by the
/// next quarantine or reset (a rename onto an existing file replaces it on
/// Windows), destroying the copy an earlier one had kept.
fn aside_path(path: &Path, tag: &str) -> PathBuf {
    let base = format!(
        "settings.json.{tag}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    let mut candidate = path.with_file_name(&base);
    let mut n = 2;
    while candidate.exists() {
        candidate = path.with_file_name(format!("{base}-{n}"));
        n += 1;
    }
    candidate
}

/// Move settings.json aside ([`aside_path`]), saying where to; nothing to do
/// (`None`) when there is none.
fn set_aside(path: &Path, tag: &str) -> Result<Option<PathBuf>, IpcError> {
    let aside = aside_path(path, tag);
    match fs::rename(path, &aside) {
        Ok(()) => Ok(Some(aside)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(IpcError::unknown(format!(
            "Could not set the settings file aside: {e}"
        ))),
    }
}

/// Enable or disable autostart
#[tauri::command]
pub async fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, IpcError> {
    off_the_runtime(move || set_autostart_blocking(&app, enabled)).await
}

fn set_autostart_blocking(app: &AppHandle, enabled: bool) -> Result<bool, IpcError> {
    // MR-692: read first. A file that cannot be verified is not saved over,
    // and the launch task is not changed for a setting that cannot be saved.
    let _write = SETTINGS_WRITE.lock();
    let mut settings = verified(load_settings(app)?)?;

    apply_autostart(app, enabled).map_err(IpcError::unknown)?;

    // Also update settings file
    settings.autostart = enabled;
    save_settings_inner(app, &settings).map_err(IpcError::unknown)?;

    Ok(true)
}

/// Point the OS launch-at-login entry at `enabled`: the elevated launch task
/// on Windows, the autostart plugin elsewhere.
fn apply_autostart(app: &AppHandle, enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        set_autostart_windows(app, enabled)
    }

    #[cfg(not(windows))]
    {
        use tauri_plugin_autostart::ManagerExt;

        let autostart = app.autolaunch();
        if enabled {
            autostart
                .enable()
                .map_err(|e| format!("Failed to enable autostart: {}", e))
        } else {
            autostart
                .disable()
                .map_err(|e| format!("Failed to disable autostart: {}", e))
        }
    }
}

/// The launch-at-login task's name (the uninstaller removes it by name).
#[cfg_attr(not(windows), allow(dead_code))]
const LAUNCH_TASK: &str = "BirdoVPN Launch At Login";

/// How long one `schtasks` call may take. It runs under the settings lock
/// (set_autostart's read-modify-write), which every save and the kill
/// switch's preference read wait on, so a hung one must not hold them for
/// good (round 3 of the review of #222).
#[cfg(windows)]
const SCHTASKS_LIMIT: std::time::Duration = std::time::Duration::from_secs(15);

#[cfg(windows)]
fn schtasks(args: &[&str]) -> Result<std::process::Output, String> {
    crate::utils::output_within(
        crate::utils::hidden_cmd("schtasks").args(args),
        SCHTASKS_LIMIT,
    )
    .map_err(|e| format!("Failed to run schtasks: {}", e))
}

/// The `schtasks /Create` arguments for the launch-at-login task: an
/// elevated logon trigger for `exe`. The action is quoted here — Task
/// Scheduler splits an unquoted "C:\Program Files\…" at the first space.
#[cfg_attr(not(windows), allow(dead_code))]
fn launch_task_create_args(exe: &std::path::Path) -> Vec<String> {
    [
        "/Create",
        "/F",
        "/TN",
        LAUNCH_TASK,
        "/TR",
        &format!("\"{}\"", exe.display()),
        "/SC",
        "ONLOGON",
        "/RL",
        "HIGHEST",
    ]
    .iter()
    .map(|a| a.to_string())
    .collect()
}

#[cfg(windows)]
fn create_launch_task() -> Result<(), String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("Failed to resolve the app path: {}", e))?;
    let args = launch_task_create_args(&exe);
    let out = schtasks(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    if !out.status.success() {
        return Err(format!(
            "Failed to register the launch-at-login task: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// schtasks error text is localized, so existence is probed by exit code
/// rather than by parsing "cannot find" out of its stderr.
#[cfg(windows)]
fn launch_task_exists() -> Result<bool, String> {
    Ok(schtasks(&["/Query", "/TN", LAUNCH_TASK])?.status.success())
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
    // Older builds wrote the useless Run-key entry; clear it on either toggle
    // so it stops logging an elevation failure at every logon.
    {
        use tauri_plugin_autostart::ManagerExt;
        let _ = app.autolaunch().disable();
    }

    if enabled {
        create_launch_task()?;
        tracing::info!("Registered elevated launch-at-login task");
    } else if launch_task_exists()? {
        let out = schtasks(&["/Delete", "/F", "/TN", LAUNCH_TASK])?;
        if !out.status.success() {
            return Err(format!(
                "Failed to remove the launch-at-login task: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        tracing::info!("Removed launch-at-login task");
    }
    Ok(())
}

/// Put the launch-at-login task back when the setting says it should exist
/// and it does not (REVIEW-WIN2-011). A GUI upgrade runs the OLD version's
/// uninstaller, whose last step deletes the task whatever the reason for the
/// uninstall; nothing re-created it while the toggle still read ON, so the
/// next boot did not start BirdoVPN and an auto-connect user booted
/// unprotected. Called at every start with the setting on, off the main
/// thread (schtasks is a process); a task that exists is left exactly as it
/// is.
#[cfg(windows)]
pub fn restore_launch_at_login_task() {
    std::thread::spawn(|| match launch_task_exists() {
        Ok(true) => {}
        Ok(false) => match create_launch_task() {
            Ok(()) => tracing::info!("Re-created the missing launch-at-login task"),
            Err(e) => tracing::warn!("Could not re-create the launch-at-login task: {}", e),
        },
        Err(e) => tracing::warn!("Could not check the launch-at-login task: {}", e),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2. The existing tests are round-trip only
    /// (compute, then verify with the same code), so they would pass just as
    /// happily if the MAC silently became something other than HMAC-SHA256.
    /// A published vector pins the bytes: every settings.json signed by an
    /// older build (hmac 0.12) must still verify under hmac 0.13, and the
    /// only way to prove that without a fixture from the old build is to
    /// prove both agree with the RFC.
    #[test]
    fn hmac_sha256_matches_rfc4231_test_case_2() {
        let key = b"Jefe";
        let data = "what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(compute_hmac(data, key).unwrap(), expected);
        assert!(verify_hmac(data, expected, key));
        // and the hex casing on disk must not matter to verification
        assert!(verify_hmac(data, &expected.to_uppercase(), key));
        // one flipped bit in the stored tag is a tamper
        assert!(!verify_hmac(data, &expected.replace("5bdc", "5bdd"), key));
    }

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

    /// WIN-FIX-3: a reapply that cannot be applied puts back what the live
    /// session runs on — every tunnel-shaping setting — and nothing else.
    #[test]
    fn a_revert_restores_the_tunnel_settings_and_keeps_the_rest() {
        let good = AppSettings::default();
        let changed = AppSettings {
            wireguard_port: "51820".into(),
            wireguard_mtu: 1280,
            custom_dns: Some(vec!["9.9.9.9".into()]),
            local_network_sharing: true,
            stealth_mode: true,
            quantum_protection: false,
            dns_filtering: true,
            split_tunneling_enabled: true,
            split_tunnel_apps: vec!["C:\\apps\\game.exe".into()],
            // Not part of the revert:
            notifications_enabled: true,
            preferred_server_id: Some("fra-1".into()),
            auto_connect: true,
            ..AppSettings::default()
        };
        let restored = with_tunnel_settings_of(changed, &good);
        assert_eq!(restored.wireguard_port, good.wireguard_port);
        assert_eq!(restored.wireguard_mtu, good.wireguard_mtu);
        assert_eq!(restored.custom_dns, good.custom_dns);
        assert_eq!(restored.local_network_sharing, good.local_network_sharing);
        assert_eq!(restored.stealth_mode, good.stealth_mode);
        assert_eq!(restored.quantum_protection, good.quantum_protection);
        assert_eq!(restored.dns_filtering, good.dns_filtering);
        assert_eq!(
            restored.split_tunneling_enabled,
            good.split_tunneling_enabled
        );
        assert_eq!(restored.split_tunnel_apps, good.split_tunnel_apps);
        assert!(restored.notifications_enabled);
        assert_eq!(restored.preferred_server_id.as_deref(), Some("fra-1"));
        assert!(restored.auto_connect);
    }

    /// WIN3-010: a revert never saves over the defaults a load serves while
    /// it cannot verify the file (its signing key unreadable): they are not
    /// the user's settings, and saving them replaced every preference. Over
    /// what is really saved it restores as before. The load holds the
    /// settings lock throughout, so a migration's re-save cannot drop a save
    /// that landed after its read.
    #[test]
    fn a_revert_never_saves_over_unverified_defaults() {
        let good = AppSettings {
            wireguard_mtu: 1280,
            ..AppSettings::default()
        };
        assert!(restored_over(Loaded::Unverified(AppSettings::default()), &good).is_err());
        let saved = AppSettings {
            killswitch_enabled: false,
            wireguard_mtu: 1420,
            ..AppSettings::default()
        };
        let restored = restored_over(Loaded::Saved(saved), &good).expect("a verified file");
        assert_eq!(restored.wireguard_mtu, 1280);
        assert!(!restored.killswitch_enabled, "not part of the revert");

        let source = include_str!("settings.rs");
        let body = |signature: &str| {
            let start = source.find(signature).expect(signature);
            let rest = &source[start..];
            &rest[..rest
                .find(
                    "
}",
                )
                .expect("end of fn")]
        };
        let restore = body("fn restore_tunnel_settings_now(");
        assert!(restore.contains("restored_over(load_settings(app)?, good)?"));
        let load = body("fn load_settings(app: &AppHandle) -> Result<Loaded, LoadError> {");
        // The one branch that serves defaults and touches nothing, which
        // every unverified signed file reaches.
        assert!(load.contains("return Ok(no_verifying_key(&path, key_may_still_exist));"));
        assert!(!load.contains("Loaded::Unverified("));
        assert_eq!(
            body("fn no_verifying_key(")
                .matches("Loaded::Unverified(AppSettings::default())")
                .count(),
            1
        );
        let lock = load.find("SETTINGS_WRITE.lock()").expect("the lock");
        assert!(lock < load.find("get_settings_path(app)").unwrap());
        assert!(lock < load.find("save_settings_inner(").unwrap());
    }

    /// WIN-FIX-3: "53" and custom ports, which no relay answers, load as
    /// "auto"; the two real choices are kept.
    #[test]
    fn a_dead_wireguard_port_loads_as_auto() {
        for (stored, loaded) in [
            ("auto", "auto"),
            ("51820", "51820"),
            ("53", "auto"),
            ("443", "auto"),
            ("5353", "auto"),
            ("", "auto"),
        ] {
            let settings = normalize_loaded_settings(AppSettings {
                wireguard_port: stored.into(),
                ..AppSettings::default()
            });
            assert_eq!(settings.wireguard_port, loaded, "{stored:?}");
        }
        let mut kept = AppSettings {
            wireguard_port: "51820".into(),
            ..AppSettings::default()
        };
        assert!(!migrate_wireguard_port(&mut kept), "nothing to re-save");
        let mut dead = AppSettings {
            wireguard_port: "53".into(),
            ..AppSettings::default()
        };
        assert!(migrate_wireguard_port(&mut dead), "re-saved once");
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

    /// D18 BirdoShield: OFF for a fresh install and OFF when the stored file
    /// predates the field — an upgrade must never silently opt a device into
    /// DNS filtering it did not ask for.
    #[test]
    fn dns_filtering_defaults_off_and_absent_field_loads_off() {
        assert!(
            !AppSettings::default().dns_filtering,
            "BirdoShield is opt-in"
        );
        // The exact 1.4.42 on-disk shape (multi-hop fields present, no
        // dns_filtering) — the frontend payload without the new key.
        let json = r#"{
            "autostart": false,
            "start_minimized": false,
            "killswitch_enabled": true,
            "notifications_enabled": true,
            "auto_connect": false,
            "preferred_server_id": null,
            "split_tunneling_enabled": false,
            "split_tunnel_apps": [],
            "custom_dns": null,
            "protocol": "wireguard",
            "local_network_sharing": false,
            "wireguard_port": "auto",
            "wireguard_mtu": 0,
            "stealth_mode": false,
            "quantum_protection": true,
            "lockdown_mode": true,
            "multi_hop_enabled": false,
            "multi_hop_entry_node_id": null,
            "multi_hop_exit_node_id": null
        }"#;
        let s: AppSettings =
            serde_json::from_str(json).expect("pre-D18 settings must still deserialize");
        assert!(!s.dns_filtering, "absent dns_filtering must load as OFF");
    }

    /// D18 BirdoShield round-trip: `true` survives serialize → deserialize
    /// (so the HMAC covers the user's choice), and `false` is omitted from the
    /// JSON entirely rather than written as `false`.
    #[test]
    fn dns_filtering_round_trips_and_is_omitted_when_off() {
        let on = AppSettings {
            dns_filtering: true,
            ..AppSettings::default()
        };
        let json = serde_json::to_string(&on).unwrap();
        assert!(
            json.contains("\"dns_filtering\":true"),
            "enabled flag must be persisted: {json}"
        );
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert!(back.dns_filtering, "true must round-trip");

        let off_json = serde_json::to_string(&AppSettings::default()).unwrap();
        assert!(
            !off_json.contains("dns_filtering"),
            "an OFF flag must not appear in the signed JSON: {off_json}"
        );
        let back: AppSettings = serde_json::from_str(&off_json).unwrap();
        assert!(!back.dns_filtering);
    }

    /// Crash reports are OPT-IN: off for a fresh install, off when an upgraded
    /// install's file predates the key (1.4.44 reported unconditionally — that
    /// must not carry over as consent), and `true` round-trips.
    #[test]
    fn crash_reports_default_off_absent_loads_off_and_true_round_trips() {
        assert!(!AppSettings::default().crash_reports_enabled);

        let v144: AppSettings = serde_json::from_str(
            r#"{"autostart":false,"start_minimized":false,"killswitch_enabled":true,
               "notifications_enabled":true,"auto_connect":false,"preferred_server_id":null,
               "split_tunneling_enabled":false,"split_tunnel_apps":[],"custom_dns":null,
               "protocol":"wireguard","local_network_sharing":false,"wireguard_port":"auto",
               "wireguard_mtu":0,"stealth_mode":false,"quantum_protection":true,
               "lockdown_mode":true,"multi_hop_enabled":false,
               "multi_hop_entry_node_id":null,"multi_hop_exit_node_id":null}"#,
        )
        .unwrap();
        assert!(
            !v144.crash_reports_enabled,
            "an upgrade must not opt anyone in"
        );

        let off_json = serde_json::to_string(&AppSettings::default()).unwrap();
        assert!(
            !off_json.contains("crash_reports_enabled"),
            "OFF must stay out of the signed JSON so older files keep verifying: {off_json}"
        );
        let on = AppSettings {
            crash_reports_enabled: true,
            ..AppSettings::default()
        };
        let json = serde_json::to_string(&on).unwrap();
        assert!(json.contains("\"crash_reports_enabled\":true"), "{json}");
        assert!(
            serde_json::from_str::<AppSettings>(&json)
                .unwrap()
                .crash_reports_enabled
        );
    }

    /// REGRESSION GUARD for the upgrade path: a settings.json signed by 1.4.42
    /// (the current shape WITHOUT `dns_filtering`) must still pass the PRIMARY
    /// HMAC check under this build. That file carries the multi-hop fields, so
    /// the `LegacyAppSettingsV1` fallback cannot rescue it — if the new field
    /// were re-serialized as `"dns_filtering":false` the signature would never
    /// match again and every upgrading install would be quarantined + reset.
    #[test]
    fn settings_signed_before_dns_filtering_still_verify_on_the_primary_check() {
        let key: &[u8] = b"unit-test-hmac-key-32-bytes-pad!";
        // What 1.4.42 serialized and signed: every field it knew, in struct
        // order, compact — the exact bytes `save_settings_inner` fed the MAC
        // (a `json!` literal would sort the keys and prove nothing).
        let v142_json = concat!(
            r#"{"autostart":true,"start_minimized":false,"killswitch_enabled":true,"#,
            r#""notifications_enabled":true,"auto_connect":false,"preferred_server_id":"node-7","#,
            r#""split_tunneling_enabled":true,"split_tunnel_apps":["C:\\games\\x.exe"],"#,
            r#""custom_dns":null,"protocol":"wireguard","local_network_sharing":false,"#,
            r#""wireguard_port":"auto","wireguard_mtu":0,"stealth_mode":false,"#,
            r#""quantum_protection":true,"lockdown_mode":true,"multi_hop_enabled":true,"#,
            r#""multi_hop_entry_node_id":"entry-1","multi_hop_exit_node_id":"exit-2"}"#
        )
        .to_string();
        let hmac = compute_hmac(&v142_json, key).unwrap();

        // The V1 fallback is NOT what saves this file (it drops multi-hop).
        let current: AppSettings = serde_json::from_str(&v142_json).unwrap();
        let v1: LegacyAppSettingsV1 = serde_json::to_value(&current)
            .and_then(serde_json::from_value)
            .unwrap();
        assert!(
            !verify_hmac(&serde_json::to_string(&v1).unwrap(), &hmac, key),
            "a multi-hop-era file is outside the V1 fallback's reach — the primary check must carry it"
        );

        // The primary check: re-serialization of the parsed struct must be
        // byte-identical to what 1.4.42 signed.
        let reserialized = serde_json::to_string(&current).unwrap();
        assert_eq!(
            reserialized, v142_json,
            "adding dns_filtering changed the signed bytes"
        );
        assert!(
            verify_hmac(&reserialized, &hmac, key),
            "a 1.4.42-signed settings file must verify unchanged on the primary check"
        );
        assert!(!current.dns_filtering);
        assert!(current.multi_hop_enabled, "user values pass through");
    }

    /// REVIEW-WIN-006: concurrent saves — the preferred-server mirror racing a
    /// user toggle — never fail, never leave a torn or foreign file, and leave
    /// no temp file behind. With the shared `settings.json.tmp` and no lock,
    /// writers truncated each other's temp file and lost renames.
    #[test]
    fn concurrent_saves_neither_fail_nor_tear_the_file() {
        // A fresh random key per run, leaked for the threads: a literal would be a
        // hard-coded cryptographic value to CodeQL, and these tests need no fixed one.
        let key: &'static [u8] = Box::leak(Box::new(rand::random::<[u8; 32]>()));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let writers: Vec<_> = (0..8)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        let settings = AppSettings {
                            preferred_server_id: Some(format!("node-{t}-{i}")),
                            ..AppSettings::default()
                        };
                        write_signed_settings(&path, &settings, |json| compute_hmac(json, key))
                            .expect("a concurrent save failed");
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }

        let content = fs::read_to_string(&path).unwrap();
        let signed: SignedSettings = serde_json::from_str(&content).expect("a whole file");
        let json = serde_json::to_string(&signed.settings).unwrap();
        assert!(
            verify_hmac(&json, &signed.hmac, key),
            "torn or mismatched file"
        );
        assert!(signed
            .settings
            .preferred_server_id
            .is_some_and(|id| id.ends_with("-24")));
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "settings.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// REVIEW-WIN2-011: the task the start-up repair creates is the toggle's
    /// own: elevated, at logon, the quoted path of this exe, under the name
    /// the uninstaller removes.
    #[test]
    fn the_launch_task_is_elevated_at_logon_with_a_quoted_path() {
        let args = launch_task_create_args(std::path::Path::new(
            r"C:\Program Files\BirdoVPN\BirdoVPN.exe",
        ));
        assert_eq!(
            args,
            [
                "/Create",
                "/F",
                "/TN",
                "BirdoVPN Launch At Login",
                "/TR",
                r#""C:\Program Files\BirdoVPN\BirdoVPN.exe""#,
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
            ]
        );
        assert!(include_str!("../../nsis-hooks.nsh")
            .contains(r#"schtasks /Delete /F /TN "BirdoVPN Launch At Login""#));
        // Start-up puts it back whenever the setting is on.
        let main = include_str!("../main.rs");
        let repair = main
            .find("commands::settings::restore_launch_at_login_task()")
            .expect("start-up repairs the task");
        let gate = main[..repair]
            .rfind(".autostart")
            .expect("only with the setting on");
        assert!(repair - gate < 200, "the repair is gated on the setting");
    }

    /// REVIEW-WIN-007 / REVIEW-WIN2-023: an account boundary forgets the
    /// account's server and its Multi-Hop route — what tray Quick Connect
    /// dials — and nothing else on the machine.
    #[test]
    fn signing_out_forgets_the_accounts_server_only() {
        let mut settings = AppSettings {
            preferred_server_id: Some("node-7".into()),
            multi_hop_enabled: true,
            multi_hop_entry_node_id: Some("ch-1".into()),
            multi_hop_exit_node_id: Some("is-1".into()),
            custom_dns: Some(vec!["9.9.9.9".into()]),
            local_network_sharing: true,
            ..AppSettings::default()
        };
        assert!(forget_account_choices(&mut settings));
        assert_eq!(settings.preferred_server_id, None);
        assert!(!settings.multi_hop_enabled);
        assert_eq!(settings.multi_hop_entry_node_id, None);
        assert_eq!(settings.multi_hop_exit_node_id, None);
        assert_eq!(settings.custom_dns, Some(vec!["9.9.9.9".to_string()]));
        assert!(settings.local_network_sharing);
        // Nothing to forget: nothing to write.
        assert!(!forget_account_choices(&mut settings));

        // A route alone is still the account's.
        let mut route_only = AppSettings {
            multi_hop_exit_node_id: Some("is-1".into()),
            ..AppSettings::default()
        };
        assert!(forget_account_choices(&mut route_only));
    }

    /// REVIEW-WIN2-023: the account-boundary read-modify-write holds the
    /// settings lock across the load, whose migrations save — so the lock
    /// must let the same thread save inside it, and keep every other writer
    /// out until the whole read-modify-write is done.
    #[test]
    fn a_read_modify_write_holds_the_settings_lock_throughout() {
        // A fresh random key per run, leaked for the threads: a literal would be a
        // hard-coded cryptographic value to CodeQL, and these tests need no fixed one.
        let key: &'static [u8] = Box::leak(Box::new(rand::random::<[u8; 32]>()));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let sign = |json: &str| compute_hmac(json, key);

        let held = SETTINGS_WRITE.lock();
        // The same thread saves inside it (a migration during the load).
        write_signed_settings(&path, &AppSettings::default(), sign)
            .expect("a nested save deadlocked or failed");

        // Another writer waits for the whole read-modify-write.
        let other = {
            let path = path.clone();
            std::thread::spawn(move || {
                let settings = AppSettings {
                    preferred_server_id: Some("mirrored".into()),
                    ..AppSettings::default()
                };
                write_signed_settings(&path, &settings, |json| compute_hmac(json, key)).unwrap();
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !other.is_finished(),
            "a writer got in mid read-modify-write"
        );
        drop(held);
        other.join().unwrap();
    }

    /// P1-dk-blocking-io-on-async-runtime: a settings command's synchronous
    /// work does not hold the async runtime. On a one-thread runtime the work
    /// below finishes only if another task on that runtime runs while it
    /// waits, which it cannot when the work runs inline on that one thread.
    #[tokio::test(flavor = "current_thread")]
    async fn settings_work_does_not_hold_the_async_runtime() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let work = off_the_runtime(move || {
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|e| IpcError::unknown(e.to_string()))
        });
        let other_task = async move {
            tokio::task::yield_now().await;
            let _ = tx.send(());
        };
        let (done, ()) = tokio::join!(work, other_task);
        assert_eq!(done, Ok(()), "the runtime was held while the work waited");
    }

    /// MR-692: the save itself (not only the revert) never replaces a file it
    /// cannot verify — the UI's copy of such a file is the defaults
    /// `get_settings` served — and neither do the two read-modify-write
    /// commands. A verified file, no file yet, or one that does not parse
    /// at all is saved over as before.
    #[test]
    fn a_save_never_replaces_a_file_it_cannot_verify() {
        assert!(may_save_over(Ok(Loaded::Unverified(AppSettings::default()))).is_err());
        assert_eq!(
            may_save_over(Ok(Loaded::Saved(AppSettings::default()))),
            Ok(())
        );
        assert_eq!(
            may_save_over(Err(LoadError::Unparseable(
                "Failed to parse settings".into()
            ))),
            Ok(()),
            "a file that does not parse has nothing to lose"
        );
        assert!(verified(Loaded::Unverified(AppSettings::default())).is_err());

        // A Windows checkout has CRLF endings (core.autocrlf).
        let source = include_str!("settings.rs").replace('\r', "");
        let body = |signature: &str| {
            let start = source.find(signature).expect(signature);
            let rest = &source[start..];
            rest[..rest.find("\n}\n").expect("end of fn")].to_string()
        };
        let save = body("fn save_settings_blocking(");
        let check = save
            .find("may_save_over(load_settings(app))?;")
            .expect("the check");
        assert!(check < save.find("save_settings_inner(").unwrap());
        assert!(body("pub async fn set_crash_reports_enabled(")
            .contains("verified(load_settings(&app)?)?"));
        let autostart = body("fn set_autostart_blocking(");
        let read = autostart
            .find("verified(load_settings(app)?)?")
            .expect("the read");
        assert!(read < autostart.find("apply_autostart(app, enabled)").unwrap());
    }

    /// Review of #222 (P2): the refusal carries its own code, so the UI can
    /// say what happened and offer a reset instead of "please try again".
    #[test]
    fn a_refused_save_says_the_file_could_not_be_verified() {
        let refusal =
            may_save_over(Ok(Loaded::Unverified(AppSettings::default()))).expect_err("refused");
        assert_eq!(refusal.code, IpcErrorCode::SettingsUnverified);
        assert_eq!(
            verified(Loaded::Unverified(AppSettings::default()))
                .expect_err("refused")
                .code,
            IpcErrorCode::SettingsUnverified
        );
        // Anything else that stops a save is not that.
        let unreadable = may_save_over(Err(LoadError::Unreadable("busy".into())));
        assert_eq!(unreadable.expect_err("refused").code, IpcErrorCode::Unknown);
    }

    fn names_in(dir: &Path, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(prefix))
            .collect();
        names.sort();
        names
    }

    /// The reset keeps the unverifiable file on disk, and tolerates none.
    /// Round 3 of the review (P3.1): a second reset (or quarantine) keeps the
    /// first copy — a fixed aside name was replaced by the next one.
    #[test]
    fn every_reset_and_quarantine_keeps_its_own_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for round in ["first", "second"] {
            fs::write(&path, round).unwrap();
            assert!(set_aside(&path, "unverified").unwrap().is_some());
            assert!(!path.exists());
        }
        let kept = names_in(dir.path(), "settings.json.unverified-");
        assert_eq!(kept.len(), 2, "{kept:?}");
        let contents: Vec<String> = kept
            .iter()
            .map(|n| fs::read_to_string(dir.path().join(n)).unwrap())
            .collect();
        assert!(contents.contains(&"first".to_string()));
        assert_eq!(
            set_aside(&path, "unverified"),
            Ok(None),
            "nothing to set aside is fine"
        );

        for round in ["one", "two"] {
            fs::write(&path, round).unwrap();
            let _ = no_verifying_key(&path, false);
        }
        assert_eq!(names_in(dir.path(), "settings.json.tampered-").len(), 2);
    }

    /// Round 3 of the review (P3.1): the reset re-checks under the settings
    /// lock and resets only a file that still cannot be verified.
    #[test]
    fn a_reset_goes_ahead_only_over_a_file_that_still_cannot_be_verified() {
        assert_eq!(
            resettable(Ok(Loaded::Unverified(AppSettings::default()))),
            Ok(true)
        );
        assert_eq!(
            resettable(Ok(Loaded::Saved(AppSettings::default()))),
            Ok(false),
            "the key came back: nothing to reset"
        );
        assert!(resettable(Err(LoadError::Unreadable("busy".into()))).is_err());

        let source = include_str!("settings.rs").replace('\r', "");
        let reset = &source[source.find("pub async fn reset_settings(").unwrap()..];
        let reset = &reset[..reset.find("\n}\n").unwrap()];
        let load = reset.find("let loaded = load_settings(&app);").unwrap();
        let check = reset.find("resettable(loaded)?").unwrap();
        assert!(reset.find("SETTINGS_WRITE.lock()").unwrap() < load);
        assert!(load < check);
        assert!(check < reset.find("reset_over(&path, quarantined,").unwrap());
        assert!(reset.contains("apply_autostart(&app, defaults.autostart)"));
    }

    /// Round 4 of the review (P3-7): a reset whose re-check quarantined the
    /// file (its key gone for good) is reported as a reset, not as "nothing
    /// was reset"; and a reset whose save fails puts the file back.
    #[test]
    fn a_reset_reports_what_happened_and_undoes_a_failed_save() {
        assert_eq!(
            resettable(Ok(Loaded::Quarantined(AppSettings::default()))),
            Ok(true),
            "the re-check's quarantine is a reset"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "the user's settings").unwrap();
        let failed = reset_over(&path, false, || Err("disk full".into()));
        assert!(failed.is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "the user's settings",
            "a failed reset leaves the file where it was"
        );
        assert!(names_in(dir.path(), "settings.json.unverified-").is_empty());

        let saved = reset_over(&path, false, || {
            fs::write(&path, "defaults").map_err(|e| e.to_string())
        });
        assert_eq!(saved, Ok(()));
        assert_eq!(fs::read_to_string(&path).unwrap(), "defaults");
        assert_eq!(names_in(dir.path(), "settings.json.unverified-").len(), 1);
    }

    /// Round 5 of the review (N5): when the re-check's own load quarantined
    /// the file and the defaults then cannot be saved, the error says the
    /// file was set aside: the reset did not leave things as they were.
    #[test]
    fn a_failed_save_after_the_quarantine_says_the_file_was_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // The quarantine already moved it: nothing is at `path`.
        let failed = reset_over(&path, true, || Err("disk full".into())).unwrap_err();
        assert!(
            failed.message.contains("was set aside"),
            "{}",
            failed.message
        );
        assert!(!failed.message.contains("not reset"), "{}", failed.message);

        // With no file and no quarantine, nothing was moved: "not reset".
        let failed = reset_over(&path, false, || Err("disk full".into())).unwrap_err();
        assert!(failed.message.contains("not reset"), "{}", failed.message);
    }

    /// Review of #222 (P3.7): a settings file that could not be READ is not
    /// saved over, unlike one that was read and does not parse. The read
    /// failure is usually transient (a scanner holding the file) and the
    /// file behind it is the user's.
    #[test]
    fn a_save_never_replaces_a_file_it_could_not_read() {
        let unreadable = may_save_over(Err(LoadError::Unreadable(
            "Failed to read settings: The process cannot access the file because it is being \
             used by another process. (os error 32)"
                .into(),
        )));
        assert!(
            unreadable.is_err(),
            "a sharing violation is not an empty file"
        );
        assert!(may_save_over(Err(LoadError::Other("no config dir".into()))).is_err());
        assert_eq!(
            may_save_over(Err(LoadError::Unparseable(
                "Failed to parse settings".into()
            ))),
            Ok(())
        );
    }

    /// Review of #222 (P2): the credential store answers "no key" and the
    /// key file is gone or not a key. That key is lost for good, so the file
    /// is quarantined and the defaults load as saved — it used to stay
    /// unverified on every load, and every save was refused for ever.
    #[test]
    fn a_lost_key_quarantines_the_file_instead_of_refusing_every_save() {
        assert!(!key_may_still_exist(&Ok(None), &KeyFile::Missing));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{"settings":{},"hmac":"00"}"#).unwrap();
        let loaded = no_verifying_key(&path, false);
        assert!(
            matches!(loaded, Loaded::Quarantined(_)),
            "quarantined, and so said"
        );
        assert_eq!(may_save_over(Ok(loaded)), Ok(()), "saves may go ahead");
        assert!(!path.exists());
        assert_eq!(
            names_in(dir.path(), "settings.json.tampered-").len(),
            1,
            "kept, not deleted"
        );
    }

    /// The other side: while a key source cannot be read right now, the key
    /// may be in it. Nothing is touched, and saves wait (`settings_unverified`).
    #[test]
    fn a_key_that_may_still_exist_leaves_the_file_alone() {
        assert!(key_may_still_exist(
            &Err("store locked".into()),
            &KeyFile::Missing
        ));
        assert!(key_may_still_exist(&Ok(None), &KeyFile::Unreadable));
        assert!(!key_may_still_exist(&Ok(Some(vec![1])), &KeyFile::Missing));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "{}").unwrap();
        assert!(matches!(
            no_verifying_key(&path, true),
            Loaded::Unverified(_)
        ));
        assert!(path.exists());
    }

    /// A key file that is absent or not a key holds no key; one that cannot
    /// be read may.
    #[test]
    fn the_key_file_is_read_as_key_missing_or_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join("settings.json");
        let key = dir.path().join("settings_hmac.key");
        assert_eq!(read_key_file(&settings), KeyFile::Missing);
        fs::write(&key, "not hex at all").unwrap();
        assert_eq!(read_key_file(&settings), KeyFile::Missing);
        fs::write(&key, "0a0b").unwrap();
        assert_eq!(read_key_file(&settings), KeyFile::Key(vec![10, 11]));
        // A directory in its place: there, and not readable as a file.
        fs::remove_file(&key).unwrap();
        fs::create_dir(&key).unwrap();
        assert_eq!(read_key_file(&settings), KeyFile::Unreadable);
    }

    /// Review of #222 (P3.8): the async Rust callers of the settings file do
    /// their I/O on the blocking pool too — the kill switch's `arm`, the
    /// account-boundary clear, the reapply's revert. (main.rs reads the
    /// settings synchronously in `setup`, on the main thread before the
    /// runtime serves anything, and stays so.)
    #[test]
    fn the_async_callers_load_and_save_off_the_runtime() {
        // A Windows checkout has CRLF endings (core.autocrlf).
        let source = include_str!("settings.rs").replace('\r', "");
        for helper in [
            "pub(crate) async fn load_settings_off_runtime(",
            "pub(crate) async fn clear_account_choices(",
            "pub(crate) async fn restore_tunnel_settings(",
        ] {
            let body = &source[source.find(helper).expect(helper)..];
            let body = &body[..body.find("\n}\n").expect("end of fn")];
            assert!(
                body.contains("tokio::task::spawn_blocking(move ||"),
                "{helper}"
            );
        }
        for (file, call) in [
            (
                include_str!("auth.rs"),
                "settings::clear_account_choices(&app).await",
            ),
            (
                include_str!("session.rs"),
                "settings::clear_account_choices(app).await",
            ),
            (
                include_str!("vpn.rs"),
                "restore_tunnel_settings(&app, &previous).await",
            ),
            (
                include_str!("killswitch.rs"),
                "load_settings_off_runtime(app)",
            ),
        ] {
            assert!(file.contains(call), "{call}");
        }
    }

    /// Round 3 of the review (P2-2): how a failed read maps. A settings.json
    /// that is not UTF-8 fails `read_to_string` with InvalidData; it is a file
    /// that does not parse, and a save may replace it. Before, every read
    /// error was Unreadable, and such a file could never be saved again.
    #[test]
    fn a_settings_file_that_is_not_utf8_does_not_parse_rather_than_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, [0xFF, 0xFE, 0x00, 0x7B]).unwrap();
        let error = fs::read_to_string(&path).expect_err("not UTF-8");
        let mapped = read_error(error);
        assert!(matches!(mapped, LoadError::Unparseable(_)), "{mapped:?}");
        assert_eq!(may_save_over(Err(mapped)), Ok(()), "a save may replace it");

        let denied = read_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(matches!(denied, LoadError::Unreadable(_)), "{denied:?}");
        assert!(may_save_over(Err(denied)).is_err());
        assert!(matches!(
            read_error(std::io::Error::other("sharing violation")),
            LoadError::Unreadable(_)
        ));
    }

    /// Every settings IPC command runs its work through `off_the_runtime`.
    #[test]
    fn every_settings_command_runs_off_the_runtime() {
        // A Windows checkout has CRLF endings (core.autocrlf).
        let source = include_str!("settings.rs").replace('\r', "");
        for command in [
            "pub async fn get_settings(",
            "pub async fn save_settings(",
            "pub async fn set_crash_reports_enabled(",
            "pub async fn set_autostart(",
            "pub async fn reset_settings(",
        ] {
            let body = &source[source.find(command).expect(command)..];
            let body = &body[..body.find("\n}\n").expect("end of fn")];
            assert!(
                body.contains("off_the_runtime(move ||"),
                "{command} does its work on the async runtime"
            );
        }
    }
}
