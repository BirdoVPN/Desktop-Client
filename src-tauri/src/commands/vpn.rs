//! VPN commands
//!
//! Handles VPN connection, disconnection, and status reporting. The connect
//! and teardown orchestration lives in `commands::session`; the commands here
//! are thin wrappers over it, and every one returns `IpcError` (contract §2).

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::api::types::ConnectResponse;
use crate::api::types::VpnConfig;
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::commands::session::{
    connect_session, connect_session_for, end_session, ensure_signed_in, ConnectPurpose,
    ConnectTarget, EndReason,
};
use crate::commands::settings::{get_settings, AppSettings};
use crate::storage::CredentialStore;
use crate::vpn::manager::{ConnectPhase, ConnectionState, GaveUp, MultiHopStatus, VpnManager};
use crate::vpn::xray::XrayManager;
use crate::vpn::AutoReconnectService;

// FIX-1-1: Client-side WireGuard key generation
use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub uptime_seconds: u64,
    pub current_latency_ms: Option<u32>,
}

/// Get the device name for this machine.
///
/// The derivation moved to `crate::utils` so the auth payloads (which live in
/// `api::types` and cannot reach a `pub(super)` item in `commands`) label a
/// machine exactly the way the VPN commands do. Kept as a thin alias because
/// the connect paths and `commands::auth` already call it by this name.
pub(super) fn get_device_name() -> String {
    crate::utils::get_device_name()
}

// ─── ADAPTIVE TRANSPORT ──────────────────────────────────────────────────────
//
// Desktop twin of Android's TransportProbe + VpnManager.onTransportBlocked
// (birdo-client-mobile). Android reports Connected before any handshake, so it
// needs a post-connect probe; the desktop `WireGuardSession` performs an
// EXPLICIT establish-time handshake (3 attempts x 5s recv timeout,
// wireguard_new.rs) and the whole connect FAILS when the network silently eats
// it — which on a DPI-filtered network (Iran, Russia, Bangladesh) is exactly
// what happens. That failure IS the probe verdict, so the fallback lives in
// `session::connect_session`: classify the error, re-ask the backend with
// `fallbackReason` (granted on ANY plan, including anonymous — see backend
// ConnectDto), and rebuild the same session over Xray Reality.

/// Wire value for "no WireGuard handshake inside the window" — the common DPI
/// case. MUST match the backend ConnectDto `fallbackReason` @IsIn list.
pub(crate) const FALLBACK_HANDSHAKE_TIMEOUT: &str = "handshake-timeout";
/// Wire value for "the transport was actively refused" (ICMP unreachable, RST).
pub(crate) const FALLBACK_TRANSPORT_BLOCKED: &str = "transport-blocked";

/// Classify a failed connect: `Some(reason)` when the establish-time WireGuard
/// handshake got no answer or was refused and an automatic stealth retry is
/// warranted; `None` for every other failure (auth, config, elevation,
/// server-side rejection…), where a fallback would only mask the real error.
/// Keyed on the TYPED transport outcome `IpcError::from_tunnel_failure`
/// records, not on the wording of the message (W1-024).
pub(crate) fn transport_fallback_reason(error: &IpcError) -> Option<&'static str> {
    use crate::commands::ipc_error::TransportFailure;
    match error.transport? {
        TransportFailure::NoResponse => Some(FALLBACK_HANDSHAKE_TIMEOUT),
        TransportFailure::Refused => Some(FALLBACK_TRANSPORT_BLOCKED),
    }
}

/// A stored `fallbackReason` as the wire value it was, `None` for anything
/// that is not one.
pub(crate) fn known_fallback_reason(reason: &str) -> Option<&'static str> {
    [FALLBACK_HANDSHAKE_TIMEOUT, FALLBACK_TRANSPORT_BLOCKED]
        .into_iter()
        .find(|known| *known == reason)
}

fn connect_failure_message(response: &ConnectResponse) -> String {
    // The `error_code` arm that used to sit between these two was removed
    // with ProtocolErrorCode (see api/types.rs): the server never sent the
    // `errorCode` key, so it was always None and this was always
    // `message` -> "Connection failed" in practice.
    response
        .message
        .clone()
        .unwrap_or_else(|| "Connection failed".to_string())
}

/// H-2 FIX: Shared helper to extract VPN config from ConnectResponse.
/// Previously duplicated ~60 lines between connect_vpn and quick_connect.
/// Any security fix (DNS validation, field extraction) now only needs one change.
///
/// F-05 FIX: Accepts optional custom_dns from user settings. When provided,
/// overrides the server-supplied DNS addresses (after validation).
///
/// FIX-1-1 / C-24 (W1-031): `local_private_key` is REQUIRED and is the only
/// private key a config can carry. The server-generated fallback is gone —
/// every caller has generated its key locally since FIX-1-1, and accepting one
/// from the backend would hand the server the client's secret. The response
/// types no longer even deserialize a `privateKey` field.
/// P3-1: `custom_mtu`: 0 = use server default, 1280-1500 = user override.
/// `custom_port`: the `wireguard_port` setting, applied only as far as
/// [`dialable_wireguard_port`] allows.
pub fn build_vpn_config(
    response: ConnectResponse,
    server_id: &str,
    custom_dns: Option<Vec<String>>,
    local_private_key: String,
    custom_mtu: u16,
    custom_port: &str,
) -> Result<(VpnConfig, String), String> {
    if !response.success {
        let msg = connect_failure_message(&response);
        tracing::error!("Server rejected connection: {}", msg);
        return Err(msg);
    }

    // Extract required fields from response
    let key_id = response.key_id.ok_or("Missing key_id in response")?;
    let private_key = local_private_key;
    let public_key = response
        .public_key
        .ok_or("Missing public_key in response")?;
    let assigned_ip = response
        .assigned_ip
        .ok_or("Missing assigned_ip in response")?;
    let server_public_key = response
        .server_public_key
        .ok_or("Missing server_public_key in response")?;
    let endpoint = response.endpoint.ok_or("Missing endpoint in response")?;
    let preshared_key = response.preshared_key; // Optional

    // FIX-R7: Validate DNS addresses to prevent command injection via netsh
    // F-05 FIX: Use custom DNS from user settings if provided, otherwise fall back to server response
    let custom_dns = custom_dns.filter(|d| !d.is_empty());
    let dns_is_custom = custom_dns.is_some();
    let dns_source = custom_dns.unwrap_or_else(|| {
        response.dns.unwrap_or_else(|| {
            // Server supplied no DNS and the user set none — fall back to public
            // resolvers. Log this for transparency: the user's resolver in this
            // case is not one they (or the server) explicitly chose.
            tracing::warn!(
                "No DNS provided by user settings or server response; \
                 falling back to public resolvers (1.1.1.1, 1.0.0.1)"
            );
            vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
        })
    });
    let dns: Vec<String> = dns_source
        .into_iter()
        .filter(|d| d.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if dns.is_empty() {
        return Err("No valid DNS addresses in server response".to_string());
    }

    // Separate IPv4 and IPv6 CIDRs for the tunnel.
    // IPv4 routes go to allowed_ips (used by existing Wintun routing).
    // IPv6 routes go to allowed_ips_v6 (for future dual-stack support).
    let all_ips = response
        .allowed_ips
        .unwrap_or_else(|| vec!["0.0.0.0/0".to_string()]);
    let allowed_ips: Vec<String> = all_ips
        .iter()
        .filter(|ip| !ip.contains(':'))
        .cloned()
        .collect();
    let allowed_ips_v6: Vec<String> = all_ips
        .iter()
        .filter(|ip| ip.contains(':'))
        .cloned()
        .collect();
    let allowed_ips = if allowed_ips.is_empty() {
        vec!["0.0.0.0/0".to_string()]
    } else {
        allowed_ips
    };

    // P3-1: Apply custom MTU from user settings (0 = server default)
    let mtu = if (1280..=1500).contains(&custom_mtu) {
        custom_mtu
    } else {
        response.mtu.unwrap_or(1420)
    };

    // The WireGuard port setting, as far as a relay can answer it.
    let endpoint = match dialable_wireguard_port(custom_port) {
        Some(port) => match endpoint.rfind(':') {
            Some(colon) => format!("{}:{}", &endpoint[..colon], port),
            None => format!("{}:{}", endpoint, port),
        },
        None => endpoint,
    };

    let persistent_keepalive = response.persistent_keepalive.unwrap_or(25);

    // Get server name for display
    let server_name = response
        .server_node
        .map(|n| n.name)
        .unwrap_or_else(|| format!("Server {}", server_id));

    let config = VpnConfig {
        server_id: server_id.to_string(),
        key_id,
        private_key,
        public_key,
        server_public_key,
        preshared_key,
        endpoint,
        allowed_ips,
        dns,
        custom_dns: dns_is_custom,
        client_ip: assigned_ip,
        // Present only for ipv6Enabled nodes — drives the tunnel to ROUTE IPv6
        // instead of blocking it.
        client_ipv6: response.client_ipv6,
        allowed_ips_v6,
        mtu,
        persistent_keepalive,
    };

    // P1-dk-allowedips-no-default-coverage: refuse a scope that leaves part of
    // the address space outside the tunnel — a hostile/compromised backend
    // must not be able to shrink allowed_ips so traffic egresses in the clear
    // under a green "Protected". This is the single choke point every connect
    // path funnels through (session::prepare_tunnel, which the user connect,
    // Multi-Hop and auto-reconnect all share); the per-platform tunnels
    // re-check it in validate_config as defense in depth.
    crate::vpn::validate_tunnel_scope(&config)?;

    Ok((config, server_name))
}

/// The only port the relays accept WireGuard on: vpn-a3 measured all ten — no
/// DNAT, nothing listening on a public 53 (WIN-FIX-3).
pub(crate) const RELAY_WIREGUARD_PORT: u16 = 51820;

/// The port a `wireguard_port` setting may make a connect dial: 51820, or
/// `None` for the server's own endpoint. "53" and custom numbers, which
/// earlier builds offered and no relay answers, are never dialled — whatever a
/// stale settings file or a session's reconnect record still says. The
/// settings load migrates them to "auto" (`settings::migrate_wireguard_port`);
/// Android applies the same rule.
pub(crate) fn dialable_wireguard_port(setting: &str) -> Option<u16> {
    (setting.trim() == "51820").then_some(RELAY_WIREGUARD_PORT)
}

/// Generate a X25519 keypair for WireGuard. Returns (local_private_key_b64, client_public_key_b64).
/// Private key bytes are zeroized immediately after encoding.
/// pub(crate) (was pub(super)) so api/contract_tests.rs can run the REAL
/// producer through the schema's `clientPublicKey` pattern instead of a
/// hand-typed 44-char literal that would pass no matter what this emits.
pub(crate) fn generate_wireguard_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    let mut private_key_bytes = secret.to_bytes();
    let local_private_key = base64::engine::general_purpose::STANDARD.encode(private_key_bytes);
    let client_public_key = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    private_key_bytes.zeroize();
    (local_private_key, client_public_key)
}

/// VPN settings extracted from the user's AppSettings.
/// Returned by `apply_vpn_settings` so callers don't need to re-read the file.
pub struct VpnSettings {
    pub custom_dns: Option<Vec<String>>,
    pub local_network_sharing: bool,
    /// 0 = use server default, 1280-1500 = user override.
    pub custom_mtu: u16,
    /// The `wireguard_port` setting; see [`dialable_wireguard_port`].
    pub custom_port: String,
    /// Enable Xray Reality stealth tunnel
    pub stealth_mode: bool,
    /// Enable Rosenpass post-quantum protection
    pub quantum_protection: bool,
    /// BirdoShield: request the fleet's filtering DNS resolver for this
    /// device (per-device `dnsFiltering` connect flag, OPEN-WORK D18).
    pub dns_filtering: bool,
    /// The whole settings file these were read from: what a later settings
    /// reapply goes back to if it cannot be applied (WIN-FIX-3). `None` when
    /// the file could not be read.
    pub snapshot: Option<AppSettings>,
}

/// The BirdoShield flag a connect body may carry, given the stored preference
/// AND the user's Custom DNS servers (PR #160 review, must-fix 1).
///
/// `build_vpn_config` writes Custom DNS into the tunnel AHEAD of the resolver
/// the server hands back, so with Custom DNS set the filtering resolver is
/// never used: posting `dnsFiltering:true` then makes the backend allocate a
/// resolver this device will not route through, while the session runs
/// unfiltered. ONE rule, applied here (the wire) and mirrored by the
/// `customDnsActive` gate in `VpnSettings.tsx` (the row), so the toggle can
/// never claim protection the tunnel does not have. The precedence itself —
/// Custom DNS wins — is the same one Mobile's
/// `WireGuardConfigBuilder.resolveDnsServers` applies; the owner decides the
/// rule once and both clients follow it. `build_vpn_config`'s own
/// `!d.is_empty()` check is the twin of the emptiness test here.
pub(crate) fn effective_dns_filtering(dns_filtering: bool, custom_dns: Option<&[String]>) -> bool {
    let custom_dns_active = custom_dns.is_some_and(|d| !d.is_empty());
    dns_filtering && !custom_dns_active
}

/// Read VPN-related settings and configure WFP split tunneling / local network sharing.
pub(super) async fn apply_vpn_settings(app: &AppHandle) -> VpnSettings {
    // Settings failing to load means security-relevant flags (stealth_mode,
    // quantum_protection) fall back to their defaults. We keep the resilient
    // fallback behaviour, but surface the cause instead of silently swallowing it.
    let settings = match get_settings(app.clone()).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(
                "Failed to load VPN settings ({}); falling back to defaults \
                 (stealth/quantum disabled)",
                e
            );
            None
        }
    };
    let custom_dns = settings.as_ref().and_then(|s| s.custom_dns.clone());
    let local_network_sharing = settings
        .as_ref()
        .map(|s| s.local_network_sharing)
        .unwrap_or(false);
    let split_tunneling_enabled = settings
        .as_ref()
        .map(|s| s.split_tunneling_enabled)
        .unwrap_or(false);
    let split_tunnel_apps = settings
        .as_ref()
        .map(|s| s.split_tunnel_apps.clone())
        .unwrap_or_default();
    let custom_mtu = settings.as_ref().map(|s| s.wireguard_mtu).unwrap_or(0);
    let custom_port = settings
        .as_ref()
        .map(|s| s.wireguard_port.clone())
        .unwrap_or_else(|| "auto".to_string());
    let stealth_mode = settings.as_ref().map(|s| s.stealth_mode).unwrap_or(false);
    let quantum_protection = settings
        .as_ref()
        .map(|s| s.quantum_protection)
        .unwrap_or(false);
    let dns_filtering = effective_dns_filtering(
        settings.as_ref().map(|s| s.dns_filtering).unwrap_or(false),
        custom_dns.as_deref(),
    );
    // Lockdown (always-on kill switch). The SETTING defaults ON on Windows
    // (AppSettings::default, desktop #34) and is user-switchable in Settings;
    // only an unreadable settings file falls back to reactive (false) here.
    // See wfp::LOCKDOWN_MODE (D-21).
    let lockdown_mode = settings.as_ref().map(|s| s.lockdown_mode).unwrap_or(false);

    // Mirror Local Network Sharing to the kill switch on every platform, so an
    // engaged block still permits the LAN when the user asked for that. Lives
    // here rather than at the connect sites so a settings CHANGE takes effect
    // too, matching the Windows call directly below.
    crate::commands::killswitch::set_lan_sharing(local_network_sharing);
    #[cfg(target_os = "windows")]
    {
        crate::vpn::wfp::set_local_network_sharing(local_network_sharing);
        crate::vpn::wfp::set_lockdown_mode(lockdown_mode);
        if split_tunneling_enabled && !split_tunnel_apps.is_empty() {
            crate::vpn::wfp::set_split_tunnel_apps(split_tunnel_apps).await;
        } else {
            crate::vpn::wfp::set_split_tunnel_apps(vec![]).await;
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = (split_tunneling_enabled, split_tunnel_apps, lockdown_mode);

    VpnSettings {
        custom_dns,
        local_network_sharing,
        custom_mtu,
        custom_port,
        stealth_mode,
        quantum_protection,
        dns_filtering,
        snapshot: settings,
    }
}

/// Bring the kill switch's process-wide settings back in line with the
/// settings file, and rebuild a block in force with them (WIN3-005).
///
/// Every connect attempt applies its settings' kill-switch side — the
/// exceptions, LAN sharing, lockdown — process-wide before it dials
/// ([`apply_vpn_settings`]). A reapply that failed and was reverted left the
/// FAILED values there: an app the user had just excepted, which the file and
/// the UI now say is not, got out on the physical NIC through the next block.
/// A block in force now (lockdown holds one for the whole session) is rebuilt
/// at once; any later one reads the restored values.
///
/// The rebuild is the failed rebuild's own (REVIEW-WIN4-001): under the commit
/// lock, and only while its `epoch` is current, the `fail_connect` pattern. A
/// Disconnect that landed first moved the epoch, and the rebuild is skipped;
/// one that lands after waits for it and disarms after. Unserialised, a pfctl
/// or iptables load finishing after the Disconnect's `disarm` left the
/// block-all in force with no session (macOS, Linux). The process-wide values
/// are set either way: they only describe the file.
async fn reapply_kill_switch_settings(app: &AppHandle, epoch: Option<u64>) {
    apply_vpn_settings(app).await;
    let vm = app.state::<VpnManager>();
    let _commit = vm.lock_commit().await;
    if !epoch.is_some_and(|epoch| vm.is_current(epoch)) {
        return;
    }
    if crate::commands::killswitch::platform_is_blocking() {
        if let Err(e) = crate::commands::killswitch::activate_killswitch().await {
            tracing::warn!(
                "Could not rebuild the kill switch's block with the restored settings: {}",
                e
            );
        }
    }
}

fn stealth_failed(detail: impl AsRef<str>) -> IpcError {
    IpcError::new(IpcErrorCode::StealthFailed, detail)
}

/// Phase 1 helper: Start Xray Reality stealth tunnel if the server provided config.
/// Returns the local `127.0.0.1:<port>` endpoint for WireGuard to route through.
pub(crate) async fn start_stealth_tunnel(
    app: &AppHandle,
    response: &ConnectResponse,
    custom_port: &str,
) -> Result<Option<String>, IpcError> {
    if !response.stealth_enabled.unwrap_or(false) || response.xray_endpoint.is_none() {
        return Ok(None);
    }

    // SEC: Validate all Xray parameters from the server response before use.
    // A compromised or MitM'd server could send malformed values to crash the client.
    let uuid = response.xray_uuid.clone().unwrap_or_default();
    let public_key = response.xray_public_key.clone().unwrap_or_default();
    let short_id = response.xray_short_id.clone().unwrap_or_default();
    let sni = response
        .xray_sni
        .clone()
        .unwrap_or_else(|| "www.microsoft.com".to_string());
    // The stealth tunnel wraps WireGuard UDP in a dokodemo-door → VLESS stream.
    // XTLS Vision (xtls-rprx-vision) is TCP-ONLY and silently drops the UDP
    // RETURN path → the classic "upload works, ~0 download" stealth bug. A
    // UDP-carrying VLESS tunnel MUST use an empty flow. Force it here regardless
    // of the server's advertised xrayFlow (mirrors the Android XrayManager fix
    // shipped in v1.3.30 / mobile #108).
    let _server_flow = response.xray_flow.clone(); // intentionally ignored
    let flow = String::new();

    // UUID: RFC 4122 format
    if uuid.is_empty()
        || uuid.len() != 36
        || !uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return Err(stealth_failed("Invalid Xray UUID format from server"));
    }
    // Public key: the X25519 Reality public key, as `xray x25519` emits it —
    // 43 chars of UNPADDED BASE64URL, not hex.
    //
    // This validator previously required `is_ascii_hexdigit()`, which every real
    // key fails: they contain `-`, `_` and letters outside a-f. Verified against
    // the live fleet, e.g. `ZUBWf8z7esYVrRZy4XaYJ02f6OnlKjOVaPf07_mahTo`.
    // So stealth mode was rejected CLIENT-SIDE for every node on every desktop
    // platform — the feature has never worked here, while Android accepts
    // base64url and works fine.
    //
    // Hex is still accepted so an older/alternate encoding cannot regress.
    let is_b64url_key = public_key.len() == 43
        && public_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let is_hex_key = public_key.len() <= 64 && public_key.chars().all(|c| c.is_ascii_hexdigit());
    if public_key.is_empty() || !(is_b64url_key || is_hex_key) {
        return Err(stealth_failed(
            "Invalid Xray public key format from server (expected 43-char base64url or hex)",
        ));
    }
    // Short ID: hex string, max 16 chars (8 bytes)
    if short_id.len() > 16 || !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(stealth_failed(
            "Invalid Xray shortId format from server (expected ≤16 hex chars)",
        ));
    }
    // SNI: valid domain name characters only, reasonable length
    if sni.is_empty()
        || sni.len() > 253
        || !sni
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return Err(stealth_failed("Invalid Xray SNI format from server"));
    }
    // Flow: allowlisted values only
    const ALLOWED_FLOWS: &[&str] = &["xtls-rprx-vision", "xtls-rprx-vision-udp", ""];
    if !ALLOWED_FLOWS.contains(&flow.as_str()) {
        return Err(stealth_failed(format!(
            "Unsupported Xray flow type '{}' from server",
            flow
        )));
    }

    // P1-dk-xray-wgport-hardcoded: derive the far-side WireGuard port from the
    // port setting (as far as `dialable_wireguard_port` allows), else from the
    // server-supplied WG endpoint, falling back to the relays' port only when
    // neither yields one. The previous hardcoded 51820 made any node on a
    // non-default port unreachable through stealth with no diagnostic.
    let wg_port = dialable_wireguard_port(custom_port)
        .or_else(|| {
            response
                .endpoint
                .as_deref()
                .and_then(|ep| ep.rfind(':').map(|i| &ep[i + 1..]))
                .and_then(|p| p.parse::<u16>().ok())
        })
        .unwrap_or(RELAY_WIREGUARD_PORT);

    let xray_config = crate::vpn::xray::XrayConfig {
        endpoint: response.xray_endpoint.clone().ok_or_else(|| {
            stealth_failed("Server indicated stealth mode but provided no Xray endpoint")
        })?,
        uuid,
        public_key,
        short_id,
        sni,
        flow,
        wg_port,
    };

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| stealth_failed(format!("Failed to get app data dir: {}", e)))?;

    let xray_manager: tauri::State<'_, XrayManager> = app.state();
    match xray_manager.start(&app_data_dir, &xray_config).await {
        Ok(local_port) => {
            tracing::info!(
                "Xray Reality tunnel active, WireGuard will use 127.0.0.1:{}",
                local_port
            );
            Ok(Some(format!("127.0.0.1:{}", local_port)))
        }
        Err(e) => {
            tracing::error!("Failed to start Xray Reality tunnel: {}", e);
            // SEC: Do NOT silently fall back — user explicitly requested stealth mode.
            // Connecting without stealth would expose VPN traffic to DPI.
            Err(stealth_failed(format!(
                "Stealth Mode couldn't start: {}. Not connecting, so your traffic isn't sent \
                 unprotected.",
                e
            )))
        }
    }
}

/// Phase 2 helper: Derive Rosenpass post-quantum hybrid PSK if the server supports it.
///
/// IMPORTANT: A previous version of this function called `derive_hybrid_psk()` which
/// mixed in client-only random entropy. That entropy never reaches the server, so the
/// PSK derived here could never match the PSK the server's WireGuard peer was configured
/// with. The handshake completed at the noise level on each side independently, but
/// every transport packet failed authentication — producing the classic
/// "tunnel up, packets out, no packets in, no IP reachable" symptom.
///
/// AUDIT-C1: Derive WireGuard PSK, preferring genuine bilateral PQ.
///
/// Order of preference:
///   1. BirdoPQ v1 ML-KEM-1024 — decapsulate the server-supplied ciphertext
///      with our persistent client secret key (HNDL-safe).
///   2. If the server enabled quantum mode but decapsulation fails, abort.
///   3. Server-provided classical PSK (TLS-delivered random; not HNDL-safe).
///   4. None — connection runs without PSK.
///
/// The selected mode is latched in `vpn::birdo_pq` so the UI can render the
/// real protection level instead of a no-op toggle indicator.
pub(crate) fn derive_quantum_psk(
    response: &ConnectResponse,
) -> Result<Option<Zeroizing<String>>, String> {
    // 1) True bilateral PQ — only succeeds when server returned a ciphertext
    //    AND we have a local keypair AND decapsulation produced a PSK.
    if let Some(psk) = crate::vpn::birdo_pq::try_decapsulate(response) {
        return Ok(Some(psk));
    }

    if response.quantum_enabled.unwrap_or(false) {
        crate::vpn::birdo_pq::record_disabled();
        return Err(
            "Post-quantum key exchange failed after the server enabled BirdoPQ. Connection aborted to prevent a silent downgrade."
                .to_string(),
        );
    }

    // 2) Fall back to the server's classical preshared_key when present.
    //    (No downgrade warning is possible here: quantum_enabled == true was
    //    already handled above by aborting the connection fail-closed.)
    if response.preshared_key.is_some() {
        crate::vpn::birdo_pq::record_server_provided();
        // Three copies exist on this path, and the caller must wipe all three:
        // the response's own (moved into `VpnConfig` by `build_vpn_config`),
        // this `Zeroizing` clone, and the copy the caller assigns over the
        // config's field — which DISPLACES the first. See the connect sites:
        // a bare `config.preshared_key = Some(..)` frees the displaced String
        // un-wiped, because `VpnConfig::drop` only wipes what is in the field
        // at drop time.
        return Ok(response.preshared_key.clone().map(Zeroizing::new));
    }

    // 3) No PSK at all.
    crate::vpn::birdo_pq::record_disabled();
    Ok(None)
}

/// Fail closed if the user requested a protected mode but the backend response
/// did not enable that mode. This prevents silent downgrade paths in normal
/// connect, quick-connect, multi-hop, and auto-reconnect.
pub(crate) fn enforce_requested_protection(
    response: &ConnectResponse,
    stealth_mode: bool,
    quantum_protection: bool,
) -> Result<(), IpcError> {
    if stealth_mode && !response.stealth_enabled.unwrap_or(false) {
        return Err(stealth_failed(
            "Stealth mode was requested but the server did not enable it. Connection aborted to prevent a silent downgrade.",
        ));
    }

    if quantum_protection && !response.quantum_enabled.unwrap_or(false) {
        crate::vpn::birdo_pq::record_disabled();
        return Err(IpcError::new(
            IpcErrorCode::PqFailed,
            "Post-quantum protection was requested but the server did not enable it. Connection aborted to prevent a silent downgrade.",
        ));
    }

    Ok(())
}

/// Check if the current process has administrator privileges.
/// The frontend calls this on mount to show a warning banner if not elevated.
#[tauri::command]
pub fn get_admin_status() -> bool {
    crate::utils::elevation::is_elevated()
}

/// Connect to a VPN server (or switch to it from a live session).
///
/// ADAPTIVE TRANSPORT, cancellation, the switch guard and the failure states
/// all live in `session::connect_session`. A `disconnect_vpn` while this is in
/// flight makes it resolve with `cancelled` (contract §3.1).
#[tauri::command]
pub async fn connect_vpn(
    #[allow(non_snake_case)] serverId: String,
    app: AppHandle,
) -> Result<bool, IpcError> {
    connect_session(
        &app,
        ConnectTarget::SingleHop {
            server_id: serverId,
        },
    )
    .await
    .map(|()| true)
}

/// Disconnect from VPN. Valid in EVERY state (contract §3.1): it cancels an
/// in-flight connect, stops auto-reconnect, tears the tunnel down and releases
/// the kill-switch block, always-on included.
#[tauri::command]
pub async fn disconnect_vpn(app: AppHandle) -> Result<bool, IpcError> {
    end_session(&app, EndReason::UserDisconnect).await;
    tracing::info!("VPN disconnected");
    Ok(true)
}

/// `get_vpn_status` and the `vpn-status-changed` payload (contract §1).
///
/// camelCase on the wire, the v2 fields included (`killSwitchBlocking`,
/// `reconnectAttempt`, `reconnectMax`, `serverId`, `multiHop`, `seq`,
/// `phase`, `error`), as the pre-v2 fields always were. The `error` payload
/// itself keeps the contract's `IpcError` shape.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatus {
    pub state: &'static str,
    pub phase: Option<ConnectPhase>,
    pub reconnect_attempt: Option<u32>,
    pub reconnect_max: Option<u32>,
    pub kill_switch_blocking: bool,
    pub error: Option<IpcError>,
    pub server_id: Option<String>,
    pub multi_hop: Option<MultiHopStatus>,
    /// Non-null only on the `error` status that ended an auto-reconnect
    /// recovery (REVIEW-WIN-009); see `manager::GaveUp`.
    pub gave_up: Option<GaveUp>,
    pub seq: u64,

    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_at: Option<String>,
    pub server_name: Option<String>,
    pub stealth_active: bool,
    pub quantum_active: bool,
    pub pq_mode: crate::vpn::birdo_pq::PqMode,

    /// What is wrong with DNS right now, one short human sentence each.
    ///
    /// Populated on ALL THREE platforms, and empty whenever there is nothing
    /// wrong. Windows (W1-007): the tunnel interface's resolvers could not be
    /// set (protected, but names will not resolve), or an adapter an OLDER
    /// build parked could not be verifiably put back. Leaking DNS is not on
    /// the list because it cannot happen while connected: the DNS guard is
    /// part of every connect, and a connect whose guard cannot be installed
    /// fails. Neither entry is visible anywhere else, and rendering a
    /// Connected badge over either is rendering reassurance from missing data.
    ///
    /// This was hard-coded `Vec::new()` off Windows while the macOS and Linux
    /// restore passes were computing exactly this value and sending it only to
    /// `tracing::error!` — telling a user whose DNS had just failed to come back
    /// to go and read a log file they cannot fetch, because they have no DNS.
    /// Windows reads the machine-state owner's degradation map; macOS and Linux
    /// read what `dns_journal::settle` published, which is the same choke point
    /// that decides whether the restore journal may be deleted, so the banner
    /// and the record can never disagree.
    ///
    /// Excludes interfaces merely recorded-but-absent (unplugged, or a network
    /// service the user deleted): those are retained in the record so they can
    /// be restored on re-attach, but there is no fault to report and nothing the
    /// user could do about one.
    pub dns_degraded: Vec<String>,
}

/// The one status builder: `get_vpn_status` and the event emitter both call
/// it, so a poll and an event can never disagree on shape. The state part is
/// ONE published snapshot (see `PublishedStatus`); the rest is data.
///
/// It answers from snapshots and NEVER waits on the operation lock, the
/// tunnel or the stealth transport (WIN-FIX-3 P0): a status that queued behind
/// the engine is what turned one stalled tunnel into a dead UI.
/// `update_stats` and `is_running_now` skip a refresh rather than wait.
pub(crate) async fn build_vpn_status(
    vpn_manager: &VpnManager,
    xray_manager: &XrayManager,
) -> VpnStatus {
    vpn_manager.update_stats().await;
    let published = vpn_manager.published();
    let stats = vpn_manager.get_stats().await;
    let (reconnect_attempt, error) = match &published.state {
        ConnectionState::Reconnecting {
            attempt,
            last_error,
        } => (Some(*attempt), last_error.clone()),
        ConnectionState::Error(error) => (None, Some(error.clone())),
        _ => (None, None),
    };

    VpnStatus {
        state: published.state.wire_name(),
        phase: published.phase,
        reconnect_attempt,
        reconnect_max: published.reconnect_max,
        kill_switch_blocking: published.kill_switch_blocking,
        error,
        server_id: published.server_id,
        multi_hop: published.multi_hop,
        gave_up: published.gave_up,
        seq: published.seq,
        bytes_sent: stats.bytes_sent,
        bytes_received: stats.bytes_received,
        connected_at: stats.connected_at.map(|t| t.to_rfc3339()),
        server_name: stats.server_name,
        stealth_active: xray_manager.is_running_now(),
        quantum_active: crate::vpn::birdo_pq::current_mode()
            == crate::vpn::birdo_pq::PqMode::Bilateral,
        pq_mode: crate::vpn::birdo_pq::current_mode(),
        #[cfg(target_os = "windows")]
        dns_degraded: crate::vpn::win_machine_state::degradation_report(),
        #[cfg(not(target_os = "windows"))]
        dns_degraded: crate::vpn::dns_journal::degradation_report(),
    }
}

/// Get current VPN connection status
#[tauri::command]
pub async fn get_vpn_status(
    vpn_manager: State<'_, VpnManager>,
    xray_manager: State<'_, XrayManager>,
) -> Result<VpnStatus, IpcError> {
    Ok(build_vpn_status(&vpn_manager, &xray_manager).await)
}

/// Get VPN connection statistics
#[tauri::command]
pub async fn get_vpn_stats(
    vpn_manager: State<'_, VpnManager>,
) -> Result<ConnectionStats, IpcError> {
    vpn_manager.update_stats().await;
    let stats = vpn_manager.get_stats().await;

    // Calculate uptime
    let uptime_seconds = stats
        .connected_at
        .map(|t| {
            chrono::Utc::now()
                .signed_duration_since(t)
                .num_seconds()
                .max(0) as u64
        })
        .unwrap_or(0);

    Ok(ConnectionStats {
        bytes_in: stats.bytes_received,
        bytes_out: stats.bytes_sent,
        packets_in: stats.packets_received,
        packets_out: stats.packets_sent,
        uptime_seconds,
        // The last handshake's round trip to the relay (W1-002/W1-026): a real
        // measurement, `null` until the session has one.
        current_latency_ms: stats.latency_ms,
    })
}

/// Quick connect to the best available server
#[tauri::command]
pub async fn quick_connect(
    app: AppHandle,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, IpcError> {
    tracing::info!("Quick connect triggered");
    let target = quick_connect_target(&app, &api, &credentials).await?;
    connect_session(&app, target).await.map(|()| true)
}

/// What quick-connect dials: the armed Multi-Hop pair, else the best server.
async fn quick_connect_target(
    app: &AppHandle,
    api: &BirdoApi,
    credentials: &CredentialStore,
) -> Result<ConnectTarget, IpcError> {
    if !crate::utils::elevation::is_elevated() {
        return Err(IpcError::not_elevated());
    }
    ensure_signed_in(api, credentials).await?;

    // MULTI-HOP HONOURED HERE, NOT IN THE UI.
    //
    // Quick-connect is reached from the tray, the auto-connect-on-launch path and
    // the dashboard button. Every one of them built a SINGLE-HOP tunnel while the
    // Multi-Hop cards stayed on screen showing the entry->exit pair the user had
    // chosen — so the app told them their traffic was leaving from the exit
    // country when it was leaving from the entry. For a feature bought
    // specifically for jurisdictional separation, silently serving the other
    // thing is the worst possible failure: the user cannot detect it, and the
    // client is the only thing that could have told them.
    //
    // The branch lives in Rust rather than in each caller because the tray and
    // the launch path have no UI to gate on, and duplicating it per call site is
    // how it went missing in the first place.
    let settings = get_settings(app.clone()).await?;
    if settings.multi_hop_enabled {
        return match (
            settings.multi_hop_entry_node_id.as_deref(),
            settings.multi_hop_exit_node_id.as_deref(),
        ) {
            (Some(entry), Some(exit)) if !entry.is_empty() && !exit.is_empty() => {
                // P6-CLI-D-03: node ids are connection history — debug only, like
                // every other chosen-node line in this file.
                tracing::debug!(%entry, %exit, "Quick connect: multi-hop armed, delegating");
                Ok(ConnectTarget::MultiHop {
                    entry_id: entry.to_string(),
                    exit_id: exit.to_string(),
                })
            }
            // Armed but incomplete — a node was destroyed, or settings were
            // half-written. REFUSE. Falling through to single-hop here is
            // exactly the silent downgrade this branch exists to prevent, and
            // it would be indistinguishable from success to the user.
            _ => Err(IpcError::unknown(
                "Multi-Hop is enabled but no entry/exit pair is selected. Choose both in \
                 Settings, or turn Multi-Hop off to use a single-hop connection.",
            )),
        };
    }

    let servers = api.get_servers().await.map_err(IpcError::from)?;
    let best_server = pick_quick_connect_server(servers, settings.preferred_server_id.as_deref())
        .ok_or_else(|| {
        IpcError::new(
            IpcErrorCode::ServerUnavailable,
            "No online servers available",
        )
    })?;

    // P6-CLI-D-03: the chosen node is connection history. INFO records that a quick
    // connect happened; the node itself only goes to debug.
    tracing::info!("Quick connecting to the preferred or best available server");
    tracing::debug!(
        "Quick connecting to {} ({})",
        best_server.name,
        best_server.id
    );
    Ok(ConnectTarget::SingleHop {
        server_id: best_server.id,
    })
}

/// Quick-connect node choice (OPEN-WORK K10): the least-loaded node the user
/// can actually use.
///
/// Until 1.4.42 this was `.find(|s| s.is_online)` on the backend's list, which
/// `/vpn/servers` sorts by NAME — so every desktop quick-connect landed on
/// Amsterdam regardless of load, and a free-plan user could be handed a paid
/// node and eat the backend's refusal because `accessible` was never checked.
/// Android (VpnManager.quickConnect) already gates on `isOnline && accessible`
/// and ranks `minByOrNull { load }`; this is the same rule. `load` is the
/// backend's composite score (max of slot% and fresh CPU% once birdo-web K10-A
/// ships; slot% before that), so ranking on it needs no client change later.
///
/// Ties on load go by name, then id (REVIEW-WIN-008), each compared by UTF-16
/// code unit — exactly JavaScript's `<` on strings — so the UI's
/// `pickBestServer` (`src/lib/ipc.ts`) lands on the same node: the Connect
/// button, auto-connect and the tray all agree. Ties used to keep LIST order
/// here while the UI used `localeCompare`, which agreed only while the
/// backend's sort happened to match the user's locale. Every node reports
/// load 0 on an idle fleet, so the tie-break is what decides most picks.
/// Both sides run `fixtures/best_server.json`.
///
/// `preferred` is the server the user last chose (`preferred_server_id`, which
/// the UI mirrors from its own selection). The tray's Quick Connect must dial
/// what the Connect button would, so a preferred node the user can use wins
/// over a less-loaded one; an offline, plan-gated or vanished one falls back to
/// the rule above rather than failing.
///
/// Kept free of Tauri state so it is unit-testable.
pub(crate) fn pick_quick_connect_server(
    servers: Vec<crate::api::types::VpnServer>,
    preferred: Option<&str>,
) -> Option<crate::api::types::VpnServer> {
    let usable: Vec<_> = servers
        .into_iter()
        .filter(|s| s.is_online && s.accessible)
        .collect();
    if let Some(chosen) = preferred.and_then(|id| usable.iter().find(|s| s.id == id)) {
        return Some(chosen.clone());
    }
    usable.into_iter().min_by(|a, b| {
        a.load
            .cmp(&b.load)
            .then_with(|| a.name.encode_utf16().cmp(b.name.encode_utf16()))
            .then_with(|| a.id.encode_utf16().cmp(b.id.encode_utf16()))
    })
}

/// What a live settings reapply came to (contract §3, WIN-FIX-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReapplyOutcome {
    /// No live session: the saved change applies at the next connect.
    NotConnected,
    /// The live session runs on the new settings.
    Applied,
    /// The new settings could not be applied. The previous ones are saved
    /// back and the session runs on them; the UI re-reads its settings and
    /// says so.
    Reverted,
}

/// Live-reapply tunnel-affecting settings to the ACTIVE session (mobile parity).
///
/// The frontend persists the change via `save_settings` first, then calls this
/// (debounced). The live tunnel is rebuilt through the SAME connect path as a
/// server switch — `connect_session_for`, which re-reads the fresh settings —
/// so there is no parallel rebuild path to drift, on the transport the session
/// already runs on (`ConnectPurpose::SettingsReapply`).
///
/// WIN-FIX-3: a rebuild that fails is reverted rather than left to strand the
/// user. Live, a switch to a port no relay answers failed its handshake, the
/// Adaptive Transport then tried Stealth (pointless for a settings change),
/// and under lockdown the block held the machine offline in `error` until the
/// user found Disconnect. Now the settings the session connected with
/// (`AutoReconnectService::connected_settings`) are saved back over the
/// tunnel-shaping fields and the session is rebuilt on them — unless it never
/// went down (a failure before the old tunnel was touched keeps it, W1-010).
/// Only if THAT fails does the rebuild end in `error`, with the block held
/// where the kill switch is armed and a working Disconnect, as before.
#[tauri::command]
pub async fn reapply_vpn_settings(app: AppHandle) -> Result<ReapplyOutcome, IpcError> {
    let vm = app.state::<VpnManager>();
    if !vm.get_state().await.is_tunnel_active() {
        tracing::debug!("reapply_vpn_settings: no active session — applies at next connect");
        return Ok(ReapplyOutcome::NotConnected);
    }
    let ar = app.state::<AutoReconnectService>();
    let Some(info) = ar.current_info().await else {
        tracing::warn!("reapply_vpn_settings: no stored target — cannot rebuild");
        return Ok(ReapplyOutcome::NotConnected);
    };
    let previous = ar.connected_settings().await;

    // P6-CLI-D-03: the node being rebuilt to is connection history.
    tracing::info!("Reapplying VPN settings — rebuilding the tunnel");
    tracing::debug!(
        "Reapplying VPN settings — rebuilding tunnel to {}",
        info.server_id
    );
    let target = ConnectTarget::of(&info);
    let purpose = ConnectPurpose::SettingsReapply {
        fallback_reason: info
            .fallback_reason
            .as_deref()
            .and_then(known_fallback_reason),
    };
    let rebuild = connect_session_for(&app, target.clone(), purpose, None).await;
    let error = match rebuild.result {
        Ok(()) => return Ok(ReapplyOutcome::Applied),
        Err(error) => error,
    };
    let plan = failed_reapply(
        error.code == IpcErrorCode::Cancelled,
        previous.is_some(),
        vm.get_state().await.is_tunnel_active(),
    );
    let Some(previous) = previous.filter(|_| plan != FailedReapply::Report) else {
        return Err(error);
    };
    tracing::warn!(
        "The settings change could not be applied ({:?}) — restoring the previous settings",
        error.code
    );
    if let Err(e) = crate::commands::settings::restore_tunnel_settings(&app, &previous) {
        tracing::error!("Could not save the previous settings back: {}", e);
        return Err(error);
    }
    reapply_kill_switch_settings(&app, rebuild.epoch).await;
    if plan == FailedReapply::RestoreSettings {
        return Ok(ReapplyOutcome::Reverted);
    }
    // WIN3-002: the rebuild's failure is on screen by now, and the user may
    // have pressed Disconnect or picked another server since. Either one
    // moved the epoch, and then this reconnect begins nothing (`cancelled`):
    // it must never bring back a session the user ended, or a server the
    // user left. A rebuild that never began has nothing to follow up.
    // Past the restore every error says so: the UI re-reads the settings only
    // then (REVIEW-WIN4-004).
    let restored = |mut error: IpcError| {
        error.settings_restored = true;
        error
    };
    let Some(rebuild_epoch) = rebuild.epoch else {
        return Err(restored(error));
    };
    connect_session_for(&app, target, purpose, Some(rebuild_epoch))
        .await
        .result
        .map(|()| ReapplyOutcome::Reverted)
        .map_err(restored)
}

/// What a settings reapply that failed does next (WIN-FIX-3). Pure, so every
/// branch is tested.
#[derive(Debug, PartialEq, Eq)]
enum FailedReapply {
    /// The error stands: a disconnect or a newer connect superseded the
    /// rebuild (it owns the state), or there is nothing to go back to.
    Report,
    /// Save the previous settings back. The rebuild failed before the old
    /// tunnel was touched, so the session still runs on them (W1-010).
    RestoreSettings,
    /// Save the previous settings back and rebuild the session on them.
    RestoreAndReconnect,
}

fn failed_reapply(cancelled: bool, have_previous: bool, session_alive: bool) -> FailedReapply {
    if cancelled || !have_previous {
        FailedReapply::Report
    } else if session_alive {
        FailedReapply::RestoreSettings
    } else {
        FailedReapply::RestoreAndReconnect
    }
}

/// Parse the endpoint IP from a "host:port" string.
/// Returns None if the host part is not a valid IPv4 address (e.g. a hostname).
pub(crate) fn parse_endpoint_ip(endpoint: &str) -> Option<std::net::Ipv4Addr> {
    if endpoint.starts_with('[') {
        // IPv6 [addr]:port — not relevant for WFP IPv4 filters
        return None;
    }
    let host = match endpoint.rfind(':') {
        Some(pos) => &endpoint[..pos],
        None => endpoint,
    };
    host.parse::<std::net::Ipv4Addr>().ok()
}

/// Get subscription status from the API
#[tauri::command]
pub async fn get_subscription_status(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<crate::api::types::SubscriptionStatus, IpcError> {
    ensure_signed_in(&api, &credentials).await?;
    api.get_subscription().await.map_err(IpcError::from)
}

/// Fetch the public client configuration (`GET /api/client-config`).
///
/// Unauthenticated on purpose — the payload is the same for every user, so
/// unlike `get_subscription_status` this command does not restore tokens or
/// refuse when signed out.
///
/// Errors are returned as `Err` rather than swallowed into a default here: the
/// CALLER owns the fallback, and the frontend's fallback is "available". If
/// this returned a synthesized `dnsFilteringAvailable: false` on a network
/// blip, every offline client would hide a feature that works.
#[tauri::command]
pub async fn get_client_config(
    api: State<'_, BirdoApi>,
) -> Result<crate::api::types::ClientConfigResponse, IpcError> {
    api.get_client_config().await.map_err(IpcError::from)
}

/// Get per-user monthly bandwidth usage + cap for the data-usage meter.
/// Distinct from `get_vpn_stats` (local live-tunnel throughput counters).
#[tauri::command]
pub async fn get_usage_stats(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<crate::api::types::UsageStats, IpcError> {
    ensure_signed_in(&api, &credentials).await?;
    api.get_usage_stats().await.map_err(IpcError::from)
}

// Multi-hop and port forwarding commands extracted to vpn_multi_hop.rs and vpn_port_forward.rs

#[cfg(test)]
mod tests {
    use super::*;

    /// WIN-FIX-3: a reapply that fails goes back to what the session ran on,
    /// and is rebuilt on it when the old tunnel is gone — never when a
    /// disconnect superseded it, and only with something to go back to.
    #[test]
    fn a_failed_reapply_goes_back_to_the_previous_settings() {
        use FailedReapply::*;
        assert_eq!(failed_reapply(false, true, false), RestoreAndReconnect);
        assert_eq!(failed_reapply(false, true, true), RestoreSettings);
        assert_eq!(failed_reapply(true, true, false), Report);
        assert_eq!(failed_reapply(true, true, true), Report);
        assert_eq!(failed_reapply(false, false, false), Report);

        // The wiring: the rebuild, then the restore, then the second rebuild
        // on the same purpose (the session's own transport, no stealth retry)
        // — as a follow-up of the first, so a Disconnect or a newer connect
        // in between wins (WIN3-002; `begin_follow_up` is tested in
        // `vpn::manager`).
        let source = include_str!("vpn.rs");
        let body = &source[source.find("pub async fn reapply_vpn_settings(").unwrap()..];
        let body = &body[..body.find("\n}").unwrap()];
        let mut last = 0;
        for needle in [
            "ar.connected_settings().await",
            "ConnectPurpose::SettingsReapply {",
            "let rebuild = connect_session_for(&app, target.clone(), purpose, None)",
            "failed_reapply(",
            "restore_tunnel_settings(&app, &previous)",
            // WIN3-005: the failed attempt's kill-switch globals go, before
            // either outcome — the session kept, or rebuilt on the old ones.
            "reapply_kill_switch_settings(&app, rebuild.epoch).await;",
            "FailedReapply::RestoreSettings",
            "let Some(rebuild_epoch) = rebuild.epoch else {",
            "connect_session_for(&app, target, purpose, Some(rebuild_epoch))",
            "ReapplyOutcome::Reverted",
            ".map_err(restored)",
        ] {
            let at = body[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
            last += at + needle.len();
        }
        assert_eq!(
            serde_json::to_value(ReapplyOutcome::Reverted).unwrap(),
            serde_json::json!("reverted")
        );
        assert_eq!(
            serde_json::to_value(ReapplyOutcome::NotConnected).unwrap(),
            serde_json::json!("not_connected")
        );
    }

    /// WIN3-005: a reverted reapply puts the kill switch's side back too —
    /// the globals from the restored file, and a block in force rebuilt with
    /// them. A source pin: both halves need an `AppHandle` and the real WFP
    /// engine, which a unit test must not touch.
    #[test]
    fn a_reverted_reapply_puts_the_kill_switch_settings_back() {
        let source = include_str!("vpn.rs");
        let body = &source[source
            .find("async fn reapply_kill_switch_settings(")
            .unwrap()..];
        let body = &body[..body.find("\n}").unwrap()];
        let mut last = 0;
        for needle in [
            "apply_vpn_settings(app).await;",
            // REVIEW-WIN4-001: the block only for the session it was asked
            // for, serialised against a Disconnect's teardown.
            "let _commit = vm.lock_commit().await;",
            "vm.is_current(epoch)",
            "killswitch::platform_is_blocking()",
            "killswitch::activate_killswitch().await",
        ] {
            let at = body[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
            last += at + needle.len();
        }
        // What apply_vpn_settings sets is exactly the kill switch's side.
        let apply = &source[source
            .find("pub(super) async fn apply_vpn_settings(")
            .unwrap()..];
        let apply = &apply[..apply.find("\n}").unwrap()];
        for global in [
            "killswitch::set_lan_sharing(local_network_sharing)",
            "wfp::set_local_network_sharing(local_network_sharing)",
            "wfp::set_lockdown_mode(lockdown_mode)",
            "wfp::set_split_tunnel_apps(split_tunnel_apps)",
        ] {
            assert!(apply.contains(global), "{global}");
        }
    }

    /// WIN-FIX-3: the relays take WireGuard on 51820 only. "53" and custom
    /// ports, offered by earlier builds, failed the handshake on every relay;
    /// a stale value left in a settings file or a reconnect record must never
    /// be dialled, and 51820 is what "auto" dials anyway.
    #[test]
    fn only_the_relays_port_is_ever_dialled() {
        assert_eq!(dialable_wireguard_port("51820"), Some(51820));
        for stale in ["auto", "53", "443", "1194", "0", "", "abc", "65535"] {
            assert_eq!(dialable_wireguard_port(stale), None, "{stale:?}");
        }
        let endpoint_for = |setting: &str| {
            let response: ConnectResponse = serde_json::from_value(serde_json::json!({
                "success": true,
                "keyId": "k1",
                "publicKey": "cGs=",
                "assignedIp": "10.8.0.2",
                "serverPublicKey": "c3BrPQ==",
                "endpoint": "203.0.113.1:51820",
            }))
            .unwrap();
            build_vpn_config(response, "ams-1", None, "a2V5".into(), 0, setting)
                .map(|(config, _)| config.endpoint.clone())
                .unwrap()
        };
        for setting in ["auto", "51820", "53", "5353", "not-a-port"] {
            assert_eq!(endpoint_for(setting), "203.0.113.1:51820", "{setting:?}");
        }
    }

    /// WIN-FIX-3 P0: `get_vpn_status` answers while every lock the engine has
    /// is held (a connect stuck in a synchronous step, a teardown stopping the
    /// tunnel) and while the stealth helper's slot is busy. In T5 the status
    /// queued behind a stalled tunnel and the UI went dead with it.
    #[tokio::test]
    async fn the_status_answers_while_the_engine_is_wedged() {
        fn not_blocking() -> crate::vpn::manager::BlockProbe {
            crate::vpn::manager::BlockProbe {
                blocking: false,
                holds_block_while_connected: false,
            }
        }
        let vm = VpnManager::with_block_probe(not_blocking);
        let xray = XrayManager::new();
        let _engine = vm.wedge_for_test().await;
        let _transport = xray.hold_slot_for_test().await;
        let status = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            build_vpn_status(&vm, &xray),
        )
        .await
        .expect("the status waited on the engine");
        assert_eq!(status.state, "disconnected");
        assert!(!status.stealth_active);
    }

    // ------------------------------------------------------------------
    // PR #160 review, must-fix 1: BirdoShield vs Custom DNS. `build_vpn_config`
    // writes Custom DNS into the tunnel ahead of the server's resolver, so the
    // connect body must not request a filtering resolver the tunnel will not
    // use — and the UI gate in VpnSettings.tsx applies the same rule.
    // ------------------------------------------------------------------

    #[test]
    fn dns_filtering_is_dropped_when_custom_dns_is_set() {
        let custom = vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()];
        assert!(!effective_dns_filtering(true, Some(&custom)));
        // A single custom resolver is enough — same threshold as the tunnel builder.
        let one = vec!["1.1.1.1".to_string()];
        assert!(!effective_dns_filtering(true, Some(&one)));
    }

    #[test]
    fn dns_filtering_survives_no_or_empty_custom_dns() {
        assert!(effective_dns_filtering(true, None));
        // An empty list is what `build_vpn_config` treats as "no custom DNS"
        // (`filter(|d| !d.is_empty())`), so it must not gate the flag either.
        let empty: Vec<String> = Vec::new();
        assert!(effective_dns_filtering(true, Some(&empty)));
    }

    #[test]
    fn dns_filtering_off_stays_off_regardless_of_custom_dns() {
        let custom = vec!["9.9.9.9".to_string()];
        assert!(!effective_dns_filtering(false, None));
        assert!(!effective_dns_filtering(false, Some(&custom)));
    }

    /// The tunnel-builder side of the same rule, asserted directly: with Custom
    /// DNS set, the resolver the server returned (the filtering one under
    /// BirdoShield) is NOT what lands in the tunnel. This is the precedence
    /// `effective_dns_filtering` exists to keep the connect body honest about.
    #[test]
    fn build_vpn_config_prefers_custom_dns_over_server_resolver() {
        // Built from the wire shape (camelCase) so the test goes through the
        // same serde defaults a real /vpn/connect response does.
        let response: ConnectResponse = serde_json::from_value(serde_json::json!({
            "success": true,
            "keyId": "key-1",
            "publicKey": "pub",
            "assignedIp": "10.0.0.2/32",
            "serverPublicKey": "spk",
            "endpoint": "203.0.113.1:51820",
            "dns": ["10.64.0.1"],            // the filtering resolver
            "allowedIps": ["0.0.0.0/0"],
        }))
        .unwrap();
        let (local_private_key, _) = generate_wireguard_keypair();
        let (config, _) = build_vpn_config(
            response,
            "server-1",
            Some(vec!["9.9.9.9".into()]),
            local_private_key,
            0,
            "auto",
        )
        .expect("config builds");
        assert_eq!(config.dns, vec!["9.9.9.9".to_string()]);
    }

    /// The exact shape a DPI-filtered connect produces: wireguard_new's marker,
    /// wrapped by handshake_with_retry, tunnel start, and VpnManager::connect.
    /// The marker is read ONCE, at the tunnel stage (`from_tunnel_failure`),
    /// and the fallback keys on the typed outcome.
    #[test]
    fn classifies_wrapped_handshake_timeout_as_fallback() {
        let err = IpcError::from_tunnel_failure(&format!(
            "Failed to start tunnel: Handshake failed after 3 attempts: {}",
            crate::vpn::ERR_HANDSHAKE_NO_RESPONSE
        ));
        assert_eq!(
            transport_fallback_reason(&err),
            Some(FALLBACK_HANDSHAKE_TIMEOUT)
        );
    }

    #[test]
    fn classifies_refused_transport_as_fallback() {
        let err = IpcError::from_tunnel_failure(&format!(
            "Failed to start tunnel: Handshake failed after 3 attempts: {}: \
             An existing connection was forcibly closed by the remote host. (os error 10054)",
            crate::vpn::ERR_HANDSHAKE_RECV
        ));
        assert_eq!(
            transport_fallback_reason(&err),
            Some(FALLBACK_TRANSPORT_BLOCKED)
        );
    }

    /// Every other failure must NOT trigger a fallback — a stealth rebuild
    /// would mask the real error (auth, config, elevation, server refusal).
    /// A code alone, whatever its words, never carries a transport outcome.
    #[test]
    fn non_transport_errors_do_not_classify() {
        for err in [
            IpcError::new(
                IpcErrorCode::SessionExpired,
                "Not authenticated. Please log in first.",
            ),
            IpcError::new(IpcErrorCode::ServerError, "Missing key_id in response"),
            IpcError::from_tunnel_failure("Connection timed out after 30s"),
            IpcError::new(
                IpcErrorCode::StealthFailed,
                "Stealth mode was requested but the server did not enable it.",
            ),
            IpcError::new(IpcErrorCode::Unknown, crate::vpn::ERR_HANDSHAKE_NO_RESPONSE),
        ] {
            assert_eq!(transport_fallback_reason(&err), None, "{err}");
        }
    }

    /// W1-031 (C-24): a response that still carries a server-generated private
    /// key cannot put it in the tunnel config — the field no longer exists on
    /// the response type, and the config key is always the local one.
    #[test]
    fn connect_response_private_key_is_never_used() {
        // Zero entropy on purpose, so no secret scanner reads it as a real key.
        let server_sent_key = "k".repeat(44);
        let response: ConnectResponse = serde_json::from_value(serde_json::json!({
            "success": true,
            "keyId": "key-1",
            "privateKey": server_sent_key,
            "publicKey": "pub",
            "assignedIp": "10.0.0.2",
            "serverPublicKey": "spk",
            "endpoint": "203.0.113.1:51820",
            "dns": ["10.64.0.1"],
            "allowedIps": ["0.0.0.0/0"],
        }))
        .unwrap();
        let (local, _) = generate_wireguard_keypair();
        let (config, _) =
            build_vpn_config(response, "server-1", None, local.clone(), 0, "auto").unwrap();
        assert_eq!(config.private_key, local);
        assert_ne!(config.private_key, server_sent_key);
    }

    /// Contract §1: the exact key set of `VpnStatus`, camelCase throughout
    /// (the casing correction of 2026-09-30); the IpcError inside keeps its
    /// contract shape.
    #[test]
    fn vpn_status_serializes_the_contract_shape() {
        let status = VpnStatus {
            state: "reconnecting",
            phase: Some(ConnectPhase::Handshaking),
            reconnect_attempt: Some(2),
            reconnect_max: Some(10),
            kill_switch_blocking: true,
            error: Some(IpcError::new(IpcErrorCode::ServerUnreachable, "x")),
            server_id: Some("exit-1".into()),
            multi_hop: Some(MultiHopStatus {
                entry_id: "entry-1".into(),
                entry_name: "Frankfurt".into(),
                exit_id: "exit-1".into(),
                exit_name: "Reykjavik".into(),
            }),
            gave_up: Some(GaveUp { attempts: 10 }),
            seq: 7,
            bytes_sent: 1,
            bytes_received: 2,
            connected_at: None,
            server_name: Some("Frankfurt → Reykjavik".into()),
            stealth_active: false,
            quantum_active: false,
            pq_mode: crate::vpn::birdo_pq::PqMode::Disabled,
            dns_degraded: vec![],
        };
        let json = serde_json::to_value(&status).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "bytesReceived",
                "bytesSent",
                "connectedAt",
                "dnsDegraded",
                "error",
                "gaveUp",
                "killSwitchBlocking",
                "multiHop",
                "phase",
                "pqMode",
                "quantumActive",
                "reconnectAttempt",
                "reconnectMax",
                "seq",
                "serverId",
                "serverName",
                "state",
                "stealthActive"
            ]
        );
        assert_eq!(json["phase"], "handshaking");
        assert_eq!(json["gaveUp"], serde_json::json!({ "attempts": 10 }));
        assert_eq!(json["error"]["code"], "server_unreachable");
        assert!(json["error"].get("retry_after_secs").is_some());
        assert_eq!(
            json["multiHop"],
            serde_json::json!({
                "entryId": "entry-1",
                "entryName": "Frankfurt",
                "exitId": "exit-1",
                "exitName": "Reykjavik"
            })
        );
    }

    /// No silent downgrade, with the right code for each refusal.
    #[test]
    fn protection_refusals_carry_their_codes() {
        let mut resp = withheld_psk_response(Some(false));
        resp.stealth_enabled = Some(false);
        assert_eq!(
            enforce_requested_protection(&resp, true, false)
                .unwrap_err()
                .code,
            IpcErrorCode::StealthFailed
        );
        assert_eq!(
            enforce_requested_protection(&resp, false, true)
                .unwrap_err()
                .code,
            IpcErrorCode::PqFailed
        );
        assert!(enforce_requested_protection(&resp, false, false).is_ok());
    }

    // ------------------------------------------------------------------
    // OPEN-WORK G5: with `pqClientCanDecapsulate:true` on the wire the backend
    // withholds `presharedKey`. This proves that a withheld PSK can never
    // degrade to a classical/no-PSK tunnel: when quantum mode is on and the
    // ciphertext cannot be decapsulated, derive_quantum_psk must ERR, not
    // return the (absent) server PSK or Ok(None).
    // ------------------------------------------------------------------

    /// Synthetic backend response: quantum on, PSK withheld, undecapsulatable
    /// ciphertext ("AAAA" is 3 bytes, ML-KEM-1024 ciphertexts are 1568).
    fn withheld_psk_response(quantum_enabled: Option<bool>) -> ConnectResponse {
        ConnectResponse {
            success: true,
            message: None,
            quota_exceeded: false,
            key_id: Some("k1".into()),
            public_key: None,
            preshared_key: None,
            assigned_ip: None,
            client_ipv6: None,
            server_public_key: None,
            endpoint: None,
            dns: None,
            allowed_ips: None,
            mtu: None,
            persistent_keepalive: None,
            server_node: None,
            stealth_enabled: None,
            xray_endpoint: None,
            xray_uuid: None,
            xray_public_key: None,
            xray_short_id: None,
            xray_sni: None,
            xray_flow: None,
            quantum_enabled,
            rosenpass_public_key: Some("AAAA".into()),
            rosenpass_endpoint: Some("bm9uY2U=".into()),
        }
    }

    #[test]
    fn derive_quantum_psk_fails_closed_when_psk_withheld() {
        let resp = withheld_psk_response(Some(true));
        let r = derive_quantum_psk(&resp);
        assert!(r.is_err(), "expected fail-closed Err, got {r:?}");
        assert!(r.unwrap_err().contains("silent downgrade"));
    }

    /// Control: the same response with quantum OFF is the legacy no-PSK path
    /// and must NOT abort — proves the test above bites on `quantum_enabled`
    /// specifically, not on the missing PSK alone.
    #[test]
    fn derive_quantum_psk_allows_no_psk_when_quantum_off() {
        let resp = withheld_psk_response(Some(false));
        assert_eq!(derive_quantum_psk(&resp), Ok(None));
    }

    /// The consequence of a BirdoPQ decapsulation that cannot happen — an
    /// unusable persisted `birdo_pq_v1.bin`, a malformed ciphertext, a missing
    /// nonce — is an ABORTED connect, never a demotion to the server's
    /// classical PSK. Three comments in `vpn::birdo_pq` once justified
    /// discarding the user's long-lived ML-KEM identity key with the opposite
    /// claim: a permanent, silent demotion for the life of the install. It
    /// cannot occur, and this is the assertion that would have said so. (The
    /// exact phrase is not repeated here — scripts/ci/check-pq-features.sh
    /// bans it from `src/` outright.) Here the server DOES offer a classical
    /// `preshared_key`, so `Ok(Some(_))` is sitting there for the taking and
    /// is still refused.
    #[test]
    fn undecapsulatable_pq_aborts_even_when_a_server_psk_is_offered() {
        let mut resp = withheld_psk_response(Some(true));
        resp.preshared_key = Some("c2VydmVyLXN1cHBsaWVkLWNsYXNzaWNhbC1wc2s=".into());
        let r = derive_quantum_psk(&resp);
        assert!(
            r.is_err(),
            "a failed PQ decapsulation must abort, not take the offered classical PSK; got {r:?}"
        );
        assert!(r.unwrap_err().contains("silent downgrade"));
    }

    /// The other direction of the same correction: with `quantum_enabled` off,
    /// `try_decapsulate` returns at its first line and the PQ key file is never
    /// opened, so the state of that file cannot affect the classical path at
    /// all — there is no install-lifetime fallback for an unusable key to
    /// cause. The server PSK is taken. (The `PqMode` latch is process-global
    /// and other tests move it, so asserting on it here would race.)
    #[test]
    fn quantum_off_takes_the_server_psk_regardless_of_the_pq_key_file() {
        let mut resp = withheld_psk_response(Some(false));
        resp.preshared_key = Some("c2VydmVyLXN1cHBsaWVkLWNsYXNzaWNhbC1wc2s=".into());
        assert_eq!(
            derive_quantum_psk(&resp),
            Ok(Some(Zeroizing::new(
                "c2VydmVyLXN1cHBsaWVkLWNsYXNzaWNhbC1wc2s=".to_string()
            )))
        );
    }

    // ------------------------------------------------------------------
    // OPEN-WORK K10: quick-connect picks the least-loaded ACCESSIBLE node.
    // ------------------------------------------------------------------

    fn server(id: &str, online: bool, accessible: bool, load: u8) -> crate::api::types::VpnServer {
        // Built from the wire shape so the test exercises the same serde
        // defaults quick-connect sees from /vpn/servers.
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": id,
            "country": "XX",
            "isOnline": online,
            "accessible": accessible,
            "load": load,
        }))
        .unwrap()
    }

    #[test]
    fn quick_connect_picks_lowest_load() {
        let picked = pick_quick_connect_server(
            vec![server("A", true, true, 60), server("B", true, true, 10)],
            None,
        )
        .unwrap();
        assert_eq!(picked.id, "B");
    }

    /// A free user's quick-connect must never target a plan-gated node, even
    /// when it is the emptiest — the backend would refuse and the user would
    /// see a failure instead of a connection.
    #[test]
    fn quick_connect_skips_inaccessible_even_when_emptier() {
        let picked = pick_quick_connect_server(
            vec![server("A", true, false, 5), server("B", true, true, 40)],
            None,
        )
        .unwrap();
        assert_eq!(picked.id, "B");
    }

    #[test]
    fn quick_connect_skips_offline_even_when_emptier() {
        let picked = pick_quick_connect_server(
            vec![server("A", false, true, 0), server("B", true, true, 40)],
            None,
        )
        .unwrap();
        assert_eq!(picked.id, "B");
    }

    #[test]
    fn quick_connect_none_when_all_offline() {
        assert!(pick_quick_connect_server(
            vec![server("A", false, true, 0), server("B", false, true, 0),],
            None
        )
        .is_none());
        assert!(pick_quick_connect_server(vec![], None).is_none());
    }

    /// The tray dials the user's own server when they can use it, even when a
    /// node is emptier — the same server the Connect button would dial.
    #[test]
    fn quick_connect_prefers_the_users_server_when_usable() {
        let picked = pick_quick_connect_server(
            vec![server("A", true, true, 5), server("B", true, true, 90)],
            Some("B"),
        )
        .unwrap();
        assert_eq!(picked.id, "B");
    }

    /// A preferred node that went offline, lost plan access or vanished falls
    /// back to the least-loaded usable one instead of failing the connect.
    #[test]
    fn quick_connect_falls_back_when_the_preferred_server_is_unusable() {
        for preferred in ["OFF", "LOCKED", "GONE"] {
            let picked = pick_quick_connect_server(
                vec![
                    server("OFF", false, true, 0),
                    server("LOCKED", true, false, 0),
                    server("A", true, true, 50),
                    server("B", true, true, 10),
                ],
                Some(preferred),
            )
            .unwrap();
            assert_eq!(picked.id, "B", "preferred {preferred}");
        }
    }

    /// REVIEW-WIN-008: the one best-server rule, run against the fixture the
    /// UI's `pickBestServer` test runs too (src/lib/ipc.test.ts). Equal loads
    /// now go by name, not list order: an idle fleet still picks
    /// deterministically, and the same node as the Connect button.
    #[test]
    fn quick_connect_follows_the_shared_best_server_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/best_server.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() >= 5, "vacuity guard");
        for case in cases {
            let mut servers: Vec<crate::api::types::VpnServer> =
                serde_json::from_value(case["servers"].clone()).unwrap();
            for _order in ["as listed", "reversed"] {
                let picked = pick_quick_connect_server(servers.clone(), None).map(|s| s.id);
                assert_eq!(
                    picked.as_deref(),
                    case["expect"].as_str(),
                    "{} ({_order})",
                    case["name"]
                );
                servers.reverse();
            }
        }
    }
}
