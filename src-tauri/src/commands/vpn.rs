//! VPN commands
//!
//! Handles VPN connection, disconnection, and status reporting.

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::api::types::ConnectResponse;
use crate::api::types::VpnConfig;
use crate::api::BirdoApi;
use crate::commands::settings::get_settings;
use crate::storage::CredentialStore;
use crate::utils::redact::sanitize_error;
use crate::vpn::manager::{ConnectionState, VpnManager};
use crate::vpn::xray::XrayManager;
use crate::vpn::AutoReconnectService;

// FIX-1-1: Client-side WireGuard key generation
use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub uptime_seconds: u64,
    pub current_latency_ms: Option<u32>,
}

/// Get the device name for this machine
pub(super) fn get_device_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| {
            if cfg!(target_os = "macos") {
                "Mac".to_string()
            } else if cfg!(target_os = "linux") {
                "Linux".to_string()
            } else {
                "Desktop".to_string()
            }
        })
}

fn connect_failure_message(response: &ConnectResponse) -> String {
    response
        .message
        .clone()
        .or_else(|| response.error_code.as_ref().map(|code| code.user_message().to_string()))
        .unwrap_or_else(|| "Connection failed".to_string())
}

/// H-2 FIX: Shared helper to extract VPN config from ConnectResponse.
/// Previously duplicated ~60 lines between connect_vpn and quick_connect.
/// Any security fix (DNS validation, field extraction) now only needs one change.
///
/// F-05 FIX: Accepts optional custom_dns from user settings. When provided,
/// overrides the server-supplied DNS addresses (after validation).
///
/// FIX-1-1: Accepts optional local_private_key from client-side keygen.
/// When provided, uses it instead of the server-returned private key.
/// P3-1: `custom_mtu`: 0 = use server default, 1280-1500 = user override.
/// P3-1: `custom_port`: "auto" = use server endpoint as-is, otherwise override the port.
pub fn build_vpn_config(
    response: ConnectResponse,
    server_id: &str,
    custom_dns: Option<Vec<String>>,
    local_private_key: Option<String>,
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
    // FIX-1-1: Prefer locally generated private key; fall back to server-provided (legacy)
    let private_key = local_private_key
        .or(response.private_key)
        .ok_or("Missing private_key: neither client-generated nor server-provided")?;
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
    let dns_source = custom_dns.filter(|d| !d.is_empty()).unwrap_or_else(|| {
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

    // P3-1: Apply custom WireGuard port from user settings
    let endpoint = if custom_port != "auto" {
        if let Ok(port) = custom_port.parse::<u16>() {
            if let Some(colon) = endpoint.rfind(':') {
                format!("{}:{}", &endpoint[..colon], port)
            } else {
                format!("{}:{}", endpoint, port)
            }
        } else {
            endpoint // invalid port string, keep server default
        }
    } else {
        endpoint
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
        client_ip: assigned_ip,
        // Present only for ipv6Enabled nodes — drives the tunnel to ROUTE IPv6
        // instead of blocking it.
        client_ipv6: response.client_ipv6,
        allowed_ips_v6,
        mtu,
        persistent_keepalive,
    };

    Ok((config, server_name))
}

/// Generate a X25519 keypair for WireGuard. Returns (local_private_key_b64, client_public_key_b64).
/// Private key bytes are zeroized immediately after encoding.
pub(super) fn generate_wireguard_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    let mut private_key_bytes = secret.to_bytes();
    let local_private_key = base64::engine::general_purpose::STANDARD.encode(&private_key_bytes);
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
    /// "auto" = use server default, otherwise a port number string.
    pub custom_port: String,
    /// Enable Xray Reality stealth tunnel
    pub stealth_mode: bool,
    /// Enable Rosenpass post-quantum protection
    pub quantum_protection: bool,
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
    // Lockdown (always-on kill switch) — OFF by default; needs device verification
    // before being enabled (see wfp::LOCKDOWN_MODE).
    let lockdown_mode = settings
        .as_ref()
        .map(|s| s.lockdown_mode)
        .unwrap_or(false);

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

    VpnSettings {
        custom_dns,
        local_network_sharing,
        custom_mtu,
        custom_port,
        stealth_mode,
        quantum_protection,
    }
}

/// Phase 1 helper: Start Xray Reality stealth tunnel if the server provided config.
/// Returns the local `127.0.0.1:<port>` endpoint for WireGuard to route through.
pub(crate) async fn start_stealth_tunnel(
    app: &AppHandle,
    response: &ConnectResponse,
) -> Result<Option<String>, String> {
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
        return Err("Invalid Xray UUID format from server".to_string());
    }
    // Public key: 64-char hex (Curve25519 key in X25519 Reality format)
    if public_key.is_empty()
        || public_key.len() > 64
        || !public_key.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(
            "Invalid Xray public key format from server (expected ≤64 hex chars)".to_string(),
        );
    }
    // Short ID: hex string, max 16 chars (8 bytes)
    if short_id.len() > 16 || !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid Xray shortId format from server (expected ≤16 hex chars)".to_string());
    }
    // SNI: valid domain name characters only, reasonable length
    if sni.is_empty()
        || sni.len() > 253
        || !sni
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return Err("Invalid Xray SNI format from server".to_string());
    }
    // Flow: allowlisted values only
    const ALLOWED_FLOWS: &[&str] = &["xtls-rprx-vision", "xtls-rprx-vision-udp", ""];
    if !ALLOWED_FLOWS.contains(&flow.as_str()) {
        return Err(format!("Unsupported Xray flow type '{}' from server", flow));
    }

    let xray_config = crate::vpn::xray::XrayConfig {
        endpoint: response
            .xray_endpoint
            .clone()
            .ok_or("Server indicated stealth mode but provided no Xray endpoint")?,
        uuid,
        public_key,
        short_id,
        sni,
        flow,
        wg_port: 51820,
    };

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;

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
            Err(format!(
                "Stealth tunnel failed to start: {}. Connection aborted to protect your privacy.",
                e
            ))
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
pub(crate) fn derive_quantum_psk(response: &ConnectResponse) -> Result<Option<String>, String> {
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
    if response.preshared_key.is_some() {
        if response.quantum_enabled.unwrap_or(false) {
            tracing::warn!(
                "BirdoPQ: server did not return a PQ ciphertext — falling back to \
                 server-provided classical PSK (NOT HNDL-safe)"
            );
        }
        crate::vpn::birdo_pq::record_server_provided();
        return Ok(response.preshared_key.clone());
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
) -> Result<(), String> {
    if stealth_mode && !response.stealth_enabled.unwrap_or(false) {
        return Err(
            "Stealth mode was requested but the server did not enable it. Connection aborted to prevent a silent downgrade."
                .to_string(),
        );
    }

    if quantum_protection && !response.quantum_enabled.unwrap_or(false) {
        crate::vpn::birdo_pq::record_disabled();
        return Err(
            "Post-quantum protection was requested but the server did not enable it. Connection aborted to prevent a silent downgrade."
                .to_string(),
        );
    }

    Ok(())
}

/// Check if the current process has administrator privileges.
/// The frontend calls this on mount to show a warning banner if not elevated.
#[tauri::command]
pub fn get_admin_status() -> bool {
    crate::utils::elevation::is_elevated()
}

/// Connect to a VPN server
#[tauri::command]
pub async fn connect_vpn(
    #[allow(non_snake_case)] serverId: String,
    app: AppHandle,
    api: State<'_, BirdoApi>,
    vpn_manager: State<'_, VpnManager>,
    credentials: State<'_, CredentialStore>,
    auto_reconnect: State<'_, AutoReconnectService>,
) -> Result<bool, String> {
    let server_id = serverId;
    tracing::debug!(server_id = %server_id, "connect_vpn called");

    // Pre-flight: refuse to proceed without admin privileges.
    // Wintun adapter creation is an in-process FFI call that requires
    // administrator — failing early with a clear message is better than
    // a cryptic Win32 error deep in the tunnel code.
    if !crate::utils::elevation::is_elevated() {
        return Err(
            "Administrator privileges required. Please right-click the app \
             and select \"Run as administrator\", or restart from an elevated terminal."
                .to_string(),
        );
    }

    // Restore tokens from credential store if not in memory
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            tracing::debug!("Restoring tokens from credential store");
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }
    }

    // Check if we have a valid token
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    // Get device name for connection
    let device_name = get_device_name();

    // FIX-1-1: Generate X25519 keypair locally — private key never leaves this device.
    let (local_private_key, client_public_key) = generate_wireguard_keypair();

    // Apply VPN settings early — needed for the API call (stealth/quantum flags)
    let vpn_settings = apply_vpn_settings(&app).await;

    // Connect via backend API — send public key, NOT private key
    tracing::debug!("Calling /vpn/connect for server {}", server_id);

    // AUDIT-C1: When PQ is requested, attach our ML-KEM-1024 client public key
    // so the server can encapsulate against it and ship us the ciphertext.
    let pq_pk = if vpn_settings.quantum_protection {
        Some(crate::vpn::birdo_pq::get_client_public_key_b64().ok_or_else(|| {
            "Post-quantum engine unavailable. Connection aborted because quantum protection is enabled."
                .to_string()
        })?)
    } else {
        None
    };

    let response = match api
        .connect_vpn(
            &server_id,
            &device_name,
            Some(client_public_key),
            if vpn_settings.stealth_mode {
                Some(true)
            } else {
                None
            },
            if vpn_settings.quantum_protection {
                Some(true)
            } else {
                None
            },
            pq_pk,
        )
        .await
    {
        Ok(resp) => {
            tracing::info!("API response received: success={}", resp.success);
            resp
        }
        Err(e) => {
            tracing::error!("API call failed: {}", e);
            return Err(sanitize_error(&format!("Failed to connect: {}", e)));
        }
    };

    if !response.success {
        let msg = connect_failure_message(&response);
        tracing::error!("Server rejected connection: {}", msg);
        return Err(msg);
    }

    enforce_requested_protection(
        &response,
        vpn_settings.stealth_mode,
        vpn_settings.quantum_protection,
    )?;

    tracing::info!("Got VPN config from server, extracting fields...");

    // Phase 1: Xray Reality Stealth Tunnel
    let stealth_endpoint_override = start_stealth_tunnel(&app, &response).await?;
    let upstream_endpoint_for_killswitch = if stealth_endpoint_override.is_some() {
        response
            .xray_endpoint
            .clone()
            .or_else(|| response.endpoint.clone())
    } else {
        None
    };

    // Phase 2: Rosenpass Post-Quantum PSK
    let quantum_psk = derive_quantum_psk(&response)?;

    // H-2 FIX: Use shared helper instead of duplicated extraction logic
    // FIX-1-1: Pass locally generated private key — server response won't contain one
    // P3-1: Pass custom MTU and port from user settings
    let (mut config, server_name) = build_vpn_config(
        response,
        &server_id,
        vpn_settings.custom_dns.clone(),
        Some(local_private_key),
        vpn_settings.custom_mtu,
        &vpn_settings.custom_port,
    )?;

    // Phase 3: Apply stealth endpoint override (Xray local proxy)
    if let Some(ref stealth_ep) = stealth_endpoint_override {
        tracing::info!(
            "Overriding WireGuard endpoint to Xray proxy: {}",
            stealth_ep
        );
        config.endpoint = stealth_ep.clone();
    }

    // Phase 3b: Apply quantum PSK override
    if let Some(ref psk) = quantum_psk {
        config.preshared_key = Some(psk.clone());
    }

    tracing::debug!(
        "Got VPN config: endpoint={}, client_ip={}",
        crate::utils::redact_endpoint(&config.endpoint),
        config.client_ip
    );

    // Set the VPN server IP for kill switch permit rules
    let killswitch_endpoint = upstream_endpoint_for_killswitch
        .as_deref()
        .unwrap_or(&config.endpoint);
    if let Some(ip) = parse_endpoint_ip(killswitch_endpoint) {
        crate::commands::killswitch::set_vpn_server_ip(Some(ip)).await;
        // update_vpn_server sets the IP AND re-activates blocking atomically
        #[cfg(target_os = "windows")]
        if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
            tracing::warn!("Failed to update WFP VPN server: {}", e);
        }
    }

    // Connect using VPN manager
    vpn_manager
        .connect(
            config,
            server_name.clone(),
            vpn_settings.local_network_sharing,
        )
        .await
        .map_err(|e| sanitize_error(&format!("Connection failed: {}", e)))?;

    // AUDIT-2026-06-19 FIX (CRITICAL): now that the tunnel is up, arm the kill
    // switch so an unexpected drop fails CLOSED — the auto-reconnect health loop
    // installs the WFP block-all during the reconnect gap (it previously
    // short-circuited because the kill switch was never armed). Best-effort: a
    // failure to arm must not tear down a working tunnel.
    if let Err(e) = crate::commands::killswitch::arm().await {
        tracing::warn!("Failed to arm kill switch after connect: {}", e);
    }

    // Wire up auto-reconnect: store reconnect info and start health monitoring
    auto_reconnect.clear_user_disconnected();
    auto_reconnect
        .store_last_config(
            server_id.clone(),
            server_name,
            vpn_settings.local_network_sharing,
            vpn_settings.custom_mtu,
            vpn_settings.custom_port,
            vpn_settings.custom_dns,
            vpn_settings.stealth_mode,
            vpn_settings.quantum_protection,
            None,
        )
        .await;
    if let Err(e) = auto_reconnect.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }

    tracing::info!("VPN connected successfully to {}", server_id);
    Ok(true)
}

/// Disconnect from VPN
#[tauri::command]
pub async fn disconnect_vpn(
    app: AppHandle,
    api: State<'_, BirdoApi>,
    vpn_manager: State<'_, VpnManager>,
    auto_reconnect: State<'_, AutoReconnectService>,
) -> Result<bool, String> {
    tracing::info!("Disconnecting from VPN");

    // Stop auto-reconnect and signal user-initiated disconnect
    auto_reconnect.set_user_disconnected();
    auto_reconnect.stop().await;
    auto_reconnect.clear_last_config().await;

    // FIX-R5: Signal that this is a user-initiated disconnect so auto-reconnect
    // does not immediately bring the tunnel back up.
    vpn_manager.set_user_disconnected(true);

    // Stop Xray Reality tunnel if running
    let xray_manager: tauri::State<'_, XrayManager> = app.state();
    xray_manager.stop().await;

    // Get key_id before disconnecting locally
    let key_id = vpn_manager.get_key_id().await;

    // PERF-DISCONNECT: Notify backend BEFORE local tunnel teardown.
    // The backend call is a fast HTTP DELETE (~100-300ms). Doing it first
    // frees the server-side resources (peer, IP) while we tear down locally.
    // Best-effort — don't fail the disconnect if the API call fails.
    if let Some(ref key_id) = key_id {
        if let Err(e) = api.disconnect_vpn(key_id).await {
            tracing::warn!("Failed to notify backend of disconnect: {}", e);
        }
    }

    // Disconnect locally (tunnel teardown, route cleanup, DNS restore)
    vpn_manager
        .disconnect()
        .await
        .map_err(|e| sanitize_error(&format!("Disconnect failed: {}", e)))?;

    // AUDIT-2026-06-19 FIX: disarm the kill switch on user-initiated disconnect so
    // the WFP block-all filters (if active) are removed and the machine is never
    // stranded behind the firewall. Best-effort; disarm() logs its own failures.
    let _ = crate::commands::killswitch::disarm().await;

    tracing::info!("VPN disconnected");
    Ok(true)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatus {
    pub state: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_at: Option<String>,
    pub server_name: Option<String>,
    pub stealth_active: bool,
    pub quantum_active: bool,
    pub pq_mode: crate::vpn::birdo_pq::PqMode,
}

/// Get current VPN connection status
#[tauri::command]
pub async fn get_vpn_status(
    vpn_manager: State<'_, VpnManager>,
    xray_manager: State<'_, XrayManager>,
) -> Result<VpnStatus, String> {
    // Update stats from tunnel
    vpn_manager.update_stats().await;

    let state = vpn_manager.get_state().await;
    let stats = vpn_manager.get_stats().await;

    let state_str = match state {
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Authenticating => "authenticating",
        ConnectionState::StealthConnecting => "stealth_connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Disconnecting => "disconnecting",
        ConnectionState::Reconnecting { .. } => "reconnecting",
        ConnectionState::KillSwitchActive => "kill_switch_active",
        ConnectionState::Error(_) => "error",
    };

    Ok(VpnStatus {
        state: state_str.to_string(),
        bytes_sent: stats.bytes_sent,
        bytes_received: stats.bytes_received,
        connected_at: stats.connected_at.map(|t| t.to_rfc3339()),
        server_name: stats.server_name,
        stealth_active: xray_manager.is_running().await,
        quantum_active: crate::vpn::birdo_pq::current_mode()
            == crate::vpn::birdo_pq::PqMode::Bilateral,
        pq_mode: crate::vpn::birdo_pq::current_mode(),
    })
}

/// Get VPN connection statistics
#[tauri::command]
pub async fn get_vpn_stats(vpn_manager: State<'_, VpnManager>) -> Result<ConnectionStats, String> {
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
        current_latency_ms: stats.latency_ms,
    })
}

/// Quick connect to the best available server
#[tauri::command]
pub async fn quick_connect(
    app: AppHandle,
    api: State<'_, BirdoApi>,
    vpn_manager: State<'_, VpnManager>,
    auto_reconnect: State<'_, AutoReconnectService>,
) -> Result<bool, String> {
    tracing::info!("Quick connect triggered");

    // Pre-flight admin check
    if !crate::utils::elevation::is_elevated() {
        return Err(
            "Administrator privileges required. Please right-click the app \
             and select \"Run as administrator\", or restart from an elevated terminal."
                .to_string(),
        );
    }

    // Check if we have a valid token
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    // Get available servers
    let servers = api
        .get_servers()
        .await
        .map_err(|e| format!("Failed to get servers: {}", e))?;

    // Find the best server (first online server)
    let best_server = servers
        .into_iter()
        .find(|s| s.is_online)
        .ok_or("No online servers available")?;

    tracing::info!(
        "Quick connecting to {} ({})",
        best_server.name,
        best_server.id
    );

    // Get device name for connection
    let device_name = get_device_name();

    // FIX-1-1: Generate X25519 keypair locally
    let (local_private_key, client_public_key) = generate_wireguard_keypair();

    // AUDIT-C1: quick-connect respects the user's quantum-protection setting too.
    let vpn_settings = apply_vpn_settings(&app).await;
    let pq_pk = if vpn_settings.quantum_protection {
        Some(crate::vpn::birdo_pq::get_client_public_key_b64().ok_or_else(|| {
            "Post-quantum engine unavailable. Connection aborted because quantum protection is enabled."
                .to_string()
        })?)
    } else {
        None
    };

    // Connect via backend API — send public key only
    let response = api
        .connect_vpn(
            &best_server.id,
            &device_name,
            Some(client_public_key),
            if vpn_settings.stealth_mode {
                Some(true)
            } else {
                None
            },
            if vpn_settings.quantum_protection {
                Some(true)
            } else {
                None
            },
            pq_pk,
        )
        .await
        .map_err(|e| sanitize_error(&format!("Failed to connect: {}", e)))?;

    if !response.success {
        let msg = connect_failure_message(&response);
        return Err(msg);
    }

    enforce_requested_protection(
        &response,
        vpn_settings.stealth_mode,
        vpn_settings.quantum_protection,
    )?;

    let stealth_endpoint_override = start_stealth_tunnel(&app, &response).await?;
    let upstream_endpoint_for_killswitch = if stealth_endpoint_override.is_some() {
        response
            .xray_endpoint
            .clone()
            .or_else(|| response.endpoint.clone())
    } else {
        None
    };
    let quantum_psk = derive_quantum_psk(&response)?;

    // H-2 FIX: Use shared helper instead of duplicated extraction logic
    // FIX-1-1: Pass locally generated private key
    // P3-1: Pass custom MTU and port from user settings
    let (mut config, _server_name) = build_vpn_config(
        response,
        &best_server.id,
        vpn_settings.custom_dns.clone(),
        Some(local_private_key),
        vpn_settings.custom_mtu,
        &vpn_settings.custom_port,
    )?;

    if let Some(ref stealth_ep) = stealth_endpoint_override {
        tracing::info!(
            "Overriding quick-connect WireGuard endpoint to Xray proxy: {}",
            stealth_ep
        );
        config.endpoint = stealth_ep.clone();
    }

    if let Some(ref psk) = quantum_psk {
        config.preshared_key = Some(psk.clone());
    }

    // Set the VPN server IP for kill switch permit rules (quick connect path)
    let killswitch_endpoint = upstream_endpoint_for_killswitch
        .as_deref()
        .unwrap_or(&config.endpoint);
    if let Some(ip) = parse_endpoint_ip(killswitch_endpoint) {
        crate::commands::killswitch::set_vpn_server_ip(Some(ip)).await;
        #[cfg(target_os = "windows")]
        if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
            tracing::warn!("Failed to update WFP VPN server: {}", e);
        }
    }

    // Connect using VPN manager
    vpn_manager
        .connect(
            config,
            best_server.name.clone(),
            vpn_settings.local_network_sharing,
        )
        .await
        .map_err(|e| sanitize_error(&format!("Connection failed: {}", e)))?;

    // AUDIT-2026-06-19 FIX (CRITICAL): arm the kill switch once the tunnel is up
    // so a drop fails closed (see connect_vpn for the full rationale).
    if let Err(e) = crate::commands::killswitch::arm().await {
        tracing::warn!("Failed to arm kill switch after quick-connect: {}", e);
    }

    // Wire up auto-reconnect for quick-connect too
    auto_reconnect.clear_user_disconnected();
    auto_reconnect
        .store_last_config(
            best_server.id.clone(),
            best_server.name.clone(),
            vpn_settings.local_network_sharing,
            vpn_settings.custom_mtu,
            vpn_settings.custom_port,
            vpn_settings.custom_dns,
            vpn_settings.stealth_mode,
            vpn_settings.quantum_protection,
            None,
        )
        .await;
    if let Err(e) = auto_reconnect.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }

    Ok(true)
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
) -> Result<crate::api::types::SubscriptionStatus, String> {
    // Restore tokens if needed
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }
    }

    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.get_subscription()
        .await
        .map_err(|e| sanitize_error(&format!("Failed to get subscription: {}", e)))
}

// Multi-hop and port forwarding commands extracted to vpn_multi_hop.rs and vpn_port_forward.rs
