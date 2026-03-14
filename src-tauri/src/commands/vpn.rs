//! VPN commands
//!
//! Handles VPN connection, disconnection, and status reporting.

use serde::Serialize;
use tauri::{AppHandle, State};

use crate::api::types::VpnConfig;
use crate::api::types::ConnectResponse;
use crate::api::BirdoApi;
use crate::commands::settings::get_settings;
use crate::storage::CredentialStore;
use crate::utils::redact::sanitize_error;
use crate::vpn::manager::{ConnectionState, VpnManager};
use crate::vpn::AutoReconnectService;

// FIX-1-1: Client-side WireGuard key generation
use boringtun::x25519::{PublicKey, StaticSecret};
use base64::Engine as _;
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
fn get_device_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "Windows PC".to_string())
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
        let msg = response.message.unwrap_or_else(|| "Connection failed".to_string());
        tracing::error!("Server rejected connection: {}", msg);
        return Err(msg);
    }

    // Extract required fields from response
    let key_id = response.key_id.ok_or("Missing key_id in response")?;
    // FIX-1-1: Prefer locally generated private key; fall back to server-provided (legacy)
    let private_key = local_private_key
        .or(response.private_key)
        .ok_or("Missing private_key: neither client-generated nor server-provided")?;
    let public_key = response.public_key.ok_or("Missing public_key in response")?;
    let assigned_ip = response.assigned_ip.ok_or("Missing assigned_ip in response")?;
    let server_public_key = response.server_public_key.ok_or("Missing server_public_key in response")?;
    let endpoint = response.endpoint.ok_or("Missing endpoint in response")?;
    let preshared_key = response.preshared_key; // Optional

    // FIX-R7: Validate DNS addresses to prevent command injection via netsh
    // F-05 FIX: Use custom DNS from user settings if provided, otherwise fall back to server response
    let dns_source = custom_dns
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| response.dns.unwrap_or_else(|| vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]));
    let dns: Vec<String> = dns_source
        .into_iter()
        .filter(|d| d.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if dns.is_empty() {
        return Err("No valid DNS addresses in server response".to_string());
    }

    // Filter out IPv6 CIDRs — Wintun tunnel is IPv4-only on Windows
    let allowed_ips: Vec<String> = response.allowed_ips
        .unwrap_or_else(|| vec!["0.0.0.0/0".to_string()])
        .into_iter()
        .filter(|ip| !ip.contains(':'))
        .collect();
    let allowed_ips = if allowed_ips.is_empty() { vec!["0.0.0.0/0".to_string()] } else { allowed_ips };

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
    let server_name = response.server_node
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
        mtu,
        persistent_keepalive,
    };

    Ok((config, server_name))
}

/// Generate a X25519 keypair for WireGuard. Returns (local_private_key_b64, client_public_key_b64).
/// Private key bytes are zeroized immediately after encoding.
fn generate_wireguard_keypair() -> (String, String) {
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
}

/// Read VPN-related settings and configure WFP split tunneling / local network sharing.
async fn apply_vpn_settings(app: &AppHandle) -> VpnSettings {
    let settings = get_settings(app.clone()).await.ok();
    let custom_dns = settings.as_ref().and_then(|s| s.custom_dns.clone());
    let local_network_sharing = settings.as_ref().map(|s| s.local_network_sharing).unwrap_or(false);
    let split_tunneling_enabled = settings.as_ref().map(|s| s.split_tunneling_enabled).unwrap_or(false);
    let split_tunnel_apps = settings.as_ref().map(|s| s.split_tunnel_apps.clone()).unwrap_or_default();
    let custom_mtu = settings.as_ref().map(|s| s.wireguard_mtu).unwrap_or(0);
    let custom_port = settings.as_ref().map(|s| s.wireguard_port.clone()).unwrap_or_else(|| "auto".to_string());

    crate::vpn::wfp::set_local_network_sharing(local_network_sharing);
    if split_tunneling_enabled && !split_tunnel_apps.is_empty() {
        crate::vpn::wfp::set_split_tunnel_apps(split_tunnel_apps).await;
    } else {
        crate::vpn::wfp::set_split_tunnel_apps(vec![]).await;
    }

    VpnSettings { custom_dns, local_network_sharing, custom_mtu, custom_port }
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
    #[allow(non_snake_case)]
    serverId: String,
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
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
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

    // Connect via backend API — send public key, NOT private key
    tracing::debug!("Calling /vpn/connect for server {}", server_id);
    let response = match api.connect_vpn(&server_id, &device_name, Some(client_public_key)).await {
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
        let msg = response.message.unwrap_or_else(|| "Connection failed".to_string());
        tracing::error!("Server rejected connection: {}", msg);
        return Err(msg);
    }

    tracing::info!("Got VPN config from server, extracting fields...");
    let vpn_settings = apply_vpn_settings(&app).await;

    // H-2 FIX: Use shared helper instead of duplicated extraction logic
    // FIX-1-1: Pass locally generated private key — server response won't contain one
    // P3-1: Pass custom MTU and port from user settings
    let (config, server_name) = build_vpn_config(
        response, &server_id, vpn_settings.custom_dns, Some(local_private_key),
        vpn_settings.custom_mtu, &vpn_settings.custom_port,
    )?;

    tracing::debug!(
        "Got VPN config: endpoint={}, client_ip={}",
        crate::utils::redact_endpoint(&config.endpoint),
        config.client_ip
    );

    // Set the VPN server IP for kill switch permit rules
    if let Some(ip) = parse_endpoint_ip(&config.endpoint) {
        crate::commands::killswitch::set_vpn_server_ip(Some(ip)).await;
        // update_vpn_server sets the IP AND re-activates blocking atomically
        if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
            tracing::warn!("Failed to update WFP VPN server: {}", e);
        }
    }

    // Connect using VPN manager
    vpn_manager
        .connect(config, server_name.clone(), vpn_settings.local_network_sharing)
        .await
        .map_err(|e| sanitize_error(&format!("Connection failed: {}", e)))?;

    // Wire up auto-reconnect: store reconnect info and start health monitoring
    auto_reconnect.clear_user_disconnected();
    auto_reconnect.store_last_config(
        server_id.clone(), server_name, vpn_settings.local_network_sharing,
        vpn_settings.custom_mtu, vpn_settings.custom_port,
    ).await;
    if let Err(e) = auto_reconnect.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }

    tracing::info!("VPN connected successfully to {}", server_id);
    Ok(true)
}

/// Disconnect from VPN
#[tauri::command]
pub async fn disconnect_vpn(
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
}

/// Get current VPN connection status
#[tauri::command]
pub async fn get_vpn_status(vpn_manager: State<'_, VpnManager>) -> Result<VpnStatus, String> {
    // Update stats from tunnel
    vpn_manager.update_stats().await;

    let state = vpn_manager.get_state().await;
    let stats = vpn_manager.get_stats().await;

    let state_str = match state {
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Disconnecting => "disconnecting",
        ConnectionState::Reconnecting { .. } => "reconnecting",
        ConnectionState::Error(_) => "error",
    };

    Ok(VpnStatus {
        state: state_str.to_string(),
        bytes_sent: stats.bytes_sent,
        bytes_received: stats.bytes_received,
        connected_at: stats.connected_at.map(|t| t.to_rfc3339()),
        server_name: stats.server_name,
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

    // Connect via backend API — send public key only
    let response = api
        .connect_vpn(&best_server.id, &device_name, Some(client_public_key))
        .await
        .map_err(|e| sanitize_error(&format!("Failed to connect: {}", e)))?;

    let vpn_settings = apply_vpn_settings(&app).await;

    // H-2 FIX: Use shared helper instead of duplicated extraction logic
    // FIX-1-1: Pass locally generated private key
    // P3-1: Pass custom MTU and port from user settings
    let (config, _server_name) = build_vpn_config(
        response, &best_server.id, vpn_settings.custom_dns, Some(local_private_key),
        vpn_settings.custom_mtu, &vpn_settings.custom_port,
    )?;

    // Set the VPN server IP for kill switch permit rules (quick connect path)
    if let Some(ip) = parse_endpoint_ip(&config.endpoint) {
        crate::commands::killswitch::set_vpn_server_ip(Some(ip)).await;
        if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
            tracing::warn!("Failed to update WFP VPN server: {}", e);
        }
    }

    // Connect using VPN manager
    vpn_manager
        .connect(config, best_server.name.clone(), vpn_settings.local_network_sharing)
        .await
        .map_err(|e| sanitize_error(&format!("Connection failed: {}", e)))?;

    // Wire up auto-reconnect for quick-connect too
    auto_reconnect.clear_user_disconnected();
    auto_reconnect.store_last_config(
        best_server.id.clone(), best_server.name.clone(), vpn_settings.local_network_sharing,
        vpn_settings.custom_mtu, vpn_settings.custom_port,
    ).await;
    if let Err(e) = auto_reconnect.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }

    Ok(true)
}

/// Parse the endpoint IP from a "host:port" string.
/// Returns None if the host part is not a valid IPv4 address (e.g. a hostname).
fn parse_endpoint_ip(endpoint: &str) -> Option<std::net::Ipv4Addr> {
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

/// Measure latency to the connected VPN server
#[tauri::command]
pub async fn measure_vpn_latency(
    vpn_manager: State<'_, VpnManager>,
) -> Result<Option<u32>, String> {
    Ok(vpn_manager.measure_latency().await)
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
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }

    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.get_subscription()
        .await
        .map_err(|e| sanitize_error(&format!("Failed to get subscription: {}", e)))
}

/// Get detailed WFP kill switch status
#[tauri::command]
pub fn get_wfp_status() -> crate::vpn::wfp::KillSwitchStatus {
    let status = crate::vpn::wfp::get_status();
    tracing::debug!(
        "WFP status: initialized={}, active={}, method={}",
        crate::vpn::wfp::is_initialized(),
        status.active,
        status.method
    );
    status
}

// ============================================================================
// Multi-Hop (Double VPN) Commands
// ============================================================================

/// Get available multi-hop routes (SOVEREIGN plan only)
#[tauri::command]
pub async fn get_multi_hop_routes(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<Vec<crate::api::types::MultiHopRoute>, String> {
    // Restore tokens if needed
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.get_multi_hop_routes()
        .await
        .map_err(|e| sanitize_error(&format!("Failed to get multi-hop routes: {}", e)))
}

/// Connect via multi-hop (double VPN): routes through entry node then exit node
#[tauri::command]
pub async fn connect_multi_hop(
    #[allow(non_snake_case)]
    entryNodeId: String,
    #[allow(non_snake_case)]
    exitNodeId: String,
    app: AppHandle,
    api: State<'_, BirdoApi>,
    vpn_manager: State<'_, VpnManager>,
    credentials: State<'_, CredentialStore>,
    auto_reconnect: State<'_, AutoReconnectService>,
) -> Result<bool, String> {
    tracing::debug!(entry = %entryNodeId, exit = %exitNodeId, "connect_multi_hop called");

    if !crate::utils::elevation::is_elevated() {
        return Err(
            "Administrator privileges required. Please right-click the app \
             and select \"Run as administrator\", or restart from an elevated terminal."
            .to_string(),
        );
    }

    // Restore tokens if needed
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    let device_name = get_device_name();
    let (local_private_key, client_public_key) = generate_wireguard_keypair();

    // Call multi-hop connect endpoint
    let mh_response = api.connect_multi_hop(
        &entryNodeId, &exitNodeId, &device_name, &client_public_key,
    ).await.map_err(|e| sanitize_error(&format!("Multi-hop connect failed: {}", e)))?;

    if !mh_response.success {
        let msg = mh_response.message.unwrap_or_else(|| "Multi-hop connection failed".to_string());
        return Err(msg);
    }

    // Convert MultiHopConnectResponse → ConnectResponse so we can reuse build_vpn_config
    let connect_response = ConnectResponse {
        success: mh_response.success,
        message: mh_response.message,
        config: mh_response.config,
        key_id: mh_response.key_id,
        private_key: mh_response.private_key,
        public_key: mh_response.public_key,
        preshared_key: mh_response.preshared_key,
        assigned_ip: mh_response.assigned_ip,
        server_public_key: mh_response.server_public_key,
        endpoint: mh_response.endpoint,
        dns: mh_response.dns,
        allowed_ips: mh_response.allowed_ips,
        mtu: mh_response.mtu,
        persistent_keepalive: mh_response.persistent_keepalive,
        server_node: None,
    };

    let vpn_settings = apply_vpn_settings(&app).await;
    let server_label = format!("Multi-Hop: {} → {}", entryNodeId, exitNodeId);
    let (config, _server_name) = build_vpn_config(
        connect_response, &entryNodeId, vpn_settings.custom_dns, Some(local_private_key),
        vpn_settings.custom_mtu, &vpn_settings.custom_port,
    )?;

    // Set VPN server IP for kill switch
    if let Some(ip) = parse_endpoint_ip(&config.endpoint) {
        crate::commands::killswitch::set_vpn_server_ip(Some(ip)).await;
        if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
            tracing::warn!("Failed to update WFP VPN server: {}", e);
        }
    }

    vpn_manager
        .connect(config, server_label.clone(), vpn_settings.local_network_sharing)
        .await
        .map_err(|e| sanitize_error(&format!("Multi-hop connection failed: {}", e)))?;

    auto_reconnect.clear_user_disconnected();
    tracing::info!("Multi-hop VPN connected: {} → {}", entryNodeId, exitNodeId);
    auto_reconnect.store_last_config(
        entryNodeId, server_label, vpn_settings.local_network_sharing,
        vpn_settings.custom_mtu, vpn_settings.custom_port,
    ).await;
    if let Err(e) = auto_reconnect.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }
    Ok(true)
}

// ============================================================================
// Port Forwarding Commands
// ============================================================================

/// Get active port forwards for the current user
#[tauri::command]
pub async fn get_port_forwards(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<Vec<crate::api::types::PortForward>, String> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.get_port_forwards()
        .await
        .map_err(|e| sanitize_error(&format!("Failed to get port forwards: {}", e)))
}

/// Create a new port forward
#[tauri::command]
pub async fn create_port_forward(
    port: u16,
    protocol: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<crate::api::types::CreatePortForwardResponse, String> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.create_port_forward(port, &protocol, None)
        .await
        .map_err(|e| sanitize_error(&format!("Failed to create port forward: {}", e)))
}

/// Delete an existing port forward
#[tauri::command]
pub async fn delete_port_forward(
    id: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, String> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.delete_port_forward(&id)
        .await
        .map_err(|e| sanitize_error(&format!("Failed to delete port forward: {}", e)))?;

    Ok(true)
}
