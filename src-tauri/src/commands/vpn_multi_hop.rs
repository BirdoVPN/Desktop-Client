//! Multi-Hop (Double VPN) commands
//!
//! Extracted from vpn.rs — handles multi-hop route listing and connection.

use tauri::{AppHandle, State};

use crate::api::BirdoApi;
use crate::api::types::ConnectResponse;
use crate::storage::CredentialStore;
use crate::utils::redact::sanitize_error;
use crate::vpn::manager::VpnManager;
use crate::vpn::AutoReconnectService;

use super::vpn::{
    apply_vpn_settings, build_vpn_config, generate_wireguard_keypair,
    get_device_name, parse_endpoint_ip,
};

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
