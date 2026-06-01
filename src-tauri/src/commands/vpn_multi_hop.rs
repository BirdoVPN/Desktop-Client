//! Multi-Hop (Double VPN) commands
//!
//! Extracted from vpn.rs — handles multi-hop route listing and connection.

use tauri::{AppHandle, State};

use crate::api::types::ConnectResponse;
use crate::api::BirdoApi;
use crate::storage::CredentialStore;
use crate::utils::redact::sanitize_error;
use crate::vpn::manager::VpnManager;
use crate::vpn::AutoReconnectService;

use super::vpn::{
    apply_vpn_settings, build_vpn_config, derive_quantum_psk, enforce_requested_protection,
    generate_wireguard_keypair, get_device_name, parse_endpoint_ip, start_stealth_tunnel,
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
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
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
    #[allow(non_snake_case)] entryNodeId: String,
    #[allow(non_snake_case)] exitNodeId: String,
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
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    let device_name = get_device_name();
    let (local_private_key, client_public_key) = generate_wireguard_keypair();
    let vpn_settings = apply_vpn_settings(&app).await;

    let pq_pk = if vpn_settings.quantum_protection {
        Some(crate::vpn::birdo_pq::get_client_public_key_b64().ok_or_else(|| {
            "Post-quantum engine unavailable. Connection aborted because quantum protection is enabled."
                .to_string()
        })?)
    } else {
        None
    };

    // Call multi-hop connect endpoint
    let mh_response = api
        .connect_multi_hop(
            &entryNodeId,
            &exitNodeId,
            &device_name,
            &client_public_key,
            vpn_settings.stealth_mode,
            vpn_settings.quantum_protection,
            pq_pk,
        )
        .await
        .map_err(|e| sanitize_error(&format!("Multi-hop connect failed: {}", e)))?;

    if !mh_response.success {
        let msg = mh_response
            .message
            .unwrap_or_else(|| "Multi-hop connection failed".to_string());
        return Err(msg);
    }

    // Convert MultiHopConnectResponse → ConnectResponse so we can reuse build_vpn_config
    let connect_response = ConnectResponse {
        success: mh_response.success,
        message: mh_response.message,
        error_code: None,
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
        stealth_enabled: mh_response.stealth_enabled,
        xray_endpoint: mh_response.xray_endpoint,
        xray_uuid: mh_response.xray_uuid,
        xray_public_key: mh_response.xray_public_key,
        xray_short_id: mh_response.xray_short_id,
        xray_sni: mh_response.xray_sni,
        xray_flow: mh_response.xray_flow,
        quantum_enabled: mh_response.quantum_enabled,
        rosenpass_public_key: mh_response.rosenpass_public_key,
        rosenpass_endpoint: mh_response.rosenpass_endpoint,
    };

    enforce_requested_protection(
        &connect_response,
        vpn_settings.stealth_mode,
        vpn_settings.quantum_protection,
    )?;

    let stealth_endpoint_override = start_stealth_tunnel(&app, &connect_response).await?;
    let upstream_endpoint_for_killswitch = if stealth_endpoint_override.is_some() {
        connect_response
            .xray_endpoint
            .clone()
            .or_else(|| connect_response.endpoint.clone())
    } else {
        None
    };
    let quantum_psk = derive_quantum_psk(&connect_response)?;

    let server_label = format!("Multi-Hop: {} → {}", entryNodeId, exitNodeId);
    let (mut config, _server_name) = build_vpn_config(
        connect_response,
        &entryNodeId,
        vpn_settings.custom_dns.clone(),
        Some(local_private_key),
        vpn_settings.custom_mtu,
        &vpn_settings.custom_port,
    )?;

    if let Some(ref stealth_ep) = stealth_endpoint_override {
        tracing::info!(
            "Overriding multi-hop WireGuard endpoint to Xray proxy: {}",
            stealth_ep
        );
        config.endpoint = stealth_ep.clone();
    }

    if let Some(ref psk) = quantum_psk {
        config.preshared_key = Some(psk.clone());
    }

    // Set VPN server IP for kill switch
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

    vpn_manager
        .connect(
            config,
            server_label.clone(),
            vpn_settings.local_network_sharing,
        )
        .await
        .map_err(|e| sanitize_error(&format!("Multi-hop connection failed: {}", e)))?;

    auto_reconnect.clear_user_disconnected();
    tracing::info!("Multi-hop VPN connected: {} → {}", entryNodeId, exitNodeId);
    auto_reconnect
        .store_last_config(
            entryNodeId,
            server_label,
            vpn_settings.local_network_sharing,
            vpn_settings.custom_mtu,
            vpn_settings.custom_port,
            vpn_settings.custom_dns,
            vpn_settings.stealth_mode,
            vpn_settings.quantum_protection,
            Some(exitNodeId.clone()),
        )
        .await;
    if let Err(e) = auto_reconnect.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }
    Ok(true)
}
