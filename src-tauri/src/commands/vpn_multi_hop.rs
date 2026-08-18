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
    engage_switch_guard, generate_wireguard_keypair, get_device_name, parse_endpoint_ip,
    release_switch_guard, start_stealth_tunnel,
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

    // Switching onto a multi-hop route from a live session is a server switch —
    // same fail-closed guard as connect_vpn across the teardown + handshake
    // window. Released only after the new tunnel is up.
    let switch_guard = engage_switch_guard(&vpn_manager).await;

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

    // VERIFY THE ROUTE WE ASKED FOR IS THE ROUTE WE GOT.
    //
    // `success: true` only says the request was handled. The client then built a
    // tunnel and displayed the entry -> exit pair from its OWN settings, never
    // reading the `multi_hop` block the backend returns describing what was
    // actually installed. So every failure mode that yields a working single-hop
    // tunnel — the forwarding install being skipped, a fallback path, a
    // response for a different pair — was rendered to the user as their chosen
    // multi-hop route.
    //
    // That is the one thing a privacy product must never do: the user cannot
    // observe their own egress country, so the client is the only thing that can
    // tell them. Refuse rather than display a route we cannot confirm.
    let Some(ref mh) = mh_response.multi_hop else {
        // P6-CLI-D-03: node ids are connection history and ERROR IS written in
        // release, so the ids go to debug and the event stays loud without them.
        tracing::error!(
            "Multi-hop connect returned success but NO route block — refusing to present an \
             unconfirmed route as multi-hop"
        );
        tracing::debug!(entry = %entryNodeId, exit = %exitNodeId, "Unconfirmed multi-hop route");
        return Err(
            "The server did not confirm the Multi-Hop route. Not connecting, because this \
             could leave you on a single-hop tunnel while the app showed two."
                .to_string(),
        );
    };
    if mh.entry_node.id != entryNodeId || mh.exit_node.id != exitNodeId {
        // P6-CLI-D-03: same treatment — four raw node ids must not reach birdo.log.
        tracing::error!("Multi-hop route MISMATCH — refusing");
        tracing::debug!(
            requested_entry = %entryNodeId,
            requested_exit = %exitNodeId,
            got_entry = %mh.entry_node.id,
            got_exit = %mh.exit_node.id,
            "Multi-hop route mismatch detail"
        );
        return Err(format!(
            "The server established a different Multi-Hop route ({}) than the one selected. \
             Not connecting.",
            mh.route
        ));
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
        // Dual-stack parity with single-hop: pass the exit node's assigned IPv6
        // through so build_vpn_config routes IPv6 (and splits allowed_ips into
        // v4/v6) exactly as the single-hop path does. None on an IPv4-only exit
        // node, in which case the tunnel blocks IPv6 to prevent a leak.
        client_ipv6: mh_response.client_ipv6,
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

    let stealth_endpoint_override =
        start_stealth_tunnel(&app, &connect_response, &vpn_settings.custom_port).await?;
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
        // Linux twin: the relay is permitted by ADDRESS and the self-permit is
        // scoped to tcp/443, so a reconnect onto a different server needs the
        // live block re-armed or its handshake is dropped.
        #[cfg(target_os = "linux")]
        if let Err(e) = crate::vpn::firewall_linux::update_vpn_server(ip).await {
            tracing::warn!("Failed to update iptables VPN server: {}", e);
        }
        // macOS twin: pf bakes the relay permit into the loaded ruleset — while
        // a block is engaged it must be re-loaded with the NEW relay IP or the
        // new handshake is dropped (see connect_vpn).
        #[cfg(target_os = "macos")]
        if crate::commands::killswitch::pf_blocking_active() {
            if let Err(e) = crate::commands::killswitch::activate_killswitch().await {
                tracing::warn!("Failed to update pf VPN server permit: {}", e);
            }
        }
    } else {
        // P6-CLI-D-03: the endpoint names the entry node. WARN is written in release,
        // so the diagnostic goes out redacted and the raw value only at debug.
        tracing::warn!(
            "Could not resolve kill switch endpoint IP from '{}'; kill switch may not filter \
             traffic to the VPN server correctly",
            crate::utils::redact::redact_hostname(killswitch_endpoint)
        );
        tracing::debug!(
            "Unresolvable kill switch endpoint (raw): {}",
            killswitch_endpoint
        );
    }

    vpn_manager
        .connect(
            config,
            server_label.clone(),
            vpn_settings.local_network_sharing,
        )
        .await
        .map_err(|e| sanitize_error(&format!("Multi-hop connection failed: {}", e)))?;

    // AUDIT-2026-06-19 FIX (CRITICAL): arm the kill switch once the multi-hop
    // tunnel is up so a drop fails closed (see connect_vpn for the full rationale).
    if let Err(e) = crate::commands::killswitch::arm(&app).await {
        tracing::warn!("Failed to arm kill switch after multi-hop connect: {}", e);
    }

    // New tunnel verified up — release the switch guard (success path only).
    release_switch_guard(switch_guard).await;

    auto_reconnect.clear_user_disconnected();
    // LOG-001: the chosen entry/exit nodes are connection history — keep them
    // out of the release log (info reaches birdo.log); debug is dev-only.
    tracing::info!("Multi-hop VPN connected");
    tracing::debug!("Multi-hop VPN connected: {} → {}", entryNodeId, exitNodeId);
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
