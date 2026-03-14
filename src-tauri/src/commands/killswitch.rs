//! Kill Switch commands
//!
//! Uses Windows Filtering Platform (WFP) to block all traffic except VPN.
//!
//! SEC-C3 FIX: State is now unified — `killswitch.rs` delegates all state
//! queries to `wfp.rs` instead of maintaining independent AtomicBool flags.
//! Previously, `KILLSWITCH_ENABLED`/`KILLSWITCH_ACTIVE` here and
//! `IS_INITIALIZED`/`IS_BLOCKING` in wfp.rs could desynchronize.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;

#[cfg(target_os = "windows")]
use crate::vpn::wfp;
use crate::utils::elevation::is_elevated;

use crate::vpn::manager::VpnManager;

/// SEC-C3 FIX: KILLSWITCH_ENABLED is the single user-intent flag.
/// Active/blocking state is delegated entirely to wfp.rs.
static KILLSWITCH_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global state for kill switch - stores allowed VPN server IP
static VPN_SERVER_IP: once_cell::sync::Lazy<Arc<RwLock<Option<Ipv4Addr>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub enabled: bool,
    pub active: bool,
    pub blocking_connections: u32,
}

/// Enable the kill switch (arm it for when VPN disconnects)
#[tauri::command]
pub async fn enable_killswitch() -> Result<bool, String> {
    tracing::info!("Enabling kill switch");

    #[cfg(target_os = "windows")]
    {
        // Check for admin privileges
        if !is_elevated() {
            tracing::warn!("Kill switch requires administrator privileges");
            return Err("Administrator privileges required for kill switch".to_string());
        }

        // Initialize WFP engine
        if let Err(e) = wfp::initialize().await {
            tracing::error!("Failed to initialize WFP engine: {}", e);
            return Err(format!("Failed to initialize firewall: {}", e));
        }
    }

    KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
    tracing::info!("Kill switch enabled and ready");
    Ok(true)
}

/// Disable the kill switch completely
/// SECURITY: Rejects the command when VPN is in an active state (Connected,
/// Connecting, Reconnecting) to prevent a compromised webview from silently
/// removing leak protection while the tunnel is up.
#[tauri::command]
pub async fn disable_killswitch(vpn_manager: State<'_, VpnManager>) -> Result<bool, String> {
    // F-16 FIX: Enforce VPN state check — reject if tunnel is active
    let state = vpn_manager.get_state().await;
    if state.is_tunnel_active() || state.can_disconnect() {
        tracing::warn!(
            "Refusing to disable kill switch while VPN is in {:?} state",
            state
        );
        return Err(
            "Cannot disable kill switch while VPN is connected or connecting. Disconnect first."
                .to_string(),
        );
    }

    tracing::info!("Disabling kill switch");

    #[cfg(target_os = "windows")]
    {
        // Remove all WFP filters and cleanup
        if let Err(e) = wfp::cleanup().await {
            tracing::warn!("Failed to cleanup WFP filters: {}", e);
        }
    }

    KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
    // SEC-C3 FIX: No longer storing KILLSWITCH_ACTIVE — wfp::is_blocking() is the source of truth
    tracing::info!("Kill switch disabled");
    Ok(true)
}

/// Activate the kill switch (block all non-VPN traffic)
/// Called automatically when VPN disconnects unexpectedly
#[tauri::command]
pub async fn activate_killswitch() -> Result<bool, String> {
    if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
        return Ok(false);
    }

    tracing::warn!("Activating kill switch - blocking all non-VPN traffic");

    #[cfg(target_os = "windows")]
    {
        let server_ip = VPN_SERVER_IP.read().await.clone();
        // Set the VPN server IP before activating
        if let Some(ip) = server_ip {
            wfp::set_vpn_server(ip).await;
        }
        if let Err(e) = wfp::activate_blocking().await {
            tracing::error!("Failed to activate blocking filters: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    // SEC-C3 FIX: Removed KILLSWITCH_ACTIVE.store — wfp::is_blocking() is the source of truth
    Ok(true)
}

/// Deactivate the kill switch (restore normal traffic)
/// Called when VPN connects successfully
#[tauri::command]
pub async fn deactivate_killswitch() -> Result<bool, String> {
    tracing::info!("Deactivating kill switch - restoring normal traffic");

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = wfp::deactivate_blocking().await {
            tracing::error!("Failed to deactivate blocking filters: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    // SEC-C3 FIX: Removed KILLSWITCH_ACTIVE.store — wfp::is_blocking() is the source of truth
    Ok(true)
}

/// Get kill switch status
/// SEC-C3 FIX: Active state now reads from wfp.rs (single source of truth)
#[tauri::command]
pub async fn get_killswitch_status() -> Result<KillSwitchStatus, String> {
    let enabled = is_enabled();
    
    #[cfg(target_os = "windows")]
    let active = wfp::is_blocking();
    #[cfg(not(target_os = "windows"))]
    let active = false;

    // blocking_connections is deprecated, always 0
    let blocking_connections = 0u32;

    Ok(KillSwitchStatus {
        enabled,
        active,
        blocking_connections,
    })
}

/// Set the allowed VPN server IP (called when connecting)
pub async fn set_vpn_server_ip(ip: Option<Ipv4Addr>) {
    *VPN_SERVER_IP.write().await = ip;
    tracing::debug!("Kill switch VPN server IP set to: {:?}", ip);
}

/// Check if kill switch is currently enabled
pub fn is_enabled() -> bool {
    KILLSWITCH_ENABLED.load(Ordering::SeqCst)
}
