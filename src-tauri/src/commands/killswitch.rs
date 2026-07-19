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
use tauri::{AppHandle, State};
use tokio::sync::RwLock;

use crate::utils::elevation::is_elevated;
#[cfg(target_os = "linux")]
use crate::vpn::firewall_linux;
#[cfg(target_os = "windows")]
use crate::vpn::wfp;

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

    #[cfg(target_os = "macos")]
    {
        if !is_elevated() {
            tracing::warn!("Kill switch requires root privileges on macOS");
            return Err("Root privileges required for kill switch".to_string());
        }
    }

    #[cfg(target_os = "linux")]
    {
        if !is_elevated() {
            tracing::warn!("Kill switch requires root privileges on Linux");
            return Err("Root privileges required for kill switch".to_string());
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

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = pf_deactivate_blocking().await {
            tracing::warn!("Failed to remove pf rules: {}", e);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = firewall_linux::deactivate_blocking().await {
            tracing::warn!("Failed to remove iptables rules: {}", e);
        }
    }

    KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
    // SEC-C3 FIX: No longer storing KILLSWITCH_ACTIVE — wfp::is_blocking() is the source of truth
    tracing::info!("Kill switch disabled");
    Ok(true)
}

/// Activate the kill switch (block all non-VPN traffic).
///
/// DT-7: Not a Tauri IPC command — called internally by the auto-reconnect
/// service when the VPN drops unexpectedly. Kept as a plain async fn to shrink
/// the IPC attack surface (the frontend never invoked it).
pub async fn activate_killswitch() -> Result<bool, String> {
    if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
        return Ok(false);
    }

    tracing::warn!("Activating kill switch - blocking all non-VPN traffic");

    #[cfg(target_os = "windows")]
    {
        let server_ip = *VPN_SERVER_IP.read().await;
        // Set the VPN server IP before activating
        if let Some(ip) = server_ip {
            wfp::set_vpn_server(ip).await;
        }
        if let Err(e) = wfp::activate_blocking().await {
            tracing::error!("Failed to activate blocking filters: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let server_ip = VPN_SERVER_IP.read().await.clone();
        if let Err(e) = pf_activate_blocking(server_ip).await {
            tracing::error!("Failed to activate pf blocking: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    #[cfg(target_os = "linux")]
    {
        let server_ip = VPN_SERVER_IP.read().await.clone();
        if let Err(e) = firewall_linux::activate_blocking(server_ip).await {
            tracing::error!("Failed to activate iptables blocking: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    // SEC-C3 FIX: Removed KILLSWITCH_ACTIVE.store — wfp::is_blocking() is the source of truth
    Ok(true)
}

/// Deactivate the kill switch (restore normal traffic).
///
/// DT-7: Not a Tauri IPC command — called internally by the auto-reconnect
/// service when the VPN reconnects. Kept as a plain async fn (the frontend
/// never invoked it).
pub async fn deactivate_killswitch() -> Result<bool, String> {
    tracing::info!("Deactivating kill switch - restoring normal traffic");

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = wfp::deactivate_blocking().await {
            tracing::error!("Failed to deactivate blocking filters: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = pf_deactivate_blocking().await {
            tracing::error!("Failed to deactivate pf blocking: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = firewall_linux::deactivate_blocking().await {
            tracing::error!("Failed to deactivate iptables blocking: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    // SEC-C3 FIX: Removed KILLSWITCH_ACTIVE.store — wfp::is_blocking() is the source of truth
    Ok(true)
}

/// Live-apply a kill-switch preference change to the CURRENT session.
///
/// The Settings toggle persists the preference via `save_settings`, but that only
/// takes effect at the next connect (arm() reads it there). Without this, a user
/// who connects with the kill switch OFF and toggles it ON mid-session would see
/// the toggle ON while WFP was never initialized and `KILLSWITCH_ENABLED` stayed
/// false — so an unexpected drop would NOT fail closed. This mirrors mobile,
/// which pushes the flag into the running service live.
///
/// The frontend persists the preference first, then calls this. Behaviour:
/// - enabled=true, session active  → arm now (init WFP + set intent; activate
///   immediately in lockdown mode).
/// - enabled=false, session active → clear the intent so a later drop won't
///   block, and lift any block currently active; WFP stays initialized and the
///   disconnect path fully cleans up.
/// - no active session → no-op; the persisted preference applies at next connect.
#[tauri::command]
pub async fn set_killswitch_live(
    enabled: bool,
    app: AppHandle,
    vpn_manager: State<'_, VpnManager>,
) -> Result<bool, String> {
    let state = vpn_manager.get_state().await;
    let active = state.is_tunnel_active() || state.can_disconnect();
    if !active {
        tracing::debug!("set_killswitch_live: no active session — applies at next connect");
        return Ok(false);
    }

    if enabled {
        // arm() re-reads the (already-persisted) preference and initializes WFP,
        // engaging the reactive protection for the live session.
        arm(&app).await
    } else {
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
        #[cfg(target_os = "windows")]
        {
            if wfp::is_blocking() {
                let _ = deactivate_killswitch().await;
            }
        }
        tracing::info!("Kill switch softened live for the active session (intent cleared)");
        Ok(true)
    }
}

/// Get kill switch status
/// SEC-C3 FIX: Active state now reads from wfp.rs (single source of truth)
#[tauri::command]
pub async fn get_killswitch_status() -> Result<KillSwitchStatus, String> {
    let enabled = is_enabled();

    #[cfg(target_os = "windows")]
    let active = wfp::is_blocking();
    #[cfg(target_os = "macos")]
    let active = PF_BLOCKING.load(Ordering::SeqCst);
    #[cfg(target_os = "linux")]
    let active = firewall_linux::is_blocking();
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
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

/// Whether the kill switch is in lockdown (always-on) mode. Cross-platform
/// accessor used by the auto-reconnect loop so it keeps the block active
/// continuously instead of deactivating in steady Connected state.
pub fn is_lockdown_mode() -> bool {
    #[cfg(target_os = "windows")]
    {
        wfp::is_lockdown_mode()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Arm the kill switch for an active VPN session.
///
/// AUDIT-2026-06-19 FIX (CRITICAL): the WFP kill switch was effectively dead.
/// `enable_killswitch` — the ONLY setter of `KILLSWITCH_ENABLED` and the only
/// caller of `wfp::initialize` — is registered as an IPC command (main.rs) but
/// was never invoked by the frontend or at startup. So `KILLSWITCH_ENABLED`
/// stayed `false` for the whole session and `activate_killswitch()` (called by
/// the auto-reconnect health loop on a drop) short-circuited to `Ok(false)`,
/// installing NO block-all filters. On an unexpected tunnel drop the OS routing
/// table fell back to the physical adapter and IPv4 traffic egressed in the
/// clear — while the UI promised an always-on kill switch.
///
/// This arms the INTENT and initializes the WFP engine as part of the connect
/// lifecycle, so the existing reactive protection actually engages. It does NOT
/// install the block-all filters itself: the auto-reconnect health loop owns the
/// activate/deactivate transitions (it deactivates while healthy-Connected and
/// activates during a drop/reconnect gap), so arming here must not fight that
/// state machine.
///
/// Best-effort: a non-elevated host (should not happen — the app manifest
/// requires administrator) logs and returns `Ok(false)` rather than failing the
/// whole connection.
pub async fn arm(app: &AppHandle) -> Result<bool, String> {
    // Respect the user's kill-switch preference (default ON). Reading it here —
    // the single choke-point every connect path funnels through — keeps all call
    // sites consistent. Fail SAFE: if settings can't be read, treat as enabled.
    let enabled = crate::commands::settings::load_settings_sync(app)
        .map(|s| s.killswitch_enabled)
        .unwrap_or(true);
    if !enabled {
        tracing::info!("Kill switch disabled by user preference — not arming");
        return Ok(false);
    }

    if !is_elevated() {
        tracing::warn!("Kill switch NOT armed: insufficient privileges (admin/root required)");
        return Ok(false);
    }

    #[cfg(target_os = "windows")]
    {
        wfp::initialize()
            .await
            .map_err(|e| format!("Failed to initialize kill-switch firewall: {}", e))?;
    }

    KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);

    // LOCKDOWN (always-on) mode: activate the block-all NOW and keep it on for
    // the whole session, so there is ZERO reactive detection window. (Reactive
    // mode — the default — leaves the block off in steady state and only
    // activates during a reconnect gap.) The tunnel is already up by the time
    // arm() runs on the connect path, so its interface LUID is published and
    // activate_blocking can permit tunneled traffic; if it cannot, it fails
    // loudly rather than blocking the user's own traffic.
    #[cfg(target_os = "windows")]
    if wfp::is_lockdown_mode() {
        if let Err(e) = activate_killswitch().await {
            // Lockdown could not install the always-on block-all (e.g. the tunnel
            // interface LUID was not published yet, so activate_blocking refused
            // rather than block the user's own traffic). DON'T disable protection
            // entirely — that would leave a later drop fully unprotected, which is
            // worse than reactive. Degrade to the reactive kill switch (block-all
            // installed on drop; it does not need the tunnel LUID) for this
            // session. KILLSWITCH_ENABLED stays true; set_lockdown_mode is an
            // in-memory session flag, so the user's saved preference is untouched.
            tracing::warn!(
                "Lockdown activation failed ({}); falling back to reactive kill switch for this session",
                e
            );
            wfp::set_lockdown_mode(false);
            return Ok(false);
        }
        tracing::info!("Kill switch armed in LOCKDOWN (always-on) mode");
        return Ok(true);
    }

    tracing::info!("Kill switch armed for active session (reactive)");
    Ok(true)
}

/// Disarm the kill switch when the user ends the session: clear the intent flag
/// and remove all firewall filters so connectivity is fully restored.
///
/// Always safe to call (no-op if never armed). MUST be called from the
/// user-initiated disconnect path so disconnecting can never strand the machine
/// behind an active block-all filter set.
pub async fn disarm() -> Result<(), String> {
    KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = wfp::cleanup().await {
            tracing::warn!("Failed to clean up WFP filters on disarm: {}", e);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = pf_deactivate_blocking().await {
            tracing::warn!("Failed to remove pf rules on disarm: {}", e);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = firewall_linux::deactivate_blocking().await {
            tracing::warn!("Failed to remove iptables rules on disarm: {}", e);
        }
    }

    tracing::info!("Kill switch disarmed");
    Ok(())
}

// ──────────────────────────────────────────────────────────────
// macOS pf (packet filter) kill switch implementation
// ──────────────────────────────────────────────────────────────

/// Tracks whether pf blocking rules are active on macOS
#[cfg(target_os = "macos")]
static PF_BLOCKING: AtomicBool = AtomicBool::new(false);

/// Anchor name for Birdo VPN pf rules
#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "com.birdo.vpn.killswitch";

/// Activate pf blocking: block all traffic except to the VPN server and localhost.
#[cfg(target_os = "macos")]
async fn pf_activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    use std::io::Write;

    let server_rule = if let Some(ip) = server_ip {
        format!("pass out quick proto udp to {} no state\n", ip)
    } else {
        String::new()
    };

    // Build pf rules for the anchor
    let rules = format!(
        "# Birdo VPN Kill Switch\n\
         block drop all\n\
         pass on lo0 all\n\
         pass out quick proto udp to any port 67 no state\n\
         pass in quick proto udp from any port 68 no state\n\
         {server_rule}"
    );

    // Pipe rules directly to pfctl via stdin — avoids TOCTOU race and world-readable temp file
    let mut child = crate::utils::hidden_cmd("pfctl")
        .args(["-a", PF_ANCHOR, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("pfctl spawn failed: {}", e))?;

    match child.stdin.take() {
        Some(mut stdin) => {
            stdin
                .write_all(rules.as_bytes())
                .map_err(|e| format!("Failed to write pf rules to stdin: {}", e))?;
            // Explicitly close stdin to signal EOF to pfctl before waiting
            drop(stdin);
        }
        None => {
            // stdin was unavailable: rules can never be loaded, so do not
            // claim the kill switch is active. Kill the child and fail loudly.
            let _ = child.kill();
            return Err("pfctl stdin unavailable; pf rules not loaded".to_string());
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("pfctl wait failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pfctl load anchor failed: {}", stderr));
    }

    // Enable pf if not already enabled
    let _ = crate::utils::hidden_cmd("pfctl").args(["-e"]).output();

    PF_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("macOS pf kill switch activated");
    Ok(())
}

/// Deactivate pf blocking: flush the Birdo anchor rules.
#[cfg(target_os = "macos")]
async fn pf_deactivate_blocking() -> Result<(), String> {
    // Flush the anchor
    let output = crate::utils::hidden_cmd("pfctl")
        .args(["-a", PF_ANCHOR, "-F", "all"])
        .output()
        .map_err(|e| format!("pfctl flush failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("pfctl flush anchor: {}", stderr);
    }

    PF_BLOCKING.store(false, Ordering::SeqCst);
    tracing::info!("macOS pf kill switch deactivated");
    Ok(())
}
