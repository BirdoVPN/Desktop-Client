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

use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::utils::elevation::is_elevated;
#[cfg(target_os = "linux")]
use crate::vpn::firewall_linux;
#[cfg(target_os = "macos")]
use crate::vpn::pf_policy::{self, Pf};
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

// DEAD-CODE SWEEP (P1-dk-dead-privileged-ipc-commands): `enable_killswitch` and
// `disable_killswitch` were registered IPC commands that no frontend code ever
// invoked (only the IPC-contract test listed them). They widened the
// renderer-reachable firewall-mutating surface for no functional reason —
// `enable_killswitch` even set KILLSWITCH_ENABLED without going through `arm()`,
// diverging from the persisted preference — so both were removed. The kill
// switch is driven by `arm()`/`disarm()` on the connect lifecycle and by
// `set_killswitch_live` from the settings screen.

type BlockingObserver = Box<dyn Fn() + Send + Sync>;

static BLOCKING_OBSERVER: std::sync::OnceLock<BlockingObserver> = std::sync::OnceLock::new();

/// Register what runs after the block-all may have engaged or released, so
/// the published VPN status (`kill_switch_blocking`) follows it even when the
/// connection state does not change — a Settings toggle during an error, the
/// give-up releasing the block (IPC contract v2, §1). Wired to
/// `VpnManager::refresh_status` at start-up; the first registration wins.
pub fn set_blocking_observer(observer: impl Fn() + Send + Sync + 'static) {
    let _ = BLOCKING_OBSERVER.set(Box::new(observer));
}

fn blocking_may_have_changed() {
    if let Some(observer) = BLOCKING_OBSERVER.get() {
        observer();
    }
}

/// Is the platform block-all engaged right now (WFP / pf / iptables)?
pub fn platform_is_blocking() -> bool {
    #[cfg(target_os = "windows")]
    {
        wfp::is_blocking()
    }
    #[cfg(target_os = "macos")]
    {
        PF_BLOCKING.load(Ordering::SeqCst)
    }
    #[cfg(target_os = "linux")]
    {
        firewall_linux::is_blocking()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

/// Activate the kill switch (block all non-VPN traffic).
///
/// DT-7: Not a Tauri IPC command — called internally by the auto-reconnect
/// service when the VPN drops unexpectedly. Kept as a plain async fn to shrink
/// the IPC attack surface (the frontend never invoked it).
pub async fn activate_killswitch() -> Result<bool, String> {
    let result = activate_platform_block().await;
    blocking_may_have_changed();
    result
}

async fn activate_platform_block() -> Result<bool, String> {
    if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
        return Ok(false);
    }

    tracing::warn!("Activating kill switch - blocking all non-VPN traffic");

    // Windows: the relay permit (address, port and transport — W1-013) was
    // handed to wfp by `session::apply_relay_permit` (`move_relay`).
    #[cfg(target_os = "windows")]
    {
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

/// Windows: point the block's relay permit at `relay` and, with `engage`, put
/// the block-all up for a rebuild — one WFP transaction (REVIEW-WIN2-001, see
/// `wfp::move_relay`). `engage` honours the user's kill-switch preference like
/// [`activate_killswitch`]; a block already in force is rebuilt whatever it.
#[cfg(target_os = "windows")]
pub(crate) async fn move_relay(
    relay: crate::vpn::wfp_policy::Relay,
    engage: bool,
) -> Result<(), String> {
    let result = wfp::move_relay(relay, engage && KILLSWITCH_ENABLED.load(Ordering::SeqCst)).await;
    blocking_may_have_changed();
    result
}

/// Deactivate the kill switch (restore normal traffic).
///
/// DT-7: Not a Tauri IPC command — called internally by the auto-reconnect
/// service when the VPN reconnects. Kept as a plain async fn (the frontend
/// never invoked it).
pub async fn deactivate_killswitch() -> Result<bool, String> {
    let result = deactivate_platform_block().await;
    blocking_may_have_changed();
    result
}

async fn deactivate_platform_block() -> Result<bool, String> {
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
) -> Result<bool, IpcError> {
    let state = vpn_manager.get_state().await;
    let active = state.is_tunnel_active() || state.can_disconnect();
    if !active {
        tracing::debug!("set_killswitch_live: no active session — applies at next connect");
        return Ok(false);
    }

    if enabled {
        // arm() re-reads the (already-persisted) preference and initializes WFP,
        // engaging the reactive protection for the live session.
        arm(&app)
            .await
            .map_err(|e| IpcError::new(IpcErrorCode::KillswitchFailed, e))
    } else {
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);

        // F-018: lift any block that is currently up, on EVERY platform. This
        // branch used to be `#[cfg(windows)]`-only, so on macOS/Linux turning the
        // kill switch off while the tunnel was Reconnecting/Error (i.e. with the
        // reactive block installed) cleared the intent flag but left the firewall
        // block in place — the machine stayed fully firewalled off until the
        // tunnel recovered, the retry budget ran out, or the user hit Disconnect.
        //
        // On macOS this does NOT lift the F-001 IPv6 leak block: that block is
        // owned by the tunnel session, not the kill switch, so `deactivate` falls
        // back to it rather than to `/etc/pf.conf`.
        if platform_is_blocking() {
            let _ = deactivate_killswitch().await;
        }

        tracing::info!("Kill switch softened live for the active session (intent cleared)");
        Ok(true)
    }
}

/// Get kill switch status
/// SEC-C3 FIX: Active state now reads from wfp.rs (single source of truth)
#[tauri::command]
pub async fn get_killswitch_status() -> Result<KillSwitchStatus, IpcError> {
    let enabled = is_enabled();
    let active = platform_is_blocking();

    // blocking_connections is deprecated, always 0
    let blocking_connections = 0u32;

    Ok(KillSwitchStatus {
        enabled,
        active,
        blocking_connections,
    })
}

/// Set the allowed VPN server IP (called when connecting)
/// Whether the user has Local Network Sharing on, mirrored here so the firewall
/// backends can honour it.
///
/// The kill switch had no idea this setting existed: LAN sharing was implemented
/// as ROUTING only, so when the block engaged, printers, NAS, Chromecast and SSH
/// went dark despite the toggle being on — and the toggle is not platform-gated
/// in the UI. Windows treats LAN sharing as two halves (routes AND firewall
/// permits); the Unix backends only ever had the first.
///
/// A global rather than a parameter because activate_killswitch() is reached
/// from the auto-reconnect loop with no AppHandle to read settings through — the
/// same reason VPN_SERVER_IP is a global.
static LAN_SHARING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Record the current Local Network Sharing preference for the firewall backends.
pub fn set_lan_sharing(enabled: bool) {
    LAN_SHARING_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Whether LAN traffic should be permitted through an active block.
///
/// Only the pf (macOS) and iptables (Linux) backends consult this. Windows
/// carries the same preference through `wfp::set_local_network_sharing`, so this
/// getter genuinely has no caller there — cfg-gated rather than
/// `#[allow(dead_code)]`, so it stays a real dead-code signal if a future caller
/// disappears.
#[cfg(not(target_os = "windows"))]
pub fn lan_sharing_enabled() -> bool {
    LAN_SHARING_ENABLED.load(Ordering::SeqCst)
}
pub async fn set_vpn_server_ip(ip: Option<Ipv4Addr>) {
    *VPN_SERVER_IP.write().await = ip;
    // This is the real exit-node address (set from vpn.rs and vpn_multi_hop.rs),
    // not a local proxy. Log only whether one is set -- the value itself is the
    // record of which server a customer chose.
    tracing::debug!(
        "Kill switch VPN server IP {}",
        if ip.is_some() { "set" } else { "cleared" }
    );
}

/// Check if kill switch is currently enabled
pub fn is_enabled() -> bool {
    KILLSWITCH_ENABLED.load(Ordering::SeqCst)
}

/// Whether the kill switch is in lockdown (always-on) mode. Cross-platform
/// accessor used by the auto-reconnect loop's GIVE-UP and offline-pause-cap
/// branches: lockdown (ON by default on Windows, switchable in Settings) is
/// the mode that keeps traffic blocked even when the session is over — for as
/// long as the app keeps running. Hard false off-Windows — the Unix
/// steady-state block (see [`holds_block_while_connected`]) is NOT lockdown
/// and must never inherit lockdown's keep-blocked-after-give-up semantics,
/// or a Unix user would be stranded behind the firewall.
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

/// Whether the platform keeps the block-all ENGAGED for the whole Connected
/// session (P1-ks-reactive-detection-window).
///
/// Gates only the "deactivate now that we are healthy" sites (auto-reconnect's
/// Connected arm, release_switch_guard, the reapply release): where this is
/// true, a healthy tunnel keeps the block and carries its traffic through the
/// tunnel-interface permits (pf utun pass rules / iptables `-o birdo0 ACCEPT`
/// / WFP tunnel-LUID permit), so a SILENT tunnel death leaks nothing while
/// the liveness watchdog needs up to ~60s to notice and reconnect.
///
/// - Windows: lockdown mode only. Lockdown is the Windows DEFAULT (the
///   `lockdown_mode` setting defaults ON, desktop #34); a user who switches
///   "Always-on kill switch" off in Settings gets the reactive mode (D-21).
/// - macOS/Linux: always, whenever the kill switch is armed. There is no
///   lockdown flag off-Windows, and a reactive-only kill switch on those
///   platforms is exactly the finding's ~60s real-IP leak window.
///
/// This must NEVER gate the escape hatches — disconnect_vpn → disarm(),
/// set_killswitch_live(false), the give-up branches and the offline-pause cap
/// (those use [`is_lockdown_mode`]) — so it cannot strand anyone.
pub fn holds_block_while_connected() -> bool {
    #[cfg(target_os = "windows")]
    {
        wfp::is_lockdown_mode()
    }
    #[cfg(not(target_os = "windows"))]
    {
        is_enabled()
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
/// lifecycle, so the existing reactive protection actually engages. On Windows
/// (outside lockdown) it does NOT install the block-all filters itself: the
/// auto-reconnect health loop owns the activate/deactivate transitions (it
/// deactivates while healthy-Connected and activates during a drop/reconnect
/// gap), so arming here must not fight that state machine. On macOS/Linux it
/// DOES activate the block immediately and the loop keeps it engaged for the
/// whole session — see [`holds_block_while_connected`].
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
    arm_with_preference(enabled).await
}

/// [`arm`] after the preference has been read — split out so the
/// preference-OFF branch is unit-testable without an `AppHandle`.
async fn arm_with_preference(enabled: bool) -> Result<bool, String> {
    if !enabled {
        // F3: the OFF preference must also CLEAR the intent flag, not merely
        // skip arming. The stale-flag path (auto_reconnect.rs never calls
        // arm() — its only callers are connect_vpn_attempt in vpn.rs and
        // vpn_multi_hop.rs):
        //   1. a session arms (flag true); the tunnel drops and the reactive
        //      block goes up; auto-reconnect exhausts its budget and the
        //      give-up branch (auto_reconnect.rs, "Max attempts reached")
        //      calls deactivate_killswitch() — which lifts the block but never
        //      touches KILLSWITCH_ENABLED — and the state goes Disconnected;
        //   2. the user turns the kill switch OFF while Disconnected: that is
        //      persisted only (set_killswitch_live no-ops without a session),
        //      so the flag is still true from step 1;
        //   3. the next USER connect runs arm() -> this branch with the
        //      persisted preference false; before this fix it returned early
        //      and left the flag set, so the next drop's activate_killswitch()
        //      blocked against the preference — and on macOS/Linux
        //      `holds_block_while_connected()` (== `is_enabled()`) stayed true,
        //      so the "healthy again, lift the block" sites in
        //      auto_reconnect.rs / vpn.rs kept the block-all engaged for the
        //      rest of the session.
        // Clearing it here makes the preference the source of truth on every
        // connect, whichever path armed the previous session.
        if KILLSWITCH_ENABLED.swap(false, Ordering::SeqCst) {
            tracing::info!(
                "Kill switch disabled by user preference — not arming (cleared a stale armed intent from the previous session)"
            );
        } else {
            tracing::info!("Kill switch disabled by user preference — not arming");
        }
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

    // STEADY-STATE BLOCK (macOS/Linux) — P1-ks-reactive-detection-window:
    // activate the block-all NOW and keep it engaged for the whole Connected
    // session. The tunnel is already up when arm() runs on the connect path,
    // and all the firewall backends permit tunneled traffic through an engaged
    // block (pf's pass rule on the tunnel's own utun, iptables `-o birdo0
    // ACCEPT`), which the switch-guard/reapply paths already rely on
    // mid-session. Reactive-only protection left every SILENT tunnel death
    // (dead peer, expired NAT mapping, sleep/resume, Wi-Fi→LTE handover)
    // leaking real-IP traffic — DNS included — for the up-to-~60s the
    // liveness watchdog needs to trip.
    // With the block held, a dead tunnel fails CLOSED instantly and the
    // watchdog/auto-reconnect still own recovery.
    //
    // Not a third mechanism: the escape hatches stay exactly the disarm-on-
    // quit / disconnect_vpn → disarm() / set_killswitch_live(false) /
    // give-up + offline-pause-cap paths, all of which release the block —
    // is_lockdown_mode() stays hard false here, so none of lockdown's
    // keep-blocked-after-give-up semantics apply.
    #[cfg(not(target_os = "windows"))]
    {
        if let Err(e) = activate_killswitch().await {
            // Degrade to reactive rather than failing the connect: the block
            // still engages on a drop, this session just keeps the detection
            // window open. KILLSWITCH_ENABLED stays true.
            tracing::warn!(
                "Steady-state block activation failed ({}); falling back to reactive kill switch for this session",
                e
            );
            return Ok(false);
        }
        tracing::info!(
            "Kill switch armed with the steady-state block engaged (always-on while connected)"
        );
        Ok(true)
    }

    #[cfg(target_os = "windows")]
    {
        tracing::info!("Kill switch armed for active session (reactive)");
        Ok(true)
    }
}

/// Disarm the kill switch when the user ends the session: clear the intent flag
/// and remove all firewall filters so connectivity is fully restored.
///
/// Always safe to call (no-op if never armed). MUST be called from the
/// user-initiated disconnect path so disconnecting can never strand the machine
/// behind an active block-all filter set.
pub async fn disarm() -> Result<(), String> {
    let result = disarm_platform().await;
    blocking_may_have_changed();
    result
}

async fn disarm_platform() -> Result<(), String> {
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
//
// WHAT the block-all permits, and when pf's answer counts as "blocking", is
// decided in `vpn::pf_policy`: plain functions, unit-tested on every OS. This
// section runs `pfctl` and records what pf reads back.
// ──────────────────────────────────────────────────────────────

/// Whether pf's block-all is in force on macOS — pf's READ-BACK answer (pf
/// enabled AND the block-all loaded), never the fact of having asked.
#[cfg(target_os = "macos")]
static PF_BLOCKING: AtomicBool = AtomicBool::new(false);

/// Serialises every writer of pf's main ruleset — the block-all, the IPv6
/// baseline, a tunnel interface change — so each read-back describes its own
/// load, and two loads built from different inputs cannot interleave.
#[cfg(target_os = "macos")]
static PF_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// MR-1125: the utun the live tunnel runs on, the ONLY interface the block-all
/// permits. Set by tunnel_macos.rs as soon as it creates the device
/// ([`tunnel_interface_up`]), cleared when the device goes.
#[cfg(target_os = "macos")]
static PF_TUNNEL_INTERFACE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// macOS: is the pf block-all ruleset currently loaded? Twin of
/// `wfp::is_blocking()` / `firewall_linux::is_blocking()`, needed by the
/// connect paths' update-the-relay-permit step: pf bakes the permitted server
/// IP into the loaded ruleset and has no incremental update, so a switch onto
/// a different relay while a block is engaged must re-load the ruleset.
#[cfg(target_os = "macos")]
pub fn pf_blocking_active() -> bool {
    PF_BLOCKING.load(Ordering::SeqCst)
}

/// True when WE enabled pf (it was disabled before us). Governs whether
/// deactivation should `pfctl -d` — we must never disable pf if the user or
/// another tool had it running.
#[cfg(target_os = "macos")]
static PF_WE_ENABLED: AtomicBool = AtomicBool::new(false);

/// F-001: true while a tunnel session wants the steady-state IPv6 leak block as
/// pf's BASELINE ruleset. This is what makes the leak block survive a kill-switch
/// cycle: `pf_deactivate_blocking()` consults it and restores the leak block
/// instead of bare `/etc/pf.conf`.
#[cfg(target_os = "macos")]
static PF_IPV6_BLOCK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Is pf currently enabled? Parses `pfctl -s info` ("Status: Enabled").
#[cfg(target_os = "macos")]
fn pf_is_enabled() -> bool {
    crate::utils::hidden_cmd("pfctl")
        .args(["-s", "info"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: Enabled"))
        .unwrap_or(false)
}

/// `pfctl -e`. A non-zero exit is an error too; it used to be ignored
/// (P1-ks-macos-pf-enable-unverified). Callers read back whether pf is
/// running rather than trust either answer.
#[cfg(target_os = "macos")]
fn pf_enable() -> Result<(), String> {
    let out = crate::utils::hidden_cmd("pfctl")
        .args(["-e"])
        .output()
        .map_err(|e| format!("pfctl -e spawn failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "pfctl -e failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// `pfctl`, as the [`Pf`] that `pf_policy`'s engage/disengage sequencing drives.
#[cfg(target_os = "macos")]
struct Pfctl;

#[cfg(target_os = "macos")]
impl Pf for Pfctl {
    fn is_enabled(&self) -> bool {
        pf_is_enabled()
    }
    fn load(&self, rules: &str) -> Result<(), String> {
        pf_load_ruleset(rules)
    }
    fn enable(&self) -> Result<(), String> {
        pf_enable()
    }
    fn live_rules(&self) -> String {
        pf_live_rules()
    }
}

// ──────────────────────────────────────────────────────────────
// F-001 (P0): macOS steady-state IPv6 leak block
//
// The relay fleet is IPv4-only, and `tunnel_macos.rs` neither routes nor blocks
// IPv6 — so on a dual-stack network every IPv6-capable app egressed via the
// physical NIC's untouched IPv6 default route for the whole "Connected" session
// (real address + geolocation exposed, no UI signal). The reactive kill switch
// could never cover it: an IPv6 leak does not drop the IPv4 tunnel, so it never
// trips, and it is torn down in steady state anyway.
//
// WHY THIS LIVES IN killswitch.rs: on macOS pf's MAIN RULESET is the only thing
// evaluated (a named anchor is inert unless `/etc/pf.conf` references it — see
// `pf_activate_blocking`'s note, the bug #59 had to fix). The kill switch owns
// the main ruleset. Two independent writers would clobber each other: the leak
// block would be silently wiped the first time `pf_deactivate_blocking()` ran
// after a reconnect, restoring the leak mid-session. So there is ONE owner and
// a two-level baseline:
//
//   kill switch blocking   → block-all ruleset (denies IPv6 as a side effect)
//   tunnel up, no block    → IPv6 leak-block ruleset   ← the baseline
//   no tunnel              → /etc/pf.conf
// ──────────────────────────────────────────────────────────────

/// The leak-block rulesets live in `resources/pf/` rather than in this source
/// file, so that CI can parse-check the EXACT bytes we ship with `pfctl -n -f` on
/// a real macOS runner (see .github/workflows/tests.yml). A pf syntax error here
/// would fail every macOS connect, and it is not otherwise reachable from a
/// Windows dev box — this is the one thing about F-001 that can be verified
/// without a dual-stack network.
///
/// Preferred ruleset: re-declares the stock `/etc/pf.conf` anchors so Apple's own
/// pf rules (application firewall / Internet Sharing) keep working for the
/// session, then appends our IPv6 block.
#[cfg(target_os = "macos")]
const PF_IPV6_RULESET_FULL: &str = include_str!("../../resources/pf/ipv6-block.conf");

/// Fallback for hosts where the stock Apple anchor file is missing or unreadable
/// (the `load anchor` line would fail the whole load). Same protection, minus the
/// Apple anchors for the session.
#[cfg(target_os = "macos")]
const PF_IPV6_RULESET_MINIMAL: &str = include_str!("../../resources/pf/ipv6-block-minimal.conf");

/// Load `rules` as pf's main ruleset via `pfctl -f -`.
///
/// Piping through stdin (rather than a temp file) avoids both a TOCTOU race and
/// a world-readable file. Shared by the kill switch and the IPv6 leak block so
/// there is exactly one code path that writes pf's main ruleset.
#[cfg(target_os = "macos")]
fn pf_load_ruleset(rules: &str) -> Result<(), String> {
    use std::io::Write;

    let mut child = crate::utils::hidden_cmd("pfctl")
        .args(["-f", "-"])
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
            // stdin was unavailable: rules can never be loaded, so do not claim
            // the ruleset is active. Kill the child and fail loudly.
            let _ = child.kill();
            return Err("pfctl stdin unavailable; pf rules not loaded".to_string());
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("pfctl wait failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "pfctl load ruleset failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Read back pf's live ruleset. Used to verify a block is genuinely in force
/// rather than trusting `pfctl`'s exit status alone.
#[cfg(target_os = "macos")]
fn pf_live_rules() -> String {
    crate::utils::hidden_cmd("pfctl")
        .args(["-s", "rules"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Install the IPv6 leak-block ruleset as pf's main ruleset and enable pf.
///
/// Tries the anchor-preserving ruleset first, falls back to the minimal one, then
/// VERIFIES the result — a leak fix that silently failed to load is worse than no
/// fix, because the UI would report protection that isn't there.
#[cfg(target_os = "macos")]
fn pf_apply_ipv6_baseline() -> Result<(), String> {
    let was_enabled = pf_is_enabled();

    if let Err(primary) = pf_load_ruleset(PF_IPV6_RULESET_FULL) {
        tracing::warn!(
            "F-001: anchor-preserving IPv6 ruleset failed to load ({}); trying the minimal ruleset",
            primary
        );
        pf_load_ruleset(PF_IPV6_RULESET_MINIMAL).map_err(|e| {
            format!("IPv6 leak block failed to load ({primary}); fallback also failed: {e}")
        })?;
    }

    // pf must actually be running or the loaded ruleset is inert — so read it
    // back rather than trust `pfctl -e`, whose exit status was ignored here too
    // (P1-ks-macos-pf-enable-unverified).
    if !was_enabled {
        if let Err(e) = pf_enable() {
            tracing::warn!("F-001: {e}; reading back whether pf is running");
        }
    }
    let enabled = pf_is_enabled();
    if !was_enabled && enabled {
        PF_WE_ENABLED.store(true, Ordering::SeqCst);
    }
    if !enabled {
        return Err("IPv6 leak block is not enforced: pf is not enabled".to_string());
    }

    // Read back: our ruleset always contains inet6 rules. If pf reports none, the
    // load did not take effect and we must NOT claim the leak is blocked.
    if !pf_live_rules().contains("inet6") {
        return Err("IPv6 leak block did not take effect (pf reports no inet6 rules)".to_string());
    }

    tracing::info!("F-001: IPv6 egress blocked for the connect window (pf main ruleset)");
    Ok(())
}

/// Restore pf to the system default ruleset and, if we were the ones who turned
/// pf on, turn it back off.
#[cfg(target_os = "macos")]
fn pf_restore_default_ruleset() {
    let output = crate::utils::hidden_cmd("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .output();
    match output {
        Ok(o) if !o.status.success() => {
            tracing::warn!(
                "pfctl restore /etc/pf.conf: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => tracing::warn!("pfctl restore failed: {}", e),
        _ => {}
    }

    // Only disable pf if we enabled it (never disable pf out from under the user
    // or another tool that had it running). The debt is cleared once pf is
    // observed OFF, not when `pfctl -d` was merely asked: a `-d` that failed
    // with the block-all still loaded must be retried by the next lift.
    if PF_WE_ENABLED.load(Ordering::SeqCst) {
        let _ = crate::utils::hidden_cmd("pfctl").args(["-d"]).output();
        if pf_is_enabled() {
            tracing::warn!("pfctl -d left pf running; the next teardown retries");
        } else {
            PF_WE_ENABLED.store(false, Ordering::SeqCst);
        }
    }
}

/// F-001: engage the steady-state IPv6 leak block for a tunnel session.
///
/// Called from `tunnel_macos.rs::start()`, INDEPENDENT of the kill-switch
/// enabled/lockdown setting — exactly as Windows blocks IPv6 at tunnel start.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_activate() -> Result<(), String> {
    let _pf = PF_LOCK.lock().await;

    // Record the intent FIRST so that, if the kill switch is mid-block, its
    // deactivation lands on our baseline instead of bare /etc/pf.conf.
    PF_IPV6_BLOCK_ACTIVE.store(true, Ordering::SeqCst);

    if PF_BLOCKING.load(Ordering::SeqCst) {
        tracing::info!(
            "F-001: kill-switch block-all is active and already denies IPv6; \
             leak block recorded as the pf baseline"
        );
        return Ok(());
    }

    pf_apply_ipv6_baseline().inspect_err(|_| {
        // Do not leave a claim we could not honour.
        PF_IPV6_BLOCK_ACTIVE.store(false, Ordering::SeqCst);
    })
}

/// F-001: lift the steady-state IPv6 leak block at teardown.
///
/// Best-effort and always safe to call (no-op if never engaged), so it can never
/// fail a disconnect — a stuck block would leave the host without IPv6.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_deactivate() {
    let _pf = PF_LOCK.lock().await;

    if !PF_IPV6_BLOCK_ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }

    if PF_BLOCKING.load(Ordering::SeqCst) {
        // The kill switch owns the ruleset right now. The baseline flag is now
        // clear, so its own deactivation will restore /etc/pf.conf.
        tracing::info!("F-001: leak block released; kill switch still owns the pf ruleset");
        return;
    }

    pf_restore_default_ruleset();
    tracing::info!("F-001: IPv6 egress block removed");
}

/// F-001: remove a leak-block / kill-switch ruleset left behind by a crash.
///
/// pf rules loaded with `pfctl -f` live in the kernel and survive process exit —
/// unlike Windows WFP dynamic sessions, which self-clean. Without this, a panic
/// or SIGKILL while blocking leaves the machine either without IPv6 or (worse,
/// if the kill switch was mid-block) fully firewalled off, with no recovery short
/// of a reboot. Only reverts rulesets carrying OUR marker anchor, so a third
/// party's pf configuration is never clobbered.
#[cfg(target_os = "macos")]
pub fn reconcile_stale_pf_state() {
    if !pf_is_enabled() {
        return;
    }
    if !pf_live_rules().contains(pf_policy::MARKER_ANCHOR) {
        return; // not ours — leave it alone
    }
    tracing::warn!("Found a stale Birdo pf ruleset from a previous run — restoring /etc/pf.conf");
    let _ = crate::utils::hidden_cmd("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .output();

    // OBSERVE the result — do not infer it from having asked.
    //
    // This used to store `false` unconditionally. If the restore failed (an
    // unreadable /etc/pf.conf, pfctl missing, not root) the kernel kept OUR
    // block-all ruleset loaded while the app recorded "not blocking" — so the
    // user had no network at all, the UI said the kill switch was off, and
    // nothing ever retried, because every recovery path is gated on
    // PF_BLOCKING. A reboot was the only way out, which is the exact failure
    // this function exists to prevent.
    //
    // The marker anchor is the ground truth: still present means still blocking.
    if pf_live_rules().contains(pf_policy::MARKER_ANCHOR) {
        tracing::error!(
            "Failed to restore /etc/pf.conf — the stale Birdo ruleset is STILL LOADED and this \
             machine's traffic remains blocked. Leaving the kill switch marked active so the \
             normal teardown path can retry; `sudo pfctl -f /etc/pf.conf` clears it manually."
        );
        PF_BLOCKING.store(true, Ordering::SeqCst);
        return;
    }

    PF_BLOCKING.store(false, Ordering::SeqCst);
    PF_IPV6_BLOCK_ACTIVE.store(false, Ordering::SeqCst);
}

/// Activate pf blocking: block everything except what
/// `pf_policy::block_all_ruleset` permits (loopback, the tunnel's own utun,
/// DHCP, the LAN with Local Network Sharing, the control plane, the relay).
///
/// CRITICAL FIX: the rules are loaded as pf's **main ruleset** (`pfctl -f -`),
/// not into a named anchor. A named anchor is only evaluated when the main
/// ruleset contains a matching `anchor "..."` line, and macOS's default
/// `/etc/pf.conf` has no such line — so the previous anchor-only approach loaded
/// rules pf never evaluated, and the kill switch silently failed OPEN (all
/// traffic leaked while the UI reported it active). The main ruleset is always
/// evaluated. `pf_deactivate_blocking` restores `/etc/pf.conf`.
#[cfg(target_os = "macos")]
async fn pf_activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    let _pf = PF_LOCK.lock().await;
    pf_engage_block(server_ip)
}

/// [`pf_activate_blocking`]'s body, under PF_LOCK: build the block-all from the
/// inputs as they are NOW, load it, and record what pf reads back.
#[cfg(target_os = "macos")]
fn pf_engage_block(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    let tunnel_interface = recorded_tunnel_interface();
    let control_plane = pf_policy::control_plane_addresses();
    // pf has no application condition, so the control-plane permit matches the
    // euid we run as (root: arm() refuses otherwise) and pf_policy scopes its
    // DESTINATION to the control-plane table.
    let euid = unsafe { libc::geteuid() };
    let rules = pf_policy::block_all_ruleset(&pf_policy::BlockAll {
        relay: server_ip,
        tunnel_interface: tunnel_interface.as_deref(),
        control_plane: &control_plane,
        euid,
        lan_sharing: lan_sharing_enabled(),
    });
    tracing::info!(
        "Kill switch: tunnel permit on {}; control-plane permit for uid {} on tcp/443 to {} addresses",
        tunnel_interface.as_deref().unwrap_or("no interface (no tunnel yet)"),
        euid,
        control_plane.len()
    );

    let engaged = pf_policy::engage(&Pfctl, &rules);
    if engaged.we_enabled {
        PF_WE_ENABLED.store(true, Ordering::SeqCst);
    }
    PF_BLOCKING.store(engaged.blocking, Ordering::SeqCst);
    match &engaged.result {
        Ok(()) => {
            tracing::info!(
                "macOS pf kill switch activated (read back: pf enabled, block-all loaded)"
            )
        }
        Err(e) => tracing::error!(
            "macOS pf kill switch NOT confirmed: {} (blocking={})",
            e,
            engaged.blocking
        ),
    }
    engaged.result
}

/// The utun the block-all permits right now (MR-1125).
#[cfg(target_os = "macos")]
fn recorded_tunnel_interface() -> Option<String> {
    PF_TUNNEL_INTERFACE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// macOS: the tunnel now runs on `name` (MR-1125).
///
/// The block-all permits the tunnel by interface NAME, and that one only. A
/// reconnect or a settings reapply engages the block BEFORE the new device
/// exists, so the name is recorded here, the moment `create_utun_device`
/// returns it, and an engaged block is re-loaded at once to let it through.
/// Until then the block has no tunnel permit at all, which is fail-closed.
#[cfg(target_os = "macos")]
pub async fn tunnel_interface_up(name: &str) {
    {
        let mut recorded = PF_TUNNEL_INTERFACE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if recorded.as_deref() == Some(name) {
            return;
        }
        *recorded = Some(name.to_string());
    }
    reload_block_if_engaged("the tunnel's new interface").await;
}

/// macOS: the tunnel's device on `name` is gone (its fd closed). Drop its
/// permit from an engaged block, or the next owner of the same unit — another
/// VPN — would pass straight through the kill switch.
#[cfg(target_os = "macos")]
pub async fn tunnel_interface_down(name: &str) {
    if forget_tunnel_interface(name) {
        reload_block_if_engaged("the tunnel interface going away").await;
    }
}

/// Forget `name`, unless a newer tunnel has already been recorded. Synchronous
/// for the paths that cannot await (a failed start, `Drop`): they only forget,
/// and the next load — every re-dial loads — drops the permit.
#[cfg(target_os = "macos")]
pub fn forget_tunnel_interface(name: &str) -> bool {
    let mut recorded = PF_TUNNEL_INTERFACE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if recorded.as_deref() != Some(name) {
        return false;
    }
    *recorded = None;
    true
}

/// Re-load an ENGAGED block-all so it reflects the inputs as they are now. A
/// block that is not engaged is left alone: its next activation reads them.
#[cfg(target_os = "macos")]
async fn reload_block_if_engaged(why: &str) {
    let server_ip = *VPN_SERVER_IP.read().await;
    let result = {
        let _pf = PF_LOCK.lock().await;
        if !PF_BLOCKING.load(Ordering::SeqCst) {
            return;
        }
        pf_engage_block(server_ip)
    };
    if let Err(e) = result {
        tracing::warn!(
            "Kill switch: re-loading the block for {} failed: {}",
            why,
            e
        );
    }
    blocking_may_have_changed();
}

/// Deactivate pf blocking: drop the block-all main ruleset and fall back to the
/// correct baseline — the IPv6 leak block if a tunnel session is still live,
/// otherwise the system default ruleset (disabling pf only if we enabled it).
///
/// F-001: the fallback is not optional. This runs on every reconnect (the
/// auto-reconnect loop deactivates once the tunnel is healthy again). Restoring
/// bare `/etc/pf.conf` here would wipe the connect-window IPv6 block and silently
/// reopen the leak for the rest of the session.
#[cfg(target_os = "macos")]
async fn pf_deactivate_blocking() -> Result<(), String> {
    let _pf = PF_LOCK.lock().await;

    let keep_ipv6_block = PF_IPV6_BLOCK_ACTIVE.load(Ordering::SeqCst);
    let teardown = if keep_ipv6_block {
        // A failed baseline load leaves the block-all ruleset loaded. That is
        // both fail-safe and still usable: block-all permits lo0 and the
        // tunnel's utun, so a healthy tunnel keeps carrying the user's traffic.
        // Falling back to /etc/pf.conf here would restore the IPv6 leak instead.
        pf_apply_ipv6_baseline()
    } else {
        // Reload the default ruleset, dropping our block-all rules. This is the
        // correct inverse of loading a main ruleset (a per-anchor flush would
        // leave our main-ruleset block rules in place and keep blocking).
        pf_restore_default_ruleset();
        Ok(())
    };

    // OBSERVE the result — do not infer it from having asked
    // (P1-ks-macos-linux-deactivate-swallows-errors). This used to store
    // PF_BLOCKING = false as its FIRST statement, so a teardown that failed
    // left the kernel blocking while every later lift — all gated on the flag —
    // believed there was nothing left to lift.
    let (blocking, result) = pf_policy::disengaged(&Pfctl, teardown);
    PF_BLOCKING.store(blocking, Ordering::SeqCst);
    match &result {
        Ok(()) if keep_ipv6_block => {
            tracing::info!("macOS pf kill switch deactivated (IPv6 leak block retained)")
        }
        Ok(()) => tracing::info!("macOS pf kill switch deactivated"),
        Err(e) if blocking => tracing::error!(
            "macOS pf kill switch is STILL BLOCKING: {}. Left marked active so the next \
             lift retries; `sudo pfctl -f /etc/pf.conf` clears it manually.",
            e
        ),
        Err(e) => tracing::warn!(
            "macOS pf kill switch lifted, but its fallback ruleset did not apply cleanly: {}",
            e
        ),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F3: an OFF preference must clear a stale armed intent (left by the
    /// auto-reconnect give-up branch, which lifts the block but never clears
    /// the flag), or the next user connect's drop blocks against the
    /// preference and (Unix) `holds_block_while_connected()` keeps the
    /// block-all engaged for the rest of the session. Only this test touches
    /// `KILLSWITCH_ENABLED`, so it needs no serialisation against the others.
    #[tokio::test]
    async fn arm_with_preference_off_clears_stale_armed_intent() {
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        assert!(
            is_enabled(),
            "precondition: intent armed by a previous session"
        );

        let armed = arm_with_preference(false).await.unwrap();

        assert!(!armed, "preference OFF must not arm");
        assert!(
            !is_enabled(),
            "preference OFF must clear KILLSWITCH_ENABLED, or the steady-state block is held against the user's setting"
        );
        // Idempotent from the cleared state too.
        assert_eq!(arm_with_preference(false).await, Ok(false));
        assert!(!is_enabled());
    }
}
