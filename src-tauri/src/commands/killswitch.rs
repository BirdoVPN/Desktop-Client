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
use tauri::{AppHandle, State};

use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::utils::elevation::is_elevated;
#[cfg(target_os = "linux")]
use crate::vpn::firewall_linux;
#[cfg(target_os = "macos")]
use crate::vpn::pf_policy::{self, Pf, PfState};
#[cfg(target_os = "windows")]
use crate::vpn::wfp;

use crate::vpn::manager::VpnManager;

/// SEC-C3 FIX: KILLSWITCH_ENABLED is the single user-intent flag.
/// Active/blocking state is delegated entirely to wfp.rs.
static KILLSWITCH_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global state for kill switch - stores allowed VPN server IP. A plain
/// mutex, so the pf backend reads it under its own lock, synchronously, in the
/// same step that loads it (P3-3).
static VPN_SERVER_IP: std::sync::Mutex<Option<Ipv4Addr>> = std::sync::Mutex::new(None);

/// The relay the block permits.
#[cfg(not(target_os = "windows"))]
fn vpn_server_ip() -> Option<Ipv4Addr> {
    *VPN_SERVER_IP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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

    // macOS reads the relay AND re-checks the intent under its own lock
    // (P3-3): a set_killswitch_live(false) that landed while this waited for
    // the lock must not be undone by a block built from the earlier intent.
    #[cfg(target_os = "macos")]
    match pf_activate_blocking().await {
        Ok(true) => {}
        Ok(false) => return Ok(false),
        Err(e) => {
            tracing::error!("Failed to activate pf blocking: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    #[cfg(target_os = "linux")]
    {
        let server_ip = vpn_server_ip();
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
    *VPN_SERVER_IP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = ip;
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
// WHAT the block-all permits, when pf's answer counts as "blocking", and how a
// lift is verified are decided in `vpn::pf_policy` (`PfState`): plain code,
// unit-tested on every OS against a scripted pf. This section runs `pfctl`,
// holds the one lock, and mirrors the state for the lock-free status probe.
// ──────────────────────────────────────────────────────────────

/// Everything the kill switch knows about pf, behind the one lock every writer
/// of pf's main ruleset takes while the app runs: the block-all, the IPv6
/// baseline, a tunnel interface change. Two writers run without it, at times
/// when nothing else does: the startup reconcile and the panic hook in main.rs.
#[cfg(target_os = "macos")]
static PF: tokio::sync::Mutex<PfState> = tokio::sync::Mutex::const_new(PfState::new());

/// `PfState::enforcing` for the lock-free status probe: pf is running our
/// block-all, or cannot be read (which counts as still blocking).
#[cfg(target_os = "macos")]
static PF_BLOCKING: AtomicBool = AtomicBool::new(false);

/// `PfState::loaded`: a block-all of ours is (or may be) loaded — a lift is owed.
#[cfg(target_os = "macos")]
static PF_LOADED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
fn mirror(state: &PfState) {
    PF_BLOCKING.store(state.enforcing, Ordering::SeqCst);
    PF_LOADED.store(state.loaded, Ordering::SeqCst);
}

/// macOS: is a block-all of ours loaded? Twin of `wfp::is_blocking()` /
/// `firewall_linux::is_blocking()`, needed by the connect paths'
/// update-the-relay-permit step: pf bakes the permitted server IP into the
/// loaded ruleset and has no incremental update, so a switch onto a different
/// relay while a block is loaded must re-load the ruleset.
#[cfg(target_os = "macos")]
pub fn pf_blocking_active() -> bool {
    PF_LOADED.load(Ordering::SeqCst)
}

/// Run `pfctl` with `args`: its stdout, or why it failed — a non-zero exit
/// included. A read that fails is an error, never an empty answer (P2-2).
#[cfg(target_os = "macos")]
fn pfctl(args: &[&str]) -> Result<String, String> {
    let out = crate::utils::hidden_cmd("pfctl")
        .args(args)
        .output()
        .map_err(|e| format!("pfctl {} could not run: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "pfctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// `pfctl`, as the [`Pf`] that `PfState` drives.
#[cfg(target_os = "macos")]
struct Pfctl;

#[cfg(target_os = "macos")]
impl Pf for Pfctl {
    fn info(&self) -> Result<String, String> {
        pfctl(&["-s", "info"])
    }
    fn rules(&self) -> Result<String, String> {
        pfctl(&["-s", "rules"])
    }
    fn load(&self, rules: &str) -> Result<(), String> {
        pf_load_ruleset(rules)
    }
    fn load_default(&self) -> Result<(), String> {
        pfctl(&["-f", "/etc/pf.conf"]).map(drop)
    }
    fn flush_rules(&self) -> Result<(), String> {
        pfctl(&["-F", "rules"]).map(drop)
    }
    fn take_ref(&self) -> Result<u64, String> {
        let out = crate::utils::hidden_cmd("pfctl")
            .args(["-E"])
            .output()
            .map_err(|e| format!("pfctl -E could not run: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "pfctl -E failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        // The token is printed alongside "pf enabled"; read both streams.
        let printed = format!(
            "{}
{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        pf_policy::parse_token(&printed).ok_or_else(|| "pfctl -E printed no token".to_string())
    }
    fn release_ref(&self, token: u64) -> Result<(), String> {
        pfctl(&["-X", &token.to_string()]).map(drop)
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
// a two-level baseline (`PfState::disengage` picks it):
//
//   kill switch blocking   → block-all ruleset (denies IPv6 as a side effect)
//   tunnel up, no block    → IPv6 leak-block ruleset   ← the baseline
//   no tunnel              → /etc/pf.conf
// ──────────────────────────────────────────────────────────────

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

/// F-001: engage the steady-state IPv6 leak block for a tunnel session.
///
/// Called from `tunnel_macos.rs::start()`, INDEPENDENT of the kill-switch
/// enabled/lockdown setting — exactly as Windows blocks IPv6 at tunnel start.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_activate() -> Result<(), String> {
    let mut pf = PF.lock().await;
    let result = pf.ipv6_on(&Pfctl);
    mirror(&pf);
    if result.is_ok() {
        if pf.loaded {
            tracing::info!(
                "F-001: kill-switch block-all is active and already denies IPv6; \
                 leak block recorded as the pf baseline"
            );
        } else {
            tracing::info!("F-001: IPv6 egress blocked for the connect window (pf main ruleset)");
        }
    }
    result
}

/// F-001: lift the steady-state IPv6 leak block at teardown.
///
/// Best-effort and always safe to call (no-op if never engaged), so it can never
/// fail a disconnect — a stuck block would leave the host without IPv6.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_deactivate() {
    let mut pf = PF.lock().await;
    let (wanted, kill_switch_owns) = (pf.ipv6_baseline, pf.loaded);
    pf.ipv6_off(&Pfctl);
    mirror(&pf);
    if wanted {
        if kill_switch_owns {
            tracing::info!("F-001: leak block released; kill switch still owns the pf ruleset");
        } else {
            tracing::info!("F-001: IPv6 egress block removed");
        }
    }
}

/// F-001: remove a leak-block / kill-switch ruleset left behind by a crash.
///
/// pf rules loaded with `pfctl -f` live in the kernel and survive process exit —
/// unlike Windows WFP dynamic sessions, which self-clean. Without this, a panic
/// or SIGKILL while blocking leaves the machine either without IPv6 or (worse,
/// if the kill switch was mid-block) fully firewalled off, with no recovery short
/// of a reboot. Only reverts rulesets carrying OUR marker anchor, so a third
/// party's pf configuration is never clobbered. Runs at startup, before anything
/// else can take the lock.
#[cfg(target_os = "macos")]
pub fn reconcile_stale_pf_state() {
    // Whether our marker is loaded; `None` when pf could not be read.
    let ours =
        |rules: Result<String, String>| rules.ok().map(|r| r.contains(pf_policy::MARKER_ANCHOR));
    // Whether pf is enabled does not matter: a stale block-all in a disabled
    // pf is one `pfctl -e` (anyone's) from blocking everything (P2-2).
    if ours(pfctl(&["-s", "rules"])) != Some(true) {
        return; // not ours, or unreadable — leave it alone
    }
    tracing::warn!("Found a stale Birdo pf ruleset from a previous run — restoring /etc/pf.conf");
    if let Err(e) = pfctl(&["-f", "/etc/pf.conf"]) {
        tracing::warn!("{e}");
    }

    // OBSERVE the result — do not infer it from having asked.
    //
    // This used to store `false` unconditionally. If the restore failed (an
    // unreadable /etc/pf.conf, pfctl missing, not root) the kernel kept OUR
    // block-all ruleset loaded while the app recorded "not blocking" — so the
    // user had no network at all, the UI said the kill switch was off, and
    // nothing ever retried, because every recovery path is gated on the flag.
    // A reboot was the only way out, which is the exact failure this function
    // exists to prevent.
    //
    // The marker anchor is the ground truth: still present — or pf no longer
    // readable — means still blocking.
    let still_ours = ours(pfctl(&["-s", "rules"])) != Some(false);
    let Ok(mut pf) = PF.try_lock() else {
        tracing::error!("Kill switch state is locked at startup; stale pf state not recorded");
        return;
    };
    if still_ours {
        tracing::error!(
            "Failed to restore /etc/pf.conf — the stale Birdo ruleset is STILL LOADED and this \
             machine's traffic remains blocked. Leaving the kill switch marked active so the \
             normal teardown path can retry; `sudo pfctl -f /etc/pf.conf` clears it manually."
        );
        pf.loaded = true;
        pf.enforcing = true;
        // Retried from here on, whether or not a session ever starts.
        ensure_pf_watchdog();
    } else {
        pf.loaded = false;
        pf.enforcing = false;
        pf.ipv6_baseline = false;
    }
    mirror(&pf);
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
///
/// `Ok(false)`: the kill switch was disarmed while this waited for the lock
/// (P3-3), and pf was left alone.
#[cfg(target_os = "macos")]
async fn pf_activate_blocking() -> Result<bool, String> {
    ensure_pf_watchdog();
    let mut pf = PF.lock().await;
    let inputs = pf_inputs();
    let result = pf.activate(&Pfctl, &inputs, KILLSWITCH_ENABLED.load(Ordering::SeqCst));
    mirror(&pf);
    match &result {
        Ok(true) => tracing::info!(
            "macOS pf kill switch activated (read back: pf enabled, block-all loaded)"
        ),
        Ok(false) => tracing::info!("Kill switch disarmed meanwhile; pf left alone"),
        Err(e) => tracing::error!(
            "macOS pf kill switch NOT confirmed: {} (enforcing={}, lift owed={})",
            e,
            pf.enforcing,
            pf.loaded
        ),
    }
    result
}

/// The block-all's inputs as they are NOW — read while the `PF` lock is held
/// (P3-3), so a load can never be built from a relay or an intent that changed
/// while it waited.
#[cfg(target_os = "macos")]
fn pf_inputs() -> pf_policy::Inputs {
    let inputs = pf_policy::Inputs {
        relay: vpn_server_ip(),
        control_plane: pf_policy::control_plane_addresses(),
        // pf has no application condition, so the control-plane permit
        // matches the euid we run as (root: arm() refuses otherwise) and
        // pf_policy scopes its DESTINATION to the control-plane table.
        euid: unsafe { libc::geteuid() },
        lan_sharing: lan_sharing_enabled(),
    };
    tracing::debug!(
        "Kill switch inputs: control-plane permit for uid {} on tcp/443 to {} addresses",
        inputs.euid,
        inputs.control_plane.len()
    );
    inputs
}

/// How often a held block is re-verified (P2-3): the auto-reconnect
/// heartbeat's period.
#[cfg(target_os = "macos")]
const PF_WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Start the pf watchdog, once per process. Cheap while nothing is held: a
/// lock and a flag every 30 s. Its own task rather than a hook in the
/// auto-reconnect loop, so it also covers a block held outside a session (a
/// lift that failed after a give-up, a stale block found at startup).
#[cfg(target_os = "macos")]
fn ensure_pf_watchdog() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        tauri::async_runtime::spawn(async {
            loop {
                tokio::time::sleep(PF_WATCHDOG_INTERVAL).await;
                pf_watchdog_tick().await;
            }
        });
    });
}

/// One watchdog pass: see `PfState::watchdog`.
#[cfg(target_os = "macos")]
async fn pf_watchdog_tick() {
    let mut pf = PF.lock().await;
    let intent = KILLSWITCH_ENABLED.load(Ordering::SeqCst);
    let outcome = pf.watchdog(&Pfctl, pf_inputs, intent);
    mirror(&pf);
    drop(pf);
    let Some(result) = outcome else {
        return;
    };
    match result {
        Ok(()) if intent => tracing::warn!(
            "Kill switch watchdog: something else had disabled or replaced the pf block; restored"
        ),
        Ok(()) => {
            tracing::info!("Kill switch watchdog: retried an owed lift of the pf block; lifted")
        }
        Err(e) => tracing::error!("Kill switch watchdog: {}", e),
    }
    blocking_may_have_changed();
}

/// macOS: the tunnel now runs on `name` (MR-1125, P2-1).
///
/// The block-all permits the tunnel by interface NAME, and that one only. A
/// reconnect or a settings reapply engages the block BEFORE the new device
/// exists, so the name is recorded here, the moment `create_utun_device`
/// returns it, and a held block is re-loaded at once and READ BACK permitting
/// it. `Err` — the tunnel's traffic would meet `block drop all` — must fail
/// the start: this used to be only logged, and an automatic reconnect could
/// reach Connected behind a block that dropped everything in the tunnel.
#[cfg(target_os = "macos")]
pub async fn tunnel_interface_up(name: &str) -> Result<(), String> {
    let mut pf = PF.lock().await;
    let held = pf.loaded;
    let inputs = pf_inputs();
    let result = pf.tunnel_up(&Pfctl, &inputs, name);
    mirror(&pf);
    drop(pf);
    if held {
        blocking_may_have_changed();
    }
    result
}

/// macOS: the tunnel on `name` is going away. Its permit leaves a held block
/// BEFORE the device's fd is closed (P3-4): once closed, the unit is free, and
/// another VPN that took it before the re-load would pass straight through the
/// kill switch. Best-effort: a teardown must not fail on it.
#[cfg(target_os = "macos")]
pub async fn tunnel_interface_down(name: &str) {
    let mut pf = PF.lock().await;
    let inputs = pf_inputs();
    let result = pf.tunnel_down(&Pfctl, &inputs, name);
    mirror(&pf);
    drop(pf);
    if let Err(e) = result {
        tracing::warn!("Kill switch: re-loading the block without {}: {}", name, e);
    }
    blocking_may_have_changed();
}

/// [`tunnel_interface_down`] for `Drop`, which cannot await: done in place
/// when the lock is free, else handed to the runtime (the fd is closed either
/// way — leaving the device alive is a guaranteed IPv4 blackhole).
#[cfg(target_os = "macos")]
pub fn tunnel_interface_gone_now(name: &str) {
    match PF.try_lock() {
        Ok(mut pf) => {
            let inputs = pf_inputs();
            if let Err(e) = pf.tunnel_down(&Pfctl, &inputs, name) {
                tracing::warn!("Kill switch: re-loading the block without {}: {}", name, e);
            }
            mirror(&pf);
        }
        Err(_) => {
            let name = name.to_string();
            tauri::async_runtime::spawn(async move {
                tunnel_interface_down(&name).await;
            });
        }
    }
}

/// Deactivate pf blocking: drop the block-all main ruleset and fall back to the
/// correct baseline — the IPv6 leak block if a tunnel session is still live,
/// otherwise the system default ruleset (dropping our pf reference).
/// `PfState::disengage` verifies the lift by reading pf back.
///
/// F-001: the fallback is not optional. This runs on every reconnect (the
/// auto-reconnect loop deactivates once the tunnel is healthy again). Restoring
/// bare `/etc/pf.conf` here would wipe the connect-window IPv6 block and silently
/// reopen the leak for the rest of the session.
#[cfg(target_os = "macos")]
async fn pf_deactivate_blocking() -> Result<(), String> {
    let mut pf = PF.lock().await;
    let onto_baseline = pf.ipv6_baseline;
    let result = pf.disengage(&Pfctl);
    mirror(&pf);
    match &result {
        Ok(()) if onto_baseline => {
            tracing::info!("macOS pf kill switch deactivated (IPv6 leak block retained)")
        }
        Ok(()) => tracing::info!("macOS pf kill switch deactivated"),
        Err(e) if pf.loaded => tracing::error!(
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
