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

/// The intent's write lock, guarding a sequence number that every write of
/// the intent bumps, ON and OFF alike (review of #222, rounds 3 and 4).
///
/// INVARIANT: `KILLSWITCH_ENABLED` is written only by [`intent_off`],
/// [`intent_on_since`] and [`intent_off_since`], all three under this lock,
/// and the lock is held for those stores alone — never across an await, a
/// firewall call or settings I/O. A
/// plain mutex therefore cannot keep anyone waiting on slow work: not the
/// Disconnect escape (`disarm`), not the live OFF. (Round 2 used an async
/// lock that `arm` held across its settings read; a hung credential store, or
/// a `schtasks` holding the settings lock, then held `disarm` for good.) It
/// also cannot self-deadlock: no path takes it twice.
///
/// `arm` reads the number BEFORE its slow read of the preference and stores
/// what it read only if nothing has written the intent since
/// ([`intent_on_since`], [`intent_off_since`]): an OFF that lands during the
/// read wins over its ON, and an ON over its OFF.
static INTENT: parking_lot::Mutex<u64> = parking_lot::const_mutex(0);

/// The intent's current sequence number, for [`intent_on_since`] and
/// [`intent_off_since`] — and for a dial, which reads it when it begins and
/// hands it to its arm ([`arm_since`]).
pub(crate) fn intent_seq() -> u64 {
    *INTENT.lock()
}

/// The user's OFF (the live toggle, `disarm`): turn the intent off whatever
/// was written before, and bump the sequence, so an `arm` that read the
/// preference before this does not store its ON over it. Whether it was on.
/// (`arm`'s own OFF is [`intent_off_since`], which stands aside instead.)
fn intent_off() -> bool {
    let mut seq = INTENT.lock();
    *seq = seq.wrapping_add(1);
    KILLSWITCH_ENABLED.swap(false, Ordering::SeqCst)
}

/// Turn the intent ON, unless it was written since `seen` was read. Whether it
/// stored it. The sequence moves on ON too (round 4 of the review of #222), so
/// an `arm` that read an OFF preference before this ON cannot clear it
/// ([`intent_off_since`]).
fn intent_on_since(seen: u64) -> bool {
    let mut seq = INTENT.lock();
    if *seq != seen {
        return false;
    }
    *seq = seq.wrapping_add(1);
    KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
    true
}

/// Turn the intent OFF for a preference read since `seen`: `arm` finding the
/// preference off. Unlike the user's OFF ([`intent_off`], the live toggle and
/// `disarm`, which always win) it does not clear an intent written after its
/// read began — that write is newer than what it read. `None` when it stood
/// aside; otherwise whether the intent was on.
fn intent_off_since(seen: u64) -> Option<bool> {
    let mut seq = INTENT.lock();
    if *seq != seen {
        return None;
    }
    *seq = seq.wrapping_add(1);
    Some(KILLSWITCH_ENABLED.swap(false, Ordering::SeqCst))
}

/// Global state for kill switch - stores allowed VPN server IP. A plain
/// mutex, so the pf backend reads it under its own lock, synchronously, in the
/// same step that loads it (P3-3), and iptables under its chains' lock in the
/// step that builds them (MR-1998).
static VPN_SERVER_IP: std::sync::Mutex<Option<Ipv4Addr>> = std::sync::Mutex::new(None);

/// The relay the block permits.
#[cfg(not(target_os = "windows"))]
pub(crate) fn vpn_server_ip() -> Option<Ipv4Addr> {
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
    let result = unless_turned_off(
        activate_platform_block(),
        deactivate_platform_block,
        activate_platform_block,
        platform_is_blocking,
    )
    .await;
    blocking_may_have_changed();
    result
}

/// Run `engage`, then apply the one rule for the intent: intent OFF plus a
/// block up (`blocking`) means lift, through `lift` — whatever `engage`
/// reported.
///
/// An activation reads `KILLSWITCH_ENABLED` BEFORE its firewall load, and the
/// block is only reported as up (`platform_is_blocking()`) once the load has
/// committed — a WFP transaction, a pfctl or iptables run, milliseconds to
/// hundreds of them. A Kill Switch OFF that lands inside that window clears
/// the intent, finds no block yet and so lifts nothing; the load then commits
/// a block the user has just turned off. In the reconnect gap the next dial
/// would not re-engage it, but nothing would lift it either: in Windows
/// lockdown it was then held for the rest of the session and kept by the
/// give-up. Re-reading the intent after the load closes the window from this
/// side, as the OFF's own `platform_is_blocking()` check closes it from the
/// other: with both SeqCst, at least one of the two sees the other's write.
///
/// Review of #222: the rule asks whether a block IS up, not whether this
/// engage put one up — a refresh that failed keeps the previous block, a
/// partial iptables load leaves its chains (and reports an error), a rebuild
/// around a new relay or tunnel LUID reports nothing engaged.
///
/// An ON can land while the lift runs, its own block going up before the lift
/// takes it down; an OFF can land again while that block is re-engaged. So
/// the intent and the block are compared again after every lift and every
/// re-engage, until they agree — an ON finds its block (`reengage`, a no-op
/// refresh if its own activation is still to come), an OFF finds none. Round
/// 3 compared once, so OFF→ON→OFF inside one window left a re-engaged block
/// that nothing looked at again, and on macOS/Linux no engine close ever
/// removes it. Bounded by [`AGREEMENT_ROUNDS`]: past it, it fails closed —
/// the block its last re-engage put up is left up, even if the intent has
/// flipped to OFF again since — and logs a warning; it stays up until the
/// next OFF or a Disconnect lifts it. No lock is held across any firewall
/// call (round 3: a lock held there kept `disarm` waiting on them).
async fn unless_turned_off<E, L, LF, R, RF>(
    engage: E,
    lift: L,
    reengage: R,
    blocking: impl Fn() -> bool,
) -> Result<bool, String>
where
    E: std::future::Future<Output = Result<bool, String>>,
    L: Fn() -> LF,
    LF: std::future::Future<Output = Result<bool, String>>,
    R: Fn() -> RF,
    RF: std::future::Future<Output = Result<bool, String>>,
{
    let mut engaged = engage.await;
    for _ in 0..AGREEMENT_ROUNDS {
        if KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
            return engaged;
        }
        if !blocking() {
            // Nothing up, and nothing wanted: whatever the engage met is moot.
            return Ok(false);
        }
        tracing::info!("The kill switch is off and its block is up — lifting it");
        lift().await?;
        if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
            return Ok(false);
        }
        tracing::info!("The kill switch was turned back on during the lift — re-engaging");
        engaged = reengage().await;
    }
    tracing::warn!("The kill switch kept changing while its block moved — leaving the last answer");
    engaged
}

/// How many lift / re-engage rounds [`unless_turned_off`] runs before it stops
/// chasing an intent that keeps flipping.
const AGREEMENT_ROUNDS: usize = 4;

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
        // MR-833: from the first block on, it is re-verified on a timer.
        ensure_iptables_watchdog();
        // MR-1998: the relay is read under the chains' lock, where the block
        // is built, not here before waiting for it.
        if let Err(e) = firewall_linux::activate_blocking().await {
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
/// [`activate_killswitch`], re-checked once the block is up the same way
/// ([`unless_turned_off`]); a block already in force is rebuilt whatever it.
#[cfg(target_os = "windows")]
pub(crate) async fn move_relay(
    relay: crate::vpn::wfp_policy::Relay,
    engage: bool,
) -> Result<(), String> {
    let engage = engage && KILLSWITCH_ENABLED.load(Ordering::SeqCst);
    let result = unless_turned_off(
        async move { wfp::move_relay(relay, engage).await.map(|()| engage) },
        deactivate_platform_block,
        activate_platform_block,
        platform_is_blocking,
    )
    .await
    .map(|_| ());
    blocking_may_have_changed();
    result
}

/// Linux: the relay was just recorded (`session::apply_relay_permit`), so a
/// block of ours that may be up is re-armed around it. Whether one is up is
/// decided under the chains' lock (MR-1998): asked lock-free, a first arm
/// still in flight, which read the previous relay, or a partial one that
/// reads as not blocking, said no, and kept the old relay until the next
/// reconnect. Under the lock that arm finishes first and is re-armed
/// here. The intent is honoured like every activation's: read before the
/// load, re-read after it ([`unless_turned_off`]).
#[cfg(target_os = "linux")]
pub(crate) async fn rearm_for_relay() -> Result<bool, String> {
    let engage = async {
        if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
            return Ok(false);
        }
        firewall_linux::rearm_if_up().await
    };
    let result = unless_turned_off(
        engage,
        deactivate_platform_block,
        activate_platform_block,
        platform_is_blocking,
    )
    .await;
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
/// The frontend persists an ON first, then calls this (`arm` reads the file).
/// An OFF reads no file: it is sent before its save, and once more after it
/// (`setKillSwitch`, round 4 of the review of #222). Behaviour:
/// - enabled=true, session active  → arm now (init WFP + set intent; activate
///   immediately in lockdown mode).
/// - enabled=true, no active session → no-op; the persisted preference
///   applies at next connect.
/// - enabled=false, in ANY state → clear the intent so a later drop won't
///   block, and lift any block currently active; WFP stays initialized and the
///   disconnect path fully cleans up. Not gated on a session: the UI sends an
///   OFF with no session only while a block is up (`killSwitchLiveApplies`),
///   and that is exactly the block the user wants gone. Gated, it was saved
///   and dropped here, and the block stayed until the next connect.
#[tauri::command]
pub async fn set_killswitch_live(
    enabled: bool,
    app: AppHandle,
    vpn_manager: State<'_, VpnManager>,
) -> Result<bool, IpcError> {
    if enabled {
        // The intent's sequence BEFORE the session check (round 4 of the
        // review of #222): a Disconnect that lands between the two moves it,
        // and `arm` then neither re-opens the engine nor engages a block for a
        // session that is gone.
        let seen = intent_seq();
        let state = vpn_manager.get_state().await;
        if !(state.is_tunnel_active() || state.can_disconnect()) {
            tracing::debug!("set_killswitch_live: no active session — applies at next connect");
            return Ok(false);
        }
        // arm() re-reads the (already-persisted) preference and initializes WFP,
        // engaging the reactive protection for the live session.
        arm_since(&app, seen)
            .await
            .map_err(|e| IpcError::new(IpcErrorCode::KillswitchFailed, e))
    } else {
        // Review of #222: a lift that failed used to be dropped here and the
        // OFF reported as applied, with the machine still blocked. It is an
        // error now, so the UI says the change could not be applied.
        //
        // macOS lifts through its own pf backend, decided under the PF lock
        // from `loaded` (N2 on #221): the lock-free status read missed a
        // block-all held by a disabled pf, and an activation in flight (that
        // one completes first, then is lifted). So `blocking` is always true
        // there and `pf_lift_if_loaded` decides — and its failure, which #221
        // used to log while reporting OK, is now the OFF's error too.
        #[cfg(target_os = "macos")]
        let turned_off = turn_off(
            || async {
                let lifted = pf_lift_if_loaded().await;
                blocking_may_have_changed();
                lifted
            },
            || true,
        )
        .await;
        // Linux likewise, under the chains' lock (MR-1999): the lock-free
        // `is_blocking()` reads no block for a first arm that hooked only
        // part of its jumps, and a watchdog pass re-arming that one then put
        // the block up behind the OFF. `lift_if_held` waits the pass out and
        // lifts what it put up.
        #[cfg(target_os = "linux")]
        let turned_off = turn_off(
            || async {
                let lifted = firewall_linux::lift_if_held().await;
                blocking_may_have_changed();
                lifted
            },
            || true,
        )
        .await;
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let turned_off = turn_off(deactivate_killswitch, platform_is_blocking).await;
        turned_off.map_err(|e| {
            IpcError::new(
                IpcErrorCode::KillswitchFailed,
                format!("The kill switch could not be turned off: {e}"),
            )
        })
    }
}

/// The live OFF: clear the intent and lift any block that is up. Clearing
/// bumps the intent's sequence ([`intent_off`]), so an `arm` that read the
/// preference before this does not store its ON over it; nothing here waits
/// on anyone's I/O.
///
/// Parameters, kept stable for the platform lanes: `lift` is the platform's
/// lift, called at most once, `FnOnce() -> impl Future<Output = Result<bool,
/// String>>` (its error is the OFF's error); `blocking` says whether a block
/// is up right now. `set_killswitch_live` passes `deactivate_killswitch` and
/// `platform_is_blocking`; a backend with a lift of its own, decided under
/// its own lock (macOS pf; Linux iptables, MR-1999), passes that instead.
async fn turn_off<L, LF>(lift: L, blocking: impl Fn() -> bool) -> Result<bool, String>
where
    L: FnOnce() -> LF,
    LF: std::future::Future<Output = Result<bool, String>>,
{
    intent_off();

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
    if blocking() {
        lift().await?;
    }

    tracing::info!("Kill switch softened live (intent cleared, any block lifted)");
    Ok(true)
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
///
/// `seen` is the intent's sequence, read by the caller before anything this
/// arm depends on: the live ON reads it before its session check, and a dial
/// when it begins (`session::connect_session_for`; round 6 of the review of
/// #222, which folded the old `arm(app)` into this). Rust publishes Connected
/// before the dial's arm, so the UI's check at the end of a dial could run
/// before it; an OFF the user made during the dial makes the dial's own arm
/// stand aside instead.
pub(crate) async fn arm_since(app: &AppHandle, seen: u64) -> Result<bool, String> {
    // Respect the user's kill-switch preference (default ON). Reading it here —
    // the single choke-point every connect path funnels through — keeps all call
    // sites consistent. Fail SAFE: if settings can't be read, treat as enabled.
    // Read on the blocking pool: it is file and credential-store I/O.
    arm_reading_since(seen, async {
        crate::commands::settings::load_settings_off_runtime(app)
            .await
            .map(|s| s.killswitch_enabled)
            .unwrap_or(true)
    })
    .await
}

/// [`arm_since`] around a `preference` read that may take any time.
///
/// Review of #222: an OFF that lands during the read (the toggle during
/// `connecting`) must win. The intent's sequence is read BEFORE the
/// preference and the ON stored only if nothing has moved it since
/// ([`intent_on_since`]). Round 2 held a lock across the read instead, and a
/// read that hung held `disarm` with it.
async fn arm_reading_since(
    seen: u64,
    preference: impl std::future::Future<Output = bool>,
) -> Result<bool, String> {
    let enabled = preference.await;
    arm_with_preference(enabled, seen).await
}

/// [`arm_since`] after the preference has been read, `seen` the intent's sequence
/// from before that read — split out so the preference-OFF branch is
/// unit-testable without an `AppHandle`.
async fn arm_with_preference(enabled: bool, seen: u64) -> Result<bool, String> {
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
        //
        // Only if nothing wrote the intent since this read began (round 4 of
        // the review of #222): an ON stored meanwhile is newer than the OFF
        // this read found, and stands.
        match intent_off_since(seen) {
            Some(true) => tracing::info!(
                "Kill switch disabled by user preference — not arming (cleared a stale armed intent from the previous session)"
            ),
            Some(false) => tracing::info!("Kill switch disabled by user preference — not arming"),
            None => tracing::info!(
                "Kill switch preference read OFF, but the switch changed since — leaving it"
            ),
        }
        return Ok(false);
    }

    // Before the engine is opened: an OFF or a Disconnect since `seen` means
    // there is nothing to arm for (round 4: a Disconnect landing between the
    // live ON's session check and this arm re-opened the engine and engaged
    // lockdown with no session).
    if intent_seq() != seen {
        tracing::info!("Kill switch changed before arming — not arming");
        return Ok(false);
    }

    if !is_elevated() {
        tracing::warn!("Kill switch NOT armed: insufficient privileges (admin/root required)");
        return Ok(false);
    }

    // MR-2110: an engine that cannot be opened leaves the intent ON
    // ([`open_engine`]), so every teardown, dial and switch after this fails
    // closed instead of reading "no block wanted".
    #[cfg(target_os = "windows")]
    if let Err(e) = open_engine(wfp::initialize(), seen).await {
        // Lockdown's always-on block cannot go up without the engine either:
        // degrade to the reactive kill switch for this session, as when its
        // activation fails below.
        wfp::set_lockdown_mode(false);
        return Err(e);
    }

    if !intent_on_since(seen) {
        tracing::info!("Kill switch changed while arming — not arming");
        return Ok(false);
    }

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

/// The kill switch as `tunnel_linux`'s netns tests arm it (MR-782): as a dial
/// arms it with the preference ON ([`arm_with_preference`]), so its block-all
/// goes up through the intent path like every other
/// (`tests::no_block_all_is_engaged_around_the_intent`) and the iptables
/// watchdog reads it as wanted. The test lifts it with [`disarm`], as a
/// Disconnect does. Dropping the guard clears the intent and removes the
/// chains as well, so a test that fails half way leaves neither to the next
/// test in the process.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod netns_kill_switch {
    pub(crate) struct Armed(());

    pub(crate) async fn arm() -> Armed {
        // Taken first: a failed arm below still drops it.
        let armed = Armed(());
        let seen = super::intent_seq();
        assert_eq!(
            super::arm_with_preference(true, seen).await,
            Ok(true),
            "the kill switch's steady-state block-all"
        );
        armed
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            super::intent_off();
            crate::vpn::firewall_linux::emergency_cleanup();
        }
    }
}

/// [`arm_with_preference`]'s step that opens the kill switch's firewall engine
/// (`open`: `wfp::initialize()`), with the preference ON and `seen` the
/// intent's sequence from before the preference was read. Split out so the
/// failure can be injected in tests.
///
/// MR-2110: a failed open used to return before the intent was stored, so it
/// stayed OFF while the user's preference was ON. `activate_killswitch()` then
/// answered `Ok(false)`, which a reconnect teardown and `fail_connect` read as
/// "the user wants no block" (`reconnect_policy::teardown_covered`) and let
/// go ahead with nothing blocking; `move_relay` dropped the guard of a server
/// switch the same way. The intent is stored ON now, before the error is
/// returned, unless the switch changed since `seen` (an OFF or a Disconnect
/// since wins, as for any arm). With no engine, the block each of those steps
/// asks for fails, and they fail closed: the dead tunnel is held, the dial
/// aborted, the switch refused before the old tunnel is touched (MR-2070,
/// MR-2071).
#[cfg(any(target_os = "windows", test))]
async fn open_engine(
    open: impl std::future::Future<Output = Result<(), String>>,
    seen: u64,
) -> Result<(), String> {
    let Err(e) = open.await else {
        return Ok(());
    };
    if intent_on_since(seen) {
        tracing::error!(
            "The kill switch's firewall could not be initialized ({}); it stays on, so \
             nothing is torn down, re-dialled or switched without its block",
            e
        );
    }
    Err(format!("Failed to initialize kill-switch firewall: {}", e))
}

/// Disarm the kill switch when the user ends the session: clear the intent flag
/// and remove all firewall filters so connectivity is fully restored.
///
/// Always safe to call (no-op if never armed). MUST be called from the
/// user-initiated disconnect path so disconnecting can never strand the machine
/// behind an active block-all filter set.
pub async fn disarm() -> Result<(), String> {
    let result = disarm_with(disarm_platform()).await;
    blocking_may_have_changed();
    result
}

/// Clear the intent, then run `cleanup`. The escape: it waits on nothing but
/// its own cleanup — the intent's lock is only ever held for two stores, so
/// no `arm` stuck in a settings read can hold it up (round 3 of the review).
async fn disarm_with(
    cleanup: impl std::future::Future<Output = Result<(), String>>,
) -> Result<(), String> {
    intent_off();
    cleanup.await
}

async fn disarm_platform() -> Result<(), String> {
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
// Linux: the control-plane self-permit follows what DoH learns
//
// Root's tcp/443 self-permit names each control-plane address
// (`vpn::iptables_policy`), so an address a DoH answer brings while a block
// is up must be added before it is dialled — the twin of macOS's table
// re-load below (P2-4, N5).
// ──────────────────────────────────────────────────────────────

/// Linux: whether control-plane addresses of `generation` already get
/// through — the resolver's lock-free fast path (N5).
#[cfg(target_os = "linux")]
pub fn control_plane_permits(generation: u64) -> bool {
    firewall_linux::permits(generation)
}

/// Linux: a DoH answer brought control-plane addresses of `generation` that
/// the live block's self-permits do not cover. The block is re-armed around
/// them NOW, before the resolver caches or hands them out; `Err` makes it
/// cache nothing, so the next request asks again. See [`learn_control_plane`].
#[cfg(target_os = "linux")]
pub async fn control_plane_learned(generation: u64) -> Result<(), String> {
    let result = learn_control_plane(
        // The re-arm reads the relay under the chains' lock (MR-1998).
        || firewall_linux::refresh_control_plane(generation),
        deactivate_platform_block,
        activate_platform_block,
        platform_is_blocking,
        || firewall_linux::permits(generation),
        firewall_linux::self_permits_missing,
    )
    .await;
    blocking_may_have_changed();
    result
}

/// What [`control_plane_learned`] does, over its parts, so the decision is
/// unit-tested on every OS.
///
/// `refresh` re-arms the live block around the current control-plane set; it
/// runs only while the intent is on, and under the one rule for the intent
/// ([`unless_turned_off`]): a block the user has turned off is lifted rather
/// than re-armed, and a block that is not up is never put up from here. Then:
///
/// - the block covers the new addresses (`covered`), or none is up: `Ok`;
/// - the re-arm landed but a self-permit would not load on this host
///   (`self_permits_missing`: no `-m owner`, say) — review of #259, L2: `Ok`.
///   The address is not permitted either way, so caching it makes nothing
///   less safe, and refusing would keep api.birdo.app from resolving even
///   while connected, when its traffic goes through the tunnel;
/// - otherwise `Err`: nothing is cached, and the next request asks again.
#[cfg(any(target_os = "linux", test))]
async fn learn_control_plane<F, FF, L, LF, R, RF>(
    refresh: F,
    lift: L,
    reengage: R,
    blocking: impl Fn() -> bool,
    covered: impl Fn() -> bool,
    self_permits_missing: impl Fn() -> bool,
) -> Result<(), String>
where
    F: FnOnce() -> FF,
    FF: std::future::Future<Output = Result<bool, String>>,
    L: Fn() -> LF,
    LF: std::future::Future<Output = Result<bool, String>>,
    R: Fn() -> RF,
    RF: std::future::Future<Output = Result<bool, String>>,
{
    let engage = async move {
        if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
            return Ok(false);
        }
        refresh().await
    };
    match unless_turned_off(engage, lift, reengage, blocking).await {
        Ok(_) if covered() => {
            tracing::info!("Kill switch: the control-plane self-permits cover the new address");
            Ok(())
        }
        Ok(_) if self_permits_missing() => {
            tracing::warn!(
                "Kill switch: a control-plane self-permit would not load on this host; \
                 the new address is cached, and reaches the API only through the tunnel"
            );
            Ok(())
        }
        Ok(_) => {
            Err("the kill switch's control-plane self-permit does not cover the new address".into())
        }
        Err(e) => {
            tracing::warn!(
                "Kill switch: re-arming for a new control-plane address failed: {}",
                e
            );
            Err(e)
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Linux: the iptables watchdog (MR-833)
//
// iptables is shared, as pf is: another tool's `iptables -F` (a firewall
// reset script, a firewalld reload, `nft flush ruleset` under iptables-nft)
// takes our jumps out of OUTPUT/INPUT/FORWARD and empties our chains without
// telling us. IPTABLES_BLOCKING is only a flag, so the status kept saying the
// block was up while nothing was filtered, until the next reconnect happened
// to re-arm it. The twin of the macOS pf watchdog below: the same period,
// started by the first block, idle while no block is held.
// ──────────────────────────────────────────────────────────────

/// How often a held iptables block is re-verified: the macOS watchdog's
/// period (`PF_WATCHDOG_INTERVAL`), the auto-reconnect heartbeat's.
#[cfg(target_os = "linux")]
const IPTABLES_WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Start the iptables watchdog, once per process, with the first activation
/// of the block. Cheap while nothing is held: a lock and two flags every 30 s,
/// no process spawned. Once the block is lifted on purpose it reads nothing
/// until the next activation. Its own task, like the pf one, so it also
/// covers a block held outside a session (a lift that failed after a give-up).
#[cfg(target_os = "linux")]
fn ensure_iptables_watchdog() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        tauri::async_runtime::spawn(async {
            let mut failing = iptables_watchdog::Failing::default();
            loop {
                tokio::time::sleep(IPTABLES_WATCHDOG_INTERVAL).await;
                iptables_watchdog_tick(&mut failing).await;
            }
        });
    });
}

/// One watchdog pass: see [`iptables_watchdog::watch`] and
/// `firewall_linux::watchdog`. `failing`: the passes before it that failed
/// in a row, so a failure that persists is one error, not one every 30 s
/// (MR-2000).
#[cfg(target_os = "linux")]
async fn iptables_watchdog_tick(failing: &mut iptables_watchdog::Failing) {
    use iptables_watchdog::Watched;
    let watched = firewall_linux::watchdog().await;
    let failed = failing.record(watched.as_ref());
    let Some(watched) = watched else {
        return;
    };
    let armed = matches!(watched, Watched::Armed { .. });
    match watched {
        Watched::Restored { what } => tracing::warn!(
            "Kill switch watchdog: something else had removed or changed part of the iptables \
             block ({}); restored",
            what
        ),
        Watched::NotRestored { what, why } if failed == 1 => tracing::error!(
            "Kill switch watchdog: part of the iptables block is gone ({}) and could not be \
             put back: {}. Retried every {}s; reported again once it is back.",
            what,
            why,
            IPTABLES_WATCHDOG_INTERVAL.as_secs()
        ),
        Watched::NotRestored { what, why } => tracing::debug!(
            "Kill switch watchdog: part of the iptables block ({}) still could not be put \
             back (failed pass {}): {}",
            what,
            failed,
            why
        ),
        // MR-2090: one error per streak; the attempts after it are counted.
        Watched::NotArmed { why, failed: 1 } => tracing::error!(
            "Kill switch watchdog: the kill switch is ON but its iptables block is NOT up — \
             it could not be put up: {}. The session runs without the block until it is; \
             retried, at most {}s apart.",
            why,
            IPTABLES_WATCHDOG_INTERVAL.as_secs()
                * u64::from(iptables_watchdog::FirstArm::MAX_APART)
        ),
        Watched::NotArmed { why, failed } => tracing::debug!(
            "Kill switch watchdog: the iptables block still could not be put up (attempt {}): {}",
            failed,
            why
        ),
        Watched::Armed { failed } => tracing::warn!(
            "Kill switch watchdog: the iptables block, wanted but not up since its activation \
             failed, is up now (after {} failed retries)",
            failed
        ),
        Watched::LiftRetried(Ok(())) => {
            tracing::info!(
                "Kill switch watchdog: retried an owed lift of the iptables block; lifted"
            )
        }
        Watched::LiftRetried(Err(e)) if failed == 1 => tracing::error!(
            "Kill switch watchdog: an owed lift of the iptables block failed again: {}. \
             Retried every {}s; reported again once it lands.",
            e,
            IPTABLES_WATCHDOG_INTERVAL.as_secs()
        ),
        Watched::LiftRetried(Err(e)) => tracing::debug!(
            "Kill switch watchdog: an owed lift of the iptables block still fails \
             (failed pass {}): {}",
            failed,
            e
        ),
    }
    if armed {
        // A block put up where none was is an activation, so the one rule
        // for the intent applies: an OFF that landed while it went up found
        // no block to lift ([`unless_turned_off`]).
        let _ = unless_turned_off(
            std::future::ready(Ok(true)),
            deactivate_platform_block,
            activate_platform_block,
            platform_is_blocking,
        )
        .await;
    }
    blocking_may_have_changed();
}

/// What the Linux watchdog decides, over an `Xtables` that runs `iptables` /
/// `ip6tables` (MR-833). Compiled into every test build, like
/// `learn_control_plane`, so the Windows job runs its tests against a
/// scripted iptables — the seam `pf_policy` gives the macOS watchdog.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod iptables_watchdog {
    /// `iptables -w 5 <args>` (`ip6tables` when `v6`): its stdout when it
    /// exits 0, why not otherwise. `firewall_linux` runs the real commands;
    /// the tests script them.
    pub(crate) trait Xtables {
        fn run(&self, v6: bool, args: &[&str]) -> Result<String, String>;
    }

    /// The generation of chains a block of ours has live, as it was loaded —
    /// what the watchdog reads back.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Live {
        /// The chain hooked into OUTPUT.
        pub out: String,
        /// The chain hooked into INPUT and FORWARD.
        pub inn: String,
        /// The rules of `out` and `inn`, IPv4, as iptables listed them
        /// ([`rules_of`]) once they were loaded (MR-2001).
        pub v4: (Vec<String>, Vec<String>),
        /// ...and IPv6. `None` on a host without ip6tables, where there is
        /// nothing to read back.
        pub v6: Option<(Vec<String>, Vec<String>)>,
    }

    /// The rules that may sit above our jump in a built-in chain: the IPv6
    /// leak block's (F-001, `tunnel_linux::install_ipv6_leak_block`), and
    /// the cover a re-install hooks in above it while it rebuilds it, with
    /// the same rules (MR-2128). Every tunnel start inserts them at the top
    /// of ip6tables' OUTPUT, while our block is held for the whole session,
    /// and they let nothing routable out (`iptables_policy` keeps our IPv6
    /// chain from accepting anything they refuse, whichever sits first).
    /// There alone: the same jumps in iptables, or in INPUT or FORWARD, are
    /// not ones `tunnel_linux` ever inserted, so they are no exception
    /// ([`may_precede`]).
    const LEAK_BLOCK_JUMPS: [&str; 2] = ["-j BIRDO_IPV6_LEAK_BLOCK", "-j BIRDO_IPV6_LEAK_COVER"];

    /// Whether `rule` may sit above our jump in `hook` of the family `v6`
    /// says: the IPv6 leak block's jumps, in ip6tables' OUTPUT only.
    fn may_precede(v6: bool, hook: &str, rule: &str) -> bool {
        v6 && hook == "OUTPUT" && LEAK_BLOCK_JUMPS.contains(&rule)
    }

    /// What an iptables probe (`-L <chain>`, `-C <hook> -j <chain>`) says
    /// about what it asked for (MR-2000).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Probe {
        /// It is installed: the probe exited 0.
        Present,
        /// It is not: the probe exited 1 (`No chain/target/match by that
        /// name`, `Bad rule (does a matching rule exist in that chain?)`),
        /// or the command is not installed (an IPv4-only host's ip6tables,
        /// AUDIT-N5), so nothing of ours can be in its table.
        Absent,
        /// The probe could not tell. Exit 4 is iptables' RESOURCE_PROBLEM:
        /// the xtables lock not had within `-w 5` ("Another app is
        /// currently holding the xtables lock. Stopped waiting after 5s."),
        /// a kernel that said EAGAIN; and iptables run without root, which
        /// is why a teardown counts it only while a block of ours may be up
        /// ([`still_installed`]). Or any other exit (2, a parameter problem,
        /// is also a `-C` jump to a chain that does not exist: we only ask
        /// that of a chain just built), a run killed by a signal, a spawn
        /// that failed. With `-w 5`, a probe under lock contention exits 4
        /// where a bare `-w` waited and then answered, so "not 0" is no
        /// longer "not there".
        Unknown,
    }

    impl Probe {
        /// From how the probe ended: its exit code (`None` when killed by a
        /// signal), or why it could not be spawned.
        pub(crate) fn of(ended: Result<Option<i32>, std::io::ErrorKind>) -> Self {
            match ended {
                Ok(Some(0)) => Self::Present,
                Ok(Some(1)) | Err(std::io::ErrorKind::NotFound) => Self::Absent,
                _ => Self::Unknown,
            }
        }

        /// Whether what was probed may be installed: it is, or the probe
        /// could not tell. What a teardown removes, and what a partial arm
        /// reports as filtering, fail closed on.
        pub(crate) fn may_be_there(self) -> bool {
            self != Self::Absent
        }
    }

    /// Whether a block of ours may be up: a generation of chains is live
    /// (`live_gen`, `LIVE_GEN`), or a block is held (`blocking`,
    /// `IPTABLES_BLOCKING`). A first arm that hooked only part of its jumps,
    /// not OUTPUT's, is live while it reads as not blocking (MR-1999), and
    /// a lift that failed is held with its generation still named. What
    /// the OFF lifts, what a new relay re-arms (MR-1998), and when a
    /// teardown counts a chain its probe could not see as still there
    /// ([`still_installed`]): decided under the chains' lock, every time.
    pub(crate) fn block_may_be_up(live_gen: i8, blocking: bool) -> bool {
        live_gen >= 0 || blocking
    }

    /// Whether a chain survived a teardown, from its IPv4 and IPv6 probes
    /// (MR-2000). Present in either: yes. One that could not tell counts
    /// while a block of ours may be up (`ours_up`, [`block_may_be_up`]): a
    /// lift that cannot confirm it landed is not reported as landed, or
    /// IPTABLES_BLOCKING would be cleared over a block still hooked, with
    /// nothing left to retry it. With none of ours up there is nothing for
    /// the lift to have left, and a host where every probe fails (iptables
    /// run without root exits 4 too) would fail every disarm.
    pub(crate) fn still_installed(probes: [Probe; 2], ours_up: bool) -> bool {
        probes.contains(&Probe::Present) || (ours_up && probes.contains(&Probe::Unknown))
    }

    /// The rules of `chain` in an `iptables -S <chain>` listing, each as the
    /// text after `-A <chain> `.
    pub(crate) fn rules_of<'a>(listing: &'a str, chain: &str) -> Vec<&'a str> {
        let prefix = format!("-A {chain} ");
        listing
            .lines()
            .filter_map(|line| line.trim().strip_prefix(prefix.as_str()))
            .map(str::trim)
            .collect()
    }

    /// What the live block lacks, read from iptables itself (`-S`). `None`
    /// while, in each family read back: our jump is in OUTPUT/INPUT/FORWARD
    /// with nothing above it that [`may_precede`] does not allow, and each
    /// chain holds the rules iptables listed for it once it was loaded, in
    /// order, its DROP last. An empty chain with its jump still in place
    /// filters nothing (the packet falls through to the built-in chain's
    /// ACCEPT policy), so a jump alone is not proof. A read that fails counts as missing: the re-arm
    /// that follows is a generation swap, which never opens a window, so a
    /// false alarm costs a re-load and no more.
    ///
    /// MR-2001: the rules are compared as text, and our jump's place too.
    /// Comparing with the text we loaded would flap and re-arm every pass
    /// (iptables canonicalises its listing: `-m tcp`, `/32`, option order),
    /// so the baseline is the kernel's own listing, read back once loaded.
    /// Caught: a flush (`iptables -F`, `-F <chain>`, `nft flush ruleset`), a
    /// deleted chain or jump, a rule added to, removed from or changed in our
    /// chains, and another tool's rule above our jump (`iptables -I OUTPUT 1
    /// -j ACCEPT`), which the re-arm puts back underneath.
    ///
    /// What this still leaves (the residual): a change is found by the next
    /// pass, up to 30 s later, not as it happens; a tool that keeps putting
    /// its rule back on top makes every pass re-arm (logged, never a gap);
    /// the IPv6 leak block's chain is not ours to check here; and rules in
    /// other tables or nftables chains are not read, though none of them can
    /// accept a packet past our DROP (an accept ends a packet's walk through
    /// one base chain only, a drop anywhere ends it).
    pub(crate) fn missing(x: &impl Xtables, live: &Live) -> Option<String> {
        let mut families = vec![(false, &live.v4)];
        if let Some(v6) = &live.v6 {
            families.push((true, v6));
        }
        for (v6, (out_rules, in_rules)) in families {
            let family = if v6 { "ip6tables" } else { "iptables" };
            for (hook, chain) in [
                ("OUTPUT", live.out.as_str()),
                ("INPUT", live.inn.as_str()),
                ("FORWARD", live.inn.as_str()),
            ] {
                let jump = format!("-j {chain}");
                // `None`: no jump (or no listing); `Some(on_top)`: whether
                // nothing but what may_precede sits above it.
                let placed = x.run(v6, &["-S", hook]).ok().and_then(|listing| {
                    let rules = rules_of(&listing, hook);
                    let at = rules.iter().position(|rule| *rule == jump)?;
                    Some(rules[..at].iter().all(|rule| may_precede(v6, hook, rule)))
                });
                match placed {
                    None => return Some(format!("{family}: the {hook} jump to {chain}")),
                    Some(false) => {
                        return Some(format!("{family}: a rule above the {hook} jump to {chain}"))
                    }
                    Some(true) => {}
                }
            }
            for (chain, loaded) in [
                (live.out.as_str(), out_rules),
                (live.inn.as_str(), in_rules),
            ] {
                let Ok(listing) = x.run(v6, &["-S", chain]) else {
                    return Some(format!("{family}: the chain {chain}"));
                };
                let held = rules_of(&listing, chain);
                if held.len() != loaded.len() {
                    return Some(format!(
                        "{family}: {chain} holds {} rules where {} were loaded",
                        held.len(),
                        loaded.len()
                    ));
                }
                if held.last() != Some(&"-j DROP") {
                    return Some(format!("{family}: {chain} no longer ends in its DROP"));
                }
                // Which rule, never its text: it carries the relay's and the
                // control plane's addresses.
                if let Some(n) = held.iter().zip(loaded).position(|(now, was)| now != was) {
                    return Some(format!(
                        "{family}: rule {} of {chain} is not the one loaded",
                        n + 1
                    ));
                }
            }
        }
        None
    }

    /// What one watchdog pass did.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Watched {
        /// A wanted block was missing `what`; it was re-armed and reads back
        /// whole.
        Restored { what: String },
        /// ...and could not be put back, for `why`.
        NotRestored { what: String, why: String },
        /// MR-2090: a wanted block of which no generation was live — its
        /// first arm had failed — was put up, and reads back whole. `failed`:
        /// how many attempts before this one could not ([`FirstArm`]).
        Armed { failed: u32 },
        /// ...or could not be, for `why`: the `failed`-th attempt in a row
        /// that could not ([`FirstArm`]); 1 opens the streak.
        NotArmed { why: String, failed: u32 },
        /// A block held but no longer wanted: a lift that failed earlier,
        /// retried.
        LiftRetried(Result<(), String>),
    }

    /// One pass of the watchdog, under the caller's lock on the chains.
    ///
    /// - `wanted` (the last request was an activation, and the kill switch is
    ///   on) with a generation `live`: read it back ([`missing`]). Whole:
    ///   nothing to do, `None`. Otherwise `rearm` — a fresh generation,
    ///   swapped in like every re-arm — and the new one is read back too.
    /// - `wanted` with NO generation live: the first arm failed (the rule
    ///   build, say), so none ever was. `rearm` puts one up, read back the
    ///   same way (MR-2090: this read nothing, and the session ran without
    ///   its block until a reconnect happened to re-arm it). This call knows
    ///   of no earlier attempt, so it reports `Armed { failed: 0 }` or
    ///   `NotArmed { failed: 1, .. }`; [`FirstArm::pass`] paces the retries
    ///   and counts them.
    /// - not wanted, but still `held`: a lift that failed — the give-up's
    ///   included, which lifts but leaves the intent set (N1 on macOS) — is
    ///   retried through `lift`. The block is never put back then: one that
    ///   somebody removed after we stopped wanting it stays removed.
    /// - not wanted and not held: nothing is read, `None`.
    pub(crate) fn watch(
        x: &impl Xtables,
        wanted: bool,
        held: bool,
        live: Option<&Live>,
        rearm: impl FnOnce() -> Result<Live, String>,
        lift: impl FnOnce() -> Result<(), String>,
    ) -> Option<Watched> {
        if !wanted {
            return held.then(|| Watched::LiftRetried(lift()));
        }
        let Some(live) = live else {
            let armed = rearm().and_then(|now| match missing(x, &now) {
                None => Ok(()),
                Some(still) => Err(format!("armed, but {still} is missing")),
            });
            return Some(match armed {
                Ok(()) => Watched::Armed { failed: 0 },
                Err(why) => Watched::NotArmed { why, failed: 1 },
            });
        };
        let what = missing(x, live)?;
        let restored = rearm().and_then(|now| match missing(x, &now) {
            None => Ok(()),
            Some(still) => Err(format!("re-armed, but {still} is still missing")),
        });
        Some(match restored {
            Ok(()) => Watched::Restored { what },
            Err(why) => Watched::NotRestored { what, why },
        })
    }

    /// MR-2090: the pace at which the watchdog retries a wanted block that
    /// never went up.
    ///
    /// At once on the next pass, then 1, 2 and at most [`Self::MAX_APART`]
    /// passes apart (30 s, 1 min, 2 min): a host where iptables cannot work
    /// at all is not made to rebuild the chains every 30 s for the whole
    /// session, and one that recovers is armed within two minutes. The
    /// attempts of one streak are counted, so only the one that opens it is
    /// reported as an error.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub(crate) struct FirstArm {
        /// Attempts that failed in a row.
        failed: u32,
        /// Passes still to sit out before the next attempt.
        wait: u32,
    }

    impl FirstArm {
        /// The most passes between two attempts.
        pub(crate) const MAX_APART: u32 = 4;

        pub(crate) const fn new() -> Self {
            Self { failed: 0, wait: 0 }
        }

        /// One pass of [`watch`], paced: while the block is wanted and none
        /// of ours is live, a pass that is not due reads nothing and is
        /// `None`. The streak ends whenever there is nothing to put up any
        /// more — the block went up, a generation is live (a reconnect armed
        /// it), or it is no longer wanted.
        pub(crate) fn pass(
            &mut self,
            x: &impl Xtables,
            wanted: bool,
            held: bool,
            live: Option<&Live>,
            rearm: impl FnOnce() -> Result<Live, String>,
            lift: impl FnOnce() -> Result<(), String>,
        ) -> Option<Watched> {
            if wanted && live.is_none() && self.wait > 0 {
                self.wait -= 1;
                return None;
            }
            match watch(x, wanted, held, live, rearm, lift) {
                Some(Watched::NotArmed { why, .. }) => {
                    self.failed = self.failed.saturating_add(1);
                    // 1, 2, 4, 4, ... passes on to the next attempt.
                    let apart = 1u32
                        .checked_shl(self.failed - 1)
                        .unwrap_or(u32::MAX)
                        .min(Self::MAX_APART);
                    self.wait = apart - 1;
                    Some(Watched::NotArmed {
                        why,
                        failed: self.failed,
                    })
                }
                Some(Watched::Armed { .. }) => Some(Watched::Armed {
                    failed: std::mem::take(self).failed,
                }),
                watched => {
                    *self = Self::new();
                    watched
                }
            }
        }
    }

    /// MR-2000: the watchdog's passes in a row that failed — a restore, or an
    /// owed lift, that did not land — so a failure that persists is reported
    /// once, by the pass that opens the streak, and not every 30 s. (A first
    /// arm's streak is [`FirstArm`]'s.)
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub(crate) struct Failing {
        /// What the streak is of: an owed lift (`true`) or a restore.
        lift: bool,
        /// Its passes so far; 0 while there is no streak.
        passes: u32,
    }

    impl Failing {
        /// One pass's outcome. The `n`-th pass in a row that failed the same
        /// way is `n` (1 opens a streak); a pass that did not fail is 0, and
        /// ends the streak. A failure of the other kind opens a streak of
        /// its own: a restore that kept failing, then an owed lift that
        /// fails once the user turned the switch off, is news (reported),
        /// not more of the same.
        pub(crate) fn record(&mut self, watched: Option<&Watched>) -> u32 {
            let lift = match watched {
                Some(Watched::NotRestored { .. }) => false,
                Some(Watched::LiftRetried(Err(_))) => true,
                _ => {
                    *self = Self::default();
                    return 0;
                }
            };
            let passes = if self.passes > 0 && self.lift == lift {
                self.passes.saturating_add(1)
            } else {
                1
            };
            *self = Self { lift, passes };
            passes
        }
    }
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
/// baseline, a tunnel interface change, the startup cleanup (which takes it
/// before anything else can). One writer does NOT take it: the panic hook in
/// main.rs restores `/etc/pf.conf` as the process dies, and another thread may
/// be mid-load right then, so the two can interleave (N11). The process is
/// going down either way; what is left is the next start's cleanup to remove,
/// and our pf reference is released there from the journal if the hook could
/// not take the lock to release it.
#[cfg(target_os = "macos")]
static PF: tokio::sync::Mutex<PfState> = tokio::sync::Mutex::const_new(PfState::new());

/// `PfState::enforcing` for the lock-free status probe: pf is running our
/// block-all, or cannot be read (which counts as still blocking).
#[cfg(target_os = "macos")]
static PF_BLOCKING: AtomicBool = AtomicBool::new(false);

/// `PfState::loaded`: a block-all of ours is (or may be) loaded — a lift is owed.
#[cfg(target_os = "macos")]
static PF_LOADED: AtomicBool = AtomicBool::new(false);

/// The control-plane generation a connection gets through with (N5):
/// `u64::MAX` while no block-all is loaded.
#[cfg(target_os = "macos")]
static PF_PERMITTED_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

#[cfg(target_os = "macos")]
fn mirror(state: &PfState) {
    PF_BLOCKING.store(state.enforcing, Ordering::SeqCst);
    PF_LOADED.store(state.loaded, Ordering::SeqCst);
    PF_PERMITTED_GEN.store(
        if state.loaded {
            state.table_gen
        } else {
            u64::MAX
        },
        Ordering::SeqCst,
    );
}

/// macOS: whether control-plane addresses of `generation` already get
/// through — the resolver's lock-free fast path (N5).
#[cfg(target_os = "macos")]
pub fn control_plane_permits(generation: u64) -> bool {
    PF_PERMITTED_GEN.load(Ordering::SeqCst) >= generation
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
    fn take_ref(&self) -> Result<pf_policy::Taken, String> {
        let child = crate::utils::hidden_cmd("pfctl")
            .args(["-E"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("pfctl -E could not run: {e}"))?;
        // The pid `pfctl -s References` lists the reference under (N4).
        let pid = child.id();
        let out = child
            .wait_with_output()
            .map_err(|e| format!("pfctl -E: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "pfctl -E failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        // The token is printed (on stderr, measured) after "pf enabled";
        // read both streams.
        let printed = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(pf_policy::Taken {
            token: pf_policy::parse_token(&printed),
            pid,
        })
    }
    fn references(&self) -> Result<String, String> {
        pfctl(&["-s", "References"])
    }
    fn release_ref(&self, token: u64) -> Result<(), String> {
        pfctl(&["-X", &token.to_string()]).map(drop)
    }
    fn record_reference(&self, held: Option<pf_policy::PfRef>) {
        pf_reference_journal::write(held);
    }
}

/// N3: the pf reference we hold, on disk. XNU frees a token only on `pfctl -X`
/// or `pfctl -d` — never when the process that took it exits — so a crash
/// mid-session (every session holds one for the IPv6 block) kept pf enabled
/// for good. The next start releases what this names.
///
/// MR-2089: root-only, in the state directory `utils::root_state` keeps
/// (`/var/db/birdovpn`), mode 0600 from creation. It used to be in
/// `dirs::data_dir()`, the USER's Application Support whenever the launch
/// kept HOME, where root wrote it by path and through any link at the name.
#[cfg(target_os = "macos")]
mod pf_reference_journal {
    use crate::utils::root_state;
    use crate::vpn::pf_policy::{self, PfRef};

    const RECORD_FILE: &str = "pf-reference";

    fn path() -> Option<std::path::PathBuf> {
        let dir = std::path::Path::new(root_state::STATE_DIR);
        if let Err(e) = root_state::ensure_private_dir(dir) {
            tracing::warn!("pf reference journal: no root-only directory ({e})");
            return None;
        }
        let path = dir.join(RECORD_FILE);
        adopt_legacy_once(&path);
        Some(path)
    }

    /// Take over, once per process, the record an older build left in
    /// `<data_dir>/BirdoVPN`: only one root wrote (`root_state::adopt_legacy`).
    fn adopt_legacy_once(path: &std::path::Path) {
        use std::sync::atomic::{AtomicBool, Ordering};
        static TRIED: AtomicBool = AtomicBool::new(false);
        if TRIED.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(base) = dirs::data_dir() else {
            return;
        };
        root_state::adopt_legacy(
            &base.join("BirdoVPN"),
            RECORD_FILE,
            path,
            |bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(pf_policy::decode_reference)
                    .is_some()
            },
            write_atomically,
        );
    }

    /// Replace the record with `held` (or remove it), staged and renamed so a
    /// crash leaves the old record or the new one, never half of one.
    pub(super) fn write(held: Option<PfRef>) {
        let Some(path) = path() else {
            return;
        };
        let written = match held {
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
            Some(held) => write_atomically(&path, pf_policy::encode_reference(held).as_bytes()),
        };
        if let Err(e) = written {
            tracing::warn!("pf reference journal not updated: {e}");
        }
    }

    /// The staging file is created NEW (O_EXCL|O_NOFOLLOW), mode 0600 from
    /// the start: never opened through a link at its name (MR-2089).
    fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let staging = path.with_extension("tmp");
        let mut f = root_state::create_new_private(&staging)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&staging, path)
    }

    /// What a previous run left, if anything: read without following a link,
    /// and only from a file that only we can write.
    pub(super) fn read() -> Option<PfRef> {
        use std::io::Read;
        let mut text = String::new();
        root_state::open_private(&path()?)
            .ok()?
            .take(4096)
            .read_to_string(&mut text)
            .ok()?;
        pf_policy::decode_reference(&text)
    }

    /// MR-2089: root never writes through a link planted on the staging name,
    /// and the record is owner-only from creation. tests.yml runs this
    /// unprivileged on macOS.
    #[cfg(test)]
    mod root_write_tests {
        use super::write_atomically;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn a_link_on_the_staging_name_is_not_written_through() {
            let dir = tempfile::tempdir().unwrap();
            let victim = dir.path().join("victim");
            std::fs::write(&victim, "not the record's").unwrap();
            let path = dir.path().join("pf-reference");
            std::os::unix::fs::symlink(&victim, path.with_extension("tmp")).unwrap();

            write_atomically(&path, b"1 2").unwrap();

            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "not the record's"
            );
            let meta = std::fs::symlink_metadata(&path).unwrap();
            assert!(
                meta.is_file(),
                "the record is a file of its own, not the link"
            );
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::read(&path).unwrap(), b"1 2");
        }
    }
}

/// N3: the panic hook's share — drop our pf reference now, if the lock is
/// free. A panic while it is held leaves the reference to the journal, which
/// the next start releases.
#[cfg(target_os = "macos")]
pub fn release_pf_reference_now() {
    if let Ok(mut pf) = PF.try_lock() {
        pf.release_reference(&Pfctl);
        mirror(&pf);
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
    // N6: the leak block is watched too, kill switch on or off.
    ensure_pf_watchdog();
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
    pf.ipv6_off(&Pfctl, false);
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
/// of a reboot. `PfState::reconcile` decides what to do and records only what pf
/// reads back afterwards (N8); only rulesets carrying OUR marker are touched, so
/// a third party's pf configuration is never clobbered. Runs at startup, before
/// anything else can take the lock.
#[cfg(target_os = "macos")]
pub fn reconcile_stale_pf_state() {
    let Ok(mut pf) = PF.try_lock() else {
        tracing::error!("Kill switch state is locked at startup; stale pf state not reconciled");
        return;
    };
    let reconciled = pf.reconcile(&Pfctl);
    // N3: the pf reference a crashed earlier run left behind. Released only if
    // pf still lists it as that run's — token AND pid.
    if let Some(leftover) = pf_reference_journal::read() {
        match pf.release_leftover(&Pfctl, leftover) {
            Ok(()) => tracing::warn!("Released the pf reference a previous run left behind"),
            Err(e) => tracing::warn!(
                "The pf reference a previous run left behind was not released ({}); \
                 retried at the next start",
                e
            ),
        }
    }
    match reconciled {
        None => {}
        Some(Ok(())) => {
            tracing::warn!("Found a stale Birdo pf ruleset from a previous run — removed")
        }
        Some(Err(e)) => {
            tracing::error!(
                "Stale Birdo pf ruleset NOT removed: {}. Retried every {}s; \
                 `sudo pfctl -f /etc/pf.conf` clears it manually.",
                e,
                PF_WATCHDOG_INTERVAL.as_secs()
            );
            ensure_pf_watchdog();
        }
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
    let (control_plane, control_plane_gen) = pf_policy::control_plane();
    let inputs = pf_policy::Inputs {
        relay: vpn_server_ip(),
        control_plane,
        control_plane_gen,
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
    let (loaded, wanted) = (pf.loaded, pf.wanted);
    let outcome = pf.watchdog(
        &Pfctl,
        pf_inputs,
        crate::api::doh_resolver::control_plane_generation(),
    );
    mirror(&pf);
    drop(pf);
    let Some(result) = outcome else {
        return;
    };
    match result {
        Ok(()) if !loaded => tracing::warn!(
            "Kill switch watchdog: something else had disabled or replaced the IPv6 leak block; restored"
        ),
        Ok(()) if wanted => tracing::warn!(
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

/// [`tunnel_interface_down`] for `Drop`, which cannot await, followed by
/// `close` — always in that order (P3-4). In place when the lock is free;
/// otherwise the re-load AND the close are handed to the runtime, so the device
/// stays open until its permit has left the block, never the other way round.
#[cfg(target_os = "macos")]
pub fn tunnel_interface_gone_then(name: &str, close: impl FnOnce() + Send + 'static) {
    match PF.try_lock() {
        Ok(mut pf) => {
            let inputs = pf_inputs();
            if let Err(e) = pf.tunnel_down(&Pfctl, &inputs, name) {
                tracing::warn!("Kill switch: re-loading the block without {}: {}", name, e);
            }
            mirror(&pf);
            drop(pf);
            close();
        }
        Err(_) => {
            let name = name.to_string();
            tauri::async_runtime::spawn(async move {
                tunnel_interface_down(&name).await;
                close();
            });
        }
    }
}

/// macOS: the kill switch turned off (N2) — see `PfState::lift_if_loaded`.
#[cfg(target_os = "macos")]
async fn pf_lift_if_loaded() -> Result<bool, String> {
    let mut pf = PF.lock().await;
    let result = pf.lift_if_loaded(&Pfctl);
    mirror(&pf);
    result
}

/// macOS: a DoH answer brought control-plane addresses of `generation` that
/// the held block's table does not cover (P2-4, N5). The block is re-loaded
/// NOW, before the resolver caches or hands them out; `Err` makes it cache
/// nothing, and the watchdog retries by generation.
#[cfg(target_os = "macos")]
pub async fn control_plane_learned(generation: u64) -> Result<(), String> {
    let mut pf = PF.lock().await;
    let result = pf.control_plane_learned(&Pfctl, pf_inputs, generation);
    mirror(&pf);
    drop(pf);
    match &result {
        Ok(()) => tracing::info!("Kill switch: control-plane table covers the new address"),
        Err(e) => tracing::warn!(
            "Kill switch: re-loading the control-plane table failed: {}",
            e
        ),
    }
    blocking_may_have_changed();
    result
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

    /// Every test that writes `KILLSWITCH_ENABLED` holds this, so one test's
    /// armed intent is never another's precondition.
    static FLAG_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn lift_into(
        lifted: &'static AtomicBool,
    ) -> impl Fn() -> std::future::Ready<Result<bool, String>> {
        move || {
            lifted.store(true, Ordering::SeqCst);
            std::future::ready(Ok(true))
        }
    }

    /// F3: an OFF preference must clear a stale armed intent (left by the
    /// auto-reconnect give-up branch, which lifts the block but never clears
    /// the flag), or the next user connect's drop blocks against the
    /// preference and (Unix) `holds_block_while_connected()` keeps the
    /// block-all engaged for the rest of the session.
    #[tokio::test]
    async fn arm_with_preference_off_clears_stale_armed_intent() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        assert!(
            is_enabled(),
            "precondition: intent armed by a previous session"
        );

        let armed = arm_with_preference(false, intent_seq()).await.unwrap();

        assert!(!armed, "preference OFF must not arm");
        assert!(
            !is_enabled(),
            "preference OFF must clear KILLSWITCH_ENABLED, or the steady-state block is held against the user's setting"
        );
        // Idempotent from the cleared state too.
        assert_eq!(arm_with_preference(false, intent_seq()).await, Ok(false));
        assert!(!is_enabled());
    }

    /// Review of #259: a control-plane address DoH learns while a Linux block
    /// is up is let through by a re-arm BEFORE the resolver may cache it.
    #[tokio::test]
    async fn a_learned_address_is_re_armed_in_before_it_is_cached() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        let rearmed = AtomicBool::new(false);
        let lifted = AtomicBool::new(false);

        let result = learn_control_plane(
            || async {
                rearmed.store(true, Ordering::SeqCst);
                Ok(true)
            },
            || async {
                lifted.store(true, Ordering::SeqCst);
                Ok(true)
            },
            || std::future::ready(Ok(true)),
            || true,
            || rearmed.load(Ordering::SeqCst),
            || false,
        )
        .await;

        assert_eq!(result, Ok(()));
        assert!(
            rearmed.load(Ordering::SeqCst),
            "the live block was re-armed"
        );
        assert!(
            !lifted.load(Ordering::SeqCst),
            "a wanted block is not lifted"
        );
    }

    /// A re-arm that failed, or one that left the address uncovered, keeps
    /// the resolver from caching it: the next request asks again.
    #[tokio::test]
    async fn an_address_the_block_does_not_cover_is_not_cached() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);

        let failed = learn_control_plane(
            || std::future::ready(Err("iptables failed".to_string())),
            || std::future::ready(Ok(true)),
            || std::future::ready(Ok(true)),
            || true,
            || false,
            || false,
        )
        .await;
        assert_eq!(failed, Err("iptables failed".to_string()));

        let uncovered = learn_control_plane(
            || std::future::ready(Ok(true)),
            || std::future::ready(Ok(true)),
            || std::future::ready(Ok(true)),
            || true,
            || false,
            || false,
        )
        .await;
        assert!(uncovered.is_err(), "{uncovered:?}");
    }

    /// Review of #259 (L2): on a host where no self-permit loads (no
    /// `-m owner`), the address is not permitted either way, so the resolver
    /// may cache it — or api.birdo.app would never resolve, even connected.
    #[tokio::test]
    async fn a_host_without_self_permits_still_caches_the_address() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        let result = learn_control_plane(
            || std::future::ready(Ok(true)),
            || std::future::ready(Ok(true)),
            || std::future::ready(Ok(true)),
            || true,
            || false,
            || true,
        )
        .await;
        assert_eq!(result, Ok(()));
    }

    /// The intent rules here too: a block the user turned off is lifted, not
    /// re-armed around the new address.
    #[tokio::test]
    async fn a_learned_address_lifts_a_block_the_user_turned_off() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
        let rearmed = AtomicBool::new(false);
        let lifted = AtomicBool::new(false);

        let result = learn_control_plane(
            || async {
                rearmed.store(true, Ordering::SeqCst);
                Ok(true)
            },
            || async {
                lifted.store(true, Ordering::SeqCst);
                Ok(true)
            },
            || std::future::ready(Ok(true)),
            || !lifted.load(Ordering::SeqCst),
            || lifted.load(Ordering::SeqCst),
            || false,
        )
        .await;

        assert_eq!(result, Ok(()));
        assert!(
            !rearmed.load(Ordering::SeqCst),
            "no re-arm against the intent"
        );
        assert!(
            lifted.load(Ordering::SeqCst),
            "the unwanted block is lifted"
        );
    }

    /// Proposed row 1 (MR-734): Kill Switch OFF lands while a reconnect
    /// attempt's block is still going up. The OFF finds no block yet, so the
    /// activation that committed after it must lift the block itself, and
    /// report that none is held.
    #[tokio::test]
    async fn an_off_that_lands_while_the_block_goes_up_lifts_it() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        let lifted = AtomicBool::new(false);

        let result = unless_turned_off(
            async {
                // The firewall load is in flight; set_killswitch_live(false)
                // clears the intent and sees nothing to lift.
                KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
                Ok(true)
            },
            || async {
                lifted.store(true, Ordering::SeqCst);
                Ok(true)
            },
            || std::future::ready(Ok(true)),
            || true,
        )
        .await;

        assert_eq!(result, Ok(false), "a block the user turned off is not held");
        assert!(
            lifted.load(Ordering::SeqCst),
            "the block that committed after the OFF must be lifted"
        );
    }

    /// The re-check lifts only what the user turned off: an intent still on
    /// keeps its block, and with nothing up there is nothing to lift (and
    /// nothing failed that the user still wants).
    #[tokio::test]
    async fn the_recheck_lifts_nothing_the_user_still_wants() {
        let _tests = FLAG_TESTS.lock().await;

        static KEPT: AtomicBool = AtomicBool::new(false);
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        let kept = unless_turned_off(
            async { Ok(true) },
            lift_into(&KEPT),
            || std::future::ready(Ok(true)),
            || true,
        );
        assert_eq!(kept.await, Ok(true));
        assert!(
            !KEPT.load(Ordering::SeqCst),
            "the switch is on: the block stays"
        );
        let failed = unless_turned_off(
            async { Err("load failed".into()) },
            lift_into(&KEPT),
            || std::future::ready(Ok(true)),
            || true,
        );
        assert_eq!(
            failed.await,
            Err("load failed".to_string()),
            "still wanted: reported"
        );

        static NOTHING_UP: AtomicBool = AtomicBool::new(false);
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
        let skipped = unless_turned_off(
            async { Ok(false) },
            lift_into(&NOTHING_UP),
            || std::future::ready(Ok(true)),
            || false,
        );
        assert_eq!(skipped.await, Ok(false));
        let moot = unless_turned_off(
            async { Err("load failed".into()) },
            lift_into(&NOTHING_UP),
            || std::future::ready(Ok(true)),
            || false,
        );
        assert_eq!(
            moot.await,
            Ok(false),
            "off, and nothing up: nothing to report"
        );
        assert!(!NOTHING_UP.load(Ordering::SeqCst));
    }

    /// Review of #222 (P3.1): intent OFF plus a block up means lift, whatever
    /// the engage reported. A partial iptables load answers an error with its
    /// chains in place; a rebuild around a new relay or tunnel LUID engages
    /// nothing new. The old re-check looked at what the engage reported, and
    /// left both up.
    #[tokio::test]
    async fn an_off_with_a_block_up_lifts_it_whatever_the_engage_reported() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);

        static AFTER_ERROR: AtomicBool = AtomicBool::new(false);
        let partial = unless_turned_off(
            async { Err("ip6tables hook failed".into()) },
            lift_into(&AFTER_ERROR),
            || std::future::ready(Ok(true)),
            || true,
        );
        assert_eq!(partial.await, Ok(false));
        assert!(
            AFTER_ERROR.load(Ordering::SeqCst),
            "the partial block is lifted"
        );

        static REBUILT: AtomicBool = AtomicBool::new(false);
        let rebuilt = unless_turned_off(
            async { Ok(false) },
            lift_into(&REBUILT),
            || std::future::ready(Ok(true)),
            || true,
        );
        assert_eq!(rebuilt.await, Ok(false));
        assert!(
            REBUILT.load(Ordering::SeqCst),
            "the rebuilt block is lifted"
        );
    }

    /// Review of #222 (P3.2): OFF, then ON, both inside one activation's
    /// load: the re-check sees the OFF and lifts, and the ON lands while the
    /// lift runs — its own block may already have gone up and come down with
    /// it. The re-check reads the intent again after the lift and gives the
    /// ON its block back. (No lock across the lift: round 3.)
    #[tokio::test]
    async fn an_on_that_lands_during_the_lift_gets_its_block_back() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        static REENGAGED: AtomicBool = AtomicBool::new(false);

        let result = unless_turned_off(
            async {
                KILLSWITCH_ENABLED.store(false, Ordering::SeqCst); // the OFF
                Ok(true)
            },
            || async {
                KILLSWITCH_ENABLED.store(true, Ordering::SeqCst); // the ON, mid-lift
                Ok(true)
            },
            || {
                REENGAGED.store(true, Ordering::SeqCst);
                std::future::ready(Ok(true))
            },
            || true,
        )
        .await;

        assert_eq!(result, Ok(true), "the ON's block is up");
        assert!(
            REENGAGED.load(Ordering::SeqCst),
            "the lift took the ON's block"
        );
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
    }

    /// Round 4 of the review (P3-5): OFF, ON and OFF again inside one window
    /// — the lift lets an ON in, the re-engage lets an OFF in. The intent and
    /// the block are compared until they agree: here both end off. Round 3
    /// compared once and returned with the re-engaged block up and the
    /// intent off.
    #[tokio::test]
    async fn the_intent_and_the_block_agree_after_off_on_off() {
        let _tests = FLAG_TESTS.lock().await;
        static BLOCK_UP: AtomicBool = AtomicBool::new(false);
        static LIFTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);

        let result = unless_turned_off(
            async {
                BLOCK_UP.store(true, Ordering::SeqCst);
                KILLSWITCH_ENABLED.store(false, Ordering::SeqCst); // OFF during the load
                Ok(true)
            },
            || {
                BLOCK_UP.store(false, Ordering::SeqCst);
                if LIFTS.fetch_add(1, Ordering::SeqCst) == 0 {
                    KILLSWITCH_ENABLED.store(true, Ordering::SeqCst); // ON during the lift
                }
                std::future::ready(Ok(true))
            },
            || {
                BLOCK_UP.store(true, Ordering::SeqCst);
                KILLSWITCH_ENABLED.store(false, Ordering::SeqCst); // OFF during the re-engage
                std::future::ready(Ok(true))
            },
            || BLOCK_UP.load(Ordering::SeqCst),
        )
        .await;

        assert_eq!(result, Ok(false));
        assert!(!is_enabled());
        assert!(
            !BLOCK_UP.load(Ordering::SeqCst),
            "intent off, and the block left up"
        );
        assert_eq!(LIFTS.load(Ordering::SeqCst), 2);
    }

    /// Review of #222 (P3.3): the toggle turned OFF during `connecting`, while
    /// `arm` was still reading the ON it would store. The OFF bumps the
    /// intent's sequence; `arm` stores ON only if it has not moved since its
    /// read began, so the OFF wins.
    #[tokio::test]
    async fn an_off_during_arms_read_wins() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);

        let seen = intent_seq();
        intent_off(); // the OFF lands while arm reads the preference
        assert!(!intent_on_since(seen), "a stale ON is not stored");
        assert!(!is_enabled(), "the OFF must be the last word");

        assert!(
            intent_on_since(intent_seq()),
            "with no OFF since, the ON is stored"
        );
        assert!(is_enabled());
        intent_off();

        // And `arm_since` stores through intent_on_since, with a sequence its
        // callers read before the preference (the dial at its start, the
        // live ON before its session check: source checks in `session` and
        // below). Its ON store needs an elevated host, so this half is a
        // source check.
        let source = include_str!("killswitch.rs").replace('\r', "");
        let read = &source[source.find("async fn arm_reading_since(").unwrap()..];
        let read = &read[..read.find("\n}\n").unwrap()];
        assert!(read.contains("arm_with_preference(enabled, seen)"));
        let arm = &source[source.find("async fn arm_with_preference(").unwrap()..];
        assert!(arm.contains("if !intent_on_since(seen) {"));
    }

    /// Round 6 of the review (P3-1): with the sequence from the dial's start,
    /// an OFF the user made during the dial makes the dial's arm stand aside.
    /// (That the dial passes it is checked in `session`.)
    #[tokio::test]
    async fn an_off_during_the_dial_makes_its_arm_stand_aside() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
        let dial_began = intent_seq();
        turn_off(|| std::future::ready(Ok(true)), || false)
            .await
            .unwrap();
        assert_eq!(
            arm_reading_since(dial_began, std::future::ready(true)).await,
            Ok(false)
        );
        assert!(!is_enabled(), "the dial's arm stood aside");
    }

    /// Round 4 of the review (P3-6): an `arm` that read the preference OFF
    /// does not clear an ON stored after its read began — the ON is newer.
    /// The sequence moves on ON too, and the preference-OFF is conditional
    /// on it; the user's own OFF (`intent_off`) still always wins.
    #[tokio::test]
    async fn a_stale_off_preference_never_clears_a_newer_on() {
        let _tests = FLAG_TESTS.lock().await;
        intent_off();
        let seen = intent_seq(); // this arm starts reading the preference
        assert!(
            intent_on_since(intent_seq()),
            "a newer arm stores ON meanwhile"
        );

        assert_eq!(arm_with_preference(false, seen).await, Ok(false));
        assert!(is_enabled(), "the stale OFF read cleared the newer ON");

        assert!(intent_off(), "the user's OFF wins whatever was read");
        assert!(!is_enabled());

        // And the live ON reads the sequence before its session check, and
        // arm checks it before opening the engine. (Both need a Tauri State
        // or an elevated host: source checks.)
        let source = include_str!("killswitch.rs").replace('\r', "");
        let live = &source[source.find("pub async fn set_killswitch_live(").unwrap()..];
        assert!(
            live.find("let seen = intent_seq();").unwrap() < live.find(".get_state()").unwrap()
        );
        let arm = &source[source.find("async fn arm_with_preference(").unwrap()..];
        let check = arm
            .find("if intent_seq() != seen {")
            .expect("checked before the engine");
        assert!(check < arm.find("wfp::initialize()").unwrap());
    }

    /// MR-2110: the arm's engine open fails (the injected `wfp::initialize`
    /// error) with the preference ON. The intent stays ON, so the block the
    /// next teardown asks for is reported as failed rather than as "no block
    /// wanted", and the teardown rule (`reconnect_policy::teardown_covered`,
    /// MR-2071) holds the tunnel. The arm used to return before storing the
    /// intent: `Ok(false)`, and the teardown went ahead with nothing blocking.
    #[tokio::test]
    async fn a_failed_engine_open_keeps_the_kill_switch_on() {
        use crate::vpn::reconnect_policy::{killswitch_failed_error, teardown_covered};
        let _tests = FLAG_TESTS.lock().await;
        let not_opened = || {
            std::future::ready(Err::<(), String>(
                "FwpmEngineOpen0 failed: 0x800706D9".into(),
            ))
        };
        intent_off();

        let opened = open_engine(not_opened(), intent_seq()).await;
        assert_eq!(
            opened,
            Err(
                "Failed to initialize kill-switch firewall: FwpmEngineOpen0 failed: 0x800706D9"
                    .into()
            ),
            "the arm still fails, and says why"
        );
        assert!(
            is_enabled(),
            "the preference is ON: a failed engine open must not leave the intent OFF"
        );

        // What a reconnect teardown, a dial and a failed connect then ask for
        // (`activate_killswitch`, through `unless_turned_off`): with no engine
        // the platform refuses (`wfp::activate_blocking`), nothing is up, and
        // that refusal is the answer, so the tunnel is held.
        let engaged = unless_turned_off(
            std::future::ready(Err(
                "Failed to activate blocking: Kill switch not initialized".into(),
            )),
            || std::future::ready(Ok(true)),
            || std::future::ready(Ok(true)),
            || false,
        )
        .await;
        assert!(engaged.is_err(), "{engaged:?}");
        assert_eq!(
            teardown_covered(&engaged, false),
            Err(killswitch_failed_error()),
            "the teardown must be held, not let through as if no block were wanted"
        );

        // An OFF (or a Disconnect) since the preference was read still wins.
        intent_off();
        let seen = intent_seq();
        intent_off();
        assert!(open_engine(not_opened(), seen).await.is_err());
        assert!(!is_enabled(), "a stale ON is not stored");

        // An engine that opens stores nothing here: the arm's own
        // `intent_on_since(seen)` does, after it.
        let seen = intent_seq();
        assert_eq!(open_engine(std::future::ready(Ok(())), seen).await, Ok(()));
        assert!(!is_enabled());
        assert_eq!(intent_seq(), seen);
    }

    /// MR-2110: the arm opens its engine through [`open_engine`] (Windows),
    /// ahead of its own ON, and a failure there drops lockdown for the session,
    /// as a lockdown activation that fails does. (The arm's ON path needs an
    /// elevated host: a source check.)
    #[test]
    fn the_arm_opens_its_engine_through_the_step_that_keeps_the_intent() {
        let source = include_str!("killswitch.rs").replace('\r', "");
        let arm = &source[source.find("async fn arm_with_preference(").unwrap()..];
        let arm = &arm[..arm.find("\n}\n").unwrap()];
        let open = arm
            .find("if let Err(e) = open_engine(wfp::initialize(), seen).await {")
            .expect("the engine is opened through open_engine");
        let degrade = arm[open..]
            .find("wfp::set_lockdown_mode(false);\n        return Err(e);")
            .expect("a failed open drops lockdown, then fails the arm");
        assert!(open + degrade < arm.find("if !intent_on_since(seen) {").unwrap());
        assert_eq!(arm.matches("wfp::initialize()").count(), 1);
        assert!(!arm.contains(".map_err(|e| format!(\"Failed to initialize kill-switch firewall"));
    }

    /// Round 3 of the review (P2-1): a settings read that never returns (a
    /// hung credential store, a `schtasks` holding the settings lock) must not
    /// hold up `disarm`, the Disconnect escape. Round 2's `arm` held an async
    /// lock across that read, and `disarm` waited on the same lock for good.
    #[tokio::test(flavor = "current_thread")]
    async fn a_hung_settings_read_never_holds_up_disarm() {
        let _tests = FLAG_TESTS.lock().await;
        let arming = arm_reading_since(intent_seq(), std::future::pending::<bool>());
        let disarming = async {
            tokio::task::yield_now().await; // arm is inside its read now
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                disarm_with(std::future::ready(Ok(()))),
            )
            .await
        };
        tokio::select! {
            _ = arming => panic!("the read never completes"),
            done = disarming => assert_eq!(done, Ok(Ok(())), "disarm waited on arm's read"),
        }
        assert!(!is_enabled());
    }

    /// The invariant [`INTENT`] documents: outside the tests, the intent is
    /// written only by `intent_off` and `intent_on_since`, under the lock.
    #[test]
    fn the_intent_is_written_only_under_its_lock() {
        let source = include_str!("killswitch.rs").replace('\r', "");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];
        let writes: Vec<usize> = ["KILLSWITCH_ENABLED.store(", "KILLSWITCH_ENABLED.swap("]
            .iter()
            .flat_map(|w| code.match_indices(w).map(|(at, _)| at))
            .collect();
        assert_eq!(writes.len(), 3, "one store in each writer");
        for at in writes {
            let owner = code[..at].rfind("\nfn ").unwrap();
            let name = &code[owner + 4..code[owner..].find('(').unwrap() + owner];
            assert!(
                ["intent_off", "intent_on_since", "intent_off_since"].contains(&name),
                "written in {name}"
            );
            assert!(
                code[owner..at].contains("INTENT.lock()"),
                "{name} writes unlocked"
            );
        }
    }

    /// Review of #222 (P3.1): a live OFF whose lift fails says so. It used to
    /// be dropped and the OFF reported as applied, with the block still up.
    #[tokio::test]
    async fn an_off_whose_lift_fails_says_so() {
        let _tests = FLAG_TESTS.lock().await;
        KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
        let off = turn_off(
            || std::future::ready(Err("WFP transaction failed".into())),
            || true,
        );
        assert_eq!(off.await, Err("WFP transaction failed".to_string()));
        assert!(!is_enabled(), "the intent is cleared either way");

        assert_eq!(
            turn_off(|| std::future::ready(Ok(true)), || false).await,
            Ok(true)
        );
    }

    /// Proposed row 1 (MR-734): an OFF is applied in every state. v1.4.45 sat
    /// in `disconnected` between reconnect attempts and this command returned
    /// before clearing anything; #220 keeps the gap in `reconnecting`, and
    /// this pins the other half — the session gate guards ON only, so an OFF
    /// with the block up and no session (the case the UI sends,
    /// `killSwitchLiveApplies`) is not saved and dropped.
    #[test]
    fn an_off_is_not_gated_on_a_live_session() {
        // A Windows checkout has CRLF endings (core.autocrlf).
        let source = include_str!("killswitch.rs").replace('\r', "");
        let live = &source[source.find("pub async fn set_killswitch_live(").unwrap()..];
        let live = &live[..live.find("\n}\n").unwrap()];
        let off = live
            .find("turn_off(deactivate_killswitch, platform_is_blocking)")
            .expect("the OFF clears the intent and lifts");
        let gate = live
            .find("no active session")
            .expect("ON still waits for a session");
        let on = live.find("if enabled {").expect("ON branch");
        let off_branch = live.find("} else {").expect("OFF branch");
        assert!(
            on < gate && gate < off_branch && off_branch < off,
            "the no-session return must sit inside the ON branch, never ahead of the OFF"
        );
    }

    /// Row 1: every block-all goes up through this module, where the intent
    /// is read before the load and re-read after it ([`unless_turned_off`]).
    /// The backends are scanned too, except wfp.rs, whose functions are the
    /// ones named here.
    /// The lockdown re-bake in tunnel.rs called `wfp::activate_blocking`
    /// directly, so an OFF that lifted the block just before it ran was
    /// undone for the rest of the session.
    #[test]
    fn no_block_all_is_engaged_around_the_intent() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![root.clone()];
        let mut offenders = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                // The backends themselves, and this module.
                if !rel.ends_with(".rs")
                    || ["commands/killswitch.rs", "vpn/wfp.rs"].contains(&rel.as_str())
                {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                // Review of #222 (P3.4): Linux re-armed around a new relay
                // through firewall_linux::update_vpn_server, which re-loaded
                // the block with no look at the intent.
                for call in [
                    "wfp::activate_blocking(",
                    "firewall_linux::activate_blocking(",
                    "firewall_linux::refresh_control_plane(",
                    "firewall_linux::rearm_if_up(",
                    "update_vpn_server(",
                ] {
                    if text.contains(call) {
                        offenders.push(format!("{rel}: {call}"));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "engaged around the intent: {offenders:?}"
        );
    }

    // ── MR-833: the Linux watchdog, against a scripted iptables ─────────

    use iptables_watchdog::{
        block_may_be_up, missing, rules_of, still_installed, watch, Failing, FirstArm, Live, Probe,
        Watched, Xtables,
    };
    use std::cell::{Cell, RefCell, RefMut};
    use std::collections::BTreeMap;

    const BUILT_IN: [&str; 3] = ["OUTPUT", "INPUT", "FORWARD"];

    /// iptables as the kernel holds it, one filter table per family: every
    /// chain's rules in order, the built-in OUTPUT/INPUT/FORWARD included. It
    /// answers the one read the watchdog makes — `-S <chain>`, built-in
    /// chains included — with iptables' own exit status and listing, and
    /// fails the test on anything else: the watchdog only reads. What other
    /// tools do to the tables are its methods (the twin of pf_policy's
    /// `FakePf`).
    struct FakeXtables {
        /// [IPv4, IPv6].
        tables: RefCell<[BTreeMap<String, Vec<String>>; 2]>,
        /// The host has no ip6tables at all.
        no_ip6tables: bool,
        /// How many commands the watchdog ran.
        runs: Cell<u32>,
    }

    impl FakeXtables {
        fn new() -> Self {
            let built_in = || {
                BUILT_IN
                    .iter()
                    .map(|hook| (hook.to_string(), Vec::new()))
                    .collect::<BTreeMap<_, _>>()
            };
            Self {
                tables: RefCell::new([built_in(), built_in()]),
                no_ip6tables: false,
                runs: Cell::new(0),
            }
        }

        fn table(&self, v6: bool) -> RefMut<'_, BTreeMap<String, Vec<String>>> {
            RefMut::map(self.tables.borrow_mut(), |t| &mut t[usize::from(v6)])
        }

        /// What `firewall_linux::activate_locked` leaves in the kernel:
        /// generation `gen` built from the policy's own rules and hooked at
        /// the top of each built-in chain, then `retire` unhooked and deleted.
        fn arm(&self, gen: u8, retire: Option<&Live>) -> Live {
            use crate::vpn::iptables_policy::{block_all, BlockAll};
            let control = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(104, 16, 0, 1)];
            let chains = block_all(&BlockAll {
                relay: Some(Ipv4Addr::new(203, 0, 113, 7)),
                control_plane: &control,
                euid: 0,
                lan_sharing: false,
            });
            let (out, inn) = (format!("BIRDO_KS_OUT{gen}"), format!("BIRDO_KS_IN{gen}"));
            let mut families = vec![(false, &chains.out_v4, &chains.in_v4)];
            if !self.no_ip6tables {
                families.push((true, &chains.out_v6, &chains.in_v6));
            }
            let text = |rules: &Vec<Vec<String>>| -> Vec<String> {
                rules.iter().map(|r| r.join(" ")).collect()
            };
            for (v6, out_rules, in_rules) in families {
                let mut table = self.table(v6);
                table.insert(out.clone(), text(out_rules));
                table.insert(inn.clone(), text(in_rules));
                for (hook, chain) in [("OUTPUT", &out), ("INPUT", &inn), ("FORWARD", &inn)] {
                    table
                        .get_mut(hook)
                        .unwrap()
                        .insert(0, format!("-j {chain}"));
                }
                if let Some(old) = retire {
                    let jumps = [format!("-j {}", old.out), format!("-j {}", old.inn)];
                    for hook in BUILT_IN {
                        table.get_mut(hook).unwrap().retain(|r| !jumps.contains(r));
                    }
                    table.remove(&old.out);
                    table.remove(&old.inn);
                }
            }
            // What iptables lists once they are loaded: the fake lists the
            // text it was given.
            Live {
                out,
                inn,
                v4: (text(&chains.out_v4), text(&chains.in_v4)),
                v6: (!self.no_ip6tables).then(|| (text(&chains.out_v6), text(&chains.in_v6))),
            }
        }

        /// Another tool's `iptables -F` (`ip6tables -F` with `v6`): every
        /// chain of the filter table emptied — our jumps and our rules — while
        /// our chains themselves stay.
        fn flush_all(&self, v6: bool) {
            self.table(v6).values_mut().for_each(Vec::clear);
        }

        /// ...and the `iptables -X` that usually follows: every user chain,
        /// empty and unreferenced by now, deleted.
        fn delete_user_chains(&self, v6: bool) {
            self.table(v6)
                .retain(|name, _| BUILT_IN.contains(&name.as_str()));
        }

        /// `iptables -F <chain>`.
        fn flush(&self, v6: bool, chain: &str) {
            self.table(v6).get_mut(chain).unwrap().clear();
        }

        /// `iptables -D <hook> -j <chain>`.
        fn unhook(&self, v6: bool, hook: &str, chain: &str) {
            let jump = format!("-j {chain}");
            self.table(v6).get_mut(hook).unwrap().retain(|r| *r != jump);
        }

        /// The rules of `chain`, to change by hand.
        fn rules(&self, v6: bool, chain: &str) -> RefMut<'_, Vec<String>> {
            RefMut::map(self.table(v6), |t| t.get_mut(chain).unwrap())
        }
    }

    impl Xtables for FakeXtables {
        fn run(&self, v6: bool, args: &[&str]) -> Result<String, String> {
            self.runs.set(self.runs.get() + 1);
            if v6 && self.no_ip6tables {
                return Err(
                    "ip6tables could not run: No such file or directory (os error 2)".into(),
                );
            }
            let table = self.table(v6);
            match args {
                ["-S", chain] => {
                    let rules = table
                        .get(*chain)
                        .ok_or("iptables: No chain/target/match by that name.")?;
                    let mut listing = if BUILT_IN.contains(chain) {
                        format!("-P {chain} ACCEPT\n")
                    } else {
                        format!("-N {chain}\n")
                    };
                    for rule in rules {
                        listing.push_str(&format!("-A {chain} {rule}\n"));
                    }
                    Ok(listing)
                }
                other => panic!("the watchdog only reads, and ran {other:?}"),
            }
        }
    }

    /// Generation 0, armed, as the first activation leaves it.
    fn armed() -> (FakeXtables, Live) {
        let x = FakeXtables::new();
        let live = x.arm(0, None);
        assert_eq!(
            missing(&x, &live),
            None,
            "a block just armed reads back whole"
        );
        (x, live)
    }

    /// The re-arm `activate_locked` makes: the other generation, swapped in.
    fn rearm<'a>(x: &'a FakeXtables, live: &'a Live) -> impl FnOnce() -> Result<Live, String> + 'a {
        move || Ok(x.arm(if live.out.ends_with('0') { 1 } else { 0 }, Some(live)))
    }

    fn no_rearm() -> Result<Live, String> {
        panic!("the watchdog re-armed a block it had no reason to touch")
    }

    fn no_lift() -> Result<(), String> {
        panic!("the watchdog lifted a block that is wanted")
    }

    /// A whole block is read back and left alone.
    #[test]
    fn the_watchdog_leaves_a_whole_block_alone() {
        let (x, live) = armed();
        let runs = x.runs.get();
        assert_eq!(watch(&x, true, true, Some(&live), no_rearm, no_lift), None);
        assert!(x.runs.get() > runs, "it was read back");
    }

    /// MR-833: another tool's `iptables -F` took our jumps and our rules, and
    /// the status still said the block was up. The watchdog notices and
    /// re-arms — a fresh generation, which reads back whole.
    #[test]
    fn the_watchdog_restores_a_block_an_iptables_flush_removed() {
        let (x, live) = armed();
        x.flush_all(false);
        let what = missing(&x, &live).expect("a flushed block is not whole");
        assert_eq!(what, "iptables: the OUTPUT jump to BIRDO_KS_OUT0");

        let watched = watch(&x, true, true, Some(&live), rearm(&x, &live), no_lift);
        assert_eq!(watched, Some(Watched::Restored { what }));
        let now = Live {
            out: "BIRDO_KS_OUT1".into(),
            inn: "BIRDO_KS_IN1".into(),
            ..live.clone()
        };
        assert_eq!(missing(&x, &now), None, "the new generation is whole");
        assert!(
            !x.table(false).contains_key(&live.out),
            "the old one is retired"
        );

        // `iptables -F; iptables -X`, the usual reset: our chains are gone too.
        let (x, live) = armed();
        x.flush_all(false);
        x.delete_user_chains(false);
        let watched = watch(&x, true, true, Some(&live), rearm(&x, &live), no_lift);
        assert!(
            matches!(watched, Some(Watched::Restored { .. })),
            "{watched:?}"
        );
    }

    /// `iptables -F BIRDO_KS_OUT0` leaves the jump in place and empties the
    /// chain: every packet falls through it to OUTPUT's ACCEPT policy. A jump
    /// alone is not a block.
    #[test]
    fn an_emptied_chain_behind_its_jump_is_not_a_block() {
        let (x, live) = armed();
        x.flush(false, &live.out);
        assert_eq!(
            missing(&x, &live),
            Some(format!(
                "iptables: BIRDO_KS_OUT0 holds 0 rules where {} were loaded",
                live.v4.0.len()
            ))
        );
        let watched = watch(&x, true, true, Some(&live), rearm(&x, &live), no_lift);
        assert!(
            matches!(watched, Some(Watched::Restored { .. })),
            "{watched:?}"
        );
    }

    /// IPv6 is read back too: `ip6tables -F` alone reopens the IPv6 leak
    /// around the IPv4-only tunnel (AUDIT-N5).
    #[test]
    fn the_watchdog_restores_an_ipv6_block_flushed_on_its_own() {
        let (x, live) = armed();
        x.flush_all(true);
        assert_eq!(
            missing(&x, &live).as_deref(),
            Some("ip6tables: the OUTPUT jump to BIRDO_KS_OUT0")
        );
        let watched = watch(&x, true, true, Some(&live), rearm(&x, &live), no_lift);
        assert!(
            matches!(watched, Some(Watched::Restored { .. })),
            "{watched:?}"
        );
    }

    /// What `missing` checks beyond a flush: a jump present, each chain's
    /// rule count equal to what the generation loaded (a rule slipped in
    /// ahead of ours changes it), and each chain ending in its DROP. Rule
    /// text and our jump's position are compared too (MR-2001, below).
    #[test]
    fn a_missing_jump_a_changed_rule_count_or_a_lost_final_drop_is_noticed() {
        let (x, live) = armed();
        x.unhook(false, "FORWARD", &live.inn);
        assert_eq!(
            missing(&x, &live).as_deref(),
            Some("iptables: the FORWARD jump to BIRDO_KS_IN0")
        );

        let (x, live) = armed();
        x.rules(false, &live.out).insert(0, "-j ACCEPT".into());
        assert_eq!(
            missing(&x, &live),
            Some(format!(
                "iptables: BIRDO_KS_OUT0 holds {} rules where {} were loaded",
                live.v4.0.len() + 1,
                live.v4.0.len()
            ))
        );

        let (x, live) = armed();
        *x.rules(true, &live.inn).last_mut().unwrap() = "-j ACCEPT".into();
        assert_eq!(
            missing(&x, &live).as_deref(),
            Some("ip6tables: BIRDO_KS_IN0 no longer ends in its DROP")
        );
    }

    /// A host without ip6tables has no IPv6 chains to read back, and is not
    /// re-armed every 30 s for their absence.
    #[test]
    fn a_host_without_ip6tables_reads_back_ipv4_alone() {
        let x = FakeXtables {
            no_ip6tables: true,
            ..FakeXtables::new()
        };
        let live = x.arm(0, None);
        assert_eq!(live.v6, None);
        assert_eq!(watch(&x, true, true, Some(&live), no_rearm, no_lift), None);
    }

    /// A re-arm that fails, or one whose rules do not read back, is reported
    /// as not restored — never as restored — and the next pass tries again.
    #[test]
    fn a_re_arm_that_did_not_take_is_not_called_restored() {
        let (x, live) = armed();
        x.flush_all(false);
        let failed = watch(
            &x,
            true,
            true,
            Some(&live),
            || Err("iptables -I OUTPUT 1 -j BIRDO_KS_OUT1 failed: Resource busy".into()),
            no_lift,
        );
        assert_eq!(
            failed,
            Some(Watched::NotRestored {
                what: "iptables: the OUTPUT jump to BIRDO_KS_OUT0".into(),
                why: "iptables -I OUTPUT 1 -j BIRDO_KS_OUT1 failed: Resource busy".into(),
            })
        );

        // Flushed again the moment it went in.
        let lost = watch(
            &x,
            true,
            true,
            Some(&live),
            || {
                let now = x.arm(1, Some(&live));
                x.flush_all(false);
                Ok(now)
            },
            no_lift,
        );
        match lost {
            Some(Watched::NotRestored { why, .. }) => assert_eq!(
                why,
                "re-armed, but iptables: the OUTPUT jump to BIRDO_KS_OUT1 is still missing"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// N1, as on macOS: a block held but no longer wanted is a lift that
    /// failed (the give-up's leaves the intent set), so the LIFT is retried —
    /// and a block somebody removed after we stopped wanting it is never put
    /// back.
    #[test]
    fn an_unwanted_block_is_lifted_never_restored() {
        let (x, live) = armed();
        let lifted = Cell::new(0);
        let lift = || {
            lifted.set(lifted.get() + 1);
            Ok(())
        };
        assert_eq!(
            watch(&x, false, true, Some(&live), no_rearm, lift),
            Some(Watched::LiftRetried(Ok(())))
        );
        assert_eq!(lifted.get(), 1);
        assert_eq!(
            watch(&x, false, true, Some(&live), no_rearm, || Err(
                "teardown incomplete".to_string()
            )),
            Some(Watched::LiftRetried(Err("teardown incomplete".into())))
        );

        x.flush_all(false);
        assert_eq!(
            watch(&x, false, false, Some(&live), no_rearm, no_lift),
            None
        );
    }

    /// Nothing wanted and nothing owed: the pass reads nothing and spawns no
    /// process — the idle watchdog after a lift. (A block wanted with
    /// nothing live is not idle: MR-2090, below.)
    #[test]
    fn an_idle_watchdog_runs_nothing() {
        let x = FakeXtables::new();
        assert_eq!(watch(&x, false, false, None, no_rearm, no_lift), None);
        assert_eq!(x.runs.get(), 0);
        let (x, live) = armed();
        let runs = x.runs.get();
        assert_eq!(
            watch(&x, false, false, Some(&live), no_rearm, no_lift),
            None
        );
        assert_eq!(x.runs.get(), runs, "a lifted block is not read back");
    }

    /// MR-2090: the first arm failed (the rule build, say), so no generation
    /// of ours was ever live while the block is wanted. The watchdog read
    /// nothing then and the session ran without its block until a reconnect
    /// happened to re-arm it. It puts the block up now, and reads it back.
    #[test]
    fn a_wanted_block_that_never_went_up_is_put_up() {
        let x = FakeXtables::new();
        let put_up = RefCell::new(None);
        let watched = watch(
            &x,
            true,
            false,
            None,
            || {
                let live = x.arm(0, None);
                *put_up.borrow_mut() = Some(live.clone());
                Ok(live)
            },
            no_lift,
        );
        let live = put_up
            .into_inner()
            .expect("the watchdog put up the wanted block that never went up");
        assert_eq!(missing(&x, &live), None, "and it reads back whole");
        assert!(watched.is_some(), "and the pass says what it did");
        assert_eq!(watched, Some(Watched::Armed { failed: 0 }));
    }

    /// MR-2090: an arm that does not take — it fails, or what it put up does
    /// not read back — is reported as not armed, never as armed.
    #[test]
    fn a_first_arm_that_did_not_take_is_not_called_armed() {
        let x = FakeXtables::new();
        let failed = watch(
            &x,
            true,
            false,
            None,
            || Err("rule build failed, block NOT changed: iptables: No chain/target/match".into()),
            no_lift,
        );
        assert_eq!(
            failed,
            Some(Watched::NotArmed {
                why: "rule build failed, block NOT changed: iptables: No chain/target/match".into(),
                failed: 1,
            })
        );
        let lost = watch(
            &x,
            true,
            false,
            None,
            || {
                let now = x.arm(0, None);
                x.flush_all(false);
                Ok(now)
            },
            no_lift,
        );
        match lost {
            Some(Watched::NotArmed { why, .. }) => assert_eq!(
                why,
                "armed, but iptables: the OUTPUT jump to BIRDO_KS_OUT0 is missing"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// MR-2090: a first arm that keeps failing is retried at once, then 1, 2
    /// and at most `FirstArm::MAX_APART` passes apart; the attempts of the
    /// streak are counted, so only its first is reported as an error, and
    /// the arm that lands says how many failed before it. A later failure
    /// opens a new streak.
    #[test]
    fn a_failing_first_arm_is_retried_with_backoff_and_counted() {
        let x = FakeXtables::new();
        let mut pace = FirstArm::new();
        let mut attempts = Vec::new();
        let mut opened = 0;
        for n in 0..20 {
            let tried = Cell::new(false);
            let watched = pace.pass(
                &x,
                true,
                false,
                None,
                || {
                    tried.set(true);
                    Err("iptables: Resource temporarily unavailable.".into())
                },
                no_lift,
            );
            match watched {
                None => assert!(!tried.get(), "pass {n} sat out, and ran nothing"),
                Some(Watched::NotArmed { failed, .. }) => {
                    assert!(tried.get());
                    attempts.push(n);
                    assert_eq!(failed as usize, attempts.len(), "the streak is counted");
                    if failed == 1 {
                        opened += 1;
                    }
                }
                other => panic!("pass {n}: {other:?}"),
            }
        }
        // 1, 2, 4, 4, 4... passes apart.
        assert_eq!(attempts, vec![0, 1, 3, 7, 11, 15, 19]);
        assert_eq!(opened, 1, "one streak, one error");
        assert_eq!(x.runs.get(), 0, "nothing was read back from a failed arm");

        // It goes up at the next attempt that is due.
        let mut landed = None;
        for _ in 0..FirstArm::MAX_APART {
            landed = pace.pass(&x, true, false, None, || Ok(x.arm(0, None)), no_lift);
            if landed.is_some() {
                break;
            }
        }
        assert_eq!(landed, Some(Watched::Armed { failed: 7 }));
        assert_eq!(pace, FirstArm::new(), "the streak is over");

        // A new failure opens a new streak, retried at once.
        let fail = || Err::<Live, String>("iptables: Permission denied".into());
        assert!(matches!(
            pace.pass(&x, true, false, None, fail, no_lift),
            Some(Watched::NotArmed { failed: 1, .. })
        ));
        assert!(matches!(
            pace.pass(&x, true, false, None, fail, no_lift),
            Some(Watched::NotArmed { failed: 2, .. })
        ));
    }

    /// The streak also ends when there is nothing left to put up: another
    /// activation made the block live (a reconnect re-armed it), or it is no
    /// longer wanted. Neither waits out the pace or is put up by it.
    #[test]
    fn a_live_or_unwanted_block_ends_the_streak() {
        let fail = || Err::<Live, String>("iptables: Resource temporarily unavailable.".into());
        let (x, live) = armed();
        let mut pace = FirstArm::new();
        pace.pass(&x, true, false, None, fail, no_lift);
        pace.pass(&x, true, false, None, fail, no_lift);
        assert_ne!(pace, FirstArm::new());
        assert_eq!(
            pace.pass(&x, true, true, Some(&live), no_rearm, no_lift),
            None,
            "a whole live block is read back at once, whatever the pace"
        );
        assert_eq!(pace, FirstArm::new());

        pace.pass(&x, true, false, None, fail, no_lift);
        assert_eq!(
            pace.pass(&x, false, false, None, no_rearm, no_lift),
            None,
            "a block no longer wanted is not put up"
        );
        assert_eq!(pace, FirstArm::new());
    }

    /// MR-2000: a restore or an owed lift that keeps failing was logged as an
    /// error every 30 s, for as long as it failed. Only the pass that opens
    /// a streak reports it now (`failed == 1` in the tick); the passes after
    /// it are counted, and a pass that does not fail ends the streak. A
    /// failure of the other kind opens a streak of its own: a restore that
    /// kept failing, then an owed lift that fails once the user turned the
    /// switch off, was counted as pass 3 of one streak, reported at debug.
    #[test]
    fn a_failure_that_persists_is_one_streak() {
        let not_restored = Watched::NotRestored {
            what: "iptables: the OUTPUT jump to BIRDO_KS_OUT0".into(),
            why: "iptables: Resource temporarily unavailable.".into(),
        };
        let lift_failed = Watched::LiftRetried(Err("teardown incomplete".into()));
        let mut failing = Failing::default();
        assert_eq!(failing.record(Some(&not_restored)), 1, "opens the streak");
        assert_eq!(failing.record(Some(&not_restored)), 2);
        assert_eq!(
            failing.record(Some(&lift_failed)),
            1,
            "a lift that fails is news after restores that did"
        );
        assert_eq!(failing.record(Some(&lift_failed)), 2);
        assert_eq!(failing.record(Some(&not_restored)), 1, "and back");
        assert_eq!(failing.record(None), 0, "a whole block ends it");
        assert_eq!(failing.record(Some(&lift_failed)), 1, "a new streak");
        for ended in [
            Watched::LiftRetried(Ok(())),
            Watched::Restored {
                what: "iptables: the OUTPUT jump to BIRDO_KS_OUT0".into(),
            },
            Watched::Armed { failed: 0 },
            // A first arm's streak is FirstArm's to count.
            Watched::NotArmed {
                why: "iptables: Permission denied".into(),
                failed: 3,
            },
        ] {
            failing.record(Some(&not_restored));
            assert_eq!(failing.record(Some(&ended)), 0, "{ended:?}");
            assert_eq!(failing, Failing::default());
        }
    }

    /// The listing as the kernel prints it (`-m tcp` and all): one entry per
    /// rule of exactly that chain.
    #[test]
    fn rules_of_reads_a_kernel_listing() {
        let listing = "-N BIRDO_KS_OUT1\n\
                       -A BIRDO_KS_OUT1 -o lo -j ACCEPT\n\
                       -A BIRDO_KS_OUT1 -d 1.1.1.1/32 -p tcp -m tcp --dport 443 -m owner --uid-owner 0 -j ACCEPT\n\
                       -A BIRDO_KS_OUT1 -j DROP\n\
                       -A BIRDO_KS_OUT10 -j ACCEPT\n";
        assert_eq!(
            rules_of(listing, "BIRDO_KS_OUT1"),
            vec![
                "-o lo -j ACCEPT",
                "-d 1.1.1.1/32 -p tcp -m tcp --dport 443 -m owner --uid-owner 0 -j ACCEPT",
                "-j DROP",
            ]
        );
    }

    /// The body of the fn whose signature begins with `start` in `source`,
    /// up to its closing brace at column 0.
    fn fn_body(source: &str, start: &str) -> String {
        let from = &source[source.find(start).unwrap_or_else(|| panic!("{start}"))..];
        from[..from.find("\n}\n").expect("end of fn")].to_string()
    }

    /// `source` without its test module: the code the app runs.
    fn non_test(source: &str) -> &str {
        &source[..source.find("\n#[cfg(test)]\nmod ").expect("a test module")]
    }

    /// The wiring the Windows job cannot run: the Linux block starts the
    /// watchdog, on the macOS period; its pass reads WANTED and the intent
    /// under the chains' lock; every activation wants the block and every
    /// lift request stops wanting it, before it runs.
    #[test]
    fn the_linux_block_starts_the_watchdog_and_its_pass_reads_under_the_lock() {
        let source = include_str!("killswitch.rs").replace('\r', "");
        let activate = fn_body(&source, "async fn activate_platform_block(");
        let started = activate
            .find("ensure_iptables_watchdog();")
            .expect("started with the block");
        assert!(started < activate.find("firewall_linux::activate_blocking(").unwrap());
        for period in ["IPTABLES_WATCHDOG_INTERVAL", "PF_WATCHDOG_INTERVAL"] {
            assert!(source.contains(&format!(
                "const {period}: std::time::Duration = std::time::Duration::from_secs(30);"
            )));
        }

        let linux = include_str!("../vpn/firewall_linux.rs").replace('\r', "");
        let pass = fn_body(&linux, "pub(crate) async fn watchdog(");
        // CHAINS held, off the async workers (MR-2000).
        let locked = pass.find("with_chains(").expect("under the lock");
        assert!(locked < pass.find("WANTED.load(").unwrap());
        assert!(locked < pass.find("killswitch::is_enabled()").unwrap());
        // MR-2090: the pass is paced, and the pace kept under the same lock.
        assert!(locked < pass.find("FIRST_ARM").expect("paced"));
        assert!(pass.contains("first_arm.pass("));
        // ...and a block it put up where none was meets the one rule for the
        // intent, as every activation does.
        let tick = fn_body(&source, "async fn iptables_watchdog_tick(");
        let armed = tick.find("if armed {").expect("an arm is followed up");
        assert!(armed < tick.find("unless_turned_off(").expect("by the one rule"));
        let on = fn_body(&linux, "pub async fn activate_blocking(");
        assert!(on.find("WANTED.store(true").unwrap() < on.find("activate_locked(").unwrap());
        let off = fn_body(&linux, "pub async fn deactivate_blocking(");
        assert!(off.find("WANTED.store(false").unwrap() < off.find("deactivate_locked()").unwrap());
    }

    /// MR-2001: another tool's ACCEPT inserted above our jump (`iptables -I
    /// OUTPUT 1 -j ACCEPT`) lets every packet out before our chain is
    /// reached, and the watchdog, comparing counts and the final DROP only,
    /// read that block as whole. Our jump must be the first rule of its hook;
    /// the re-arm inserts the new generation at the top, above the other
    /// tool's rule, which stays where it is never reached.
    #[test]
    fn an_accept_inserted_above_our_jump_is_noticed_and_re_armed_above_it() {
        for (v6, family) in [(false, "iptables"), (true, "ip6tables")] {
            for (hook, chain) in [
                ("OUTPUT", "BIRDO_KS_OUT0"),
                ("INPUT", "BIRDO_KS_IN0"),
                ("FORWARD", "BIRDO_KS_IN0"),
            ] {
                let (x, live) = armed();
                x.rules(v6, hook).insert(0, "-j ACCEPT".into());
                assert_eq!(
                    missing(&x, &live),
                    Some(format!("{family}: a rule above the {hook} jump to {chain}"))
                );
                let watched = watch(&x, true, true, Some(&live), rearm(&x, &live), no_lift);
                assert!(
                    matches!(watched, Some(Watched::Restored { .. })),
                    "{family} {hook}: {watched:?}"
                );
                let jump = if hook == "OUTPUT" {
                    "-j BIRDO_KS_OUT1"
                } else {
                    "-j BIRDO_KS_IN1"
                };
                assert_eq!(*x.rules(v6, hook), vec![jump, "-j ACCEPT"]);
            }
        }
    }

    /// MR-2001: a rule of ours swapped for another, the count and the final
    /// DROP unchanged, is noticed too: each chain is compared, rule by rule,
    /// with what iptables listed once it was loaded. The finding names the
    /// rule by its place, never by its text, which carries the relay's and
    /// the control plane's addresses.
    #[test]
    fn a_rule_of_ours_swapped_for_another_is_noticed() {
        let (x, live) = armed();
        x.rules(false, &live.out)[1] = "-j ACCEPT".into();
        assert_eq!(
            missing(&x, &live).as_deref(),
            Some("iptables: rule 2 of BIRDO_KS_OUT0 is not the one loaded")
        );

        let (x, live) = armed();
        x.rules(true, &live.inn)[0] = "-j ACCEPT".into();
        assert_eq!(
            missing(&x, &live).as_deref(),
            Some("ip6tables: rule 1 of BIRDO_KS_IN0 is not the one loaded")
        );
        let watched = watch(&x, true, true, Some(&live), rearm(&x, &live), no_lift);
        assert!(
            matches!(watched, Some(Watched::Restored { .. })),
            "{watched:?}"
        );
    }

    /// MR-2001: the rules that may sit above our jump are the IPv6 leak
    /// block's (F-001), and since MR-2128 the cover a re-install puts above
    /// it while it rebuilds it. Every tunnel start inserts them at the top of
    /// ip6tables' OUTPUT while our block is held for the whole session, and
    /// they let nothing routable out; flagging them would re-arm the block,
    /// and blame another tool, at every connect. Their names are
    /// tunnel_linux.rs's. There alone: tunnel_linux inserts them nowhere
    /// else, so the same jumps above our IPv4 OUTPUT jump, or above an INPUT
    /// or FORWARD jump, are another tool's rules, and noticed.
    #[test]
    fn the_ipv6_leak_block_may_sit_above_our_jump() {
        for leak_block in ["-j BIRDO_IPV6_LEAK_BLOCK", "-j BIRDO_IPV6_LEAK_COVER"] {
            let (x, live) = armed();
            x.rules(true, "OUTPUT").insert(0, leak_block.into());
            assert_eq!(missing(&x, &live), None, "{leak_block}");
            assert_eq!(watch(&x, true, true, Some(&live), no_rearm, no_lift), None);

            for (v6, family, hook, chain) in [
                (false, "iptables", "OUTPUT", "BIRDO_KS_OUT0"),
                (false, "iptables", "INPUT", "BIRDO_KS_IN0"),
                (true, "ip6tables", "INPUT", "BIRDO_KS_IN0"),
                (true, "ip6tables", "FORWARD", "BIRDO_KS_IN0"),
            ] {
                let (x, live) = armed();
                x.rules(v6, hook).insert(0, leak_block.into());
                assert_eq!(
                    missing(&x, &live),
                    Some(format!("{family}: a rule above the {hook} jump to {chain}")),
                    "{leak_block}"
                );
            }
        }

        let tunnel = include_str!("../vpn/tunnel_linux.rs").replace('\r', "");
        assert!(tunnel.contains("const IPV6_BLOCK_CHAIN: &str = \"BIRDO_IPV6_LEAK_BLOCK\";"));
        assert!(tunnel.contains("const IPV6_BLOCK_COVER: &str = \"BIRDO_IPV6_LEAK_COVER\";"));
        assert!(tunnel.contains("ip6t(&[\"-I\", \"OUTPUT\", \"1\", \"-j\", IPV6_BLOCK_CHAIN])"));
        assert!(tunnel.contains("ip6t(&[\"-I\", \"OUTPUT\", \"1\", \"-j\", IPV6_BLOCK_COVER])"));
        // ...and inserts them nowhere else.
        assert_eq!(tunnel.matches("ip6t(&[\"-I\", ").count(), 2, "{tunnel}");
    }

    /// MR-2000: with `-w 5`, a probe (`-L <chain>`, `-C <hook> -j <chain>`)
    /// that waits out another tool's hold on the xtables lock exits 4. It
    /// was read as "not there", like the exit 1 of a chain that is gone. A
    /// lift under that contention then probed none of our chains, unhooked
    /// nothing, verified nothing left, and reported the block lifted:
    /// IPTABLES_BLOCKING cleared over a block still hooked, and nothing
    /// retried. Only iptables' "no such chain or rule" (exit 1), or no
    /// iptables at all, is absence now; anything else could not tell.
    #[test]
    fn a_probe_that_waited_out_the_xtables_lock_is_not_absence() {
        use std::io::ErrorKind;
        let exit = |code| Probe::of(Ok(Some(code)));
        assert_eq!(exit(0), Probe::Present);
        assert_eq!(exit(1), Probe::Absent, "No chain/target/match by that name");
        assert_eq!(
            Probe::of(Err(ErrorKind::NotFound)),
            Probe::Absent,
            "an IPv4-only host's ip6tables (AUDIT-N5)"
        );
        // "Another app is currently holding the xtables lock. Stopped
        // waiting after 5s." — RESOURCE_PROBLEM.
        assert_eq!(exit(4), Probe::Unknown);
        assert_eq!(exit(2), Probe::Unknown);
        assert_eq!(Probe::of(Ok(None)), Probe::Unknown, "killed by a signal");
        assert_eq!(Probe::of(Err(ErrorKind::PermissionDenied)), Probe::Unknown);
        assert!(Probe::Present.may_be_there() && Probe::Unknown.may_be_there());
        assert!(!Probe::Absent.may_be_there());

        // The lift under contention: a block is up (generation 0, held),
        // and every probe of the teardown's check exits 4. Every chain
        // counts as still installed, so the lift returns Err, the flag
        // stays set and the watchdog retries the owed lift.
        let ours_up = block_may_be_up(0, true);
        assert!(still_installed([exit(4), exit(4)], ours_up));
        assert!(still_installed([exit(4), exit(1)], ours_up));
        // A partial first arm (live, read as not blocking) is ours too.
        assert!(still_installed(
            [exit(1), exit(4)],
            block_may_be_up(1, false)
        ));
        // Gone in both families: lifted.
        assert!(!still_installed([exit(1), exit(1)], ours_up));
        assert!(!still_installed(
            [exit(1), Probe::of(Err(ErrorKind::NotFound))],
            ours_up
        ));
        // Seen in either family: never lifted, whatever is up.
        assert!(still_installed([exit(1), exit(0)], false));
        // With none of ours up (a disarm after the lift landed, a process
        // that never armed: iptables run without root exits 4 on every
        // probe), a probe that cannot tell is no leftover of ours.
        assert!(!still_installed(
            [exit(4), exit(4)],
            block_may_be_up(-1, false)
        ));
    }

    /// MR-1999: whether a block of ours may be up, as the OFF, the relay
    /// re-arm and the teardown's check decide it under the chains' lock. A
    /// first arm that hooked only part of its jumps, not OUTPUT's, is live
    /// (LIVE_GEN >= 0) while it reads as not blocking: the OFF must lift it.
    /// A lift that failed keeps the block held with its generation named.
    #[test]
    fn a_partial_first_arm_is_a_block_the_off_lifts() {
        assert!(!block_may_be_up(-1, false), "nothing of ours");
        assert!(block_may_be_up(0, false), "a partial first arm");
        assert!(block_may_be_up(1, false), "a partial first arm");
        assert!(block_may_be_up(0, true), "an armed block");
        assert!(block_may_be_up(-1, true), "held, no generation named");

        // The Linux OFF, the relay re-arm and the teardown's check ask it,
        // with the chains' lock held, from the flags as they are.
        let linux = include_str!("../vpn/firewall_linux.rs").replace('\r', "");
        let code = non_test(&linux);
        let flags = fn_body(code, "fn ours_may_be_up(");
        for read in [
            "block_may_be_up(",
            "LIVE_GEN.load(Ordering::SeqCst)",
            "IPTABLES_BLOCKING.load(Ordering::SeqCst)",
        ] {
            assert!(flags.contains(read), "{flags}");
        }
        for entry in [
            "pub async fn lift_if_held(",
            "pub async fn rearm_if_up(",
            "fn deactivate_locked(",
        ] {
            let body = fn_body(code, entry);
            assert!(body.contains("ours_may_be_up()"), "{entry}");
            assert!(
                !body.contains("LIVE_GEN.load("),
                "{entry} decides on its own"
            );
        }
    }

    /// MR-2000: what the watchdog's re-arm and lift run with the chains'
    /// lock held logs no error of its own. The pass returns the failure,
    /// and the tick reports a failure that persists once per streak
    /// (`Failing`, `FirstArm`); an error logged inside — "teardown
    /// incomplete", "re-arm could not hook the new rule set" — fired on
    /// every pass, every 30 s, for as long as the failure lasted. The
    /// callers that are not the watchdog log it at error, outside the lock.
    #[test]
    fn the_watchdogs_locked_work_logs_no_error_of_its_own() {
        let linux = include_str!("../vpn/firewall_linux.rs").replace('\r', "");
        let code = non_test(&linux);
        let mut seen = Vec::new();
        for (at, _) in code.match_indices("tracing::error!") {
            let owner = code[..at].rfind("fn ").unwrap() + 3;
            let name = &code[owner..owner + code[owner..].find(['(', '<']).unwrap()];
            let body = fn_body(code, &format!("fn {name}"));
            let here = at - code.find(&format!("fn {name}")).unwrap();
            match name {
                // The non-watchdog entry points' helper.
                "logged" => {}
                // Once the pass is over, outside the lock: it could not run.
                "watchdog" => assert!(body.find(".await").unwrap() < here),
                // A self-permit that would not load, when it is news: the
                // live generation had its self-permits. A re-arm of chains
                // that lacked them already says so at debug.
                "load_chain" => {
                    let news = body
                        .find("if SELF_PERMITS_MISSING.load(Ordering::SeqCst) {")
                        .expect("decided by what the live generation lacks");
                    let otherwise = news + body[news..].find("} else {").unwrap();
                    assert!(otherwise < here, "{body}");
                }
                other => panic!("{other} logs at error"),
            }
            seen.push(name);
        }
        assert_eq!(seen, ["logged", "load_chain", "watchdog"]);

        for (entry, logs) in [
            (
                "pub async fn deactivate_blocking(",
                "logged(\"the lift failed\", lifted)",
            ),
            (
                "pub async fn lift_if_held(",
                "logged(\"the lift failed\", lifted)",
            ),
            (
                "pub async fn refresh_control_plane(",
                "logged(\"the control-plane re-arm failed\", refreshed)",
            ),
            (
                "pub async fn rearm_if_up(",
                "logged(\"the re-arm around the new relay failed\", rearmed)",
            ),
        ] {
            let body = fn_body(code, entry);
            let lock = body.find("with_chains(").expect(entry);
            assert!(lock < body.find(logs).expect(entry), "{entry}");
        }
        // activate_blocking's one caller logs its failure at error.
        let source = include_str!("killswitch.rs").replace('\r', "");
        let activate = fn_body(&source, "async fn activate_platform_block(");
        let call = activate
            .find("firewall_linux::activate_blocking()")
            .unwrap();
        assert!(activate[call..]
            .contains("tracing::error!(\"Failed to activate iptables blocking: {}\", e);"));
    }

    /// MR-1998 (with AUD-DESK-09's two more sites): the relay a Linux block
    /// permits is read in the step that builds it, under the chains' lock,
    /// as macOS reads it under pf's (P3-3). The activation, the control-plane
    /// re-arm and the watchdog's pass each read it BEFORE they waited for
    /// the lock: a server switch that got the lock first and re-armed for the
    /// new relay was then undone by a re-arm for the old one, which dropped
    /// the new relay's handshake.
    #[test]
    fn the_linux_block_reads_its_relay_under_the_chains_lock() {
        let source = include_str!("killswitch.rs").replace('\r', "");
        let code = non_test(&source);
        for call in [
            "firewall_linux::activate_blocking()",
            "firewall_linux::refresh_control_plane(generation)",
            "firewall_linux::watchdog()",
        ] {
            assert!(code.contains(call), "{call} is handed no relay");
        }
        // Here, only macOS's pf_inputs reads it, under pf's lock.
        for (at, _) in code.match_indices("vpn_server_ip()") {
            let owner = code[..at].rfind("fn ").unwrap() + 3;
            let name = &code[owner..owner + code[owner..].find('(').unwrap()];
            assert!(
                ["vpn_server_ip", "pf_inputs"].contains(&name),
                "the relay is read in {name}"
            );
        }

        let linux = include_str!("../vpn/firewall_linux.rs").replace('\r', "");
        let linux = non_test(&linux);
        let reads: Vec<usize> = linux
            .match_indices("vpn_server_ip()")
            .map(|(at, _)| at)
            .collect();
        let built = linux.find("fn activate_locked(").expect("activate_locked");
        let end = built + linux[built..].find("\n}\n").unwrap();
        assert_eq!(reads.len(), 1, "read once, where the block is built");
        assert!(
            (built..end).contains(&reads[0]),
            "read outside activate_locked"
        );
        // activate_locked takes no relay, and runs with CHAINS held only.
        assert!(linux.contains("fn activate_locked() -> Result<(), String>"));

        // A relay write re-arms whatever of ours may be up, decided under
        // the lock too: asked lock-free (`platform_is_blocking()`), a first
        // arm still in flight, built from the previous relay, said no, and
        // kept it until the next reconnect.
        let session = include_str!("session.rs").replace('\r', "");
        let permit = fn_body(&session, "pub(crate) async fn apply_relay_permit(");
        let linux_permit = permit
            .find("#[cfg(target_os = \"linux\")]")
            .expect("a Linux re-arm");
        let linux_permit = &permit[linux_permit..];
        let linux_permit =
            &linux_permit[..linux_permit.find("#[cfg(target_os = \"macos\")]").unwrap()];
        assert!(
            linux_permit.contains("killswitch::rearm_for_relay()"),
            "{linux_permit}"
        );
        assert!(
            !linux_permit.contains("platform_is_blocking()"),
            "{linux_permit}"
        );
        let relay = fn_body(&source, "pub(crate) async fn rearm_for_relay(");
        let mut at = 0;
        for step in [
            "KILLSWITCH_ENABLED.load(",
            "firewall_linux::rearm_if_up()",
            "unless_turned_off(",
        ] {
            at += relay[at..].find(step).unwrap_or_else(|| panic!("{step}"));
        }
        let rearm = fn_body(linux, "pub async fn rearm_if_up(");
        let mut at = 0;
        for step in [
            "with_chains(",
            "if !ours_may_be_up() {",
            "WANTED.store(true",
            "activate_locked()",
        ] {
            at += rearm[at..].find(step).unwrap_or_else(|| panic!("{step}"));
        }
    }

    /// MR-1999: the Linux OFF lifts under the chains' lock, deciding there
    /// from what is live, like macOS's `pf_lift_if_loaded` (N2). It asked the
    /// lock-free `is_blocking()` first: a first arm that hooked only part of
    /// its jumps, not OUTPUT's, reads as not blocking with a generation live,
    /// so an OFF that landed while the watchdog re-armed it lifted nothing,
    /// and the re-arm put the block up behind it until the next pass lifted
    /// it, 30 s later. Taking the lock waits that pass out first.
    #[test]
    fn the_linux_off_lifts_under_the_chains_lock() {
        let source = include_str!("killswitch.rs").replace('\r', "");
        let live = fn_body(&source, "pub async fn set_killswitch_live(");
        let linux_off = live
            .find("#[cfg(target_os = \"linux\")]")
            .expect("a Linux OFF of its own");
        let off = &live[linux_off + 1..];
        let off = &off[..off.find("#[cfg(").expect("the other platforms' OFF")];
        assert!(off.contains("firewall_linux::lift_if_held()"), "{off}");
        assert!(off.contains("|| true,"), "decided under the lock: {off}");

        let linux = include_str!("../vpn/firewall_linux.rs").replace('\r', "");
        let lift = fn_body(&linux, "pub async fn lift_if_held(");
        let locked = lift.find("with_chains(").expect("under CHAINS");
        // `ours_may_be_up`: LIVE_GEN and IPTABLES_BLOCKING, as
        // `a_partial_first_arm_is_a_block_the_off_lifts` decides them.
        for step in [
            "WANTED.store(false",
            "if !ours_may_be_up() {",
            "deactivate_locked()",
        ] {
            let at = lift.find(step).unwrap_or_else(|| panic!("{step}"));
            assert!(locked < at, "{step} before the lock");
        }
    }

    /// MR-2000: every iptables run of the Linux kill switch waits a bounded
    /// time for the xtables lock (`-w 5`): a bare `-w` waited for as long as
    /// another tool held it, with CHAINS held. Every change to the chains,
    /// and every watchdog pass, runs with CHAINS held OFF the async workers
    /// (`with_chains`): they were blocking process spawns on a tokio worker,
    /// the watchdog's every 30 s. A failure that persists is reported once
    /// per streak.
    #[test]
    fn the_linux_chains_change_off_the_async_workers_with_a_bounded_wait() {
        let linux = include_str!("../vpn/firewall_linux.rs").replace('\r', "");
        let code = non_test(&linux);
        assert!(code.contains("const XTABLES_WAIT_SECS: &str = \"5\";"));
        assert_eq!(
            code.matches("hidden_cmd(").count(),
            1,
            "one way to run iptables"
        );
        let run = fn_body(code, "fn xtables(");
        assert!(run.contains(".args([\"-w\", XTABLES_WAIT_SECS])"), "{run}");
        assert!(!code.contains(".arg(\"-w\")"));

        assert!(
            !code.contains("CHAINS.lock("),
            "CHAINS is taken in with_chains alone"
        );
        let with_chains = fn_body(code, "async fn with_chains<");
        assert!(
            with_chains.contains("locked_blocking(&CHAINS, work)"),
            "{with_chains}"
        );
        for entry in [
            "pub async fn activate_blocking(",
            "pub async fn refresh_control_plane(",
            "pub async fn rearm_if_up(",
            "pub async fn deactivate_blocking(",
            "pub async fn lift_if_held(",
            "pub(crate) async fn watchdog(",
        ] {
            assert!(fn_body(code, entry).contains("with_chains("), "{entry}");
        }

        let source = include_str!("killswitch.rs").replace('\r', "");
        let tick = fn_body(&source, "async fn iptables_watchdog_tick(");
        let counted = tick.find("failing.record(").expect("failures counted");
        assert!(counted < tick.find("match watched").unwrap());
    }
}
