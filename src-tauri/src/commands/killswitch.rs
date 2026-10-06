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
/// [`intent_off_since`].
fn intent_seq() -> u64 {
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
        #[cfg(not(target_os = "macos"))]
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
/// `platform_is_blocking`; a backend with a lift of its own (macOS pf) passes
/// that instead.
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
pub async fn arm(app: &AppHandle) -> Result<bool, String> {
    arm_since(app, intent_seq()).await
}

/// [`arm`], `seen` the intent's sequence read before anything this arm
/// depends on (the live ON reads it before its session check).
async fn arm_since(app: &AppHandle, seen: u64) -> Result<bool, String> {
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

/// [`arm`] around a `preference` read that may take any time.
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

/// [`arm`] after the preference has been read, `seen` the intent's sequence
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

    #[cfg(target_os = "windows")]
    {
        wfp::initialize()
            .await
            .map_err(|e| format!("Failed to initialize kill-switch firewall: {}", e))?;
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
/// for good. The next start releases what this names. Root-only: the app runs
/// as root, so this lives in root's own Application Support, mode 0600.
#[cfg(target_os = "macos")]
mod pf_reference_journal {
    use crate::vpn::pf_policy::{self, PfRef};

    fn path() -> Option<std::path::PathBuf> {
        let mut dir = dirs::data_dir()?;
        dir.push("BirdoVPN");
        std::fs::create_dir_all(&dir).ok()?;
        dir.push("pf-reference");
        Some(dir)
    }

    /// Replace the record with `held` (or remove it), staged and renamed so a
    /// crash leaves the old record or the new one, never half of one.
    pub(super) fn write(held: Option<PfRef>) {
        let Some(path) = path() else {
            tracing::warn!("pf reference journal: no data directory");
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

    fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let staging = path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&staging)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&staging, path)
    }

    /// What a previous run left, if anything.
    pub(super) fn read() -> Option<PfRef> {
        pf_policy::decode_reference(&std::fs::read_to_string(path()?).ok()?)
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

        // And `arm` takes the sequence before the preference, and stores
        // through intent_on_since. (Its ON store needs an elevated host, so
        // this half is a source check.)
        let source = include_str!("killswitch.rs").replace('\r', "");
        assert!(source.contains("arm_since(app, intent_seq()).await"));
        let read = &source[source.find("async fn arm_reading_since(").unwrap()..];
        let read = &read[..read.find("\n}\n").unwrap()];
        assert!(read.contains("arm_with_preference(enabled, seen)"));
        let arm = &source[source.find("async fn arm_with_preference(").unwrap()..];
        assert!(arm.contains("if !intent_on_since(seen) {"));
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
}
