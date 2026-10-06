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
#[cfg(target_os = "windows")]
use crate::vpn::wfp;

use crate::vpn::manager::VpnManager;

/// SEC-C3 FIX: KILLSWITCH_ENABLED is the single user-intent flag.
/// Active/blocking state is delegated entirely to wfp.rs.
static KILLSWITCH_ENABLED: AtomicBool = AtomicBool::new(false);

/// The intent's write lock, guarding a sequence number every OFF bumps
/// (review of #222).
///
/// INVARIANT: `KILLSWITCH_ENABLED` is written only by [`intent_off`] and
/// [`intent_on_since`], both under this lock, and the lock is held for those
/// stores alone — never across an await, a firewall call or settings I/O. A
/// plain mutex therefore cannot keep anyone waiting on slow work: not the
/// Disconnect escape (`disarm`), not the live OFF. (Round 2 used an async
/// lock that `arm` held across its settings read; a hung credential store, or
/// a `schtasks` holding the settings lock, then held `disarm` for good.) It
/// also cannot self-deadlock: no path takes it twice.
///
/// `arm` reads the number BEFORE its slow read of the preference and stores
/// ON only if no OFF has bumped it since ([`intent_on_since`]), so an OFF
/// that lands during the read wins.
static INTENT: parking_lot::Mutex<u64> = parking_lot::const_mutex(0);

/// The intent's current sequence number, for [`intent_on_since`].
fn intent_seq() -> u64 {
    *INTENT.lock()
}

/// Turn the intent OFF (the only way it turns off) and bump the sequence, so
/// an `arm` that read the preference before this does not store its ON over
/// it. Whether it was on.
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
/// removes it. Bounded by [`AGREEMENT_ROUNDS`]: past it the last answer
/// stands and the writers' own checks (the OFF's lift, `arm`'s activation)
/// take it from there. No lock is held across any firewall call (round 3: a
/// lock held there kept `disarm` waiting on them).
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
        turn_off(deactivate_killswitch, platform_is_blocking)
            .await
            .map_err(|e| {
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
    // block (pf utun0-15 pass rules, iptables `-o birdo0 ACCEPT`), which the
    // switch-guard/reapply paths already rely on mid-session. Reactive-only
    // protection left every SILENT tunnel death (dead peer, expired NAT
    // mapping, sleep/resume, Wi-Fi→LTE handover) leaking real-IP traffic —
    // DNS included — for the up-to-~60s the liveness watchdog needs to trip.
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
// ──────────────────────────────────────────────────────────────

/// Tracks whether pf blocking rules are active on macOS
#[cfg(target_os = "macos")]
static PF_BLOCKING: AtomicBool = AtomicBool::new(false);

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

/// Marker anchor embedded in every ruleset WE load, so a stale ruleset left by a
/// crash can be positively identified as ours before we replace it. Declaring an
/// empty anchor is a no-op for packet processing but shows up in `pfctl -s rules`.
#[cfg(target_os = "macos")]
const PF_MARKER_ANCHOR: &str = "com.birdo.vpn";

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

    // pf must actually be running or the loaded ruleset is inert.
    if !was_enabled {
        crate::utils::hidden_cmd("pfctl")
            .args(["-e"])
            .output()
            .map_err(|e| format!("pfctl enable failed: {}", e))?;
        PF_WE_ENABLED.store(true, Ordering::SeqCst);
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
    // or another tool that had it running).
    if PF_WE_ENABLED.swap(false, Ordering::SeqCst) {
        let _ = crate::utils::hidden_cmd("pfctl").args(["-d"]).output();
    }
}

/// F-001: engage the steady-state IPv6 leak block for a tunnel session.
///
/// Called from `tunnel_macos.rs::start()`, INDEPENDENT of the kill-switch
/// enabled/lockdown setting — exactly as Windows blocks IPv6 at tunnel start.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_activate() -> Result<(), String> {
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
    if !pf_live_rules().contains(PF_MARKER_ANCHOR) {
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
    if pf_live_rules().contains(PF_MARKER_ANCHOR) {
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

/// Activate pf blocking: block all traffic except to the VPN server and localhost.
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
    // Let the tunnel re-establish while blocked by permitting the VPN server.
    // WireGuard is UDP; allow the server on both transports so a stealth/TCP
    // fallback can also reconnect through the block.
    // RELAY PERMIT — must be STATEFUL, and must also permit the INBOUND reply.
    //
    // This rule used to be `... to <ip> no state`. `no state` suppresses pf's
    // implicit state creation, and the ruleset below has no `pass in` rule for
    // the relay, so the relay's reply packets matched only the non-quick
    // `block drop all` (pf is last-match) and were silently dropped. The
    // WireGuard handshake is a REQUEST/RESPONSE exchange, so with the block
    // engaged no tunnel could EVER be established — the kill switch became a
    // permanent "cannot connect" rather than a fail-closed gap. `keep state`
    // plus the explicit inbound permit fixes that; both are scoped to the one
    // relay IP, so this does not widen the block for anything else.
    let server_rule = if let Some(ip) = server_ip {
        format!(
            "pass out quick inet proto {{ udp tcp }} to {ip} keep state\n\
             pass in quick inet proto {{ udp tcp }} from {ip} keep state\n"
        )
    } else {
        String::new()
    };

    // SELF-PERMIT: let OUR OWN process reach the control plane.
    //
    // Without this the kill switch makes reconnection impossible, which is the
    // opposite of what it is for. auto_reconnect arms the block and then calls
    // https://api.birdo.app for a fresh config — a DIFFERENT host from the
    // permitted relay, over the physical NIC — and DNS is blocked too. macOS is
    // worse than Linux here: `block drop all` with no state-passing rule kills
    // even an already-established socket. So every reconnect attempt fails for a
    // reason that is not the network, and the loop eventually gives up and drops
    // the block, leaving the machine fully open.
    //
    // Windows uses a per-app WFP permit (ALE_APP_ID). pf has no app condition, so
    // match the euid we run as and scope it to TCP/443 — narrow enough to be
    // meaningful, broad enough to survive the control plane changing address.
    // `keep state` so replies come back.
    let euid = unsafe { libc::geteuid() };
    // LAN permit: honour Local Network Sharing while the block is engaged, so a
    // dropped tunnel does not also take out the printer and the NAS. Includes
    // 169.254/16 for mDNS/Bonjour, which is what actually makes AirPlay and
    // printer discovery work.
    let lan_permit = if lan_sharing_enabled() {
        "pass quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } no state\n"
    } else {
        ""
    };
    let self_permit = format!("pass out quick proto tcp to any port 443 user {euid} keep state\n");
    tracing::info!("Kill switch: self-permit for uid {} on tcp/443", euid);

    // Default-deny with `quick` passes short-circuiting for the allow-list.
    // Permit utun0..utun15. create_utun_device() probes `for unit in 0..256` and
    // takes the FIRST FREE unit, so on a Mac where system services already hold
    // utun0-3 (VPNs, Continuity, Handoff — common) our tunnel lands on utun4+
    // and `block drop all` ate its traffic. The worst path is not the reconnect
    // gap: reapply_vpn_settings arms the block and never deactivates, so
    // CHANGING ANY VPN SETTING WHILE CONNECTED killed all internet for the rest
    // of the session.
    //
    // pfctl tolerates naming absent interfaces (which is how utun2/utun3 already
    // loaded), so listing 16 is safe. The live device name cannot be used
    // instead: reapply_vpn_settings arms the block BEFORE the new tunnel exists,
    // so there is no name to bind at rule-load time.
    // back up before deactivation lands, traffic already inside the VPN is not
    // dropped by this main ruleset.
    //
    // DHCP: both directions are stated explicitly because these rules are
    // `no state` — pf will not infer the reply from the request, so each
    // direction has to match on its own.
    //     request: client :68 -> server :67
    //     reply:   server :67 -> client :68
    // The inbound rule used to read `from any port 68`, which is the CLIENT's
    // port. A DHCP reply arrives FROM :67, so that rule matched nothing and
    // every reply fell through to `block drop all` while the kill switch was
    // armed. The lease could then never be renewed, so a long VPN session ended
    // with the LAN connection dying underneath it — and, because the tunnel
    // itself kept working until the lease actually lapsed, the cause looked
    // nothing like the kill switch.
    let rules = format!(
        "# Birdo VPN Kill Switch (main ruleset — pf evaluates this directly)\n\
         set block-policy drop\n\
         anchor \"{PF_MARKER_ANCHOR}\"\n\
         block drop all\n\
         pass quick on lo0 all\n\
         pass quick on utun0 all\n\
         pass quick on utun1 all\n\
         pass quick on utun2 all\n\
         pass quick on utun3 all\n\
         pass quick on utun4 all\n\
         pass quick on utun5 all\n\
         pass quick on utun6 all\n\
         pass quick on utun7 all\n\
         pass quick on utun8 all\n\
         pass quick on utun9 all\n\
         pass quick on utun10 all\n\
         pass quick on utun11 all\n\
         pass quick on utun12 all\n\
         pass quick on utun13 all\n\
         pass quick on utun14 all\n\
         pass quick on utun15 all\n\
         pass out quick proto udp from any port 68 to any port 67 no state\n\
         pass in quick proto udp from any port 67 to any port 68 no state\n\
         {lan_permit}\
         {self_permit}\
         {server_rule}"
    );

    // Record pf's pre-existing state BEFORE we change it, so deactivation only
    // disables pf if we were the ones who enabled it.
    let was_enabled = pf_is_enabled();

    // Pipe rules directly to pfctl via stdin — avoids TOCTOU race and world-readable temp file
    pf_load_ruleset(&rules)?;

    // Enable pf if it wasn't already, and remember that we did so.
    if !was_enabled {
        let en = crate::utils::hidden_cmd("pfctl").args(["-e"]).output();
        // `pfctl -e` returns non-zero if pf was already enabled; we already
        // guarded on was_enabled, so treat a spawn failure as fatal — an
        // un-enabled pf means the loaded block ruleset is not enforced.
        match en {
            Ok(_) => PF_WE_ENABLED.store(true, Ordering::SeqCst),
            Err(e) => return Err(format!("pfctl enable failed: {}", e)),
        }
    }

    PF_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("macOS pf kill switch activated (main ruleset enforced)");
    Ok(())
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
    PF_BLOCKING.store(false, Ordering::SeqCst);

    if PF_IPV6_BLOCK_ACTIVE.load(Ordering::SeqCst) {
        // Propagating the error deliberately leaves the block-all ruleset loaded.
        // That is both fail-safe and still usable: block-all permits lo0 and utun*,
        // so a healthy tunnel keeps carrying the user's traffic. Falling back to
        // /etc/pf.conf here would restore the IPv6 leak instead.
        pf_apply_ipv6_baseline()?;
        tracing::info!("macOS pf kill switch deactivated (IPv6 leak block retained)");
        return Ok(());
    }

    // Reload the default ruleset, dropping our block-all rules. This is the
    // correct inverse of loading a main ruleset (a per-anchor flush would leave
    // our main-ruleset block rules in place and keep blocking).
    pf_restore_default_ruleset();
    tracing::info!("macOS pf kill switch deactivated");
    Ok(())
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
