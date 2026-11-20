//! Auto-reconnect service for VPN connections
//!
//! Watches the live session and recovers it when it dies. The DECISIONS live
//! in `reconnect_policy` (pure and unit-tested, W1-029); this module gathers
//! what the policy needs to see and carries out what it decides.
//!
//! What it watches, all without sending a packet of its own except the
//! WireGuard handshakes to our relay and the 30 s control-plane heartbeat:
//!   * WireGuard handshake age (W1-002) — the iOS/Android liveness rule;
//!   * the physical default route and resume events (W1-003), via
//!     `network_events`;
//!   * the stealth transport exiting under the session (W1-005);
//!   * the tunnel's own packet path still running (WIN-FIX-3; Windows only —
//!     macOS and Linux rely on the 180 s handshake-age backstop, MR-1117).
//!
//! # It cannot hang (WIN-FIX-3 P0)
//! Every network call it makes has a hard cap ([`HEARTBEAT_TIMEOUT`],
//! [`OLD_KEY_PROBE_TIMEOUT`], [`REDIAL_API_TIMEOUT`]; the tunnel build has
//! `CONNECT_TIMEOUT`), it reads the tunnel only through lock-free snapshots
//! (`wireguard_new` module docs), and it checks in with a watchdog on an OS
//! thread of its own. A loop that stops checking in is restarted with the
//! block left exactly as it was — see [`AutoReconnectService::start`].

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{watch, Mutex as TokioMutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, MissedTickBehavior};

use super::manager::{
    ConnectPhase, ConnectionState, GaveUp, MultiHopStatus, SessionLabel, VpnManager,
};
use super::network_events::{self, PhysicalRoute};
use super::reconnect_policy::{
    self, Action, Budget, DropCause, HeartbeatVerdict, LinkState, Liveness, LocalLink, Observed,
    OnRelease, QuietRebuilds, ReconnectPolicy, ReleaseLook, Tick,
};
use super::relay_retry::{self, SelectionOrigin};
use super::xray::XrayManager;
use crate::api::attestation::DesktopAttestation;
use crate::api::client::{build_connect_request, build_multi_hop_request};
use crate::api::types::{ConnectRequest, ConnectResponse, MultiHopConnectRequest};
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::commands::killswitch;
use crate::commands::settings::AppSettings;

/// H-5 FIX: Instead of storing the full VpnConfig (which has zeroized keys),
/// store only the metadata needed to request fresh keys from the backend.
#[derive(Debug, Clone)]
pub struct ReconnectInfo {
    /// The server dialled: for Multi-Hop, the ENTRY node.
    pub server_id: String,
    pub server_name: String,
    pub local_network_sharing: bool,
    /// P3-3: Persist custom MTU so reconnects honour user settings (0 = server default).
    pub custom_mtu: u16,
    /// P3-3: Persist custom port so reconnects honour user settings ("auto" = server default).
    pub custom_port: String,
    /// Persist custom DNS so reconnects match the user's active settings.
    pub custom_dns: Option<Vec<String>>,
    /// Whether reconnect must request and receive Xray Reality stealth mode.
    pub stealth_mode: bool,
    /// Whether reconnect must request and receive BirdoPQ protection.
    pub quantum_protection: bool,
    /// BirdoShield (D18): the per-device `dnsFiltering` flag this session was
    /// dialled with. A reconnect MUST re-send it — the backend keys the
    /// filtering resolver on the connect body, so a re-dial without it would
    /// hand back an unfiltered config and silently un-shield the session the
    /// user believed was protected.
    pub dns_filtering: bool,
    /// ADAPTIVE TRANSPORT: the `fallbackReason` wire value under which this
    /// session was granted the stealth transport (None = ordinary direct
    /// session). A reconnect must re-send it: the network is proven to filter
    /// direct WireGuard, so rebuilding direct would fail its establish-time
    /// handshake on every attempt — and the grant is fallback-scoped, NOT the
    /// plan-gated `stealth_mode` preference, which stays false. Session-scoped
    /// on purpose (never persisted): the next fresh connect re-tests the fast
    /// path, mirroring Android's expiring stealth preference.
    pub fallback_reason: Option<String>,
    /// The confirmed Multi-Hop route. None means a single-hop session.
    pub multi_hop: Option<MultiHopStatus>,
    /// MR-2390: who chose `server_id`. It decides how far the session may
    /// move when that server leaves the pool (`relay_retry::next`). A move
    /// keeps it.
    pub origin: SelectionOrigin,
}

impl ReconnectInfo {
    /// What the session is published as (contract §1: `server_id` is the
    /// exit for Multi-Hop).
    pub fn label(&self) -> SessionLabel {
        SessionLabel {
            server_name: self.server_name.clone(),
            server_id: self
                .multi_hop
                .as_ref()
                .map_or_else(|| self.server_id.clone(), |m| m.exit_id.clone()),
            multi_hop: self.multi_hop.clone(),
        }
    }
}

/// The session on record with its BirdoShield flag put through the fleet gate
/// as it is NOW (owner 2026-11-13). The session keeps the user's preference;
/// the gate can go off, or on, while it runs, so the unattended re-dial reads
/// it when it sends, exactly as a user-initiated dial does. Pure: the caller
/// passes `client::dns_filtering_gate_on()`.
pub(crate) fn redial_info_under_gate(info: &ReconnectInfo, gate_on: bool) -> ReconnectInfo {
    ReconnectInfo {
        dns_filtering: crate::api::client::dns_filtering_with_gate(info.dns_filtering, gate_on),
        ..info.clone()
    }
}

/// The exact `/vpn/connect` body a single-hop auto-reconnect posts for
/// `info`. Pure (no I/O): the attestation is fetched by the caller. Every
/// session property `ReconnectInfo` carries for the WIRE is mapped here —
/// `stealth_mode` / `quantum_protection` as `Some(true)`-or-absent, the
/// fallback-scoped stealth grant, and the D18 BirdoShield flag — through the
/// same `build_connect_request` the user-initiated connect uses, so the
/// re-dial cannot silently drop a property the session was granted.
pub(crate) fn reconnect_connect_request(
    info: &ReconnectInfo,
    device_name: &str,
    client_public_key: String,
    pq_client_public_key: Option<String>,
    attestation: Option<DesktopAttestation>,
) -> ConnectRequest {
    build_connect_request(
        &info.server_id,
        device_name,
        Some(client_public_key),
        if info.stealth_mode { Some(true) } else { None },
        // ADAPTIVE TRANSPORT: keep the fallback-scoped stealth grant across
        // reconnects — see ReconnectInfo::fallback_reason.
        info.fallback_reason.as_deref(),
        if info.quantum_protection {
            Some(true)
        } else {
            None
        },
        pq_client_public_key,
        info.dns_filtering,
        attestation,
    )
}

/// The exact `/vpn/multi-hop/connect` body a double-VPN auto-reconnect posts
/// — twin of [`reconnect_connect_request`]. `info.server_id` is the ENTRY
/// node; `exit_node_id` is the confirmed route's exit, passed explicitly so
/// the caller's `Some` check and this builder cannot disagree.
pub(crate) fn reconnect_multi_hop_request(
    info: &ReconnectInfo,
    exit_node_id: &str,
    device_name: &str,
    client_public_key: &str,
    pq_client_public_key: Option<String>,
    attestation: Option<DesktopAttestation>,
) -> MultiHopConnectRequest {
    build_multi_hop_request(
        &info.server_id,
        exit_node_id,
        device_name,
        client_public_key,
        info.stealth_mode,
        info.quantum_protection,
        pq_client_public_key,
        info.dns_filtering,
        attestation,
    )
}

/// Configuration for auto-reconnect behavior
#[derive(Debug, Clone)]
pub struct AutoReconnectConfig {
    /// Whether auto-reconnect is enabled
    pub enabled: bool,
    /// Initial delay before first reconnect attempt (ms)
    pub initial_delay_ms: u64,
    /// Maximum delay between reconnect attempts (ms)
    pub max_delay_ms: u64,
    /// Maximum number of reconnect attempts (0 = unlimited)
    pub max_attempts: u32,
    /// Backoff multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Health check interval when connected (ms)
    pub health_check_interval_ms: u64,
}

impl Default for AutoReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay_ms: 1000, // 1 second
            max_delay_ms: 60000,    // 1 minute max
            max_attempts: 10,       // Give up after 10 tries
            backoff_multiplier: 2.0,
            health_check_interval_ms: 5000, // Check every 5 seconds
        }
    }
}

impl AutoReconnectConfig {
    fn budget(&self) -> Budget {
        Budget {
            max_attempts: self.max_attempts,
            initial_delay: Duration::from_millis(self.initial_delay_ms),
            max_delay: Duration::from_millis(self.max_delay_ms),
            multiplier: self.backoff_multiplier,
            jitter: reconnect_policy::BACKOFF_JITTER,
        }
    }
}

/// FIX-2-13: the control-plane heartbeat that lets the backend reap orphaned
/// keys. It is no longer a liveness signal (the handshake age is), but its
/// `valid:false` answer is how a revocation arrives.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Whether a heartbeat is due for the session the loop watches (MR-946).
///
/// The FIRST one goes out as soon as the session is seen Connected — a new
/// connect, a re-dial or a server switch alike, since each of them starts a
/// fresh `SessionWatch` — and then one every [`HEARTBEAT_INTERVAL`]. It used
/// to count the first interval from the connect, so a key's first check-in
/// came 30 s late.
///
/// `last` is stamped BEFORE each request goes out (`ReconnectLoop::heartbeat`),
/// so a heartbeat that fails or never answers still waits a full interval for
/// the next: a failing heartbeat cannot become a burst. A new session beats
/// at once only after a connect the server has just accepted, which is
/// itself paced by the reconnect backoff and its breaker.
fn heartbeat_due(connected_since: Option<Instant>, last: Option<Instant>, now: Instant) -> bool {
    if connected_since.is_none() {
        return false;
    }
    last.is_none_or(|last| now.saturating_duration_since(last) >= HEARTBEAT_INTERVAL)
}

/// The one heartbeat for a dead session's key, after its tunnel came down: a
/// network that is down must not hold the recovery up for longer than this.
const OLD_KEY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The cap on the 30 s heartbeat. It rides the tunnel, and a tunnel whose
/// relay dropped the peer never answers it: the client's own 30 s request
/// timeout (more with a token refresh) kept the loop from judging liveness
/// for that long (WIN-FIX-3).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// The cap on a re-dial's control-plane exchange (attestation, `/vpn/connect`,
/// a token refresh and its retry): each request has the client's 30 s, and a
/// refresh can chain three of them.
const REDIAL_API_TIMEOUT: Duration = Duration::from_secs(45);

/// MR-2390: the cap on the server list a re-dial fetches to move off a
/// server that left the pool. When it runs out, that attempt fails like a
/// refused one and the next asks again; the server that left is never
/// re-dialled meanwhile. MR-2514: also the cap on the list a user connect
/// fetches for its one retry on another server (`commands::session`); when
/// it runs out, there is no retry.
pub(crate) const SERVER_LIST_TIMEOUT: Duration = Duration::from_secs(15);

/// How many health-check intervals the loop may go without checking in, when
/// it has not announced a longer step, before the watchdog restarts it.
const WATCHDOG_TICKS: u32 = 6;

/// What a teardown (or a give-up) may take before the watchdog acts: the
/// operation lock (30 s), the tunnel stop (15 s), the state writes and the
/// old-key probe, with room to spare — plus, when the stop timed out, the
/// wait for the cleanup it handed to a thread of its own, up to the
/// platform's [`EMERGENCY_TEARDOWN_BOUND`] (MR-2036: 65 s on Windows). That
/// case is a wedged netsh, the very one the wait is for; without it in the
/// allowance the watchdog took the loop for stuck and aborted it mid-wait.
///
/// [`EMERGENCY_TEARDOWN_BOUND`]: crate::vpn::EMERGENCY_TEARDOWN_BOUND
const TEARDOWN_ALLOWANCE: Duration =
    Duration::from_secs(90).saturating_add(crate::vpn::EMERGENCY_TEARDOWN_BOUND);

/// What a re-dial may take after its backoff: the server list of a move
/// ([`SERVER_LIST_TIMEOUT`], MR-2390), the DNS flush (5 s),
/// [`REDIAL_API_TIMEOUT`], the stealth helper's start, and `connect` (the
/// operation lock, 30 s, then `CONNECT_TIMEOUT`, 30 s), with room to spare —
/// plus, when the build failed, the wait for the dropped tunnel's cleanup
/// (MR-823; Linux too since MR-2039), up to the platform's
/// [`EMERGENCY_TEARDOWN_BOUND`].
///
/// [`EMERGENCY_TEARDOWN_BOUND`]: crate::vpn::EMERGENCY_TEARDOWN_BOUND
const DIAL_ALLOWANCE: Duration =
    Duration::from_secs(150).saturating_add(crate::vpn::EMERGENCY_TEARDOWN_BOUND);

/// Emitted once per session when the heartbeat reports the Free allowance used
/// up inside its grace window (birdo-web #590, contract v2 §4). The session
/// itself is untouched until the server ends it.
const QUOTA_WARNING_EVENT: &str = "quota-warning";

/// The `quota-warning` payload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuotaWarning {
    /// Seconds until the server ends the session, when it said.
    seconds_remaining: Option<u64>,
}

/// How long `stop()` waits for the loop to finish its current step before
/// aborting it. Normally milliseconds: every caller cancels the manager's
/// epoch first, and a cancelled dial returns at its next await. But the
/// tunnel build's machine-state passes are synchronous netsh (documented at
/// 10-25 s on AV-heavy machines), and aborting the task in the middle of a
/// build would drop it without the release that lifts the DNS guard. So
/// the grace outlasts a whole build (CONNECT_TIMEOUT) and abort stays a last
/// resort for a loop that is truly wedged.
const STOP_GRACE: Duration = Duration::from_secs(35);

struct LoopTask {
    shutdown: watch::Sender<bool>,
    handle: JoinHandle<()>,
    /// The loop's generation, as it checks in (see `Beat`).
    generation: u64,
}

/// The Free-allowance grace warning (birdo-web #590): at most once per
/// SESSION (REVIEW-WIN2-024). A reconnect or a settings reapply inside the
/// grace window builds a new tunnel and starts a new loop, and the mark used
/// to live in the loop's per-tunnel `SessionWatch`, so each of them sent the
/// notice and the system notification again. The service holds it, and it is
/// cleared with the session on record.
#[derive(Clone, Default)]
struct QuotaNotice(Arc<AtomicBool>);

impl QuotaNotice {
    /// True the first time it is asked in a session.
    fn claim(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }

    fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The session's quiet-rebuild cap (MR-2369, `reconnect_policy::QuietRebuilds`),
/// shared with every loop of the session like [`QuotaNotice`]: a loop the
/// watchdog restarts must not start the episode over, or a rebuild that
/// wedges the loop could re-dial for ever. A new session on record starts it
/// whole, and so does the session's end; within a session only
/// `QUIET_REBUILD_EPISODE_RESET` of health does.
#[derive(Clone, Default)]
struct QuietRebuildCap(Arc<std::sync::Mutex<QuietRebuilds>>);

impl QuietRebuildCap {
    /// Never held across an await.
    fn with<R>(&self, f: impl FnOnce(&mut QuietRebuilds) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn reset(&self) {
        self.with(|cap| *cap = QuietRebuilds::default());
    }
}

/// Auto-reconnect service
#[derive(Clone)]
pub struct AutoReconnectService {
    config: Arc<RwLock<AutoReconnectConfig>>,
    vpn_manager: Arc<VpnManager>,

    /// H-5 FIX: Store only server_id + server_name for reconnection.
    /// Fresh keys are fetched from the API on each reconnect attempt.
    last_reconnect_info: Arc<RwLock<Option<ReconnectInfo>>>,

    /// The settings file as the session on record connected with: what a
    /// settings reapply that cannot be applied goes back to (WIN-FIX-3).
    connected_settings: Arc<RwLock<Option<AppSettings>>>,

    /// API client for fetching fresh VPN configs on reconnect
    api: Arc<BirdoApi>,

    /// App handle used to access managed Xray state and app data paths during
    /// protected auto-reconnects. If unavailable, protected reconnect fails
    /// closed instead of downgrading to direct WireGuard.
    app_handle: Arc<std::sync::RwLock<Option<AppHandle>>>,

    /// The ONE running loop, if any (W1-018). `stop()` waits for it to exit,
    /// so a `start()` that follows can never run beside a straggler.
    task: Arc<TokioMutex<Option<LoopTask>>>,

    /// How many loops are alive right now; the tests assert it never exceeds 1.
    live_loops: Arc<AtomicUsize>,

    /// Shared with every loop of the session.
    quota_notice: QuotaNotice,

    /// Shared with every loop of the session (MR-2369).
    quiet_rebuilds: QuietRebuildCap,

    /// The running loop's last check-in, read by the watchdog.
    pulse: Pulse,

    /// The watchdog thread is running (the first `start` starts it).
    watchdog: Arc<AtomicBool>,

    /// Loops the watchdog has restarted.
    restarts: Arc<AtomicUsize>,
}

/// The running loop's sign of life (WIN-FIX-3): when it last checked in, and
/// how long it said it may be silent from then. Written by the loop, read by
/// the watchdog thread; never held across anything.
#[derive(Clone, Default)]
struct Pulse(Arc<std::sync::Mutex<Option<Beat>>>);

#[derive(Debug, Clone, Copy)]
struct Beat {
    /// Which loop checked in: a restarted loop's beat must not be cleared by
    /// the loop it replaced (see `LoopAlive`).
    generation: u64,
    at: Instant,
    allowance: Duration,
}

impl Pulse {
    fn beat(&self, generation: u64, allowance: Duration) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Beat {
            generation,
            at: Instant::now(),
            allowance,
        });
    }

    fn read(&self) -> Option<Beat> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Give the loop of `generation` a fresh `allowance` from now — only
    /// while its beat is still the one on record. A loop that ended has
    /// cleared it, and a cleared pulse stays clear: re-beating it is what had
    /// the watchdog restart a loop that had already finished (WIN3-008).
    fn renew(&self, generation: u64, allowance: Duration, now: Instant) -> bool {
        let mut beat = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match beat.as_mut() {
            Some(b) if b.generation == generation => {
                b.at = now;
                b.allowance = allowance;
                true
            }
            _ => false,
        }
    }

    /// The loop of `generation` is gone: there is nothing to watch.
    fn clear(&self, generation: u64) {
        let mut beat = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if beat.is_some_and(|b| b.generation == generation) {
            *beat = None;
        }
    }
}

/// Whether a loop that last checked in `silent_for` ago, saying it might be
/// silent for `allowance`, has stopped.
fn overdue(silent_for: Duration, allowance: Duration) -> bool {
    silent_for > allowance
}

/// The watchdog's measure of a loop's silence (WIN3-003).
///
/// `Instant` on Windows counts the time the machine spent in standby; the
/// watchdog's `thread::sleep` does not. After a wake it looked at a beat
/// from before the sleep, read the whole sleep as silence, and restarted a
/// healthy loop — losing its policy, its session watch and a pending roam.
/// A look more than two periods after the previous one means the watchdog
/// itself was away (asleep with the machine, or frozen with the process),
/// and the loop could not have run either: silence counts from the waking.
struct WatchdogClock {
    last_look: Instant,
    awake_since: Instant,
}

impl WatchdogClock {
    fn new(now: Instant) -> Self {
        Self {
            last_look: now,
            awake_since: now,
        }
    }

    /// Record a look at `now`, one `period` after the last one was due.
    fn look(&mut self, now: Instant, period: Duration) {
        if now.saturating_duration_since(self.last_look) > period * 2 {
            self.awake_since = now;
        }
        self.last_look = now;
    }

    /// How long a loop that checked in at `beat` has been silent as of
    /// `now`, counting only time the watchdog was awake to see.
    fn silent_for(&self, beat: Instant, now: Instant) -> Duration {
        now.saturating_duration_since(beat.max(self.awake_since))
    }
}

/// One look of the watchdog at `now`: the loop to restart, if one is overdue,
/// with how long it has been silent (for the log). A verdict renews that
/// loop's allowance from `now`, so the restart gets a whole allowance before
/// the next one — and a loop that ended (its pulse cleared) gets none
/// (WIN3-008). Apart from the thread so a test can drive it across a freeze
/// (REVIEW-WIN3-013).
fn watchdog_look(
    clock: &mut WatchdogClock,
    pulse: &Pulse,
    now: Instant,
    period: Duration,
) -> Option<(Beat, Duration)> {
    clock.look(now, period);
    let beat = pulse.read()?;
    let silent_for = clock.silent_for(beat.at, now);
    (overdue(silent_for, beat.allowance) && pulse.renew(beat.generation, beat.allowance, now))
        .then_some((beat, silent_for))
}

/// Held by a loop task for as long as it lives — an aborted one included,
/// which never reaches the end of its body.
struct LoopAlive {
    live_loops: Arc<AtomicUsize>,
    pulse: Pulse,
    generation: u64,
}

impl Drop for LoopAlive {
    fn drop(&mut self) {
        self.live_loops.fetch_sub(1, Ordering::SeqCst);
        self.pulse.clear(self.generation);
    }
}

impl AutoReconnectService {
    /// Create a new auto-reconnect service
    pub fn new(vpn_manager: Arc<VpnManager>, api: Arc<BirdoApi>) -> Self {
        Self {
            config: Arc::new(RwLock::new(AutoReconnectConfig::default())),
            vpn_manager,
            last_reconnect_info: Arc::new(RwLock::new(None)),
            connected_settings: Arc::new(RwLock::new(None)),
            api,
            app_handle: Arc::new(std::sync::RwLock::new(None)),
            task: Arc::new(TokioMutex::new(None)),
            live_loops: Arc::new(AtomicUsize::new(0)),
            quota_notice: QuotaNotice::default(),
            quiet_rebuilds: QuietRebuildCap::default(),
            pulse: Pulse::default(),
            watchdog: Arc::new(AtomicBool::new(false)),
            restarts: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Attach the Tauri app handle after setup so reconnects can start Xray.
    pub fn set_app_handle(&self, app: AppHandle) {
        match self.app_handle.write() {
            Ok(mut guard) => *guard = Some(app),
            Err(_) => tracing::warn!("Auto-reconnect app handle lock poisoned"),
        }
    }

    /// H-5 FIX: Store only the reconnect metadata, never key material: keys
    /// are zeroized after WireGuard session creation and every re-dial fetches
    /// fresh ones.
    pub async fn store_last_config(&self, info: ReconnectInfo) {
        tracing::debug!("Stored reconnect info for: {}", info.server_name);
        // MR-1861: a new session on record, which an update may resume again
        // (a Disconnect had stopped `update_resume` from recording). Before
        // the write, so a Disconnect racing it still wins.
        crate::commands::update_resume::session_started();
        // MR-2369: a connect (the user's, the tray's, auto-connect, a
        // settings reapply, an update's resume) starts a new episode. The
        // reconnect loop's own re-dials never come through here.
        self.quiet_rebuilds.reset();
        *self.last_reconnect_info.write().await = Some(info);
    }

    /// The session on record: what `reapply_vpn_settings` rebuilds, and what a
    /// failed switch reverts to. None when there is no session.
    pub async fn current_info(&self) -> Option<ReconnectInfo> {
        self.last_reconnect_info.read().await.clone()
    }

    /// [`current_info`](Self::current_info) without waiting, for a caller
    /// that cannot await: the process exit (`commands::update_resume`).
    /// `None` too while the record is being written.
    pub fn current_info_now(&self) -> Option<ReconnectInfo> {
        self.last_reconnect_info
            .try_read()
            .ok()
            .and_then(|info| info.clone())
    }

    /// Record the settings the session on record connected with.
    pub async fn store_connected_settings(&self, settings: Option<AppSettings>) {
        *self.connected_settings.write().await = settings;
    }

    /// See `connected_settings`. None when there is no session.
    pub async fn connected_settings(&self) -> Option<AppSettings> {
        self.connected_settings.read().await.clone()
    }

    /// Clear stored config (called on intentional disconnect): the session
    /// is over.
    pub async fn clear_last_config(&self) {
        *self.last_reconnect_info.write().await = None;
        *self.connected_settings.write().await = None;
        self.quota_notice.reset();
        self.quiet_rebuilds.reset();
    }

    /// Start the health check monitoring loop. Idempotent.
    ///
    /// The first start also starts the watchdog, on an OS thread so that a
    /// runtime with every worker busy cannot silence it as well. When the loop
    /// has not checked in for longer than it said it might (`WATCHDOG_TICKS`
    /// health-check intervals per step; a teardown or a re-dial announces its
    /// own, longer allowance), the watchdog logs it and restarts the loop.
    ///
    /// Restart, not release: the owner's rule is fail-closed — in lockdown the
    /// block holds until the user disconnects or turns the kill switch off,
    /// and a stuck loop is an engine fault, not the user's decision. Releasing
    /// the block would leak exactly when the protection is meant to hold. A
    /// fresh loop re-reads the session and resumes recovery (tear down,
    /// re-dial, or end as the policy says) with the block untouched. The way
    /// out never depends on the loop: Disconnect releases the block on a
    /// deadline (`session::end_session`) and quitting always exits
    /// (`main.rs`).
    pub async fn start(&self) -> Result<(), String> {
        let mut task = self.task.lock().await;
        self.start_locked(&mut task).await
    }

    /// [`start`](Self::start) with the task slot already held, so a restart
    /// can replace a loop in ONE hold of it (WIN3-008).
    async fn start_locked(&self, task: &mut Option<LoopTask>) -> Result<(), String> {
        if task.as_ref().is_some_and(|t| !t.handle.is_finished()) {
            return Ok(());
        }

        let cfg = self.config.read().await.clone();
        if !cfg.enabled {
            return Ok(());
        }
        let check_interval = Duration::from_millis(cfg.health_check_interval_ms);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        static GENERATIONS: AtomicU64 = AtomicU64::new(0);
        let generation = GENERATIONS.fetch_add(1, Ordering::SeqCst) + 1;
        let worker = self.new_loop(&cfg, shutdown_rx, generation);
        self.live_loops.fetch_add(1, Ordering::SeqCst);
        let alive = LoopAlive {
            live_loops: Arc::clone(&self.live_loops),
            pulse: self.pulse.clone(),
            generation,
        };
        let handle = tokio::spawn(async move {
            let _alive = alive;
            worker.run(check_interval).await;
        });
        *task = Some(LoopTask {
            shutdown: shutdown_tx,
            handle,
            generation,
        });
        self.spawn_watchdog(check_interval);

        tracing::info!("Auto-reconnect service started");
        Ok(())
    }

    /// The loop [`start_locked`](Self::start_locked) runs, on the session's
    /// shared state: the session on record, the quota notice and the
    /// quiet-rebuild cap (MR-2369), which a restarted loop must carry on
    /// with, not start over.
    fn new_loop(
        &self,
        cfg: &AutoReconnectConfig,
        shutdown: watch::Receiver<bool>,
        generation: u64,
    ) -> ReconnectLoop {
        let check_interval = Duration::from_millis(cfg.health_check_interval_ms);
        let app = self.app_handle.read().ok().and_then(|guard| guard.clone());
        let transport_exits = app
            .as_ref()
            .map(|app| app.state::<XrayManager>().subscribe_exits());
        ReconnectLoop {
            vpn_manager: Arc::clone(&self.vpn_manager),
            last_reconnect_info: Arc::clone(&self.last_reconnect_info),
            api: Arc::clone(&self.api),
            app,
            shutdown,
            network: network_events::subscribe(),
            transport_exits,
            policy: ReconnectPolicy::new(cfg.budget()),
            session: SessionWatch::default(),
            quota_notice: self.quota_notice.clone(),
            quiet_rebuilds: self.quiet_rebuilds.clone(),
            rng: reconnect_policy::unit_random,
            alive: None,
            pulse: self.pulse.clone(),
            generation,
            step_allowance: check_interval * WATCHDOG_TICKS,
        }
    }

    /// The watchdog thread (see [`start`](Self::start)). It looks once per
    /// health-check interval. After a restart it gives the new loop a whole
    /// allowance before judging again, so a runtime that cannot run the new
    /// loop either is reported once per allowance, not on every look.
    fn spawn_watchdog(&self, period: Duration) {
        if self.watchdog.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.watchdog.store(false, Ordering::SeqCst);
            return;
        };
        let svc = self.clone();
        let spawned = std::thread::Builder::new()
            .name("birdo-reconnect-watchdog".into())
            .spawn(move || {
                let mut clock = WatchdogClock::new(Instant::now());
                loop {
                    std::thread::sleep(period);
                    let Some((beat, silent_for)) =
                        watchdog_look(&mut clock, &svc.pulse, Instant::now(), period)
                    else {
                        continue;
                    };
                    tracing::error!(
                        "Auto-reconnect has not checked in for {} s (allowed {} s) — restarting \
                         it; the kill switch's block is left as it is (blocking: {})",
                        silent_for.as_secs(),
                        beat.allowance.as_secs(),
                        killswitch::platform_is_blocking()
                    );
                    let svc = svc.clone();
                    let generation = beat.generation;
                    runtime.spawn(async move { svc.restart_stalled(generation).await });
                }
            });
        if spawned.is_err() {
            tracing::warn!("Could not start the auto-reconnect watchdog");
            self.watchdog.store(false, Ordering::SeqCst);
        }
    }

    /// Replace the loop of `generation`, which stopped checking in. It is
    /// aborted at its current await; one stuck in a synchronous call ends at
    /// its next one.
    ///
    /// WIN3-008: only that loop, only while it still runs, and in one hold of
    /// the task slot. A loop stopped on purpose (`stop` took it), one that
    /// finished on its own (a give-up, which a restart would undo) and a
    /// newer loop a connect has started since (possibly mid-dial) are all
    /// left alone; and a `stop` cannot slip in between the abort and the new
    /// start and miss the loop that start creates.
    async fn restart_stalled(&self, generation: u64) {
        let mut task = self.task.lock().await;
        if !task
            .as_ref()
            .is_some_and(|t| t.generation == generation && !t.handle.is_finished())
        {
            return;
        }
        let Some(LoopTask {
            shutdown, handle, ..
        }) = task.take()
        else {
            return;
        };
        let _ = shutdown.send(true);
        handle.abort();
        // A loop parked at an await is gone at once; wait that moment, so the
        // new one never runs beside it. One stuck in a synchronous call is
        // not waited for.
        let _ = timeout(Duration::from_secs(1), handle).await;
        if let Err(e) = self.start_locked(&mut task).await {
            tracing::error!("The auto-reconnect loop could not be restarted: {}", e);
        }
        self.restarts.fetch_add(1, Ordering::SeqCst);
    }

    /// Stop the loop and WAIT for it to exit (W1-018: `stop()` used to flip a
    /// flag the loop only read between ticks, so a quick stop/start left the
    /// old loop running beside the new one).
    pub async fn stop(&self) {
        let mut task = self.task.lock().await;
        let Some(LoopTask {
            shutdown, handle, ..
        }) = task.take()
        else {
            return;
        };
        let _ = shutdown.send(true);
        let abort = handle.abort_handle();
        if timeout(STOP_GRACE, handle).await.is_err() {
            tracing::warn!("Auto-reconnect loop did not stop within {STOP_GRACE:?} — aborting it");
            abort.abort();
        }
        tracing::info!("Auto-reconnect service stopped");
    }

    #[cfg(test)]
    fn live_loops(&self) -> usize {
        self.live_loops.load(Ordering::SeqCst)
    }
}

/// Per-session facts the policy needs that the manager does not keep.
#[derive(Default)]
struct SessionWatch {
    connected_since: Option<Instant>,
    /// The default route the session was built over (W1-003).
    pinned_route: Option<PhysicalRoute>,
    resumes_seen: u64,
    /// A resume asked the path to be re-proven at this instant.
    verify_since: Option<Instant>,
    last_heartbeat: Option<Instant>,
    /// Whether the machine had a route off it at the last look.
    link: LocalLink,
    /// The packet path's tick across looks (WIN3-003).
    #[cfg(target_os = "windows")]
    stall: super::wireguard_new::StallWatch,
    /// Heartbeats that failed on the network in a row (interface loss).
    /// Windows only: elsewhere there is no rebuild-and-re-prove path, and
    /// macOS has no route signal to tell a local outage from a dead tunnel.
    #[cfg(target_os = "windows")]
    heartbeat_misses: u32,
    /// The send-path rule's one rebuild per episode (interface loss).
    #[cfg(target_os = "windows")]
    send_repair: reconnect_policy::SendPathRepair,
    /// MR-2369: a live check-in said server housekeeping released this key
    /// (`reaped`) and the cap allowed a quiet rebuild. The first look past
    /// its random wait declares the tunnel dead (`DropCause::ServerReleased`),
    /// and the policy's teardown and re-dial rebuild it.
    release: Option<PendingRelease>,
}

/// A quiet rebuild the cap allowed, waiting out its jitter (MR-2369).
struct PendingRelease {
    /// When the tunnel is declared dead: the check-in plus
    /// `reconnect_policy::release_wait`.
    due: Instant,
    /// How the session ends if the rebuild cannot go ahead (the 426 floor).
    ending: IpcError,
}

/// A heartbeat's outcome on the wire, apart from sending it (MR-2369), so a
/// test hands the loop a real reply.
enum HeartbeatReply {
    Answered(crate::api::types::HeartbeatResponse),
    Failed(crate::api::ApiError),
    /// No answer inside `HEARTBEAT_TIMEOUT`.
    Unanswered,
}

/// What a heartbeat's outcome asks of the loop.
#[derive(Debug, PartialEq)]
enum AfterReply {
    Continue,
    /// The server ended the session: `end_by_server`.
    End(IpcError),
    /// The user is ending the session: theirs to end.
    Stop,
}

enum Wake {
    Tick,
    Network,
    TransportDied,
}

enum Flow {
    /// Wait for the next wake-up.
    Continue,
    /// Decide again at once (after a teardown or a dial).
    Again,
    Stop,
}

struct ReconnectLoop {
    vpn_manager: Arc<VpnManager>,
    last_reconnect_info: Arc<RwLock<Option<ReconnectInfo>>>,
    api: Arc<BirdoApi>,
    app: Option<AppHandle>,
    shutdown: watch::Receiver<bool>,
    network: watch::Receiver<u64>,
    transport_exits: Option<watch::Receiver<u64>>,
    policy: ReconnectPolicy,
    session: SessionWatch,
    quota_notice: QuotaNotice,
    /// The session's quiet-rebuild cap (MR-2369), shared with the service.
    quiet_rebuilds: QuietRebuildCap,
    /// The quiet rebuild's jitter source (`reconnect_policy::unit_random`).
    rng: fn() -> f64,
    /// When the session was last known to be alive on the server — it
    /// connected, or a heartbeat answered for it — and the resume count then.
    /// Kept across teardowns: it is what reads the old key's answer
    /// (`reconnect_policy::recently_alive`).
    alive: Option<(Instant, u64)>,
    /// Where this loop checks in with the watchdog, as `generation`.
    pulse: Pulse,
    generation: u64,
    /// How long one ordinary step may take (`WATCHDOG_TICKS` intervals).
    step_allowance: Duration,
}

/// Interface loss: rebuild the live tunnel's path to the relay on `path`
/// (`VpnManager::repath`: our routes back, a fresh socket, a forced
/// handshake) and open a re-prove window for it. It is the send-path rule's
/// one rebuild for this episode. `Err` means re-dial.
///
/// Heartbeats missed during the outage say nothing about the rebuilt path:
/// the window opened here judges it, so they are forgotten — or, once it
/// closes, they would open a second, redundant window that re-dials a
/// healthy tunnel if its answer happens to be lost.
#[cfg(target_os = "windows")]
async fn rebuild_path<S: PathSignals>(
    signals: &S,
    session: &mut SessionWatch,
    path: PhysicalRoute,
    now: Instant,
) -> Result<(), String> {
    session.send_repair.rebuilt(now);
    session.verify_since = Some(now);
    session.heartbeat_misses = 0;
    signals.repath(path).await.map(|_| ())
}

/// What the packet path's rules read off the live tunnel (Windows), and the
/// clock they read it by. A trait so a test can drive the rules — in their
/// order — on paused time (MR-1408); the reconnect loop's is the manager.
#[cfg(target_os = "windows")]
trait PathSignals {
    /// Now, for the stall rule: read after the awaits that gathered the
    /// signals, not at the start of the look.
    fn now(&self) -> Instant;
    async fn packet_path_progress(&self) -> Option<Instant>;
    async fn send_health(&self) -> Option<super::wireguard_new::SendHealth>;
    async fn repath(&self, path: PhysicalRoute) -> Result<bool, String>;
    async fn peer_unresponsive(&self) -> bool;
    /// A resume: what went unanswered before the sleep is forgotten.
    async fn restart_response_watch(&self);
    /// Ask the relay for a handshake now.
    async fn force_handshake(&self);
}

#[cfg(target_os = "windows")]
impl PathSignals for VpnManager {
    fn now(&self) -> Instant {
        Instant::now()
    }

    async fn packet_path_progress(&self) -> Option<Instant> {
        VpnManager::packet_path_progress(self).await
    }

    async fn send_health(&self) -> Option<super::wireguard_new::SendHealth> {
        VpnManager::send_health(self).await
    }

    async fn repath(&self, path: PhysicalRoute) -> Result<bool, String> {
        VpnManager::repath(self, path).await
    }

    async fn peer_unresponsive(&self) -> bool {
        VpnManager::peer_unresponsive(self).await
    }

    async fn restart_response_watch(&self) {
        VpnManager::restart_response_watch(self).await
    }

    async fn force_handshake(&self) {
        VpnManager::force_handshake(self).await
    }
}

/// W1-003 / interface loss (Windows): what a look does on finding the machine
/// resumed since the last one, apart from `check_liveness` so a test can
/// drive it with a fake tunnel. The path is to be re-proven now, not when the
/// handshake goes stale; what went unanswered before the sleep says nothing
/// about the path the machine woke on; the adapter may have been powered
/// down with the machine, taking our routes and the socket's path with it, so
/// unless this look already rebuilt it (`rebuilt`) it is rebuilt on the route
/// the machine woke on (with none yet, the link's return does it); and the
/// relay is asked for a handshake. `Err`: the rebuild failed, the caller
/// re-dials (no handshake is asked of the path that was just given up).
#[cfg(target_os = "windows")]
async fn reprove_after_resume<S: PathSignals>(
    signals: &S,
    session: &mut SessionWatch,
    route: Option<PhysicalRoute>,
    rebuilt: &mut bool,
    now: Instant,
) -> Result<(), String> {
    session.verify_since = Some(now);
    signals.restart_response_watch().await;
    if let (Some(path), false) = (route, *rebuilt) {
        tracing::info!("Resumed — rebuilding the tunnel's path to the relay");
        *rebuilt = true;
        if let Err(e) = rebuild_path(signals, session, path, now).await {
            tracing::warn!(
                "Rebuilding the path to the relay failed ({}) — re-dialling",
                e
            );
            return Err(e);
        }
    }
    signals.force_handshake().await;
    Ok(())
}

/// The rules that judge the packet path itself, in the order a look applies
/// them (Windows): the stall rule, the send-path rule, the fast dead-path
/// rule. `Some` is the look's verdict; `None` leaves it to the handshake-age
/// backstop. `rebuilt`: this look already rebuilt the relay socket (a roam, a
/// resume, the link's return).
///
/// The stall rule comes first (MR-1408): a packet path that stopped running
/// stops the retransmits the fast rule counts with it, and whatever the fast
/// rule or the send-path rule reads beside a stalled path, the cause is the
/// stall — re-dialled at once, with no old-key probe
/// (`reconnect_policy::asks_the_old_key`).
#[cfg(target_os = "windows")]
async fn judge_packet_path<S: PathSignals>(
    signals: &S,
    session: &mut SessionWatch,
    route: Option<PhysicalRoute>,
    link: LinkState,
    rebuilt: bool,
    now: Instant,
) -> Option<Liveness> {
    // WIN-FIX-3 P0: the packet path itself stopped running. Nothing it
    // carries gets through, the relay's answers included, and boringtun's
    // retransmits (what the fast rule below counts) stop with it — the
    // T5 hang sat here, Protected, until the 180 s backstop. Judged over
    // two looks, so a sleep the machine just woke from is not one
    // (WIN3-003).
    // Windows only (MR-1117): macOS and Linux have no stall rule, so a
    // stalled packet path there is caught by the 180 s backstop.
    if session
        .stall
        .observe(signals.packet_path_progress().await, signals.now())
    {
        tracing::warn!("The tunnel's packet path stopped running — declaring the tunnel dead");
        return Some(Liveness::Dead(DropCause::PacketPathStalled));
    }

    // Interface loss (2026-10-07): the OS refuses our sends for a path
    // reason (WSAEINVAL, WSAENETUNREACH, …) and keeps refusing them. The
    // rules around this one read the relay's side, and a relay with
    // traffic for us keeps initiating handshakes that reach us, so they
    // all read healthy while nothing left. Rebuild the socket on the
    // current path once; refused again, re-dial.
    if !rebuilt {
        let health = signals.send_health().await.unwrap_or_default();
        let broken = super::wireguard_new::send_path_broken(&health, now);
        match session
            .send_repair
            .observe(broken, link == LinkState::Offline, now)
        {
            reconnect_policy::SendPathVerdict::Fine => {}
            reconnect_policy::SendPathVerdict::Rebuild => {
                tracing::warn!(
                    "Sends to the relay have been refused for {} s (os error {}) — \
                     rebuilding the socket on the current path",
                    health
                        .failing_since
                        .map_or(0, |t| now.saturating_duration_since(t).as_secs()),
                    health.last_code.unwrap_or_default()
                );
                let Some(path) = route else {
                    return Some(Liveness::Dead(DropCause::PathChanged));
                };
                if let Err(e) = rebuild_path(signals, session, path, now).await {
                    tracing::warn!(
                        "Rebuilding the path to the relay failed ({}) — re-dialling",
                        e
                    );
                    return Some(Liveness::Dead(DropCause::PathChanged));
                }
            }
            reconnect_policy::SendPathVerdict::Escalate => {
                tracing::warn!(
                    "Sends to the relay are still refused on the rebuilt socket — declaring \
                     the tunnel dead"
                );
                return Some(Liveness::Dead(DropCause::PathChanged));
            }
        }
    }

    // The fast dead-path rule: with the relay unreachable the tunnel
    // stops carrying traffic at once, and waiting for the 180 s
    // handshake-age backstop left the app saying Protected for minutes.
    if link != LinkState::Offline && signals.peer_unresponsive().await {
        tracing::warn!(
            "The relay stopped answering handshakes while traffic is waiting — declaring \
             the tunnel dead"
        );
        return Some(Liveness::Dead(DropCause::HandshakeStale));
    }

    None
}

async fn transport_exit(exits: &mut Option<watch::Receiver<u64>>) {
    if let Some(rx) = exits {
        if rx.changed().await.is_ok() {
            return;
        }
    }
    std::future::pending::<()>().await
}

impl ReconnectLoop {
    async fn run(mut self, check_interval: Duration) {
        // MR-2369: a new loop (a connect, or a restart of one that stopped
        // checking in) has seen no check-in yet: no healthy run carries over.
        self.quiet_rebuilds.with(QuietRebuilds::interrupted);
        let mut ticker = interval(check_interval);
        // After a resume, one tick — not a burst of every tick that was missed.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            self.check_in(self.step_allowance);
            let mut wake = tokio::select! {
                _ = self.shutdown.changed() => break,
                _ = ticker.tick() => Wake::Tick,
                _ = self.network.changed() => Wake::Network,
                _ = transport_exit(&mut self.transport_exits) => Wake::TransportDied,
            };
            loop {
                if *self.shutdown.borrow() {
                    return;
                }
                self.check_in(self.step_allowance);
                match self.step(wake).await {
                    Flow::Continue => break,
                    Flow::Again => wake = Wake::Tick,
                    Flow::Stop => return,
                }
            }
        }
        tracing::debug!("Auto-reconnect loop received shutdown signal");
    }

    /// Tell the watchdog this loop is alive and may be silent for `allowance`.
    fn check_in(&self, allowance: Duration) {
        self.pulse.beat(self.generation, allowance);
    }

    async fn step(&mut self, wake: Wake) -> Flow {
        let vm = Arc::clone(&self.vpn_manager);
        let state = vm.get_state().await;
        let observed = match state {
            ConnectionState::Connected => Observed::Connected,
            ConnectionState::Connecting
            | ConnectionState::Switching
            | ConnectionState::Disconnecting => Observed::Busy,
            ConnectionState::Reconnecting { .. }
            | ConnectionState::Error(_)
            | ConnectionState::Disconnected => Observed::NotConnected,
        };
        let now = Instant::now();
        let route = network_events::default_route();
        let upgrade_blocked = crate::api::upgrade_gate::is_blocked();

        let liveness = if observed == Observed::Connected {
            if let Some(ending) = self.release_stopped_by_floor(now, upgrade_blocked) {
                return self.end_by_server(ending).await;
            }
            self.check_liveness(&wake, route, now).await
        } else {
            self.session = SessionWatch::default();
            // MR-2369: a session that is not up is not a healthy one.
            self.quiet_rebuilds.with(QuietRebuilds::interrupted);
            Liveness::Healthy
        };
        let tick = Tick {
            now,
            observed,
            holds_tunnel: observed == Observed::NotConnected && vm.holds_tunnel().await,
            liveness,
            connectivity: network_events::connectivity_of(route.as_ref()),
            upgrade_blocked,
            has_target: self.last_reconnect_info.read().await.is_some(),
        };
        let action = self.policy.decide(&tick);
        self.execute(action, now).await
    }

    /// MR-2369: a quiet rebuild cannot get past the 426 floor (its re-dial
    /// would be refused, and the policy only halts over a dead tunnel that
    /// still reads Connected). With the floor latched, the pending rebuild's
    /// ending, to end the session with; otherwise nothing.
    fn release_stopped_by_floor(
        &mut self,
        now: Instant,
        upgrade_blocked: bool,
    ) -> Option<IpcError> {
        let look = self
            .session
            .release
            .as_ref()
            .map(|r| reconnect_policy::release_look(r.due, now, upgrade_blocked))?;
        if look != ReleaseLook::End {
            return None;
        }
        self.session.release.take().map(|r| r.ending)
    }

    async fn check_liveness(
        &mut self,
        wake: &Wake,
        route: Option<PhysicalRoute>,
        now: Instant,
    ) -> Liveness {
        let vm = Arc::clone(&self.vpn_manager);
        if self.session.connected_since.is_none() {
            // A new tunnel: the server has just accepted this session's key.
            self.alive = Some((now, network_events::resume_count()));
        }
        let session = &mut self.session;
        let connected_since = *session.connected_since.get_or_insert_with(|| {
            session.pinned_route = route;
            session.resumes_seen = network_events::resume_count();
            now
        });

        // W1-005: xray died under the session; WireGuard is sending into a
        // dead loopback port.
        if matches!(wake, Wake::TransportDied) {
            return Liveness::Dead(DropCause::TransportDied);
        }
        // MR-2369: housekeeping released this key at a check-in, the cap
        // allowed a quiet rebuild, and its random wait has run out. (Until
        // then the dead tunnel's routes keep traffic in it.)
        if session.release.as_ref().is_some_and(|r| {
            reconnect_policy::release_look(r.due, now, false) == ReleaseLook::Rebuild
        }) {
            session.release = None;
            return Liveness::Dead(DropCause::ServerReleased);
        }
        // At most one rebuild of the relay socket per look.
        #[cfg(target_os = "windows")]
        let mut rebuilt = false;
        // W1-003: the socket and the endpoint host route are pinned to the
        // interface the session was built over; if the default route moved,
        // nothing of ours leaves the machine any more. Windows follows the new
        // route in place first (same session, same key); the forced handshake
        // must then complete inside PATH_VERIFY_WINDOW, or the verify rule
        // below declares the path dead and the fast re-dial takes over.
        if reconnect_policy::needs_rebind(session.pinned_route.as_ref(), route.as_ref()) {
            #[cfg(target_os = "windows")]
            if let (Some(from), Some(to)) = (session.pinned_route, route) {
                match vm.roam(from, to).await {
                    Ok(()) => {
                        tracing::info!(
                            "Default route moved — the tunnel followed it; re-proving the path"
                        );
                        session.pinned_route = Some(to);
                        session.verify_since = Some(now);
                        session.send_repair.rebuilt(now);
                        rebuilt = true;
                    }
                    Err(e) => {
                        tracing::warn!("In-place roam not possible ({}) — re-dialling", e);
                        return Liveness::Dead(DropCause::PathChanged);
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            return Liveness::Dead(DropCause::PathChanged);
        }
        if session.pinned_route.is_none() {
            session.pinned_route = route;
        }
        // W1-003: after a resume, prove the path now instead of waiting for
        // the handshake to go stale.
        let resumes = network_events::resume_count();
        if resumes != session.resumes_seen {
            session.resumes_seen = resumes;
            #[cfg(target_os = "windows")]
            if reprove_after_resume(vm.as_ref(), session, route, &mut rebuilt, now)
                .await
                .is_err()
            {
                return Liveness::Dead(DropCause::PathChanged);
            }
            #[cfg(not(target_os = "windows"))]
            {
                session.verify_since = Some(now);
                vm.force_handshake().await;
            }
        }
        // Wi-Fi re-associates for several seconds after a resume. The window
        // to prove the path opens when there is a path to prove, so a slow
        // re-association does not read as a broken tunnel.
        if route.is_none() && session.verify_since.is_some() {
            session.verify_since = Some(now);
        }
        // REVIEW-WIN2-005: a local outage is not a dead peer. While there is
        // no route off the machine the fast rule below cannot judge the
        // relay; when the route comes back on the same path (a different one
        // was handled above), the path is re-proven like after a resume.
        let link = session
            .link
            .observe(network_events::connectivity_of(route.as_ref()));
        if link == LinkState::Returned {
            session.verify_since = Some(now);
            #[cfg(target_os = "windows")]
            vm.restart_response_watch().await;
            // Interface loss (2026-10-07): an adapter that went away took our
            // routes with it — the endpoint host route among them — and the
            // socket connected over it is refused every send from then on
            // (WSAEINVAL). A nudge on that socket proved nothing and fixed
            // nothing; rebuild the path on the route that came back.
            #[cfg(target_os = "windows")]
            if let (Some(path), false) = (route, rebuilt) {
                tracing::info!("The network is back — rebuilding the tunnel's path to the relay");
                rebuilt = true;
                if let Err(e) = rebuild_path(vm.as_ref(), session, path, now).await {
                    tracing::warn!(
                        "Rebuilding the path to the relay failed ({}) — re-dialling",
                        e
                    );
                    return Liveness::Dead(DropCause::PathChanged);
                }
            }
            vm.force_handshake().await;
        }
        // Interface loss: a heartbeat that keeps failing on the network
        // while there is a route off the machine says the tunnel may carry
        // nothing. It tears nothing down — the API can be down while the
        // tunnel is fine — it asks the tunnel to prove itself with a
        // handshake the relay must answer inside PATH_VERIFY_WINDOW.
        // Windows only, and never without a route signal (see
        // `reconnect_policy::heartbeat_reprove`).
        #[cfg(target_os = "windows")]
        if reconnect_policy::heartbeat_reprove(
            session.heartbeat_misses,
            network_events::connectivity_of(route.as_ref()),
            link,
            session.verify_since.is_some(),
        ) {
            tracing::info!(
                "The heartbeat failed {} times in a row — re-proving the tunnel with a handshake",
                session.heartbeat_misses
            );
            session.heartbeat_misses = 0;
            session.verify_since = Some(now);
            vm.force_handshake().await;
        }

        // The packet path's own rules (Windows), in their order: the stall
        // rule, the send-path rule, the fast dead-path rule.
        #[cfg(target_os = "windows")]
        if let Some(dead) = judge_packet_path(vm.as_ref(), session, route, link, rebuilt, now).await
        {
            return dead;
        }

        let Some(age) = vm.handshake_age().await else {
            // The tunnel went away under us; the next tick sees the new state.
            return Liveness::Healthy;
        };
        // A re-prove window closes only on the relay's answer to an
        // initiation of OURS (`reconnect_policy::judged_age`).
        #[cfg(target_os = "windows")]
        let proof_age = vm.proof_age().await.unwrap_or(age);
        #[cfg(not(target_os = "windows"))]
        let proof_age = age;
        let mut verify_elapsed = session.verify_since.map(|t| now.duration_since(t));
        if verify_elapsed.is_some_and(|elapsed| proof_age < elapsed) {
            tracing::info!("Tunnel re-proven — the relay answered a handshake on this path");
            session.verify_since = None;
            verify_elapsed = None;
            // The path is proven: heartbeats missed before it was (during an
            // outage) must not open a second window.
            #[cfg(target_os = "windows")]
            {
                session.heartbeat_misses = 0;
            }
        }
        let age = reconnect_policy::judged_age(age, proof_age, verify_elapsed.is_some());
        reconnect_policy::liveness(now.duration_since(connected_since), age, verify_elapsed)
    }

    async fn execute(&mut self, action: Action, now: Instant) -> Flow {
        let vm = Arc::clone(&self.vpn_manager);
        match action {
            Action::Idle => self.heartbeat(now).await,
            Action::Nudge => {
                vm.force_handshake().await;
                self.heartbeat(now).await
            }
            Action::Recovered => {
                tracing::info!("Reconnection successful");
                // Deactivate kill switch now that we're connected — UNLESS
                // the platform holds the block for the whole session (Windows
                // lockdown mode; ALWAYS on macOS/Linux, where the steady-state
                // block is what closes the reactive detection window — the
                // tunnel-interface permits carry the traffic). The give-up
                // branch still gates on is_lockdown_mode() and DOES release
                // the block on Unix, so this cannot strand anyone once the
                // session is over.
                if !killswitch::holds_block_while_connected() {
                    let _ = killswitch::deactivate_killswitch().await;
                }
                // MR-946: the re-dialled key checks in now, not one tick (or
                // one heartbeat interval) later.
                self.heartbeat(now).await
            }
            Action::TearDown { cause } => {
                tracing::warn!(
                    "Tunnel declared dead ({cause:?}) — tearing it down before recovering"
                );
                self.check_in(TEARDOWN_ALLOWANCE);
                // Fail closed FIRST: from here until a new tunnel is up,
                // nothing may leave on the physical NIC.
                let engaged = killswitch::activate_killswitch().await;
                if let Err(e) = &engaged {
                    tracing::warn!("Kill switch activation before teardown failed: {}", e);
                }
                // MR-2071: without a block, the dead tunnel's routes are all
                // that keep traffic off the physical NIC. The teardown used
                // to go ahead regardless, and everything left in the clear
                // until the dial aborted; the tunnel is held instead.
                if let Some(held) = self
                    .hold_dead_tunnel(&engaged, killswitch::platform_is_blocking())
                    .await
                {
                    return held;
                }
                // The dead session's key, read before the teardown clears it.
                let old_key = vm.get_key_id().await;
                let attempt = self.policy.attempts() + 1;
                let last_error = self.policy.last_error().cloned();
                let _ = vm
                    .disconnect_to(ConnectionState::Reconnecting {
                        attempt,
                        last_error: last_error.clone(),
                    })
                    .await;
                vm.set_reconnecting(attempt, last_error, self.policy.reconnect_max())
                    .await;
                self.session = SessionWatch::default();
                // REVIEW-WIN2-002 / REVIEW-AND2-001: before any re-dial, ask
                // the old key whether the server took it. Its answer to the
                // heartbeat that rode the tunnel died with the peer.
                if reconnect_policy::asks_the_old_key(cause) {
                    if let Some(key_id) = old_key {
                        if let Some(error) = self.ask_the_old_key(&key_id, now).await {
                            tracing::warn!(
                                "The server had already ended this session ({:?}) — not re-dialling",
                                error.code
                            );
                            return self.end_by_server(error).await;
                        }
                    }
                }
                Flow::Again
            }
            Action::PauseOffline { attempt } => {
                if let Err(e) = killswitch::activate_killswitch().await {
                    tracing::warn!("Kill switch activation during offline pause failed: {}", e);
                }
                vm.set_reconnecting(
                    attempt,
                    self.policy.last_error().cloned(),
                    self.policy.reconnect_max(),
                )
                .await;
                tracing::debug!("Auto-reconnect paused — no route off this machine; waiting");
                Flow::Continue
            }
            Action::Dial { attempt, delay } => self.dial(attempt, delay).await,
            Action::GiveUp(error) => {
                // An ending the server decided (the re-dial refused over the
                // Free allowance, REVIEW-WIN2-002) is not a recovery that
                // failed: it reads by its own code, unmarked.
                let gave_up = reconnect_policy::marks_give_up(error.code).then(|| GaveUp {
                    attempts: self.policy.attempts(),
                });
                self.give_up(error, gave_up).await;
                Flow::Stop
            }
            Action::Halt => {
                // Forced version floor: the backend has refused this build
                // (HTTP 426). Every re-dial would be refused identically, so
                // retrying is a self-inflicted DoS against our own control
                // plane. A live tunnel is left alone: the floor blocks the
                // control plane, not the data plane.
                tracing::error!(
                    "Auto-reconnect stopping — the backend requires a newer client build"
                );
                Flow::Stop
            }
        }
    }

    async fn dial(&mut self, attempt: u32, delay: Duration) -> Flow {
        let vm = Arc::clone(&self.vpn_manager);
        let max = self.policy.reconnect_max();

        // SECURITY FIX (PB-4): reconnecting without the block could leak.
        // Abort THIS attempt — it is already spent, so a persistent activation
        // failure still reaches the give-up (the only thing that releases the
        // block) instead of spinning here.
        if let Err(e) = killswitch::activate_killswitch().await {
            tracing::error!(
                "Kill switch activation failed during reconnect: {}. Aborting attempt {} to \
                 prevent a traffic leak.",
                e,
                attempt
            );
            let error = reconnect_policy::killswitch_failed_error();
            self.policy.on_dial_failed(error.clone());
            vm.set_reconnecting(attempt, Some(error), max).await;
            return Flow::Continue;
        }
        vm.set_reconnecting(attempt, self.policy.last_error().cloned(), max)
            .await;
        tracing::info!(
            "Auto-reconnect attempt {} (delay: {}ms)",
            attempt,
            delay.as_millis()
        );
        self.check_in(delay + DIAL_ALLOWANCE);

        if !delay.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.shutdown.changed() => return Flow::Stop,
                // The network changed during the backoff: dial now.
                _ = self.network.changed() => {}
            }
        }

        // No select on shutdown from here: a dial is cancelled through the
        // manager's epoch (end_session cancels before it stops this loop),
        // which unwinds a half-built tunnel properly. Dropping the future
        // would not.
        let epoch = vm.current_epoch();
        // MR-2390: the session's server left the pool. Move it off that
        // server first. The re-dial never goes back to it.
        if let Some(flow) = self.leave_the_server(attempt, epoch).await {
            return flow;
        }
        match self.redial(epoch).await {
            Ok(()) => {
                tracing::info!("Auto-reconnect successful on attempt {}", attempt);
                Flow::Again
            }
            Err(e) if e.code == IpcErrorCode::Cancelled => Flow::Continue,
            Err(e) => {
                tracing::warn!("Auto-reconnect attempt {} failed: {}", attempt, e);
                self.policy.on_dial_failed(e.clone());
                vm.set_reconnecting(attempt, Some(e), max).await;
                Flow::Again
            }
        }
    }

    /// One unattended re-dial with fresh keys, through the same tunnel
    /// preparation the user-initiated connect uses.
    async fn redial(&self, epoch: u64) -> Result<(), IpcError> {
        let vm = &self.vpn_manager;
        let info = self
            .last_reconnect_info
            .read()
            .await
            .clone()
            .ok_or_else(|| IpcError::unknown("There is no session to reconnect."))?;
        // Stealth reconnects need the managed Xray state; without the runtime
        // they fail closed rather than downgrade to direct WireGuard.
        let app = self
            .app
            .as_ref()
            .ok_or_else(|| IpcError::unknown("The app runtime is unavailable."))?;

        // FIX-1-6: flush the DNS cache so no stale entry leaks through the
        // system resolver before the new tunnel's DNS is set.
        flush_dns_cache().await;

        // SEC-PII: same generic label as every other auth/connect payload —
        // never the raw hostname.
        let device_name = crate::utils::get_device_name();
        // FIX-1-1: a fresh client-side keypair for every re-dial. MR-822: a
        // `WgPrivateKey`, moved to `vm.connect` and on into the tunnel, and
        // wiped on drop, so no error path frees it un-wiped (AR-1). Only
        // `ReconnectInfo` outlives the attempt, and it holds no key.
        let (private_key, client_public_key) = crate::commands::vpn::generate_wireguard_keypair();
        // MR-703 / MR-1742: a re-dial is a new connect, so it gets a keypair of
        // its own; the secret is moved into `prepare_tunnel` below and is
        // wiped there, or on any earlier exit.
        let pq_session = info
            .quantum_protection
            .then(crate::vpn::birdo_pq::PqSession::begin);
        let pq_pk = pq_session
            .as_ref()
            .map(crate::vpn::birdo_pq::PqSession::public_key_b64);

        // MR-691: on connections of its own, like the old-key probe. A re-dial
        // always follows a teardown, and the shared client's first request
        // went out on a keep-alive connection the heartbeats had opened
        // through the dead tunnel: it failed at once and cost the attempt.
        let api = self.api_after_teardown();
        vm.set_phase(ConnectPhase::Authenticating);
        let response = vm
            .run_cancellable(
                epoch,
                timeout(
                    REDIAL_API_TIMEOUT,
                    request_fresh_response(&api, &info, &device_name, client_public_key, pq_pk),
                ),
            )
            .await?
            .map_err(|_| {
                IpcError::new(
                    IpcErrorCode::ServerUnreachable,
                    "The VPN service did not answer in time.",
                )
            })??;

        let prepared = crate::commands::session::prepare_tunnel(
            app,
            vm,
            epoch,
            response,
            crate::commands::session::TunnelRequest {
                server_id: &info.server_id,
                stealth_mode: info.stealth_mode,
                quantum_protection: info.quantum_protection,
                pq_session,
                fallback_reason: info.fallback_reason.as_deref(),
                custom_dns: info.custom_dns.clone(),
                custom_mtu: info.custom_mtu,
                custom_port: &info.custom_port,
            },
        )
        .await?;
        // The block `dial` engaged is rebuilt around this relay before the
        // handshake (REVIEW-WIN2-001: in lockdown it used to keep naming the
        // relay of the session that died). Only a block in force is rebuilt
        // here, and one that could not be stays in force (MR-2070): nothing
        // leaves in the clear, and a handshake it drops fails the attempt.
        if let Err(e) = crate::commands::session::apply_relay_permit(
            &prepared.relay_endpoint,
            prepared.started_stealth,
            false,
        )
        .await
        {
            tracing::warn!("The re-dial's relay permit was not rebuilt: {}", e);
        }

        vm.set_phase(ConnectPhase::Handshaking);
        vm.connect(
            prepared.config,
            private_key,
            info.label(),
            &prepared.relay_endpoint,
            info.local_network_sharing,
            epoch,
        )
        .await
    }

    /// MR-2390: the session's server left the pool (drained or deleted, seen
    /// at a check-in or in the old key's answer), and the cap allowed the
    /// episode's one move. Before the re-dial goes out, this fetches the
    /// server list on connections of its own (like the re-dial) and puts the
    /// server it chooses on record ([`move_record`]). The re-dial and its
    /// retries then dial that server, and the session is published on it.
    ///
    /// `None`: dial what the record says. `Some`: this attempt ends here.
    /// When the list does not arrive, the attempt fails like a refused
    /// re-dial: it is spent and backed off, and the next attempt asks again.
    /// The server that left is never re-dialled meanwhile. When no server
    /// qualifies, the session ends at once as unavailable. A location the
    /// user picked is never moved abroad.
    async fn leave_the_server(&mut self, attempt: u32, epoch: u64) -> Option<Flow> {
        let leaving = self
            .quiet_rebuilds
            .with(|cap| cap.leaving().map(str::to_string))?;
        let vm = Arc::clone(&self.vpn_manager);
        let api = self.api_after_teardown();
        let listed = match vm
            .run_cancellable(epoch, timeout(SERVER_LIST_TIMEOUT, api.get_servers()))
            .await
        {
            // A Disconnect or a newer connect: the session is theirs now.
            Err(_) => return Some(Flow::Continue),
            Ok(Ok(listed)) => listed.map_err(IpcError::from),
            Ok(Err(_)) => Err(IpcError::new(
                IpcErrorCode::ServerUnreachable,
                "The VPN service did not answer in time.",
            )),
        };
        let servers = match listed {
            Ok(servers) => servers,
            Err(error) => {
                tracing::warn!(
                    "Auto-reconnect attempt {} failed: no server list to move the session off a \
                     server that left ({:?})",
                    attempt,
                    error.code
                );
                self.policy.on_dial_failed(error.clone());
                vm.set_reconnecting(attempt, Some(error), self.policy.reconnect_max())
                    .await;
                return Some(Flow::Again);
            }
        };
        // The move is decided now, whatever it comes to.
        self.quiet_rebuilds.with(QuietRebuilds::left);
        // A deleted server is gone from this list: where it was comes from
        // the lists fetched before it (owner, 2026-11-19).
        let last_known = relay_retry::known_location(&leaving);
        relay_retry::remember(&servers);
        let moved = move_record(
            &mut *self.last_reconnect_info.write().await,
            &leaving,
            &servers,
            last_known.as_ref(),
        );
        match moved {
            Ok(()) => None,
            Err(ending) => Some(self.end_by_server(ending).await),
        }
    }

    async fn heartbeat(&mut self, now: Instant) -> Flow {
        if !heartbeat_due(
            self.session.connected_since,
            self.session.last_heartbeat,
            now,
        ) {
            return Flow::Continue;
        }
        self.session.last_heartbeat = Some(now);
        let Some(key_id) = self.vpn_manager.get_key_id().await else {
            return Flow::Continue;
        };
        let reply = tokio::select! {
            r = timeout(HEARTBEAT_TIMEOUT, self.api.heartbeat(&key_id)) => match r {
                Ok(Ok(resp)) => HeartbeatReply::Answered(resp),
                Ok(Err(e)) => HeartbeatReply::Failed(e),
                Err(_) => HeartbeatReply::Unanswered,
            },
            _ = self.shutdown.changed() => return Flow::Stop,
        };
        match self.take_reply(reply, now).await {
            AfterReply::Continue => Flow::Continue,
            AfterReply::End(error) => self.end_by_server(error).await,
            AfterReply::Stop => Flow::Stop,
        }
    }

    /// What a heartbeat's outcome at `now` does: the miss count, the alive
    /// mark, the quiet-rebuild cap's healthy run, the quota notice, a pending
    /// quiet rebuild, and what is left for the caller to carry out (an
    /// ending). Apart from the request so a test drives a real reply through
    /// it (MR-2369).
    async fn take_reply(&mut self, reply: HeartbeatReply, now: Instant) -> AfterReply {
        let resp = match reply {
            HeartbeatReply::Answered(resp) => resp,
            // Visible, not debug: the server reaps a session it has not heard
            // from for 5 minutes, so heartbeats failing in a row end in an
            // outage, and the log must say why (live retest 2026-10-02).
            HeartbeatReply::Failed(e) => {
                tracing::warn!("Heartbeat failed: {}", heartbeat_failure(&e));
                // MR-2369: not a healthy check-in.
                self.quiet_rebuilds.with(QuietRebuilds::interrupted);
                // An HTTP status crossed the tunnel to arrive; only a failure
                // on the network itself says the tunnel may carry nothing,
                // and one never sent says nothing either way.
                #[cfg(target_os = "windows")]
                {
                    self.session.heartbeat_misses =
                        misses_after_failure(self.session.heartbeat_misses, &e);
                }
                return AfterReply::Continue;
            }
            HeartbeatReply::Unanswered => {
                // A heartbeat that rides a dead tunnel never answers; the
                // liveness rules, not this, decide that the tunnel is dead —
                // on Windows a run of these only asks the tunnel to prove
                // itself (`reconnect_policy::heartbeat_reprove`).
                tracing::warn!("Heartbeat unanswered after {:?}", HEARTBEAT_TIMEOUT);
                self.quiet_rebuilds.with(QuietRebuilds::interrupted);
                #[cfg(target_os = "windows")]
                {
                    self.session.heartbeat_misses = self.session.heartbeat_misses.saturating_add(1);
                }
                return AfterReply::Continue;
            }
        };
        #[cfg(target_os = "windows")]
        {
            self.session.heartbeat_misses = 0;
        }
        if resp.valid {
            self.alive = Some((now, network_events::resume_count()));
            // MR-2369: a healthy check-in; ten minutes of them, none missed,
            // give the episode's quiet rebuild back.
            self.quiet_rebuilds.with(|cap| cap.healthy(now));
        }
        match reconnect_policy::heartbeat_verdict(&resp) {
            HeartbeatVerdict::End(error) => {
                // The server ended this VPN session: another device took the
                // slot (`evicted`), it was revoked or is gone with no record
                // of why (`revoked`), or the Free allowance ran out after its
                // grace window (`quota_exceeded`, birdo-web #590; the peer is
                // already gone). A key housekeeping reaped, or one that went
                // with a drained server (MR-2390), is rebuilt instead (the
                // next arm), until its cap is spent. The AUTH session is
                // intact, so this is not `session_expired`, and the owner
                // default (iOS parity, P1-parity-021) is: tear down, release
                // the block, no auto-retry.
                tracing::warn!(
                    "Heartbeat: the server ended this VPN session ({:?})",
                    error.code
                );
                AfterReply::End(error)
            }
            HeartbeatVerdict::Rebuild { ending, moves } => match self.on_release(moves).await {
                // MR-2369: housekeeping reaped the key. The contract allows
                // one quiet rebuild: after a random wait (so a fleet-wide
                // reap does not come back as one burst), the next look
                // declares the tunnel dead, and the policy tears it down
                // (behind the kill switch's block) and re-dials with a new
                // key — the path every dead tunnel's re-dial takes.
                // MR-2390: a drained server's key (`moves`) takes the same
                // path, and its re-dial moves off that server first
                // (`leave_the_server`).
                OnRelease::Rebuild => {
                    let wait = reconnect_policy::release_wait((self.rng)());
                    tracing::warn!(
                        "Heartbeat: the server {} — rebuilding it quietly in {} ms ({} of {} \
                         this episode)",
                        release_words(moves),
                        wait.as_millis(),
                        self.quiet_rebuilds.with(|cap| cap.spent()),
                        reconnect_policy::QUIET_REBUILDS_PER_EPISODE
                    );
                    self.session.release = Some(PendingRelease {
                        due: now + wait,
                        ending,
                    });
                    AfterReply::Continue
                }
                // Released again with the episode's rebuild spent, or with
                // no session on record to re-dial: end the session as before
                // MR-2369, never another re-dial.
                OnRelease::End => {
                    tracing::warn!(
                        "Heartbeat: the server {} and no quiet rebuild is left — ending the \
                         session ({:?})",
                        release_words(moves),
                        ending.code
                    );
                    AfterReply::End(ending)
                }
                // The user is ending the session: theirs to end.
                OnRelease::StandDown => AfterReply::Stop,
            },
            HeartbeatVerdict::QuotaGrace { seconds_remaining } => {
                // Once per session: the heartbeat repeats every 30 s for the
                // whole grace window, and a reconnect or a reapply inside it
                // starts a new tunnel; the warning is news only once.
                if self.quota_notice.claim() {
                    tracing::warn!("Heartbeat: the Free data allowance is used up (grace window)");
                    if let Some(app) = &self.app {
                        let _ = app.emit(QUOTA_WARNING_EVENT, QuotaWarning { seconds_remaining });
                    }
                }
                AfterReply::Continue
            }
            HeartbeatVerdict::ServerGoingOffline => {
                tracing::warn!("Heartbeat: server going offline");
                AfterReply::Continue
            }
            HeartbeatVerdict::Fine => {
                tracing::debug!("Heartbeat sent");
                AfterReply::Continue
            }
        }
    }

    /// MR-2071: `engaged` is the kill switch's answer to the block asked for
    /// before a dead tunnel's teardown, `blocking` whether a block is in force
    /// now. `None`: the block covers the teardown
    /// (`reconnect_policy::teardown_covered`), which goes ahead. Otherwise
    /// the tunnel is NOT torn down: its /1 routes swallow everything, which
    /// keeps traffic off the physical NIC. The session reads `Reconnecting`
    /// with the kill switch's error, and the next look asks for the teardown
    /// again (a held tunnel comes first, W1-001) — behind a block, if one goes
    /// up by then. Each held teardown spends an attempt
    /// (`ReconnectPolicy::on_teardown_held`), so a kill switch that never arms
    /// ends in the give-up, whose own teardown ends the session in `Error`.
    /// Disconnect is the way out meanwhile, as in any reconnect; turning the
    /// kill switch off is another (the next look's engage then answers
    /// `Ok(false)`, and the teardown goes ahead).
    async fn hold_dead_tunnel(
        &mut self,
        engaged: &Result<bool, String>,
        blocking: bool,
    ) -> Option<Flow> {
        let error = reconnect_policy::teardown_covered(engaged, blocking).err()?;
        tracing::error!(
            "The kill switch could not block traffic — keeping the dead tunnel in place, so \
             nothing leaves outside it, and trying again"
        );
        let attempt = self.policy.on_teardown_held(error.clone());
        self.vpn_manager
            .set_reconnecting(attempt, Some(error), self.policy.reconnect_max())
            .await;
        Some(Flow::Continue)
    }

    /// The server ended the session (a heartbeat said so, or the old key's
    /// answer after a teardown). Not a give-up: the UI words it by its code,
    /// not as "stopped reconnecting". The owner default (iOS parity,
    /// P1-parity-021): tear down, release the block, no auto-retry.
    async fn end_by_server(&mut self, error: IpcError) -> Flow {
        self.give_up(error, None).await;
        *self.last_reconnect_info.write().await = None;
        self.quota_notice.reset();
        self.quiet_rebuilds.reset();
        Flow::Stop
    }

    /// MR-2369: housekeeping released this session's key at a live check-in
    /// or, MR-2390 (`moves`), its server left the pool, at a check-in or
    /// in the old key's answer. While this loop is being stopped
    /// (Disconnect, sign-out and quit stop it before they clear the record)
    /// nothing is re-dialled, ended or spent. Otherwise the result is what
    /// the episode's cap allows (`reconnect_policy::QuietRebuilds`). With no
    /// session on record to re-dial, that is an ending. A rebuild for a
    /// server that left must move off the server on record.
    async fn on_release(&self, moves: bool) -> OnRelease {
        let stopping = *self.shutdown.borrow();
        let on_record = self
            .last_reconnect_info
            .read()
            .await
            .as_ref()
            .map(|info| info.server_id.clone());
        self.quiet_rebuilds.with(|cap| {
            if moves {
                cap.on_server_left(stopping, on_record.as_deref())
            } else {
                cap.on_release(stopping, on_record.is_some())
            }
        })
    }

    /// The API on connections of its own (bound to the physical address on
    /// Windows), for the requests sent after a teardown: the old-key probe
    /// and the re-dial. The shared client's pool keeps the keep-alive
    /// connections the heartbeats opened THROUGH the tunnel, from an address
    /// the teardown has just removed (WIN3-001).
    fn api_after_teardown(&self) -> BirdoApi {
        #[cfg(target_os = "windows")]
        let local = network_events::physical_source_address();
        #[cfg(not(target_os = "windows"))]
        let local = None;
        self.api.on_fresh_connections(local).unwrap_or_else(|e| {
            tracing::warn!("No client of its own after the teardown ({e}); using the shared one");
            (*self.api).clone()
        })
    }

    /// One heartbeat for the dead session's key, sent once its tunnel is
    /// down — so over the physical network, through the app's control-plane
    /// permit, like the re-dial it precedes. Bounded, so an outage only
    /// costs [`OLD_KEY_PROBE_TIMEOUT`]. `Some` ends the session
    /// (`reconnect_policy::after_teardown`).
    ///
    /// WIN3-001: no answer re-dials, and the re-dial evicts the device that
    /// took the slot, so the probe must not fail for reasons of its own. Live,
    /// it failed in 0.4 s: the shared client handed it a keep-alive connection
    /// the heartbeats had opened through the tunnel the teardown had just
    /// removed. It now sends on connections of its own (bound to the physical
    /// address on Windows) and asks once more if a request fails.
    async fn ask_the_old_key(&mut self, key_id: &str, now: Instant) -> Option<IpcError> {
        let api = self.api_after_teardown();
        let reply = tokio::select! {
            r = ask_twice(OLD_KEY_PROBE_TIMEOUT, || api.heartbeat(key_id)) => r,
            _ = self.shutdown.changed() => Err("shutting down"),
        };
        let alive = reconnect_policy::recently_alive(
            self.alive.map(|(at, _)| at),
            now,
            self.alive
                .is_some_and(|(_, resumes)| resumes != network_events::resume_count()),
        );
        let (ending, answer) = probe_verdict(&reply, alive);
        let (ending, left) = self
            .unless_the_server_left(ending, reply.as_ref().ok())
            .await;
        let outcome = match (&ending, left) {
            (Some(_), _) => "end the session",
            (None, true) => "re-dial another server",
            (None, false) => "re-dial",
        };
        tracing::info!("Old-key probe: {answer} (recently alive: {alive}) -> {outcome}");
        ending
    }

    /// MR-2390: the old key's verdict (`ending`, from
    /// `reconnect_policy::after_teardown`), unless its `answer` says the
    /// server left the pool (`reconnect_policy::server_left`). Such a server
    /// is never re-dialled. The re-dial moves off it (`leave_the_server`),
    /// once per episode on the quiet-rebuild cap, and past that the session
    /// ends as unavailable. The second value says whether the server left.
    async fn unless_the_server_left(
        &self,
        ending: Option<IpcError>,
        answer: Option<&crate::api::types::HeartbeatResponse>,
    ) -> (Option<IpcError>, bool) {
        if ending.is_some() || !reconnect_policy::server_left(answer) {
            return (ending, false);
        }
        let ending = match self.on_release(true).await {
            OnRelease::End => Some(reconnect_policy::server_left_error()),
            OnRelease::Rebuild | OnRelease::StandDown => None,
        };
        (ending, true)
    }

    /// End recovery in `Error`. Always-on keeps the block engaged (the user
    /// asked for exactly that) except for a revocation; otherwise the block is
    /// released so a session that is over cannot hold the machine offline.
    /// `gave_up` marks the status as the end of a recovery (REVIEW-WIN-009).
    async fn give_up(&mut self, error: IpcError, gave_up: Option<GaveUp>) {
        self.check_in(TEARDOWN_ALLOWANCE);
        let vm = Arc::clone(&self.vpn_manager);
        let keep_block =
            reconnect_policy::give_up_keeps_block(error.code, killswitch::is_lockdown_mode());
        if keep_block {
            tracing::error!(
                "Auto-reconnect gave up ({:?}) with the always-on kill switch armed — traffic \
                 stays blocked until you disconnect or turn the kill switch off",
                error.code
            );
            if let Err(e) = killswitch::activate_killswitch().await {
                tracing::warn!("Kill switch activation at give-up failed: {}", e);
            }
        } else {
            tracing::error!("Auto-reconnect gave up ({:?})", error.code);
        }

        // Anything still held is dead: tear it down with the block (if any)
        // still engaged, and land in Error either way.
        vm.end_in_error(error, gave_up).await;
        if let Some(app) = &self.app {
            app.state::<XrayManager>().stop().await;
        }

        if !keep_block {
            // The session is over: forget the IPv6-block intent BEFORE
            // deactivating, or deactivate_blocking() would re-install a
            // standalone IPv6 block for a tunnel that will never come back
            // and silently blackhole IPv6 for the rest of the run.
            #[cfg(target_os = "windows")]
            crate::vpn::wfp::clear_ipv6_block_intent();
            let _ = killswitch::deactivate_killswitch().await;
        }
    }
}

/// The unattended re-dial's `/vpn/connect` (or multi-hop) call. The body is
/// assembled by the two PURE builders above (unit-tested in vpn/tests.rs
/// against a `ReconnectInfo`) and posted as-is, so what the tests assert on is
/// the very struct that reaches the wire (PR #160 review, nit 3).
async fn request_fresh_response(
    api: &BirdoApi,
    info: &ReconnectInfo,
    device_name: &str,
    client_public_key: String,
    pq_client_public_key: Option<String>,
) -> Result<ConnectResponse, IpcError> {
    let info = &redial_info_under_gate(info, crate::api::client::dns_filtering_gate_on());
    let attestation = api.desktop_attestation().await;
    let response = if let Some(route) = info.multi_hop.as_ref() {
        let payload = reconnect_multi_hop_request(
            info,
            &route.exit_id,
            device_name,
            &client_public_key,
            pq_client_public_key,
            attestation,
        );
        let response = api.post_multi_hop_request(&payload).await?;
        crate::commands::session::verified_multi_hop_response(
            response,
            &info.server_id,
            &route.exit_id,
        )?
        .0
    } else {
        let payload = reconnect_connect_request(
            info,
            device_name,
            client_public_key,
            pq_client_public_key,
            attestation,
        );
        api.post_connect_request(&payload).await?
    };
    // REVIEW-WIN2-002: a used-up Free allowance arrives HERE on Windows. The
    // server removes the peer before it answers the heartbeat that says so,
    // and that answer rides the removed peer; the tunnel then dies, and this
    // re-dial is refused with `quotaExceeded` — a hard refusal that ends the
    // recovery at once, releasing the block (`give_up_keeps_block`).
    if !response.success {
        return Err(IpcError::connect_refused_with(
            response.message.as_deref().unwrap_or("Connection failed"),
            response.quota_exceeded,
            response.refusal_reason.as_deref(),
            response.account_restriction.as_ref(),
        ));
    }
    Ok(response)
}

/// What the old-key probe's `reply` decides, and how it reads in the log
/// (WIN3-001): an answer that says the session is over ends it
/// (`reconnect_policy::after_teardown`); no answer — both requests failed,
/// the budget ran out, the loop is shutting down — re-dials. The log line has
/// no identifiers (the node-agent privacy convention), so a re-dial after a
/// takeover can be told apart from a probe that never got its answer
/// (Android logs the same).
fn probe_verdict<'r>(
    reply: &'r Result<crate::api::types::HeartbeatResponse, &'static str>,
    recently_alive: bool,
) -> (Option<IpcError>, &'r str) {
    let ending = reconnect_policy::after_teardown(reply.as_ref().ok(), recently_alive);
    let answer = match reply {
        Ok(r) if r.valid => "valid",
        Ok(r) => r.reason.as_deref().unwrap_or("invalid, no reason"),
        Err(why) => why,
    };
    (ending, answer)
}

/// MR-2390: move the session on `record` off `leaving`, the server that left
/// the pool, to the server `relay_retry::next` picks from `servers` for the
/// session's origin. The name moves with the id, so the session is published
/// on the new server. Kept apart from the loop so a test can drive it.
///
/// `Ok`: the record names the new server, or there was nothing to move (no
/// session on record, or one that is not on that server). `Err`: no server
/// qualifies, so the session ends with this error. That covers a location
/// the user picked with nothing else in its country (or, deleted, no country
/// known), and a Multi-Hop route, which is the user's own pair of locations
/// and never moves.
///
/// `last_known`: where `leaving` was when an earlier list named it
/// (`relay_retry::known_location`), for a deleted server `servers` no longer
/// has.
fn move_record(
    record: &mut Option<ReconnectInfo>,
    leaving: &str,
    servers: &[crate::api::types::VpnServer],
    last_known: Option<&relay_retry::Location>,
) -> Result<(), IpcError> {
    let Some(info) = record.as_mut().filter(|info| info.server_id == leaving) else {
        return Ok(());
    };
    let choice = match info.multi_hop {
        None => relay_retry::next(leaving, servers, info.origin, last_known),
        Some(_) => None,
    };
    tracing::warn!("{}", relay_retry::log_line(choice.as_ref(), info.origin));
    let choice = choice.ok_or_else(reconnect_policy::server_left_error)?;
    info.server_id = choice.server.id;
    info.server_name = choice.server.name;
    Ok(())
}

/// What a quiet rebuild's log line says happened at the check-in: a reap
/// (MR-2369) or a server that left the pool (MR-2390). No identifiers.
fn release_words(moves: bool) -> &'static str {
    if moves {
        "left the pool with this session's key"
    } else {
        "released this session's key"
    }
}

/// Ask, and ask once more if the request FAILED, all inside `budget`
/// (WIN3-001). A request that ran out of time is not repeated: the budget is
/// spent. `Err` says which, for the probe's log line.
async fn ask_twice<T, Fut>(
    budget: Duration,
    mut ask: impl FnMut() -> Fut,
) -> Result<T, &'static str>
where
    Fut: std::future::Future<Output = Result<T, crate::api::ApiError>>,
{
    let asked = async {
        match ask().await {
            Ok(answer) => Ok(answer),
            Err(first) => {
                tracing::info!(
                    "Old-key probe: the request failed ({}) — asking once more",
                    heartbeat_failure(&first)
                );
                ask().await.map_err(|_| "request failed twice")
            }
        }
    };
    timeout(budget, asked)
        .await
        .unwrap_or(Err("no answer in time"))
}

/// Flush the system DNS cache, off the runtime's worker threads and bounded
/// (W1-017: this used to run a synchronous process from inside the loop).
async fn flush_dns_cache() {
    #[cfg(target_os = "windows")]
    let (program, args) = ("ipconfig", ["/flushdns"]);
    #[cfg(target_os = "macos")]
    let (program, args) = ("dscacheutil", ["-flushcache"]);
    #[cfg(target_os = "linux")]
    let (program, args) = ("resolvectl", ["flush-caches"]);
    let _ = crate::utils::run_bounded(
        crate::utils::hidden_async_cmd(program).args(args),
        Duration::from_secs(5),
    )
    .await;
}

/// Whether a failed heartbeat failed on the NETWORK — no connection, no
/// answer — rather than with an answer (a status, an unreadable body), which
/// had to cross the tunnel to arrive. (Windows only; see `SessionWatch`.)
///
/// A certificate the pin refused (`CertificatePinningFailed`, MR-2537) is an
/// answer too: the server's certificate crossed the tunnel to be refused. It
/// used to arrive as `Network` and count as a miss, which could only open a
/// re-prove the relay then answers; it resets the run now, like a status.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn heartbeat_missed_the_network(e: &crate::api::ApiError) -> bool {
    matches!(e, crate::api::ApiError::Network(_))
}

/// The run of network misses after a heartbeat that failed with `e`
/// (Windows only; see `SessionWatch`): one more when it failed on the
/// network; reset by an answer, which had to cross the tunnel to arrive; and
/// UNCHANGED when it was never sent — the API client's retry gate answered it
/// (`ApiError::Held`, MR-1808), so it says nothing about the tunnel either way
/// (review of #289).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn misses_after_failure(misses: u32, e: &crate::api::ApiError) -> u32 {
    match e {
        crate::api::ApiError::Held { .. } => misses,
        e if heartbeat_missed_the_network(e) => misses.saturating_add(1),
        _ => 0,
    }
}

/// What a failed heartbeat met, for the log: a status or a kind, never the
/// error's text — a transport error names the URL, and the heartbeat's URL
/// carries the session's key id (the node-agent privacy convention).
fn heartbeat_failure(e: &crate::api::ApiError) -> String {
    use crate::api::ApiError as E;
    match e {
        E::Network(_) => "network error".into(),
        E::NotAuthenticated => "not signed in".into(),
        E::Unauthorized => "HTTP 401".into(),
        E::Forbidden => "HTTP 403".into(),
        E::NotFound => "HTTP 404".into(),
        E::RateLimited { .. } => "HTTP 429".into(),
        E::Held { status, .. } => format!("not sent (waiting out HTTP {status}'s Retry-After)"),
        E::UpgradeRequired(_) => "HTTP 426".into(),
        E::ServerError(status) | E::ServerBusy { status, .. } | E::Rejected { status, .. } => {
            format!("HTTP {status}")
        }
        E::Parse(_) => "unreadable reply".into(),
        E::CertificatePinningFailed(_) => "certificate pin mismatch".into(),
        _ => "other error".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_heartbeat_is_logged_without_its_url() {
        use crate::api::ApiError;
        let url = "error sending request for url (https://api.birdo.app/vpn/heartbeat/key-123)";
        for e in [
            ApiError::Network(url.into()),
            ApiError::Parse(url.into()),
            ApiError::Unknown(url.into()),
            ApiError::Rejected {
                status: 409,
                message: url.into(),
            },
        ] {
            let line = heartbeat_failure(&e);
            assert!(
                !line.contains("key-123") && !line.contains("http"),
                "{line}"
            );
        }
        assert_eq!(heartbeat_failure(&ApiError::ServerError(503)), "HTTP 503");
        assert_eq!(
            heartbeat_failure(&ApiError::RateLimited {
                retry_after_secs: Some(30)
            }),
            "HTTP 429"
        );
        assert_eq!(
            heartbeat_failure(&ApiError::ServerBusy {
                status: 503,
                retry_after_secs: 30
            }),
            "HTTP 503"
        );
    }

    /// Review of #289: a heartbeat the retry gate answered was never sent, so
    /// it neither counts as a network miss nor clears the run of them (that
    /// would hide a dead tunnel from the re-prove rule); a real answer, which
    /// crossed the tunnel, clears it; a network failure adds one.
    #[test]
    fn a_heartbeat_that_was_never_sent_leaves_the_misses_alone() {
        use crate::api::ApiError;
        let held = ApiError::Held {
            status: 429,
            retry_after_secs: 30,
        };
        assert_eq!(misses_after_failure(2, &held), 2);
        assert_eq!(misses_after_failure(0, &held), 0);
        assert_eq!(
            misses_after_failure(2, &ApiError::Network("reset".into())),
            3
        );
        assert_eq!(
            misses_after_failure(u32::MAX, &ApiError::Network("reset".into())),
            u32::MAX
        );
        for answered in [
            ApiError::RateLimited {
                retry_after_secs: Some(30),
            },
            ApiError::ServerBusy {
                status: 503,
                retry_after_secs: 30,
            },
            ApiError::ServerError(502),
            ApiError::Unauthorized,
        ] {
            assert_eq!(misses_after_failure(2, &answered), 0, "{answered:?}");
        }
        assert_eq!(
            heartbeat_failure(&held),
            "not sent (waiting out HTTP 429's Retry-After)"
        );
    }

    /// MR-2537: a heartbeat whose certificate the pin refused was answered,
    /// through the tunnel, so it is no network miss: it resets the run like
    /// a status (it used to arrive as `Network` and add one). Its log line
    /// says what it was.
    #[test]
    fn a_pin_refusal_is_an_answer_not_a_missed_heartbeat() {
        use crate::api::ApiError;
        let pin = ApiError::CertificatePinningFailed("certificate SPKI pin mismatch".into());
        assert!(!heartbeat_missed_the_network(&pin), "pin");
        assert_eq!(misses_after_failure(2, &pin), 0, "pin");
        assert_eq!(heartbeat_failure(&pin), "certificate pin mismatch");
    }

    /// MR-946: the first heartbeat goes out as soon as the session is seen
    /// Connected, then one per interval. It used to wait a whole interval
    /// first, so a new key's first check-in came 30 s after the connect.
    #[test]
    fn the_first_heartbeat_goes_out_at_once_then_every_interval() {
        let s = Duration::from_secs;
        let t0 = Instant::now();
        // No session: nothing to beat for.
        assert!(!heartbeat_due(None, None, t0));
        // Just connected, never beaten: due now, not 30 s from now.
        assert!(heartbeat_due(Some(t0), None, t0));
        // Beaten at t0: the next one waits the interval.
        for later in [s(0), s(1), s(5), s(29)] {
            assert!(!heartbeat_due(Some(t0), Some(t0), t0 + later), "{later:?}");
        }
        assert!(heartbeat_due(Some(t0), Some(t0), t0 + HEARTBEAT_INTERVAL));

        // A heartbeat failing on every 5 s tick for two minutes is still one
        // request per interval (it is stamped before it goes out), never a
        // burst: t = 0, 30, 60, 90, 120.
        let mut last = None;
        let mut sent = Vec::new();
        for tick in 0..=24u64 {
            let now = t0 + s(5 * tick);
            if heartbeat_due(Some(t0), last, now) {
                last = Some(now);
                sent.push(5 * tick);
            }
        }
        assert_eq!(sent, vec![0, 30, 60, 90, 120]);

        // A re-dial or a server switch starts a fresh watch: its key checks
        // in at once too.
        let fresh = SessionWatch::default();
        let redialled = t0 + s(42);
        assert!(heartbeat_due(
            Some(redialled),
            fresh.last_heartbeat,
            redialled
        ));
    }

    /// MR-946, the wiring: the stamp is written before the request goes out
    /// (so a failure cannot repeat at once), and a recovered session beats
    /// on the step that sees it back, not on the next tick.
    #[test]
    fn a_heartbeat_is_stamped_before_it_goes_out_and_a_recovery_beats() {
        let source: String = include_str!("auto_reconnect.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let beat = &source[source
            .find("asyncfnheartbeat(&mutself,now:Instant)->Flow{")
            .expect("the heartbeat")..];
        let due = beat.find("heartbeat_due(").expect("the due check");
        let stamp = beat
            .find("self.session.last_heartbeat=Some(now);")
            .expect("the stamp");
        let request = beat
            .find("self.api.heartbeat(&key_id)")
            .expect("the request");
        assert!(due < stamp && stamp < request);

        let recovered = &source[source.find("Action::Recovered=>{").expect("Recovered")..];
        let recovered = &recovered[..recovered.find("Action::TearDown").expect("next arm")];
        assert!(
            recovered.contains("self.heartbeat(now).await"),
            "{recovered}"
        );
    }

    fn service() -> AutoReconnectService {
        AutoReconnectService::new(Arc::new(VpnManager::new()), Arc::new(BirdoApi::new()))
    }

    /// W1-018: start → stop → start must leave exactly ONE loop, and stop
    /// must not return while the old loop is still running.
    #[tokio::test]
    async fn start_stop_start_leaves_exactly_one_loop() {
        let svc = service();
        svc.start().await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(svc.live_loops(), 1);

        svc.stop().await;
        assert_eq!(svc.live_loops(), 0, "stop() returned with the loop alive");

        svc.start().await.unwrap();
        svc.start().await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            svc.live_loops(),
            1,
            "start() while running spawned a second loop"
        );
        svc.stop().await;
        assert_eq!(svc.live_loops(), 0);
    }

    async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// WIN-FIX-3: a loop that stops checking in is restarted by the watchdog
    /// thread, and once whatever held it lets go, exactly one loop is left.
    /// The wedge here is a lock the loop awaits on every step (the session
    /// record); in T5 it was the tunnel's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_watchdog_restarts_a_loop_that_stopped_checking_in() {
        let svc = service();
        svc.config.write().await.health_check_interval_ms = 20;
        svc.start().await.unwrap();
        wait_until("the first check-in", || svc.pulse.read().is_some()).await;

        let stalled = running(&svc).await.expect("a loop");
        let record = svc.last_reconnect_info.write().await;
        wait_until("a restart", || svc.restarts.load(Ordering::SeqCst) >= 1).await;
        // REVIEW-WIN3-013: this read `live_loops() <= 1` once, right here.
        // But the restart waits only a second for the aborted loop to be
        // dropped before it starts the next one, and a loaded runner can take
        // longer, so the count could read 2 for a moment and fail a correct
        // restart. What must hold is that the stalled loop goes and its
        // successor is a different one: waited for, not sampled.
        wait_until("the stalled loop to be gone", || svc.live_loops() <= 1).await;
        assert_ne!(
            running(&svc).await,
            Some(stalled),
            "the stalled loop runs on"
        );
        drop(record);

        wait_until("one live loop checking in again", || {
            svc.live_loops() == 1
                && svc
                    .pulse
                    .read()
                    .is_some_and(|b| b.at.elapsed() < Duration::from_millis(500))
        })
        .await;
        svc.stop().await;
        assert_eq!(svc.live_loops(), 0);
        assert!(svc.pulse.read().is_none(), "a stopped loop is not watched");
    }

    /// The generation of the loop that is running now, if one is.
    async fn running(svc: &AutoReconnectService) -> Option<u64> {
        svc.task
            .lock()
            .await
            .as_ref()
            .filter(|t| !t.handle.is_finished())
            .map(|t| t.generation)
    }

    /// WIN3-008: a restart replaces exactly the loop the watchdog judged,
    /// and only while it still runs. A loop `stop()` took, a newer one a
    /// connect has started since (possibly mid-dial), and one that finished
    /// on its own (a give-up, which a restart would undo) are left alone —
    /// and a pulse a finished loop cleared is never brought back.
    #[tokio::test]
    async fn a_restart_replaces_only_the_loop_it_judged() {
        let svc = service();
        svc.start().await.unwrap();
        let stopped = running(&svc).await.expect("a loop");
        svc.stop().await;
        svc.restart_stalled(stopped).await;
        assert_eq!(running(&svc).await, None, "a stopped loop came back");

        svc.start().await.unwrap();
        let newer = running(&svc).await.expect("a loop");
        svc.restart_stalled(stopped).await;
        assert_eq!(
            running(&svc).await,
            Some(newer),
            "a newer loop was replaced"
        );

        svc.task.lock().await.as_ref().unwrap().handle.abort();
        wait_until("the loop to finish", || {
            svc.task
                .try_lock()
                .is_ok_and(|t| t.as_ref().is_some_and(|t| t.handle.is_finished()))
        })
        .await;
        svc.restart_stalled(newer).await;
        assert_eq!(running(&svc).await, None, "a finished loop was restarted");
        assert_eq!(svc.restarts.load(Ordering::SeqCst), 0);

        svc.start().await.unwrap();
        let stuck = running(&svc).await.expect("a loop");
        svc.restart_stalled(stuck).await;
        let replaced = running(&svc).await.expect("a new loop");
        assert_ne!(replaced, stuck);
        assert_eq!(svc.restarts.load(Ordering::SeqCst), 1);
        assert_eq!(svc.live_loops(), 1, "the new loop ran beside the old one");
        svc.stop().await;

        let pulse = Pulse::default();
        let now = Instant::now();
        pulse.beat(7, Duration::from_secs(30));
        assert!(pulse.renew(7, Duration::from_secs(30), now));
        assert!(
            !pulse.renew(8, Duration::from_secs(30), now),
            "another loop's beat"
        );
        pulse.clear(7);
        assert!(!pulse.renew(7, Duration::from_secs(30), now));
        assert!(pulse.read().is_none(), "a cleared pulse was re-beaten");
    }

    /// The watchdog's own looks across a standby (WIN3-003; REVIEW-WIN3-013
    /// found no freeze or resume test). A healthy loop is not restarted for
    /// the hour the machine slept; one that stays silent after the wake is,
    /// one allowance later, and once — the restart gets a whole allowance
    /// before the next verdict. A loop that checks in after the wake, or one
    /// that ended, is never restarted.
    #[test]
    fn the_watchdog_judges_a_loop_across_a_standby() {
        let s = Duration::from_secs;
        let (period, allowance) = (s(5), s(30));
        let t0 = Instant::now();
        let beat_at = |pulse: &Pulse, generation: u64, at: Instant| {
            *pulse.0.lock().unwrap() = Some(Beat {
                generation,
                at,
                allowance,
            });
        };
        let looks = |clock: &mut WatchdogClock, pulse: &Pulse, from: Instant, to: Instant| {
            let mut verdicts = Vec::new();
            let mut now = from;
            while now <= to {
                if let Some((beat, silent)) = watchdog_look(clock, pulse, now, period) {
                    verdicts.push((now, beat.generation, silent));
                }
                now += period;
            }
            verdicts
        };

        // A loop that checked in just before the machine slept for an hour,
        // and is silent after the wake.
        let pulse = Pulse::default();
        let mut clock = WatchdogClock::new(t0);
        beat_at(&pulse, 1, t0);
        assert!(looks(&mut clock, &pulse, t0 + period, t0 + s(25)).is_empty());
        let woke = t0 + s(25) + s(3600);
        let verdicts = looks(&mut clock, &pulse, woke, woke + s(60));
        assert_eq!(
            verdicts.iter().map(|v| (v.0, v.1)).collect::<Vec<_>>(),
            [(woke + s(35), 1)],
            "restarted for the sleep, or more than once per allowance: {verdicts:?}"
        );
        assert_eq!(verdicts[0].2, s(35), "the sleep counted as silence");

        // A loop that checks in after the wake is left alone.
        let pulse = Pulse::default();
        let mut clock = WatchdogClock::new(t0);
        beat_at(&pulse, 2, t0);
        assert!(looks(&mut clock, &pulse, t0 + period, t0 + s(25)).is_empty());
        let mut now = woke;
        for _ in 0..24 {
            assert!(watchdog_look(&mut clock, &pulse, now, period).is_none());
            beat_at(&pulse, 2, now);
            now += period;
        }

        // A loop that ended (a give-up) is not restarted, slept on or not.
        let pulse = Pulse::default();
        let mut clock = WatchdogClock::new(t0);
        beat_at(&pulse, 3, t0);
        pulse.clear(3);
        assert!(looks(&mut clock, &pulse, t0 + period, woke + s(60)).is_empty());
    }

    #[test]
    fn a_loop_is_overdue_only_past_what_it_announced() {
        let s = Duration::from_secs;
        assert!(!overdue(s(30), s(30)));
        assert!(overdue(s(31), s(30)));
        // A re-dial announces its backoff and its own budget.
        assert!(!overdue(s(60 + 120), s(60) + DIAL_ALLOWANCE));
        assert_eq!(WATCHDOG_TICKS, 6);
        // The allowances cover the steps they announce.
        assert!(HEARTBEAT_TIMEOUT < Duration::from_secs(5) * WATCHDOG_TICKS);
        // MR-2036 (review): a stop() that timed out, or a build that failed,
        // is followed by the manager's wait for the dropped tunnel's cleanup,
        // as long as the bound the manager waits on (65 s on Windows).
        let cleanup = crate::vpn::emergency_teardowns().bound;
        assert_eq!(cleanup, crate::vpn::EMERGENCY_TEARDOWN_BOUND);
        // MR-2390: a move's server list goes before all of it.
        assert!(
            SERVER_LIST_TIMEOUT + REDIAL_API_TIMEOUT + Duration::from_secs(60 + 5) + cleanup
                < DIAL_ALLOWANCE
        );
        assert!(
            Duration::from_secs(30 + 15 + 5) + cleanup + OLD_KEY_PROBE_TIMEOUT < TEARDOWN_ALLOWANCE
        );
    }

    /// WIN3-003: a standby is not a stuck loop. The watchdog's sleep stops
    /// while the machine sleeps and `Instant` does not, so its first look
    /// after an hour in standby found a beat an hour old and restarted a
    /// healthy loop. A loop that really stops is still caught, one allowance
    /// after the wake.
    #[test]
    fn the_watchdog_does_not_count_a_sleep_as_silence() {
        let s = Duration::from_secs;
        let (period, allowance) = (s(5), s(30));
        let t0 = Instant::now();
        let mut clock = WatchdogClock::new(t0);
        let beat = t0;

        clock.look(t0 + period, period);
        assert_eq!(clock.silent_for(beat, t0 + period), period);

        let woke = t0 + period + s(3600);
        clock.look(woke, period);
        assert!(
            !overdue(clock.silent_for(beat, woke), allowance),
            "the sleep read as silence"
        );

        let mut now = woke;
        for _ in 0..6 {
            now += period;
            clock.look(now, period);
        }
        assert_eq!(clock.silent_for(beat, now), allowance);
        now += period;
        clock.look(now, period);
        assert!(overdue(clock.silent_for(beat, now), allowance));
        // A beat after the wake counts from the beat.
        assert_eq!(clock.silent_for(now - s(1), now), s(1));
    }

    /// WIN-FIX-3: every network call the loop makes is capped. (That a
    /// stalled packet path is judged before the fast rule is driven in
    /// `packet_path_rule_tests`, MR-1408.)
    #[test]
    fn every_network_call_of_the_loop_is_capped() {
        let source: String = include_str!("auto_reconnect.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let body = |head: &str| {
            let head: String = head.chars().filter(|c| !c.is_whitespace()).collect();
            let start = source.find(&head).unwrap_or_else(|| panic!("{head}"));
            source[start..].to_string()
        };
        let heartbeat = body("async fn heartbeat(&mut self, now: Instant) -> Flow {");
        assert!(heartbeat.contains("timeout(HEARTBEAT_TIMEOUT,self.api.heartbeat(&key_id))"));
        let redial = body("async fn redial(&self, epoch: u64)");
        assert!(redial.contains("timeout(REDIAL_API_TIMEOUT,request_fresh_response("));
        let probe = body("async fn ask_the_old_key(");
        assert!(probe.contains("ask_twice(OLD_KEY_PROBE_TIMEOUT,||api.heartbeat(key_id))"));
        let twice = body("async fn ask_twice<");
        assert!(twice.contains("timeout(budget,asked)"));
    }

    #[test]
    fn a_multi_hop_session_is_published_on_its_exit() {
        let info = ReconnectInfo {
            server_id: "entry-1".into(),
            server_name: "Frankfurt → Reykjavik".into(),
            local_network_sharing: false,
            custom_mtu: 0,
            custom_port: "auto".into(),
            custom_dns: None,
            stealth_mode: false,
            quantum_protection: false,
            dns_filtering: false,
            fallback_reason: None,
            multi_hop: Some(MultiHopStatus {
                entry_id: "entry-1".into(),
                entry_name: "Frankfurt".into(),
                exit_id: "exit-1".into(),
                exit_name: "Reykjavik".into(),
            }),
            origin: SelectionOrigin::User,
        };
        assert_eq!(info.label().server_id, "exit-1");
        let single = ReconnectInfo {
            multi_hop: None,
            ..info
        };
        assert_eq!(single.label().server_id, "entry-1");
    }

    /// REVIEW-WIN2-005, the wiring of `reconnect_policy::LocalLink` (tested
    /// there): the fast dead-peer rule is not consulted while there is no
    /// route off the machine, and a route that comes back re-proves the path
    /// with the unanswered run forgotten.
    #[test]
    fn a_local_outage_is_not_judged_by_the_fast_rule() {
        let source = include_str!("auto_reconnect.rs");
        let start = source.find("async fn check_liveness(").unwrap();
        let body = &source[start..];
        let body = &body[..body.find("\n    }").unwrap()];
        let mut last = 0;
        for needle in [
            ".link\n",
            ".observe(network_events::connectivity_of(route.as_ref()))",
            "if link == LinkState::Returned {",
            "session.verify_since = Some(now);",
            "vm.restart_response_watch().await;",
            // Interface loss: the path is rebuilt, not just nudged.
            "rebuild_path(vm.as_ref(), session, path, now).await",
            "vm.force_handshake().await;",
            // The fast rule is told the link (`packet_path_rule_tests`
            // drives it: never consulted while offline).
            "judge_packet_path(vm.as_ref(), session, route, link, rebuilt, now)",
        ] {
            let needle = needle.trim_end_matches('\n');
            let at = body[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
            last += at + needle.len();
        }
    }

    /// Interface loss (2026-10-07), the wiring of the pieces tested in
    /// `reconnect_policy` and `wireguard_new`: a resume rebuilds the path
    /// like the link's return does; the packet path's rules run before the
    /// handshake-age backstop (their order — the send-path rule between the
    /// stall rule and the fast rule, rebuilding once and re-dialling when
    /// that did not help — is driven in `packet_path_rule_tests`); and a
    /// re-prove window is judged by the relay's answer to OUR initiation, not
    /// by boringtun's age.
    #[test]
    fn a_path_the_os_refuses_is_rebuilt_then_redialled() {
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let start = source.find("async fn check_liveness(").unwrap();
        let body = &source[start..];
        let body = &body[..body.find("\n    }\n").unwrap()];

        // The resume branch's own behaviour is driven in
        // `packet_path_rule_tests::a_resume_re_proves_the_path_in_order`; this
        // is only that the branch hands it to that function.
        let resume = &body[body.find("if resumes != session.resumes_seen {").unwrap()..];
        assert!(
            resume.contains("reprove_after_resume(vm.as_ref(), session, route, &mut rebuilt, now)")
        );

        let mut last = 0;
        for needle in [
            "judge_packet_path(vm.as_ref(), session, route, link, rebuilt, now)",
            "return dead;",
            "let proof_age = vm.proof_age().await.unwrap_or(age);",
            "proof_age < elapsed",
            // A window closed on proof forgets the outage's missed heartbeats.
            "session.heartbeat_misses = 0;",
            "reconnect_policy::judged_age(age, proof_age, verify_elapsed.is_some())",
            "reconnect_policy::liveness(",
        ] {
            let at = body[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
            last += at + needle.len();
        }

        let helper = &source[source.find("async fn rebuild_path(").unwrap()..];
        let helper = &helper[..helper.find("\n}\n").unwrap()];
        for step in [
            "session.send_repair.rebuilt(now);",
            "session.verify_since = Some(now);",
            "session.heartbeat_misses = 0;",
            "signals.repath(path).await",
        ] {
            assert!(helper.contains(step), "rebuild_path lost `{step}`");
        }
    }

    /// Review of #254: the heartbeat re-prove is Windows-only and asks the
    /// route signal, so macOS (no signal: `Unknown`, read as online) never
    /// re-dials mid-outage as `PathChanged` over missed heartbeats. The pure
    /// half is `reconnect_policy::no_route_signal_never_reproves_on_missed_heartbeats`.
    #[test]
    fn the_heartbeat_reprove_is_windows_only_and_asks_the_route_signal() {
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];
        let at = code
            .find("if reconnect_policy::heartbeat_reprove(")
            .expect("the re-prove");
        assert!(
            code[..at]
                .trim_end()
                .ends_with("#[cfg(target_os = \"windows\")]"),
            "the heartbeat re-prove lost its Windows gate"
        );
        assert!(code[at..].starts_with(
            "if reconnect_policy::heartbeat_reprove(\n            session.heartbeat_misses,\n            \
             network_events::connectivity_of(route.as_ref()),"
        ));
        // Every write of the miss count sits in a Windows-only block, and the
        // field itself is Windows-only.
        let field = code.find("    heartbeat_misses: u32,").expect("the field");
        assert!(code[..field]
            .trim_end()
            .ends_with("#[cfg(target_os = \"windows\")]"));
        let heartbeat = &code[code.find("async fn heartbeat(&mut self").unwrap()..];
        let heartbeat = &heartbeat[..heartbeat
            .find("match reconnect_policy::heartbeat_verdict")
            .unwrap()];
        for (i, _) in heartbeat.match_indices("self.session.heartbeat_misses =") {
            let before = heartbeat[..i].trim_end();
            assert!(
                before.ends_with("#[cfg(target_os = \"windows\")]\n                {")
                    || before.ends_with("#[cfg(target_os = \"windows\")]\n        {"),
                "a miss-count write outside a Windows block: {}",
                &heartbeat[i.saturating_sub(120)..i]
            );
        }
    }

    /// Interface loss: only a heartbeat that failed on the network counts
    /// toward a re-prove; any answer — a status included — crossed the
    /// tunnel and resets the run.
    #[test]
    fn only_a_heartbeat_lost_on_the_network_counts_toward_a_reprove() {
        use crate::api::ApiError;
        assert!(heartbeat_missed_the_network(&ApiError::Network(
            "connection reset".into()
        )));
        for answered in [
            ApiError::ServerError(503),
            ApiError::Unauthorized,
            ApiError::Parse("x".into()),
            ApiError::Rejected {
                status: 409,
                message: "x".into(),
            },
        ] {
            assert!(!heartbeat_missed_the_network(&answered), "{answered:?}");
        }
        let source: String = include_str!("auto_reconnect.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let heartbeat = &source[source
            .find("asyncfnheartbeat(&mutself,now:Instant)->Flow{")
            .unwrap()..];
        let heartbeat = &heartbeat[..heartbeat
            .find("matchreconnect_policy::heartbeat_verdict")
            .unwrap()];
        // The failure rule itself, with a gated (never sent) heartbeat, is
        // `misses_after_failure` (a_heartbeat_that_was_never_sent_…).
        assert!(heartbeat.contains(
            "self.session.heartbeat_misses=misses_after_failure(self.session.heartbeat_misses,&e);"
        ));
        assert!(heartbeat.contains(
            "self.session.heartbeat_misses=self.session.heartbeat_misses.saturating_add(1);"
        ));
        assert!(heartbeat.contains("self.session.heartbeat_misses=0;}ifresp.valid{"));
    }

    /// REVIEW-WIN-009: every give-up the POLICY decides is marked on the final
    /// status with the attempts it spent — except an ending the server decided
    /// (REVIEW-WIN2-002, `reconnect_policy::marks_give_up`); the heartbeat's
    /// revocation, which ends no recovery, is not marked either.
    #[test]
    fn policy_give_ups_are_marked_and_revocations_are_not() {
        let source = include_str!("auto_reconnect.rs");
        let arm = &source[source.find("Action::GiveUp(error) => {").unwrap()..];
        let arm = &arm[..arm.find("Flow::Stop").unwrap()];
        assert!(
            arm.contains("reconnect_policy::marks_give_up(error.code).then("),
            "{arm}"
        );
        assert!(arm.contains("attempts: self.policy.attempts()"), "{arm}");
        assert!(arm.contains("self.give_up(error, gave_up)"), "{arm}");

        // Both ways the server's ending arrives — the heartbeat, and the old
        // key's answer after a teardown — end unmarked, with no re-dial.
        // (What a reply decides is driven in
        // `a_reaped_reply_is_rebuilt_once_then_ended`.)
        let beat = &source[source
            .find("match self.take_reply(reply, now).await {")
            .unwrap()..];
        let beat = &beat[..beat.find("AfterReply::Stop").unwrap()];
        assert!(
            beat.contains("AfterReply::End(error) => self.end_by_server(error).await,"),
            "{beat}"
        );
        let helper = &source[source.find("async fn end_by_server(").unwrap()..];
        let helper = &helper[..helper.find("Flow::Stop").unwrap()];
        assert!(helper.contains("self.give_up(error, None)"), "{helper}");
        assert!(helper.contains("last_reconnect_info.write().await = None"));
    }

    /// Proposed row 1 (MR-734): v1.4.45 parked the gap between re-dials in
    /// `Disconnected` for up to 5 s with the block up, and a Kill Switch OFF
    /// there was taken for "no session": saved, never applied, re-blocked by
    /// the next attempt. Every state this loop writes during a recovery is
    /// `Reconnecting` (the teardown, the offline pause, a failed dial) and it
    /// ends in `Error`: the loop never publishes `Disconnected`, nor tears
    /// down to it.
    #[test]
    fn the_reconnect_gap_is_never_published_as_disconnected() {
        // A Windows checkout has CRLF endings (core.autocrlf).
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];
        for write in ["ConnectionState::Disconnected)", ".disconnect().await"] {
            assert!(!code.contains(write), "the loop writes `{write}`");
        }
        let teardown = &code[code.find("Action::TearDown { cause } => {").unwrap()..];
        assert!(teardown.contains(".disconnect_to(ConnectionState::Reconnecting {"));
        let dial = &code[code.find("async fn dial(").unwrap()..];
        let dial = &dial[..dial.find("\n    }\n").unwrap()];
        assert!(
            dial.matches("vm.set_reconnecting(attempt,").count() >= 3,
            "every outcome of a dial that does not connect stays `Reconnecting`"
        );
    }

    /// REVIEW-WIN2-002 generalised (REVIEW-AND2-001), the wiring of
    /// `reconnect_policy::after_teardown` (its table is tested there): the
    /// key is read BEFORE the teardown clears it, asked only after the
    /// tunnel is down (so the probe leaves over the physical network), and
    /// before the re-dial; an ending stops the loop.
    #[test]
    fn a_dead_session_asks_its_old_key_before_re_dialling() {
        let source = include_str!("auto_reconnect.rs");
        let arm = &source[source.find("Action::TearDown { cause } => {").unwrap()..];
        let arm = &arm[..arm.find("Action::PauseOffline").unwrap()];
        let mut last = 0;
        for needle in [
            "let old_key = vm.get_key_id().await;",
            ".disconnect_to(ConnectionState::Reconnecting {",
            "reconnect_policy::asks_the_old_key(cause)",
            "self.ask_the_old_key(&key_id, now).await",
            "return self.end_by_server(error).await;",
            "Flow::Again",
        ] {
            let at = arm[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
            last += at + needle.len();
        }
        let probe = &source[source.find("async fn ask_the_old_key(").unwrap()..];
        let probe = &probe[..probe.find("\n    }").unwrap()];
        // WIN3-001: on connections of its own, not the pool the tunnel's
        // heartbeats left behind.
        assert!(probe.contains("let api = self.api_after_teardown();"));
        assert!(probe.contains("ask_twice(OLD_KEY_PROBE_TIMEOUT, || api.heartbeat(key_id))"));
        // What the reply decides is driven in
        // `a_failed_probe_re_dials_and_never_ends_the_session`.
        assert!(probe.contains("let (ending, answer) = probe_verdict(&reply, alive);"));
        assert_eq!(OLD_KEY_PROBE_TIMEOUT, Duration::from_secs(5));
        let fresh = &source[source.find("fn api_after_teardown(&self)").unwrap()..];
        assert!(fresh[..fresh.find("\n    }").unwrap()]
            .contains("self.api.on_fresh_connections(local)"));
    }

    /// MR-2071, the wiring of `reconnect_policy::teardown_covered` (the rule,
    /// and the budget a held tunnel spends, are driven in `reconnect_policy`):
    /// the block goes up first, and a teardown it does not cover goes to the
    /// hold before anything is torn down. The hold tears nothing down, reads
    /// `Reconnecting`, and ends the step: the next look asks again.
    #[test]
    fn a_dead_tunnel_is_held_when_the_kill_switch_cannot_block() {
        fn in_order(haystack: &str, needles: &[&str]) {
            let mut last = 0;
            for needle in needles {
                let at = haystack[last..]
                    .find(needle)
                    .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
                last += at + needle.len();
            }
        }
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let arm = &source[source.find("Action::TearDown { cause } => {").unwrap()..];
        let arm = &arm[..arm.find("Action::PauseOffline").unwrap()];
        in_order(
            arm,
            &[
                "let engaged = killswitch::activate_killswitch().await;",
                ".hold_dead_tunnel(&engaged, killswitch::platform_is_blocking())",
                "return held;",
                "let old_key = vm.get_key_id().await;",
                ".disconnect_to(ConnectionState::Reconnecting {",
            ],
        );
        let hold = &source[source.find("async fn hold_dead_tunnel(").unwrap()..];
        let hold = &hold[..hold.find("\n    }\n").unwrap()];
        for teardown in ["disconnect_to", "end_in_error", "deactivate_killswitch"] {
            assert!(!hold.contains(teardown), "the hold calls `{teardown}`");
        }
        in_order(
            hold,
            &[
                "reconnect_policy::teardown_covered(engaged, blocking).err()?;",
                "self.policy.on_teardown_held(error.clone())",
                ".set_reconnecting(attempt, Some(error), self.policy.reconnect_max())",
                "Some(Flow::Continue)",
            ],
        );
    }

    /// MR-2071, the hold driven by an injected engage result (no firewall is
    /// touched): an engage that failed with nothing blocking holds the dead
    /// tunnel — the step ends there, reading `Reconnecting` with the kill
    /// switch's error, an attempt spent — and every engage that covers the
    /// teardown lets it go ahead, with nothing written.
    #[tokio::test]
    async fn the_hold_follows_the_engage_it_is_given() {
        use crate::vpn::manager::BlockProbe;
        let vm = Arc::new(VpnManager::with_block_probe(|| BlockProbe {
            blocking: false,
            holds_block_while_connected: false,
        }));
        vm.set_state(ConnectionState::Connected).await.unwrap();
        let cfg = AutoReconnectConfig::default();
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut lp = ReconnectLoop {
            vpn_manager: Arc::clone(&vm),
            last_reconnect_info: Arc::new(RwLock::new(None)),
            api: Arc::new(BirdoApi::new()),
            app: None,
            shutdown,
            network: network_events::subscribe(),
            transport_exits: None,
            policy: ReconnectPolicy::new(cfg.budget()),
            session: SessionWatch::default(),
            quota_notice: QuotaNotice::default(),
            quiet_rebuilds: QuietRebuildCap::default(),
            rng: reconnect_policy::unit_random,
            alive: None,
            pulse: Pulse::default(),
            generation: 0,
            step_allowance: Duration::from_secs(1),
        };
        let failed = || Err::<bool, String>("FwpmTransactionCommit0 failed".into());

        // Covered: the block is up, the user wants none, or a block is still
        // in force after a failed refresh. The teardown goes ahead.
        for (engaged, blocking) in [(Ok(true), false), (Ok(false), false), (failed(), true)] {
            assert!(
                lp.hold_dead_tunnel(&engaged, blocking).await.is_none(),
                "{engaged:?} blocking={blocking}"
            );
        }
        assert_eq!(lp.policy.attempts(), 0);
        let seq = vm.published().seq;
        assert_eq!(vm.get_state().await, ConnectionState::Connected);

        // Not covered: held, and the step ends (`Continue`, not `Again`).
        for attempt in 1..=2 {
            let held = lp.hold_dead_tunnel(&failed(), false).await;
            assert!(matches!(held, Some(Flow::Continue)), "attempt {attempt}");
            assert_eq!(lp.policy.attempts(), attempt);
            match vm.get_state().await {
                ConnectionState::Reconnecting {
                    attempt: shown,
                    last_error: Some(error),
                } => {
                    assert_eq!(shown, attempt);
                    assert_eq!(error, reconnect_policy::killswitch_failed_error());
                }
                other => panic!("expected Reconnecting, got {other:?}"),
            }
        }
        let p = vm.published();
        assert!(p.seq > seq);
        assert_eq!(p.reconnect_max, Some(cfg.max_attempts));
    }

    /// MR-691: the re-dial follows a teardown too, so its `/vpn/connect` (or
    /// multi-hop) request goes out on connections of its own. On the shared
    /// client the first one met a keep-alive connection that died with the
    /// tunnel, failed at once and cost the attempt.
    #[test]
    fn a_re_dial_goes_out_on_connections_of_its_own() {
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let redial = &source[source.find("async fn redial(&self, epoch: u64)").unwrap()..];
        let redial: String = redial[..redial.find("\n    }\n").unwrap()]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let fresh = redial
            .find("letapi=self.api_after_teardown();")
            .expect("the re-dial builds its own client");
        let request = redial
            .find("request_fresh_response(&api,")
            .expect("and sends its request on it");
        assert!(fresh < request);
        assert!(
            !redial.contains("&self.api"),
            "nothing in the re-dial uses the pool"
        );
    }

    /// WIN3-001: the probe's first request can meet a connection that died
    /// with the tunnel. It is asked once more inside the same budget, and
    /// that answer counts. Twice failed is no answer; a probe that ran out of
    /// time is not asked again.
    #[tokio::test]
    async fn an_old_key_probe_that_fails_is_asked_once_more() {
        use crate::api::ApiError;
        let budget = Duration::from_secs(5);

        let calls = AtomicUsize::new(0);
        let answer = ask_twice(budget, || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Err(ApiError::Network("connection aborted".into()))
                } else {
                    Ok("valid:false, revoked")
                }
            }
        })
        .await;
        assert_eq!(answer, Ok("valid:false, revoked"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let calls = AtomicUsize::new(0);
        let answer: Result<(), _> = ask_twice(budget, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(ApiError::Network("connection refused".into())) }
        })
        .await;
        assert_eq!(answer, Err("request failed twice"));
        assert_eq!(calls.load(Ordering::SeqCst), 2, "a third try");

        let calls = AtomicUsize::new(0);
        let answer: Result<(), _> = ask_twice(Duration::from_millis(50), || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<(), ApiError>>()
        })
        .await;
        assert_eq!(answer, Err("no answer in time"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a spent budget was asked again"
        );
    }

    /// WIN3-001 (REVIEW-WIN3-013: "a failed probe request" was untested
    /// end to end): a probe whose requests fail gives no answer, and no
    /// answer re-dials — even for a session that was alive a moment ago,
    /// where a "session over" answer would end it. A first request that
    /// fails and a second that answers is decided by that answer.
    #[tokio::test]
    async fn a_failed_probe_re_dials_and_never_ends_the_session() {
        use crate::api::types::HeartbeatResponse;
        use crate::api::ApiError;
        let budget = Duration::from_secs(5);
        let answer =
            |json: &'static str| -> HeartbeatResponse { serde_json::from_str(json).unwrap() };

        let reply: Result<HeartbeatResponse, _> = ask_twice(budget, || async {
            Err(ApiError::Network("connection aborted".into()))
        })
        .await;
        for recently_alive in [true, false] {
            let (ending, said) = probe_verdict(&reply, recently_alive);
            assert!(ending.is_none(), "a failed probe ended the session");
            assert_eq!(said, "request failed twice");
        }

        let reply: Result<HeartbeatResponse, _> = ask_twice(Duration::from_millis(50), || {
            std::future::pending::<Result<HeartbeatResponse, ApiError>>()
        })
        .await;
        let (ending, said) = probe_verdict(&reply, true);
        assert!(ending.is_none());
        assert_eq!(said, "no answer in time");

        let calls = AtomicUsize::new(0);
        let reply = ask_twice(budget, || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Err(ApiError::Network("connection aborted".into()))
                } else {
                    Ok(answer(r#"{"valid":false,"reason":"evicted"}"#))
                }
            }
        })
        .await;
        let (ending, said) = probe_verdict(&reply, false);
        assert_eq!(said, "evicted");
        assert_eq!(ending.map(|e| e.code), Some(IpcErrorCode::Evicted));
    }

    /// The grace warning goes out once per session, not on every 30 s
    /// heartbeat of the 15-minute window.
    #[tokio::test]
    async fn the_quota_warning_goes_out_once_per_session() {
        let svc = service();
        assert!(svc.quota_notice.claim(), "the first grace heartbeat warns");
        assert!(!svc.quota_notice.claim(), "the next one does not");

        // REVIEW-WIN2-024: a reconnect or a settings reapply inside the grace
        // window starts a NEW loop over a new tunnel. It shares the session's
        // notice, so it does not warn again.
        svc.start().await.unwrap();
        svc.stop().await;
        svc.start().await.unwrap();
        svc.stop().await;
        assert!(!svc.quota_notice.claim());

        // The session ends (disconnect, sign-out): the next one may warn.
        svc.clear_last_config().await;
        assert!(svc.quota_notice.claim());

        // The heartbeat arm asks the shared notice, not the per-tunnel watch.
        let source = include_str!("auto_reconnect.rs");
        let arm = &source[source
            .find("HeartbeatVerdict::QuotaGrace { seconds_remaining } => {")
            .unwrap()..];
        let arm = &arm[..arm.find("Flow::Continue").unwrap()];
        let check = arm
            .find("if self.quota_notice.claim()")
            .expect("a once-per-session check");
        let emit = arm.find("QUOTA_WARNING_EVENT").expect("emitted");
        assert!(check < emit, "{arm}");
        let payload = serde_json::to_value(QuotaWarning {
            seconds_remaining: Some(540),
        })
        .unwrap();
        assert_eq!(payload, serde_json::json!({ "secondsRemaining": 540 }));
    }

    fn session_on_record() -> ReconnectInfo {
        ReconnectInfo {
            server_id: "node-1".into(),
            server_name: "Test node".into(),
            local_network_sharing: false,
            custom_mtu: 0,
            custom_port: "auto".into(),
            custom_dns: None,
            stealth_mode: false,
            quantum_protection: false,
            dns_filtering: false,
            fallback_reason: None,
            multi_hop: None,
            origin: SelectionOrigin::User,
        }
    }

    const REAPED: &str = r#"{"valid":false,"serverOnline":false,"message":"Connection not found. Please reconnect.","reason":"reaped"}"#;
    const DRAINED: &str = r#"{"valid":false,"serverOnline":false,"message":"Connection not found. Please reconnect.","reason":"server_offline"}"#;
    const HB_NOT_FOUND: &str = "Connection not found. Please reconnect.";

    /// A real heartbeat reply, decoded as `BirdoApi::heartbeat` decodes it.
    fn reply(json: &str) -> HeartbeatReply {
        HeartbeatReply::Answered(serde_json::from_str(json).unwrap())
    }

    /// A loop over a Connected session, with no tunnel, firewall or network
    /// behind it. Its quiet rebuild waits `rng`'s draw.
    async fn released_loop(
        info: Option<ReconnectInfo>,
        shutdown: watch::Receiver<bool>,
        cap: QuietRebuildCap,
        rng: fn() -> f64,
    ) -> ReconnectLoop {
        let vm = Arc::new(VpnManager::new());
        vm.set_state(ConnectionState::Connected).await.unwrap();
        ReconnectLoop {
            vpn_manager: vm,
            last_reconnect_info: Arc::new(RwLock::new(info)),
            api: Arc::new(BirdoApi::new()),
            app: None,
            shutdown,
            network: network_events::subscribe(),
            transport_exits: None,
            policy: ReconnectPolicy::new(AutoReconnectConfig::default().budget()),
            session: SessionWatch::default(),
            quota_notice: QuotaNotice::default(),
            quiet_rebuilds: cap,
            rng,
            alive: None,
            pulse: Pulse::default(),
            generation: 0,
            step_allowance: Duration::from_secs(1),
        }
    }

    fn connected_tick(now: Instant, liveness: Liveness) -> Tick {
        Tick {
            now,
            observed: Observed::Connected,
            holds_tunnel: false,
            liveness,
            connectivity: reconnect_policy::Connectivity::Online,
            upgrade_blocked: false,
            has_target: true,
        }
    }

    /// MR-2369, driven with real replies: a `reaped` check-in schedules ONE
    /// quiet rebuild after its random wait (7.5 s for a draw of 0.5); before
    /// it the tunnel is left alone, at it the look declares the tunnel dead
    /// as `ServerReleased`, which the policy tears down like any dead tunnel
    /// (no old-key probe). The re-dialled key reaped again ends the session
    /// with the revocation it had before MR-2369, and so does every later
    /// reap: never a loop.
    #[tokio::test]
    async fn a_reaped_reply_is_rebuilt_once_then_ended() {
        let (_tx, shutdown) = watch::channel(false);
        let cap = QuietRebuildCap::default();
        let mut lp = released_loop(Some(session_on_record()), shutdown, cap.clone(), || 0.5).await;
        let now = Instant::now();
        assert_eq!(
            lp.take_reply(reply(REAPED), now).await,
            AfterReply::Continue
        );
        let due = lp
            .session
            .release
            .as_ref()
            .map(|r| r.due)
            .expect("a quiet rebuild is pending");
        assert_eq!(due, now + Duration::from_millis(7500));
        assert_eq!(cap.with(|cap| cap.spent()), 1);

        let early = lp
            .check_liveness(&Wake::Tick, None, now + Duration::from_secs(7))
            .await;
        assert_ne!(early, Liveness::Dead(DropCause::ServerReleased));
        assert!(lp.session.release.is_some(), "still waiting");

        let liveness = lp.check_liveness(&Wake::Tick, None, due).await;
        assert_eq!(liveness, Liveness::Dead(DropCause::ServerReleased));
        assert!(lp.session.release.is_none(), "taken by the look");
        let Action::TearDown { cause } = lp.policy.decide(&connected_tick(due, liveness)) else {
            panic!("expected the teardown");
        };
        assert_eq!(cause, DropCause::ServerReleased);
        assert!(!reconnect_policy::asks_the_old_key(cause));

        // The re-dialled tunnel is a new watch; its key is reaped too.
        lp.session = SessionWatch::default();
        let ending = AfterReply::End(reconnect_policy::revoked_error(Some(HB_NOT_FOUND)));
        for k in 1..=4u64 {
            let at = due + Duration::from_secs(60 * k);
            assert_eq!(lp.take_reply(reply(REAPED), at).await, ending, "reap {k}");
            assert!(lp.session.release.is_none());
        }
        assert_eq!(cap.with(|cap| cap.spent()), 1);
    }

    /// MR-2369: `revoked`, `evicted` and `quota_exceeded` end the session
    /// from the reply, as before: no rebuild pending, the cap untouched. (A
    /// drained server's `server_offline` is rebuilt elsewhere since MR-2390:
    /// `a_drained_reply_is_rebuilt_once_on_another_server_then_ended`.)
    #[tokio::test]
    async fn every_other_ending_reply_ends_without_touching_the_cap() {
        for (json, ending) in [
            (
                r#"{"valid":false,"serverOnline":false,"message":"Connection has been revoked. Please reconnect.","reason":"revoked"}"#,
                reconnect_policy::revoked_error(Some(
                    "Connection has been revoked. Please reconnect.",
                )),
            ),
            (
                r#"{"valid":false,"serverOnline":false,"message":"Connection not found. Please reconnect.","reason":"evicted"}"#,
                reconnect_policy::evicted_error(),
            ),
            (
                r#"{"valid":false,"serverOnline":true,"quotaExceeded":true,"reason":"quota_exceeded","message":"x"}"#,
                reconnect_policy::quota_exceeded_error(),
            ),
            (
                r#"{"valid":false,"serverOnline":false,"quotaExceeded":true,"message":"x","reason":"reaped"}"#,
                reconnect_policy::quota_exceeded_error(),
            ),
            (
                r#"{"valid":false,"serverOnline":false,"quotaExceeded":true,"message":"x","reason":"server_offline"}"#,
                reconnect_policy::quota_exceeded_error(),
            ),
        ] {
            let (_tx, shutdown) = watch::channel(false);
            let cap = QuietRebuildCap::default();
            let mut lp =
                released_loop(Some(session_on_record()), shutdown, cap.clone(), || 0.0).await;
            assert_eq!(
                lp.take_reply(reply(json), Instant::now()).await,
                AfterReply::End(ending),
                "{json}"
            );
            assert!(lp.session.release.is_none(), "{json}");
            assert_eq!(cap.with(|cap| cap.spent()), 0, "{json}");
        }
    }

    /// MR-2390, driven with real replies: a drained server's check-in
    /// (`server_offline`, `valid:false`) schedules the episode's ONE quiet
    /// rebuild, like a reap: the same random wait, then a look that declares
    /// the tunnel dead as `ServerReleased` (no old-key probe). The rebuild
    /// names the server to move off, so the re-dial does not go back to it.
    /// It used to end the session as a revocation, and before that it
    /// re-dialled the same server ten times. Drained again in the same
    /// episode, or reaped after it, the session ends: as unavailable, and as
    /// the reap's revocation. Never a loop.
    #[tokio::test]
    async fn a_drained_reply_is_rebuilt_once_on_another_server_then_ended() {
        let (_tx, shutdown) = watch::channel(false);
        let cap = QuietRebuildCap::default();
        let mut lp = released_loop(Some(session_on_record()), shutdown, cap.clone(), || 0.5).await;
        let now = Instant::now();
        assert_eq!(
            lp.take_reply(reply(DRAINED), now).await,
            AfterReply::Continue
        );
        let due = lp
            .session
            .release
            .as_ref()
            .map(|r| r.due)
            .expect("a quiet rebuild is pending");
        assert_eq!(due, now + Duration::from_millis(7500));
        assert_eq!(cap.with(|cap| cap.spent()), 1);
        assert_eq!(
            cap.with(|cap| cap.leaving().map(str::to_string)),
            Some("node-1".to_string()),
            "the re-dial must move off the server on record"
        );
        let liveness = lp.check_liveness(&Wake::Tick, None, due).await;
        assert_eq!(liveness, Liveness::Dead(DropCause::ServerReleased));
        let Action::TearDown { cause } = lp.policy.decide(&connected_tick(due, liveness)) else {
            panic!("expected the teardown");
        };
        assert!(!reconnect_policy::asks_the_old_key(cause));

        // The re-dial moved the session (`leave_the_server`, driven in
        // `the_session_on_record_moves_by_its_origin`). Then the rebuilt
        // tunnel's server drains too, and it is reaped: the episode's one
        // rebuild is spent.
        assert_eq!(
            move_record(
                &mut *lp.last_reconnect_info.write().await,
                "node-1",
                &drained_fleet(),
                None
            ),
            Ok(())
        );
        cap.with(QuietRebuilds::left);
        lp.session = SessionWatch::default();
        let at = due + Duration::from_secs(60);
        assert_eq!(
            lp.take_reply(reply(DRAINED), at).await,
            AfterReply::End(reconnect_policy::server_left_error())
        );
        assert_eq!(
            lp.take_reply(reply(REAPED), at).await,
            AfterReply::End(reconnect_policy::revoked_error(Some(HB_NOT_FOUND)))
        );
        assert!(lp.session.release.is_none());
        assert_eq!(cap.with(|cap| cap.spent()), 1);
    }

    /// MR-2390: the old key's answer after a teardown. `server_offline` (the
    /// key removed with a drained server, or still live on a server that is
    /// not ONLINE) re-dials on ANOTHER server, on the same one-per-episode
    /// cap. It used to re-dial the same server, which the backend refuses.
    /// Past the cap it ends as unavailable. Any other answer keeps its
    /// verdict, and the cap is not touched.
    #[tokio::test]
    async fn the_old_keys_drained_answer_moves_the_re_dial_once() {
        let answer = |json: &str| -> crate::api::types::HeartbeatResponse {
            serde_json::from_str(json).unwrap()
        };
        let (_tx, shutdown) = watch::channel(false);
        let cap = QuietRebuildCap::default();
        let lp = released_loop(Some(session_on_record()), shutdown, cap.clone(), || 0.0).await;

        for kept in [
            r#"{"valid":true,"serverOnline":true,"reason":"ok"}"#,
            r#"{"valid":false,"serverOnline":false,"reason":"reaped"}"#,
        ] {
            assert_eq!(
                lp.unless_the_server_left(None, Some(&answer(kept))).await,
                (None, false),
                "{kept}"
            );
        }
        let evicted = reconnect_policy::evicted_error();
        assert_eq!(
            lp.unless_the_server_left(Some(evicted.clone()), Some(&answer(DRAINED)))
                .await,
            (Some(evicted), false),
            "an ending stands"
        );
        assert_eq!(lp.unless_the_server_left(None, None).await, (None, false));
        assert_eq!(cap.with(|cap| cap.spent()), 0);

        assert_eq!(
            lp.unless_the_server_left(
                None,
                Some(&answer(
                    r#"{"valid":true,"serverOnline":false,"reason":"server_offline"}"#
                ))
            )
            .await,
            (None, true),
            "re-dial, elsewhere"
        );
        assert_eq!(
            cap.with(|cap| cap.leaving().map(str::to_string)),
            Some("node-1".to_string())
        );
        // A check-in had already reported the drain: still that one move.
        assert_eq!(
            lp.unless_the_server_left(None, Some(&answer(DRAINED)))
                .await,
            (None, true),
            "the same drain, before its move"
        );
        assert_eq!(cap.with(|cap| cap.spent()), 1);
        // Once moved, the next drain finds the episode's move spent.
        cap.with(QuietRebuilds::left);
        assert_eq!(
            lp.unless_the_server_left(None, Some(&answer(DRAINED)))
                .await,
            (Some(reconnect_policy::server_left_error()), true),
            "the episode's move is spent"
        );
        assert_eq!(cap.with(|cap| cap.spent()), 1);
    }

    /// A list of servers in the `/vpn/servers` wire shape, and a session on
    /// `node-1` (DE, Frankfurt) chosen by `origin`.
    fn drained_fleet() -> Vec<crate::api::types::VpnServer> {
        [
            ("node-1", "DE", "Frankfurt", 0, false),
            ("de-ber", "DE", "Berlin", 60, true),
            ("nl-ams", "NL", "Amsterdam", 5, true),
        ]
        .into_iter()
        .map(|(id, cc, city, load, online)| {
            serde_json::from_value(serde_json::json!({
                "id": id, "name": format!("Name {id}"), "country": cc, "countryCode": cc,
                "city": city, "load": load, "isOnline": online, "accessible": true,
            }))
            .unwrap()
        })
        .collect()
    }

    fn on_record(origin: SelectionOrigin) -> Option<ReconnectInfo> {
        Some(ReconnectInfo {
            origin,
            ..session_on_record()
        })
    }

    /// MR-2390, the move itself: a server the client chose moves to the best
    /// server anywhere; one the user picked stays in its country. The name
    /// moves with the id, so the session is published on the new server,
    /// and the origin stays. With nothing left in the user's country, or on a
    /// Multi-Hop route, nothing moves and the session ends as unavailable.
    /// It is never moved abroad.
    #[test]
    fn the_session_on_record_moves_by_its_origin() {
        let fleet = drained_fleet();
        let mut record = on_record(SelectionOrigin::Automatic);
        assert_eq!(move_record(&mut record, "node-1", &fleet, None), Ok(()));
        let moved = record.unwrap();
        assert_eq!(
            (moved.server_id.as_str(), moved.server_name.as_str()),
            ("nl-ams", "Name nl-ams")
        );
        assert_eq!(moved.origin, SelectionOrigin::Automatic);

        let mut record = on_record(SelectionOrigin::User);
        assert_eq!(move_record(&mut record, "node-1", &fleet, None), Ok(()));
        assert_eq!(record.unwrap().server_id, "de-ber", "never abroad");

        let abroad_only: Vec<_> = fleet.iter().filter(|s| s.id != "de-ber").cloned().collect();
        let mut record = on_record(SelectionOrigin::User);
        assert_eq!(
            move_record(&mut record, "node-1", &abroad_only, None),
            Err(reconnect_policy::server_left_error())
        );
        assert_eq!(record.unwrap().server_id, "node-1", "not moved");

        let mut record = on_record(SelectionOrigin::Automatic);
        if let Some(info) = record.as_mut() {
            info.multi_hop = Some(MultiHopStatus {
                entry_id: "node-1".into(),
                entry_name: "Frankfurt".into(),
                exit_id: "nl-ams".into(),
                exit_name: "Amsterdam".into(),
            });
        }
        assert_eq!(
            move_record(&mut record, "node-1", &fleet, None),
            Err(reconnect_policy::server_left_error()),
            "a Multi-Hop route is never moved"
        );

        // Nothing on record, or a session that is not on that server:
        // nothing to move.
        let mut none = None;
        assert_eq!(move_record(&mut none, "node-1", &fleet, None), Ok(()));
        let mut elsewhere = on_record(SelectionOrigin::Automatic);
        assert_eq!(move_record(&mut elsewhere, "other", &fleet, None), Ok(()));
        assert_eq!(elsewhere.unwrap().server_id, "node-1");
    }

    /// MR-2390, a DELETED server (owner, 2026-11-19, every client): gone from
    /// the list the move fetches, so where it was comes from the lists
    /// fetched before (`relay_retry::known_location`). A server the client
    /// chose moves to the best server anywhere, another country when its own
    /// has none. One the user picked moves only within its country. With
    /// nothing there, or its country unknown, it does not move: the session
    /// ends as unavailable, and the always-on kill switch keeps its block
    /// (the UI then says the block is on purpose, `vpnErrorCopy`). The
    /// deleted server is never picked, and the episode has one move.
    #[test]
    fn a_deleted_server_moves_by_its_origin_from_where_it_was() {
        let frankfurt = relay_retry::Location {
            country_code: "DE".into(),
            city: "Frankfurt".into(),
        };
        // node-1 (DE, Frankfurt) is deleted: the list no longer has it.
        let listed: Vec<_> = drained_fleet()
            .into_iter()
            .filter(|s| s.id != "node-1")
            .collect();
        let abroad_only: Vec<_> = listed
            .iter()
            .filter(|s| s.id != "de-ber")
            .cloned()
            .collect();

        // The client's pick: another country when its own has none, and
        // anywhere when where it was is not known.
        for last_known in [Some(&frankfurt), None] {
            let mut record = on_record(SelectionOrigin::Automatic);
            assert_eq!(
                move_record(&mut record, "node-1", &abroad_only, last_known),
                Ok(())
            );
            let moved = record.unwrap();
            assert_eq!(
                (moved.server_id.as_str(), moved.origin),
                ("nl-ams", SelectionOrigin::Automatic),
                "{last_known:?}"
            );
        }

        // The user's pick: within its country when a server is there.
        let mut record = on_record(SelectionOrigin::User);
        assert_eq!(
            move_record(&mut record, "node-1", &listed, Some(&frankfurt)),
            Ok(())
        );
        let moved = record.unwrap();
        assert_eq!(
            (moved.server_id.as_str(), moved.server_name.as_str()),
            ("de-ber", "Name de-ber")
        );
        assert_eq!(moved.origin, SelectionOrigin::User);

        // Nothing in its country, or its country unknown: no move, and the
        // session ends as unavailable, the block held under always-on only.
        for last_known in [Some(&frankfurt), None] {
            let mut record = on_record(SelectionOrigin::User);
            let ending = move_record(&mut record, "node-1", &abroad_only, last_known).unwrap_err();
            assert_eq!(ending, reconnect_policy::server_left_error());
            assert_eq!(ending.code, IpcErrorCode::ServerUnavailable);
            assert!(reconnect_policy::give_up_keeps_block(ending.code, true));
            assert!(!reconnect_policy::give_up_keeps_block(ending.code, false));
            assert_eq!(record.unwrap().server_id, "node-1", "not moved");
        }

        // The deleted server is never picked, whatever an earlier list said
        // of it.
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            let mut record = on_record(origin);
            let _ = move_record(&mut record, "node-1", &listed, Some(&frankfurt));
            assert_ne!(record.unwrap().server_id, "node-1", "{origin:?}");
        }

        // One move per episode: the server it moved to is deleted too, and
        // the cap ends the session instead of moving it again.
        let mut cap = QuietRebuilds::default();
        assert_eq!(
            cap.on_server_left(false, Some("node-1")),
            OnRelease::Rebuild
        );
        cap.left();
        assert_eq!(cap.on_server_left(false, Some("de-ber")), OnRelease::End);
        assert_eq!(cap.spent(), 1);
    }

    /// MR-2390, the wiring of the move (the choice and the record are driven
    /// above): a dial moves the session off a server that left BEFORE it
    /// re-dials, under the same epoch. The server list comes on connections
    /// of its own (like the re-dial), capped and cancellable. The cap's mark
    /// is cleared only once the list is in hand, and a move that finds
    /// nowhere to go ends the session.
    #[test]
    fn a_dial_moves_off_a_server_that_left_before_it_re_dials() {
        fn in_order(haystack: &str, needles: &[&str]) {
            let mut last = 0;
            for needle in needles {
                let at = haystack[last..]
                    .find(needle)
                    .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
                last += at + needle.len();
            }
        }
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];
        let dial = &code[code.find("async fn dial(").unwrap()..];
        let dial = &dial[..dial.find("\n    }\n").unwrap()];
        in_order(
            dial,
            &[
                "let epoch = vm.current_epoch();",
                "self.leave_the_server(attempt, epoch).await",
                "return flow;",
                "self.redial(epoch).await",
            ],
        );
        let leave = &code[code.find("async fn leave_the_server(").unwrap()..];
        let leave = &leave[..leave.find("\n    }\n").unwrap()];
        in_order(
            leave,
            &[
                "cap.leaving()",
                "let api = self.api_after_teardown();",
                ".run_cancellable(epoch, timeout(SERVER_LIST_TIMEOUT, api.get_servers()))",
                "self.policy.on_dial_failed(error.clone());",
                "self.quiet_rebuilds.with(QuietRebuilds::left);",
                "relay_retry::known_location(&leaving)",
                "relay_retry::remember(&servers);",
                "move_record(",
                "self.end_by_server(ending).await",
            ],
        );
    }

    /// MR-2369: a reap that arrives while the user ends the session (the
    /// loop being stopped: Disconnect, sign-out and quit stop it first)
    /// re-dials, ends and spends nothing. With no session on record and no
    /// one stopping the loop, the session ends with the reap's ending — not a
    /// stop that would leave a dead tunnel reading Connected.
    #[tokio::test]
    async fn a_reap_while_the_user_disconnects_is_never_rebuilt() {
        let cap = QuietRebuildCap::default();
        let (tx, shutdown) = watch::channel(false);
        let mut lp = released_loop(Some(session_on_record()), shutdown, cap.clone(), || 0.0).await;
        tx.send(true).unwrap();
        assert_eq!(
            lp.take_reply(reply(REAPED), Instant::now()).await,
            AfterReply::Stop
        );
        assert!(lp.session.release.is_none());

        let (_tx, shutdown) = watch::channel(false);
        let mut lp = released_loop(None, shutdown, cap.clone(), || 0.0).await;
        assert_eq!(
            lp.take_reply(reply(REAPED), Instant::now()).await,
            AfterReply::End(reconnect_policy::revoked_error(Some(HB_NOT_FOUND)))
        );
        assert!(lp.session.release.is_none());
        assert_eq!(cap.with(|cap| cap.spent()), 0, "nothing spent");
    }

    /// MR-2369 (review): a pending quiet rebuild cannot pass the 426 floor.
    /// Latched (before the reap or during its wait), the session ends with
    /// the reap's ending instead of the policy halting over a dead tunnel
    /// that reads Connected; unlatched, the rebuild is left to its look.
    #[tokio::test]
    async fn the_floor_ends_a_pending_rebuild_instead_of_halting_over_it() {
        let (_tx, shutdown) = watch::channel(false);
        let mut lp = released_loop(
            Some(session_on_record()),
            shutdown,
            QuietRebuildCap::default(),
            || 0.5,
        )
        .await;
        let now = Instant::now();
        assert_eq!(
            lp.release_stopped_by_floor(now, true),
            None,
            "nothing pending"
        );
        assert_eq!(
            lp.take_reply(reply(REAPED), now).await,
            AfterReply::Continue
        );
        assert_eq!(lp.release_stopped_by_floor(now, false), None);
        assert_eq!(
            lp.release_stopped_by_floor(now + Duration::from_secs(60), false),
            None,
            "due: the look's to rebuild"
        );
        assert!(lp.session.release.is_some());
        assert_eq!(
            lp.release_stopped_by_floor(now + Duration::from_secs(1), true),
            Some(reconnect_policy::revoked_error(Some(HB_NOT_FOUND)))
        );
        assert!(lp.session.release.is_none());

        // The step asks before it looks, and ends the session with it.
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let step = &source[source.find("async fn step(&mut self, wake: Wake)").unwrap()..];
        let step = &step[..step.find("let tick = Tick {").unwrap()];
        let floor = step
            .find("if let Some(ending) = self.release_stopped_by_floor(now, upgrade_blocked) {")
            .expect("the floor check");
        let end = step
            .find("return self.end_by_server(ending).await;")
            .expect("the ending");
        let look = step.find("self.check_liveness(").expect("the look");
        assert!(floor < end && end < look, "{step}");
    }

    /// MR-2369 (review): the cap is the SESSION's, so a loop that replaces
    /// another — a watchdog restart builds it the way `start_locked` does —
    /// carries on with what the episode spent. Two loops built by the
    /// service: the first spends the rebuild on a reap, the second ends on
    /// one. Then a running loop and its restart: each starts on the
    /// session's cap (its start ends the session's healthy run), and the
    /// restart refills nothing. A new session on record, and the session's
    /// end, start the cap whole.
    #[tokio::test]
    async fn the_cap_is_the_sessions_across_loops_and_restarts() {
        let svc = service();
        let cfg = AutoReconnectConfig::default();
        let spent = |svc: &AutoReconnectService| svc.quiet_rebuilds.with(|cap| cap.spent());
        let in_run =
            |svc: &AutoReconnectService| svc.quiet_rebuilds.with(|cap| cap.in_healthy_run());
        svc.store_last_config(session_on_record()).await;

        let (_tx1, shutdown) = watch::channel(false);
        let mut first = svc.new_loop(&cfg, shutdown, 1001);
        let now = Instant::now();
        assert_eq!(
            first.take_reply(reply(REAPED), now).await,
            AfterReply::Continue
        );
        assert!(first.session.release.is_some());
        let (_tx2, shutdown) = watch::channel(false);
        let mut second = svc.new_loop(&cfg, shutdown, 1002);
        assert_eq!(
            second.take_reply(reply(REAPED), now).await,
            AfterReply::End(reconnect_policy::revoked_error(Some(HB_NOT_FOUND))),
            "the replacing loop re-dialled again"
        );
        assert_eq!(spent(&svc), 1);

        // Running loops, with nothing on record for them to dial, over a
        // session that reads Connected (no tunnel, no key: the look finds it
        // healthy and the heartbeat has nothing to send). Connected, a
        // step never ends the run for being down: only the loop's start
        // can.
        *svc.last_reconnect_info.write().await = None;
        svc.vpn_manager
            .set_state(ConnectionState::Connected)
            .await
            .unwrap();
        svc.quiet_rebuilds.with(|cap| cap.healthy(Instant::now()));
        svc.start().await.unwrap();
        wait_until("the loop to start on the session's cap", || !in_run(&svc)).await;
        let generation = running(&svc).await.expect("a loop");
        svc.quiet_rebuilds.with(|cap| cap.healthy(Instant::now()));
        svc.restart_stalled(generation).await;
        let restarted = running(&svc).await.expect("a restarted loop");
        assert_ne!(restarted, generation);
        wait_until("the restarted loop to start on the session's cap", || {
            !in_run(&svc)
        })
        .await;
        assert_eq!(spent(&svc), 1, "a restart refilled the cap");
        svc.stop().await;

        svc.store_last_config(session_on_record()).await;
        assert_eq!(spent(&svc), 0, "a new session");
        let (_tx3, shutdown) = watch::channel(false);
        let mut third = svc.new_loop(&cfg, shutdown, 1003);
        assert_eq!(
            third.take_reply(reply(REAPED), now).await,
            AfterReply::Continue
        );
        assert_eq!(spent(&svc), 1);
        svc.clear_last_config().await;
        assert_eq!(spent(&svc), 0, "the session ended");
    }

    /// MR-2369 (review): the healthy run, driven with real replies: a valid
    /// check-in starts or continues it, a failed or unanswered one ends it.
    /// Its longest gap is two heartbeat intervals and a timeout.
    #[tokio::test]
    async fn only_valid_check_ins_make_a_healthy_run() {
        use crate::api::ApiError;
        assert_eq!(
            reconnect_policy::HEALTHY_RUN_MAX_GAP,
            HEARTBEAT_INTERVAL * 2 + HEARTBEAT_TIMEOUT
        );
        let (_tx, shutdown) = watch::channel(false);
        let cap = QuietRebuildCap::default();
        let mut lp = released_loop(Some(session_on_record()), shutdown, cap.clone(), || 0.0).await;
        let in_run = || cap.with(|cap| cap.in_healthy_run());
        let ok = r#"{"valid":true,"serverOnline":true,"reason":"ok"}"#;
        let now = Instant::now();
        assert_eq!(lp.take_reply(reply(ok), now).await, AfterReply::Continue);
        assert!(in_run());
        lp.take_reply(HeartbeatReply::Unanswered, now).await;
        assert!(!in_run(), "unanswered");
        lp.take_reply(reply(ok), now).await;
        assert!(in_run());
        lp.take_reply(HeartbeatReply::Failed(ApiError::ServerError(503)), now)
            .await;
        assert!(!in_run(), "failed");
    }

    /// MR-2369 (review): production re-dials are jittered.
    #[test]
    fn production_redials_are_jittered() {
        assert_eq!(
            AutoReconnectConfig::default().budget().jitter,
            reconnect_policy::BACKOFF_JITTER
        );
    }

    /// MR-2369, the wiring left to read: the reap arm only schedules the
    /// rebuild — no teardown, kill switch or dial of its own: the policy's
    /// teardown arm does that, behind the block, as for every dead tunnel
    /// (`a_dead_tunnel_is_held_when_the_kill_switch_cannot_block`) — and the
    /// session's end resets the cap.
    #[test]
    fn a_reap_goes_through_the_teardown_and_the_cap() {
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];
        let arm = &code[code
            .find("HeartbeatVerdict::Rebuild { ending, moves } =>")
            .unwrap()..];
        let arm = &arm[..arm.find("HeartbeatVerdict::QuotaGrace").unwrap()];
        assert!(arm.contains("self.session.release = Some(PendingRelease {"));
        for teardown in [
            "disconnect_to",
            "end_in_error",
            "killswitch::",
            ".dial(",
            ".redial(",
            "give_up(",
            "end_by_server(",
        ] {
            assert!(!arm.contains(teardown), "the reap arm calls `{teardown}`");
        }
        let end = &code[code.find("async fn end_by_server(").unwrap()..];
        let end = &end[..end.find("Flow::Stop").unwrap()];
        assert!(end.contains("self.quiet_rebuilds.reset();"), "{end}");
    }
}

/// MR-1408 (REVIEW-WIN3-013): the packet path's rules driven in their order
/// on paused time, against a tunnel whose signals the test sets. These used
/// to be a source-order pin on `check_liveness`.
#[cfg(all(test, target_os = "windows"))]
mod packet_path_rule_tests {
    use super::*;
    use crate::vpn::wireguard_new::{
        SendHealth, PACKET_PATH_STALL, SEND_PATH_BROKEN_AFTER, SEND_PATH_MIN_FAILURES,
        STALL_CONFIRM,
    };
    use std::sync::Mutex;
    use tokio::time::advance;

    /// A live tunnel as the rules see it: when its packet path last made
    /// progress, whether the relay reads unresponsive, what the OS says about
    /// our sends — and the paused clock.
    #[derive(Default)]
    struct Tunnel {
        progress: Mutex<Option<Instant>>,
        unresponsive: AtomicBool,
        sends: Mutex<SendHealth>,
        repaths: AtomicUsize,
        /// What a resume did to the tunnel, in order.
        calls: Mutex<Vec<&'static str>>,
        /// `repath` fails.
        repath_fails: AtomicBool,
    }

    impl Tunnel {
        /// The packet path ran just now.
        fn ticks(&self) {
            *self.progress.lock().unwrap() = Some(self.now());
        }
    }

    impl PathSignals for Tunnel {
        fn now(&self) -> Instant {
            tokio::time::Instant::now().into_std()
        }

        async fn packet_path_progress(&self) -> Option<Instant> {
            *self.progress.lock().unwrap()
        }

        async fn send_health(&self) -> Option<SendHealth> {
            Some(*self.sends.lock().unwrap())
        }

        async fn repath(&self, _path: PhysicalRoute) -> Result<bool, String> {
            self.repaths.fetch_add(1, Ordering::SeqCst);
            self.calls.lock().unwrap().push("repath");
            if self.repath_fails.load(Ordering::SeqCst) {
                return Err("adapter gone".into());
            }
            Ok(true)
        }

        async fn peer_unresponsive(&self) -> bool {
            self.unresponsive.load(Ordering::SeqCst)
        }

        async fn restart_response_watch(&self) {
            self.calls.lock().unwrap().push("restart_response_watch");
        }

        async fn force_handshake(&self) {
            self.calls.lock().unwrap().push("force_handshake");
        }
    }

    const ROUTE: PhysicalRoute = PhysicalRoute {
        gateway: std::net::Ipv4Addr::new(192, 0, 2, 1),
        interface: 7,
    };

    /// One look, as `check_liveness` takes it.
    async fn look(
        tunnel: &Tunnel,
        session: &mut SessionWatch,
        link: LinkState,
    ) -> Option<Liveness> {
        judge_packet_path(tunnel, session, Some(ROUTE), link, false, tunnel.now()).await
    }

    /// W1-003 / interface loss (MA-DESK-013): on a resume the window to prove
    /// the path opens, the unanswered run before the sleep is forgotten, the
    /// path is rebuilt on the route the machine woke on (once per look, and
    /// not when there is no route yet), and only then is a handshake asked
    /// for; a rebuild that fails gives the path up and asks for none.
    #[tokio::test(start_paused = true)]
    async fn a_resume_re_proves_the_path_in_order() {
        let now = Instant::now();

        // The usual resume: a route, nothing rebuilt yet this look.
        let tunnel = Tunnel::default();
        let mut session = SessionWatch {
            heartbeat_misses: 4,
            ..SessionWatch::default()
        };
        let mut rebuilt = false;
        let verdict =
            reprove_after_resume(&tunnel, &mut session, Some(ROUTE), &mut rebuilt, now).await;
        assert_eq!(verdict, Ok(()));
        assert_eq!(
            *tunnel.calls.lock().unwrap(),
            ["restart_response_watch", "repath", "force_handshake"]
        );
        assert!(rebuilt, "the look does not know it rebuilt the path");
        assert_eq!(session.verify_since, Some(now), "no window to prove it in");
        assert_eq!(
            session.heartbeat_misses, 0,
            "the outage's missed heartbeats were kept"
        );

        // The roam already rebuilt it this look: no second rebuild.
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        let mut rebuilt = true;
        let verdict =
            reprove_after_resume(&tunnel, &mut session, Some(ROUTE), &mut rebuilt, now).await;
        assert_eq!(verdict, Ok(()));
        assert_eq!(
            *tunnel.calls.lock().unwrap(),
            ["restart_response_watch", "force_handshake"]
        );
        assert_eq!(session.verify_since, Some(now));

        // No route yet (Wi-Fi still associating): nothing to rebuild on; the
        // link's return does it. The window still opens.
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        let mut rebuilt = false;
        let verdict = reprove_after_resume(&tunnel, &mut session, None, &mut rebuilt, now).await;
        assert_eq!(verdict, Ok(()));
        assert_eq!(
            *tunnel.calls.lock().unwrap(),
            ["restart_response_watch", "force_handshake"]
        );
        assert!(!rebuilt);
        assert_eq!(session.verify_since, Some(now));

        // The rebuild fails: re-dial, and no handshake is asked of the path
        // just given up.
        let tunnel = Tunnel::default();
        tunnel.repath_fails.store(true, Ordering::SeqCst);
        let mut session = SessionWatch::default();
        let mut rebuilt = false;
        let verdict =
            reprove_after_resume(&tunnel, &mut session, Some(ROUTE), &mut rebuilt, now).await;
        assert_eq!(verdict, Err("adapter gone".to_string()));
        assert_eq!(
            *tunnel.calls.lock().unwrap(),
            ["restart_response_watch", "repath"]
        );
    }

    const STALLED: Option<Liveness> = Some(Liveness::Dead(DropCause::PacketPathStalled));
    const PEER_GONE: Option<Liveness> = Some(Liveness::Dead(DropCause::HandshakeStale));
    const PATH_GONE: Option<Liveness> = Some(Liveness::Dead(DropCause::PathChanged));

    /// The stall rule is judged before the fast rule: on the look that
    /// confirms a stall, a relay that ALSO reads unresponsive does not make
    /// it a stale handshake. The cause decides the recovery — a stall is
    /// re-dialled at once, a stale handshake asks the old key first and
    /// counts toward the breaker.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_packet_path_is_judged_before_the_fast_rule() {
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        tunnel.ticks();
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);

        // The packet path stops. The first look past the stall window only
        // suspects it: the machine may have just woken (WIN3-003).
        advance(PACKET_PATH_STALL).await;
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);

        // The relay reads unresponsive too by the confirming look.
        tunnel.unresponsive.store(true, Ordering::SeqCst);
        advance(STALL_CONFIRM).await;
        assert_eq!(
            look(&tunnel, &mut session, LinkState::Online).await,
            STALLED
        );
    }

    /// Across a freeze — the machine asleep, or the process frozen with it,
    /// which `Instant` on Windows counts as time passed (WIN3-003) — the stall
    /// rule starts over: the looks either side are too far apart to confirm
    /// anything, and a packet path that runs again on waking is healthy. One
    /// that stays stopped is still caught, `STALL_CONFIRM` after the first
    /// look past the wake.
    #[tokio::test(start_paused = true)]
    async fn a_freeze_is_not_a_stall_and_a_real_one_after_it_still_is() {
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        let asleep = Duration::from_secs(3600);
        tunnel.ticks();
        advance(PACKET_PATH_STALL).await;
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);

        advance(asleep).await;
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);
        tunnel.ticks();
        advance(STALL_CONFIRM).await;
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);

        advance(asleep).await;
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);
        advance(STALL_CONFIRM).await;
        assert_eq!(
            look(&tunnel, &mut session, LinkState::Online).await,
            STALLED
        );
    }

    /// The control: with the packet path running, the same unresponsive relay
    /// IS the fast rule's — and while the machine has no route off it the
    /// fast rule is not consulted at all (REVIEW-WIN2-005).
    #[tokio::test(start_paused = true)]
    async fn a_running_packet_path_leaves_an_unresponsive_relay_to_the_fast_rule() {
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        tunnel.unresponsive.store(true, Ordering::SeqCst);
        for _ in 0..4 {
            advance(Duration::from_secs(5)).await;
            tunnel.ticks();
            assert_eq!(look(&tunnel, &mut session, LinkState::Offline).await, None);
        }
        assert_eq!(
            look(&tunnel, &mut session, LinkState::Online).await,
            PEER_GONE
        );
    }

    /// A stall beside sends the OS refuses is still the stall: the send-path
    /// rule, which sits between the two, neither rebuilds the socket nor
    /// renames the cause.
    #[tokio::test(start_paused = true)]
    async fn a_stall_wins_over_refused_sends_too() {
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        tunnel.ticks();
        *tunnel.sends.lock().unwrap() = SendHealth {
            failing_since: Some(tunnel.now()),
            failures: SEND_PATH_MIN_FAILURES,
            last_code: Some(10022),
        };
        advance(PACKET_PATH_STALL).await;
        // Not yet a stall, and the sends are broken: the one rebuild.
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);
        assert_eq!(tunnel.repaths.load(Ordering::SeqCst), 1);
        advance(STALL_CONFIRM).await;
        assert_eq!(
            look(&tunnel, &mut session, LinkState::Online).await,
            STALLED
        );
        assert_eq!(tunnel.repaths.load(Ordering::SeqCst), 1, "a second rebuild");
    }

    /// With the packet path running, refused sends are rebuilt once and,
    /// refused again on the rebuilt socket, re-dialled (interface loss).
    #[tokio::test(start_paused = true)]
    async fn refused_sends_are_rebuilt_once_then_redialled() {
        let tunnel = Tunnel::default();
        let mut session = SessionWatch::default();
        *tunnel.sends.lock().unwrap() = SendHealth {
            failing_since: Some(tunnel.now()),
            failures: SEND_PATH_MIN_FAILURES,
            last_code: Some(10051),
        };
        advance(SEND_PATH_BROKEN_AFTER).await;
        tunnel.ticks();
        assert_eq!(look(&tunnel, &mut session, LinkState::Online).await, None);
        assert_eq!(tunnel.repaths.load(Ordering::SeqCst), 1);
        assert!(
            session.verify_since.is_some(),
            "the rebuilt path is re-proven"
        );

        advance(Duration::from_secs(5)).await;
        tunnel.ticks();
        assert_eq!(
            look(&tunnel, &mut session, LinkState::Online).await,
            PATH_GONE
        );
        assert_eq!(tunnel.repaths.load(Ordering::SeqCst), 1);
    }
}
