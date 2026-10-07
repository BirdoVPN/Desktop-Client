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
//!   * the tunnel's own packet path still running (WIN-FIX-3).
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
use zeroize::Zeroizing;

use super::manager::{
    ConnectPhase, ConnectionState, GaveUp, MultiHopStatus, SessionLabel, VpnManager,
};
use super::network_events::{self, PhysicalRoute};
use super::reconnect_policy::{
    self, Action, Budget, DropCause, HeartbeatVerdict, LinkState, Liveness, LocalLink, Observed,
    ReconnectPolicy, Tick,
};
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
        }
    }
}

/// FIX-2-13: the control-plane heartbeat that lets the backend reap orphaned
/// keys. It is no longer a liveness signal (the handshake age is), but its
/// `valid:false` answer is how a revocation arrives.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

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

/// How many health-check intervals the loop may go without checking in, when
/// it has not announced a longer step, before the watchdog restarts it.
const WATCHDOG_TICKS: u32 = 6;

/// What a teardown (or a give-up) may take before the watchdog acts: the
/// operation lock (30 s), the tunnel stop (15 s), the state writes and the
/// old-key probe, with room to spare.
const TEARDOWN_ALLOWANCE: Duration = Duration::from_secs(90);

/// What a re-dial may take after its backoff: the DNS flush (5 s),
/// [`REDIAL_API_TIMEOUT`], the stealth helper's start, and `connect` (the
/// operation lock, 30 s, then `CONNECT_TIMEOUT`, 30 s), with room to spare.
const DIAL_ALLOWANCE: Duration = Duration::from_secs(150);

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
    fn renew(&self, generation: u64, allowance: Duration) -> bool {
        let mut beat = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match beat.as_mut() {
            Some(b) if b.generation == generation => {
                b.at = Instant::now();
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
        *self.last_reconnect_info.write().await = Some(info);
    }

    /// The session on record: what `reapply_vpn_settings` rebuilds, and what a
    /// failed switch reverts to. None when there is no session.
    pub async fn current_info(&self) -> Option<ReconnectInfo> {
        self.last_reconnect_info.read().await.clone()
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
        let app = self.app_handle.read().ok().and_then(|guard| guard.clone());
        let transport_exits = app
            .as_ref()
            .map(|app| app.state::<XrayManager>().subscribe_exits());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        static GENERATIONS: AtomicU64 = AtomicU64::new(0);
        let generation = GENERATIONS.fetch_add(1, Ordering::SeqCst) + 1;
        let worker = ReconnectLoop {
            vpn_manager: Arc::clone(&self.vpn_manager),
            last_reconnect_info: Arc::clone(&self.last_reconnect_info),
            api: Arc::clone(&self.api),
            app,
            shutdown: shutdown_rx,
            network: network_events::subscribe(),
            transport_exits,
            policy: ReconnectPolicy::new(cfg.budget()),
            session: SessionWatch::default(),
            quota_notice: self.quota_notice.clone(),
            alive: None,
            pulse: self.pulse.clone(),
            generation,
            step_allowance: check_interval * WATCHDOG_TICKS,
        };
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
                    let now = Instant::now();
                    clock.look(now, period);
                    let Some(beat) = svc.pulse.read() else {
                        continue;
                    };
                    let silent_for = clock.silent_for(beat.at, now);
                    if !overdue(silent_for, beat.allowance) {
                        continue;
                    }
                    // The restart gets a whole allowance before the next
                    // verdict — unless the loop has ended meanwhile.
                    if !svc.pulse.renew(beat.generation, beat.allowance) {
                        continue;
                    }
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
    heartbeat_misses: u32,
    /// The send-path rule's one rebuild per episode (interface loss).
    #[cfg(target_os = "windows")]
    send_repair: reconnect_policy::SendPathRepair,
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
#[cfg(target_os = "windows")]
async fn rebuild_path(
    vm: &VpnManager,
    session: &mut SessionWatch,
    path: PhysicalRoute,
    now: Instant,
) -> Result<(), String> {
    session.send_repair.rebuilt(now);
    session.verify_since = Some(now);
    vm.repath(path).await.map(|_| ())
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

        let liveness = if observed == Observed::Connected {
            self.check_liveness(&wake, route, now).await
        } else {
            self.session = SessionWatch::default();
            Liveness::Healthy
        };
        let tick = Tick {
            now,
            observed,
            holds_tunnel: observed == Observed::NotConnected && vm.holds_tunnel().await,
            liveness,
            connectivity: network_events::connectivity_of(route.as_ref()),
            upgrade_blocked: crate::api::upgrade_gate::is_blocked(),
            has_target: self.last_reconnect_info.read().await.is_some(),
        };
        let action = self.policy.decide(&tick);
        self.execute(action, now).await
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
            session.verify_since = Some(now);
            // What went unanswered before the sleep says nothing about the
            // path the machine woke on.
            #[cfg(target_os = "windows")]
            vm.restart_response_watch().await;
            // Interface loss: the adapter may have been powered down with the
            // machine, taking our routes and the socket's path with it.
            // Rebuild on the route it woke on; with none yet, the link's
            // return does it.
            #[cfg(target_os = "windows")]
            if let (Some(path), false) = (route, rebuilt) {
                tracing::info!("Resumed — rebuilding the tunnel's path to the relay");
                rebuilt = true;
                if let Err(e) = rebuild_path(&vm, session, path, now).await {
                    tracing::warn!(
                        "Rebuilding the path to the relay failed ({}) — re-dialling",
                        e
                    );
                    return Liveness::Dead(DropCause::PathChanged);
                }
            }
            vm.force_handshake().await;
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
                if let Err(e) = rebuild_path(&vm, session, path, now).await {
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
        if reconnect_policy::heartbeat_reprove(
            session.heartbeat_misses,
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

        // WIN-FIX-3 P0: the packet path itself stopped running. Nothing it
        // carries gets through, the relay's answers included, and boringtun's
        // retransmits (what the fast rule below counts) stop with it — the
        // T5 hang sat here, Protected, until the 180 s backstop. Judged over
        // two looks, so a sleep the machine just woke from is not one
        // (WIN3-003).
        #[cfg(target_os = "windows")]
        if session
            .stall
            .observe(vm.packet_path_progress().await, Instant::now())
        {
            tracing::warn!("The tunnel's packet path stopped running — declaring the tunnel dead");
            return Liveness::Dead(DropCause::PacketPathStalled);
        }

        // Interface loss (2026-10-07): the OS refuses our sends for a path
        // reason (WSAEINVAL, WSAENETUNREACH, …) and keeps refusing them. The
        // rules around this one read the relay's side, and a relay with
        // traffic for us keeps initiating handshakes that reach us, so they
        // all read healthy while nothing left. Rebuild the socket on the
        // current path once; refused again, re-dial.
        #[cfg(target_os = "windows")]
        if !rebuilt {
            let health = vm.send_health().await.unwrap_or_default();
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
                        return Liveness::Dead(DropCause::PathChanged);
                    };
                    if let Err(e) = rebuild_path(&vm, session, path, now).await {
                        tracing::warn!(
                            "Rebuilding the path to the relay failed ({}) — re-dialling",
                            e
                        );
                        return Liveness::Dead(DropCause::PathChanged);
                    }
                }
                reconnect_policy::SendPathVerdict::Escalate => {
                    tracing::warn!(
                        "Sends to the relay are still refused on the rebuilt socket — declaring \
                         the tunnel dead"
                    );
                    return Liveness::Dead(DropCause::PathChanged);
                }
            }
        }

        // The fast dead-path rule: with the relay unreachable the tunnel
        // stops carrying traffic at once, and waiting for the 180 s
        // handshake-age backstop left the app saying Protected for minutes.
        #[cfg(target_os = "windows")]
        if link != LinkState::Offline && vm.peer_unresponsive().await {
            tracing::warn!(
                "The relay stopped answering handshakes while traffic is waiting — declaring \
                 the tunnel dead"
            );
            return Liveness::Dead(DropCause::HandshakeStale);
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
                Flow::Continue
            }
            Action::TearDown { cause } => {
                tracing::warn!(
                    "Tunnel declared dead ({cause:?}) — tearing it down before recovering"
                );
                self.check_in(TEARDOWN_ALLOWANCE);
                // Fail closed FIRST: from here until a new tunnel is up,
                // nothing may leave on the physical NIC.
                if let Err(e) = killswitch::activate_killswitch().await {
                    tracing::warn!("Kill switch activation before teardown failed: {}", e);
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
            let error = IpcError::new(
                IpcErrorCode::KillswitchFailed,
                "The kill switch could not block traffic while reconnecting.",
            );
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
        match self.redial(vm.current_epoch()).await {
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
        // FIX-1-1: a fresh client-side keypair for every re-dial. Zeroizing
        // until it is moved into the config, so no error path frees it
        // un-wiped (AR-1).
        let (private_key, client_public_key) = crate::commands::vpn::generate_wireguard_keypair();
        let mut private_key = Zeroizing::new(private_key);
        let pq_pk = if info.quantum_protection {
            Some(
                crate::vpn::birdo_pq::get_client_public_key_b64().ok_or_else(|| {
                    IpcError::new(
                        IpcErrorCode::PqFailed,
                        "Post-quantum engine unavailable during reconnect; refusing a downgrade.",
                    )
                })?,
            )
        } else {
            None
        };

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
                fallback_reason: info.fallback_reason.as_deref(),
                custom_dns: info.custom_dns.clone(),
                custom_mtu: info.custom_mtu,
                custom_port: &info.custom_port,
            },
            &mut private_key,
        )
        .await?;
        // The block `dial` engaged is rebuilt around this relay before the
        // handshake (REVIEW-WIN2-001: in lockdown it used to keep naming the
        // relay of the session that died).
        crate::commands::session::apply_relay_permit(
            &prepared.relay_endpoint,
            prepared.started_stealth,
            false,
        )
        .await;

        vm.set_phase(ConnectPhase::Handshaking);
        vm.connect(
            prepared.config,
            info.label(),
            info.local_network_sharing,
            epoch,
        )
        .await
    }

    async fn heartbeat(&mut self, now: Instant) -> Flow {
        let Some(since) = self.session.last_heartbeat.or(self.session.connected_since) else {
            return Flow::Continue;
        };
        if now.duration_since(since) < HEARTBEAT_INTERVAL {
            return Flow::Continue;
        }
        self.session.last_heartbeat = Some(now);
        let Some(key_id) = self.vpn_manager.get_key_id().await else {
            return Flow::Continue;
        };
        let result = tokio::select! {
            r = timeout(HEARTBEAT_TIMEOUT, self.api.heartbeat(&key_id)) => r,
            _ = self.shutdown.changed() => return Flow::Stop,
        };
        let resp = match result {
            Ok(Ok(resp)) => resp,
            // Visible, not debug: the server reaps a session it has not heard
            // from for 5 minutes, so heartbeats failing in a row end in an
            // outage, and the log must say why (live retest 2026-10-02).
            Ok(Err(e)) => {
                tracing::warn!("Heartbeat failed: {}", heartbeat_failure(&e));
                // An HTTP status crossed the tunnel to arrive; only a failure
                // on the network itself says the tunnel may carry nothing.
                self.session.heartbeat_misses = if heartbeat_missed_the_network(&e) {
                    self.session.heartbeat_misses.saturating_add(1)
                } else {
                    0
                };
                return Flow::Continue;
            }
            Err(_) => {
                // A heartbeat that rides a dead tunnel never answers; the
                // liveness rules, not this, decide that the tunnel is dead —
                // a run of these only asks the tunnel to prove itself
                // (`reconnect_policy::heartbeat_reprove`).
                tracing::warn!("Heartbeat unanswered after {:?}", HEARTBEAT_TIMEOUT);
                self.session.heartbeat_misses = self.session.heartbeat_misses.saturating_add(1);
                return Flow::Continue;
            }
        };
        self.session.heartbeat_misses = 0;
        if resp.valid {
            self.alive = Some((now, network_events::resume_count()));
        }
        match reconnect_policy::heartbeat_verdict(&resp) {
            HeartbeatVerdict::End(error) => {
                // The server ended this VPN session: another device took the
                // slot, the peer was reaped (`revoked`), or the Free allowance
                // ran out after its grace window (`quota_exceeded`, birdo-web
                // #590; the peer is already gone). The AUTH session is intact,
                // so this is not `session_expired`, and the owner default (iOS
                // parity, P1-parity-021) is: tear down, release the block, no
                // auto-retry.
                tracing::warn!(
                    "Heartbeat: the server ended this VPN session ({:?})",
                    error.code
                );
                self.end_by_server(error).await
            }
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
                Flow::Continue
            }
            HeartbeatVerdict::ServerGoingOffline => {
                tracing::warn!("Heartbeat: server going offline");
                Flow::Continue
            }
            HeartbeatVerdict::Fine => {
                tracing::debug!("Heartbeat sent");
                Flow::Continue
            }
        }
    }

    /// The server ended the session (a heartbeat said so, or the old key's
    /// answer after a teardown). Not a give-up: the UI words it by its code,
    /// not as "stopped reconnecting". The owner default (iOS parity,
    /// P1-parity-021): tear down, release the block, no auto-retry.
    async fn end_by_server(&mut self, error: IpcError) -> Flow {
        self.give_up(error, None).await;
        *self.last_reconnect_info.write().await = None;
        self.quota_notice.reset();
        Flow::Stop
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
        let ending = reconnect_policy::after_teardown(reply.as_ref().ok(), alive);
        // One line either way, with no identifiers (the node-agent privacy
        // convention), so a re-dial after a takeover can be told apart from
        // a probe that never got its answer (Android logs the same).
        let answer = match &reply {
            Ok(r) if r.valid => "valid",
            Ok(r) => r.reason.as_deref().unwrap_or("invalid, no reason"),
            Err(why) => why,
        };
        let outcome = if ending.is_some() {
            "end the session"
        } else {
            "re-dial"
        };
        tracing::info!("Old-key probe: {answer} (recently alive: {alive}) -> {outcome}");
        ending
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
        return Err(IpcError::connect_refused(
            response.message.as_deref().unwrap_or("Connection failed"),
            response.quota_exceeded,
        ));
    }
    Ok(response)
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
/// had to cross the tunnel to arrive.
fn heartbeat_missed_the_network(e: &crate::api::ApiError) -> bool {
    matches!(e, crate::api::ApiError::Network(_))
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
        E::RateLimited => "HTTP 429".into(),
        E::UpgradeRequired(_) => "HTTP 426".into(),
        E::ServerError(status) | E::Rejected { status, .. } => format!("HTTP {status}"),
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

        let record = svc.last_reconnect_info.write().await;
        wait_until("a restart", || svc.restarts.load(Ordering::SeqCst) >= 1).await;
        assert!(svc.live_loops() <= 1, "the stalled loop was not stopped");
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
        pulse.beat(7, Duration::from_secs(30));
        assert!(pulse.renew(7, Duration::from_secs(30)));
        assert!(
            !pulse.renew(8, Duration::from_secs(30)),
            "another loop's beat"
        );
        pulse.clear(7);
        assert!(!pulse.renew(7, Duration::from_secs(30)));
        assert!(pulse.read().is_none(), "a cleared pulse was re-beaten");
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
        assert!(REDIAL_API_TIMEOUT + Duration::from_secs(60 + 5) < DIAL_ALLOWANCE);
        assert!(Duration::from_secs(30 + 15 + 5) + OLD_KEY_PROBE_TIMEOUT < TEARDOWN_ALLOWANCE);
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

    /// WIN-FIX-3: every network call the loop makes is capped, and a stalled
    /// packet path is judged before the fast rule (which cannot fire once
    /// the retransmits it counts have stopped with it).
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

        let liveness = body("async fn check_liveness(");
        let stall = liveness
            .find("ifsession.stall.observe(vm.packet_path_progress().await,Instant::now()){")
            .expect("the stall rule");
        let fast = liveness
            .find("vm.peer_unresponsive().await")
            .expect("the fast rule");
        assert!(stall < fast);
        assert!(liveness[stall..fast].contains("Liveness::Dead(DropCause::PacketPathStalled)"));
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
            "rebuild_path(&vm, session, path, now).await",
            "vm.force_handshake().await;",
            "if link != LinkState::Offline && vm.peer_unresponsive().await {",
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
    /// like the link's return does; the send-path rule sits between the stall
    /// rule and the fast rule, rebuilds once and re-dials when that did not
    /// help; and a re-prove window is judged by the relay's answer to OUR
    /// initiation, not by boringtun's age.
    #[test]
    fn a_path_the_os_refuses_is_rebuilt_then_redialled() {
        let source = include_str!("auto_reconnect.rs").replace('\r', "");
        let start = source.find("async fn check_liveness(").unwrap();
        let body = &source[start..];
        let body = &body[..body.find("\n    }\n").unwrap()];

        let resume = &body[body.find("if resumes != session.resumes_seen {").unwrap()..];
        let resume = &resume[..resume.find("vm.force_handshake().await;").unwrap()];
        assert!(resume.contains("rebuild_path(&vm, session, path, now).await"));

        let mut last = 0;
        for needle in [
            "Liveness::Dead(DropCause::PacketPathStalled)",
            "vm.send_health().await",
            "super::wireguard_new::send_path_broken(&health, now)",
            ".observe(broken, link == LinkState::Offline, now)",
            "reconnect_policy::SendPathVerdict::Rebuild => {",
            "rebuild_path(&vm, session, path, now).await",
            "reconnect_policy::SendPathVerdict::Escalate => {",
            "return Liveness::Dead(DropCause::PathChanged);",
            "vm.peer_unresponsive().await",
            "let proof_age = vm.proof_age().await.unwrap_or(age);",
            "proof_age < elapsed",
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
            "vm.repath(path).await",
        ] {
            assert!(helper.contains(step), "rebuild_path lost `{step}`");
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
        assert!(heartbeat.contains("ifheartbeat_missed_the_network(&e){"));
        assert!(heartbeat.contains(
            "self.session.heartbeat_misses=self.session.heartbeat_misses.saturating_add(1);"
        ));
        assert!(heartbeat.contains("self.session.heartbeat_misses=0;ifresp.valid{"));
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
        let ended = &source[source.find("HeartbeatVerdict::End(error) => {").unwrap()..];
        let ended = &ended[..ended.find("HeartbeatVerdict::QuotaGrace").unwrap()];
        assert!(ended.contains("self.end_by_server(error).await"), "{ended}");
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
        assert!(probe.contains("reconnect_policy::after_teardown("));
        assert_eq!(OLD_KEY_PROBE_TIMEOUT, Duration::from_secs(5));
        let fresh = &source[source.find("fn api_after_teardown(&self)").unwrap()..];
        assert!(fresh[..fresh.find("\n    }").unwrap()]
            .contains("self.api.on_fresh_connections(local)"));
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
}
