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
//!   * the stealth transport exiting under the session (W1-005).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};
use tokio::sync::{watch, Mutex as TokioMutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, MissedTickBehavior};
use zeroize::Zeroizing;

use super::manager::{ConnectPhase, ConnectionState, MultiHopStatus, SessionLabel, VpnManager};
use super::network_events::{self, PhysicalRoute};
use super::reconnect_policy::{
    self, Action, Budget, DropCause, Liveness, Observed, ReconnectPolicy, Tick,
};
use super::xray::XrayManager;
use crate::api::attestation::DesktopAttestation;
use crate::api::client::{build_connect_request, build_multi_hop_request};
use crate::api::types::{ConnectRequest, ConnectResponse, MultiHopConnectRequest};
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::commands::killswitch;

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

/// How long `stop()` waits for the loop to finish its current step before
/// aborting it. Normally milliseconds: every caller cancels the manager's
/// epoch first, and a cancelled dial returns at its next await. But the
/// tunnel build's machine-state passes are synchronous netsh (documented at
/// 10-25 s on AV-heavy machines), and aborting the task in the middle of a
/// build would drop it without the release that hands the DNS park back. So
/// the grace outlasts a whole build (CONNECT_TIMEOUT) and abort stays a last
/// resort for a loop that is truly wedged.
const STOP_GRACE: Duration = Duration::from_secs(35);

struct LoopTask {
    shutdown: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// Auto-reconnect service
#[derive(Clone)]
pub struct AutoReconnectService {
    config: Arc<RwLock<AutoReconnectConfig>>,
    vpn_manager: Arc<VpnManager>,

    /// H-5 FIX: Store only server_id + server_name for reconnection.
    /// Fresh keys are fetched from the API on each reconnect attempt.
    last_reconnect_info: Arc<RwLock<Option<ReconnectInfo>>>,

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
}

impl AutoReconnectService {
    /// Create a new auto-reconnect service
    pub fn new(vpn_manager: Arc<VpnManager>, api: Arc<BirdoApi>) -> Self {
        Self {
            config: Arc::new(RwLock::new(AutoReconnectConfig::default())),
            vpn_manager,
            last_reconnect_info: Arc::new(RwLock::new(None)),
            api,
            app_handle: Arc::new(std::sync::RwLock::new(None)),
            task: Arc::new(TokioMutex::new(None)),
            live_loops: Arc::new(AtomicUsize::new(0)),
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

    /// Clear stored config (called on intentional disconnect)
    pub async fn clear_last_config(&self) {
        *self.last_reconnect_info.write().await = None;
    }

    /// Start the health check monitoring loop. Idempotent.
    pub async fn start(&self) -> Result<(), String> {
        let mut task = self.task.lock().await;
        if task.as_ref().is_some_and(|t| !t.handle.is_finished()) {
            return Ok(());
        }

        let cfg = self.config.read().await.clone();
        if !cfg.enabled {
            return Ok(());
        }
        let app = self.app_handle.read().ok().and_then(|guard| guard.clone());
        let transport_exits = app
            .as_ref()
            .map(|app| app.state::<XrayManager>().subscribe_exits());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
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
        };
        let live_loops = Arc::clone(&self.live_loops);
        let check_interval = Duration::from_millis(cfg.health_check_interval_ms);
        let handle = tokio::spawn(async move {
            live_loops.fetch_add(1, Ordering::SeqCst);
            worker.run(check_interval).await;
            live_loops.fetch_sub(1, Ordering::SeqCst);
        });
        *task = Some(LoopTask {
            shutdown: shutdown_tx,
            handle,
        });

        tracing::info!("Auto-reconnect service started");
        Ok(())
    }

    /// Stop the loop and WAIT for it to exit (W1-018: `stop()` used to flip a
    /// flag the loop only read between ticks, so a quick stop/start left the
    /// old loop running beside the new one).
    pub async fn stop(&self) {
        let mut task = self.task.lock().await;
        let Some(LoopTask { shutdown, handle }) = task.take() else {
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
                match self.step(wake).await {
                    Flow::Continue => break,
                    Flow::Again => wake = Wake::Tick,
                    Flow::Stop => return,
                }
            }
        }
        tracing::debug!("Auto-reconnect loop received shutdown signal");
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
        // W1-003: the socket and the endpoint host route are pinned to the
        // interface the session was built over; if the default route moved,
        // nothing of ours leaves the machine any more.
        if reconnect_policy::needs_rebind(session.pinned_route.as_ref(), route.as_ref()) {
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
            vm.force_handshake().await;
        }
        // Wi-Fi re-associates for several seconds after a resume. The window
        // to prove the path opens when there is a path to prove, so a slow
        // re-association does not read as a broken tunnel.
        if route.is_none() && session.verify_since.is_some() {
            session.verify_since = Some(now);
        }

        let Some(age) = vm.handshake_age().await else {
            // The tunnel went away under us; the next tick sees the new state.
            return Liveness::Healthy;
        };
        let mut verify_elapsed = session.verify_since.map(|t| now.duration_since(t));
        if verify_elapsed.is_some_and(|elapsed| age < elapsed) {
            session.verify_since = None;
            verify_elapsed = None;
        }
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
                // Fail closed FIRST: from here until a new tunnel is up,
                // nothing may leave on the physical NIC.
                if let Err(e) = killswitch::activate_killswitch().await {
                    tracing::warn!("Kill switch activation before teardown failed: {}", e);
                }
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
                self.give_up(error).await;
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

        vm.set_phase(ConnectPhase::Authenticating);
        let response = vm
            .run_cancellable(
                epoch,
                request_fresh_response(&self.api, &info, &device_name, client_public_key, pq_pk),
            )
            .await??;

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
        crate::commands::session::apply_relay_permit(&prepared.relay_endpoint).await;

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
            r = self.api.heartbeat(&key_id) => r,
            _ = self.shutdown.changed() => return Flow::Stop,
        };
        match result {
            Ok(resp) if !resp.valid => {
                // The server ended this VPN session: another device took the
                // slot, or the peer was reaped. The AUTH session is intact, so
                // this is `revoked`, not `session_expired` — and the owner
                // default (iOS parity, P1-parity-021) is: tear down, release
                // the block, no auto-retry.
                tracing::warn!("Heartbeat: the server ended this VPN session (revoked)");
                self.give_up(reconnect_policy::revoked_error(resp.message.as_deref()))
                    .await;
                *self.last_reconnect_info.write().await = None;
                Flow::Stop
            }
            Ok(resp) if !resp.server_online => {
                tracing::warn!("Heartbeat: server going offline");
                Flow::Continue
            }
            Ok(_) => {
                tracing::debug!("Heartbeat sent");
                Flow::Continue
            }
            Err(e) => {
                tracing::debug!("Heartbeat failed: {}", e);
                Flow::Continue
            }
        }
    }

    /// End recovery in `Error`. Always-on keeps the block engaged (the user
    /// asked for exactly that) except for a revocation; otherwise the block is
    /// released so a session that is over cannot hold the machine offline.
    async fn give_up(&mut self, error: IpcError) {
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
        if vm.holds_tunnel().await {
            let _ = vm.disconnect_to(ConnectionState::Error(error)).await;
        } else {
            let _ = vm.set_state(ConnectionState::Error(error)).await;
        }
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
    if !response.success {
        return Err(IpcError::connect_refused(
            response.message.as_deref().unwrap_or("Connection failed"),
        ));
    }
    Ok(response)
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
