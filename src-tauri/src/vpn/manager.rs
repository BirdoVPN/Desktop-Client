//! VPN Manager
//!
//! High-level VPN connection management with deadlock prevention (SM-002).
//!
//! # Security Notes
//! - Uses timeout-based lock acquisition to prevent deadlocks
//! - State transitions are validated to prevent illegal states
//! - Operation lock prevents concurrent connect/disconnect races
//!
//! # The state choke point (IPC contract v2, §1)
//! Every write of [`ConnectionState`] goes through `write_state_with`, which
//! PUBLISHES the new status: it recomputes the derived fields
//! (`kill_switch_blocking`, the phase), bumps `seq` when anything the UI can
//! see changed, and wakes the `vpn-status-changed` emitter (`main.rs`), which
//! also drives the tray. The UI therefore learns about a drop, a reconnect or a
//! give-up without polling and without any window being open (W1-023).
//!
//! # Cancellation (W1-021)
//! A connect attempt carries the EPOCH it started under. `begin_attempt` (a
//! newer user connect) and `cancel_in_flight` (disconnect, logout, exit, session
//! expiry) bump it, and an attempt whose epoch is no longer current stops at its
//! next await — including mid-tunnel-build, where it unwinds exactly like the
//! CONNECT_TIMEOUT path already does.
//!
//! ## How long "its next await" can be (REVIEW-WIN-013)
//! Usually well under a second, but the tunnel build also has SYNCHRONOUS
//! steps, and neither the cancellation `select!` in `connect` nor
//! `CONNECT_TIMEOUT` can fire during one: the Wintun adapter open/create, the
//! route installs (inside `block_in_place`, run to completion on purpose: an
//! added route must be recorded, I10), the DNS guard and the tunnel DNS. On
//! the native-API path each takes milliseconds. Where a native call fails and
//! the `route.exe` / `netsh` fallback runs instead, one such call has been
//! measured at 10-25 s on AV-heavy machines, and a cancel waits for it.
//!
//! What the user sees: `end_session` cancels, then its `disconnect()` queues
//! on the operation lock the build holds. That wait is capped by
//! `OPERATION_LOCK_TIMEOUT` (30 s); past it the session is ended and
//! published as `disconnected` anyway, and the build, when its step returns,
//! finds its epoch superseded and tears its own tunnel down. A switch adds the
//! backend notify for the old session in front (capped at 3 s). So a
//! Disconnect during a connect lands in about a second on the native path,
//! after the current synchronous step otherwise, and in no case later than
//! about 35 s.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{watch, Mutex as TokioMutex, MutexGuard, RwLock};
use tokio::time::timeout;

// Platform-specific tunnel implementation
#[cfg(target_os = "windows")]
use super::tunnel::WintunTunnel as PlatformTunnel;
#[cfg(target_os = "linux")]
use super::tunnel_linux::LinuxTunnel as PlatformTunnel;
#[cfg(target_os = "macos")]
use super::tunnel_macos::UtunTunnel as PlatformTunnel;

use crate::api::types::VpnConfig;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};

/// SM-002: Timeout for state lock acquisition to prevent deadlocks
const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// SM-002: Timeout for operation lock to prevent concurrent operations hanging
const OPERATION_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// CONNECT-FIX: Maximum time allowed for the entire connect operation
/// If tunnel creation + start exceeds this, we force-fail to prevent hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The connection state. Every variant is set by some path (W1-034 removed the
/// three that nothing ever wrote: Authenticating, StealthConnecting and
/// KillSwitchActive — their detail now lives in [`ConnectPhase`] and in
/// `kill_switch_blocking`).
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    /// Auto-reconnect is recovering a session that dropped. `last_error` is the
    /// most recent failed attempt, shown beside the attempt counter.
    Reconnecting {
        attempt: u32,
        last_error: Option<IpcError>,
    },
    /// A live server switch or settings reapply is rebuilding the tunnel.
    Switching,
    Error(IpcError),
}

impl ConnectionState {
    /// Check if traffic can flow in this state
    pub fn is_tunnel_active(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Check if a new connection can be initiated
    /// STATE-FIX: Also allow connecting from Reconnecting state, which is set
    /// by auto-reconnect before calling connect(). Without this, reconnect fails silently.
    /// `Switching` is the pre-state of a live rebuild whose old tunnel is gone.
    pub fn can_connect(&self) -> bool {
        matches!(
            self,
            ConnectionState::Disconnected
                | ConnectionState::Error(_)
                | ConnectionState::Reconnecting { .. }
                | ConnectionState::Switching
        )
    }

    /// Check if disconnect is meaningful in this state
    pub fn can_disconnect(&self) -> bool {
        !matches!(
            self,
            ConnectionState::Disconnected | ConnectionState::Disconnecting
        )
    }

    /// A tunnel is being built for this state; `phase` is only meaningful here.
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            ConnectionState::Connecting
                | ConnectionState::Reconnecting { .. }
                | ConnectionState::Switching
        )
    }

    /// The `state` string of the IPC contract.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "disconnected",
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Disconnecting => "disconnecting",
            ConnectionState::Reconnecting { .. } => "reconnecting",
            ConnectionState::Switching => "switching",
            ConnectionState::Error(_) => "error",
        }
    }
}

/// Optional detail while connecting / reconnecting / switching (contract §1).
///
/// The contract's `configuring` is never emitted: route and DNS setup happen
/// inside the tunnel build, after the handshake, with no point at which the
/// manager could report them separately. `phase` is optional detail, so the
/// build reads as `handshaking` until it finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectPhase {
    Authenticating,
    NegotiatingPq,
    StartingStealth,
    Handshaking,
}

/// The confirmed Multi-Hop route of the live session (contract §1 `multiHop`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHopStatus {
    pub entry_id: String,
    pub entry_name: String,
    pub exit_id: String,
    pub exit_name: String,
}

/// Auto-reconnect gave up (contract §1 `gaveUp`, REVIEW-WIN-009).
///
/// Set only on the `error` status that ENDS a recovery — the budget spent, the
/// circuit breaker, a hard refusal — and cleared with that state. The UI used
/// to infer a give-up from seeing `reconnecting` turn into `error`, but the
/// emitter publishes the latest snapshot behind a `watch`, so a breaker trip
/// (TearDown and GiveUp back to back) can reach it as `connected → error`: no
/// "stopped reconnecting" copy, and a generic error notification instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GaveUp {
    /// Re-dials spent in the episode that gave up (0 for a breaker trip,
    /// which gives up before dialling).
    pub attempts: u32,
}

/// What a session is on, published together with the Connected state so a
/// status can never show one server's state with another's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLabel {
    pub server_name: String,
    /// The server the tunnel is on — for Multi-Hop, the EXIT.
    pub server_id: String,
    pub multi_hop: Option<MultiHopStatus>,
}

/// The state part of `VpnStatus`, as last published. Read as ONE snapshot so
/// a status can never pair a new state with an old `seq` (or the reverse),
/// which is what let a stale poll flip the UI back (W2-009).
#[derive(Debug, Clone, PartialEq)]
pub struct PublishedStatus {
    pub seq: u64,
    pub state: ConnectionState,
    pub phase: Option<ConnectPhase>,
    pub reconnect_max: Option<u32>,
    pub kill_switch_blocking: bool,
    pub server_id: Option<String>,
    pub multi_hop: Option<MultiHopStatus>,
    pub gave_up: Option<GaveUp>,
}

/// The kill-switch facts `kill_switch_blocking` is derived from. A function
/// pointer rather than direct calls so unit tests are not at the mercy of the
/// process-global WFP flags other tests toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockProbe {
    /// The platform block-all is engaged (WFP / pf / iptables).
    pub blocking: bool,
    /// The block stays up for a healthy session and the tunnel interface is
    /// permitted through it (Windows lockdown; macOS/Linux whenever armed).
    pub holds_block_while_connected: bool,
}

fn platform_block_probe() -> BlockProbe {
    BlockProbe {
        blocking: crate::commands::killswitch::platform_is_blocking(),
        holds_block_while_connected: crate::commands::killswitch::holds_block_while_connected(),
    }
}

/// `kill_switch_blocking` (contract §1): the block-all is engaged AND traffic
/// cannot flow through a tunnel. A healthy Connected session never qualifies
/// (lockdown carries its traffic through the tunnel-interface permit), and
/// neither does a switch whose OLD tunnel is still up under a block that
/// permits it. Everything else with the block engaged — reconnecting, a
/// failed switch, the lockdown give-up, always-on with no tunnel — does.
pub fn kill_switch_blocking(
    probe: BlockProbe,
    state: &ConnectionState,
    tunnel_present: bool,
) -> bool {
    if !probe.blocking {
        return false;
    }
    let tunnel_carries_traffic = match state {
        ConnectionState::Connected => true,
        ConnectionState::Switching => tunnel_present && probe.holds_block_while_connected,
        _ => false,
    };
    !tunnel_carries_traffic
}

struct StatusBus {
    published: std::sync::Mutex<PublishedStatus>,
    tx: watch::Sender<u64>,
    probe: fn() -> BlockProbe,
    /// Mirrors `VpnManager::tunnel.is_some()` for the synchronous derivation
    /// of `kill_switch_blocking` (the Option itself sits behind an async lock).
    tunnel_present: AtomicBool,
}

impl StatusBus {
    fn new(probe: fn() -> BlockProbe) -> Self {
        let (tx, _rx) = watch::channel(0);
        Self {
            published: std::sync::Mutex::new(PublishedStatus {
                seq: 0,
                state: ConnectionState::Disconnected,
                phase: None,
                reconnect_max: None,
                kill_switch_blocking: false,
                server_id: None,
                multi_hop: None,
                gave_up: None,
            }),
            tx,
            probe,
            tunnel_present: AtomicBool::new(false),
        }
    }

    /// Apply `f`, re-derive, and bump `seq` iff anything visible changed.
    fn publish(&self, f: impl FnOnce(&mut PublishedStatus)) {
        let probe = (self.probe)();
        let tunnel_present = self.tunnel_present.load(AtomicOrdering::SeqCst);
        let mut p = self.published.lock().unwrap_or_else(|e| e.into_inner());
        let before = p.clone();
        f(&mut p);
        if !p.state.is_in_progress() {
            p.phase = None;
        }
        if !matches!(p.state, ConnectionState::Reconnecting { .. }) {
            p.reconnect_max = None;
        }
        if !matches!(p.state, ConnectionState::Error(_)) {
            p.gave_up = None;
        }
        p.kill_switch_blocking = kill_switch_blocking(probe, &p.state, tunnel_present);
        p.seq = before.seq;
        if *p != before {
            p.seq = before.seq.wrapping_add(1);
            self.tx.send_replace(p.seq);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Last MEASURED round-trip latency, ms. `None` until a real probe has run
    /// this session — consumers must treat `None` as "unmeasured", never as 0.
    pub latency_ms: Option<u32>,
    // P6-CLI-X-01: the `latency_samples` ring buffer is GONE. Its only reader
    // was `jitter_ms()`, whose only reader was the 60-second quality report, so
    // once that went it was a 20-entry buffer being maintained for nobody.
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    pub server_id: Option<String>,
    pub key_id: Option<String>,
    pub server_name: Option<String>,
}

impl ConnectionStats {
    fn empty() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            latency_ms: None,
            connected_at: None,
            server_id: None,
            key_id: None,
            server_name: None,
        }
    }

    // P6-CLI-X-01: `jitter_ms()` is GONE. Jitter was computed for one consumer
    // only — the 60-second quality report — and nothing else ever read it.

    // P1-dk-fabricated-quality-telemetry: `packet_loss_percent()` (TX packet
    // delta vs RX packet delta) and its `prev_packets_*` snapshot machinery were
    // removed. The two directions are independent counters, so a normal
    // upload-heavy minute reported a large invented "loss" — the quality report
    // now derives loss from probe outcomes in auto_reconnect.rs instead.

    // P6-CLI-X-01: `push_latency_sample()` is GONE with `latency_samples`.
}

#[derive(Clone)]
pub struct VpnManager {
    state: Arc<RwLock<ConnectionState>>,
    pub(crate) stats: Arc<RwLock<ConnectionStats>>,
    tunnel: Arc<RwLock<Option<PlatformTunnel>>>,
    current_config: Arc<RwLock<Option<VpnConfig>>>,
    /// SM-002: Operation lock to prevent concurrent connect/disconnect
    /// Only one connect or disconnect operation can run at a time
    operation_lock: Arc<TokioMutex<()>>,
    status: Arc<StatusBus>,
    /// W1-021: the cancellation epoch. See the module docs.
    epoch: Arc<watch::Sender<u64>>,
    /// Serialises a connect's COMMIT (arm the kill switch, start
    /// auto-reconnect) against `end_session`, so a disconnect that lands while
    /// a tunnel is coming up can never be followed by an `arm()` that
    /// re-installs a block nobody will remove.
    commit_lock: Arc<TokioMutex<()>>,
}

/// SM-002: Error type for VPN operations
#[derive(Debug, Clone)]
pub enum VpnError {
    /// Lock acquisition timed out - possible deadlock
    LockTimeout(String),
    /// Invalid state transition attempted
    InvalidStateTransition { from: String, to: String },
    /// Operation already in progress
    OperationInProgress,
}

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnError::LockTimeout(msg) => write!(f, "Lock timeout: {}", msg),
            VpnError::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {} to {}", from, to)
            }
            VpnError::OperationInProgress => write!(f, "Another operation is already in progress"),
        }
    }
}

impl std::error::Error for VpnError {}

impl VpnManager {
    /// Release the machine state's DNS side synchronously, for exit paths that
    /// cannot await.
    ///
    /// WHY THIS EXISTS. Two exits cannot run the async teardown:
    ///   * `RunEvent::ExitRequested` with `RESTART_EXIT_CODE` (a
    ///     `plugin-process` relaunch) returns before `teardown_for_exit`,
    ///     because a restart cannot be held open — `prevent_exit()` is a
    ///     documented no-op for it;
    ///   * the Windows updater's `on_before_exit` hook, which runs immediately
    ///     before the plugin calls `std::process::exit(0)` (W1-004).
    ///
    /// `install_update` now performs the full `end_session` teardown BEFORE it
    /// installs, so on the normal update path this finds nothing held; it is
    /// the backstop for a teardown that timed out. Nothing the current build
    /// does to DNS outlives the process (the DNS guard is a dynamic WFP
    /// filter), but an adapter an OLDER build parked and this process adopted
    /// gets one more restore attempt here.
    ///
    /// Goes straight to the machine-state owner rather than through
    /// `self.tunnel`: a reconnect empties that Option for the whole create +
    /// handshake window, so an exit landing in that window would find `None`.
    ///
    /// Synchronous and lock-free of any async lock, so it can never wedge an
    /// exit that must not be held open.
    #[cfg(target_os = "windows")]
    pub fn restore_dns_blocking(&self) -> bool {
        crate::vpn::win_machine_state::release_dns_at_exit()
    }

    /// Create a new VPN manager
    pub fn new() -> Self {
        Self::with_block_probe(platform_block_probe)
    }

    /// A manager whose `kill_switch_blocking` derivation reads `probe`
    /// instead of the process-global firewall flags. Production uses
    /// [`VpnManager::new`]; tests pin the probe to stay deterministic.
    pub fn with_block_probe(probe: fn() -> BlockProbe) -> Self {
        let (epoch, _rx) = watch::channel(0u64);
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(ConnectionStats::empty())),
            tunnel: Arc::new(RwLock::new(None)),
            current_config: Arc::new(RwLock::new(None)),
            operation_lock: Arc::new(TokioMutex::new(())),
            status: Arc::new(StatusBus::new(probe)),
            epoch: Arc::new(epoch),
            commit_lock: Arc::new(TokioMutex::new(())),
        }
    }

    // ── Status publication ──────────────────────────────────────────────

    /// The last published status. See [`PublishedStatus`].
    pub fn published(&self) -> PublishedStatus {
        self.status
            .published
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Wakes on every `seq` bump. The emitter in `main.rs` is the consumer.
    pub fn subscribe_status(&self) -> watch::Receiver<u64> {
        self.status.tx.subscribe()
    }

    /// Re-derive the published status after something OUTSIDE the state
    /// changed — the kill switch engaging or releasing (contract §1: emit when
    /// `kill_switch_blocking` changes without a state change). Wired to
    /// `killswitch::set_blocking_observer` at startup.
    pub fn refresh_status(&self) {
        self.status.publish(|_| {});
    }

    /// Record the connect phase; ignored unless a tunnel is being built.
    pub fn set_phase(&self, phase: ConnectPhase) {
        self.status.publish(|p| p.phase = Some(phase));
    }

    fn set_tunnel_present(&self, present: bool) {
        self.status
            .tunnel_present
            .store(present, AtomicOrdering::SeqCst);
    }

    // ── Cancellation epoch ──────────────────────────────────────────────

    fn bump_epoch(&self) -> u64 {
        let mut next = 0;
        self.epoch.send_modify(|e| {
            *e = e.wrapping_add(1);
            next = *e;
        });
        next
    }

    /// Start a new USER-initiated connect: supersedes (cancels) any attempt or
    /// auto-reconnect dial still in flight, and returns this attempt's epoch.
    pub fn begin_attempt(&self) -> u64 {
        self.bump_epoch()
    }

    /// [`begin_attempt`](Self::begin_attempt) for a connect that FOLLOWS UP
    /// the attempt of epoch `of`: it begins only while that epoch is still
    /// current. `None`: something superseded it, and nothing began.
    ///
    /// WIN3-002: the settings revert reconnects after its rebuild failed, and
    /// the failure is published first — which is when the user presses
    /// Disconnect, or picks another server. Both move the epoch. A revert that
    /// took a fresh one regardless brought the tunnel and the block back
    /// after the Disconnect, or dragged the user back to the old server. The
    /// check and the bump are one step, under the commit lock at the caller.
    pub fn begin_follow_up(&self, of: u64) -> Option<u64> {
        let mut began = None;
        self.epoch.send_if_modified(|e| {
            if *e != of {
                return false;
            }
            *e = e.wrapping_add(1);
            began = Some(*e);
            true
        });
        began
    }

    /// Cancel whatever connect or re-dial is in flight (disconnect, logout,
    /// exit, session expiry). The cancelled attempt resolves with `cancelled`.
    pub fn cancel_in_flight(&self) {
        self.bump_epoch();
    }

    /// The epoch an auto-reconnect dial runs under (it does not supersede).
    pub fn current_epoch(&self) -> u64 {
        *self.epoch.borrow()
    }

    pub fn is_current(&self, epoch: u64) -> bool {
        self.current_epoch() == epoch
    }

    /// Resolves once `epoch` is no longer current.
    pub async fn cancelled(&self, epoch: u64) {
        let mut rx = self.epoch.subscribe();
        loop {
            if *rx.borrow_and_update() != epoch {
                return;
            }
            if rx.changed().await.is_err() {
                // The sender lives as long as this manager; unreachable, but
                // never report a cancellation that did not happen.
                std::future::pending::<()>().await;
            }
        }
    }

    /// Run `fut` unless `epoch` is superseded first, in which case the attempt
    /// resolves with `cancelled` and `fut` is dropped at its current await.
    pub async fn run_cancellable<F: Future>(
        &self,
        epoch: u64,
        fut: F,
    ) -> Result<F::Output, IpcError> {
        tokio::select! {
            out = fut => Ok(out),
            _ = self.cancelled(epoch) => Err(IpcError::cancelled()),
        }
    }

    /// See the `commit_lock` field.
    pub async fn lock_commit(&self) -> MutexGuard<'_, ()> {
        self.commit_lock.lock().await
    }

    /// The commit lock for a TEARDOWN (`end_session`): cancel whatever is in
    /// flight, wait for the lock, then cancel AGAIN.
    ///
    /// The first cancel interrupts an attempt that is mid-build and holds no
    /// lock. The second is the one REVIEW-WIN-003 found missing: a connect
    /// begins its attempt only once it holds this same lock, and tokio's mutex
    /// is FIFO, so a connect that queued on the lock before the teardown did
    /// acquires first and takes a FRESH epoch the first cancel never saw. Its
    /// tunnel then came up after the user's Disconnect, armed the kill switch
    /// and started auto-reconnect. Cancelling once more under the lock
    /// supersedes it at its next await.
    pub async fn lock_commit_for_teardown(&self) -> MutexGuard<'_, ()> {
        self.cancel_in_flight();
        let guard = self.commit_lock.lock().await;
        self.cancel_in_flight();
        guard
    }

    // ── State ───────────────────────────────────────────────────────────

    /// SM-002: Acquire state read lock with timeout to prevent deadlock
    async fn read_state_with_timeout(&self) -> Result<ConnectionState, VpnError> {
        match timeout(STATE_LOCK_TIMEOUT, self.state.read()).await {
            Ok(guard) => Ok(guard.clone()),
            Err(_) => {
                tracing::error!("State read lock timeout - possible deadlock");
                Err(VpnError::LockTimeout("state read lock".into()))
            }
        }
    }

    /// SM-002: Acquire state write lock with timeout to prevent deadlock.
    /// THE choke point: every state write publishes (see the module docs).
    async fn write_state_with(
        &self,
        new_state: ConnectionState,
        extra: impl FnOnce(&mut PublishedStatus),
    ) -> Result<ConnectionState, VpnError> {
        match timeout(STATE_LOCK_TIMEOUT, self.state.write()).await {
            Ok(mut guard) => {
                let old_state = std::mem::replace(&mut *guard, new_state.clone());
                tracing::debug!(
                    old_state = old_state.wire_name(),
                    new_state = new_state.wire_name(),
                    "State transition"
                );
                self.status.publish(|p| {
                    p.state = new_state;
                    extra(p);
                });
                Ok(old_state)
            }
            Err(_) => {
                tracing::error!("State write lock timeout - possible deadlock");
                Err(VpnError::LockTimeout("state write lock".into()))
            }
        }
    }

    async fn write_state_with_timeout(
        &self,
        new_state: ConnectionState,
    ) -> Result<ConnectionState, VpnError> {
        self.write_state_with(new_state, |_| {}).await
    }

    /// Get current connection state
    pub async fn get_state(&self) -> ConnectionState {
        self.read_state_with_timeout().await.unwrap_or_else(|_| {
            ConnectionState::Error(IpcError::unknown("Internal error reading the VPN state."))
        })
    }

    /// Set connection state (used by auto-reconnect to set Reconnecting state)
    pub async fn set_state(&self, new_state: ConnectionState) -> Result<(), String> {
        self.write_state_with_timeout(new_state)
            .await
            .map_err(|e| format!("Failed to set state: {}", e))?;
        Ok(())
    }

    /// Enter (or advance) `Reconnecting`, publishing the retry budget with it.
    pub async fn set_reconnecting(
        &self,
        attempt: u32,
        last_error: Option<IpcError>,
        reconnect_max: Option<u32>,
    ) {
        let _ = self
            .write_state_with(
                ConnectionState::Reconnecting {
                    attempt,
                    last_error,
                },
                |p| p.reconnect_max = reconnect_max,
            )
            .await;
    }

    /// Get current connection stats
    pub async fn get_stats(&self) -> ConnectionStats {
        match timeout(STATE_LOCK_TIMEOUT, self.stats.read()).await {
            Ok(guard) => guard.clone(),
            Err(_) => {
                tracing::error!("Stats read lock timeout");
                ConnectionStats::empty()
            }
        }
    }

    /// SM-002: Acquire operation lock with timeout
    async fn acquire_operation_lock(&self) -> Result<tokio::sync::MutexGuard<'_, ()>, VpnError> {
        match timeout(OPERATION_LOCK_TIMEOUT, self.operation_lock.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => {
                tracing::error!("Operation lock timeout - another operation may be stuck");
                Err(VpnError::OperationInProgress)
            }
        }
    }

    /// Connect to a VPN server under `epoch` (see [`VpnManager::begin_attempt`]).
    ///
    /// On failure the state is left IN PROGRESS (`Connecting`, `Switching` or
    /// `Reconnecting`) and the caller writes the outcome: a user connect ends
    /// in `Error` (or reverts a switch whose old tunnel survived), an
    /// auto-reconnect dial stays `Reconnecting` with the failure as its
    /// `last_error`. Writing `Error` here made every failed re-dial flash an
    /// error at the UI and the tray between attempts. A cancelled attempt
    /// writes nothing: whoever cancelled it owns the state.
    ///
    /// SM-002: Uses operation lock to prevent concurrent connect/disconnect
    pub async fn connect(
        &self,
        config: VpnConfig,
        label: SessionLabel,
        local_network_sharing: bool,
        epoch: u64,
    ) -> Result<(), IpcError> {
        // LOG-001: the chosen node is connection history — keep the name out
        // of the release log (info reaches birdo.log); debug is dev-only.
        tracing::info!("VpnManager::connect called");
        tracing::debug!(
            "VpnManager::connect called for server: {}",
            label.server_name
        );

        // SM-002: Acquire operation lock first to prevent concurrent operations.
        // A disconnect must not queue behind a connect it is cancelling, so the
        // wait itself is cancellable.
        let _operation_guard = tokio::select! {
            guard = self.acquire_operation_lock() => guard.map_err(|e| {
                IpcError::unknown(format!("Failed to acquire operation lock: {}", e))
            })?,
            _ = self.cancelled(epoch) => return Err(IpcError::cancelled()),
        };
        if !self.is_current(epoch) {
            return Err(IpcError::cancelled());
        }

        // Check current state with timeout
        let current_state = self
            .read_state_with_timeout()
            .await
            .map_err(|e| IpcError::unknown(format!("Failed to read state: {}", e)))?;

        tracing::debug!("Current VPN state: {}", current_state.wire_name());

        // What the UI sees while the tunnel is (re)built. A switch and a
        // re-dial keep their own label for the whole window; before this, the
        // teardown wrote Disconnecting and then Connecting, so a server switch
        // read as a disconnect followed by a fresh connect.
        let in_progress = match &current_state {
            ConnectionState::Switching => ConnectionState::Switching,
            ConnectionState::Reconnecting { .. } => current_state.clone(),
            _ => ConnectionState::Connecting,
        };

        // I2 NO ORPHANS. The teardown used to be gated on `Connected |
        // Connecting`, and `can_connect()` admits `Disconnected`, `Error`,
        // `KillSwitchActive` and `Reconnecting` — so on EVERY auto-reconnect
        // path (the only `connect()` call site there always runs with state
        // `Reconnecting{n}`) the gate never fired and the live tunnel in
        // `self.tunnel` was simply overwritten. Dropping it there ran its
        // emergency unwind against machine state a NEW tunnel had since taken
        // over: physical adapters un-parked, split-default routes deleted, IPv6
        // block lifted, UI showing Connected. That is issue #98.
        //
        // `ConnectionState` is a UI-facing claim written independently of the
        // tunnel, so it cannot be the input to a disposal decision (I3). The
        // Option is the record of tunnel existence; take it, dispose of it, and
        // do that from ANY state.
        //
        // NOT #105's "refuse to connect while `self.tunnel.is_some()`": combined
        // with `disconnect()`'s early return — `can_disconnect()` is false in
        // `Disconnected` / `Disconnecting`, so it returns Ok(()) without taking
        // the tunnel — that would turn the orphan from a leak into a permanent
        // lockout where Connect refuses, Disconnect no-ops and only quitting
        // the app recovers. The correct form is: dispose unconditionally.
        let displaced = match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
            Ok(mut guard) => guard.take(),
            Err(_) => {
                tracing::error!(
                    "Tunnel lock timeout before connect — cannot safely create a new tunnel \
                     while an old one may still be live"
                );
                return Err(IpcError::unknown(
                    "Tunnel lock timeout during teardown — please try again",
                ));
            }
        };
        if displaced.is_some() {
            self.set_tunnel_present(false);
        }

        // The machine state (the DNS guard + installed routes) is deliberately
        // NOT released between the outgoing tunnel and the incoming one. Moving
        // it to a generation the manager holds means the old tunnel's
        // stop()/Drop cannot lift or delete anything on its way out, and the
        // new tunnel ADOPTS it — so DNS cannot leave on the physical NICs during
        // the multi-second create + handshake window. Every failure arm below
        // hands this generation back with `release_machine_state_after_failed_connect`,
        // so a connect that never produces a tunnel cannot strand it.
        #[cfg(target_os = "windows")]
        let transition_gen = crate::vpn::win_machine_state::begin_transition();

        if displaced.is_some()
            || matches!(
                current_state,
                ConnectionState::Connected | ConnectionState::Connecting
            )
        {
            tracing::info!(
                "Tearing down the existing tunnel before connecting (state {}, tunnel present: \
                 {})",
                current_state.wire_name(),
                displaced.is_some()
            );
            let _ = self.write_state_with_timeout(in_progress.clone()).await;

            // LEAK-2: this is a server switch — a new tunnel is already committed.
            // Hold the IPv6 block across the teardown, otherwise the old tunnel's
            // stop() lifts it and IPv6 egresses the physical NIC for the whole
            // teardown + setup window. Released below, once the new tunnel's
            // start() is about to re-install it.
            #[cfg(target_os = "windows")]
            {
                if let Err(e) = crate::vpn::wfp::block_ipv6().await {
                    tracing::warn!("Could not block IPv6 before server switch: {}", e);
                }
                crate::vpn::wfp::hold_ipv6_block(true);
            }

            // The tunnel is already out of the Option, so the data plane is
            // disposed here and nothing can reach it again. Its stop() will find
            // that it no longer owns the machine state and will leave the DNS
            // guard and the routes exactly where they are.
            if let Some(tunnel) = displaced {
                match timeout(Duration::from_secs(10), tunnel.stop()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!("Old tunnel teardown error (continuing): {}", e);
                    }
                    Err(_) => {
                        tracing::warn!(
                            "Old tunnel teardown timed out (continuing): Tunnel stop timed out"
                        );
                    }
                }
            }

            // Release the hold in BOTH outcomes: a held block with no tunnel and no
            // connect in flight could never be lifted.
            #[cfg(target_os = "windows")]
            crate::vpn::wfp::hold_ipv6_block(false);

            // LEAK-2 (macOS/Linux): the old tunnel's stop() just lifted the F-001
            // IPv6 leak block. Windows holds the block across the teardown above;
            // Unix has no hold, so on a dual-stack network IPv6 egressed the
            // physical NIC (real address) for the whole switch window. Re-engage
            // the block NOW — before the new tunnel's multi-second create+handshake
            // — so nothing leaks during the gap. The new tunnel's start() re-owns
            // it idempotently (and lifts it only if the new node is dual-stack),
            // and every connect-failure path already lifts it via
            // lift_ipv6_block_after_failed_connect(), so it can never get stuck.
            #[cfg(target_os = "macos")]
            if let Err(e) = crate::commands::killswitch::ipv6_block_activate().await {
                tracing::warn!("Could not re-engage IPv6 block during server switch: {}", e);
            }
            #[cfg(target_os = "linux")]
            if let Err(e) = crate::vpn::tunnel_linux::install_ipv6_leak_block() {
                tracing::warn!("Could not re-engage IPv6 block during server switch: {}", e);
            }
        } else if !current_state.can_connect() {
            let err = VpnError::InvalidStateTransition {
                from: current_state.wire_name().to_string(),
                to: "connecting".into(),
            };
            tracing::warn!("{}", err);
            #[cfg(target_os = "windows")]
            self.release_machine_state_after_failed_connect(transition_gen)
                .await;
            return Err(IpcError::unknown(err.to_string()));
        }

        // Set the in-progress state with timeout
        if let Err(e) = self.write_state_with_timeout(in_progress).await {
            #[cfg(target_os = "windows")]
            self.release_machine_state_after_failed_connect(transition_gen)
                .await;
            return Err(IpcError::unknown(format!(
                "Failed to set connecting state: {}",
                e
            )));
        }

        // LOG-001: node name demoted to debug — see connect() above.
        tracing::info!("Creating VPN tunnel");
        tracing::debug!("Creating VPN tunnel for: {}", label.server_name);
        tracing::debug!(
            "Tunnel config: endpoint={}, client_ip={}",
            crate::utils::redact_endpoint(&config.endpoint),
            crate::utils::redact_ip(&config.client_ip)
        );

        // CONNECT-FIX: Wrap the entire tunnel creation + start in a timeout.
        // If tunnel creation or start hangs (e.g. netsh deadlocks on Windows
        // UAC prompt, or antivirus blocks wintun.dll), we fail fast instead of
        // leaving the state stuck at Connecting forever.
        //
        // W1-021: and race it against cancellation. A disconnect during the
        // build drops the half-built tunnel at its current await — the SAME
        // unwind the timeout performs, so it needs no new cleanup path.
        let build = timeout(CONNECT_TIMEOUT, async {
            let tunnel = PlatformTunnel::create(&config, local_network_sharing)
                .await
                .map_err(|e| format!("Failed to create tunnel: {}", e))?;
            tunnel
                .start()
                .await
                .map_err(|e| format!("Failed to start tunnel: {}", e))?;
            Ok::<PlatformTunnel, String>(tunnel)
        });
        let tunnel_result = tokio::select! {
            result = build => Some(result),
            _ = self.cancelled(epoch) => None,
        };

        match tunnel_result {
            Some(Ok(Ok(tunnel))) => {
                if !self.is_current(epoch) {
                    // Superseded in the instant the build finished: this tunnel
                    // belongs to nobody. Dispose of it here, under the operation
                    // lock, rather than hand an orphan to the next connect.
                    tracing::info!("Connect cancelled as the tunnel came up — tearing it down");
                    if let Err(e) = timeout(Duration::from_secs(10), tunnel.stop())
                        .await
                        .unwrap_or_else(|_| Err("Tunnel stop timed out".to_string()))
                    {
                        tracing::warn!("Cancelled tunnel teardown: {}", e);
                    }
                    #[cfg(target_os = "windows")]
                    self.release_machine_state_after_failed_connect(transition_gen)
                        .await;
                    self.lift_ipv6_block_after_failed_connect().await;
                    return Err(IpcError::cancelled());
                }
                tracing::info!("Tunnel started successfully");

                // P1-dk-manager-tunnel-dropped-state-connected: store the tunnel
                // BEFORE transitioning to Connected. The old order dropped a live
                // tunnel on a write-lock timeout while leaving state=Connected —
                // green UI with traffic on the physical NIC. If the store fails,
                // stop the tunnel and surface the failure instead.
                match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
                    Ok(mut guard) => *guard = Some(tunnel),
                    Err(_) => {
                        tracing::error!(
                            "Tunnel write lock timeout — stopping fresh tunnel instead of \
                             reporting Connected without one"
                        );
                        let _ = tunnel.stop().await;
                        #[cfg(target_os = "windows")]
                        self.release_machine_state_after_failed_connect(transition_gen)
                            .await;
                        return Err(IpcError::unknown("Internal error storing tunnel state"));
                    }
                }
                self.set_tunnel_present(true);

                match timeout(STATE_LOCK_TIMEOUT, self.current_config.write()).await {
                    Ok(mut guard) => {
                        // FIX-R3: Store config for reconnect metadata but scrub key material.
                        // The WireGuard session now owns copies via SensitiveKey with ZeroizeOnDrop.
                        // Auto-reconnect must request fresh keys from the backend.
                        let mut scrubbed_config = config.clone();
                        scrubbed_config.scrub_key_material();
                        *guard = Some(scrubbed_config);
                    }
                    Err(_) => tracing::error!("Config write lock timeout"),
                }

                // Stats BEFORE the Connected publication: the status the emitter
                // builds for it reads the server name from here.
                match timeout(STATE_LOCK_TIMEOUT, self.stats.write()).await {
                    Ok(mut stats) => {
                        stats.connected_at = Some(chrono::Utc::now());
                        stats.server_id = Some(config.server_id.clone());
                        stats.key_id = Some(config.key_id.clone());
                        stats.server_name = Some(label.server_name.clone());
                        stats.bytes_sent = 0;
                        stats.bytes_received = 0;
                        // Latency belongs to a PATH; a new session (possibly a
                        // different server) must not inherit the old one's
                        // measurements now that update_stats keeps them.
                        stats.latency_ms = None;
                    }
                    Err(_) => tracing::error!("Stats write lock timeout"),
                }

                let _ = self
                    .write_state_with(ConnectionState::Connected, |p| {
                        p.server_id = Some(label.server_id);
                        p.multi_hop = label.multi_hop;
                    })
                    .await;

                tracing::info!("VPN connected successfully");
                Ok(())
            }
            Some(Ok(Err(e))) => {
                // P6-CLI-D-03 (defence in depth): this is a catch-all for error
                // strings built anywhere in the tunnel stack. Individual sites redact
                // their own endpoints, but sanitising here means a future format!()
                // that forgets cannot reintroduce the leak.
                tracing::error!(
                    "Tunnel creation/start failed: {}",
                    crate::utils::redact::sanitize_error(&e)
                );
                // Release the machine state BEFORE lifting the IPv6 block, never
                // the reverse.
                #[cfg(target_os = "windows")]
                self.release_machine_state_after_failed_connect(transition_gen)
                    .await;
                self.lift_ipv6_block_after_failed_connect().await;
                Err(IpcError::from_tunnel_failure(&e))
            }
            // Timed out, or cancelled: both dropped start() mid-await along with
            // the half-built tunnel; if it had already claimed, its Drop released
            // and this is a no-op. If it never got that far, the generation held
            // across the teardown still owns the machine state.
            outcome => {
                let cancelled = outcome.is_none();
                if cancelled {
                    tracing::info!("Connect cancelled during the tunnel build");
                } else {
                    tracing::error!("Connection timed out after {}s", CONNECT_TIMEOUT.as_secs());
                }
                #[cfg(target_os = "windows")]
                self.release_machine_state_after_failed_connect(transition_gen)
                    .await;
                self.lift_ipv6_block_after_failed_connect().await;
                if cancelled {
                    Err(IpcError::cancelled())
                } else {
                    // Not transport-shaped: the handshake has its own, shorter
                    // budget, so a 30 s stall is setup (netsh, AV, the driver).
                    Err(IpcError::new(
                        IpcErrorCode::AdapterFailed,
                        format!(
                            "Setting up the VPN adapter timed out after {}s.",
                            CONNECT_TIMEOUT.as_secs()
                        ),
                    ))
                }
            }
        }
    }

    /// A connect that never produced a live tunnel must not leave the DNS guard
    /// or our routes installed either.
    ///
    /// A no-op unless `gen` is still the owner — if the new tunnel got as far as
    /// claiming and was then dropped, its own `Drop` already released, and
    /// re-releasing from here would be a second owner acting on state it does not
    /// hold. `block_in_place` because the release is synchronous (W1-017): it
    /// must not pin a runtime worker, and it must not become cancellable either.
    #[cfg(target_os = "windows")]
    async fn release_machine_state_after_failed_connect(
        &self,
        gen: crate::vpn::win_machine_state::Gen,
    ) {
        if tokio::task::block_in_place(|| crate::vpn::win_machine_state::release_all(gen)) {
            tracing::info!(
                "Restored adapter DNS left by an earlier version after a failed connect"
            );
        }
    }

    /// A connect that never produced a live tunnel must not leave IPv6 blocked
    /// (the tunnel blocks it up-front, and only a tunnel teardown lifts it).
    ///
    /// Safe on every failure path: `unblock_ipv6` is a no-op while the kill switch
    /// owns the block, so a failed RECONNECT still keeps IPv6 contained.
    async fn lift_ipv6_block_after_failed_connect(&self) {
        #[cfg(target_os = "windows")]
        if let Err(e) = crate::vpn::wfp::unblock_ipv6().await {
            tracing::warn!("Failed to lift IPv6 block after a failed connect: {}", e);
        }

        // F-001: same contract on macOS/Linux. `start()` installs the block before
        // DNS configuration, so a connect that fails after that point (or that
        // trips CONNECT_TIMEOUT) would otherwise strand the host with no IPv6
        // until the next successful connect+disconnect cycle.
        #[cfg(target_os = "macos")]
        crate::commands::killswitch::ipv6_block_deactivate().await;

        #[cfg(target_os = "linux")]
        crate::vpn::tunnel_linux::remove_ipv6_leak_block();
    }

    /// Disconnect from VPN
    pub async fn disconnect(&self) -> Result<(), String> {
        self.disconnect_to(ConnectionState::Disconnected).await
    }

    /// Tear the tunnel down and end in `final_state`.
    ///
    /// Auto-reconnect tears a dead tunnel down to `Reconnecting`, and a give-up
    /// to `Error`, so the UI never sees a `disconnected` flicker in the middle
    /// of a recovery.
    ///
    /// SM-002: Uses operation lock to prevent concurrent connect/disconnect
    /// STATE-FIX: Wraps tunnel stop in a 15s timeout with forced cleanup.
    /// A stuck Disconnecting state is worse than a dirty Disconnected state.
    pub async fn disconnect_to(&self, final_state: ConnectionState) -> Result<(), String> {
        self.disconnect_to_with(final_state, |_| {}).await
    }

    /// End a recovery that gave up: tear down whatever tunnel is still held
    /// and land in `Error` marked [`GaveUp`] — ONE visible change either way.
    /// `gave_up: None` is an `Error` that ends no recovery (a revocation
    /// noticed on a healthy session).
    pub async fn end_in_error(&self, error: IpcError, gave_up: Option<GaveUp>) {
        let state = ConnectionState::Error(error);
        if self.holds_tunnel().await {
            let _ = self
                .disconnect_to_with(state, |p| p.gave_up = gave_up)
                .await;
        } else {
            let _ = self.write_state_with(state, |p| p.gave_up = gave_up).await;
        }
    }

    async fn disconnect_to_with(
        &self,
        final_state: ConnectionState,
        extra: impl FnOnce(&mut PublishedStatus),
    ) -> Result<(), String> {
        // SM-002: Acquire operation lock first
        let _operation_guard = self
            .acquire_operation_lock()
            .await
            .map_err(|e| format!("Failed to acquire operation lock: {}", e))?;

        // Check current state with timeout
        let current_state = self
            .read_state_with_timeout()
            .await
            .map_err(|e| format!("Failed to read state: {}", e))?;

        // I2/I3: `can_disconnect()` is false in `Disconnected` and
        // `Disconnecting`, and `ConnectionState` is written by paths that
        // never touch `self.tunnel` — so returning on the state alone made an
        // orphaned live tunnel unreachable by any user action. Take the record
        // into account: if there IS a tunnel, disconnect means something no
        // matter what the state claims.
        if !current_state.can_disconnect() && !self.holds_tunnel().await {
            tracing::debug!("Already disconnected or disconnecting");
            return Ok(());
        }

        let interim = if final_state == ConnectionState::Disconnected {
            ConnectionState::Disconnecting
        } else {
            final_state.clone()
        };
        let _ = self.write_state_with_timeout(interim).await;

        tracing::info!("Disconnecting from VPN");

        // STATE-FIX: Wrap entire tunnel stop in a 15s timeout.
        // If tunnel.stop() hangs (e.g. netsh deadlocks on UAC/antivirus), we
        // force transition to Disconnected rather than staying stuck forever.
        let stop_result = match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
            Ok(mut guard) => {
                if let Some(tunnel) = guard.take() {
                    self.set_tunnel_present(false);
                    match timeout(Duration::from_secs(15), tunnel.stop()).await {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => {
                            tracing::error!("Tunnel stop failed: {}", e);
                            Err(e)
                        }
                        Err(_) => {
                            tracing::error!("Tunnel stop timed out after 15s — forcing cleanup");
                            Err("Tunnel stop timed out".to_string())
                        }
                    }
                } else {
                    Ok(())
                }
            }
            Err(_) => {
                tracing::error!("Tunnel write lock timeout during disconnect");
                Err("Lock timeout".to_string())
            }
        };

        match timeout(STATE_LOCK_TIMEOUT, self.current_config.write()).await {
            Ok(mut guard) => *guard = None,
            Err(_) => tracing::error!("Config write lock timeout during disconnect"),
        }

        // Update stats with timeout
        match timeout(STATE_LOCK_TIMEOUT, self.stats.write()).await {
            Ok(mut stats) => {
                stats.connected_at = None;
                stats.server_id = None;
                stats.key_id = None;
                stats.server_name = None;
                // Measurements die with the session (update_stats no longer
                // clears latency on its own, so do it at the boundary).
                stats.latency_ms = None;
            }
            Err(_) => tracing::error!("Stats write lock timeout during disconnect"),
        }

        // STATE-FIX: ALWAYS reach the final state, even on error.
        // A stuck Disconnecting state blocks all future operations.
        let _ = self
            .write_state_with(final_state, |p| {
                p.server_id = None;
                p.multi_hop = None;
                extra(p);
            })
            .await;

        match stop_result {
            Ok(()) => {
                tracing::info!("VPN disconnected cleanly");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("VPN disconnected with errors: {}", e);
                // Return Ok — we're disconnected, just not cleanly.
                // The caller doesn't need to retry disconnection.
                Ok(())
            }
        }
    }

    /// Does the manager still HOLD a tunnel object (I2 NO ORPHANS)?
    ///
    /// Named for what it actually reads. It answers "is there a tunnel value
    /// that has not been disposed of", which is the question `disconnect()`
    /// needs — an orphan is unreachable by any user action if the decision is
    /// left to `ConnectionState`, whose `is_tunnel_active()` is `matches!(self,
    /// Connected)` and so is false in exactly the states where an orphan can
    /// exist.
    ///
    /// It is NOT the I3 machine-state predicate, and must not be used as one.
    /// I3 asks whether the DNS guard and the installed routes are in force, and
    /// this `Option` is emptied by `connect()` itself — deliberately, into
    /// `displaced` — for the whole create + handshake window, during which the
    /// machine state is very much still in force under a generation the manager holds.
    /// The predicate for that is `win_machine_state::is_owner`, which reads the
    /// ownership token rather than a container, and every DNS, route and
    /// firewall mutation in this codebase is already gated on it.
    ///
    /// A busy lock answers `true`: absence has to be positively established,
    /// and the `take()` that follows finds out for certain.
    pub async fn holds_tunnel(&self) -> bool {
        match timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            Ok(guard) => guard.is_some(),
            Err(_) => {
                tracing::warn!("Tunnel read lock timeout in holds_tunnel — assuming one exists");
                true
            }
        }
    }

    /// Time since the live tunnel's last completed WireGuard handshake
    /// (W1-002). `None` when there is no tunnel with a WireGuard session.
    pub async fn handshake_age(&self) -> Option<Duration> {
        let guard = timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await.ok()?;
        guard.as_ref()?.handshake_age().await
    }

    /// W1-003: move the live tunnel onto a new default route in place (see
    /// `WintunTunnel::roam`). `Err` means the caller should re-dial.
    #[cfg(target_os = "windows")]
    pub async fn roam(
        &self,
        from: crate::vpn::network_events::PhysicalRoute,
        to: crate::vpn::network_events::PhysicalRoute,
    ) -> Result<(), String> {
        let guard = timeout(STATE_LOCK_TIMEOUT, self.tunnel.read())
            .await
            .map_err(|_| "tunnel lock timeout".to_string())?;
        let tunnel = guard.as_ref().ok_or_else(|| "no tunnel".to_string())?;
        tunnel
            .roam((from.gateway, from.interface), (to.gateway, to.interface))
            .await
    }

    /// The fast dead-path signal: the relay has stopped answering handshakes
    /// while traffic is waiting (see `wireguard_new::peer_unresponsive`).
    #[cfg(target_os = "windows")]
    pub async fn peer_unresponsive(&self) -> bool {
        match timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            Ok(guard) => match guard.as_ref() {
                Some(tunnel) => tunnel.peer_unresponsive().await,
                None => false,
            },
            Err(_) => false,
        }
    }

    /// When the live tunnel's packet path last ticked, for the stall rule
    /// (`wireguard_new::StallWatch`). `None` with no tunnel, or one that has
    /// not ticked yet.
    #[cfg(target_os = "windows")]
    pub async fn packet_path_tick(&self) -> Option<std::time::Instant> {
        match timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            Ok(guard) => match guard.as_ref() {
                Some(tunnel) => tunnel.packet_path_tick().await,
                None => None,
            },
            Err(_) => None,
        }
    }

    /// Forget unanswered handshakes sent before a resume.
    #[cfg(target_os = "windows")]
    pub async fn restart_response_watch(&self) {
        if let Ok(guard) = timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            if let Some(tunnel) = guard.as_ref() {
                tunnel.restart_response_watch().await;
            }
        }
    }

    /// Ask the live tunnel for a fresh handshake now (a no-op while one is
    /// already in flight). Used after resume and when an idle session's
    /// handshake is getting old, so liveness is proven rather than assumed.
    pub async fn force_handshake(&self) {
        if let Ok(guard) = timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            if let Some(tunnel) = guard.as_ref() {
                tunnel.force_handshake().await;
            }
        }
    }

    /// Get the current key_id for API disconnect call
    pub async fn get_key_id(&self) -> Option<String> {
        match timeout(STATE_LOCK_TIMEOUT, self.stats.read()).await {
            Ok(guard) => guard.key_id.clone(),
            Err(_) => {
                tracing::error!("Stats read lock timeout in get_key_id");
                None
            }
        }
    }

    /// Refresh the byte counters and the latency from the live tunnel.
    ///
    /// The status choke point runs this on every `get_vpn_status`, every 2 s
    /// stats poll and every status event, so it NEVER waits (WIN-FIX-3 P0): a
    /// connect or a teardown holding the tunnel (a stop takes up to 15 s) or
    /// the stats skips the refresh, and the last counters are served. The
    /// tunnel's own readings are lock-free (`wireguard_new` module docs).
    pub async fn update_stats(&self) {
        let Ok(tunnel_guard) = self.tunnel.try_read() else {
            return;
        };
        let Some(tunnel) = tunnel_guard.as_ref() else {
            return;
        };
        let (sent, received, pkts_sent, pkts_received) = tunnel.get_stats();
        let latency = tunnel.get_latency_ms().await;
        drop(tunnel_guard);
        let Ok(mut stats) = self.stats.try_write() else {
            return;
        };
        stats.bytes_sent = sent;
        stats.bytes_received = received;
        stats.packets_sent = pkts_sent;
        stats.packets_received = pkts_received;
        // P1-dk-fabricated-quality-telemetry: only OVERWRITE the latency when
        // the tunnel actually measured one (the handshake RTT, W1-002), so a
        // session that has not rekeyed yet keeps "unmeasured" rather than 0.
        if let Some(lat) = latency {
            stats.latency_ms = Some(lat);
        }
    }
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Every lock the engine has, held as a wedged engine would hold them: a
/// connect stuck in a synchronous step (the operation and commit locks), a
/// teardown stopping the tunnel (its write lock), a state write in progress.
#[cfg(test)]
pub(crate) struct WedgedEngine<'a> {
    _operation: MutexGuard<'a, ()>,
    _commit: MutexGuard<'a, ()>,
    _state: tokio::sync::RwLockWriteGuard<'a, ConnectionState>,
    _tunnel: tokio::sync::RwLockWriteGuard<'a, Option<PlatformTunnel>>,
}

#[cfg(test)]
impl VpnManager {
    pub(crate) async fn wedge_for_test(&self) -> WedgedEngine<'_> {
        WedgedEngine {
            _operation: self.operation_lock.lock().await,
            _commit: self.commit_lock.lock().await,
            _state: self.state.write().await,
            _tunnel: self.tunnel.write().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_blocking() -> BlockProbe {
        BlockProbe {
            blocking: false,
            holds_block_while_connected: false,
        }
    }

    fn reactive_blocking() -> BlockProbe {
        BlockProbe {
            blocking: true,
            holds_block_while_connected: false,
        }
    }

    fn label() -> SessionLabel {
        SessionLabel {
            server_name: "Amsterdam".into(),
            server_id: "ams-1".into(),
            multi_hop: None,
        }
    }

    #[test]
    fn blocking_needs_the_block_and_no_tunnel_carrying_traffic() {
        let lockdown = BlockProbe {
            blocking: true,
            holds_block_while_connected: true,
        };
        // A healthy lockdown session carries its traffic through the permit.
        assert!(!kill_switch_blocking(
            lockdown,
            &ConnectionState::Connected,
            true
        ));
        // A switch whose old tunnel is still up under lockdown: still carrying.
        assert!(!kill_switch_blocking(
            lockdown,
            &ConnectionState::Switching,
            true
        ));
        // Reactive switch after the teardown: nothing carries traffic.
        assert!(kill_switch_blocking(
            reactive_blocking(),
            &ConnectionState::Switching,
            false
        ));
        for state in [
            ConnectionState::Reconnecting {
                attempt: 1,
                last_error: None,
            },
            ConnectionState::Error(IpcError::unknown("x")),
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
        ] {
            assert!(kill_switch_blocking(lockdown, &state, false), "{state:?}");
            assert!(
                !kill_switch_blocking(not_blocking(), &state, false),
                "{state:?}"
            );
        }
    }

    #[tokio::test]
    async fn every_visible_change_bumps_seq_once_and_nothing_else_does() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let mut rx = mgr.subscribe_status();
        assert_eq!(mgr.published().seq, 0);

        mgr.set_state(ConnectionState::Connecting).await.unwrap();
        assert_eq!(mgr.published().seq, 1);
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        // Same state again: nothing visible changed, no event.
        mgr.set_state(ConnectionState::Connecting).await.unwrap();
        assert_eq!(mgr.published().seq, 1);
        assert!(!rx.has_changed().unwrap());

        // A phase change while connecting is visible.
        mgr.set_phase(ConnectPhase::Authenticating);
        assert_eq!(mgr.published().seq, 2);
        assert_eq!(mgr.published().phase, Some(ConnectPhase::Authenticating));

        // Stats-only refreshes never emit.
        mgr.update_stats().await;
        mgr.refresh_status();
        assert_eq!(mgr.published().seq, 2);
    }

    #[tokio::test]
    async fn the_phase_and_budget_do_not_outlive_their_state() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        mgr.set_reconnecting(2, None, Some(10)).await;
        mgr.set_phase(ConnectPhase::Handshaking);
        let p = mgr.published();
        assert_eq!(p.reconnect_max, Some(10));
        assert_eq!(p.phase, Some(ConnectPhase::Handshaking));

        mgr.set_state(ConnectionState::Error(IpcError::unknown("x")))
            .await
            .unwrap();
        let p = mgr.published();
        assert_eq!(p.reconnect_max, None);
        assert_eq!(p.phase, None);
        // A phase set outside a build is ignored.
        mgr.set_phase(ConnectPhase::Authenticating);
        assert_eq!(mgr.published().phase, None);
    }

    #[tokio::test]
    async fn the_error_travels_with_the_state() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let err = IpcError::new(IpcErrorCode::Revoked, "Connection has been revoked.");
        mgr.set_state(ConnectionState::Error(err.clone()))
            .await
            .unwrap();
        assert_eq!(mgr.published().state, ConnectionState::Error(err));
    }

    #[tokio::test]
    async fn blocking_changes_publish_without_a_state_change() {
        use std::sync::atomic::AtomicBool;
        static BLOCKING: AtomicBool = AtomicBool::new(false);
        fn probe() -> BlockProbe {
            BlockProbe {
                blocking: BLOCKING.load(AtomicOrdering::SeqCst),
                holds_block_while_connected: false,
            }
        }
        let mgr = VpnManager::with_block_probe(probe);
        mgr.set_state(ConnectionState::Error(IpcError::unknown("x")))
            .await
            .unwrap();
        let seq = mgr.published().seq;
        assert!(!mgr.published().kill_switch_blocking);

        BLOCKING.store(true, AtomicOrdering::SeqCst);
        mgr.refresh_status();
        assert!(mgr.published().kill_switch_blocking);
        assert_eq!(mgr.published().seq, seq + 1);
    }

    /// REVIEW-WIN-013: the module docs promise a Disconnect during a stuck
    /// build lands within the operation-lock timeout (plus the 3 s notify).
    /// The promise and the constant must not drift apart.
    #[test]
    fn the_documented_cancel_bound_is_the_operation_lock_timeout() {
        // The module docs only: the rest of the file holds this test's own
        // strings, which would match themselves.
        let source = include_str!("manager.rs").replace("\r\n", "\n");
        let docs = &source[..source.find("\nuse ").expect("the first use")];
        assert_eq!(OPERATION_LOCK_TIMEOUT, Duration::from_secs(30));
        assert!(docs.contains("`OPERATION_LOCK_TIMEOUT` (30 s)"));
        assert!(docs.contains("no case later than\n//! about 35 s."));
    }

    #[tokio::test]
    async fn a_superseded_epoch_is_cancelled() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let first = mgr.begin_attempt();
        assert!(mgr.is_current(first));
        let second = mgr.begin_attempt();
        assert!(!mgr.is_current(first));
        assert!(mgr.is_current(second));
        // Resolves immediately for a stale epoch.
        tokio::time::timeout(Duration::from_secs(1), mgr.cancelled(first))
            .await
            .expect("a superseded epoch must read as cancelled");

        // And a pending operation is dropped the moment its epoch is cancelled.
        let mgr2 = mgr.clone();
        let pending = tokio::spawn(async move {
            mgr2.run_cancellable(second, std::future::pending::<()>())
                .await
        });
        tokio::task::yield_now().await;
        mgr.cancel_in_flight();
        let out = tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out.unwrap_err().code, IpcErrorCode::Cancelled);
    }

    /// REVIEW-WIN-003: a connect queued on the commit lock AHEAD of a teardown
    /// begins its attempt once the lock frees — after the teardown's first
    /// cancel — so the teardown must cancel again once it holds the lock.
    /// With a single cancel before the wait, the connect's epoch is still
    /// current when the teardown finishes, and its tunnel would come up after
    /// the user's Disconnect.
    #[tokio::test]
    async fn a_connect_queued_ahead_of_a_teardown_is_still_cancelled() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        // A failing switch holds the lock through its teardown (fail_connect).
        let held = mgr.lock_commit().await;

        // Tray Quick Connect queues on the lock, exactly as connect_session
        // takes its epoch.
        let connect = {
            let mgr = mgr.clone();
            tokio::spawn(async move {
                let _commit = mgr.lock_commit().await;
                mgr.begin_attempt()
            })
        };
        tokio::task::yield_now().await;

        // Tray Disconnect queues behind it.
        let teardown = {
            let mgr = mgr.clone();
            tokio::spawn(async move {
                let _commit = mgr.lock_commit_for_teardown().await;
            })
        };
        tokio::task::yield_now().await;

        drop(held);
        let epoch = connect.await.unwrap();
        teardown.await.unwrap();
        assert!(
            !mgr.is_current(epoch),
            "the connect that queued ahead of the Disconnect survived it"
        );
    }

    /// WIN3-002: the settings revert follows up the rebuild that failed. A
    /// Disconnect pressed in between — the failure's `error` is on screen
    /// while the failing rebuild still holds the commit lock — or a newer
    /// connect wins: the revert begins nothing. With nothing in between it
    /// begins as before.
    #[tokio::test]
    async fn a_revert_never_undoes_a_disconnect_pressed_after_the_failure() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let rebuild = mgr.begin_attempt();

        // fail_connect publishes the error under the lock; the user's
        // Disconnect cancels and queues behind it.
        let failing = mgr.lock_commit().await;
        let teardown = {
            let mgr = mgr.clone();
            tokio::spawn(async move {
                let _commit = mgr.lock_commit_for_teardown().await;
            })
        };
        tokio::task::yield_now().await;
        drop(failing);
        teardown.await.unwrap();

        // The revert's reconnect, queued after the teardown.
        let _commit = mgr.lock_commit().await;
        let epoch = mgr.current_epoch();
        assert_eq!(
            mgr.begin_follow_up(rebuild),
            None,
            "the revert reconnected after the user's Disconnect"
        );
        assert_eq!(
            mgr.current_epoch(),
            epoch,
            "a refused revert moved the epoch"
        );

        // A newer connect (another server) supersedes the same way.
        let rebuild = mgr.begin_attempt();
        let _newer = mgr.begin_attempt();
        assert_eq!(mgr.begin_follow_up(rebuild), None);

        // Nothing in between: the revert begins, and supersedes the rebuild.
        let rebuild = mgr.begin_attempt();
        let revert = mgr.begin_follow_up(rebuild).expect("the revert begins");
        assert!(mgr.is_current(revert) && !mgr.is_current(rebuild));
    }

    /// W1-021: a connect whose epoch was superseded before it could start
    /// touches nothing — no tunnel, no machine state, no state write.
    #[tokio::test]
    async fn a_cancelled_connect_touches_nothing() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let stale = mgr.begin_attempt();
        mgr.cancel_in_flight();
        let seq = mgr.published().seq;
        let config = VpnConfig {
            server_id: "ams-1".into(),
            key_id: "k".into(),
            private_key: "p".into(),
            public_key: "q".into(),
            server_public_key: "s".into(),
            preshared_key: None,
            endpoint: "203.0.113.1:51820".into(),
            allowed_ips: vec!["0.0.0.0/0".into()],
            dns: vec!["10.0.0.1".into()],
            custom_dns: false,
            client_ip: "10.0.0.2".into(),
            client_ipv6: None,
            allowed_ips_v6: vec![],
            mtu: 1420,
            persistent_keepalive: 25,
        };
        let err = mgr
            .connect(config, label(), false, stale)
            .await
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Cancelled);
        assert_eq!(mgr.published().seq, seq);
        assert_eq!(mgr.get_state().await, ConnectionState::Disconnected);
        assert!(!mgr.holds_tunnel().await);
    }

    /// The UI recognises an auto-reconnect give-up as a `reconnecting` →
    /// `error` transition and words it from `error.code`. Ending a recovery
    /// in `Error` must therefore be ONE visible change, never passing through
    /// `disconnecting` / `disconnected`, and the code must be on it.
    #[tokio::test]
    async fn a_give_up_is_one_transition_from_reconnecting_to_error() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        mgr.set_reconnecting(10, Some(IpcError::unknown("last try")), Some(10))
            .await;
        let before = mgr.published().seq;

        let verdict = IpcError::new(IpcErrorCode::ServerUnreachable, "gave up");
        mgr.disconnect_to(ConnectionState::Error(verdict.clone()))
            .await
            .unwrap();

        let after = mgr.published();
        assert_eq!(after.seq, before + 1, "an intermediate state was published");
        assert_eq!(after.state, ConnectionState::Error(verdict));
        assert_eq!(after.reconnect_max, None);
    }

    /// REVIEW-WIN-009: the give-up is ON the final status, not inferred from a
    /// transition the UI may never see; and it does not outlive the error.
    #[tokio::test]
    async fn a_give_up_is_marked_on_the_error_status_itself() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        mgr.set_reconnecting(10, None, Some(10)).await;
        let verdict = IpcError::new(IpcErrorCode::ServerUnreachable, "gave up");
        mgr.end_in_error(verdict.clone(), Some(GaveUp { attempts: 10 }))
            .await;
        let p = mgr.published();
        assert_eq!(p.state, ConnectionState::Error(verdict));
        assert_eq!(p.gave_up, Some(GaveUp { attempts: 10 }));

        // An error that ends no recovery carries no mark.
        mgr.end_in_error(IpcError::unknown("revoked"), None).await;
        assert_eq!(mgr.published().gave_up, None);

        mgr.end_in_error(IpcError::unknown("again"), Some(GaveUp { attempts: 0 }))
            .await;
        mgr.set_state(ConnectionState::Connecting).await.unwrap();
        assert_eq!(mgr.published().gave_up, None, "the mark outlived the error");
    }

    /// WIN-FIX-3 P0: the stats refresh behind every status read skips a
    /// tunnel that is busy instead of waiting for it. It used to wait up to
    /// 5 s per call for a teardown's tunnel lock (a stop holds it 15 s), on
    /// every status read, stats poll and status event.
    #[tokio::test]
    async fn the_stats_refresh_never_waits_for_a_busy_tunnel() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let _wedged = mgr.wedge_for_test().await;
        tokio::time::timeout(Duration::from_millis(200), mgr.update_stats())
            .await
            .expect("update_stats waited on the engine");
    }

    #[tokio::test]
    async fn disconnecting_clears_the_session_label() {
        let mgr = VpnManager::with_block_probe(not_blocking);
        let _ = mgr
            .write_state_with(ConnectionState::Connected, |p| {
                p.server_id = Some("exit-1".into());
                p.multi_hop = Some(MultiHopStatus {
                    entry_id: "entry-1".into(),
                    entry_name: "Frankfurt".into(),
                    exit_id: "exit-1".into(),
                    exit_name: "Reykjavik".into(),
                });
            })
            .await;
        assert_eq!(mgr.published().server_id.as_deref(), Some("exit-1"));
        mgr.disconnect().await.unwrap();
        let p = mgr.published();
        assert_eq!(p.state, ConnectionState::Disconnected);
        assert_eq!(p.server_id, None);
        assert_eq!(p.multi_hop, None);
    }
}
