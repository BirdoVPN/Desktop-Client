//! VPN Manager
//!
//! High-level VPN connection management with deadlock prevention (SM-002).
//!
//! # Security Notes
//! - Uses timeout-based lock acquisition to prevent deadlocks
//! - State transitions are validated to prevent illegal states
//! - Operation lock prevents concurrent connect/disconnect races

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex as TokioMutex, RwLock};
use tokio::time::timeout;

// Platform-specific tunnel implementation
#[cfg(target_os = "windows")]
use super::tunnel::WintunTunnel as PlatformTunnel;
#[cfg(target_os = "linux")]
use super::tunnel_linux::LinuxTunnel as PlatformTunnel;
#[cfg(target_os = "macos")]
use super::tunnel_macos::UtunTunnel as PlatformTunnel;

use crate::api::types::VpnConfig;

/// SM-002: Timeout for state lock acquisition to prevent deadlocks
const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// SM-002: Timeout for operation lock to prevent concurrent operations hanging
const OPERATION_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// CONNECT-FIX: Maximum time allowed for the entire connect operation
/// If tunnel creation + start exceeds this, we force-fail to prevent hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Variants reserved for upcoming auth/stealth/killswitch state transitions
pub enum ConnectionState {
    Disconnected,
    Connecting,
    /// P1-6: API auth in progress (after calling /vpn/connect, before config applied)
    Authenticating,
    /// P1-6: Xray Reality stealth tunnel being established
    StealthConnecting,
    Connected,
    Disconnecting,
    /// SM-002: Reconnecting state with attempt tracking
    Reconnecting {
        attempt: u32,
    },
    /// P1-6: Kill switch active after disconnect (blocking all non-VPN traffic)
    KillSwitchActive,
    Error(String),
}

impl ConnectionState {
    /// Check if traffic can flow in this state
    pub fn is_tunnel_active(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Check if a new connection can be initiated
    /// STATE-FIX: Also allow connecting from Reconnecting state, which is set
    /// by auto-reconnect before calling connect(). Without this, reconnect fails silently.
    pub fn can_connect(&self) -> bool {
        matches!(
            self,
            ConnectionState::Disconnected
                | ConnectionState::Error(_)
                | ConnectionState::KillSwitchActive
                | ConnectionState::Reconnecting { .. }
        )
    }

    /// Check if disconnect is meaningful in this state
    pub fn can_disconnect(&self) -> bool {
        !matches!(
            self,
            ConnectionState::Disconnected
                | ConnectionState::Disconnecting
                | ConnectionState::KillSwitchActive
        )
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
    // P6-CLI-X-01: `jitter_ms()` is GONE. Jitter was computed for one consumer
    // only — the 60-second quality report — and nothing else ever read it.

    // P1-dk-fabricated-quality-telemetry: `packet_loss_percent()` (TX packet
    // delta vs RX packet delta) and its `prev_packets_*` snapshot machinery were
    // removed. The two directions are independent counters, so a normal
    // upload-heavy minute reported a large invented "loss" — the quality report
    // now derives loss from probe outcomes in auto_reconnect.rs instead.

    // P6-CLI-X-01: `push_latency_sample()` is GONE with `latency_samples`.
}

pub struct VpnManager {
    state: Arc<RwLock<ConnectionState>>,
    pub(crate) stats: Arc<RwLock<ConnectionStats>>,
    tunnel: Arc<RwLock<Option<PlatformTunnel>>>,
    current_config: Arc<RwLock<Option<VpnConfig>>>,
    /// SM-002: Operation lock to prevent concurrent connect/disconnect
    /// Only one connect or disconnect operation can run at a time
    operation_lock: Arc<TokioMutex<()>>,
    /// FIX-R5: When true, user explicitly disconnected — auto-reconnect must not fire.
    /// This prevents the race where user clicks "Disconnect" but auto-reconnect
    /// immediately brings the VPN back up.
    user_initiated_disconnect: Arc<AtomicBool>,
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
    /// General error
    General(String),
}

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnError::LockTimeout(msg) => write!(f, "Lock timeout: {}", msg),
            VpnError::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {} to {}", from, to)
            }
            VpnError::OperationInProgress => write!(f, "Another operation is already in progress"),
            VpnError::General(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for VpnError {}

impl VpnManager {
    /// Restore physical-adapter DNS synchronously, for exit paths that cannot
    /// await.
    ///
    /// WHY THIS EXISTS. `RunEvent::ExitRequested` with `RESTART_EXIT_CODE` (the
    /// updater relaunch) returns before `teardown_for_exit`, because a restart
    /// cannot be held open — `prevent_exit()` is a documented no-op for it. The
    /// comment there reasons that the startup reconcile in `setup()` cleans up
    /// after the relaunch, and that is true for kernel firewall state: there are
    /// macOS and Linux arms for exactly that. There is no Windows arm, and
    /// Windows is where `configure_dns` parks EVERY physical adapter on
    /// `static none`.
    ///
    /// So an in-app update performed while connected leaves the machine with no
    /// resolvers, and the relaunched instance then cannot resolve the API it
    /// needs to reconnect. That is not a crash path — it is the normal update
    /// path.
    ///
    /// Goes straight to the machine-state owner rather than through
    /// `self.tunnel`. Reading it through the tunnel is what made this fragile:
    /// a reconnect empties that Option for the whole create + handshake window,
    /// so an exit landing in that window found `None` and restored nothing. The
    /// park record no longer lives in the tunnel, so there is nothing to look
    /// through.
    ///
    /// Synchronous and lock-free of any async lock, so it can never wedge an
    /// exit that must not be held open.
    #[cfg(target_os = "windows")]
    pub fn restore_dns_blocking(&self) -> bool {
        crate::vpn::win_machine_state::release_dns_at_exit()
    }

    /// Create a new VPN manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(ConnectionStats {
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                latency_ms: None,
                connected_at: None,
                server_id: None,
                key_id: None,
                server_name: None,
            })),
            tunnel: Arc::new(RwLock::new(None)),
            current_config: Arc::new(RwLock::new(None)),
            operation_lock: Arc::new(TokioMutex::new(())),
            user_initiated_disconnect: Arc::new(AtomicBool::new(false)),
        }
    }

    /// FIX-R5: Mark that the user explicitly disconnected.
    /// Auto-reconnect checks this flag and does NOT reconnect if true.
    pub fn set_user_disconnected(&self, value: bool) {
        self.user_initiated_disconnect
            .store(value, AtomicOrdering::SeqCst);
    }

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

    /// SM-002: Acquire state write lock with timeout to prevent deadlock
    async fn write_state_with_timeout(
        &self,
        new_state: ConnectionState,
    ) -> Result<ConnectionState, VpnError> {
        match timeout(STATE_LOCK_TIMEOUT, self.state.write()).await {
            Ok(mut guard) => {
                let old_state = guard.clone();
                *guard = new_state.clone();
                tracing::debug!(
                    old_state = ?old_state,
                    new_state = ?new_state,
                    "State transition"
                );
                Ok(old_state)
            }
            Err(_) => {
                tracing::error!("State write lock timeout - possible deadlock");
                Err(VpnError::LockTimeout("state write lock".into()))
            }
        }
    }

    /// Get current connection state
    pub async fn get_state(&self) -> ConnectionState {
        self.read_state_with_timeout()
            .await
            .unwrap_or(ConnectionState::Error("Lock timeout".into()))
    }

    /// Set connection state (used by auto-reconnect to set Reconnecting state)
    pub async fn set_state(&self, new_state: ConnectionState) -> Result<(), String> {
        self.write_state_with_timeout(new_state)
            .await
            .map_err(|e| format!("Failed to set state: {}", e))?;
        Ok(())
    }

    /// Get current connection stats
    pub async fn get_stats(&self) -> ConnectionStats {
        match timeout(STATE_LOCK_TIMEOUT, self.stats.read()).await {
            Ok(guard) => guard.clone(),
            Err(_) => {
                tracing::error!("Stats read lock timeout");
                ConnectionStats {
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

    /// Connect to a VPN server
    /// SM-002: Uses operation lock to prevent concurrent connect/disconnect
    pub async fn connect(
        &self,
        config: VpnConfig,
        server_name: String,
        local_network_sharing: bool,
    ) -> Result<(), String> {
        // LOG-001: the chosen node is connection history — keep the name out
        // of the release log (info reaches birdo.log); debug is dev-only.
        tracing::info!("VpnManager::connect called");
        tracing::debug!("VpnManager::connect called for server: {}", server_name);

        // FIX-R5: Clear the user-disconnected flag so auto-reconnect can work again
        self.user_initiated_disconnect
            .store(false, AtomicOrdering::SeqCst);

        // SM-002: Acquire operation lock first to prevent concurrent operations
        let _operation_guard = self
            .acquire_operation_lock()
            .await
            .map_err(|e| format!("Failed to acquire operation lock: {}", e))?;

        // Check current state with timeout
        let current_state = self
            .read_state_with_timeout()
            .await
            .map_err(|e| format!("Failed to read state: {}", e))?;

        tracing::debug!("Current VPN state: {:?}", current_state);

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
        // `Disconnected` / `Disconnecting` / `KillSwitchActive`, so it returns
        // Ok(()) without taking the tunnel — that would turn the orphan from a
        // leak into a permanent lockout where Connect refuses, Disconnect no-ops
        // and only quitting the app recovers. The correct form is: dispose
        // unconditionally.
        let displaced = match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
            Ok(mut guard) => guard.take(),
            Err(_) => {
                tracing::error!(
                    "Tunnel lock timeout before connect — cannot safely create a new tunnel \
                     while an old one may still be live"
                );
                let _ = self
                    .write_state_with_timeout(ConnectionState::Error("Tunnel lock timeout".into()))
                    .await;
                return Err("Tunnel lock timeout during teardown — please try again".into());
            }
        };

        // The machine state (parked DNS + installed routes) is deliberately NOT
        // released between the outgoing tunnel and the incoming one. Moving it to
        // a generation the manager holds means the old tunnel's stop()/Drop
        // cannot un-park or delete anything on its way out, and the new tunnel
        // ADOPTS it — so the physical NICs never carry ISP resolvers during the
        // multi-second create + handshake window. Every failure arm below hands
        // this generation back with `release_after_failed_connect`, so a connect
        // that never produces a tunnel cannot strand the park.
        #[cfg(target_os = "windows")]
        let transition_gen = crate::vpn::win_machine_state::begin_transition();

        if displaced.is_some()
            || matches!(
                current_state,
                ConnectionState::Connected | ConnectionState::Connecting
            )
        {
            tracing::info!(
                "Tearing down the existing tunnel before connecting (state {:?}, tunnel present: \
                 {})",
                current_state,
                displaced.is_some()
            );
            let _ = self
                .write_state_with_timeout(ConnectionState::Disconnecting)
                .await;

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
            // that it no longer owns the machine state and will leave the park
            // and the routes exactly where they are.
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
                from: format!("{:?}", current_state),
                to: "Connecting".into(),
            };
            tracing::warn!("{}", err);
            #[cfg(target_os = "windows")]
            self.release_machine_state_after_failed_connect(transition_gen)
                .await;
            return Err(err.to_string());
        }

        // Set connecting state with timeout
        if let Err(e) = self
            .write_state_with_timeout(ConnectionState::Connecting)
            .await
        {
            #[cfg(target_os = "windows")]
            self.release_machine_state_after_failed_connect(transition_gen)
                .await;
            return Err(format!("Failed to set connecting state: {}", e));
        }
        tracing::info!("Set state to Connecting");

        // LOG-001: node name demoted to debug — see connect() above.
        tracing::info!("Creating VPN tunnel");
        tracing::debug!("Creating VPN tunnel for: {}", server_name);
        tracing::debug!(
            "Tunnel config: endpoint={}, client_ip={}",
            crate::utils::redact_endpoint(&config.endpoint),
            crate::utils::redact_ip(&config.client_ip)
        );

        // CONNECT-FIX: Wrap the entire tunnel creation + start in a timeout.
        // If tunnel creation or start hangs (e.g. netsh deadlocks on Windows
        // UAC prompt, or antivirus blocks wintun.dll), we fail fast instead of
        // leaving the state stuck at Connecting forever.
        let tunnel_result = timeout(CONNECT_TIMEOUT, async {
            let tunnel = PlatformTunnel::create(&config, local_network_sharing)
                .await
                .map_err(|e| format!("Failed to create tunnel: {}", e))?;
            tunnel
                .start()
                .await
                .map_err(|e| format!("Failed to start tunnel: {}", e))?;
            Ok::<PlatformTunnel, String>(tunnel)
        })
        .await;

        match tunnel_result {
            Ok(Ok(tunnel)) => {
                tracing::info!("Tunnel started successfully");

                // P1-dk-manager-tunnel-dropped-state-connected: store the tunnel
                // BEFORE transitioning to Connected. The old order dropped a live
                // tunnel on a write-lock timeout while leaving state=Connected —
                // green UI with traffic on the physical NIC. If the store fails,
                // stop the tunnel and surface Error instead.
                match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
                    Ok(mut guard) => *guard = Some(tunnel),
                    Err(_) => {
                        tracing::error!(
                            "Tunnel write lock timeout — stopping fresh tunnel instead of \
                             reporting Connected without one"
                        );
                        let _ = tunnel.stop().await;
                        let _ = self
                            .write_state_with_timeout(ConnectionState::Error(
                                "Internal error storing tunnel state".to_string(),
                            ))
                            .await;
                        #[cfg(target_os = "windows")]
                        self.release_machine_state_after_failed_connect(transition_gen)
                            .await;
                        return Err("Tunnel state lock timeout during connect".to_string());
                    }
                }

                // Update state with timeout protection
                let _ = self
                    .write_state_with_timeout(ConnectionState::Connected)
                    .await;

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

                // Update stats with timeout
                match timeout(STATE_LOCK_TIMEOUT, self.stats.write()).await {
                    Ok(mut stats) => {
                        stats.connected_at = Some(chrono::Utc::now());
                        stats.server_id = Some(config.server_id.clone());
                        stats.key_id = Some(config.key_id.clone());
                        stats.server_name = Some(server_name);
                        stats.bytes_sent = 0;
                        stats.bytes_received = 0;
                        // Latency belongs to a PATH; a new session (possibly a
                        // different server) must not inherit the old one's
                        // measurements now that update_stats keeps them.
                        stats.latency_ms = None;
                    }
                    Err(_) => tracing::error!("Stats write lock timeout"),
                }

                tracing::info!("VPN connected successfully");
                Ok(())
            }
            Ok(Err(e)) => {
                // P6-CLI-D-03 (defence in depth): this is a catch-all for error
                // strings built anywhere in the tunnel stack. Individual sites redact
                // their own endpoints, but sanitising here means a future format!()
                // that forgets cannot reintroduce the leak.
                tracing::error!(
                    "Tunnel creation/start failed: {}",
                    crate::utils::redact::sanitize_error(&e)
                );
                let err = VpnError::General(e);
                let _ = self
                    .write_state_with_timeout(ConnectionState::Error(err.to_string()))
                    .await;
                // Un-park BEFORE lifting the IPv6 block, never the reverse: the
                // reverse leaves an interval with the physical resolvers back and
                // egress already clear.
                #[cfg(target_os = "windows")]
                self.release_machine_state_after_failed_connect(transition_gen)
                    .await;
                self.lift_ipv6_block_after_failed_connect().await;
                Err(err.to_string())
            }
            Err(_) => {
                let err = VpnError::General(format!(
                    "Connection timed out after {}s",
                    CONNECT_TIMEOUT.as_secs()
                ));
                tracing::error!("{}", err);
                let _ = self
                    .write_state_with_timeout(ConnectionState::Error(err.to_string()))
                    .await;
                // CONNECT_TIMEOUT cancelled start() mid-await and dropped the
                // half-built tunnel; if it had already claimed, its Drop released
                // and this is a no-op. If it never got that far, the generation
                // held across the teardown still owns the park.
                #[cfg(target_os = "windows")]
                self.release_machine_state_after_failed_connect(transition_gen)
                    .await;
                self.lift_ipv6_block_after_failed_connect().await;
                Err(err.to_string())
            }
        }
    }

    /// A connect that never produced a live tunnel must not leave the machine's
    /// resolvers parked or our routes installed either.
    ///
    /// A no-op unless `gen` is still the owner — if the new tunnel got as far as
    /// claiming and was then dropped, its own `Drop` already released, and
    /// re-releasing from here would be a second owner acting on state it does not
    /// hold.
    #[cfg(target_os = "windows")]
    async fn release_machine_state_after_failed_connect(
        &self,
        gen: crate::vpn::win_machine_state::Gen,
    ) {
        if crate::vpn::win_machine_state::release_all(gen) {
            tracing::info!("Un-parked the physical adapters after a failed connect");
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
    /// SM-002: Uses operation lock to prevent concurrent connect/disconnect
    /// STATE-FIX: Wraps tunnel stop in a 15s timeout with forced cleanup.
    /// A stuck Disconnecting state is worse than a dirty Disconnected state.
    pub async fn disconnect(&self) -> Result<(), String> {
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

        // I2/I3: `can_disconnect()` is false in `Disconnected`, `Disconnecting`
        // and `KillSwitchActive`, and `ConnectionState` is written by paths that
        // never touch `self.tunnel` — so returning on the state alone made an
        // orphaned live tunnel unreachable by any user action. Take the record
        // into account: if there IS a tunnel, disconnect means something no
        // matter what the state claims.
        if !current_state.can_disconnect() && !self.holds_tunnel().await {
            tracing::debug!("Already disconnected or disconnecting");
            return Ok(());
        }

        let _ = self
            .write_state_with_timeout(ConnectionState::Disconnecting)
            .await;

        tracing::info!("Disconnecting from VPN");

        // STATE-FIX: Wrap entire tunnel stop in a 15s timeout.
        // If tunnel.stop() hangs (e.g. netsh deadlocks on UAC/antivirus), we
        // force transition to Disconnected rather than staying stuck forever.
        let stop_result = match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
            Ok(mut guard) => {
                if let Some(tunnel) = guard.take() {
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

        // STATE-FIX: ALWAYS transition to Disconnected, even on error.
        // A stuck Disconnecting state blocks all future operations.
        let _ = self
            .write_state_with_timeout(ConnectionState::Disconnected)
            .await;

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
    /// Connected)` and so is false in exactly the four states where an orphan
    /// can exist.
    ///
    /// It is NOT the I3 machine-state predicate, and must not be used as one.
    /// I3 asks whether the parked DNS and the installed routes are in force, and
    /// this `Option` is emptied by `connect()` itself — deliberately, into
    /// `displaced` — for the whole create + handshake window, during which the
    /// park is very much still in force under a generation the manager holds.
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

    /// Update bandwidth stats (called periodically)
    pub async fn update_stats(&self) {
        match timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            Ok(tunnel_guard) => {
                if let Some(tunnel) = tunnel_guard.as_ref() {
                    let (sent, received, pkts_sent, pkts_received) = tunnel.get_stats();
                    let latency = tunnel.get_latency_ms().await;
                    match timeout(STATE_LOCK_TIMEOUT, self.stats.write()).await {
                        Ok(mut stats) => {
                            stats.bytes_sent = sent;
                            stats.bytes_received = received;
                            stats.packets_sent = pkts_sent;
                            stats.packets_received = pkts_received;
                            // P1-dk-fabricated-quality-telemetry: only OVERWRITE
                            // the latency when the tunnel actually measured one.
                            // The tunnel probe is idle in production, so blindly
                            // assigning here reset a real measurement (the
                            // heartbeat RTT recorded by auto_reconnect.rs) back
                            // to None on every 2s stats poll.
                            if let Some(lat) = latency {
                                stats.latency_ms = Some(lat);
                            }
                        }
                        Err(_) => tracing::error!("Stats write lock timeout in update_stats"),
                    }
                }
            }
            Err(_) => tracing::error!("Tunnel read lock timeout in update_stats"),
        }
    }

    /// Measure latency to the VPN server.
    ///
    /// DT-6: the `measure_vpn_latency` IPC command that called this was removed
    /// (never invoked from the UI). Retained because it is still exercised by a
    /// unit test and remains a useful manager-level accessor; allow dead_code in
    /// non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn measure_latency(&self) -> Option<u32> {
        match timeout(STATE_LOCK_TIMEOUT, self.tunnel.read()).await {
            Ok(tunnel_guard) => {
                if let Some(tunnel) = tunnel_guard.as_ref() {
                    tunnel.measure_latency().await
                } else {
                    None
                }
            }
            Err(_) => {
                tracing::error!("Tunnel read lock timeout in measure_latency");
                None
            }
        }
    }
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for VpnManager {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            stats: Arc::clone(&self.stats),
            tunnel: Arc::clone(&self.tunnel),
            current_config: Arc::clone(&self.current_config),
            operation_lock: Arc::clone(&self.operation_lock),
            user_initiated_disconnect: Arc::clone(&self.user_initiated_disconnect),
        }
    }
}
