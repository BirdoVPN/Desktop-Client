//! VPN Manager
//!
//! High-level VPN connection management with deadlock prevention (SM-002).
//!
//! # Security Notes
//! - Uses timeout-based lock acquisition to prevent deadlocks
//! - State transitions are validated to prevent illegal states
//! - Operation lock prevents concurrent connect/disconnect races

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;
use tokio::sync::{RwLock, Mutex as TokioMutex};
use tokio::time::timeout;

// Platform-specific tunnel implementation
#[cfg(target_os = "windows")]
use super::tunnel::WintunTunnel as PlatformTunnel;
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
    Reconnecting { attempt: u32 },
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
        matches!(self, 
            ConnectionState::Disconnected | 
            ConnectionState::Error(_) |
            ConnectionState::KillSwitchActive |
            ConnectionState::Reconnecting { .. }
        )
    }
    
    /// Check if disconnect is meaningful in this state
    pub fn can_disconnect(&self) -> bool {
        !matches!(self, ConnectionState::Disconnected | ConnectionState::Disconnecting | ConnectionState::KillSwitchActive)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub latency_ms: Option<u32>,
    /// P2-16: Rolling latency samples for jitter calculation (stddev).
    pub latency_samples: Vec<u32>,
    /// P2-16: Packets sent at last quality report (for loss estimation).
    pub prev_packets_sent: u64,
    /// P2-16: Packets received at last quality report (for loss estimation).
    pub prev_packets_received: u64,
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    pub server_id: Option<String>,
    pub key_id: Option<String>,
    pub server_name: Option<String>,
}

impl ConnectionStats {
    /// P2-16: Compute jitter as standard deviation of recent latency samples.
    pub fn jitter_ms(&self) -> f64 {
        if self.latency_samples.len() < 2 {
            return 0.0;
        }
        let mean = self.latency_samples.iter().map(|&s| s as f64).sum::<f64>()
            / self.latency_samples.len() as f64;
        let variance = self.latency_samples.iter()
            .map(|&s| { let d = s as f64 - mean; d * d })
            .sum::<f64>() / self.latency_samples.len() as f64;
        variance.sqrt()
    }

    /// P2-16: Estimate packet loss percentage since last report window.
    pub fn packet_loss_percent(&self) -> f64 {
        let sent_delta = self.packets_sent.saturating_sub(self.prev_packets_sent);
        let recv_delta = self.packets_received.saturating_sub(self.prev_packets_received);
        if sent_delta == 0 {
            return 0.0;
        }
        let lost = sent_delta.saturating_sub(recv_delta);
        (lost as f64 / sent_delta as f64) * 100.0
    }

    /// Push a latency sample, keeping at most 20 entries.
    pub fn push_latency_sample(&mut self, ms: u32) {
        self.latency_samples.push(ms);
        if self.latency_samples.len() > 20 {
            self.latency_samples.remove(0);
        }
    }

    /// Snapshot the current packet counters for the next loss calculation window.
    pub fn snapshot_packets(&mut self) {
        self.prev_packets_sent = self.packets_sent;
        self.prev_packets_received = self.packets_received;
    }
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
                latency_samples: Vec::new(),
                prev_packets_sent: 0,
                prev_packets_received: 0,
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
        self.user_initiated_disconnect.store(value, AtomicOrdering::SeqCst);
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
    async fn write_state_with_timeout(&self, new_state: ConnectionState) -> Result<ConnectionState, VpnError> {
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
        self.read_state_with_timeout().await.unwrap_or(ConnectionState::Error("Lock timeout".into()))
    }

    /// Set connection state (used by auto-reconnect to set Reconnecting state)
    pub async fn set_state(&self, new_state: ConnectionState) -> Result<(), String> {
        self.write_state_with_timeout(new_state).await
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
                    latency_samples: Vec::new(),
                    prev_packets_sent: 0,
                    prev_packets_received: 0,
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
        tracing::info!("VpnManager::connect called for server: {}", server_name);
        
        // FIX-R5: Clear the user-disconnected flag so auto-reconnect can work again
        self.user_initiated_disconnect.store(false, AtomicOrdering::SeqCst);
        
        // SM-002: Acquire operation lock first to prevent concurrent operations
        let _operation_guard = self.acquire_operation_lock().await
            .map_err(|e| format!("Failed to acquire operation lock: {}", e))?;
        
        // Check current state with timeout
        let current_state = self.read_state_with_timeout().await
            .map_err(|e| format!("Failed to read state: {}", e))?;
        
        tracing::debug!("Current VPN state: {:?}", current_state);
        
        // If already connected, auto-disconnect first (acts as reconnect).
        // This handles edge cases: stale state, rapid reconnect, UI race.
        if matches!(current_state, ConnectionState::Connected | ConnectionState::Connecting) {
            tracing::info!("Already {:?} — tearing down old tunnel before reconnecting", current_state);
            let _ = self.write_state_with_timeout(ConnectionState::Disconnecting).await;
            
            match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
                Ok(mut guard) => {
                    if let Some(tunnel) = guard.take() {
                        if let Err(e) = timeout(Duration::from_secs(10), tunnel.stop()).await
                            .unwrap_or(Err("Tunnel stop timed out".into()))
                        {
                            tracing::warn!("Old tunnel teardown error (continuing): {}", e);
                        }
                    }
                }
                Err(_) => {
                    tracing::error!("Tunnel lock timeout during auto-disconnect — cannot safely create new tunnel");
                    let _ = self.write_state_with_timeout(ConnectionState::Error(
                        "Tunnel lock timeout".into()
                    )).await;
                    return Err("Tunnel lock timeout during teardown — please try again".into());
                }
            }
        } else if !current_state.can_connect() {
            let err = VpnError::InvalidStateTransition {
                from: format!("{:?}", current_state),
                to: "Connecting".into(),
            };
            tracing::warn!("{}", err);
            return Err(err.to_string());
        }

        // Set connecting state with timeout
        self.write_state_with_timeout(ConnectionState::Connecting).await
            .map_err(|e| format!("Failed to set connecting state: {}", e))?;
        tracing::info!("Set state to Connecting");

        tracing::info!("Creating VPN tunnel for: {}", server_name);
        tracing::debug!("Tunnel config: endpoint={}, client_ip={}", config.endpoint, config.client_ip);

        // CONNECT-FIX: Wrap the entire tunnel creation + start in a timeout.
        // If tunnel creation or start hangs (e.g. netsh deadlocks on Windows
        // UAC prompt, or antivirus blocks wintun.dll), we fail fast instead of
        // leaving the state stuck at Connecting forever.
        let tunnel_result = timeout(CONNECT_TIMEOUT, async {
            let tunnel = PlatformTunnel::create(&config, local_network_sharing).await
                .map_err(|e| format!("Failed to create tunnel: {}", e))?;
            tunnel.start().await
                .map_err(|e| format!("Failed to start tunnel: {}", e))?;
            Ok::<PlatformTunnel, String>(tunnel)
        }).await;

        match tunnel_result {
            Ok(Ok(tunnel)) => {
                tracing::info!("Tunnel started successfully");

                // Update state with timeout protection
                let _ = self.write_state_with_timeout(ConnectionState::Connected).await;
                
                // Update tunnel reference with timeout
                match timeout(STATE_LOCK_TIMEOUT, self.tunnel.write()).await {
                    Ok(mut guard) => *guard = Some(tunnel),
                    Err(_) => tracing::error!("Tunnel write lock timeout"),
                }
                
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
                    }
                    Err(_) => tracing::error!("Stats write lock timeout"),
                }

                tracing::info!("VPN connected successfully");
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::error!("Tunnel creation/start failed: {}", e);
                let err = VpnError::General(e);
                let _ = self.write_state_with_timeout(ConnectionState::Error(err.to_string())).await;
                Err(err.to_string())
            }
            Err(_) => {
                let err = VpnError::General(format!("Connection timed out after {}s", CONNECT_TIMEOUT.as_secs()));
                tracing::error!("{}", err);
                let _ = self.write_state_with_timeout(ConnectionState::Error(err.to_string())).await;
                Err(err.to_string())
            }
        }
    }

    /// Disconnect from VPN
    /// SM-002: Uses operation lock to prevent concurrent connect/disconnect
    /// STATE-FIX: Wraps tunnel stop in a 15s timeout with forced cleanup.
    /// A stuck Disconnecting state is worse than a dirty Disconnected state.
    pub async fn disconnect(&self) -> Result<(), String> {
        // SM-002: Acquire operation lock first
        let _operation_guard = self.acquire_operation_lock().await
            .map_err(|e| format!("Failed to acquire operation lock: {}", e))?;
        
        // Check current state with timeout
        let current_state = self.read_state_with_timeout().await
            .map_err(|e| format!("Failed to read state: {}", e))?;
        
        if !current_state.can_disconnect() {
            tracing::debug!("Already disconnected or disconnecting");
            return Ok(());
        }

        let _ = self.write_state_with_timeout(ConnectionState::Disconnecting).await;

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
        let _ = self.write_state_with_timeout(ConnectionState::Disconnected).await;
        
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
                            stats.latency_ms = latency;
                            // P2-16: Push latency sample for jitter calculation
                            if let Some(lat) = latency {
                                stats.push_latency_sample(lat);
                            }
                        }
                        Err(_) => tracing::error!("Stats write lock timeout in update_stats"),
                    }
                }
            }
            Err(_) => tracing::error!("Tunnel read lock timeout in update_stats"),
        }
    }

    /// Measure latency to the VPN server
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
