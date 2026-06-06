//! Auto-reconnect service for VPN connections
//!
//! Monitors VPN connection health and automatically attempts reconnection
//! when the connection drops unexpectedly.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::AppHandle;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;

// FIX-1-1: Client-side keygen for auto-reconnect
use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::manager::{ConnectionState, VpnManager};
use crate::api::types::{ConnectResponse, MultiHopConnectResponse};
use crate::api::{ApiError, BirdoApi};

/// H-5 FIX: Instead of storing the full VpnConfig (which has zeroized keys),
/// store only the metadata needed to request fresh keys from the backend.
#[derive(Debug, Clone)]
pub struct ReconnectInfo {
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
    /// Exit node for multi-hop reconnects. None means a normal single-hop reconnect.
    pub multi_hop_exit_node_id: Option<String>,
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

/// Auto-reconnect service
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

    /// Current reconnect attempt count
    attempt_count: Arc<AtomicU32>,

    /// Whether we're currently in reconnect mode
    is_reconnecting: Arc<AtomicBool>,

    /// Channel to stop the health check loop
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,

    /// Whether the service is running
    running: Arc<AtomicBool>,

    /// STATE-FIX: When true, the user explicitly disconnected — do NOT auto-reconnect.
    user_disconnected: Arc<AtomicBool>,
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
            attempt_count: Arc::new(AtomicU32::new(0)),
            is_reconnecting: Arc::new(AtomicBool::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            user_disconnected: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Update auto-reconnect configuration
    pub async fn set_config(&self, config: AutoReconnectConfig) {
        *self.config.write().await = config;
    }

    /// Attach the Tauri app handle after setup so reconnects can start Xray.
    pub fn set_app_handle(&self, app: AppHandle) {
        match self.app_handle.write() {
            Ok(mut guard) => *guard = Some(app),
            Err(_) => tracing::warn!("Auto-reconnect app handle lock poisoned"),
        }
    }

    /// Enable or disable auto-reconnect
    pub async fn set_enabled(&self, enabled: bool) {
        self.config.write().await.enabled = enabled;
        tracing::info!(
            "Auto-reconnect {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Check if auto-reconnect is enabled
    pub async fn is_enabled(&self) -> bool {
        self.config.read().await.enabled
    }

    /// H-5 FIX: Store only the reconnect metadata (server_id + name).
    /// The full VpnConfig with key material is NOT stored because keys are
    /// zeroized after WireGuard session creation. Reconnect fetches fresh keys.
    pub async fn store_last_config(
        &self,
        server_id: String,
        server_name: String,
        local_network_sharing: bool,
        custom_mtu: u16,
        custom_port: String,
        custom_dns: Option<Vec<String>>,
        stealth_mode: bool,
        quantum_protection: bool,
        multi_hop_exit_node_id: Option<String>,
    ) {
        let server_name_log = server_name.clone();
        *self.last_reconnect_info.write().await = Some(ReconnectInfo {
            server_id,
            server_name,
            local_network_sharing,
            custom_mtu,
            custom_port,
            custom_dns,
            stealth_mode,
            quantum_protection,
            multi_hop_exit_node_id,
        });
        self.attempt_count.store(0, Ordering::SeqCst);
        tracing::debug!("Stored reconnect info for: {}", server_name_log);
    }

    /// Clear stored config (called on intentional disconnect)
    pub async fn clear_last_config(&self) {
        *self.last_reconnect_info.write().await = None;
        self.attempt_count.store(0, Ordering::SeqCst);
        self.is_reconnecting.store(false, Ordering::SeqCst);
    }

    /// STATE-FIX: Call this when user manually disconnects
    pub fn set_user_disconnected(&self) {
        self.user_disconnected.store(true, Ordering::SeqCst);
        self.attempt_count.store(0, Ordering::SeqCst);
        self.is_reconnecting.store(false, Ordering::SeqCst);
        tracing::debug!("User-initiated disconnect flag set — auto-reconnect suppressed");
    }

    /// STATE-FIX: Call this when user manually connects
    pub fn clear_user_disconnected(&self) {
        self.user_disconnected.store(false, Ordering::SeqCst);
        tracing::debug!("User-initiated disconnect flag cleared");
    }

    /// Start the health check monitoring loop
    pub async fn start(&self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx);
        self.running.store(true, Ordering::SeqCst);

        let config = Arc::clone(&self.config);
        let vpn_manager = Arc::clone(&self.vpn_manager);
        let last_reconnect_info = Arc::clone(&self.last_reconnect_info);
        let api = Arc::clone(&self.api);
        let app_handle = Arc::clone(&self.app_handle);
        let attempt_count = Arc::clone(&self.attempt_count);
        let is_reconnecting = Arc::clone(&self.is_reconnecting);
        let running = Arc::clone(&self.running);
        let user_disconnected = Arc::clone(&self.user_disconnected);

        tokio::spawn(async move {
            Self::health_check_loop(
                config,
                vpn_manager,
                last_reconnect_info,
                api,
                app_handle,
                attempt_count,
                is_reconnecting,
                running,
                user_disconnected,
                shutdown_rx,
            )
            .await;
        });

        tracing::info!("Auto-reconnect service started");
        Ok(())
    }

    /// Stop the health check monitoring loop
    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(()).await;
        }
        self.running.store(false, Ordering::SeqCst);
        self.is_reconnecting.store(false, Ordering::SeqCst);
        tracing::info!("Auto-reconnect service stopped");
    }

    /// Health check loop - monitors connection and triggers reconnect
    async fn health_check_loop(
        config: Arc<RwLock<AutoReconnectConfig>>,
        vpn_manager: Arc<VpnManager>,
        last_reconnect_info: Arc<RwLock<Option<ReconnectInfo>>>,
        api: Arc<BirdoApi>,
        app_handle: Arc<std::sync::RwLock<Option<AppHandle>>>,
        attempt_count: Arc<AtomicU32>,
        is_reconnecting: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        user_disconnected: Arc<AtomicBool>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        // Import killswitch here to avoid circular module dependency at struct level
        use crate::commands::killswitch;

        let check_interval = config.read().await.health_check_interval_ms;
        let mut interval = interval(Duration::from_millis(check_interval));
        // FIX-2-13: Heartbeat counter — send heartbeat every ~30s (6 ticks × 5s)
        let mut heartbeat_tick_count: u32 = 0;
        const HEARTBEAT_EVERY_N_TICKS: u32 = 6;
        // P2-15: Quality report counter — send every ~60s (12 ticks × 5s)
        let mut quality_tick_count: u32 = 0;
        const QUALITY_EVERY_N_TICKS: u32 = 12;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::debug!("Health check loop received shutdown signal");
                    break;
                }
                _ = interval.tick() => {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }

                    // STATE-FIX: If user explicitly disconnected, skip all reconnect logic
                    if user_disconnected.load(Ordering::SeqCst) {
                        continue;
                    }

                    let state = vpn_manager.get_state().await;
                    let cfg = config.read().await.clone();

                    match state {
                        ConnectionState::Connected => {
                            // Reset attempt count on successful connection
                            if is_reconnecting.load(Ordering::SeqCst) {
                                tracing::info!("Reconnection successful");
                                is_reconnecting.store(false, Ordering::SeqCst);
                                attempt_count.store(0, Ordering::SeqCst);

                                // Deactivate kill switch now that we're connected
                                let _ = killswitch::deactivate_killswitch().await;
                            }

                            // FIX-2-13: Periodic heartbeat to backend while connected.
                            // Reports session liveness so backend can detect orphaned keys.
                            // P1-9: Parse response — disconnect if session invalid.
                            heartbeat_tick_count += 1;
                            if heartbeat_tick_count >= HEARTBEAT_EVERY_N_TICKS {
                                heartbeat_tick_count = 0;
                                if let Some(key_id) = vpn_manager.get_key_id().await {
                                    match api.heartbeat(&key_id).await {
                                        Ok(resp) => {
                                            if !resp.valid {
                                                tracing::warn!("Heartbeat: session invalidated by server — disconnecting");
                                                let _ = vpn_manager.disconnect().await;
                                                let _ = vpn_manager.set_state(
                                                    ConnectionState::Error("Session expired — please reconnect".to_string())
                                                ).await;
                                                *last_reconnect_info.write().await = None;
                                            } else if !resp.server_online {
                                                tracing::warn!("Heartbeat: server going offline");
                                            } else {
                                                tracing::debug!("Heartbeat sent for key {}", key_id);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Heartbeat failed: {}", e);
                                        }
                                    }
                                }
                            }

                            // P2-15: Periodic quality telemetry reporting
                            quality_tick_count += 1;
                            if quality_tick_count >= QUALITY_EVERY_N_TICKS {
                                quality_tick_count = 0;
                                let stats = vpn_manager.get_stats().await;
                                if let Some(ref key_id) = stats.key_id {
                                    let connected_secs = stats.connected_at
                                        .map(|t| (chrono::Utc::now() - t).num_seconds().max(0) as u64)
                                        .unwrap_or(0);
                                    // P2-16: Use real jitter and packet loss from rolling stats
                                    let jitter = stats.jitter_ms();
                                    let loss = stats.packet_loss_percent();
                                    let report = crate::api::types::QualityReport {
                                        key_id: key_id.clone(),
                                        latency_ms: stats.latency_ms.unwrap_or(0) as f64,
                                        jitter_ms: jitter,
                                        packet_loss_percent: loss,
                                        bytes_in: stats.bytes_received,
                                        bytes_out: stats.bytes_sent,
                                        handshake_age_seconds: connected_secs,
                                        connection_state: "connected".to_string(),
                                        platform: std::env::consts::OS.to_string(),
                                    };
                                    // Snapshot packet counters for the next loss window
                                    {
                                        let mut stats_w = vpn_manager.stats.write().await;
                                        stats_w.snapshot_packets();
                                    }
                                    if let Err(e) = api.report_quality(&report).await {
                                        tracing::debug!("Quality report failed (non-fatal): {}", e);
                                    }
                                }
                            }
                        }
                        ConnectionState::Disconnected => {
                            // Clone reconnect info atomically to prevent TOCTOU race condition
                            let info_snapshot = last_reconnect_info.read().await.clone();

                            // Check if we should auto-reconnect
                            if cfg.enabled && info_snapshot.is_some() {
                                let attempts = attempt_count.load(Ordering::SeqCst);

                                if cfg.max_attempts == 0 || attempts < cfg.max_attempts {
                                    // Trigger reconnect
                                    is_reconnecting.store(true, Ordering::SeqCst);

                                    // SECURITY FIX (PB-4): Handle kill switch activation failure.
                                    match killswitch::activate_killswitch().await {
                                        Ok(_) => {
                                            tracing::info!("Kill switch activated for reconnect protection");
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Kill switch activation failed during reconnect: {}. \
                                                 Aborting reconnect to prevent traffic leak.",
                                                e
                                            );
                                            is_reconnecting.store(false, Ordering::SeqCst);
                                            continue;
                                        }
                                    }

                                    // Calculate delay with exponential backoff
                                    let delay = Self::calculate_backoff(
                                        attempts,
                                        cfg.initial_delay_ms,
                                        cfg.max_delay_ms,
                                        cfg.backoff_multiplier,
                                    );

                                    tracing::info!(
                                        "Auto-reconnect attempt {} (delay: {}ms)",
                                        attempts + 1,
                                        delay
                                    );

                                    // Set Reconnecting state so the UI can show progress
                                    let _ = vpn_manager.set_state(
                                        ConnectionState::Reconnecting { attempt: attempts + 1 }
                                    ).await;

                                    tokio::time::sleep(Duration::from_millis(delay)).await;

                                    // H-5 FIX: Fetch fresh VPN config from API instead of reusing
                                    // zeroized key material. The stored ReconnectInfo only has
                                    // server_id + server_name — keys are fetched fresh each time.
                                    if let Some(ref info) = info_snapshot {
                                        attempt_count.fetch_add(1, Ordering::SeqCst);

                                        // FIX-1-6: Flush DNS cache before reconnect to prevent
                                        // stale DNS entries from leaking through the system resolver
                                        // during the brief window before the new tunnel's DNS is set.
                                        #[cfg(target_os = "windows")]
                                        { let _ = crate::utils::hidden_cmd("ipconfig").args(["/flushdns"]).output(); }
                                        #[cfg(target_os = "macos")]
                                        { let _ = std::process::Command::new("dscacheutil").args(["-flushcache"]).output(); }
                                        #[cfg(target_os = "linux")]
                                        { let _ = std::process::Command::new("resolvectl").args(["flush-caches"]).output(); }

                                        let device_name = hostname::get()
                                            .map(|h| h.to_string_lossy().to_string())
                                            .unwrap_or_else(|_| "Windows PC".to_string());

                                        // FIX-1-1: Generate fresh keypair for reconnect too
                                        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
                                        let public = PublicKey::from(&secret);
                                        let mut private_key_bytes = secret.to_bytes();
                                        // AR-1 FIX: Use `mut` so we can zeroize the base64-encoded
                                        // private key on error paths (it's moved on success path).
                                        let mut local_private_key = base64::engine::general_purpose::STANDARD.encode(&private_key_bytes);
                                        let client_public_key = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
                                        private_key_bytes.zeroize();

                                        let pq_pk = if info.quantum_protection {
                                            match crate::vpn::birdo_pq::get_client_public_key_b64() {
                                                Some(pk) => Some(pk),
                                                None => {
                                                    tracing::error!(
                                                        "Post-quantum engine unavailable during auto-reconnect; refusing downgrade"
                                                    );
                                                    local_private_key.zeroize();
                                                    continue;
                                                }
                                            }
                                        } else {
                                            None
                                        };

                                        let response_result = Self::request_fresh_response(
                                            &api,
                                            info,
                                            &device_name,
                                            client_public_key,
                                            pq_pk,
                                        ).await;

                                        match response_result {
                                            Ok(response) => {
                                                // Re-check user disconnect flag before committing
                                                if user_disconnected.load(Ordering::SeqCst) {
                                                    tracing::info!("User disconnected during reconnect — aborting");
                                                    local_private_key.zeroize();
                                                    continue;
                                                }

                                                if let Err(e) = crate::commands::vpn::enforce_requested_protection(
                                                    &response,
                                                    info.stealth_mode,
                                                    info.quantum_protection,
                                                ) {
                                                    tracing::error!("Auto-reconnect aborted: {}", e);
                                                    local_private_key.zeroize();
                                                    continue;
                                                }

                                                let stealth_endpoint_override = match Self::start_stealth_for_reconnect(
                                                    &app_handle,
                                                    &response,
                                                    info.stealth_mode,
                                                ).await {
                                                    Ok(endpoint) => endpoint,
                                                    Err(e) => {
                                                        tracing::error!("Auto-reconnect stealth setup failed: {}", e);
                                                        local_private_key.zeroize();
                                                        continue;
                                                    }
                                                };

                                                let upstream_endpoint_for_killswitch = if stealth_endpoint_override.is_some() {
                                                    response.xray_endpoint.clone().or_else(|| response.endpoint.clone())
                                                } else {
                                                    None
                                                };

                                                let quantum_psk = match crate::commands::vpn::derive_quantum_psk(&response) {
                                                    Ok(psk) => psk,
                                                    Err(e) => {
                                                        tracing::error!("Auto-reconnect PQ setup failed: {}", e);
                                                        local_private_key.zeroize();
                                                        continue;
                                                    }
                                                };

                                                // Use the shared config builder — pass local private key
                                                // P3-3: Pass custom MTU, port, and DNS so reconnects honour user settings
                                                match crate::commands::vpn::build_vpn_config(response, &info.server_id, info.custom_dns.clone(), Some(local_private_key), info.custom_mtu, &info.custom_port) {
                                                    Ok((mut config, _name)) => {
                                                        // local_private_key moved into config → WireGuardSession
                                                        // handles zeroization from here
                                                        if let Some(ref stealth_endpoint) = stealth_endpoint_override {
                                                            config.endpoint = stealth_endpoint.clone();
                                                        }
                                                        if let Some(ref psk) = quantum_psk {
                                                            config.preshared_key = Some(psk.clone());
                                                        }

                                                        let killswitch_endpoint = upstream_endpoint_for_killswitch
                                                            .as_deref()
                                                            .unwrap_or(&config.endpoint);
                                                        if let Some(ip) = crate::commands::vpn::parse_endpoint_ip(killswitch_endpoint) {
                                                            crate::commands::killswitch::set_vpn_server_ip(Some(ip)).await;
                                                            #[cfg(target_os = "windows")]
                                                            if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
                                                                tracing::warn!("Failed to update WFP VPN server during reconnect: {}", e);
                                                            }
                                                        }

                                                        match vpn_manager.connect(config, info.server_name.clone(), info.local_network_sharing).await {
                                                            Ok(_) => {
                                                                tracing::info!("Auto-reconnect successful on attempt {}", attempts + 1);
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!("Auto-reconnect tunnel failed on attempt {}: {}", attempts + 1, e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!("Auto-reconnect config build failed: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                // AR-1 FIX: Zeroize key material on API error path
                                                local_private_key.zeroize();
                                                tracing::warn!("Auto-reconnect API call failed on attempt {}: {}", attempts + 1, e);
                                            }
                                        }
                                    }
                                } else {
                                    // Max attempts reached
                                    if is_reconnecting.load(Ordering::SeqCst) {
                                        tracing::error!(
                                            "Auto-reconnect failed after {} attempts, giving up",
                                            cfg.max_attempts
                                        );
                                        is_reconnecting.store(false, Ordering::SeqCst);
                                    }
                                }
                            }
                        }
                        ConnectionState::Error(ref error_msg) => {
                            // STATE-001: Error state should trigger recovery
                            let info_snapshot = last_reconnect_info.read().await.clone();

                            if cfg.enabled && info_snapshot.is_some() {
                                let attempts = attempt_count.load(Ordering::SeqCst);

                                tracing::warn!(
                                    "Connection error detected: {}, attempting recovery (attempt {})",
                                    error_msg,
                                    attempts + 1
                                );

                                if cfg.max_attempts == 0 || attempts < cfg.max_attempts {
                                    // SECURITY FIX (PB-4): Handle kill switch activation failure.
                                    // If kill switch fails during error recovery, abort to prevent leak.
                                    match killswitch::activate_killswitch().await {
                                        Ok(_) => {
                                            tracing::info!("Kill switch activated for error recovery");
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Kill switch activation failed during error recovery: {}. \
                                                 Aborting to prevent traffic leak.",
                                                e
                                            );
                                            is_reconnecting.store(false, Ordering::SeqCst);
                                            continue;
                                        }
                                    }

                                    // Clean disconnect to reset state machine to Disconnected
                                    let _ = vpn_manager.disconnect().await;

                                    // The next loop iteration will see Disconnected state
                                    // and trigger the normal reconnect logic
                                    is_reconnecting.store(true, Ordering::SeqCst);
                                } else {
                                    tracing::error!(
                                        "Error recovery failed after {} attempts, giving up",
                                        cfg.max_attempts
                                    );
                                    is_reconnecting.store(false, Ordering::SeqCst);
                                    // Deactivate kill switch since we're giving up
                                    let _ = killswitch::deactivate_killswitch().await;
                                }
                            }
                        }
                        _ => {
                            // Connecting or Disconnecting - wait
                        }
                    }
                }
            }
        }
    }

    /// Calculate backoff delay with exponential growth
    fn calculate_backoff(
        attempts: u32,
        initial_delay: u64,
        max_delay: u64,
        multiplier: f64,
    ) -> u64 {
        let delay = initial_delay as f64 * multiplier.powi(attempts as i32);
        (delay as u64).min(max_delay)
    }

    async fn request_fresh_response(
        api: &BirdoApi,
        info: &ReconnectInfo,
        device_name: &str,
        client_public_key: String,
        pq_client_public_key: Option<String>,
    ) -> Result<ConnectResponse, ApiError> {
        if let Some(exit_node_id) = info.multi_hop_exit_node_id.as_deref() {
            let response = api
                .connect_multi_hop(
                    &info.server_id,
                    exit_node_id,
                    device_name,
                    &client_public_key,
                    info.stealth_mode,
                    info.quantum_protection,
                    pq_client_public_key,
                )
                .await?;
            Ok(Self::multi_hop_response_to_connect_response(response))
        } else {
            api.connect_vpn(
                &info.server_id,
                device_name,
                Some(client_public_key),
                if info.stealth_mode { Some(true) } else { None },
                if info.quantum_protection {
                    Some(true)
                } else {
                    None
                },
                pq_client_public_key,
            )
            .await
        }
    }

    async fn start_stealth_for_reconnect(
        app_handle: &Arc<std::sync::RwLock<Option<AppHandle>>>,
        response: &ConnectResponse,
        stealth_requested: bool,
    ) -> Result<Option<String>, String> {
        if !stealth_requested && !response.stealth_enabled.unwrap_or(false) {
            return Ok(None);
        }

        let app = app_handle
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| {
                "Stealth reconnect requested but the app runtime is unavailable; refusing downgrade."
                    .to_string()
            })?;

        crate::commands::vpn::start_stealth_tunnel(&app, response).await
    }

    fn multi_hop_response_to_connect_response(
        response: MultiHopConnectResponse,
    ) -> ConnectResponse {
        ConnectResponse {
            success: response.success,
            message: response.message,
            error_code: None,
            config: response.config,
            key_id: response.key_id,
            private_key: response.private_key,
            public_key: response.public_key,
            preshared_key: response.preshared_key,
            assigned_ip: response.assigned_ip,
            client_ipv6: response.client_ipv6.clone(),
            server_public_key: response.server_public_key,
            endpoint: response.endpoint,
            dns: response.dns,
            allowed_ips: response.allowed_ips,
            mtu: response.mtu,
            persistent_keepalive: response.persistent_keepalive,
            server_node: None,
            stealth_enabled: response.stealth_enabled,
            xray_endpoint: response.xray_endpoint,
            xray_uuid: response.xray_uuid,
            xray_public_key: response.xray_public_key,
            xray_short_id: response.xray_short_id,
            xray_sni: response.xray_sni,
            xray_flow: response.xray_flow,
            quantum_enabled: response.quantum_enabled,
            rosenpass_public_key: response.rosenpass_public_key,
            rosenpass_endpoint: response.rosenpass_endpoint,
        }
    }

    /// Get current reconnect status
    pub fn get_status(&self) -> AutoReconnectStatus {
        AutoReconnectStatus {
            is_reconnecting: self.is_reconnecting.load(Ordering::SeqCst),
            attempt_count: self.attempt_count.load(Ordering::SeqCst),
            is_running: self.running.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AutoReconnectStatus {
    pub is_reconnecting: bool,
    pub attempt_count: u32,
    pub is_running: bool,
}

impl Clone for AutoReconnectService {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            vpn_manager: Arc::clone(&self.vpn_manager),
            last_reconnect_info: Arc::clone(&self.last_reconnect_info),
            api: Arc::clone(&self.api),
            app_handle: Arc::clone(&self.app_handle),
            attempt_count: Arc::clone(&self.attempt_count),
            is_reconnecting: Arc::clone(&self.is_reconnecting),
            shutdown_tx: Arc::clone(&self.shutdown_tx),
            running: Arc::clone(&self.running),
            user_disconnected: Arc::clone(&self.user_disconnected),
        }
    }
}
