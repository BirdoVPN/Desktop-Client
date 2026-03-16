//! Network connectivity monitor for Windows.
//!
//! Periodically checks system network availability using the Windows
//! NLM (Network List Manager) COM API conceptually, but implemented
//! via a simpler DNS probe to avoid heavyweight COM dependencies.
//!
//! Emits connectivity state changes that the auto-reconnect module
//! uses to pause/resume reconnection attempts.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::interval;

/// Current network connectivity state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityState {
    /// System has network connectivity (DNS resolves).
    Online,
    /// System has no network connectivity.
    Offline,
    /// Connectivity state has not yet been determined.
    Unknown,
}

/// Monitors system network connectivity by probing DNS resolution.
pub struct NetworkMonitor {
    is_running: Arc<AtomicBool>,
    tx: watch::Sender<ConnectivityState>,
    rx: watch::Receiver<ConnectivityState>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(ConnectivityState::Unknown);
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            tx,
            rx,
        }
    }

    /// Get a receiver that can be cloned and used to watch connectivity changes.
    pub fn subscribe(&self) -> watch::Receiver<ConnectivityState> {
        self.rx.clone()
    }

    /// Get current connectivity state without subscribing.
    pub fn current(&self) -> ConnectivityState {
        *self.rx.borrow()
    }

    /// Start the monitoring loop. Call once at startup.
    pub fn start(&self) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }
        let running = self.is_running.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(5));
            let mut last_state = ConnectivityState::Unknown;

            while running.load(Ordering::SeqCst) {
                check_interval.tick().await;

                let online = check_connectivity().await;
                let new_state = if online {
                    ConnectivityState::Online
                } else {
                    ConnectivityState::Offline
                };

                if new_state != last_state {
                    tracing::info!(
                        "Network connectivity changed: {:?} -> {:?}",
                        last_state,
                        new_state
                    );
                    let _ = tx.send(new_state);
                    last_state = new_state;
                }
            }
        });
    }

    /// Stop monitoring.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

/// Probe connectivity by attempting DNS resolution of well-known hosts.
/// Uses multiple resolvers to avoid single-point failures.
async fn check_connectivity() -> bool {
    use tokio::net::lookup_host;

    let probes = ["birdo.app:443", "1.1.1.1:443", "9.9.9.9:443"];
    for probe in probes {
        if lookup_host(probe).await.is_ok() {
            return true;
        }
    }
    false
}
