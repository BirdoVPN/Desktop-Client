//! Network connectivity monitor for Windows.
//!
//! Periodically checks system network availability using the Windows
//! NLM (Network List Manager) COM API conceptually, but implemented
//! via a simpler DNS probe to avoid heavyweight COM dependencies.
//!
//! Emits connectivity state changes that the auto-reconnect module
//! uses to pause/resume reconnection attempts.
//!
//! Wired into `auto_reconnect.rs`: the health-check loop subscribes to this
//! monitor so an offline machine does not burn its finite reconnect budget (and
//! then tear down the kill switch) while it was never going to succeed, and
//! reconnects promptly when connectivity returns. A couple of pure accessors
//! (`current`, `stop`) are retained for completeness though not every call site
//! uses them, so keep the module-level dead-code allowance.
#![allow(dead_code)]

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

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
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
                    if let Err(e) = tx.send(new_state) {
                        tracing::warn!(
                            "Failed to broadcast connectivity change (no active receivers): {}",
                            e
                        );
                    }
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

/// Probe connectivity with a real TCP handshake to well-known anycast resolvers
/// on :443. Uses multiple IPs to avoid single-point failures.
///
/// Deliberately NOT a DNS lookup: `lookup_host("1.1.1.1:443")` parses an IP
/// literal and returns instantly WITHOUT touching the network, so it would
/// report "online" even with the cable unplugged. A TCP connect is a genuine
/// reachability test. It also works while the kill-switch block-all is active:
/// the connect originates in THIS process (which the block permits by
/// ALE_APP_ID), whereas a getaddrinfo lookup would be serviced by the DNS Client
/// service — a different process — and denied, which would falsely read as
/// "offline" and deadlock the reconnect pause.
///
/// WHAT THE PROBE DISCLOSES. No user PAYLOAD crosses it, but the metadata is not
/// nothing and the docstring used to claim otherwise. While the tunnel is down
/// and the block-all is engaged — the window the kill switch exists for — this
/// SYN leaves over the physical NIC, so Cloudflare, then Quad9, then Google each
/// see the user's real address on a 5-second cadence for as long as the pause
/// lasts. That is deliberate rather than accidental, for two reasons:
///
///   * These are not new counterparties. The control-plane resolver already
///     reaches exactly these three operators over HTTPS for every
///     `api.birdo.app` resolution (`vpn::doh::DOH_PROVIDERS` —
///     cloudflare-dns.com, dns.google, dns.quad9.net), so dropping them here
///     would not stop the client talking to them.
///   * Every alternative target is worse. The VPN relay is only contractually a
///     WireGuard UDP listener, so a TCP probe at it can fail permanently on a
///     node with no :443 service — and a probe that can never succeed turns the
///     offline→online edge in `auto_reconnect` into a reconnect that never
///     fires. Our own control plane needs DNS, which the block-all denies to the
///     DNS Client service, and pointing a fixed 5-second bare-TCP beacon at our
///     own edge trades one signal for a per-client SYN cadence against our own
///     DDoS protection.
///
/// If this is ever revisited, the fix is to stop probing on a fixed interval at
/// all (back off hard once Offline is established) rather than to swap the
/// addresses.
async fn check_connectivity() -> bool {
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    // Bound each connect so a blackhole route cannot hang the check. Keeps the
    // check interval and stop() responsive.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

    let probes = ["1.1.1.1:443", "9.9.9.9:443", "8.8.8.8:443"];
    for probe in probes {
        if let Ok(Ok(_stream)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(probe)).await {
            return true;
        }
    }
    false
}
