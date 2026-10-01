//! The Windows packet path: Wintun ⇄ boringtun ⇄ the relay socket (W1-006).
//!
//! # Why it is shaped like this
//!
//! It used to be ONE tokio task that slept 10 µs / 500 µs / 5 ms between
//! polls. tokio sleeps at millisecond granularity at best (coarser on Windows,
//! per its own docs), so "10 µs" was really a timer-resolution wait on every
//! packet in both directions, each wake drained at most 64 packets, an RX
//! batch ended at the first keepalive or handshake datagram, every received
//! packet went through a heap `Vec`, and an idle tunnel still woke the CPU
//! ~200 times a second.
//!
//! Now nothing polls:
//!
//! * **Send** — a dedicated OS thread blocks in `Session::receive_blocking`,
//!   which waits on Wintun's read-wait event (`WintunGetReadWaitEvent`) and
//!   the session's shutdown event. It seals each packet into a buffer owned by
//!   the thread and sends it on the relay socket. `Session::shutdown` is what
//!   wakes it to exit.
//! * **Receive** — a tokio task awaiting the socket's readiness (IOCP-backed,
//!   no timer involved). Each datagram is opened into a buffer owned by the
//!   task and copied once into the Wintun send ring — no per-packet allocation.
//!   A keepalive or a handshake message no longer ends anything; the next
//!   datagram is simply awaited.
//! * **Timers** — boringtun wants `update_timers` about every 250 ms (keepalive,
//!   rekey, handshake retransmit). That interval, in the receive task, is the
//!   only periodic wake-up left: 4 per second while idle.
//!
//! Failures are counted, not logged per packet (W1-019): see [`ErrorSummary`].

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use tokio::time::{interval, timeout, MissedTickBehavior};
use wintun::Session;
use zeroize::Zeroizing;

use super::buffer_pool::{MAX_PACKET_SIZE, WIREGUARD_OVERHEAD};
use super::wireguard_new::{Opened, Outbound, WireGuardSession};

/// boringtun's timer cadence (its own device implementation uses the same).
const TIMER_INTERVAL: Duration = Duration::from_millis(250);

/// At most one line per failure kind per this interval (W1-019).
const SUMMARY_INTERVAL: Duration = Duration::from_secs(10);

/// How long `stop()` waits for each half before giving up on it.
const JOIN_CAP: Duration = Duration::from_secs(3);

/// Wintun hands out packets up to 64 KiB; the send thread's sealing buffer
/// takes the largest plus WireGuard's framing, allocated once per thread.
const MAX_SEALED: usize = u16::MAX as usize + WIREGUARD_OVERHEAD;

/// Byte and packet counters shared with `WintunTunnel::get_stats`.
#[derive(Clone)]
pub(super) struct Counters {
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub packets_sent: Arc<AtomicU64>,
    pub packets_received: Arc<AtomicU64>,
}

/// Aggregates a stream of identical failures into a few log lines (W1-019).
///
/// After a relay goes away every outbound packet fails the same way, and the
/// old per-packet `warn!` wrote thousands of identical lines a second — until
/// birdo.log hit its size cap and the rest of the session (the reconnect and
/// give-up lines included) was silently discarded. Now: the first failure is
/// logged as it happens, the rest are counted, and the count is reported at
/// most once per `window`.
pub(super) struct ErrorSummary {
    what: &'static str,
    window: Duration,
    last_line: Option<Instant>,
    suppressed: u64,
}

impl ErrorSummary {
    pub(super) fn new(what: &'static str, window: Duration) -> Self {
        Self {
            what,
            window,
            last_line: None,
            suppressed: 0,
        }
    }

    /// Record one failure; `Some(line)` when a line should be written now.
    pub(super) fn note(&mut self, now: Instant, error: &str) -> Option<String> {
        if self
            .last_line
            .is_some_and(|at| now.duration_since(at) < self.window)
        {
            self.suppressed += 1;
            return None;
        }
        let line = match std::mem::take(&mut self.suppressed) {
            0 => format!("{}: {}", self.what, error),
            n => format!(
                "{}: {} ({} more in the last {} s)",
                self.what,
                error,
                n,
                self.window.as_secs()
            ),
        };
        self.last_line = Some(now);
        Some(line)
    }

    /// Report what was counted since the last line once its window has passed,
    /// so the tail of a burst is not lost when the failures stop.
    pub(super) fn flush(&mut self, now: Instant) -> Option<String> {
        let due = self
            .last_line
            .is_some_and(|at| now.duration_since(at) >= self.window);
        if !due || self.suppressed == 0 {
            return None;
        }
        let n = std::mem::take(&mut self.suppressed);
        self.last_line = Some(now);
        Some(format!(
            "{}: {} more in the last {} s",
            self.what,
            n,
            self.window.as_secs()
        ))
    }
}

/// The two halves of a running packet path. Dropping it without `stop()`
/// leaves them running, so `WintunTunnel::stop` always stops it.
pub(super) struct DataPlane {
    session: Arc<Session>,
    running: Arc<AtomicBool>,
    shutdown: watch::Sender<bool>,
    rx_task: tokio::task::JoinHandle<()>,
    tx_thread: std::thread::JoinHandle<()>,
    tx_exited: oneshot::Receiver<()>,
}

impl DataPlane {
    /// Start both halves. Must be called from inside the tokio runtime.
    pub(super) fn start(
        session: Arc<Session>,
        wg: Arc<WireGuardSession>,
        counters: Counters,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (tx_done, tx_exited) = oneshot::channel();
        let runtime = tokio::runtime::Handle::current();

        let tx_thread = {
            let session = Arc::clone(&session);
            let wg = Arc::clone(&wg);
            let running = Arc::clone(&running);
            let counters = counters.clone();
            std::thread::Builder::new()
                .name("birdo-tunnel-tx".into())
                .spawn(move || {
                    // Signalled on every exit, a panic included.
                    let _exited = ExitSignal(Some(tx_done));
                    send_loop(&session, &wg, &running, &counters, &runtime);
                })
                .map_err(|e| format!("Failed to start the tunnel send thread: {}", e))?
        };
        let rx_task = tokio::spawn(receive_loop(
            Arc::clone(&session),
            wg,
            shutdown_rx,
            counters,
        ));

        tracing::debug!("Data plane started (event-driven send thread + receive task)");
        Ok(Self {
            session,
            running,
            shutdown,
            rx_task,
            tx_thread,
            tx_exited,
        })
    }

    /// Stop both halves and wait for them, so neither still holds the Wintun
    /// session when the caller releases the adapter — a session outliving its
    /// tunnel is what made a server switch fail to recreate the adapter.
    pub(super) async fn stop(self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown.send(true);
        // Wakes the send thread out of receive_blocking.
        if let Err(e) = self.session.shutdown() {
            tracing::warn!("Could not signal the Wintun session to shut down: {}", e);
        }

        let abort = self.rx_task.abort_handle();
        if timeout(JOIN_CAP, self.rx_task).await.is_err() {
            tracing::warn!(
                "Receive task did not exit within {:?} — aborting it",
                JOIN_CAP
            );
            abort.abort();
        }
        match timeout(JOIN_CAP, self.tx_exited).await {
            Ok(_) => {
                let thread = self.tx_thread;
                let _ = tokio::task::spawn_blocking(move || thread.join()).await;
            }
            Err(_) => tracing::error!(
                "Send thread did not exit within {:?} — the adapter may stay held",
                JOIN_CAP
            ),
        }
        tracing::debug!("Data plane stopped");
    }
}

struct ExitSignal(Option<oneshot::Sender<()>>);

impl Drop for ExitSignal {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

/// Send one datagram from outside the runtime. A UDP send only waits when the
/// socket buffer is full; then it parks this thread until the socket is
/// writable again.
fn send_blocking(
    socket: &UdpSocket,
    data: &[u8],
    runtime: &tokio::runtime::Handle,
) -> Result<(), String> {
    loop {
        match socket.try_send(data) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => runtime
                .block_on(socket.writable())
                .map_err(|e| format!("Failed to send: {}", e))?,
            Err(e) => return Err(format!("Failed to send: {}", e)),
        }
    }
}

/// Adapter → relay. Runs on its own OS thread.
fn send_loop(
    session: &Arc<Session>,
    wg: &WireGuardSession,
    running: &AtomicBool,
    counters: &Counters,
    runtime: &tokio::runtime::Handle,
) {
    let mut socket_rx = wg.subscribe_socket();
    let mut socket = socket_rx.borrow_and_update().clone();
    // Holds plaintext on its way in; wiped when the thread ends.
    let mut sealed = Zeroizing::new(vec![0u8; MAX_SEALED]);
    let mut failures = ErrorSummary::new("Tunnel send failures", SUMMARY_INTERVAL);

    loop {
        let packet = match session.receive_blocking() {
            Ok(packet) => packet,
            Err(wintun::Error::ShuttingDown) => break,
            Err(e) => {
                tracing::error!("Reading from the tunnel adapter failed: {}", e);
                break;
            }
        };
        if !running.load(Ordering::Relaxed) {
            break;
        }
        if socket_rx.has_changed().unwrap_or(false) {
            socket = socket_rx.borrow_and_update().clone();
        }

        let result = {
            let data = packet.bytes();
            counters
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            counters.packets_sent.fetch_add(1, Ordering::Relaxed);
            match wg.seal(data, &mut sealed) {
                Outbound::Send(out) => send_blocking(&socket, out, runtime),
                Outbound::Queued => Ok(()),
                Outbound::Failed(e) => Err(e),
            }
        };
        // Hand the ring slot back before anything else can wait.
        drop(packet);

        let now = Instant::now();
        if let Err(e) = result {
            if let Some(line) = failures.note(now, &e) {
                tracing::warn!("{}", line);
            }
        } else if let Some(line) = failures.flush(now) {
            tracing::warn!("{}", line);
        }
    }
    if let Some(line) = failures.flush(Instant::now() + SUMMARY_INTERVAL) {
        tracing::warn!("{}", line);
    }
    tracing::debug!("Tunnel send thread ended");
}

/// Relay → adapter, plus boringtun's timers.
async fn receive_loop(
    session: Arc<Session>,
    wg: Arc<WireGuardSession>,
    mut shutdown: watch::Receiver<bool>,
    counters: Counters,
) {
    let mut socket_rx = wg.subscribe_socket();
    let mut socket = socket_rx.borrow_and_update().clone();
    let mut datagram = Zeroizing::new(vec![0u8; MAX_PACKET_SIZE]);
    let mut plain = Zeroizing::new(vec![0u8; MAX_PACKET_SIZE]);
    let mut timer_buf = [0u8; WIREGUARD_OVERHEAD];
    let mut timers = interval(TIMER_INTERVAL);
    timers.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut receive_failures = ErrorSummary::new("Tunnel receive failures", SUMMARY_INTERVAL);
    let mut adapter_failures = ErrorSummary::new("Tunnel adapter write failures", SUMMARY_INTERVAL);
    let mut last_stats_log = Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            changed = socket_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                socket = socket_rx.borrow_and_update().clone();
                tracing::debug!("Receive path moved to the new socket");
            }
            _ = timers.tick() => {
                let now = Instant::now();
                if let Ok(Some(message)) = wg.tick_timers(&mut timer_buf) {
                    let _ = socket.send(message).await;
                }
                for summary in [&mut receive_failures, &mut adapter_failures] {
                    if let Some(line) = summary.flush(now) {
                        tracing::warn!("{}", line);
                    }
                }
                // POWER: debug and once a minute, so a release build writes
                // nothing to disk while connected.
                if now.duration_since(last_stats_log) >= Duration::from_secs(60) {
                    last_stats_log = now;
                    tracing::debug!(
                        "VPN traffic stats — TX: {} pkts / {} bytes, RX: {} pkts / {} bytes",
                        counters.packets_sent.load(Ordering::Relaxed),
                        counters.bytes_sent.load(Ordering::Relaxed),
                        counters.packets_received.load(Ordering::Relaxed),
                        counters.bytes_received.load(Ordering::Relaxed),
                    );
                }
            }
            received = socket.recv(&mut datagram) => {
                let n = match received {
                    Ok(n) => n,
                    Err(e) => {
                        // WSAECONNRESET after an ICMP port-unreachable, a
                        // network going away: the next datagram decides.
                        // The pause keeps a persistent error from spinning.
                        if let Some(line) = receive_failures.note(Instant::now(), &e.to_string()) {
                            tracing::warn!("{}", line);
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let reply = match wg.open(&datagram[..n], &mut plain) {
                    Opened::Packet(data) => {
                        counters
                            .bytes_received
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        counters.packets_received.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = write_to_adapter(&session, data) {
                            if let Some(line) = adapter_failures.note(Instant::now(), &e) {
                                tracing::warn!("{}", line);
                            }
                        }
                        false
                    }
                    Opened::Reply(message) => {
                        let _ = socket.send(message).await;
                        true
                    }
                    Opened::Nothing => false,
                };
                if reply {
                    // boringtun's contract after any WriteToNetwork: send what
                    // it queued behind the handshake.
                    while let Some(queued) = wg.next_queued(&mut plain) {
                        let _ = socket.send(queued).await;
                    }
                }
            }
        }
    }
    tracing::debug!("Tunnel receive task ended");
}

/// Copy one decrypted packet into the Wintun send ring.
fn write_to_adapter(session: &Arc<Session>, data: &[u8]) -> Result<(), String> {
    let len = u16::try_from(data.len()).map_err(|_| "packet larger than 64 KiB".to_string())?;
    let mut packet = session
        .allocate_send_packet(len)
        .map_err(|e| format!("the adapter ring is full or gone ({})", e))?;
    packet.bytes_mut().copy_from_slice(data);
    session.send_packet(packet);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W1-019: ten thousand identical failures in one second are ONE line,
    /// and the count is reported once the window passes — not dropped.
    #[test]
    fn a_failure_storm_is_one_line_then_a_count() {
        let start = Instant::now();
        let mut summary = ErrorSummary::new("Tunnel send failures", SUMMARY_INTERVAL);
        let mut lines = Vec::new();
        for i in 0..10_000u64 {
            let now = start + Duration::from_micros(i * 100);
            lines.extend(summary.note(now, "Failed to send: network unreachable"));
        }
        assert_eq!(
            lines,
            vec!["Tunnel send failures: Failed to send: network unreachable".to_string()]
        );
        // Still inside the window: nothing yet.
        assert_eq!(summary.flush(start + Duration::from_secs(5)), None);
        let tail = summary
            .flush(start + SUMMARY_INTERVAL)
            .expect("the count is reported");
        assert!(tail.contains("9999 more"), "{tail}");
        // Reported once.
        assert_eq!(summary.flush(start + SUMMARY_INTERVAL * 3), None);
    }

    /// A failure that keeps happening is reported once per window with the
    /// count it has reached — the log keeps moving, it never goes silent.
    #[test]
    fn a_persistent_failure_is_reported_once_per_window() {
        let start = Instant::now();
        let mut summary = ErrorSummary::new("Tunnel receive failures", SUMMARY_INTERVAL);
        assert!(summary.note(start, "reset").is_some());
        assert!(summary
            .note(start + Duration::from_secs(1), "reset")
            .is_none());
        assert!(summary
            .note(start + Duration::from_secs(2), "reset")
            .is_none());
        let next = summary
            .note(start + SUMMARY_INTERVAL, "reset")
            .expect("a new window starts with a line");
        assert!(next.contains("(2 more in the last 10 s)"), "{next}");
    }

    #[test]
    fn nothing_to_flush_without_failures() {
        let mut summary = ErrorSummary::new("x", SUMMARY_INTERVAL);
        assert_eq!(summary.flush(Instant::now() + SUMMARY_INTERVAL), None);
    }

    /// The sealing buffer takes any packet Wintun can hand out, plus framing.
    #[test]
    #[allow(clippy::assertions_on_constants)] // asserting the real constants IS the point
    fn the_send_buffer_fits_the_largest_wintun_packet() {
        assert!(MAX_SEALED >= u16::MAX as usize + 32);
        assert!(MAX_PACKET_SIZE >= 9000 + WIREGUARD_OVERHEAD);
    }
}
