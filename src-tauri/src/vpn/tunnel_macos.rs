//! macOS utun tunnel implementation
//!
//! Creates and manages a utun virtual network interface for WireGuard VPN on macOS.
//! Uses the kernel utun interface via AF_SYSTEM sockets.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use super::wireguard_new::WireGuardSession;
use crate::api::types::VpnConfig;
use crate::utils::redact_ip;
use crate::vpn::dns_journal::DnsRestoreOutcome;

/// Run a command without visible terminal window
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// utun adapter name (assigned by macOS kernel, typically utun0, utun1, etc.)
const ADAPTER_PREFIX: &str = "utun";

/// DNS resolver config path
const RESOLVER_DIR: &str = "/etc/resolver";

/// Stores original DNS and default route info for restoration on disconnect
#[derive(Debug, Clone)]
struct NetworkSnapshot {
    /// The primary network service name (e.g. "Wi-Fi", "Ethernet")
    service_name: String,
    /// Original DNS servers
    dns_servers: Vec<String>,
    /// Original default gateway
    default_gateway: Option<String>,
    /// Original default interface
    default_interface: Option<String>,
    /// EVERY enabled network service and its original resolvers, so each can be
    /// restored exactly. Repointing only the primary service leaks: with Wi-Fi
    /// and Ethernet both active, unscoped queries can still go to the other
    /// service's ISP resolvers.
    all_dns: Vec<(String, Vec<String>)>,
}

/// Every ENABLED network service, in the order macOS prefers them.
///
/// `networksetup -listallnetworkservices` prints a header line, and prefixes
/// disabled services with `*` — both are filtered out here. Disabled services
/// carry no traffic, and calling -setdnsservers on one errors.
fn list_network_services() -> Vec<String> {
    let output = match cmd("networksetup")
        .args(["-listallnetworkservices"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(|l| l.to_string())
        .collect()
}

/// Current resolvers for one service, normalised to "empty means DHCP".
fn dns_servers_for(service: &str) -> Vec<String> {
    query_dns_servers(service).unwrap_or_default()
}

/// The same query, keeping the one distinction `dns_servers_for` throws away:
/// `None` means the QUESTION failed (no such service, networksetup missing),
/// `Some(vec![])` means the service genuinely has no manually-set resolvers.
///
/// That difference is load-bearing in the two places that decide the journal's
/// fate, and nowhere else:
///
/// 1. `set_service_dns`, verifying a restore back to DHCP. An unanswerable query
///    and "the service is now on DHCP" both look like the empty list, and
///    treating the first as the second reports a restore that never happened.
/// 2. `restore_services_pass`'s probe (via `ServiceDns::Unreadable`), deciding
///    whether a service is still on the tunnel's resolvers at all. There, the
///    lenient reading says "not on the tunnel DNS, so the user already fixed
///    it", and the record is deleted off that.
///
/// The remaining caller is snapshot CAPTURE, which genuinely wants the lenient
/// reading: a service we cannot interrogate has nothing worth recording.
fn query_dns_servers(service: &str) -> Option<Vec<String>> {
    let raw = match cmd("networksetup")
        .args(["-getdnsservers", service])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        // The QUESTION failed: no such service, networksetup missing, a locked
        // SystemConfiguration store.
        _ => return None,
    };
    interpret_dns_query(Some(raw.as_str()))
}

/// Interpret a `networksetup -getdnsservers` result, `None` meaning the command
/// itself could not be run or exited non-zero.
///
/// Split out from the process spawn purely so the distinction this file turns on
/// - an unanswerable question (`None`) versus an answer of "none" (`Some([])`) -
/// is asserted by a test rather than only by prose. Nothing on macOS can be
/// exercised by the one CI job that runs `cargo test`, so anything that is not
/// pulled out into a pure function here is verified by nothing.
fn interpret_dns_query(raw: Option<&str>) -> Option<Vec<String>> {
    let text = raw?.trim();
    if text.contains("aren't any") || text.is_empty() {
        return Some(Vec::new());
    }
    Some(text.lines().map(|l| l.trim().to_string()).collect())
}

/// Does a read-back PROVE the write landed?
///
/// `after` is `None` when `-getdnsservers` could not be answered, and that must
/// never count as success: through the lenient `dns_servers_for`, an
/// unanswerable query and "this service is on DHCP now" are the same empty list,
/// so reading the first as the second certifies a restore-to-DHCP that never
/// happened and lets the journal be deleted.
fn dns_write_verified(intended: &[String], after: Option<Vec<String>>) -> bool {
    after.is_some_and(|after| after.as_slice() == intended)
}

/// What a restore pass could learn about one recorded network service.
///
/// The three outcomes are deliberately distinct. Collapsing `Unreadable` into
/// "carries something else, leave it alone" is exactly the hole that survived
/// the first version of this fix: `dns_servers_for` maps a FAILED query to the
/// empty list, which against a non-empty `tunnel_dns` reads as "the user already
/// fixed it", so the service was skipped, counted as neither restored nor
/// unverified, and the journal was deleted while every service was still on dead
/// tunnel resolvers. Windows has always kept the record in that case
/// (`win_machine_state::reconcile_record`, "live DNS unreadable during restore -
/// leaving it alone and KEEPING the record").
#[derive(Debug, Clone, PartialEq, Eq)]
enum ServiceDns {
    /// Its current resolvers, read successfully.
    Known(Vec<String>),
    /// It is no longer in `networksetup -listallnetworkservices`: removed or
    /// disabled since the record was written. Nothing to do and nothing the user
    /// could do, but the record is kept in case it comes back.
    Absent,
    /// It is still there, but `-getdnsservers` could not be answered. We cannot
    /// tell whether it is still on the tunnel's resolvers, so we must not act as
    /// though we know it is not.
    Unreadable,
}

/// macOS utun tunnel for WireGuard VPN
pub struct UtunTunnel {
    config: VpnConfig,
    running: Arc<AtomicBool>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    wg_session: Arc<RwLock<Option<WireGuardSession>>>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    /// The utun device name assigned by the kernel (e.g. "utun3")
    utun_name: Arc<RwLock<Option<String>>>,
    /// The raw file descriptor for the utun device
    utun_fd: Arc<RwLock<Option<i32>>>,
    /// Network snapshot for restoration on disconnect
    network_snapshot: Arc<RwLock<Option<NetworkSnapshot>>>,
    /// Whether to allow local network access while VPN is active
    local_network_sharing: bool,
    /// Endpoint IP for route exclusion
    endpoint_ip: Arc<RwLock<Option<String>>>,
    /// JoinHandle of the spawned packet loop.
    ///
    /// P1-dk-tun-fd-close-race: stop() must JOIN this task before closing the
    /// utun fd. The loop's spawn_blocking closures capture the raw i32; closing
    /// while one is still in flight lets the kernel recycle the descriptor
    /// number, and the stale read()/write() then lands on whatever unrelated
    /// file or socket this process opens next.
    packet_loop: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

/// LAST-RESORT teardown. `stop()` closes the utun fd at the very END, after
/// `restore_dns()` — which shells out to `networksetup` once per network service
/// and routinely takes longer than the 10 s cap `VpnManager::connect()` puts on a
/// server-switch teardown. When that cap fires, the manager logs and CONTINUES,
/// dropping the `stop()` future before it ever reaches the fd close. With no
/// `Drop` (Windows' `WintunTunnel` has one; this type did not) the fd stayed
/// open, so the utun device survived — still holding the `0.0.0.0/1` +
/// `128.0.0.0/1` half-defaults with a dead packet loop. That is a total IPv4
/// blackhole: the next connect then failed with "File exists" adding its own
/// half-defaults, the connectivity probes (routed INTO the tunnel) could not
/// answer, and the app was declared offline — the start of the frozen-switch
/// cascade. Closing the fd destroys the interface, and the kernel drops its
/// routes with it.
impl Drop for UtunTunnel {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Drop cannot await. `try_write` is enough: by the time the tunnel is
        // being dropped nothing else legitimately holds this lock, and failing to
        // acquire it must never panic or block a teardown.
        if let Ok(mut guard) = self.utun_fd.try_write() {
            if let Some(fd) = guard.take() {
                // Drop cannot join the packet loop (no await), so this close
                // carries the small fd-recycle race stop() eliminates.
                // Accepted: this is the last-resort path for a DROPPED
                // half-built tunnel, and leaving the device alive (the
                // alternative) is a guaranteed IPv4 blackhole.
                let _ = unsafe { libc::close(fd) };
                tracing::warn!(
                    "UtunTunnel dropped with the utun fd still open — closed it to \
                     destroy the interface and release its routes"
                );
            }
        }
    }
}

impl UtunTunnel {
    /// Create a new utun tunnel with the given VPN configuration.
    pub async fn create(config: &VpnConfig, local_network_sharing: bool) -> Result<Self, String> {
        // Validate config before any system changes
        validate_config(config)?;

        Ok(Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            wg_session: Arc::new(RwLock::new(None)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            utun_name: Arc::new(RwLock::new(None)),
            utun_fd: Arc::new(RwLock::new(None)),
            network_snapshot: Arc::new(RwLock::new(None)),
            local_network_sharing,
            endpoint_ip: Arc::new(RwLock::new(None)),
            packet_loop: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the tunnel: create utun device, configure routes/DNS, start packet loop.
    pub async fn start(&self) -> Result<(), String> {
        tracing::info!("Starting macOS utun tunnel");

        // Check for root privileges
        if !crate::utils::elevation::is_elevated() {
            tracing::warn!("Tunnel requires root privileges for utun/route configuration");
        }

        // Snapshot current network config for restoration
        let snapshot = capture_network_snapshot(&self.config.dns).await?;
        tracing::info!(
            "Captured network snapshot: service={}",
            snapshot.service_name
        );
        *self.network_snapshot.write().await = Some(snapshot);

        // Create the utun device
        let (utun_name, utun_fd) =
            create_utun_device().map_err(|e| format!("Failed to create utun device: {}", e))?;
        tracing::info!("Created utun device: {}", utun_name);

        *self.utun_name.write().await = Some(utun_name.clone());
        *self.utun_fd.write().await = Some(utun_fd);

        // Create WireGuard session BEFORE configuring routes
        // (needs direct network access for DNS resolution of endpoint)
        let wg_session = WireGuardSession::new(
            &self.config.private_key,
            &self.config.server_public_key,
            &self.config.endpoint,
            self.config.preshared_key.as_deref(),
            self.config.persistent_keepalive,
        )
        .await
        .map_err(|e| format!("Failed to create WireGuard session: {}", e))?;
        tracing::info!("WireGuard session created");

        let endpoint_ip = wg_session.endpoint_ip();
        tracing::info!(
            "WireGuard endpoint IP: {}",
            redact_ip(&endpoint_ip.to_string())
        );
        *self.endpoint_ip.write().await = Some(endpoint_ip.to_string());

        // Helper: on a startup configuration failure after the utun fd has been
        // created, close the fd so it does not leak until the next stop()/drop.
        // This only runs on the error path; the success path is unchanged.
        let close_fd_on_err = |fd: i32| {
            let _ = unsafe { libc::close(fd) };
            tracing::warn!("Closed utun file descriptor after startup failure");
        };

        // Configure the utun interface IP
        if let Err(e) = configure_utun_address(&utun_name, &self.config.client_ip, &self.config.mtu)
        {
            close_fd_on_err(utun_fd);
            *self.utun_fd.write().await = None;
            return Err(e);
        }

        // Configure routing
        if let Err(e) = configure_routes(
            &utun_name,
            &endpoint_ip.to_string(),
            &self.config.allowed_ips,
            self.local_network_sharing,
        )
        .await
        {
            close_fd_on_err(utun_fd);
            *self.utun_fd.write().await = None;
            return Err(e);
        }

        // F-001 (P0): block IPv6 egress for the whole Connected session. Installed
        // here — at tunnel start, INDEPENDENT of the kill-switch enabled/lockdown
        // setting — exactly as Windows does (tunnel.rs LEAK-2). The kill switch
        // cannot cover this: it is preference-gated (and released on disarm/
        // give-up), and an IPv6 leak never drops the (IPv4-only) tunnel so the
        // reactive path never trips.
        //
        // macOS blocks IPv6 unconditionally — including on dual-stack nodes —
        // and that is deliberate, not an oversight.
        //
        // The fleet DOES have routable IPv6 now, and Linux/Windows route it
        // through the tunnel when the backend issues a client_ipv6. macOS cannot
        // yet, because the utun write path hard-codes the 4-byte protocol header
        // to AF_INET:
        //
        //     write_buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        //
        // Every decrypted IPv6 reply would be handed to the kernel labelled as
        // IPv4 and dropped, so "routing" v6 here would build a ONE-WAY tunnel:
        // requests leave, nothing comes back. `validate_config` also parses
        // client_ip, every DNS entry and every allowed-ip as Ipv4Addr and rejects
        // prefix > 32.
        //
        // Until that is addressed (AF header derived from the first nibble, inet6
        // addressing, v6 routes, relaxed validation), black-holing IPv6 is the
        // only leak-safe option on this platform. A macOS user on a dual-stack
        // node therefore gets working IPv4 and no IPv6 — degraded, but never
        // leaking their real address.
        if let Err(e) = crate::commands::killswitch::ipv6_block_activate().await {
            close_fd_on_err(utun_fd);
            *self.utun_fd.write().await = None;
            return Err(format!("Failed to block IPv6 leaks: {}", e));
        }

        // Configure DNS.
        //
        // Persist what every service currently holds BEFORE repointing them: the
        // snapshot captured at the top of start() lives in this process, and
        // `panic = "abort"`, a SIGKILL or a power cut all skip stop() entirely,
        // leaving every enabled service pointed at tunnel resolvers that no
        // longer exist. Cleared by restore_dns (see vpn::dns_journal).
        if let Some(snapshot) = self.network_snapshot.read().await.as_ref() {
            // `all_dns` is empty exactly when `list_network_services()` failed —
            // the same condition that sends configure_dns down its single-service
            // fallback, where it repoints `get_primary_network_service()` alone.
            // Recording only `all_dns` there would move DNS aside and journal
            // nothing to put back, so the crash path would be blind on precisely
            // the path the clean restore already handles (see its `else` arms).
            let recorded: Vec<(String, Vec<String>)> = if snapshot.all_dns.is_empty() {
                vec![(snapshot.service_name.clone(), snapshot.dns_servers.clone())]
            } else {
                snapshot.all_dns.clone()
            };
            crate::vpn::dns_journal::record_macos(&recorded, &self.config.dns);
        }
        if let Err(e) = configure_dns(&self.config.dns).await {
            crate::commands::killswitch::ipv6_block_deactivate().await;
            close_fd_on_err(utun_fd);
            *self.utun_fd.write().await = None;
            return Err(e);
        }

        // Store WireGuard session
        *self.wg_session.write().await = Some(wg_session);
        self.running.store(true, Ordering::SeqCst);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx);

        // Start packet processing loop
        let running = self.running.clone();
        let bytes_sent = self.bytes_sent.clone();
        let bytes_received = self.bytes_received.clone();
        let packets_sent = self.packets_sent.clone();
        let packets_received = self.packets_received.clone();
        let wg_session = self.wg_session.clone();
        let fd = utun_fd;

        let loop_handle = tokio::spawn(async move {
            Self::packet_loop(
                fd,
                wg_session,
                running,
                bytes_sent,
                bytes_received,
                packets_sent,
                packets_received,
                shutdown_rx,
            )
            .await;
        });
        // Keep the handle so stop() can join the loop before closing the fd
        // (P1-dk-tun-fd-close-race).
        *self.packet_loop.write().await = Some(loop_handle);

        tracing::info!("macOS tunnel started successfully");
        Ok(())
    }

    /// Stop the tunnel and restore network configuration.
    pub async fn stop(&self) -> Result<(), String> {
        tracing::info!("Stopping macOS utun tunnel");

        self.running.store(false, Ordering::SeqCst);

        // Signal the packet loop to stop
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(()).await;
        }

        // P1-dk-tun-fd-close-race: JOIN the packet loop before the fd close
        // below. The loop's spawn_blocking closures capture the raw i32 fd;
        // without the join, an in-flight libc::read/libc::write can execute
        // AFTER close(2) returns the number to the kernel's free pool — and the
        // stale syscall then reads from or writes packet bytes into whatever
        // unrelated descriptor (log file, TLS socket, keystore handle) this
        // process opened next. The fd is O_NONBLOCK, so the loop drains within
        // one iteration of the shutdown signal; the timeout is a safety valve
        // only. If it ever fires we abort the task and fall through to the
        // close anyway — a stuck loop must not leave the device alive owning
        // the half-default routes (that is the frozen-switch blackhole).
        if let Some(handle) = self.packet_loop.write().await.take() {
            let abort = handle.abort_handle();
            if tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .is_err()
            {
                abort.abort();
                tracing::warn!(
                    "Packet loop did not exit within 5s of shutdown — aborted it; \
                     closing the utun fd regardless"
                );
            }
        }

        // Restore DNS
        if let Some(snapshot) = self.network_snapshot.read().await.as_ref() {
            restore_dns(snapshot).await;
        }

        // F-001: lift the IPv6 block. Best-effort so it can never fail teardown
        // (a stuck block would leave the host without IPv6 after disconnect).
        crate::commands::killswitch::ipv6_block_deactivate().await;

        // Remove routes
        if let Some(ep_ip) = self.endpoint_ip.read().await.as_ref() {
            remove_routes(ep_ip, &self.config.allowed_ips, self.local_network_sharing).await;
        }

        // Close the utun file descriptor
        if let Some(fd) = self.utun_fd.write().await.take() {
            let _ = unsafe { libc::close(fd) };
            tracing::info!("Closed utun file descriptor");
        }

        // Destroy the utun interface (happens automatically when fd is closed)
        *self.utun_name.write().await = None;

        // Clear WireGuard session
        *self.wg_session.write().await = None;

        tracing::info!("macOS tunnel stopped successfully");
        Ok(())
    }

    /// Check if the tunnel is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get tunnel statistics: (bytes_sent, bytes_received, packets_sent, packets_received)
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }

    /// Get current latency in milliseconds.
    pub async fn get_latency_ms(&self) -> Option<u32> {
        if let Some(session) = self.wg_session.read().await.as_ref() {
            session.get_latency_ms().await
        } else {
            None
        }
    }

    /// Measure latency to the VPN endpoint.
    pub async fn measure_latency(&self) -> Option<u32> {
        if let Some(session) = self.wg_session.read().await.as_ref() {
            session.measure_latency().await
        } else {
            None
        }
    }

    /// Get the client IP address.
    pub fn get_client_ip(&self) -> &str {
        &self.config.client_ip
    }

    /// Get the server endpoint address.
    pub fn get_endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Packet processing loop: read from utun, encrypt via WireGuard, send to server.
    async fn packet_loop(
        utun_fd: i32,
        wg_session: Arc<RwLock<Option<WireGuardSession>>>,
        running: Arc<AtomicBool>,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        packets_sent: Arc<AtomicU64>,
        packets_received: Arc<AtomicU64>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        tracing::info!("Packet loop started on utun fd={}", utun_fd);

        // macOS utun prepends a 4-byte protocol header (AF_INET = 2 for IPv4)
        const UTUN_HEADER_SIZE: usize = 4;
        const MAX_PACKET_SIZE: usize = 65536;

        // Same cadence Windows uses (tunnel.rs). 250ms is comfortably finer than
        // boringtun's shortest timer, so no deadline is ever missed.
        // Idle backoff, mirroring Windows (tunnel.rs). The fd is O_NONBLOCK and
        // recv_packet returns Ok(None) immediately on WouldBlock, so an idle
        // tunnel previously spun a core at 100% forever. Any packet in either
        // direction resets the counter, so only the FIRST packet after a
        // sustained idle pays the extra latency.
        let mut idle_cycles: u32 = 0;
        const IDLE_THRESHOLD: u32 = 100;
        const DEEP_IDLE_THRESHOLD: u32 = 2_000;
        const SLOW_POLL_US: u64 = 500;
        const DEEP_POLL_US: u64 = 5_000;
        // Drain up to this many decrypted packets per wake, so a burst is not
        // paced one packet per loop iteration.
        const MAX_BATCH_SIZE: usize = 64;
        let mut last_timer_update = std::time::Instant::now();
        const TIMER_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

        let mut read_buf = vec![0u8; MAX_PACKET_SIZE + UTUN_HEADER_SIZE];
        let mut write_buf = vec![0u8; MAX_PACKET_SIZE + UTUN_HEADER_SIZE];

        loop {
            let mut did_work = false;
            if !running.load(Ordering::SeqCst) {
                tracing::info!("Packet loop: running flag cleared, exiting");
                break;
            }

            // The read buffer is moved into the blocking read task below and normally
            // returned for reuse. If it was not returned (e.g. the shutdown branch of the
            // select won, or the blocking task failed to join), restore it to full size so
            // the next read is never issued against a zero-length buffer.
            if read_buf.len() != MAX_PACKET_SIZE + UTUN_HEADER_SIZE {
                read_buf = vec![0u8; MAX_PACKET_SIZE + UTUN_HEADER_SIZE];
            }

            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Packet loop: shutdown signal received");
                    break;
                }
                // Read from utun (async via tokio::task::spawn_blocking for the fd read).
                // The owned read buffer is moved into the blocking task and returned back
                // together with the byte count, so it is reused across iterations instead of
                // cloning ~64KB every loop cycle (including idle EAGAIN polls).
                result = tokio::task::spawn_blocking({
                    let fd = utun_fd;
                    let mut buf = std::mem::take(&mut read_buf);
                    move || {
                        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                        if n < 0 {
                            let err = std::io::Error::last_os_error();
                            if err.raw_os_error() != Some(libc::EAGAIN) {
                                tracing::debug!("utun read error: {}", err);
                            }
                        }
                        (buf, n)
                    }
                }) => {
                    if let Ok((buf, n)) = result {
                        // Return the buffer to the loop for reuse on the next iteration.
                        read_buf = buf;
                        if n > UTUN_HEADER_SIZE as isize {
                            // Strip 4-byte utun header to get raw IP packet
                            let ip_packet = &read_buf[UTUN_HEADER_SIZE..n as usize];
                            let packet_len = ip_packet.len() as u64;

                            // Encrypt and send via WireGuard
                            if let Some(session) = wg_session.read().await.as_ref() {
                                match session.send_packet(ip_packet).await {
                                    Ok(_) => {
                                        bytes_sent.fetch_add(packet_len, Ordering::Relaxed);
                                        packets_sent.fetch_add(1, Ordering::Relaxed);
                                        did_work = true;
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to send WG packet: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Read from WireGuard and write decrypted packets to utun
            for _ in 0..MAX_BATCH_SIZE {
                if let Some(session) = wg_session.read().await.as_ref() {
                    if let Ok(Some(decrypted)) = session.recv_packet().await {
                        did_work = true;
                        let packet_len = decrypted.len() as u64;

                        // Prepend utun header (AF_INET = 0x00000002 for IPv4)
                        write_buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]);
                        write_buf[4..4 + decrypted.len()].copy_from_slice(&decrypted);

                        let write_len = 4 + decrypted.len();
                        let fd = utun_fd;
                        let buf = write_buf[..write_len].to_vec();
                        let expected = buf.len();
                        // P1-dk-macos-rx-counters-on-failed-write: only count a
                        // packet as received when the utun write fully succeeds
                        // (as the Linux path does) — otherwise a dead utun keeps
                        // RX rising and the watchdog's data-plane signal never
                        // fires.
                        let write_ok = tokio::task::spawn_blocking(move || {
                            let written = unsafe {
                                libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
                            };
                            if written < 0 {
                                tracing::debug!(
                                    "utun write error: {}",
                                    std::io::Error::last_os_error()
                                );
                            }
                            written == expected as isize
                        })
                        .await
                        .unwrap_or(false);

                        if write_ok {
                            bytes_received.fetch_add(packet_len, Ordering::Relaxed);
                            packets_received.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        break; // nothing queued — stop draining
                    }
                } else {
                    break;
                }
            }

            // Drive boringtun's timers — WITHOUT this the session dies.
            //
            // boringtun advances all session state inside update_timers():
            // persistent keepalives, REKEY_AFTER_TIME rekeys, and dead-peer
            // detection. `encapsulate` reads the current keypair with no age
            // check, so once the server discards it at REJECT_AFTER_TIME the
            // client keeps happily encrypting to a session that no longer exists
            // — upload appears to work, download stops, and there is no
            // client-side recovery. Windows found this (FIX-DL, tunnel.rs:1834)
            // and fixed it; the Unix tunnels were never given the same tick, so
            // the keepalive plumbed in at start() was never actually emitted.
            //
            // The fd is O_NONBLOCK, so this is reached every iteration even when
            // the tunnel is completely idle — which is exactly when it matters.
            if last_timer_update.elapsed() >= TIMER_INTERVAL {
                last_timer_update = std::time::Instant::now();
                if let Some(session) = wg_session.read().await.as_ref() {
                    if let Err(e) = session.update_timers().await {
                        tracing::trace!("Timer update error: {}", e);
                    }
                }
            }

            if did_work {
                idle_cycles = 0;
            } else {
                idle_cycles = idle_cycles.saturating_add(1);
                if idle_cycles > DEEP_IDLE_THRESHOLD {
                    tokio::time::sleep(std::time::Duration::from_micros(DEEP_POLL_US)).await;
                } else if idle_cycles > IDLE_THRESHOLD {
                    tokio::time::sleep(std::time::Duration::from_micros(SLOW_POLL_US)).await;
                }
            }
        }

        tracing::info!("Packet loop exited");
    }
}

// ──────────────────────────────────────────────────────────────
// Platform-specific helper functions
// ──────────────────────────────────────────────────────────────

/// Validate all VPN config values before they reach system commands.
fn validate_config(config: &VpnConfig) -> Result<(), String> {
    Ipv4Addr::from_str(&config.client_ip)
        .map_err(|_| format!("Invalid client_ip: '{}'", config.client_ip))?;

    let endpoint_host = config
        .endpoint
        .split(':')
        .next()
        .ok_or_else(|| "Invalid endpoint format: missing host".to_string())?;
    if endpoint_host.parse::<Ipv4Addr>().is_err() {
        if endpoint_host.is_empty()
            || endpoint_host.len() > 253
            || !endpoint_host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            || endpoint_host.starts_with('-')
            || endpoint_host.starts_with('.')
        {
            // P6-CLI-D-03: this Err string is logged verbatim by the catch-all handlers
            // in manager.rs / auto_reconnect.rs at levels release builds write.
            return Err(format!(
                "Invalid endpoint hostname: '{}'",
                crate::utils::redact::redact_hostname(endpoint_host)
            ));
        }
    }

    for dns in &config.dns {
        Ipv4Addr::from_str(dns).map_err(|_| format!("Invalid DNS address: '{}'", dns))?;
    }

    for cidr in &config.allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: '{}'", cidr));
        }
        Ipv4Addr::from_str(parts[0]).map_err(|_| format!("Invalid network in CIDR: '{}'", cidr))?;
        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid prefix in CIDR: '{}'", cidr))?;
        if prefix > 32 {
            return Err(format!("Prefix out of range in CIDR: '{}'", cidr));
        }
    }

    if config.mtu < 576 || config.mtu > 9000 {
        return Err(format!("Invalid MTU: {} (expected 576-9000)", config.mtu));
    }

    // P1-dk-allowedips-no-default-coverage: the CIDRs above are only
    // syntax-checked; also refuse a scope that does not cover the full address
    // space (defense in depth — build_vpn_config already enforces this at the
    // choke point every connect path funnels through).
    crate::vpn::validate_tunnel_scope(config)?;

    Ok(())
}

/// Create a macOS utun device via AF_SYSTEM socket.
///
/// Returns (utun_name, raw_fd) on success.
fn create_utun_device() -> Result<(String, i32), String> {
    use std::os::unix::io::RawFd;

    // macOS-specific constants for utun
    const AF_SYSTEM: i32 = 32; // AF_SYSTEM
    const SYSPROTO_CONTROL: i32 = 2;
    const AF_SYS_CONTROL: i32 = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    // struct ctl_info { u_int32_t ctl_id; char ctl_name[96]; }
    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    // struct sockaddr_ctl { ... }
    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32, // utun unit number + 1
        sc_reserved: [u32; 5],
    }

    // CTLIOCGINFO ioctl number
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;

    // Create AF_SYSTEM socket
    let fd: RawFd = unsafe { libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(format!(
            "Failed to create AF_SYSTEM socket: errno {}",
            std::io::Error::last_os_error()
        ));
    }

    // Get the control ID for utun
    let mut ctl_info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0u8; 96],
    };
    ctl_info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);

    let ret = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info as *mut CtlInfo) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(format!(
            "ioctl CTLIOCGINFO failed: errno {}",
            std::io::Error::last_os_error()
        ));
    }

    tracing::debug!("utun control id: {}", ctl_info.ctl_id);

    // Try successive unit numbers until one works (auto-assign)
    for unit in 0..256u32 {
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: ctl_info.ctl_id,
            sc_unit: unit + 1, // utun unit = sc_unit - 1
            sc_reserved: [0; 5],
        };

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };

        if ret == 0 {
            let utun_name = format!("utun{}", unit);
            tracing::info!(
                "Successfully created utun device: {} (fd={})",
                utun_name,
                fd
            );

            // Set non-blocking mode. Failure here is logged: a blocking fd would
            // cause the packet_loop read() to hang, so surface it for diagnosis.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags >= 0 {
                let set_ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
                if set_ret < 0 {
                    tracing::warn!(
                        "Failed to set O_NONBLOCK on utun fd: {}",
                        std::io::Error::last_os_error()
                    );
                }
            } else {
                tracing::warn!(
                    "Failed to read flags (F_GETFL) on utun fd; cannot set non-blocking mode: {}",
                    std::io::Error::last_os_error()
                );
            }

            return Ok((utun_name, fd));
        }
    }

    unsafe { libc::close(fd) };
    Err("Failed to create utun device: all unit numbers 0-255 in use".to_string())
}

/// Configure the utun interface IP address and MTU.
fn configure_utun_address(utun_name: &str, client_ip: &str, mtu: &u16) -> Result<(), String> {
    // Validate utun_name to prevent command injection
    if !utun_name.starts_with("utun") || !utun_name[4..].chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("Invalid utun name: {}", utun_name));
    }

    // ifconfig utunN inet <client_ip> <client_ip> up
    let output = cmd("ifconfig")
        .args([utun_name, "inet", client_ip, client_ip, "up"])
        .output()
        .map_err(|e| format!("Failed to configure utun address: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ifconfig address failed: {}", stderr));
    }
    tracing::info!("Configured {} with IP {}", utun_name, redact_ip(client_ip));

    // Set MTU
    let output = cmd("ifconfig")
        .args([utun_name, "mtu", &mtu.to_string()])
        .output()
        .map_err(|e| format!("Failed to set MTU: {}", e))?;

    if !output.status.success() {
        tracing::warn!(
            "Failed to set MTU to {}: {}",
            mtu,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Configure routing to send traffic through the VPN tunnel.
/// Expand a default route into two halves, leaving everything else untouched.
///
/// The BSD routing table keys on (destination, netmask) with no metric tiebreak,
/// so a second `0.0.0.0/0` can never be installed — `route add` returns
/// "File exists" and the host's own default keeps winning. That is why the old
/// code reported Connected while every packet still left via the physical NIC.
///
/// `0.0.0.0/1` + `128.0.0.0/1` cover the same space but are MORE SPECIFIC, so
/// longest-prefix match picks them over the existing default without deleting
/// it — which also means teardown has nothing to restore.
///
/// Shared by configure_routes and remove_routes so the two can never disagree
/// about what was installed.
/// Networks routed around the tunnel when Local Network Sharing is on.
///
/// Shared between install and teardown so the two cannot drift. These used to
/// be installed and then NEVER removed — leaving routes pointing at a gateway
/// that stops existing the moment the user changes network.
const LAN_SHARING_CIDRS: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

/// Teardown subset — deliberately EXCLUDES 169.254.0.0/16.
///
/// macOS installs its own link-local route on the primary interface, so our
/// `route add` for it always fails with "File exists". We therefore never owned
/// it, and deleting it at teardown would remove the OS's route rather than ours —
/// breaking mDNS/Bonjour for every other app on the machine.
///
/// Kept adjacent to the add-side list above so any drift between them is visible
/// in one screen.
const LAN_SHARING_CIDRS_OWNED: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

fn expand_default_v4(allowed_ips: &[String]) -> Vec<String> {
    allowed_ips
        .iter()
        .flat_map(|cidr| match cidr.trim() {
            "0.0.0.0/0" => vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()],
            other => vec![other.to_string()],
        })
        .collect()
}

async fn configure_routes(
    utun_name: &str,
    endpoint_ip: &str,
    allowed_ips: &[String],
    local_network_sharing: bool,
) -> Result<(), String> {
    // Get current default gateway for endpoint route
    let default_gw = get_default_gateway()?;
    tracing::info!("Default gateway: {}", redact_ip(&default_gw));

    // Add a specific route for the VPN endpoint via the real gateway
    // so WireGuard UDP packets don't get caught in the VPN tunnel
    let output = cmd("route")
        .args(["-n", "add", "-host", endpoint_ip, default_gw.as_str()])
        .output()
        .map_err(|e| format!("Failed to add endpoint route: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // MUST be fatal (except an existing identical route). Once the default
        // below is genuinely captured, a missing endpoint route sends WireGuard's
        // own outer UDP back into the tunnel — an encapsulation loop that reaches
        // Connected and carries zero traffic. Warning here would convert a visible
        // failure into an invisible one.
        if !stderr.contains("File exists") {
            return Err(format!(
                "Failed to pin the endpoint route: {}",
                stderr.trim()
            ));
        }
        tracing::debug!("Endpoint route already present");
    }

    let allowed_ips = expand_default_v4(allowed_ips);

    // Add routes for allowed_ips via the utun interface
    for cidr in &allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            tracing::warn!(
                "Skipping malformed allowed_ip (expected CIDR notation): {}",
                cidr
            );
            continue;
        }

        let network = parts[0];
        let prefix: u8 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("Skipping allowed_ip with invalid CIDR prefix: {}", cidr);
                continue;
            }
        };
        let mask = prefix_to_mask(prefix);

        // route -n add -net <network> -netmask <mask> -interface <utun>
        let output = cmd("route")
            .args([
                "-n",
                "add",
                "-net",
                network,
                "-netmask",
                &mask,
                "-interface",
                utun_name,
            ])
            .output()
            .map_err(|e| format!("Failed to add route for {}: {}", cidr, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // A collision is usually OUR OWN leaked state: if a previous teardown
            // was cut short (e.g. the switch teardown cap fired while restore_dns
            // was still running), the old utun's `0.0.0.0/1` + `128.0.0.0/1`
            // survive and every later connect fails here forever — the machine
            // becomes permanently unable to connect until reboot. Reclaim the route
            // instead: delete it and retry ONCE. Ownership is still verified,
            // because a retry that fails is treated exactly as before.
            let mut recovered = false;
            if stderr.contains("File exists") {
                tracing::warn!(
                    "Route {} already exists (stale from an interrupted teardown?) — \
                     reclaiming it",
                    cidr
                );
                let _ = cmd("route")
                    .args(["-n", "delete", "-net", network, "-netmask", &mask])
                    .output();
                let retry = cmd("route")
                    .args([
                        "-n",
                        "add",
                        "-net",
                        network,
                        "-netmask",
                        &mask,
                        "-interface",
                        utun_name,
                    ])
                    .output()
                    .map_err(|e| format!("Failed to re-add route for {}: {}", cidr, e))?;
                recovered = retry.status.success();
                if !recovered {
                    tracing::error!(
                        "Reclaiming route {} failed: {}",
                        cidr,
                        String::from_utf8_lossy(&retry.stderr).trim()
                    );
                }
            }
            if !recovered {
                // Fatal now that defaults are split. Before the split a `0.0.0.0/0`
                // collision was expected and warning was survivable-looking; after
                // it, a collision on `0.0.0.0/1` or `128.0.0.0/1` means the tunnel
                // did NOT capture traffic, and continuing would report Connected
                // while everything egresses the physical NIC.
                return Err(format!(
                    "Failed to route {} into the tunnel: {}",
                    cidr,
                    stderr.trim()
                ));
            }
        }
    }

    // If local network sharing is enabled, add RFC1918 routes via the real gateway
    if local_network_sharing {
        // 169.254/16 included for mDNS/Bonjour, matching Windows. Without it
        // printer and AirPlay DISCOVERY fails even though the LAN itself is
        // reachable, which reads as "Local Network Sharing is broken".
        let rfc1918 = LAN_SHARING_CIDRS;
        for cidr in &rfc1918 {
            let parts: Vec<&str> = cidr.split('/').collect();
            let mask = prefix_to_mask(parts[1].parse().unwrap_or(8));
            let _ = cmd("route")
                .args([
                    "-n",
                    "add",
                    "-net",
                    parts[0],
                    "-netmask",
                    &mask,
                    &default_gw,
                ])
                .output();
        }
        tracing::info!("Added local network sharing routes (RFC1918)");
    }

    Ok(())
}

/// Configure DNS servers on macOS via networksetup.
async fn configure_dns(dns_servers: &[String]) -> Result<(), String> {
    // Point EVERY enabled service at the tunnel resolvers, not just the primary.
    //
    // The leak this closes: with Wi-Fi and Ethernet both active, only the service
    // owning the default route was repointed. Plug in Ethernet while Wi-Fi stays
    // associated and the primary flips — the utun routes and the endpoint route
    // both remain valid so traffic keeps flowing and the UI stays green, but the
    // newly-primary service's ISP resolvers become resolver #1 for every unscoped
    // query. `get_primary_network_service` is evaluated once at connect, so
    // nothing notices.
    //
    // Windows disables DNS on all non-VPN adapters for exactly this reason.
    let services = list_network_services();
    if services.is_empty() {
        // Fall back to the old behaviour rather than silently configuring nothing.
        let service = get_primary_network_service()?;
        let mut args = vec!["-setdnsservers".to_string(), service.clone()];
        args.extend(dns_servers.iter().cloned());
        let output = cmd("networksetup")
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to set DNS: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "networksetup DNS failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        tracing::warn!(
            "Could not enumerate network services; configured DNS on '{}' only",
            service
        );
        let _ = cmd("dscacheutil").args(["-flushcache"]).output();
        let _ = cmd("killall").args(["-HUP", "mDNSResponder"]).output();
        return Ok(());
    }

    let mut configured = 0usize;
    let mut first_error: Option<String> = None;
    for service in &services {
        let mut args = vec!["-setdnsservers".to_string(), service.clone()];
        args.extend(dns_servers.iter().cloned());
        match cmd("networksetup").args(&args).output() {
            Ok(o) if o.status.success() => configured += 1,
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                tracing::warn!("Could not set DNS on '{}': {}", service, err);
                first_error.get_or_insert(err);
            }
            Err(e) => {
                tracing::warn!("Could not set DNS on '{}': {}", service, e);
                first_error.get_or_insert(e.to_string());
            }
        }
    }

    // Zero services configured means DNS is entirely unprotected — fail the
    // connect rather than proceed with a leak. A partial failure is tolerated:
    // some services (inactive adapters, Thunderbolt bridges) legitimately reject
    // the call, and the ones carrying traffic are configured.
    if configured == 0 {
        return Err(format!(
            "Failed to configure DNS on any network service: {}",
            first_error.unwrap_or_else(|| "unknown error".into())
        ));
    }

    tracing::info!(
        "Configured DNS on {}/{} network services: {:?}",
        configured,
        services.len(),
        dns_servers
    );

    // Flush DNS cache
    let _ = cmd("dscacheutil").args(["-flushcache"]).output();
    let _ = cmd("killall").args(["-HUP", "mDNSResponder"]).output();

    Ok(())
}

/// Restore original DNS configuration.
async fn restore_dns(snapshot: &NetworkSnapshot) {
    // Restore EVERY service we touched, each to exactly what it had.
    //
    // This must mirror configure_dns precisely. Restoring only the primary would
    // leave every other service pinned to tunnel resolvers that stop existing at
    // disconnect — the user's DNS would simply break, on an interface Birdo
    // never appeared to touch.
    let mut outcome = DnsRestoreOutcome::default();
    if !snapshot.all_dns.is_empty() {
        for (service, servers) in &snapshot.all_dns {
            outcome.note(set_service_dns(service, servers), || {
                format!("{}: could not put its pre-connect DNS back", service)
            });
        }
        tracing::info!(
            "Restored DNS on {}/{} network services",
            outcome.restored,
            snapshot.all_dns.len()
        );
    } else if snapshot.dns_servers.is_empty() {
        // Legacy single-service path, kept for a snapshot captured before the
        // all-services change (e.g. an upgrade mid-session). Routed through the
        // same helper as the loop above so the "empty means DHCP" idiom and the
        // read-back cannot drift between the two.
        outcome.note(set_service_dns(&snapshot.service_name, &[]), || {
            format!(
                "{}: could not hand its DNS back to DHCP",
                snapshot.service_name
            )
        });
    } else {
        outcome.note(
            set_service_dns(&snapshot.service_name, &snapshot.dns_servers),
            || {
                format!(
                    "{}: could not put its pre-connect DNS back",
                    snapshot.service_name
                )
            },
        );
    }

    // Flush DNS cache
    let _ = cmd("dscacheutil").args(["-flushcache"]).output();
    let _ = cmd("killall").args(["-HUP", "mDNSResponder"]).output();

    // Drop the on-disk record only for services that provably carry their own
    // resolvers again. A networksetup write that did not take (no privileges, a
    // locked SystemConfiguration store) leaves a service pointing at tunnel
    // resolvers that are about to stop existing, and this file is then the only
    // surviving description of the real ones — see dns_journal::settle.
    crate::vpn::dns_journal::settle(outcome, crate::vpn::dns_journal::clear);
}

/// Point one service's resolvers at `servers`, or hand it back to DHCP when the
/// list is empty, and report whether the change is PROVABLY in effect.
///
/// One implementation, shared by the clean restore and the journal restore. The
/// "empty means DHCP" idiom is networksetup-specific, and a second hand-written
/// copy of it is the estate's recurring bug shape.
///
/// # Why the read-back, and why a caller must not skip it
///
/// The exit status is a hint, not an answer, and the caller that matters most
/// runs UNPRIVILEGED: there is no self-elevation off Windows, so the startup
/// reconcile — the only thing that can heal a SIGKILL, an OOM kill or a power
/// cut — normally runs as the login user, who cannot write
/// /Library/Preferences/SystemConfiguration/preferences.plist (root-owned, and
/// networksetup carries no setuid bit). This function used to discard
/// `.output()` entirely and return `()`, so the crash-recovery path counted
/// every ATTEMPT as a restore, reported success, and then deleted the journal —
/// destroying the only record of the user's real resolvers while the services
/// were still pointing at a tunnel resolver that no longer existed.
///
/// `-getdnsservers` is read-only and answers correctly for any user, and it is
/// the same call that captured the snapshot, so the comparison is a round-trip
/// through one representation (notably "no manually-set servers" reads back as
/// the empty list on both sides).
fn set_service_dns(service: &str, servers: &[String]) -> bool {
    let mut args = vec!["-setdnsservers".to_string(), service.to_string()];
    if servers.is_empty() {
        // "empty" is networksetup's way of saying "go back to DHCP".
        args.push("empty".to_string());
    } else {
        args.extend(servers.iter().cloned());
    }
    // Two attempts, matching the Windows restore pass (`for attempt in 1..=2`).
    // A single networksetup failure against a momentarily locked
    // SystemConfiguration store is common, a second attempt costs milliseconds,
    // and giving up after one turns a recoverable blip into a KEPT journal and a
    // user-visible banner. Neither Unix path retried; both do now.
    for attempt in 1..=2 {
        match cmd("networksetup").args(&args).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::warn!(
                "networksetup rejected the DNS change for '{}' (attempt {}): {}",
                service,
                attempt,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => tracing::warn!(
                "Could not run networksetup for '{}' (attempt {}): {}",
                service,
                attempt,
                e
            ),
        }
        // query_dns_servers, not dns_servers_for: a query that could not be
        // answered must never read as "the service is on DHCP now", which is
        // what would certify a restore to DHCP that never happened.
        if dns_write_verified(servers, query_dns_servers(service)) {
            return true;
        }
    }
    tracing::error!(
        "DNS change for '{}' did not take after 2 attempts — asked for {:?}, the service still \
         reports something else (or cannot be read at all). Not counting it as restored.",
        service,
        servers
    );
    false
}

/// Put back the resolvers on services a previous session repointed and never
/// restored, for the panic hook and the startup reconcile.
///
/// A service is reverted only while it still holds EXACTLY the tunnel resolvers
/// that session installed. That is what separates "we set this" from "the user
/// has since fixed their DNS by hand", and it is what makes this safe to run
/// from `setup()` against an arbitrarily old record. It also means a service
/// that was never reached (an inactive adapter or a Thunderbolt bridge —
/// configure_dns tolerates partial failure) is left alone rather than reset.
pub(super) fn restore_services_still_on_tunnel_dns(
    services: &[(String, Vec<String>)],
    tunnel_dns: &[String],
) -> DnsRestoreOutcome {
    // Enumerate once. An EMPTY list means the enumeration itself failed
    // (networksetup missing, a locked store) - calling every recorded service
    // "Absent" on that basis would silently downgrade a real fault to a dormant
    // one, so treat it as "cannot rule anything out" and let the per-service
    // query answer for itself.
    let present = list_network_services();
    let outcome = restore_services_pass(
        services,
        tunnel_dns,
        |service| {
            if !present.is_empty() && !present.iter().any(|s| s.as_str() == service) {
                return ServiceDns::Absent;
            }
            match query_dns_servers(service) {
                Some(live) => ServiceDns::Known(live),
                None => ServiceDns::Unreadable,
            }
        },
        set_service_dns,
    );
    if outcome.restored > 0 {
        let _ = cmd("dscacheutil").args(["-flushcache"]).output();
        let _ = cmd("killall").args(["-HUP", "mDNSResponder"]).output();
        tracing::warn!(
            "{} of {} network services were left on tunnel resolvers by a previous session — \
             restored their pre-connect DNS",
            outcome.restored,
            services.len()
        );
    }
    if outcome.unverified > 0 {
        // Loud, and actionable: this process could not do it, but the record is
        // being KEPT so a privileged one still can.
        tracing::error!(
            "{} of {} network services are STILL on the previous session's tunnel resolvers — \
             this process could not write their DNS back (running without root? networksetup \
             needs it). The DNS journal is being KEPT; re-launch Birdo with administrator \
             privileges to retry.",
            outcome.unverified,
            services.len()
        );
    }
    outcome
}

/// The pass itself, with the two system touches injected so it can be unit
/// tested without a Mac and without mutating the host's DNS.
///
/// `apply` must answer with a VERIFIED result (see `set_service_dns`): the
/// counts it produces are what decide whether the journal — the only record of
/// `original` — is deleted.
fn restore_services_pass(
    services: &[(String, Vec<String>)],
    tunnel_dns: &[String],
    probe: impl Fn(&str) -> ServiceDns,
    apply: impl Fn(&str, &[String]) -> bool,
) -> DnsRestoreOutcome {
    let mut outcome = DnsRestoreOutcome::default();
    for (service, original) in services {
        match probe(service) {
            ServiceDns::Known(live) if live.as_slice() != tunnel_dns => {
                // Not ours to touch, and not a failure either - the user has
                // fixed this service by hand, or it was never reached at connect
                // time. It must NOT count as unverified, or the journal would be
                // kept forever and every start would log an error about it.
                //
                // Reachable ONLY from a query that was actually answered. The
                // lenient `dns_servers_for` used to feed this comparison, so an
                // unanswerable query arrived here as the empty list and took
                // this branch - see `ServiceDns`.
                continue;
            }
            ServiceDns::Known(_) => outcome.note(apply(service, original), || {
                format!("{}: could not put its pre-connect DNS back", service)
            }),
            ServiceDns::Unreadable => {
                tracing::error!(
                    "Current resolvers for '{}' could not be read, so we cannot tell whether it \
                     is still on a previous session's tunnel DNS. KEEPING the journal.",
                    service
                );
                outcome.note(false, || {
                    format!(
                        "{}: current DNS unreadable - it may still be on tunnel resolvers",
                        service
                    )
                });
            }
            ServiceDns::Absent => {
                // Dormant, not a fault: keeps the record (the service may be
                // re-added and is still unrestored) but raises no banner,
                // because there is nothing a user could do about it and a
                // warning that can never be cleared is how a real one gets
                // ignored. Windows draws the same line.
                tracing::info!(
                    "Network service '{}' is no longer present - keeping its record in case it \
                     comes back",
                    service
                );
                outcome.note_dormant();
            }
        }
    }
    outcome
}

/// Remove VPN-specific routes.
async fn remove_routes(endpoint_ip: &str, allowed_ips: &[String], local_network_sharing: bool) {
    // Remove endpoint route
    let _ = cmd("route")
        .args(["-n", "delete", "-host", endpoint_ip])
        .output();

    // Remove allowed_ip routes.
    //
    // Expanded through the SAME helper configure_routes used, so we delete
    // exactly the routes we installed and nothing else. Previously this emitted
    // an unqualified `route -n delete -net 0.0.0.0 -netmask 0.0.0.0`, which does
    // not match anything we added (we never managed to add a default) and instead
    // deletes the HOST'S OWN default — stranding the machine with no internet
    // after every disconnect.
    let allowed_ips = expand_default_v4(allowed_ips);

    for cidr in &allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            tracing::warn!(
                "Skipping malformed allowed_ip during route removal: {}",
                cidr
            );
            continue;
        }
        let prefix: u8 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "Skipping allowed_ip with invalid CIDR prefix during route removal: {}",
                    cidr
                );
                continue;
            }
        };
        let mask = prefix_to_mask(prefix);
        let _ = cmd("route")
            .args(["-n", "delete", "-net", parts[0], "-netmask", &mask])
            .output();
    }

    // Remove the Local Network Sharing routes — ONLY if we added them, and only
    // the ones we could actually own.
    //
    // This was unconditional, which repeated on the LAN routes the exact mistake
    // that had just been fixed for the default route: deleting something we never
    // installed. With sharing OFF we add nothing, so every delete here targeted
    // the USER'S own routes — `route delete -net <cidr>` matches on destination
    // alone and does not care who created it.
    if local_network_sharing {
        for cidr in LAN_SHARING_CIDRS_OWNED {
            if let Some((net, prefix)) = cidr.split_once('/') {
                if let Ok(p) = prefix.parse::<u8>() {
                    let mask = prefix_to_mask(p);
                    let _ = cmd("route")
                        .args(["-n", "delete", "-net", net, "-netmask", &mask])
                        .output();
                }
            }
        }
    }
    tracing::info!("Removed VPN routes");
}

/// Capture current network configuration for later restoration.
///
/// `tunnel_dns` is what `configure_dns` is about to install; it is needed here to
/// recognise — and refuse — a baseline left behind by a previous session that did
/// not restore DNS.
async fn capture_network_snapshot(tunnel_dns: &[String]) -> Result<NetworkSnapshot, String> {
    let service = get_primary_network_service()?;

    // Get current DNS servers
    let output = cmd("networksetup")
        .args(["-getdnsservers", &service])
        .output()
        .map_err(|e| format!("Failed to get DNS: {}", e))?;

    let dns_text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let dns_servers = if dns_text.contains("aren't any") || dns_text.is_empty() {
        vec![] // DHCP DNS
    } else {
        dns_text.lines().map(|l| l.trim().to_string()).collect()
    };

    let default_gateway = get_default_gateway().ok();
    let default_interface = get_default_interface().ok();

    // Snapshot every enabled service BEFORE anything is changed, so each can be
    // put back exactly. Captured even for services that already use DHCP — an
    // empty vec is meaningful here and restores as "empty".
    //
    // A previous session that exited dirty is reconciled at startup and by the
    // panic hook (vpn::dns_journal), so by the time a connect reaches here the
    // services hold the user's own configuration again. If that reconcile could
    // not run — the record was lost, or the write failed — the live state may
    // still be a dead tunnel's resolvers, and capturing THAT as "the original"
    // latches it forever: every later disconnect faithfully restores resolvers
    // belonging to a tunnel that no longer exists, and every new connect
    // re-captures the same poisoned baseline, so the damage never self-heals.
    // Refuse the resolvers we are about to install as a baseline and say so — a
    // filtered service IS the signal that a previous session did not shut down
    // cleanly. This mirrors the marker check tunnel_linux.rs's capture already
    // performs; recording DHCP instead is the same fallback restore_dns uses and
    // always yields working DNS.
    let all_dns: Vec<(String, Vec<String>)> = list_network_services()
        .into_iter()
        .map(|s| {
            let mut servers = dns_servers_for(&s);
            if !servers.is_empty() && servers.as_slice() == tunnel_dns {
                tracing::warn!(
                    "'{}' still points at the tunnel resolvers at capture time — a previous \
                     session exited without restoring DNS. Recording it as DHCP rather than \
                     making those resolvers permanent.",
                    s
                );
                servers = Vec::new();
            }
            (s, servers)
        })
        .collect();

    Ok(NetworkSnapshot {
        service_name: service,
        dns_servers,
        default_gateway,
        default_interface,
        all_dns,
    })
}

/// Get the primary network service name (e.g. "Wi-Fi", "Ethernet").
fn get_primary_network_service() -> Result<String, String> {
    let output = cmd("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to get default route: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract interface from "interface: en0"
    let iface = stdout
        .lines()
        .find(|l| l.trim().starts_with("interface:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not determine default interface".to_string())?;

    // Map interface to network service name
    let output = cmd("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .map_err(|e| format!("Failed to list hardware ports: {}", e))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_service = String::new();

    for line in text.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port: ") {
            current_service = name.trim().to_string();
        } else if let Some(dev) = line.strip_prefix("Device: ") {
            if dev.trim() == iface {
                return Ok(current_service);
            }
        }
    }

    // Fallback: try "Wi-Fi" or first available
    Ok("Wi-Fi".to_string())
}

/// Get the default gateway IP.
fn get_default_gateway() -> Result<String, String> {
    let output = cmd("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to get default gateway: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|l| l.trim().starts_with("gateway:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not determine default gateway".to_string())
}

/// Get the default network interface name.
fn get_default_interface() -> Result<String, String> {
    let output = cmd("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to get default interface: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|l| l.trim().starts_with("interface:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not determine default interface".to_string())
}

/// Convert a CIDR prefix length to a dotted-decimal netmask.
fn prefix_to_mask(prefix: u8) -> String {
    if prefix == 0 {
        return "0.0.0.0".to_string();
    }
    let mask_bits: u32 = !0u32 << (32 - prefix as u32);
    format!(
        "{}.{}.{}.{}",
        (mask_bits >> 24) & 0xFF,
        (mask_bits >> 16) & 0xFF,
        (mask_bits >> 8) & 0xFF,
        mask_bits & 0xFF,
    )
}

#[cfg(test)]
mod dns_journal_restore_tests {
    use super::{dns_write_verified, interpret_dns_query, restore_services_pass, ServiceDns};
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn services(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(name, dns)| {
                (
                    (*name).to_string(),
                    dns.iter().map(|d| (*d).to_string()).collect(),
                )
            })
            .collect()
    }

    fn tunnel_dns() -> Vec<String> {
        vec!["10.8.0.1".to_string()]
    }

    fn on_tunnel(_: &str) -> ServiceDns {
        ServiceDns::Known(tunnel_dns())
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// THE regression.
    ///
    /// The user double-clicks Birdo.app to heal a crash. There is no
    /// self-elevation off Windows, so this instance is the login user and every
    /// `networksetup -setdnsservers` fails to reach the root-owned
    /// SystemConfiguration store. Nothing may be counted as restored: the
    /// journal holding `original` is deleted off that count, and it is the only
    /// surviving record of the user's real resolvers.
    #[test]
    fn an_unprivileged_pass_restores_nothing_and_keeps_the_journal() {
        let services = services(&[("Wi-Fi", &["192.168.1.1"]), ("USB 10/100 LAN", &[])]);
        let outcome = restore_services_pass(
            &services,
            &tunnel_dns(),
            // Read-back: every service is still on the dead tunnel resolver.
            on_tunnel,
            // The write never landed (networksetup may still have exited 0).
            |_: &str, _: &[String]| false,
        );
        assert_eq!(outcome.restored, 0, "an attempt is not a restore");
        assert_eq!(outcome.unverified, 2);
        assert_eq!(
            outcome.problems.len(),
            2,
            "both must reach the status banner"
        );
        assert!(
            !outcome.may_clear_journal(),
            "the journal would be deleted while both services are still on a resolver that no \
             longer exists - the user's real resolvers would be unrecoverable"
        );
    }

    /// The privileged pass, modelled against real state so the read-back is the
    /// thing that decides.
    #[test]
    fn a_privileged_pass_restores_every_service_and_releases_the_journal() {
        let services = services(&[("Wi-Fi", &["192.168.1.1"]), ("Ethernet", &[])]);
        let live: RefCell<HashMap<String, Vec<String>>> = RefCell::new(
            services
                .iter()
                .map(|(name, _)| (name.clone(), tunnel_dns()))
                .collect(),
        );
        let outcome = restore_services_pass(
            &services,
            &tunnel_dns(),
            |name: &str| match live.borrow().get(name) {
                Some(dns) => ServiceDns::Known(dns.clone()),
                None => ServiceDns::Absent,
            },
            |name: &str, want: &[String]| {
                live.borrow_mut().insert(name.to_string(), want.to_vec());
                true
            },
        );
        assert_eq!(outcome.restored, 2);
        assert_eq!(outcome.unverified, 0);
        assert!(outcome.problems.is_empty());
        assert!(outcome.may_clear_journal());
        assert_eq!(live.borrow()["Wi-Fi"], vec!["192.168.1.1".to_string()]);
        assert!(
            live.borrow()["Ethernet"].is_empty(),
            "empty means back to DHCP"
        );
    }

    /// One service reachable, one not: the record must survive for the one that
    /// was missed.
    #[test]
    fn a_partial_pass_keeps_the_journal() {
        let services = services(&[("Wi-Fi", &["192.168.1.1"]), ("Ethernet", &["10.0.0.1"])]);
        let outcome = restore_services_pass(
            &services,
            &tunnel_dns(),
            on_tunnel,
            |name: &str, _: &[String]| name == "Wi-Fi",
        );
        assert_eq!(outcome.restored, 1);
        assert_eq!(outcome.unverified, 1);
        assert!(!outcome.may_clear_journal());
    }

    /// Self-healing, and the reason "unverified" must not simply mean "not
    /// restored": a service the user already fixed by hand is skipped, so the
    /// pass is fully verified and the stale record is dropped rather than
    /// kept - and logged about - forever.
    #[test]
    fn a_service_the_user_already_fixed_is_skipped_and_the_journal_is_released() {
        let services = services(&[("Wi-Fi", &["192.168.1.1"])]);
        let outcome = restore_services_pass(
            &services,
            &tunnel_dns(),
            |_: &str| ServiceDns::Known(strings(&["1.1.1.1"])),
            |_: &str, _: &[String]| {
                panic!("must not touch a service that is no longer on the tunnel resolvers")
            },
        );
        assert_eq!(outcome.restored, 0);
        assert_eq!(outcome.unverified, 0);
        assert!(outcome.may_clear_journal());
    }

    /// THE residual hole this pass had after the first fix.
    ///
    /// `networksetup -getdnsservers` fails (a locked SystemConfiguration store,
    /// or the binary is unavailable). Through the LENIENT `dns_servers_for` that
    /// arrived here as the empty list, which against a non-empty `tunnel_dns`
    /// reads as "the user already fixed this" - so the service was skipped,
    /// counted as neither restored nor unverified, and `settle` DELETED the
    /// journal while the machine was still pointing at tunnel resolvers that no
    /// longer exist. Exactly the conflation the read-back fix removed from
    /// `set_service_dns`, left on the one path whose answer decides the record's
    /// fate.
    #[test]
    fn an_unreadable_service_keeps_the_journal_instead_of_reading_as_already_fixed() {
        let services = services(&[("Wi-Fi", &["192.168.1.1"])]);
        let outcome = restore_services_pass(
            &services,
            &tunnel_dns(),
            |_: &str| ServiceDns::Unreadable,
            |_: &str, _: &[String]| {
                panic!("must not write to a service whose current state we cannot read")
            },
        );
        assert_eq!(outcome.restored, 0);
        assert_eq!(outcome.unverified, 1);
        assert!(
            !outcome.may_clear_journal(),
            "an unanswerable query is a FAULT that keeps the record, which is what Windows has \
             always done - not evidence that there is nothing left to restore"
        );
        assert_eq!(outcome.problems.len(), 1, "the user must be told");
    }

    /// ...and the other side of that line: a service that has genuinely gone
    /// away keeps the record too, but silently. Without this, a user who deletes
    /// a network service would get a warning banner they can never clear, and
    /// the fix for a destroyed journal would have manufactured a permanent
    /// false alarm.
    #[test]
    fn an_absent_service_keeps_the_journal_without_raising_a_banner() {
        let services = services(&[("Thunderbolt Bridge", &["192.168.1.1"])]);
        let outcome = restore_services_pass(
            &services,
            &tunnel_dns(),
            |_: &str| ServiceDns::Absent,
            |_: &str, _: &[String]| panic!("must not write to a service that is not there"),
        );
        assert_eq!(outcome.unverified, 1);
        assert!(!outcome.may_clear_journal());
        assert!(
            outcome.problems.is_empty(),
            "nothing the user can act on, so nothing to put in front of them"
        );
    }

    // -- interpret_dns_query: the second commit's whole point, finally asserted --

    /// `Some(vec![])` and `None` are NOT the same answer. This is the
    /// distinction the restore-to-DHCP verification turns on, and until now
    /// every macOS test stubbed the query out entirely, so nothing asserted it.
    #[test]
    fn an_unanswerable_query_is_none_not_an_empty_list() {
        assert_eq!(interpret_dns_query(None), None);
        assert_eq!(
            interpret_dns_query(Some("There aren't any DNS Servers set on Wi-Fi.\n")),
            Some(Vec::new()),
            "'no servers set' is an ANSWER, and it means DHCP"
        );
        assert_eq!(interpret_dns_query(Some("   \n")), Some(Vec::new()));
    }

    #[test]
    fn a_listed_answer_is_parsed_line_by_line() {
        assert_eq!(
            interpret_dns_query(Some("192.168.1.1\n 8.8.8.8 \n")),
            Some(strings(&["192.168.1.1", "8.8.8.8"]))
        );
    }

    // -- dns_write_verified: the read-back rule set_service_dns applies --

    /// The restore-to-DHCP hole. The intended value is the empty list, and an
    /// unanswerable query renders as the empty list through `dns_servers_for` -
    /// so the lenient reading would certify a restore that never happened and
    /// release the journal.
    #[test]
    fn a_dhcp_restore_is_not_verified_by_a_query_that_failed() {
        assert!(
            !dns_write_verified(&[], None),
            "None is 'we do not know', and 'we do not know' may never clear the journal"
        );
        assert!(dns_write_verified(&[], Some(Vec::new())));
    }

    #[test]
    fn a_read_back_must_match_the_servers_we_asked_for() {
        let want = strings(&["192.168.1.1"]);
        assert!(dns_write_verified(&want, Some(want.clone())));
        assert!(!dns_write_verified(&want, Some(strings(&["10.8.0.1"]))));
        assert!(!dns_write_verified(&want, Some(Vec::new())));
        assert!(!dns_write_verified(&want, None));
    }
}
