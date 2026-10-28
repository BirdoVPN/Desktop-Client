//! macOS utun tunnel implementation
//!
//! Creates and manages a utun virtual network interface for WireGuard VPN on macOS.
//! Uses the kernel utun interface via AF_SYSTEM sockets.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use super::device_fd::{self, CloseOutcome, DeviceSlot, SharedFd};
use super::wireguard_new::{WgPrivateKey, WireGuardSession};
use crate::api::types::VpnConfig;
use crate::utils::redact_ip;
use crate::vpn::dns_journal::DnsRestoreOutcome;
use crate::vpn::route_journal::{self, GatewayRoute, RouteDelete};

/// Run a command without visible terminal window
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// Stores original DNS info for restoration on disconnect
#[derive(Debug, Clone)]
struct NetworkSnapshot {
    /// The primary network service name (e.g. "Wi-Fi", "Ethernet")
    service_name: String,
    /// Original DNS servers
    dns_servers: Vec<String>,
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
/// Split out from the process spawn purely so the distinction this file turns
/// on, an unanswerable question (`None`) versus an answer of "none"
/// (`Some([])`), is asserted by a test rather than only by prose. Nothing on macOS can be
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
    /// The utun device's file descriptor, shared with the packet loop and each
    /// of its in-flight blocking reads/writes (MR-820, see `device_fd`).
    utun_fd: Arc<DeviceSlot<OwnedFd>>,
    /// Network snapshot for restoration on disconnect
    network_snapshot: Arc<RwLock<Option<NetworkSnapshot>>>,
    /// Whether to allow local network access while VPN is active
    local_network_sharing: bool,
    /// The routes this session added, in the order they went in (MR-2088).
    /// Teardown — stop(), a failed start's unwind, `Drop` — removes exactly
    /// these, and nothing that merely shares a prefix with one of them.
    owned_routes: OwnedRoutes,
    /// JoinHandle of the spawned packet loop.
    ///
    /// P1-dk-tun-fd-close-race: stop() JOINS this task before closing the utun
    /// fd. Joining the task alone did not join the blocking reads/writes it
    /// had already handed off (MR-820); those now hold the fd themselves, and
    /// the close waits for them (`device_fd::close_when_idle`).
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
/// cascade. Closing the fd destroys the interface, and the kernel drops the
/// routes INTO it with it; the routes this session added via the physical
/// gateway are removed first (MR-2088).
impl Drop for UtunTunnel {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // MR-2088: routes this session added that nothing has removed yet (a
        // stop() cut short by the switch-teardown cap, a start() cancelled
        // after configure_routes). Closing the fd withdraws the routes into
        // the utun, but not the endpoint host route or the LAN-sharing routes
        // via the physical gateway, which used to outlive every such drop
        // pointing at whatever gateway the host had then. Removed first, as
        // stop() does, and only while they are still ours.
        let routes = take_owned_routes(&self.owned_routes);
        if !routes.is_empty() {
            tracing::warn!(
                "UtunTunnel dropped with {} route(s) still installed — removing them",
                routes.len()
            );
            remove_owned_routes(routes);
        }
        // Drop cannot await. `try_write` is enough: by the time the tunnel is
        // being dropped nothing else legitimately holds this lock, and failing to
        // acquire it must never panic or block a teardown.
        if let Ok(mut guard) = self.utun_fd.try_write() {
            if let Some(fd) = guard.take() {
                // Drop cannot wait for in-flight I/O (no await), and with the
                // fd shared it does not need to (MR-820): letting go of this
                // reference closes it now, or — if a blocking read/write or the
                // exiting loop still holds it — the moment that returns. Never
                // under a syscall still using the number, never twice. This
                // used to close the raw fd outright and accept the recycle race
                // as the price of not leaving the device alive for good (a
                // guaranteed IPv4 blackhole).
                let close = move || {
                    drop(fd);
                    tracing::warn!(
                        "UtunTunnel dropped with the utun fd still open — released it to \
                         destroy the interface and release its routes"
                    );
                };
                // MR-1125 / P3-4: the kill-switch permit leaves a held block
                // BEFORE the fd closes and frees the unit for someone else —
                // in place when the lock is free, else on the runtime, which
                // then closes the fd itself, after the re-load. The device
                // outlives this Drop by that wait; it is never closed first.
                let name = self.utun_name.try_read().ok().and_then(|n| n.clone());
                match name {
                    Some(name) => {
                        crate::commands::killswitch::tunnel_interface_gone_then(&name, close)
                    }
                    None => close(),
                }
            }
        }
    }
}

impl UtunTunnel {
    /// Create a new utun tunnel with the given VPN configuration.
    ///
    /// MR-822: takes `config` by move (it used to clone it). The config holds
    /// no private key; that is handed to [`start`](Self::start).
    pub async fn create(config: VpnConfig, local_network_sharing: bool) -> Result<Self, String> {
        // Validate config before any system changes
        validate_config(&config)?;

        Ok(Self {
            config,
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
            owned_routes: OwnedRoutes::default(),
            packet_loop: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the tunnel: create utun device, configure routes/DNS, start packet loop.
    ///
    /// MR-822: `private_key` moves into the WireGuard session, and the tunnel
    /// keeps no copy. A start that fails before the session is built drops it,
    /// which wipes it.
    pub async fn start(&self, private_key: WgPrivateKey) -> Result<(), String> {
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
        *self.utun_fd.write().await = Some(Arc::new(utun_fd));

        // MR-1125: the kill switch permits the tunnel by interface NAME — this
        // one, whichever free unit it landed on, and no other — so record it
        // now. A reconnect or a settings reapply engaged the block before this
        // device existed; that block is re-loaded here and read back permitting
        // it. P2-1: if that cannot be confirmed, the tunnel's traffic would meet
        // `block drop all`, so the start FAILS — it used to log and carry on,
        // and an automatic reconnect reached Connected with nothing getting
        // through.
        if let Err(e) = crate::commands::killswitch::tunnel_interface_up(&utun_name).await {
            self.abandon_utun(&utun_name).await;
            return Err(format!(
                "{}: the kill switch could not let the new tunnel through: {e}",
                crate::vpn::ERR_FIREWALL_NOT_ENFORCED
            ));
        }

        // Create WireGuard session BEFORE configuring routes
        // (needs direct network access for DNS resolution of endpoint)
        let wg_session = match WireGuardSession::new(
            private_key,
            &self.config.server_public_key,
            &self.config.endpoint,
            self.config.preshared_key.as_deref(),
            self.config.persistent_keepalive,
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                self.abandon_utun(&utun_name).await;
                return Err(format!("Failed to create WireGuard session: {}", e));
            }
        };
        tracing::info!("WireGuard session created");

        let endpoint_ip = wg_session.endpoint_ip();
        tracing::info!(
            "WireGuard endpoint IP: {}",
            redact_ip(&endpoint_ip.to_string())
        );

        // Configure the utun interface IP
        if let Err(e) = configure_utun_address(&utun_name, &self.config.client_ip, &self.config.mtu)
        {
            self.abandon_utun(&utun_name).await;
            return Err(e);
        }

        // Configure routing. It can fail part-way, with the endpoint route and
        // a half-default already in: each route it added is in owned_routes by
        // then, so the unwind removes exactly those (MR-2088) — never the
        // route that failed this start, which is usually another VPN's.
        if let Err(e) = configure_routes(
            &utun_name,
            &endpoint_ip.to_string(),
            &self.config.allowed_ips,
            self.local_network_sharing,
            &self.owned_routes,
        )
        .await
        {
            self.abandon_utun(&utun_name).await;
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
        //
        // DISCLOSURE (MR-1124): that degradation is user-visible. While
        // connected on macOS, every IPv6-only site and service is unreachable,
        // kill switch on or off, since this block is not the kill switch's.
        // Settings says so on macOS (`MACOS_IPV6_NOTE` in
        // src/components/Settings.tsx). That line goes when this block does,
        // once macOS routes IPv6.
        if let Err(e) = crate::commands::killswitch::ipv6_block_activate().await {
            self.abandon_utun(&utun_name).await;
            return Err(format!(
                "{}: failed to block IPv6 leaks: {}",
                crate::vpn::ERR_FIREWALL_NOT_ENFORCED,
                e
            ));
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
            self.abandon_utun(&utun_name).await;
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
        // The loop's own reference (MR-820), taken from the slot so start()
        // keeps none. Bound first: the read guard must be gone before stop()
        // takes the write lock. An empty slot means a stop() already ran; this
        // one finishes whatever it did not.
        let loop_fd = self.utun_fd.read().await.clone();
        let Some(fd) = loop_fd else {
            let _ = self.stop().await;
            return Err("The utun device was closed before the packet loop started".to_string());
        };

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

    /// A start that failed after the utun device existed. The routes it added
    /// go first (MR-2088): closing the utun withdraws only the routes INTO
    /// it, and the endpoint and LAN-sharing routes via the physical gateway
    /// used to outlive every failed start. Its kill-switch permit then leaves
    /// a held block, while this process still owns the unit (P3-4) — not just
    /// forgotten until the next load — and only then is the fd closed, which
    /// destroys the device. The fd stays in `utun_fd` across the await, so a
    /// cancelled start still leaves it to `Drop`; it is taken and closed with
    /// no await in between (N7), so it can never be closed twice either.
    async fn abandon_utun(&self, name: &str) {
        remove_owned_routes(take_owned_routes(&self.owned_routes));
        crate::commands::killswitch::tunnel_interface_down(name).await;
        let mut slot = self.utun_fd.write().await;
        if let Some(fd) = slot.take() {
            // No packet loop exists yet, so this is the only reference and
            // letting go of it closes the fd (MR-820).
            drop(fd);
            tracing::warn!("Closed utun file descriptor after startup failure");
        }
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
        // below. The fd is O_NONBLOCK, so the loop drains within one iteration
        // of the shutdown signal; the timeout is a safety valve only. If it
        // ever fires we abort the task and fall through to the close anyway —
        // a stuck loop must not leave the device alive owning the half-default
        // routes (that is the frozen-switch blackhole).
        //
        // MR-820: the task join does not cover a read the loop had already
        // handed to the blocking pool (the select! detaches it when shutdown
        // wins). Each of those holds its own reference to the fd now, and the
        // close at the end of stop() waits for them.
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
        // MR-782: unless a server switch holds it for the incoming tunnel.
        crate::commands::killswitch::ipv6_block_deactivate().await;

        // Remove the routes this session added — only those, and each only
        // while it is still ours (MR-2088), so a route that merely shares a
        // prefix with one of them (another VPN's 0.0.0.0/1, an endpoint route
        // that was there before we connected) is never touched.
        remove_owned_routes(take_owned_routes(&self.owned_routes));

        // Close the utun file descriptor — destroying the interface — but take
        // its permit out of a held kill-switch block FIRST (MR-1125 / P3-4):
        // once the fd is closed the unit is free, and another VPN that takes it
        // before the re-load would pass straight through. Only when THIS stop
        // closes the device: after a failed start it is already gone, and a
        // newer tunnel may hold the same unit by now.
        //
        // N7: the fd is READ, not taken, across that await. The manager puts a
        // 10 s cap on a teardown and drops this future when it fires; an fd
        // taken out of `utun_fd` before the await was then closed by nobody,
        // and the device lived on. It is taken and closed with no await in
        // between, so a cancel leaves it where `Drop` finds it — and that holds
        // for the wait on in-flight I/O below too (MR-820: closing under a
        // blocking read/write used to hand its number to the free pool while
        // the syscall had yet to run).
        let open = self.utun_fd.read().await.is_some();
        let utun_name = self.utun_name.read().await.clone();
        if open {
            if let Some(name) = utun_name.as_deref() {
                crate::commands::killswitch::tunnel_interface_down(name).await;
            }
        }
        match device_fd::close_when_idle(&self.utun_fd, device_fd::IN_FLIGHT_WAIT).await {
            CloseOutcome::Closed => tracing::info!("Closed utun file descriptor"),
            CloseOutcome::Deferred => tracing::warn!(
                "utun fd still held by in-flight I/O after {:?} — released our reference; it \
                 closes when that I/O returns",
                device_fd::IN_FLIGHT_WAIT
            ),
            CloseOutcome::Empty => {}
        }
        *self.utun_name.write().await = None;

        // Clear WireGuard session
        *self.wg_session.write().await = None;

        tracing::info!("macOS tunnel stopped successfully");
        Ok(())
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

    /// Time since the last completed WireGuard handshake (W1-002). `None` once
    /// the WireGuard session is gone (the tunnel is being stopped).
    pub async fn handshake_age(&self) -> Option<std::time::Duration> {
        self.wg_session
            .read()
            .await
            .as_ref()
            .map(|session| session.handshake_age())
    }

    /// Start a handshake now unless one is in flight (see
    /// `WireGuardSession::force_handshake`).
    pub async fn force_handshake(&self) {
        if let Some(session) = self.wg_session.read().await.as_ref() {
            session.force_handshake().await;
        }
    }

    /// Packet processing loop: read from utun, encrypt via WireGuard, send to server.
    ///
    /// MR-820: every blocking read/write gets its own clone of `utun_fd` and
    /// holds it for the length of the syscall, so the descriptor cannot be
    /// closed (and its number recycled) under one the loop has detached.
    #[allow(clippy::too_many_arguments)] // shared session handles, moved into the task once
    async fn packet_loop(
        utun_fd: SharedFd,
        wg_session: Arc<RwLock<Option<WireGuardSession>>>,
        running: Arc<AtomicBool>,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        packets_sent: Arc<AtomicU64>,
        packets_received: Arc<AtomicU64>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        tracing::info!("Packet loop started on utun fd={}", utun_fd.as_raw_fd());

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
                // The closure owns a reference to the fd until the read returns
                // (MR-820): when shutdown wins this select!, it is detached, not
                // cancelled.
                result = tokio::task::spawn_blocking({
                    let fd = Arc::clone(&utun_fd);
                    let mut buf = std::mem::take(&mut read_buf);
                    move || {
                        let n = unsafe {
                            libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                        };
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
                        let fd = Arc::clone(&utun_fd);
                        let buf = write_buf[..write_len].to_vec();
                        let expected = buf.len();
                        // P1-dk-macos-rx-counters-on-failed-write: only count a
                        // packet as received when the utun write fully succeeds
                        // (as the Linux path does) — otherwise a dead utun keeps
                        // RX rising and the watchdog's data-plane signal never
                        // fires.
                        let write_ok = tokio::task::spawn_blocking(move || {
                            let written = unsafe {
                                libc::write(
                                    fd.as_raw_fd(),
                                    buf.as_ptr() as *const libc::c_void,
                                    buf.len(),
                                )
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
    if endpoint_host.parse::<Ipv4Addr>().is_err()
        && (endpoint_host.is_empty()
            || endpoint_host.len() > 253
            || !endpoint_host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            || endpoint_host.starts_with('-')
            || endpoint_host.starts_with('.'))
    {
        // P6-CLI-D-03: this Err string is logged verbatim by the catch-all handlers
        // in manager.rs / auto_reconnect.rs at levels release builds write.
        return Err(format!(
            "Invalid endpoint hostname: '{}'",
            crate::utils::redact::redact_hostname(endpoint_host)
        ));
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

    // MR-2116: the one bound the queued-packet buffers are sized against.
    let max_mtu = super::buffer_pool::MAX_MTU;
    if config.mtu < 576 || config.mtu > max_mtu {
        return Err(format!(
            "Invalid MTU: {} (expected 576-{})",
            config.mtu, max_mtu
        ));
    }

    // P1-dk-allowedips-no-default-coverage: the CIDRs above are only
    // syntax-checked; also refuse a scope that does not cover the full address
    // space (defense in depth — build_vpn_config already enforces this at the
    // choke point every connect path funnels through).
    crate::vpn::validate_tunnel_scope(config)?;

    Ok(())
}

/// AF_SYSTEM / SYSPROTO_CONTROL: the socket a utun is created from.
const AF_SYSTEM: i32 = 32;
const SYSPROTO_CONTROL: i32 = 2;

/// Create the kernel-control socket a utun is connected from, close-on-exec.
///
/// Without FD_CLOEXEC, any long-lived child spawned while the tunnel is up
/// (xray, re-spawned by the stealth path) inherited the descriptor, and its
/// copy kept the utun — and the half-default routes through it — alive after
/// stop() closed ours. Darwin's socket(2) has no SOCK_CLOEXEC, so the flag is
/// set straight after socket() and before connect() creates the interface; a
/// failure to set it fails the start, as a failure to set O_NONBLOCK does.
/// Creating the socket needs no privilege (connecting it to the utun control
/// does), so the test runs this as is.
fn open_utun_control_socket() -> Result<std::os::fd::RawFd, String> {
    // SAFETY: socket(2) with constant arguments; no memory is passed.
    let fd = unsafe { libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(format!(
            "Failed to create AF_SYSTEM socket: errno {}",
            std::io::Error::last_os_error()
        ));
    }
    if let Err(e) = device_fd::set_cloexec(fd) {
        // SAFETY: `fd` was created above and nothing else owns it.
        unsafe { libc::close(fd) };
        return Err(format!("Could not make the utun fd close-on-exec: {e}"));
    }
    Ok(fd)
}

/// Create a macOS utun device via AF_SYSTEM socket.
///
/// Returns (utun_name, fd) on success; the fd is owned from here on (MR-820),
/// so it is closed exactly once, by whoever lets go of it last.
fn create_utun_device() -> Result<(String, OwnedFd), String> {
    use std::os::unix::io::RawFd;

    // macOS-specific constants for utun (AF_SYSTEM / SYSPROTO_CONTROL above)
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

    // Create the AF_SYSTEM socket, close-on-exec before connect() makes it a
    // utun.
    let fd: RawFd = open_utun_control_socket()?;

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

            // Non-blocking, or no device. This used to warn and carry on, but
            // a blocking read on an idle utun never returns, and stop()'s close
            // waits for in-flight reads (MR-820): the interface would outlive
            // stop(), still holding the half-default routes.
            if let Err(e) = device_fd::set_nonblocking(fd) {
                unsafe { libc::close(fd) };
                return Err(format!("Could not make the utun fd non-blocking: {}", e));
            }

            // SAFETY: `fd` was opened above, is valid, and nothing else owns
            // it; from here on only the OwnedFd does.
            return Ok((utun_name, unsafe { OwnedFd::from_raw_fd(fd) }));
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

/// Networks routed around the tunnel when Local Network Sharing is on.
///
/// These used to be installed and then NEVER removed — leaving routes pointing
/// at a gateway that stops existing the moment the user changes network. Each
/// one that goes in is now an [`OwnedRoute`], removed at teardown; one that was
/// already there is not ours and stays. On most Macs that is 169.254.0.0/16:
/// macOS installs its own link-local route on the primary interface, our add
/// fails with "File exists", and teardown leaves the OS's route alone
/// (deleting it would break mDNS/Bonjour for every other app on the machine).
const LAN_SHARING_CIDRS: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

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
/// Teardown does not re-expand this: it removes what configure_routes recorded
/// adding ([`OwnedRoute`]), so it cannot disagree about what was installed.
fn expand_default_v4(allowed_ips: &[String]) -> Vec<String> {
    allowed_ips
        .iter()
        .flat_map(|cidr| match cidr.trim() {
            "0.0.0.0/0" => vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()],
            other => vec![other.to_string()],
        })
        .collect()
}

/// Pin the VPN endpoint to the real gateway, so WireGuard's own outer UDP does
/// not get captured by the tunnel's own routes.
///
/// Extracted from `configure_routes` so it can be exercised on a macOS CI
/// runner, which has no utun device and therefore cannot run `configure_routes`
/// itself. F-008 records that nothing from the five-platform parity audit had
/// ever been run, and macOS is the platform it singles out as deserving real
/// hardware — its route behaviour differs from Linux. This does not replace
/// that; it covers the half the audit is really about, which is that a failed
/// route-add is RETURNED rather than swallowed.
///
/// MR-740: a route this call added goes on the crash-recovery record at once.
/// It sits on the physical interface, so unlike the utun's routes it outlives
/// a killed process; the next start removes it. One that was already there is
/// not ours: it is not recorded, and teardown leaves it where it was (MR-2088
/// — it used to delete it by destination, someone else's or not).
fn pin_endpoint_route(
    endpoint_ip: &str,
    default_gw: &str,
    owned: &OwnedRoutes,
) -> Result<(), String> {
    let route = OwnedRoute {
        dst: format!("{endpoint_ip}/32"),
        via: RouteVia::Gateway(default_gw.to_string()),
    };
    if let Err(output) = add_owned_route(route, owned) {
        // MUST be fatal (except an existing identical route). Once the default
        // is genuinely captured, a missing endpoint route sends WireGuard's own
        // outer UDP back into the tunnel — an encapsulation loop that reaches
        // Connected and carries zero traffic. Warning here would convert a
        // visible failure into an invisible one.
        if !output.contains("File exists") {
            return Err(format!("Failed to pin the endpoint route: {}", output));
        }
        tracing::debug!("Endpoint route already present");
    }
    Ok(())
}

/// MR-740: the crash-recovery record of a route to `dst` via `gateway`.
fn gateway_record(dst: &str, gateway: &str) -> GatewayRoute {
    GatewayRoute {
        dst: dst.to_string(),
        via: gateway.to_string(),
        dev: None,
    }
}

/// `route` arguments that name `dst` (an IPv4 CIDR) as a host or a network.
fn route_target(dst: &str) -> Option<Vec<String>> {
    let (net, prefix) = dst.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok().filter(|p| (1..=32).contains(p))?;
    Some(if prefix == 32 {
        vec!["-host".to_string(), net.to_string()]
    } else {
        vec![
            "-net".to_string(),
            net.to_string(),
            "-netmask".to_string(),
            prefix_to_mask(prefix),
        ]
    })
}

/// `route -n <verb> <target>`, its stdout and stderr together.
fn run_route(verb: &str, target: &[String]) -> Result<(bool, String), String> {
    let mut args = vec!["-n".to_string(), verb.to_string()];
    args.extend_from_slice(target);
    run_route_args(&args)
}

/// `route <args>`: whether the kernel made the change, and stdout and stderr
/// together.
fn run_route_args(args: &[String]) -> Result<(bool, String), String> {
    let out = cmd("route")
        .args(args)
        .output()
        .map_err(|e| format!("could not run route: {}", e))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    Ok((
        route_change_made(out.status.success(), &stderr),
        format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr),
    ))
}

/// Did `route` make the change? Its exit status alone does not say: macOS
/// `route` exits 0 when the kernel refuses an add ("File exists") or a delete
/// or lookup ("not in table"), and only warns about it on stderr ("route:
/// writing to routing socket: File exists"). Read by its status, every
/// collision was a route we had added (MR-2088), and the fatal paths for a
/// refused add in pin_endpoint_route and configure_routes never ran. A change
/// counts as made only when nothing was written to stderr either.
fn route_change_made(exit_ok: bool, stderr: &str) -> bool {
    exit_ok && stderr.trim().is_empty()
}

/// Where a route of ours points.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteVia {
    /// The physical gateway: the endpoint host route, the LAN-sharing routes.
    Gateway(String),
    /// The session's utun (`-interface utunN`): the allowed IPs.
    Interface(String),
}

/// A route this session added, held with what makes it ours (MR-2088).
///
/// BSD `route delete` matches on the destination and mask alone; the kernel
/// ignores a gateway or interface named with it. Teardown used to delete by
/// prefix, so it removed whatever route held each one: another VPN's
/// `0.0.0.0/1` and `128.0.0.0/1`, or an endpoint host route that was already
/// there when we connected (which our add had only met as "File exists"). Now
/// a route is recorded only once its add succeeded, and deleted only while
/// `route -n get` still shows it where we put it: via our gateway, or into our
/// utun. The Linux twin is tunnel_linux.rs's `OwnedRoute` (bug B, #300).
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedRoute {
    /// IPv4 CIDR, e.g. `0.0.0.0/1` or `203.0.113.7/32`.
    dst: String,
    via: RouteVia,
}

impl OwnedRoute {
    /// `route` argv for `-n <verb> <target> <gateway>` or
    /// `-n <verb> <target> -interface <utun>`: the add and the delete come from
    /// the same place, so they cannot be qualified differently. `None` for a
    /// destination [`route_target`] cannot name (a /0 above all).
    fn route_args(&self, verb: &str) -> Option<Vec<String>> {
        let mut args = vec!["-n".to_string(), verb.to_string()];
        args.extend(route_target(&self.dst)?);
        match &self.via {
            RouteVia::Gateway(gateway) => args.push(gateway.clone()),
            RouteVia::Interface(utun) => args.extend(["-interface".to_string(), utun.clone()]),
        }
        Some(args)
    }

    /// MR-740: this route's crash-recovery record, when it outlives the utun.
    /// A route via the physical gateway does; one into the utun dies with it.
    fn gateway_record(&self) -> Option<GatewayRoute> {
        match &self.via {
            RouteVia::Gateway(gateway) => Some(gateway_record(&self.dst, gateway)),
            RouteVia::Interface(_) => None,
        }
    }

    /// Does `route -n get`'s answer describe this route itself: the same
    /// destination and mask, via our gateway or into our utun?
    fn described_by(&self, output: &str) -> bool {
        match &self.via {
            RouteVia::Gateway(gateway) => {
                route_journal::route_get_describes(output, &gateway_record(&self.dst, gateway))
            }
            RouteVia::Interface(utun) => {
                route_journal::route_get_interface_at(output, &self.dst) == Some(utun.as_str())
            }
        }
    }

    /// Delete this route — only while the table still holds it as ours. A
    /// route someone else has put at the same destination since, or had there
    /// all along, is left alone.
    fn delete(&self) -> RouteDelete {
        let (Some(target), Some(args)) = (route_target(&self.dst), self.route_args("delete"))
        else {
            return RouteDelete::Absent;
        };
        let got = match run_route("get", &target) {
            Ok(got) => got,
            Err(e) => return RouteDelete::Failed(e),
        };
        match got {
            (false, output) => route_journal::route_tool_outcome(false, &output),
            (true, output) if !self.described_by(&output) => {
                tracing::info!(
                    "The route to {} is no longer ours — left in place",
                    redact_ip(&self.dst)
                );
                RouteDelete::Absent
            }
            (true, _) => match run_route_args(&args) {
                Ok((ok, output)) => route_journal::route_tool_outcome(ok, &output),
                Err(e) => RouteDelete::Failed(e),
            },
        }
    }
}

/// MR-740: delete a route the crash-recovery record names, exactly as a
/// teardown deletes one of ours: only while `route -n get` still shows this
/// destination (and mask) via the recorded gateway; a route someone else has
/// put there since is left alone. `route_journal::reconcile` calls this, at
/// start-up, where no tunnel of this process is up.
pub(super) fn delete_recorded_route(route: &GatewayRoute) -> RouteDelete {
    OwnedRoute {
        dst: route.dst.clone(),
        via: RouteVia::Gateway(route.via.clone()),
    }
    .delete()
}

/// The routes a tunnel owns, in the order they were added.
type OwnedRoutes = std::sync::Mutex<Vec<OwnedRoute>>;

/// Take every owned route out of `owned`, leaving it empty. A poisoned lock
/// still yields its routes: a teardown must never skip them.
fn take_owned_routes(owned: &OwnedRoutes) -> Vec<OwnedRoute> {
    std::mem::take(&mut *owned.lock().unwrap_or_else(|e| e.into_inner()))
}

/// `route add` `route`, recording it in `owned` as soon as the add succeeded —
/// before anything else can fail or be cancelled. Returns `route`'s answer on
/// a failure ("File exists" when something already holds the destination).
///
/// MR-740: a route that outlives the utun also goes on the crash-recovery
/// record at once, so a session killed from here on (SIGKILL, a panic) leaves
/// the next start a record of it to remove.
fn add_owned_route(route: OwnedRoute, owned: &OwnedRoutes) -> Result<(), String> {
    let Some(args) = route.route_args("add") else {
        return Err(format!("{} is not a prefix `route` can name", route.dst));
    };
    let (ok, output) = run_route_args(&args)?;
    if !ok {
        return Err(output.trim().to_string());
    }
    let record = route.gateway_record();
    owned.lock().unwrap_or_else(|e| e.into_inner()).push(route);
    if let Some(record) = record {
        route_journal::remember(&record);
    }
    Ok(())
}

/// Remove the routes this session added, newest first, each only while it is
/// still ours (see [`OwnedRoute`]).
///
/// Synchronous so `Drop` can call it. Best-effort: a route into the utun is
/// already gone if the utun is, and a failed delete must never stop the rest
/// of a teardown.
///
/// This replaces deleting by prefix, which removed routes we never installed:
/// the HOST's own default once (an unqualified `0.0.0.0/0` delete), macOS's
/// link-local 169.254.0.0/16, an endpoint route that was already there, and
/// another VPN's half-defaults (MR-2088).
///
/// MR-740: a route proved gone leaves the crash-recovery record; one whose
/// delete failed stays on it, for the next start to retry.
fn remove_owned_routes(routes: Vec<OwnedRoute>) {
    if routes.is_empty() {
        return;
    }
    for route in routes.iter().rev() {
        let deleted = route.delete();
        match &deleted {
            RouteDelete::Removed => {}
            RouteDelete::Absent => tracing::debug!(
                "Route {} was already gone at teardown",
                redact_ip(&route.dst)
            ),
            RouteDelete::Failed(e) => {
                tracing::warn!("Could not remove route {}: {}", redact_ip(&route.dst), e)
            }
        }
        if deleted.settled() {
            if let Some(record) = route.gateway_record() {
                route_journal::forget(&record);
            }
        }
    }
    tracing::info!("Removed {} VPN route(s)", routes.len());
}

/// What holds a destination an allowed-IP add collided with ("File exists").
#[derive(Debug, Clone, PartialEq, Eq)]
enum Collision {
    /// A route into this session's own utun: in already (a repeated allowed
    /// IP, or the utun's own address). Nothing to do.
    Ours,
    /// A route into a utun that no longer exists: a dead tunnel's leftover,
    /// which nothing can be using. Taken over.
    Stale,
    /// Anything else — another VPN's live utun, a route via a gateway, an
    /// answer that cannot be read. Left alone, and the start fails.
    Foreign,
}

/// Classify a collision at `dst` from `route -n get`'s answer about it.
/// `utun_exists` is the one question it asks the system, so this is pure.
fn classify_collision(
    output: &str,
    dst: &str,
    our_utun: &str,
    utun_exists: impl Fn(&str) -> bool,
) -> Collision {
    match route_journal::route_get_interface_at(output, dst) {
        Some(iface) if iface == our_utun => Collision::Ours,
        Some(iface) if is_utun_name(iface) && !utun_exists(iface) => Collision::Stale,
        _ => Collision::Foreign,
    }
}

/// `utun` and a unit number: the only kind of interface whose leftover route
/// a start may take over.
fn is_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|unit| !unit.is_empty() && unit.chars().all(|c| c.is_ascii_digit()))
}

/// Does an interface called `name` exist right now? A name that cannot even
/// be asked about counts as existing, so it is never taken for a dead one.
fn interface_exists(name: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(name) else {
        return true;
    };
    // SAFETY: `name` is a valid NUL-terminated string for the whole call.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

/// Our add of `route` (into this session's utun) met "File exists". Returns
/// whether the destination is now routed into this utun; `false` leaves the
/// collision to fail the start.
///
/// A collision used to be reclaimed unconditionally: the route at that prefix
/// was deleted, whoever's it was, and ours added in its place — which took
/// another VPN's `0.0.0.0/1` and `128.0.0.0/1` away from it (MR-2088). The
/// case it was written for, our own previous utun surviving an interrupted
/// teardown with its half-defaults, is now covered where it starts: stop(),
/// a failed start's unwind and `Drop` each remove the routes they added. So
/// only a route into a utun that no longer exists is taken over here.
fn resolve_collision(route: &OwnedRoute, owned: &OwnedRoutes) -> Result<bool, String> {
    let RouteVia::Interface(utun) = &route.via else {
        return Ok(false);
    };
    let Some(target) = route_target(&route.dst) else {
        return Ok(false);
    };
    let (_, output) = run_route("get", &target)?;
    match classify_collision(&output, &route.dst, utun, interface_exists) {
        Collision::Ours => Ok(true),
        Collision::Foreign => {
            tracing::warn!(
                "Route {} is already held by another interface or gateway — not ours, left in \
                 place",
                route.dst
            );
            Ok(false)
        }
        Collision::Stale => {
            tracing::warn!(
                "Route {} still points at a utun that no longer exists — reclaiming it",
                route.dst
            );
            // By destination only: the dead utun can no longer be named to
            // `route`, and the lookup above showed what holds the prefix.
            let _ = run_route("delete", &target);
            match add_owned_route(route.clone(), owned) {
                Ok(()) => Ok(true),
                Err(e) => {
                    tracing::error!("Reclaiming route {} failed: {}", route.dst, e);
                    Ok(false)
                }
            }
        }
    }
}

async fn configure_routes(
    utun_name: &str,
    endpoint_ip: &str,
    allowed_ips: &[String],
    local_network_sharing: bool,
    owned: &OwnedRoutes,
) -> Result<(), String> {
    // Get current default gateway for endpoint route
    let default_gw = get_default_gateway()?;
    tracing::info!("Default gateway: {}", redact_ip(&default_gw));

    pin_endpoint_route(endpoint_ip, &default_gw, owned)?;

    let allowed_ips = expand_default_v4(allowed_ips);

    // Add routes for allowed_ips via the utun interface:
    // route -n add -net <network> -netmask <mask> -interface <utun>
    for cidr in &allowed_ips {
        let route = OwnedRoute {
            dst: cidr.clone(),
            via: RouteVia::Interface(utun_name.to_string()),
        };
        if let Err(output) = add_owned_route(route.clone(), owned) {
            // A collision is taken over only from a utun that no longer
            // exists (see resolve_collision); another VPN's route stays its.
            if output.contains("File exists") && resolve_collision(&route, owned)? {
                continue;
            }
            // Fatal now that defaults are split. Before the split a `0.0.0.0/0`
            // collision was expected and warning was survivable-looking; after
            // it, a collision on `0.0.0.0/1` or `128.0.0.0/1` means the tunnel
            // did NOT capture traffic, and continuing would report Connected
            // while everything egresses the physical NIC.
            return Err(format!(
                "Failed to route {} into the tunnel: {}",
                cidr, output
            ));
        }
    }

    // If local network sharing is enabled, add RFC1918 routes via the real gateway
    if local_network_sharing {
        // 169.254/16 included for mDNS/Bonjour, matching Windows. Without it
        // printer and AirPlay DISCOVERY fails even though the LAN itself is
        // reachable, which reads as "Local Network Sharing is broken".
        for cidr in LAN_SHARING_CIDRS {
            let route = OwnedRoute {
                dst: cidr.to_string(),
                via: RouteVia::Gateway(default_gw.clone()),
            };
            // Best-effort, as before; only a route that went in is ours to
            // remove — macOS's own 169.254.0.0/16 is not (LAN_SHARING_CIDRS).
            let _ = add_owned_route(route, owned);
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

// ────────────────────────────────────────────────────────────────────────────────
// F-008 macOS parity: the endpoint route
//
// The owner has no Mac, so this runs on the CI runner. It cannot cover what a
// real Mac would — no tunnel, no network path — and F-008's note that macOS
// route behaviour deserves real hardware still stands. What it does cover is
// the contract the audit is named for: the failure is RETURNED, not
// swallowed, and the ONE tolerated case is an already-present route.
//
// MR-2088: and route ownership against the real `route` tool and real utuns
// (TEST-NET prefixes only, never a default half): teardown deletes only what
// this session added, a start takes no other tunnel's route, and a failed
// start or a dropped tunnel removes the endpoint route it pinned.
// ────────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod endpoint_route_tests {
    use super::*;

    /// `route` rejects a malformed destination, and that rejection must reach
    /// the caller. If this returned Ok, `configure_routes` would go on to
    /// install the split default over an unpinned endpoint — Connected, zero
    /// traffic, nothing on screen to say why.
    ///
    /// Needs no privileges: the address is refused before the routing table is
    /// touched.
    #[test]
    fn a_malformed_endpoint_is_fatal_not_swallowed() {
        let err = pin_endpoint_route("999.999.999.999", "192.0.2.1", &OwnedRoutes::default())
            .expect_err("a malformed endpoint must not be accepted");
        assert!(
            err.contains("Failed to pin the endpoint route")
                || err.contains("Failed to add endpoint route"),
            "refused, but not with the endpoint-route error: {err}"
        );
    }

    /// Same from the gateway side.
    #[test]
    fn a_malformed_gateway_is_fatal_not_swallowed() {
        let err = pin_endpoint_route("192.0.2.10", "not-a-gateway", &OwnedRoutes::default())
            .expect_err("a malformed gateway must not be accepted");
        assert!(
            err.contains("Failed to pin the endpoint route")
                || err.contains("Failed to add endpoint route"),
            "refused, but not with the endpoint-route error: {err}"
        );
    }

    /// The ONE tolerated failure, proven rather than asserted in a comment: a
    /// route that is already present returns Ok, because reconnecting over a
    /// surviving route is normal and must not be fatal.
    ///
    /// Root-only — it really installs a route to TEST-NET-1 and removes it.
    #[test]
    #[ignore = "mutates host routing; run as root via --ignored (CI does)"]
    fn an_already_present_route_is_tolerated() {
        let gw = match get_default_gateway() {
            Ok(g) => g,
            Err(e) => panic!("no default gateway on this runner: {e}"),
        };
        const DEST: &str = "192.0.2.123"; // RFC 5737 TEST-NET-1

        let _ = cmd("route").args(["-n", "delete", "-host", DEST]).output();

        let owned = OwnedRoutes::default();
        pin_endpoint_route(DEST, &gw, &owned).expect("first add should succeed");
        // Second call hits "File exists" — the tolerated case.
        let second = pin_endpoint_route(DEST, &gw, &owned);

        let _ = cmd("route").args(["-n", "delete", "-host", DEST]).output();

        second.expect("an already-present endpoint route must be tolerated, not fatal");
    }

    /// Does the table hold a host route to `dest` via `gw`?
    fn host_route_via(dest: &str, gw: &str) -> bool {
        let Ok(out) = cmd("route").args(["-n", "get", "-host", dest]).output() else {
            return false;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let field = |name: &str| {
            text.lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.trim() == name)
                .map(|(_, v)| v.trim().to_string())
        };
        out.status.success()
            && field("destination").as_deref() == Some(dest)
            && field("gateway").as_deref() == Some(gw)
    }

    /// MR-740: the endpoint route outlives a killed session (the utun dies
    /// with the process; this route, via the physical gateway, does not) and
    /// used to stay until reboot. The next start's journal-driven recovery
    /// must remove it.
    ///
    /// Root-only — it really installs a route to TEST-NET-1, and the recovery
    /// keeps its record in /var/run/birdovpn.
    #[test]
    #[ignore = "mutates host routing; run as root via --ignored (CI does)"]
    fn a_pinned_route_a_killed_session_left_is_removed_at_the_next_start() {
        let gw = match get_default_gateway() {
            Ok(g) => g,
            Err(e) => panic!("no default gateway on this runner: {e}"),
        };
        const DEST: &str = "192.0.2.124"; // RFC 5737 TEST-NET-1

        let _ = cmd("route").args(["-n", "delete", "-host", DEST]).output();
        // The session is killed: what it owned is never torn down.
        pin_endpoint_route(DEST, &gw, &OwnedRoutes::default()).expect("the add should succeed");
        let pinned = host_route_via(DEST, &gw);

        // What the next launch runs after a SIGKILL.
        crate::vpn::dns_journal::reconcile();
        let left = host_route_via(DEST, &gw);

        let _ = cmd("route").args(["-n", "delete", "-host", DEST]).output();
        assert!(pinned, "precondition: the pinned route is in");
        assert!(
            !left,
            "the endpoint route a killed session left survived the next start's recovery"
        );
    }

    /// Does the table hold the route to exactly `net`/`mask` into `iface`?
    fn routed_into(net: &str, mask: &str, iface: &str) -> bool {
        let Ok(out) = cmd("route")
            .args(["-n", "get", "-net", net, "-netmask", mask])
            .output()
        else {
            return false;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let field = |name: &str| {
            text.lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.trim() == name)
                .map(|(_, v)| v.trim().to_string())
        };
        out.status.success()
            && field("destination").as_deref() == Some(net)
            && field("mask").as_deref() == Some(mask)
            && field("interface").as_deref() == Some(iface)
    }

    /// MR-2088: an endpoint route that was already there when we connected is
    /// not ours — the pin met "File exists" — and teardown leaves it. It used
    /// to delete it by destination.
    ///
    /// Root-only — it really installs a route to TEST-NET-1 and removes it.
    #[test]
    #[ignore = "mutates host routing; run as root via --ignored (CI does)"]
    fn a_teardown_leaves_an_endpoint_route_it_did_not_add() {
        let gw = match get_default_gateway() {
            Ok(g) => g,
            Err(e) => panic!("no default gateway on this runner: {e}"),
        };
        const DEST: &str = "192.0.2.125"; // RFC 5737 TEST-NET-1

        let _ = cmd("route").args(["-n", "delete", "-host", DEST]).output();
        // Someone else's pin to the same address.
        let theirs = cmd("route")
            .args(["-n", "add", "-host", DEST, gw.as_str()])
            .output()
            .is_ok_and(|o| o.status.success());

        let owned = OwnedRoutes::default();
        let pinned = pin_endpoint_route(DEST, &gw, &owned);
        remove_owned_routes(take_owned_routes(&owned));
        let left = host_route_via(DEST, &gw);

        let _ = cmd("route").args(["-n", "delete", "-host", DEST]).output();
        assert!(theirs, "precondition: the other route is in");
        pinned.expect("an endpoint route already there is tolerated");
        assert!(
            left,
            "teardown deleted an endpoint route this session never added"
        );
    }

    /// MR-2088: another tunnel's route at one of our allowed IPs is neither
    /// taken (the start fails instead) nor deleted, and the failed start's
    /// unwind removes the endpoint route it had already pinned. The old start
    /// deleted the other tunnel's route and put ours in its place, and its
    /// unwind (abandon_utun) removed no route at all.
    ///
    /// Root-only — it creates two utuns, routes TEST-NET-2 through one of
    /// them, pins a TEST-NET-1 host and removes everything again.
    #[tokio::test]
    #[ignore = "mutates host routing; run as root via --ignored (CI does)"]
    async fn a_start_neither_takes_nor_deletes_another_tunnels_route() {
        let gw = match get_default_gateway() {
            Ok(g) => g,
            Err(e) => panic!("no default gateway on this runner: {e}"),
        };
        const ENDPOINT: &str = "192.0.2.126"; // RFC 5737 TEST-NET-1
        const NET: &str = "198.51.100.0/24"; // RFC 5737 TEST-NET-2

        let (theirs, their_fd) = create_utun_device().expect("a utun (root)");
        let (ours, our_fd) = create_utun_device().expect("a second utun (root)");
        configure_utun_address(&theirs, "198.18.0.1", &1420).expect("their address");
        configure_utun_address(&ours, "198.18.0.2", &1420).expect("our address");
        let _ = cmd("route")
            .args(["-n", "delete", "-host", ENDPOINT])
            .output();
        let theirs_in = cmd("route")
            .args([
                "-n",
                "add",
                "-net",
                "198.51.100.0",
                "-netmask",
                "255.255.255.0",
                "-interface",
                theirs.as_str(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());

        let owned = OwnedRoutes::default();
        let started = configure_routes(&ours, ENDPOINT, &[NET.to_string()], false, &owned).await;
        // What a failed start's unwind (abandon_utun) does with the routes.
        remove_owned_routes(take_owned_routes(&owned));
        let theirs_kept = routed_into("198.51.100.0", "255.255.255.0", &theirs);
        let endpoint_left = host_route_via(ENDPOINT, &gw);

        let _ = cmd("route")
            .args([
                "-n",
                "delete",
                "-net",
                "198.51.100.0",
                "-netmask",
                "255.255.255.0",
            ])
            .output();
        let _ = cmd("route")
            .args(["-n", "delete", "-host", ENDPOINT])
            .output();
        drop(our_fd);
        drop(their_fd);
        assert!(theirs_in, "precondition: the other tunnel's route is in");
        assert!(
            started.is_err(),
            "a start that collided with another tunnel's route reported success"
        );
        assert!(
            theirs_kept,
            "the start took or deleted another tunnel's route"
        );
        assert!(
            !endpoint_left,
            "the failed start left its endpoint route behind"
        );
    }

    fn drop_test_config() -> VpnConfig {
        VpnConfig {
            server_id: "test".into(),
            key_id: "test".into(),
            public_key: String::new(),
            server_public_key: String::new(),
            preshared_key: None,
            endpoint: "192.0.2.127:51820".into(),
            allowed_ips: vec!["0.0.0.0/0".into()],
            dns: vec!["198.18.0.53".into()],
            custom_dns: false,
            client_ip: "198.18.0.3".into(),
            client_ipv6: None,
            allowed_ips_v6: Vec::new(),
            mtu: 1420,
            persistent_keepalive: 25,
        }
    }

    /// MR-2088: a tunnel dropped with its routes still in (a stop() cut short
    /// by the switch-teardown cap, a cancelled start) removes the endpoint
    /// route it pinned. Closing the utun withdraws only the routes INTO it,
    /// and that was all the old Drop did.
    ///
    /// Root-only — it creates a utun, routes TEST-NET-2 into it, pins a
    /// TEST-NET-1 host and drops the tunnel.
    #[tokio::test]
    #[ignore = "mutates host routing; run as root via --ignored (CI does)"]
    async fn a_dropped_tunnel_removes_the_endpoint_route_it_pinned() {
        let gw = match get_default_gateway() {
            Ok(g) => g,
            Err(e) => panic!("no default gateway on this runner: {e}"),
        };
        const ENDPOINT: &str = "192.0.2.127"; // RFC 5737 TEST-NET-1
        const NET: &str = "198.51.100.0/24"; // RFC 5737 TEST-NET-2

        let tunnel = UtunTunnel::create(drop_test_config(), false)
            .await
            .expect("a valid config");
        let (ours, fd) = create_utun_device().expect("a utun (root)");
        configure_utun_address(&ours, "198.18.0.3", &1420).expect("our address");
        *tunnel.utun_fd.write().await = Some(Arc::new(fd));
        let _ = cmd("route")
            .args(["-n", "delete", "-host", ENDPOINT])
            .output();

        let routed = configure_routes(
            &ours,
            ENDPOINT,
            &[NET.to_string()],
            false,
            &tunnel.owned_routes,
        )
        .await;
        let pinned = host_route_via(ENDPOINT, &gw);
        drop(tunnel);
        let left = host_route_via(ENDPOINT, &gw);

        let _ = cmd("route")
            .args(["-n", "delete", "-host", ENDPOINT])
            .output();
        routed.expect("the routes went in");
        assert!(pinned, "precondition: the endpoint route is in");
        assert!(!left, "a dropped tunnel left its endpoint route behind");
    }
}

/// MR-2088: a route is added and deleted with the same qualifiers, counts as
/// ours only while `route -n get` shows it where we put it, and a collision is
/// taken over only from a utun that no longer exists. Pure, so it runs
/// unprivileged in the macOS loop of tests.yml (the Linux twin is
/// tunnel_linux.rs's `owned_route_tests`).
#[cfg(test)]
mod owned_route_tests {
    use super::{
        classify_collision, is_utun_name, route_change_made, take_owned_routes, Collision,
        OwnedRoute, OwnedRoutes, RouteVia,
    };

    fn half(utun: &str) -> OwnedRoute {
        OwnedRoute {
            dst: "0.0.0.0/1".into(),
            via: RouteVia::Interface(utun.into()),
        }
    }

    fn endpoint() -> OwnedRoute {
        OwnedRoute {
            dst: "203.0.113.7/32".into(),
            via: RouteVia::Gateway("192.168.1.1".into()),
        }
    }

    /// `route -n get` for the `0.0.0.0/1` half-default into `iface`: `route`
    /// prints the address 0.0.0.0 as `default`, and an `-interface` route has
    /// no gateway line.
    fn low_half_into(iface: &str) -> String {
        format!(
            "   route to: default\ndestination: default\n       mask: 128.0.0.0\n  interface: {iface}\n      flags: <UP,DONE,STATIC>\n"
        )
    }

    #[test]
    fn the_delete_is_qualified_exactly_as_the_add() {
        assert_eq!(
            half("utun3").route_args("add").unwrap(),
            [
                "-n",
                "add",
                "-net",
                "0.0.0.0",
                "-netmask",
                "128.0.0.0",
                "-interface",
                "utun3"
            ]
        );
        assert_eq!(
            half("utun3").route_args("delete").unwrap(),
            [
                "-n",
                "delete",
                "-net",
                "0.0.0.0",
                "-netmask",
                "128.0.0.0",
                "-interface",
                "utun3"
            ]
        );
        assert_eq!(
            endpoint().route_args("delete").unwrap(),
            ["-n", "delete", "-host", "203.0.113.7", "192.168.1.1"]
        );
        let lan = OwnedRoute {
            dst: "10.0.0.0/8".into(),
            via: RouteVia::Gateway("192.168.1.1".into()),
        };
        assert_eq!(
            lan.route_args("add").unwrap(),
            [
                "-n",
                "add",
                "-net",
                "10.0.0.0",
                "-netmask",
                "255.0.0.0",
                "192.168.1.1"
            ]
        );
        // A prefix `route` cannot name is never handed to it — a /0 above all.
        let default = OwnedRoute {
            dst: "0.0.0.0/0".into(),
            via: RouteVia::Interface("utun3".into()),
        };
        assert_eq!(default.route_args("delete"), None);
    }

    /// MR-740: only a route via the physical gateway outlives the utun, so
    /// only such a route goes on the crash-recovery record.
    #[test]
    fn only_routes_via_the_gateway_go_on_the_crash_record() {
        assert_eq!(half("utun3").gateway_record(), None);
        assert_eq!(
            endpoint().gateway_record(),
            Some(crate::vpn::route_journal::GatewayRoute {
                dst: "203.0.113.7/32".into(),
                via: "192.168.1.1".into(),
                dev: None,
            })
        );
    }

    /// A route is ours only while the table shows it where we put it. The
    /// same prefix through another VPN's utun, via another VPN's gateway, or
    /// the host default a lookup falls back to, is not.
    #[test]
    fn a_route_is_ours_only_where_we_put_it() {
        assert!(half("utun3").described_by(&low_half_into("utun3")));
        assert!(!half("utun3").described_by(&low_half_into("utun5")));
        let openvpn = "   route to: default\ndestination: default\n       mask: 128.0.0.0\n    gateway: 10.8.0.1\n  interface: utun5\n";
        assert!(!half("utun3").described_by(openvpn));
        let host_default = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert!(!half("utun3").described_by(host_default));

        let pinned = "   route to: 203.0.113.7\ndestination: 203.0.113.7\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert!(endpoint().described_by(pinned));
        assert!(!endpoint().described_by(&pinned.replace("192.168.1.1", "192.168.1.254")));
        assert!(!endpoint().described_by(host_default));
    }

    /// "File exists" on an allowed IP: a route into our own utun is in
    /// already, and only one into a utun that no longer exists is taken over.
    /// Another VPN's live utun, a non-utun interface, the host default and a
    /// failed lookup are left alone, and the start fails.
    #[test]
    fn a_collision_is_taken_over_only_from_a_dead_utun() {
        // `exists`: what the system answers about every interface it is asked
        // about.
        let at = |iface: &str, exists: bool| {
            classify_collision(
                &low_half_into(iface),
                "0.0.0.0/1",
                "utun3",
                move |_: &str| exists,
            )
        };
        assert_eq!(at("utun3", true), Collision::Ours);
        assert_eq!(at("utun7", false), Collision::Stale);
        assert_eq!(at("utun7", true), Collision::Foreign);
        assert_eq!(at("en0", false), Collision::Foreign);

        let host_default = "destination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(
            classify_collision(host_default, "0.0.0.0/1", "utun3", |_: &str| false),
            Collision::Foreign
        );
        assert_eq!(
            classify_collision(
                "route: writing to routing socket: not in table\n",
                "0.0.0.0/1",
                "utun3",
                |_: &str| false
            ),
            Collision::Foreign
        );
    }

    /// macOS `route` exits 0 when the kernel refuses the change and only
    /// warns on stderr: by its status alone, a collision read as an add of
    /// ours (seen on the CI runner: another tunnel's route was recorded as
    /// ours, and a pre-existing endpoint route deleted at teardown).
    #[test]
    fn a_refused_change_is_not_read_as_made() {
        assert!(route_change_made(true, ""));
        assert!(route_change_made(true, "\n"));
        assert!(!route_change_made(
            true,
            "route: writing to routing socket: File exists\n"
        ));
        assert!(!route_change_made(
            true,
            "route: writing to routing socket: not in table\n"
        ));
        assert!(!route_change_made(false, ""));
        assert!(!route_change_made(
            false,
            "route: must be root to alter routing table\n"
        ));
    }

    #[test]
    fn only_a_utun_name_is_reclaimable() {
        assert!(is_utun_name("utun0") && is_utun_name("utun12"));
        for name in ["utun", "en0", "utun1a", "-utun1", "ipsec0", ""] {
            assert!(!is_utun_name(name), "{name}");
        }
    }

    /// Teardown takes the routes exactly once: stop(), the unwind and Drop
    /// cannot each delete the same set.
    #[test]
    fn owned_routes_are_taken_once() {
        let owned = OwnedRoutes::default();
        owned.lock().unwrap().push(half("utun3"));
        assert_eq!(take_owned_routes(&owned).len(), 1);
        assert!(take_owned_routes(&owned).is_empty());
    }
}

/// The utun descriptor is close-on-exec. Run UNPRIVILEGED on the macOS leg of
/// tests.yml: creating the kernel-control socket needs no root (connecting it
/// to the utun control does), so the very function create_utun_device() opens
/// its device through is what is checked.
#[cfg(test)]
mod utun_fd_tests {
    use super::open_utun_control_socket;
    use crate::vpn::device_fd::set_cloexec;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn is_cloexec(fd: &OwnedFd) -> bool {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD: {}", std::io::Error::last_os_error());
        flags & libc::FD_CLOEXEC != 0
    }

    /// The regression: the socket was created without FD_CLOEXEC, so a child
    /// spawned while the tunnel was up (a re-spawned xray) kept a copy and the
    /// utun outlived stop().
    #[test]
    fn the_utun_control_socket_is_close_on_exec() {
        let fd = open_utun_control_socket().expect("an AF_SYSTEM control socket");
        // SAFETY: just created, and owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        assert!(
            is_cloexec(&fd),
            "the utun socket is inherited by every child spawned while it is open"
        );
    }

    /// The control for the test above (a fresh socket() does NOT start out
    /// close-on-exec on Darwin, so the flag there is set_cloexec's doing),
    /// and set_cloexec refuses a bad descriptor rather than passing it.
    #[test]
    fn set_cloexec_sets_the_flag_a_plain_socket_lacks_and_refuses_a_bad_fd() {
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        assert!(raw >= 0, "socket: {}", std::io::Error::last_os_error());
        // SAFETY: just created, and owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(!is_cloexec(&fd), "a plain socket() starts out inheritable");

        set_cloexec(fd.as_raw_fd()).expect("a valid fd");
        assert!(is_cloexec(&fd), "FD_CLOEXEC was not set");

        assert!(set_cloexec(-1).is_err(), "a bad fd passed as close-on-exec");
    }
}
