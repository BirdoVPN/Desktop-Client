//! What the OS knows about the network, for the reconnect engine — without
//! sending a single packet.
//!
//! REPLACES `network_monitor.rs` (W1-011, probe half; W1-018). That module
//! TCP-connected to 1.1.1.1, 9.9.9.9 and 8.8.8.8 every 5 s:
//!   * the probes were routed by a dead tunnel's own /1 routes into that dead
//!     tunnel, read "offline", and parked auto-reconnect forever (W1-001);
//!   * during every reconnect gap they left the physical NIC — through the
//!     kill switch's own-process permit — showing three third parties the
//!     user's real address, and ~17k handshakes a day went to Cloudflare while
//!     connected;
//!   * `stop()`/`start()` raced and left duplicate probe loops behind.
//!
//! The signal now is the ROUTING TABLE: "is there a physical IPv4 default
//! route?". It is local state, costs no traffic, is unaffected by our WFP
//! block-all, and is never ours — the tunnel installs 0.0.0.0/1 + 128.0.0.0/1,
//! never a /0. Reachability of Birdo is then tested by the only thing that can
//! answer it honestly: the WireGuard handshake of the next dial.
//!
//! Why not `GetNetworkConnectivityHint`: its level comes from NCSI's active
//! probe, which runs in another process. While our block-all is engaged (the
//! whole reconnect gap) that probe is blocked, so the hint degrades to
//! LocalAccess and would read "offline" in exactly the window it is consulted
//! — the W1-001 trap again, one layer down.
//!
//! Events (Windows): `NotifyRouteChange2` for default-route changes
//! (Wi-Fi ⇄ Ethernet, a dock, a lost lease) and
//! `PowerRegisterSuspendResumeNotification` for resume. Both are registered
//! once per process and never cancelled (Vista+ / Windows 8+; the app requires
//! Windows 10). There is no per-session loop to start or stop, so nothing can
//! be duplicated.
//!
//! Linux reads `/proc/net/route` (a file read, zero packets) when asked and has
//! no event source yet; macOS has neither yet and reports `Unknown`, which the
//! reconnect engine treats as online (the handshake decides).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use tokio::sync::watch;

use super::reconnect_policy::Connectivity;

/// The physical default route a session is built over. (Never built on macOS,
/// which has no route signal yet.)
#[cfg_attr(target_os = "macos", allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRoute {
    pub gateway: Ipv4Addr,
    pub interface: u32,
}

/// One IPv4 default route (0.0.0.0/0 via a real next hop) as the routing
/// table reports it.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultRouteCandidate {
    pub gateway: Ipv4Addr,
    pub interface: u32,
    /// The route's own metric (`MIB_IPFORWARD_ROW2::Metric`).
    pub route_metric: u32,
    /// The interface's metric (`MIB_IPINTERFACE_ROW::Metric`); `None` when it
    /// could not be read.
    pub interface_metric: Option<u32>,
}

/// The default route Windows itself prefers (REVIEW-WIN-005), with a tie-break
/// that does not depend on table order.
///
/// Windows routes by route metric PLUS interface metric. Ranking by the route
/// metric alone, first-found wins, made the pick follow `GetIpForwardTable2`'s
/// row order whenever two DHCP defaults both carried route metric 0 — the
/// normal case for a docked laptop on Ethernet and Wi-Fi at once. A Wi-Fi
/// renew that reordered the table flipped the pick, the session read that as
/// `Dead(PathChanged)` and tore a healthy tunnel down, a blackout the breaker
/// does not count and so could repeat indefinitely. The pinned host route
/// could equally land on the interface Windows was not using.
///
/// Ties on the effective metric go to the lowest interface index, then the
/// lowest gateway, so the same table always yields the same route whatever
/// order it is read in. An interface whose metric cannot be read ranks last:
/// it is usually going away.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn preferred_default_route(candidates: &[DefaultRouteCandidate]) -> Option<PhysicalRoute> {
    candidates
        .iter()
        .min_by_key(|c| {
            let effective = c
                .interface_metric
                .map_or(u32::MAX, |m| m.saturating_add(c.route_metric));
            (effective, c.interface, u32::from(c.gateway))
        })
        .map(|c| PhysicalRoute {
            gateway: c.gateway,
            interface: c.interface,
        })
}

static RESUMES: AtomicU64 = AtomicU64::new(0);
static EVENTS: OnceLock<watch::Sender<u64>> = OnceLock::new();

fn events() -> &'static watch::Sender<u64> {
    EVENTS.get_or_init(|| watch::channel(0).0)
}

/// Wakes on every (debounced) default-route change and every resume.
pub fn subscribe() -> watch::Receiver<u64> {
    events().subscribe()
}

/// How many times the machine has resumed from sleep since start-up.
pub fn resume_count() -> u64 {
    RESUMES.load(Ordering::SeqCst)
}

/// Whether this platform provides the default-route signal at all.
const HAS_ROUTE_SIGNAL: bool = cfg!(any(target_os = "windows", target_os = "linux"));

/// The lowest-metric physical IPv4 default route, read live.
pub fn default_route() -> Option<PhysicalRoute> {
    #[cfg(target_os = "windows")]
    {
        super::tunnel::default_route_native()
            .map(|(gateway, interface)| PhysicalRoute { gateway, interface })
    }
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let (gateway, iface) = parse_proc_net_route(&table)?;
        let name = std::ffi::CString::new(iface).ok()?;
        // SAFETY: `name` is a valid NUL-terminated C string for the call.
        let interface = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Some(PhysicalRoute { gateway, interface })
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

/// The address this machine reaches its physical default gateway from: what
/// a request bound to leave AROUND the tunnel uses (REVIEW-WIN2-007). `None`
/// without a default route. The tunnel's /1 routes do not capture the gateway
/// (it is on the physical interface's own, more specific subnet).
#[cfg(target_os = "windows")]
pub fn physical_source_address() -> Option<std::net::IpAddr> {
    source_address_toward(std::net::IpAddr::V4(default_route()?.gateway))
}

/// The local address the routing table picks to reach `to`. A connected UDP
/// socket reports it, and connecting one sends nothing.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn source_address_toward(to: std::net::IpAddr) -> Option<std::net::IpAddr> {
    if to.is_unspecified() {
        return None;
    }
    let any: std::net::IpAddr = match to {
        std::net::IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        std::net::IpAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = std::net::UdpSocket::bind((any, 0)).ok()?;
    socket.connect((to, 9)).ok()?;
    let local = socket.local_addr().ok()?.ip();
    (!local.is_unspecified()).then_some(local)
}

/// `route` as a connectivity reading (see the module docs).
pub fn connectivity_of(route: Option<&PhysicalRoute>) -> Connectivity {
    if !HAS_ROUTE_SIGNAL {
        Connectivity::Unknown
    } else if route.is_some() {
        Connectivity::Online
    } else {
        Connectivity::Offline
    }
}

/// The default route in a `/proc/net/route` dump: destination and mask
/// 0.0.0.0, flags UP|GATEWAY, not our own `birdo0`. Fields are little-endian
/// hex. Lowest metric wins.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_route(table: &str) -> Option<(Ipv4Addr, String)> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    let mut best: Option<(u32, Ipv4Addr, String)> = None;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[0] == "birdo0" {
            continue;
        }
        let hex = |s: &str| u32::from_str_radix(s, 16).ok();
        let (Some(dest), Some(gw), Some(flags), Some(metric), Some(mask)) = (
            hex(f[1]),
            hex(f[2]),
            hex(f[3]),
            f[6].parse::<u32>().ok(),
            hex(f[7]),
        ) else {
            continue;
        };
        if dest != 0 || mask != 0 || flags & (RTF_UP | RTF_GATEWAY) != RTF_UP | RTF_GATEWAY {
            continue;
        }
        let gateway = Ipv4Addr::from(gw.to_le_bytes());
        if best.as_ref().is_none_or(|(m, _, _)| metric < *m) {
            best = Some((metric, gateway, f[0].to_string()));
        }
    }
    best.map(|(_, gateway, iface)| (gateway, iface))
}

/// Register the OS notifications. Idempotent; call once at start-up.
pub fn start() {
    #[cfg(target_os = "windows")]
    windows_events::start();
}

#[cfg(target_os = "windows")]
mod windows_events {
    use std::sync::mpsc;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use windows::Win32::Foundation::{HANDLE, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        NotifyRouteChange2, MIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE,
    };
    use windows::Win32::Networking::WinSock::AF_INET;
    use windows::Win32::System::Power::{
        PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC};

    use super::{events, RESUMES};

    /// Changes arrive in bursts (a dock brings several interfaces and routes
    /// up at once); one re-evaluation per burst is enough.
    const DEBOUNCE: Duration = Duration::from_secs(1);

    enum Event {
        RouteChanged,
        Resumed,
    }

    static SENDER: OnceLock<Mutex<mpsc::Sender<Event>>> = OnceLock::new();
    static STARTED: OnceLock<()> = OnceLock::new();

    fn notify(event: Event) {
        if let Some(tx) = SENDER.get() {
            let _ = tx.lock().map(|tx| tx.send(event));
        }
    }

    /// `PIPFORWARD_CHANGE_CALLBACK`, on a thread-pool thread. Only default
    /// routes matter: our own /1 and host routes change on every connect.
    unsafe extern "system" fn on_route_change(
        _context: *const core::ffi::c_void,
        row: *const MIB_IPFORWARD_ROW2,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        // SAFETY: `row` is either null (initial notification, which we do not
        // request) or valid for the duration of the callback.
        if let Some(row) = unsafe { row.as_ref() } {
            if row.DestinationPrefix.PrefixLength == 0 {
                notify(Event::RouteChanged);
            }
        }
    }

    /// `PDEVICE_NOTIFY_CALLBACK_ROUTINE`. Must return ERROR_SUCCESS.
    unsafe extern "system" fn on_power(
        _context: *const core::ffi::c_void,
        kind: u32,
        _setting: *const core::ffi::c_void,
    ) -> u32 {
        if kind == PBT_APMRESUMEAUTOMATIC {
            notify(Event::Resumed);
        }
        0
    }

    pub(super) fn start() {
        if STARTED.set(()).is_err() {
            return;
        }
        let (tx, rx) = mpsc::channel::<Event>();
        let _ = SENDER.set(Mutex::new(tx));

        // One thread for the process lifetime: coalesce, then publish.
        std::thread::spawn(move || {
            while let Ok(first) = rx.recv() {
                let mut resumed = matches!(first, Event::Resumed);
                std::thread::sleep(DEBOUNCE);
                while let Ok(more) = rx.try_recv() {
                    resumed |= matches!(more, Event::Resumed);
                }
                if resumed {
                    RESUMES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tracing::info!("System resumed — the tunnel will be re-verified");
                } else {
                    tracing::debug!("Default route changed");
                }
                events().send_modify(|n| *n = n.wrapping_add(1));
                // An interface that just got its gateway is an uplink now, not
                // a host-only network the inbound block may exempt.
                crate::vpn::wfp::refresh_after_network_change();
            }
        });

        let mut route_handle = HANDLE::default();
        // SAFETY: the callback is a plain `extern "system"` fn with the
        // documented signature, it touches only process-global state, and the
        // registration is never cancelled, so no context pointer can dangle.
        let rc: WIN32_ERROR = unsafe {
            NotifyRouteChange2(
                AF_INET,
                Some(on_route_change),
                std::ptr::null(),
                false, // InitialNotification: BOOLEAN FALSE (windows 0.62 binds it as bool)
                &mut route_handle,
            )
        };
        if rc.0 != 0 {
            tracing::warn!(
                "Route-change notifications unavailable (rc={}) — network changes are \
                 caught by the handshake-age rule instead",
                rc.0
            );
        }

        // The subscribe parameters must outlive the registration, which lasts
        // for the process: leak one small struct deliberately.
        let params: &'static mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
            Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
                Callback: Some(on_power),
                Context: std::ptr::null_mut(),
            }));
        let mut power_handle: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: with DEVICE_NOTIFY_CALLBACK the recipient is a pointer to a
        // DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS (documented contract), valid for
        // the process lifetime (leaked above).
        let rc = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                HANDLE(params as *mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS as *mut _),
                &mut power_handle,
            )
        };
        if rc.0 != 0 {
            tracing::warn!(
                "Resume notifications unavailable (rc={}) — a resume is caught by the \
                 handshake-age rule instead",
                rc.0
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REVIEW-WIN2-007: the source address is what the routing table picks,
    /// read off a connected UDP socket that sends nothing (loopback here).
    #[test]
    fn the_source_address_is_the_one_the_route_picks() {
        let loopback = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(source_address_toward(loopback), Some(loopback));
        assert_eq!(
            source_address_toward(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            None,
            "an on-link default route has no gateway to aim at"
        );
    }

    const TABLE: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
        birdo0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
        wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
        eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
        eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

    #[test]
    fn proc_net_route_yields_the_lowest_metric_physical_default() {
        assert_eq!(
            parse_proc_net_route(TABLE),
            Some((Ipv4Addr::new(192, 168, 1, 1), "eth0".to_string()))
        );
    }

    #[test]
    fn no_default_route_reads_as_none() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
            eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n\
            birdo0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n";
        assert_eq!(parse_proc_net_route(table), None);
    }

    #[test]
    fn connectivity_is_the_presence_of_a_route() {
        let route = PhysicalRoute {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface: 7,
        };
        if HAS_ROUTE_SIGNAL {
            assert_eq!(connectivity_of(Some(&route)), Connectivity::Online);
            assert_eq!(connectivity_of(None), Connectivity::Offline);
        } else {
            assert_eq!(connectivity_of(None), Connectivity::Unknown);
        }
    }

    /// REVIEW-WIN-005: a docked laptop with Ethernet and Wi-Fi defaults both at
    /// route metric 0 must pick the same route whichever order the table is
    /// read in — the one Windows uses (lower interface metric) — and an exact
    /// tie must break on a stable key, not on row order.
    #[test]
    fn the_default_route_is_the_one_windows_uses_in_any_table_order() {
        let ethernet = DefaultRouteCandidate {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface: 12,
            route_metric: 0,
            interface_metric: Some(25),
        };
        let wifi = DefaultRouteCandidate {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface: 7,
            route_metric: 0,
            interface_metric: Some(35),
        };
        let want = Some(PhysicalRoute {
            gateway: ethernet.gateway,
            interface: 12,
        });
        assert_eq!(preferred_default_route(&[ethernet, wifi]), want);
        assert_eq!(preferred_default_route(&[wifi, ethernet]), want);

        // The route metric counts too: a manual high route metric on the
        // Ethernet default hands the session to Wi-Fi, as Windows would.
        let heavy = DefaultRouteCandidate {
            route_metric: 50,
            ..ethernet
        };
        assert_eq!(
            preferred_default_route(&[heavy, wifi]).map(|r| r.interface),
            Some(7)
        );

        // Equal effective metrics: lowest interface index, in either order.
        let twin = DefaultRouteCandidate {
            interface_metric: Some(25),
            ..wifi
        };
        assert_eq!(
            preferred_default_route(&[ethernet, twin]).map(|r| r.interface),
            Some(7)
        );
        assert_eq!(
            preferred_default_route(&[twin, ethernet]).map(|r| r.interface),
            Some(7)
        );

        // An interface whose metric could not be read ranks last.
        let unknown = DefaultRouteCandidate {
            interface_metric: None,
            ..twin
        };
        assert_eq!(
            preferred_default_route(&[unknown, ethernet]).map(|r| r.interface),
            Some(12)
        );
        assert_eq!(preferred_default_route(&[]), None);
    }

    /// W1-011: nothing in the reconnect engine may send a packet to find out
    /// whether the network is up. Pins that the third-party probe targets are
    /// gone from the source that decides connectivity.
    #[test]
    fn no_connectivity_probe_targets_remain() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vpn");
        for file in [
            "network_events.rs",
            "auto_reconnect.rs",
            "reconnect_policy.rs",
        ] {
            let text = std::fs::read_to_string(dir.join(file)).expect("read source");
            // Built at run time so this file does not match its own needles.
            for host in ["1.1.1.1", "9.9.9.9", "8.8.8.8"] {
                let target = [host, ":443"].concat();
                assert!(
                    !text.contains(&target),
                    "{file} probes {target} again (W1-011)"
                );
            }
            assert!(
                !text.contains(&["TcpStream", "::connect"].concat()),
                "{file}"
            );
        }
        assert!(
            !dir.join("network_monitor.rs").exists(),
            "the probing monitor is back"
        );
    }

    /// Google and Quad9 are retired, so no resolv.conf we write may name
    /// them either: the Linux restore's last resort (tunnel_linux.rs
    /// `FALLBACK_NAMESERVERS`) wrote 1.1.1.1 + 8.8.8.8 until it became
    /// Cloudflare's 1.1.1.1 + 1.0.0.1. Read as text because tunnel_linux.rs
    /// compiles only on Linux, and this test runs in the Windows job too
    /// (tunnel_linux.rs's own test of the content runs on the Linux leg).
    #[test]
    fn no_retired_public_resolver_in_the_resolv_conf_we_write() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vpn");
        let linux = std::fs::read_to_string(dir.join("tunnel_linux.rs")).expect("read source");
        let fallback = linux
            .lines()
            .find(|line| line.starts_with("const FALLBACK_NAMESERVERS"))
            .expect("tunnel_linux.rs declares FALLBACK_NAMESERVERS");
        assert!(fallback.contains("\"1.1.1.1\", \"1.0.0.1\""), "{fallback}");
        for host in ["8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"] {
            assert!(!fallback.contains(host), "{fallback}");
            let line = ["nameserver ", host].concat();
            assert!(
                !linux.contains(&line),
                "tunnel_linux.rs writes `{line}` into resolv.conf"
            );
        }
    }
}
