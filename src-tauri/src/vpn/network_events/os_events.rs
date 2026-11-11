//! Network-change and resume sources for Linux and macOS (MA-DESK-010,
//! A-M49), feeding the same signal the Windows callbacks feed
//! (`network_events::subscribe()` and `resume_count()`).
//!
//! No new dependency: only `libc`, already linked on both platforms.
//!
//! * Linux route changes: an `AF_NETLINK`/`NETLINK_ROUTE` socket subscribed to
//!   the IPv4 route group. A default route added, replaced or removed in the
//!   main table (Wi-Fi to Ethernet, a lost lease, a dock) is one event.
//! * macOS route changes: an `AF_ROUTE` socket, which the kernel feeds every
//!   routing-table change. Only an IPv4 default route being added, deleted or
//!   changed is an event, as on Windows (the tunnel's own /1 and host routes
//!   change on every connect and must not wake the engine).
//! * Resume, both: a suspend detector. `CLOCK_MONOTONIC` (Linux) and
//!   `CLOCK_UPTIME_RAW` (macOS) stand still while the machine sleeps;
//!   `CLOCK_BOOTTIME` (Linux) and `CLOCK_MONOTONIC` (macOS) keep running. A
//!   poll that finds the second clock far ahead of the first has just woken
//!   from sleep. logind's `PrepareForSleep` (D-Bus) and
//!   `NSWorkspaceDidWakeNotification` (AppKit run loop) would announce it a
//!   few seconds sooner, but each needs a crate that is not a direct
//!   dependency of this app, and a poll needs no run loop and no session bus
//!   (a system service or a minimal desktop has neither). Detection latency
//!   is at most [`CLOCK_POLL`].
//!
//! Every source degrades to what the app did before: if one cannot start it
//! logs a warning and the liveness tick and the handshake find the change.
//! Nothing here panics.

// Each platform compiles only some of these; the pure logic is compiled (and
// tested) everywhere so the Windows job covers it too.
#![allow(dead_code)]

use std::sync::mpsc;
use std::time::Duration;

/// Changes arrive in bursts (a dock or a Wi-Fi join brings several routes
/// up at once); one re-evaluation per burst is enough.
pub(super) const DEBOUNCE: Duration = Duration::from_secs(1);

/// How often the suspend detector reads the clocks.
pub(super) const CLOCK_POLL: Duration = Duration::from_secs(5);

/// Sleep time at or above which a poll counts as a resume. The clocks differ
/// only by time spent suspended, never by scheduling delay, so this only
/// has to clear read noise; a lid closed for less is not worth a re-prove.
pub(super) const SUSPEND_THRESHOLD: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event {
    RouteChanged,
    Resumed,
}

/// Coalesce bursts: after the first event wait [`DEBOUNCE`]-long, fold in
/// everything that arrived meanwhile, then call `publish(resumed)` once.
/// Returns when every sender is gone.
pub(super) fn run_publisher(
    rx: mpsc::Receiver<Event>,
    debounce: Duration,
    mut publish: impl FnMut(bool),
) {
    while let Ok(first) = rx.recv() {
        let mut resumed = first == Event::Resumed;
        std::thread::sleep(debounce);
        while let Ok(more) = rx.try_recv() {
            resumed |= more == Event::Resumed;
        }
        publish(resumed);
    }
}

/// Spots a suspend from two clocks: `awake` stops while the machine sleeps,
/// `elapsed` does not.
#[derive(Debug, Default)]
pub(super) struct SuspendDetector {
    last: Option<(Duration, Duration)>,
}

impl SuspendDetector {
    /// Feed one reading of both clocks; `true` when at least `threshold` of
    /// sleep passed since the previous reading. A clock that went backwards
    /// reads as no sleep.
    pub(super) fn observe(
        &mut self,
        awake: Duration,
        elapsed: Duration,
        threshold: Duration,
    ) -> bool {
        let Some((last_awake, last_elapsed)) = self.last.replace((awake, elapsed)) else {
            return false;
        };
        let slept = elapsed
            .saturating_sub(last_elapsed)
            .saturating_sub(awake.saturating_sub(last_awake));
        slept >= threshold
    }
}

// ---------------------------------------------------------------------------
// Linux: rtnetlink message classification
// ---------------------------------------------------------------------------

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const AF_INET_FAMILY: u8 = 2;
const RT_TABLE_MAIN: u32 = 254;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;
/// sizeof(struct nlmsghdr) and sizeof(struct rtmsg).
const NLMSG_HDRLEN: usize = 16;
const RTMSG_LEN: usize = 12;
/// sizeof(struct ifinfomsg) and sizeof(struct ifaddrmsg); both carry the
/// interface index as a u32 at offset 4.
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const IF_INDEX_AT: usize = 4;
/// Offset of `ifi_change` in `ifinfomsg`: the mask of flag bits that changed.
const IF_CHANGE_AT: usize = 12;
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x1_0000;
/// Link attribute carrying a wireless-extension event (scan, roam, ...).
const IFLA_WIRELESS: u16 = 11;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// Whether a datagram from the route group (one or more netlink messages)
/// reports an IPv4 default route being added or removed in the main table,
/// other than on `ignore_oif` (our own tunnel interface; 0 ignores nothing).
/// A truncated or malformed message reads as "no".
pub(super) fn netlink_default_route_change(buf: &[u8], ignore_oif: u32) -> bool {
    let mut at = 0usize;
    while at + NLMSG_HDRLEN <= buf.len() {
        let Some(len) = read_u32(buf, at).map(|l| l as usize) else {
            return false;
        };
        let Some(kind) = read_u16(buf, at + 4) else {
            return false;
        };
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            return false;
        }
        if kind == NLMSG_DONE || kind == NLMSG_ERROR {
            return false;
        }
        if (kind == RTM_NEWROUTE || kind == RTM_DELROUTE)
            && route_message_is_default(&buf[at + NLMSG_HDRLEN..at + len], ignore_oif)
        {
            return true;
        }
        at += align4(len);
    }
    false
}

/// Whether a datagram from the link or IPv4-address group reports a link
/// going up or down, or an IPv4 address being added or removed, on any
/// interface other than `ignore_ifindex` (our own tunnel; 0 ignores nothing).
/// A dropped link does not always produce an RTM_DELROUTE, so these count as
/// a network change too. A truncated or malformed message reads as "no".
pub(super) fn netlink_link_or_addr_change(buf: &[u8], ignore_ifindex: u32) -> bool {
    let mut at = 0usize;
    while at + NLMSG_HDRLEN <= buf.len() {
        let Some(len) = read_u32(buf, at).map(|l| l as usize) else {
            return false;
        };
        let Some(kind) = read_u16(buf, at + 4) else {
            return false;
        };
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            return false;
        }
        if kind == NLMSG_DONE || kind == NLMSG_ERROR {
            return false;
        }
        let body = &buf[at + NLMSG_HDRLEN..at + len];
        let hit = match kind {
            // A link going away always counts. RTM_NEWLINK is also sent for
            // MTU, queue, statistics and Wi-Fi (IFLA_WIRELESS) updates, which
            // must not wake the tunnel; only a change of the up/running
            // state does (a new link reports ifi_change = 0xFFFFFFFF).
            RTM_DELLINK => body.len() >= IFINFOMSG_LEN,
            RTM_NEWLINK => link_state_changed(body),
            RTM_NEWADDR | RTM_DELADDR => body.len() >= IFADDRMSG_LEN && body[0] == AF_INET_FAMILY,
            _ => false,
        };
        if hit {
            let index = read_u32(body, IF_INDEX_AT).unwrap_or(0);
            if !(ignore_ifindex != 0 && index == ignore_ifindex) {
                return true;
            }
        }
        at += align4(len);
    }
    false
}

/// `body` is the `struct ifinfomsg` and its attributes: whether the up or
/// running state changed and the message is not a wireless-extension event.
/// A truncated attribute list reads as "no".
fn link_state_changed(body: &[u8]) -> bool {
    if body.len() < IFINFOMSG_LEN {
        return false;
    }
    let Some(change) = read_u32(body, IF_CHANGE_AT) else {
        return false;
    };
    if change & (IFF_UP | IFF_RUNNING | IFF_LOWER_UP) == 0 {
        return false;
    }
    let mut at = IFINFOMSG_LEN;
    while at + 4 <= body.len() {
        let (Some(alen), Some(atype)) = (read_u16(body, at), read_u16(body, at + 2)) else {
            return false;
        };
        let alen = usize::from(alen);
        if alen < 4 || at + alen > body.len() {
            return false;
        }
        // The type's nested/byte-order flag bits are masked off.
        if atype & 0x3fff == IFLA_WIRELESS {
            return false;
        }
        at += align4(alen);
    }
    true
}

/// `body` is the `struct rtmsg` and its attributes.
fn route_message_is_default(body: &[u8], ignore_oif: u32) -> bool {
    if body.len() < RTMSG_LEN {
        return false;
    }
    let (family, dst_len, table_byte) = (body[0], body[1], body[4]);
    if family != AF_INET_FAMILY || dst_len != 0 {
        return false;
    }
    let mut table = u32::from(table_byte);
    let mut oif = 0u32;
    let mut at = RTMSG_LEN;
    while at + 4 <= body.len() {
        let (Some(alen), Some(atype)) = (read_u16(body, at), read_u16(body, at + 2)) else {
            break;
        };
        let alen = usize::from(alen);
        if alen < 4 || at + alen > body.len() {
            break;
        }
        match atype {
            RTA_TABLE => table = read_u32(body, at + 4).unwrap_or(table),
            RTA_OIF => oif = read_u32(body, at + 4).unwrap_or(0),
            _ => {}
        }
        at += align4(alen);
    }
    table == RT_TABLE_MAIN && !(ignore_oif != 0 && oif == ignore_oif)
}

// ---------------------------------------------------------------------------
// macOS: PF_ROUTE message classification
// ---------------------------------------------------------------------------

const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_CHANGE: u8 = 0x3;
const RTA_DST: i32 = 0x1;
const RTA_NETMASK: i32 = 0x4;
/// The sockaddr slots, in the order the kernel lays them out after the
/// header: DST, GATEWAY, NETMASK, GENMASK, IFP, IFA, AUTHOR, BRD.
const RTA_SLOTS: i32 = 8;
/// sizeof(struct rt_msghdr) on Darwin.
const RT_MSGHDR_LEN: usize = 92;

/// Whether one `PF_ROUTE` message is an IPv4 default route (0.0.0.0/0, which
/// the kernel sends with a zero netmask) being added, deleted or changed.
/// Anything short or unrecognised reads as "no".
pub(super) fn route_msg_is_default_v4(msg: &[u8]) -> bool {
    if msg.len() < RT_MSGHDR_LEN {
        return false;
    }
    let kind = msg[3];
    if kind != RTM_ADD && kind != RTM_DELETE && kind != RTM_CHANGE {
        return false;
    }
    let addrs = match msg.get(12..16).and_then(|b| b.try_into().ok()) {
        Some(b) => i32::from_ne_bytes(b),
        None => return false,
    };
    if addrs & RTA_DST == 0 || addrs & RTA_NETMASK == 0 {
        return false;
    }
    let mut at = RT_MSGHDR_LEN;
    let mut dst_is_zero_v4 = false;
    let mut mask_is_zero = false;
    for slot in 0..RTA_SLOTS {
        let bit = 1 << slot;
        if addrs & bit == 0 {
            continue;
        }
        let Some(&sa_len) = msg.get(at) else {
            return false;
        };
        let sa_len = usize::from(sa_len);
        // The kernel rounds each sockaddr up to 4 bytes; a zero length still
        // occupies 4.
        let stride = if sa_len == 0 { 4 } else { align4(sa_len) };
        if at + stride > msg.len() {
            return false;
        }
        let sa = &msg[at..at + stride];
        match bit {
            RTA_DST => {
                // sockaddr_in: len, family, port(2), addr(4).
                dst_is_zero_v4 = sa_len >= 8
                    && sa[1] == AF_INET_FAMILY
                    && sa.get(4..8).is_some_and(|a| a == [0u8; 4]);
            }
            RTA_NETMASK => {
                // Bytes past `sa_len` are absent, i.e. zero. A mask that
                // stops before the address bytes is the zero mask.
                let present = sa_len.min(8).saturating_sub(4);
                mask_is_zero = sa
                    .get(4..4 + present)
                    .is_none_or(|a| a.iter().all(|&b| b == 0));
            }
            _ => {}
        }
        at += stride;
    }
    dst_is_zero_v4 && mask_is_zero
}

// ---------------------------------------------------------------------------
// Platform glue
// ---------------------------------------------------------------------------

/// Start the sources for this platform. `publish(resumed)` is called once per
/// debounced burst. Idempotent.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn start(publish: fn(bool)) {
    use std::sync::OnceLock;
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let (tx, rx) = mpsc::channel::<Event>();
    if let Err(e) = std::thread::Builder::new()
        .name("net-events-publish".into())
        .spawn(move || run_publisher(rx, DEBOUNCE, publish))
    {
        tracing::warn!("Network event thread did not start ({e}) — changes are caught by the handshake-age rule instead");
        return;
    }

    let route_tx = tx.clone();
    if let Err(e) = std::thread::Builder::new()
        .name("net-events-route".into())
        .spawn(move || route_loop(route_tx))
    {
        tracing::warn!("Route-change source did not start ({e}) — network changes are caught by the handshake-age rule instead");
    }
    if let Err(e) = std::thread::Builder::new()
        .name("net-events-resume".into())
        .spawn(move || resume_loop(tx))
    {
        tracing::warn!("Resume detector did not start ({e}) — a resume is caught by the handshake-age rule instead");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_clock(id: libc::clockid_t) -> Option<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the call.
    let rc = unsafe { libc::clock_gettime(id, &mut ts) };
    if rc != 0 {
        return None;
    }
    Some(Duration::new(
        u64::try_from(ts.tv_sec).ok()?,
        u32::try_from(ts.tv_nsec).ok()?,
    ))
}

/// (clock that stops in sleep, clock that does not).
#[cfg(target_os = "linux")]
fn clock_pair() -> Option<(Duration, Duration)> {
    Some((
        read_clock(libc::CLOCK_MONOTONIC)?,
        read_clock(libc::CLOCK_BOOTTIME)?,
    ))
}

/// (clock that stops in sleep, clock that does not).
#[cfg(target_os = "macos")]
fn clock_pair() -> Option<(Duration, Duration)> {
    Some((
        read_clock(libc::CLOCK_UPTIME_RAW)?,
        read_clock(libc::CLOCK_MONOTONIC)?,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resume_loop(tx: mpsc::Sender<Event>) {
    let mut detector = SuspendDetector::default();
    if clock_pair().is_none() {
        tracing::warn!(
            "Suspend clocks unreadable — a resume is caught by the handshake-age rule instead"
        );
        return;
    }
    loop {
        std::thread::sleep(CLOCK_POLL);
        let Some((awake, elapsed)) = clock_pair() else {
            continue;
        };
        if detector.observe(awake, elapsed, SUSPEND_THRESHOLD) && tx.send(Event::Resumed).is_err() {
            return;
        }
    }
}

/// Index of our own tunnel interface, 0 when it does not exist. Its routes
/// are never "the network" changing.
#[cfg(target_os = "linux")]
fn tunnel_ifindex() -> u32 {
    let Ok(name) = std::ffi::CString::new("birdo0") else {
        return 0;
    };
    // SAFETY: `name` is a valid NUL-terminated C string for the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

#[cfg(target_os = "linux")]
fn route_loop(tx: mpsc::Sender<Event>) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// RTMGRP_LINK, RTMGRP_IPV4_IFADDR and RTMGRP_IPV4_ROUTE. A dropped link
    /// does not always produce an RTM_DELROUTE, so link and address changes
    /// are heard too (MR-688).
    const RTMGRP_LINK: u32 = 0x1;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV4_ROUTE: u32 = 0x40;
    const ENOBUFS: i32 = 105;

    // SAFETY: plain socket(2); the result is checked before use.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        tracing::warn!(
            "Route-change socket unavailable ({}) — network changes are caught by the handshake-age rule instead",
            std::io::Error::last_os_error()
        );
        return;
    }
    // SAFETY: `raw` is a fresh, valid descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: an all-zero sockaddr_nl is a valid value for every field.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    // SAFETY: `addr` is a valid sockaddr_nl and the length is its size.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::warn!(
            "Route-change socket did not bind ({}) — network changes are caught by the handshake-age rule instead",
            std::io::Error::last_os_error()
        );
        return;
    }

    let mut buf = vec![0u8; 32 * 1024];
    loop {
        // SAFETY: `buf` is valid for `buf.len()` writable bytes.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                // The kernel dropped messages we did not read in time: assume
                // the route changed.
                Some(ENOBUFS) => {
                    if tx.send(Event::RouteChanged).is_err() {
                        return;
                    }
                    continue;
                }
                _ => {
                    tracing::warn!("Route-change socket failed ({err}) — falling back to the handshake-age rule");
                    return;
                }
            }
        }
        if n == 0 {
            return;
        }
        let len = usize::try_from(n).unwrap_or(0).min(buf.len());
        // Our own tunnel interface is never "the network".
        let tunnel = tunnel_ifindex();
        if (netlink_default_route_change(&buf[..len], tunnel)
            || netlink_link_or_addr_change(&buf[..len], tunnel))
            && tx.send(Event::RouteChanged).is_err()
        {
            return;
        }
    }
}

#[cfg(target_os = "macos")]
fn route_loop(tx: mpsc::Sender<Event>) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: plain socket(2); the result is checked before use.
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if raw < 0 {
        tracing::warn!(
            "Route-change socket unavailable ({}) — network changes are caught by the handshake-age rule instead",
            std::io::Error::last_os_error()
        );
        return;
    }
    // SAFETY: `raw` is a fresh, valid descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut buf = vec![0u8; 8 * 1024];
    loop {
        // SAFETY: `buf` is valid for `buf.len()` writable bytes.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            tracing::warn!(
                "Route-change socket failed ({err}) — falling back to the handshake-age rule"
            );
            return;
        }
        if n == 0 {
            return;
        }
        let len = usize::try_from(n).unwrap_or(0).min(buf.len());
        if route_msg_is_default_v4(&buf[..len]) && tx.send(Event::RouteChanged).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_suspend_is_the_gap_between_the_two_clocks() {
        let mut d = SuspendDetector::default();
        let t = SUSPEND_THRESHOLD;
        // First reading has nothing to compare with.
        assert!(!d.observe(secs(100), secs(100), t));
        // Five awake seconds: both clocks move together.
        assert!(!d.observe(secs(105), secs(105), t));
        // Ten-minute sleep: the awake clock barely moves.
        assert!(d.observe(secs(106), secs(706), t));
        // And it is a single event, not a standing condition.
        assert!(!d.observe(secs(111), secs(711), t));
    }

    #[test]
    fn a_short_sleep_or_a_backwards_clock_is_not_a_resume() {
        let mut d = SuspendDetector::default();
        let t = SUSPEND_THRESHOLD;
        assert!(!d.observe(secs(50), secs(50), t));
        assert!(!d.observe(secs(55), secs(59), t)); // 4 s slept
        assert!(!d.observe(secs(40), secs(30), t)); // clocks stepped back
        assert!(d.observe(secs(41), secs(61), t)); // 30 s slept
    }

    #[test]
    fn a_burst_is_one_publish_and_a_resume_in_it_is_kept() {
        let (tx, rx) = mpsc::channel();
        tx.send(Event::RouteChanged).unwrap();
        tx.send(Event::RouteChanged).unwrap();
        tx.send(Event::Resumed).unwrap();
        tx.send(Event::RouteChanged).unwrap();
        drop(tx);
        let mut seen = Vec::new();
        run_publisher(rx, Duration::from_millis(1), |resumed| seen.push(resumed));
        assert_eq!(seen, [true]);

        let (tx, rx) = mpsc::channel();
        tx.send(Event::RouteChanged).unwrap();
        tx.send(Event::RouteChanged).unwrap();
        drop(tx);
        let mut seen = Vec::new();
        run_publisher(rx, Duration::from_millis(1), |resumed| seen.push(resumed));
        assert_eq!(seen, [false]);
    }

    /// One rtnetlink route message.
    fn nl_route(kind: u16, family: u8, dst_len: u8, table: u8, attrs: &[(u16, u32)]) -> Vec<u8> {
        let mut body = vec![family, dst_len, 0, 0, table, 3, 0, 1, 0, 0, 0, 0];
        for (t, v) in attrs {
            body.extend_from_slice(&8u16.to_ne_bytes());
            body.extend_from_slice(&t.to_ne_bytes());
            body.extend_from_slice(&v.to_ne_bytes());
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn netlink_default_route_events_are_recognised() {
        let add = nl_route(RTM_NEWROUTE, 2, 0, 254, &[(RTA_OIF, 3)]);
        let del = nl_route(RTM_DELROUTE, 2, 0, 254, &[(RTA_OIF, 3)]);
        assert!(netlink_default_route_change(&add, 0));
        assert!(netlink_default_route_change(&del, 0));
        // Not default, not IPv4, not the main table, wrong message kind.
        assert!(!netlink_default_route_change(
            &nl_route(RTM_NEWROUTE, 2, 24, 254, &[]),
            0
        ));
        assert!(!netlink_default_route_change(
            &nl_route(RTM_NEWROUTE, 2, 1, 254, &[]),
            0
        ));
        assert!(!netlink_default_route_change(
            &nl_route(RTM_NEWROUTE, 10, 0, 254, &[]),
            0
        ));
        assert!(!netlink_default_route_change(
            &nl_route(RTM_NEWROUTE, 2, 0, 100, &[]),
            0
        ));
        assert!(!netlink_default_route_change(
            &nl_route(16, 2, 0, 254, &[]),
            0
        ));
        // A large table id arrives as an attribute and overrides the byte.
        assert!(netlink_default_route_change(
            &nl_route(RTM_NEWROUTE, 2, 0, 252, &[(RTA_TABLE, 254)]),
            0
        ));
        assert!(!netlink_default_route_change(
            &nl_route(RTM_NEWROUTE, 2, 0, 254, &[(RTA_TABLE, 1000)]),
            0
        ));
    }

    /// One rtnetlink link (`ifinfomsg`) or address (`ifaddrmsg`) message.
    fn nl_if(kind: u16, family: u8, index: u32) -> Vec<u8> {
        let body_len = if kind == RTM_NEWLINK || kind == RTM_DELLINK {
            IFINFOMSG_LEN
        } else {
            IFADDRMSG_LEN
        };
        let mut body = vec![0u8; body_len];
        body[0] = family;
        body[IF_INDEX_AT..IF_INDEX_AT + 4].copy_from_slice(&index.to_ne_bytes());
        if kind == RTM_NEWLINK {
            // A new link: every flag reads as changed.
            body[IF_CHANGE_AT..IF_CHANGE_AT + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn netlink_link_and_address_events_are_recognised() {
        for kind in [RTM_NEWLINK, RTM_DELLINK] {
            assert!(netlink_link_or_addr_change(&nl_if(kind, 0, 3), 0));
            assert!(netlink_link_or_addr_change(&nl_if(kind, 10, 3), 0));
        }
        for kind in [RTM_NEWADDR, RTM_DELADDR] {
            assert!(netlink_link_or_addr_change(&nl_if(kind, 2, 3), 0));
            // IPv6 addresses are not watched (the route watcher is IPv4 only).
            assert!(!netlink_link_or_addr_change(&nl_if(kind, 10, 3), 0));
        }
    }

    #[test]
    fn netlink_link_and_address_ignore_unrelated_and_our_tunnel() {
        // Route messages and other kinds are not link/address changes.
        assert!(!netlink_link_or_addr_change(
            &nl_route(RTM_NEWROUTE, 2, 0, 254, &[(RTA_OIF, 3)]),
            0
        ));
        assert!(!netlink_link_or_addr_change(&nl_if(18, 0, 3), 0));
        assert!(!netlink_link_or_addr_change(&nl_if(NLMSG_DONE, 0, 3), 0));
        // Our own tunnel interface is never "the network".
        assert!(!netlink_link_or_addr_change(&nl_if(RTM_NEWLINK, 0, 9), 9));
        assert!(!netlink_link_or_addr_change(&nl_if(RTM_NEWADDR, 2, 9), 9));
        assert!(netlink_link_or_addr_change(&nl_if(RTM_NEWLINK, 0, 9), 3));
        // Route and link messages do not cross over.
        assert!(!netlink_default_route_change(&nl_if(RTM_NEWLINK, 0, 3), 0));
    }

    /// An RTM_NEWLINK with the given `ifi_change` and raw rtattrs.
    fn nl_newlink(change: u32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![0u8; IFINFOMSG_LEN];
        body[IF_INDEX_AT..IF_INDEX_AT + 4].copy_from_slice(&3u32.to_ne_bytes());
        body[IF_CHANGE_AT..IF_CHANGE_AT + 4].copy_from_slice(&change.to_ne_bytes());
        for (t, v) in attrs {
            body.extend_from_slice(&((4 + v.len()) as u16).to_ne_bytes());
            body.extend_from_slice(&t.to_ne_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn only_a_link_state_change_counts_for_newlink() {
        // Up, running and lower-up bits each count.
        for bit in [IFF_UP, IFF_RUNNING, IFF_LOWER_UP] {
            assert!(netlink_link_or_addr_change(&nl_newlink(bit, &[]), 0));
        }
        // A new link reports every bit as changed.
        assert!(netlink_link_or_addr_change(&nl_newlink(u32::MAX, &[]), 0));
        // An attribute-only update (MTU, queue, stats) or an unrelated flag.
        assert!(!netlink_link_or_addr_change(&nl_newlink(0, &[]), 0));
        assert!(!netlink_link_or_addr_change(
            &nl_newlink(0x2, &[(4, &[0u8; 4])]),
            0
        ));
        // A wireless-extension event is skipped even with state bits set.
        assert!(!netlink_link_or_addr_change(
            &nl_newlink(IFF_RUNNING, &[(IFLA_WIRELESS, &[0u8; 8])]),
            0
        ));
        assert!(!netlink_link_or_addr_change(
            &nl_newlink(u32::MAX, &[(IFLA_WIRELESS, &[0u8; 8])]),
            0
        ));
        // Other attributes alongside a state change are fine.
        assert!(netlink_link_or_addr_change(
            &nl_newlink(IFF_RUNNING, &[(4, &[0u8; 4])]),
            0
        ));
        // DELLINK always counts.
        assert!(netlink_link_or_addr_change(&nl_if(RTM_DELLINK, 0, 3), 0));
        // A truncated attribute walk is "no", without a panic.
        let mut cut = nl_newlink(IFF_RUNNING, &[(4, &[0u8; 8])]);
        cut.truncate(cut.len() - 3);
        let len = cut.len() as u32;
        cut[..4].copy_from_slice(&len.to_ne_bytes());
        assert!(!netlink_link_or_addr_change(&cut, 0));
        let mut lying = nl_newlink(IFF_RUNNING, &[(4, &[0u8; 4])]);
        let at = NLMSG_HDRLEN + IFINFOMSG_LEN;
        lying[at..at + 2].copy_from_slice(&200u16.to_ne_bytes());
        assert!(!netlink_link_or_addr_change(&lying, 0));
        let mut tiny = nl_newlink(IFF_RUNNING, &[(4, &[0u8; 4])]);
        tiny[at..at + 2].copy_from_slice(&2u16.to_ne_bytes());
        assert!(!netlink_link_or_addr_change(&tiny, 0));
    }

    #[test]
    fn netlink_link_and_address_garbage_is_safe() {
        assert!(!netlink_link_or_addr_change(&[], 0));
        assert!(!netlink_link_or_addr_change(&[1, 2, 3], 0));
        let mut cut = nl_if(RTM_DELLINK, 0, 3);
        cut.truncate(cut.len() - 3);
        assert!(!netlink_link_or_addr_change(&cut, 0));
        // A short body (shorter than ifinfomsg) is not a link message.
        let mut short = nl_if(RTM_NEWLINK, 0, 3);
        short.truncate(NLMSG_HDRLEN + IFADDRMSG_LEN);
        short[..4].copy_from_slice(&((NLMSG_HDRLEN + IFADDRMSG_LEN) as u32).to_ne_bytes());
        assert!(!netlink_link_or_addr_change(&short, 0));
        let mut lying = nl_if(RTM_NEWADDR, 2, 3);
        lying[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(!netlink_link_or_addr_change(&lying, 0));
        // A second message in the datagram is still found.
        let mut dgram = nl_if(18, 0, 3);
        dgram.extend(nl_if(RTM_DELADDR, 2, 4));
        assert!(netlink_link_or_addr_change(&dgram, 0));
    }

    #[test]
    fn our_own_tunnel_interface_is_not_a_network_change() {
        let on_tunnel = nl_route(RTM_NEWROUTE, 2, 0, 254, &[(RTA_OIF, 9)]);
        assert!(!netlink_default_route_change(&on_tunnel, 9));
        assert!(netlink_default_route_change(&on_tunnel, 3));
        assert!(netlink_default_route_change(&on_tunnel, 0));
    }

    #[test]
    fn a_datagram_with_several_messages_is_searched_and_garbage_is_safe() {
        let mut dgram = nl_route(RTM_NEWROUTE, 2, 24, 254, &[]);
        dgram.extend(nl_route(RTM_DELROUTE, 2, 0, 254, &[(RTA_OIF, 2)]));
        assert!(netlink_default_route_change(&dgram, 0));

        assert!(!netlink_default_route_change(&[], 0));
        assert!(!netlink_default_route_change(&[1, 2, 3], 0));
        let mut cut = nl_route(RTM_NEWROUTE, 2, 0, 254, &[(RTA_OIF, 2)]);
        cut.truncate(cut.len() - 3);
        assert!(!netlink_default_route_change(&cut, 0));
        // A length field that points past the buffer or below the header.
        let mut lying = nl_route(RTM_NEWROUTE, 2, 0, 254, &[]);
        lying[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(!netlink_default_route_change(&lying, 0));
        lying[..4].copy_from_slice(&1u32.to_ne_bytes());
        assert!(!netlink_default_route_change(&lying, 0));
    }

    /// One PF_ROUTE message: header, then DST and optional GATEWAY and
    /// NETMASK sockaddrs.
    fn pf_route(kind: u8, dst: [u8; 4], mask: Option<&[u8]>) -> Vec<u8> {
        let mut addrs = RTA_DST;
        let mut tail = vec![
            16u8, 2, 0, 0, dst[0], dst[1], dst[2], dst[3], 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        // GATEWAY slot (always present in the kernel's messages here).
        addrs |= 0x2;
        tail.extend_from_slice(&[16, 2, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        if let Some(mask) = mask {
            addrs |= RTA_NETMASK;
            tail.extend_from_slice(mask);
        }
        let mut msg = vec![0u8; RT_MSGHDR_LEN];
        msg[0..2].copy_from_slice(&((RT_MSGHDR_LEN + tail.len()) as u16).to_ne_bytes());
        msg[2] = 5;
        msg[3] = kind;
        msg[12..16].copy_from_slice(&addrs.to_ne_bytes());
        msg.extend_from_slice(&tail);
        msg
    }

    #[test]
    fn a_pf_route_default_route_is_recognised() {
        // The kernel sends the zero mask with length 0 (4 bytes of room) ...
        let zero_len = [0u8, 0, 0, 0];
        // ... or as a full sockaddr_in of zeros.
        let full_zero = [16u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for kind in [RTM_ADD, RTM_DELETE, RTM_CHANGE] {
            assert!(route_msg_is_default_v4(&pf_route(
                kind,
                [0; 4],
                Some(&zero_len)
            )));
            assert!(route_msg_is_default_v4(&pf_route(
                kind,
                [0; 4],
                Some(&full_zero)
            )));
        }
    }

    #[test]
    fn a_pf_route_tunnel_half_route_or_other_message_is_not() {
        // The tunnel's 0.0.0.0/1 and 128.0.0.0/1: not a /0.
        let slash1 = [8u8, 2, 0, 0, 128, 0, 0, 0];
        assert!(!route_msg_is_default_v4(&pf_route(
            RTM_ADD,
            [0; 4],
            Some(&slash1)
        )));
        assert!(!route_msg_is_default_v4(&pf_route(
            RTM_ADD,
            [128, 0, 0, 0],
            Some(&slash1)
        )));
        // A host route has no netmask.
        assert!(!route_msg_is_default_v4(&pf_route(RTM_ADD, [0; 4], None)));
        // Another destination with a zero mask is not 0.0.0.0.
        assert!(!route_msg_is_default_v4(&pf_route(
            RTM_ADD,
            [10, 0, 0, 0],
            Some(&[0u8, 0, 0, 0])
        )));
        // Link and address messages (RTM_IFINFO) are not route changes.
        assert!(!route_msg_is_default_v4(&pf_route(
            0xe,
            [0; 4],
            Some(&[0u8, 0, 0, 0])
        )));
        // Short and cut messages are safe.
        assert!(!route_msg_is_default_v4(&[]));
        assert!(!route_msg_is_default_v4(&[0u8; 20]));
        let mut cut = pf_route(RTM_ADD, [0; 4], Some(&[0u8, 0, 0, 0]));
        cut.truncate(RT_MSGHDR_LEN + 20);
        assert!(!route_msg_is_default_v4(&cut));
    }
}
