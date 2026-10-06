//! What the WFP dynamic session must contain, as plain data.
//!
//! `wfp.rs` turns these specs into `FWPM_FILTER0`s. Everything that decides
//! WHICH filters exist — app scoping (W1-013, D-24), the inbound half of the
//! kill switch (W1-014) and the DNS guard that replaced adapter parking
//! (W1-007) — lives here, free of FFI, so it is unit-tested against a model of
//! WFP's own matching rules (see the tests) rather than trusted.
//!
//! # How WFP reads a spec
//!
//! All our filters sit in one sublayer. Within it, the MATCHING filter with the
//! highest weight decides. Within one filter, conditions on the SAME field are
//! ORed and conditions on different fields are ANDed — so
//! `[Protocol(6), Protocol(17), RemotePort(53)]` is "TCP or UDP, to port 53".
//!
//! # The weights
//!
//! | weight | what                                                          |
//! |-------:|----------------------------------------------------------------|
//! |     15 | STUN/TURN blocks (while the block-all is up)                  |
//! |     13 | DNS permits: the tunnel's resolvers over the tunnel; loopback;|
//! |        | the user's LAN resolver (Custom DNS + LAN sharing); the relay |
//! |        | flow itself when it runs on a DNS port                        |
//! |     12 | name-resolution blocks: DNS/DoT/DoQ anywhere else; LLMNR,     |
//! |        | mDNS and NetBIOS name queries unless LAN sharing is on        |
//! |     10 | permits: loopback, DHCP, IPv6 neighbor discovery, relay,      |
//! |        | control plane, tunnel, LAN, kill-switch exceptions, host-only |
//! |        | virtual networks (inbound)                                    |
//! |      1 | block-all (while the kill switch blocks)                      |
//!
//! The DNS block sits ABOVE every ordinary permit on purpose: the LAN-sharing
//! permit would otherwise let a query reach the router, and the tunnel-interface
//! permit would let one reach any resolver the user types into `nslookup`. It
//! is in force whenever the DNS guard OR the block-all is (REVIEW-WIN2-004), so
//! a reconnect gap and a held lockdown block keep DNS inside too.

use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const WEIGHT_BLOCK_ALL: u8 = 1;
pub(crate) const WEIGHT_PERMIT: u8 = 10;
pub(crate) const WEIGHT_BLOCK_NAME_RESOLUTION: u8 = 12;
pub(crate) const WEIGHT_PERMIT_DNS: u8 = 13;
pub(crate) const WEIGHT_BLOCK_STUN: u8 = 15;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;

/// Plain DNS (UDP/TCP 53), DNS-over-TLS (TCP 853) and DNS-over-QUIC (UDP 853).
const DNS_PORTS: [u16; 2] = [53, 853];

/// Multicast/broadcast name resolution that asks the LOCAL network about a
/// name: NetBIOS name service (137), mDNS (5353), LLMNR (5355).
const LAN_NAME_PORTS: [u16; 3] = [137, 5353, 5355];

/// The only port the app's own control plane needs through a block: HTTPS to
/// the API, DoH and the updater (the Linux twin is scoped the same way).
const CONTROL_PLANE_PORT: u16 = 443;

/// The ranges Local Network Sharing opens.
const LAN_RANGES: [(Ipv4Addr, u8, &str); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8, "10.0.0.0/8"),
    (Ipv4Addr::new(172, 16, 0, 0), 12, "172.16.0.0/12"),
    (Ipv4Addr::new(192, 168, 0, 0), 16, "192.168.0.0/16"),
    (Ipv4Addr::new(169, 254, 0, 0), 16, "link-local"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Layer {
    ConnectV4,
    ConnectV6,
    /// Inbound-initiated flows: incoming TCP accepts and the first packet of
    /// anything else (W1-014).
    RecvAcceptV4,
    RecvAcceptV6,
}

impl Layer {
    pub(crate) fn is_v6(self) -> bool {
        matches!(self, Layer::ConnectV6 | Layer::RecvAcceptV6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Condition {
    RemoteV4 {
        addr: Ipv4Addr,
        prefix: u8,
    },
    RemoteV6 {
        addr: Ipv6Addr,
        prefix: u8,
    },
    Protocol(u8),
    RemotePort(u16),
    RemotePortRange(u16, u16),
    LocalPort(u16),
    /// The interface the flow uses, by LUID.
    LocalInterface(u64),
    /// The executable that owns the socket (`FWPM_CONDITION_ALE_APP_ID`).
    App(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterSpec {
    pub name: String,
    pub layer: Layer,
    pub action: Action,
    pub weight: u8,
    pub conditions: Vec<Condition>,
}

/// How the tunnel reaches the relay, and so what the relay permit is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayTransport {
    /// This process's WireGuard socket, UDP.
    WireGuardUdp,
    /// The xray helper's Reality connection, TCP.
    StealthTcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Relay {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub transport: RelayTransport,
}

/// The relay permit for a `"a.b.c.d:port"` endpoint. `None` for a hostname,
/// an IPv6 literal or a missing port: there is no address to scope a permit to.
pub(crate) fn parse_relay(endpoint: &str, transport: RelayTransport) -> Option<Relay> {
    let addr: std::net::SocketAddrV4 = endpoint.parse().ok()?;
    Some(Relay {
        ip: *addr.ip(),
        port: addr.port(),
        transport,
    })
}

/// DNS only through the tunnel (W1-007). Installed for every session, with or
/// without the kill switch, for as long as the machine-state owner holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsGuard {
    /// The resolvers the tunnel interface was given (IPv4 by validation),
    /// reached over the tunnel.
    pub resolvers: Vec<Ipv4Addr>,
    /// Custom DNS servers on the user's own network (a Pi-hole), reached
    /// OUTSIDE the tunnel: see [`split_resolvers`]. Empty unless Local Network
    /// Sharing is on.
    pub lan_resolvers: Vec<Ipv4Addr>,
    /// The tunnel interface the resolvers must be reached over.
    pub tunnel_luid: u64,
    /// Local Network Sharing leaves LAN name resolution alone.
    pub lan_sharing: bool,
    /// The tunnel's own relay. On a DNS port — WireGuard port 53 is a preset
    /// in VPN Settings — the block would otherwise drop the tunnel itself.
    pub relay: Option<Relay>,
    /// This executable, whose WireGuard socket carries the tunnel.
    pub self_exe: Option<String>,
}

/// Which of a session's resolvers are reached through the tunnel, and which
/// on the user's own network (REVIEW-WIN2-006).
///
/// A Custom DNS server in a private range, with Local Network Sharing on, is
/// the user's LAN resolver (a Pi-hole, AdGuard Home): Local Network Sharing
/// already sends the user's private ranges to the LAN, and the relay cannot
/// reach that network, so pinning such a resolver into the tunnel left the
/// session with no DNS at all. It is an explicit, user-chosen exception, and
/// the only one: the server's own resolvers always stay in the tunnel (the
/// fleet resolver is itself in 10/8), and without Local Network Sharing a
/// private Custom DNS server stays pinned to the tunnel — unreachable, but
/// never reached in the clear.
pub(crate) fn split_resolvers(
    resolvers: &[Ipv4Addr],
    custom: bool,
    lan_sharing: bool,
) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    resolvers
        .iter()
        .copied()
        .partition(|ip| !(custom && lan_sharing && in_lan_range(*ip)))
}

fn in_lan_range(ip: Ipv4Addr) -> bool {
    LAN_RANGES.iter().any(|(net, prefix, _)| {
        let mask = u32::MAX << (32 - prefix);
        u32::from(ip) & mask == u32::from(*net) & mask
    })
}

/// The kill switch's block-all and everything it lets through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BlockAll {
    /// This executable, when its path is known.
    pub self_exe: Option<String>,
    pub relay: Option<Relay>,
    /// The verified xray binary, in a stealth session.
    pub stealth_helper: Option<String>,
    /// Lockdown with a published tunnel interface.
    pub tunnel_luid: Option<u64>,
    pub lan_sharing: bool,
    /// Kill-switch exceptions (the historical "split tunnel" apps).
    pub exceptions: Vec<String>,
    /// Up interfaces with no default gateway — VirtualBox host-only, the
    /// WSL/Hyper-V switches. Inbound from them is not the internet reaching
    /// the machine, so the inbound block leaves them alone.
    pub host_only_interfaces: Vec<u64>,
}

/// Everything the dynamic session holds at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    pub block_all: Option<BlockAll>,
    /// The standalone outbound-IPv6 block of a tunnel session (LEAK-2). The
    /// block-all covers IPv6 itself, so this only matters without it.
    pub v6_block: bool,
    pub dns_guard: Option<DnsGuard>,
}

/// What the session must hold once the relay permit has moved to `block.relay`
/// (REVIEW-WIN2-001), or `None` when nothing is to be committed.
///
/// `engage`: the caller is putting the block-all up for the rebuild of a live
/// session. Without it, a block already in force is rebuilt around the new
/// relay at once: lockdown holds the block for the whole session, and a
/// give-up can leave it held. With no block in force and none being engaged,
/// the relay is only recorded, for the next block.
///
/// Either way the block-all and the new relay's permit come into force in ONE
/// transaction, before the handshake that needs it. The relay used to be
/// re-baked only outside lockdown, after the switch guard had already gone up
/// naming the previous relay, so under lockdown (the Windows default) every
/// live server switch, port or Stealth change and every connect behind a held
/// block sent its handshake into our own block-all.
pub(crate) fn after_relay_move(
    installed: &Policy,
    block: BlockAll,
    engage: bool,
) -> Option<Policy> {
    (engage || installed.block_all.is_some()).then(|| Policy {
        block_all: Some(block),
        ..installed.clone()
    })
}

fn spec(
    name: impl Into<String>,
    layer: Layer,
    action: Action,
    weight: u8,
    conditions: Vec<Condition>,
) -> FilterSpec {
    FilterSpec {
        name: name.into(),
        layer,
        action,
        weight,
        conditions,
    }
}

fn ports(list: &[u16]) -> impl Iterator<Item = Condition> + '_ {
    list.iter().map(|p| Condition::RemotePort(*p))
}

fn loopback(layer: Layer) -> Condition {
    if layer.is_v6() {
        Condition::RemoteV6 {
            addr: Ipv6Addr::LOCALHOST,
            prefix: 128,
        }
    } else {
        Condition::RemoteV4 {
            addr: Ipv4Addr::new(127, 0, 0, 0),
            prefix: 8,
        }
    }
}

fn file_name(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
}

/// The filters `policy` needs. `app_resolves` says whether an executable's WFP
/// app id could be obtained; an app-scoped permit is only ever built for one
/// that did, and the fallbacks below are decided here, where they are tested.
pub(crate) fn filter_specs(
    policy: &Policy,
    app_resolves: &dyn Fn(&str) -> bool,
) -> Vec<FilterSpec> {
    let mut out = Vec::new();
    match &policy.block_all {
        Some(block) => block_all_specs(block, app_resolves, &mut out),
        None if policy.v6_block => standalone_v6_specs(&mut out),
        None => {}
    }
    // REVIEW-WIN2-004: DNS stays inside for as long as EITHER holds — the
    // session's guard or the block-all. The guard alone used to carry the DNS
    // block, and a reconnect's teardown lifts it, so for the whole gap — and
    // for as long as a lockdown give-up held the block — the block-all's LAN
    // permit let DNS reach the router while the UI read "all traffic
    // blocked".
    if policy.block_all.is_some() || policy.dns_guard.is_some() {
        name_resolution_specs(policy, app_resolves, &mut out);
    }
    out
}

/// An executable `policy` scopes a permit to, whose WFP app id `wfp.rs` must
/// resolve before the specs are built.
pub(crate) struct NamedApp<'a> {
    pub path: &'a str,
    /// What an unresolvable id costs, for the log.
    pub consequence: &'static str,
    /// Log at ERROR (a permit the session depends on) rather than WARN.
    pub loud: bool,
}

/// Every executable `policy` names. The DNS guard names this executable too,
/// for its relay flow on a DNS port: without that, a guard alone (reactive
/// mode, Connected) built that permit unscoped, for any app.
pub(crate) fn named_apps(policy: &Policy) -> Vec<NamedApp<'_>> {
    let mut out = Vec::new();
    if let Some(block) = &policy.block_all {
        if let Some(path) = block.self_exe.as_deref() {
            out.push(NamedApp {
                path,
                consequence: "the relay permit falls back to address scope and the control \
                              plane is blocked while the block is up",
                loud: true,
            });
        }
        if let Some(path) = block.stealth_helper.as_deref() {
            out.push(NamedApp {
                path,
                consequence: "the stealth relay permit falls back to address scope",
                loud: true,
            });
        }
        for path in &block.exceptions {
            out.push(NamedApp {
                path,
                consequence: "this kill-switch exception is skipped",
                loud: false,
            });
        }
    }
    if let Some(guard) = policy.dns_guard.as_ref().filter(|g| g.relay.is_some()) {
        if let Some(path) = guard.self_exe.as_deref() {
            out.push(NamedApp {
                path,
                consequence: "the relay permit on a DNS port falls back to address scope",
                loud: false,
            });
        }
    }
    out
}

/// The tunnel's own flow to `relay` (D-24 / W1-013): only the process that
/// carries the tunnel — this executable's WireGuard socket over UDP, or the
/// xray helper over TCP — on the tunnel's protocol and port. Returns the
/// conditions and the permit's name. With no resolvable app id the flow is
/// scoped by address, protocol and port, and the name says so.
fn relay_flow(
    relay: Relay,
    self_exe: Option<&str>,
    stealth_helper: Option<&str>,
    app_resolves: &dyn Fn(&str) -> bool,
) -> (Vec<Condition>, String) {
    let (app, protocol, label) = match relay.transport {
        RelayTransport::WireGuardUdp => (self_exe, UDP, "WireGuard"),
        RelayTransport::StealthTcp => (stealth_helper, TCP, "stealth"),
    };
    let mut conditions = vec![
        Condition::RemoteV4 {
            addr: relay.ip,
            prefix: 32,
        },
        Condition::Protocol(protocol),
        Condition::RemotePort(relay.port),
    ];
    let name = match app.filter(|path| app_resolves(path)) {
        Some(path) => {
            conditions.push(Condition::App(path.to_string()));
            format!("Birdo: Permit the relay ({label})")
        }
        // The app id could not be resolved. A tunnel that cannot reach its
        // relay cannot recover either, so the permit stays — scoped by
        // address, protocol and port, just not by app. wfp.rs logs this at
        // ERROR.
        None => format!("Birdo: Permit the relay ({label}, any app — app id unavailable)"),
    };
    (conditions, name)
}

/// LEAK-2's connect-window IPv6 block: outbound IPv6 blocked, loopback and
/// DHCPv6 still permitted.
fn standalone_v6_specs(out: &mut Vec<FilterSpec>) {
    let layer = Layer::ConnectV6;
    out.push(spec(
        "Birdo: Block all outbound IPv6",
        layer,
        Action::Block,
        WEIGHT_BLOCK_ALL,
        vec![],
    ));
    out.push(spec(
        "Birdo: Permit IPv6 localhost",
        layer,
        Action::Permit,
        WEIGHT_PERMIT,
        vec![loopback(layer)],
    ));
    out.push(spec(
        "Birdo: Permit DHCPv6",
        layer,
        Action::Permit,
        WEIGHT_PERMIT,
        vec![
            Condition::Protocol(UDP),
            Condition::RemotePortRange(546, 547),
        ],
    ));
}

fn block_all_specs(
    block: &BlockAll,
    app_resolves: &dyn Fn(&str) -> bool,
    out: &mut Vec<FilterSpec>,
) {
    use Layer::*;
    let all_layers = [ConnectV4, ConnectV6, RecvAcceptV4, RecvAcceptV6];
    let self_app = block.self_exe.as_deref().filter(|path| app_resolves(path));

    for layer in all_layers {
        let (direction, family) = match layer {
            ConnectV4 => ("outbound", "IPv4"),
            ConnectV6 => ("outbound", "IPv6"),
            RecvAcceptV4 => ("inbound", "IPv4"),
            RecvAcceptV6 => ("inbound", "IPv6"),
        };
        out.push(spec(
            format!("Birdo: Block all {direction} {family}"),
            layer,
            Action::Block,
            WEIGHT_BLOCK_ALL,
            vec![],
        ));
        out.push(spec(
            format!("Birdo: Permit {family} localhost ({direction})"),
            layer,
            Action::Permit,
            WEIGHT_PERMIT,
            vec![loopback(layer)],
        ));
    }

    // DHCP both ways: the lease's renewals are outbound, an offer or ack may
    // arrive as a new inbound flow (broadcast to the client port).
    out.push(spec(
        "Birdo: Permit DHCP",
        ConnectV4,
        Action::Permit,
        WEIGHT_PERMIT,
        vec![Condition::Protocol(UDP), Condition::RemotePortRange(67, 68)],
    ));
    out.push(spec(
        "Birdo: Permit DHCP (inbound)",
        RecvAcceptV4,
        Action::Permit,
        WEIGHT_PERMIT,
        vec![
            Condition::Protocol(UDP),
            Condition::LocalPort(68),
            Condition::RemotePort(67),
        ],
    ));
    out.push(spec(
        "Birdo: Permit DHCPv6",
        ConnectV6,
        Action::Permit,
        WEIGHT_PERMIT,
        vec![
            Condition::Protocol(UDP),
            Condition::RemotePortRange(546, 547),
        ],
    ));
    out.push(spec(
        "Birdo: Permit DHCPv6 (inbound)",
        RecvAcceptV6,
        Action::Permit,
        WEIGHT_PERMIT,
        vec![
            Condition::Protocol(UDP),
            Condition::LocalPort(546),
            Condition::RemotePort(547),
        ],
    ));

    // IPv6 neighbor discovery (router solicitation 133, advertisement 134,
    // neighbor solicitation 135 / advertisement 136, redirect 137). It is
    // link-local and carries no traffic of anyone's, but the ALE layers see
    // it: with the inbound block up and no permit, the physical NIC's IPv6
    // would decay over a long lockdown session (no router advertisements, no
    // answers to neighbor solicitations). WFP carries the ICMP type in the
    // local-port field. The same set wireguard-windows permits.
    for (layer, types) in [
        (ConnectV6, &[133u16, 135, 136][..]),
        (RecvAcceptV6, &[134u16, 135, 136, 137][..]),
    ] {
        out.push(spec(
            "Birdo: Permit IPv6 neighbor discovery",
            layer,
            Action::Permit,
            WEIGHT_PERMIT,
            [Condition::Protocol(ICMPV6)]
                .into_iter()
                .chain(types.iter().map(|t| Condition::LocalPort(*t)))
                .collect(),
        ));
    }

    // D-24 / W1-013: the relay is reachable only by the process that carries
    // the tunnel, only on the tunnel's protocol and port. It used to be
    // reachable by ANY process, on anything, whenever the block was up.
    if let Some(relay) = block.relay {
        let (conditions, name) = relay_flow(
            relay,
            block.self_exe.as_deref(),
            block.stealth_helper.as_deref(),
            app_resolves,
        );
        // A TCP relay flow is always initiated here, so only the WireGuard
        // UDP flow gets an inbound twin.
        let inbound = relay.transport == RelayTransport::WireGuardUdp;
        if inbound {
            out.push(spec(
                format!("{name} (inbound)"),
                RecvAcceptV4,
                Action::Permit,
                WEIGHT_PERMIT,
                conditions.clone(),
            ));
        }
        out.push(spec(
            name,
            ConnectV4,
            Action::Permit,
            WEIGHT_PERMIT,
            conditions,
        ));
    }

    // The control plane (API, DoH, updater) during a gap. Scoped to this
    // executable AND tcp/443; with no app id there is no safe way to scope it,
    // so there is no permit — the reconnect then fails closed (and loudly).
    if let Some(path) = self_app {
        for layer in [ConnectV4, ConnectV6] {
            out.push(spec(
                "Birdo: Permit the app's own HTTPS (control plane)",
                layer,
                Action::Permit,
                WEIGHT_PERMIT,
                vec![
                    Condition::App(path.to_string()),
                    Condition::Protocol(TCP),
                    Condition::RemotePort(CONTROL_PLANE_PORT),
                ],
            ));
        }
    }

    if let Some(luid) = block.tunnel_luid {
        for layer in all_layers {
            out.push(spec(
                "Birdo: Permit the tunnel interface",
                layer,
                Action::Permit,
                WEIGHT_PERMIT,
                vec![Condition::LocalInterface(luid)],
            ));
        }
    }

    for luid in &block.host_only_interfaces {
        for layer in [RecvAcceptV4, RecvAcceptV6] {
            out.push(spec(
                "Birdo: Permit inbound on a host-only virtual network",
                layer,
                Action::Permit,
                WEIGHT_PERMIT,
                vec![Condition::LocalInterface(*luid)],
            ));
        }
    }

    if block.lan_sharing {
        for (addr, prefix, label) in LAN_RANGES {
            for layer in [ConnectV4, RecvAcceptV4] {
                out.push(spec(
                    format!("Birdo: Permit LAN {label}"),
                    layer,
                    Action::Permit,
                    WEIGHT_PERMIT,
                    vec![Condition::RemoteV4 { addr, prefix }],
                ));
            }
        }
    }

    // Kill-switch exceptions: EXEMPT from the block, both directions. (They
    // cannot route an app outside the tunnel — which is why the UI calls them
    // exceptions, not split tunneling.)
    for path in block.exceptions.iter().filter(|p| app_resolves(p)) {
        for layer in all_layers {
            out.push(spec(
                format!("Birdo: Permit kill-switch exception ({})", file_name(path)),
                layer,
                Action::Permit,
                WEIGHT_PERMIT,
                vec![Condition::App(path.clone())],
            ));
        }
    }

    // WebRTC STUN/TURN leak prevention, above every permit. The SAME ranges on
    // both families: a WebRTC client tries every address family it has, so a
    // port left open on one is the leak. Google's STUN servers
    // (stun.l.google.com) answer on 19302, and Google Meet sends its media to
    // UDP 19302-19309; f0710b9 widened the IPv4 block to that range and left
    // the IPv6 twin at 19302 alone, which this used to carry over.
    for layer in [ConnectV4, ConnectV6] {
        for (label, protocol, low, high) in [
            ("STUN/UDP", UDP, 3478, 3497),
            ("TURN/TCP", TCP, 3478, 3497),
            ("Google STUN", UDP, 19302, 19309),
        ] {
            out.push(spec(
                format!("Birdo: Block {label}"),
                layer,
                Action::Block,
                WEIGHT_BLOCK_STUN,
                vec![
                    Condition::Protocol(protocol),
                    Condition::RemotePortRange(low, high),
                ],
            ));
        }
    }
}

/// W1-007. What replaced parking every physical adapter on `static none`:
/// filters in the dynamic session, which the OS removes with the process, so an
/// unclean exit can no longer leave the machine without DNS. In force whenever
/// the session's DNS guard OR the kill switch's block-all is (REVIEW-WIN2-004).
///
/// Blocked:
///   * DNS (UDP/TCP 53), DoT (TCP 853) and DoQ (UDP 853) to ANY resolver except
///     the tunnel's own, over the tunnel interface. That covers Smart
///     Multi-Homed Name Resolution's parallel queries to the physical adapters'
///     resolvers, however those were configured (DHCP or static), queries on
///     virtual adapters, and applications that bypass the system resolver.
///   * LLMNR (5355), mDNS (5353) and NetBIOS name queries (137) when Local
///     Network Sharing is off — Windows falls back to them for single-label
///     names, broadcasting what is being looked up to everyone on the LAN.
///
/// Permitted: the tunnel resolvers over the tunnel; resolvers on loopback (a
/// local DNS proxy, which itself can only forward through the tunnel); the
/// user's own LAN resolver when they chose one with Local Network Sharing on
/// ([`split_resolvers`]); and the tunnel's own relay flow when it runs on a
/// DNS port.
///
/// Not blocked: DNS-over-HTTPS (443) — encrypted, and routed through the
/// tunnel like any other HTTPS.
fn name_resolution_specs(
    policy: &Policy,
    app_resolves: &dyn Fn(&str) -> bool,
    out: &mut Vec<FilterSpec>,
) {
    use Layer::*;
    let dns = || {
        [Condition::Protocol(TCP), Condition::Protocol(UDP)]
            .into_iter()
            .chain(ports(&DNS_PORTS))
    };
    let guard = policy.dns_guard.as_ref();

    if let Some(guard) = guard.filter(|g| !g.resolvers.is_empty()) {
        let mut conditions: Vec<Condition> = dns().collect();
        conditions.extend(guard.resolvers.iter().map(|ip| Condition::RemoteV4 {
            addr: *ip,
            prefix: 32,
        }));
        conditions.push(Condition::LocalInterface(guard.tunnel_luid));
        out.push(spec(
            "Birdo: Permit DNS to the tunnel resolvers",
            ConnectV4,
            Action::Permit,
            WEIGHT_PERMIT_DNS,
            conditions,
        ));
    }
    if let Some(guard) = guard.filter(|g| !g.lan_resolvers.is_empty()) {
        // No interface condition: Local Network Sharing routes it to the LAN.
        let mut conditions: Vec<Condition> = dns().collect();
        conditions.extend(guard.lan_resolvers.iter().map(|ip| Condition::RemoteV4 {
            addr: *ip,
            prefix: 32,
        }));
        out.push(spec(
            "Birdo: Permit DNS to your own network's resolver (Custom DNS, Local Network Sharing)",
            ConnectV4,
            Action::Permit,
            WEIGHT_PERMIT_DNS,
            conditions,
        ));
    }

    // The tunnel itself on a DNS port: the relay the block lets the next
    // handshake reach, and the one the live tunnel's guard names (they differ
    // for the length of a switch). Same scoping as the relay permit, one
    // weight above the DNS block.
    let flows = [
        policy.block_all.as_ref().and_then(|b| {
            b.relay.map(|relay| {
                relay_flow(
                    relay,
                    b.self_exe.as_deref(),
                    b.stealth_helper.as_deref(),
                    app_resolves,
                )
            })
        }),
        guard.and_then(|g| {
            g.relay
                .map(|relay| relay_flow(relay, g.self_exe.as_deref(), None, app_resolves))
        }),
    ];
    let mut on_dns_ports: Vec<(Vec<Condition>, String)> = Vec::new();
    for (conditions, name) in flows.into_iter().flatten() {
        let dns_port = conditions
            .iter()
            .any(|c| matches!(c, Condition::RemotePort(p) if DNS_PORTS.contains(p)));
        if dns_port && !on_dns_ports.iter().any(|(c, _)| *c == conditions) {
            on_dns_ports.push((conditions, name));
        }
    }
    for (conditions, name) in on_dns_ports {
        out.push(spec(
            format!("{name} on a DNS port"),
            ConnectV4,
            Action::Permit,
            WEIGHT_PERMIT_DNS,
            conditions,
        ));
    }

    let lan_sharing = guard.map_or_else(
        || policy.block_all.as_ref().is_some_and(|b| b.lan_sharing),
        |g| g.lan_sharing,
    );
    for layer in [ConnectV4, ConnectV6] {
        out.push(spec(
            "Birdo: Permit DNS on loopback",
            layer,
            Action::Permit,
            WEIGHT_PERMIT_DNS,
            dns().chain([loopback(layer)]).collect(),
        ));
        out.push(spec(
            "Birdo: Block DNS outside the tunnel",
            layer,
            Action::Block,
            WEIGHT_BLOCK_NAME_RESOLUTION,
            dns().collect(),
        ));
        if !lan_sharing {
            out.push(spec(
                "Birdo: Block LLMNR, mDNS and NetBIOS name queries",
                layer,
                Action::Block,
                WEIGHT_BLOCK_NAME_RESOLUTION,
                [Condition::Protocol(UDP)]
                    .into_iter()
                    .chain(ports(&LAN_NAME_PORTS))
                    .collect(),
            ));
        }
    }
}

/// Up interfaces with no default gateway: the host's side of VirtualBox
/// host-only, WSL and Hyper-V virtual switches. Excludes loopback and the
/// tunnel. An uplink that has not got its gateway YET is re-evaluated on the
/// next default-route change (`wfp::refresh_after_network_change`).
pub(crate) fn host_only_interfaces(
    interfaces: &[InterfaceFacts],
    tunnel_luid: Option<u64>,
) -> Vec<u64> {
    let mut luids: Vec<u64> = interfaces
        .iter()
        .filter(|i| i.up && !i.loopback && !i.has_gateway && Some(i.luid) != tunnel_luid)
        .map(|i| i.luid)
        .collect();
    luids.sort_unstable();
    luids.dedup();
    luids
}

/// What `wfp.rs` reads off `GetAdaptersAddresses` for [`host_only_interfaces`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InterfaceFacts {
    pub luid: u64,
    pub up: bool,
    pub loopback: bool,
    pub has_gateway: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // ── A model of WFP's decision inside our sublayer ────────────────────

    /// One flow as WFP classifies it at an ALE layer.
    #[derive(Debug, Clone)]
    struct Flow {
        layer: Layer,
        app: &'static str,
        remote: IpAddr,
        remote_port: u16,
        local_port: u16,
        protocol: u8,
        interface: u64,
    }

    fn cond_field(c: &Condition) -> u8 {
        match c {
            Condition::RemoteV4 { .. } | Condition::RemoteV6 { .. } => 0,
            Condition::Protocol(_) => 1,
            Condition::RemotePort(_) | Condition::RemotePortRange(..) => 2,
            Condition::LocalPort(_) => 3,
            Condition::LocalInterface(_) => 4,
            Condition::App(_) => 5,
        }
    }

    fn cond_matches(c: &Condition, f: &Flow) -> bool {
        match (c, f.remote) {
            (Condition::RemoteV4 { addr, prefix }, IpAddr::V4(ip)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(ip) & mask == u32::from(*addr) & mask
            }
            (Condition::RemoteV6 { addr, prefix }, IpAddr::V6(ip)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(ip) & mask == u128::from(*addr) & mask
            }
            (Condition::RemoteV4 { .. } | Condition::RemoteV6 { .. }, _) => false,
            (Condition::Protocol(p), _) => f.protocol == *p,
            (Condition::RemotePort(p), _) => f.remote_port == *p,
            (Condition::RemotePortRange(lo, hi), _) => (*lo..=*hi).contains(&f.remote_port),
            (Condition::LocalPort(p), _) => f.local_port == *p,
            (Condition::LocalInterface(l), _) => f.interface == *l,
            (Condition::App(a), _) => f.app == a,
        }
    }

    /// Same field ORed, different fields ANDed.
    fn spec_matches(s: &FilterSpec, f: &Flow) -> bool {
        s.layer == f.layer
            && (0..6u8).all(|field| {
                let of_field: Vec<&Condition> = s
                    .conditions
                    .iter()
                    .filter(|c| cond_field(c) == field)
                    .collect();
                of_field.is_empty() || of_field.iter().any(|c| cond_matches(c, f))
            })
    }

    /// The highest-weight matching filter decides; `None` means our sublayer
    /// has no opinion (the flow is not ours to judge).
    fn decide(specs: &[FilterSpec], f: &Flow) -> Option<Action> {
        let matching: Vec<&FilterSpec> = specs.iter().filter(|s| spec_matches(s, f)).collect();
        let top = matching.iter().map(|s| s.weight).max()?;
        let actions: Vec<Action> = matching
            .iter()
            .filter(|s| s.weight == top)
            .map(|s| s.action)
            .collect();
        assert!(
            actions.iter().all(|a| *a == actions[0]),
            "two filters of weight {top} disagree on {f:?} — WFP's order between them is undefined"
        );
        Some(actions[0])
    }

    // ── Fixtures ─────────────────────────────────────────────────────────

    const SELF: &str = r"C:\Program Files\BirdoVPN\BirdoVPN.exe";
    const XRAY: &str = r"C:\Program Files\BirdoVPN\resources\xray.exe";
    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";
    const EXCEPTED: &str = r"C:\Games\game.exe";
    const WIFI: u64 = 0x0047_0000_0001;
    const TUNNEL: u64 = 0x0035_0000_0009;
    const VBOX: u64 = 0x0006_0000_0003;
    const RELAY: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 13, 13, 1);

    fn all_resolve(_: &str) -> bool {
        true
    }

    fn block(relay: Option<Relay>) -> BlockAll {
        BlockAll {
            self_exe: Some(SELF.to_string()),
            relay,
            stealth_helper: None,
            tunnel_luid: Some(TUNNEL),
            lan_sharing: false,
            exceptions: vec![EXCEPTED.to_string()],
            host_only_interfaces: vec![VBOX],
        }
    }

    fn wg_relay() -> Relay {
        Relay {
            ip: RELAY,
            port: 51820,
            transport: RelayTransport::WireGuardUdp,
        }
    }

    fn guard(lan_sharing: bool) -> DnsGuard {
        DnsGuard {
            resolvers: vec![RESOLVER],
            lan_resolvers: vec![],
            tunnel_luid: TUNNEL,
            lan_sharing,
            relay: Some(wg_relay()),
            self_exe: Some(SELF.to_string()),
        }
    }

    fn lockdown() -> Policy {
        Policy {
            block_all: Some(block(Some(wg_relay()))),
            v6_block: false,
            dns_guard: Some(guard(false)),
        }
    }

    fn out4(app: &'static str, ip: [u8; 4], port: u16, protocol: u8, interface: u64) -> Flow {
        Flow {
            layer: Layer::ConnectV4,
            app,
            remote: IpAddr::from(ip),
            remote_port: port,
            local_port: 50000,
            protocol,
            interface,
        }
    }

    fn in4(
        app: &'static str,
        from: [u8; 4],
        local_port: u16,
        protocol: u8,
        interface: u64,
    ) -> Flow {
        Flow {
            layer: Layer::RecvAcceptV4,
            app,
            remote: IpAddr::from(from),
            remote_port: 40000,
            local_port,
            protocol,
            interface,
        }
    }

    fn specs(policy: &Policy) -> Vec<FilterSpec> {
        filter_specs(policy, &all_resolve)
    }

    // ── W1-013 (D-24): app-scoped permits ───────────────────────────────

    #[test]
    fn only_the_app_reaches_the_relay_and_only_on_the_tunnels_port() {
        let s = specs(&lockdown());
        let wg = out4(SELF, RELAY.octets(), 51820, UDP, WIFI);
        assert_eq!(decide(&s, &wg), Some(Action::Permit));
        // Any other process to the same relay, same port: blocked (D-24).
        assert_eq!(
            decide(&s, &out4(CHROME, RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Block)
        );
        // The app itself, another port or protocol: not a relay flow.
        assert_eq!(
            decide(&s, &out4(SELF, RELAY.octets(), 22, TCP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(SELF, RELAY.octets(), 51821, UDP, WIFI)),
            Some(Action::Block)
        );
    }

    #[test]
    fn every_relay_and_control_plane_permit_names_its_app() {
        let s = specs(&lockdown());
        for f in s.iter().filter(|f| {
            f.action == Action::Permit
                && f.conditions.iter().any(|c| {
                    matches!(c, Condition::RemoteV4 { addr, .. } if *addr == RELAY)
                        || *c == Condition::RemotePort(CONTROL_PLANE_PORT)
                })
        }) {
            assert!(
                f.conditions.contains(&Condition::App(SELF.to_string())),
                "{} is not scoped to the app",
                f.name
            );
        }
        // No permit anywhere is "the relay address, and nothing else".
        assert!(!s.iter().any(|f| f.action == Action::Permit
            && f.conditions
                == vec![Condition::RemoteV4 {
                    addr: RELAY,
                    prefix: 32
                }]));
    }

    #[test]
    fn the_control_plane_permit_is_the_apps_https_and_nothing_else() {
        let s = specs(&lockdown());
        let api = [104, 21, 5, 9];
        assert_eq!(
            decide(&s, &out4(SELF, api, 443, TCP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(SELF, api, 80, TCP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(SELF, api, 443, UDP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, api, 443, TCP, WIFI)),
            Some(Action::Block)
        );
    }

    #[test]
    fn stealth_permits_only_xray_to_the_relay_over_tcp() {
        let mut policy = lockdown();
        let b = policy.block_all.as_mut().unwrap();
        b.relay = Some(Relay {
            ip: RELAY,
            port: 8443,
            transport: RelayTransport::StealthTcp,
        });
        b.stealth_helper = Some(XRAY.to_string());
        let s = specs(&policy);
        assert_eq!(
            decide(&s, &out4(XRAY, RELAY.octets(), 8443, TCP, WIFI)),
            Some(Action::Permit)
        );
        // xray is no longer permitted to anything else (it used to be).
        assert_eq!(
            decide(&s, &out4(XRAY, [1, 1, 1, 1], 443, TCP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, RELAY.octets(), 8443, TCP, WIFI)),
            Some(Action::Block)
        );
        // WireGuard reaches xray over loopback.
        assert_eq!(
            decide(&s, &out4(SELF, [127, 0, 0, 1], 40001, UDP, 1)),
            Some(Action::Permit)
        );
    }

    /// An app id that cannot be resolved must not silently drop the relay
    /// permit (a lockdown session could then never reconnect): it falls back
    /// to address + protocol + port. The control plane has no safe fallback.
    #[test]
    fn an_unresolvable_app_falls_back_loudly_scoped_not_open() {
        let s = filter_specs(&lockdown(), &|path| path != SELF);
        let relay: Vec<&FilterSpec> = s
            .iter()
            .filter(|f| {
                f.conditions.contains(&Condition::RemoteV4 {
                    addr: RELAY,
                    prefix: 32,
                })
            })
            .collect();
        assert!(!relay.is_empty());
        for f in relay {
            assert!(f.name.contains("app id unavailable"), "{}", f.name);
            assert!(f.conditions.contains(&Condition::Protocol(UDP)));
            assert!(f.conditions.contains(&Condition::RemotePort(51820)));
            assert!(!f.conditions.iter().any(|c| matches!(c, Condition::App(_))));
        }
        assert!(
            !s.iter().any(|f| f
                .conditions
                .contains(&Condition::RemotePort(CONTROL_PLANE_PORT))
                && f.action == Action::Permit),
            "an unscoped tcp/443 permit would let every app through the block"
        );
    }

    // ── REVIEW-WIN2-001: the relay moves with the block ─────────────────

    /// The server a switch goes to.
    const NEXT_RELAY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

    fn relay_to(ip: Ipv4Addr, port: u16, transport: RelayTransport) -> Relay {
        Relay {
            ip,
            port,
            transport,
        }
    }

    /// Every permit that names `ip` is scoped to an app: moving the relay
    /// never opens the address to every process on the machine.
    fn every_permit_to_names_an_app(s: &[FilterSpec], ip: Ipv4Addr) {
        for f in s.iter().filter(|f| {
            f.action == Action::Permit
                && f.conditions.contains(&Condition::RemoteV4 {
                    addr: ip,
                    prefix: 32,
                })
        }) {
            assert!(
                f.conditions.iter().any(|c| matches!(c, Condition::App(_))),
                "{} is not scoped to an app",
                f.name
            );
        }
    }

    /// The Windows default: connected to A under lockdown, the user picks B.
    /// The switch guard's commit already carries B's permit, so the new
    /// handshake leaves; nothing else reaches B, and A is closed behind it.
    #[test]
    fn a_lockdown_switch_commits_the_new_relay_with_the_block() {
        let installed = lockdown();
        let next = after_relay_move(
            &installed,
            block(Some(relay_to(
                NEXT_RELAY,
                51820,
                RelayTransport::WireGuardUdp,
            ))),
            true,
        )
        .expect("the switch guard commits");
        let s = specs(&next);
        assert_eq!(
            decide(&s, &out4(SELF, NEXT_RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, NEXT_RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(SELF, RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Block),
            "the previous relay stays open behind the switch"
        );
        assert_eq!(next.dns_guard, installed.dns_guard);
        every_permit_to_names_an_app(&s, NEXT_RELAY);
    }

    /// Lockdown again, with no engage: the block is already in force (held
    /// for the session, or by a give-up). A port or transport change, a
    /// re-dial onto another relay, or a connect to another server from the
    /// blocking state moves the permit at once — this commit used to be
    /// skipped in lockdown, which left the held block naming the old relay.
    #[test]
    fn a_held_block_is_rebuilt_around_the_new_relay_without_an_engage() {
        let mut gave_up = lockdown();
        gave_up.dns_guard = None;
        gave_up.block_all.as_mut().unwrap().tunnel_luid = None;
        let next = after_relay_move(
            &gave_up,
            BlockAll {
                tunnel_luid: None,
                ..block(Some(relay_to(NEXT_RELAY, 53, RelayTransport::WireGuardUdp)))
            },
            false,
        )
        .expect("a held block is rebuilt");
        let s = specs(&next);
        assert_eq!(
            decide(&s, &out4(SELF, NEXT_RELAY.octets(), 53, UDP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(SELF, RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Block)
        );
    }

    /// Reactive mode: Connected holds no block-all. The guard's commit is the
    /// FIRST block of the rebuild, and it already names B — there is no
    /// moment with the block up and only the old relay permitted.
    #[test]
    fn a_reactive_switch_engages_the_block_already_naming_the_new_relay() {
        let connected = Policy {
            block_all: None,
            v6_block: true,
            dns_guard: Some(guard(false)),
        };
        let next = after_relay_move(
            &connected,
            BlockAll {
                tunnel_luid: None,
                ..block(Some(relay_to(
                    NEXT_RELAY,
                    51820,
                    RelayTransport::WireGuardUdp,
                )))
            },
            true,
        )
        .expect("the switch guard commits");
        let s = specs(&next);
        assert_eq!(
            decide(&s, &out4(SELF, NEXT_RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, [142, 250, 1, 1], 443, TCP, WIFI)),
            Some(Action::Block),
            "the guard is a block-all"
        );
        assert!(next.v6_block, "the session's IPv6 intent is kept");
    }

    /// Nothing blocking and nothing engaged (a fresh connect; the kill switch
    /// off): the relay is only recorded, and the session is not touched.
    #[test]
    fn with_no_block_a_relay_move_commits_nothing() {
        let reactive = Policy {
            block_all: None,
            v6_block: true,
            dns_guard: Some(guard(false)),
        };
        assert_eq!(
            after_relay_move(&reactive, block(Some(wg_relay())), false),
            None
        );
        assert_eq!(
            after_relay_move(&Policy::default(), block(Some(wg_relay())), false),
            None
        );
    }

    /// A switch onto Stealth: the same commit lets xray — and only xray —
    /// reach B over TCP.
    #[test]
    fn a_switch_onto_stealth_commits_the_helpers_permit_with_the_block() {
        let next = after_relay_move(
            &lockdown(),
            BlockAll {
                stealth_helper: Some(XRAY.to_string()),
                ..block(Some(relay_to(NEXT_RELAY, 443, RelayTransport::StealthTcp)))
            },
            true,
        )
        .expect("the switch guard commits");
        let s = specs(&next);
        assert_eq!(
            decide(&s, &out4(XRAY, NEXT_RELAY.octets(), 443, TCP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(SELF, NEXT_RELAY.octets(), 443, UDP, WIFI)),
            Some(Action::Block)
        );
        // The app's own HTTPS (the control plane) is the one other way to B.
        assert_eq!(
            decide(&s, &out4(CHROME, NEXT_RELAY.octets(), 443, TCP, WIFI)),
            Some(Action::Block)
        );
        every_permit_to_names_an_app(&s, NEXT_RELAY);
    }

    // ── W1-014: inbound ─────────────────────────────────────────────────

    #[test]
    fn inbound_on_the_physical_nic_is_blocked_on_both_families() {
        let s = specs(&lockdown());
        assert_eq!(
            decide(&s, &in4(SVCHOST, [203, 0, 113, 99], 445, TCP, WIFI)),
            Some(Action::Block)
        );
        let v6 = Flow {
            layer: Layer::RecvAcceptV6,
            app: SVCHOST,
            remote: "2001:db8::99".parse().unwrap(),
            remote_port: 40000,
            local_port: 3389,
            protocol: TCP,
            interface: WIFI,
        };
        assert_eq!(decide(&s, &v6), Some(Action::Block));
        for layer in [Layer::RecvAcceptV4, Layer::RecvAcceptV6] {
            assert!(s.iter().any(|f| f.layer == layer
                && f.action == Action::Block
                && f.weight == WEIGHT_BLOCK_ALL
                && f.conditions.is_empty()));
        }
    }

    #[test]
    fn inbound_keeps_dhcp_loopback_the_tunnel_and_host_only_networks() {
        let s = specs(&lockdown());
        // A DHCP offer broadcast to the client port.
        assert_eq!(
            decide(
                &s,
                &Flow {
                    remote_port: 67,
                    ..in4(SVCHOST, [192, 168, 1, 1], 68, UDP, WIFI)
                }
            ),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &in4(SVCHOST, [127, 0, 0, 1], 8080, TCP, 1)),
            Some(Action::Permit)
        );
        // Port forwarding arrives over the tunnel.
        assert_eq!(
            decide(&s, &in4(CHROME, [10, 13, 13, 1], 8080, TCP, TUNNEL)),
            Some(Action::Permit)
        );
        // A VirtualBox guest talking to its host.
        assert_eq!(
            decide(&s, &in4(SVCHOST, [192, 168, 56, 101], 445, TCP, VBOX)),
            Some(Action::Permit)
        );
    }

    #[test]
    fn neighbor_discovery_survives_the_block_but_inbound_ping_does_not() {
        let s = specs(&lockdown());
        let icmp6 = |layer: Layer, icmp_type: u16| Flow {
            layer,
            app: SVCHOST,
            remote: "fe80::1".parse().unwrap(),
            remote_port: 0,
            local_port: icmp_type,
            protocol: ICMPV6,
            interface: WIFI,
        };
        for t in [134, 135, 136, 137] {
            assert_eq!(
                decide(&s, &icmp6(Layer::RecvAcceptV6, t)),
                Some(Action::Permit),
                "{t}"
            );
        }
        for t in [133, 135, 136] {
            assert_eq!(
                decide(&s, &icmp6(Layer::ConnectV6, t)),
                Some(Action::Permit),
                "{t}"
            );
        }
        // An echo request from outside is not neighbor discovery.
        assert_eq!(
            decide(&s, &icmp6(Layer::RecvAcceptV6, 128)),
            Some(Action::Block)
        );
    }

    #[test]
    fn lan_sharing_opens_the_lan_both_ways_and_nothing_else() {
        let mut policy = lockdown();
        policy.block_all.as_mut().unwrap().lan_sharing = true;
        let s = specs(&policy);
        assert_eq!(
            decide(&s, &in4(SVCHOST, [192, 168, 1, 50], 445, TCP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, [192, 168, 1, 20], 631, TCP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &in4(SVCHOST, [203, 0, 113, 99], 445, TCP, WIFI)),
            Some(Action::Block)
        );
    }

    #[test]
    fn a_kill_switch_exception_is_exempt_both_ways() {
        let s = specs(&lockdown());
        assert_eq!(
            decide(&s, &out4(EXCEPTED, [8, 8, 4, 4], 27015, UDP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &in4(EXCEPTED, [8, 8, 4, 4], 27015, UDP, WIFI)),
            Some(Action::Permit)
        );
    }

    #[test]
    fn nothing_inbound_is_touched_without_the_block_all() {
        let policy = Policy {
            block_all: None,
            v6_block: true,
            dns_guard: Some(guard(false)),
        };
        let s = specs(&policy);
        assert!(!s
            .iter()
            .any(|f| matches!(f.layer, Layer::RecvAcceptV4 | Layer::RecvAcceptV6)));
    }

    // ── W1-007: the DNS guard ───────────────────────────────────────────

    #[test]
    fn dns_reaches_only_the_tunnel_resolver_over_the_tunnel() {
        for policy in [
            lockdown(),
            Policy {
                block_all: None,
                v6_block: true,
                dns_guard: Some(guard(false)),
            },
        ] {
            let s = specs(&policy);
            assert_eq!(
                decide(&s, &out4(SVCHOST, RESOLVER.octets(), 53, UDP, TUNNEL)),
                Some(Action::Permit)
            );
            assert_eq!(
                decide(&s, &out4(SVCHOST, RESOLVER.octets(), 53, TCP, TUNNEL)),
                Some(Action::Permit)
            );
            // SMHNR's query to the Wi-Fi resolvers — static or DHCP alike.
            for isp in [[8, 8, 8, 8], [194, 168, 4, 100], [192, 168, 1, 1]] {
                assert_eq!(
                    decide(&s, &out4(SVCHOST, isp, 53, UDP, WIFI)),
                    Some(Action::Block),
                    "{isp:?}"
                );
            }
            // The tunnel resolver's address, but off the tunnel: blocked.
            assert_eq!(
                decide(&s, &out4(SVCHOST, RESOLVER.octets(), 53, UDP, WIFI)),
                Some(Action::Block)
            );
            // Another resolver through the tunnel (nslookup x 1.1.1.1).
            assert_eq!(
                decide(&s, &out4(SVCHOST, [1, 1, 1, 1], 53, UDP, TUNNEL)),
                Some(Action::Block)
            );
            // DoT and DoQ anywhere else.
            assert_eq!(
                decide(&s, &out4(CHROME, [1, 1, 1, 1], 853, TCP, TUNNEL)),
                Some(Action::Block)
            );
            assert_eq!(
                decide(&s, &out4(CHROME, [1, 1, 1, 1], 853, UDP, WIFI)),
                Some(Action::Block)
            );
            // IPv6 DNS: loopback only.
            let v6 = |ip: &str| Flow {
                layer: Layer::ConnectV6,
                app: SVCHOST,
                remote: ip.parse().unwrap(),
                remote_port: 53,
                local_port: 50000,
                protocol: UDP,
                interface: WIFI,
            };
            assert_eq!(decide(&s, &v6("2001:4860:4860::8888")), Some(Action::Block));
            assert_eq!(decide(&s, &v6("fe80::1")), Some(Action::Block));
            assert_eq!(decide(&s, &v6("::1")), Some(Action::Permit));
            // A local DNS proxy.
            assert_eq!(
                decide(&s, &out4(SVCHOST, [127, 0, 0, 1], 53, UDP, 1)),
                Some(Action::Permit)
            );
        }
    }

    /// The DNS block outranks every ordinary permit: the LAN permit (router
    /// DNS), the tunnel-interface permit and the kill-switch exceptions.
    #[test]
    fn the_dns_block_beats_every_ordinary_permit() {
        let mut policy = lockdown();
        policy.block_all.as_mut().unwrap().lan_sharing = true;
        let s = specs(&policy);
        assert_eq!(
            decide(&s, &out4(SVCHOST, [192, 168, 1, 1], 53, UDP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(EXCEPTED, [9, 9, 9, 9], 53, UDP, WIFI)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, [9, 9, 9, 9], 53, UDP, TUNNEL)),
            Some(Action::Block)
        );
    }

    #[test]
    fn the_dns_permit_names_only_the_tunnel_resolvers_on_the_tunnel() {
        let s = specs(&lockdown());
        let permits: Vec<&FilterSpec> = s
            .iter()
            .filter(|f| f.action == Action::Permit && f.weight == WEIGHT_PERMIT_DNS)
            .collect();
        assert!(permits
            .iter()
            .any(|f| f.conditions.contains(&Condition::LocalInterface(TUNNEL))));
        for f in &permits {
            if f.conditions.contains(&Condition::LocalInterface(TUNNEL)) {
                let remotes: Vec<&Condition> = f
                    .conditions
                    .iter()
                    .filter(|c| {
                        matches!(c, Condition::RemoteV4 { .. } | Condition::RemoteV6 { .. })
                    })
                    .collect();
                assert_eq!(
                    remotes,
                    vec![&Condition::RemoteV4 {
                        addr: RESOLVER,
                        prefix: 32
                    }]
                );
            } else {
                assert!(
                    f.conditions.contains(&loopback(f.layer)),
                    "{} permits DNS beyond loopback",
                    f.name
                );
            }
        }
    }

    #[test]
    fn lan_name_resolution_is_blocked_unless_lan_sharing_is_on() {
        let mdns = |s: &[FilterSpec]| decide(s, &out4(SVCHOST, [224, 0, 0, 251], 5353, UDP, WIFI));
        let llmnr = |s: &[FilterSpec]| decide(s, &out4(SVCHOST, [224, 0, 0, 252], 5355, UDP, WIFI));
        let netbios =
            |s: &[FilterSpec]| decide(s, &out4(SVCHOST, [192, 168, 1, 255], 137, UDP, WIFI));

        let reactive = Policy {
            block_all: None,
            v6_block: true,
            dns_guard: Some(guard(false)),
        };
        let s = specs(&reactive);
        assert_eq!(mdns(&s), Some(Action::Block));
        assert_eq!(llmnr(&s), Some(Action::Block));
        assert_eq!(netbios(&s), Some(Action::Block));

        let sharing = Policy {
            dns_guard: Some(guard(true)),
            ..reactive
        };
        let s = specs(&sharing);
        assert_eq!(mdns(&s), None, "LAN sharing leaves LAN discovery alone");
        assert_eq!(llmnr(&s), None);
    }

    /// Without a tunnel resolver there is nothing to permit: DNS stays blocked
    /// rather than falling open.
    #[test]
    fn a_guard_with_no_resolvers_blocks_all_dns() {
        let policy = Policy {
            block_all: None,
            v6_block: false,
            dns_guard: Some(DnsGuard {
                resolvers: vec![],
                ..guard(false)
            }),
        };
        let s = specs(&policy);
        assert_eq!(
            decide(&s, &out4(SVCHOST, RESOLVER.octets(), 53, UDP, TUNNEL)),
            Some(Action::Block)
        );
    }

    // ── REVIEW-WIN2-004: the block-all keeps DNS inside on its own ──────

    /// The reconnect gap, and a lockdown give-up's held block: the tunnel is
    /// gone and its guard lifted, only the block-all is up. With LAN sharing
    /// on, its LAN permit used to let Windows' resolver reach the router.
    #[test]
    fn the_block_all_alone_keeps_dns_inside_even_with_lan_sharing() {
        let gap = Policy {
            block_all: Some(BlockAll {
                tunnel_luid: None,
                lan_sharing: true,
                ..block(Some(wg_relay()))
            }),
            v6_block: false,
            dns_guard: None,
        };
        let s = specs(&gap);
        for (protocol, port) in [(UDP, 53), (TCP, 53), (TCP, 853), (UDP, 853)] {
            assert_eq!(
                decide(&s, &out4(SVCHOST, [192, 168, 1, 1], port, protocol, WIFI)),
                Some(Action::Block),
                "{protocol}/{port}"
            );
        }
        assert_eq!(
            decide(&s, &out4(EXCEPTED, [9, 9, 9, 9], 53, UDP, WIFI)),
            Some(Action::Block)
        );
        // LAN sharing still works for everything that is not DNS…
        assert_eq!(
            decide(&s, &out4(CHROME, [192, 168, 1, 20], 631, TCP, WIFI)),
            Some(Action::Permit)
        );
        // …and so do the re-dial, its control plane and DHCP.
        assert_eq!(
            decide(&s, &out4(SELF, RELAY.octets(), 51820, UDP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(SELF, [104, 21, 5, 9], 443, TCP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(SVCHOST, [255, 255, 255, 255], 67, UDP, WIFI)),
            Some(Action::Permit)
        );
        // A local DNS proxy is still loopback.
        assert_eq!(
            decide(&s, &out4(SVCHOST, [127, 0, 0, 1], 53, UDP, 1)),
            Some(Action::Permit)
        );
    }

    /// Both up (lockdown, Connected): one name-resolution block, not two.
    #[test]
    fn the_block_and_the_guard_share_one_dns_block() {
        let s = specs(&lockdown());
        let blocks = s
            .iter()
            .filter(|f| f.name == "Birdo: Block DNS outside the tunnel")
            .count();
        assert_eq!(blocks, 2, "one per family");
    }

    // ── The relay on a DNS port ─────────────────────────────────────────

    /// WireGuard port 53 is a preset in VPN Settings. The DNS block must not
    /// drop the tunnel itself — under the guard alone (reactive, Connected),
    /// under the block-all alone (the re-dial in a gap) and under both — and
    /// nothing else may use that hole.
    #[test]
    fn a_relay_on_port_53_is_not_blocked_by_the_dns_block() {
        let on_53 = relay_to(RELAY, 53, RelayTransport::WireGuardUdp);
        let guarded = DnsGuard {
            relay: Some(on_53),
            ..guard(false)
        };
        let policies = [
            Policy {
                block_all: None,
                v6_block: true,
                dns_guard: Some(guarded.clone()),
            },
            Policy {
                block_all: Some(BlockAll {
                    tunnel_luid: None,
                    ..block(Some(on_53))
                }),
                v6_block: false,
                dns_guard: None,
            },
            Policy {
                block_all: Some(block(Some(on_53))),
                v6_block: false,
                dns_guard: Some(guarded),
            },
        ];
        for policy in policies {
            let s = specs(&policy);
            assert_eq!(
                decide(&s, &out4(SELF, RELAY.octets(), 53, UDP, WIFI)),
                Some(Action::Permit),
                "{policy:?}"
            );
            // Another process asking the relay's address for DNS.
            assert_eq!(
                decide(&s, &out4(SVCHOST, RELAY.octets(), 53, UDP, WIFI)),
                Some(Action::Block)
            );
            // The app's own DNS anywhere else.
            assert_eq!(
                decide(&s, &out4(SELF, [8, 8, 8, 8], 53, UDP, WIFI)),
                Some(Action::Block)
            );
            every_permit_to_names_an_app(&s, RELAY);
        }
    }

    /// `wfp.rs` resolves app ids only for the executables the policy names,
    /// and an unresolved one builds its permit for any app. A guard alone
    /// names this executable, for its relay flow; without that the permit
    /// above was built unscoped in reactive mode.
    #[test]
    fn the_guard_names_the_app_its_relay_permit_is_scoped_to() {
        let guard_only = Policy {
            block_all: None,
            v6_block: true,
            dns_guard: Some(guard(false)),
        };
        let names = |policy: &Policy| -> Vec<String> {
            named_apps(policy)
                .iter()
                .map(|a| a.path.to_string())
                .collect()
        };
        assert_eq!(names(&guard_only), vec![SELF.to_string()]);
        // Scoped only when it resolves: what `wfp.rs` hands filter_specs.
        let on_53 = Policy {
            dns_guard: Some(DnsGuard {
                relay: Some(relay_to(RELAY, 53, RelayTransport::WireGuardUdp)),
                ..guard(false)
            }),
            ..guard_only
        };
        let resolvable = names(&on_53);
        let resolved = |path: &str| resolvable.iter().any(|p| p == path);
        every_permit_to_names_an_app(&filter_specs(&on_53, &resolved), RELAY);

        let lockdown_names = names(&lockdown());
        assert!(lockdown_names.iter().any(|p| p == SELF));
        assert!(lockdown_names.iter().any(|p| p == EXCEPTED));
        assert!(named_apps(&Policy::default()).is_empty());
    }

    /// A switch from a relay on port 53 to one on 853 (TCP, Stealth): for the
    /// length of the switch both flows are the tunnel's own.
    #[test]
    fn during_a_switch_both_relays_on_dns_ports_are_the_tunnels() {
        let next = relay_to(NEXT_RELAY, 853, RelayTransport::StealthTcp);
        let policy = Policy {
            block_all: Some(BlockAll {
                stealth_helper: Some(XRAY.to_string()),
                ..block(Some(next))
            }),
            v6_block: false,
            dns_guard: Some(DnsGuard {
                relay: Some(relay_to(RELAY, 53, RelayTransport::WireGuardUdp)),
                ..guard(false)
            }),
        };
        let s = specs(&policy);
        assert_eq!(
            decide(&s, &out4(XRAY, NEXT_RELAY.octets(), 853, TCP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(SELF, RELAY.octets(), 53, UDP, WIFI)),
            Some(Action::Permit)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, NEXT_RELAY.octets(), 853, TCP, WIFI)),
            Some(Action::Block)
        );
    }

    // ── REVIEW-WIN2-006: a LAN resolver chosen as Custom DNS ────────────

    const PIHOLE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);

    /// Which resolvers leave the tunnel: only the user's own private Custom
    /// DNS, and only with Local Network Sharing on.
    #[test]
    fn only_a_private_custom_resolver_with_lan_sharing_is_the_lans() {
        let public = Ipv4Addr::new(9, 9, 9, 9);
        let fleet = Ipv4Addr::new(10, 13, 13, 1);
        let ten = Ipv4Addr::new(10, 0, 0, 53);
        let corp = Ipv4Addr::new(172, 20, 0, 53);
        let all = [PIHOLE, public, ten, corp];

        let (tunnel, lan) = split_resolvers(&all, true, true);
        assert_eq!(tunnel, vec![public]);
        assert_eq!(lan, vec![PIHOLE, ten, corp]);
        // Without LAN sharing it stays pinned to the tunnel (unreachable,
        // never in the clear).
        assert_eq!(split_resolvers(&all, true, false), (all.to_vec(), vec![]));
        // The server's own resolvers never leave — the fleet's is in 10/8.
        assert_eq!(
            split_resolvers(&[fleet, public], false, true),
            (vec![fleet, public], vec![])
        );
    }

    #[test]
    fn a_lan_resolver_is_reachable_with_lan_sharing_and_nothing_else_is() {
        let lan_guard = DnsGuard {
            resolvers: vec![],
            lan_resolvers: vec![PIHOLE],
            ..guard(true)
        };
        let policies = [
            // Reactive, Connected.
            Policy {
                block_all: None,
                v6_block: true,
                dns_guard: Some(lan_guard.clone()),
            },
            // Lockdown, Connected, LAN sharing on.
            Policy {
                block_all: Some(BlockAll {
                    lan_sharing: true,
                    ..block(Some(wg_relay()))
                }),
                v6_block: false,
                dns_guard: Some(lan_guard),
            },
        ];
        for policy in policies {
            let s = specs(&policy);
            for (protocol, port) in [(UDP, 53), (TCP, 53)] {
                assert_eq!(
                    decide(&s, &out4(SVCHOST, PIHOLE.octets(), port, protocol, WIFI)),
                    Some(Action::Permit),
                    "{policy:?}"
                );
            }
            // The router, any other LAN host, and the internet stay blocked.
            for other in [[192, 168, 1, 1], [192, 168, 1, 3], [8, 8, 8, 8]] {
                assert_eq!(
                    decide(&s, &out4(SVCHOST, other, 53, UDP, WIFI)),
                    Some(Action::Block),
                    "{other:?}"
                );
            }
        }
        // In the gap the guard is lifted and the LAN resolver goes with it:
        // nothing resolves, nothing leaves.
        let gap = Policy {
            block_all: Some(BlockAll {
                tunnel_luid: None,
                lan_sharing: true,
                ..block(Some(wg_relay()))
            }),
            v6_block: false,
            dns_guard: None,
        };
        assert_eq!(
            decide(&specs(&gap), &out4(SVCHOST, PIHOLE.octets(), 53, UDP, WIFI)),
            Some(Action::Block)
        );
    }

    // ── Ordering and scope ──────────────────────────────────────────────

    #[test]
    #[allow(clippy::assertions_on_constants)] // asserting the real constants IS the point
    fn the_weights_are_ordered() {
        assert!(WEIGHT_BLOCK_ALL < WEIGHT_PERMIT);
        assert!(WEIGHT_PERMIT < WEIGHT_BLOCK_NAME_RESOLUTION);
        assert!(WEIGHT_BLOCK_NAME_RESOLUTION < WEIGHT_PERMIT_DNS);
        assert!(WEIGHT_PERMIT_DNS < WEIGHT_BLOCK_STUN);
    }

    #[test]
    fn every_filter_uses_a_known_weight_for_its_action() {
        let mut policy = lockdown();
        let b = policy.block_all.as_mut().unwrap();
        b.lan_sharing = true;
        b.stealth_helper = Some(XRAY.to_string());
        for f in specs(&policy) {
            let ok = match f.action {
                Action::Block => [
                    WEIGHT_BLOCK_ALL,
                    WEIGHT_BLOCK_NAME_RESOLUTION,
                    WEIGHT_BLOCK_STUN,
                ]
                .contains(&f.weight),
                Action::Permit => [WEIGHT_PERMIT, WEIGHT_PERMIT_DNS].contains(&f.weight),
            };
            assert!(ok, "{} has weight {}", f.name, f.weight);
            // Only block-alls may be unconditional.
            assert!(
                !f.conditions.is_empty()
                    || (f.action == Action::Block && f.weight == WEIGHT_BLOCK_ALL),
                "{} matches everything",
                f.name
            );
        }
    }

    #[test]
    fn stun_stays_blocked_even_through_the_tunnel_permit() {
        let s = specs(&lockdown());
        assert_eq!(
            decide(&s, &out4(CHROME, [74, 125, 250, 129], 19302, UDP, TUNNEL)),
            Some(Action::Block)
        );
        assert_eq!(
            decide(&s, &out4(CHROME, [142, 250, 1, 1], 443, TCP, TUNNEL)),
            Some(Action::Permit)
        );
    }

    /// The STUN residue of P1-ks-wfp-webrtc-claim-false-in-reactive: IPv4
    /// blocked Google STUN on 19302-19309 and IPv6 on 19302 alone, so Meet's
    /// media ports were open over IPv6 through the tunnel permit. Both
    /// families carry the same STUN/TURN blocks now.
    #[test]
    fn stun_is_blocked_on_the_same_ports_on_both_families() {
        let s = specs(&lockdown());
        let stun = |layer: Layer| -> Vec<(&str, &[Condition])> {
            s.iter()
                .filter(|f| f.layer == layer && f.weight == WEIGHT_BLOCK_STUN)
                .map(|f| (f.name.as_str(), f.conditions.as_slice()))
                .collect()
        };
        assert_eq!(stun(Layer::ConnectV4).len(), 3);
        assert_eq!(stun(Layer::ConnectV4), stun(Layer::ConnectV6));

        let meet_v6 = Flow {
            layer: Layer::ConnectV6,
            app: CHROME,
            remote: "2001:db8::5".parse().unwrap(),
            remote_port: 19305,
            local_port: 50000,
            protocol: UDP,
            interface: TUNNEL,
        };
        assert_eq!(decide(&s, &meet_v6), Some(Action::Block));
        assert_eq!(
            decide(&s, &out4(CHROME, [74, 125, 250, 129], 19309, UDP, TUNNEL)),
            Some(Action::Block)
        );
    }

    #[test]
    fn the_standalone_ipv6_block_is_outbound_only_and_yields_to_the_block_all() {
        let alone = specs(&Policy {
            block_all: None,
            v6_block: true,
            dns_guard: None,
        });
        assert_eq!(alone.len(), 3);
        assert!(alone.iter().all(|f| f.layer == Layer::ConnectV6));
        let v6 = Flow {
            layer: Layer::ConnectV6,
            app: CHROME,
            remote: "2606:4700::1111".parse().unwrap(),
            remote_port: 443,
            local_port: 50000,
            protocol: TCP,
            interface: WIFI,
        };
        assert_eq!(decide(&alone, &v6), Some(Action::Block));

        // With the block-all up, its own v6 block-all covers it once.
        let both = specs(&Policy {
            v6_block: true,
            ..lockdown()
        });
        let v6_block_alls = both
            .iter()
            .filter(|f| f.layer == Layer::ConnectV6 && f.conditions.is_empty())
            .count();
        assert_eq!(v6_block_alls, 1);
    }

    #[test]
    fn a_relay_needs_an_address_and_a_port() {
        assert_eq!(
            parse_relay("203.0.113.7:8443", RelayTransport::StealthTcp),
            Some(Relay {
                ip: RELAY,
                port: 8443,
                transport: RelayTransport::StealthTcp
            })
        );
        assert_eq!(
            parse_relay("203.0.113.7", RelayTransport::WireGuardUdp),
            None
        );
        assert_eq!(
            parse_relay("relay.example:51820", RelayTransport::WireGuardUdp),
            None
        );
        assert_eq!(
            parse_relay("[2001:db8::1]:51820", RelayTransport::WireGuardUdp),
            None
        );
    }

    #[test]
    fn an_empty_policy_installs_nothing() {
        assert!(specs(&Policy::default()).is_empty());
    }

    /// Reactive mode, Connected: no block-all, so ordinary traffic is not
    /// ours to judge — only DNS and the IPv6 block are.
    #[test]
    fn a_reactive_session_judges_only_dns_and_ipv6() {
        let s = specs(&Policy {
            block_all: None,
            v6_block: true,
            dns_guard: Some(guard(false)),
        });
        assert_eq!(
            decide(&s, &out4(CHROME, [142, 250, 1, 1], 443, TCP, WIFI)),
            None
        );
        assert_eq!(
            decide(&s, &out4(CHROME, [8, 8, 8, 8], 53, UDP, WIFI)),
            Some(Action::Block)
        );
    }

    #[test]
    fn host_only_interfaces_are_the_gatewayless_up_ones_but_never_the_tunnel() {
        let facts = [
            InterfaceFacts {
                luid: WIFI,
                up: true,
                loopback: false,
                has_gateway: true,
            },
            InterfaceFacts {
                luid: VBOX,
                up: true,
                loopback: false,
                has_gateway: false,
            },
            InterfaceFacts {
                luid: 77,
                up: false,
                loopback: false,
                has_gateway: false,
            },
            InterfaceFacts {
                luid: 1,
                up: true,
                loopback: true,
                has_gateway: false,
            },
            InterfaceFacts {
                luid: TUNNEL,
                up: true,
                loopback: false,
                has_gateway: false,
            },
        ];
        assert_eq!(host_only_interfaces(&facts, Some(TUNNEL)), vec![VBOX]);
    }
}
