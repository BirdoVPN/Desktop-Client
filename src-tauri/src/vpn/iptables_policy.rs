//! What the Linux kill switch's iptables chains contain, as plain data.
//!
//! `vpn/firewall_linux.rs` runs `iptables` / `ip6tables` and owns the
//! two-generation swap. WHAT each chain permits is decided here instead, free
//! of any process spawn, so it is unit-tested on every OS (the Windows job runs
//! these tests): the twin of `pf_policy` on macOS. The Linux CI runner then
//! builds the chains for real, never hooked into a built-in chain, and reads
//! the kernel's own listing back through the same checker
//! (`firewall_linux::iptables_chain_tests`, run by tests.yml's root step).
//!
//! # What the block-all permits (IPv4, outbound)
//!
//! | rule                                            | why                          |
//! |-------------------------------------------------|------------------------------|
//! | `-o lo`                                         | local IPC, the stealth helper|
//! | udp to port 67                                  | DHCP: the lease outlives the block |
//! | `-d <relay>`                                    | the re-dial (WireGuard, stealth) |
//! | `-o birdo0`                                     | traffic already in the tunnel |
//! | the LAN ranges, with Local Network Sharing      | printers, NAS, SSH           |
//! | our uid's tcp/443 to each control-plane address | the control plane: API and DoH |
//!
//! Everything else meets `-j DROP`. IPv6 permits nothing but loopback, DHCPv6
//! and link-local ICMPv6: the control plane is reached over IPv4 only.

use std::net::Ipv4Addr;

/// The tunnel interface `tunnel_linux` creates.
const TUNNEL_INTERFACE: &str = "birdo0";

/// HTTPS: the API, the web origin's client config and DoH. The relay has its
/// own permit; nothing else of the app's needs a way out while the block is
/// up (the macOS and Windows twins scope it the same way).
const CONTROL_PLANE_PORT: &str = "443";

/// RFC 1918 plus 169.254/16, which carries mDNS discovery.
const LAN_RANGES: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

/// The inputs the block-all is built from, all read at (re-)arm time so every
/// generation carries the current relay, addresses and preference.
pub(crate) struct BlockAll<'a> {
    /// The relay the tunnel dials (VPN_SERVER_IP). `None` permits no relay.
    pub relay: Option<Ipv4Addr>,
    /// Where our uid's tcp/443 may go: `doh_resolver::control_plane`.
    pub control_plane: &'a [Ipv4Addr],
    /// The effective uid the app runs as.
    pub euid: u32,
    /// Local Network Sharing.
    pub lan_sharing: bool,
}

/// One rule: the arguments that follow `-A <chain>`.
pub(crate) type Rule = Vec<String>;

/// The four chains of one generation, rule by rule, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chains {
    /// IPv4, hooked into OUTPUT.
    pub out_v4: Vec<Rule>,
    /// IPv4, hooked into INPUT and FORWARD.
    pub in_v4: Vec<Rule>,
    /// IPv6, hooked into OUTPUT.
    pub out_v6: Vec<Rule>,
    /// IPv6, hooked into INPUT and FORWARD.
    pub in_v6: Vec<Rule>,
}

fn rule(args: &[&str]) -> Rule {
    args.iter().map(|a| (*a).to_string()).collect()
}

/// The kill switch's block-all for `b`.
pub(crate) fn block_all(b: &BlockAll<'_>) -> Chains {
    // ---------------------------------------------------------------- IPv4 OUT
    let mut out_v4 = vec![
        rule(&["-o", "lo", "-j", "ACCEPT"]),
        // DHCP client -> server, so the machine can keep its lease.
        rule(&["-p", "udp", "--dport", "67", "-j", "ACCEPT"]),
    ];
    // The relay: WireGuard handshake and the stealth fallback.
    if let Some(ip) = b.relay {
        out_v4.push(rule(&["-d", &ip.to_string(), "-j", "ACCEPT"]));
    }
    out_v4.push(rule(&["-o", TUNNEL_INTERFACE, "-j", "ACCEPT"]));
    // LAN PERMIT: honour Local Network Sharing while the block is engaged, so
    // a dropped tunnel does not also take out the printer, the NAS and SSH.
    if b.lan_sharing {
        for cidr in LAN_RANGES {
            out_v4.push(rule(&["-d", cidr, "-j", "ACCEPT"]));
        }
    }
    // SELF-PERMIT: let OUR OWN process reach the control plane.
    //
    // Without it the kill switch makes reconnection impossible:
    // auto_reconnect arms the block and then asks https://api.birdo.app for
    // a fresh config — a different host from the permitted relay — with DoH
    // (tcp/443) for name resolution, because port-53 DNS is blocked too.
    //
    // iptables has no application identity (Windows keys this permit on the
    // executable's ALE app id), so it matches the euid we run as. The client
    // runs as ROOT, so `--uid-owner 0` on its own exempts every root-owned
    // process. bf8af6d4 narrowed it to tcp/443, but to ANY destination: every
    // root daemon, anything run under sudo, could still open HTTPS to any
    // host from the real address through the block. The destination is now
    // each control-plane address, one rule apiece, as macOS's
    // `<birdo_control>` table (pf_policy): the DoH provider the app dials by
    // address and every address a DoH answer gave our own hosts. No ipset and
    // no nftables set — neither is guaranteed on the distros we ship to, and a
    // handful of `-d` rules needs nothing new at runtime.
    //
    // That is narrower than `any`, but it is NOT narrow (P3-2 on macOS):
    // these are shared Cloudflare edge addresses, which serve every
    // Cloudflare-hosted site by SNI, so a root process can most likely still
    // reach other Cloudflare-hosted HTTPS sites through them. Only
    // per-process scoping closes that (a cgroup2 match is the follow-up).
    // With no address there is no permit at all, and the re-dial fails
    // closed rather than falling back to `any`.
    let euid = b.euid.to_string();
    for ip in b.control_plane {
        out_v4.push(rule(&[
            "-d",
            &format!("{ip}/32"),
            "-p",
            "tcp",
            "--dport",
            CONTROL_PLANE_PORT,
            "-m",
            "owner",
            "--uid-owner",
            &euid,
            "-j",
            "ACCEPT",
        ]));
    }
    out_v4.push(rule(&["-j", "DROP"]));

    // ----------------------------------------------------------- IPv4 IN/FWD
    let mut in_v4 = vec![
        rule(&["-i", "lo", "-j", "ACCEPT"]),
        // DHCP server -> client.
        rule(&["-p", "udp", "--dport", "68", "-j", "ACCEPT"]),
    ];
    if let Some(ip) = b.relay {
        in_v4.push(rule(&["-s", &ip.to_string(), "-j", "ACCEPT"]));
    }
    in_v4.push(rule(&["-i", TUNNEL_INTERFACE, "-j", "ACCEPT"]));
    if b.lan_sharing {
        for cidr in LAN_RANGES {
            in_v4.push(rule(&["-s", cidr, "-j", "ACCEPT"]));
        }
    }
    // Replies to traffic permitted outbound (control plane, relay, LAN).
    // INBOUND only: an unscoped ESTABLISHED accept in OUTPUT let plaintext
    // flows opened before the block keep running through it.
    in_v4.push(rule(&[
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED",
        "-j",
        "ACCEPT",
    ]));
    in_v4.push(rule(&["-j", "DROP"]));

    // ---------------------------------------------------------------- IPv6
    // AUDIT-N5: dual-stack hosts must not leak IPv6 around the IPv4-only
    // tunnel. ICMPv6 (NDP / RA / RS) is scoped to link-local and multicast:
    // a blanket `-p ipv6-icmp` accept would sit in front of tunnel_linux's
    // BIRDO_IPV6_LEAK_BLOCK and re-permit ICMPv6 to GLOBAL destinations.
    let mut out_v6 = vec![
        rule(&["-o", "lo", "-j", "ACCEPT"]),
        rule(&["-p", "udp", "--dport", "547", "-j", "ACCEPT"]),
    ];
    for dst in ["fe80::/10", "ff02::/16"] {
        out_v6.push(rule(&["-p", "ipv6-icmp", "-d", dst, "-j", "ACCEPT"]));
    }
    out_v6.push(rule(&["-j", "DROP"]));

    let mut in_v6 = vec![
        rule(&["-i", "lo", "-j", "ACCEPT"]),
        rule(&["-p", "udp", "--dport", "546", "-j", "ACCEPT"]),
    ];
    for src in ["fe80::/10", "ff02::/16"] {
        in_v6.push(rule(&["-p", "ipv6-icmp", "-s", src, "-j", "ACCEPT"]));
    }
    in_v6.push(rule(&["-j", "DROP"]));

    Chains {
        out_v4,
        in_v4,
        out_v6,
        in_v6,
    }
}

/// Whether `rule` is a control-plane self-permit. Its failure to load is
/// tolerated (the block still goes up, only narrower: no control plane), where
/// any other rule's failure abandons the generation.
pub(crate) fn is_self_permit(rule: &[String]) -> bool {
    rule.iter().any(|a| a == "--uid-owner")
}

/// The control-plane generation a generation's self-permits cover (N5 on
/// macOS): what it was built from if every self-permit loaded, else none —
/// so the next DoH answer for our hosts retries the re-arm instead of being
/// cached behind a permit that is not there.
pub(crate) fn covered_generation(control_plane_gen: u64, self_permits_loaded: bool) -> u64 {
    if self_permits_loaded {
        control_plane_gen
    } else {
        0
    }
}

/// Reads a chain the way the kernel would for one OUTBOUND packet: the target
/// of the first matching rule. Interprets exactly the options [`block_all`]
/// writes — and the `-m tcp` / `-m udp` the kernel's `iptables -S` listing
/// adds — and panics on any other, so a new kind of permit must be taught
/// here before a test can pass with it.
#[cfg(test)]
pub(crate) mod check {
    use std::net::IpAddr;

    /// One outbound packet.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Packet<'a> {
        pub proto: &'a str,
        pub dst: IpAddr,
        pub dport: u16,
        pub oif: &'a str,
        pub uid: u32,
    }

    /// The target of the first rule in `chain` that matches `p`, or `None`
    /// if it falls through (which in a hooked chain means ACCEPT by policy).
    pub(crate) fn verdict<'r>(chain: &'r [Vec<String>], p: &Packet<'_>) -> Option<&'r str> {
        chain.iter().find_map(|r| matches(r, p))
    }

    fn matches<'r>(rule: &'r [String], p: &Packet<'_>) -> Option<&'r str> {
        let mut target = None;
        let mut it = rule.iter().map(String::as_str);
        while let Some(opt) = it.next() {
            let mut value = || {
                it.next()
                    .unwrap_or_else(|| panic!("{opt} without a value in {rule:?}"))
            };
            let hit = match opt {
                "-o" => value() == p.oif,
                "-d" => cidr_contains(value(), p.dst),
                "-p" => value() == p.proto,
                "--dport" => value().parse::<u16>().ok() == Some(p.dport),
                "--uid-owner" => value().parse::<u32>().ok() == Some(p.uid),
                // A module load; its options are matched above.
                "-m" => {
                    let module = value();
                    assert!(
                        ["tcp", "udp", "owner", "icmp6"].contains(&module),
                        "unexpected match module {module} in an OUT chain: {rule:?}"
                    );
                    true
                }
                "-j" => {
                    target = Some(value());
                    true
                }
                other => panic!("the checker does not know {other} (in {rule:?})"),
            };
            if !hit {
                return None;
            }
        }
        Some(target.unwrap_or_else(|| panic!("a rule with no target: {rule:?}")))
    }

    /// `cidr` as iptables reads it: `addr/len`, or a bare host address.
    fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
        let (addr, len) = match cidr.split_once('/') {
            Some((a, l)) => (a, Some(l.parse::<u32>().expect("prefix length"))),
            None => (cidr, None),
        };
        match (addr.parse::<IpAddr>().expect("address"), ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let len = len.unwrap_or(32);
                let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let len = len.unwrap_or(128);
                let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    /// The rules of `chain` in an `iptables -S <chain>` listing.
    pub(crate) fn parse_listing(listing: &str, chain: &str) -> Vec<Vec<String>> {
        let prefix = format!("-A {chain} ");
        listing
            .lines()
            .filter_map(|l| l.trim().strip_prefix(&prefix))
            .map(|rest| rest.split_whitespace().map(str::to_string).collect())
            .collect()
    }

    /// Every rule that mentions port 443 or a uid is a control-plane
    /// self-permit: an ACCEPT for tcp to port 443, for `euid`, to exactly one
    /// host address (`/32`) of `control_plane`. Holds for our rule text and for
    /// the kernel's listing of it.
    pub(crate) fn port_443_is_scoped(
        chain: &[Vec<String>],
        control_plane: &[std::net::Ipv4Addr],
        euid: u32,
    ) -> bool {
        let allowed: Vec<String> = control_plane.iter().map(|ip| format!("{ip}/32")).collect();
        let euid = euid.to_string();
        chain
            .iter()
            .filter(|r| r.iter().any(|a| a == "443" || a == "--uid-owner"))
            .all(|r| {
                let after = |opt: &str| {
                    r.iter()
                        .position(|a| a == opt)
                        .and_then(|i| r.get(i + 1))
                        .map(String::as_str)
                };
                after("-d").is_some_and(|d| allowed.iter().any(|a| a == d))
                    && after("-p") == Some("tcp")
                    && after("--dport") == Some("443")
                    && after("--uid-owner") == Some(euid.as_str())
                    && after("-j") == Some("ACCEPT")
                    && !r.iter().any(|a| a == "!")
            })
    }

    /// The destinations of the self-permits in `chain`, in order.
    pub(crate) fn self_permit_destinations(chain: &[Vec<String>]) -> Vec<String> {
        chain
            .iter()
            .filter(|r| super::is_self_permit(r))
            .filter_map(|r| {
                r.iter()
                    .position(|a| a == "-d")
                    .and_then(|i| r.get(i + 1))
                    .cloned()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::check::{port_443_is_scoped, self_permit_destinations, verdict, Packet};
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    const DOH: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const DOH2: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 1);
    const API: Ipv4Addr = Ipv4Addr::new(104, 16, 0, 1);
    const RELAY: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const ROOT: u32 = 0;

    /// Every shape a session can arm: each input on and off, with and
    /// without control-plane addresses, as root and (defensively) not.
    fn every_shape(control_plane: &[Ipv4Addr]) -> Vec<BlockAll<'_>> {
        let mut shapes = Vec::new();
        for relay in [None, Some(RELAY)] {
            for lan_sharing in [false, true] {
                for euid in [ROOT, 1000] {
                    shapes.push(BlockAll {
                        relay,
                        control_plane,
                        euid,
                        lan_sharing,
                    });
                }
            }
        }
        shapes
    }

    const CONTROL_SETS: [&[Ipv4Addr]; 3] = [&[DOH, DOH2, API], &[DOH], &[]];

    fn tcp443(dst: IpAddr, uid: u32) -> Packet<'static> {
        Packet {
            proto: "tcp",
            dst,
            dport: 443,
            oif: "eth0",
            uid,
        }
    }

    // ── the root tcp/443 permit (P3-MAC review of #221) ────────────────

    /// No rule anywhere permits tcp/443 — or anything for a uid — without a
    /// destination, and that destination is a control-plane host address.
    #[test]
    fn no_rule_permits_tcp_443_without_a_control_plane_destination() {
        for control in CONTROL_SETS {
            for shape in every_shape(control) {
                let c = block_all(&shape);
                for chain in [&c.out_v4, &c.in_v4, &c.out_v6, &c.in_v6] {
                    assert!(
                        port_443_is_scoped(chain, control, shape.euid),
                        "an unscoped tcp/443 or uid permit in {chain:?}"
                    );
                }
            }
        }
    }

    /// The self-permits' destinations ARE the control set: one `/32` per
    /// address, in order, none missing and none extra.
    #[test]
    fn the_self_permit_destinations_equal_the_control_set() {
        for control in CONTROL_SETS {
            for shape in every_shape(control) {
                let c = block_all(&shape);
                let want: Vec<String> = control.iter().map(|ip| format!("{ip}/32")).collect();
                assert_eq!(self_permit_destinations(&c.out_v4), want);
                assert_eq!(
                    c.out_v4.iter().filter(|r| is_self_permit(r)).count(),
                    control.len()
                );
            }
        }
    }

    /// No address, no permit: the re-dial fails closed rather than falling
    /// back to "any".
    #[test]
    fn no_control_plane_address_means_no_self_permit_at_all() {
        for shape in every_shape(&[]) {
            let c = block_all(&shape);
            for chain in [&c.out_v4, &c.in_v4, &c.out_v6, &c.in_v6] {
                assert!(!chain.iter().any(|r| is_self_permit(r)), "{chain:?}");
                assert!(!chain.iter().flatten().any(|a| a == "443"), "{chain:?}");
            }
        }
    }

    /// The control plane is IPv4: nothing on IPv6 names a port 443 or a uid.
    #[test]
    fn ipv6_permits_no_control_plane_at_all() {
        for shape in every_shape(&[DOH, API]) {
            let c = block_all(&shape);
            for chain in [&c.out_v6, &c.in_v6] {
                assert!(
                    !chain
                        .iter()
                        .flatten()
                        .any(|a| a == "443" || a == "--uid-owner"),
                    "{chain:?}"
                );
            }
        }
    }

    /// What the OUT chain does with real packets, read like the kernel does.
    #[test]
    fn the_out_chain_lets_our_uid_reach_only_the_control_plane() {
        let github = IpAddr::V4(Ipv4Addr::new(140, 82, 112, 3));
        let github_cdn = IpAddr::V4(Ipv4Addr::new(185, 199, 108, 133));
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        for control in CONTROL_SETS {
            for shape in every_shape(control) {
                let out = block_all(&shape).out_v4;
                let uid = shape.euid;
                for ip in control {
                    let to = IpAddr::V4(*ip);
                    assert_eq!(verdict(&out, &tcp443(to, uid)), Some("ACCEPT"));
                    // Another uid, another transport, another port: no.
                    assert_eq!(verdict(&out, &tcp443(to, uid + 1)), Some("DROP"));
                    let udp = Packet {
                        proto: "udp",
                        ..tcp443(to, uid)
                    };
                    assert_eq!(verdict(&out, &udp), Some("DROP"));
                    let http = Packet {
                        dport: 80,
                        ..tcp443(to, uid)
                    };
                    assert_eq!(verdict(&out, &http), Some("DROP"));
                }
                // Anywhere else on 443 — GitHub's release hosts included
                // (MR-1824) — meets the DROP.
                for to in [github, github_cdn, public] {
                    assert_eq!(verdict(&out, &tcp443(to, uid)), Some("DROP"), "{to}");
                }
                // Plaintext DNS off the tunnel is blocked too.
                let dns = Packet {
                    proto: "udp",
                    dport: 53,
                    ..tcp443(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), uid)
                };
                assert_eq!(verdict(&out, &dns), Some("DROP"));
            }
        }
    }

    /// The other permits are unchanged by the narrowing: the tunnel, the
    /// relay, loopback, DHCP and (only with sharing on) the LAN.
    #[test]
    fn the_tunnel_relay_dhcp_and_lan_permits_are_kept() {
        let printer = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let anywhere = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        for shape in every_shape(&[DOH]) {
            let out = block_all(&shape).out_v4;
            let any_uid = 1234;
            let tunnel = Packet {
                oif: "birdo0",
                ..tcp443(anywhere, any_uid)
            };
            assert_eq!(verdict(&out, &tunnel), Some("ACCEPT"));
            let lo = Packet {
                oif: "lo",
                ..tcp443(anywhere, any_uid)
            };
            assert_eq!(verdict(&out, &lo), Some("ACCEPT"));
            let dhcp = Packet {
                proto: "udp",
                dport: 67,
                ..tcp443(IpAddr::V4(Ipv4Addr::BROADCAST), any_uid)
            };
            assert_eq!(verdict(&out, &dhcp), Some("ACCEPT"));
            let relay = Packet {
                proto: "udp",
                dport: 51820,
                ..tcp443(IpAddr::V4(RELAY), any_uid)
            };
            let want = if shape.relay.is_some() {
                "ACCEPT"
            } else {
                "DROP"
            };
            assert_eq!(verdict(&out, &relay), Some(want));
            let lan = if shape.lan_sharing { "ACCEPT" } else { "DROP" };
            assert_eq!(verdict(&out, &tcp443(printer, any_uid)), Some(lan));
        }
    }

    /// An exhaustive whitelist of the OUT chain, as pf_policy keeps for the
    /// macOS block-all (P3-8): a new permit, or a changed one (a lost `-d`, a
    /// lost uid), fails here rather than slipping through a search for one
    /// bad rule. Every chain ends in its single, unconditional DROP.
    #[test]
    fn every_out_rule_is_whitelisted_and_every_chain_ends_in_drop() {
        for control in CONTROL_SETS {
            for shape in every_shape(control) {
                let c = block_all(&shape);
                let mut want = vec![
                    rule(&["-o", "lo", "-j", "ACCEPT"]),
                    rule(&["-p", "udp", "--dport", "67", "-j", "ACCEPT"]),
                ];
                if let Some(ip) = shape.relay {
                    want.push(rule(&["-d", &ip.to_string(), "-j", "ACCEPT"]));
                }
                want.push(rule(&["-o", "birdo0", "-j", "ACCEPT"]));
                if shape.lan_sharing {
                    for cidr in LAN_RANGES {
                        want.push(rule(&["-d", cidr, "-j", "ACCEPT"]));
                    }
                }
                for ip in control {
                    want.push(rule(&[
                        "-d",
                        &format!("{ip}/32"),
                        "-p",
                        "tcp",
                        "--dport",
                        "443",
                        "-m",
                        "owner",
                        "--uid-owner",
                        &shape.euid.to_string(),
                        "-j",
                        "ACCEPT",
                    ]));
                }
                want.push(rule(&["-j", "DROP"]));
                assert_eq!(c.out_v4, want);

                for chain in [&c.out_v4, &c.in_v4, &c.out_v6, &c.in_v6] {
                    assert_eq!(chain.last(), Some(&rule(&["-j", "DROP"])), "{chain:?}");
                    assert_eq!(
                        chain
                            .iter()
                            .filter(|r| r.contains(&"DROP".to_string()))
                            .count(),
                        1,
                        "{chain:?}"
                    );
                }
            }
        }
    }

    /// IPv6 out: only link-local housekeeping; a global destination on 443
    /// (Cloudflare's own v6 DoH address) meets the DROP.
    #[test]
    fn the_ipv6_out_chain_drops_global_https() {
        let cloudflare_v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
        for shape in every_shape(&[DOH]) {
            let out = block_all(&shape).out_v6;
            assert_eq!(
                verdict(&out, &tcp443(cloudflare_v6, shape.euid)),
                Some("DROP")
            );
        }
    }

    /// A generation records the control-plane generation it permits only if
    /// every self-permit loaded.
    #[test]
    fn a_generation_covers_its_addresses_only_if_every_self_permit_loaded() {
        assert_eq!(covered_generation(7, true), 7);
        assert_eq!(covered_generation(7, false), 0);
    }

    /// The executor writes no permit of its own: every rule it loads comes
    /// from `block_all`, which the tests above hold to the closure.
    #[test]
    fn firewall_linux_writes_no_permit_of_its_own() {
        let src = include_str!("firewall_linux.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        for literal in ["\"--uid-owner\"", "\"443\"", "\"ACCEPT\"", "\"owner\""] {
            assert!(
                !code.contains(literal),
                "firewall_linux.rs builds a rule itself ({literal}); build it in iptables_policy"
            );
        }
        assert!(code.contains("iptables_policy::block_all("));
    }

    /// The checker reads the kernel's listing the same way as our text.
    #[test]
    fn the_checker_reads_an_iptables_listing() {
        let listing = "-N BIRDO_KS_OUT1\n\
                       -A BIRDO_KS_OUT1 -o lo -j ACCEPT\n\
                       -A BIRDO_KS_OUT1 -d 1.1.1.1/32 -p tcp -m tcp --dport 443 -m owner --uid-owner 0 -j ACCEPT\n\
                       -A BIRDO_KS_OUT1 -j DROP\n";
        let chain = super::check::parse_listing(listing, "BIRDO_KS_OUT1");
        assert_eq!(chain.len(), 3);
        assert!(port_443_is_scoped(&chain, &[DOH], ROOT));
        assert!(!port_443_is_scoped(&chain, &[API], ROOT));
        assert_eq!(
            verdict(&chain, &tcp443(IpAddr::V4(DOH), ROOT)),
            Some("ACCEPT")
        );
        assert_eq!(
            verdict(&chain, &tcp443(IpAddr::V4(API), ROOT)),
            Some("DROP")
        );

        // The pre-fix rule — tcp/443 for root to anywhere — is caught.
        let unscoped = super::check::parse_listing(
            "-A X -p tcp -m tcp --dport 443 -m owner --uid-owner 0 -j ACCEPT\n-A X -j DROP",
            "X",
        );
        assert!(!port_443_is_scoped(&unscoped, &[DOH], ROOT));
        assert_eq!(
            verdict(&unscoped, &tcp443(IpAddr::V4(API), ROOT)),
            Some("ACCEPT")
        );
    }
}
