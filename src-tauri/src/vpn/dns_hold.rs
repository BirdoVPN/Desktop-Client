//! MR-2135: what a server switch's DNS hold holds, and what it lets through,
//! shared by the Linux hold (an iptables mangle chain, `tunnel_linux.rs`) and
//! the macOS one (rules in pf's main ruleset, `pf_policy.rs`).
//!
//! With the kill switch off, a switch used to let DNS out on the physical
//! link for the whole gap between the outgoing tunnel's stop() (which puts
//! the original resolvers back) and the incoming tunnel's start() (which
//! configures its own only after the device is up and the handshake done).
//! Windows holds its DNS guard across that gap
//! (`win_machine_state::begin_transition`); the Unix twins hold DNS in the
//! firewall instead.
//!
//! MR-2255: and the rest of IPv4 with it. The owner deferred this on
//! 2026-11-07 (DNS only) and reversed that on 2026-11-18. Windows keeps its
//! /1 routes into the tunnel adapter through the gap, so nothing routable
//! leaves the physical NIC there; Linux and macOS lose their tunnel routes
//! with the outgoing device, so with the kill switch off every new IPv4 flow
//! in the gap went out directly, from the real address. The hold now lets out
//! only what the kill switch's block-all lets out ([`Ipv4Hold`]): loopback,
//! the tunnel, DHCP, the LAN with Local Network Sharing, the app's own
//! control-plane HTTPS and the incoming relay. IPv6 is the leak block's,
//! held across the switch since MR-782.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Plain DNS (53), DNS-over-TLS (TCP 853) and DNS-over-QUIC (UDP 853), each
/// over TCP and UDP: what Windows' DNS guard blocks (wfp_policy.rs DNS_PORTS).
/// DNS-over-HTTPS on 443 cannot be told apart from any other HTTPS, here or
/// on Windows, and the app's own DoH must keep working.
pub(crate) const DNS_HOLD_PORTS: [&str; 2] = ["53", "853"];

/// NetBIOS name service (137), mDNS (5353) and LLMNR (5355): held as well
/// unless Local Network Sharing is on, as Windows does (LAN_NAME_PORTS).
pub(crate) const DNS_HOLD_LAN_NAME_PORTS: [&str; 3] = ["137", "5353", "5355"];

/// What the hold lets through, from the incoming session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DnsHoldExempt {
    /// The incoming relay: a relay on a DNS port must still get its handshake
    /// (Windows permits the tunnel's own flow on a DNS port the same way).
    /// `None` for a hostname endpoint, which is resolved later, over DoH.
    pub(crate) relay: Option<IpAddr>,
    /// The user's own resolvers on the local network (a Pi-hole), with Local
    /// Network Sharing on only, as Windows' `split_resolvers`.
    pub(crate) lan_resolvers: Vec<IpAddr>,
    pub(crate) local_network_sharing: bool,
    /// MR-2255: hold the rest of IPv4 too, and what that lets out. `None`:
    /// DNS only ([`with_ipv4_hold`](Self::with_ipv4_hold) says when).
    pub(crate) ipv4: Option<Ipv4Hold>,
}

/// MR-2255: what the IPv4 hold lets out besides loopback, the tunnel's own
/// interface, DHCP and (with Local Network Sharing on) the LAN ranges: the
/// kill switch's block-all permits, for the incoming session. Everything else
/// over IPv4 is dropped from before the outgoing tunnel's stop() until the
/// incoming tunnel's build is over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv4Hold {
    /// The incoming relay, both directions of its handshake and the stealth
    /// transport. `None` for an IPv6 relay, which IPv4 does not reach.
    pub(crate) relay: Option<Ipv4Addr>,
    /// Where the app's own tcp/443 may go: `doh_resolver::control_plane`, as
    /// the block-all's self-permit. Empty: no such permit, as there.
    pub(crate) control_plane: Vec<Ipv4Addr>,
    /// The euid that self-permit matches (the app's, root).
    pub(crate) euid: u32,
}

impl DnsHoldExempt {
    /// MR-2255: hold the rest of IPv4 as well, letting out what [`Ipv4Hold`]
    /// lists, when the incoming relay's address is known. A hostname endpoint
    /// keeps the DNS-only hold: the address it resolves to (over DoH, during
    /// the new start()) is not known here, and holding IPv4 would drop the
    /// handshake to it. The backend sends an address (`${node.ip}:${port}`),
    /// so that is the exception.
    pub(crate) fn with_ipv4_hold(mut self, control_plane: Vec<Ipv4Addr>, euid: u32) -> Self {
        self.ipv4 = self.relay.map(|relay| Ipv4Hold {
            relay: match relay {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            },
            control_plane,
            euid,
        });
        self
    }

    /// The same hold without its IPv4 half: what a platform falls back to
    /// when the firewall refuses the full one, so a refused IPv4 hold never
    /// costs the switch its DNS hold.
    pub(crate) fn dns_only(&self) -> Self {
        Self {
            ipv4: None,
            ..self.clone()
        }
    }

    /// Every address the hold lets through: the relay, then the LAN
    /// resolvers.
    pub(crate) fn addresses(&self) -> impl Iterator<Item = &IpAddr> {
        self.relay.iter().chain(&self.lan_resolvers)
    }

    /// The destination ports the hold drops: DNS always, and the LAN name
    /// ports unless Local Network Sharing is on.
    pub(crate) fn held_ports(&self) -> Vec<&'static str> {
        let lan_name_ports: &[&'static str] = if self.local_network_sharing {
            &[]
        } else {
            &DNS_HOLD_LAN_NAME_PORTS
        };
        DNS_HOLD_PORTS
            .iter()
            .chain(lan_name_ports)
            .copied()
            .collect()
    }
}

/// An address on the local network: private, link-local or unique-local.
fn is_lan_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// What the hold for a switch onto a session at `endpoint`, with resolvers
/// `dns`, lets through (the incoming `VpnConfig`'s two fields).
pub(crate) fn dns_hold_exempt(
    endpoint: &str,
    dns: &[String],
    local_network_sharing: bool,
) -> DnsHoldExempt {
    let relay = endpoint.parse::<SocketAddr>().ok().map(|a| a.ip());
    let lan_resolvers = if local_network_sharing {
        dns.iter()
            .filter_map(|d| d.parse::<IpAddr>().ok())
            .filter(is_lan_address)
            .collect()
    } else {
        Vec::new()
    };
    DnsHoldExempt {
        relay,
        lan_resolvers,
        local_network_sharing,
        ipv4: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exemptions_come_from_the_incoming_session() {
        let dns = vec![
            "192.168.1.2".to_string(),
            "fe80::1".to_string(),
            "1.1.1.1".to_string(),
        ];
        let on = dns_hold_exempt("203.0.113.9:51820", &dns, true);
        assert_eq!(on.relay, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(
            on.lan_resolvers,
            vec![
                "192.168.1.2".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
        let off = dns_hold_exempt("203.0.113.9:51820", &dns, false);
        assert!(
            off.lan_resolvers.is_empty(),
            "LAN resolvers with sharing off"
        );
        let hostname = dns_hold_exempt("relay.example.net:51820", &dns, false);
        assert_eq!(
            hostname.relay, None,
            "a hostname is resolved later, over DoH"
        );
        let v6 = dns_hold_exempt("[2001:db8::7]:51820", &dns, false);
        assert_eq!(v6.relay, Some("2001:db8::7".parse().unwrap()));
    }

    #[test]
    fn the_relay_comes_first_then_the_lan_resolvers() {
        let dns = vec!["10.0.0.53".to_string()];
        let exempt = dns_hold_exempt("203.0.113.9:53", &dns, true);
        let all: Vec<String> = exempt.addresses().map(IpAddr::to_string).collect();
        assert_eq!(all, vec!["203.0.113.9", "10.0.0.53"]);
        assert_eq!(
            DnsHoldExempt::default().addresses().count(),
            0,
            "nothing exempt"
        );
    }

    /// As Windows: the LAN name ports are held only with Local Network
    /// Sharing off; DNS proper is held either way.
    #[test]
    fn the_lan_name_ports_are_held_only_with_sharing_off() {
        let off = dns_hold_exempt("203.0.113.9:51820", &[], false);
        assert_eq!(off.held_ports(), vec!["53", "853", "137", "5353", "5355"]);
        let on = dns_hold_exempt("203.0.113.9:51820", &[], true);
        assert_eq!(on.held_ports(), vec!["53", "853"]);
    }

    const DOH: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    /// MR-2255: an address relay holds IPv4 too, with the relay, the
    /// control plane and the euid the permits need. A hostname relay keeps
    /// the DNS-only hold: its address is not known when the hold goes up.
    #[test]
    fn ipv4_is_held_whenever_the_relays_address_is_known() {
        let v4 = dns_hold_exempt("203.0.113.9:51820", &[], false).with_ipv4_hold(vec![DOH], 0);
        assert_eq!(
            v4.ipv4,
            Some(Ipv4Hold {
                relay: Some(Ipv4Addr::new(203, 0, 113, 9)),
                control_plane: vec![DOH],
                euid: 0,
            })
        );
        let v6 = dns_hold_exempt("[2001:db8::7]:51820", &[], false).with_ipv4_hold(vec![DOH], 0);
        assert_eq!(
            v6.ipv4.as_ref().map(|h| h.relay),
            Some(None),
            "an IPv6 relay: IPv4 held, with no relay to let through on it"
        );
        let hostname =
            dns_hold_exempt("relay.example.net:51820", &[], false).with_ipv4_hold(vec![DOH], 0);
        assert_eq!(hostname.ipv4, None, "a hostname relay holds DNS only");
        assert_eq!(
            dns_hold_exempt("203.0.113.9:51820", &[], false).ipv4,
            None,
            "nothing holds IPv4 unless asked"
        );
    }

    /// The fallback a platform loads when its firewall refuses the full
    /// hold: the same DNS hold, nothing of IPv4.
    #[test]
    fn the_dns_only_fallback_keeps_everything_but_the_ipv4_half() {
        let dns = vec!["192.168.1.2".to_string()];
        let full = dns_hold_exempt("203.0.113.9:51820", &dns, true).with_ipv4_hold(vec![DOH], 0);
        let dns_only = full.dns_only();
        assert_eq!(dns_only.ipv4, None);
        assert_eq!(
            dns_only,
            DnsHoldExempt {
                ipv4: None,
                ..full.clone()
            }
        );
        assert_eq!(dns_only.held_ports(), full.held_ports());
        assert!(dns_only.addresses().eq(full.addresses()));
    }
}
