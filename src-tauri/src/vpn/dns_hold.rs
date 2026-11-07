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
//! firewall instead. DNS only, by owner decision (2026-11-07): other IPv4
//! keeps going out directly in the gap with the kill switch off, a known
//! difference from Windows.

use std::net::{IpAddr, SocketAddr};

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
}

impl DnsHoldExempt {
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
}
