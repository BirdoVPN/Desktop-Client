//! VPN tunnel module
//!
//! WireGuard tunnel management using platform-specific virtual adapters:
//! - Windows: Wintun virtual network adapter
//! - macOS: utun kernel interface

pub mod auto_reconnect;
pub mod birdo_pq; // AUDIT-C1: BirdoPQ v1 ML-KEM-1024 PSK derivation (mirror of Android RosenpassManager)
pub mod buffer_pool; // FIX-2-4: Reduced to packet size constants only
pub mod doh; // DNS-over-HTTPS resolver for SEC-002
pub mod manager;
pub mod network_monitor; // P2-15: System network connectivity monitor
pub mod speed_test; // On-device speed test (P3-26)
pub mod xray; // Xray Reality stealth tunnel (matching Android XrayManager)

// Platform-specific tunnel implementations
#[cfg(target_os = "windows")]
pub mod tunnel;
#[cfg(target_os = "linux")]
pub mod tunnel_linux;
#[cfg(target_os = "macos")]
pub mod tunnel_macos;

#[cfg(target_os = "windows")]
mod tunnel_dns; // DNS helpers extracted from tunnel.rs (Windows-specific netsh/powershell)
                // Removed: pub mod wireguard; - deprecated file with placeholder crypto
mod wireguard_new;

// Windows Filtering Platform for kill switch
#[cfg(target_os = "windows")]
pub mod wfp;

// Linux iptables firewall for kill switch
#[cfg(target_os = "linux")]
pub mod firewall_linux;

// Re-export the new boringtun-based implementation
pub use manager::VpnManager;
#[allow(unused_imports)]
pub use wireguard_new::WireGuardSession;

// Re-export DoH resolver (available for future use)
#[allow(unused_imports)]
pub use doh::resolve_via_doh;

// Public API for auto-reconnect (may be used by external consumers)
#[allow(unused_imports)]
pub use auto_reconnect::{AutoReconnectConfig, AutoReconnectService, AutoReconnectStatus};

// Unit tests for auto-reconnect, kill switch, tunnel health
#[cfg(test)]
mod tests;

// ──────────────────────────────────────────────────────────────
// P1-dk-allowedips-no-default-coverage: server-supplied tunnel scope
// ──────────────────────────────────────────────────────────────

/// Refuse a server-supplied tunnel scope that leaves part of the address
/// space OUTSIDE the tunnel.
///
/// The connect response's `allowed_ips` become the routes the client installs
/// verbatim; everything they do not cover keeps flowing over the physical NIC
/// with the user's real IP while the UI reports Connected. A compromised
/// backend, a stolen API credential, or a forged connect response could
/// therefore silently de-anonymise users by shrinking the scope. The backend
/// has exactly one legitimate shape — full coverage (`0.0.0.0/0` + `::/0`,
/// possibly pre-split into /1 halves) — and the desktop has NO route-based
/// split-tunnel mode (the "split tunneling" setting is app-based kill-switch
/// exemptions; routed traffic still goes through the tunnel, see settings.rs
/// and wfp.rs), so anything less than full IPv4 unicast coverage fails the
/// connect instead of connecting partial. The IPv6 set gets the same
/// requirement whenever the config asks the client to ROUTE IPv6
/// (`client_ipv6` present) rather than block it — a partial v6 set with a v6
/// address assigned would leak the uncovered space. DNS containment in the
/// routed scope is checked explicitly, so the validator stays correct if a
/// real route-based split mode ever lands.
pub fn validate_tunnel_scope(config: &crate::api::types::VpnConfig) -> Result<(), String> {
    let mut v4_ranges: Vec<(u128, u128)> = Vec::with_capacity(config.allowed_ips.len());
    for cidr in &config.allowed_ips {
        let (net, prefix) = parse_ipv4_cidr(cidr)
            .ok_or_else(|| format!("Invalid IPv4 CIDR in allowed_ips: '{}'", cidr))?;
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let start = net & mask;
        let last = start | !mask;
        v4_ranges.push((start as u128, last as u128));
    }
    if !ranges_cover(v4_ranges.clone(), u32::MAX as u128) {
        return Err(format!(
            "Server-supplied allowed_ips {:?} do not cover the full IPv4 space — refusing a partial tunnel that would leak traffic outside the VPN",
            config.allowed_ips
        ));
    }

    let mut v6_ranges: Vec<(u128, u128)> = Vec::with_capacity(config.allowed_ips_v6.len());
    for cidr in &config.allowed_ips_v6 {
        let (net, prefix) = parse_ipv6_cidr(cidr)
            .ok_or_else(|| format!("Invalid IPv6 CIDR in allowed_ips: '{}'", cidr))?;
        let mask: u128 = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        let start = net & mask;
        let last = start | !mask;
        v6_ranges.push((start, last));
    }
    if config.client_ipv6.is_some() && !ranges_cover(v6_ranges.clone(), u128::MAX) {
        return Err(format!(
            "Server-supplied IPv6 allowed_ips {:?} do not cover the full IPv6 space while the config assigns a tunnel IPv6 address — refusing a partial dual-stack tunnel",
            config.allowed_ips_v6
        ));
    }

    // Every resolver must sit inside the routed scope, or DNS queries would
    // egress in the clear. (IPv6 resolvers are only checked when the config
    // routes IPv6; with IPv6 blocked they are unreachable, which fails
    // closed, not open.)
    for dns in &config.dns {
        match dns.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                if !ip_in_ranges(u32::from(ip) as u128, &v4_ranges) {
                    return Err(format!(
                        "DNS server {} is outside the tunnel's routed prefixes",
                        dns
                    ));
                }
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                if config.client_ipv6.is_some() && !ip_in_ranges(u128::from(ip), &v6_ranges) {
                    return Err(format!(
                        "DNS server {} is outside the tunnel's routed IPv6 prefixes",
                        dns
                    ));
                }
            }
            Err(_) => return Err(format!("Invalid DNS address: '{}'", dns)),
        }
    }

    Ok(())
}

fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u8)> {
    let (net, plen) = cidr.split_once('/')?;
    let net: std::net::Ipv4Addr = net.parse().ok()?;
    let plen: u8 = plen.parse().ok()?;
    if plen > 32 {
        return None;
    }
    Some((u32::from(net), plen))
}

fn parse_ipv6_cidr(cidr: &str) -> Option<(u128, u8)> {
    let (net, plen) = cidr.split_once('/')?;
    let net: std::net::Ipv6Addr = net.parse().ok()?;
    let plen: u8 = plen.parse().ok()?;
    if plen > 128 {
        return None;
    }
    Some((u128::from(net), plen))
}

/// Do the inclusive `(start, last)` ranges, unioned, cover `0..=full_last`?
fn ranges_cover(mut ranges: Vec<(u128, u128)>, full_last: u128) -> bool {
    if ranges.is_empty() {
        return false;
    }
    ranges.sort_unstable();
    let mut covered_to: Option<u128> = None; // contiguous inclusive cover from 0
    for (start, last) in ranges {
        match covered_to {
            None => {
                if start != 0 {
                    return false;
                }
                covered_to = Some(last);
            }
            Some(c) => {
                if c >= full_last {
                    return true;
                }
                if start > c + 1 {
                    return false;
                }
                if last > c {
                    covered_to = Some(last);
                }
            }
        }
    }
    covered_to.is_some_and(|c| c >= full_last)
}

fn ip_in_ranges(ip: u128, ranges: &[(u128, u128)]) -> bool {
    ranges
        .iter()
        .any(|(start, last)| ip >= *start && ip <= *last)
}

#[cfg(test)]
mod scope_tests {
    use super::validate_tunnel_scope;
    use crate::api::types::VpnConfig;

    fn config(
        allowed_ips: &[&str],
        allowed_ips_v6: &[&str],
        client_ipv6: Option<&str>,
    ) -> VpnConfig {
        VpnConfig {
            server_id: "test".into(),
            key_id: "k".into(),
            private_key: String::new(),
            public_key: String::new(),
            server_public_key: String::new(),
            preshared_key: None,
            endpoint: "203.0.113.1:51820".into(),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
            dns: vec!["10.8.0.1".into()],
            client_ip: "10.8.0.2".into(),
            client_ipv6: client_ipv6.map(|s| s.to_string()),
            allowed_ips_v6: allowed_ips_v6.iter().map(|s| s.to_string()).collect(),
            mtu: 1420,
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn accepts_full_default_route() {
        assert!(validate_tunnel_scope(&config(&["0.0.0.0/0"], &[], None)).is_ok());
    }

    #[test]
    fn accepts_pre_split_half_pair() {
        assert!(validate_tunnel_scope(&config(&["0.0.0.0/1", "128.0.0.0/1"], &[], None)).is_ok());
    }

    #[test]
    fn accepts_any_union_covering_all() {
        assert!(validate_tunnel_scope(&config(
            &["128.0.0.0/2", "0.0.0.0/1", "192.0.0.0/2"],
            &[],
            None
        ))
        .is_ok());
    }

    #[test]
    fn rejects_shrunk_scope() {
        // The hostile-backend shape: only RFC1918 routed, everything else
        // egresses in the clear while the UI says Connected.
        assert!(validate_tunnel_scope(&config(&["10.0.0.0/8"], &[], None)).is_err());
    }

    #[test]
    fn rejects_almost_full_scope() {
        assert!(validate_tunnel_scope(&config(&["0.0.0.0/1"], &[], None)).is_err());
    }

    #[test]
    fn rejects_partial_v6_when_routing_v6() {
        assert!(
            validate_tunnel_scope(&config(&["0.0.0.0/0"], &["2000::/3"], Some("fd00::2/128")))
                .is_err()
        );
    }

    #[test]
    fn accepts_full_dual_stack() {
        assert!(
            validate_tunnel_scope(&config(&["0.0.0.0/0"], &["::/0"], Some("fd00::2/128"))).is_ok()
        );
    }

    #[test]
    fn ignores_v6_scope_when_v6_is_blocked() {
        // No client_ipv6 => the client BLOCKS IPv6 instead of routing it, so a
        // partial (or absent) v6 set is fail-closed, not a leak.
        assert!(validate_tunnel_scope(&config(&["0.0.0.0/0"], &[], None)).is_ok());
    }

    #[test]
    fn rejects_dns_outside_scope_shape() {
        let mut c = config(&["0.0.0.0/0"], &[], None);
        c.dns = vec!["not-an-ip".into()];
        assert!(validate_tunnel_scope(&c).is_err());
    }
}
