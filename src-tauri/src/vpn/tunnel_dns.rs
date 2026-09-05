//! DNS reads for the Windows tunnel.
//!
//! One job: turn `netsh interface <family> show dns <adapter>` into an origin,
//! or into an ERROR. Enumeration, parking, un-parking and the durable record all
//! live in `win_machine_state`, which owns them across tunnel lifetimes.

use std::process::Command;

/// Hidden command helper
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// Read one address family's DNS origin for an adapter.
///
/// `family` is the netsh read context: `"ipv4"` or `"ipv6"`. Returns
/// `(was_dhcp, statically_configured_servers)`.
///
/// A FAILED READ IS AN ERROR, NOT A CONFIGURATION. This function used to be a
/// pair of helpers that matched only `Ok(output) => output` and never looked at
/// `status.success()`. A netsh that runs and fails prints nothing, and
/// `parse_dns_config_v4("")` yields exactly `(false, [])` — indistinguishable
/// from a genuinely static-with-no-servers adapter, which is the one shape the
/// un-park deliberately refuses to act on. So the process manufactured its own
/// unrecoverable record, with no failure visible anywhere (issue #102). The
/// caller must now decide what to do about a failure, and its decision is: never
/// mutate what you could not read.
///
/// Empty output is treated as a failure for the same reason: netsh always prints
/// at least a `Configuration for interface ...` header for an adapter it can
/// address, so nothing at all means we did not read the adapter.
pub(super) fn read_dns_family(
    adapter_name: &str,
    family: &str,
) -> Result<(bool, Vec<String>), String> {
    let output = cmd("netsh")
        .args(["interface", family, "show", "dns", adapter_name])
        .output()
        .map_err(|e| {
            format!(
                "netsh interface {} show dns could not run for '{}': {}",
                family, adapter_name, e
            )
        })?;

    if !output.status.success() {
        return Err(format!(
            "netsh interface {} show dns '{}' exited {:?}: {}",
            family,
            adapter_name,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Err(format!(
            "netsh interface {} show dns '{}' printed nothing",
            family, adapter_name
        ));
    }

    Ok(if family.eq_ignore_ascii_case("ipv6") {
        parse_dns_config_v6(&stdout)
    } else {
        parse_dns_config_v4(&stdout)
    })
}

/// Extract the STATICALLY configured resolvers from `netsh interface <family>
/// show dns <adapter>`.
///
/// ONE implementation, two thin wrappers. The v4 and v6 scans were separate
/// functions and immediately drifted: the v6 copy required a label line to hold
/// no address, but netsh puts the FIRST server on the label line, so `capturing`
/// never flipped and it returned an empty list for every input on earth. That is
/// the estate's recurring bug shape — a fix applied to one of two parallel paths
/// — so the paths are now the same path.
///
/// WHY ANY OF THIS. netsh reports DHCP-leased and statically configured
/// resolvers under the same command, and they need opposite treatment on
/// restore. `dns_servers` is documented as "empty = was DHCP" (see
/// `AdapterDnsSnapshot` in tunnel.rs), and restore feeds a NON-empty list
/// straight into `netsh set dns ... static <ip>`. So capturing a DHCP-leased
/// address PINS the adapter to that network:
///
///     Configuration for interface "WiFi 3"
///         DNS servers configured through DHCP:  194.168.4.100
///                                               194.168.8.100
///         Register with which suffix:           Primary only
///
/// Connect once at home, disconnect, and Wi-Fi is statically set to the home
/// router. Move to another network and name resolution stops, with no VPN
/// running to blame.
///
/// HOW THE STATE MACHINE WORKS. Continuation lines carry no marker, so the scan
/// is anchored on the label line. A label is identified by stripping address
/// tokens first and asking whether ':' survives — necessary for IPv6, where a
/// bare continuation address is full of colons. Capture starts only on a label
/// that names DNS servers and does NOT mention DHCP; any other label (notably
/// `Register with which suffix:`) ends the region rather than leaving it open.
/// "DNS" and "DHCP" are acronyms and survive netsh localisation, which matching
/// the English "Statically Configured DNS Servers" would not.
///
/// A parseable address is still required per token, because these values are fed
/// back verbatim into `netsh set/add dns static <ip>`. Annotations such as
/// "1.1.1.1 (Preferred)" are handled naturally: the address parses, the
/// annotation does not.
/// Returns `(was_dhcp, statically_configured_servers)`.
///
/// `was_dhcp` is NOT `servers.is_empty()`. An adapter can be sourced `static`
/// and hold no servers at all — measured on a stock Windows 11 box with no VPN
/// running, VirtualBox Host-Only, the Hyper-V/WSL vSwitch and the OpenVPN TAP
/// adapter were ALL `Statically Configured DNS Servers: None`, two of them Up.
/// Treating that as DHCP makes disconnect rewrite other products' network
/// configuration. See `DnsOrigin`.
fn parse_dns_config(stdout: &str, parse_token: fn(&str) -> Option<String>) -> (bool, Vec<String>) {
    let mut servers = Vec::new();
    let mut capturing = false;
    let mut saw_dhcp_label = false;
    for line in stdout.lines() {
        let label_part: String = line
            .split_whitespace()
            .filter(|t| parse_token(t).is_none())
            .collect::<Vec<_>>()
            .join(" ");
        if label_part.contains(':') {
            let up = label_part.to_ascii_uppercase();
            let dns_label = up.contains("DNS");
            let dhcp_label = up.contains("DHCP");
            if dns_label && dhcp_label {
                saw_dhcp_label = true;
            }
            capturing = dns_label && !dhcp_label;
        }
        if !capturing {
            continue;
        }
        if let Some(ip) = line.split_whitespace().find_map(parse_token) {
            servers.push(ip);
        }
    }
    (saw_dhcp_label, servers)
}

fn v4_token(token: &str) -> Option<String> {
    token
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|_| token.to_string())
}

/// `%zone` is kept on the returned string (netsh accepts and needs it) but
/// stripped before parsing.
fn v6_token(token: &str) -> Option<String> {
    let bare = token.split('%').next()?;
    bare.parse::<std::net::Ipv6Addr>()
        .ok()
        .map(|_| token.to_string())
}

pub(super) fn parse_dns_config_v4(stdout: &str) -> (bool, Vec<String>) {
    parse_dns_config(stdout, v4_token)
}

pub(super) fn parse_dns_config_v6(stdout: &str) -> (bool, Vec<String>) {
    parse_dns_config(stdout, v6_token)
}

#[cfg(test)]
mod dns_parse_tests {
    use super::{parse_dns_config_v4, parse_dns_config_v6};

    // Captured verbatim from `netsh interface ipv4 show dns name="WiFi 3"` on a
    // real Windows 11 machine, 2026-08-27. This is the case the previous parser
    // got wrong.
    const DHCP_TWO_SERVERS: &str = r#"
Configuration for interface "WiFi 3"
    DNS servers configured through DHCP:  194.168.4.100
                                          194.168.8.100
    Register with which suffix:           Primary only
"#;

    // Captured verbatim from the same machine, `name="Ethernet 2"`.
    const STATIC_NONE: &str = r#"
Configuration for interface "Ethernet 2"
    Statically Configured DNS Servers:    None
    Register with which suffix:           Primary only
"#;

    const STATIC_TWO_SERVERS: &str = r#"
Configuration for interface "Ethernet 2"
    Statically Configured DNS Servers:    1.1.1.1
                                          8.8.8.8
    Register with which suffix:           Primary only
"#;

    // Captured from `netsh interface ipv4 show dns` on a stock Windows 11 box
    // with NO VPN running. VirtualBox Host-Only and the Hyper-V/WSL vSwitch were
    // both Up and both static-with-no-servers, so the enumeration returns them
    // and the old "empty means DHCP" rule reconfigured them on disconnect.
    const STATIC_NONE_VIRTUAL: &str = r#"
Configuration for interface "Ethernet 2"
    Statically Configured DNS Servers:    None
    Register with which suffix:           Primary only
"#;

    #[test]
    fn static_with_no_servers_is_not_reported_as_dhcp() {
        // THE BUG: `servers.is_empty()` was used as "was DHCP". It is not.
        // Getting this wrong makes disconnect run `netsh set dns ... dhcp` on
        // VirtualBox's and Hyper-V's adapters.
        let (was_dhcp, servers) = parse_dns_config_v4(STATIC_NONE_VIRTUAL);
        assert!(servers.is_empty(), "no static servers are configured");
        assert!(!was_dhcp, "static-with-none must NOT be reported as DHCP");
    }

    #[test]
    fn dhcp_sourced_adapter_is_reported_as_dhcp() {
        let (was_dhcp, servers) = parse_dns_config_v4(DHCP_TWO_SERVERS);
        assert!(
            servers.is_empty(),
            "DHCP-leased servers are not ours to restore"
        );
        assert!(
            was_dhcp,
            "must be recognised as DHCP so restore hands it back"
        );
    }

    #[test]
    fn static_with_servers_is_not_dhcp() {
        let (was_dhcp, servers) = parse_dns_config_v4(STATIC_TWO_SERVERS);
        assert_eq!(servers, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
        assert!(!was_dhcp);
    }

    #[test]
    fn dhcp_leased_servers_are_not_captured() {
        // The regression this guards: capturing these turned a DHCP adapter into
        // a statically pinned one on disconnect.
        assert!(parse_dns_config_v4(DHCP_TWO_SERVERS).1.is_empty());
    }

    #[test]
    fn static_servers_are_captured_in_order_including_the_first() {
        // The first server sits on the LABEL line, which an earlier parser that
        // required the line to start with a digit silently dropped.
        assert_eq!(
            parse_dns_config_v4(STATIC_TWO_SERVERS).1,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }

    #[test]
    fn static_none_is_empty() {
        assert!(parse_dns_config_v4(STATIC_NONE).1.is_empty());
    }

    #[test]
    fn annotations_do_not_break_capture() {
        let s = "    Statically Configured DNS Servers:    1.1.1.1 (Preferred)
";
        assert_eq!(parse_dns_config_v4(s).1, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn v6_dhcp_leased_servers_are_not_captured() {
        let s = "Configuration for interface \"WiFi 3\"
                     DNS servers configured through DHCP:  2001:4860:4860::8888
                                                           2001:4860:4860::8844
";
        assert!(parse_dns_config_v6(s).1.is_empty());
    }

    #[test]
    fn a_second_label_ends_the_capture_region() {
        // "Register with which suffix:" contains ':' and no "DHCP". An earlier
        // version keyed only on the absence of "DHCP", so this line flipped
        // capture back ON at the end of a DHCP block and swallowed anything
        // after it.
        let s = "    DNS servers configured through DHCP:  192.168.1.1
    \r
                 Register with which suffix:           Primary only
    \r
                                                       9.9.9.9
";
        assert!(parse_dns_config_v4(s).1.is_empty());
    }

    #[test]
    fn v6_label_line_carrying_the_first_server_is_still_a_label() {
        // REGRESSION GUARD. The v6 scan used to require a label line to contain
        // no address — but netsh puts the FIRST server on the label line, so the
        // guard never matched, `capturing` never became true, and the function
        // returned an empty list for EVERY input. It silently stopped restoring
        // IPv6 resolvers entirely.
        let one = "    Statically Configured DNS Servers:    2606:4700:4700::1111
";
        assert_eq!(
            parse_dns_config_v6(one).1,
            vec!["2606:4700:4700::1111".to_string()]
        );
    }

    #[test]
    fn v6_static_servers_are_captured_including_continuations() {
        // Continuation lines are bare IPv6 addresses, which contain ':' — the
        // reason the v6 label test cannot be the v4 one verbatim.
        let s = "    Statically Configured DNS Servers:    2606:4700:4700::1111
                                                               2606:4700:4700::1001
";
        assert_eq!(
            parse_dns_config_v6(s).1,
            vec![
                "2606:4700:4700::1111".to_string(),
                "2606:4700:4700::1001".to_string()
            ]
        );
    }
}
