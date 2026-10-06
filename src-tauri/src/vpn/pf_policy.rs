//! What the macOS kill switch's pf ruleset contains, as a plain function.
//!
//! `commands/killswitch.rs` owns pf's MAIN ruleset on macOS and runs `pfctl`.
//! Everything that decides WHAT that ruleset permits lives here instead, free
//! of `pfctl`, so it is unit-tested on every OS (the Windows job runs these
//! tests) rather than only on a Mac nobody on the team has. The macOS CI
//! runner then feeds every ruleset shape to `pfctl -nv` (`pfctl_parse_tests`,
//! run by tests.yml's pf parse-check step), which is the part a Windows box
//! cannot check.
//!
//! # What the block-all permits
//!
//! | rule                                     | why                               |
//! |------------------------------------------|-----------------------------------|
//! | `lo0`                                    | local IPC, the stealth helper     |
//! | `utun0`..`utun15`                        | traffic already inside the VPN    |
//! | DHCP, both directions                    | the LAN lease outlives the block  |
//! | the LAN ranges, with Local Network Sharing | printers, NAS, AirPlay          |
//! | root's tcp/443 to `<birdo_control>`      | the control plane: API and DoH    |
//! | the relay, both directions               | the re-dial                       |
//!
//! Everything else, IPv6 included, meets `block drop all`.

use std::net::Ipv4Addr;

/// Marker anchor in EVERY ruleset we load (this block-all and the IPv6 leak
/// block in `resources/pf/`). Declaring an empty anchor is a no-op for packet
/// processing but shows up in `pfctl -s rules`, which is how
/// `reconcile_stale_pf_state` (and the panic hook in main.rs) tell OUR ruleset
/// apart from a third party's before reverting anything.
pub(crate) const MARKER_ANCHOR: &str = "com.birdo.vpn";

/// The pf table the control-plane permit is scoped to.
pub(crate) const CONTROL_PLANE_TABLE: &str = "birdo_control";

/// HTTPS: the API, the web origin's client config and DoH. Nothing else of the
/// app's own needs a way out while the block is up — the relay has its own
/// permit (the Windows and Linux twins scope it the same way).
const CONTROL_PLANE_PORT: u16 = 443;

/// The inputs the block-all ruleset is built from — all of them read at load
/// time, so every (re-)load carries the current relay and addresses.
pub(crate) struct BlockAll<'a> {
    /// The relay the tunnel dials (VPN_SERVER_IP). `None` permits no relay.
    pub relay: Option<Ipv4Addr>,
    /// Where the control-plane permit may go: [`control_plane_addresses`].
    pub control_plane: &'a [Ipv4Addr],
    /// The effective uid the app runs as (always 0 on macOS: see below).
    pub euid: u32,
    /// Local Network Sharing.
    pub lan_sharing: bool,
}

/// The kill switch's block-all, as the text `pfctl -f -` loads as pf's MAIN
/// ruleset (a named anchor is inert on stock macOS: see `pf_activate_blocking`).
pub(crate) fn block_all_ruleset(b: &BlockAll<'_>) -> String {
    let mut r = String::from(
        "# Birdo VPN Kill Switch (main ruleset - pf evaluates this directly)\n\
         set block-policy drop\n",
    );

    // CONTROL PLANE (P1-ks-macos-root-443-permit): the addresses the app's own
    // HTTPS may reach while the block is up.
    if !b.control_plane.is_empty() {
        let addrs: Vec<String> = b.control_plane.iter().map(Ipv4Addr::to_string).collect();
        r.push_str(&format!(
            "table <{CONTROL_PLANE_TABLE}> const {{ {} }}\n",
            addrs.join(", ")
        ));
    }

    r.push_str(&format!(
        "anchor \"{MARKER_ANCHOR}\"\n\
         block drop all\n\
         pass quick on lo0 all\n"
    ));

    // Permit utun0..utun15. create_utun_device() probes `for unit in 0..256`
    // and takes the FIRST FREE unit, so on a Mac where system services already
    // hold utun0-3 (VPNs, Continuity, Handoff — common) our tunnel lands on
    // utun4+ and `block drop all` ate its traffic. pfctl tolerates naming
    // absent interfaces, so listing 16 is safe. The live device name cannot
    // be used instead: reapply_vpn_settings arms the block BEFORE the new
    // tunnel exists, so there is no name to bind at rule-load time.
    for unit in 0..16 {
        r.push_str(&format!("pass quick on utun{unit} all\n"));
    }

    // DHCP: both directions are stated explicitly because these rules are
    // `no state` — pf will not infer the reply from the request, so each
    // direction has to match on its own.
    //     request: client :68 -> server :67
    //     reply:   server :67 -> client :68
    // The inbound rule used to read `from any port 68`, which is the CLIENT's
    // port. A DHCP reply arrives FROM :67, so that rule matched nothing and
    // every reply fell through to `block drop all` while the kill switch was
    // armed. The lease could then never be renewed, so a long VPN session ended
    // with the LAN connection dying underneath it — and, because the tunnel
    // itself kept working until the lease actually lapsed, the cause looked
    // nothing like the kill switch.
    r.push_str(
        "pass out quick proto udp from any port 68 to any port 67 no state\n\
         pass in quick proto udp from any port 67 to any port 68 no state\n",
    );

    // LAN permit: honour Local Network Sharing while the block is engaged, so a
    // dropped tunnel does not also take out the printer and the NAS. Includes
    // 169.254/16 for mDNS/Bonjour, which is what actually makes AirPlay and
    // printer discovery work.
    if b.lan_sharing {
        r.push_str(
            "pass quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } no state\n",
        );
    }

    // SELF-PERMIT: let OUR OWN process reach the control plane.
    //
    // Without it the kill switch makes reconnection impossible: auto_reconnect
    // engages the block and then asks https://api.birdo.app for a fresh config —
    // a different host from the permitted relay, over the physical NIC — and
    // port-53 DNS is blocked too. pf has no application condition (Windows
    // scopes this permit to the executable's ALE app id), so the rule matches
    // the euid we run as. But the app runs as ROOT on macOS — arm() refuses
    // otherwise — so this used to read `to any port 443 user 0`: every
    // root-owned process on the machine (system daemons, anything run under
    // sudo, a privileged helper) could open HTTPS to ANY host over the
    // physical NIC, from the real address, during exactly the window the kill
    // switch exists to seal (P1-ks-macos-root-443-permit).
    //
    // The destination is now the table above: the DoH provider the app dials
    // by address and the addresses it last resolved for its own hosts. What a
    // root process can still reach on tcp/443 while blocked is those
    // addresses, and nothing else. They are CDN addresses, so that is narrow,
    // not empty. Without a single address there is no permit at all, and the
    // re-dial fails closed. `keep state` so replies come back.
    if !b.control_plane.is_empty() {
        r.push_str(&format!(
            "pass out quick inet proto tcp to <{CONTROL_PLANE_TABLE}> port {CONTROL_PLANE_PORT} user {} keep state\n",
            b.euid
        ));
    }

    // RELAY PERMIT — must be STATEFUL, and must also permit the INBOUND reply.
    //
    // This rule used to be `... to <ip> no state`. `no state` suppresses pf's
    // implicit state creation, and the ruleset has no other `pass in` rule for
    // the relay, so the relay's reply packets matched only the non-quick
    // `block drop all` (pf is last-match) and were silently dropped. The
    // WireGuard handshake is a REQUEST/RESPONSE exchange, so with the block
    // engaged no tunnel could EVER be established — the kill switch became a
    // permanent "cannot connect" rather than a fail-closed gap. `keep state`
    // plus the explicit inbound permit fixes that; both are scoped to the one
    // relay IP. Both transports, so a stealth/TCP fallback can reconnect too.
    if let Some(ip) = b.relay {
        r.push_str(&format!(
            "pass out quick inet proto {{ udp tcp }} to {ip} keep state\n\
             pass in quick inet proto {{ udp tcp }} from {ip} keep state\n"
        ));
    }

    r
}

/// The addresses the control-plane permit names: the DoH provider's (how the
/// app finds the API at all once port-53 DNS is blocked) and the last ones
/// this process resolved for its own hosts.
///
/// Read when the ruleset is (re-)loaded, which every re-dial does
/// (auto_reconnect engages the block before each attempt). So an API address
/// that changed under a block is permitted from the next attempt: the DoH
/// lookup that found it is itself permitted, and it lands in the resolver's
/// cache before the connection that needs it fails.
pub(crate) fn control_plane_addresses() -> Vec<Ipv4Addr> {
    let mut addrs = crate::vpn::doh::bootstrap_addrs();
    addrs.extend(crate::api::doh_resolver::control_plane_v4());
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

/// Every pass rule that names a `user` also names the control-plane table —
/// so no rule lets a uid out to any destination. Holds for our ruleset text
/// AND for pf's printout of it (`user = 0`).
#[cfg(test)]
fn root_permits_are_scoped(text: &str) -> bool {
    let table = format!("<{CONTROL_PLANE_TABLE}>");
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("pass") && l.contains(" user "))
        .all(|l| l.contains(&table))
}

/// The ruleset shapes a session can load: every input on and off.
#[cfg(test)]
fn every_shape<'a>(control_plane: &'a [Ipv4Addr]) -> Vec<BlockAll<'a>> {
    let mut shapes = Vec::new();
    for relay in [None, Some(Ipv4Addr::new(203, 0, 113, 7))] {
        for lan_sharing in [false, true] {
            shapes.push(BlockAll {
                relay,
                control_plane,
                euid: 0,
                lan_sharing,
            });
        }
    }
    shapes
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOH: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const API: Ipv4Addr = Ipv4Addr::new(104, 16, 0, 1);

    fn ruleset(control_plane: &[Ipv4Addr]) -> String {
        block_all_ruleset(&BlockAll {
            relay: Some(Ipv4Addr::new(203, 0, 113, 7)),
            control_plane,
            euid: 0,
            lan_sharing: false,
        })
    }

    // ── P1-ks-macos-root-443-permit ────────────────────────────────────

    #[test]
    fn the_control_plane_permit_goes_to_the_table_and_nowhere_else() {
        let r = ruleset(&[DOH, API]);
        assert!(
            r.contains("table <birdo_control> const { 1.1.1.1, 104.16.0.1 }\n"),
            "the table must list exactly the control-plane addresses:\n{r}"
        );
        assert!(
            r.contains(
                "pass out quick inet proto tcp to <birdo_control> port 443 user 0 keep state\n"
            ),
            "{r}"
        );
        assert!(
            !r.contains("to any port 443"),
            "root must not reach ANY host on 443 through the block:\n{r}"
        );
        for shape in every_shape(&[DOH, API]) {
            let r = block_all_ruleset(&shape);
            assert!(root_permits_are_scoped(&r), "{r}");
        }
    }

    /// No address, no permit: the re-dial fails closed rather than falling
    /// back to "any".
    #[test]
    fn no_control_plane_address_means_no_root_permit_at_all() {
        let r = ruleset(&[]);
        assert!(!r.contains(" user "), "{r}");
        assert!(!r.contains("table <"), "{r}");
        assert!(!r.contains("port 443"), "{r}");
    }

    #[test]
    fn the_control_plane_set_holds_every_doh_bootstrap_address() {
        let set = control_plane_addresses();
        for ip in crate::vpn::doh::bootstrap_addrs() {
            assert!(set.contains(&ip), "{ip} missing from {set:?}");
        }
        let mut sorted = set.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(set, sorted, "sorted and de-duplicated");
    }

    // ── The rest of the ruleset, unchanged in substance ────────────────

    #[test]
    fn the_block_all_carries_the_marker_and_denies_by_default() {
        let r = ruleset(&[DOH]);
        let lines: Vec<&str> = r.lines().collect();
        assert_eq!(lines[1], "set block-policy drop");
        let block = lines.iter().position(|l| *l == "block drop all").unwrap();
        let marker = lines
            .iter()
            .position(|l| *l == "anchor \"com.birdo.vpn\"")
            .expect("marker anchor: reconcile_stale_pf_state greps for it");
        assert!(marker < block, "{r}");
        // Every permit is `quick`, so `block drop all` (pf is last-match)
        // is the answer for everything they do not name.
        for l in &lines[block + 1..] {
            assert!(l.starts_with("pass ") && l.contains(" quick "), "{l}");
        }
    }

    #[test]
    fn relay_dhcp_and_lan_permits_are_kept() {
        let with = block_all_ruleset(&BlockAll {
            relay: Some(Ipv4Addr::new(203, 0, 113, 7)),
            control_plane: &[DOH],
            euid: 0,
            lan_sharing: true,
        });
        for rule in [
            "pass out quick inet proto { udp tcp } to 203.0.113.7 keep state\n",
            "pass in quick inet proto { udp tcp } from 203.0.113.7 keep state\n",
            "pass out quick proto udp from any port 68 to any port 67 no state\n",
            "pass in quick proto udp from any port 67 to any port 68 no state\n",
            "pass quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } no state\n",
        ] {
            assert!(with.contains(rule), "missing {rule:?} in:\n{with}");
        }
        let without = block_all_ruleset(&BlockAll {
            relay: None,
            control_plane: &[DOH],
            euid: 0,
            lan_sharing: false,
        });
        assert!(!without.contains("203.0.113.7"), "{without}");
        assert!(!without.contains("10.0.0.0/8"), "{without}");
    }
}

/// The macOS runner's half: pf itself parses every ruleset shape, and its own
/// printout keeps root to the table. Root-only (`pfctl` opens /dev/pf even to
/// parse), so `#[ignore]`d here and run by tests.yml's "pf ruleset parse-check
/// (macOS)" step under sudo. `-n` parses without loading: the runner's own
/// firewall is never touched.
#[cfg(all(test, target_os = "macos"))]
mod pfctl_parse_tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// `pfctl -nvf -`: parse `rules` and print them as pf reads them.
    fn pfctl_parse(rules: &str) -> String {
        let mut child = Command::new("pfctl")
            .args(["-n", "-v", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pfctl");
        child
            .stdin
            .take()
            .expect("pfctl stdin")
            .write_all(rules.as_bytes())
            .expect("write the ruleset to pfctl");
        let out = child.wait_with_output().expect("wait for pfctl");
        assert!(
            out.status.success(),
            "pfctl rejected the ruleset: {}\n--- ruleset ---\n{rules}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    #[ignore = "needs root and macOS pfctl; run by tests.yml's pf parse-check step"]
    fn every_block_all_shape_parses() {
        let control_plane = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(104, 16, 0, 1)];
        for shape in every_shape(&control_plane) {
            let rules = block_all_ruleset(&shape);
            let printed = pfctl_parse(&rules);
            println!("--- pfctl -nv printout ---\n{printed}");
            assert!(
                printed.contains("<birdo_control>"),
                "the control-plane permit must name the table:\n{printed}"
            );
            assert!(root_permits_are_scoped(&printed), "{printed}");
        }
    }

    #[test]
    #[ignore = "needs root and macOS pfctl; run by tests.yml's pf parse-check step"]
    fn the_shape_without_a_control_plane_parses() {
        let rules = block_all_ruleset(&BlockAll {
            relay: None,
            control_plane: &[],
            euid: 0,
            lan_sharing: false,
        });
        let printed = pfctl_parse(&rules);
        assert!(!printed.contains(" user "), "{printed}");
    }
}
