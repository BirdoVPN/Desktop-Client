//! What the macOS kill switch's pf ruleset contains, and how pf's answer is
//! read back, as plain functions.
//!
//! `commands/killswitch.rs` owns pf's MAIN ruleset on macOS and runs `pfctl`.
//! Everything that decides WHAT that ruleset permits, and WHEN the kill switch
//! may say it is blocking, lives here instead, free of `pfctl`, so it is
//! unit-tested on every OS (the Windows job runs these tests) rather than only
//! on a Mac nobody on the team has. The macOS CI runner then feeds every
//! ruleset shape to `pfctl -nv` and runs pf's own printout through the same
//! read-back detector (`pfctl_parse_tests`, run by tests.yml's pf parse-check
//! step), which is the part of the kill switch a Windows box cannot check.
//!
//! # What the block-all permits
//!
//! | rule                                     | why                               |
//! |------------------------------------------|-----------------------------------|
//! | `lo0`                                    | local IPC, the stealth helper     |
//! | the tunnel's own utun, BY NAME           | traffic already inside the VPN    |
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
/// apart from a third party's before reverting anything. Rulesets older builds
/// left behind carry only this one, so the block-all keeps it too.
pub(crate) const MARKER_ANCHOR: &str = "com.birdo.vpn";

/// Marker anchor carried by the block-all ruleset ONLY.
///
/// The IPv6 leak block carries [`MARKER_ANCHOR`] as well, so that marker alone
/// cannot tell "the kill switch is blocking" apart from "the IPv6 baseline is
/// loaded" — and the read-back that decides `PF_BLOCKING` must
/// (P1-ks-macos-pf-enable-unverified). Not `com.birdo.vpn.killswitch`: that is
/// the pre-#59 anchor the panic hook still flushes on mixed-upgrade hosts.
pub(crate) const BLOCK_ANCHOR: &str = "com.birdo.vpn.blockall";

/// The pf table the control-plane permit is scoped to.
pub(crate) const CONTROL_PLANE_TABLE: &str = "birdo_control";

/// HTTPS: the API, the web origin's client config and DoH. Nothing else of the
/// app's own needs a way out while the block is up — the relay has its own
/// permit (the Windows and Linux twins scope it the same way).
const CONTROL_PLANE_PORT: u16 = 443;

/// The inputs the block-all ruleset is built from — all of them read at load
/// time, so every (re-)load carries the current relay, interface and addresses.
pub(crate) struct BlockAll<'a> {
    /// The relay the tunnel dials (VPN_SERVER_IP). `None` permits no relay.
    pub relay: Option<Ipv4Addr>,
    /// The utun the live tunnel runs on. `None` while no tunnel exists — a
    /// reconnect gap, or a reapply that arms the block before the new tunnel
    /// is built — and then no utun is permitted at all.
    pub tunnel_interface: Option<&'a str>,
    /// Where the control-plane permit may go: [`control_plane_addresses`].
    pub control_plane: &'a [Ipv4Addr],
    /// The effective uid the app runs as (always 0 on macOS: see below).
    pub euid: u32,
    /// Local Network Sharing.
    pub lan_sharing: bool,
}

/// `utun` followed by a unit number, as `create_utun_device` names it
/// (`utun{unit}` for unit 0..256). Anything else is refused before it can be
/// written into a ruleset that pf parses.
pub(crate) fn is_utun_name(name: &str) -> bool {
    name.strip_prefix("utun").is_some_and(|unit| {
        (1..=3).contains(&unit.len()) && unit.bytes().all(|b| b.is_ascii_digit())
    })
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
         anchor \"{BLOCK_ANCHOR}\"\n\
         block drop all\n\
         pass quick on lo0 all\n"
    ));

    // TUNNEL PERMIT (MR-1125): exactly the interface the tunnel is using.
    //
    // This was a fixed `utun0`..`utun15` list, because the live name was not
    // known when reapply_vpn_settings armed the block. Both directions of that
    // were wrong: create_utun_device() takes the FIRST FREE unit of 0..256, so
    // on a Mac where other software already holds 16 utuns our tunnel landed on
    // utun16+ and `block drop all` ate all of its traffic; and every other
    // utun0-15 — another VPN's, iCloud Private Relay's — passed straight
    // through the block. The tunnel now records its interface when it creates
    // it (`killswitch::tunnel_interface_up`), which re-loads an engaged block,
    // so the not-yet-built case is simply "no tunnel permit yet".
    match b.tunnel_interface {
        Some(name) if is_utun_name(name) => r.push_str(&format!("pass quick on {name} all\n")),
        Some(_) => {
            // The kernel named it; this cannot happen. Refuse rather than write
            // an arbitrary string into a ruleset — the tunnel stays blocked.
            tracing::error!(
                "Kill switch: refusing a malformed tunnel interface name; no tunnel permit"
            );
        }
        None => {}
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

/// Whether `live_rules` — `pfctl -s rules` — shows the block-all as pf's main
/// ruleset. pf prints an anchor rule as `anchor "<name>" all`.
pub(crate) fn block_all_loaded(live_rules: &str) -> bool {
    let line = format!("anchor \"{BLOCK_ANCHOR}\"");
    live_rules
        .lines()
        .any(|l| l.trim_start().starts_with(&line))
}

/// The pfctl operations the kill switch sequences: `pfctl` itself on macOS
/// (`killswitch::Pfctl`), a scripted fake in the tests below.
pub(crate) trait Pf {
    /// `pfctl -s info` reports `Status: Enabled`.
    fn is_enabled(&self) -> bool;
    /// `pfctl -f -`: `rules` becomes pf's main ruleset. All or nothing — a
    /// failed load leaves whatever was loaded before in force.
    fn load(&self, rules: &str) -> Result<(), String>;
    /// `pfctl -e`. `Err` on a spawn failure AND on a non-zero exit.
    fn enable(&self) -> Result<(), String>;
    /// `pfctl -s rules`: pf's live main ruleset, as pf prints it.
    fn live_rules(&self) -> String;
}

/// What pf reports — read back, never inferred from having asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observed {
    pub enabled: bool,
    pub block_all_loaded: bool,
}

impl Observed {
    pub(crate) fn read(pf: &impl Pf) -> Self {
        Self {
            enabled: pf.is_enabled(),
            block_all_loaded: block_all_loaded(&pf.live_rules()),
        }
    }

    /// Traffic is blocked only while pf is running AND the block-all is its
    /// main ruleset. A loaded ruleset in a disabled pf is inert.
    pub(crate) fn blocking(self) -> bool {
        self.enabled && self.block_all_loaded
    }
}

/// The outcome of [`engage`]: what the kill switch may record.
#[derive(Debug)]
pub(crate) struct Engaged {
    /// What PF_BLOCKING must hold: pf's answer, not the request.
    pub blocking: bool,
    /// pf was off before this call and is on after it, so a teardown owes a
    /// `pfctl -d` (PF_WE_ENABLED is only ever SET from this).
    pub we_enabled: bool,
    pub result: Result<(), String>,
}

/// Load `rules` as the block-all, enable pf if it was off, and report what pf
/// then says is in force (P1-ks-macos-pf-enable-unverified).
///
/// This used to accept any exit status from `pfctl -e` and set PF_BLOCKING
/// with no read-back, so a pf that failed to start (another process holding
/// /dev/pf, a policy restriction) held an inert ruleset while the status, the
/// UI and auto-reconnect all proceeded as if the block were enforced — every
/// packet of the reconnect gap left in the clear. `Ok` now means pf is running
/// with the block-all as its main ruleset, read back after the load.
pub(crate) fn engage(pf: &impl Pf, rules: &str) -> Engaged {
    let was_enabled = pf.is_enabled();

    if let Err(e) = pf.load(rules) {
        // All or nothing: whatever was in force before still is. Say which.
        return Engaged {
            blocking: Observed::read(pf).blocking(),
            we_enabled: false,
            result: Err(e),
        };
    }

    if !was_enabled {
        // Logged, not returned: the read-back below is what decides, so a pf
        // that some other process enabled in the meantime still counts.
        if let Err(e) = pf.enable() {
            tracing::warn!("Kill switch: {e}; reading back whether pf is running");
        }
    }

    let seen = Observed::read(pf);
    let result = if !seen.enabled {
        Err("pf is not enabled, so the loaded block-all ruleset is not enforced".to_string())
    } else if !seen.block_all_loaded {
        Err("the block-all ruleset is not pf's live ruleset after loading it".to_string())
    } else {
        Ok(())
    };
    Engaged {
        blocking: seen.blocking(),
        we_enabled: !was_enabled && seen.enabled,
        result,
    }
}

/// After a teardown attempt: what PF_BLOCKING must hold, and what to report.
///
/// `pf_deactivate_blocking` used to store PF_BLOCKING = false as its FIRST
/// statement (P1-ks-macos-linux-deactivate-swallows-errors). When the teardown
/// then failed — the IPv6 baseline refused to load, `/etc/pf.conf` unreadable —
/// the kernel kept the block-all while the app recorded "not blocking". Every
/// later lift (set_killswitch_live, the give-up) is gated on that flag, so
/// nothing ever retried and the Mac had no network until the app restarted.
/// The Linux half was fixed in bf8af6d4; this is the macOS half: the flag
/// follows pf's read-back, whatever the teardown returned.
pub(crate) fn disengaged(pf: &impl Pf, teardown: Result<(), String>) -> (bool, Result<(), String>) {
    if Observed::read(pf).blocking() {
        let why = teardown.err().map(|e| format!(": {e}")).unwrap_or_default();
        return (
            true,
            Err(format!("the block-all ruleset is still in force{why}")),
        );
    }
    (false, teardown)
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

/// The utun interfaces `text` permits (`pass quick on utunN ...`), in order.
#[cfg(test)]
fn tunnel_permits(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("pass quick on utun"))
        .map(|rest| {
            let unit: String = rest.chars().take_while(char::is_ascii_digit).collect();
            format!("utun{unit}")
        })
        .collect()
}

/// The ruleset shapes a session can load: every input on and off.
#[cfg(test)]
fn every_shape<'a>(control_plane: &'a [Ipv4Addr]) -> Vec<BlockAll<'a>> {
    let mut shapes = Vec::new();
    for relay in [None, Some(Ipv4Addr::new(203, 0, 113, 7))] {
        for tunnel_interface in [None, Some("utun3"), Some("utun17"), Some("utun255")] {
            for lan_sharing in [false, true] {
                shapes.push(BlockAll {
                    relay,
                    tunnel_interface,
                    control_plane,
                    euid: 0,
                    lan_sharing,
                });
            }
        }
    }
    shapes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const DOH: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const API: Ipv4Addr = Ipv4Addr::new(104, 16, 0, 1);

    fn ruleset(tunnel_interface: Option<&str>, control_plane: &[Ipv4Addr]) -> String {
        block_all_ruleset(&BlockAll {
            relay: Some(Ipv4Addr::new(203, 0, 113, 7)),
            tunnel_interface,
            control_plane,
            euid: 0,
            lan_sharing: false,
        })
    }

    // ── P1-ks-macos-root-443-permit ────────────────────────────────────

    #[test]
    fn the_control_plane_permit_goes_to_the_table_and_nowhere_else() {
        let r = ruleset(Some("utun4"), &[DOH, API]);
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
        let r = ruleset(Some("utun4"), &[]);
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

    // ── MR-1125 ────────────────────────────────────────────────────────

    #[test]
    fn the_tunnel_permit_names_exactly_the_live_utun() {
        // utun16+ was blocked by the old fixed utun0-15 list.
        let r = ruleset(Some("utun17"), &[DOH]);
        assert_eq!(tunnel_permits(&r), vec!["utun17".to_string()], "{r}");
        // …and another VPN's utun0-15 is no longer let through.
        let r = ruleset(Some("utun2"), &[DOH]);
        assert_eq!(tunnel_permits(&r), vec!["utun2".to_string()], "{r}");
        assert!(!r.contains("utun0"), "{r}");
        assert!(!r.contains("utun15"), "{r}");
    }

    /// A reapply arms the block before the new tunnel exists, and a
    /// reconnect gap has none: no utun is permitted until one is recorded.
    #[test]
    fn no_tunnel_means_no_utun_is_permitted() {
        let r = ruleset(None, &[DOH]);
        assert!(tunnel_permits(&r).is_empty(), "{r}");
        assert!(!r.contains("utun"), "{r}");
    }

    #[test]
    fn a_malformed_interface_name_never_reaches_the_ruleset() {
        for bad in [
            "utun1 all\npass all",
            "utun",
            "utun1234",
            "utunx",
            "utun-1",
            "en0",
            "UTUN3",
            "",
        ] {
            let r = ruleset(Some(bad), &[DOH]);
            assert!(tunnel_permits(&r).is_empty(), "{bad:?} permitted:\n{r}");
            assert!(!r.contains("pass all"), "{bad:?} injected a rule:\n{r}");
        }
    }

    #[test]
    fn utun_names_are_recognised_exactly() {
        for good in ["utun0", "utun9", "utun15", "utun16", "utun255"] {
            assert!(is_utun_name(good), "{good}");
        }
        for bad in [
            "utun", "utun1234", "utun1a", "tun0", "utun 1", " utun1", "ipsec0",
        ] {
            assert!(!is_utun_name(bad), "{bad:?}");
        }
    }

    // ── The rest of the ruleset, unchanged in substance ────────────────

    #[test]
    fn the_block_all_carries_both_markers_and_denies_by_default() {
        let r = ruleset(Some("utun4"), &[DOH]);
        let lines: Vec<&str> = r.lines().collect();
        assert_eq!(lines[1], "set block-policy drop");
        let block = lines.iter().position(|l| *l == "block drop all").unwrap();
        let marker = lines
            .iter()
            .position(|l| *l == "anchor \"com.birdo.vpn\"")
            .expect("marker anchor: reconcile_stale_pf_state greps for it");
        let own = lines
            .iter()
            .position(|l| *l == "anchor \"com.birdo.vpn.blockall\"")
            .expect("block-all anchor: the read-back looks for it");
        assert!(marker < block && own < block, "{r}");
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
            tunnel_interface: Some("utun4"),
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
            tunnel_interface: Some("utun4"),
            control_plane: &[DOH],
            euid: 0,
            lan_sharing: false,
        });
        assert!(!without.contains("203.0.113.7"), "{without}");
        assert!(!without.contains("10.0.0.0/8"), "{without}");
    }

    // ── The read-back detector ─────────────────────────────────────────

    /// What `pfctl -s rules` prints for a loaded ruleset, near enough for the
    /// detector: filter rules only (no comments, options or tables), anchors
    /// suffixed ` all`. The real printout is checked on the macOS runner.
    fn pf_prints(rules: &str) -> String {
        rules
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| {
                !l.starts_with("set ") && !l.starts_with("table ") && !l.starts_with("load ")
            })
            .map(|l| {
                if l.starts_with("anchor ") {
                    format!("{l} all")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn only_the_block_all_reads_back_as_the_block() {
        assert!(block_all_loaded(&pf_prints(&ruleset(
            Some("utun4"),
            &[DOH]
        ))));
        // The IPv6 leak block carries the shared marker, not ours.
        for baseline in [
            include_str!("../../resources/pf/ipv6-block.conf"),
            include_str!("../../resources/pf/ipv6-block-minimal.conf"),
        ] {
            let printed = pf_prints(baseline);
            assert!(
                printed.contains("anchor \"com.birdo.vpn\" all"),
                "{printed}"
            );
            assert!(!block_all_loaded(&printed), "{printed}");
        }
        // Stock /etc/pf.conf, and a pfctl that printed nothing (it failed).
        assert!(!block_all_loaded(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all"
        ));
        assert!(!block_all_loaded(""));
    }

    // ── engage / disengaged, against a scripted pf ─────────────────────

    #[derive(Default)]
    struct FakePf {
        enabled: Cell<bool>,
        live: RefCell<String>,
        /// `pfctl -f -` exits non-zero (and, being atomic, changes nothing).
        load_fails: bool,
        /// `pfctl -f -` exits 0, but the live ruleset is not ours afterwards
        /// (another writer replaced it).
        load_lost: bool,
        /// `pfctl -e` exits non-zero and pf stays off.
        enable_fails: bool,
        /// `pfctl -e` exits 0, and pf is still off.
        enable_lies: bool,
        enable_calls: Cell<u32>,
    }

    impl Pf for FakePf {
        fn is_enabled(&self) -> bool {
            self.enabled.get()
        }
        fn load(&self, rules: &str) -> Result<(), String> {
            if self.load_fails {
                return Err("pfctl load ruleset failed: syntax error".to_string());
            }
            if !self.load_lost {
                *self.live.borrow_mut() = pf_prints(rules);
            }
            Ok(())
        }
        fn enable(&self) -> Result<(), String> {
            self.enable_calls.set(self.enable_calls.get() + 1);
            if self.enable_fails {
                return Err("pfctl -e failed: /dev/pf: Resource busy".to_string());
            }
            if !self.enable_lies {
                self.enabled.set(true);
            }
            Ok(())
        }
        fn live_rules(&self) -> String {
            self.live.borrow().clone()
        }
    }

    fn block() -> String {
        ruleset(Some("utun4"), &[DOH])
    }

    #[test]
    fn engage_reports_blocking_once_pf_says_so() {
        let pf = FakePf::default();
        let out = engage(&pf, &block());
        assert_eq!(out.result, Ok(()));
        assert!(out.blocking);
        assert!(out.we_enabled, "pf was off: teardown owes a pfctl -d");
        assert_eq!(pf.enable_calls.get(), 1);
    }

    /// P1-ks-macos-pf-enable-unverified: the old code took `Ok(_)` from
    /// `pfctl -e` whatever its exit status and stored PF_BLOCKING = true.
    #[test]
    fn a_pf_that_would_not_start_is_not_reported_as_blocking() {
        let pf = FakePf {
            enable_fails: true,
            ..Default::default()
        };
        let out = engage(&pf, &block());
        assert!(!out.blocking, "an inert ruleset is not a block");
        assert!(!out.we_enabled);
        assert!(out.result.unwrap_err().contains("not enabled"));
    }

    #[test]
    fn an_exit_status_of_zero_is_not_taken_as_proof() {
        let pf = FakePf {
            enable_lies: true,
            ..Default::default()
        };
        let out = engage(&pf, &block());
        assert!(!out.blocking);
        assert!(!out.we_enabled);
        assert!(out.result.is_err());
    }

    #[test]
    fn a_block_all_missing_from_pfs_live_rules_is_not_reported_as_blocking() {
        let pf = FakePf {
            load_lost: true,
            ..Default::default()
        };
        pf.enabled.set(true);
        let out = engage(&pf, &block());
        assert!(!out.blocking);
        assert!(out.result.unwrap_err().contains("not pf's live ruleset"));
    }

    /// pfctl -f is all or nothing, so a failed re-load (a relay move, a new
    /// tunnel interface) leaves the previous block in force — and says so.
    #[test]
    fn a_failed_load_reports_whatever_is_still_in_force() {
        let held = FakePf {
            load_fails: true,
            ..Default::default()
        };
        held.enabled.set(true);
        *held.live.borrow_mut() = pf_prints(&block());
        let out = engage(&held, &block());
        assert!(out.result.is_err());
        assert!(out.blocking, "the previous block-all is still loaded");

        let none = FakePf {
            load_fails: true,
            ..Default::default()
        };
        let out = engage(&none, &block());
        assert!(out.result.is_err());
        assert!(!out.blocking);
        assert_eq!(
            none.enable_calls.get(),
            0,
            "nothing loaded, nothing to enable"
        );
    }

    /// Someone else's pf: never claim we enabled it, or teardown would
    /// `pfctl -d` it out from under them.
    #[test]
    fn re_engaging_a_running_pf_does_not_claim_we_enabled_it() {
        let pf = FakePf::default();
        pf.enabled.set(true);
        let out = engage(&pf, &block());
        assert_eq!(out.result, Ok(()));
        assert!(out.blocking);
        assert!(!out.we_enabled);
        assert_eq!(pf.enable_calls.get(), 0);
    }

    /// P1-ks-macos-linux-deactivate-swallows-errors (macOS half): a
    /// teardown that did not land keeps the flag, so the next lift retries.
    #[test]
    fn a_teardown_that_left_the_block_in_force_keeps_the_flag() {
        let pf = FakePf::default();
        pf.enabled.set(true);
        *pf.live.borrow_mut() = pf_prints(&block());

        let (blocking, result) = disengaged(&pf, Err("IPv6 leak block failed to load".into()));
        assert!(blocking, "the old code stored false before trying");
        let e = result.unwrap_err();
        assert!(
            e.contains("still in force") && e.contains("IPv6 leak block failed"),
            "{e}"
        );

        // A teardown that claimed success proves nothing either.
        let (blocking, result) = disengaged(&pf, Ok(()));
        assert!(blocking);
        assert!(result.is_err());
    }

    #[test]
    fn a_teardown_that_landed_clears_the_flag() {
        let pf = FakePf::default();
        pf.enabled.set(true);
        *pf.live.borrow_mut() = pf_prints(include_str!("../../resources/pf/ipv6-block.conf"));
        assert_eq!(disengaged(&pf, Ok(())), (false, Ok(())));

        // The block lifted but the fallback did not apply cleanly: not
        // blocking, and the teardown's own error still reaches the caller.
        let (blocking, result) = disengaged(&pf, Err("pfctl restore failed".into()));
        assert!(!blocking);
        assert_eq!(result, Err("pfctl restore failed".to_string()));
    }

    /// A disabled pf enforces nothing, whatever is loaded in it.
    #[test]
    fn a_disabled_pf_is_not_blocking_even_with_the_block_loaded() {
        let pf = FakePf::default();
        *pf.live.borrow_mut() = pf_prints(&block());
        assert!(!Observed::read(&pf).blocking());
        assert_eq!(disengaged(&pf, Ok(())), (false, Ok(())));
    }
}

/// The macOS runner's half: pf itself parses every ruleset shape, and its own
/// printout reads back as the block. Root-only (`pfctl` opens /dev/pf even to
/// parse), so `#[ignore]`d here and run by tests.yml's "pf ruleset parse-check
/// (macOS)" step under sudo. `-n` parses without loading: the runner's own
/// firewall is never touched.
#[cfg(all(test, target_os = "macos"))]
mod pfctl_parse_tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// `pfctl -nvf -`: parse `rules` and print them as pf reads them — the
    /// same printer `pfctl -s rules` (the read-back) uses.
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
    fn every_block_all_shape_parses_and_reads_back_as_the_block() {
        let control_plane = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(104, 16, 0, 1)];
        for shape in every_shape(&control_plane) {
            let rules = block_all_ruleset(&shape);
            let printed = pfctl_parse(&rules);
            println!("--- pfctl -nv printout ---\n{printed}");
            assert!(
                block_all_loaded(&printed),
                "the read-back would not recognise this block-all:\n{printed}"
            );
            assert_eq!(
                tunnel_permits(&printed),
                shape
                    .tunnel_interface
                    .map(str::to_string)
                    .into_iter()
                    .collect::<Vec<_>>(),
                "{printed}"
            );
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
            tunnel_interface: None,
            control_plane: &[],
            euid: 0,
            lan_sharing: false,
        });
        let printed = pfctl_parse(&rules);
        assert!(block_all_loaded(&printed), "{printed}");
        assert!(!printed.contains(" user "), "{printed}");
    }
}
