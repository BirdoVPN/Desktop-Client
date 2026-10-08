//! What the macOS kill switch's pf ruleset contains, and how pf's answer is
//! read back, as plain functions.
//!
//! `commands/killswitch.rs` owns pf's MAIN ruleset on macOS and runs `pfctl`.
//! Everything that decides WHAT that ruleset permits, WHEN the kill switch may
//! say it is blocking, and how a lift is verified (`PfState`) lives here
//! instead, free of `pfctl`, so it is
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
    // by address, and every address a DoH answer gave our own hosts. That is
    // narrower than `any`, but it is NOT narrow, and must not be described as
    // if it were (P3-2): these are SHARED Cloudflare edge addresses — 1.1.1.1
    // and its siblings, and the anycast front of api.birdo.app — and an edge
    // serves every Cloudflare-hosted site by SNI. So a root process can most
    // likely still reach other Cloudflare-hosted HTTPS sites on tcp/443
    // through the block, from the real address. Only per-process scoping
    // closes that, and pf has none. Without a single address there is no
    // permit at all, and the re-dial fails closed. `keep state` so replies
    // come back.
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

/// The addresses the control-plane permit names, with the generation that
/// covers them (N5): `api::doh_resolver::control_plane`, the set the Linux
/// kill switch's self-permits name too.
///
/// Read whenever the ruleset is (re-)loaded, and a held block is re-loaded
/// the moment a DoH answer brings an address it does not hold yet
/// (`killswitch::control_plane_learned`), before that address is dialled.
pub(crate) fn control_plane() -> (Vec<Ipv4Addr>, u64) {
    crate::api::doh_resolver::control_plane()
}

/// The IPv6 leak block (F-001), as the bytes we ship: `resources/pf/` rather
/// than this file, so CI can parse-check them with `pfctl -n -f` on a real
/// macOS runner. The preferred ruleset re-declares the stock `/etc/pf.conf`
/// anchors so Apple's own pf rules keep working for the session; the minimal
/// one is for hosts where `/etc/pf.anchors/com.apple` is missing or
/// unreadable (its `load anchor` line would fail the whole load).
pub(crate) const IPV6_RULESET_FULL: &str = include_str!("../../resources/pf/ipv6-block.conf");
pub(crate) const IPV6_RULESET_MINIMAL: &str =
    include_str!("../../resources/pf/ipv6-block-minimal.conf");

/// Whether `pfctl -s info` reports pf running.
pub(crate) fn parse_enabled(info: &str) -> bool {
    info.contains("Status: Enabled")
}

/// Whether `live_rules` — `pfctl -s rules` — shows the block-all as pf's main
/// ruleset. pf prints an anchor rule as `anchor "<name>" all`.
pub(crate) fn block_all_loaded(live_rules: &str) -> bool {
    let line = format!("anchor \"{BLOCK_ANCHOR}\"");
    live_rules
        .lines()
        .any(|l| l.trim_start().starts_with(&line))
}

/// Whether `live_rules` carries OUR marker anchor (`anchor "com.birdo.vpn"`),
/// as both the block-all and the IPv6 leak block do. Exact: the block-all's
/// own `com.birdo.vpn.blockall` anchor does not count.
pub(crate) fn marker_loaded(live_rules: &str) -> bool {
    let line = format!("anchor \"{MARKER_ANCHOR}\"");
    live_rules
        .lines()
        .any(|l| l.trim_start().starts_with(&line))
}

/// The pfctl operations the kill switch sequences: `pfctl` itself on macOS
/// (`killswitch::Pfctl`), a scripted fake in the tests below. A READ that
/// fails is an `Err`, never an empty answer: an unreadable pf is not a pf
/// with nothing loaded (P2-2).
///
/// There is deliberately no `pfctl -e` / `pfctl -d` here (P2-3). macOS pf is
/// reference-counted: `pfctl -E` takes a reference (enabling pf if it was
/// off) and returns a token, and `pfctl -X <token>` drops exactly that
/// reference — pf stops only when none is left. `-d` stops pf for EVERYONE
/// and invalidates every token, so ours used to kill another tool's
/// firewall; and a third party's `-X` could stop the pf our block relied on
/// whenever ours was the anonymous `-e`.
pub(crate) trait Pf {
    /// `pfctl -s info`.
    fn info(&self) -> Result<String, String>;
    /// `pfctl -s rules`: pf's live main ruleset, as pf prints it.
    fn rules(&self) -> Result<String, String>;
    /// `pfctl -f -`: `rules` becomes pf's main ruleset. All or nothing — a
    /// failed load leaves whatever was loaded before in force.
    fn load(&self, rules: &str) -> Result<(), String>;
    /// `pfctl -f /etc/pf.conf`: the system's own ruleset back.
    fn load_default(&self) -> Result<(), String>;
    /// `pfctl -F rules`: flush the main ruleset's filter rules.
    fn flush_rules(&self) -> Result<(), String>;
    /// `pfctl -E`: take a reference on pf, enabling it if it was off. The
    /// pid of that pfctl, and the token if it printed one.
    fn take_ref(&self) -> Result<Taken, String>;
    /// `pfctl -s References`: the live references, as pf lists them.
    fn references(&self) -> Result<String, String>;
    /// `pfctl -X <token>`: drop exactly that reference.
    fn release_ref(&self, token: u64) -> Result<(), String>;
    /// Persist the reference we hold (`None`: none) where a crash cannot lose
    /// it (N3): XNU frees a token only on `-X` or `-d`, never on exit.
    fn record_reference(&self, held: Option<PfRef>);
}

/// One reference on pf: its token and the pid of the `pfctl -E` that took it
/// — the two columns `pfctl -s References` lists it by (measured on the macOS
/// runner: `PID  Process Name  TOKEN  TIMESTAMP`, where TIMESTAMP is an age
/// and so not an identity). The pid is what makes it OURS: XNU token values
/// can recur after a `pfctl -d`, and `-X` of a value someone else now holds
/// would drop THEIR reference (N4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PfRef {
    pub token: u64,
    pub pid: u32,
}

/// What one `pfctl -E` returned: its pid, and its token if it printed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Taken {
    pub token: Option<u64>,
    pub pid: u32,
}

/// The references `pfctl -s References` lists. A row is
/// `<pid>  <process name…>  <token>  <d> days <hh:mm:ss>`; the header, the
/// `TOKENS:` line and "No pf starter references held" are not rows.
pub(crate) fn parse_references(listing: &str) -> Vec<PfRef> {
    listing
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let n = f.len();
            if n < 6 || f[n - 2] != "days" {
                return None;
            }
            Some(PfRef {
                pid: f[0].parse().ok()?,
                token: f[n - 4].parse().ok()?,
            })
        })
        .collect()
}

/// Whether a failed `pfctl -X` means the token is DEAD — `pf: token invalid`,
/// or `pf not enabled` after a `pfctl -d` killed every token (both measured)
/// — rather than that the release must be retried.
pub(crate) fn is_dead_token_error(error: &str) -> bool {
    error.contains("token invalid") || error.contains("pf not enabled")
}

/// The reference journal's one line (N3).
pub(crate) fn encode_reference(held: PfRef) -> String {
    format!("token={} pid={}\n", held.token, held.pid)
}

/// [`encode_reference`]'s inverse; `None` for anything else.
pub(crate) fn decode_reference(text: &str) -> Option<PfRef> {
    let mut token = None;
    let mut pid = None;
    for field in text.split_whitespace() {
        match field.split_once('=')? {
            ("token", v) => token = Some(v.parse().ok()?),
            ("pid", v) => pid = Some(v.parse().ok()?),
            _ => return None,
        }
    }
    Some(PfRef {
        token: token?,
        pid: pid?,
    })
}

/// The token in `pfctl -E`'s output (`Token : 12345`), on whichever stream
/// it was printed.
pub(crate) fn parse_token(output: &str) -> Option<u64> {
    output.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        (key.trim() == "Token")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// What pf reports — read back, never inferred from having asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observed {
    pub enabled: bool,
    pub block_all_loaded: bool,
    /// The live ruleset has IPv6 rules (the leak block always does).
    pub has_inet6: bool,
    /// Our marker anchor is loaded (the block-all or the IPv6 leak block).
    pub marker_loaded: bool,
    /// The utun interfaces the live ruleset permits (MR-1125, P2-1).
    pub tunnel_permits: Vec<String>,
}

impl Observed {
    /// Both reads, or why pf could not be read.
    pub(crate) fn read(pf: &impl Pf) -> Result<Self, String> {
        let info = pf.info()?;
        let rules = pf.rules()?;
        Ok(Self {
            enabled: parse_enabled(&info),
            block_all_loaded: block_all_loaded(&rules),
            has_inet6: rules.contains("inet6"),
            marker_loaded: marker_loaded(&rules),
            tunnel_permits: tunnel_permits(&rules),
        })
    }

    /// Traffic is blocked only while pf is running AND the block-all is its
    /// main ruleset. A loaded ruleset in a disabled pf is inert.
    pub(crate) fn enforcing(&self) -> bool {
        self.enabled && self.block_all_loaded
    }
}

/// ` (<why>)` for an error worth carrying into another message.
fn because(r: &Result<(), String>) -> String {
    match r {
        Ok(()) => String::new(),
        Err(e) => format!(" ({e})"),
    }
}

/// The block-all's inputs that live outside `PfState`, read under the same
/// lock as the state (P3-3): the relay, the control-plane addresses, our
/// euid, Local Network Sharing.
#[derive(Debug, Clone)]
pub(crate) struct Inputs {
    pub relay: Option<Ipv4Addr>,
    pub control_plane: Vec<Ipv4Addr>,
    /// The control-plane generation `control_plane` covers (N5).
    pub control_plane_gen: u64,
    pub euid: u32,
    pub lan_sharing: bool,
}

/// What the macOS kill switch knows about pf, and the only code that changes
/// it. `killswitch.rs` keeps one of these behind a single async lock and
/// mirrors `enforcing` / `loaded` into atomics for the lock-free status probe.
#[derive(Debug)]
pub(crate) struct PfState {
    /// Our block-all is, or may be, pf's main ruleset — so a lift is owed.
    /// Follows pf's read-back, and stays set whenever pf cannot be read.
    pub loaded: bool,
    /// ...and pf is enforcing it. What the status reports as "blocking".
    pub enforcing: bool,
    /// F-001: a tunnel session wants the IPv6 leak block as the baseline a
    /// lift falls back to, instead of bare `/etc/pf.conf`.
    pub ipv6_baseline: bool,
    /// Our reference on pf (`pfctl -E`), held while any ruleset of ours is
    /// loaded and released with `pfctl -X` of exactly this token (P2-3) —
    /// only after `pfctl -s References` confirms it is still ours (N4).
    pub token: Option<PfRef>,
    /// MR-1125: the utun the live tunnel runs on — the ONLY interface the
    /// block-all permits. Recorded the moment the device is created.
    pub tunnel: Option<String>,
    /// N1: the block is WANTED — set by an activation, cleared by every lift
    /// request. `KILLSWITCH_ENABLED` cannot stand in for it: the give-up
    /// lifts the block but leaves the intent set (F3), so a give-up lift that
    /// failed looked wanted, was never retried, and a user's own `pfctl -f`
    /// to get the network back was undone by the watchdog.
    pub wanted: bool,
    /// N8: a ruleset of ours left by a previous run that the startup
    /// cleanup could not remove — retried by the watchdog until it goes.
    pub stale: bool,
    /// N5: the control-plane generation the LOADED block-all's table covers.
    pub table_gen: u64,
}

impl PfState {
    pub(crate) const fn new() -> Self {
        Self {
            loaded: false,
            enforcing: false,
            ipv6_baseline: false,
            token: None,
            tunnel: None,
            wanted: false,
            stale: false,
            table_gen: 0,
        }
    }

    /// Whether a connection to control-plane addresses of `generation` gets
    /// through: no block-all loaded, or one whose table covers it (N5).
    pub(crate) fn permits(&self, generation: u64) -> bool {
        !self.loaded || self.table_gen >= generation
    }

    /// The block-all for `inputs` and the recorded tunnel.
    pub(crate) fn block_all(&self, inputs: &Inputs) -> String {
        block_all_ruleset(&BlockAll {
            relay: inputs.relay,
            tunnel_interface: self.tunnel.as_deref(),
            control_plane: &inputs.control_plane,
            euid: inputs.euid,
            lan_sharing: inputs.lan_sharing,
        })
    }

    /// Whether pf's answer is the block we want: running, the block-all
    /// loaded, and — P2-1 — permitting the tunnel's own utun. The anchor
    /// alone cannot prove that: a re-load that never took leaves an older
    /// block-all, anchor and all, that drops every packet of the new tunnel.
    fn check(&self, seen: &Observed) -> Result<(), String> {
        if !seen.enabled {
            return Err(
                "pf is not enabled, so the loaded block-all ruleset is not enforced".to_string(),
            );
        }
        if !seen.block_all_loaded {
            return Err(
                "the block-all ruleset is not pf's live ruleset after loading it".to_string(),
            );
        }
        if let Some(tunnel) = self.tunnel.as_deref().filter(|t| is_utun_name(t)) {
            if !seen.tunnel_permits.iter().any(|p| p == tunnel) {
                return Err(format!(
                    "the live block-all does not permit the tunnel's interface {tunnel}"
                ));
            }
        }
        Ok(())
    }

    /// Record pf's answer. An answer pf could not give counts as STILL
    /// BLOCKING (P2-2): the flag gates every later lift, so "unknown" must
    /// keep the lift owed rather than declare it done.
    fn record(&mut self, seen: &Result<Observed, String>) {
        match seen {
            Ok(s) => {
                self.loaded = s.block_all_loaded;
                self.enforcing = s.enforcing();
            }
            Err(_) => {
                self.loaded = true;
                self.enforcing = true;
            }
        }
    }

    /// Record (and journal) the reference we hold.
    fn set_token(&mut self, pf: &impl Pf, held: Option<PfRef>) {
        self.token = held;
        pf.record_reference(held);
    }

    /// Whether `held` is still a live reference of OURS — token AND pid in
    /// `pfctl -s References` — or `None` when pf could not say.
    fn alive(pf: &impl Pf, held: PfRef) -> Option<bool> {
        pf.references()
            .ok()
            .map(|listing| parse_references(&listing).contains(&held))
    }

    /// Hold a reference on pf (P2-3): ALWAYS our own `pfctl -E`, even when pf
    /// is already running, so another tool's `-X` can never stop the pf our
    /// block depends on. One is enough, so one we hold is kept — once pf
    /// confirms it is alive and ours (N4). It used to be trusted whenever pf
    /// was running: a `pfctl -d` kills every token and someone's `-E` can
    /// start pf again, and an unreadable `pfctl -s info` counted as "pf off"
    /// and took a SECOND reference.
    fn hold_reference(&mut self, pf: &impl Pf) {
        if let Some(held) = self.token {
            match Self::alive(pf, held) {
                Some(true) => return,
                // Killed by a `pfctl -d`, or its value since issued to someone
                // else: replaced, never released.
                Some(false) => self.set_token(pf, None),
                // pf cannot say: keep ours rather than take a second.
                None => {
                    tracing::warn!(
                        "Kill switch: pf references unreadable; keeping the one we hold"
                    );
                    return;
                }
            }
        }
        match pf.take_ref() {
            Ok(Taken {
                token: Some(token),
                pid,
            }) => self.set_token(pf, Some(PfRef { token, pid })),
            Ok(Taken { token: None, pid }) => {
                // N4: the reference exists but its token was not printed.
                // Find it by its pfctl's pid, or it could never be released.
                let found = pf.references().ok().and_then(|listing| {
                    parse_references(&listing)
                        .into_iter()
                        .find(|r| r.pid == pid)
                });
                match found {
                    Some(held) => self.set_token(pf, Some(held)),
                    None => tracing::error!(
                        "Kill switch: pfctl -E took a pf reference but neither printed nor listed \
                         its token; it cannot be released"
                    ),
                }
            }
            // The read-back that follows decides; this only explains it.
            Err(e) => tracing::warn!("Kill switch: {e}; reading back whether pf is running"),
        }
    }

    /// Drop our reference, if we hold one. pf stops only if nobody else
    /// holds one — never `pfctl -d` (P2-3). Only a reference pf confirms is
    /// still OURS is released (N4); a dead one is just forgotten. A release
    /// that fails for any reason but a dead token keeps it, journalled, for
    /// the next release to retry — it used to be discarded on any error.
    fn release(&mut self, pf: &impl Pf) {
        let Some(held) = self.token else {
            return;
        };
        if Self::alive(pf, held) == Some(false) {
            self.set_token(pf, None);
            return;
        }
        match pf.release_ref(held.token) {
            Ok(()) => self.set_token(pf, None),
            Err(e) if is_dead_token_error(&e) => self.set_token(pf, None),
            Err(e) => tracing::warn!(
                "Kill switch: releasing our pf reference failed ({e}); kept for the next release"
            ),
        }
    }

    /// N3: drop our reference now — the panic hook, which cannot wait for a
    /// teardown.
    pub(crate) fn release_reference(&mut self, pf: &impl Pf) {
        self.release(pf);
    }

    /// N3: the reference a crashed earlier run left in the journal. XNU frees
    /// a token only on `-X` or `-d`, so without this every crash kept pf
    /// enabled for good. Released only if pf lists it — token AND pid — as
    /// still alive; the journal is cleared unless the release must be retried
    /// at the next start.
    pub(crate) fn release_leftover(&mut self, pf: &impl Pf, leftover: PfRef) -> Result<(), String> {
        let released = match Self::alive(pf, leftover) {
            Some(false) => Ok(()),
            None => Err("pf references could not be read".to_string()),
            Some(true) => match pf.release_ref(leftover.token) {
                Err(e) if is_dead_token_error(&e) => Ok(()),
                other => other,
            },
        };
        if released.is_ok() {
            pf.record_reference(self.token);
        }
        released
    }

    /// Load `rules` as the block-all, hold a reference on pf, and record what
    /// pf then says is in force (P1-ks-macos-pf-enable-unverified). `Ok`
    /// means pf is running with the block-all as its main ruleset.
    pub(crate) fn engage(&mut self, pf: &impl Pf, inputs: &Inputs) -> Result<(), String> {
        if let Err(e) = pf.load(&self.block_all(inputs)) {
            // All or nothing: whatever was in force before still is. Say which.
            let seen = Observed::read(pf);
            self.record(&seen);
            return Err(e);
        }
        self.stale = false;
        self.hold_reference(pf);

        let seen = Observed::read(pf);
        self.record(&seen);
        let seen = seen.map_err(|e| {
            format!("pf could not be read back after loading the block-all ({e}); it is treated as in force")
        })?;
        self.check(&seen)?;
        self.table_gen = inputs.control_plane_gen;
        Ok(())
    }

    /// Lift the block-all onto the right baseline — the IPv6 leak block while
    /// a tunnel session wants it, else `/etc/pf.conf` — and record what pf
    /// then says (P1-ks-macos-linux-deactivate-swallows-errors, P2-2).
    ///
    /// The flag used to be cleared FIRST, then whatever the teardown did was
    /// ignored, so a failed lift left the Mac blocked while every later lift
    /// (all gated on the flag) believed there was nothing to lift. Now:
    ///   * pf unreadable afterwards → still blocking, `Err`;
    ///   * the block-all still loaded — enabled OR NOT: a disabled pf holding
    ///     it is one `pfctl -e` from blocking everything — is not a finished
    ///     teardown. Onto the IPv6 baseline it is left in place (fail-safe and
    ///     usable: it still permits the tunnel; flushing would reopen the IPv6
    ///     leak). Onto `/etc/pf.conf` the session is over, so pf's filter
    ///     rules are flushed to get the network back, and that is verified too.
    ///
    /// Our pf reference is dropped only once nothing of ours is loaded.
    pub(crate) fn disengage(&mut self, pf: &impl Pf) -> Result<(), String> {
        self.wanted = false;
        let to_baseline = self.ipv6_baseline;
        let teardown = if to_baseline {
            self.load_ipv6_baseline(pf)
        } else {
            pf.load_default()
        };

        let seen = Observed::read(pf);
        self.record(&seen);
        let seen = seen.map_err(|e| {
            format!(
                "pf could not be read back after lifting the block ({e}); it is treated as still in force{}",
                because(&teardown)
            )
        })?;
        if !seen.block_all_loaded {
            if !to_baseline {
                self.release(pf);
            }
            return teardown;
        }

        if to_baseline {
            return Err(format!(
                "the block-all is still loaded{}",
                because(&teardown)
            ));
        }

        tracing::warn!(
            "Kill switch: the block-all survived restoring /etc/pf.conf{}; flushing pf's rules",
            because(&teardown)
        );
        let flushed = pf.flush_rules();
        let seen = Observed::read(pf);
        self.record(&seen);
        match seen {
            Ok(s) if !s.block_all_loaded => {
                tracing::warn!(
                    "Kill switch lifted by flushing pf's rules; /etc/pf.conf is not loaded until pf is next reloaded"
                );
                self.release(pf);
                Ok(())
            }
            Ok(_) => Err(format!(
                "the block-all is still loaded after flushing pf's rules{}{}",
                because(&teardown),
                because(&flushed)
            )),
            Err(e) => Err(format!(
                "pf could not be read back after flushing its rules ({e}); it is treated as still in force"
            )),
        }
    }

    /// A held block, re-verified on a timer (P2-3). pf is shared: another
    /// tool's `pfctl -d` or `pfctl -f` takes our block away without telling
    /// us, and before this nothing noticed until the next reconnect.
    ///
    /// A block held but no longer WANTED (N1) is a lift that failed — the
    /// give-up's included — so that lift is retried instead, and a block
    /// someone else removed is never re-imposed. `inputs` are gathered only if
    /// the block must be re-loaded. `None`: nothing held, or nothing wrong.
    pub(crate) fn watchdog(
        &mut self,
        pf: &impl Pf,
        inputs: impl FnOnce() -> Inputs,
        control_plane_gen: u64,
    ) -> Option<Result<(), String>> {
        if self.stale && !self.ipv6_baseline {
            return match self.reconcile(pf) {
                Some(result) => Some(result),
                // Gone by other hands: done. Unreadable: try again next time.
                None => (!self.stale).then_some(Ok(())),
            };
        }
        if !self.loaded {
            return self.watch_ipv6_baseline(pf);
        }
        if !self.wanted {
            return Some(self.disengage(pf));
        }
        let seen = Observed::read(pf);
        // N5: a table older than what DoH has since learned is a re-load
        // that failed — retried here.
        if seen.as_ref().is_ok_and(|s| self.check(s).is_ok()) && self.table_gen >= control_plane_gen
        {
            self.record(&seen);
            return None;
        }
        Some(self.engage(pf, &inputs()))
    }

    /// N5: a DoH answer brought control-plane addresses of `generation`. A
    /// loaded block-all whose table does not cover them is re-loaded NOW,
    /// before they are cached or dialled. `Err`: they would meet
    /// `block drop all` — the resolver then caches nothing.
    pub(crate) fn control_plane_learned(
        &mut self,
        pf: &impl Pf,
        inputs: impl FnOnce() -> Inputs,
        generation: u64,
    ) -> Result<(), String> {
        if self.permits(generation) {
            return Ok(());
        }
        self.reload_if_loaded(pf, &inputs())
    }

    /// The startup cleanup (N8): pf rulesets survive the process, so a crash
    /// mid-session leaves ours behind — the block-all (no network at all) or
    /// the IPv6 leak block (no IPv6). No session exists yet, so EVERYTHING of
    /// ours goes: `/etc/pf.conf` back, and if ours survives that, pf's filter
    /// rules are flushed; both are read back. Only rulesets carrying our
    /// marker are touched, so a third party's pf configuration is not.
    ///
    /// What is recorded comes from that read-back. It used to be "the restore
    /// failed, so enforcing" even on a disabled pf, which reported a block that
    /// was enforcing nothing — and a stale IPv6-only ruleset recorded that way
    /// got one lift attempt, which "succeeded" because no block-all was
    /// loaded, and the IPv6 block stayed. Now a remainder of ours is `stale`,
    /// and the watchdog keeps at it. `None`: nothing of ours, or unreadable.
    pub(crate) fn reconcile(&mut self, pf: &impl Pf) -> Option<Result<(), String>> {
        let ours = |s: &Observed| s.marker_loaded || s.block_all_loaded;
        match Observed::read(pf) {
            Ok(s) if ours(&s) => {}
            Ok(_) => {
                self.stale = false;
                return None;
            }
            // Unreadable: nothing to act on, and nothing learnt either.
            Err(_) => return None,
        }
        let restored = pf.load_default();
        let mut seen = Observed::read(pf);
        let mut flushed = Ok(());
        if seen.as_ref().is_ok_and(ours) {
            flushed = pf.flush_rules();
            seen = Observed::read(pf);
        }
        self.wanted = false;
        self.ipv6_baseline = false;
        self.record(&seen);
        match seen {
            Ok(s) if !ours(&s) => {
                self.stale = false;
                Some(Ok(()))
            }
            Ok(_) => {
                self.stale = true;
                Some(Err(format!(
                    "a ruleset of ours from a previous run is still loaded{}{}",
                    because(&restored),
                    because(&flushed)
                )))
            }
            Err(e) => {
                self.stale = true;
                Some(Err(format!(
                    "pf could not be read back after removing our stale ruleset ({e}); it is treated as still loaded"
                )))
            }
        }
    }

    /// N6: the F-001 IPv6 leak block, watched like the kill switch's block.
    /// It is pf's whole ruleset for the session whenever no block-all is
    /// loaded, and another tool's `pfctl -f` or `pfctl -d` used to remove it
    /// for good — IPv6 back on the physical NIC, silently, for the rest of
    /// the session. Re-loaded when pf is off or our ruleset is not there.
    fn watch_ipv6_baseline(&mut self, pf: &impl Pf) -> Option<Result<(), String>> {
        if !self.ipv6_baseline {
            return None;
        }
        let seen = Observed::read(pf);
        if seen
            .as_ref()
            .is_ok_and(|s| s.enabled && s.marker_loaded && s.has_inet6)
        {
            return None;
        }
        Some(self.load_ipv6_baseline(pf))
    }

    /// Engage the block-all if the kill switch is armed — `intent` read under
    /// the same lock as this state (P3-3), so a `set_killswitch_live(false)`
    /// that cleared it while this call waited for the lock is not undone.
    /// `Ok(false)`: not armed, pf untouched.
    pub(crate) fn activate(
        &mut self,
        pf: &impl Pf,
        inputs: &Inputs,
        intent: bool,
    ) -> Result<bool, String> {
        if !intent {
            return Ok(false);
        }
        self.wanted = true;
        self.engage(pf, inputs).map(|()| true)
    }

    /// The kill switch turned off (N2): no longer wanted, and lifted if a
    /// block-all of ours is LOADED — enforcing or not. `Ok(true)` if a lift
    /// was needed and landed. Decided here, under the caller's lock, rather
    /// than from a lock-free read of the status: that missed a block-all held
    /// by a disabled pf, and an activation still in flight.
    pub(crate) fn lift_if_loaded(&mut self, pf: &impl Pf) -> Result<bool, String> {
        self.wanted = false;
        if !self.loaded {
            return Ok(false);
        }
        self.disengage(pf).map(|()| true)
    }

    /// Re-load a block-all of ours around the current inputs (a new
    /// control-plane address). Nothing loaded, nothing to do: the next
    /// activation reads them.
    pub(crate) fn reload_if_loaded(&mut self, pf: &impl Pf, inputs: &Inputs) -> Result<(), String> {
        if !self.loaded {
            return Ok(());
        }
        if !self.wanted {
            // A failed lift: re-loading would re-impose what nobody wants.
            return self.disengage(pf);
        }
        self.engage(pf, inputs)
    }

    /// MR-1125 / P2-1: the tunnel now runs on `name`. Recorded, and a block
    /// of ours is re-loaded at once and READ BACK permitting exactly that
    /// utun. `Err` means the tunnel's traffic would meet `block drop all`,
    /// so the start must fail rather than report Connected.
    pub(crate) fn tunnel_up(
        &mut self,
        pf: &impl Pf,
        inputs: &Inputs,
        name: &str,
    ) -> Result<(), String> {
        self.tunnel = Some(name.to_string());
        self.reload_if_loaded(pf, inputs)
    }

    /// The tunnel on `name` is going away: forget it — unless a newer tunnel
    /// has been recorded since — and re-load a block of ours without its
    /// permit, so the next owner of the unit (another VPN) is not let through.
    pub(crate) fn tunnel_down(
        &mut self,
        pf: &impl Pf,
        inputs: &Inputs,
        name: &str,
    ) -> Result<(), String> {
        if self.tunnel.as_deref() != Some(name) {
            return Ok(());
        }
        self.tunnel = None;
        self.reload_if_loaded(pf, inputs)
    }

    /// F-001: the tunnel session wants the IPv6 leak block as pf's baseline.
    pub(crate) fn ipv6_on(&mut self, pf: &impl Pf) -> Result<(), String> {
        // Record the intent FIRST so that, if the kill switch is mid-block,
        // its lift lands on this baseline instead of bare /etc/pf.conf.
        self.ipv6_baseline = true;
        if self.loaded {
            // The block-all owns the ruleset and already denies IPv6.
            return Ok(());
        }
        let loaded = self.load_ipv6_baseline(pf);
        if loaded.is_err() {
            // Do not leave a claim we could not honour — nor a half-loaded
            // baseline and a reference nothing will ever release.
            self.ipv6_baseline = false;
            if let Err(e) = pf.load_default() {
                tracing::warn!("F-001: restoring /etc/pf.conf after a failed IPv6 block: {e}");
            }
            self.release(pf);
        }
        loaded
    }

    /// F-001: the tunnel session is over. Best-effort, never fails a
    /// disconnect — a stuck leak block would leave the host without IPv6.
    pub(crate) fn ipv6_off(&mut self, pf: &impl Pf) {
        if !std::mem::take(&mut self.ipv6_baseline) {
            return;
        }
        if self.loaded {
            // The kill switch owns the ruleset; with the baseline cleared its
            // own lift restores /etc/pf.conf.
            return;
        }
        if let Err(e) = pf.load_default() {
            tracing::warn!("F-001: restoring /etc/pf.conf after the IPv6 block failed: {e}");
        }
        // Even if the restore failed: with our reference gone pf stops
        // unless someone else needs it, and a stopped pf blocks nothing.
        self.release(pf);
    }

    /// Install the IPv6 leak block as pf's main ruleset, hold a reference on
    /// pf, and read back that it is enforced — a leak fix that silently
    /// failed to load is worse than none, because the UI would claim
    /// protection that is not there.
    fn load_ipv6_baseline(&mut self, pf: &impl Pf) -> Result<(), String> {
        if let Err(primary) = pf.load(IPV6_RULESET_FULL) {
            tracing::warn!(
                "F-001: anchor-preserving IPv6 ruleset failed to load ({primary}); trying the minimal ruleset"
            );
            pf.load(IPV6_RULESET_MINIMAL).map_err(|e| {
                format!("IPv6 leak block failed to load ({primary}); fallback also failed: {e}")
            })?;
        }
        self.stale = false;
        self.hold_reference(pf);
        let seen = Observed::read(pf)
            .map_err(|e| format!("IPv6 leak block could not be read back: {e}"))?;
        if !seen.enabled {
            return Err("IPv6 leak block is not enforced: pf is not enabled".to_string());
        }
        if !seen.has_inet6 {
            return Err(
                "IPv6 leak block did not take effect (pf reports no inet6 rules)".to_string(),
            );
        }
        Ok(())
    }
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

/// Every rule that mentions tcp/443 is the control-plane permit: scoped to
/// the table AND to a user. Holds for our text (`port 443 user 0`) and pf's
/// printout of it (`port = 443 user = 0`).
#[cfg(test)]
fn port_443_is_scoped(text: &str) -> bool {
    let table = format!("<{CONTROL_PLANE_TABLE}>");
    text.lines()
        .map(str::trim)
        .filter(|l| l.contains("port 443") || l.contains("port = 443"))
        .all(|l| {
            l.starts_with("pass out quick inet proto tcp")
                && l.contains(&table)
                && (l.contains(" user 0 ") || l.contains(" user = 0 "))
        })
}

/// The utun interfaces `text` permits (`pass quick on utunN ...`), in order —
/// our ruleset text and pf's printout of it alike.
pub(crate) fn tunnel_permits(text: &str) -> Vec<String> {
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

    /// P3-8: after `block drop all` there is NOTHING but the rules each input
    /// asks for — an exhaustive whitelist, not a search for one bad rule. A
    /// new permit (or a changed one: `to any`, a lost `user 0`) fails here.
    #[test]
    fn every_rule_after_the_block_is_whitelisted() {
        for control_plane in [&[DOH, API][..], &[][..]] {
            for shape in every_shape(control_plane) {
                let r = block_all_ruleset(&shape);
                let mut allowed = vec![
                    "pass quick on lo0 all".to_string(),
                    "pass out quick proto udp from any port 68 to any port 67 no state".to_string(),
                    "pass in quick proto udp from any port 67 to any port 68 no state".to_string(),
                ];
                if let Some(t) = shape.tunnel_interface {
                    allowed.push(format!("pass quick on {t} all"));
                }
                if shape.lan_sharing {
                    allowed.push(
                        "pass quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } no state"
                            .to_string(),
                    );
                }
                if !control_plane.is_empty() {
                    allowed.push(
                        "pass out quick inet proto tcp to <birdo_control> port 443 user 0 keep state"
                            .to_string(),
                    );
                }
                if let Some(ip) = shape.relay {
                    allowed.push(format!(
                        "pass out quick inet proto {{ udp tcp }} to {ip} keep state"
                    ));
                    allowed.push(format!(
                        "pass in quick inet proto {{ udp tcp }} from {ip} keep state"
                    ));
                }
                let after: Vec<&str> = r
                    .lines()
                    .skip_while(|l| *l != "block drop all")
                    .skip(1)
                    .collect();
                let mut want: Vec<&str> = allowed.iter().map(String::as_str).collect();
                let mut got = after.clone();
                want.sort_unstable();
                got.sort_unstable();
                assert_eq!(got, want, "unexpected permits in:\n{r}");
                assert!(port_443_is_scoped(&r), "{r}");

                // N10: and BEFORE it, nothing but the header — a `pass quick`
                // slipped in above `block drop all` would win over it.
                let mut header = vec![
                    "# Birdo VPN Kill Switch (main ruleset - pf evaluates this directly)"
                        .to_string(),
                    "set block-policy drop".to_string(),
                ];
                if !control_plane.is_empty() {
                    let addrs: Vec<String> =
                        control_plane.iter().map(ToString::to_string).collect();
                    header.push(format!(
                        "table <birdo_control> const {{ {} }}",
                        addrs.join(", ")
                    ));
                }
                header.push("anchor \"com.birdo.vpn\"".to_string());
                header.push("anchor \"com.birdo.vpn.blockall\"".to_string());
                header.push("block drop all".to_string());
                let before: Vec<&str> = r.lines().take(header.len()).collect();
                assert_eq!(before, header, "unexpected header in:\n{r}");
                assert_eq!(
                    r.lines().filter(|l| *l == "block drop all").count(),
                    1,
                    "{r}"
                );
            }
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
        let (set, _) = control_plane();
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

    // ── PfState, against a scripted pf ─────────────────────────────────

    /// The stock macOS /etc/pf.conf, as `pf_prints` sees it once loaded.
    const STOCK_PF_CONF: &str = "scrub-anchor \"com.apple/*\"\n\
                                 nat-anchor \"com.apple/*\"\n\
                                 rdr-anchor \"com.apple/*\"\n\
                                 dummynet-anchor \"com.apple/*\"\n\
                                 anchor \"com.apple/*\"\n\
                                 load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";

    /// pf as XNU runs it: reference-counted. `pfctl -E` adds a token, `-X`
    /// drops one, pf runs while any reference (or an anonymous `-e`) is
    /// held, and `-d` stops it for everyone and invalidates every token.
    #[derive(Default)]
    struct FakePf {
        refs: RefCell<Vec<PfRef>>,
        /// Someone ran a plain `pfctl -e`.
        anonymous: Cell<bool>,
        next_token: Cell<u64>,
        /// `pfctl -s References` fails.
        references_fail: Cell<bool>,
        /// `pfctl -X` fails for a reason other than a dead token.
        release_fails: Cell<bool>,
        /// `pfctl -E` takes a reference but prints no token.
        enable_prints_no_token: bool,
        /// What the reference journal holds (N3).
        journal: RefCell<Option<PfRef>>,
        live: RefCell<String>,
        /// `pfctl -s info` / `-s rules` fail (not root, /dev/pf busy).
        unreadable: Cell<bool>,
        /// `pfctl -f -` exits non-zero (and, being atomic, changes nothing).
        load_fails: bool,
        /// `pfctl -f -` exits 0, but the live ruleset is not ours afterwards
        /// (another writer replaced it).
        load_lost: bool,
        /// `pfctl -f /etc/pf.conf` fails (the file is missing or unreadable).
        default_fails: bool,
        /// `pfctl -F rules` fails.
        flush_fails: bool,
        /// `pfctl -E` fails and pf stays off.
        enable_fails: bool,
        /// `pfctl -E` prints a token, and pf is still off.
        enable_lies: bool,
        loads: Cell<u32>,
        take_ref_calls: Cell<u32>,
        released: RefCell<Vec<u64>>,
        flush_calls: Cell<u32>,
    }

    impl FakePf {
        fn running(&self) -> bool {
            self.anonymous.get() || !self.refs.borrow().is_empty()
        }
        /// A fresh reference: the next token, from a fresh pfctl pid.
        fn mint(&self) -> PfRef {
            self.next_token.set(self.next_token.get() + 1);
            PfRef {
                token: 1000 + self.next_token.get(),
                pid: 50_000 + self.next_token.get() as u32,
            }
        }
        /// Another tool's `pfctl -E`.
        fn third_party_takes_a_ref(&self) -> u64 {
            let held = self.mint();
            self.refs.borrow_mut().push(held);
            held.token
        }
        /// Another tool's `pfctl -E` that happens to get `token` — XNU token
        /// values can recur after a `pfctl -d`.
        fn third_party_takes_token(&self, token: u64) {
            let pid = self.mint().pid;
            self.refs.borrow_mut().push(PfRef { token, pid });
        }
        /// Another tool's `pfctl -X`.
        fn third_party_releases(&self, token: u64) {
            self.refs.borrow_mut().retain(|r| r.token != token);
        }
        fn holds(&self, held: PfRef) -> bool {
            self.refs.borrow().contains(&held)
        }
        /// Another tool's `pfctl -d`: pf stops for everyone, tokens die.
        fn third_party_disables(&self) {
            self.refs.borrow_mut().clear();
            self.anonymous.set(false);
        }
    }

    impl Pf for FakePf {
        fn info(&self) -> Result<String, String> {
            if self.unreadable.get() {
                return Err("pfctl: /dev/pf: Permission denied".to_string());
            }
            Ok(if self.running() {
                "Status: Enabled for 0 days 00:01:02".to_string()
            } else {
                "Status: Disabled for 0 days 00:00:00".to_string()
            })
        }
        fn rules(&self) -> Result<String, String> {
            if self.unreadable.get() {
                return Err("pfctl: /dev/pf: Permission denied".to_string());
            }
            Ok(self.live.borrow().clone())
        }
        fn load(&self, rules: &str) -> Result<(), String> {
            self.loads.set(self.loads.get() + 1);
            if self.load_fails {
                return Err("pfctl load ruleset failed: syntax error".to_string());
            }
            if !self.load_lost {
                *self.live.borrow_mut() = pf_prints(rules);
            }
            Ok(())
        }
        fn load_default(&self) -> Result<(), String> {
            if self.default_fails {
                return Err("pfctl: /etc/pf.conf: No such file or directory".to_string());
            }
            *self.live.borrow_mut() = pf_prints(STOCK_PF_CONF);
            Ok(())
        }
        fn flush_rules(&self) -> Result<(), String> {
            self.flush_calls.set(self.flush_calls.get() + 1);
            if self.flush_fails {
                return Err("pfctl -F rules failed".to_string());
            }
            self.live.borrow_mut().clear();
            Ok(())
        }
        fn take_ref(&self) -> Result<Taken, String> {
            self.take_ref_calls.set(self.take_ref_calls.get() + 1);
            if self.enable_fails {
                return Err("pfctl -E failed: /dev/pf: Resource busy".to_string());
            }
            let held = self.mint();
            if !self.enable_lies {
                self.refs.borrow_mut().push(held);
            }
            Ok(Taken {
                token: (!self.enable_prints_no_token).then_some(held.token),
                pid: held.pid,
            })
        }
        /// As the macOS runner printed it.
        fn references(&self) -> Result<String, String> {
            if self.references_fail.get() {
                return Err("pfctl -s References failed: /dev/pf: Resource busy".to_string());
            }
            let refs = self.refs.borrow();
            if refs.is_empty() {
                return Ok("No pf starter references held\n".to_string());
            }
            let mut out = String::from(
                "TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n",
            );
            for r in refs.iter() {
                out.push_str(&format!(
                    "{:<8} pfctl                        {:<24} 0 days 00:00:00\n",
                    r.pid, r.token
                ));
            }
            Ok(out)
        }
        /// With the messages the macOS runner printed.
        fn release_ref(&self, token: u64) -> Result<(), String> {
            self.released.borrow_mut().push(token);
            if self.release_fails.get() {
                return Err("pfctl -X could not run: Resource temporarily unavailable".to_string());
            }
            if !self.running() {
                return Err("pfctl -X failed: pfctl: pf not enabled".to_string());
            }
            let mut refs = self.refs.borrow_mut();
            let Some(i) = refs.iter().position(|r| r.token == token) else {
                return Err("pfctl -X failed: pfctl: pf: token invalid".to_string());
            };
            refs.remove(i);
            Ok(())
        }
        fn record_reference(&self, held: Option<PfRef>) {
            *self.journal.borrow_mut() = held;
        }
    }

    fn inputs() -> Inputs {
        Inputs {
            relay: Some(Ipv4Addr::new(203, 0, 113, 7)),
            control_plane: vec![DOH],
            control_plane_gen: 1,
            euid: 0,
            lan_sharing: false,
        }
    }

    /// The inputs once DoH has learned API's address (generation 2).
    fn inputs_with_api() -> Inputs {
        Inputs {
            control_plane: vec![DOH, API],
            control_plane_gen: 2,
            ..inputs()
        }
    }

    /// pf running our block-all around a tunnel on utun4, as engage leaves it.
    fn engaged() -> (FakePf, PfState) {
        let pf = FakePf::default();
        let mut state = PfState::new();
        state.tunnel = Some("utun4".to_string());
        assert_eq!(state.activate(&pf, &inputs(), true), Ok(true));
        (pf, state)
    }

    #[test]
    fn parse_token_reads_pfctl_e_output() {
        let out = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 13889855467069839711\n";
        assert_eq!(parse_token(out), Some(13889855467069839711));
        assert_eq!(parse_token("Token: 42"), Some(42));
        for nothing in [
            "pf enabled",
            "Token : ",
            "Token : abc",
            "Status: Enabled",
            "",
        ] {
            assert_eq!(parse_token(nothing), None, "{nothing:?}");
        }
    }

    #[test]
    fn engage_reports_blocking_once_pf_says_so() {
        let (pf, state) = engaged();
        assert!(state.loaded && state.enforcing);
        assert_eq!(state.token, pf.refs.borrow().first().copied());
        assert_eq!(pf.take_ref_calls.get(), 1);
    }

    /// P1-ks-macos-pf-enable-unverified: the old code took `Ok(_)` from
    /// `pfctl -e` whatever its exit status and stored PF_BLOCKING = true.
    #[test]
    fn a_pf_that_would_not_start_is_not_reported_as_blocking() {
        let pf = FakePf {
            enable_fails: true,
            ..Default::default()
        };
        let mut state = PfState::new();
        let e = state.engage(&pf, &inputs()).unwrap_err();
        assert!(e.contains("not enabled"), "{e}");
        assert!(!state.enforcing, "an inert ruleset is not a block");
        assert!(state.loaded, "...but it is loaded, so a lift is owed");
        assert_eq!(state.token, None);
    }

    #[test]
    fn an_exit_status_of_zero_is_not_taken_as_proof() {
        let pf = FakePf {
            enable_lies: true,
            ..Default::default()
        };
        let mut state = PfState::new();
        assert!(state.engage(&pf, &inputs()).is_err());
        assert!(!state.enforcing);
    }

    #[test]
    fn a_block_all_missing_from_pfs_live_rules_is_not_reported_as_blocking() {
        let pf = FakePf {
            load_lost: true,
            ..Default::default()
        };
        pf.anonymous.set(true);
        let mut state = PfState::new();
        let e = state.engage(&pf, &inputs()).unwrap_err();
        assert!(e.contains("not pf's live ruleset"), "{e}");
        assert!(!state.loaded && !state.enforcing);
    }

    /// pfctl -f is all or nothing, so a failed re-load (a relay move) leaves
    /// the previous block in force — and says so.
    #[test]
    fn a_failed_load_reports_whatever_is_still_in_force() {
        let (held, mut state) = engaged();
        let held = FakePf {
            load_fails: true,
            ..held
        };
        assert!(state.engage(&held, &inputs()).is_err());
        assert!(state.enforcing, "the previous block-all is still loaded");

        let none = FakePf {
            load_fails: true,
            ..Default::default()
        };
        let mut state = PfState::new();
        assert!(state.engage(&none, &inputs()).is_err());
        assert!(!state.loaded);
        assert_eq!(none.take_ref_calls.get(), 0, "nothing loaded, no reference");
    }

    // ── P2-3: pf is reference-counted ──────────────────────────────────

    /// Even on a pf someone else is running, we take our OWN reference, and
    /// our teardown drops only that one — their pf keeps running.
    #[test]
    fn a_running_pf_gets_our_own_reference_and_keeps_theirs() {
        let pf = FakePf::default();
        pf.anonymous.set(true);
        let mut state = PfState::new();
        assert_eq!(state.engage(&pf, &inputs()), Ok(()));
        assert_eq!(pf.take_ref_calls.get(), 1, "always our own -E");
        let ours = state.token.unwrap();

        assert_eq!(state.disengage(&pf), Ok(()));
        assert_eq!(*pf.released.borrow(), vec![ours.token], "only our token");
        assert!(pf.running(), "their pf is not ours to stop");
    }

    /// The race the anonymous `-e` lost: a third party's `-X` cannot stop
    /// the pf our block depends on, because we hold a reference of our own.
    #[test]
    fn another_tools_release_does_not_stop_our_block() {
        let pf = FakePf::default();
        let theirs = pf.third_party_takes_a_ref();
        let mut state = PfState::new();
        state.engage(&pf, &inputs()).unwrap();
        pf.third_party_releases(theirs);
        assert!(pf.running());
        assert!(Observed::read(&pf).unwrap().enforcing());
    }

    #[test]
    fn a_reference_we_hold_is_not_doubled() {
        let (pf, mut state) = engaged();
        state.engage(&pf, &inputs()).unwrap();
        state.engage(&pf, &inputs()).unwrap();
        assert_eq!(pf.take_ref_calls.get(), 1);
        assert_eq!(pf.refs.borrow().len(), 1);
    }

    #[test]
    fn the_watchdog_leaves_a_healthy_block_alone() {
        let (pf, mut state) = engaged();
        let loads = pf.loads.get();
        assert_eq!(state.watchdog(&pf, inputs, 1), None);
        assert_eq!(pf.loads.get(), loads, "nothing re-loaded");
        assert!(state.enforcing);
    }

    /// Another tool's `pfctl -d` stops pf for everyone and kills our token.
    /// The watchdog notices and re-engages with a NEW reference.
    #[test]
    fn the_watchdog_restores_a_block_another_tool_disabled() {
        let (pf, mut state) = engaged();
        let old = state.token.unwrap();
        pf.third_party_disables();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(state.enforcing && pf.running());
        assert_ne!(state.token, Some(old), "the dead token was replaced");
        assert!(
            pf.released.borrow().is_empty(),
            "a dead token is not released"
        );
    }

    /// ...and a block-all replaced by another tool's `pfctl -f`.
    #[test]
    fn the_watchdog_restores_a_block_another_tool_replaced() {
        let (pf, mut state) = engaged();
        pf.load_default().unwrap();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(block_all_loaded(&pf.rules().unwrap()));
    }

    /// Kill switch off with a block still held: that is a lift that failed
    /// earlier, so the watchdog retries the LIFT, never the block.
    #[test]
    fn the_watchdog_retries_an_owed_lift_when_the_kill_switch_is_off() {
        let (pf, mut state) = engaged();
        state.wanted = false;
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(!state.loaded && !pf.running());
    }

    /// N1: the give-up lifts but leaves KILLSWITCH_ENABLED set. A give-up
    /// lift that FAILED must still be retried — it used to look wanted.
    #[test]
    fn a_failed_give_up_lift_is_retried_by_the_watchdog() {
        let (pf, mut state) = engaged();
        let stuck = FakePf {
            default_fails: true,
            flush_fails: true,
            ..pf
        };
        assert!(state.disengage(&stuck).is_err(), "the give-up's lift fails");
        assert!(state.loaded && !state.wanted);
        let pf = FakePf {
            default_fails: false,
            flush_fails: false,
            ..stuck
        };
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(!state.loaded);
        assert!(!block_all_loaded(&pf.rules().unwrap()));
    }

    /// N1: after that failed lift the user clears pf themselves
    /// (`pfctl -f /etc/pf.conf`). The watchdog must not put the block back.
    #[test]
    fn the_watchdog_never_reimposes_a_block_nobody_wants() {
        let (pf, mut state) = engaged();
        let stuck = FakePf {
            default_fails: true,
            flush_fails: true,
            ..pf
        };
        assert!(state.disengage(&stuck).is_err());
        let pf = FakePf {
            default_fails: false,
            flush_fails: false,
            ..stuck
        };
        pf.load_default().unwrap();
        let loads = pf.loads.get();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(!block_all_loaded(&pf.rules().unwrap()), "not re-imposed");
        assert_eq!(pf.loads.get(), loads, "no block-all loaded");
        assert!(!state.loaded);
    }

    /// N2: turning the kill switch off lifts a block that is LOADED, even
    /// when pf is not enforcing it — the lock-free status read missed this.
    #[test]
    fn turning_the_kill_switch_off_lifts_a_loaded_block_even_if_inert() {
        let (pf, mut state) = engaged();
        // pf stopped under us: the block-all is still loaded, nothing is
        // enforced, and the status says so.
        pf.third_party_disables();
        state.enforcing = false;
        assert_eq!(state.lift_if_loaded(&pf), Ok(true));
        assert!(!state.loaded && !state.wanted);
        assert!(!block_all_loaded(&pf.rules().unwrap()));
    }

    #[test]
    fn turning_the_kill_switch_off_with_nothing_loaded_touches_nothing() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        state.wanted = true;
        assert_eq!(state.lift_if_loaded(&pf), Ok(false));
        assert!(!state.wanted);
        assert_eq!(pf.loads.get(), 0);
    }

    /// N1: a re-load (a new tunnel, a new control-plane address) of a block
    /// nobody wants retries the lift rather than re-imposing the block.
    #[test]
    fn a_reload_of_an_unwanted_block_retries_the_lift() {
        let (pf, mut state) = engaged();
        state.wanted = false;
        assert_eq!(state.tunnel_up(&pf, &inputs(), "utun9"), Ok(()));
        assert!(!state.loaded && !block_all_loaded(&pf.rules().unwrap()));
    }

    #[test]
    fn the_watchdog_ignores_a_block_it_does_not_hold() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert_eq!(state.watchdog(&pf, inputs, 1), None);
        assert_eq!(pf.loads.get(), 0);
    }

    // ── P2-2: a read that fails is not an answer ───────────────────────

    #[test]
    fn an_unreadable_pf_after_engaging_counts_as_in_force() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        pf.unreadable.set(true);
        let e = state.engage(&pf, &inputs()).unwrap_err();
        assert!(e.contains("could not be read back"), "{e}");
        assert!(
            state.loaded && state.enforcing,
            "unknown is not 'not blocking'"
        );
    }

    #[test]
    fn an_unreadable_pf_after_a_teardown_counts_as_still_blocking() {
        let (pf, mut state) = engaged();
        pf.unreadable.set(true);
        let e = state.disengage(&pf).unwrap_err();
        assert!(e.contains("still in force"), "{e}");
        assert!(
            state.loaded,
            "the lift must stay owed, so the next one retries"
        );
        assert!(
            state.token.is_some(),
            "our reference is not dropped on a guess"
        );
    }

    // ── P1-ks-macos-linux-deactivate-swallows-errors (macOS half) ──────

    #[test]
    fn a_teardown_that_landed_clears_the_flag_and_drops_our_reference() {
        let (pf, mut state) = engaged();
        assert_eq!(state.disengage(&pf), Ok(()));
        assert!(!state.loaded && !state.enforcing);
        assert_eq!(state.token, None);
        assert!(!pf.running(), "nobody else needed pf");
    }

    /// The IPv6 fallback failing must keep the block-all (fail-safe, and it
    /// still permits the tunnel) — never flush it, which would reopen the
    /// IPv6 leak for the rest of the session.
    #[test]
    fn a_failed_ipv6_fallback_keeps_the_block_and_never_flushes() {
        let (pf, mut state) = engaged();
        state.ipv6_baseline = true;
        let pf = FakePf {
            load_fails: true,
            ..pf
        };
        let e = state.disengage(&pf).unwrap_err();
        assert!(
            e.contains("still loaded") && e.contains("IPv6 leak block failed"),
            "{e}"
        );
        assert!(state.loaded && state.enforcing);
        assert_eq!(pf.flush_calls.get(), 0);
        assert!(
            state.token.is_some() && pf.running(),
            "the block is still wanted"
        );
    }

    /// P2-2: `/etc/pf.conf` failing to load used to be a warning and a
    /// "deactivated". The session is over, so the block-all is flushed — and
    /// the flush is read back like everything else.
    #[test]
    fn a_failed_restore_falls_back_to_flushing_and_is_verified() {
        let (pf, mut state) = engaged();
        let pf = FakePf {
            default_fails: true,
            ..pf
        };
        assert_eq!(state.disengage(&pf), Ok(()));
        assert_eq!(pf.flush_calls.get(), 1);
        assert!(!state.loaded);

        let (pf, mut state) = engaged();
        let pf = FakePf {
            default_fails: true,
            flush_fails: true,
            ..pf
        };
        let e = state.disengage(&pf).unwrap_err();
        assert!(
            e.contains("still loaded") && e.contains("/etc/pf.conf"),
            "{e}"
        );
        assert!(
            state.loaded && state.enforcing,
            "the restore error is not swallowed"
        );
        assert!(state.token.is_some());
    }

    /// P2-2: a disabled pf still HOLDING the block-all is not a finished
    /// teardown — the next `pfctl -E`, ours or anyone's, blocks everything.
    #[test]
    fn a_block_all_left_in_a_disabled_pf_is_not_a_finished_teardown() {
        // Not enforcing, so not "blocking" — but still loaded, so the lift
        // goes on: the block-all is flushed and THAT is read back.
        let (pf, mut state) = engaged();
        pf.third_party_disables();
        let pf = FakePf {
            default_fails: true,
            ..pf
        };
        assert_eq!(state.disengage(&pf), Ok(()));
        assert_eq!(
            pf.flush_calls.get(),
            1,
            "a disabled pf is no reason to stop"
        );
        assert!(!block_all_loaded(&pf.rules().unwrap()));
        assert!(!state.loaded);

        // And when even the flush fails, the lift stays owed.
        let (pf, mut state) = engaged();
        pf.third_party_disables();
        let pf = FakePf {
            default_fails: true,
            flush_fails: true,
            ..pf
        };
        assert!(state.disengage(&pf).is_err());
        assert!(state.loaded, "a lift is still owed");
        assert!(!state.enforcing, "but nothing is being enforced right now");
    }

    // ── F-001 baseline ─────────────────────────────────────────────────

    #[test]
    fn the_ipv6_baseline_is_loaded_enforced_and_lifted() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert_eq!(state.ipv6_on(&pf), Ok(()));
        assert!(pf.rules().unwrap().contains("inet6") && pf.running());
        // The kill switch engages and lifts back onto the baseline,
        // keeping the one reference.
        state.engage(&pf, &inputs()).unwrap();
        assert_eq!(state.disengage(&pf), Ok(()));
        assert!(pf.rules().unwrap().contains("inet6"), "baseline retained");
        assert!(pf.running());
        assert_eq!(pf.take_ref_calls.get(), 1);
        state.ipv6_off(&pf);
        assert!(!pf.rules().unwrap().contains("inet6"));
        assert!(!pf.running(), "our reference was the only one");
    }

    #[test]
    fn an_ipv6_baseline_pf_will_not_enforce_is_refused_not_claimed() {
        let pf = FakePf {
            enable_fails: true,
            ..Default::default()
        };
        let mut state = PfState::new();
        let e = state.ipv6_on(&pf).unwrap_err();
        assert!(e.contains("not enabled"), "{e}");
        assert!(!state.ipv6_baseline, "no claim we could not honour");
        assert!(
            !pf.rules().unwrap().contains("inet6"),
            "nor a half-loaded baseline"
        );
    }

    /// While the block-all owns the ruleset it already denies IPv6: the
    /// baseline is only recorded, and released without touching pf.
    #[test]
    fn the_baseline_defers_to_a_loaded_block_all() {
        let (pf, mut state) = engaged();
        assert_eq!(state.ipv6_on(&pf), Ok(()));
        assert!(block_all_loaded(&pf.rules().unwrap()));
        state.ipv6_off(&pf);
        assert!(block_all_loaded(&pf.rules().unwrap()));
        assert!(state.loaded && state.token.is_some());
    }

    // ── P2-1 / MR-1125: the tunnel's own utun, confirmed ──────────────

    #[test]
    fn a_new_tunnel_while_blocking_is_reloaded_and_its_permit_read_back() {
        let (pf, mut state) = engaged();
        assert_eq!(state.tunnel_up(&pf, &inputs(), "utun17"), Ok(()));
        assert_eq!(
            tunnel_permits(&pf.rules().unwrap()),
            vec!["utun17".to_string()]
        );
        assert!(state.enforcing);
    }

    /// P2-1: a re-load that did not take leaves the OLD block-all — anchor,
    /// pf enabled and all — dropping every packet of the new tunnel. Only
    /// reading back the utun permit tells; the start must then fail.
    #[test]
    fn a_new_tunnel_whose_permit_never_took_fails_the_start() {
        let (pf, mut state) = engaged();
        let pf = FakePf {
            load_lost: true,
            ..pf
        };
        let e = state.tunnel_up(&pf, &inputs(), "utun17").unwrap_err();
        assert!(
            e.contains("does not permit the tunnel's interface utun17"),
            "{e}"
        );

        let (pf, mut state) = engaged();
        let pf = FakePf {
            load_fails: true,
            ..pf
        };
        assert!(state.tunnel_up(&pf, &inputs(), "utun17").is_err());
    }

    /// No block held: the name is recorded for the next activation, and pf
    /// is not touched.
    #[test]
    fn a_new_tunnel_without_a_block_is_only_recorded() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert_eq!(state.tunnel_up(&pf, &inputs(), "utun5"), Ok(()));
        assert_eq!(state.tunnel.as_deref(), Some("utun5"));
        assert_eq!(pf.loads.get(), 0);
        state.engage(&pf, &inputs()).unwrap();
        assert_eq!(
            tunnel_permits(&pf.rules().unwrap()),
            vec!["utun5".to_string()]
        );
    }

    #[test]
    fn a_tunnel_going_away_takes_its_permit_with_it() {
        let (pf, mut state) = engaged();
        assert_eq!(state.tunnel_down(&pf, &inputs(), "utun4"), Ok(()));
        assert_eq!(state.tunnel, None);
        assert!(tunnel_permits(&pf.rules().unwrap()).is_empty());
        assert!(
            state.enforcing,
            "still blocking, just without the dead utun"
        );
    }

    /// A late teardown of an OLD tunnel must not strip a newer one's permit.
    #[test]
    fn a_superseded_tunnel_going_away_changes_nothing() {
        let (pf, mut state) = engaged();
        state.tunnel_up(&pf, &inputs(), "utun5").unwrap();
        let loads = pf.loads.get();
        assert_eq!(state.tunnel_down(&pf, &inputs(), "utun4"), Ok(()));
        assert_eq!(state.tunnel.as_deref(), Some("utun5"));
        assert_eq!(pf.loads.get(), loads);
    }

    #[test]
    fn the_watchdog_restores_a_lost_tunnel_permit() {
        let (pf, mut state) = engaged();
        pf.load(&ruleset(None, &[DOH])).unwrap();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert_eq!(
            tunnel_permits(&pf.rules().unwrap()),
            vec!["utun4".to_string()]
        );
    }

    // ── N8: the startup cleanup ────────────────────────────────────────

    /// A pf left by a crashed previous run: `rules` loaded, our process
    /// holding no reference, pf running or not.
    fn left_behind(rules: &str, running: bool) -> FakePf {
        let pf = FakePf::default();
        *pf.live.borrow_mut() = pf_prints(rules);
        pf.anonymous.set(running);
        pf
    }

    #[test]
    fn nothing_of_ours_at_startup_is_left_alone() {
        let pf = left_behind(STOCK_PF_CONF, true);
        let mut state = PfState::new();
        assert_eq!(state.reconcile(&pf), None);
        assert_eq!(pf.loads.get(), 0);
        assert_eq!(pf.flush_calls.get(), 0);
    }

    #[test]
    fn a_stale_block_all_is_removed_at_startup() {
        let pf = left_behind(&ruleset(Some("utun4"), &[DOH]), true);
        let mut state = PfState::new();
        assert_eq!(state.reconcile(&pf), Some(Ok(())));
        assert!(!state.loaded && !state.enforcing && !state.stale);
        assert!(!marker_loaded(&pf.rules().unwrap()));
    }

    /// N8: in a DISABLED pf the stale block-all enforces nothing. The old
    /// cleanup recorded "enforcing" whenever its restore failed.
    #[test]
    fn a_stale_block_in_a_disabled_pf_is_owed_but_never_reported_enforcing() {
        let pf = FakePf {
            default_fails: true,
            flush_fails: true,
            ..left_behind(&ruleset(Some("utun4"), &[DOH]), false)
        };
        let mut state = PfState::new();
        assert!(matches!(state.reconcile(&pf), Some(Err(_))));
        assert!(state.loaded, "a lift is owed");
        assert!(!state.enforcing, "pf is disabled: nothing is enforced");
        assert!(!state.wanted);
    }

    /// N8: the IPv6-only remainder and an unloadable /etc/pf.conf: flushed.
    #[test]
    fn a_stale_ipv6_block_survives_no_unloadable_pf_conf() {
        let pf = FakePf {
            default_fails: true,
            ..left_behind(IPV6_RULESET_FULL, true)
        };
        let mut state = PfState::new();
        assert_eq!(state.reconcile(&pf), Some(Ok(())));
        assert_eq!(pf.flush_calls.get(), 1);
        assert!(!marker_loaded(&pf.rules().unwrap()));
    }

    /// N8: and if even the flush fails, it is not given up on after one
    /// lift that "succeeded" because no block-all was loaded: the watchdog
    /// keeps at it until the remainder is gone.
    #[test]
    fn a_stale_ipv6_block_that_will_not_go_is_retried_until_it_does() {
        let stuck = FakePf {
            default_fails: true,
            flush_fails: true,
            ..left_behind(IPV6_RULESET_FULL, true)
        };
        let mut state = PfState::new();
        assert!(matches!(state.reconcile(&stuck), Some(Err(_))));
        assert!(state.stale && !state.loaded && !state.enforcing);
        assert!(matches!(state.watchdog(&stuck, inputs, 1), Some(Err(_))));
        assert!(state.stale, "still there, still owed");

        let pf = FakePf {
            default_fails: false,
            flush_fails: false,
            ..stuck
        };
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(!state.stale);
        assert!(!marker_loaded(&pf.rules().unwrap()));
        assert_eq!(state.watchdog(&pf, inputs, 1), None, "and then left alone");
    }

    /// A new session's own ruleset replaces a stale remainder: no clean-up
    /// fights the session's IPv6 block.
    #[test]
    fn a_new_session_replaces_a_stale_remainder() {
        let stuck = FakePf {
            default_fails: true,
            flush_fails: true,
            ..left_behind(IPV6_RULESET_FULL, true)
        };
        let mut state = PfState::new();
        let _ = state.reconcile(&stuck);
        let pf = FakePf {
            default_fails: false,
            flush_fails: false,
            ..stuck
        };
        assert_eq!(state.ipv6_on(&pf), Ok(()));
        assert!(!state.stale);
        assert_eq!(state.watchdog(&pf, inputs, 1), None);
        assert!(
            marker_loaded(&pf.rules().unwrap()),
            "the session's block stays"
        );
    }

    // ── N6: the IPv6 leak block is watched too ─────────────────────────

    fn ipv6_only() -> (FakePf, PfState) {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert_eq!(state.ipv6_on(&pf), Ok(()));
        (pf, state)
    }

    #[test]
    fn the_watchdog_leaves_a_healthy_ipv6_block_alone() {
        let (pf, mut state) = ipv6_only();
        let loads = pf.loads.get();
        assert_eq!(state.watchdog(&pf, inputs, 1), None);
        assert_eq!(pf.loads.get(), loads);
    }

    /// Another tool's `pfctl -f` replaced our ruleset: IPv6 was back on the
    /// physical NIC for the rest of the session.
    #[test]
    fn the_watchdog_restores_an_ipv6_block_another_tool_replaced() {
        let (pf, mut state) = ipv6_only();
        pf.load_default().unwrap();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        let rules = pf.rules().unwrap();
        assert!(marker_loaded(&rules) && rules.contains("inet6"), "{rules}");
    }

    #[test]
    fn the_watchdog_restores_an_ipv6_block_another_tool_disabled() {
        let (pf, mut state) = ipv6_only();
        pf.third_party_disables();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(pf.running(), "a new reference of ours");
    }

    /// Someone else's inet6 rules are not our block.
    #[test]
    fn another_tools_inet6_rules_are_not_our_ipv6_block() {
        let (pf, mut state) = ipv6_only();
        pf.load("pass quick inet6 from any to any keep state")
            .unwrap();
        assert_eq!(state.watchdog(&pf, inputs, 1), Some(Ok(())));
        assert!(marker_loaded(&pf.rules().unwrap()));
    }

    #[test]
    fn the_marker_is_matched_exactly() {
        assert!(marker_loaded("anchor \"com.birdo.vpn\" all"));
        assert!(!marker_loaded("anchor \"com.birdo.vpn.blockall\" all"));
        assert!(!marker_loaded("anchor \"com.apple/*\" all"));
    }

    // ── N5: a new control-plane address is permitted before it is dialled ─

    #[test]
    fn a_new_control_plane_address_is_let_through_before_it_is_used() {
        let (pf, mut state) = engaged();
        assert!(!state.permits(2));
        assert_eq!(state.control_plane_learned(&pf, inputs_with_api, 2), Ok(()));
        assert!(state.permits(2));
        assert_eq!(state.table_gen, 2);
        assert!(pf.rules().is_ok());
        assert_eq!(pf.loads.get(), 2, "one re-load");
    }

    #[test]
    fn an_address_the_table_already_covers_needs_no_reload() {
        let (pf, mut state) = engaged();
        let loads = pf.loads.get();
        assert_eq!(state.control_plane_learned(&pf, inputs, 1), Ok(()));
        assert_eq!(pf.loads.get(), loads);
    }

    #[test]
    fn without_a_block_there_is_nothing_to_reload() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert!(state.permits(99));
        assert_eq!(
            state.control_plane_learned(&pf, inputs_with_api, 99),
            Ok(())
        );
        assert_eq!(pf.loads.get(), 0);
    }

    /// N5: a re-load that failed is not forgotten: the table stays at its
    /// old generation, and the watchdog retries it.
    #[test]
    fn a_failed_control_plane_reload_is_retried_by_the_watchdog() {
        let (pf, mut state) = engaged();
        let failing = FakePf {
            load_fails: true,
            ..pf
        };
        assert!(state
            .control_plane_learned(&failing, inputs_with_api, 2)
            .is_err());
        assert_eq!(state.table_gen, 1);
        assert!(!state.permits(2));

        let pf = FakePf {
            load_fails: false,
            ..failing
        };
        assert_eq!(state.watchdog(&pf, inputs_with_api, 2), Some(Ok(())));
        assert_eq!(state.table_gen, 2);
        assert!(state.permits(2));
    }

    // ── P3-3: the intent, read under the lock ──────────────────────────

    #[test]
    fn activate_leaves_pf_alone_once_the_kill_switch_is_off() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert_eq!(state.activate(&pf, &inputs(), false), Ok(false));
        assert_eq!(pf.loads.get(), 0);
        assert_eq!(state.activate(&pf, &inputs(), true), Ok(true));
        assert!(state.enforcing);
    }

    #[test]
    fn a_reload_needs_a_block_to_reload() {
        let pf = FakePf::default();
        let mut state = PfState::new();
        assert_eq!(state.reload_if_loaded(&pf, &inputs()), Ok(()));
        assert_eq!(pf.loads.get(), 0);
    }
    // ── N4: a reference is ours only while pf lists it as ours ─────────

    /// Measured on the macOS runner (pfctl -s References / -X).
    const REFERENCES_TWO: &str = "TOKENS:
PID      Process Name                 TOKEN                    TIMESTAMP
28906    pfctl                        5852851722069127749      0 days 00:00:00
28868    pfctl                        13135966724954164036     0 days 00:00:00
";

    #[test]
    fn references_parse_as_pfctl_prints_them() {
        assert_eq!(
            parse_references(REFERENCES_TWO),
            vec![
                PfRef {
                    token: 5852851722069127749,
                    pid: 28906
                },
                PfRef {
                    token: 13135966724954164036,
                    pid: 28868
                },
            ]
        );
        assert!(parse_references("No pf starter references held").is_empty());
        assert!(parse_references("").is_empty());
        // A process name with spaces still parses.
        assert_eq!(
            parse_references("7  Birdo VPN Helper  42  3 days 01:02:03"),
            vec![PfRef { token: 42, pid: 7 }]
        );
    }

    #[test]
    fn only_a_dead_token_is_a_dead_token() {
        assert!(is_dead_token_error(
            "pfctl -X failed: pfctl: pf: token invalid"
        ));
        assert!(is_dead_token_error(
            "pfctl -X failed: pfctl: pf not enabled"
        ));
        assert!(!is_dead_token_error(
            "pfctl -X could not run: Resource temporarily unavailable"
        ));
        assert!(!is_dead_token_error("pfctl -X failed: Permission denied"));
    }

    #[test]
    fn the_journal_line_round_trips() {
        let held = PfRef {
            token: 13135966724954164036,
            pid: 28868,
        };
        assert_eq!(decode_reference(&encode_reference(held)), Some(held));
        for junk in [
            "",
            "token=1",
            "pid=2",
            "token=x pid=2",
            "token=1 pid=2 extra=3",
        ] {
            assert_eq!(decode_reference(junk), None, "{junk:?}");
        }
    }

    /// N4: XNU token values can recur. After a `pfctl -d` killed ours,
    /// another tool's reference can carry the SAME value: it is not ours to
    /// keep, and `-X` of that value would drop THEIRS.
    #[test]
    fn a_recurring_token_value_is_never_taken_for_ours() {
        let (pf, mut state) = engaged();
        let ours = state.token.unwrap();
        pf.third_party_disables();
        pf.third_party_takes_token(ours.token);

        // Re-engaging takes a reference of our own instead of trusting it...
        state.engage(&pf, &inputs()).unwrap();
        assert_ne!(state.token, Some(ours));
        // ...and our teardown never -X'es their value.
        assert_eq!(state.disengage(&pf), Ok(()));
        assert!(!pf.released.borrow().contains(&ours.token));
        assert!(
            pf.refs.borrow().iter().any(|r| r.token == ours.token),
            "theirs survives"
        );
    }

    /// N4: an unreadable pf is not "pf off": no second reference is taken.
    #[test]
    fn an_unreadable_pf_never_takes_a_second_reference() {
        let (pf, mut state) = engaged();
        pf.references_fail.set(true);
        pf.unreadable.set(true);
        let _ = state.engage(&pf, &inputs());
        assert_eq!(pf.take_ref_calls.get(), 1);
        assert_eq!(pf.refs.borrow().len(), 1);
    }

    /// N4: a release that fails for any reason but a dead token keeps the
    /// token — journalled — and the next release retries it.
    #[test]
    fn a_release_that_must_be_retried_keeps_the_token() {
        let (pf, mut state) = engaged();
        let ours = state.token.unwrap();
        pf.release_fails.set(true);
        assert_eq!(state.disengage(&pf), Ok(()), "the block itself is lifted");
        assert_eq!(state.token, Some(ours));
        assert_eq!(*pf.journal.borrow(), Some(ours));
        assert!(pf.holds(ours));

        pf.release_fails.set(false);
        assert_eq!(state.lift_if_loaded(&pf), Ok(false));
        state.disengage(&pf).unwrap();
        assert_eq!(state.token, None);
        assert!(!pf.holds(ours) && !pf.running());
        assert_eq!(*pf.journal.borrow(), None);
    }

    /// N4: `pfctl -E` took a reference but printed no token: it is found by
    /// the pid of that pfctl, so it can still be released.
    #[test]
    fn a_reference_whose_token_was_not_printed_is_found_by_its_pid() {
        let pf = FakePf {
            enable_prints_no_token: true,
            ..Default::default()
        };
        let mut state = PfState::new();
        state.tunnel = Some("utun4".to_string());
        assert_eq!(state.activate(&pf, &inputs(), true), Ok(true));
        let held = state.token.expect("recovered from the listing");
        assert!(pf.holds(held));
        state.disengage(&pf).unwrap();
        assert!(!pf.running(), "and released");
    }

    // ── N3: a crash must not leak our reference ────────────────────────

    /// The panic hook drops our reference at once (when the lock is free).
    #[test]
    fn the_panic_hook_releases_our_reference() {
        let (pf, mut state) = engaged();
        let ours = state.token.unwrap();
        state.release_reference(&pf);
        assert!(!pf.holds(ours) && !pf.running());
        assert_eq!(*pf.journal.borrow(), None);
    }

    #[test]
    fn every_change_of_reference_is_journalled() {
        let (pf, mut state) = engaged();
        assert_eq!(*pf.journal.borrow(), state.token);
        assert!(pf.journal.borrow().is_some());
        state.disengage(&pf).unwrap();
        assert_eq!(*pf.journal.borrow(), None);
    }

    /// A crashed run's reference is released at the next start — only if pf
    /// still lists it, token AND pid.
    #[test]
    fn a_crashed_runs_reference_is_released_at_the_next_start() {
        let pf = FakePf::default();
        let leftover = pf.mint();
        pf.refs.borrow_mut().push(leftover);
        *pf.journal.borrow_mut() = Some(leftover);

        let mut state = PfState::new();
        assert_eq!(state.release_leftover(&pf, leftover), Ok(()));
        assert!(!pf.holds(leftover) && !pf.running());
        assert_eq!(*pf.journal.borrow(), None);
    }

    #[test]
    fn a_leftover_value_now_held_by_another_tool_is_left_alone() {
        let pf = FakePf::default();
        let leftover = PfRef {
            token: 77,
            pid: 4242,
        };
        pf.third_party_takes_token(77);
        let mut state = PfState::new();
        assert_eq!(state.release_leftover(&pf, leftover), Ok(()));
        assert!(pf.released.borrow().is_empty(), "never -X'ed");
        assert!(pf.running());
        assert_eq!(*pf.journal.borrow(), None);
    }

    #[test]
    fn an_unreadable_leftover_is_kept_for_the_next_start() {
        let pf = FakePf::default();
        let leftover = pf.mint();
        pf.refs.borrow_mut().push(leftover);
        *pf.journal.borrow_mut() = Some(leftover);
        pf.references_fail.set(true);
        let mut state = PfState::new();
        assert!(state.release_leftover(&pf, leftover).is_err());
        assert_eq!(*pf.journal.borrow(), Some(leftover));
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
            assert!(port_443_is_scoped(&printed), "{printed}");
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

    fn pfctl(args: &[&str]) -> std::process::Output {
        Command::new("pfctl")
            .args(args)
            .output()
            .expect("spawn pfctl")
    }

    fn pf_running() -> bool {
        parse_enabled(&String::from_utf8_lossy(&pfctl(&["-s", "info"]).stdout))
    }

    /// `pfctl -E` as the app runs it: the reference, by token and by the pid
    /// of the pfctl that took it.
    fn take_reference() -> PfRef {
        let child = Command::new("pfctl")
            .args(["-E"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pfctl -E");
        let pid = child.id();
        let out = child.wait_with_output().expect("wait for pfctl -E");
        assert!(
            out.status.success(),
            "pfctl -E: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let printed = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        PfRef {
            token: parse_token(&printed).expect("a token"),
            pid,
        }
    }

    fn listed() -> Vec<PfRef> {
        let out = pfctl(&["-s", "References"]);
        let listing = String::from_utf8_lossy(&out.stdout).into_owned();
        println!("--- pfctl -s References ---\n{listing}");
        parse_references(&listing)
    }

    /// N4/N10 against the real pfctl: a SECOND `-E` on a pf that is already
    /// running is a reference of its own, listed by its own pfctl's pid;
    /// dropping the first leaves pf running on the second; a dead token's
    /// `-X` reads as dead; dropping the last restores pf's state.
    #[test]
    #[ignore = "needs root and macOS pfctl; run by tests.yml's pf parse-check step"]
    fn a_second_reference_on_a_running_pf_is_its_own() {
        let before = pf_running();
        let first = take_reference();
        assert!(pf_running());
        let second = take_reference();
        assert_ne!(first, second);
        let refs = listed();
        assert!(refs.contains(&first) && refs.contains(&second), "{refs:?}");

        let dropped = pfctl(&["-X", &first.token.to_string()]);
        assert!(
            dropped.status.success(),
            "{}",
            String::from_utf8_lossy(&dropped.stderr)
        );
        assert!(pf_running(), "the second reference keeps pf running");
        let refs = listed();
        assert!(!refs.contains(&first) && refs.contains(&second), "{refs:?}");

        let again = pfctl(&["-X", &first.token.to_string()]);
        assert!(!again.status.success());
        let why = String::from_utf8_lossy(&again.stderr).into_owned();
        assert!(
            is_dead_token_error(&why),
            "a dead token reads as dead: {why}"
        );

        let last = pfctl(&["-X", &second.token.to_string()]);
        assert!(
            last.status.success(),
            "{}",
            String::from_utf8_lossy(&last.stderr)
        );
        assert_eq!(
            pf_running(),
            before,
            "dropping our references restores pf's state"
        );
    }

    /// P2-3 against the real pfctl: `-E` prints a token `parse_token` reads,
    /// and `-X` of exactly that token leaves pf as it was. This takes and
    /// drops one reference on the runner's pf, loading no rules.
    #[test]
    #[ignore = "needs root and macOS pfctl; run by tests.yml's pf parse-check step"]
    fn a_pf_reference_round_trips_through_its_token() {
        let before = pf_running();
        let taken = pfctl(&["-E"]);
        assert!(
            taken.status.success(),
            "pfctl -E: {}",
            String::from_utf8_lossy(&taken.stderr)
        );
        let printed = format!(
            "{}\n{}",
            String::from_utf8_lossy(&taken.stdout),
            String::from_utf8_lossy(&taken.stderr)
        );
        println!("--- pfctl -E printed ---\n{printed}");
        let token = parse_token(&printed).expect("pfctl -E printed a token parse_token reads");
        assert!(pf_running(), "a reference enables pf");
        let released = pfctl(&["-X", &token.to_string()]);
        assert!(
            released.status.success(),
            "pfctl -X {token}: {}",
            String::from_utf8_lossy(&released.stderr)
        );
        assert_eq!(
            pf_running(),
            before,
            "dropping our reference restores pf's state"
        );
    }
}
