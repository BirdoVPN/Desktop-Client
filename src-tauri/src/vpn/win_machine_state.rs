//! Process-global owner of the Windows machine state a VPN session moves aside.
//!
//! # Why this exists at all
//!
//! Parking a physical adapter on `static none` and installing a `/1` split
//! default are changes to the MACHINE. The record of them used to live inside
//! `WintunTunnel`, so every question about them became a question about tunnel
//! lifetime — and tunnel lifetime is precisely what was broken. Two
//! `WintunTunnel` values can legitimately exist over one OS adapter
//! (`Adapter::open` deliberately reuses it), and `VpnManager::tunnel` is written
//! by paths that do not dispose of what they displace, so an orphan tunnel
//! could sit on the heap believing it owned adapters a LIVE tunnel had since
//! adopted. Its `Drop` then un-parked every physical NIC and deleted the live
//! tunnel's routes while the UI read Connected (issue #98).
//!
//! So the state moves out of the tunnel. The tunnel becomes a data-plane object
//! — adapter, session, WireGuard, packet loop — and this module is the single
//! owner of everything the machine keeps.
//!
//! # The invariants (issue #105, numbered as in the design)
//!
//! * **I1 SINGLE OWNER** — at most one generation owns the park and the routes.
//!   A holder whose generation is not the current one performs NO machine-state
//!   mutation of any kind. Every public mutator here starts with that check; a
//!   non-owner is a no-op, not an error.
//! * **I4 THE RECORD IS THE PARK** — `parked ⊆ recorded` holds after every
//!   individual statement, because the loop is per adapter and the durable
//!   record for an adapter is written BEFORE that adapter is mutated. An adapter
//!   we could not read, or could not record, is never touched (issue #102).
//! * **I5 OBSERVED, NOT ASSUMED** — every read checks the command's exit status,
//!   and every park and un-park is read back before the record entry is written
//!   or cleared. A read that FAILS is a distinct outcome (`Err`), never a valid
//!   configuration: the old code turned a failed `netsh` into `(false, [])`,
//!   which is indistinguishable from a genuinely static-with-no-servers adapter
//!   — the one shape the un-park deliberately refuses to act on. The process
//!   manufactured its own unrecoverable record.
//! * **I5b SNAPSHOT ONLY AN UNPARKED ADAPTER** — an adapter already in the
//!   record is never re-read. A second generation ADOPTS the record; it never
//!   re-derives one. Re-deriving is what turned a transient leak into permanent
//!   resolver loss, because a parked adapter reads back as the terminal shape.
//! * **I6 ENUMERATION IS STRUCTURED AND CONTINUOUS** — the adapter set comes
//!   from `GetAdaptersAddresses` (numeric `OperStatus`/`IfType`, not a localised
//!   netsh column) and is re-derived for the whole life of the SESSION, not once
//!   at connect (issue #99). The session, and deliberately not the life of the
//!   park: the park outlives the session whenever an un-park could not be
//!   verified, and a refresh that outlived its tunnel would re-park every
//!   physical adapter with nothing connected — that is I13, and
//!   `refresh_live_session` is where it is enforced.
//! * **I7 STABLE IDENTITY** — entries are keyed by interface GUID, which cannot
//!   change while the adapter is parked. Adapter NAMES are user-editable in
//!   Network Connections and are localised on a fresh install; a rename would
//!   otherwise make the adapter unrestorable by every path at once. The name is
//!   re-resolved from the GUID at mutation time and is otherwise a log label.
//! * **I10 ROUTE OWNERSHIP** — a route is deleted only by the owner that
//!   installed it, matched on (destination prefix, interface index, next hop).
//!   An unattributable route (interface index 0) is never deleted (issue #100).
//! * **I12 IDEMPOTENCE** — claim/adopt/refresh over an already-parked,
//!   already-recorded adapter change neither the machine nor the record. That is
//!   what makes adoption safe and the periodic refresh possible.
//! * **I13 NO PARK MAY FOLLOW AN UN-PARK** — the refresh ticker parks only while
//!   `owner == live_session == Some(its gen)`, and there are exactly TWO
//!   un-parks in the process, both of which close `live_session` before a single
//!   netsh runs: `release_dns_locked`, as its first statement under the same
//!   lock, and `reconcile_record`, which restores off the on-disk record without
//!   the lock and so closes it by hand through `close_live_session_for_unpark`.
//!   So the ticker cannot outlive what put the machine back, on any exit path,
//!   without anyone having to remember a new one; see `refresh_live_session` for
//!   the path-by-path table.
//!   A park that follows NO un-park is idempotent (I12) and is healed by the
//!   record, which `reconcile_record` now adopts into the next process.
//!
//! # Deliberately synchronous
//!
//! Every operation must be callable from `Drop` and from the panic hook
//! (`panic = "abort"` — nothing else runs), so nothing here may `await` and the
//! lock is a `std::sync::Mutex`. `reconcile_record` does not take the lock at
//! all: it runs from the panic hook, where the lock may be held by the thread
//! that is dying.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::tunnel::{AdapterDnsSnapshot, ADAPTER_GUID, ADAPTER_NAME};

/// Hidden command helper — creates a Command that won't flash console windows.
fn cmd(program: &str) -> std::process::Command {
    crate::utils::hidden_cmd(program)
}

/// Monotonic ownership token. Never reused, never reset.
pub(super) type Gen = u64;

static NEXT_GEN: AtomicU64 = AtomicU64::new(1);

/// Mint a fresh ownership token. Cheap; take one per tunnel and one per
/// manager-driven transition.
pub(super) fn next_generation() -> Gen {
    NEXT_GEN.fetch_add(1, Ordering::SeqCst)
}

/// How often the park is re-derived while a generation owns it (I6/#99).
///
/// A NIC that comes up mid-session — a dock negotiating after resume, Wi-Fi
/// re-associating, a phone tether appearing — carries ISP resolvers alongside a
/// live tunnel until the next pass, and Windows Smart Multi-Homed Name
/// Resolution races them against the tunnel's. Ten seconds is the bound on that
/// window.
pub(super) const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// One adapter as the OS describes it, not as netsh prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdapterId {
    /// Interface GUID string, `{XXXXXXXX-...}`, upper-cased. The record key
    /// (I7). Empty only for a legacy journal entry written before this module.
    pub(super) guid: String,
    /// Current friendly name (the connection alias netsh addresses). A log
    /// label and a netsh argument — never an identity.
    pub(super) name: String,
    /// `OperStatus == IfOperStatusUp`. Numeric, so it does not drift with the
    /// display language the way the netsh `State` column does.
    pub(super) up: bool,
}

impl AdapterId {
    fn key(&self) -> String {
        record_key(&self.guid, &self.name)
    }
}

/// The one place a record key is derived, so the enumeration side and the
/// journal side cannot disagree. GUID when we have one; the upper-cased name
/// only for a legacy journal entry that predates GUID keying.
fn record_key(guid: &str, name: &str) -> String {
    if guid.is_empty() {
        format!("name:{}", name.to_ascii_uppercase())
    } else {
        guid.to_string()
    }
}

fn entry_key(entry: &AdapterDnsSnapshot) -> String {
    record_key(&entry.adapter_guid, &entry.adapter_name)
}

/// A route THIS process installed, described precisely enough to delete exactly
/// it and nothing else.
///
/// `next_hop` is the unspecified address for an on-link route (the `/1` pair on
/// the Wintun interface); otherwise the gateway the add used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OwnedRoute {
    pub(super) dest: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) next_hop: IpAddr,
    pub(super) if_index: u32,
}

struct MachineState {
    /// The generation permitted to mutate. `None` = nothing is moved aside.
    owner: Option<Gen>,
    /// The generation whose DATA PLANE is live, i.e. the one and only generation
    /// whose refresh ticker may park anything (I13).
    ///
    /// Ownership cannot answer that question: ownership outlives the session
    /// whenever an un-park could not be verified. This can, because it is set in
    /// exactly one place — [`claim_locked`], the operation that establishes a
    /// park for a live tunnel — and cleared in exactly the places where the data
    /// plane stops being the thing that owns the park: [`release_dns_locked`]
    /// (the ONLY un-park), [`begin_transition`], a [`take_ownership`] that
    /// moves the park to a different generation, and
    /// [`release_owner_if_clean`] — which is what keeps `live_session ⊆
    /// {owner}` true on every reachable path rather than on the ones someone
    /// happened to check. Never `Some(g)` unless `owner == Some(g)`; the test
    /// `clearing_the_owner_clears_the_live_session_too` IS that sentence, and
    /// it fails if this list is ever short by one again.
    live_session: Option<Gen>,
    /// The park record, keyed by adapter GUID (I7). This IS the park: an
    /// adapter is in here iff we have durably recorded it, and we only ever
    /// mutate an adapter that is already in here (I4).
    park: BTreeMap<String, AdapterDnsSnapshot>,
    /// Routes this process installed, for owner-qualified deletion (I10).
    routes: Vec<OwnedRoute>,
    /// Adapters we could not park or could not restore, keyed the same way as
    /// `park` so an entry CLEARS when that adapter recovers. Surfaced rather
    /// than only logged: the estate's rule is never to render reassurance from
    /// missing data, and an adapter that keeps ISP resolvers through a whole
    /// session while the UI reads Connected is exactly that.
    ///
    /// Also the retry list. An adapter that is recorded AND degraded is one whose
    /// park did not verify — recorded, so its origin is safe, but not actually
    /// suppressed — so the next pass re-issues the park (never the read).
    degraded: BTreeMap<String, Degradation>,
}

/// One adapter's unfinished business, and whether the USER has any stake in it.
///
/// The map does two jobs and they are not the same set. It is the RETRY LIST —
/// an entry here is re-attempted on every pass, which is what re-parks an
/// adapter whose suppression failed and what re-parks one that comes back after
/// being unplugged. It is ALSO what the UI renders.
///
/// A DORMANT entry — the adapter is recorded as parked but is not attached to
/// this machine right now — belongs in the first set and not the second. It
/// must stay recorded: the entry is the only thing that still knows the
/// adapter's real resolvers, and Windows keeps the parked `static none` in the
/// per-GUID registry key across an unplug, so an adapter dropped from the
/// record and later re-attached would come back with no resolvers and nothing
/// left to restore them from. That is #102's terminal shape reached by a
/// different road. But it is not a fault in THIS session, the user cannot act
/// on it, and reporting it made the DNS warning permanent and therefore
/// meaningless — see `restore_pass`.
struct Degradation {
    message: String,
    /// Show it to the user. False only for dormancy.
    reportable: bool,
}

impl Degradation {
    /// Something is wrong with an adapter that is here now.
    fn fault(message: String) -> Self {
        Self {
            message,
            reportable: true,
        }
    }

    /// Recorded, retryable, but not attached — nothing for the user to see.
    fn dormant(message: String) -> Self {
        Self {
            message,
            reportable: false,
        }
    }
}

static STATE: Mutex<MachineState> = Mutex::new(MachineState {
    owner: None,
    live_session: None,
    park: BTreeMap::new(),
    routes: Vec::new(),
    degraded: BTreeMap::new(),
});

/// A poisoned lock still describes real machine state, and refusing to look at
/// it would strand the adapters it names. Recover the value instead.
fn state() -> std::sync::MutexGuard<'static, MachineState> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

// ──────────────────────────────────────────────────────────────
// The I/O boundary
// ──────────────────────────────────────────────────────────────

/// Everything this module does to the machine, behind one trait so the state
/// machine can be tested against scripted failures without a device.
///
/// Reads return `Result` on purpose: "we could not read this adapter" must not
/// be representable as a configuration (I5).
pub(super) trait MachineIo {
    fn enumerate(&self) -> Result<Vec<AdapterId>, String>;
    fn read_dns(&self, adapter: &AdapterId) -> Result<AdapterDnsSnapshot, String>;
    fn park_dns(&self, adapter: &AdapterId) -> Result<(), String>;
    fn restore_dns(&self, adapter: &AdapterId, entry: &AdapterDnsSnapshot) -> Result<(), String>;
    fn persist(&self, entries: &[AdapterDnsSnapshot]) -> Result<(), String>;
    fn clear_record(&self);
    fn delete_route(&self, route: &OwnedRoute);
}

/// The real implementation: native IP Helper for enumeration, netsh for the
/// per-family reads and writes.
///
/// # Why the DNS reads did NOT move to the registry
///
/// The design for this cluster called for reading DNS origin from
/// `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip{,6}\Parameters\Interfaces\{GUID}`
/// specifically to collapse the netsh spawns. That was tried and rejected, and
/// the reason is worth more than the saving:
///
/// * The registry does not answer the question this module asks. The one
///   distinction the whole subsystem turns on — "DHCP-sourced" versus "static
///   with no servers", the shape #96 was fixed to respect and the shape #102
///   showed we must never manufacture — is not a single value there. It is
///   inferred from `NameServer` (static) being absent or empty while
///   `DhcpNameServer` (the lease's, cached and NOT cleared when the adapter is
///   parked) is populated. Reading a stale `DhcpNameServer` as the adapter's
///   live origin is precisely the "Unknown → DHCP" mapping that got design R3
///   rejected in #105, and it would reinstate the blanket-DHCP behaviour #96
///   deleted for rewriting VirtualBox/Hyper-V configuration.
/// * The v4 and v6 keys are separate hives with different value names, so the
///   registry path is a second implementation of a parser that has already
///   drifted between families twice in this file (see `parse_dns_config_v6`).
///   The netsh path is one implementation with a captured-output corpus in
///   `tunnel_dns.rs`; the registry path would have neither.
/// * I5 requires a read-back after every write, and `netsh set dns` is what
///   performs the write. Verifying it through a different mechanism than the one
///   that wrote it verifies the registry, not the resolver stack.
///
/// # What that costs, measured in spawns
///
/// A park costs 6 hidden `netsh` spawns per adapter (read v4+v6, park v4+v6,
/// read back v4+v6) and an un-park costs up to 6 more. At a typical 30-60ms per
/// hidden spawn that is ~0.2-0.4s per adapter, so ~0.6-1.2s of a connect on a
/// 3-adapter laptop.
///
/// The periodic refresh (I6/#99) costs NOTHING in steady state: `park_pass`
/// skips every adapter already in the record without reading it, so a tick on an
/// unchanged machine issues zero spawns and only an adapter that has just
/// appeared pays the 6. That is what makes a 10s interval affordable, and it is
/// why the registry saving would not have bought back the thing it was wanted
/// for. The dominant connect-time cost here was never the spawn count — it was
/// netsh's synchronous network validation at 10-25s per call, which `park_dns`
/// suppresses with `validate=no`.
///
/// Enumeration is the part that DID have to move off netsh: the netsh `State`
/// column is localised, so on a non-English Windows the old parser matched
/// nothing and control fell through to a PowerShell fallback that filtered a
/// DIFFERENT set (`-Physical`) — a language-conditional twin drift inside one
/// function, and a ~9s PowerShell cold start paid on every localised install.
pub(super) struct SystemIo;

impl MachineIo for SystemIo {
    fn enumerate(&self) -> Result<Vec<AdapterId>, String> {
        enumerate_adapters_native()
    }

    fn read_dns(&self, adapter: &AdapterId) -> Result<AdapterDnsSnapshot, String> {
        // Both families or nothing. Half a reading is not a reading: the record
        // feeds `netsh set dns` back verbatim on both, so a v6 failure with a v4
        // success would record a v6 origin we never observed.
        let (v4_was_dhcp, dns_servers) = super::tunnel_dns::read_dns_family(&adapter.name, "ipv4")?;
        let (v6_was_dhcp, dns_servers_v6) =
            super::tunnel_dns::read_dns_family(&adapter.name, "ipv6")?;
        Ok(AdapterDnsSnapshot {
            adapter_name: adapter.name.clone(),
            adapter_guid: adapter.guid.clone(),
            v4_was_dhcp,
            v6_was_dhcp,
            dns_servers,
            dns_servers_v6,
        })
    }

    fn park_dns(&self, adapter: &AdapterId) -> Result<(), String> {
        // The `ipv6` pass is NOT optional: netsh's `ip` context is IPv4-only, so
        // IPv6 resolvers (RA/RDNSS, usually an fe80:: link-local) stayed
        // registered and SMHNR kept querying them on the physical NIC. On a
        // dual-stack session the ::/1 + 8000::/1 tunnel routes do not capture
        // link-local scope, so those queries egress in the clear.
        //
        // `validate=no` is critical: without it netsh synchronously validates the
        // change against the network (NLA re-evaluation), which blocks for 10-25s
        // per call on some machines — the dominant cause of slow connects.
        //
        // `ip` and `ipv4` are aliases for the same netsh context; the write paths
        // use `ip` and the read path uses `ipv4`, as they always have.
        let name_arg = format!("name={}", adapter.name);
        let v4 = run_netsh(&[
            "interface",
            "ip",
            "set",
            "dns",
            &name_arg,
            "static",
            "none",
            "validate=no",
        ]);
        let v6 = run_netsh(&[
            "interface",
            "ipv6",
            "set",
            "dns",
            &name_arg,
            "static",
            "none",
            "validate=no",
        ]);
        join_family_results(v4, v6)
    }

    fn restore_dns(&self, adapter: &AdapterId, entry: &AdapterDnsSnapshot) -> Result<(), String> {
        let (v4_dhcp, v4_servers) = intent_v4(entry);
        let (v6_dhcp, v6_servers) = intent_v6(entry);
        // Both families, unconditionally — see `park_dns`. An adapter left with
        // its IPv6 resolvers suppressed because the IPv4 write failed is a
        // half-restored adapter that reads as restored.
        let v4 = restore_family(&adapter.name, "ip", &v4_servers, v4_dhcp);
        let v6 = restore_family(&adapter.name, "ipv6", &v6_servers, v6_dhcp);
        join_family_results(v4, v6)
    }

    fn persist(&self, entries: &[AdapterDnsSnapshot]) -> Result<(), String> {
        crate::vpn::dns_journal::record_windows(entries)
    }

    fn clear_record(&self) {
        crate::vpn::dns_journal::clear();
    }

    fn delete_route(&self, route: &OwnedRoute) {
        delete_owned_route(route);
    }
}

/// Combine the two families' outcomes without letting either short-circuit the
/// other. Ok only when BOTH succeeded; the error names every family that failed.
fn join_family_results(v4: Result<(), String>, v6: Result<(), String>) -> Result<(), String> {
    match (v4, v6) {
        (Ok(()), Ok(())) => Ok(()),
        (v4, v6) => Err([v4.err(), v6.err()]
            .into_iter()
            .flatten()
            .collect::<Vec<String>>()
            .join("; ")),
    }
}

/// Run one netsh invocation and treat a non-zero exit as a failure.
///
/// The old code issued every mutation as `let _ = ...output()`, so "restored"
/// was a claim the process made about work it never looked at (I5).
fn run_netsh(args: &[&str]) -> Result<(), String> {
    let output = cmd("netsh")
        .args(args)
        .output()
        .map_err(|e| format!("netsh could not run ({}): {}", args.join(" "), e))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "netsh {} exited {:?}: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// Write one address family's resolvers back on an adapter.
///
/// `servers` empty + `was_dhcp` = hand it back to DHCP/RA. `servers` empty and
/// NOT `was_dhcp` = the adapter was ALREADY `static` with no servers before we
/// parked it, so parking it was a no-op and un-parking must be one too. Forcing
/// DHCP there is what silently reconfigured VirtualBox / Hyper-V / OpenVPN
/// adapters on every disconnect (#96), and it is the case the origin flag exists
/// to distinguish — `was_dhcp` is NOT `servers.is_empty()`.
fn restore_family(
    adapter_name: &str,
    family: &str,
    servers: &[String],
    was_dhcp: bool,
) -> Result<(), String> {
    let name_arg = format!("name={}", adapter_name);

    if servers.is_empty() {
        if !was_dhcp {
            tracing::debug!(
                "{} ({}): was static with no servers before connect — leaving as-is",
                adapter_name,
                family
            );
            return Ok(());
        }
        return run_netsh(&[
            "interface",
            family,
            "set",
            "dns",
            &name_arg,
            "dhcp",
            "validate=no",
        ]);
    }

    for (i, dns) in servers.iter().enumerate() {
        if i == 0 {
            run_netsh(&[
                "interface",
                family,
                "set",
                "dns",
                &name_arg,
                "static",
                dns,
                "validate=no",
            ])?;
        } else {
            run_netsh(&[
                "interface",
                family,
                "add",
                "dns",
                &name_arg,
                dns,
                &format!("index={}", i + 1),
                "validate=no",
            ])?;
        }
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
// Pure shape helpers — the vocabulary the state machine reasons in
// ──────────────────────────────────────────────────────────────

/// Whether an IPv6 resolver address is link-local (`fe80::/10`), i.e. learned
/// from a Router Advertisement rather than configured by the user. Accepts the
/// zone suffix netsh prints on link-local addresses (`fe80::1%13`).
///
/// Hand-rolled rather than `Ipv6Addr::is_unicast_link_local`, which is still
/// unstable on the toolchain this crate pins.
fn is_link_local_v6(addr: &str) -> bool {
    let bare = addr.split('%').next().unwrap_or(addr);
    match bare.parse::<Ipv6Addr>() {
        Ok(ip) => {
            let o = ip.octets();
            o[0] == 0xfe && (o[1] & 0xc0) == 0x80
        }
        Err(_) => false,
    }
}

/// What `restore_dns` will WRITE for IPv4: `(hand back to DHCP?, static list)`.
///
/// Split out so the read-back can be compared against the intent rather than
/// against the record — the two differ for the link-local IPv6 case below, and
/// comparing against the wrong one would make every verified restore fail.
fn intent_v4(entry: &AdapterDnsSnapshot) -> (bool, Vec<String>) {
    if entry.dns_servers.is_empty() {
        (entry.v4_was_dhcp, Vec::new())
    } else {
        (false, entry.dns_servers.clone())
    }
}

/// IPv6 twin of [`intent_v4`], carrying the link-local rule.
///
/// A `fe80::` resolver was learned from a Router Advertisement (RDNSS); Windows
/// re-learns it the moment the adapter is back on DHCP/RA, and pinning a
/// zone-scoped address statically would outlive the router that advertised it.
/// But "Windows re-learns it" only happens if something puts the adapter BACK on
/// DHCP/RA — an adapter whose only IPv6 resolvers were link-local filters to an
/// empty list, and with the origin flag saying `static` the empty case
/// deliberately does nothing, leaving it parked with no IPv6 resolvers at all.
/// So hand it back to DHCP/RA when everything it had was link-local, and only
/// then: with NO IPv6 resolvers at all it is the genuinely-static-with-none case
/// the origin flag exists to leave alone.
fn intent_v6(entry: &AdapterDnsSnapshot) -> (bool, Vec<String>) {
    let v6_static: Vec<String> = entry
        .dns_servers_v6
        .iter()
        .filter(|dns| !is_link_local_v6(dns))
        .cloned()
        .collect();
    let had_only_link_local = !entry.dns_servers_v6.is_empty() && v6_static.is_empty();
    if v6_static.is_empty() {
        (entry.v6_was_dhcp || had_only_link_local, Vec::new())
    } else {
        (false, v6_static)
    }
}

/// Is this live reading the shape `park_dns` leaves behind — `static`, no
/// servers, on BOTH families?
///
/// This is the "is it still ours?" test. An adapter that no longer looks like
/// this has been reconfigured since — by the user fixing DNS by hand, by another
/// VPN, by a driver reinstall — and is not ours to rewrite.
fn is_parked_shape(live: &AdapterDnsSnapshot) -> bool {
    !live.v4_was_dhcp
        && live.dns_servers.is_empty()
        && !live.v6_was_dhcp
        && live.dns_servers_v6.is_empty()
}

/// Does a live reading match what `restore_dns` intended to write?
fn matches_intent(entry: &AdapterDnsSnapshot, live: &AdapterDnsSnapshot) -> bool {
    let (v4_dhcp, v4_servers) = intent_v4(entry);
    let (v6_dhcp, v6_servers) = intent_v6(entry);
    live.v4_was_dhcp == v4_dhcp
        && live.dns_servers == v4_servers
        && live.v6_was_dhcp == v6_dhcp
        && live.dns_servers_v6 == v6_servers
}

// ──────────────────────────────────────────────────────────────
// The state machine
// ──────────────────────────────────────────────────────────────

/// Park every eligible adapter that is not already recorded.
///
/// THE ORDER IS THE WHOLE POINT, and it is per adapter, per family:
///
/// ```text
/// for each eligible adapter A (by GUID):
///   1. READ  A's v4 and v6 origin.  ── fails ⇒ skip A entirely (not parked,
///                                        not recorded, surfaced)
///   2. WRITE the record entry for A durably, with the origin from (1).
///                                   ── fails ⇒ skip A entirely (not parked)
///   3. PARK  A (netsh, both families).
///   4. READ BACK A.                 ── mismatch ⇒ keep the entry, surface
/// ```
///
/// Step 1 before 3 is fidelity: a snapshot of a parked adapter is worthless
/// (I5b). Step 2 before 3 is durability: a mutation whose record is not on disk
/// is a mutation nothing can undo (I4). Step 4 after 3 is honesty: netsh exits
/// non-zero silently and the parser cannot tell that from success (I5).
///
/// Because the loop is per adapter, `parked ⊆ recorded` holds after every single
/// statement, not only at the end of a successful run. There is no such thing as
/// "the snapshot failed after some adapters were already parked": a failure at
/// adapter *k* leaves `1..k-1` parked AND recorded — a complete, restorable
/// state — and adapter *k* untouched. That is issue #102, made unaskable rather
/// than answered.
///
/// Why "skip the adapter" rather than "park it with an unknown origin": an
/// unknown origin has no safe restore. "Leave it alone" is the permanent
/// resolver loss #102 describes; "force DHCP" is #96, rewriting
/// VirtualBox/Hyper-V/OpenVPN configuration on every disconnect; "retry the read
/// later" cannot work because by then the adapter is parked and reads as the
/// terminal shape for everyone. So: never mutate what you could not read. The
/// residual risk is one adapter keeping ISP resolvers for the session, which is
/// recorded in `degraded` rather than being silent.
fn park_pass(st: &mut MachineState, io: &dyn MachineIo) {
    let adapters = match io.enumerate() {
        Ok(list) => list,
        Err(e) => {
            let msg = format!("Could not enumerate adapters to park: {}", e);
            tracing::error!("{}", msg);
            // Not an adapter key: enumeration failing is a whole-pass problem,
            // and a later successful pass overwrites it in place.
            st.degraded
                .insert("enumeration".to_string(), Degradation::fault(msg));
            return;
        }
    };

    st.degraded.remove("enumeration");

    for adapter in adapters.iter().filter(|a| a.up) {
        let key = adapter.key();

        // I5b + I12: an adapter already in the record is ADOPTED, never
        // re-read. Re-reading it now would capture the parked state (`static`,
        // no servers) as if it were the user's own configuration, for every
        // adapter at once — the mechanism that turns a transient leak into
        // permanent resolver loss.
        //
        // But recorded is not the same as suppressed. An adapter whose park
        // failed, or whose park could not be verified, is recorded (so its
        // origin is safe) and still carrying its ISP resolvers — and without a
        // retry it carries them for the WHOLE session with a log line as the
        // only trace. So the mutation is retried on every pass; the read never
        // is.
        if st.park.contains_key(&key) {
            // Occupied here means "recorded but not verifiably suppressed"; a
            // clean entry is skipped, which is what makes the pass idempotent.
            if let std::collections::btree_map::Entry::Occupied(mut slot) = st.degraded.entry(key) {
                match park_and_verify(io, adapter) {
                    Ok(()) => {
                        tracing::info!("{}: DNS suppression recovered on retry", adapter.name);
                        slot.remove();
                    }
                    Err(msg) => {
                        tracing::debug!("{} (retry)", msg);
                        // Present and still failing: a fault, even if the entry
                        // that got us here was a dormant one.
                        slot.insert(Degradation::fault(msg));
                    }
                }
            }
            continue;
        }

        // 1. READ
        let origin = match io.read_dns(adapter) {
            Ok(origin) => origin,
            Err(e) => {
                let msg = format!(
                    "{}: DNS origin unreadable ({}) — NOT parked, so this adapter keeps its \
                     resolvers for this session",
                    adapter.name, e
                );
                tracing::error!("{}", msg);
                st.degraded.insert(key, Degradation::fault(msg));
                continue;
            }
        };

        // 2. RECORD, durably, BEFORE the mutation
        st.park.insert(key.clone(), origin);
        let entries: Vec<AdapterDnsSnapshot> = st.park.values().cloned().collect();
        if let Err(e) = io.persist(&entries) {
            st.park.remove(&key);
            let msg = format!(
                "{}: could not record the pre-connect DNS ({}) — NOT parked",
                adapter.name, e
            );
            tracing::error!("{}", msg);
            st.degraded.insert(key, Degradation::fault(msg));
            continue;
        }

        // 3 + 4. PARK, then read back. The entry STAYS either way: a half-parked
        // adapter must remain restorable, and the un-park re-checks the live
        // shape anyway, so a record for an adapter that is not actually parked
        // costs one guarded read.
        match park_and_verify(io, adapter) {
            Ok(()) => {
                tracing::debug!("Parked IPv4 + IPv6 DNS on {}", adapter.name);
                st.degraded.remove(&key);
            }
            Err(msg) => {
                tracing::error!("{}", msg);
                st.degraded.insert(key, Degradation::fault(msg));
            }
        }
    }
}

/// Suppress both families on `adapter` and confirm it took.
///
/// The read-back is the honesty half of I5: netsh exits non-zero silently, and
/// the parser cannot tell that from success, so "parked" without a read-back is
/// a claim about work nobody looked at.
fn park_and_verify(io: &dyn MachineIo, adapter: &AdapterId) -> Result<(), String> {
    io.park_dns(adapter)
        .map_err(|e| format!("{}: could not suppress DNS ({})", adapter.name, e))?;
    match io.read_dns(adapter) {
        Ok(after) if is_parked_shape(&after) => Ok(()),
        Ok(_) => Err(format!(
            "{}: still carries resolvers after being parked — SMHNR may race the tunnel",
            adapter.name
        )),
        Err(e) => Err(format!(
            "{}: park could not be verified ({})",
            adapter.name, e
        )),
    }
}

/// Put back every recorded adapter, and drop from the record only the entries
/// whose read-back matched.
///
/// The mirror of [`park_pass`], and its ordering matters just as much:
///
/// ```text
/// for each recorded entry E:
///   0. Is E's adapter attached? Absent (from a SUCCESSFUL enumeration)
///                           ⇒ keep E, touch nothing, do NOT report.
///   1. READ E's live state. Not parked-shaped ⇒ drop E, touch nothing.
///                           Read FAILED       ⇒ keep E, touch nothing, report.
///   2. WRITE the recorded origin (both families).
///   3. READ BACK. Match ⇒ drop E. Mismatch ⇒ one retry, then keep E + report.
/// ```
///
/// # The record converges
///
/// Every entry has a terminal state and reaches it:
///
/// * restored and read back ⇒ dropped (3);
/// * no longer parked-shaped — the user fixed DNS by hand, another product took
///   the adapter, a driver reinstall ⇒ dropped (1);
/// * the adapter is not attached ⇒ retained, but silent, and re-examined the
///   next time it appears (0).
///
/// Step 0 is what makes that a list rather than a hole. Without it the third
/// case fell into (1)'s failed-read arm and became a hard fault re-reported on
/// every disconnect and every startup for as long as the adapter stayed away —
/// unclearable, because no restore of an absent adapter can ever succeed.
/// A retained dormant entry is the CORRECT terminal state for that case, not a
/// leak of one: it is the only surviving description of the adapter's real
/// resolvers, and dropping it would be indistinguishable from #102.
///
/// Step 1's second clause is the correction to the old behaviour: a failed read
/// used to be silently a PASS, because the snapshot helper returned
/// `Some((false, []))` on a non-zero exit — so "netsh failing to answer counts as
/// not ours" described behaviour the code did not have, and we acted on adapters
/// whose state we had failed to read.
///
/// Retaining an entry is always the safe direction. The un-park is guarded, so a
/// retained entry costs one extra guarded read next time and can never rewrite an
/// adapter that is no longer parked.
///
/// Returns whether anything was actually written back.
fn restore_pass(
    park: &mut BTreeMap<String, AdapterDnsSnapshot>,
    io: &dyn MachineIo,
    degraded: &mut BTreeMap<String, Degradation>,
) -> bool {
    // I7: address each entry by the CURRENT name for its GUID. An adapter
    // renamed while parked is still restorable; without this it would be
    // unrestorable by the process, by the journal and by the startup reconcile,
    // permanently.
    // `None` when enumeration FAILED, which is not the same as "no adapters".
    // Collapsing the two is what would make every entry look dormant on a
    // machine where enumeration is broken, and dormancy suppresses the user's
    // only warning — so the failure has to stay representable (I5).
    let present: Option<BTreeMap<String, String>> = match io.enumerate() {
        Ok(list) => Some(
            list.into_iter()
                .filter(|a| !a.guid.is_empty())
                .map(|a| (a.guid, a.name))
                .collect(),
        ),
        Err(e) => {
            // Not fatal: fall back to the recorded names, which are correct
            // unless the adapter was renamed.
            tracing::warn!("Could not enumerate adapters during DNS restore: {}", e);
            None
        }
    };
    let current_names = present.clone().unwrap_or_default();

    let mut restored_any = false;
    for key in park.keys().cloned().collect::<Vec<String>>() {
        let Some(entry) = park.get(&key).cloned() else {
            continue;
        };
        let name = current_names
            .get(&entry.adapter_guid)
            .cloned()
            .unwrap_or_else(|| entry.adapter_name.clone());
        if name != entry.adapter_name {
            tracing::info!(
                "Adapter recorded as '{}' is now named '{}' — restoring by GUID",
                entry.adapter_name,
                name
            );
        }
        let adapter = AdapterId {
            guid: entry.adapter_guid.clone(),
            name,
            up: true,
        };

        // 0. Is it even here? A recorded adapter that a SUCCESSFUL enumeration
        // does not list has been detached — a dock unplugged, a tether removed,
        // a USB NIC pulled — and this is the entry's third outcome, not a
        // failure of one of the other two.
        //
        // It used to fall through to the read below, where netsh cannot address
        // an absent adapter, and came out as "live DNS unreadable — KEEPING the
        // record": an ERROR line and a reported degradation, on every disconnect
        // and every startup, for as long as the adapter stayed away. Nothing
        // could ever clear it, because nothing could ever restore it. That is
        // the non-convergence: a permanent DNS warning the user cannot act on,
        // which is worth precisely as much as no warning at all.
        //
        // The record is still KEPT — it is the only thing that knows this
        // adapter's real resolvers, and Windows preserves the parked `static
        // none` under the interface's GUID across an unplug, so the entry is
        // exactly what heals it if it comes back. It stays on the retry list
        // too, so `park_pass` re-parks it on re-attach and `restore_pass` puts
        // it back on the next disconnect after that. It is only the REPORT it
        // leaves, because there is no fault here to report.
        if let Some(present) = &present {
            // A legacy record (pre-GUID keying) has only a name to be identified
            // by, so its presence has to be decided on the name. Without that it
            // falls into the failed-read arm below and becomes precisely the
            // permanent, unclearable warning this outcome exists to prevent.
            let attached = if entry.adapter_guid.is_empty() {
                present
                    .values()
                    .any(|n| n.eq_ignore_ascii_case(&entry.adapter_name))
            } else {
                present.contains_key(&entry.adapter_guid)
            };
            if !attached {
                let msg = format!(
                    "{}: recorded as parked but not attached — keeping the record for a re-attach",
                    entry.adapter_name
                );
                tracing::info!("{}", msg);
                degraded.insert(key, Degradation::dormant(msg));
                continue;
            }
        }

        // 1. Is it still ours?
        let live = match io.read_dns(&adapter) {
            Ok(live) => live,
            Err(e) => {
                let msg = format!(
                    "{}: live DNS unreadable during restore ({}) — leaving it alone and KEEPING \
                     the record",
                    adapter.name, e
                );
                tracing::error!("{}", msg);
                degraded.insert(key, Degradation::fault(msg));
                continue;
            }
        };
        if !is_parked_shape(&live) {
            tracing::info!(
                "{} carries resolvers again — leaving it alone",
                adapter.name
            );
            park.remove(&key);
            degraded.remove(&key);
            continue;
        }

        // 2 + 3. Write, then verify. One retry, because a single netsh failure
        // under AV is common and a second attempt costs milliseconds.
        let mut verified = false;
        let mut last_problem = String::new();
        for attempt in 1..=2 {
            match io.restore_dns(&adapter, &entry) {
                Ok(()) => restored_any = true,
                Err(e) => {
                    last_problem = format!("write failed ({})", e);
                    continue;
                }
            }
            match io.read_dns(&adapter) {
                Ok(after) if matches_intent(&entry, &after) => {
                    verified = true;
                    break;
                }
                Ok(_) => last_problem = "read-back does not match the recorded origin".to_string(),
                Err(e) => last_problem = format!("read-back failed ({})", e),
            }
            tracing::warn!(
                "{}: DNS restore attempt {} unverified — {}",
                adapter.name,
                attempt,
                last_problem
            );
        }

        if verified {
            park.remove(&key);
            degraded.remove(&key);
        } else {
            let msg = format!(
                "{}: DNS could not be verifiably restored ({}) — KEEPING the record so a later \
                 pass can finish the job",
                adapter.name, last_problem
            );
            tracing::error!("{}", msg);
            degraded.insert(key, Degradation::fault(msg));
        }
    }
    restored_any
}

/// The record is empty ⇒ nothing is moved aside ⇒ nobody owns anything.
fn release_owner_if_clean(st: &mut MachineState) {
    if st.park.is_empty() && st.routes.is_empty() {
        st.owner = None;
        // I13, and it is what makes `live_session ⊆ {owner}` a checkable
        // invariant rather than a sentence in a doc comment. Reachable with a
        // session still open through ONE door: [`release_routes_locked`] on a
        // generation whose park happens to be empty — a machine whose physical
        // NICs were all down at connect. That left `owner = None` next to
        // `live_session = Some(gen)`, which no ticker can act on (both halves
        // are required) but which contradicts the stated invariant, and an
        // invariant that is only true by accident is the shape this subsystem
        // has been rejected for five times. Both callers are teardown, so the
        // session really is over here.
        st.live_session = None;
    }
}

/// Write the park record out, or delete it when there is nothing left to
/// describe.
///
/// Deliberately NOT cleared while entries remain: those entries are then the
/// only thing that still knows what to put back (I5). "Remain" means one of the
/// two retained outcomes in [`restore_pass`] — an adapter still present whose
/// restore did not verify, or one that is not attached — and both are healed by
/// a later pass, so the file empties itself and is then deleted.
fn flush_record(park: &BTreeMap<String, AdapterDnsSnapshot>, io: &dyn MachineIo) {
    if park.is_empty() {
        io.clear_record();
        return;
    }
    let entries: Vec<AdapterDnsSnapshot> = park.values().cloned().collect();
    if let Err(e) = io.persist(&entries) {
        tracing::error!(
            "Could not update the DNS journal ({}) — an abnormal exit may restore a stale set",
            e
        );
    }
}

// ──────────────────────────────────────────────────────────────
// Public API — every mutator is owner-gated (I1)
// ──────────────────────────────────────────────────────────────

/// Take ownership for `gen` without touching anything yet.
///
/// Called at the very top of `start()`, BEFORE the first machine mutation, so
/// every route and every park that follows is attributable to this generation
/// and no other holder may undo it. Adopts whatever a previous generation left
/// in force: on a reconnect the manager deliberately holds the park and the
/// routes across the gap rather than releasing them into it, and this is where
/// the incoming tunnel picks them up.
pub(super) fn take_ownership(gen: Gen) {
    let mut st = state();
    take_ownership_locked(&mut st, gen);
}

/// Core of [`take_ownership`], over an explicit state so the tests can drive it.
fn take_ownership_locked(st: &mut MachineState, gen: Gen) {
    if st.owner == Some(gen) {
        return;
    }
    tracing::debug!(
        "Machine state ownership: {:?} -> {} ({} parked adapter(s), {} route(s) inherited)",
        st.owner,
        gen,
        st.park.len(),
        st.routes.len()
    );
    // A genuinely fresh session — nothing inherited — starts with a clean
    // degradation list, so the UI shows THIS session's problems. An adoption
    // keeps them: the adapters they describe are still unparked.
    if st.park.is_empty() && st.routes.is_empty() {
        st.degraded.clear();
    }
    // I13: the park has moved to a generation that has not claimed yet, so no
    // data plane owns it at this instant. Keeps `live_session ⊆ {owner}` an
    // invariant rather than a coincidence — the displaced generation's ticker
    // already fails the owner half, and this stops it passing the session half.
    st.live_session = None;
    st.owner = Some(gen);
}

/// Take ownership for `gen` and park everything not already parked.
///
/// This is acquire and adopt in one operation. A second generation claiming
/// while a park is in force INHERITS the record untouched and re-snapshots
/// nothing — that is the whole of the #98 DNS fix, and it is also what makes the
/// periodic refresh safe (I5b + I12).
pub(super) fn claim(gen: Gen) {
    let io = SystemIo;
    let mut st = state();
    let previous = st.owner;
    claim_locked(&mut st, &io, gen);
    let recorded = st.park.len();
    drop(st);
    match previous {
        Some(prev) if prev != gen => tracing::info!(
            "DNS park adopted from generation {} by generation {} ({} adapter(s) recorded)",
            prev,
            gen,
            recorded
        ),
        _ => tracing::debug!(
            "DNS park claimed by generation {} ({} adapter(s) recorded)",
            gen,
            recorded
        ),
    }
}

/// Core of [`claim`], over an explicit state so the tests can drive it.
///
/// This is the ONE place `live_session` is opened (I13). `claim` is called from
/// `configure_dns`, i.e. by a tunnel that has a data plane, so it is exactly the
/// moment at which a refresh ticker for `gen` becomes legitimate.
fn claim_locked(st: &mut MachineState, io: &dyn MachineIo, gen: Gen) {
    st.owner = Some(gen);
    st.live_session = Some(gen);
    park_pass(st, io);
}

/// Core of [`release_dns`]. Returns whether anything was put back.
///
/// The ownership check lives HERE, not in the caller, so there is no path to the
/// machine that skips it (I1).
fn release_dns_locked(st: &mut MachineState, io: &dyn MachineIo, gen: Gen) -> bool {
    // I13, and it is the FIRST statement on purpose. This is the only function
    // in the process that can un-park, and closing the session here — under the
    // same lock, before a single netsh runs — is what makes "no park may follow
    // an un-park" true on every exit path at once rather than on the N paths
    // someone remembered to add a flag-clear to. `refresh_live_session` takes
    // this same lock and re-reads `live_session` INSIDE it, so a pass cannot
    // interleave; a pass already blocked on the lock finds the door shut.
    //
    // Before the owner check, deliberately: a non-owner's session is over too,
    // and a stale `live_session` is exactly the residue both criticals grew from.
    if st.live_session == Some(gen) {
        st.live_session = None;
    }
    if st.owner != Some(gen) {
        tracing::debug!(
            "Generation {} asked to un-park DNS but does not own it (owner {:?}) — doing nothing",
            gen,
            st.owner
        );
        return false;
    }
    if st.park.is_empty() {
        release_owner_if_clean(st);
        return false;
    }
    let mut degraded = std::mem::take(&mut st.degraded);
    let restored = restore_pass(&mut st.park, io, &mut degraded);
    flush_record(&st.park, io);
    st.degraded = degraded;
    release_owner_if_clean(st);
    restored
}

/// Core of [`release_routes`].
fn release_routes_locked(st: &mut MachineState, io: &dyn MachineIo, gen: Gen) {
    if st.owner != Some(gen) {
        tracing::debug!(
            "Generation {} asked to remove routes but does not own them (owner {:?}) — doing \
             nothing",
            gen,
            st.owner
        );
        return;
    }
    let routes = std::mem::take(&mut st.routes);
    for route in &routes {
        io.delete_route(route);
    }
    if !routes.is_empty() {
        tracing::debug!("Removed {} owned route(s)", routes.len());
    }
    release_owner_if_clean(st);
}

/// Re-derive the park for the CURRENT owner of a LIVE session (I6/#99).
///
/// Idempotent by construction: adapters already in the record are skipped, so
/// this parks only what has appeared since.
///
/// Returns whether the caller should keep ticking. Both halves of that answer
/// are computed HERE, under the lock, and that is the point of the signature.
///
/// # Why ownership alone cannot gate the ticker, and why a flag on the tunnel
/// could not either
///
/// The refresh thread first looped on `is_owner(gen)`, and ownership does not
/// end when the session does. `release_owner_if_clean` clears the owner only
/// once the park AND the routes are empty, and [`restore_pass`] deliberately
/// RETAINS an entry it could not verifiably restore — an adapter unplugged
/// mid-session is the ordinary way to get one. So a session that ended with any
/// retained entry left `owner == Some(gen)` forever, the thread kept running
/// with no tunnel anywhere, and every ten seconds it parked every physical
/// adapter on `static none`: a machine-wide DNS blackhole with the UI reading
/// Disconnected. That is verbatim the failure design R5 was rejected for in
/// issue #105, reintroduced through the back door.
///
/// The second attempt scoped it to the session with an `AtomicBool` the tunnel
/// owned, cleared by `stop()` and by `Drop`. That is N parallel paths wearing a
/// disguise, and it took one review to find the N+1th: the updater relaunch
/// (`RunEvent::ExitRequested` with `RESTART_EXIT_CODE`) un-parks through
/// [`release_dns_at_exit`], which never sees a tunnel at all — so the flag
/// stayed set, the ticker survived the un-park, and it re-parked every physical
/// adapter on a process that was about to be replaced. The same blackhole,
/// through a second door. Adding a third clear would only invite a fourth door.
///
/// # I13: the door is the un-park, and there is only one of them
///
/// So the gate stopped being a flag that N call sites must remember to clear and
/// became a property of the state machine. Two conditions, both read from
/// `MachineState` under the one lock:
///
/// * `owner == Some(gen)` — a displaced tunnel must not park on behalf of the
///   generation that succeeded it.
/// * `live_session == Some(gen)` — a generation whose DATA PLANE is live.
///
/// `live_session` is opened in exactly one place ([`claim_locked`]) and closed
/// by every un-park (plus the two ownership moves that mean "held with no data
/// plane"). There are exactly two un-parks: [`release_dns_locked`], which closes
/// the session as its first statement while holding this lock, and
/// [`reconcile_record`], which restores off the on-disk record without the lock
/// and therefore closes the session by hand, first, through
/// [`close_live_session_for_unpark`]. Because un-parking is what closes the
/// gate, the answer to "can the ticker run after X?" is the same for every X:
///
/// | how the process/session ends                       | why no park follows |
/// |----------------------------------------------------|---------------------|
/// | `stop()`                                            | un-parks ⇒ closed   |
/// | `WintunTunnel::drop` (owner)                        | un-parks ⇒ closed   |
/// | `WintunTunnel::drop` (displaced)                    | `begin_transition`/`take_ownership` already closed it |
/// | updater relaunch (`RESTART_EXIT_CODE`)              | `release_dns_at_exit` un-parks ⇒ closed |
/// | `ExitRequested` teardown (`teardown_for_exit`)      | disconnect un-parks ⇒ closed |
/// | panic under `panic = "abort"`                       | hook un-parks off the record and closes the session by hand first ([`close_live_session_for_unpark`]) — it cannot use the lock-holding route, so it does not pretend to |
/// | `std::process::exit`, `TerminateProcess`, SIGKILL, OOM, power loss, Windows shutdown/logoff | NOTHING was un-parked, so a late pass is idempotent (I12) — it re-parks only what is already parked and already recorded. The on-disk record survives, and [`reconcile_record`] adopts it at next start. |
///
/// The last row is the whole reason a one-way "shutting down" latch would have
/// been the wrong shape: a park that follows no un-park is harmless, and a latch
/// that made it impossible would also have to be un-latched for reconnect —
/// which is another N-paths problem. The dangerous event is not "the process is
/// ending", it is "something was put back". Gate on that and there is one door.
pub(super) fn refresh_live_session(gen: Gen) -> bool {
    let io = SystemIo;
    let mut st = state();
    refresh_live_session_locked(&mut st, &io, gen)
}

/// Core of [`refresh_live_session`], over an explicit state so a test can drive
/// the ticker's EXACT body rather than a predicate that resembles it.
///
/// That distinction is the round-2 lesson. The guard lives HERE, inside the one
/// call the thread is able to make, and not in the thread's loop — so a thread
/// that ignores its stop signal (a `loop {}` that discards this return, a spawn
/// nobody remembered to bound, a future door) still cannot mutate the machine.
/// The return value only ends the thread; the gate is what protects the
/// adapters, and the two are deliberately not the same thing.
fn refresh_live_session_locked(st: &mut MachineState, io: &dyn MachineIo, gen: Gen) -> bool {
    if !should_refresh(st.owner, st.live_session, gen) {
        return false;
    }
    let before = st.park.len();
    park_pass(st, io);
    let after = st.park.len();
    if after > before {
        tracing::info!(
            "Parked {} adapter(s) that came up mid-session",
            after - before
        );
    }
    true
}

/// May the refresh ticker run another pass?
///
/// Pure, so the rule that a LIVE DATA PLANE — not ownership — bounds the ticker
/// is testable without the process-global state, without a tunnel and without a
/// ten-second sleep. Both conditions are required and neither implies the other:
/// ownership without a live session is the state a partly-failed un-park leaves
/// behind, and that is the combination that kept parking adapters on a machine
/// with no tunnel.
fn should_refresh(owner: Option<Gen>, live_session: Option<Gen>, gen: Gen) -> bool {
    live_session == Some(gen) && owner == Some(gen)
}

/// Is `gen` the current owner? The liveness predicate every teardown decision
/// should ask instead of reading `ConnectionState` (I3).
pub(super) fn is_owner(gen: Gen) -> bool {
    state().owner == Some(gen)
}

/// Move ownership to a fresh generation held by the caller, so a tunnel that is
/// about to be disposed cannot un-park or delete anything on its way out.
///
/// The park and the routes stay IN FORCE across the gap — this is the ordering
/// rule that separates "dispose the data plane" from "release the machine". The
/// incoming tunnel adopts them; if no incoming tunnel arrives, the caller must
/// [`release_all`] the returned generation.
pub(super) fn begin_transition() -> Gen {
    let gen = next_generation();
    let mut st = state();
    begin_transition_locked(&mut st, gen);
    gen
}

/// Core of [`begin_transition`], over an explicit state so the tests can drive
/// it.
fn begin_transition_locked(st: &mut MachineState, gen: Gen) {
    // I13: the park is about to be held by a generation with NO data plane.
    // Nothing may refresh it until a new tunnel claims.
    st.live_session = None;
    if st.owner.is_some() || !st.park.is_empty() || !st.routes.is_empty() {
        tracing::debug!(
            "Machine state held across a transition by generation {} (was {:?})",
            gen,
            st.owner
        );
        st.owner = Some(gen);
    }
}

/// Un-park the physical adapters. Owner only. Returns whether anything was put
/// back.
pub(super) fn release_dns(gen: Gen) -> bool {
    let io = SystemIo;
    let mut st = state();
    release_dns_locked(&mut st, &io, gen)
}

/// Delete exactly the routes this owner installed (I10). Owner only.
pub(super) fn release_routes(gen: Gen) {
    let io = SystemIo;
    let mut st = state();
    release_routes_locked(&mut st, &io, gen)
}

/// Both halves, for the emergency unwind.
pub(super) fn release_all(gen: Gen) -> bool {
    let restored = release_dns(gen);
    release_routes(gen);
    restored
}

/// Record a route THIS generation just installed, so — and only so — it can be
/// deleted later.
///
/// An interface index of 0 is refused: a route we cannot attribute to an
/// interface is a route we must never delete. That is the difference between
/// removing our own `0.0.0.0/1` and removing Cloudflare WARP's (#100).
pub(super) fn record_route(gen: Gen, route: OwnedRoute) {
    let mut st = state();
    if st.owner != Some(gen) {
        return;
    }
    if !push_owned_route(&mut st.routes, route) {
        tracing::warn!(
            "Not recording route {}/{} — with no interface index it could not be deleted \
             later in a way that is guaranteed to hit only ours",
            route.dest,
            route.prefix_len
        );
    }
}

/// Append `route` unless it is unattributable or already recorded. Returns
/// whether the route is now in the list.
///
/// Pure, so the "interface index 0 is never recorded and therefore never
/// deleted" half of I10 is testable without the process-global state, and so a
/// reconnect that re-adds the same rows records each of them once.
fn push_owned_route(routes: &mut Vec<OwnedRoute>, route: OwnedRoute) -> bool {
    if route.if_index == 0 {
        return false;
    }
    if !routes.contains(&route) {
        routes.push(route);
    }
    true
}

/// Every `(adapter, family)` this session could not park or could not restore.
///
/// Surfaced through `VpnStatus` rather than only logged: an adapter that keeps
/// its ISP resolvers for a whole session while the UI reads Connected is the
/// definition of rendering reassurance from missing data.
///
/// # Why this does not block
///
/// The Dashboard polls `get_vpn_status` on a short interval, and that is an
/// `async` Tauri command — so this synchronous call runs ON a tokio worker
/// thread. A park pass holds the machine-state lock across up to six hidden
/// `netsh` spawns PER ADAPTER at ~0.2-0.4s each, so a plain `lock()` here would
/// park a worker for seconds at a time, every poll, for as long as the pass runs
/// — on a connect, on a reconnect and on every refresh tick.
///
/// So it never waits. The report is advisory UI text, and the honest answer
/// while a pass is mutating the very map it summarises is the last complete one,
/// not a stalled thread. The cache is refreshed here and only here, so there is
/// no second place to keep in step.
pub fn degradation_report() -> Vec<String> {
    static LAST: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let Ok(st) = STATE.try_lock() else {
        return LAST.lock().unwrap_or_else(|e| e.into_inner()).clone();
    };
    let report: Vec<String> = st
        .degraded
        .values()
        .filter(|d| d.reportable)
        .map(|d| d.message.clone())
        .collect();
    drop(st);
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = report.clone();
    report
}

/// Un-park the physical adapters on behalf of whoever currently owns them.
///
/// ONLY for process-exit paths — the updater relaunch, where
/// `RunEvent::ExitRequested` carries `RESTART_EXIT_CODE` and `prevent_exit()` is
/// a documented no-op, so the normal teardown never runs. There is exactly one
/// owner at that point and the process is about to be replaced, so "whoever owns
/// it" is unambiguous.
///
/// Deliberately NOT reachable through the tunnel. Routing it through
/// `VpnManager::tunnel` is what made the #97 fix fragile: a reconnect empties
/// that Option for the whole create + handshake window, so an exit landing in
/// that window found `None` and restored nothing. The record does not live in
/// the tunnel any more.
pub fn release_dns_at_exit() -> bool {
    let owner = state().owner;
    match owner {
        Some(gen) => release_dns(gen),
        None => false,
    }
}

/// Load the entries a reconcile could NOT restore into the RUNNING process, so
/// the record on disk and the record in memory describe the same machine.
///
/// # The bug this closes
///
/// [`restore_pass`] deliberately retains an entry it could not verifiably
/// restore, and the module docs call that entry "the last thing that knows what
/// to put back". [`reconcile_record`] wrote those survivors back to disk and
/// then dropped them on the floor: `STATE.park` stayed EMPTY. A process that
/// started after a crash, a SIGKILL or a power cut therefore ran with adapters
/// parked on `static none` that it could not see, and every consequence of that
/// is worse than the leak it was recovering from:
///
/// * The next connect's [`park_pass`] does not find those adapters in `st.park`,
///   so I5b does not fire and it RE-READS them — capturing the parked shape as
///   if it were the user's own configuration. That is #102's terminal state,
///   reached from the recovery path.
/// * `park_pass` then persists `st.park`, which does not contain the survivors,
///   so `io.persist` CLOBBERS them out of the journal. The only description of
///   those adapters' real resolvers is destroyed by the act of connecting again.
/// * Nothing retries them: [`release_dns_at_exit`] reads `state().owner`, which
///   is `None`, so a clean quit does not even look.
///
/// # Why it takes an owner
///
/// The survivors are machine state that is moved aside RIGHT NOW, and this
/// module's whole contract is that such state has exactly one owner (I1). Giving
/// it a fresh generation makes every existing mechanism apply to it unchanged:
/// `take_ownership` on the next connect ADOPTS it (park non-empty ⇒ the
/// degradations are kept, which is correct — those adapters really are still
/// unrestored), `park_pass` skips re-reading it (I5b) and persists it alongside
/// the new entries, `restore_pass` retries it on the next disconnect, and
/// `release_dns_at_exit` retries it on quit. Deliberately NO `live_session`:
/// nothing is connected, so no refresh ticker may exist for this generation
/// (I13).
///
/// Refuses to act when this process has state of its own — at `setup()` there is
/// none by construction (no tunnel can be up that early), and from the panic
/// hook a non-empty `st.park` means the DYING process holds the newer truth and
/// the file must not overwrite it.
fn adopt_unrestored(st: &mut MachineState, park: BTreeMap<String, AdapterDnsSnapshot>) {
    if park.is_empty() {
        return;
    }
    if !st.park.is_empty() || st.owner.is_some() {
        tracing::debug!(
            "Not adopting {} unrestored record entr(ies) — this process already owns machine \
             state (owner {:?}, {} parked)",
            park.len(),
            st.owner,
            st.park.len()
        );
        return;
    }
    let gen = next_generation();
    tracing::warn!(
        "Adopting {} adapter(s) a previous session left parked and could not restore — \
         generation {} now owns them, so the next connect will not re-snapshot them \
         and the next disconnect or quit will retry the restore",
        park.len(),
        gen
    );
    st.park = park;
    st.owner = Some(gen);
    st.live_session = None;
}

/// Close the data plane for the one un-park that does not go through
/// [`release_dns_locked`] (I13).
///
/// # Why this is not covered by "the un-park closes the door"
///
/// [`reconcile_record`] un-parks off the ON-DISK record and deliberately never
/// takes the lock, so the act of un-parking there does not clear `live_session`
/// the way every other door does. From `setup()` that is harmless — nothing is
/// connected, so no ticker exists. From the PANIC HOOK it is not: the refresh
/// thread for the live generation is still running, and [`park_pass`] re-issues
/// the park for any adapter that is BOTH recorded and degraded (that is the
/// retry list, and an adapter whose park failed at connect is exactly one).
///
/// The composition is what bites. The hook reads that adapter, finds it is not
/// parked-shaped — correct, its park failed — drops it from the record and
/// flushes, so the file no longer describes it. A ticker pass landing in the
/// window between that flush and `panic = "abort"` reaping the process then
/// PARKS it, with nothing on disk left to put it back and no process left to
/// try: `static none` forever, which is #102's terminal shape manufactured by
/// the recovery path. The window is small, but "a park followed an un-park" is
/// the exact shape I13 exists to make unreachable, and the module's own exit
/// table claimed this row was closed when it was not.
///
/// `try_lock`, never `lock`, for the same reason [`reconcile_record`] does not
/// lock: the panicking thread may already hold it, and a `std::sync::Mutex`
/// re-entered on one thread deadlocks — hanging the process instead of aborting
/// it. Failing to take it is SAFE here, not merely tolerable: a lock held by a
/// thread that is about to `abort` is never released and never poisoned, so the
/// ticker blocks inside [`state`] until the OS reaps it. Taken or not taken, no
/// park follows the un-park.
fn close_live_session_for_unpark() {
    if let Ok(mut st) = STATE.try_lock() {
        st.live_session = None;
    }
}

/// The crash twin: put back whatever a PREVIOUS process left moved aside,
/// driven entirely off the on-disk record.
///
/// Deliberately never BLOCKS on the global lock. It runs from the panic hook,
/// where this thread may already hold it and a `std::sync::Mutex` re-entered on
/// one thread deadlocks, and from `setup()`, where no tunnel can be up and a
/// record on disk therefore means exactly one thing: a previous session did not
/// restore DNS. The restore itself is driven entirely off the passed-in record,
/// never off `STATE`; the only two touches of the global are `try_lock` and
/// skipped when it is held — closing the session up front (I13) and adopting
/// what could not be restored at the end.
///
/// Owns the record's lifecycle itself — entries it could not verifiably restore
/// stay on disk. That is why `dns_journal::reconcile` must not clear the file on
/// Windows: clearing it would destroy the last thing that knows what to put back.
pub(super) fn reconcile_record(entries: &[AdapterDnsSnapshot]) -> bool {
    if entries.is_empty() {
        return false;
    }
    // I13, and this is the ONE un-park that cannot close the gate by performing
    // it, because it deliberately does not take the lock. So it closes it by
    // hand, FIRST, before a single netsh runs — see `close_live_session_for_unpark`.
    close_live_session_for_unpark();
    let io = SystemIo;
    let mut park: BTreeMap<String, AdapterDnsSnapshot> =
        entries.iter().map(|e| (entry_key(e), e.clone())).collect();
    tracing::warn!(
        "{} adapter(s) recorded as parked by a previous session — checking whether they still are",
        park.len()
    );
    let mut degraded: BTreeMap<String, Degradation> = BTreeMap::new();
    let restored = restore_pass(&mut park, &io, &mut degraded);
    flush_record(&park, &io);
    // try_lock, never lock: this runs from the panic hook, and the thread that
    // is dying may already hold it — a std::sync::Mutex re-entered on the same
    // thread deadlocks, which would hang the process instead of aborting it.
    // Losing the adoption and the report is the acceptable outcome there; every
    // entry was already logged at ERROR, and the record is still on disk for the
    // next start. At `setup()`, where the adoption actually matters, this
    // process is single-threaded past the panic hook and the lock is free.
    if !park.is_empty() || !degraded.is_empty() {
        if let Ok(mut st) = STATE.try_lock() {
            adopt_unrestored(&mut st, park);
            st.degraded.extend(degraded);
        }
    }
    if restored {
        let _ = cmd("ipconfig").args(["/flushdns"]).output();
    }
    restored
}

// ──────────────────────────────────────────────────────────────
// Native enumeration (I6/I7)
// ──────────────────────────────────────────────────────────────

/// Render a `u128` GUID constant in the `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`
/// form `GetAdaptersAddresses` reports in `AdapterName`.
///
/// The byte order mirrors `windows::core::GUID::from_u128`, which is what
/// `Adapter::create` is handed, so the two name the same adapter. Built here
/// rather than leaning on `GUID`'s `Debug`, whose format is not part of that
/// crate's contract.
fn guid_registry_string(value: u128) -> String {
    let b = value.to_be_bytes();
    format!(
        "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

/// Enumerate every non-loopback, non-Birdo adapter with its GUID, current
/// friendly name and numeric operational status.
///
/// `GetAdaptersAddresses` is language-independent, gives the GUID (the record
/// key) and the friendly name (the netsh argument) in one call, and costs
/// microseconds. It replaces parsing the netsh `State` column against the ASCII
/// literal `"connected"`, which matched nothing on a localised Windows and fell
/// through to a PowerShell fallback that enumerated a different set.
fn enumerate_adapters_native() -> Result<Vec<AdapterId>, String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    // u64-backed so the buffer is 8-byte aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut last_rc = ERROR_SUCCESS;

    // The adapter set can change between the sizing call and the fetch, so retry
    // a bounded number of times rather than once.
    for _ in 0..4 {
        buf.clear();
        buf.resize((size as usize).div_ceil(8), 0);
        // SAFETY: `buf` is at least `size` bytes and correctly aligned; `size` is
        // an in/out parameter the OS updates with the required length.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        last_rc = rc;
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != ERROR_SUCCESS {
            return Err(format!("GetAdaptersAddresses failed: {}", rc));
        }

        let birdo_guid = guid_registry_string(ADAPTER_GUID);
        let mut out = Vec::new();
        let mut cursor = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cursor.is_null() {
            // SAFETY: the OS built this list in `buf`; `Next` is either null or
            // points at another entry inside the same buffer.
            let entry = unsafe { &*cursor };
            cursor = entry.Next as *const IP_ADAPTER_ADDRESSES_LH;

            if entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            // SAFETY: both are NUL-terminated strings owned by the buffer above.
            let guid = unsafe { entry.AdapterName.to_string() }.unwrap_or_default();
            let name = unsafe { entry.FriendlyName.to_string() }.unwrap_or_default();
            if guid.is_empty() || name.is_empty() {
                continue;
            }
            // Never park our own tunnel adapter. Matched on BOTH the name and the
            // fixed GUID: the last-resort creation path lets Windows assign a
            // GUID, and a user can rename the connection, so either alone can
            // miss.
            if name.eq_ignore_ascii_case(ADAPTER_NAME) || guid.eq_ignore_ascii_case(&birdo_guid) {
                continue;
            }
            out.push(AdapterId {
                guid: guid.to_ascii_uppercase(),
                name,
                up: entry.OperStatus == IfOperStatusUp,
            });
        }
        return Ok(out);
    }

    Err(format!(
        "GetAdaptersAddresses kept asking for a larger buffer (last rc {})",
        last_rc
    ))
}

// ──────────────────────────────────────────────────────────────
// Owner-qualified route deletion (I10 / issue #100)
// ──────────────────────────────────────────────────────────────

/// The `route.exe` argv for deleting exactly one owned route, or `None` when the
/// route cannot be deleted safely.
///
/// Pure, so the qualification is testable. `route delete <net> mask <mask>` with
/// no gateway and no interface removes EVERY route matching that destination and
/// mask, whoever installed it — Cloudflare WARP and Tailscale both install `/1`
/// split-defaults, and `local_network_sharing` made the same call for
/// `10.0.0.0/8`, which is a common corporate route. Both the gateway and the
/// interface index are therefore mandatory.
fn route_delete_argv(route: &OwnedRoute) -> Option<Vec<String>> {
    // I10: an unattributable route is never deleted.
    if route.if_index == 0 {
        return None;
    }
    let (IpAddr::V4(dest), IpAddr::V4(next_hop)) = (route.dest, route.next_hop) else {
        // IPv6 has no route.exe fallback here on purpose: the v6 routes this
        // process installs live on the Wintun interface and die with it, so the
        // native delete failing is not a leak. Adding a text-mode v6 fallback
        // would be a second, untested code path for no gain.
        return None;
    };
    if route.prefix_len > 32 {
        return None;
    }
    let mask = Ipv4Addr::from(if route.prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - route.prefix_len)
    });
    Some(vec![
        "delete".to_string(),
        dest.to_string(),
        "mask".to_string(),
        mask.to_string(),
        next_hop.to_string(),
        "IF".to_string(),
        route.if_index.to_string(),
    ])
}

/// Delete one route via `DeleteIpForwardEntry2`, the exact-row twin of the
/// `CreateIpForwardEntry2` that added it. Matching on the row means the
/// destination prefix, the interface index AND the next hop must all agree, so
/// another product's identically-shaped route on a different interface is
/// untouched.
#[allow(clippy::field_reassign_with_default)] // MIB_* FFI rows: initialise, then populate
fn delete_route_native(route: &OwnedRoute) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    if route.if_index == 0 {
        return Err("no interface index".to_string());
    }

    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: fills the row with valid defaults.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = route.if_index;
    row.DestinationPrefix.PrefixLength = route.prefix_len;
    match (route.dest, route.next_hop) {
        (IpAddr::V4(dest), IpAddr::V4(next_hop)) => {
            // Writes to SOCKADDR_INET union fields are safe; octets in network order.
            row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
                u32::from_ne_bytes(dest.octets());
            row.NextHop.Ipv4.sin_family = AF_INET;
            row.NextHop.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(next_hop.octets());
        }
        (IpAddr::V6(dest), IpAddr::V6(next_hop)) => {
            row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte = dest.octets();
            row.NextHop.Ipv6.sin6_family = AF_INET6;
            row.NextHop.Ipv6.sin6_addr.u.Byte = next_hop.octets();
        }
        _ => return Err("mixed address families".to_string()),
    }

    // SAFETY: `row` is fully initialised by InitializeIpForwardEntry + our fields.
    let e = unsafe { DeleteIpForwardEntry2(&row) };
    // 0 = removed; 1168 = ERROR_NOT_FOUND, which is the normal outcome when the
    // route already went away with its interface.
    if e.0 != 0 && e.0 != 1168 {
        return Err(format!("DeleteIpForwardEntry2 failed: 0x{:08X}", e.0));
    }
    Ok(())
}

fn delete_owned_route(route: &OwnedRoute) {
    match delete_route_native(route) {
        Ok(()) => {
            tracing::debug!(
                "Removed owned route {}/{} on IF {}",
                route.dest,
                route.prefix_len,
                route.if_index
            );
            return;
        }
        Err(e) => tracing::debug!(
            "Native delete of {}/{} on IF {} failed ({}); falling back to route.exe",
            route.dest,
            route.prefix_len,
            route.if_index,
            e
        ),
    }
    let Some(argv) = route_delete_argv(route) else {
        tracing::warn!(
            "Leaving route {}/{} in place — it cannot be deleted in a way that is guaranteed to \
             hit only ours",
            route.dest,
            route.prefix_len
        );
        return;
    };
    let _ = cmd("route").args(&argv).output();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn snap(
        guid: &str,
        name: &str,
        v4_dhcp: bool,
        v4: &[&str],
        v6_dhcp: bool,
        v6: &[&str],
    ) -> AdapterDnsSnapshot {
        AdapterDnsSnapshot {
            adapter_name: name.to_string(),
            adapter_guid: guid.to_string(),
            v4_was_dhcp: v4_dhcp,
            v6_was_dhcp: v6_dhcp,
            dns_servers: v4.iter().map(|s| s.to_string()).collect(),
            dns_servers_v6: v6.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn parked(guid: &str, name: &str) -> AdapterDnsSnapshot {
        snap(guid, name, false, &[], false, &[])
    }

    #[derive(Default)]
    struct Machine {
        /// guid -> (live DNS configuration, did WE park it?)
        adapters: Vec<(AdapterId, AdapterDnsSnapshot, bool)>,
        persisted: Option<Vec<AdapterDnsSnapshot>>,
        reads: Vec<String>,
        /// guids whose read must fail
        read_fails: Vec<String>,
        /// guids whose park must fail
        park_fails: Vec<String>,
        /// guids whose restore netsh must fail
        restore_fails: Vec<String>,
        persist_fails: bool,
        enumerate_fails: bool,
        deleted_routes: Vec<OwnedRoute>,
    }

    struct FakeIo(RefCell<Machine>);

    impl FakeIo {
        fn new(m: Machine) -> Self {
            FakeIo(RefCell::new(m))
        }
        fn with<R>(&self, f: impl FnOnce(&mut Machine) -> R) -> R {
            f(&mut self.0.borrow_mut())
        }
        /// The set the machine is ACTUALLY parked on, by us.
        fn parked_set(&self) -> Vec<String> {
            self.with(|m| {
                m.adapters
                    .iter()
                    .filter(|(_, _, ours)| *ours)
                    .map(|(a, _, _)| a.key())
                    .collect()
            })
        }
        fn recorded_set(&self) -> Vec<String> {
            self.with(|m| {
                m.persisted
                    .as_ref()
                    .map(|e| e.iter().map(entry_key).collect())
                    .unwrap_or_default()
            })
        }
        /// I4, asserted after EVERY individual call.
        fn assert_parked_subset_of_recorded(&self, label: &str) {
            let recorded = self.recorded_set();
            for guid in self.parked_set() {
                assert!(
                    recorded.contains(&guid),
                    "{}: {} is parked on the machine but is not in the durable record — nothing \
                     will ever un-park it",
                    label,
                    guid
                );
            }
        }
        fn live(&self, key: &str) -> AdapterDnsSnapshot {
            self.with(|m| {
                m.adapters
                    .iter()
                    .find(|(a, _, _)| a.key() == key)
                    .map(|(_, s, _)| s.clone())
                    .expect("adapter exists")
            })
        }
    }

    impl MachineIo for FakeIo {
        fn enumerate(&self) -> Result<Vec<AdapterId>, String> {
            self.with(|m| {
                if m.enumerate_fails {
                    return Err("enumeration unavailable".to_string());
                }
                Ok(m.adapters.iter().map(|(a, _, _)| a.clone()).collect())
            })
        }

        fn read_dns(&self, adapter: &AdapterId) -> Result<AdapterDnsSnapshot, String> {
            self.with(|m| {
                m.reads.push(adapter.key());
                if m.read_fails.contains(&adapter.key()) {
                    return Err("netsh exited 1".to_string());
                }
                m.adapters
                    .iter()
                    .find(|(a, _, _)| a.key() == adapter.key())
                    .map(|(_, s, _)| s.clone())
                    .ok_or_else(|| "no such adapter".to_string())
            })
        }

        fn park_dns(&self, adapter: &AdapterId) -> Result<(), String> {
            self.with(|m| {
                if m.park_fails.contains(&adapter.key()) {
                    return Err("netsh set dns failed".to_string());
                }
                for (a, live, ours) in m.adapters.iter_mut() {
                    if a.key() == adapter.key() {
                        *live = parked(&a.guid, &a.name);
                        *ours = true;
                    }
                }
                Ok(())
            })
        }

        fn restore_dns(
            &self,
            adapter: &AdapterId,
            entry: &AdapterDnsSnapshot,
        ) -> Result<(), String> {
            self.with(|m| {
                if m.restore_fails.contains(&adapter.key()) {
                    return Err("netsh set dns failed".to_string());
                }
                let (v4_dhcp, v4) = intent_v4(entry);
                let (v6_dhcp, v6) = intent_v6(entry);
                for (a, live, ours) in m.adapters.iter_mut() {
                    if a.key() == adapter.key() {
                        *live = AdapterDnsSnapshot {
                            adapter_name: a.name.clone(),
                            adapter_guid: a.guid.clone(),
                            v4_was_dhcp: v4_dhcp,
                            v6_was_dhcp: v6_dhcp,
                            dns_servers: v4.clone(),
                            dns_servers_v6: v6.clone(),
                        };
                        *ours = false;
                    }
                }
                Ok(())
            })
        }

        fn persist(&self, entries: &[AdapterDnsSnapshot]) -> Result<(), String> {
            self.with(|m| {
                if m.persist_fails {
                    return Err("disk full".to_string());
                }
                m.persisted = Some(entries.to_vec());
                Ok(())
            })
        }

        fn clear_record(&self) {
            self.with(|m| m.persisted = None);
        }

        fn delete_route(&self, route: &OwnedRoute) {
            self.with(|m| m.deleted_routes.push(*route));
        }
    }

    fn adapter(guid: &str, name: &str) -> AdapterId {
        AdapterId {
            guid: guid.to_string(),
            name: name.to_string(),
            up: true,
        }
    }

    fn two_adapters() -> Machine {
        Machine {
            adapters: vec![
                (
                    adapter("{A}", "Wi-Fi"),
                    snap("{A}", "Wi-Fi", true, &[], true, &[]),
                    false,
                ),
                (
                    adapter("{B}", "Ethernet"),
                    snap(
                        "{B}",
                        "Ethernet",
                        false,
                        &["1.1.1.1", "8.8.8.8"],
                        false,
                        &[],
                    ),
                    false,
                ),
            ],
            ..Default::default()
        }
    }

    fn fresh() -> MachineState {
        MachineState {
            owner: Some(1),
            live_session: None,
            park: BTreeMap::new(),
            routes: Vec::new(),
            degraded: BTreeMap::new(),
        }
    }

    // ── I4 / #102 ────────────────────────────────────────────────

    #[test]
    fn park_never_exceeds_the_record_when_a_read_fails() {
        // THE BUG (#102): the old code built the snapshot list dropping failures
        // and then parked the UNFILTERED enumeration, so an adapter whose read
        // failed was parked with no record that it was ever touched — and
        // nothing, not even a clean disconnect, would ever un-park it.
        let mut m = two_adapters();
        m.read_fails.push("{B}".to_string());
        let io = FakeIo::new(m);
        let mut st = fresh();

        park_pass(&mut st, &io);

        io.assert_parked_subset_of_recorded("read failure");
        assert!(
            !io.parked_set().contains(&"{B}".to_string()),
            "an adapter we could not read must NOT be parked"
        );
        assert!(!st.park.contains_key("{B}"));
        assert!(st.park.contains_key("{A}"), "the readable one still parks");
        assert!(
            st.degraded.values().any(|d| d.message.contains("Ethernet")),
            "the leak must be surfaced, not silent"
        );
    }

    #[test]
    fn a_failed_record_write_means_the_adapter_is_not_parked() {
        let io = FakeIo::new(Machine {
            persist_fails: true,
            ..two_adapters()
        });
        let mut st = fresh();

        park_pass(&mut st, &io);

        assert!(
            io.parked_set().is_empty(),
            "a mutation whose record is not on disk is a mutation nothing can undo"
        );
        assert!(st.park.is_empty());
        assert_eq!(st.degraded.len(), 2);
    }

    #[test]
    fn a_failed_park_is_retried_on_the_next_pass_and_clears_when_it_recovers() {
        // Recorded is not suppressed. Without the retry, an adapter whose park
        // failed at connect keeps its ISP resolvers for the whole session and
        // the periodic refresh walks straight past it, because it is already in
        // the record.
        let mut m = two_adapters();
        m.park_fails.push("{A}".to_string());
        let io = FakeIo::new(m);
        let mut st = fresh();

        claim_locked(&mut st, &io, 1);
        assert!(!io.parked_set().contains(&"{A}".to_string()));
        assert!(st.degraded.contains_key("{A}"));
        io.with(|m| m.reads.clear());

        // netsh recovers; the next refresh must fix it WITHOUT re-reading the
        // origin (that would capture the parked state as the user's own).
        io.with(|m| m.park_fails.clear());
        park_pass(&mut st, &io);

        assert!(
            io.parked_set().contains(&"{A}".to_string()),
            "a failed park must be retried while the session owns the adapter"
        );
        assert!(
            !st.degraded.contains_key("{A}"),
            "and the degradation must clear when it recovers"
        );
        assert!(
            !io.with(|m| m.reads.contains(&"{B}".to_string())),
            "the healthy adapter is still never re-read"
        );
        io.assert_parked_subset_of_recorded("park retry");
    }

    #[test]
    fn a_failed_park_keeps_the_record_so_the_adapter_stays_restorable() {
        let mut m = two_adapters();
        m.park_fails.push("{A}".to_string());
        let io = FakeIo::new(m);
        let mut st = fresh();

        park_pass(&mut st, &io);

        io.assert_parked_subset_of_recorded("park failure");
        assert!(
            st.park.contains_key("{A}"),
            "a half-parked adapter must stay in the record"
        );
        assert!(st.degraded.values().any(|d| d.message.contains("Wi-Fi")));
    }

    // ── I5b / I12 / #98 ──────────────────────────────────────────

    #[test]
    fn adopting_an_existing_park_re_reads_nothing_and_changes_nothing() {
        // #98's mechanism: a second generation's configure_dns used to snapshot
        // adapters the FIRST one had already parked. Every read returns `static
        // none` → the terminal shape → the record is overwritten with a poison
        // value for every adapter at once.
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);
        let record_after_first = st.park.clone();
        io.with(|m| m.reads.clear());

        // A later generation adopts.
        st.owner = Some(2);
        park_pass(&mut st, &io);

        assert_eq!(
            io.with(|m| m.reads.len()),
            0,
            "adoption must issue ZERO reads — re-reading a parked adapter records the parked \
             state as the user's own configuration"
        );
        assert_eq!(
            st.park, record_after_first,
            "the record must be byte-identical after adoption"
        );
    }

    #[test]
    fn a_non_owner_cannot_un_park_anything() {
        // THE #98 LEAK ITSELF. The orphaned tunnel's Drop un-parked every
        // physical adapter while the NEW tunnel was live and carrying traffic,
        // with the UI reading Connected. Revert the ownership check in
        // release_dns_locked and this test fails.
        let io = FakeIo::new(two_adapters());
        let mut st = fresh(); // owner = generation 1
        claim_locked(&mut st, &io, 1);
        let parked_before = io.parked_set();
        assert_eq!(parked_before.len(), 2);
        let record_before = st.park.clone();

        // A new tunnel takes over, exactly as `claim`/`begin_transition` do.
        claim_locked(&mut st, &io, 2);
        assert_eq!(st.park, record_before, "adoption changes no record");

        // The orphan (generation 1) now runs its emergency unwind.
        let restored = release_dns_locked(&mut st, &io, 1);

        assert!(!restored);
        assert_eq!(
            io.parked_set(),
            parked_before,
            "a generation that no longer owns the park must not un-park anything"
        );
        assert_eq!(st.park, record_before, "and must not touch the record");
        assert_eq!(st.owner, Some(2), "ownership is unchanged by a non-owner");

        // The real owner still can, and that clears the record.
        assert!(release_dns_locked(&mut st, &io, 2));
        assert!(io.parked_set().is_empty());
        assert!(st.park.is_empty());
        assert_eq!(st.owner, None);
    }

    #[test]
    fn a_non_owner_cannot_delete_the_live_tunnels_routes() {
        // The route half of #98: the orphan's Drop ran the same
        // `cleanup_routes_blocking` that removes the /1 split-default pair — the
        // pair the LIVE tunnel was routing over.
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        st.owner = Some(1);
        let split_low = OwnedRoute {
            dest: v4("0.0.0.0"),
            prefix_len: 1,
            next_hop: v4("0.0.0.0"),
            if_index: 27,
        };
        let split_high = OwnedRoute {
            dest: v4("128.0.0.0"),
            prefix_len: 1,
            next_hop: v4("0.0.0.0"),
            if_index: 27,
        };
        assert!(push_owned_route(&mut st.routes, split_low));
        assert!(push_owned_route(&mut st.routes, split_high));

        st.owner = Some(2); // a new tunnel adopts them

        release_routes_locked(&mut st, &io, 1);
        assert!(
            io.with(|m| m.deleted_routes.is_empty()),
            "an orphan must not delete routes the live tunnel is using"
        );
        assert_eq!(st.routes.len(), 2);

        release_routes_locked(&mut st, &io, 2);
        assert_eq!(io.with(|m| m.deleted_routes.len()), 2);
        assert!(st.routes.is_empty());
    }

    // ── I5: verified restore ─────────────────────────────────────

    #[test]
    fn restore_puts_back_the_exact_pre_connect_configuration() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);

        let mut degraded = BTreeMap::new();
        let restored = restore_pass(&mut st.park, &io, &mut degraded);

        assert!(restored);
        assert!(st.park.is_empty(), "a verified restore clears the record");
        assert!(degraded.is_empty());
        // Wi-Fi was DHCP; Ethernet had two static servers.
        assert!(io.live("{A}").v4_was_dhcp);
        assert_eq!(io.live("{B}").dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn a_restore_whose_read_back_fails_keeps_the_record() {
        // The record may be cleared only for a pair whose read-back matched.
        // Clearing it unconditionally is how a failed un-park became permanent.
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);
        io.with(|m| m.restore_fails.push("{B}".to_string()));

        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);

        assert!(
            st.park.contains_key("{B}"),
            "an unverified restore must keep its record"
        );
        assert!(!st.park.contains_key("{A}"), "the verified one is dropped");
        assert!(degraded.values().any(|d| d.message.contains("Ethernet")));
    }

    #[test]
    fn a_restore_whose_live_read_fails_touches_nothing_and_keeps_the_record() {
        // The correction to "netsh failing to answer counts as not ours": it did
        // not, because the old snapshot helper turned a non-zero exit into
        // Some((false, [])) — the parked shape — so we acted on adapters whose
        // state we had failed to read.
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);
        io.with(|m| m.read_fails.push("{A}".to_string()));

        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);

        assert!(st.park.contains_key("{A}"));
        assert!(
            io.parked_set().contains(&"{A}".to_string()),
            "an unreadable adapter must not be written to"
        );
    }

    #[test]
    fn an_adapter_the_user_fixed_by_hand_is_dropped_untouched() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);
        // The user sets Wi-Fi to 9.9.9.9 themselves.
        io.with(|m| {
            for (a, live, ours) in m.adapters.iter_mut() {
                if a.guid == "{A}" {
                    *live = snap("{A}", "Wi-Fi", false, &["9.9.9.9"], false, &[]);
                    *ours = false;
                }
            }
        });

        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);

        assert_eq!(io.live("{A}").dns_servers, vec!["9.9.9.9"]);
        assert!(!st.park.contains_key("{A}"));
    }

    #[test]
    fn a_static_with_no_servers_adapter_is_left_exactly_as_it_was() {
        // Measured on a stock Windows 11 box: VirtualBox Host-Only, the
        // Hyper-V/WSL vSwitch and the OpenVPN TAP adapter are all `static` with
        // no servers and Up. Parking them is a no-op, so un-parking must be one
        // too — forcing DHCP there is an unrequested, elevated change to other
        // products' networking on every disconnect (#96).
        let io = FakeIo::new(Machine {
            adapters: vec![(
                adapter("{V}", "VirtualBox Host-Only Network"),
                parked("{V}", "VirtualBox Host-Only Network"),
                false,
            )],
            ..Default::default()
        });
        let mut st = fresh();
        park_pass(&mut st, &io);

        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);

        let live = io.live("{V}");
        assert!(!live.v4_was_dhcp, "must NOT be handed to DHCP");
        assert!(!live.v6_was_dhcp, "IPv6 twin: must NOT be handed to DHCP");
        assert!(st.park.is_empty(), "and the record is still cleared");
    }

    #[test]
    fn ipv6_resolvers_that_were_all_link_local_go_back_to_dhcp_ra() {
        // fe80:: resolvers come from RDNSS. Restoring them statically would
        // outlive the router; leaving them empty with a `static` origin would
        // leave the adapter with no IPv6 resolvers at all.
        let entry = snap("{L}", "Ethernet", true, &[], false, &["fe80::1%13"]);
        assert_eq!(intent_v6(&entry), (true, Vec::new()));
        // ...but an adapter that genuinely had none stays static-with-none.
        let none = snap("{N}", "Ethernet", true, &[], false, &[]);
        assert_eq!(intent_v6(&none), (false, Vec::new()));
        // ...and a real static v6 resolver survives verbatim.
        let real = snap(
            "{R}",
            "Ethernet",
            true,
            &[],
            false,
            &["2606:4700:4700::1111"],
        );
        assert_eq!(
            intent_v6(&real),
            (false, vec!["2606:4700:4700::1111".to_string()])
        );
    }

    // ── v4 / v6 twin parity ──────────────────────────────────────
    //
    // These twins have drifted TWICE in this subsystem, so the parity is
    // asserted rather than promised in a comment. `FakeIo` substitutes for
    // `SystemIo`, so what these cover is the shared decision logic — the
    // combinator and the two verification predicates. The netsh argv in
    // `SystemIo::park_dns` / `restore_dns` / `read_dns` is NOT reachable from a
    // unit test and is inspection-only.

    /// Neither family may short-circuit the other, and a half-failure must never
    /// read as success. [`join_family_results`] is the single place the two are
    /// combined: both arms are evaluated before it is called (no `?`), so it is
    /// the only thing that can lose one.
    #[test]
    fn a_family_that_failed_can_never_be_reported_as_done() {
        assert!(join_family_results(Ok(()), Ok(())).is_ok());

        let v6_failed = join_family_results(Ok(()), Err("ipv6 exited 1".to_string()))
            .expect_err("an IPv6 failure with IPv4 fine is NOT a success");
        assert!(v6_failed.contains("ipv6"), "{}", v6_failed);

        let v4_failed = join_family_results(Err("ipv4 exited 1".to_string()), Ok(()))
            .expect_err("and the twin holds the other way round");
        assert!(v4_failed.contains("ipv4"), "{}", v4_failed);

        // Both failed: the message names BOTH, so neither can be hidden by the
        // other in a log line.
        let both = join_family_results(
            Err("ipv4 exited 1".to_string()),
            Err("ipv6 exited 1".to_string()),
        )
        .expect_err("both failed");
        assert!(both.contains("ipv4") && both.contains("ipv6"), "{}", both);
    }

    /// "Is it parked?" is a BOTH-families question. An adapter still holding
    /// IPv6 resolvers is not parked however clean its IPv4 side looks — SMHNR
    /// queries RA/RDNSS resolvers too, which is the entire reason `park_dns` has
    /// an `ipv6` arm.
    #[test]
    fn an_adapter_still_holding_one_familys_resolvers_is_not_parked() {
        assert!(is_parked_shape(&snap(
            "{A}",
            "Wi-Fi",
            false,
            &[],
            false,
            &[]
        )));
        assert!(
            !is_parked_shape(&snap(
                "{A}",
                "Wi-Fi",
                false,
                &[],
                false,
                &["2606:4700:4700::1111"]
            )),
            "IPv4 clean but IPv6 resolvers still registered must NOT verify as parked"
        );
        assert!(
            !is_parked_shape(&snap("{A}", "Wi-Fi", false, &[], true, &[])),
            "nor must an adapter whose IPv6 is still sourced from DHCP/RA"
        );
        assert!(
            !is_parked_shape(&snap("{A}", "Wi-Fi", false, &["1.1.1.1"], false, &[])),
            "the IPv4 twin of the same question"
        );
        assert!(
            !is_parked_shape(&snap("{A}", "Wi-Fi", true, &[], false, &[])),
            "and the IPv4 origin half of it"
        );
    }

    /// [`matches_intent`] is the restore-side twin of the same question: an
    /// adapter whose IPv4 came back while its IPv6 stayed suppressed is a
    /// half-restored adapter, and it must not clear the record.
    #[test]
    fn a_restore_that_only_took_on_one_family_does_not_verify() {
        let entry = snap(
            "{B}",
            "Ethernet",
            false,
            &["1.1.1.1"],
            false,
            &["2606:4700:4700::1111"],
        );
        let (v4_dhcp, v4) = intent_v4(&entry);
        let (v6_dhcp, v6) = intent_v6(&entry);
        let full = AdapterDnsSnapshot {
            adapter_name: "Ethernet".to_string(),
            adapter_guid: "{B}".to_string(),
            v4_was_dhcp: v4_dhcp,
            v6_was_dhcp: v6_dhcp,
            dns_servers: v4,
            dns_servers_v6: v6,
        };
        assert!(matches_intent(&entry, &full), "the whole intent, written");

        let mut v6_missing = full.clone();
        v6_missing.dns_servers_v6.clear();
        assert!(
            !matches_intent(&entry, &v6_missing),
            "IPv4 back, IPv6 still suppressed — a half-restored adapter reading as restored"
        );

        let mut v4_missing = full;
        v4_missing.dns_servers.clear();
        assert!(
            !matches_intent(&entry, &v4_missing),
            "and the twin the other way round"
        );
    }

    // ── I6 / #99 ─────────────────────────────────────────────────

    #[test]
    fn refresh_parks_an_adapter_that_came_up_mid_session() {
        let io = FakeIo::new(Machine {
            adapters: vec![(
                adapter("{A}", "Wi-Fi"),
                snap("{A}", "Wi-Fi", true, &[], true, &[]),
                false,
            )],
            ..Default::default()
        });
        let mut st = fresh();
        park_pass(&mut st, &io);

        // Ethernet is plugged in while connected.
        io.with(|m| {
            m.adapters.push((
                adapter("{B}", "Ethernet"),
                snap("{B}", "Ethernet", true, &[], true, &[]),
                false,
            ))
        });
        io.with(|m| m.reads.clear());

        park_pass(&mut st, &io);

        assert!(
            io.parked_set().contains(&"{B}".to_string()),
            "an adapter that comes up mid-session must be parked (#99)"
        );
        assert!(
            !io.with(|m| m.reads.contains(&"{A}".to_string())),
            "and the already-parked one must not be re-read (#99's own objection \
             to the naive fix)"
        );
        io.assert_parked_subset_of_recorded("refresh");
    }

    #[test]
    fn an_unplugged_adapter_is_kept_on_record_but_not_reported() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);
        assert_eq!(st.park.len(), 2);

        // The dock is unplugged while connected: gone from enumeration, and
        // netsh can no longer address it.
        io.with(|m| m.adapters.retain(|(a, _, _)| a.guid != "{B}"));

        let mut degraded = std::mem::take(&mut st.degraded);
        restore_pass(&mut st.park, &io, &mut degraded);

        assert!(
            st.park.contains_key("{B}"),
            "the record for a detached adapter is the only thing that still knows its              resolvers, and Windows keeps the parked `static none` under its GUID — dropping              it would strand the adapter on re-attach"
        );
        assert!(
            !degraded.get("{B}").expect("still on the retry list").reportable,
            "an adapter that is not attached is not a fault this session can fix, and              reporting it forever is what made the DNS warning permanent"
        );
        assert!(
            !st.park.contains_key("{A}"),
            "the adapter that IS present must still be restored and dropped"
        );
    }

    #[test]
    fn a_re_attached_adapter_is_re_parked_and_then_restorable() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);

        // Unplug, end the session: {B} goes dormant and stays on record.
        io.with(|m| m.adapters.retain(|(a, _, _)| a.guid != "{B}"));
        let mut degraded = std::mem::take(&mut st.degraded);
        restore_pass(&mut st.park, &io, &mut degraded);
        st.degraded = degraded;

        // Plug it back in, un-parked this time (a driver reinstall, say).
        io.with(|m| {
            m.adapters.push((
                adapter("{B}", "Ethernet"),
                snap("{B}", "Ethernet", true, &[], true, &[]),
                false,
            ))
        });
        park_pass(&mut st, &io);

        assert!(
            io.parked_set().contains(&"{B}".to_string()),
            "a dormant entry stays on the RETRY list precisely so re-attach re-parks it"
        );
        io.assert_parked_subset_of_recorded("re-attach");

        // And now it converges: present, parked, restorable, record emptied.
        let mut degraded = std::mem::take(&mut st.degraded);
        restore_pass(&mut st.park, &io, &mut degraded);
        assert!(
            st.park.is_empty(),
            "every entry must have a terminal state — the record has to empty itself"
        );
    }

    // ── I13: no park may follow an un-park ───────────────────────

    /// May the ticker for `gen` run another pass against this state?
    fn ticker_alive(st: &MachineState, gen: Gen) -> bool {
        should_refresh(st.owner, st.live_session, gen)
    }

    /// A session that ends with a retained entry — the ordinary case — keeps the
    /// generation OWNING the park, which is why ownership can never be the
    /// ticker's gate. R1 shipped exactly that and blackholed DNS machine-wide.
    #[test]
    fn a_failed_restore_leaves_ownership_behind_so_ownership_cannot_gate_the_ticker() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        claim_locked(&mut st, &io, 7);
        assert!(
            ticker_alive(&st, 7),
            "a claimed, live generation refreshes (#99)"
        );

        // One adapter cannot be read back, so its entry is retained.
        io.with(|m| m.read_fails.push("{B}".to_string()));
        assert!(release_dns_locked(&mut st, &io, 7));

        assert!(
            !st.park.is_empty() && st.owner == Some(7),
            "a retained entry keeps the generation owning the park after the session ended \
             — this is the state the old ticker looped forever in"
        );
        assert!(
            !ticker_alive(&st, 7),
            "the un-park must have shut the ticker down: otherwise it re-parks every physical \
             adapter every 10s with no tunnel anywhere"
        );
        assert!(
            !ticker_alive(&st, 8),
            "and no other generation may inherit a ticker either"
        );
    }

    /// THE REPEAT (round 2 -> round 3). `release_dns_at_exit` is the updater
    /// relaunch's un-park: `RunEvent::ExitRequested` carries `RESTART_EXIT_CODE`,
    /// `prevent_exit()` is a documented no-op, the normal teardown never runs and
    /// NO TUNNEL IS INVOLVED — it reads the owner straight out of the state.
    ///
    /// The round-2 gate was an `AtomicBool` the tunnel cleared in `stop()` and in
    /// `Drop`. Neither runs here, so the flag stayed set, the ticker outlived the
    /// un-park, and it re-parked every physical adapter on `static none` while
    /// the process was being replaced — R5's rejected failure design, second
    /// door.
    ///
    /// This test drives that door with no tunnel anywhere, which is the point: if
    /// the gate can only be closed by something a tunnel owns, this cannot pass.
    #[test]
    fn the_updater_relaunch_un_park_shuts_the_ticker_down_with_no_tunnel_involved() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        claim_locked(&mut st, &io, 7);

        // Retain an entry, so ownership survives the un-park exactly as it does
        // in the field — an adapter unplugged mid-session is the ordinary way.
        io.with(|m| m.read_fails.push("{B}".to_string()));

        // `release_dns_at_exit()` in miniature: whoever owns it, un-park it.
        let owner = st.owner.expect("a connected session has an owner");
        release_dns_locked(&mut st, &io, owner);

        assert_eq!(
            st.owner,
            Some(7),
            "the retained entry keeps ownership alive"
        );
        assert!(
            !ticker_alive(&st, 7),
            "the relaunch door must close the ticker too — this is the assertion the round-2 \
             AtomicBool could not make, because nothing on that path ever cleared it"
        );
    }

    /// Every door that un-parks gives the SAME answer, and it is the un-park —
    /// not the door — that gives it. That is the difference between one gate and
    /// N call sites: a door nobody has thought of yet still has to un-park to be
    /// dangerous, and un-parking is what closes the gate.
    #[test]
    fn every_un_park_door_closes_the_ticker() {
        /// How one exit door reaches the un-park.
        type Door = fn(&mut MachineState, &FakeIo);

        // (label, how that door reaches the un-park)
        let doors: Vec<(&str, Door)> = vec![
            // stop() / Drop: the tunnel un-parks with its OWN generation.
            ("tunnel stop or drop", |st, io| {
                release_dns_locked(st, io, 7);
            }),
            // The updater relaunch and the panic hook's owner path: un-park
            // whoever owns it, no tunnel in sight.
            ("release_dns_at_exit", |st, io| {
                let owner = st.owner.unwrap();
                release_dns_locked(st, io, owner);
            }),
            // The exit teardown, which disconnects first: same call, plus the
            // routes.
            ("exit teardown", |st, io| {
                release_dns_locked(st, io, 7);
                release_routes_locked(st, io, 7);
            }),
        ];

        for (label, door) in doors {
            let io = FakeIo::new(two_adapters());
            let mut st = fresh();
            claim_locked(&mut st, &io, 7);
            // Retained entry ⇒ ownership outlives the session, the state R1 and
            // R2 both went wrong in.
            io.with(|m| m.read_fails.push("{B}".to_string()));
            assert!(ticker_alive(&st, 7), "{}: precondition", label);

            door(&mut st, &io);

            // Drive the ticker's ACTUAL body, twice — this is the thread that
            // ignored its stop signal, or that nobody remembered to bound. It
            // must not touch the machine. The gate is inside the call, not in
            // the caller's loop, precisely so it does not matter whether the
            // thread stops.
            let parked_after_door = io.parked_set();
            let recorded_after_door = io.recorded_set();
            io.with(|m| m.reads.clear());
            assert!(!refresh_live_session_locked(&mut st, &io, 7), "{}", label);
            assert!(!refresh_live_session_locked(&mut st, &io, 7), "{}", label);
            assert_eq!(
                io.parked_set(),
                parked_after_door,
                "{}: the ticker re-parked an adapter after the un-park — this IS the blackhole",
                label
            );
            assert_eq!(io.recorded_set(), recorded_after_door, "{}", label);
            assert!(
                io.with(|m| m.reads.is_empty()),
                "{}: and it read nothing",
                label
            );

            assert!(
                !ticker_alive(&st, 7),
                "{}: a park pass after this door would re-park every physical adapter with \
                 nothing connected",
                label
            );
        }
    }

    /// The gate is not a one-way latch: a reconnect in the same process must get
    /// its ticker back, or #99's mid-session NIC never gets parked again. This is
    /// the reason "set a shutting-down flag and never clear it" is the wrong
    /// shape — it would have to be un-set somewhere, and that is N paths again.
    #[test]
    fn a_new_session_reopens_the_ticker_for_its_own_generation_only() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();

        claim_locked(&mut st, &io, 7);
        io.with(|m| m.read_fails.push("{B}".to_string()));
        release_dns_locked(&mut st, &io, 7);
        assert!(!ticker_alive(&st, 7));

        // Reconnect: the manager holds the park across the gap, then the new
        // tunnel takes ownership and claims.
        io.with(|m| m.read_fails.clear());
        begin_transition_locked(&mut st, 8);
        assert!(
            !ticker_alive(&st, 7) && !ticker_alive(&st, 8),
            "a park held across a transition has no data plane — nobody may refresh it"
        );
        take_ownership_locked(&mut st, 9);
        assert!(!ticker_alive(&st, 9), "ownership alone is still not enough");
        claim_locked(&mut st, &io, 9);

        assert!(ticker_alive(&st, 9), "the new session refreshes");
        assert!(
            !ticker_alive(&st, 7) && !ticker_alive(&st, 8),
            "and only the new session does"
        );
    }

    /// A server switch displaces the outgoing tunnel WITHOUT un-parking (that is
    /// deliberate — the park is held across the gap so the physical NICs never
    /// carry ISP resolvers during the create + handshake window). The outgoing
    /// tunnel's Drop takes the non-owner early return, so nothing it owns clears
    /// anything: the transition itself has to close the ticker.
    #[test]
    fn a_displaced_generation_loses_its_ticker_without_any_un_park() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        claim_locked(&mut st, &io, 7);
        assert!(ticker_alive(&st, 7));

        begin_transition_locked(&mut st, 8);

        assert!(
            !st.park.is_empty(),
            "the park is deliberately held across the transition"
        );
        assert!(
            !ticker_alive(&st, 7),
            "the displaced generation must not keep parking on behalf of its successor"
        );
    }

    /// The one exit shape that CANNOT close the gate — a SIGKILL, an OOM kill, a
    /// power cut, `TerminateProcess`, a Windows shutdown — un-parks nothing, so
    /// a last pass before the OS reaps the thread is idempotent (I12): it touches
    /// no adapter that is not already parked AND already recorded, and it cannot
    /// re-snapshot one (I5b). That is why the design gates on the un-park rather
    /// than on "the process is ending", which is not observable on those paths.
    #[test]
    fn a_pass_that_follows_no_un_park_is_harmless() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        claim_locked(&mut st, &io, 7);

        let recorded_before = io.recorded_set();
        let parked_before = io.parked_set();
        io.with(|m| m.reads.clear());

        // The ticker gets one more pass in before the process dies.
        assert!(ticker_alive(&st, 7));
        park_pass(&mut st, &io);

        assert!(
            io.with(|m| m.reads.is_empty()),
            "I5b: a recorded adapter is never re-read, so the parked shape cannot be captured \
             as the user's own configuration"
        );
        assert_eq!(io.parked_set(), parked_before, "no new machine mutation");
        assert_eq!(io.recorded_set(), recorded_before, "no record churn");
    }

    /// I13's SECOND door, and the only one that cannot close itself by
    /// un-parking: [`reconcile_record`] restores off the ON-DISK record and
    /// deliberately never takes the lock, so it closes the session by hand
    /// through [`close_live_session_for_unpark`] instead.
    ///
    /// Driven against the process-global `STATE` on purpose — that is the state
    /// the running ticker reads, and a helper that clears a copy would protect
    /// nothing. This is the ONLY test in this module that touches `STATE`; every
    /// other one drives an explicit `MachineState`, and nothing else may start
    /// using the global or the two will race under the test harness's threads.
    #[test]
    fn the_panic_hook_helper_closes_the_live_session_on_the_process_global_state() {
        {
            let mut st = state();
            st.owner = Some(4242);
            st.live_session = Some(4242);
        }

        close_live_session_for_unpark();

        let st = state();
        assert!(
            st.live_session.is_none(),
            "the panic hook's un-park must shut the ticker down before it issues a single netsh"
        );
        assert!(
            !should_refresh(st.owner, st.live_session, 4242),
            "and the ticker's own gate must agree"
        );
    }

    /// WHY that helper has to exist, composed.
    ///
    /// An adapter whose park FAILED is recorded (so its origin is safe) and on
    /// the retry list, so [`park_pass`] re-issues its park on every tick. The
    /// panic hook reads it, correctly finds it is not parked-shaped, drops it
    /// from the record and flushes. A ticker pass landing after that flush parks
    /// an adapter that nothing on disk describes any more, milliseconds before
    /// `panic = "abort"` reaps the process — `static none` forever, with no
    /// process left to fix it. That is #102's terminal shape reached from the
    /// recovery path, and it is a park that followed an un-park.
    #[test]
    fn the_panic_hook_un_park_must_close_the_ticker_before_it_flushes_the_record() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        io.with(|m| m.park_fails.push("{B}".to_string()));
        claim_locked(&mut st, &io, 7);
        assert!(
            st.park.contains_key("{B}") && st.degraded.contains_key("{B}"),
            "a failed park is recorded AND on the retry list — that is the setup"
        );
        assert!(ticker_alive(&st, 7), "precondition");

        // `reconcile_record` in miniature: close the session (what the helper
        // does), then restore off the ON-DISK record and flush what survives.
        st.live_session = None;
        let mut from_disk: BTreeMap<String, AdapterDnsSnapshot> = io
            .with(|m| m.persisted.clone())
            .expect("the record reached the disk")
            .into_iter()
            .map(|e| (entry_key(&e), e))
            .collect();
        let mut hook_degraded = BTreeMap::new();
        restore_pass(&mut from_disk, &io, &mut hook_degraded);
        flush_record(&from_disk, &io);
        assert!(
            io.with(|m| m.persisted.is_none()),
            "the hook emptied the record — nothing on disk describes {{B}} any more"
        );

        // The park that failed at connect would succeed now. The ticker must
        // never get the chance to issue it.
        io.with(|m| m.park_fails.clear());
        let parked_after_hook = io.parked_set();
        assert!(!refresh_live_session_locked(&mut st, &io, 7));
        assert!(!refresh_live_session_locked(&mut st, &io, 7));
        assert_eq!(
            io.parked_set(),
            parked_after_hook,
            "the ticker parked an adapter after the hook cleared the record — permanent \
             resolver loss, and nothing left running to undo it"
        );
    }

    /// `live_session ⊆ {owner}` is stated as an invariant on the field, so it
    /// has to be one. It was true by accident: [`release_owner_if_clean`]
    /// cleared `owner` and left `live_session` behind, and one caller reaches
    /// it with a session still open — [`release_routes_locked`] on a generation
    /// whose park is EMPTY, which is what a machine whose physical NICs were all
    /// down at connect produces. No ticker could act on the residue (both halves
    /// of [`should_refresh`] are required), but "no ticker can act on it" is a
    /// second argument the field doc does not make, and the gap between a stated
    /// rule and the enforced one is what five rejected designs had in common.
    #[test]
    fn clearing_the_owner_clears_the_live_session_too() {
        // Every physical NIC is down, so nothing is eligible and the park is
        // empty for a perfectly live session.
        let io = FakeIo::new(Machine::default());
        let mut st = fresh();
        claim_locked(&mut st, &io, 7);
        st.routes.push(OwnedRoute {
            dest: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 1,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            if_index: 12,
        });
        assert!(
            st.park.is_empty() && ticker_alive(&st, 7),
            "an empty park with a live session is the precondition, not a bug"
        );

        release_routes_locked(&mut st, &io, 7);

        assert_eq!(st.owner, None, "nothing is moved aside any more");
        assert_eq!(
            st.live_session, None,
            "the session must go with the ownership it is defined as a subset of",
        );
        assert!(!ticker_alive(&st, 7), "and no ticker may survive it");
    }

    // ── The record has to come BACK, not just go out ─────────────

    /// CRITICAL 2. `reconcile_record` RETAINS what it could not verifiably
    /// restore — the module docs call a retained entry "the last thing that knows
    /// what to put back" — and then wrote it to disk and dropped it on the floor:
    /// `STATE.park` stayed empty. Everything downstream then treats a parked
    /// adapter as unparked.
    ///
    /// Without the adoption, the next connect RE-READS that adapter (I5b never
    /// fires, because the record it checks is empty in memory) and captures
    /// `static none` as the user's own configuration. That is #102's terminal
    /// shape, reached from the recovery path.
    #[test]
    fn an_unrestored_entry_is_adopted_so_the_next_connect_cannot_re_snapshot_it() {
        // {B} is still parked from a previous process; its real resolvers survive
        // only in the record.
        let mut m = two_adapters();
        m.adapters[1].1 = parked("{B}", "Ethernet");
        m.adapters[1].2 = true;
        let io = FakeIo::new(m);

        let survivor = snap(
            "{B}",
            "Ethernet",
            false,
            &["1.1.1.1", "8.8.8.8"],
            false,
            &[],
        );
        let mut recovered = BTreeMap::new();
        recovered.insert(entry_key(&survivor), survivor.clone());

        let mut st = MachineState {
            owner: None,
            live_session: None,
            park: BTreeMap::new(),
            routes: Vec::new(),
            degraded: BTreeMap::new(),
        };
        adopt_unrestored(&mut st, recovered);

        assert_eq!(
            st.park.len(),
            1,
            "the survivor must be visible to the running process, not only to the disk"
        );
        assert!(
            st.owner.is_some(),
            "it is machine state that is moved aside right now, so it needs an owner (I1) — \
             otherwise release_dns_at_exit reads owner=None and a clean quit never retries it"
        );
        assert!(
            st.live_session.is_none(),
            "nothing is connected, so no refresh ticker may exist for that generation (I13)"
        );

        // Now connect. The adopted adapter must not be read, and the record must
        // still describe its REAL resolvers afterwards.
        io.with(|m| m.reads.clear());
        let gen = next_generation();
        take_ownership_locked(&mut st, gen);
        claim_locked(&mut st, &io, gen);

        assert!(
            !io.with(|m| m.reads.contains(&"{B}".to_string())),
            "I5b: the adopted adapter was re-read, so the parked shape has just been captured \
             as its origin — permanent resolver loss"
        );
        assert_eq!(
            st.park.get("{B}").map(|e| e.dns_servers.clone()),
            Some(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]),
            "the recovered origin must survive the connect"
        );
        assert!(
            io.recorded_set().contains(&"{B}".to_string()),
            "and the durable record must still carry it — park_pass persists st.park, so an \
             un-adopted survivor is CLOBBERED off the disk by the act of connecting again"
        );

        // And it is restorable, which is the entire point of keeping it.
        let mut degraded = std::mem::take(&mut st.degraded);
        restore_pass(&mut st.park, &io, &mut degraded);
        assert_eq!(
            io.live("{B}").dns_servers,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            "the previous process's resolvers must come back"
        );
    }

    /// The adoption is refused when this process already holds state of its own.
    /// At `setup()` that cannot happen (no tunnel can be up that early); from the
    /// panic hook it can, and there the DYING process's in-memory record is the
    /// newer one — overwriting it with the file would restore a stale set.
    #[test]
    fn adoption_never_overwrites_a_record_this_process_already_holds() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        claim_locked(&mut st, &io, 7);
        let mine = st.park.clone();

        let stale = snap("{Z}", "Old NIC", false, &["9.9.9.9"], false, &[]);
        let mut from_disk = BTreeMap::new();
        from_disk.insert(entry_key(&stale), stale);
        adopt_unrestored(&mut st, from_disk);

        assert_eq!(st.park, mine, "the live record wins");
        assert_eq!(st.owner, Some(7), "and keeps its owner");
    }

    #[test]
    fn a_down_adapter_is_not_parked() {
        let io = FakeIo::new(Machine {
            adapters: vec![(
                AdapterId {
                    guid: "{D}".into(),
                    name: "Ethernet".into(),
                    up: false,
                },
                snap("{D}", "Ethernet", true, &[], true, &[]),
                false,
            )],
            ..Default::default()
        });
        let mut st = fresh();
        park_pass(&mut st, &io);
        assert!(st.park.is_empty());
    }

    // ── I7 ───────────────────────────────────────────────────────

    #[test]
    fn an_adapter_renamed_while_parked_is_still_restored() {
        let io = FakeIo::new(two_adapters());
        let mut st = fresh();
        park_pass(&mut st, &io);
        // The user renames the connection in Network Connections.
        io.with(|m| {
            for (a, live, _) in m.adapters.iter_mut() {
                if a.guid == "{B}" {
                    a.name = "Work LAN".to_string();
                    live.adapter_name = "Work LAN".to_string();
                }
            }
        });

        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);

        assert_eq!(io.live("{B}").dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert!(st.park.is_empty());
    }

    // ── I4 as a sequence property ────────────────────────────────

    #[test]
    fn parked_is_a_subset_of_recorded_after_every_single_call() {
        // The test that would have caught the current bug and every previous
        // attempt's version of it: drive a long sequence of claim / refresh /
        // adopt / release with failures injected everywhere and assert the
        // containment after EVERY step, not only at the end.
        let mut m = two_adapters();
        m.adapters.push((
            adapter("{C}", "vEthernet (WSL)"),
            parked("{C}", "vEthernet (WSL)"),
            false,
        ));
        let io = FakeIo::new(m);
        let mut st = fresh();

        // A deterministic script of failure injections, one per step.
        let script: [(&str, &str); 10] = [
            ("park", ""),
            ("park", "read:{C}"),
            ("park", "persist"),
            ("release", ""),
            ("park", "park:{A}"),
            ("park", ""),
            ("release", "restore:{B}"),
            ("park", ""),
            ("release", "read:{A}"),
            ("release", ""),
        ];

        for (step, (op, injection)) in script.iter().enumerate() {
            io.with(|m| {
                m.read_fails.clear();
                m.park_fails.clear();
                m.restore_fails.clear();
                m.persist_fails = false;
                match injection.split_once(':') {
                    Some(("read", g)) => m.read_fails.push(g.to_string()),
                    Some(("park", g)) => m.park_fails.push(g.to_string()),
                    Some(("restore", g)) => m.restore_fails.push(g.to_string()),
                    _ => m.persist_fails = *injection == "persist",
                }
            });

            match *op {
                "park" => claim_locked(&mut st, &io, 1),
                _ => {
                    release_dns_locked(&mut st, &io, 1);
                    // release_dns_locked drops ownership once the record is
                    // empty; the next park in the script re-claims it.
                    st.owner = Some(1);
                }
            }

            io.assert_parked_subset_of_recorded(&format!("step {} ({} {})", step, op, injection));
        }
    }

    // ── I10 / #100 ───────────────────────────────────────────────

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn split_default_deletes_are_qualified_by_gateway_and_interface() {
        // THE BUG (#100): `route delete 0.0.0.0 mask 128.0.0.0` with no
        // qualifier removes every /1 on the machine — Cloudflare WARP's and
        // Tailscale's included.
        let argv = route_delete_argv(&OwnedRoute {
            dest: v4("0.0.0.0"),
            prefix_len: 1,
            next_hop: v4("0.0.0.0"),
            if_index: 27,
        })
        .expect("a route on a known interface is deletable");

        assert_eq!(
            argv,
            vec![
                "delete",
                "0.0.0.0",
                "mask",
                "128.0.0.0",
                "0.0.0.0",
                "IF",
                "27"
            ]
        );
        let tail = argv.join(" ");
        assert!(
            tail.ends_with("IF 27"),
            "the interface qualifier is what stops us deleting another product's /1"
        );
    }

    #[test]
    fn lan_sharing_deletes_are_qualified_too() {
        // The same defect at lower profile, and arguably the more damaging one:
        // a corporate 10.0.0.0/8 route via the physical gateway is common.
        let argv = route_delete_argv(&OwnedRoute {
            dest: v4("10.0.0.0"),
            prefix_len: 8,
            next_hop: v4("192.168.1.1"),
            if_index: 12,
        })
        .expect("deletable");
        assert_eq!(
            argv,
            vec![
                "delete",
                "10.0.0.0",
                "mask",
                "255.0.0.0",
                "192.168.1.1",
                "IF",
                "12"
            ]
        );
    }

    #[test]
    fn an_unattributable_route_is_never_deleted() {
        assert!(route_delete_argv(&OwnedRoute {
            dest: v4("0.0.0.0"),
            prefix_len: 1,
            next_hop: v4("0.0.0.0"),
            if_index: 0,
        })
        .is_none());
    }

    #[test]
    fn record_route_refuses_an_unattributable_route() {
        let mut routes = Vec::new();
        assert!(!push_owned_route(
            &mut routes,
            OwnedRoute {
                dest: v4("0.0.0.0"),
                prefix_len: 1,
                next_hop: v4("0.0.0.0"),
                if_index: 0,
            }
        ));
        assert!(
            routes.is_empty(),
            "a route we cannot attribute to an interface must never enter the delete list"
        );

        let ours = OwnedRoute {
            dest: v4("0.0.0.0"),
            prefix_len: 1,
            next_hop: v4("0.0.0.0"),
            if_index: 27,
        };
        assert!(push_owned_route(&mut routes, ours));
        // Idempotent: a reconnect re-adds the same rows and each must be
        // deleted exactly once.
        assert!(push_owned_route(&mut routes, ours));
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn the_birdo_adapter_guid_renders_in_the_form_the_os_reports() {
        // GetAdaptersAddresses reports AdapterName in this form, and it is how
        // we recognise (and refuse to park) our own tunnel adapter even when the
        // user has renamed the connection.
        assert_eq!(
            guid_registry_string(super::ADAPTER_GUID),
            "{000B1BD0-0000-0001-0000-0000B1BD0B1D}"
        );
    }

    #[test]
    fn the_endpoint_host_route_keeps_its_gateway() {
        let argv = route_delete_argv(&OwnedRoute {
            dest: v4("203.0.113.7"),
            prefix_len: 32,
            next_hop: v4("192.168.1.1"),
            if_index: 12,
        })
        .expect("deletable");
        assert_eq!(argv[3], "255.255.255.255");
        assert_eq!(argv[4], "192.168.1.1");
    }

    // ── record keying ────────────────────────────────────────────

    #[test]
    fn a_legacy_journal_entry_without_a_guid_is_keyed_by_name() {
        // Records written before GUID keying must still reconcile after an
        // upgrade — the machine they describe is a machine with no resolvers.
        let legacy = snap("", "Wi-Fi", true, &[], true, &[]);
        assert_eq!(entry_key(&legacy), "name:WI-FI");
        let modern = snap("{A}", "Wi-Fi", true, &[], true, &[]);
        assert_eq!(entry_key(&modern), "{A}");
    }
}
