//! Process-global owner of the Windows machine state a VPN session changes.
//!
//! # What that is now
//!
//! * **The DNS guard** — WFP filters in the dynamic session that let DNS out
//!   only to the tunnel's resolvers over the tunnel (W1-007, see
//!   `wfp_policy`). They replaced "parking" every physical adapter's DNS on
//!   `static none`, which rewrote the machine's PERSISTENT configuration:
//!   every unclean exit (End task, a crash, power loss, an update or an
//!   uninstall of a killed app) left the machine without DNS until BirdoVPN
//!   ran again, and on an adapter with STATIC resolvers the park did not even
//!   take — the static list was erased, Windows fell back to the DHCP lease,
//!   and the un-park then read "carries resolvers again" and dropped the
//!   record, so the user's own DNS settings were gone for good. Nothing here
//!   rewrites adapter DNS any more.
//! * **Routes** this process installed, deleted exactly and only by their
//!   owner (I10), and journaled when they outlive the tunnel adapter so a
//!   crash no longer leaves them behind (W1-041).
//! * **The heal of older builds' parks.** Machines parked by builds before
//!   this one still carry the durable record (`dns-restore.json`); the startup
//!   reconcile, the uninstaller's `--reconcile-and-exit` and every later
//!   release retry it until it converges. It is fed no new parks.
//!
//! # The invariants that survive (numbered as in issue #105)
//!
//! * **I1 SINGLE OWNER** — at most one generation owns the DNS guard, the
//!   routes and any adopted record. A holder whose generation is not the
//!   current one performs NO machine-state mutation of any kind. Every public
//!   mutator starts with that check; a non-owner is a no-op, not an error.
//!   That is also what holds the DNS guard across a server switch: the
//!   outgoing tunnel no longer owns it, so it cannot lift it.
//! * **I4 THE RECORD BEFORE THE LOSS** — a gateway route is journaled as soon
//!   as it is in, and a record entry is dropped only for state a read-back
//!   PROVED is back.
//! * **I5 OBSERVED, NOT ASSUMED** — every restore is read back; a read that
//!   fails is an error, never a configuration.
//! * **I7 STABLE IDENTITY** — records are keyed by interface GUID; names are
//!   re-resolved at restore time.
//! * **I10 ROUTE OWNERSHIP** — a route is deleted only by the owner that
//!   installed it, matched on (destination prefix, interface index, next hop).
//!   An unattributable route (interface index 0) is never deleted (#100).
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
use super::wfp_policy::DnsGuard;

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

/// One adapter as the OS describes it, not as netsh prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdapterId {
    /// Interface GUID string, `{XXXXXXXX-...}`, upper-cased. The record key
    /// (I7). Empty only for a legacy journal entry written before GUID keying.
    pub(super) guid: String,
    /// Current friendly name (the connection alias netsh addresses). A log
    /// label and a netsh argument — never an identity.
    pub(super) name: String,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct OwnedRoute {
    pub(super) dest: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) next_hop: IpAddr,
    pub(super) if_index: u32,
}

impl OwnedRoute {
    /// Routes via a gateway sit on a PHYSICAL interface and survive the
    /// process (the endpoint host route, the LAN-sharing routes); on-link
    /// routes live on the Wintun adapter and go with it. Only the first kind
    /// is journaled (W1-041) — and only it can be deleted safely after a
    /// crash, because a gateway makes the row specific to us, whereas the
    /// Wintun interface index may since belong to another product's tunnel
    /// with its own on-link /1.
    fn outlives_the_tunnel(&self) -> bool {
        !self.next_hop.is_unspecified()
    }
}

struct MachineState {
    /// The generation permitted to mutate. `None` = nothing is held.
    owner: Option<Gen>,
    /// The owner has the DNS guard installed.
    dns_guard: bool,
    /// Adapters a PREVIOUS build parked and this process could not yet
    /// restore, adopted from the record at start-up. Retried on every release.
    park: BTreeMap<String, AdapterDnsSnapshot>,
    /// Routes this process installed, for owner-qualified deletion (I10).
    routes: Vec<OwnedRoute>,
    /// What the user should know about DNS right now, keyed so an entry CLEARS
    /// when its cause does. Surfaced through `VpnStatus::dns_degraded`.
    degraded: BTreeMap<String, Degradation>,
}

/// One thing that is wrong with DNS, and whether the USER has any stake in it.
struct Degradation {
    /// A short sentence for the status banner.
    report: String,
    /// Show it to the user. False only for a recorded adapter that is not
    /// attached: it stays on record (it is the only thing that still knows its
    /// resolvers) but there is nothing to act on.
    reportable: bool,
}

impl Degradation {
    fn fault(report: String) -> Self {
        Self {
            report,
            reportable: true,
        }
    }

    fn dormant(report: String) -> Self {
        Self {
            report,
            reportable: false,
        }
    }
}

/// The degradation key for the tunnel interface's own resolvers.
const TUNNEL_DNS_KEY: &str = "tunnel-dns";

static STATE: Mutex<MachineState> = Mutex::new(MachineState {
    owner: None,
    dns_guard: false,
    park: BTreeMap::new(),
    routes: Vec::new(),
    degraded: BTreeMap::new(),
});

/// A poisoned lock still describes real machine state, and refusing to look at
/// it would strand what it names. Recover the value instead.
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
    fn restore_dns(&self, adapter: &AdapterId, entry: &AdapterDnsSnapshot) -> Result<(), String>;
    fn persist(&self, adapters: &[AdapterDnsSnapshot], routes: &[OwnedRoute])
        -> Result<(), String>;
    fn clear_record(&self);
    fn add_route(&self, route: &OwnedRoute) -> Result<(), String>;
    /// Whether the route is gone (deleted, or already not there).
    fn delete_route(&self, route: &OwnedRoute) -> bool;
    fn install_dns_guard(&self, guard: &DnsGuard) -> Result<(), String>;
    fn release_dns_guard(&self);
}

/// The real implementation: native IP Helper for enumeration and routes, WFP
/// for the DNS guard, netsh for the legacy restores.
///
/// The reads stay on netsh (not the registry) because "DHCP-sourced" versus
/// "static with no servers" is not a single registry value, and a restore
/// must be verified through the mechanism that wrote it.
pub(super) struct SystemIo;

impl MachineIo for SystemIo {
    fn enumerate(&self) -> Result<Vec<AdapterId>, String> {
        enumerate_adapters_native()
    }

    fn read_dns(&self, adapter: &AdapterId) -> Result<AdapterDnsSnapshot, String> {
        // Both families or nothing. Half a reading is not a reading.
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

    fn restore_dns(&self, adapter: &AdapterId, entry: &AdapterDnsSnapshot) -> Result<(), String> {
        let (v4_dhcp, v4_servers) = intent_v4(entry);
        let (v6_dhcp, v6_servers) = intent_v6(entry);
        // Both families, unconditionally. An adapter left with its IPv6
        // resolvers suppressed because the IPv4 write failed is a half-restored
        // adapter that reads as restored.
        let v4 = restore_family(&adapter.name, "ip", &v4_servers, v4_dhcp);
        let v6 = restore_family(&adapter.name, "ipv6", &v6_servers, v6_dhcp);
        join_family_results(v4, v6)
    }

    fn persist(
        &self,
        adapters: &[AdapterDnsSnapshot],
        routes: &[OwnedRoute],
    ) -> Result<(), String> {
        crate::vpn::dns_journal::record_windows(adapters, routes)
    }

    fn clear_record(&self) {
        crate::vpn::dns_journal::clear();
    }

    fn add_route(&self, route: &OwnedRoute) -> Result<(), String> {
        match (route.dest, route.next_hop) {
            (IpAddr::V4(dest), IpAddr::V4(next_hop)) => {
                super::tunnel::add_route_native(dest, route.prefix_len, next_hop, route.if_index, 1)
            }
            _ => Err("only IPv4 routes are moved".to_string()),
        }
    }

    fn delete_route(&self, route: &OwnedRoute) -> bool {
        delete_owned_route(route)
    }

    fn install_dns_guard(&self, guard: &DnsGuard) -> Result<(), String> {
        crate::vpn::wfp::set_dns_guard(Some(guard.clone()))
    }

    fn release_dns_guard(&self) {
        if let Err(e) = crate::vpn::wfp::set_dns_guard(None) {
            tracing::warn!("Could not lift the DNS guard: {}", e);
        }
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

/// Run one netsh invocation and treat a non-zero exit as a failure (I5).
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
/// NOT `was_dhcp` = the adapter was ALREADY `static` with no servers before it
/// was parked, so the restore is a no-op too. Forcing DHCP there is what
/// silently reconfigured VirtualBox / Hyper-V / OpenVPN adapters on every
/// disconnect (#96) — `was_dhcp` is NOT `servers.is_empty()`.
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
                "{} ({}): was static with no servers — leaving as-is",
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
// Pure shape helpers — the vocabulary the heal reasons in
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
/// re-learns it once the adapter is back on DHCP/RA, and pinning a zone-scoped
/// address statically would outlive the router that advertised it. So an
/// adapter whose only IPv6 resolvers were link-local goes back to DHCP/RA; one
/// with NO IPv6 resolvers at all is the genuinely-static-with-none case.
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

/// Where one address family of a recorded adapter stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FamilyState {
    /// Already what the record says it was.
    Restored,
    /// What a park left behind: the record must be written back.
    Parked,
    /// Configured since by someone else: not ours to rewrite.
    Foreign,
}

/// Is this family still the way a park left it?
///
/// A park wrote `static none`, and that reads back one of two ways:
///   * `static` with no servers — the shape the old heal knew about;
///   * sourced from DHCP, when the adapter had STATIC resolvers: `static none`
///     erases the static list and Windows falls back to the lease. The old heal
///     read that as "carries resolvers again — not ours", dropped the record,
///     and the user's static DNS was lost for good (measured on the owner's
///     machine against 1.4.45: `WiFi 3`, static 8.8.8.8 / 8.8.4.4, on DHCP
///     resolvers after two connect/disconnect cycles).
///
/// Anything else — a static list other than the recorded one, DHCP on a family
/// the park never touched — is someone else's configuration.
fn family_state(intent: (bool, &[String]), live: (bool, &[String])) -> FamilyState {
    let (intent_dhcp, intent_servers) = intent;
    let (live_dhcp, live_servers) = live;
    let static_none = !live_dhcp && live_servers.is_empty();
    let erased_to_dhcp = !intent_dhcp && !intent_servers.is_empty() && live_dhcp;
    if live_dhcp == intent_dhcp && live_servers == intent_servers {
        FamilyState::Restored
    } else if static_none || erased_to_dhcp {
        FamilyState::Parked
    } else {
        FamilyState::Foreign
    }
}

/// Where a recorded adapter stands, both families together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    /// Nothing to do: drop the record entry.
    Restored,
    /// Write the record back and verify.
    NeedsRestore,
    /// Someone reconfigured it since: drop the entry, touch nothing.
    Foreign,
}

fn entry_state(entry: &AdapterDnsSnapshot, live: &AdapterDnsSnapshot) -> EntryState {
    let (v4_dhcp, v4) = intent_v4(entry);
    let (v6_dhcp, v6) = intent_v6(entry);
    let families = [
        family_state((v4_dhcp, &v4), (live.v4_was_dhcp, &live.dns_servers)),
        family_state((v6_dhcp, &v6), (live.v6_was_dhcp, &live.dns_servers_v6)),
    ];
    if families.contains(&FamilyState::Foreign) {
        EntryState::Foreign
    } else if families.contains(&FamilyState::Parked) {
        EntryState::NeedsRestore
    } else {
        EntryState::Restored
    }
}

/// Does a live reading match what `restore_dns` intended to write?
fn matches_intent(entry: &AdapterDnsSnapshot, live: &AdapterDnsSnapshot) -> bool {
    entry_state(entry, live) == EntryState::Restored
}

// ──────────────────────────────────────────────────────────────
// The heal of older builds' parks
// ──────────────────────────────────────────────────────────────

/// Put back every recorded adapter, and drop from the record only the entries
/// whose read-back matched.
///
/// ```text
/// for each recorded entry E:
///   0. Is E's adapter attached? Absent (from a SUCCESSFUL enumeration)
///                           ⇒ keep E, touch nothing, do NOT report.
///   1. READ E's live state. Restored or foreign ⇒ drop E, touch nothing.
///                           Read FAILED        ⇒ keep E, touch nothing, report.
///   2. WRITE the recorded origin (both families).
///   3. READ BACK. Match ⇒ drop E. Mismatch ⇒ one retry, then keep E + report.
/// ```
///
/// Every entry has a terminal state and reaches it; a retained entry is always
/// the safe direction (it costs one more guarded read next time).
///
/// Returns whether anything was actually written back.
fn restore_pass(
    park: &mut BTreeMap<String, AdapterDnsSnapshot>,
    io: &dyn MachineIo,
    degraded: &mut BTreeMap<String, Degradation>,
) -> bool {
    // `None` when enumeration FAILED, which is not the same as "no adapters":
    // collapsing the two would make every entry look dormant on a machine
    // where enumeration is broken, and dormancy suppresses the report (I5).
    let present: Option<BTreeMap<String, String>> = match io.enumerate() {
        Ok(list) => Some(
            list.into_iter()
                .filter(|a| !a.guid.is_empty())
                .map(|a| (a.guid, a.name))
                .collect(),
        ),
        Err(e) => {
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
        // I7: address each entry by the CURRENT name for its GUID.
        let name = current_names
            .get(&entry.adapter_guid)
            .cloned()
            .unwrap_or_else(|| entry.adapter_name.clone());
        let adapter = AdapterId {
            guid: entry.adapter_guid.clone(),
            name,
        };
        let label = adapter.name.clone();

        // 0. Is it even here? A detached adapter keeps its record (Windows
        // keeps the parked configuration under its GUID across an unplug), but
        // there is nothing the user could do about it, so it is not reported.
        if let Some(present) = &present {
            let attached = if entry.adapter_guid.is_empty() {
                present
                    .values()
                    .any(|n| n.eq_ignore_ascii_case(&entry.adapter_name))
            } else {
                present.contains_key(&entry.adapter_guid)
            };
            if !attached {
                tracing::info!(
                    "{}: recorded as parked but not attached — keeping the record for a re-attach",
                    entry.adapter_name
                );
                degraded.insert(
                    key,
                    Degradation::dormant(format!(
                        "{}: its DNS settings will be restored when it is reconnected",
                        entry.adapter_name
                    )),
                );
                continue;
            }
        }

        // 1. Where does it stand?
        let live = match io.read_dns(&adapter) {
            Ok(live) => live,
            Err(e) => {
                tracing::error!(
                    "{}: live DNS unreadable during restore ({}) — leaving it alone and KEEPING \
                     the record",
                    label,
                    e
                );
                degraded.insert(key, Degradation::fault(unrestored(&label)));
                continue;
            }
        };
        match entry_state(&entry, &live) {
            EntryState::Restored => {
                tracing::info!("{}: DNS is already as it was — dropping the record", label);
                park.remove(&key);
                degraded.remove(&key);
                continue;
            }
            EntryState::Foreign => {
                tracing::info!("{}: DNS was reconfigured since — leaving it alone", label);
                park.remove(&key);
                degraded.remove(&key);
                continue;
            }
            EntryState::NeedsRestore => {}
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
                label,
                attempt,
                last_problem
            );
        }

        if verified {
            tracing::info!("{}: DNS restored to its pre-connect configuration", label);
            park.remove(&key);
            degraded.remove(&key);
        } else {
            tracing::error!(
                "{}: DNS could not be verifiably restored ({}) — KEEPING the record so a later \
                 pass can finish the job",
                label,
                last_problem
            );
            degraded.insert(key, Degradation::fault(unrestored(&label)));
        }
    }
    restored_any
}

/// The banner sentence for an adapter an earlier session left changed.
fn unrestored(adapter: &str) -> String {
    format!("{adapter}: DNS settings changed by an earlier Birdo version could not be restored")
}

/// Nothing is held any more ⇒ nobody owns anything.
fn release_owner_if_clean(st: &mut MachineState) {
    if st.park.is_empty() && st.routes.is_empty() && !st.dns_guard {
        st.owner = None;
    }
}

/// Write the record out (the adopted adapters and the journaled routes), or
/// delete it when there is nothing left to describe. Never cleared while
/// entries remain: those entries are then the only thing that still knows
/// what to put back (I5).
fn flush_record(st: &MachineState, io: &dyn MachineIo) {
    let routes: Vec<OwnedRoute> = st
        .routes
        .iter()
        .copied()
        .filter(OwnedRoute::outlives_the_tunnel)
        .collect();
    if st.park.is_empty() && routes.is_empty() {
        io.clear_record();
        return;
    }
    let entries: Vec<AdapterDnsSnapshot> = st.park.values().cloned().collect();
    if let Err(e) = io.persist(&entries, &routes) {
        tracing::error!(
            "Could not update the machine-state journal ({}) — a crash now may leave a route \
             behind",
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
/// every route and the DNS guard that follow are attributable to this
/// generation and no other holder may undo them. Adopts whatever a previous
/// generation left in force: on a reconnect the manager holds the DNS guard and
/// the routes across the gap, and this is where the incoming tunnel picks them
/// up.
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
        "Machine state ownership: {:?} -> {} ({} route(s), DNS guard {}, {} adopted record(s))",
        st.owner,
        gen,
        st.routes.len(),
        st.dns_guard,
        st.park.len()
    );
    // A genuinely fresh session starts with a clean report, so the UI shows
    // THIS session's problems. Adopted records keep theirs: those adapters are
    // still unrestored.
    if st.park.is_empty() && st.routes.is_empty() && !st.dns_guard {
        st.degraded.clear();
    }
    st.owner = Some(gen);
}

/// Install the DNS guard for the live tunnel of `gen` (W1-007). Fails — and the
/// connect with it — when it cannot be installed: DNS must never be left free to
/// leave outside the tunnel.
pub(super) fn guard_dns(gen: Gen, guard: DnsGuard) -> Result<(), String> {
    let io = SystemIo;
    let mut st = state();
    guard_dns_locked(&mut st, &io, gen, guard)
}

fn guard_dns_locked(
    st: &mut MachineState,
    io: &dyn MachineIo,
    gen: Gen,
    guard: DnsGuard,
) -> Result<(), String> {
    if st.owner != Some(gen) {
        return Err("this tunnel no longer owns the machine state".to_string());
    }
    io.install_dns_guard(&guard)?;
    st.dns_guard = true;
    Ok(())
}

/// Record whether the tunnel interface got its resolvers. Without them the
/// guard leaves nothing to resolve with — the session is protected but names
/// do not resolve, and the user must be told rather than left guessing.
pub(super) fn note_tunnel_dns(gen: Gen, applied: bool) {
    let mut st = state();
    note_tunnel_dns_locked(&mut st, gen, applied);
}

fn note_tunnel_dns_locked(st: &mut MachineState, gen: Gen, applied: bool) {
    if st.owner != Some(gen) {
        return;
    }
    if applied {
        st.degraded.remove(TUNNEL_DNS_KEY);
    } else {
        st.degraded.insert(
            TUNNEL_DNS_KEY.to_string(),
            Degradation::fault(
                "The VPN's DNS servers could not be set, so websites may not load".to_string(),
            ),
        );
    }
}

/// Core of [`release_dns`]: lift the DNS guard and retry any adopted record.
/// Returns whether any adapter DNS was put back.
///
/// The ownership check lives HERE, not in the caller, so there is no path to the
/// machine that skips it (I1).
fn release_dns_locked(st: &mut MachineState, io: &dyn MachineIo, gen: Gen) -> bool {
    if st.owner != Some(gen) {
        tracing::debug!(
            "Generation {} asked to release DNS but does not own it (owner {:?}) — doing nothing",
            gen,
            st.owner
        );
        return false;
    }
    if st.dns_guard {
        io.release_dns_guard();
        st.dns_guard = false;
    }
    st.degraded.remove(TUNNEL_DNS_KEY);
    let restored = if st.park.is_empty() {
        false
    } else {
        let mut degraded = std::mem::take(&mut st.degraded);
        let restored = restore_pass(&mut st.park, io, &mut degraded);
        st.degraded = degraded;
        flush_record(st, io);
        restored
    };
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
    // A route whose delete failed is still ours and still installed: it
    // stays recorded (and journaled, when it outlives the tunnel), so the
    // owner keeps it and the next release or start-up retries it
    // (REVIEW-WIN2-032).
    let total = routes.len();
    st.routes = routes
        .into_iter()
        .filter(|route| !io.delete_route(route))
        .collect();
    if total > 0 {
        tracing::debug!(
            "Removed {} of {} owned route(s)",
            total - st.routes.len(),
            total
        );
        flush_record(st, io);
    }
    release_owner_if_clean(st);
}

/// Is `gen` the current owner? The liveness predicate every teardown decision
/// should ask instead of reading `ConnectionState` (I3).
pub(super) fn is_owner(gen: Gen) -> bool {
    state().owner == Some(gen)
}

/// Move ownership to a fresh generation held by the caller, so a tunnel that is
/// about to be disposed cannot lift the DNS guard or delete routes on its way
/// out.
///
/// They stay IN FORCE across the gap — the physical NICs never get their DNS
/// back during the create + handshake window of a switch. The incoming tunnel
/// adopts them; if no incoming tunnel arrives, the caller must [`release_all`]
/// the returned generation.
pub(super) fn begin_transition() -> Gen {
    let gen = next_generation();
    let mut st = state();
    begin_transition_locked(&mut st, gen);
    gen
}

/// Core of [`begin_transition`], over an explicit state so the tests can drive
/// it.
fn begin_transition_locked(st: &mut MachineState, gen: Gen) {
    if st.owner.is_some() || !st.park.is_empty() || !st.routes.is_empty() || st.dns_guard {
        tracing::debug!(
            "Machine state held across a transition by generation {} (was {:?})",
            gen,
            st.owner
        );
        st.owner = Some(gen);
    }
}

/// Lift the DNS guard and retry any adopted record. Owner only. Returns whether
/// any adapter DNS was put back.
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
/// deleted later. A gateway route is journaled at once (W1-041).
///
/// An interface index of 0 is refused: a route we cannot attribute to an
/// interface is a route we must never delete. That is the difference between
/// removing our own `0.0.0.0/1` and removing Cloudflare WARP's (#100).
pub(super) fn record_route(gen: Gen, route: OwnedRoute) {
    let io = SystemIo;
    let mut st = state();
    record_route_locked(&mut st, &io, gen, route);
}

fn record_route_locked(st: &mut MachineState, io: &dyn MachineIo, gen: Gen, route: OwnedRoute) {
    if st.owner != Some(gen) {
        return;
    }
    let already = st.routes.contains(&route);
    if !push_owned_route(&mut st.routes, route) {
        tracing::warn!(
            "Not recording route {}/{} — with no interface index it could not be deleted \
             later in a way that is guaranteed to hit only ours",
            route.dest,
            route.prefix_len
        );
        return;
    }
    if !already && route.outlives_the_tunnel() {
        flush_record(st, io);
    }
}

/// Append `route` unless it is unattributable or already recorded. Returns
/// whether the route is now in the list.
fn push_owned_route(routes: &mut Vec<OwnedRoute>, route: OwnedRoute) -> bool {
    if route.if_index == 0 {
        return false;
    }
    if !routes.contains(&route) {
        routes.push(route);
    }
    true
}

/// Replace one owned route with another: add `new`, record it, then delete
/// exactly `old` (I10). Owner only (I1), all under the one lock, so ownership
/// cannot move halfway.
///
/// If `new` cannot be added, nothing changes and the error is returned. A
/// failure to delete `old` leaves nothing of ours behind that the owner does
/// not still know about: it is dropped from the list only after the delete.
fn replace_route_locked(
    st: &mut MachineState,
    io: &dyn MachineIo,
    gen: Gen,
    old: OwnedRoute,
    new: OwnedRoute,
) -> Result<(), String> {
    if st.owner != Some(gen) {
        return Err("this tunnel no longer owns the machine state".to_string());
    }
    if old == new {
        return Ok(());
    }
    if new.if_index == 0 {
        return Err("the new route has no interface".to_string());
    }
    io.add_route(&new)?;
    push_owned_route(&mut st.routes, new);
    flush_record(st, io);
    if st.routes.contains(&old) && io.delete_route(&old) {
        st.routes.retain(|r| *r != old);
        flush_record(st, io);
    }
    Ok(())
}

/// W1-003: the default route moved from `from` to `to` (gateway, interface).
/// Move every gateway route this owner holds on the old path — the endpoint
/// host route and the LAN-sharing routes — onto the new one, one exact
/// replacement at a time. Returns how many moved.
pub(super) fn move_gateway_routes(
    gen: Gen,
    from: (Ipv4Addr, u32),
    to: (Ipv4Addr, u32),
) -> Result<usize, String> {
    let io = SystemIo;
    let mut st = state();
    move_gateway_routes_locked(&mut st, &io, gen, from, to)
}

fn move_gateway_routes_locked(
    st: &mut MachineState,
    io: &dyn MachineIo,
    gen: Gen,
    from: (Ipv4Addr, u32),
    to: (Ipv4Addr, u32),
) -> Result<usize, String> {
    if st.owner != Some(gen) {
        return Err("this tunnel no longer owns the machine state".to_string());
    }
    let on_old_path: Vec<OwnedRoute> = st
        .routes
        .iter()
        .copied()
        .filter(|r| r.next_hop == IpAddr::V4(from.0) && r.if_index == from.1)
        .collect();
    for old in &on_old_path {
        let new = OwnedRoute {
            next_hop: IpAddr::V4(to.0),
            if_index: to.1,
            ..*old
        };
        replace_route_locked(st, io, gen, *old, new)?;
    }
    Ok(on_old_path.len())
}

/// Every DNS problem the user should know about right now, one short sentence
/// each (see the `dns_degraded` field of `VpnStatus`).
///
/// # Why this does not block
///
/// The status is built on a tokio worker, and a restore pass holds the lock
/// across netsh spawns. The honest answer while a pass is mutating the map it
/// summarises is the last complete one, not a stalled thread.
pub fn degradation_report() -> Vec<String> {
    static LAST: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let Ok(st) = STATE.try_lock() else {
        return LAST.lock().unwrap_or_else(|e| e.into_inner()).clone();
    };
    let report: Vec<String> = st
        .degraded
        .values()
        .filter(|d| d.reportable)
        .map(|d| d.report.clone())
        .collect();
    drop(st);
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = report.clone();
    report
}

/// Lift the guard and retry any adopted record on behalf of whoever owns them.
///
/// ONLY for process-exit paths that cannot run the teardown — the updater
/// relaunch and the timed-out exit teardown. The DNS guard dies with the
/// process anyway (dynamic WFP session); what matters here is the retry of any
/// record a previous build left.
pub fn release_dns_at_exit() -> bool {
    let owner = state().owner;
    match owner {
        Some(gen) => release_dns(gen),
        None => false,
    }
}

/// Load the entries a reconcile could NOT restore into the RUNNING process, so
/// the record on disk and the record in memory describe the same machine, and
/// every later release (disconnect, quit) retries them.
///
/// Refuses to act when this process already holds state of its own — from the
/// panic hook that state is the newer truth and the file must not overwrite it.
fn adopt_unrestored(st: &mut MachineState, park: BTreeMap<String, AdapterDnsSnapshot>) {
    if park.is_empty() {
        return;
    }
    if !st.park.is_empty() || st.owner.is_some() {
        tracing::debug!(
            "Not adopting {} unrestored record entr(ies) — this process already owns machine \
             state (owner {:?})",
            park.len(),
            st.owner
        );
        return;
    }
    let gen = next_generation();
    tracing::warn!(
        "Adopting {} adapter(s) an earlier version left changed and that could not be \
         restored yet — generation {} owns them, and the next disconnect or quit retries",
        park.len(),
        gen
    );
    st.park = park;
    st.owner = Some(gen);
}

/// Is a journal written in boot `recorded` about THIS boot (`now`)? Routes are
/// not persistent: a reboot removes them, and after one an interface index may
/// name another adapter, so a journaled route is only ever deleted in the boot
/// that installed it. The tolerance absorbs clock adjustments between the two
/// readings.
fn same_boot(recorded: Option<u64>, now: Option<u64>) -> bool {
    const TOLERANCE_MS: u64 = 5 * 60 * 1000;
    match (recorded, now) {
        (Some(a), Some(b)) => a.abs_diff(b) <= TOLERANCE_MS,
        _ => false,
    }
}

/// When this boot began, in ms since the Unix epoch (the wall clock minus the
/// uptime). `None` if the clock is before 1970.
pub(super) fn boot_epoch_ms() -> Option<u64> {
    // SAFETY: GetTickCount64 has no preconditions.
    let uptime = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    now.checked_sub(uptime)
}

/// The crash twin: put back whatever a PREVIOUS process left behind, driven
/// entirely off the on-disk record — gateway routes a crash stranded (W1-041)
/// and adapters an older build parked.
///
/// Runs at start-up (no tunnel can be up that early), from the uninstaller's
/// `--reconcile-and-exit`, and from the panic hook. Deliberately never BLOCKS
/// on the global lock: the panic hook's thread may already hold it, and a
/// `std::sync::Mutex` re-entered on one thread deadlocks.
///
/// Owns the record's lifecycle itself — entries it could not verifiably
/// restore stay on disk.
pub(super) fn reconcile_record(
    entries: &[AdapterDnsSnapshot],
    routes: &[OwnedRoute],
    boot: Option<u64>,
) -> bool {
    let io = SystemIo;
    reconcile_record_with(&io, entries, routes, same_boot(boot, boot_epoch_ms()))
}

fn reconcile_record_with(
    io: &dyn MachineIo,
    entries: &[AdapterDnsSnapshot],
    routes: &[OwnedRoute],
    this_boot: bool,
) -> bool {
    if entries.is_empty() && routes.is_empty() {
        return false;
    }
    // REVIEW-WIN2-032: a route whose delete failed stays on record, for the
    // next start in this boot; it used to be forgotten with the rest.
    let mut undeleted: Vec<OwnedRoute> = Vec::new();
    if !routes.is_empty() {
        if this_boot {
            tracing::warn!(
                "Removing {} route(s) a previous session left behind",
                routes.len()
            );
            for route in routes.iter().filter(|r| r.outlives_the_tunnel()) {
                if !io.delete_route(route) {
                    undeleted.push(*route);
                }
            }
        } else {
            tracing::info!(
                "The journal's {} route(s) are from an earlier boot — already gone",
                routes.len()
            );
        }
    }
    let mut park: BTreeMap<String, AdapterDnsSnapshot> =
        entries.iter().map(|e| (entry_key(e), e.clone())).collect();
    let mut degraded: BTreeMap<String, Degradation> = BTreeMap::new();
    let restored = if park.is_empty() {
        false
    } else {
        tracing::warn!(
            "{} adapter(s) recorded as changed by an earlier session — checking whether they \
             still are",
            park.len()
        );
        restore_pass(&mut park, io, &mut degraded)
    };
    // Flush what survives: the adapters not yet restored, and the routes
    // that could not be deleted.
    let survivors = MachineState {
        owner: None,
        dns_guard: false,
        park: park.clone(),
        routes: undeleted,
        degraded: BTreeMap::new(),
    };
    flush_record(&survivors, io);
    // try_lock, never lock: see above. Losing the adoption from the panic hook
    // is acceptable — every entry was logged and the record is still on disk.
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

/// Enumerate every non-loopback, non-Birdo adapter with its GUID and current
/// friendly name.
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

/// Whether the route is gone afterwards.
fn delete_owned_route(route: &OwnedRoute) -> bool {
    match delete_route_native(route) {
        Ok(()) => {
            tracing::debug!(
                "Removed owned route {}/{} on IF {}",
                route.dest,
                route.prefix_len,
                route.if_index
            );
            return true;
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
        return false;
    };
    cmd("route")
        .args(&argv)
        .output()
        .is_ok_and(|out| out.status.success())
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

    /// The shape `park_dns` (older builds) left behind: `static`, no servers.
    fn parked(guid: &str, name: &str) -> AdapterDnsSnapshot {
        snap(guid, name, false, &[], false, &[])
    }

    #[derive(Default)]
    struct Machine {
        /// (adapter, live DNS configuration)
        adapters: Vec<(AdapterId, AdapterDnsSnapshot)>,
        persisted: Option<(Vec<AdapterDnsSnapshot>, Vec<OwnedRoute>)>,
        reads: Vec<String>,
        read_fails: Vec<String>,
        restore_fails: Vec<String>,
        enumerate_fails: bool,
        added_routes: Vec<OwnedRoute>,
        add_route_fails: bool,
        deleted_routes: Vec<OwnedRoute>,
        /// Routes whose delete fails (native and route.exe both).
        delete_fails: Vec<OwnedRoute>,
        guard: Option<DnsGuard>,
        guard_fails: bool,
    }

    struct FakeIo(RefCell<Machine>);

    impl FakeIo {
        fn new(m: Machine) -> Self {
            FakeIo(RefCell::new(m))
        }
        fn with<R>(&self, f: impl FnOnce(&mut Machine) -> R) -> R {
            f(&mut self.0.borrow_mut())
        }
        fn live(&self, key: &str) -> AdapterDnsSnapshot {
            self.with(|m| {
                m.adapters
                    .iter()
                    .find(|(a, _)| record_key(&a.guid, &a.name) == key)
                    .map(|(_, s)| s.clone())
                    .expect("adapter exists")
            })
        }
        fn journaled_routes(&self) -> Vec<OwnedRoute> {
            self.with(|m| m.persisted.clone().map(|(_, r)| r).unwrap_or_default())
        }
    }

    impl MachineIo for FakeIo {
        fn enumerate(&self) -> Result<Vec<AdapterId>, String> {
            self.with(|m| {
                if m.enumerate_fails {
                    return Err("enumeration unavailable".to_string());
                }
                Ok(m.adapters.iter().map(|(a, _)| a.clone()).collect())
            })
        }

        fn read_dns(&self, adapter: &AdapterId) -> Result<AdapterDnsSnapshot, String> {
            self.with(|m| {
                let key = record_key(&adapter.guid, &adapter.name);
                m.reads.push(key.clone());
                if m.read_fails.contains(&key) {
                    return Err("netsh exited 1".to_string());
                }
                m.adapters
                    .iter()
                    .find(|(a, _)| a.guid == adapter.guid)
                    .map(|(_, s)| s.clone())
                    .ok_or_else(|| "no such adapter".to_string())
            })
        }

        fn restore_dns(
            &self,
            adapter: &AdapterId,
            entry: &AdapterDnsSnapshot,
        ) -> Result<(), String> {
            self.with(|m| {
                if m.restore_fails.contains(&adapter.guid) {
                    return Err("netsh set dns failed".to_string());
                }
                let (v4_dhcp, v4) = intent_v4(entry);
                let (v6_dhcp, v6) = intent_v6(entry);
                for (a, live) in m.adapters.iter_mut() {
                    if a.guid == adapter.guid {
                        *live = AdapterDnsSnapshot {
                            adapter_name: a.name.clone(),
                            adapter_guid: a.guid.clone(),
                            v4_was_dhcp: v4_dhcp,
                            v6_was_dhcp: v6_dhcp,
                            dns_servers: v4.clone(),
                            dns_servers_v6: v6.clone(),
                        };
                    }
                }
                Ok(())
            })
        }

        fn persist(
            &self,
            adapters: &[AdapterDnsSnapshot],
            routes: &[OwnedRoute],
        ) -> Result<(), String> {
            self.with(|m| m.persisted = Some((adapters.to_vec(), routes.to_vec())));
            Ok(())
        }

        fn clear_record(&self) {
            self.with(|m| m.persisted = None);
        }

        fn add_route(&self, route: &OwnedRoute) -> Result<(), String> {
            self.with(|m| {
                if m.add_route_fails {
                    return Err("CreateIpForwardEntry2 failed".to_string());
                }
                m.added_routes.push(*route);
                Ok(())
            })
        }

        fn delete_route(&self, route: &OwnedRoute) -> bool {
            self.with(|m| {
                if m.delete_fails.contains(route) {
                    return false;
                }
                m.deleted_routes.push(*route);
                true
            })
        }

        fn install_dns_guard(&self, guard: &DnsGuard) -> Result<(), String> {
            self.with(|m| {
                if m.guard_fails {
                    return Err("FwpmFilterAdd0 failed".to_string());
                }
                m.guard = Some(guard.clone());
                Ok(())
            })
        }

        fn release_dns_guard(&self) {
            self.with(|m| m.guard = None);
        }
    }

    fn adapter(guid: &str, name: &str) -> AdapterId {
        AdapterId {
            guid: guid.to_string(),
            name: name.to_string(),
        }
    }

    fn state_owned_by(gen: Gen) -> MachineState {
        MachineState {
            owner: Some(gen),
            dns_guard: false,
            park: BTreeMap::new(),
            routes: Vec::new(),
            degraded: BTreeMap::new(),
        }
    }

    /// Two adapters an OLDER build parked: Wi-Fi was DHCP, Ethernet had two
    /// static resolvers. The record says so; the machine shows `static none`.
    fn parked_by_an_older_build() -> (FakeIo, MachineState) {
        let io = FakeIo::new(Machine {
            adapters: vec![
                (adapter("{A}", "Wi-Fi"), parked("{A}", "Wi-Fi")),
                (adapter("{B}", "Ethernet"), parked("{B}", "Ethernet")),
            ],
            ..Default::default()
        });
        let mut st = state_owned_by(1);
        for entry in [
            snap("{A}", "Wi-Fi", true, &[], true, &[]),
            snap(
                "{B}",
                "Ethernet",
                false,
                &["1.1.1.1", "8.8.8.8"],
                false,
                &[],
            ),
        ] {
            st.park.insert(entry_key(&entry), entry);
        }
        (io, st)
    }

    fn guard() -> DnsGuard {
        DnsGuard {
            resolvers: vec![Ipv4Addr::new(10, 13, 13, 1)],
            lan_resolvers: vec![],
            tunnel_luid: 9,
            lan_sharing: false,
            relay: None,
            self_exe: None,
        }
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn route(dest: &str, prefix_len: u8, next_hop: &str, if_index: u32) -> OwnedRoute {
        OwnedRoute {
            dest: v4(dest),
            prefix_len,
            next_hop: v4(next_hop),
            if_index,
        }
    }

    // ── W1-007: the DNS guard is machine state with one owner (I1) ─────

    #[test]
    fn the_guard_is_installed_by_the_owner_and_lifted_only_by_the_owner() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(7);
        guard_dns_locked(&mut st, &io, 7, guard()).expect("installed");
        assert_eq!(io.with(|m| m.guard.clone()), Some(guard()));

        // A server switch: the manager holds everything across the gap.
        begin_transition_locked(&mut st, 8);
        // The outgoing tunnel's stop()/Drop must not lift it.
        release_dns_locked(&mut st, &io, 7);
        assert!(
            io.with(|m| m.guard.is_some()),
            "a displaced tunnel lifted the DNS guard of the session that replaced it"
        );

        // The incoming tunnel adopts and re-installs over its own interface.
        take_ownership_locked(&mut st, 9);
        guard_dns_locked(&mut st, &io, 9, guard()).unwrap();
        release_dns_locked(&mut st, &io, 9);
        assert!(io.with(|m| m.guard.is_none()), "the owner lifts it");
        assert_eq!(st.owner, None, "nothing is held any more");
    }

    #[test]
    fn a_guard_that_cannot_be_installed_fails_the_connect() {
        let io = FakeIo::new(Machine {
            guard_fails: true,
            ..Default::default()
        });
        let mut st = state_owned_by(7);
        assert!(guard_dns_locked(&mut st, &io, 7, guard()).is_err());
        assert!(!st.dns_guard);
        assert!(
            guard_dns_locked(&mut state_owned_by(1), &io, 7, guard()).is_err(),
            "a non-owner installs nothing"
        );
    }

    /// Ownership is released only once nothing is held — the guard counts.
    #[test]
    fn the_owner_stays_while_the_guard_is_held() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(7);
        guard_dns_locked(&mut st, &io, 7, guard()).unwrap();
        release_routes_locked(&mut st, &io, 7);
        assert_eq!(st.owner, Some(7));
        release_dns_locked(&mut st, &io, 7);
        assert_eq!(st.owner, None);
    }

    #[test]
    fn the_tunnel_dns_failure_is_one_honest_sentence_and_clears() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(7);
        note_tunnel_dns_locked(&mut st, 7, false);
        let report: Vec<&str> = st.degraded.values().map(|d| d.report.as_str()).collect();
        assert_eq!(
            report,
            vec!["The VPN's DNS servers could not be set, so websites may not load"]
        );
        note_tunnel_dns_locked(&mut st, 7, true);
        assert!(st.degraded.is_empty());
        note_tunnel_dns_locked(&mut st, 7, false);
        release_dns_locked(&mut st, &io, 7);
        assert!(st.degraded.is_empty(), "the session that owned it is over");
    }

    // ── I10 / W1-041: routes ────────────────────────────────────────────

    #[test]
    fn a_non_owner_cannot_delete_the_live_tunnels_routes() {
        // The route half of #98: an orphan's Drop removed the /1 pair the LIVE
        // tunnel was routing over.
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(1);
        assert!(push_owned_route(
            &mut st.routes,
            route("0.0.0.0", 1, "0.0.0.0", 27)
        ));
        assert!(push_owned_route(
            &mut st.routes,
            route("128.0.0.0", 1, "0.0.0.0", 27)
        ));

        st.owner = Some(2); // a new tunnel adopts them

        release_routes_locked(&mut st, &io, 1);
        assert!(io.with(|m| m.deleted_routes.is_empty()));
        assert_eq!(st.routes.len(), 2);

        release_routes_locked(&mut st, &io, 2);
        assert_eq!(io.with(|m| m.deleted_routes.len()), 2);
        assert!(st.routes.is_empty());
    }

    /// W1-041: the routes that outlive the adapter reach the journal the
    /// moment they are in; the on-link Wintun routes never do.
    #[test]
    fn gateway_routes_are_journaled_and_on_link_routes_are_not() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(7);
        let endpoint = route("203.0.113.7", 32, "192.168.1.1", 12);
        let split = route("0.0.0.0", 1, "0.0.0.0", 27);
        let lan = route("10.0.0.0", 8, "192.168.1.1", 12);
        record_route_locked(&mut st, &io, 7, endpoint);
        assert_eq!(io.journaled_routes(), vec![endpoint]);
        record_route_locked(&mut st, &io, 7, split);
        record_route_locked(&mut st, &io, 7, lan);
        assert_eq!(io.journaled_routes(), vec![endpoint, lan]);

        // A clean teardown empties the journal again.
        release_routes_locked(&mut st, &io, 7);
        assert!(io.with(|m| m.persisted.is_none()));
    }

    /// REVIEW-WIN2-032: a route whose delete failed (native AND route.exe)
    /// is still installed, so it stays on record — journaled for the next
    /// start in this boot after a crash, and kept by its owner after a
    /// teardown — instead of being forgotten with the rest.
    #[test]
    fn a_route_that_could_not_be_deleted_stays_on_record() {
        let stuck = route("203.0.113.7", 32, "192.168.1.1", 12);
        let gone = route("10.0.0.0", 8, "192.168.1.1", 12);

        // After a crash: the journal keeps only the one still installed.
        let io = FakeIo::new(Machine {
            delete_fails: vec![stuck],
            ..Machine::default()
        });
        reconcile_record_with(&io, &[], &[stuck, gone], true);
        assert_eq!(io.with(|m| m.deleted_routes.clone()), vec![gone]);
        assert_eq!(io.journaled_routes(), vec![stuck]);

        // After a teardown: the owner keeps it, and it stays journaled.
        let io = FakeIo::new(Machine {
            delete_fails: vec![stuck],
            ..Machine::default()
        });
        let mut st = state_owned_by(7);
        record_route_locked(&mut st, &io, 7, stuck);
        record_route_locked(&mut st, &io, 7, gone);
        release_routes_locked(&mut st, &io, 7);
        assert_eq!(st.routes, vec![stuck]);
        assert_eq!(st.owner, Some(7), "the owner still holds a route");
        assert_eq!(io.journaled_routes(), vec![stuck]);

        // The next release deletes it once it can.
        io.with(|m| m.delete_fails.clear());
        release_routes_locked(&mut st, &io, 7);
        assert!(st.routes.is_empty());
        assert_eq!(st.owner, None);
        assert!(io.with(|m| m.persisted.is_none()));
    }

    #[test]
    fn a_crash_leftover_is_removed_at_the_next_start_in_the_same_boot_only() {
        let endpoint = route("203.0.113.7", 32, "192.168.1.1", 12);
        let split = route("0.0.0.0", 1, "0.0.0.0", 27);

        let io = FakeIo::new(Machine::default());
        reconcile_record_with(&io, &[], &[endpoint, split], true);
        assert_eq!(
            io.with(|m| m.deleted_routes.clone()),
            vec![endpoint],
            "only the gateway route is ours to delete after a crash"
        );
        assert!(
            io.with(|m| m.persisted.is_none()),
            "and the journal is cleared"
        );

        let io = FakeIo::new(Machine::default());
        reconcile_record_with(&io, &[], &[endpoint], false);
        assert!(
            io.with(|m| m.deleted_routes.is_empty()),
            "a reboot already removed it — and the index may name another adapter now"
        );
    }

    #[test]
    fn a_journal_is_from_this_boot_within_the_tolerance_only() {
        let boot = 1_790_000_000_000u64;
        assert!(same_boot(Some(boot), Some(boot + 30_000)));
        assert!(!same_boot(Some(boot), Some(boot + 3_600_000)));
        assert!(
            !same_boot(None, Some(boot)),
            "an older build's journal has no boot mark"
        );
    }

    // ── W1-003: roaming moves our routes exactly ─────────────────────────

    #[test]
    fn a_replaced_route_is_added_before_the_old_one_is_deleted_exactly() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(7);
        let old = route("203.0.113.7", 32, "192.168.1.1", 12);
        let new = route("203.0.113.7", 32, "10.0.0.1", 15);
        record_route_locked(&mut st, &io, 7, old);

        replace_route_locked(&mut st, &io, 7, old, new).expect("replaced");
        assert_eq!(io.with(|m| m.added_routes.clone()), vec![new]);
        assert_eq!(io.with(|m| m.deleted_routes.clone()), vec![old]);
        assert_eq!(st.routes, vec![new]);
        assert_eq!(io.journaled_routes(), vec![new]);
    }

    #[test]
    fn a_failed_replacement_changes_nothing() {
        let io = FakeIo::new(Machine {
            add_route_fails: true,
            ..Default::default()
        });
        let mut st = state_owned_by(7);
        let old = route("203.0.113.7", 32, "192.168.1.1", 12);
        record_route_locked(&mut st, &io, 7, old);
        assert!(replace_route_locked(
            &mut st,
            &io,
            7,
            old,
            route("203.0.113.7", 32, "10.0.0.1", 15)
        )
        .is_err());
        assert_eq!(st.routes, vec![old]);
        assert!(io.with(|m| m.deleted_routes.is_empty()));
    }

    #[test]
    fn a_non_owner_cannot_replace_a_route() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(8);
        let old = route("203.0.113.7", 32, "192.168.1.1", 12);
        st.routes.push(old);
        assert!(replace_route_locked(
            &mut st,
            &io,
            7,
            old,
            route("203.0.113.7", 32, "10.0.0.1", 15)
        )
        .is_err());
        assert!(io.with(|m| m.added_routes.is_empty() && m.deleted_routes.is_empty()));
    }

    #[test]
    fn a_roam_moves_every_gateway_route_on_the_old_path_and_nothing_else() {
        let io = FakeIo::new(Machine::default());
        let mut st = state_owned_by(7);
        let endpoint = route("203.0.113.7", 32, "192.168.1.1", 12);
        let lan = route("10.0.0.0", 8, "192.168.1.1", 12);
        let split = route("0.0.0.0", 1, "0.0.0.0", 27);
        let foreign_path = route("172.16.0.0", 12, "192.168.9.1", 30);
        for r in [endpoint, lan, split, foreign_path] {
            record_route_locked(&mut st, &io, 7, r);
        }
        let moved = move_gateway_routes_locked(
            &mut st,
            &io,
            7,
            ("192.168.1.1".parse().unwrap(), 12),
            ("10.0.0.1".parse().unwrap(), 15),
        )
        .unwrap();
        assert_eq!(moved, 2);
        assert!(st
            .routes
            .contains(&route("203.0.113.7", 32, "10.0.0.1", 15)));
        assert!(st.routes.contains(&route("10.0.0.0", 8, "10.0.0.1", 15)));
        assert!(st.routes.contains(&split));
        assert!(st.routes.contains(&foreign_path));
        assert!(!st.routes.contains(&endpoint) && !st.routes.contains(&lan));
    }

    #[test]
    fn split_default_deletes_are_qualified_by_gateway_and_interface() {
        // THE BUG (#100): `route delete 0.0.0.0 mask 128.0.0.0` with no
        // qualifier removes every /1 on the machine — Cloudflare WARP's and
        // Tailscale's included.
        let argv = route_delete_argv(&route("0.0.0.0", 1, "0.0.0.0", 27))
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
    }

    #[test]
    fn lan_sharing_deletes_are_qualified_too() {
        let argv = route_delete_argv(&route("10.0.0.0", 8, "192.168.1.1", 12)).expect("deletable");
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
        assert!(route_delete_argv(&route("0.0.0.0", 1, "0.0.0.0", 0)).is_none());
    }

    #[test]
    fn record_route_refuses_an_unattributable_route() {
        let mut routes = Vec::new();
        assert!(!push_owned_route(
            &mut routes,
            route("0.0.0.0", 1, "0.0.0.0", 0)
        ));
        assert!(routes.is_empty());
        let ours = route("0.0.0.0", 1, "0.0.0.0", 27);
        assert!(push_owned_route(&mut routes, ours));
        // Idempotent: a reconnect re-adds the same rows.
        assert!(push_owned_route(&mut routes, ours));
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn the_endpoint_host_route_keeps_its_gateway() {
        let argv =
            route_delete_argv(&route("203.0.113.7", 32, "192.168.1.1", 12)).expect("deletable");
        assert_eq!(argv[3], "255.255.255.255");
        assert_eq!(argv[4], "192.168.1.1");
    }

    #[test]
    fn the_birdo_adapter_guid_renders_in_the_form_the_os_reports() {
        assert_eq!(
            guid_registry_string(super::ADAPTER_GUID),
            "{000B1BD0-0000-0001-0000-0000B1BD0B1D}"
        );
    }

    // ── The heal of older builds' parks (I5, I7) ───────────────────────

    #[test]
    fn restore_puts_back_the_exact_pre_connect_configuration() {
        let (io, mut st) = parked_by_an_older_build();
        let mut degraded = BTreeMap::new();
        assert!(restore_pass(&mut st.park, &io, &mut degraded));
        assert!(st.park.is_empty(), "a verified restore clears the record");
        assert!(degraded.is_empty());
        assert!(io.live("{A}").v4_was_dhcp);
        assert_eq!(io.live("{B}").dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    /// The coordinator's live finding on 1.4.45: `WiFi 3` had STATIC 8.8.8.8
    /// / 8.8.4.4. The park's `static none` erased them, Windows fell back to
    /// the DHCP lease, and the old heal read "carries resolvers again — not
    /// ours" and dropped the record: the user's DNS settings, gone. The heal
    /// must put the static list back.
    #[test]
    fn a_static_list_the_park_erased_is_restored_not_abandoned() {
        let io = FakeIo::new(Machine {
            adapters: vec![(
                adapter("{W}", "WiFi 3"),
                // What the machine shows after the park: v4 on DHCP, v6 on DHCP.
                snap("{W}", "WiFi 3", true, &[], true, &[]),
            )],
            ..Default::default()
        });
        let recorded = snap("{W}", "WiFi 3", false, &["8.8.8.8", "8.8.4.4"], true, &[]);
        let mut park = BTreeMap::new();
        park.insert(entry_key(&recorded), recorded);

        let mut degraded = BTreeMap::new();
        assert!(restore_pass(&mut park, &io, &mut degraded));
        let live = io.live("{W}");
        assert!(!live.v4_was_dhcp, "the adapter is static again");
        assert_eq!(live.dns_servers, vec!["8.8.8.8", "8.8.4.4"]);
        assert!(live.v6_was_dhcp, "the untouched IPv6 side stays on DHCP");
        assert!(park.is_empty() && degraded.is_empty());
    }

    /// The same regression, read the way the heal really reads it: through
    /// netsh's text. After the erase the adapter shows a DHCP LEASE (the
    /// router's resolvers), which the parser deliberately does not capture as
    /// configuration. That reading — DHCP with resolvers present — must still
    /// classify as the park's leftover (static v4 recorded, empty v6), and the
    /// write-back must be the recorded list exactly: same servers, same order,
    /// nothing from the lease.
    #[test]
    fn the_erase_seen_through_netsh_with_a_dhcp_lease_is_still_ours_to_restore() {
        use super::super::tunnel_dns::{parse_dns_config_v4, parse_dns_config_v6};
        let v4_after_erase = "
Configuration for interface \"WiFi 3\"
    DNS servers configured through DHCP:  194.168.4.100
                                          194.168.8.100
    Register with which suffix:           Primary only
";
        let v6_after_erase = "
Configuration for interface \"WiFi 3\"
    DNS servers configured through DHCP:  None
    Register with which suffix:           Primary only
";
        let (v4_dhcp, v4) = parse_dns_config_v4(v4_after_erase);
        let (v6_dhcp, v6) = parse_dns_config_v6(v6_after_erase);
        assert!(v4_dhcp && v4.is_empty(), "a lease is not configuration");
        assert!(v6_dhcp && v6.is_empty());
        let live = AdapterDnsSnapshot {
            adapter_name: "WiFi 3".into(),
            adapter_guid: "{W}".into(),
            v4_was_dhcp: v4_dhcp,
            v6_was_dhcp: v6_dhcp,
            dns_servers: v4,
            dns_servers_v6: v6,
        };
        let recorded = snap("{W}", "WiFi 3", false, &["8.8.8.8", "8.8.4.4"], true, &[]);
        assert_eq!(entry_state(&recorded, &live), EntryState::NeedsRestore);

        let io = FakeIo::new(Machine {
            adapters: vec![(adapter("{W}", "WiFi 3"), live)],
            ..Default::default()
        });
        let mut park = BTreeMap::new();
        park.insert(entry_key(&recorded), recorded.clone());
        let mut degraded = BTreeMap::new();
        assert!(restore_pass(&mut park, &io, &mut degraded));
        let after = io.live("{W}");
        assert_eq!(
            (after.v4_was_dhcp, after.dns_servers.clone()),
            (false, recorded.dns_servers.clone()),
            "the recorded static list, exactly"
        );
        assert_eq!(
            (after.v6_was_dhcp, after.dns_servers_v6),
            (true, Vec::<String>::new())
        );
        assert!(park.is_empty() && degraded.is_empty());
    }

    #[test]
    fn a_family_is_parked_foreign_or_restored() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        let static_list = s(&["8.8.8.8", "8.8.4.4"]);
        let none: Vec<String> = Vec::new();
        use FamilyState::*;
        // Recorded static list.
        assert_eq!(
            family_state((false, &static_list), (false, &static_list)),
            Restored
        );
        assert_eq!(family_state((false, &static_list), (false, &none)), Parked);
        assert_eq!(family_state((false, &static_list), (true, &none)), Parked);
        assert_eq!(
            family_state((false, &static_list), (false, &s(&["9.9.9.9"]))),
            Foreign,
            "someone set other resolvers since"
        );
        // Recorded DHCP.
        assert_eq!(family_state((true, &none), (true, &none)), Restored);
        assert_eq!(family_state((true, &none), (false, &none)), Parked);
        assert_eq!(
            family_state((true, &none), (false, &s(&["1.1.1.1"]))),
            Foreign
        );
        // Recorded static-with-none (VirtualBox, Hyper-V): parking was a no-op.
        assert_eq!(family_state((false, &none), (false, &none)), Restored);
        assert_eq!(family_state((false, &none), (true, &none)), Foreign);
    }

    #[test]
    fn a_restore_whose_read_back_fails_keeps_the_record() {
        let (io, mut st) = parked_by_an_older_build();
        io.with(|m| m.restore_fails.push("{B}".to_string()));
        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);
        assert!(
            st.park.contains_key("{B}"),
            "an unverified restore keeps its record"
        );
        assert!(!st.park.contains_key("{A}"), "the verified one is dropped");
        assert_eq!(
            degraded.get("{B}").map(|d| d.report.as_str()),
            Some(
                "Ethernet: DNS settings changed by an earlier Birdo version could not be restored"
            )
        );
    }

    #[test]
    fn a_restore_whose_live_read_fails_touches_nothing_and_keeps_the_record() {
        let (io, mut st) = parked_by_an_older_build();
        io.with(|m| m.read_fails.push("{A}".to_string()));
        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);
        assert!(st.park.contains_key("{A}"));
        assert_eq!(io.live("{A}"), parked("{A}", "Wi-Fi"), "not written to");
    }

    #[test]
    fn an_adapter_the_user_fixed_by_hand_is_dropped_untouched() {
        let (io, mut st) = parked_by_an_older_build();
        io.with(|m| m.adapters[0].1 = snap("{A}", "Wi-Fi", false, &["9.9.9.9"], false, &[]));
        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);
        assert_eq!(io.live("{A}").dns_servers, vec!["9.9.9.9"]);
        assert!(!st.park.contains_key("{A}"));
    }

    #[test]
    fn a_static_with_no_servers_adapter_is_left_exactly_as_it_was() {
        // VirtualBox Host-Only, the Hyper-V/WSL vSwitch, OpenVPN TAP: `static`
        // with no servers. Forcing DHCP there rewrites other products'
        // networking (#96).
        let io = FakeIo::new(Machine {
            adapters: vec![(
                adapter("{V}", "VirtualBox Host-Only Network"),
                parked("{V}", "VirtualBox Host-Only Network"),
            )],
            ..Default::default()
        });
        let mut park = BTreeMap::new();
        let entry = parked("{V}", "VirtualBox Host-Only Network");
        park.insert(entry_key(&entry), entry);
        let mut degraded = BTreeMap::new();
        assert!(
            !restore_pass(&mut park, &io, &mut degraded),
            "nothing written"
        );
        let live = io.live("{V}");
        assert!(!live.v4_was_dhcp && !live.v6_was_dhcp);
        assert!(park.is_empty());
    }

    #[test]
    fn ipv6_resolvers_that_were_all_link_local_go_back_to_dhcp_ra() {
        let entry = snap("{L}", "Ethernet", true, &[], false, &["fe80::1%13"]);
        assert_eq!(intent_v6(&entry), (true, Vec::new()));
        let none = snap("{N}", "Ethernet", true, &[], false, &[]);
        assert_eq!(intent_v6(&none), (false, Vec::new()));
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

    #[test]
    fn a_family_that_failed_can_never_be_reported_as_done() {
        assert!(join_family_results(Ok(()), Ok(())).is_ok());
        let v6_failed = join_family_results(Ok(()), Err("ipv6 exited 1".to_string()))
            .expect_err("an IPv6 failure with IPv4 fine is NOT a success");
        assert!(v6_failed.contains("ipv6"));
        let v4_failed = join_family_results(Err("ipv4 exited 1".to_string()), Ok(()))
            .expect_err("and the twin holds the other way round");
        assert!(v4_failed.contains("ipv4"));
        let both = join_family_results(
            Err("ipv4 exited 1".to_string()),
            Err("ipv6 exited 1".to_string()),
        )
        .expect_err("both failed");
        assert!(both.contains("ipv4") && both.contains("ipv6"));
    }

    /// A restore that took on one family only is a half-restored adapter.
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
        let full = snap(
            "{B}",
            "Ethernet",
            false,
            &["1.1.1.1"],
            false,
            &["2606:4700:4700::1111"],
        );
        assert!(matches_intent(&entry, &full));
        let mut v6_missing = full.clone();
        v6_missing.dns_servers_v6.clear();
        assert!(!matches_intent(&entry, &v6_missing));
        let mut v4_missing = full;
        v4_missing.dns_servers.clear();
        assert!(!matches_intent(&entry, &v4_missing));
    }

    #[test]
    fn an_unplugged_adapter_is_kept_on_record_but_not_reported() {
        let (io, mut st) = parked_by_an_older_build();
        io.with(|m| m.adapters.retain(|(a, _)| a.guid != "{B}"));
        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);
        assert!(
            st.park.contains_key("{B}"),
            "the record for a detached adapter is the only thing that still knows its resolvers"
        );
        assert!(!degraded.get("{B}").expect("still on the list").reportable);
        assert!(!st.park.contains_key("{A}"));
    }

    #[test]
    fn an_adapter_renamed_while_parked_is_still_restored() {
        let (io, mut st) = parked_by_an_older_build();
        io.with(|m| {
            m.adapters[1].0.name = "Work LAN".to_string();
            m.adapters[1].1.adapter_name = "Work LAN".to_string();
        });
        let mut degraded = BTreeMap::new();
        restore_pass(&mut st.park, &io, &mut degraded);
        assert_eq!(io.live("{B}").dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert!(st.park.is_empty());
    }

    /// What the start-up reconcile could not restore is ADOPTED, so the
    /// running process retries it on its next release (disconnect or quit).
    #[test]
    fn an_unrestored_entry_is_adopted_and_retried_on_the_next_release() {
        let (io, parked_state) = parked_by_an_older_build();
        let mut st = MachineState {
            owner: None,
            ..state_owned_by(0)
        };
        adopt_unrestored(&mut st, parked_state.park);
        assert_eq!(st.park.len(), 2);
        let owner = st.owner.expect("adopted state needs an owner (I1)");

        // A session comes and goes: its release retries the record.
        take_ownership_locked(&mut st, owner + 1);
        release_dns_locked(&mut st, &io, owner + 1);
        assert!(st.park.is_empty(), "the retry restored both adapters");
        assert_eq!(io.live("{B}").dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn adoption_never_overwrites_a_record_this_process_already_holds() {
        let (_, mut st) = parked_by_an_older_build();
        let mine = st.park.clone();
        let stale = snap("{Z}", "Old NIC", false, &["9.9.9.9"], false, &[]);
        let mut from_disk = BTreeMap::new();
        from_disk.insert(entry_key(&stale), stale);
        adopt_unrestored(&mut st, from_disk);
        assert_eq!(st.park, mine, "the live record wins");
        assert_eq!(st.owner, Some(1));
    }

    #[test]
    fn a_legacy_journal_entry_without_a_guid_is_keyed_by_name() {
        let legacy = snap("", "Wi-Fi", true, &[], true, &[]);
        assert_eq!(entry_key(&legacy), "name:WI-FI");
        let modern = snap("{A}", "Wi-Fi", true, &[], true, &[]);
        assert_eq!(entry_key(&modern), "{A}");
    }

    /// W1-007 as a source pin: nothing in the tunnel's DNS path may write the
    /// physical adapters' DNS again. `static none` on a physical adapter was
    /// the persistent change every unclean exit left behind.
    #[test]
    fn nothing_parks_adapter_dns_any_more() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vpn");
        // Built at run time so this file does not match its own needle.
        let needle = ["\"no", "ne\""].concat();
        for file in ["tunnel.rs", "win_machine_state.rs", "tunnel_dns.rs"] {
            let text = std::fs::read_to_string(dir.join(file)).expect("read source");
            assert!(!text.contains(&needle), "{file} parks adapter DNS again");
        }
    }
}
