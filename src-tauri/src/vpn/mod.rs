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
mod tunnel_dns; // netsh DNS reads + their captured-output parsers (Windows only)

// Process-global owner of the Windows machine state a session moves aside: the
// parked physical-adapter DNS and the installed routes. Lives outside the tunnel
// because it outlives individual tunnels — see the module docs for the
// invariants (issues #98, #99, #100, #102, #105).
#[cfg(target_os = "windows")]
pub mod win_machine_state;
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

// ADAPTIVE TRANSPORT: the establish-time handshake failure markers, re-exported
// so commands::vpn::transport_fallback_reason can classify a failed connect
// without wireguard_new becoming a public module.
pub(crate) use wireguard_new::{ERR_HANDSHAKE_NO_RESPONSE, ERR_HANDSHAKE_RECV};

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

// ──────────────────────────────────────────────────────────────
// Crash-durable DNS restore journal
// ──────────────────────────────────────────────────────────────

/// What a live tunnel moved aside, persisted so an abnormal exit can be undone.
///
/// WHY THIS EXISTS. `Cargo.toml` sets `panic = "abort"`, so `cleanup_on_crash()`
/// is the last code a panic runs — and a SIGKILL, an OOM kill or a power cut do
/// not reach even that. Every platform's `configure_dns` moves the host's
/// resolvers aside: Windows parks EVERY connected physical adapter on `static
/// none` to suppress the SMHNR leak, macOS repoints EVERY enabled service at the
/// tunnel resolvers, Linux pins /etc/resolv.conf. The snapshot that undoes all
/// three lives in the process that died, so a dirty exit leaves the machine with
/// no working DNS and nothing on it that knows what the configuration used to be.
///
/// Windows additionally cannot self-heal, which is the half that makes the damage
/// permanent: after a crash the next connect snapshots the PARKED state (`static`,
/// no servers) as if it were the user's own configuration, and
/// `restore_adapter_dns` deliberately no-ops on exactly that shape — parking it
/// was a no-op, and forcing DHCP there is what used to reconfigure VirtualBox and
/// Hyper-V adapters on every disconnect. So every later disconnect correctly
/// refuses to undo it. Linux already refuses its own marker as a baseline for the
/// same reason (see `capture_network_snapshot` in tunnel_linux.rs); this record
/// gives Windows and macOS the same protection.
///
/// The file is written BEFORE the first mutation and deleted by the restore
/// paths, so its presence means exactly one thing: a previous session did not
/// restore DNS. Restoring is still guarded per platform by "is the live state the
/// one we left?", so a machine the user has since fixed by hand is never
/// rewritten.
pub mod dns_journal {
    use serde::{Deserialize, Serialize};

    /// Beside the log file, under the same `<data_dir>/BirdoVPN` main.rs's log
    /// layer creates — deliberately the same launch context as the log, so a
    /// client started with `sudo` reads back the file that same client wrote.
    const JOURNAL_FILE: &str = "dns-restore.json";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct DnsJournal {
        /// `std::env::consts::OS` of the writer. A record from another platform
        /// (a synced home directory) describes commands this host cannot run.
        #[serde(default)]
        os: String,

        /// Windows: every physical adapter `configure_dns` parked, with the
        /// resolvers it had. Restored through the same helper the clean
        /// disconnect uses, so the two cannot drift.
        #[cfg(target_os = "windows")]
        #[serde(default)]
        adapters: Vec<super::tunnel::AdapterDnsSnapshot>,

        /// macOS: every enabled service `configure_dns` repointed, with the
        /// resolvers it had (empty = networksetup's "empty", i.e. back to DHCP).
        #[cfg(target_os = "macos")]
        #[serde(default)]
        services: Vec<(String, Vec<String>)>,

        /// macOS: the tunnel resolvers we installed. A service is reverted only
        /// while it still points at these — that is what separates "we set this"
        /// from "the user has since fixed their DNS by hand".
        #[cfg(target_os = "macos")]
        #[serde(default)]
        tunnel_dns: Vec<String>,

        /// Linux: the pre-connect bytes of /etc/resolv.conf. `None` when the file
        /// was unreadable, or when it already carried our marker — a file we
        /// wrote is never a valid baseline.
        #[cfg(target_os = "linux")]
        #[serde(default)]
        resolv_conf_backup: Option<String>,

        /// Linux: was the tun link also configured through resolvectl?
        #[cfg(target_os = "linux")]
        #[serde(default)]
        uses_systemd_resolved: bool,
    }

    fn path() -> Option<std::path::PathBuf> {
        let mut dir = dirs::data_dir()?;
        dir.push("BirdoVPN");
        std::fs::create_dir_all(&dir).ok()?;
        dir.push(JOURNAL_FILE);
        Some(dir)
    }

    /// Where the new bytes are staged before they replace the record.
    ///
    /// Deliberately a sibling: a rename is only atomic within one filesystem, so
    /// a system temp dir would silently degrade this back into a copy.
    fn staging_path(path: &std::path::Path) -> std::path::PathBuf {
        path.with_extension("json.tmp")
    }

    /// Where an unreadable record is kept instead of being deleted.
    fn preserved_path(path: &std::path::Path) -> std::path::PathBuf {
        path.with_extension("json.corrupt")
    }

    /// Replace `path` with `bytes` so that every crash point leaves either the
    /// whole old record or the whole new one — never a shorter one.
    ///
    /// WHY NOT `create + truncate + write_all`, which is what this used to be:
    /// the truncate destroys the old record BEFORE the new one exists, and on
    /// NTFS the metadata (length 0) is journalled while the data is not
    /// necessarily flushed, so the exposure outlives a successful return. A
    /// crash, an OOM kill or a power cut in that window leaves a zero-length or
    /// NUL-padded file — and on Windows that is terminal, not cosmetic: the
    /// adapters are still parked, nothing on disk says what they were, the next
    /// connect re-snapshots `static`/no-servers as if it were the user's own
    /// configuration, and `restore_family` then correctly refuses to undo that
    /// shape forever after. The host has no resolvers, permanently, reached
    /// through the durability mechanism that exists to prevent exactly that
    /// (#102, and I4: "a mutation whose record is not durable is a mutation
    /// nothing can undo"). `park_pass` persists once per adapter, so an N-NIC
    /// host used to open N of those windows on every single connect.
    ///
    /// Success here is the caller's permission to mutate the machine, so it must
    /// mean the bytes are on the disk. Do NOT "simplify" the fsync away:
    /// renaming a file whose contents are still only in the page cache moves an
    /// empty file into place just as effectively as it moves a full one, which
    /// would leave this atomic but not durable — and durability is the half I4
    /// is asking for.
    fn write_bytes_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        let staging = staging_path(path);
        if let Err(e) = stage_bytes(&staging, bytes) {
            // Never touch the destination on the way out: the old record is
            // still the only thing that knows what to put back.
            let _ = std::fs::remove_file(&staging);
            return Err(e);
        }
        match replace_with_retry(&staging, path) {
            Ok(()) => {
                sync_parent_dir(path);
                Ok(())
            }
            Err(e) => {
                let _ = std::fs::remove_file(&staging);
                Err(e)
            }
        }
    }

    /// Write the bytes into the staging file and get them onto the disk.
    fn stage_bytes(staging: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        // The record names network services and resolvers — which machine was on
        // which network. Same sensitivity as birdo.log, so the same owner-only
        // mode on multi-user Unix hosts (Windows relies on the %APPDATA% ACL).
        // The staging file holds those same bytes, so it takes the same mode.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(staging)?;
        f.write_all(bytes)?;
        f.sync_all()
    }

    /// Move the staged file over the record.
    ///
    /// `std::fs::rename` is `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows,
    /// which does replace an existing destination — but it can fail with a
    /// transient sharing violation while an AV scanner or the search indexer
    /// holds either file open. That failure is not cosmetic: `park_pass` refuses
    /// to park an adapter whose record did not persist, so a scanner's
    /// few-millisecond window would otherwise cost the user DNS-leak suppression
    /// on that adapter for the whole session. Retry briefly, then report it. The
    /// bound stays small on purpose — `write` is reachable from teardown paths
    /// that must not stall.
    fn replace_with_retry(
        staging: &std::path::Path,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        const ATTEMPTS: u32 = 3;
        let mut attempt = 1;
        loop {
            match std::fs::rename(staging, path) {
                Ok(()) => return Ok(()),
                Err(e) if attempt < ATTEMPTS => {
                    tracing::debug!("DNS journal replace failed ({}) — retrying", e);
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// On Unix the rename itself is only durable once the DIRECTORY entry is
    /// flushed, so a power cut can otherwise resurrect the pre-rename listing.
    /// Best-effort: some filesystems refuse an fsync on a directory handle, and
    /// failing it leaves the write no worse off than it already was.
    fn sync_parent_dir(_path: &std::path::Path) {
        #[cfg(unix)]
        {
            if let Some(dir) = _path.parent() {
                if let Ok(handle) = std::fs::File::open(dir) {
                    let _ = handle.sync_all();
                }
            }
        }
    }

    fn write(journal: &DnsJournal) -> Result<(), String> {
        let Some(path) = path() else {
            tracing::warn!(
                "No data directory — DNS could not be made restorable after an abnormal exit"
            );
            return Err("no data directory".to_string());
        };
        let json = match serde_json::to_vec_pretty(journal) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!("Could not serialise the DNS journal: {}", e);
                return Err(format!("could not serialise the DNS journal: {}", e));
            }
        };
        match write_bytes_atomically(&path, &json) {
            Ok(()) => {
                tracing::debug!("DNS journal written");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "Could not write the DNS journal ({}) — an abnormal exit will leave this host \
                     without resolvers",
                    e
                );
                Err(e.to_string())
            }
        }
    }

    fn read() -> Option<DnsJournal> {
        let path = path()?;
        read_at(&path)
    }

    fn read_at(path: &std::path::Path) -> Option<DnsJournal> {
        let bytes = std::fs::read(path).ok()?;
        match serde_json::from_slice::<DnsJournal>(&bytes) {
            Ok(journal) if journal.os == std::env::consts::OS => Some(journal),
            Ok(journal) => {
                tracing::warn!(
                    "Ignoring a DNS journal written on {} — this host is {}",
                    journal.os,
                    std::env::consts::OS
                );
                None
            }
            Err(e) => {
                // NOT deleted. Unreadable is the one state where the bytes are
                // both useless to this process and the only surviving trace of
                // what a previous session moved aside — on Windows, of which
                // adapters are parked on `static`/no-servers and what their
                // resolvers used to be. Deleting is the only irreversible option
                // available here, so it is the one thing not done: the file is
                // set aside under a name nothing else writes, where a support
                // session can still read the resolvers out of it by hand. (With
                // an atomic write, reaching this at all means external
                // corruption, a half-restored backup, or a record from a future
                // schema — none of which are ours to destroy.)
                match set_aside_unreadable(path) {
                    Some(kept) => tracing::error!(
                        "Unreadable DNS journal ({}) — kept at {} for recovery, not deleted",
                        e,
                        kept.display()
                    ),
                    None => tracing::error!(
                        "Unreadable DNS journal ({}) — and it could not be set aside; leaving it \
                         in place",
                        e
                    ),
                }
                None
            }
        }
    }

    /// What one platform's restore pass actually achieved.
    ///
    /// `unverified` is the load-bearing field. It counts state a previous
    /// session moved aside that this pass did NOT prove it put back — and while
    /// it is non-zero, the journal is the only surviving description of the
    /// user's real resolvers.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub(super) struct DnsRestoreOutcome {
        /// Restores that a read-back PROVED are in effect.
        pub(super) restored: usize,
        /// Restores that were attempted and could not be proved. Never
        /// increment this for something we chose not to touch: a service the
        /// user has already fixed by hand is not unverified, it is done.
        pub(super) unverified: usize,
        /// The subset of `unverified` a human can see and act on, one readable
        /// line each - the same contract as `win_machine_state`'s degradation
        /// report, and what `get_vpn_status` renders as the "DNS not fully
        /// protected" banner.
        ///
        /// A strict subset, not a mirror of the count: state that is unverified
        /// only because the network service is no longer attached keeps the
        /// record but is NOT reportable, because there is nothing the user could
        /// do about it and a banner nobody can clear is how a real one gets
        /// ignored.
        pub(super) problems: Vec<String>,
    }

    #[cfg_attr(target_os = "windows", allow(dead_code))]
    impl DnsRestoreOutcome {
        /// Fold in one restore attempt, `verified` being the read-back's answer
        /// and NOT the exit status of whatever tool performed the write.
        ///
        /// `describe` is evaluated only on failure, and is what the user is
        /// shown. Taking it is deliberate: there is no way to add to
        /// `unverified` without also saying what broke, so the banner cannot
        /// drift away from the journal rule the way it did when the whole field
        /// was hard-coded empty off Windows.
        pub(super) fn note(&mut self, verified: bool, describe: impl FnOnce() -> String) {
            if verified {
                self.restored += 1;
            } else {
                self.unverified += 1;
                self.problems.push(describe());
            }
        }

        /// Fold in state we could not verify and the user cannot fix - a network
        /// service that is no longer attached, an adapter unplugged since the
        /// record was written.
        ///
        /// It KEEPS the record (the service may come back and still needs its
        /// resolvers put back), but it raises no banner. Mirrors Windows'
        /// `Degradation::dormant`, which is explicitly distinct from a fault.
        pub(super) fn note_dormant(&mut self) {
            self.unverified += 1;
        }

        /// The rule this type exists to carry: the record may be dropped only
        /// when nothing is left that it alone knows how to put back.
        pub(super) fn may_clear_journal(&self) -> bool {
            self.unverified == 0
        }
    }

    /// Decide the on-disk record's fate after a platform restore pass, and
    /// report whether anything was verifiably put back.
    ///
    /// # Why the journal is not cleared unconditionally
    ///
    /// It used to be, on macOS and Linux, and that is how a recoverable outage
    /// became a permanent one. There is no self-elevation off Windows
    /// (`main.rs` gates `self_elevate` on `cfg(windows)`), so the startup
    /// reconcile — the ONLY thing that can heal a SIGKILL, an OOM kill or a
    /// power cut — normally runs as the ordinary login user, who cannot write
    /// the SystemConfiguration store or `/etc/resolv.conf`. The restore then
    /// silently did nothing, `restored` counted the ATTEMPT, and deleting
    /// `dns-restore.json` on the way out destroyed the last thing that knew
    /// what to put back: the machine was left with no DNS at all, by the very
    /// act of trying to recover. Windows already encodes this rule in
    /// `win_machine_state::reconcile_record`, which retains every entry it
    /// could not verify; this is that rule for the two Unix twins.
    ///
    /// Keeping a record we could not act on is cheap and self-healing: each
    /// pass re-checks the live state first, so a machine the user has since
    /// fixed by hand is examined once and the record is then dropped.
    ///
    /// Takes the clearing action as an argument so the rule itself is unit-
    /// testable on any host — including the Windows runner, which is the only
    /// CI job that actually RUNS the Rust test suite.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(super) fn settle(outcome: DnsRestoreOutcome, clear_journal: impl FnOnce()) -> bool {
        // Publish FIRST, and unconditionally. Every Unix restore pass funnels
        // through here, so this is the only place where what the user is shown
        // cannot drift out of step with what the journal was allowed to do. A
        // fully verified pass publishes an empty list, which is what clears the
        // banner.
        publish_degraded(outcome.problems.clone());
        if outcome.may_clear_journal() {
            clear_journal();
        } else {
            tracing::error!(
                "{} DNS restore(s) could not be verified — KEEPING the DNS journal so a \
                 later start (or one with the privileges this one lacked) can retry. \
                 Deleting it would destroy the only record of the pre-connect resolvers.",
                outcome.unverified
            );
        }
        outcome.restored > 0
    }

    /// The last restore pass's user-actionable failures - Unix's counterpart to
    /// `win_machine_state::degradation_report()`.
    ///
    /// # Why this is not just a log line
    ///
    /// `VpnStatus::dns_degraded` hard-coded `Vec::new()` on every platform but
    /// Windows, and its own doc says rendering a Connected badge over an
    /// unrestored adapter is "rendering reassurance from missing data". The
    /// macOS and Linux passes now COMPUTE that exact value, and sending it only
    /// to `tracing::error!` tells a user whose DNS this app has just failed to
    /// put back to go and read a log file - which they cannot fetch, because
    /// they have no DNS. Same fault, same banner, on all three platforms.
    ///
    /// Deliberately not `cfg`-gated: the store exists everywhere so the Windows
    /// job - the only CI job that runs `cargo test` - executes its tests.
    /// Windows simply reads `win_machine_state` instead, which is richer.
    static DEGRADED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    /// Replace the report wholesale: each pass is a complete statement about the
    /// machine, so a stale entry from a previous pass must never survive one
    /// that no longer sees it.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    fn publish_degraded(lines: Vec<String>) {
        if let Ok(mut current) = DEGRADED.lock() {
            *current = lines;
        }
    }

    /// Read the report. A poisoned lock reports nothing rather than panicking a
    /// status poll - and `panic = "abort"` means it cannot be poisoned anyway.
    ///
    /// Windows reads `win_machine_state::degradation_report()` instead, so this
    /// one has no non-test caller there. It is still COMPILED and still TESTED
    /// there, which is the point: the Windows job is the only one that runs
    /// `cargo test`.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub fn degradation_report() -> Vec<String> {
        DEGRADED.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Fold a retained record's baseline into a fresh capture (macOS).
    ///
    /// # Why this exists
    ///
    /// Keeping the journal past an unverified restore turned it into a
    /// CROSS-SESSION record, and the writers were never told. The sequence that
    /// bites: a crash leaves every service on tunnel resolvers; the unprivileged
    /// relaunch cannot write them back, so `settle` correctly KEEPS the record;
    /// the user connects again, and `configure_dns` captures "what these
    /// services currently have" - which is the DEAD TUNNEL RESOLVERS of the
    /// crashed session. Writing that over the retained record replaces the last
    /// copy of the user's real DNS with the precise value the record exists to
    /// undo, and every restore afterwards "succeeds" at restoring nothing.
    ///
    /// Windows closes this with `win_machine_state::adopt_unrestored`, which
    /// hands the live process ownership of the record so the next connect does
    /// not re-snapshot those adapters. This is that rule for the macOS record: a
    /// capture that reads back the PREVIOUS session's tunnel resolvers is not a
    /// baseline, so the older one is kept.
    ///
    /// Pure and free of `cfg` so the Windows job actually runs its tests.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(super) fn merge_macos_capture(
        fresh: &[(String, Vec<String>)],
        old_services: &[(String, Vec<String>)],
        old_tunnel_dns: &[String],
    ) -> Vec<(String, Vec<String>)> {
        if old_tunnel_dns.is_empty() {
            // Nothing to recognise pollution by.
            return fresh.to_vec();
        }
        let mut merged: Vec<(String, Vec<String>)> = fresh
            .iter()
            .map(|(service, captured)| {
                if captured.as_slice() != old_tunnel_dns {
                    // Carries something other than the previous session's tunnel
                    // resolvers, so this capture is a real baseline - and a newer
                    // one than the record's.
                    return (service.clone(), captured.clone());
                }
                match old_services.iter().find(|(s, _)| s == service) {
                    Some((_, original)) => (service.clone(), original.clone()),
                    // Polluted, and nothing older to fall back on. Keep it
                    // rather than invent one.
                    None => (service.clone(), captured.clone()),
                }
            })
            .collect();
        // Services the record knows about that this capture did not see -
        // `list_network_services()` failed and `configure_dns` fell back to the
        // primary service alone. Dropping them would silently discard a baseline
        // that is still unrestored, so carry them across.
        for (service, original) in old_services {
            if !merged.iter().any(|(s, _)| s == service) {
                merged.push((service.clone(), original.clone()));
            }
        }
        merged
    }

    /// The same rule for the Linux record.
    ///
    /// `fresh` is `None` exactly when /etc/resolv.conf was unreadable OR already
    /// carried our marker - and "already ours" IS the retained-record case, so
    /// this is not a corner. Writing that `None` over a retained backup drops
    /// the real bytes and arms `restore_dns`'s fallback, which writes
    /// `nameserver 1.1.1.1` / `nameserver 8.8.8.8`, then verifies (our marker is
    /// legitimately gone) and clears the journal: the user's own resolvers
    /// replaced by two public ones, permanently, by the recovery path.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(super) fn merge_linux_capture(
        fresh: Option<&str>,
        retained: Option<&str>,
    ) -> Option<String> {
        match fresh {
            // A real, marker-free read of the live file: newer and better than
            // whatever the record holds.
            Some(bytes) => Some(bytes.to_string()),
            None => retained.map(|bytes| bytes.to_string()),
        }
    }

    /// Move an unreadable record aside, without clobbering one already kept: the
    /// first one preserved is the one closest to whatever went wrong.
    fn set_aside_unreadable(path: &std::path::Path) -> Option<std::path::PathBuf> {
        let mut kept = preserved_path(path);
        if kept.exists() {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            kept = path.with_extension(format!("json.corrupt.{}", stamp));
        }
        std::fs::rename(path, &kept).ok().map(|()| kept)
    }

    /// Drop the record. Called by the restore paths once the resolvers are back,
    /// so a record can never outlive the state it describes.
    pub(super) fn clear() {
        let Some(path) = path() else {
            return;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::debug!("DNS journal cleared"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                "Could not clear the DNS journal ({}) — the next startup will re-check the live \
                 state and find nothing to do",
                e
            ),
        }
    }

    /// Record the adapters the machine-state owner is about to park.
    ///
    /// Returns whether the record actually reached the disk. The Windows owner
    /// writes the record for an adapter BEFORE parking it and refuses to park it
    /// if this fails: a mutation whose record is not durable is a mutation
    /// nothing can undo (I4).
    #[cfg(target_os = "windows")]
    pub(super) fn record_windows(
        adapters: &[super::tunnel::AdapterDnsSnapshot],
    ) -> Result<(), String> {
        write(&DnsJournal {
            os: std::env::consts::OS.to_string(),
            adapters: adapters.to_vec(),
        })
    }

    /// Record the services `configure_dns` is about to repoint, and the tunnel
    /// resolvers it is about to point them at.
    #[cfg(target_os = "macos")]
    pub(super) fn record_macos(services: &[(String, Vec<String>)], tunnel_dns: &[String]) {
        // Never blindly overwrite: a record still on disk at connect time is one
        // a previous restore could not prove, and this capture may be reading
        // that session's tunnel resolvers back. See `merge_macos_capture`.
        let services = match read() {
            Some(old) => merge_macos_capture(services, &old.services, &old.tunnel_dns),
            None => services.to_vec(),
        };
        let _ = write(&DnsJournal {
            os: std::env::consts::OS.to_string(),
            services,
            tunnel_dns: tunnel_dns.to_vec(),
        });
    }

    /// Record the /etc/resolv.conf `configure_dns` is about to overwrite.
    #[cfg(target_os = "linux")]
    pub(super) fn record_linux(resolv_conf_backup: Option<String>, uses_systemd_resolved: bool) {
        // Same rule as macOS: the caller's capture is `None` whenever the file
        // already carried our marker, which is precisely the retained-record
        // case. See `merge_linux_capture`.
        let retained = read().and_then(|old| old.resolv_conf_backup);
        let resolv_conf_backup =
            merge_linux_capture(resolv_conf_backup.as_deref(), retained.as_deref());
        let _ = write(&DnsJournal {
            os: std::env::consts::OS.to_string(),
            resolv_conf_backup,
            uses_systemd_resolved,
        });
    }

    /// Put back whatever a previous session left moved aside.
    ///
    /// Synchronous, lock-free and async-free by construction, so it is callable
    /// from the panic hook (`panic = "abort"` — nothing else runs) and from
    /// `setup()`, where no tunnel can be up yet and a record on disk therefore
    /// means exactly one thing. The startup call is the ONLY thing that can heal
    /// a SIGKILL, an OOM kill or a power cut, none of which reach the hook.
    ///
    /// Each platform re-checks that the live state is still the state it left
    /// before touching anything, so a machine the user has already fixed by
    /// hand is examined once and then left alone. The record is dropped only
    /// for state a read-back PROVED is back — see `settle`.
    ///
    /// Returns whether anything was actually restored.
    pub fn reconcile() -> bool {
        let Some(journal) = read() else {
            return false;
        };

        // Windows owns its own record lifecycle and deliberately does NOT clear
        // unconditionally. An entry whose restore could not be verified stays on
        // disk: clearing it would destroy the last thing that knows what to put
        // back, which is exactly how a failed un-park became permanent (I5).
        // `reconcile_record` re-persists what remains, or deletes the file when
        // nothing is left to describe.
        #[cfg(target_os = "windows")]
        {
            super::win_machine_state::reconcile_record(&journal.adapters)
        }

        #[cfg(not(target_os = "windows"))]
        {
            #[cfg(target_os = "macos")]
            let outcome = super::tunnel_macos::restore_services_still_on_tunnel_dns(
                &journal.services,
                &journal.tunnel_dns,
            );
            #[cfg(target_os = "linux")]
            let outcome = super::tunnel_linux::restore_resolv_conf_if_ours(
                journal.resolv_conf_backup,
                journal.uses_systemd_resolved,
            );
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let outcome = {
                let _ = &journal;
                DnsRestoreOutcome::default()
            };

            // NOT an unconditional `clear()`. The restores above prove
            // themselves with a read-back, and anything they could not prove
            // keeps its record — deleting that is what turned a crash into a
            // machine with no resolvers at all. See `settle`.
            settle(outcome, clear)
        }
    }

    /// The journal-lifecycle rule, exercised on every platform.
    ///
    /// Deliberately NOT `cfg(target_os)`-gated: the Windows job is the only CI
    /// job that RUNS `cargo test`, and the rule these tests protect is the one
    /// the macOS and Linux paths were missing.
    #[cfg(test)]
    mod settle_tests {
        use super::{
            degradation_report, merge_linux_capture, merge_macos_capture, settle, DnsRestoreOutcome,
        };
        use std::cell::Cell;
        use std::sync::{Mutex, MutexGuard};

        /// `settle` publishes into a process-wide store, so the tests that
        /// observe it must not interleave. `cargo test` runs them on N threads.
        static SERIAL: Mutex<()> = Mutex::new(());

        fn serial() -> MutexGuard<'static, ()> {
            SERIAL.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn svc(name: &str, servers: &[&str]) -> (String, Vec<String>) {
            (
                name.to_string(),
                servers.iter().map(|s| s.to_string()).collect(),
            )
        }

        fn lines(v: &[&str]) -> Vec<String> {
            v.iter().map(|s| s.to_string()).collect()
        }

        /// Run `settle` and report whether it deleted the record.
        fn run_settle(outcome: DnsRestoreOutcome) -> (bool, bool) {
            let cleared = Cell::new(false);
            let restored = settle(outcome, || cleared.set(true));
            (cleared.get(), restored)
        }

        fn unverified(n: usize) -> DnsRestoreOutcome {
            let mut outcome = DnsRestoreOutcome::default();
            for i in 0..n {
                outcome.note(false, || format!("service {}: could not restore", i));
            }
            outcome
        }

        /// THE regression. An unprivileged recovery run attempts every restore
        /// and lands none of them; the record it is holding is the only thing
        /// that still knows the user's real resolvers, so it must survive.
        #[test]
        fn an_unverified_restore_keeps_the_journal() {
            let _g = serial();
            let (cleared, restored) = run_settle(unverified(3));
            assert!(
                !cleared,
                "the journal was deleted after a restore that never landed - this is the \
                 bug: the pre-connect resolvers are now unrecoverable"
            );
            assert!(
                !restored,
                "nothing was proved restored, so nothing may be reported"
            );
        }

        /// A partial pass is still a failed pass for the entries it missed.
        #[test]
        fn a_partial_restore_keeps_the_journal() {
            let _g = serial();
            let mut outcome = unverified(1);
            outcome.note(true, || {
                unreachable!("a verified restore has no problem to describe")
            });
            outcome.note(true, || unreachable!());
            assert_eq!(outcome.restored, 2);
            let (cleared, restored) = run_settle(outcome);
            assert!(
                !cleared,
                "one unverified entry is enough to keep the record"
            );
            assert!(restored);
        }

        /// Fully proved: the record now describes nothing and must go, or every
        /// later start would re-run a pointless pass and log an error forever.
        #[test]
        fn a_fully_verified_restore_clears_the_journal() {
            let _g = serial();
            let mut outcome = DnsRestoreOutcome::default();
            outcome.note(true, || unreachable!());
            outcome.note(true, || unreachable!());
            let (cleared, restored) = run_settle(outcome);
            assert!(cleared);
            assert!(restored);
        }

        /// Nothing to do - the user already fixed their DNS by hand, so the
        /// live state is no longer the state we left. Self-healing: the record
        /// is dropped even though nothing was restored.
        #[test]
        fn nothing_left_to_restore_clears_the_journal() {
            let _g = serial();
            let (cleared, restored) = run_settle(DnsRestoreOutcome::default());
            assert!(cleared);
            assert!(!restored);
        }

        #[test]
        fn may_clear_journal_tracks_only_the_unverified_count() {
            let mut outcome = DnsRestoreOutcome::default();
            assert!(outcome.may_clear_journal());
            outcome.note(true, || unreachable!());
            assert!(outcome.may_clear_journal());
            outcome.note(false, || "eth0: nope".to_string());
            assert!(!outcome.may_clear_journal());
            assert_eq!(outcome.restored, 1);
            assert_eq!(outcome.unverified, 1);
        }

        /// A service that is no longer attached keeps the record - it may come
        /// back and it is still unrestored - but it must NOT raise a banner: the
        /// user cannot plug in an adapter to satisfy a warning they cannot read,
        /// and a permanent banner is how a real one gets ignored. This is
        /// Windows' dormant-vs-fault distinction, which the first version of
        /// this fix collapsed.
        #[test]
        fn a_dormant_entry_keeps_the_record_without_raising_a_banner() {
            let _g = serial();
            let mut outcome = DnsRestoreOutcome::default();
            outcome.note_dormant();
            assert!(
                !outcome.may_clear_journal(),
                "a dormant entry is still unrestored state - the record describes it"
            );
            assert!(outcome.problems.is_empty());
            let (cleared, _) = run_settle(outcome);
            assert!(!cleared);
            assert!(
                degradation_report().is_empty(),
                "a dormant entry must not reach the user-facing banner"
            );
        }

        /// The reporting twin. `VpnStatus::dns_degraded` was hard-coded empty
        /// off Windows while these very counts were being computed and thrown
        /// into a log file, so a user with no DNS saw a clean Connected screen.
        #[test]
        fn settle_publishes_the_problems_for_the_status_banner() {
            let _g = serial();
            let mut outcome = DnsRestoreOutcome::default();
            outcome.note(false, || {
                "Wi-Fi: could not put its pre-connect DNS back".to_string()
            });
            outcome.note(true, || unreachable!());
            run_settle(outcome);
            assert_eq!(
                degradation_report(),
                lines(&["Wi-Fi: could not put its pre-connect DNS back"])
            );
        }

        /// ...and a later clean pass must take it away again, or the banner
        /// becomes a permanent scar from one bad disconnect.
        #[test]
        fn a_clean_pass_clears_the_banner() {
            let _g = serial();
            let mut dirty = DnsRestoreOutcome::default();
            dirty.note(false, || {
                "Ethernet: could not put its pre-connect DNS back".to_string()
            });
            run_settle(dirty);
            assert!(!degradation_report().is_empty());
            run_settle(DnsRestoreOutcome::default());
            assert!(
                degradation_report().is_empty(),
                "a fully settled pass is a complete statement: nothing is degraded"
            );
        }

        // ── merge_macos_capture ──────────────────────────────────────────────

        /// THE cross-session regression. A crash left Wi-Fi on the tunnel
        /// resolvers, the unprivileged relaunch could not put them back, so the
        /// record was (correctly) KEPT - and then the next connect captured
        /// those same dead tunnel resolvers as the "baseline" and wrote them
        /// over it. The record would then restore the machine to the exact
        /// broken state it exists to undo.
        #[test]
        fn a_capture_polluted_by_the_previous_tunnel_keeps_the_older_baseline() {
            let old = vec![svc("Wi-Fi", &["192.168.1.1"])];
            let old_tunnel = lines(&["10.8.0.1"]);
            // What configure_dns reads off the live machine right now:
            let fresh = vec![svc("Wi-Fi", &["10.8.0.1"])];
            assert_eq!(
                merge_macos_capture(&fresh, &old, &old_tunnel),
                vec![svc("Wi-Fi", &["192.168.1.1"])],
                "the retained baseline must survive a capture that is just the old tunnel DNS"
            );
        }

        /// The other half: once a service really does carry its own resolvers
        /// again, the fresh read is the better baseline and the stale record
        /// entry must not shadow it forever.
        #[test]
        fn a_genuine_capture_wins_over_the_record() {
            let old = vec![svc("Wi-Fi", &["192.168.1.1"])];
            let fresh = vec![svc("Wi-Fi", &["9.9.9.9"])];
            assert_eq!(
                merge_macos_capture(&fresh, &old, &lines(&["10.8.0.1"])),
                vec![svc("Wi-Fi", &["9.9.9.9"])]
            );
        }

        /// Restoring to DHCP is the empty list, and so is a polluted capture on
        /// a record whose tunnel_dns was never written. Nothing to recognise
        /// pollution by, so nothing may be substituted.
        #[test]
        fn an_empty_tunnel_dns_disables_the_substitution() {
            let old = vec![svc("Wi-Fi", &["192.168.1.1"])];
            let fresh = vec![svc("Wi-Fi", &[])];
            assert_eq!(merge_macos_capture(&fresh, &old, &[]), fresh);
        }

        /// A capture taken through the single-service fallback (
        /// `list_network_services()` failed) must not silently drop the other
        /// services the record is still holding baselines for.
        #[test]
        fn services_the_capture_missed_are_carried_across() {
            let old = vec![
                svc("Wi-Fi", &["192.168.1.1"]),
                svc("Ethernet", &["10.0.0.1"]),
            ];
            let fresh = vec![svc("Wi-Fi", &["10.8.0.1"])];
            let merged = merge_macos_capture(&fresh, &old, &lines(&["10.8.0.1"]));
            assert_eq!(
                merged,
                vec![
                    svc("Wi-Fi", &["192.168.1.1"]),
                    svc("Ethernet", &["10.0.0.1"])
                ]
            );
        }

        // ── merge_linux_capture ──────────────────────────────────────────────

        /// `record_linux` filters out a resolv.conf carrying our own marker, so
        /// a capture taken while a previous session is still unrestored is
        /// ALWAYS `None`. Writing that over the retained bytes armed
        /// `restore_dns`'s fallback, which writes 1.1.1.1/8.8.8.8, verifies
        /// (our marker is legitimately gone) and clears the journal.
        #[test]
        fn a_none_capture_never_overwrites_retained_resolv_conf_bytes() {
            assert_eq!(
                merge_linux_capture(None, Some("nameserver 192.168.1.1\n")),
                Some("nameserver 192.168.1.1\n".to_string())
            );
        }

        #[test]
        fn a_real_capture_wins_and_none_over_nothing_stays_none() {
            assert_eq!(
                merge_linux_capture(Some("nameserver 9.9.9.9\n"), Some("nameserver 1.1.1.1\n")),
                Some("nameserver 9.9.9.9\n".to_string())
            );
            assert_eq!(merge_linux_capture(None, None), None);
        }
    }

    /// Durability of the record itself — the property every other invariant in
    /// `win_machine_state` is standing on (I4). These drive the path-taking
    /// helpers directly rather than `write`/`read`, which resolve their own
    /// path under the real data directory.
    #[cfg(test)]
    mod journal_durability_tests {
        use super::{
            preserved_path, read_at, set_aside_unreadable, staging_path, write_bytes_atomically,
        };

        /// The smallest byte string `read_at` accepts on the host running the
        /// test: every platform-specific field carries `#[serde(default)]`.
        fn record_for_this_os() -> Vec<u8> {
            format!("{{\"os\":\"{}\"}}", std::env::consts::OS).into_bytes()
        }

        #[test]
        fn a_record_for_this_os_round_trips() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            write_bytes_atomically(&path, &record_for_this_os()).unwrap();
            assert!(read_at(&path).is_some());
        }

        #[test]
        fn a_written_record_leaves_no_staging_file_behind() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            write_bytes_atomically(&path, b"first").unwrap();
            write_bytes_atomically(&path, b"second").unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"second".to_vec());
            assert!(
                !staging_path(&path).exists(),
                "the staging sibling must not survive a successful write"
            );
        }

        /// #102 regression. The old implementation opened the record itself with
        /// `truncate(true)`, so ANY failure from that point on — a full disk, a
        /// crash, a power cut — left a zero-length record and no way to un-park
        /// the adapters it described. Fault-injected here by parking a DIRECTORY
        /// on the staging path, which makes the staging open fail; the old code
        /// had no staging file to fail on.
        #[test]
        fn a_failed_write_leaves_the_previous_record_intact() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            let previous = record_for_this_os();
            write_bytes_atomically(&path, &previous).unwrap();

            std::fs::create_dir(staging_path(&path)).unwrap();
            write_bytes_atomically(&path, b"never lands")
                .expect_err("staging onto a directory must fail");

            assert_eq!(std::fs::read(&path).unwrap(), previous);
            assert!(
                read_at(&path).is_some(),
                "the surviving record must still be restorable"
            );
        }

        #[test]
        fn a_failed_replace_cleans_up_the_staging_file() {
            let dir = tempfile::tempdir().unwrap();
            // A non-empty directory cannot be replaced by a rename on any
            // supported platform, so the staging step succeeds and the replace
            // is the step that fails.
            let path = dir.path().join("dns-restore.json");
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("occupied"), b"x").unwrap();

            write_bytes_atomically(&path, b"cannot land").expect_err("replace must fail");
            assert!(
                !staging_path(&path).exists(),
                "a failed write must not leave resolver bytes lying in a stray file"
            );
        }

        /// The record is the last thing that knows what to put back, so an
        /// unreadable one is set aside, never removed.
        #[test]
        fn an_unreadable_record_is_kept_not_deleted() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            let torn = b"{\"os\": \"wind";
            std::fs::write(&path, torn).unwrap();

            assert!(read_at(&path).is_none());
            assert!(
                !path.exists(),
                "the unreadable record is moved out of the way"
            );
            assert_eq!(
                std::fs::read(preserved_path(&path)).unwrap(),
                torn.to_vec(),
                "its bytes must still be recoverable by hand"
            );
        }

        #[test]
        fn a_second_unreadable_record_does_not_clobber_the_first() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            std::fs::write(&path, b"first casualty").unwrap();
            set_aside_unreadable(&path).expect("first set-aside");

            std::fs::write(&path, b"second casualty").unwrap();
            let second = set_aside_unreadable(&path).expect("second set-aside");

            assert_eq!(
                std::fs::read(preserved_path(&path)).unwrap(),
                b"first casualty".to_vec()
            );
            assert_ne!(second, preserved_path(&path));
            assert_eq!(std::fs::read(second).unwrap(), b"second casualty".to_vec());
        }

        /// A record from another platform describes commands this host cannot
        /// run, but it is still somebody's restore data (a synced home
        /// directory) — ignored, not touched.
        #[test]
        fn a_record_from_another_os_is_left_on_disk() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            std::fs::write(&path, b"{\"os\":\"plan9\"}").unwrap();

            assert!(read_at(&path).is_none());
            assert!(path.exists());
            assert!(!preserved_path(&path).exists());
        }
    }
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
