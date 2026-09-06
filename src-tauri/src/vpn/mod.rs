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
        let _ = write(&DnsJournal {
            os: std::env::consts::OS.to_string(),
            services: services.to_vec(),
            tunnel_dns: tunnel_dns.to_vec(),
        });
    }

    /// Record the /etc/resolv.conf `configure_dns` is about to overwrite.
    #[cfg(target_os = "linux")]
    pub(super) fn record_linux(resolv_conf_backup: Option<String>, uses_systemd_resolved: bool) {
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
    /// before touching anything; the record is dropped either way, so a machine
    /// the user has already fixed by hand is examined once and then left alone.
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
            let restored = super::tunnel_macos::restore_services_still_on_tunnel_dns(
                &journal.services,
                &journal.tunnel_dns,
            );
            #[cfg(target_os = "linux")]
            let restored = super::tunnel_linux::restore_resolv_conf_if_ours(
                journal.resolv_conf_backup,
                journal.uses_systemd_resolved,
            );
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let restored = {
                let _ = &journal;
                false
            };

            clear();
            restored
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
