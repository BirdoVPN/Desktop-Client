//! VPN tunnel module
//!
//! WireGuard tunnel management using platform-specific virtual adapters:
//! - Windows: Wintun virtual network adapter
//! - macOS: utun kernel interface

pub mod auto_reconnect;
pub mod birdo_pq; // AUDIT-C1: BirdoPQ v1 ML-KEM-1024 PSK derivation (twin of Android BirdoPqManager)
pub mod buffer_pool; // FIX-2-4: Reduced to packet size constants only
pub mod doh; // DNS-over-HTTPS resolver for SEC-002
pub mod manager;
pub mod network_events; // OS route/resume signals for reconnect — zero packets (W1-011)
pub mod reconnect_policy; // Pure auto-reconnect decisions + circuit breaker (W1-029)
pub mod speed_test; // On-device speed test (P3-26)
pub mod xray; // Xray Reality stealth tunnel (matching Android XrayManager)

// Platform-specific tunnel implementations
#[cfg(target_os = "windows")]
pub mod tunnel;
#[cfg(target_os = "linux")]
pub mod tunnel_linux;
#[cfg(target_os = "macos")]
pub mod tunnel_macos;
// Shared ownership of the Linux/macOS tunnel fd, so no blocking read/write can
// outlive its descriptor (MR-820). Compiled into every test build too, so the
// Windows job runs its tests.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
mod device_fd;
// The emergency cleanup a dropped tunnel hands to a thread of its own, and the
// manager's waits for it (MR-823, MR-2039, MR-2036).
pub(crate) mod emergency_teardown;

/// The emergency cleanups this platform's tunnels hand off, and the longest
/// one can take (see `emergency_teardown`). macOS hands none off.
pub(crate) fn emergency_teardowns() -> emergency_teardown::InFlight {
    #[cfg(target_os = "windows")]
    {
        tunnel::emergency_teardowns()
    }
    #[cfg(target_os = "linux")]
    {
        tunnel_linux::emergency_teardowns()
    }
    #[cfg(target_os = "macos")]
    {
        static NONE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        emergency_teardown::InFlight {
            count: &NONE,
            bound: std::time::Duration::ZERO,
        }
    }
}

#[cfg(target_os = "windows")]
mod tunnel_dns; // netsh DNS reads + their captured-output parsers (Windows only)

// The event-driven Wintun <-> WireGuard packet path (W1-006)
#[cfg(target_os = "windows")]
mod data_plane;

// Process-global owner of the Windows machine state a session changes: the DNS
// guard, the installed routes, and the heal of DNS older builds parked. Lives
// outside the tunnel because it outlives individual tunnels — see the module
// docs for the invariants (issues #98, #100, #102, #105; W1-007, W1-041).
#[cfg(target_os = "windows")]
pub mod win_machine_state;
// Removed: pub mod wireguard; - deprecated file with placeholder crypto
mod wireguard_new;

// Windows Filtering Platform for kill switch
#[cfg(target_os = "windows")]
pub mod wfp;
// What the WFP session must contain, as testable data (W1-007/013/014)
#[cfg(target_os = "windows")]
pub(crate) mod wfp_policy;

// One-time heal of the netsh firewall rules builds <= 1.3.19 left (W1-036)
#[cfg(target_os = "windows")]
pub mod legacy_firewall;

// Linux iptables firewall for kill switch
#[cfg(target_os = "linux")]
pub mod firewall_linux;
// What the Linux iptables kill switch loads, as testable data. Compiled into
// every test build too, so the Windows job runs its tests.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod iptables_policy;

// What the macOS pf kill switch loads and reads back, as testable functions.
// Compiled into every test build too, so the Windows job runs its tests.
#[cfg(any(target_os = "macos", test))]
pub(crate) mod pf_policy;

// MR-740: the crash-recovery record of the routes a Linux/macOS session puts
// via the physical gateway, which outlive the tunnel device. Root-only; the
// next start removes what a killed session left. Compiled into every test
// build too, so the Windows job runs its tests.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) mod route_journal;

// Re-export the new boringtun-based implementation
pub use manager::VpnManager;
#[allow(unused_imports)]
pub use wireguard_new::WireGuardSession;
// MR-822: the client's WireGuard private key, moved (as a Box: one heap copy,
// wiped on drop) from its generation to the tunnel, and never cloned,
// serialized or printed on the way.
pub use wireguard_new::WgPrivateKey;

// ADAPTIVE TRANSPORT: the establish-time handshake failure markers, re-exported
// so commands::vpn::transport_fallback_reason can classify a failed connect
// without wireguard_new becoming a public module.
pub(crate) use wireguard_new::{ERR_HANDSHAKE_NO_RESPONSE, ERR_HANDSHAKE_RECV};

/// Marks a connect that failed because the platform firewall (macOS pf)
/// could not be enforced — the IPv6 leak block, or the kill switch letting
/// the new tunnel through — so `IpcError::from_tunnel_failure` reports the
/// kill switch rather than "the VPN adapter" (P3-5).
pub(crate) const ERR_FIREWALL_NOT_ENFORCED: &str = "the firewall (pf) could not be enforced";

// Re-export DoH resolver (available for future use)
#[allow(unused_imports)]
pub use doh::resolve_via_doh;

// Public API for auto-reconnect (may be used by external consumers)
#[allow(unused_imports)]
pub use auto_reconnect::{AutoReconnectConfig, AutoReconnectService};

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

    /// On macOS and Linux in the root-only `utils::root_state::STATE_DIR`
    /// (MR-2050, `/var/lib/birdovpn` / `/var/db/birdovpn`), the twin of the
    /// Windows directory below. It used to sit beside the log in
    /// `<data_dir>/BirdoVPN`, which is the USER's folder whenever the launch
    /// kept HOME (`sudo -E`): any process of theirs could plant a journal there
    /// and have root point /etc/resolv.conf where it said. A journal an older
    /// build left there is taken over once, only if root wrote it
    /// (`adopt_legacy_once`), and never read there again.
    ///
    /// On Windows in the admin-only `%ProgramData%\BirdoVPN` (MR-1721,
    /// `utils::protected_dir`). The record tells the ELEVATED client which
    /// routes to delete and which resolvers to put on which adapter, and in
    /// the user's %APPDATA% any unelevated process of theirs could write one:
    /// a planted journal had the client delete routes and point DNS where it
    /// said. A journal an older build left in %APPDATA% is taken over once
    /// ([`migrate_legacy`]) and never read there again.
    const JOURNAL_FILE: &str = "dns-restore.json";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct DnsJournal {
        /// `std::env::consts::OS` of the writer. A record from another platform
        /// (a synced home directory) describes commands this host cannot run.
        #[serde(default)]
        os: String,

        /// Windows: every physical adapter an OLDER build's `configure_dns`
        /// parked, with the resolvers it had. Nothing new is parked (W1-007);
        /// this is kept so those machines are healed.
        #[cfg(target_os = "windows")]
        #[serde(default)]
        adapters: Vec<super::tunnel::AdapterDnsSnapshot>,

        /// Windows: the routes this session installed that outlive the tunnel
        /// adapter (the endpoint host route, the LAN-sharing routes), so a
        /// crash no longer leaves them behind (W1-041).
        #[cfg(target_os = "windows")]
        #[serde(default)]
        routes: Vec<super::win_machine_state::OwnedRoute>,

        /// Windows: when the boot that wrote `routes` began (ms since the
        /// epoch). Routes do not survive a reboot, and after one an interface
        /// index may name another adapter, so they are only removed in the same
        /// boot.
        #[cfg(target_os = "windows")]
        #[serde(default)]
        boot: Option<u64>,

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

        /// Linux (MR-2018): the symlink target /etc/resolv.conf had before the
        /// pin replaced it (NetworkManager, resolvconf, WSL), so a crash
        /// recovery puts the LINK back rather than a frozen copy of its
        /// target. `None` when it was a regular file. Absent in records older
        /// builds wrote, which restore the bytes as they always did.
        #[cfg(target_os = "linux")]
        #[serde(default)]
        resolv_conf_link: Option<String>,

        /// Linux: was the tun link also configured through resolvectl?
        #[cfg(target_os = "linux")]
        #[serde(default)]
        uses_systemd_resolved: bool,
    }

    fn path() -> Option<std::path::PathBuf> {
        #[cfg(windows)]
        {
            let dir = match crate::utils::protected_dir::ensure() {
                Ok(dir) => dir,
                Err(e) => {
                    tracing::warn!("No admin-only directory for the DNS journal ({})", e);
                    return None;
                }
            };
            let path = dir.join(JOURNAL_FILE);
            migrate_legacy_once(&path);
            Some(path)
        }
        #[cfg(not(windows))]
        {
            // MR-2050: a fixed root-only directory, never one HOME names.
            let dir = std::path::Path::new(crate::utils::root_state::STATE_DIR);
            if let Err(e) = crate::utils::root_state::ensure_private_dir(dir) {
                tracing::warn!("No root-only directory for the DNS journal ({})", e);
                return None;
            }
            let path = dir.join(JOURNAL_FILE);
            adopt_legacy_once(&path);
            Some(path)
        }
    }

    /// MR-2050: take over the journal an older build left in
    /// `<data_dir>/BirdoVPN`, at most once per process (a flag, as
    /// `migrate_legacy_once`, because the panic hook reaches this too). Only
    /// one root wrote is moved (`root_state::adopt_legacy`); one in a folder the
    /// user owns or can write is left there, unread.
    #[cfg(not(windows))]
    fn adopt_legacy_once(path: &std::path::Path) {
        use std::sync::atomic::{AtomicBool, Ordering};
        static TRIED: AtomicBool = AtomicBool::new(false);
        if TRIED.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(base) = dirs::data_dir() else {
            return;
        };
        crate::utils::root_state::adopt_legacy(
            &base.join("BirdoVPN"),
            JOURNAL_FILE,
            path,
            |bytes| {
                serde_json::from_slice::<DnsJournal>(bytes)
                    .is_ok_and(|journal| journal.os == std::env::consts::OS)
            },
            write_bytes_atomically,
        );
    }

    /// [`migrate_legacy`] for this account, at most once per process. A flag
    /// rather than a `Once`: the panic hook reaches this through
    /// `reconcile`, and must never wait on another thread.
    #[cfg(windows)]
    fn migrate_legacy_once(protected: &std::path::Path) {
        use std::sync::atomic::{AtomicBool, Ordering};
        static TRIED: AtomicBool = AtomicBool::new(false);
        if TRIED.swap(true, Ordering::SeqCst) {
            return;
        }
        let (Some(base), Ok(sid)) = (
            dirs::data_dir(),
            crate::utils::protected_dir::current_user_sid(),
        ) else {
            return;
        };
        let legacy = crate::utils::safe_fs::OwnedDir::new(base, &["BirdoVPN"]);
        let marker = protected.with_file_name(format!("dns-journal-migrated-{sid}"));
        migrate_legacy(
            &legacy,
            protected,
            &marker,
            crate::utils::protected_dir::legacy_upgrade_window(),
        );
    }

    /// What became of a journal a pre-MR-1721 build left in %APPDATA%.
    #[cfg_attr(not(windows), allow(dead_code))]
    #[derive(Debug, PartialEq, Eq)]
    enum Migration {
        /// This account's was looked at before: a file there now is
        /// something any process of the user could have written.
        AlreadyDone,
        /// There was none.
        NoneThere,
        /// Moved into the admin-only directory.
        Moved,
        /// Left where it is, unread by the app from now on: unreadable, from
        /// another OS, or a journal is already in the admin-only directory
        /// (another account's machine state, which is the newer record).
        LeftInPlace,
        /// The admin-only copy could not be written; tried again next start.
        Failed,
    }

    /// Take over the journal an older build left in `legacy` (this account's
    /// %APPDATA%\BirdoVPN), ONCE: `marker`, in the admin-only directory where
    /// an unelevated process can neither create nor delete it, records that
    /// this account's was looked at, and from then on that folder is never
    /// read for a journal again.
    ///
    /// Rewrite an unverified %APPDATA% journal for a takeover OUTSIDE the
    /// legacy-upgrade window (D6c): drop every route (nothing is deleted on an
    /// unverified record) and heal every recorded adapter to DHCP / automatic
    /// DNS rather than to its journal-supplied resolver values. `None` when the
    /// bytes do not parse (the caller keeps them as-is; the OS check already
    /// refused a non-journal). Windows only; a no-op elsewhere.
    #[cfg(windows)]
    fn sanitize_unverified_journal(bytes: &[u8]) -> Option<Vec<u8>> {
        let mut journal: DnsJournal = serde_json::from_slice(bytes).ok()?;
        journal.routes.clear();
        for adapter in &mut journal.adapters {
            adapter.dns_servers.clear();
            adapter.dns_servers_v6.clear();
            adapter.v4_was_dhcp = true;
            adapter.v6_was_dhcp = true;
        }
        serde_json::to_vec(&journal).ok()
    }

    #[cfg(not(windows))]
    fn sanitize_unverified_journal(_bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// D6c (W1-008 vs #293 R1): the journal describes MACHINE state — adapter
    /// DNS a killed session parked, routes a crash stranded — so it is taken
    /// over on every account's first start, not only inside the legacy-upgrade
    /// window; otherwise on a multi-account PC the account that did not consume
    /// the machine-wide window would have its journal marked migrated UNREAD and
    /// the machine left without DNS.
    ///
    /// But the %APPDATA% journal is UNSIGNED and only checked to parse with
    /// `os == "windows"`, and the same-boot test is freshness, not authorship.
    /// So OUTSIDE the window a same-user process could plant one to make the
    /// elevated app delete the gateway routes it names and set journal-supplied
    /// resolvers on parked adapters, machine-wide. Outside the window the
    /// takeover is therefore SANITISED ([`sanitize_unverified_journal`]): the
    /// `routes` are dropped (no route is deleted on an unverified record) and
    /// every adapter is healed to DHCP/automatic DNS instead of to
    /// journal-supplied resolver values — still enough to lift a park and give
    /// the machine working DNS back, but it cannot be steered to attacker
    /// values. INSIDE the window (a genuine pre-#287 upgrade) the record is
    /// trusted as before, routes and resolvers included.
    ///
    /// The old file is read and deleted through checked handles (MR-1945).
    #[cfg_attr(not(windows), allow(dead_code))]
    fn migrate_legacy(
        legacy: &crate::utils::safe_fs::OwnedDir,
        protected: &std::path::Path,
        marker: &std::path::Path,
        upgrade_window: bool,
    ) -> Migration {
        use std::io::Read;
        if marker.exists() {
            return Migration::AlreadyDone;
        }
        let outcome = match legacy.open_rw(JOURNAL_FILE) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Migration::NoneThere,
            Err(e) => {
                tracing::warn!(
                    "The old DNS journal could not be read ({}) — left in place",
                    e
                );
                Migration::LeftInPlace
            }
            Ok(file) => {
                // A journal is a few kilobytes; a larger file is not one.
                let mut bytes = Vec::new();
                let read = file.take(1 << 20).read_to_end(&mut bytes);
                let ours = read.is_ok()
                    && serde_json::from_slice::<DnsJournal>(&bytes)
                        .is_ok_and(|journal| journal.os == std::env::consts::OS);
                if !ours || protected.exists() {
                    tracing::warn!(
                        "Left the old DNS journal in %APPDATA% in place, unused (MR-1721)"
                    );
                    Migration::LeftInPlace
                } else {
                    // Outside the upgrade window the record is unverified: drop
                    // routes and heal to DHCP, never to journal-supplied values.
                    let bytes = if upgrade_window {
                        bytes
                    } else {
                        sanitize_unverified_journal(&bytes).unwrap_or(bytes)
                    };
                    match write_bytes_atomically(protected, &bytes) {
                        Ok(()) => {
                            if let Err(e) = legacy.remove_file(JOURNAL_FILE) {
                                tracing::warn!("The old DNS journal was not deleted: {}", e);
                            }
                            tracing::info!("Moved the DNS journal to the admin-only directory");
                            Migration::Moved
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Could not move the old DNS journal ({}) — retrying next start",
                                e
                            );
                            return Migration::Failed;
                        }
                    }
                }
            }
        };
        if let Err(e) = std::fs::write(marker, b"") {
            tracing::warn!("Could not record the DNS journal's migration: {}", e);
        }
        outcome
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
        // mode on multi-user Unix hosts. On Windows it inherits the admin-only
        // directory's ACL (MR-1721): SYSTEM and Administrators alone.
        // The staging file holds those same bytes, so it takes the same mode.
        //
        // MR-2089: off Windows root writes it, so it is created NEW
        // (O_EXCL|O_NOFOLLOW) with that mode from the start. It used to be
        // opened with O_TRUNC, which wrote THROUGH a link planted at the name
        // and kept the mode of a file already there.
        #[cfg(unix)]
        let mut f = crate::utils::root_state::create_new_private(staging)?;
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(staging)?;
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
                "No journal directory — DNS could not be made restorable after an abnormal exit"
            );
            return Err("no journal directory".to_string());
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
        let bytes = read_bytes(path)?;
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

    /// The record's bytes, `None` when there is none.
    ///
    /// MR-2089: off Windows root acts on what it reads here, so the file is
    /// opened without following a link and must be a regular file that only
    /// we can write (`root_state::open_private`); anything else is refused and
    /// left alone. A journal is a few kilobytes; a larger file is not one.
    #[cfg(unix)]
    fn read_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        let read = crate::utils::root_state::open_private(path)
            .and_then(|file| file.take(1 << 20).read_to_end(&mut bytes));
        match read {
            Ok(_) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!("DNS journal not read: {}", e);
                None
            }
        }
    }

    #[cfg(not(unix))]
    fn read_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
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
        ///
        /// Only the macOS restore has such entries (a detached network
        /// service); the Linux record is one file, which is there or is not.
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    /// Pure and free of `cfg` so the Windows job actually runs its tests; only
    /// `record_macos` calls it outside them.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    /// `nameserver 1.1.1.1` / `nameserver 1.0.0.1`, then verifies (our marker is
    /// legitimately gone) and clears the journal: the user's own resolvers
    /// replaced by two public ones, permanently, by the recovery path.
    ///
    /// MR-2018: each side is `(bytes, symlink target)`, and the pair moves
    /// together. A live file that is a SYMLINK is a real baseline even when its
    /// target cannot be read (a resolver daemon between restarts): our pin is
    /// only ever a regular file. Only a capture with neither - the live file
    /// is ours, or unreadable and not a link - defers to the record.
    ///
    /// Pure for the same reason; only `record_linux` calls it outside tests.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn merge_linux_capture(
        fresh: (Option<&str>, Option<&str>),
        retained: (Option<&str>, Option<&str>),
    ) -> (Option<String>, Option<String>) {
        let owned = |(bytes, link): (Option<&str>, Option<&str>)| {
            (bytes.map(str::to_string), link.map(str::to_string))
        };
        match fresh {
            // A real read of the live file: newer and better than whatever the
            // record holds.
            (Some(_), _) | (_, Some(_)) => owned(fresh),
            (None, None) => owned(retained),
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

    /// Record what the Windows machine-state owner holds: adapters an older
    /// build parked and could not yet be restored, and the routes that would
    /// outlive a crash. Returns whether the record actually reached the disk.
    #[cfg(target_os = "windows")]
    pub(super) fn record_windows(
        adapters: &[super::tunnel::AdapterDnsSnapshot],
        routes: &[super::win_machine_state::OwnedRoute],
    ) -> Result<(), String> {
        write(&DnsJournal {
            os: std::env::consts::OS.to_string(),
            adapters: adapters.to_vec(),
            routes: routes.to_vec(),
            boot: super::win_machine_state::boot_epoch_ms(),
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
    pub(super) fn record_linux(
        resolv_conf_backup: Option<String>,
        resolv_conf_link: Option<String>,
        uses_systemd_resolved: bool,
    ) {
        // Same rule as macOS: the caller's capture is `None` whenever the file
        // already carried our marker, which is precisely the retained-record
        // case. See `merge_linux_capture`.
        let retained = read()
            .map(|old| (old.resolv_conf_backup, old.resolv_conf_link))
            .unwrap_or_default();
        let (resolv_conf_backup, resolv_conf_link) = merge_linux_capture(
            (resolv_conf_backup.as_deref(), resolv_conf_link.as_deref()),
            (retained.0.as_deref(), retained.1.as_deref()),
        );
        let _ = write(&DnsJournal {
            os: std::env::consts::OS.to_string(),
            resolv_conf_backup,
            resolv_conf_link,
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
    ///
    /// MR-740: on Linux and macOS this is also where the routes a killed
    /// session left via the physical gateway are removed (`route_journal`;
    /// Windows keeps them in this journal, W1-041). They have their own
    /// root-only record, so they are reconciled whether or not DNS was moved
    /// aside. They do not count towards the return value, which is about DNS.
    pub fn reconcile() -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let removed = super::route_journal::reconcile();
            if removed > 0 {
                tracing::warn!(
                    "Removed {} route(s) a previous session left behind",
                    removed
                );
            }
        }

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
            super::win_machine_state::reconcile_record(
                &journal.adapters,
                &journal.routes,
                journal.boot,
            )
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
                journal.resolv_conf_link,
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
        /// `restore_dns`'s fallback, which writes 1.1.1.1/1.0.0.1, verifies
        /// (our marker is legitimately gone) and clears the journal.
        #[test]
        fn a_none_capture_never_overwrites_retained_resolv_conf_bytes() {
            assert_eq!(
                merge_linux_capture((None, None), (Some("nameserver 192.168.1.1\n"), None)),
                (Some("nameserver 192.168.1.1\n".to_string()), None)
            );
        }

        #[test]
        fn a_real_capture_wins_and_none_over_nothing_stays_none() {
            assert_eq!(
                merge_linux_capture(
                    (Some("nameserver 9.9.9.9\n"), None),
                    (Some("nameserver 1.1.1.1\n"), None)
                ),
                (Some("nameserver 9.9.9.9\n".to_string()), None)
            );
            assert_eq!(
                merge_linux_capture((None, None), (None, None)),
                (None, None)
            );
        }

        /// MR-2018: the symlink travels with its bytes. A retained record's
        /// link survives a capture that reads our own pin back (neither bytes
        /// nor a link), and is never paired with a fresh capture's bytes.
        #[test]
        fn the_retained_symlink_moves_with_its_bytes() {
            let nm = "/run/NetworkManager/resolv.conf";
            assert_eq!(
                merge_linux_capture((None, None), (Some("nameserver 10.0.0.1\n"), Some(nm))),
                (
                    Some("nameserver 10.0.0.1\n".to_string()),
                    Some(nm.to_string())
                )
            );
            // A plain file now: the fresh capture wins whole, link and all.
            assert_eq!(
                merge_linux_capture(
                    (Some("nameserver 9.9.9.9\n"), None),
                    (Some("nameserver 10.0.0.1\n"), Some(nm))
                ),
                (Some("nameserver 9.9.9.9\n".to_string()), None)
            );
        }

        /// A live symlink whose target cannot be read is still a real baseline
        /// (our pin is only ever a regular file), so it is not traded for an
        /// older record.
        #[test]
        fn a_dangling_live_symlink_is_a_baseline() {
            let wsl = "/mnt/wsl/resolv.conf";
            assert_eq!(
                merge_linux_capture((None, Some(wsl)), (Some("nameserver 10.0.0.1\n"), None)),
                (None, Some(wsl.to_string()))
            );
        }
    }

    /// MR-1721: on Windows the journal lives in the admin-only directory. One
    /// an older build left in the user's %APPDATA% is taken over once, and
    /// that folder is never read for a journal again.
    #[cfg(test)]
    mod legacy_journal_tests {
        #[cfg(windows)]
        use super::DnsJournal;
        use super::{migrate_legacy, Migration, JOURNAL_FILE};
        use crate::utils::safe_fs::OwnedDir;
        use std::path::PathBuf;

        struct Dirs {
            _tmp: tempfile::TempDir,
            legacy: OwnedDir,
            protected: PathBuf,
            marker: PathBuf,
        }

        fn dirs() -> Dirs {
            let tmp = tempfile::tempdir().unwrap();
            let legacy = OwnedDir::new(tmp.path(), &["BirdoVPN"]);
            std::fs::create_dir_all(legacy.path()).unwrap();
            let admin = tmp.path().join("admin-only");
            std::fs::create_dir_all(&admin).unwrap();
            Dirs {
                protected: admin.join(JOURNAL_FILE),
                marker: admin.join("dns-journal-migrated-S-1-5-21-1-2-3-1001"),
                legacy,
                _tmp: tmp,
            }
        }

        fn journal(extra: &str) -> String {
            format!(r#"{{"os":"{}"{extra}}}"#, std::env::consts::OS)
        }

        fn read(p: &std::path::Path) -> String {
            std::fs::read_to_string(p).unwrap()
        }

        #[test]
        fn an_old_journal_is_moved_once() {
            let d = dirs();
            std::fs::write(d.legacy.join(JOURNAL_FILE), journal("")).unwrap();

            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, true),
                Migration::Moved
            );
            assert_eq!(read(&d.protected), journal(""));
            assert!(!d.legacy.join(JOURNAL_FILE).exists());
            assert!(d.marker.exists());

            // THE FINDING: what an unelevated process writes there now is
            // never read — it named routes for the elevated client to delete.
            std::fs::write(d.legacy.join(JOURNAL_FILE), journal(r#","routes":[]"#)).unwrap();
            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, true),
                Migration::AlreadyDone
            );
            assert_eq!(read(&d.protected), journal(""));
        }

        /// Nothing there at the first look closes it just the same.
        #[test]
        fn a_journal_planted_after_the_first_look_is_never_read() {
            let d = dirs();
            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, true),
                Migration::NoneThere
            );
            assert!(d.marker.exists());
            std::fs::write(d.legacy.join(JOURNAL_FILE), journal("")).unwrap();
            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, true),
                Migration::AlreadyDone
            );
            assert!(!d.protected.exists());
        }

        /// D6c (W1-008): the DNS journal is MACHINE state, so its takeover does
        /// not depend on the legacy-upgrade window — unlike the settings key and
        /// the resume record. A new account whose crashed session parked DNS
        /// still has its journal read and moved into the admin-only directory
        /// (where the reconcile restores it), rather than marked migrated unread,
        /// which would leave the machine without DNS.
        #[test]
        fn the_journal_is_taken_over_regardless_of_the_upgrade_window() {
            let d = dirs();
            std::fs::write(d.legacy.join(JOURNAL_FILE), journal("")).unwrap();
            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, false),
                Migration::Moved,
                "a new account's journal must still be restored (machine state)"
            );
            // Taken over (sanitised outside the window — see the sanitise tests);
            // still a journal of this OS that the reconcile can read.
            assert!(d.protected.exists());
            assert!(read(&d.protected).contains(&format!("\"os\":\"{}\"", std::env::consts::OS)));
            assert!(!d.legacy.join(JOURNAL_FILE).exists());
            assert!(d.marker.exists());
        }

        /// D6c MEDIUM: OUTSIDE the upgrade window the journal is unverified, so
        /// its takeover drops the routes (the elevated app deletes none) and
        /// heals adapters to DHCP, never to journal-supplied resolver values —
        /// a planted journal cannot steer DNS or delete gateway routes. INSIDE
        /// the window (a genuine upgrade) routes and resolvers are preserved.
        #[cfg(windows)]
        #[test]
        fn an_unverified_journal_is_sanitised_outside_the_window() {
            use super::super::tunnel::AdapterDnsSnapshot;
            use super::super::win_machine_state::OwnedRoute;
            use std::net::{IpAddr, Ipv4Addr};

            let make = || DnsJournal {
                os: std::env::consts::OS.to_string(),
                adapters: vec![AdapterDnsSnapshot {
                    adapter_name: "Wi-Fi".into(),
                    adapter_guid: "{GUID}".into(),
                    v4_was_dhcp: false,
                    v6_was_dhcp: false,
                    dns_servers: vec!["203.0.113.53".into()],
                    dns_servers_v6: vec!["2001:db8::53".into()],
                }],
                routes: vec![OwnedRoute {
                    dest: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                    prefix_len: 32,
                    next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    if_index: 7,
                }],
                boot: Some(123),
            };
            let bytes = serde_json::to_vec(&make()).unwrap();

            // Outside the window: sanitised.
            let d = dirs();
            std::fs::write(d.legacy.join(JOURNAL_FILE), &bytes).unwrap();
            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, false),
                Migration::Moved
            );
            let got: DnsJournal =
                serde_json::from_slice(&std::fs::read(&d.protected).unwrap()).unwrap();
            assert!(
                got.routes.is_empty(),
                "routes must be dropped outside the window"
            );
            assert_eq!(got.adapters.len(), 1);
            let a = &got.adapters[0];
            assert!(a.dns_servers.is_empty() && a.dns_servers_v6.is_empty());
            assert!(
                a.v4_was_dhcp && a.v6_was_dhcp,
                "adapter must be healed to DHCP"
            );
            assert_eq!(a.adapter_guid, "{GUID}", "the adapter identity is kept");

            // Inside the window: trusted verbatim.
            let d2 = dirs();
            std::fs::write(d2.legacy.join(JOURNAL_FILE), &bytes).unwrap();
            assert_eq!(
                migrate_legacy(&d2.legacy, &d2.protected, &d2.marker, true),
                Migration::Moved
            );
            let kept: DnsJournal =
                serde_json::from_slice(&std::fs::read(&d2.protected).unwrap()).unwrap();
            assert_eq!(kept.routes.len(), 1, "routes kept inside the window");
            assert_eq!(
                kept.adapters[0].dns_servers,
                vec!["203.0.113.53".to_string()]
            );
            assert!(!kept.adapters[0].v4_was_dhcp);
        }

        /// The machine-wide record already in the admin-only directory is
        /// the newer one: it is never overwritten by an account's old file.
        #[test]
        fn a_journal_already_in_the_admin_only_directory_is_kept() {
            let d = dirs();
            std::fs::write(&d.protected, journal(r#","boot":1"#)).unwrap();
            std::fs::write(d.legacy.join(JOURNAL_FILE), journal("")).unwrap();
            assert_eq!(
                migrate_legacy(&d.legacy, &d.protected, &d.marker, true),
                Migration::LeftInPlace
            );
            assert_eq!(read(&d.protected), journal(r#","boot":1"#));
            assert!(d.legacy.join(JOURNAL_FILE).exists(), "kept for support");
        }

        /// Not a journal of this OS: left for a support session, not taken.
        #[test]
        fn an_unreadable_or_foreign_journal_is_left_in_place() {
            for bytes in ["not json", r#"{"os":"plan9"}"#] {
                let d = dirs();
                std::fs::write(d.legacy.join(JOURNAL_FILE), bytes).unwrap();
                assert_eq!(
                    migrate_legacy(&d.legacy, &d.protected, &d.marker, true),
                    Migration::LeftInPlace,
                    "{bytes}"
                );
                assert!(!d.protected.exists());
                assert_eq!(read(&d.legacy.join(JOURNAL_FILE)), bytes);
                assert!(d.marker.exists());
            }
        }

        /// The Windows journal path is the admin-only directory's, never the
        /// user's data folder.
        #[test]
        fn the_windows_journal_lives_in_the_admin_only_directory() {
            let src = include_str!("mod.rs").replace('\r', "");
            let path_fn = &src[src
                .find("    fn path() -> Option<std::path::PathBuf> {")
                .expect("path()")..];
            let windows = &path_fn[..path_fn.find("#[cfg(not(windows))]").unwrap()];
            assert!(windows.contains("#[cfg(windows)]"));
            assert!(windows.contains("crate::utils::protected_dir::ensure()"));
            assert!(windows.contains("migrate_legacy_once(&path)"));
            assert!(!windows.contains("data_dir"), "{windows}");
        }
    }

    /// W1-008: the uninstaller restores what the journal describes BEFORE it
    /// deletes anything, and keeps a journal that still describes something.
    /// Source pins: the hook script is not reachable from a unit test, and
    /// they cannot see the template around it — the compile-only makensis
    /// harness does (lanes/WIN-FIX-1/tmp/d8-harness/build.sh, REVIEW-WIN2-020).
    #[cfg(test)]
    mod uninstall_tests {
        const HOOKS: &str = include_str!("../../nsis-hooks.nsh");
        const MAIN: &str = include_str!("../main.rs");

        /// `needles` appear in `haystack` in this order, each after the last.
        fn in_order(haystack: &str, needles: &[&str]) {
            let mut last = 0;
            for needle in needles {
                let at = haystack[last..]
                    .find(needle)
                    .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
                last += at + needle.len();
            }
        }

        #[test]
        fn the_uninstaller_reconciles_before_it_deletes_anything() {
            let pre = hook_macro("NSIS_HOOK_PREUNINSTALL");
            // REVIEW-WIN2-008: a running app is stopped FIRST — the template
            // does it only after this hook, and the reconcile beside a live
            // session deleted its routes and rewrote its journal. Then the
            // reconcile, which must finish (nsExec waits; REVIEW-WIN2-019: it
            // is bounded) before anything is deleted. The macro takes a full
            // PATH since tauri-bundler 2.10 (cli 2.12): a bare exe name
            // matches nothing and reports "not running"
            // (scripts/ci/check-nsis-hook-macros.sh checks this form against
            // the template compiled into the locked CLI). The one call lives
            // in BIRDO_STOP_APP_IF_RUNNING, which the MSI-era removal in
            // NSIS_HOOK_PREINSTALL uses too (WIN2-012).
            assert!(hook_macro("BIRDO_STOP_APP_IF_RUNNING").contains(
                r#"!insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}""#
            ));
            in_order(
                pre,
                &[
                    "!insertmacro BIRDO_STOP_APP_IF_RUNNING",
                    "nsExec::Exec /TIMEOUT=",
                    "--reconcile-and-exit",
                ],
            );
            assert!(!pre.contains("RMDir"));
            assert!(!pre.contains("ExecWait"), "unbounded");
            // The flag main() honours is the one the hook passes.
            assert!(MAIN.contains(r#"const RECONCILE_AND_EXIT: &str = "--reconcile-and-exit";"#));
            let flag = MAIN
                .find("arg == RECONCILE_AND_EXIT")
                .expect("main() handles it");
            let tauri = MAIN.find("tauri::Builder::default()").expect("the app");
            assert!(
                flag < tauri,
                "the flag is handled before any window or plugin"
            );
        }

        /// D6c HIGH: the uninstaller never deletes a per-user FOLDER with NSIS
        /// (`RMDir /r` follows junctions, so an elevated uninstall could delete
        /// files anywhere); the exe does it without following links. No hook
        /// touches $APPDATA/$LOCALAPPDATA/%TEMP% with RMDir or CopyFiles any
        /// more, and the old %TEMP% journal round-trip is gone.
        #[test]
        fn no_hook_recursively_deletes_a_user_folder() {
            for m in ["NSIS_HOOK_PREUNINSTALL", "NSIS_HOOK_POSTUNINSTALL"] {
                let body = hook_macro(m);
                for line in body.lines().filter(|l| !l.trim_start().starts_with(';')) {
                    assert!(!line.contains("RMDir"), "{m}: {line}");
                    assert!(!line.contains("CopyFiles"), "{m}: {line}");
                    assert!(!line.contains("birdo-journal-keep"), "{m}: {line}");
                    assert!(!line.contains("$APPDATA"), "{m}: {line}");
                    assert!(!line.contains("$LOCALAPPDATA"), "{m}: {line}");
                }
            }
            // The exe removes the folders without following a link
            // (`remove_tree_no_follow`), keeping the DNS journal.
            let pd = include_str!("../utils/protected_dir.rs");
            assert!(pd.contains("fn remove_app_data_folders_in("));
            assert!(pd.contains("fn remove_tree_no_follow("));
            assert!(pd.contains(r#"name.starts_with("dns-restore.json")"#));
        }

        /// D6c HIGH: with "Delete the application data" ticked, POSTUNINSTALL
        /// still clears the Credential Manager entries and the install registry
        /// records the suppressed template block would have — under the saved
        /// choice, not $DeleteAppDataCheckboxState (which PREUNINSTALL zeroed).
        #[test]
        fn the_non_folder_app_data_cleanup_runs_under_the_saved_choice() {
            let post = hook_macro("NSIS_HOOK_POSTUNINSTALL");
            let delete = &post[post
                .find("${If} $BirdoDeleteAppData = 1")
                .expect("the saved-choice app-data block")..];
            in_order(
                delete,
                &[
                    "${AndIf} $UpdateMode <> 1",
                    r#"CredDeleteW(w "access_token.BirdoVPN""#,
                    r#"CredDeleteW(w "refresh_token.BirdoVPN""#,
                    r#"CredDeleteW(w "settings_hmac_key.BirdoVPN""#,
                    r#"CredDeleteW(w "biometric_lock_enabled.BirdoVPN""#,
                    r#"DeleteRegKey HKLM "${BIRDO_MANUPRODUCTKEY}""#,
                    r#"DeleteRegValue HKCU "${BIRDO_MANUPRODUCTKEY}" "Installer Language""#,
                ],
            );
            // POSTUNINSTALL's LOGIC must not read the template's own variable
            // (PREUNINSTALL zeroed it); a mention in a comment is fine.
            for line in post.lines().filter(|l| !l.trim_start().starts_with(';')) {
                assert!(
                    !line.contains("$DeleteAppDataCheckboxState"),
                    "POSTUNINSTALL reads the zeroed template flag: {line}"
                );
            }
        }

        /// R2 / D6c HIGH: after the reconcile, a real uninstall has the exe
        /// remove the updater's installer, the set-aside squats and the
        /// per-user folders — not NSIS, whose `RMDir /r` follows junctions —
        /// and never on an in-place update. PREUNINSTALL then zeroes the
        /// template's own delete-app-data flag so its `RmDir /r` cannot run.
        #[test]
        fn the_uninstaller_removes_only_the_leftovers_through_the_exe() {
            let pre = hook_macro("NSIS_HOOK_PREUNINSTALL");
            in_order(
                pre,
                &[
                    "--reconcile-and-exit",
                    "${If} $UpdateMode <> 1",
                    "${If} $DeleteAppDataCheckboxState = 1",
                    r#"StrCpy $1 " --with-app-data""#,
                    "nsExec::Exec /TIMEOUT=",
                    r#""$INSTDIR\${MAINBINARYNAME}.exe" --remove-leftovers-and-exit$1'"#,
                    "${EndIf}",
                    // Save the choice, then neutralise the template's RmDir.
                    "StrCpy $BirdoDeleteAppData $DeleteAppDataCheckboxState",
                    "StrCpy $DeleteAppDataCheckboxState 0",
                ],
            );
            assert!(MAIN.contains(
                r#"const REMOVE_LEFTOVERS_AND_EXIT: &str = "--remove-leftovers-and-exit";"#
            ));
            assert!(MAIN.contains(r#"const WITH_APP_DATA: &str = "--with-app-data";"#));
            let flag = MAIN
                .find("arg == REMOVE_LEFTOVERS_AND_EXIT")
                .expect("main() handles it");
            // D6c BLOCKER: the cleanup sweep is dispatched BEFORE the process
            // holds the per-user directories (hold_app_dirs) and before the file
            // logger opens birdo.log inside one of them — otherwise this process
            // would hold what the sweep must delete.
            let hold = MAIN
                .find("file_log::hold_app_dirs();")
                .expect("main() holds the app dirs");
            let init = MAIN.find(".init();").expect("main() starts the subscriber");
            assert!(
                flag < hold && flag < init,
                "the cleanup sweep must run before hold_app_dirs() and the file logger"
            );
            // D6c LOW: main() only LATCHES the window (read-only) before the
            // reconcile short-circuit; it never consumes it.
            let latch = MAIN
                .find("let _ = crate::utils::protected_dir::legacy_upgrade_window();")
                .expect("main() latches the upgrade window read-only");
            let reconcile = MAIN.find("arg == RECONCILE_AND_EXIT").unwrap();
            let tauri = MAIN.find("tauri::Builder::default()").unwrap();
            assert!(
                flag < latch && latch < reconcile && reconcile < tauri,
                "the window is latched before the reconcile short-circuit, after the cleanup flag"
            );
            // The marker is consumed only in setup (the primary instance),
            // after the settings load, and never in main()'s pre-setup path.
            let pre_setup = &MAIN[..tauri];
            assert!(
                !pre_setup.contains("consume_legacy_upgrade_window"),
                "an auxiliary exit must not consume the upgrade marker"
            );
            let setup = &MAIN[MAIN.find(".setup(").expect("setup")..];
            in_order(
                setup,
                &[
                    "load_startup_settings",
                    "if startup_verified {",
                    "consume_legacy_upgrade_window()",
                ],
            );
            // Nothing in ProgramData is deleted by NSIS itself, and nothing
            // ever deletes the state key (ProtectedStateDir) or a settings key.
            for m in ["NSIS_HOOK_PREUNINSTALL", "NSIS_HOOK_POSTUNINSTALL"] {
                let code: Vec<&str> = hook_macro(m)
                    .lines()
                    .filter(|l| !l.trim_start().starts_with(';'))
                    .collect();
                for line in &code {
                    assert!(!line.contains("ProgramData"), "{m}: {line}");
                    assert!(!line.contains("SetShellVarContext all"), "{m}: {line}");
                    assert!(
                        !(line.contains("DeleteRegKey") && line.contains("BIRDO_STATE_KEY")),
                        "{m}: {line}"
                    );
                }
            }
        }

        /// D6c MEDIUM: the app version must be strictly greater than
        /// BIRDO_LAST_PRE_TRUST_VERSION. The installer marks "entry version <=
        /// floor" as a pre-#287 upgrade, and the v1.4.47 tag predates #287, so a
        /// build from main that still reported 1.4.47 would make every
        /// reinstall/upgrade re-open the legacy-trust window.
        #[test]
        fn the_app_version_is_past_the_legacy_trust_floor() {
            fn semver(s: &str) -> Vec<u64> {
                s.split('.').map(|p| p.parse().unwrap_or(0)).collect()
            }
            let conf: serde_json::Value =
                serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
            let app = conf["version"].as_str().unwrap();
            assert_eq!(
                app,
                env!("CARGO_PKG_VERSION"),
                "tauri.conf.json vs Cargo.toml"
            );
            let floor = "1.4.47"; // == BIRDO_LAST_PRE_TRUST_VERSION
            assert!(HOOKS.contains(&format!(
                r#"!define BIRDO_LAST_PRE_TRUST_VERSION "{floor}""#
            )));
            assert!(
                semver(app) > semver(floor),
                "the app version {app} must be strictly greater than the legacy-trust floor {floor}"
            );
        }

        /// R1: the installer marks the upgrade of a pre-#287 install, and only
        /// that: the version on the entry it replaces (read before the
        /// reinstall page's uninstall-first can delete it, and for a silent
        /// install in PREINSTALL), an MSI-era install, or a marker still
        /// pending. Written only once the install has succeeded; an
        /// uninstall drops one never consumed, as a value (the key keeps
        /// ProtectedStateDir).
        #[test]
        fn the_installer_marks_only_the_upgrade_of_a_pre_287_install() {
            // v1.4.47 (d4f0968) is the last release without #287 (8958efa4).
            assert!(HOOKS.contains(r#"!define BIRDO_LAST_PRE_TRUST_VERSION "1.4.47""#));
            // The first statement of the GUI-init/PREINSTALL adoption.
            assert!(hook_function("BirdoAdoptLegacyRecord")
                .lines()
                .skip(1)
                .find(|l| !l.trim_start().starts_with(';') && !l.trim().is_empty())
                .is_some_and(|l| l.trim() == "Call BirdoNotePriorInstall"));
            let note = hook_function("BirdoNotePriorInstall");
            in_order(
                note,
                &[
                    "${If} $BirdoPriorChecked = 1",
                    "Return",
                    r#"ReadRegDWORD $0 HKLM "${BIRDO_STATE_KEY}" "${BIRDO_LEGACY_UPGRADE_VALUE}""#,
                    "StrCpy $BirdoLegacyUpgrade 1",
                    r#"ReadRegStr $0 HKLM "${BIRDO_UNINSTALL_ROOT}\BirdoVPN" "DisplayVersion""#,
                    r#"${If} $0 != """#,
                    r#"${VersionCompare} $0 "${BIRDO_LAST_PRE_TRUST_VERSION}" $1"#,
                    "${If} $1 != 1",
                    "StrCpy $BirdoLegacyUpgrade 1",
                ],
            );
            in_order(
                hook_macro("NSIS_HOOK_PREINSTALL"),
                &[
                    "Call BirdoAdoptLegacyRecord",
                    "Call BirdoMsiEraEntries",
                    "${If} $0 > 0",
                    "StrCpy $BirdoLegacyUpgrade 1",
                ],
            );
            in_order(
                hook_macro("NSIS_HOOK_POSTINSTALL"),
                &[
                    "${If} $BirdoLegacyUpgrade = 1",
                    r#"WriteRegDWORD HKLM "${BIRDO_STATE_KEY}" "${BIRDO_LEGACY_UPGRADE_VALUE}" 1"#,
                    "${EndIf}",
                ],
            );
            assert_eq!(HOOKS.matches("WriteRegDWORD").count(), 1);
            in_order(
                hook_macro("NSIS_HOOK_POSTUNINSTALL"),
                &[
                    "${If} $UpdateMode <> 1",
                    r#"DeleteRegValue HKLM "${BIRDO_STATE_KEY}" "${BIRDO_LEGACY_UPGRADE_VALUE}""#,
                    "${EndIf}",
                ],
            );
        }

        /// REVIEW-WIN2-011: an in-place update keeps the launch-at-login
        /// task, like everything else.
        #[test]
        fn an_update_keeps_the_launch_at_login_task() {
            let post = hook_macro("NSIS_HOOK_POSTUNINSTALL");
            in_order(
                post,
                &[
                    "${If} $UpdateMode <> 1",
                    r#"schtasks /Delete /F /TN "BirdoVPN Launch At Login""#,
                    "${EndIf}",
                ],
            );
        }

        /// The body of `!macro <name>` in the hooks, up to its `!macroend`.
        fn hook_macro(name: &str) -> &'static str {
            let start = HOOKS
                .find(&format!("!macro {name}"))
                .unwrap_or_else(|| panic!("no macro {name}"));
            let body = &HOOKS[start..];
            &body[..body.find("!macroend").expect("!macroend")]
        }

        /// The body of `Function <name>` in the hooks, up to `FunctionEnd`.
        fn hook_function(name: &str) -> &'static str {
            let start = HOOKS
                .find(&format!("Function {name}\n"))
                .or_else(|| HOOKS.find(&format!("Function {name}\r\n")))
                .unwrap_or_else(|| panic!("no function {name}"));
            let body = &HOOKS[start..];
            &body[..body.find("FunctionEnd").expect("FunctionEnd")]
        }

        /// D8: the installer publishes as "Birdo Networks Ltd", and the hooks'
        /// own literals for the install record and its parent are the ones
        /// Tauri's template derives from it (`Software\<publisher>[\<product>]`).
        /// The build fails on a mismatch too (`!error` in NSIS_HOOK_PREINSTALL,
        /// the parent key included since REVIEW-WIN2-017); this catches it
        /// without a Windows bundle.
        #[test]
        fn the_installer_publishes_as_birdo_networks_ltd() {
            let conf: serde_json::Value =
                serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
            let publisher = conf["bundle"]["publisher"].as_str().unwrap();
            let product = conf["productName"].as_str().unwrap();
            assert_eq!(publisher, "Birdo Networks Ltd");
            assert!(
                HOOKS.contains(&format!(r#"!define BIRDO_MANUKEY "Software\{publisher}""#)),
                "the hooks' publisher key does not follow bundle.publisher"
            );
            assert!(
                HOOKS.contains(&format!(
                    r#"!define BIRDO_MANUPRODUCTKEY "${{BIRDO_MANUKEY}}\{product}""#
                )),
                "the hooks' record key does not follow productName"
            );
            assert_eq!(
                conf["bundle"]["windows"]["nsis"]["installMode"], "perMachine",
                "the machine records are written to HKLM"
            );
            let pre = hook_macro("NSIS_HOOK_PREINSTALL");
            for guard in [
                r#"!if "${BIRDO_MANUPRODUCTKEY}" != "${MANUPRODUCTKEY}""#,
                r#"!if "${BIRDO_MANUKEY}" != "${MANUKEY}""#,
                r#"!if "${INSTALLMODE}" != "perMachine""#,
            ] {
                assert!(pre.contains(guard), "{guard}");
            }
            assert_eq!(pre.matches("!error").count(), 4);
            // No second, unguarded copy of the parent key's literal.
            assert_eq!(HOOKS.matches(r#""Software\Birdo Networks Ltd"#).count(), 1);
        }

        /// D8: an upgrade from the old publisher adopts its install record
        /// before any page reads it (GUI and passive: Modern UI's GUI init;
        /// silent: PREINSTALL); a cancelled OR failed install puts the
        /// registry back (REVIEW-WIN2-014); a successful one keeps the old
        /// record as a mirror for a rollback (REVIEW-WIN2-013), which the
        /// uninstaller drops — as HKLM, whatever SHCTX the template switched
        /// to (REVIEW-WIN2-016).
        #[test]
        fn an_upgrade_adopts_the_old_publishers_record() {
            assert!(HOOKS.contains(r#"!define BIRDO_LEGACY_MANUKEY "Software\Birdo VPN""#));
            assert!(HOOKS.contains("!define MUI_CUSTOMFUNCTION_GUIINIT BirdoAdoptLegacyRecord"));
            assert!(HOOKS.contains("!define MUI_CUSTOMFUNCTION_ABORT BirdoForgetAdoptedRecord"));
            assert!(hook_function(".onInstFailed").contains("Call BirdoForgetAdoptedRecord"));

            let adopt = hook_function("BirdoAdoptLegacyRecord");
            in_order(
                adopt,
                &[
                    r#"ReadRegStr $0 SHCTX "${BIRDO_MANUPRODUCTKEY}" """#,
                    r#"ReadRegStr $0 SHCTX "${BIRDO_LEGACY_MANUPRODUCTKEY}" """#,
                    r#"WriteRegStr SHCTX "${BIRDO_MANUPRODUCTKEY}" "" $0"#,
                ],
            );
            assert!(adopt.contains("StrCpy $INSTDIR $0"));

            // Silent: adopt, move the output path, and only then remove the
            // folder the template created first — if it is empty
            // (REVIEW-WIN2-015: it was the working directory until then).
            in_order(
                hook_macro("NSIS_HOOK_PREINSTALL"),
                &[
                    "StrCpy $BirdoOutPathBeforeAdoption $INSTDIR",
                    "Call BirdoAdoptLegacyRecord",
                    "SetOutPath $INSTDIR",
                    "${If} $INSTDIR != $BirdoOutPathBeforeAdoption",
                    "RMDir $BirdoOutPathBeforeAdoption",
                ],
            );
            assert!(!hook_macro("NSIS_HOOK_PREINSTALL").contains("RMDir /r"));

            let post = hook_macro("NSIS_HOOK_POSTINSTALL");
            assert!(
                post.contains(r#"WriteRegStr HKLM "${BIRDO_LEGACY_MANUPRODUCTKEY}" "" $INSTDIR"#)
            );
            assert!(!post.contains("BIRDO_DROP_LEGACY_PUBLISHER_RECORD"));

            assert!(hook_macro("NSIS_HOOK_POSTUNINSTALL")
                .contains("!insertmacro BIRDO_DROP_LEGACY_PUBLISHER_RECORD"));
            let drop = hook_macro("BIRDO_DROP_LEGACY_PUBLISHER_RECORD");
            assert!(drop.contains(r#"DeleteRegKey HKLM "${BIRDO_LEGACY_MANUPRODUCTKEY}""#));
            assert!(
                !drop.contains("SHCTX"),
                "SHCTX is HKCU after the template's T:881"
            );
            // Never the whole old publisher key: a 1.0.0 install ("Birdo VPN"
            // product) keeps its own record under it.
            assert!(drop.contains(r#"DeleteRegKey /ifempty HKLM "${BIRDO_LEGACY_MANUKEY}""#));
            assert!(!drop.contains(r#"DeleteRegKey HKLM "${BIRDO_LEGACY_MANUKEY}""#));
        }

        /// WIN2-012: an upgrade over the MSI that builds b15aece..79fd4ae also
        /// shipped (same folder, publisher "Birdo VPN") removes that MSI
        /// BEFORE any file of ours is laid down, after stopping a running app,
        /// and matches nothing but its exact entry. Behaviour, with a real MSI
        /// of that shape: scripts/ci/nsis-msi-era-upgrade.ps1.
        #[test]
        fn an_upgrade_removes_the_msi_era_install_first() {
            in_order(
                hook_macro("NSIS_HOOK_PREINSTALL"),
                &[
                    "Call BirdoAdoptLegacyRecord",
                    "Push 0",
                    "Call BirdoMsiEraEntries",
                    "!insertmacro BIRDO_STOP_APP_IF_RUNNING",
                    "SetOutPath $TEMP",
                    "Push 1",
                    "Call BirdoMsiEraEntries",
                    "SetOutPath $INSTDIR",
                    "StrCpy $WixMode 1",
                ],
            );
            assert!(HOOKS.contains(r#"!define BIRDO_MSI_ERA_PUBLISHER "Birdo VPN""#));
            in_order(
                hook_function("BirdoIsMsiEraEntry"),
                &[
                    "${If} $1 = 38",
                    // Only a real GUID reaches msiexec (the round trip).
                    "IIDFromString",
                    "${If} $3 == 0",
                    "${AndIf} $1 == $0",
                    r#"${If} $1 S== "BirdoVPN""#,
                    r#"${If} $1 S== "${BIRDO_MSI_ERA_PUBLISHER}""#,
                    r#""WindowsInstaller""#,
                ],
            );
            let remove = hook_function("BirdoRemoveMsiEraEntry");
            in_order(
                remove,
                &[
                    "MsiQueryProductStateW",
                    "${If} $1 = -1",
                    r#"DeleteRegKey HKLM "${BIRDO_UNINSTALL_ROOT}\$0""#,
                    // Only an installed product is uninstalled, its code quoted.
                    "${ElseIf} $1 = 5",
                    r#"msiexec.exe" /x "$0" /qn /norestart"#,
                    "${ElseIf} $1 == 3010",
                    "StrCpy $BirdoMsiEraRemoved 1",
                    "SetRebootFlag true",
                    // -2 INVALIDARG, 1, 2, a failed call: left alone.
                    "${Else}",
                    "Leaving $0 alone",
                ],
            );
            // After a 3010, a GUI install's finish page offers the restart in
            // place of the template's "Create desktop shortcut" checkbox, and
            // the MSI took its own shortcut with it: the hook makes it, with
            // the template's own function (the NSIS build in
            // nsis-installer.yml fails if that name ever goes). Silent and
            // passive installs got theirs from the template already.
            in_order(
                hook_macro("NSIS_HOOK_POSTINSTALL"),
                &[
                    "${If} ${RebootFlag}",
                    "${AndIf} $BirdoMsiEraRemoved = 1",
                    "${AndIf} $PassiveMode <> 1",
                    "${AndIfNot} ${Silent}",
                    "Call CreateOrUpdateDesktopShortcut",
                    "${EndIf}",
                ],
            );
            assert!(
                !HOOKS.contains(r#""UninstallString""#),
                "the entry's own command is never run"
            );
        }

        /// MR-1606 / REVIEW-WIN2-018: the confirm page's "Delete the
        /// application data" says that the DNS-restore journal survives it.
        /// The custom English.nsh replaces the bundler's; every language the
        /// installer offers has to carry the sentence.
        /// scripts/ci/check-nsis-language.sh checks the generated installer
        /// and the CLI's own strings.
        #[test]
        fn the_confirm_page_says_the_journal_is_kept() {
            let conf: serde_json::Value =
                serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
            let nsis = &conf["bundle"]["windows"]["nsis"];
            assert_eq!(nsis["languages"], serde_json::json!(["English"]));
            assert_eq!(nsis["customLanguageFiles"]["English"], "nsis/English.nsh");
            assert!(include_str!("../../nsis/English.nsh").contains(
                r#"LangString deleteAppData ${LANG_ENGLISH} "Delete the application data (keeps the DNS-restore journal)""#
            ));
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

    /// MR-2089: off Windows the whole client runs as root, so the journal is
    /// written and read without ever following a link at its name, and is
    /// owner-only from the moment it exists. Unix only (on Windows it sits in
    /// the admin-only directory, MR-1721); tests.yml runs these unprivileged
    /// on Linux and macOS.
    #[cfg(all(test, unix))]
    mod root_write_tests {
        use super::{read_at, staging_path, write_bytes_atomically};
        use std::os::unix::fs::PermissionsExt;

        /// The smallest record this host reads back: every other field
        /// defaults.
        fn record() -> Vec<u8> {
            format!("{{\"os\":\"{}\"}}", std::env::consts::OS).into_bytes()
        }

        fn mode(path: &std::path::Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        /// A link planted on the staging name used to be opened with
        /// O_CREAT|O_TRUNC and written THROUGH: root truncated and overwrote
        /// whatever file it named.
        #[test]
        fn a_link_on_the_staging_name_is_not_written_through() {
            let dir = tempfile::tempdir().unwrap();
            let victim = dir.path().join("victim");
            std::fs::write(&victim, b"not the journal's").unwrap();
            let path = dir.path().join("dns-restore.json");
            std::os::unix::fs::symlink(&victim, staging_path(&path)).unwrap();

            write_bytes_atomically(&path, &record()).unwrap();

            assert_eq!(std::fs::read(&victim).unwrap(), b"not the journal's");
            assert!(
                std::fs::symlink_metadata(&path).unwrap().is_file(),
                "the journal is a file of its own, not the link"
            );
            assert_eq!(std::fs::read(&path).unwrap(), record());
            assert_eq!(mode(&path), 0o600);
        }

        /// A staging file a crash left behind kept its own mode under O_TRUNC,
        /// and the rename then made that mode the journal's.
        #[test]
        fn the_journal_is_owner_only_from_creation() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            std::fs::write(staging_path(&path), b"left by a crash").unwrap();
            std::fs::set_permissions(staging_path(&path), std::fs::Permissions::from_mode(0o644))
                .unwrap();

            write_bytes_atomically(&path, &record()).unwrap();

            assert_eq!(mode(&path), 0o600);
            assert_eq!(std::fs::read(&path).unwrap(), record());
        }

        /// The journal tells root what to put back into /etc/resolv.conf or
        /// the network services, so a link at its name is never followed...
        #[test]
        fn a_linked_journal_is_not_read() {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = dir.path().join("elsewhere.json");
            std::fs::write(&elsewhere, record()).unwrap();
            let path = dir.path().join("dns-restore.json");
            std::os::unix::fs::symlink(&elsewhere, &path).unwrap();

            assert!(read_at(&path).is_none());
            assert_eq!(std::fs::read(&elsewhere).unwrap(), record());
        }

        /// ...and a journal someone else could have written is not read.
        #[test]
        fn a_journal_others_can_write_is_not_read() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dns-restore.json");
            std::fs::write(&path, record()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                read_at(&path).is_some(),
                "control: an owner-only journal is read"
            );

            for wider in [0o620, 0o602, 0o666] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(wider)).unwrap();
                assert!(read_at(&path).is_none(), "{wider:o}");
                assert!(path.exists(), "{wider:o}: refused, not set aside");
            }
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
            public_key: String::new(),
            server_public_key: String::new(),
            preshared_key: None,
            endpoint: "203.0.113.1:51820".into(),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
            dns: vec!["10.8.0.1".into()],
            custom_dns: false,
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
