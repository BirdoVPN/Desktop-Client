//! MR-740: the crash-recovery record of the routes a Linux or macOS session
//! installs via the PHYSICAL gateway.
//!
//! WHY THIS EXISTS. The tunnel's own routes (`0.0.0.0/1`, `128.0.0.0/1`, the
//! IPv6 halves) go through birdo0 / the utun, and the kernel deletes them with
//! the device when the process dies. The routes that keep the tunnel working
//! do not: the relay's host route (`<relay>/32 via <gateway>`, which keeps
//! WireGuard's own UDP out of the tunnel) and, with Local Network Sharing, the
//! private ranges via that same gateway. They sit on the physical interface,
//! so a SIGKILL, an OOM kill or a panic (`panic = "abort"`) left them in the
//! table until the next reboot, pinned to the gateway of the network the
//! session began on. After a move to another network that relay (and, with
//! sharing, every private range) still pointed at a gateway that was gone, and
//! the next connect to that relay found "File exists", took the leftover for
//! someone else's route and handshook into the void (MR-2051). Windows has
//! journalled the same routes since W1-041 (`dns_journal`'s `routes`); this is
//! that record for the two Unix platforms.
//!
//! WHERE. Root-only, never the user's home (MR-2050: the DNS journal still
//! lives in `dirs::data_dir()`, which is the user's own folder when the GUI is
//! started with a kept HOME, and a record there would let any process of that
//! user name routes for root to delete). `/run/birdovpn` on Linux and
//! `/var/run/birdovpn` on macOS: a directory this process creates 0700, and
//! refuses unless it is a real directory owned by the effective user (root,
//! for the elevated client) that nobody else can write. Both sit on storage
//! the OS clears at boot, which is also the lifetime of a route; the record
//! carries its boot as well, and one from another boot is dropped without
//! deleting anything.
//!
//! WHEN. An entry is written as soon as its route is in, and dropped once a
//! teardown proved the route gone. `reconcile` runs where no tunnel of this
//! process can be up (at start-up, from the panic hook and for
//! `--reconcile-and-exit`, all through `dns_journal::reconcile`): it deletes
//! every route a previous process left, each with the exact qualifiers it was
//! added with, and keeps on record any delete it could not prove.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

/// The record's file name inside the record directory.
const RECORD_FILE: &str = "routes.json";

/// Where a new record is staged before it replaces the old one.
const STAGING_FILE: &str = "routes.json.tmp";

/// A handful of routes is well under a kilobyte; a larger file is not ours.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// The record directory: root-only, on storage the OS clears at boot.
#[cfg(target_os = "linux")]
const RECORD_DIR: &str = "/run/birdovpn";
#[cfg(target_os = "macos")]
const RECORD_DIR: &str = "/var/run/birdovpn";

/// Linux deletes a route by `dst via gw dev if`, so an entry without its
/// interface cannot be deleted exactly and is refused. macOS names none.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const NEEDS_DEV: bool = cfg!(target_os = "linux");

/// One route a session installed via the physical gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayRoute {
    /// IPv4 CIDR, e.g. `203.0.113.7/32`.
    pub(crate) dst: String,
    /// The gateway it was added via.
    pub(crate) via: String,
    /// Linux: the interface it was added on. macOS: `None`.
    #[serde(default)]
    pub(crate) dev: Option<String>,
}

impl GatewayRoute {
    /// Only plainly a route of ours is ever deleted. The fields become `ip` /
    /// `route` arguments, where a value beginning with `-` reads as an option;
    /// and no route of ours is a default route, whose delete would cut the
    /// host off.
    fn is_well_formed(&self, needs_dev: bool) -> bool {
        let dst_ok = super::parse_ipv4_cidr(&self.dst).is_some_and(|(_, prefix)| prefix > 0);
        let via_ok = self.via.parse::<std::net::Ipv4Addr>().is_ok();
        let dev_ok = match self.dev.as_deref() {
            Some(dev) => is_interface_name(dev),
            None => !needs_dev,
        };
        dst_ok && via_ok && dev_ok
    }
}

/// An interface name as `ip` takes it: non-empty, at most IFNAMSIZ - 1
/// bytes, printable, no `/`, and not option-shaped.
fn is_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_graphic() && c != '/')
}

/// What is on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    /// `std::env::consts::OS` of the writer.
    os: String,
    /// The boot the routes were installed in (Linux `boot_id`, macOS
    /// `kern.bootsessionuuid`). `None` when it could not be read.
    #[serde(default)]
    boot: Option<String>,
    #[serde(default)]
    routes: Vec<GatewayRoute>,
}

/// The outcome of one delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteDelete {
    /// The route was there and is gone now.
    Removed,
    /// Nothing of ours is there: already deleted, its interface is gone, or
    /// the destination now belongs to someone else's route.
    Absent,
    /// Not proved gone (no privileges, `ip`/`route` missing, any other
    /// error). Kept on record for the next start.
    Failed(String),
}

impl RouteDelete {
    /// Is nothing of ours left at that destination?
    pub(crate) fn settled(&self) -> bool {
        !matches!(self, RouteDelete::Failed(_))
    }
}

/// Is a record written in boot `recorded` about this boot (`now`)? A route
/// never survives a reboot, and after one the same destination and gateway
/// may be someone else's, so only a provable match lets a delete run.
fn same_boot(recorded: Option<&str>, now: Option<&str>) -> bool {
    matches!((recorded, now), (Some(a), Some(b)) if a == b)
}

/// The routes of `record` that still describe this boot.
fn this_boots_routes(record: Option<Record>, now: Option<&str>) -> Vec<GatewayRoute> {
    match record {
        Some(record) if same_boot(record.boot.as_deref(), now) => record.routes,
        _ => Vec::new(),
    }
}

fn record_of(now: Option<&str>, routes: Vec<GatewayRoute>) -> Record {
    Record {
        os: std::env::consts::OS.to_string(),
        boot: now.map(str::to_string),
        routes,
    }
}

/// What a reconcile pass did.
#[derive(Debug, Default, PartialEq, Eq)]
struct Reconciled {
    removed: usize,
    /// The routes whose delete failed: still on record.
    kept: Vec<GatewayRoute>,
}

/// Delete every route `record` names, if it is this boot's. Pure apart from
/// `delete`, so the rule runs in the Windows test job too.
fn settle(
    record: Record,
    now: Option<&str>,
    needs_dev: bool,
    mut delete: impl FnMut(&GatewayRoute) -> RouteDelete,
) -> Reconciled {
    let mut done = Reconciled::default();
    if record.routes.is_empty() {
        return done;
    }
    if !same_boot(record.boot.as_deref(), now) {
        tracing::info!(
            "The route record's {} route(s) are from an earlier boot — already gone",
            record.routes.len()
        );
        return done;
    }
    // The same line Windows logs (win_machine_state::reconcile_record); the
    // device checks look for it.
    tracing::warn!(
        "Removing {} route(s) a previous session left behind",
        record.routes.len()
    );
    for route in record.routes {
        if !route.is_well_formed(needs_dev) {
            tracing::warn!("Dropped a malformed entry from the route record, deleting nothing");
            continue;
        }
        match delete(&route) {
            RouteDelete::Removed => done.removed += 1,
            RouteDelete::Absent => {}
            RouteDelete::Failed(e) => {
                tracing::warn!(
                    "A route a previous session left could not be removed ({}) — kept for the \
                     next start",
                    e
                );
                done.kept.push(route);
            }
        }
    }
    done
}

// ──────────────────────────────────────────────────────────────
// Reading the delete tools' answers (pure, tested on every platform)
// ──────────────────────────────────────────────────────────────

/// Linux: `ip route del <dst> via <gw> dev <if>`'s answer. ESRCH ("No such
/// process") is "no such route"; a missing device took its routes with it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ip_route_del_outcome(success: bool, stderr: &str) -> RouteDelete {
    if success {
        RouteDelete::Removed
    } else if stderr.contains("No such process")
        || stderr.contains("Cannot find device")
        || stderr.contains("No such device")
    {
        RouteDelete::Absent
    } else {
        RouteDelete::Failed(stderr.trim().to_string())
    }
}

/// macOS: `route -n get` / `route -n delete`'s answer. ESRCH is "not in
/// table".
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn route_tool_outcome(success: bool, output: &str) -> RouteDelete {
    if success {
        RouteDelete::Removed
    } else if output.contains("not in table") {
        RouteDelete::Absent
    } else {
        RouteDelete::Failed(output.trim().to_string())
    }
}

/// macOS: does `route -n get`'s output describe `route` itself — this
/// destination and mask, via this gateway? BSD `route delete` matches on the
/// destination alone, so this is what keeps a recovery from deleting a route
/// someone else has since put there (a corporate VPN's 10.0.0.0/8, say).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn route_get_describes(output: &str, route: &GatewayRoute) -> bool {
    let field = |name: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(name).map(str::trim))
    };
    let Some((net, prefix)) = super::parse_ipv4_cidr(&route.dst) else {
        return false;
    };
    let ip = |value: Option<&str>| value.and_then(|v| v.parse::<std::net::Ipv4Addr>().ok());
    let mask = std::net::Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix.max(1))));
    let dst_ok = ip(field("destination:")) == Some(std::net::Ipv4Addr::from(net));
    let via_ok = ip(field("gateway:")) == route.via.parse().ok();
    let mask_ok = match field("mask:") {
        // A host route prints no mask.
        None => prefix == 32,
        Some(m) => ip(Some(m)) == Some(mask),
    };
    dst_ok && via_ok && mask_ok
}

// ──────────────────────────────────────────────────────────────
// The record on disk
// ──────────────────────────────────────────────────────────────

/// Serialises this process's read-modify-writes. `reconcile` only ever TRIES
/// it: the panic hook calls that, possibly on a thread holding it.
static WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn untrusted(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("the route record {what}"),
    )
}

/// The record's metadata must be ours alone: owned by the effective user
/// and writable by nobody else.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_owner(meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(untrusted("is owned by another user"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(untrusted("is writable by other users"));
    }
    Ok(())
}

/// The record directory must be a real directory (not a link) that only we
/// can write. Off Unix (the Windows test build) there is nothing to check.
fn check_dir(dir: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(untrusted("directory is not a directory"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    check_owner(&meta)?;
    Ok(())
}

/// Create the record directory owner-only, or verify the one there.
fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(e) = builder.create(dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    check_dir(dir)
}

/// The record in `dir`, if there is one this process may act on.
fn read_in(dir: &Path) -> Option<Record> {
    let opened = check_dir(dir).and_then(|()| {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(dir.join(RECORD_FILE))?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(untrusted("is not a file"));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        check_owner(&meta)?;
        Ok(file)
    });
    let file = match opened {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!("Route record not read: {}", e);
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_RECORD_BYTES).read_to_end(&mut bytes) {
        tracing::warn!("Route record not read: {}", e);
        return None;
    }
    match serde_json::from_slice::<Record>(&bytes) {
        Ok(record) if record.os == std::env::consts::OS => Some(record),
        Ok(record) => {
            tracing::warn!(
                "Ignoring a route record written on {} — this host is {}",
                record.os,
                std::env::consts::OS
            );
            None
        }
        Err(e) => {
            // Root-only and gone at the next boot: nothing else can read it
            // either, and the next write replaces it.
            tracing::warn!("Unreadable route record ({}) — ignored", e);
            None
        }
    }
}

/// Replace the record in `dir` with `record`, or remove it when it names no
/// route. Staged and renamed, so a crash leaves the old record or the new
/// one, never part of one.
fn write_in(dir: &Path, record: &Record) -> std::io::Result<()> {
    let path = dir.join(RECORD_FILE);
    if record.routes.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    ensure_dir(dir)?;
    let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    let staging = dir.join(STAGING_FILE);
    if let Err(e) = stage_and_replace(&staging, &path, &bytes) {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    // The rename is durable once the directory entry is. Best-effort.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// Write `bytes` to `staging`, get them onto the disk, and move the file
/// over `path`.
fn stage_and_replace(staging: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(staging)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(staging, path)
}

fn lock_writer() -> std::sync::MutexGuard<'static, ()> {
    WRITER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Add `route` (once) to the record in `dir`, written in boot `now`.
/// Entries from another boot are gone with it and are not carried over.
fn remember_in(dir: &Path, now: Option<&str>, route: &GatewayRoute) -> std::io::Result<()> {
    let _writer = lock_writer();
    let mut routes = this_boots_routes(read_in(dir), now);
    if !routes.contains(route) {
        routes.push(route.clone());
    }
    write_in(dir, &record_of(now, routes))
}

/// Drop every entry `gone` matches from the record in `dir`.
fn forget_in(
    dir: &Path,
    now: Option<&str>,
    gone: impl Fn(&GatewayRoute) -> bool,
) -> std::io::Result<()> {
    let _writer = lock_writer();
    let Some(record) = read_in(dir) else {
        return Ok(());
    };
    let mut routes = this_boots_routes(Some(record), now);
    routes.retain(|r| !gone(r));
    write_in(dir, &record_of(now, routes))
}

/// [`reconcile`] against `dir`. Returns how many routes it removed.
fn reconcile_in(
    dir: &Path,
    now: Option<&str>,
    needs_dev: bool,
    delete: impl FnMut(&GatewayRoute) -> RouteDelete,
) -> usize {
    // Held if free, never waited on (see WRITER).
    let _writer = WRITER.try_lock();
    let Some(record) = read_in(dir) else {
        return 0;
    };
    let done = settle(record, now, needs_dev, delete);
    if let Err(e) = write_in(dir, &record_of(now, done.kept)) {
        tracing::warn!("Route record not updated after the recovery: {}", e);
    }
    done.removed
}

// ──────────────────────────────────────────────────────────────
// The platform entry points
// ──────────────────────────────────────────────────────────────

/// The boot this process runs in.
#[cfg(target_os = "linux")]
fn current_boot() -> Option<String> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()?
        .trim()
        .to_string();
    (!id.is_empty()).then_some(id)
}

/// The boot this process runs in.
#[cfg(target_os = "macos")]
fn current_boot() -> Option<String> {
    let out = crate::utils::hidden_cmd("sysctl")
        .args(["-n", "kern.bootsessionuuid"])
        .output()
        .ok()?;
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !id.is_empty()).then_some(id)
}

/// Record `route`, which this session just installed. Best-effort: a record
/// that cannot be written costs the crash recovery of this route, never the
/// connect.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn remember(route: &GatewayRoute) {
    if let Err(e) = remember_in(Path::new(RECORD_DIR), current_boot().as_deref(), route) {
        tracing::warn!(
            "Route record not written ({}) — a crash would leave this route behind until \
             reboot",
            e
        );
    }
}

/// Drop `route` from the record: a teardown proved it gone.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn forget(route: &GatewayRoute) {
    if let Err(e) = forget_in(Path::new(RECORD_DIR), current_boot().as_deref(), |r| {
        r == route
    }) {
        tracing::warn!("Route record not updated: {}", e);
    }
}

/// Drop every entry for `dst`: a teardown deleted the route at that
/// destination (macOS deletes by destination).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn forget_destination(dst: &str) {
    if let Err(e) = forget_in(Path::new(RECORD_DIR), current_boot().as_deref(), |r| {
        r.dst == dst
    }) {
        tracing::warn!("Route record not updated: {}", e);
    }
}

/// Delete the routes a previous process left behind (see the module docs),
/// and keep on record any delete that did not prove its route gone. Only
/// where no tunnel of this process can be up: beside a live session these
/// are that session's routes. Returns how many routes it removed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn reconcile() -> usize {
    #[cfg(target_os = "linux")]
    let delete = super::tunnel_linux::delete_recorded_route;
    #[cfg(target_os = "macos")]
    let delete = super::tunnel_macos::delete_recorded_route;
    reconcile_in(
        Path::new(RECORD_DIR),
        current_boot().as_deref(),
        NEEDS_DEV,
        delete,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const BOOT: Option<&str> = Some("boot-a");

    fn endpoint() -> GatewayRoute {
        GatewayRoute {
            dst: "203.0.113.7/32".into(),
            via: "192.168.1.1".into(),
            dev: Some("wlan0".into()),
        }
    }

    fn lan() -> GatewayRoute {
        GatewayRoute {
            dst: "192.168.0.0/16".into(),
            via: "192.168.1.1".into(),
            dev: Some("wlan0".into()),
        }
    }

    fn dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("birdovpn");
        (tmp, dir)
    }

    /// Run a recovery against `dir`, answering every delete with `answer`,
    /// and report which routes it was asked to delete.
    fn recover(
        dir: &Path,
        now: Option<&str>,
        answer: impl Fn(&GatewayRoute) -> RouteDelete,
    ) -> (usize, Vec<GatewayRoute>) {
        let asked = RefCell::new(Vec::new());
        let removed = reconcile_in(dir, now, true, |r| {
            asked.borrow_mut().push(r.clone());
            answer(r)
        });
        (removed, asked.into_inner())
    }

    /// THE crash, simulated: a session records its gateway routes and dies
    /// without a teardown; the next start's recovery deletes exactly those
    /// routes and leaves no record behind.
    #[test]
    fn a_killed_sessions_routes_are_deleted_by_the_next_start() {
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        remember_in(&dir, BOOT, &lan()).unwrap();
        assert!(
            dir.join(RECORD_FILE).exists(),
            "the snapshot was not written"
        );

        let (removed, asked) = recover(&dir, BOOT, |_| RouteDelete::Removed);
        assert_eq!(asked, vec![endpoint(), lan()]);
        assert_eq!(removed, 2);
        assert!(
            !dir.join(RECORD_FILE).exists(),
            "a fully recovered record must be removed"
        );
        // A second start finds nothing to do.
        assert_eq!(recover(&dir, BOOT, |_| RouteDelete::Removed), (0, vec![]));
    }

    /// The snapshot round-trips: what is recorded is read back field for
    /// field, once per route, in the order the routes went in.
    #[test]
    fn the_snapshot_reads_back_what_was_written_once_per_route() {
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        remember_in(&dir, BOOT, &lan()).unwrap();
        let record = read_in(&dir).expect("the record");
        assert_eq!(record.os, std::env::consts::OS);
        assert_eq!(record.boot.as_deref(), BOOT);
        assert_eq!(record.routes, vec![endpoint(), lan()]);
    }

    /// A delete that could not be proved (an unprivileged start, `ip`
    /// missing) keeps its route on record for a later start; the ones that
    /// are gone leave it.
    #[test]
    fn an_unproved_delete_stays_on_record_for_the_next_start() {
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        remember_in(&dir, BOOT, &lan()).unwrap();

        let (removed, _) = recover(&dir, BOOT, |r| {
            if r.dst == endpoint().dst {
                RouteDelete::Failed("RTNETLINK answers: Operation not permitted".into())
            } else {
                RouteDelete::Absent
            }
        });
        assert_eq!(removed, 0);
        assert_eq!(read_in(&dir).unwrap().routes, vec![endpoint()]);

        let (removed, asked) = recover(&dir, BOOT, |_| RouteDelete::Removed);
        assert_eq!((removed, asked), (1, vec![endpoint()]));
        assert!(!dir.join(RECORD_FILE).exists());
    }

    /// Routes do not survive a reboot, and after one the same destination and
    /// gateway may be someone else's: a record from another boot (or one whose
    /// boot is unknown) deletes nothing and is dropped.
    #[test]
    fn a_record_from_another_boot_deletes_nothing() {
        for now in [Some("boot-b"), None] {
            let (_tmp, dir) = dir();
            remember_in(&dir, BOOT, &endpoint()).unwrap();
            let (removed, asked) = recover(&dir, now, |_| RouteDelete::Removed);
            assert_eq!((removed, asked), (0, vec![]), "now = {now:?}");
            assert!(!dir.join(RECORD_FILE).exists(), "now = {now:?}");
        }
    }

    /// A new route after a reboot starts a fresh record: the old boot's
    /// entries are not carried into this one.
    #[test]
    fn a_new_boots_record_does_not_carry_the_old_boots_routes() {
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        remember_in(&dir, Some("boot-b"), &lan()).unwrap();
        let record = read_in(&dir).unwrap();
        assert_eq!(record.boot.as_deref(), Some("boot-b"));
        assert_eq!(record.routes, vec![lan()]);
    }

    /// A clean teardown drops exactly the route it removed; the last one
    /// takes the file with it.
    #[test]
    fn a_teardown_forgets_exactly_the_routes_it_removed() {
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        remember_in(&dir, BOOT, &lan()).unwrap();
        forget_in(&dir, BOOT, |r| *r == endpoint()).unwrap();
        assert_eq!(read_in(&dir).unwrap().routes, vec![lan()]);
        forget_in(&dir, BOOT, |r| r.dst == lan().dst).unwrap();
        assert!(!dir.join(RECORD_FILE).exists());
        // Nothing on record: nothing to do, and nothing created.
        forget_in(&dir, BOOT, |_| true).unwrap();
        assert!(!dir.join(RECORD_FILE).exists());
    }

    /// Never hand the delete tools something that is not plainly a route of
    /// ours: option-shaped values, a default route, a non-IPv4 gateway, or (on
    /// Linux) an entry without the interface its exact delete needs.
    #[test]
    fn a_malformed_entry_is_never_deleted() {
        let bad = [
            GatewayRoute {
                dst: "-f".into(),
                ..endpoint()
            },
            GatewayRoute {
                dst: "0.0.0.0/0".into(),
                ..endpoint()
            },
            GatewayRoute {
                via: "fe80::1".into(),
                ..endpoint()
            },
            GatewayRoute {
                dev: Some("-x".into()),
                ..endpoint()
            },
            GatewayRoute {
                dev: Some("a/b".into()),
                ..endpoint()
            },
            GatewayRoute {
                dev: None,
                ..endpoint()
            },
        ];
        let record = record_of(BOOT, bad.to_vec());
        let done = settle(record, BOOT, true, |r| panic!("asked to delete {r:?}"));
        assert_eq!(done, Reconciled::default());

        // macOS names no interface, so there the last one is fine.
        let mac = GatewayRoute {
            dev: None,
            ..endpoint()
        };
        assert!(mac.is_well_formed(false));
        assert!(!mac.is_well_formed(true));
        assert!(endpoint().is_well_formed(true));
    }

    /// A record from another OS (a copied home, a shared disk) describes
    /// commands this host cannot run.
    #[test]
    fn a_record_from_another_os_is_ignored() {
        let (_tmp, dir) = dir();
        ensure_dir(&dir).unwrap();
        let foreign = Record {
            os: "plan9".into(),
            boot: BOOT.map(str::to_string),
            routes: vec![endpoint()],
        };
        std::fs::write(dir.join(RECORD_FILE), serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(read_in(&dir).is_none());
        assert_eq!(recover(&dir, BOOT, |_| RouteDelete::Removed), (0, vec![]));
    }

    #[test]
    fn ip_route_del_answers_are_read() {
        assert_eq!(ip_route_del_outcome(true, ""), RouteDelete::Removed);
        assert_eq!(
            ip_route_del_outcome(false, "RTNETLINK answers: No such process\n"),
            RouteDelete::Absent
        );
        assert_eq!(
            ip_route_del_outcome(false, "Cannot find device \"wlan0\"\n"),
            RouteDelete::Absent
        );
        assert_eq!(
            ip_route_del_outcome(false, "RTNETLINK answers: Operation not permitted\n"),
            RouteDelete::Failed("RTNETLINK answers: Operation not permitted".into())
        );
        assert!(!RouteDelete::Failed(String::new()).settled());
        assert!(RouteDelete::Absent.settled() && RouteDelete::Removed.settled());
    }

    #[test]
    fn route_tool_answers_are_read() {
        assert_eq!(
            route_tool_outcome(true, "delete host 192.0.2.10"),
            RouteDelete::Removed
        );
        assert_eq!(
            route_tool_outcome(
                false,
                "route: writing to routing socket: not in table\ndelete host 192.0.2.10: not in table"
            ),
            RouteDelete::Absent
        );
        assert_eq!(
            route_tool_outcome(false, "route: must be root to alter routing table\n"),
            RouteDelete::Failed("route: must be root to alter routing table".into())
        );
    }

    /// `route -n get` must describe our route itself before a recovery
    /// deletes by destination: not the default route a host lookup falls
    /// back to, not another gateway's route to the same network.
    #[test]
    fn route_get_must_describe_the_recorded_route() {
        let host = GatewayRoute {
            dst: "192.0.2.10/32".into(),
            via: "192.168.1.1".into(),
            dev: None,
        };
        let ours = "   route to: 192.0.2.10\ndestination: 192.0.2.10\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n";
        assert!(route_get_describes(ours, &host));

        let fell_back_to_default = "   route to: 192.0.2.10\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert!(!route_get_describes(fell_back_to_default, &host));

        let other_gateway = ours.replace("192.168.1.1", "10.0.0.1");
        assert!(!route_get_describes(&other_gateway, &host));

        let net = GatewayRoute {
            dst: "10.0.0.0/8".into(),
            via: "192.168.1.1".into(),
            dev: None,
        };
        let ours = "   route to: 10.0.0.0\ndestination: 10.0.0.0\n       mask: 255.0.0.0\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert!(route_get_describes(ours, &net));
        assert!(!route_get_describes(
            &ours.replace("255.0.0.0", "255.255.0.0"),
            &net
        ));
        // A corporate VPN's 10.0.0.0/8 through its utun is not ours.
        assert!(!route_get_describes(
            &ours.replace("192.168.1.1", "utun4"),
            &net
        ));
        // A host route without a mask line is not a /8.
        assert!(!route_get_describes(
            "destination: 10.0.0.0\n    gateway: 192.168.1.1\n",
            &net
        ));
    }

    /// The record and its directory are the effective user's alone (root's,
    /// for the elevated client): 0700 and 0600.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_record_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(RECORD_FILE)), 0o600);
    }

    /// MR-2050: a record in a directory anyone else can write could have been
    /// planted, so it is neither read nor written.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_directory_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, dir) = dir();
        remember_in(&dir, BOOT, &endpoint()).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_in(&dir).is_none(), "a planted record was read");
        assert_eq!(recover(&dir, BOOT, |_| RouteDelete::Removed), (0, vec![]));
        assert!(remember_in(&dir, BOOT, &lan()).is_err());
    }

    /// A record that is a symlink is refused (O_NOFOLLOW), and so is a
    /// record directory that is one.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_symlinked_record_or_directory_is_refused() {
        let (tmp, dir) = dir();
        ensure_dir(&dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere.json");
        std::fs::write(
            &elsewhere,
            serde_json::to_vec(&record_of(BOOT, vec![endpoint()])).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join(RECORD_FILE)).unwrap();
        assert!(
            read_in(&dir).is_none(),
            "the record was read through a link"
        );

        let real = tmp.path().join("real");
        remember_in(&real, BOOT, &endpoint()).unwrap();
        let linked = tmp.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(read_in(&linked).is_none(), "the directory was a link");
    }
}
