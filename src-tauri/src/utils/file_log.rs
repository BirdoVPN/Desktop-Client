//! The on-device diagnostic log: the user's switch for it, and its delete
//! button (MR-808).
//!
//! WHAT IS ON DISK. `birdo.log` (and, past [`MAX_LOG_BYTES`], one rotated
//! `birdo.log.1`) in [`log_dir`]: `%APPDATA%\BirdoVPN\logs` on Windows,
//! `~/Library/Application Support/BirdoVPN/logs` on macOS,
//! `~/.local/share/BirdoVPN/logs` on Linux. A release build writes INFO and
//! above (`log_policy`), with addresses redacted, and launch prunes it to the
//! last `log_retention::MAX_LOG_AGE_DAYS` days. A panic also writes
//! `crash_YYYYMMDD_HHMMSS.txt` (location, sanitised message, backtrace) to
//! [`crash_dir`]: `%LOCALAPPDATA%\Birdo VPN\crashes` on Windows; at most five,
//! same window. Read together they are a dated record of when this device
//! connected, reconnected, went offline and failed: connection history, on the
//! user's own disk. Nothing here is sent anywhere. Sentry is a separate,
//! opt-in channel (`crash_report`).
//!
//! THE SWITCH is `AppSettings::file_logging_enabled`, default ON (see there
//! for why). Off means nothing more is written: no log line, no crash file.
//! Files already on disk are left alone until the user deletes them
//! ([`delete_logs`]); the launch sweep still prunes them to the retention
//! window, so they also age out on their own.
//!
//! WHY THE GATE STARTS UNDECIDED. The file layer is built at the top of
//! `main()`, before Tauri exists, and the setting can only be read in
//! `setup()`: it needs the app's config directory and the settings signing
//! key. The log used to be opened right there, so a user who had turned it off
//! would still have had every launch appended to it. Now nothing is opened
//! until `setup()` has decided ([`apply`]); the lines logged before that (the
//! elevation check among them) are held in memory, bounded, and written once
//! the log is on, or dropped when it is off. A panic before `setup()` writes no
//! crash file for the same reason: the user's choice is not known yet, and
//! writing one would ignore an "off". A run that never reaches `setup()` (the
//! uninstaller's `--reconcile-and-exit`, a second instance handing over to the
//! first) never decides, and persists nothing.
//!
//! NOT A LOG: the DNS journal (`vpn::dns_journal`, `dns-restore.json` in the
//! directory above `logs`). It is the record of the resolvers to put back, the
//! machine's only way to undo a DNS change a crash left behind, so neither the
//! switch nor the delete touches it. Neither touches `settings.json`, the device
//! id, the PQ key or the Xray config.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use super::log_retention::{is_crash_report_name, RotatingLog, MAX_LOG_BYTES};

/// The live log's file name. Its rotated generation is
/// `log_retention::rotated_path` of it (`birdo.log.1`).
pub const LOG_FILE_NAME: &str = "birdo.log";

/// Where `birdo.log` lives: `<data dir>/BirdoVPN/logs`. The single definition:
/// `main()` writes there, and [`delete_logs`] deletes there.
pub fn log_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|base| base.join("BirdoVPN").join("logs"))
}

/// Where crash reports go, under `base` (the local data directory). The
/// single definition, shared by `main.rs`'s writer and [`crash_dir`].
pub fn crash_dir_in(base: &Path) -> PathBuf {
    base.join("Birdo VPN").join("crashes")
}

/// Where crash reports go: `<local data dir>/Birdo VPN/crashes`. `None` when
/// the OS has no such directory: [`delete_logs`] then deletes nothing there
/// rather than guess (the writer's fallback is the working directory, which is
/// nobody's to clear).
pub fn crash_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|base| crash_dir_in(&base))
}

const UNDECIDED: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;

/// How much the gate holds while undecided: a few dozen lines are logged
/// before `setup()`; past this, the rest are dropped rather than grow memory.
const HELD_CAP: usize = 64 * 1024;

/// Whether log lines may reach the disk: undecided (held in memory), on, or
/// off. See the module docs for why it starts undecided.
pub struct LogGate {
    mode: AtomicU8,
    held: Mutex<Vec<u8>>,
}

impl LogGate {
    /// A gate that holds lines until [`LogGate::set`] decides.
    pub const fn undecided() -> Self {
        Self {
            mode: AtomicU8::new(UNDECIDED),
            held: Mutex::new(Vec::new()),
        }
    }

    /// A gate that is on from the start (tests, and `RotatingLog::open`).
    #[cfg(test)]
    pub const fn on() -> Self {
        Self {
            mode: AtomicU8::new(ON),
            held: Mutex::new(Vec::new()),
        }
    }

    /// Decide. Off drops whatever is held, unwritten. Returns whether the
    /// decision changed anything.
    pub fn set(&self, enabled: bool) -> bool {
        let mut held = self.lock_held();
        let next = if enabled { ON } else { OFF };
        let before = self.mode.swap(next, Ordering::SeqCst);
        if !enabled {
            *held = Vec::new();
        }
        before != next
    }

    pub fn is_on(&self) -> bool {
        self.mode.load(Ordering::SeqCst) == ON
    }

    pub fn is_undecided(&self) -> bool {
        self.mode.load(Ordering::SeqCst) == UNDECIDED
    }

    /// Keep a line written before the gate was decided. A line that arrives
    /// as the gate turns on is kept too (the next write puts it out first);
    /// one that arrives once it is off is dropped.
    fn hold(&self, bytes: &[u8]) {
        let mut held = self.lock_held();
        if self.mode.load(Ordering::SeqCst) != OFF && held.len() + bytes.len() <= HELD_CAP {
            held.extend_from_slice(bytes);
        }
    }

    /// What is held, handed over once (the log writes it out on turning on).
    pub fn take_held(&self) -> Vec<u8> {
        std::mem::take(&mut *self.lock_held())
    }

    fn lock_held(&self) -> MutexGuard<'_, Vec<u8>> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The writer `RotatingLog` hands out while its gate is undecided.
pub struct Held(pub &'static LogGate);

impl Write for Held {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.hold(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The user's choice for this process. Undecided until `setup()` reads it.
static FILE_LOGGING: LogGate = LogGate::undecided();

/// This process's `birdo.log` writer, once `main()` has built it.
static FILE_LOG: OnceLock<RotatingLog> = OnceLock::new();

/// Build this process's `birdo.log` writer at `path`, gated on the user's
/// choice. Opens nothing: the file is opened on the first line written after
/// [`apply`] has said on.
pub fn install(path: &Path) -> &'static RotatingLog {
    FILE_LOG.get_or_init(|| RotatingLog::gated(path, MAX_LOG_BYTES, &FILE_LOGGING))
}

/// Apply the user's choice: at start-up (`setup()`), on every settings save
/// and on a reset, so the live gate always equals what is saved. Takes effect
/// at once in both directions: on writes what was held and opens the file,
/// off closes it. The change is logged AFTER it, so turning the log off never
/// writes a line saying so into the file.
pub fn apply(enabled: bool) {
    let changed = FILE_LOGGING.set(enabled);
    if let Some(log) = FILE_LOG.get() {
        log.sync();
    }
    if changed {
        tracing::info!(
            "Diagnostic log on this device: {}",
            if enabled { "on" } else { "off" }
        );
    }
}

/// Whether this process may write to disk what the log records (crash
/// reports included). False until `setup()` has read the user's choice.
pub fn persists() -> bool {
    FILE_LOGGING.is_on()
}

/// What [`delete_logs`] did, in counts. Never a path: the UI has no use for
/// one, and a path carries the account's user name.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Deleted {
    /// Files removed.
    pub deleted: u32,
    /// Files (or a directory) that are ours by name and were not removed: in
    /// use by another program, no permission, or a link where the directory
    /// should be.
    pub failed: u32,
}

/// `birdo.log` or a rotated generation of it (`birdo.log.1`; any
/// `birdo.log.<digits>`). Nothing else in the log directory is ours to delete.
fn is_log_file_name(name: &str) -> bool {
    name == LOG_FILE_NAME
        || name
            .strip_prefix(LOG_FILE_NAME)
            .and_then(|rest| rest.strip_prefix('.'))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Delete the diagnostic log and the local crash reports now (Settings ›
/// Privacy & Security › "Delete Logs Now").
///
/// THE OPEN FILE. While the log is on, this process holds `birdo.log` open.
/// It is not truncated in place: the log's handle is CLOSED, with the log's
/// lock held across the close and every removal, so no line from this
/// process can land in between, and the next line opens a fresh file (created
/// owner-only, as always). Deleting rather than truncating means the file is
/// really gone, and its rotated generation and the crash files go the same
/// way. On Windows, Rust opens files with `FILE_SHARE_DELETE`, so a line
/// already being written through a handle cloned before the lock was taken
/// does not block the removal; it goes into the deleted file and is gone with
/// it. Another program holding a file without that share mode does block it:
/// the file is counted as `failed`, never reported as deleted.
pub fn delete_logs() -> Deleted {
    let run = || delete_logs_in(log_dir().as_deref(), crash_dir().as_deref());
    match FILE_LOG.get() {
        Some(log) => log.closed_for(run),
        None => run(),
    }
}

/// [`delete_logs`] over given directories. Only names this app writes are
/// deleted: `birdo.log*` from `log_dir`, `crash_*.txt` from `crash_dir`.
pub fn delete_logs_in(log_dir: Option<&Path>, crash_dir: Option<&Path>) -> Deleted {
    let mut tally = Deleted::default();
    if let Some(dir) = log_dir {
        delete_in(dir, is_log_file_name, &mut tally);
    }
    if let Some(dir) = crash_dir {
        delete_in(dir, is_crash_report_name, &mut tally);
    }
    tally
}

/// Remove every regular file directly in `dir` whose name `ours` accepts.
///
/// No paths from anywhere else: `dir` is one of the app's two known
/// directories, and each candidate is `dir` joined with a name read from it.
/// Never recursive, and never through a link: a `dir` that is a symlink or a
/// junction is refused outright (`symlink_metadata` does not follow it, and a
/// junction is a link there too), and an entry that is a link or a directory is
/// skipped, whatever its name. Removing a link would only unlink the link
/// (neither `DeleteFileW` nor `unlink` follows one), but it is not a file this
/// app wrote, so it is not this app's to remove.
fn delete_in(dir: &Path, ours: fn(&str) -> bool, tally: &mut Deleted) {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        // A link or a file where the directory should be: refused, and said.
        Ok(_) => {
            tally.failed += 1;
            return;
        }
        // No directory: nothing was ever written there.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(_) => {
            tally.failed += 1;
            return;
        }
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        tally.failed += 1;
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !ours(name) {
            continue;
        }
        let path = dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => {}
            _ => continue,
        }
        match std::fs::remove_file(&path) {
            Ok(()) => tally.deleted += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => tally.failed += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(
            &p,
            "2026-10-13T12:00:00Z INFO  VPN connected successfully\n",
        )
        .unwrap();
        p
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Exactly the files this app writes go: the log, its rotated
    /// generation, the crash reports. Anything else in either directory stays
    /// (the DNS journal lives one level up and is never even listed).
    #[test]
    fn only_the_logs_and_crash_reports_are_deleted() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        let crashes = root.path().join("crashes");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::create_dir_all(&crashes).unwrap();
        write(&logs, "birdo.log");
        write(&logs, "birdo.log.1");
        write(&logs, "birdo.log.old");
        write(&logs, "birdo.logx");
        write(&logs, "notes.txt");
        write(&crashes, "crash_20261013_120000.txt");
        write(&crashes, "crash_20261012_080000.txt");
        write(&crashes, "crash_20261013_120000.dmp");
        write(&crashes, "readme.txt");
        let journal = write(root.path(), "dns-restore.json");

        let done = delete_logs_in(Some(&logs), Some(&crashes));

        assert_eq!(
            done,
            Deleted {
                deleted: 4,
                failed: 0
            }
        );
        assert_eq!(names(&logs), ["birdo.log.old", "birdo.logx", "notes.txt"]);
        assert_eq!(names(&crashes), ["crash_20261013_120000.dmp", "readme.txt"]);
        assert!(journal.exists(), "the DNS journal is not a log");
    }

    #[test]
    fn empty_and_missing_directories_delete_nothing_and_fail_nothing() {
        let root = tempfile::tempdir().unwrap();
        let empty = root.path().join("logs");
        std::fs::create_dir_all(&empty).unwrap();
        let absent = root.path().join("crashes");

        assert_eq!(
            delete_logs_in(Some(&empty), Some(&absent)),
            Deleted::default()
        );
        assert_eq!(delete_logs_in(None, None), Deleted::default());
        assert!(!absent.exists(), "deleting must not create a directory");
    }

    /// A directory inside one of ours, named like a log, is not a log.
    #[test]
    fn a_directory_named_like_a_log_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        std::fs::create_dir_all(logs.join("birdo.log.1")).unwrap();
        write(&logs.join("birdo.log.1"), "birdo.log");

        assert_eq!(delete_logs_in(Some(&logs), None), Deleted::default());
        assert!(logs.join("birdo.log.1").join("birdo.log").exists());
    }

    /// A link named like a log is skipped, and what it points at survives.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_is_skipped_and_its_target_survives() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let target = write(root.path(), "precious.txt");
        std::os::unix::fs::symlink(&target, logs.join("birdo.log")).unwrap();
        write(&logs, "birdo.log.1");

        let done = delete_logs_in(Some(&logs), None);

        assert_eq!(
            done,
            Deleted {
                deleted: 1,
                failed: 0
            }
        );
        assert!(target.exists(), "the link's target was deleted");
        assert!(
            std::fs::symlink_metadata(logs.join("birdo.log")).is_ok(),
            "the link itself is not ours to remove"
        );
    }

    /// A linked DIRECTORY is refused outright: nothing behind it is touched.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let victim = write(&elsewhere, "birdo.log");
        let logs = root.path().join("logs");
        std::os::unix::fs::symlink(&elsewhere, &logs).unwrap();

        let done = delete_logs_in(Some(&logs), None);

        assert_eq!(
            done,
            Deleted {
                deleted: 0,
                failed: 1
            }
        );
        assert!(victim.exists());
    }

    /// The same two refusals on Windows, where a symlink needs a privilege
    /// (or Developer Mode) the test may not have: skipped there, not failed.
    #[cfg(windows)]
    #[test]
    fn a_symlinked_log_is_skipped_and_its_target_survives() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let target = write(root.path(), "precious.txt");
        if std::os::windows::fs::symlink_file(&target, logs.join("birdo.log")).is_err() {
            eprintln!("skipped: this account cannot create symlinks");
            return;
        }
        write(&logs, "birdo.log.1");

        let done = delete_logs_in(Some(&logs), None);

        assert_eq!(
            done,
            Deleted {
                deleted: 1,
                failed: 0
            }
        );
        assert!(target.exists(), "the link's target was deleted");
        assert!(std::fs::symlink_metadata(logs.join("birdo.log")).is_ok());
    }

    #[test]
    fn the_rotated_generation_name_is_one_the_delete_knows() {
        let live = Path::new("logs").join(LOG_FILE_NAME);
        let rotated = super::super::log_retention::rotated_path(&live);
        let rotated = rotated.file_name().unwrap().to_str().unwrap();
        assert!(is_log_file_name(LOG_FILE_NAME));
        assert!(is_log_file_name(rotated), "{rotated}");
        for not_ours in [
            "birdo.log.",
            "birdo.log.1.bak",
            "birdo.log.tmp",
            "x-birdo.log",
        ] {
            assert!(!is_log_file_name(not_ours), "{not_ours}");
        }
    }

    // ── the gate ──────────────────────────────────────────────────────────

    fn leaked_gate() -> &'static LogGate {
        Box::leak(Box::new(LogGate::undecided()))
    }

    /// THE FINDING (MR-808): with the log off, launching must neither create
    /// nor append to it — not even with the lines logged before `setup()`
    /// read the choice.
    #[test]
    fn an_undecided_log_opens_nothing_and_off_drops_what_it_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join(LOG_FILE_NAME);
        let gate = leaked_gate();
        let log = RotatingLog::gated(&path, MAX_LOG_BYTES, gate);

        log.writer()
            .write_all(b"NOT running as administrator\n")
            .unwrap();
        assert!(!path.exists(), "an undecided log opened the file");

        gate.set(false);
        log.sync();
        log.writer().write_all(b"Connected\n").unwrap();
        assert!(!path.exists(), "a log that is off wrote anyway");
        assert!(gate.take_held().is_empty(), "off keeps nothing in memory");
    }

    /// On: what was held is written first, in order, and the directory is
    /// created on the way.
    #[test]
    fn turning_on_writes_the_held_lines_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join(LOG_FILE_NAME);
        let gate = leaked_gate();
        let log = RotatingLog::gated(&path, MAX_LOG_BYTES, gate);

        log.writer().write_all(b"one\n").unwrap();
        gate.set(true);
        log.sync();
        log.writer().write_all(b"two\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    }

    /// Live in both directions: off closes the file, on opens it again.
    #[test]
    fn the_switch_applies_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_FILE_NAME);
        let gate = leaked_gate();
        let log = RotatingLog::gated(&path, MAX_LOG_BYTES, gate);
        gate.set(true);
        log.writer().write_all(b"kept\n").unwrap();

        gate.set(false);
        log.sync();
        log.writer().write_all(b"never written\n").unwrap();
        // Closed, so the delete can remove it even where an open handle would
        // stop it.
        std::fs::remove_file(&path).unwrap();
        log.writer().write_all(b"never written either\n").unwrap();
        assert!(!path.exists(), "a log that is off came back");

        gate.set(true);
        log.writer().write_all(b"back on\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "back on\n");
    }

    /// Deleting while the log is on: the open file goes, and the next line
    /// starts a fresh one.
    #[test]
    fn deleting_while_on_closes_the_file_and_the_next_line_starts_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let path = logs.join(LOG_FILE_NAME);
        let gate = leaked_gate();
        gate.set(true);
        let log = RotatingLog::gated(&path, MAX_LOG_BYTES, gate);
        log.writer().write_all(b"history\n").unwrap();
        write(&logs, "birdo.log.1");

        let done = log.closed_for(|| delete_logs_in(Some(&logs), None));

        assert_eq!(
            done,
            Deleted {
                deleted: 2,
                failed: 0
            }
        );
        assert!(!path.exists());
        log.writer().write_all(b"after\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
    }

    #[test]
    fn the_held_lines_are_bounded() {
        let gate = leaked_gate();
        let line = vec![b'x'; 1024];
        for _ in 0..(HELD_CAP / line.len() + 10) {
            Held(gate).write_all(&line).unwrap();
        }
        assert!(gate.take_held().len() <= HELD_CAP);
    }

    /// The switch must stay wired: `setup()` decides the gate, and a crash
    /// file is written only when it is on. The call sites are in `main.rs`,
    /// the BIN target, which `cargo test --lib` never compiles (same technique
    /// as `log_retention::tests::the_retention_sweep_is_still_wired_into_main`).
    #[test]
    fn the_switch_is_still_wired_into_main() {
        let src = include_str!("../main.rs").replace('\r', "");
        assert!(
            src.contains("file_log::install("),
            "main() no longer builds birdo.log behind the user's switch"
        );
        assert!(
            src.contains("file_log::apply("),
            "setup() no longer applies the user's choice, so the log never opens"
        );
        let writer = &src[src.find("fn write_crash_report(").unwrap()..];
        let writer = &writer[..writer.find("\n}\n").unwrap()];
        let gate = writer
            .find("file_log::persists()")
            .expect("write_crash_report no longer checks the switch");
        assert!(
            gate < writer.find("create_dir_all").unwrap(),
            "write_crash_report touches the disk before checking the switch"
        );
    }
}
