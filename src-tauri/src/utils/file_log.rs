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
//! the log is on, or dropped when it is off.
//!
//! THE SAVED CHOICE, BEFORE IT CAN BE VERIFIED. Right after the subscriber is
//! installed, `main()` reads `settings.json` WITHOUT its signature check
//! ([`read_saved_choice`]). That is safe only in the direction it acts on: a
//! saved "off" switches the log off at once (an unverified "off" can only mean
//! less is written), while "on" (or no file yet, the default) is only
//! remembered. A run that ends before `setup()` decides uses it
//! ([`decide_from_saved_choice`]): the uninstaller's `--reconcile-and-exit`,
//! whose two lines are how the install smoke test and support see that the
//! pre-uninstall reconcile ran, and a panic during start-up (WebView2 that
//! will not start, a plugin that fails), whose held lines and crash file would
//! otherwise be lost. Unreadable or unparseable, the file says nothing, and
//! such a run persists nothing. `setup()` still makes the verified decision.
//!
//! NOT A LOG: the DNS journal (`vpn::dns_journal`, `dns-restore.json`: in the
//! admin-only `%ProgramData%\BirdoVPN` on Windows since MR-1721, in the
//! directory above `logs` elsewhere). It is the record of the resolvers to put
//! back, the machine's only way to undo a DNS change a crash left behind, so
//! neither the switch nor the delete touches it. Neither touches
//! `settings.json`, the device id, the PQ key or the Xray config.
//!
//! THE DELETES RUN ELEVATED in folders the user can write (MR-1945), so every
//! one goes through [`OwnedDir`]: by a checked handle, never by a path.

use std::io::{self, Write};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use super::log_retention::{is_crash_report_name, RotatingLog, MAX_LOG_BYTES};
use super::safe_fs::OwnedDir;

/// The live log's file name. Its rotated generation is
/// `log_retention::rotated_path` of it (`birdo.log.1`).
pub const LOG_FILE_NAME: &str = "birdo.log";

/// Where `birdo.log` lives: `<data dir>/BirdoVPN/logs`. The single definition:
/// `main()` writes and prunes there, and [`delete_logs`] deletes there.
pub fn log_dir() -> Option<OwnedDir> {
    dirs::data_dir().map(|base| OwnedDir::new(base, &["BirdoVPN", "logs"]))
}

/// Where crash reports go, under `base` (the local data directory). The
/// single definition, shared by `main.rs`'s writer and [`crash_dir`].
pub fn crash_dir_in(base: PathBuf) -> OwnedDir {
    OwnedDir::new(base, &["Birdo VPN", "crashes"])
}

/// Where crash reports go: `<local data dir>/Birdo VPN/crashes`. `None` when
/// the OS has no such directory: [`delete_logs`] then deletes nothing there
/// rather than guess (the writer's fallback is the working directory, which is
/// nobody's to clear).
pub fn crash_dir() -> Option<OwnedDir> {
    dirs::data_local_dir().map(crash_dir_in)
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
pub fn install(dir: OwnedDir, name: &str) -> &'static RotatingLog {
    FILE_LOG.get_or_init(|| RotatingLog::gated(dir, name, MAX_LOG_BYTES, &FILE_LOGGING))
}

/// Hold the app's user-writable state directories open for the process
/// lifetime (MR-1945 H1): the config directory (`settings.json` and its
/// atomic writes), the logs directory and the crash directory. While a handle
/// is held, an unprivileged process cannot rename the directory or replace it
/// with a junction, so the elevated client's by-path create/append/rename
/// operations in those directories cannot be redirected. Each directory's
/// whole chain is verified (no reparse point, expected final path) at hold
/// time; one that cannot be verified is left unheld and simply operates as
/// before. Best-effort: never worth failing startup over, and a no-op where
/// there is no data directory. The guards are leaked on purpose — they live
/// as long as the process.
pub fn hold_app_dirs() {
    let mut dirs: Vec<OwnedDir> = Vec::new();
    if let Some(config) = dirs::config_dir() {
        dirs.push(OwnedDir::new(config, &[APP_IDENTIFIER]));
    }
    if let Some(dir) = log_dir() {
        dirs.push(dir);
    }
    if let Some(dir) = crash_dir() {
        dirs.push(dir);
    }
    for dir in dirs {
        match dir.hold_open() {
            Ok(guard) => HELD.lock().unwrap_or_else(|e| e.into_inner()).push(guard),
            Err(e) => tracing::warn!(
                "Could not hold a state directory open against a junction swap: {}",
                e
            ),
        }
    }
}

/// The held directory guards, for the process lifetime.
static HELD: Mutex<Vec<crate::utils::safe_fs::DirGuard>> = Mutex::new(Vec::new());

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
/// reports included). False until the user's choice is known.
pub fn persists() -> bool {
    FILE_LOGGING.is_on()
}

/// Tauri's identifier for this app (`tauri.conf.json`): the directory under
/// the OS config directory that holds `settings.json`. Pinned against
/// tauri.conf.json by a test.
const APP_IDENTIFIER: &str = "uk.birdo.vpn.desktop";

/// `settings.json` where `commands::settings::get_settings_path` finds it:
/// Tauri's `app_config_dir()`, which is `dirs::config_dir()/<identifier>`
/// (tauri 2, `path/desktop.rs`) because this app sets no
/// `appDirectoriesOverride`. Both are pinned by a test.
pub(crate) fn settings_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join(APP_IDENTIFIER).join("settings.json"))
}

/// What `settings.json` says about the log, read without verifying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedChoice {
    /// The file says on, does not have the key (the default), or does not
    /// exist yet (a first run: the default).
    On,
    /// The file says off.
    Off,
    /// Not read yet, unreadable, or not settings this build can read.
    Unknown,
}

/// What [`read_saved_choice`] found, as a `SavedChoice` discriminant.
static SAVED: AtomicU8 = AtomicU8::new(SavedChoice::Unknown as u8);

/// The log switch in `settings.json`'s text. Signed files keep the settings
/// under `settings`; an unsigned file from before signing has them at the top.
pub fn saved_choice(read: io::Result<String>) -> SavedChoice {
    use serde_json::Value;
    let text = match read {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return SavedChoice::On,
        Err(_) => return SavedChoice::Unknown,
    };
    let Ok(Value::Object(file)) = serde_json::from_str::<Value>(&text) else {
        return SavedChoice::Unknown;
    };
    let settings = match file.get("settings") {
        Some(Value::Object(signed)) => signed,
        Some(_) => return SavedChoice::Unknown,
        None => &file,
    };
    match settings.get("file_logging_enabled") {
        None | Some(Value::Bool(true)) => SavedChoice::On,
        Some(Value::Bool(false)) => SavedChoice::Off,
        Some(_) => SavedChoice::Unknown,
    }
}

/// Read the saved choice before Tauri exists (see the module docs). Called by
/// `main()` right after the subscriber is installed. A saved "off" switches
/// the log off now; anything else leaves it undecided for `setup()`. Nothing
/// from the file is logged.
pub fn read_saved_choice() {
    let choice = settings_path().map_or(SavedChoice::Unknown, |path| {
        saved_choice(std::fs::read_to_string(path))
    });
    SAVED.store(choice as u8, Ordering::SeqCst);
    if choice == SavedChoice::Off {
        apply(false);
    }
}

/// What [`read_saved_choice`] found (`Unknown` before it ran).
pub fn saved() -> SavedChoice {
    match SAVED.load(Ordering::SeqCst) {
        x if x == SavedChoice::On as u8 => SavedChoice::On,
        x if x == SavedChoice::Off as u8 => SavedChoice::Off,
        _ => SavedChoice::Unknown,
    }
}

/// For a run that may end before `setup()` decides: the uninstaller's
/// `--reconcile-and-exit`, and the panic hook. If the log is still undecided
/// and the saved choice is on, turn it on now, so the held lines are written
/// and a crash file may be. Returns whether it did.
pub fn decide_from_saved_choice() -> bool {
    if FILE_LOGGING.is_undecided() && saved() == SavedChoice::On {
        apply(true);
        return true;
    }
    false
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
    let run = || delete_logs_in(log_dir().as_ref(), crash_dir().as_ref());
    match FILE_LOG.get() {
        Some(log) => log.closed_for(run),
        None => run(),
    }
}

/// [`delete_logs`] over given directories. Only names this app writes are
/// deleted: `birdo.log*` from `log_dir`, `crash_*.txt` from `crash_dir`.
pub fn delete_logs_in(log_dir: Option<&OwnedDir>, crash_dir: Option<&OwnedDir>) -> Deleted {
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
/// directories, and each candidate is a name read from it. Never recursive,
/// and never through a link: a `dir` that is a symlink or a junction is
/// refused outright (`symlink_metadata` does not follow it, and a junction is
/// a link there too), and an entry that is a link or a directory is skipped,
/// whatever its name: it is not a file this app wrote, so it is not this app's
/// to remove.
///
/// Those checks are a first pass over a listing, and a listing is only a
/// snapshot of a folder the user can change between the check and the delete
/// (MR-1945): the junction may be planted after, or above, `logs`. So the
/// delete itself is [`OwnedDir::remove_file`], which opens the file without
/// following a link, checks where its handle really is, and deletes through
/// that handle. A file that fails that is counted `failed`, never deleted.
fn delete_in(dir: &OwnedDir, ours: fn(&str) -> bool, tally: &mut Deleted) {
    let path = dir.path();
    match std::fs::symlink_metadata(path) {
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
    let Ok(entries) = std::fs::read_dir(path) else {
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
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(meta) if meta.file_type().is_file() => {}
            _ => continue,
        }
        match dir.remove_file(name) {
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

    /// The folder at `dir`, standing in for one of the app's: its parent as
    /// the root, its own name as the app's folder.
    fn under(dir: &Path) -> OwnedDir {
        let name = dir.file_name().unwrap().to_str().unwrap();
        OwnedDir::new(dir.parent().unwrap(), &[name])
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

        let done = delete_logs_in(Some(&under(&logs)), Some(&under(&crashes)));

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
            delete_logs_in(Some(&under(&empty)), Some(&under(&absent))),
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

        assert_eq!(
            delete_logs_in(Some(&under(&logs)), None),
            Deleted::default()
        );
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

        let done = delete_logs_in(Some(&under(&logs)), None);

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

        let done = delete_logs_in(Some(&under(&logs)), None);

        assert_eq!(
            done,
            Deleted {
                deleted: 0,
                failed: 1
            }
        );
        assert!(victim.exists());
    }

    /// The same on Windows. A symlink there needs a privilege (or Developer
    /// Mode): a dev account without it skips, saying so; CI (an administrator)
    /// must not skip, or the test would pass there without testing anything.
    #[cfg(windows)]
    #[test]
    fn a_symlinked_log_is_skipped_and_its_target_survives() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let target = write(root.path(), "precious.txt");
        if let Err(e) = std::os::windows::fs::symlink_file(&target, logs.join("birdo.log")) {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI cannot create a symlink ({e}), so this test would test nothing"
            );
            eprintln!("SKIPPED: this account cannot create symlinks ({e})");
            return;
        }
        write(&logs, "birdo.log.1");

        let done = delete_logs_in(Some(&under(&logs)), None);

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

    /// A JUNCTION where the log directory should be is refused outright. A
    /// junction needs no privilege, so any process running as the user can
    /// plant one in %APPDATA%, and the app that follows it runs elevated.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_log_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let victim = write(&elsewhere, "birdo.log");
        let logs = root.path().join("logs");
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&logs)
            .arg(&elsewhere)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed: {made:?}");
        assert!(
            std::fs::symlink_metadata(&logs)
                .unwrap()
                .file_type()
                .is_symlink(),
            "std must see a junction as a link, or the refusal below is luck"
        );

        let done = delete_logs_in(Some(&under(&logs)), None);

        assert_eq!(
            done,
            Deleted {
                deleted: 0,
                failed: 1
            }
        );
        assert!(victim.exists(), "the delete followed the junction");
    }

    /// MR-1945: a junction one level ABOVE `logs` (on `BirdoVPN`) makes
    /// `logs` a real directory somewhere else, so the directory check passes
    /// and the old delete removed whatever `birdo.log*` it found there. The
    /// delete goes through a checked handle now: nothing behind the junction
    /// is removed, and each refusal is counted.
    #[cfg(windows)]
    #[test]
    fn a_junction_above_the_log_directory_deletes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("logs")).unwrap();
        let victims = [
            write(&elsewhere.join("logs"), "birdo.log"),
            write(&elsewhere.join("logs"), "birdo.log.1"),
        ];
        crate::utils::safe_fs::tests::junction(&root.path().join("BirdoVPN"), &elsewhere);

        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        let done = delete_logs_in(Some(&logs), None);

        assert_eq!(
            done,
            Deleted {
                deleted: 0,
                failed: 2
            }
        );
        for victim in victims {
            assert!(victim.exists(), "the delete followed the junction");
        }
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

    /// A gated log at `path`, for tests that still address it by path.
    fn gated_log(path: &Path, cap: u64, gate: &'static LogGate) -> RotatingLog {
        let name = path.file_name().unwrap().to_str().unwrap();
        RotatingLog::gated(OwnedDir::new(path.parent().unwrap(), &[]), name, cap, gate)
    }

    /// THE FINDING (MR-808): with the log off, launching must neither create
    /// nor append to it — not even with the lines logged before `setup()`
    /// read the choice.
    #[test]
    fn an_undecided_log_opens_nothing_and_off_drops_what_it_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join(LOG_FILE_NAME);
        let gate = leaked_gate();
        let log = gated_log(&path, MAX_LOG_BYTES, gate);

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
        let log = gated_log(&path, MAX_LOG_BYTES, gate);

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
        let log = gated_log(&path, MAX_LOG_BYTES, gate);
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
        let log = gated_log(&path, MAX_LOG_BYTES, gate);
        log.writer().write_all(b"history\n").unwrap();
        write(&logs, "birdo.log.1");

        let done = log.closed_for(|| delete_logs_in(Some(&under(&logs)), None));

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

    // ── the saved choice, before it can be verified ───────────────────────

    fn choice(text: &str) -> SavedChoice {
        saved_choice(Ok(text.to_string()))
    }

    #[test]
    fn a_saved_off_reads_off_and_everything_else_on_or_unknown() {
        // The signed shape `save_settings` writes, and the unsigned legacy one.
        assert_eq!(
            choice(r#"{"settings":{"autostart":false,"file_logging_enabled":false},"hmac":"ab"}"#),
            SavedChoice::Off
        );
        assert_eq!(
            choice(r#"{"autostart":false,"file_logging_enabled":false}"#),
            SavedChoice::Off
        );
        // ON is never written (skip_serializing_if): no key is the default.
        assert_eq!(
            choice(r#"{"settings":{"autostart":false},"hmac":"ab"}"#),
            SavedChoice::On
        );
        assert_eq!(
            choice(r#"{"settings":{"file_logging_enabled":true},"hmac":"ab"}"#),
            SavedChoice::On
        );
        // A first run has no file: the default.
        let missing = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(saved_choice(Err(missing)), SavedChoice::On);
        // Anything this cannot read says nothing.
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(saved_choice(Err(denied)), SavedChoice::Unknown);
        for unreadable in [
            "",
            "not json",
            "[]",
            "3",
            r#"{"settings":"x","hmac":"ab"}"#,
            r#"{"settings":{"file_logging_enabled":"no"},"hmac":"ab"}"#,
        ] {
            assert_eq!(choice(unreadable), SavedChoice::Unknown, "{unreadable}");
        }
    }

    /// The early read must look where `get_settings_path` does: Tauri's
    /// `app_config_dir()`, which is `<config dir>/<identifier>` unless
    /// tauri.conf.json overrides the app directories.
    #[test]
    fn the_early_read_looks_where_the_settings_really_are() {
        let conf =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json"))
                .unwrap();
        let conf: serde_json::Value = serde_json::from_str(&conf).unwrap();
        assert_eq!(conf["identifier"], APP_IDENTIFIER);
        assert!(
            conf["app"].get("appDirectoriesOverride").is_none(),
            "tauri.conf.json now overrides the app directories: settings_path() must follow"
        );
        let settings = include_str!("../commands/settings.rs").replace('\r', "");
        let get = &settings[settings.find("fn get_settings_path(").unwrap()..];
        let get = &get[..get.find("\n}\n").unwrap()];
        assert!(get.contains(".app_config_dir()") && get.contains("\"settings.json\""));
        if let Some(path) = settings_path() {
            assert!(path.ends_with(Path::new(APP_IDENTIFIER).join("settings.json")));
        }
    }

    /// The switch must stay wired: `setup()` decides the gate, and a crash
    /// file is written only when it is on. The call sites are in `main.rs`,
    /// the BIN target, which `cargo test --lib` never compiles (same technique
    /// as `log_retention::tests::the_retention_sweep_is_still_wired_into_main`).
    #[test]
    fn the_switch_is_still_wired_into_main() {
        let src = include_str!("../main.rs").replace('\r', "");
        let body = |signature: &str| {
            let start = src.find(signature).expect(signature);
            let rest = &src[start..];
            rest[..rest.find("\n}\n").expect("end of fn")].to_string()
        };
        assert!(
            src.contains("file_log::install("),
            "main() no longer builds birdo.log behind the user's switch"
        );
        assert!(
            src.contains("file_log::apply("),
            "setup() no longer applies the user's choice, so the log never opens"
        );
        let writer = body("fn write_crash_report(");
        let gate = writer
            .find("file_log::persists()")
            .expect("write_crash_report no longer checks the switch");
        assert!(
            gate < writer.find("create_dir_all").unwrap(),
            "write_crash_report touches the disk before checking the switch"
        );

        // The saved choice is read as soon as the subscriber exists...
        let main_fn = body("fn main() {");
        let read = main_fn
            .find("file_log::read_saved_choice()")
            .expect("main() no longer reads the saved choice early");
        assert!(main_fn.find(".init();").unwrap() < read);
        // ...and the runs that may end before setup() decide from it: the
        // uninstaller's reconcile (whose lines the NSIS smoke test reads from
        // birdo.log), and a panic, before its PANIC line.
        let reconcile = body("fn reconcile_and_exit(");
        let decided = reconcile
            .find("file_log::decide_from_saved_choice()")
            .expect("--reconcile-and-exit no longer decides the log, so it persists nothing");
        assert!(decided < reconcile.find("info!(").unwrap());
        let hook = body("fn setup_panic_hook(");
        let decided = hook
            .find("file_log::decide_from_saved_choice()")
            .expect("a start-up panic no longer decides the log, so it leaves nothing");
        assert!(decided < hook.find(r#"error!("PANIC"#).unwrap());
    }
}
