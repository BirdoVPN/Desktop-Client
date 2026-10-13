//! Resume the VPN session an update ended (MR-1861).
//!
//! An update ends the running app. The in-app updater ends the session and
//! exits for the installer (`updater::install_update`, W1-004). A manual
//! installer stops the app itself: the template's `CheckIfAppIsRunning` (and
//! nsis-hooks.nsh's `BIRDO_STOP_APP_IF_RUNNING`, the same call) asks Restart
//! Manager to shut it down, which reaches the app as WM_ENDSESSION. Either way
//! the installer then starts the new version, and with Auto-Connect off — the
//! default — a user who was protected came back DISCONNECTED, kill switch and
//! all, until they reconnected by hand (device test 2026-10-07, 1.4.46 on
//! Windows, row 1b).
//!
//! So the session on record is written down as the app is ended for an
//! update, and the first start of the new version puts it back:
//!
//! - The in-app updater records it before it ends the session ([`record`]),
//!   on every platform; the macOS/Linux restart into the installed update
//!   finds that record.
//! - On WINDOWS ONLY, an exit that skips the teardown records the session
//!   still on record ([`record_if_exit_kept_the_session`], from `main.rs`):
//!   Restart Manager's WM_ENDSESSION, which tao turns straight into
//!   `RunEvent::Exit` with no `ExitRequested` (tao 0.37, event_loop.rs). Not
//!   while Windows itself is shutting down or signing out: that is no update.
//!   Not on macOS, where a plain Quit takes the same path (Cmd+Q, the Dock's
//!   Quit and logout reach `RunEvent::Exit` through applicationWillTerminate,
//!   with no `ExitRequested`): a user who quits has chosen to end the session.
//!   So a manual DMG or AppImage upgrade does not resume; only the in-app one
//!   does.
//! - Every other end of a session — Disconnect, Quit, sign-out, an expired
//!   sign-in — and an install that failed throw the record away ([`discard`],
//!   from `session::end_session` and `install_update`), and nothing is
//!   recorded again until a new session is on record ([`session_started`]):
//!   a WM_ENDSESSION landing while that teardown runs must not write back the
//!   session the user just ended. A user who chose to be disconnected is never
//!   connected again by it. A sign-in typed in by hand discards it too: the
//!   session belonged to whoever was signed in before.
//!
//! At start ([`load_at_start`]) the record is read and DELETED, whatever it
//! says: it is used once, and one that cannot be deleted, or is larger than
//! [`MAX_RECORD_BYTES`], is not used. It is kept for the UI only when a
//! DIFFERENT version wrote it — the app was updated in between; the version in
//! the record is the "last run" version — and it is at most [`MAX_AGE_SECS`]
//! old, so a record left by a crash, a shutdown or an install that never
//! finished cannot connect anyone later. "Different" is plain inequality: a
//! downgrade resumes too. The uninstaller stops a running app the same way
//! (PREUNINSTALL), so an uninstall while connected leaves a record as well:
//! "Delete the application data" removes it, a reinstall of the same version
//! or anything after the hour drops it, and a reinstall of another version
//! within the hour resumes the session, as an update would.
//!
//! The UI takes it once ([`take_update_resume`]) from the session controller,
//! which exists only signed in and past the consent screen: this never signs
//! anyone in, and never reaches the API before consent (D7). It connects with
//! the ordinary connect commands, so the session comes back with the saved
//! settings and the kill switch armed exactly as on any connect.
//!
//! The record names the server (for Multi-Hop, the entry and the exit), as
//! `preferred_server_id` in settings.json already does, and lives from one
//! update to the next start. It is not signed (an HMAC is a follow-up): what
//! can write the user's data dir can plant one, and all it can do is make the
//! signed-in app connect to a server the API accepts for that account.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::commands::session::ConnectTarget;
use crate::vpn::AutoReconnectService;

/// Beside the DNS journal and the logs, under `<data_dir>/BirdoVPN`, so the
/// uninstaller's "Delete the application data" removes it with them
/// (nsis-hooks.nsh, D-23).
const FILE_NAME: &str = "resume-after-update.json";

/// How old a record may be and still be acted on. An update takes minutes;
/// past an hour the user has been disconnected long enough to have noticed,
/// and a connect nobody asked for is the bigger surprise.
pub const MAX_AGE_SECS: i64 = 60 * 60;

/// A record is a few hundred bytes; anything larger is not ours and is
/// deleted unread.
pub const MAX_RECORD_BYTES: u64 = 4 * 1024;

/// This build's version, which a record's is compared with.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where the session was. `ResumeTarget` in `src/lib/ipc.ts` reads this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ResumeTarget {
    SingleHop { server_id: String },
    MultiHop { entry_id: String, exit_id: String },
}

impl ResumeTarget {
    pub(crate) fn of(target: &ConnectTarget) -> Self {
        match target {
            ConnectTarget::SingleHop { server_id } => Self::SingleHop {
                server_id: server_id.clone(),
            },
            ConnectTarget::MultiHop { entry_id, exit_id } => Self::MultiHop {
                entry_id: entry_id.clone(),
                exit_id: exit_id.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    /// The version that was running when the update began.
    version: String,
    /// When, in seconds since the epoch.
    written_at: i64,
    target: ResumeTarget,
}

impl Record {
    /// Whether a start of `version` at `now` may act on it: the app was
    /// updated since, and not long ago. A record from the future (the clock
    /// moved back) is not trusted either.
    fn resumable(&self, version: &str, now: i64) -> bool {
        self.version != version && (0..=MAX_AGE_SECS).contains(&now.saturating_sub(self.written_at))
    }
}

/// The record on disk and what the start found in it. A struct rather than
/// bare statics so the tests drive their own in a temp dir.
struct ResumeStore {
    /// `None`: no data dir, nothing is recorded.
    path: Option<PathBuf>,
    /// What the start found, until the UI takes it. Also what `record` and
    /// `discard` hold, so a discard cannot land between a record's check of
    /// `ended_by_choice` and its write.
    pending: Mutex<Option<Record>>,
    /// The last session ended for another reason than an update, and no new
    /// one is on record yet: nothing may be recorded.
    ended_by_choice: AtomicBool,
}

impl ResumeStore {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            pending: Mutex::new(None),
            ended_by_choice: AtomicBool::new(false),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Option<Record>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record(&self, target: ResumeTarget, version: &str, now: i64) {
        let Some(path) = &self.path else { return };
        let _held = self.pending();
        if self.ended_by_choice.load(Ordering::SeqCst) {
            tracing::info!("The VPN session was ended by choice — not recording it for an update");
            return;
        }
        let record = Record {
            version: version.to_string(),
            written_at: now,
            target,
        };
        match write_record(path, &record) {
            Ok(()) => tracing::info!("Recorded the VPN session for the update to resume"),
            Err(e) => tracing::warn!("Could not record the VPN session for the update: {e}"),
        }
    }

    fn load(&self, version: &str, now: i64) {
        let found = self.path.as_deref().and_then(read_once);
        let mut pending = self.pending();
        *pending = None;
        match found {
            Some(record) if record.resumable(version, now) => {
                tracing::info!("Started after an update that ended a VPN session — resuming it");
                *pending = Some(record);
            }
            Some(_) => tracing::info!(
                "Dropped a VPN session record that is not from an update, or is too old"
            ),
            None => {}
        }
    }

    fn take(&self, version: &str, now: i64) -> Option<ResumeTarget> {
        let record = self.pending().take()?;
        record.resumable(version, now).then_some(record.target)
    }

    fn discard(&self) {
        let mut pending = self.pending();
        self.ended_by_choice.store(true, Ordering::SeqCst);
        *pending = None;
        if let Some(path) = &self.path {
            if fs::remove_file(path).is_ok() {
                tracing::info!(
                    "The VPN session ended for another reason than an update — not resuming it"
                );
            }
        }
    }

    fn session_started(&self) {
        self.ended_by_choice.store(false, Ordering::SeqCst);
    }
}

/// Write via a sibling staging file and a rename, so a record is whole or
/// absent. Owner-only on multi-user Unix hosts, like the DNS journal beside it.
fn write_record(path: &Path, record: &Record) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let staging = path.with_extension("json.tmp");
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = opts
        .open(&staging)
        .and_then(|mut f| {
            f.write_all(&bytes)?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&staging, path));
    if written.is_err() {
        let _ = fs::remove_file(&staging);
    }
    written
}

/// Read the record and delete it. `None` when there is none, when it cannot be
/// deleted (it would be used again), when it is larger than
/// [`MAX_RECORD_BYTES`], or when it is unreadable.
fn read_once(path: &Path) -> Option<Record> {
    let mut bytes = Vec::new();
    // At most one byte past the cap is read, and the handle is closed before
    // the delete (Windows refuses to delete an open file).
    fs::File::open(path)
        .ok()?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    fs::remove_file(path).ok()?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn default_path() -> Option<PathBuf> {
    let mut path = dirs::data_dir()?;
    path.push("BirdoVPN");
    path.push(FILE_NAME);
    Some(path)
}

static STORE: LazyLock<ResumeStore> = LazyLock::new(|| ResumeStore::new(default_path()));

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The in-app updater, before it ends the session to install.
pub(crate) fn record(target: &ConnectTarget) {
    STORE.record(ResumeTarget::of(target), VERSION, now());
}

/// What an exit leaves to resume: the session on record, unless the exit ran
/// the teardown (the user quit) or Windows is ending the user's session.
fn kept_at_exit(
    teardown_started: bool,
    os_session_ending: bool,
    on_record: Option<ConnectTarget>,
) -> Option<ResumeTarget> {
    if teardown_started || os_session_ending {
        return None;
    }
    on_record.as_ref().map(ResumeTarget::of)
}

/// `main.rs`, at `RunEvent::Exit`. `teardown_started`: the exit came through
/// `ExitRequested` and its teardown, which ends (and discards) the session.
/// Synchronous and brief: tao exits the process as soon as this returns.
pub fn record_if_exit_kept_the_session(app: &AppHandle, teardown_started: bool) {
    // Windows only. On macOS a plain Quit — Cmd+Q, the Dock's Quit (Tauri's
    // default menu Quit is `terminate:`), logout — also reaches
    // `RunEvent::Exit` with no `ExitRequested` (tao's applicationWillTerminate),
    // and must never leave a session to resume. The in-app update records its
    // own before it ends the session (`install_update`).
    if !cfg!(target_os = "windows") {
        return;
    }
    let on_record = app
        .try_state::<AutoReconnectService>()
        .and_then(|ar| ar.current_info_now())
        .map(|info| ConnectTarget::of(&info));
    if let Some(target) = kept_at_exit(teardown_started, os_session_ending(), on_record) {
        STORE.record(target, VERSION, now());
    }
}

/// Windows is shutting down or signing the user out: a WM_ENDSESSION then
/// comes from that, not from an installer.
fn os_session_ending() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SHUTTINGDOWN};
        // SAFETY: GetSystemMetrics takes an index and reads system state; it
        // has no pointer arguments and no preconditions.
        unsafe { GetSystemMetrics(SM_SHUTTINGDOWN) != 0 }
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// `main.rs`, in `setup()`: read (and delete) the record, keep it for the UI if
/// it is from an update.
pub fn load_at_start() {
    STORE.load(VERSION, now());
}

/// Every end of a session but an update's (`session::end_session`), an
/// install that failed, and a sign-in typed in by hand (`auth`, `oauth`).
/// Nothing is recorded again until [`session_started`].
pub fn discard() {
    STORE.discard();
}

/// A new session is on record (`AutoReconnectService::store_last_config`):
/// an update may record it again.
pub fn session_started() {
    STORE.session_started();
}

/// The session the update ended, once: on the first start of the new version,
/// within [`MAX_AGE_SECS`] of the update. The session controller asks once the
/// settings and the server list are in (signed in, consent given), unless the
/// user has connected or disconnected first.
#[tauri::command]
pub fn take_update_resume() -> Option<ResumeTarget> {
    STORE.take(VERSION, now())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_791_000_000;

    fn single(id: &str) -> ResumeTarget {
        ResumeTarget::SingleHop {
            server_id: id.into(),
        }
    }

    fn store(dir: &tempfile::TempDir) -> ResumeStore {
        ResumeStore::new(Some(dir.path().join(FILE_NAME)))
    }

    /// MR-1861: connected when the update began, so the first start of the
    /// new version puts the session back — once.
    #[test]
    fn the_first_start_after_an_update_resumes_the_session_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        store(&dir).record(single("node-7"), "1.4.47", T);
        assert!(path.exists());

        let next = store(&dir);
        next.load("1.4.48", T + 90);
        assert!(!path.exists(), "the record is deleted when it is read");
        assert_eq!(next.take("1.4.48", T + 95), Some(single("node-7")));
        assert_eq!(next.take("1.4.48", T + 96), None, "taken once");

        // A second start finds nothing.
        let again = store(&dir);
        again.load("1.4.48", T + 120);
        assert_eq!(again.take("1.4.48", T + 121), None);
    }

    /// The same version starting again is no update: a crash, a shutdown, a
    /// reinstall of the same build. The record goes, unused.
    #[test]
    fn a_start_of_the_same_version_drops_the_record() {
        let dir = tempfile::tempdir().unwrap();
        store(&dir).record(single("node-7"), "1.4.47", T);
        let next = store(&dir);
        next.load("1.4.47", T + 10);
        assert!(!dir.path().join(FILE_NAME).exists());
        assert_eq!(next.take("1.4.47", T + 11), None);
    }

    /// A stale record never connects anyone: older than an hour at start, or
    /// by the time the UI asks, or written "in the future".
    #[test]
    fn a_record_older_than_an_hour_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        store(&dir).record(single("node-7"), "1.4.47", T);
        let late = store(&dir);
        late.load("1.4.48", T + MAX_AGE_SECS + 1);
        assert!(!dir.path().join(FILE_NAME).exists());
        assert_eq!(late.take("1.4.48", T + MAX_AGE_SECS + 2), None);

        store(&dir).record(single("node-7"), "1.4.47", T);
        let slow = store(&dir);
        slow.load("1.4.48", T + MAX_AGE_SECS - 5);
        assert_eq!(slow.take("1.4.48", T + MAX_AGE_SECS + 1), None);

        store(&dir).record(single("node-7"), "1.4.47", T + 600);
        let skewed = store(&dir);
        skewed.load("1.4.48", T);
        assert_eq!(skewed.take("1.4.48", T + 1), None);

        // At the limit it still counts.
        store(&dir).record(single("node-7"), "1.4.47", T);
        let edge = store(&dir);
        edge.load("1.4.48", T + MAX_AGE_SECS);
        assert_eq!(
            edge.take("1.4.48", T + MAX_AGE_SECS),
            Some(single("node-7"))
        );
    }

    /// Disconnect, Quit, sign-out and a failed install discard the record and
    /// anything the start already found.
    #[test]
    fn discard_forgets_the_record_and_the_pending_resume() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.record(single("node-7"), "1.4.47", T);
        s.discard();
        assert!(!dir.path().join(FILE_NAME).exists());
        let next = store(&dir);
        next.load("1.4.48", T + 5);
        assert_eq!(next.take("1.4.48", T + 6), None);

        store(&dir).record(single("node-7"), "1.4.47", T);
        let found = store(&dir);
        found.load("1.4.48", T + 5);
        found.discard();
        assert_eq!(found.take("1.4.48", T + 6), None);
    }

    /// Review of #276, L1: Disconnect discards first and clears the session on
    /// record later, after the teardown's lock. A WM_ENDSESSION (or an update)
    /// in between must not write back the session the user just ended; only
    /// a new session on record lifts that.
    #[test]
    fn nothing_is_recorded_after_a_discard_until_a_new_session_starts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let s = store(&dir);
        s.discard();
        s.record(single("node-7"), "1.4.47", T);
        assert!(!path.exists(), "recorded a session the user had ended");

        s.session_started();
        s.record(single("node-8"), "1.4.47", T + 60);
        assert!(path.exists());
        let next = store(&dir);
        next.load("1.4.48", T + 90);
        assert_eq!(next.take("1.4.48", T + 91), Some(single("node-8")));
    }

    /// Review of #276, L5: a record is a few hundred bytes. A larger file is
    /// deleted, never parsed.
    #[test]
    fn an_oversized_record_is_deleted_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let valid = serde_json::to_vec(&Record {
            version: "1.4.47".into(),
            written_at: T,
            target: single("node-7"),
        })
        .unwrap();
        // A valid record padded past the cap with JSON whitespace.
        let mut padded = valid.clone();
        padded.resize(MAX_RECORD_BYTES as usize + 1, b' ');
        fs::write(&path, &padded).unwrap();
        let s = store(&dir);
        s.load("1.4.48", T + 5);
        assert!(!path.exists());
        assert_eq!(s.take("1.4.48", T + 6), None);

        // At the cap it is still read.
        padded.truncate(MAX_RECORD_BYTES as usize);
        fs::write(&path, &padded).unwrap();
        let s = store(&dir);
        s.load("1.4.48", T + 5);
        assert_eq!(s.take("1.4.48", T + 6), Some(single("node-7")));
    }

    /// An unreadable record is deleted and ignored, never retried.
    #[test]
    fn an_unreadable_record_is_deleted_and_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        fs::write(&path, b"{\"version\":").unwrap();
        let s = store(&dir);
        s.load("1.4.48", T);
        assert!(!path.exists());
        assert_eq!(s.take("1.4.48", T), None);
    }

    /// A newer record replaces the older, and leaves no staging file.
    #[test]
    fn a_new_record_replaces_the_old_one_whole() {
        let dir = tempfile::tempdir().unwrap();
        store(&dir).record(single("node-1"), "1.4.47", T);
        let multi = ResumeTarget::MultiHop {
            entry_id: "entry-1".into(),
            exit_id: "exit-2".into(),
        };
        store(&dir).record(multi.clone(), "1.4.47", T + 30);
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec![FILE_NAME.to_string()]);
        let next = store(&dir);
        next.load("1.4.48", T + 40);
        assert_eq!(next.take("1.4.48", T + 41), Some(multi));
    }

    /// Only an exit that skipped the teardown, outside a Windows shutdown,
    /// with a session on record, leaves one to resume.
    #[test]
    fn only_an_exit_without_the_teardown_keeps_the_session() {
        let on_record = || {
            Some(ConnectTarget::MultiHop {
                entry_id: "entry-1".into(),
                exit_id: "exit-2".into(),
            })
        };
        assert_eq!(
            kept_at_exit(false, false, on_record()),
            Some(ResumeTarget::MultiHop {
                entry_id: "entry-1".into(),
                exit_id: "exit-2".into()
            })
        );
        assert_eq!(
            kept_at_exit(true, false, on_record()),
            None,
            "the user quit"
        );
        assert_eq!(
            kept_at_exit(false, true, on_record()),
            None,
            "Windows shutdown"
        );
        assert_eq!(kept_at_exit(false, false, None), None, "no session");
    }

    /// The wire shape `parseResumeTarget` (src/lib/ipc.ts) reads.
    #[test]
    fn the_target_serializes_as_the_ui_reads_it() {
        assert_eq!(
            serde_json::to_value(single("node-7")).unwrap(),
            serde_json::json!({ "kind": "singleHop", "serverId": "node-7" })
        );
        assert_eq!(
            serde_json::to_value(ResumeTarget::of(&ConnectTarget::MultiHop {
                entry_id: "entry-1".into(),
                exit_id: "exit-2".into(),
            }))
            .unwrap(),
            serde_json::json!({ "kind": "multiHop", "entryId": "entry-1", "exitId": "exit-2" })
        );
    }

    fn body<'a>(source: &'a str, start: &str) -> &'a str {
        let from = &source[source.find(start).unwrap_or_else(|| panic!("{start}"))..];
        &from[..from.find("\n}").expect("end of fn")]
    }

    /// The in-app updater records the session before it ends it for the
    /// install, and forgets it when the install fails (the app keeps running,
    /// still this version).
    #[test]
    fn the_in_app_updater_records_before_the_teardown_and_forgets_a_failed_install() {
        let install = body(include_str!("updater.rs"), "pub async fn install_update(");
        let record = install
            .find("update_resume::record(target)")
            .expect("record");
        let end = install
            .find("end_session(&app, EndReason::Update)")
            .expect("teardown");
        let failed = install
            .find("if let Err(e) = update.install(bundle)")
            .expect("install");
        let discard = install.find("update_resume::discard()").expect("discard");
        let recover = install
            .find("recover_from_failed_install(&app, resume")
            .expect("recover");
        assert!(record < end && end < failed && failed < discard && discard < recover);
    }

    /// Every end of a session except an update's discards the record.
    #[test]
    fn every_other_end_of_a_session_discards_the_record() {
        let end = body(include_str!("session.rs"), "pub async fn end_session(");
        let guard = end
            .find("if reason != EndReason::Update {")
            .expect("the Update exception");
        let discard = end
            .find("crate::commands::update_resume::discard()")
            .expect("discard");
        let teardown = end.find("spawn(tear_down(").expect("teardown");
        assert!(guard < discard && discard < teardown);
    }

    /// main.rs loads the record at start, records at an exit that skipped the
    /// teardown, and registers the UI's take.
    #[test]
    fn main_loads_records_and_registers_the_take() {
        let main = include_str!("../main.rs");
        let setup = &main[main.find(".setup(|app| {").expect("setup")..];
        assert!(setup.contains("commands::update_resume::load_at_start();"));
        let handler = body(main, "fn ipc_handler()");
        assert!(handler.contains("commands::update_resume::take_update_resume,"));
        let run = &main[main.find(".run(|app_handle, event| {").expect("run")..];
        let exit = run.find("RunEvent::Exit").expect("RunEvent::Exit");
        let recorded = run
            .find("commands::update_resume::record_if_exit_kept_the_session(")
            .expect("record at exit");
        let flag = run[recorded..]
            .find("EXIT_TEARDOWN_STARTED.load(")
            .expect("the teardown flag");
        let requested = run.find("RunEvent::ExitRequested").expect("ExitRequested");
        assert!(exit < recorded && recorded < requested && flag < 200);
    }

    /// Review of #276, M1: the exit path records on Windows only. On macOS a
    /// plain Quit (Cmd+Q, the Dock, logout) reaches `RunEvent::Exit` with no
    /// `ExitRequested` too, and must never leave a session to resume.
    #[test]
    fn only_windows_records_at_exit() {
        let source = include_str!("update_resume.rs");
        let exit = body(
            source,
            "pub fn record_if_exit_kept_the_session(app: &AppHandle, teardown_started: bool) {",
        );
        let guard = exit
            .find("if !cfg!(target_os = \"windows\") {")
            .expect("the Windows-only guard");
        assert_eq!(exit[guard..].lines().nth(1).map(str::trim), Some("return;"));
        let first_statement = exit
            .lines()
            .skip(1)
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("//"))
            .expect("a statement");
        assert_eq!(first_statement, "if !cfg!(target_os = \"windows\") {");
        let state = exit
            .find("try_state::<AutoReconnectService>()")
            .expect("state");
        assert!(guard < state);
    }

    /// Review of #276, L1/L4: a new session on record lifts the discard, and
    /// every sign-in typed in by hand discards a pending resume.
    #[test]
    fn a_new_session_lifts_the_discard_and_a_manual_sign_in_discards() {
        let ar = include_str!("../vpn/auto_reconnect.rs");
        let method = &ar[ar.find("pub async fn store_last_config(").expect("method")..];
        let method = &method[..method.find("\n    }").expect("end of method")];
        assert!(method.contains("crate::commands::update_resume::session_started();"));

        let auth = include_str!("auth.rs");
        for login in [
            "login",
            "verify_2fa",
            "register_anonymous",
            "login_anonymous",
        ] {
            let f = body(auth, &format!("pub async fn {login}("));
            assert!(
                f.contains("crate::commands::update_resume::discard();"),
                "{login} does not discard a pending resume"
            );
        }
        let sso = body(include_str!("oauth.rs"), "pub async fn native_oauth_login(");
        assert!(sso.contains("crate::commands::update_resume::discard();"));
    }
}
