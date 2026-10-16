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
//! update to the next start.
//!
//! MR-1933: it is SIGNED, with the settings key (`settings::existing_signing_keys`,
//! which on Windows lives where no unelevated process can read it, MR-1721),
//! and a record that does not verify is deleted unused. It sits in the user's
//! data folder, which any process of theirs can write, and it makes the
//! elevated app connect with no click: unsigned, a planted one could start a
//! session the user never asked for, to a server of the planter's choosing.
//! The MAC is over a label and the record (`MAC_LABEL`), so no other value the
//! key signs can pass for one. No key yet (a fresh install that never saved a
//! setting) means nothing is recorded: one is never minted here, which on
//! Windows would end the settings migration before it ran. A record written by
//! 1.4.47, the one build that wrote them unsigned, is dropped, so the update
//! FROM 1.4.47 does not resume.
//!
//! It is read and deleted through checked handles (`utils::safe_fs`, MR-1945):
//! the folder is the user's, and the app runs elevated.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tauri::{AppHandle, Manager};

use crate::commands::session::ConnectTarget;
use crate::utils::safe_fs::OwnedDir;
use crate::vpn::AutoReconnectService;

/// Beside the logs, under `<data_dir>/BirdoVPN`, so the uninstaller's "Delete
/// the application data" removes it with them (nsis-hooks.nsh, D-23).
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

/// What is on disk (MR-1933): the record and its HMAC-SHA256, hex.
#[derive(Debug, Serialize, Deserialize)]
struct SignedRecord {
    record: Record,
    hmac: String,
}

/// Prefixed to the record's JSON under the MAC, so nothing else the settings
/// key signs (settings.json itself) can pass for a record.
const MAC_LABEL: &[u8] = b"BirdoVPN update-resume record v1\n";

/// The keys a record may be signed and verified with: the settings key, as
/// `settings::existing_signing_keys` gives it (a test's own in the tests).
type Keys = Box<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>;

fn mac(record: &Record, key: &[u8]) -> Option<Hmac<Sha256>> {
    let json = serde_json::to_vec(record).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(MAC_LABEL);
    mac.update(&json);
    Some(mac)
}

/// `record`, signed with the first of `keys`; `None` without one.
fn sign(record: Record, keys: &[Vec<u8>]) -> Option<SignedRecord> {
    let hmac = hex::encode(mac(&record, keys.first()?)?.finalize().into_bytes());
    Some(SignedRecord { record, hmac })
}

/// Whether one of `keys` signed `signed` (constant-time comparison).
fn verifies(signed: &SignedRecord, keys: &[Vec<u8>]) -> bool {
    let Ok(expected) = hex::decode(&signed.hmac) else {
        return false;
    };
    keys.iter()
        .any(|key| mac(&signed.record, key).is_some_and(|mac| mac.verify_slice(&expected).is_ok()))
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
    /// The folder the record is in. `None`: no data dir, nothing is recorded.
    dir: Option<OwnedDir>,
    /// The keys it is signed and verified with (MR-1933).
    keys: Keys,
    /// MR-1933: the one-shot marker that an unsigned 1.4.47 record has already
    /// been accepted for this account. It lives where a user cannot delete it
    /// to re-arm the one-time acceptance (the admin-only directory on Windows).
    /// `None` disables the one-time acceptance.
    legacy_marker: Option<PathBuf>,
    /// What the start found, until the UI takes it. Also what `record` and
    /// `discard` hold, so a discard cannot land between a record's check of
    /// `ended_by_choice` and its write.
    pending: Mutex<Option<Record>>,
    /// The last session ended for another reason than an update, and no new
    /// one is on record yet: nothing may be recorded.
    ended_by_choice: AtomicBool,
}

impl ResumeStore {
    fn new(dir: Option<OwnedDir>, keys: Keys, legacy_marker: Option<PathBuf>) -> Self {
        Self {
            dir,
            keys,
            legacy_marker,
            pending: Mutex::new(None),
            ended_by_choice: AtomicBool::new(false),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Option<Record>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record(&self, target: ResumeTarget, version: &str, now: i64) {
        let Some(dir) = &self.dir else { return };
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
        let Some(signed) = sign(record, &(self.keys)()) else {
            tracing::warn!(
                "No settings key to sign the VPN session record with — not recording it for the update"
            );
            return;
        };
        match write_record(dir, &signed) {
            Ok(()) => tracing::info!("Recorded the VPN session for the update to resume"),
            Err(e) => tracing::warn!("Could not record the VPN session for the update: {e}"),
        }
    }

    fn load(&self, version: &str, now: i64) {
        let found = self.dir.as_ref().and_then(|dir| self.read_once(dir));
        // LOW 3 (#287 review): close the one-time unsigned-record window on the
        // FIRST start whether or not a 1.4.47 record was found (the genuine one
        // was already read just above). Otherwise the window would stay open
        // forever and an attacker could plant an unsigned record with a fresh
        // `written_at` at any later date and have it resumed.
        self.close_legacy_window();
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

    /// Mark the unsigned-record window closed if it is not already (LOW 3).
    fn close_legacy_window(&self) {
        let Some(marker) = self.legacy_marker.as_ref() else {
            return;
        };
        if marker_present(marker) {
            return;
        }
        match create_marker(marker) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => tracing::warn!("Could not close the unsigned-record window ({e})"),
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
        if let Some(dir) = &self.dir {
            if dir.remove_file(FILE_NAME).is_ok() {
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

/// Write via a uniquely-named staging file and a rename, so a record is whole
/// or absent. Owner-only on multi-user Unix hosts, like the logs beside it.
///
/// MR-1945 H1: the staging file is created new through a checked handle and
/// renamed within `dir`, never written to a predictable path a user could have
/// turned into a symlink; `dir` is held open for the process lifetime.
fn write_record(dir: &OwnedDir, record: &SignedRecord) -> std::io::Result<()> {
    // R5: created inside verified, held parents and held from then on.
    dir.ensure_held()?;
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let staging = format!("{FILE_NAME}.{:016x}.tmp", rand::random::<u64>());
    let written = dir
        .create_new(&staging)
        .and_then(|mut f| {
            f.write_all(&bytes)?;
            f.sync_all()
        })
        .and_then(|()| dir.rename_within(&staging, FILE_NAME));
    if written.is_err() {
        let _ = dir.remove_file(&staging);
    }
    written
}

/// Read the record and delete it. `None` when there is none, when it cannot be
/// deleted (it would be used again), when it is larger than
/// [`MAX_RECORD_BYTES`], when it is unreadable, or when none of `keys`
/// signed it (MR-1933).
impl ResumeStore {
    /// Read the record and delete it. `None` when there is none, when it
    /// cannot be deleted (it would be used again), when it is larger than
    /// [`MAX_RECORD_BYTES`], when it is unreadable, or when it is neither
    /// signed with the settings key nor the one accepted unsigned record
    /// (MR-1933).
    fn read_once(&self, dir: &OwnedDir) -> Option<Record> {
        let mut bytes = Vec::new();
        // At most one byte past the cap is read, and the handle is closed
        // before the delete. Both through checked handles (MR-1945): a
        // junction planted on the folder neither feeds this a file from
        // elsewhere nor has the delete remove one.
        dir.open_rw(FILE_NAME)
            .ok()?
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        dir.remove_file(FILE_NAME).ok()?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return None;
        }
        if let Ok(signed) = serde_json::from_slice::<SignedRecord>(&bytes) {
            if verifies(&signed, &(self.keys)()) {
                return Some(signed.record);
            }
            tracing::warn!("Dropped a VPN session record that is not signed with the settings key");
            return None;
        }
        // MR-1933: 1.4.47 wrote this record UNSIGNED. Accept it exactly once,
        // only if it names that version, so the update FROM 1.4.47 can resume —
        // every later version signs. The one-shot marker (in a place a user
        // cannot clear) closes the window after the first boot of the new
        // version, so a planted unsigned record cannot drive a connect twice.
        self.accept_unsigned_once(&bytes)
    }

    fn accept_unsigned_once(&self, bytes: &[u8]) -> Option<Record> {
        let marker = self.legacy_marker.as_ref()?;
        let record: Record = serde_json::from_slice(bytes).ok()?;
        if record.version != LEGACY_UNSIGNED_VERSION {
            return None;
        }
        if marker_present(marker) {
            tracing::warn!("An unsigned VPN session record was ignored (already accepted once)");
            return None;
        }
        // Close the window first, whatever happens next: this one-time
        // acceptance must not be re-armable even if the record is then too old
        // to resume.
        if let Err(e) = create_marker(marker) {
            // Could not record the one-shot (or one appeared meanwhile):
            // refuse rather than risk accepting it again on the next boot.
            tracing::warn!("Could not mark the 1.4.47 resume record consumed ({e}); ignoring it");
            return None;
        }
        tracing::info!("Accepted the unsigned 1.4.47 VPN session record once");
        Some(record)
    }
}

/// The one build that wrote the resume record unsigned (MR-1933).
const LEGACY_UNSIGNED_VERSION: &str = "1.4.47";

/// `<data_dir>/BirdoVPN`, where the record lives.
fn default_dir() -> Option<OwnedDir> {
    dirs::data_dir().map(|base| OwnedDir::new(base, &["BirdoVPN"]))
}

/// The one-shot marker for the 1.4.47 unsigned-record acceptance (MR-1933),
/// where a user cannot delete it: the admin-only directory on Windows (per
/// account), root's own state directory elsewhere.
///
/// MR-2089 (review of #327): that is `root_state::STATE_DIR` now. It was
/// `<data_dir>/BirdoVPN`, the USER's own folder whenever the launch kept HOME,
/// where they could delete it to re-open the window, and where root created
/// it by path through any link planted at its name ([`create_marker`]).
fn default_legacy_marker() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let dir = crate::utils::protected_dir::ensure().ok()?;
        let sid = crate::utils::protected_dir::current_user_sid().ok()?;
        windows_legacy_marker(
            &dir,
            &sid,
            crate::utils::protected_dir::legacy_upgrade_window(),
        )
    }
    #[cfg(not(windows))]
    {
        Some(
            std::path::Path::new(crate::utils::root_state::STATE_DIR)
                .join("resume-unsigned-consumed"),
        )
    }
}

/// Off Windows, where 1.4.48 kept the one-shot marker: `<data_dir>/BirdoVPN`.
/// Looked at only by [`carry_closed_window`], never opened or followed.
#[cfg(not(windows))]
fn marker_of_1_4_48() -> Option<PathBuf> {
    dirs::data_dir().map(|base| base.join("BirdoVPN").join("resume-unsigned-consumed"))
}

/// Keep the window 1.4.48 closed closed now that the marker lives in the
/// state directory: anything at `old` (that build's marker) has `marker` made
/// first, before the first start of this build can accept a planted unsigned
/// record there. It can only ever close the window: whoever can write `old`
/// can only stop a record from being accepted.
#[cfg(not(windows))]
fn carry_closed_window(old: Option<&std::path::Path>, marker: &std::path::Path) {
    if !old.is_some_and(marker_present) || marker_present(marker) {
        return;
    }
    match create_marker(marker) {
        Ok(()) => {
            tracing::info!("The unsigned-record window an earlier version closed stays closed")
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        // `accept_unsigned_once` refuses all the same when it cannot make the
        // marker either.
        Err(e) => tracing::warn!("Could not carry the closed unsigned-record window over ({e})"),
    }
}

/// Whether the one-shot marker is there. Anything at its name counts, a link
/// too: it is never followed (a dangling link answered `exists()` false).
fn marker_present(marker: &std::path::Path) -> bool {
    fs::symlink_metadata(marker).is_ok()
}

/// Create the one-shot marker: a new empty file, never through a link at its
/// name. `AlreadyExists` when anything is there already.
///
/// MR-2089 (review of #327): it was `fs::write` by path (O_CREAT|O_TRUNC,
/// following a link) after an `exists()` check that a dangling link passes,
/// so root created or emptied whatever file a link at the name pointed to:
/// `/etc/nologin`, say, which locks every other user out. Off Windows it is
/// now O_CREAT|O_EXCL|O_NOFOLLOW, owner-only, in a folder that must be ours
/// alone (`root_state::ensure_private_dir`, never `create_dir_all`).
fn create_marker(marker: &std::path::Path) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(parent) = marker.parent() {
            crate::utils::root_state::ensure_private_dir(parent)?;
        }
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    {
        if let Some(parent) = marker.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    opts.open(marker).map(drop)
}

/// R1 (Windows): the unsigned 1.4.47 record can only be the update FROM
/// 1.4.47, so its one-time acceptance exists only on the first start after the
/// installer upgraded a pre-MR-1721 install (`upgrade_window`). On a fresh
/// install there is no marker, so `accept_unsigned_once` accepts nothing: an
/// unsigned record planted there with a fresh `written_at` connects nobody.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_legacy_marker(
    admin_only: &std::path::Path,
    sid: &str,
    upgrade_window: bool,
) -> Option<PathBuf> {
    upgrade_window.then(|| admin_only.join(format!("resume-unsigned-consumed-{sid}")))
}

static STORE: LazyLock<ResumeStore> = LazyLock::new(|| {
    let marker = default_legacy_marker();
    #[cfg(not(windows))]
    if let Some(marker) = &marker {
        carry_closed_window(marker_of_1_4_48().as_deref(), marker);
    }
    ResumeStore::new(
        default_dir(),
        Box::new(crate::commands::settings::existing_signing_keys),
        marker,
    )
});

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

    /// The settings key, in these tests.
    /// A key minted per test run, as the app mints the real one.
    static KEY: LazyLock<[u8; 32]> = LazyLock::new(rand::random);
    /// Some other key.
    static OTHER: LazyLock<[u8; 32]> = LazyLock::new(rand::random);

    fn keyed(key: [u8; 32]) -> Keys {
        Box::new(move || vec![key.to_vec()])
    }

    fn store(dir: &tempfile::TempDir) -> ResumeStore {
        ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(dir.path().join("marker").join("consumed")),
        )
    }

    fn signed_bytes(record: Record, key: [u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&sign(record, &[key.to_vec()]).unwrap()).unwrap()
    }

    fn record_of(target: ResumeTarget) -> Record {
        record_ver(target, "1.4.47")
    }

    fn record_ver(target: ResumeTarget, version: &str) -> Record {
        Record {
            version: version.into(),
            written_at: T,
            target,
        }
    }

    fn unsigned_bytes(record: &Record) -> Vec<u8> {
        serde_json::to_vec(record).unwrap()
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
        let valid = signed_bytes(record_of(single("node-7")), *KEY);
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

    // ── MR-1933: signed with the settings key ─────────────────────────────

    /// THE FINDING. The record makes the elevated app connect with no click,
    /// and it sits in a folder any process of the user can write. One that
    /// is not signed with the settings key — an unsigned record of any version
    /// but 1.4.47, a forgery, another key's — is deleted and never resumed. On
    /// main each of these connected. (The one-time 1.4.47 exception is its own
    /// test.)
    #[test]
    fn a_record_not_signed_with_the_settings_key_is_dropped() {
        let unsigned = unsigned_bytes(&record_ver(single("node-7"), "1.4.46"));
        let other_key = signed_bytes(record_of(single("node-7")), *OTHER);
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&signed_bytes(record_of(single("node-7")), *KEY)).unwrap();
        tampered["record"]["target"]["serverId"] = "attacker-node".into();
        let tampered = serde_json::to_vec(&tampered).unwrap();
        let mut garbled: serde_json::Value =
            serde_json::from_slice(&signed_bytes(record_of(single("node-7")), *KEY)).unwrap();
        garbled["hmac"] = "zz".into();
        let garbled = serde_json::to_vec(&garbled).unwrap();

        for (what, bytes) in [
            ("unsigned (not 1.4.47)", unsigned),
            ("another key", other_key),
            ("a tampered target", tampered),
            ("a garbled MAC", garbled),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(FILE_NAME);
            fs::write(&path, &bytes).unwrap();
            let s = store(&dir);
            s.load("1.4.48", T + 5);
            assert!(!path.exists(), "{what}: not deleted");
            assert_eq!(s.take("1.4.48", T + 6), None, "{what}: resumed");
        }
    }

    /// MR-1933: 1.4.47 wrote the record unsigned, so the update FROM it must
    /// still resume. The unsigned record is accepted EXACTLY ONCE: a one-shot
    /// marker (which a user cannot reach) closes the window, so a second
    /// unsigned record — a plant — is dropped.
    #[test]
    fn an_unsigned_1447_record_is_accepted_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker").join("consumed");
        let s = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(marker.clone()),
        );
        fs::write(
            dir.path().join(FILE_NAME),
            unsigned_bytes(&record_of(single("node-7"))),
        )
        .unwrap();

        s.load("1.4.48", T + 5);
        assert_eq!(
            s.take("1.4.48", T + 6),
            Some(single("node-7")),
            "the upgrade resumes"
        );
        assert!(marker.exists(), "the one-shot window is closed");

        // A second unsigned 1.4.47 record (a plant) is ignored now.
        fs::write(
            dir.path().join(FILE_NAME),
            unsigned_bytes(&record_of(single("attacker-node"))),
        )
        .unwrap();
        let s2 = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(marker),
        );
        s2.load("1.4.48", T + 5);
        assert_eq!(
            s2.take("1.4.48", T + 6),
            None,
            "a second unsigned record is a plant"
        );
    }

    /// The one-time acceptance still obeys the version and age checks, and
    /// closes its window even when it does not resume (so it cannot be re-armed
    /// by an aged record).
    #[test]
    fn the_unsigned_acceptance_still_checks_version_and_age() {
        // An unsigned record of another version is never the one-time
        // exception: it is not resumed (its own dir, so the window-close of one
        // case does not mask the other).
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker").join("consumed");
        fs::write(
            dir.path().join(FILE_NAME),
            unsigned_bytes(&record_ver(single("node-7"), "1.4.40")),
        )
        .unwrap();
        let s = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(marker.clone()),
        );
        s.load("1.4.48", T + 5);
        assert_eq!(
            s.take("1.4.48", T + 6),
            None,
            "a non-1.4.47 record is not resumed"
        );

        // A 1.4.47 record older than the hour consumes the window but does not
        // resume.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker").join("consumed");
        fs::write(
            dir.path().join(FILE_NAME),
            unsigned_bytes(&record_of(single("node-7"))),
        )
        .unwrap();
        let s = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(marker.clone()),
        );
        s.load("1.4.48", T + MAX_AGE_SECS + 1);
        assert_eq!(
            s.take("1.4.48", T + MAX_AGE_SECS + 2),
            None,
            "too old to resume"
        );
        assert!(marker.exists(), "but the window is closed");
    }

    /// LOW 3 (#287 review): the one-time window is closed on the FIRST
    /// `load_at_start` even when no unsigned record is present, so an attacker
    /// cannot plant one with a fresh `written_at` later.
    #[test]
    fn the_unsigned_window_closes_on_the_first_load_even_with_no_record() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker").join("consumed");
        let s = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(marker.clone()),
        );
        // No record on disk at the first start.
        s.load("1.4.48", T + 5);
        assert!(marker.exists(), "the window is closed on first load");

        // A record planted afterwards, even a genuine-looking 1.4.47 one, is
        // not resumed.
        fs::write(
            dir.path().join(FILE_NAME),
            unsigned_bytes(&record_of(single("attacker-node"))),
        )
        .unwrap();
        let s2 = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*KEY),
            Some(marker),
        );
        s2.load("1.4.48", T + 6);
        assert_eq!(s2.take("1.4.48", T + 7), None, "the window stays closed");
    }

    /// R1: on Windows the one-time acceptance exists only on the first start
    /// after the installer upgraded a pre-MR-1721 install. On a fresh install
    /// (no upgrade marker) there is no window at all: an unsigned 1.4.47
    /// record planted there with a fresh `written_at` is dropped.
    #[test]
    fn a_fresh_install_accepts_no_unsigned_record() {
        let dir = tempfile::tempdir().unwrap();
        let admin = dir.path().join("admin-only");
        assert_eq!(
            windows_legacy_marker(&admin, "S-1-5-21-1", true),
            Some(admin.join("resume-unsigned-consumed-S-1-5-21-1"))
        );
        let marker = windows_legacy_marker(&admin, "S-1-5-21-1", false);
        assert_eq!(marker, None);

        fs::write(
            dir.path().join(FILE_NAME),
            unsigned_bytes(&record_of(single("attacker-node"))),
        )
        .unwrap();
        let s = ResumeStore::new(Some(OwnedDir::new(dir.path(), &[])), keyed(*KEY), marker);
        s.load("1.4.48", T + 5);
        assert_eq!(
            s.take("1.4.48", T + 6),
            None,
            "a fresh install resumed a plant"
        );
        assert!(!dir.path().join(FILE_NAME).exists(), "the plant is deleted");
    }

    /// What `record` writes is signed, verifies with the key, and with that
    /// key only.
    #[test]
    fn a_record_is_written_signed() {
        let dir = tempfile::tempdir().unwrap();
        store(&dir).record(single("node-7"), "1.4.47", T);
        let signed: SignedRecord =
            serde_json::from_slice(&fs::read(dir.path().join(FILE_NAME)).unwrap()).unwrap();
        assert_eq!(signed.record, record_of(single("node-7")));
        assert!(verifies(&signed, &[KEY.to_vec()]));
        assert!(!verifies(&signed, &[OTHER.to_vec()]));
        assert!(!verifies(&signed, &[]));

        // A start whose key changed since (a reset settings key) drops it.
        let rekeyed = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            keyed(*OTHER),
            Some(dir.path().join("marker").join("consumed")),
        );
        rekeyed.load("1.4.48", T + 5);
        assert_eq!(rekeyed.take("1.4.48", T + 6), None);
    }

    /// No settings key yet: nothing is recorded (and none is minted).
    #[test]
    fn without_a_key_nothing_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let s = ResumeStore::new(
            Some(OwnedDir::new(dir.path(), &[])),
            Box::new(Vec::new),
            Some(dir.path().join("marker").join("consumed")),
        );
        s.record(single("node-7"), "1.4.47", T);
        assert!(!dir.path().join(FILE_NAME).exists());
    }

    /// The MAC covers a label, so another value the settings key signs over
    /// the same bytes (settings.json's MAC is over the bare JSON) is not a
    /// record's.
    #[test]
    fn the_mac_is_bound_to_the_record_label() {
        let record = record_of(single("node-7"));
        let mut mac = Hmac::<Sha256>::new_from_slice(&*KEY).unwrap();
        mac.update(&serde_json::to_vec(&record).unwrap());
        let bare = hex::encode(mac.finalize().into_bytes());
        let signed = SignedRecord { record, hmac: bare };
        assert!(!verifies(&signed, &[KEY.to_vec()]));
    }

    /// The real store signs with the settings key and never mints one.
    #[test]
    fn the_store_signs_with_the_existing_settings_key() {
        let source = include_str!("update_resume.rs").replace('\r', "");
        let store = &source[source.find("static STORE: LazyLock<ResumeStore>").unwrap()..];
        let store = &store[..store.find("});").unwrap()];
        assert!(store.contains("crate::commands::settings::existing_signing_keys"));
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
        let installing = install.find("update.install(bundle)").expect("install");
        let failed = install
            .find("if let Err(e) = installed")
            .expect("a failed install");
        assert!(installing < failed);
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

/// MR-2089 (review of #327): off Windows the one-shot marker is root's own
/// (`root_state::STATE_DIR`) and is never created through a link at its
/// name. Unix only; tests.yml runs these unprivileged on Linux and macOS.
#[cfg(all(test, unix))]
mod root_write_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const T: i64 = 1_791_000_000;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A store in `dir` whose one-shot marker is `marker`.
    fn store(dir: &Path, marker: &Path) -> ResumeStore {
        ResumeStore::new(
            Some(OwnedDir::new(dir, &[])),
            Box::new(|| vec![vec![7; 32]]),
            Some(marker.to_path_buf()),
        )
    }

    /// An unsigned record of 1.4.47's, the one the window accepts once.
    fn plant_unsigned(dir: &Path) {
        let record = Record {
            version: LEGACY_UNSIGNED_VERSION.into(),
            written_at: T,
            target: ResumeTarget::SingleHop {
                server_id: "node-7".into(),
            },
        };
        fs::write(dir.join(FILE_NAME), serde_json::to_vec(&record).unwrap()).unwrap();
    }

    /// `<dir>/marker/consumed`, its folder ours alone.
    fn marker_in(dir: &Path) -> std::path::PathBuf {
        let folder = dir.join("marker");
        fs::create_dir(&folder).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
        folder.join("consumed")
    }

    #[test]
    fn the_marker_lives_in_the_root_only_state_directory() {
        assert_eq!(
            default_legacy_marker(),
            Some(Path::new(crate::utils::root_state::STATE_DIR).join("resume-unsigned-consumed"))
        );
    }

    /// The marker was `fs::write` by path after `exists()`, which a dangling
    /// link answers false: closing the window at every start created the file
    /// the link named, as root.
    #[test]
    fn closing_the_window_never_creates_a_file_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        let victim = dir.path().join("victim");
        std::os::unix::fs::symlink(&victim, &marker).unwrap();

        store(dir.path(), &marker).load("1.4.48", T + 5);

        assert!(
            fs::symlink_metadata(&victim).is_err(),
            "created through the link"
        );
        assert!(fs::symlink_metadata(&marker)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// The same link at the one-time acceptance: it was written through and
    /// the plant accepted. Anything at the marker's name is the window closed.
    #[test]
    fn a_link_on_the_marker_neither_is_written_through_nor_opens_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        let victim = dir.path().join("victim");
        std::os::unix::fs::symlink(&victim, &marker).unwrap();
        plant_unsigned(dir.path());

        let s = store(dir.path(), &marker);
        s.load("1.4.48", T + 5);

        assert!(
            fs::symlink_metadata(&victim).is_err(),
            "created through the link"
        );
        assert_eq!(s.take("1.4.48", T + 6), None, "the plant was resumed");
    }

    /// The marker is owner-only from creation, in a folder made owner-only.
    #[test]
    fn the_marker_is_owner_only_in_a_folder_of_ours_alone() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("state").join("consumed");

        store(dir.path(), &marker).load("1.4.48", T + 5);

        assert!(fs::symlink_metadata(&marker).unwrap().is_file());
        assert_eq!(mode(&marker), 0o600);
        assert_eq!(mode(marker.parent().unwrap()), 0o700);
    }

    /// A marker folder others can write is one they could empty: no marker is
    /// made there, and so nothing is accepted on the strength of one.
    #[test]
    fn a_marker_folder_others_can_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        fs::set_permissions(marker.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
        plant_unsigned(dir.path());

        let s = store(dir.path(), &marker);
        s.load("1.4.48", T + 5);

        assert!(fs::symlink_metadata(&marker).is_err());
        assert_eq!(s.take("1.4.48", T + 6), None);
    }

    /// 1.4.48 kept the marker in `<data_dir>/BirdoVPN`. A window it closed
    /// there stays closed now that the marker lives in the state directory:
    /// otherwise the first start of this build would accept a planted
    /// unsigned record once more. With nothing there, the one-time window is
    /// what it was.
    #[test]
    fn a_window_an_earlier_version_closed_stays_closed() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("consumed-by-1.4.48");
        fs::write(&old, b"").unwrap();
        let marker = marker_in(dir.path());
        plant_unsigned(dir.path());

        carry_closed_window(Some(&old), &marker);

        assert!(marker_present(&marker));
        let s = store(dir.path(), &marker);
        s.load("1.4.48", T + 5);
        assert_eq!(s.take("1.4.48", T + 6), None, "the window re-opened");

        // Control: nothing at the old name, so nothing is made, and the
        // record is accepted once.
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        plant_unsigned(dir.path());
        carry_closed_window(Some(&dir.path().join("absent")), &marker);
        carry_closed_window(None, &marker);
        assert!(!marker_present(&marker));
        let s = store(dir.path(), &marker);
        s.load("1.4.48", T + 5);
        assert!(s.take("1.4.48", T + 6).is_some(), "the one-time window");
        assert!(marker_present(&marker));
    }
}
