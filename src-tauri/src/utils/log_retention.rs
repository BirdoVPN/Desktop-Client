//! Lifecycle of the on-disk log: how big it may get, and **how far back it may
//! reach**.
//!
//! WHY THIS MODULE EXISTS (LOG-002). Every other control on `birdo.log` is
//! *forward-only*. `utils::log_policy` clamps the level the file layer will
//! accept from now on; the `redact_*` call sites rewrite values from now on;
//! `rotate_if_large` only reacts once the file has already grown past
//! [`MAX_LOG_BYTES`], and even then it *renames* the old content to
//! `birdo.log.1` rather than dropping it. Nothing has ever looked at what is
//! ALREADY in the file.
//!
//! The consequence, measured on a real install: a log opened in append mode in
//! June still held every line written since — 2.5 months of connection history
//! (exit-node endpoints, tunnel client IPs, WireGuard source ports, the chosen
//! server names, the configured resolvers), in a 1.3 MB file that will not
//! reach the 10 MiB rotation threshold for years. Upgrading to a redacting
//! build changed nothing about it: the redaction work applies to lines written
//! after the upgrade. `log_policy`'s own doc comment calls this file "the
//! artefact a user later emails to support" — so the first support request
//! after the fix would still have handed over the whole pre-fix period, on a
//! product whose policy states that connection logs are not kept. Endpoint
//! backup, file-sync and DLP agents collect the same file without being asked.
//!
//! THE FIX IS A RETENTION WINDOW, not a one-off migration. A one-off "delete
//! the log when upgrading past version X" would clear today's backlog and then
//! leave the next multi-year accumulation to happen again, silently, for
//! anyone whose lines are all post-fix. A window is self-maintaining: on every
//! launch the log is cut back to [`MAX_LOG_AGE_DAYS`] days, so the file can
//! only ever describe recent activity, whatever build wrote it.
//!
//! WHY THE WINDOW IS SHORT, and please do not quietly widen it. The file exists
//! so that a failure a user is actively troubleshooting (the raw `/vpn/connect`
//! error, a tunnel that will not come up) is recoverable from disk on a release
//! GUI build with no console. That loop is measured in days: the user hits the
//! problem, reproduces it, and sends the log. It is NOT an archive, and every
//! extra day it spans is another day of connection history sitting on the disk
//! and inside every backup of it. A user who genuinely needs a longer record
//! can copy the file aside; the default must not decide that for them.

use chrono::{DateTime, Duration, Utc};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::file_log::{Held, LogGate};
use super::safe_fs::OwnedDir;

/// How far back `birdo.log` may reach. See the module docs before changing it.
pub const MAX_LOG_AGE_DAYS: i64 = 7;

/// PWR-5: cap for `birdo.log` before it gets rotated aside.
///
/// Lives here rather than in `main.rs` so the size cap and the age cap — the
/// two halves of one retention policy — cannot drift apart, and so the
/// rotated-file NAME has exactly one definition (`rotated_path`): the sweep
/// below has to prune the same `birdo.log.1` that rotation writes.
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// The oldest record `now` allows the log to keep.
pub fn cutoff(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::days(MAX_LOG_AGE_DAYS)
}

/// What a scan of a log file concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// The first record is already inside the window — leave the file alone.
    KeepAll,
    /// The record at this byte offset is the first one inside the window;
    /// everything before it is expired.
    DropFirst(u64),
    /// Every dated record is older than the window — the file becomes empty.
    DropAll,
    /// Not one line carried a parseable timestamp, so the content cannot be
    /// dated from the inside. The caller falls back to the file's mtime.
    Undated,
}

/// The one rotated generation `rotate_if_large` produces for `path`.
///
/// SINGLE DEFINITION ON PURPOSE. Rotation used to build this name inline; if
/// the sweep built its own copy, renaming the rotation target would leave a
/// forever-file behind that still matched nothing here — the exact
/// guard-on-some-of-N-paths shape that keeps biting this crate.
pub fn rotated_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.1",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("birdo.log")
    ))
}

/// Parse the leading RFC3339 timestamp of a log line, if it has one.
///
/// `tracing_subscriber`'s default fmt timer writes it as the first
/// whitespace-delimited token: `2026-06-05T20:55:36.097915Z DEBUG birdo_…`.
/// Anything else — a wrapped backtrace, a blank line, a panic payload spanning
/// several lines — returns `None` and is treated as a continuation of the
/// record above it, which is what keeps a dropped record's backtrace from
/// surviving the record itself.
fn line_timestamp(line: &[u8]) -> Option<DateTime<Utc>> {
    let token = line.split(|b| b.is_ascii_whitespace()).next()?;
    // "2026-06-05T20:55:36Z" is the shortest legal form (20 bytes) and a
    // fractional-seconds + offset form the longest we could see. The bound is
    // a cheap guard so a pathological line never reaches the date parser.
    if token.len() < 20 || token.len() > 40 {
        return None;
    }
    let token = std::str::from_utf8(token).ok()?;
    DateTime::parse_from_rfc3339(token)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Find where the retained part of a log starts.
///
/// Pure and streaming: it holds one line at a time, so a 20 MiB log costs a
/// sequential read and no meaningful memory.
pub fn scan<R: BufRead>(reader: &mut R, cutoff: DateTime<Utc>) -> io::Result<Retention> {
    let mut offset: u64 = 0;
    let mut saw_dated_line = false;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if let Some(ts) = line_timestamp(&line) {
            saw_dated_line = true;
            if ts >= cutoff {
                return Ok(if offset == 0 {
                    Retention::KeepAll
                } else {
                    Retention::DropFirst(offset)
                });
            }
        }
        offset += read as u64;
    }
    Ok(if saw_dated_line {
        Retention::DropAll
    } else {
        Retention::Undated
    })
}

/// Should a file that scanned as [`Retention::Undated`] be emptied, given its
/// mtime?
///
/// A file whose lines carry no timestamps cannot be dated from the inside. Its
/// mtime is the only evidence available, and it is an UPPER bound on the age of
/// every line in it: if the last write is already outside the window, so is all
/// of the content. If the mtime is recent we keep the file — some of it may be
/// old, but destroying an unrecognised file's content on a guess costs a user
/// their diagnostics for no proven privacy gain. An unknown mtime is treated
/// the same as a recent one.
pub fn undated_should_truncate(modified: Option<DateTime<Utc>>, cutoff: DateTime<Utc>) -> bool {
    matches!(modified, Some(m) if m < cutoff)
}

/// Copy `file[from..]` to `file[0..]` and truncate, in place.
///
/// IN PLACE, DELIBERATELY, rather than write-a-temp-and-rename: the log is
/// created 0600 on Unix (`main.rs`, P6-CLI-D-08) and a fresh temp file would be
/// created under the process umask instead, silently widening the permissions
/// of the very file this module exists to protect. Editing the original also
/// keeps the inode, so nothing that already has the path open is left writing
/// to an orphan.
///
/// The copy is safe against self-overlap: chunk *k* is fully read into memory
/// before it is written, and the region written for chunk *k* always ends below
/// where chunk *k+1* starts reading, so no chunk can ever read bytes an earlier
/// chunk overwrote.
fn shift_head_off(file: &mut std::fs::File, from: u64) -> io::Result<()> {
    if from == 0 {
        return Ok(());
    }
    let len = file.metadata()?.len();
    if from >= len {
        file.set_len(0)?;
        return file.flush();
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut read_at = from;
    let mut write_at = 0u64;
    while read_at < len {
        file.seek(SeekFrom::Start(read_at))?;
        let n = file.read(&mut buf)?;
        if n == 0 {
            break; // short file / truncated under us — stop with what we moved
        }
        file.seek(SeekFrom::Start(write_at))?;
        file.write_all(&buf[..n])?;
        read_at += n as u64;
        write_at += n as u64;
    }
    file.set_len(write_at)?;
    file.flush()
}

/// Apply the retention window to the log file `name` in `dir`.
///
/// Returns the decision that was applied, or an IO error. Missing file is not
/// an error — it is the first-run case — and reports [`Retention::KeepAll`].
///
/// MR-1945: the file is opened through [`OwnedDir::open_rw`], never by a
/// plain path. This runs elevated in a directory the user can write, and a
/// truncation that followed a planted junction or link emptied whatever old
/// file it named; a file that is not exactly the app's is an error, and is
/// left as it is.
pub fn enforce_file(dir: &OwnedDir, name: &str, cutoff: DateTime<Utc>) -> io::Result<Retention> {
    let mut file = match dir.open_rw(name) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Retention::KeepAll),
        Err(e) => return Err(e),
    };
    prune(&mut file, cutoff)
}

/// [`enforce_file`] on a file it has opened and checked.
fn prune(file: &mut std::fs::File, cutoff: DateTime<Utc>) -> io::Result<Retention> {
    let decision = {
        let mut reader = BufReader::new(&*file);
        scan(&mut reader, cutoff)?
    };

    match decision {
        Retention::KeepAll => {}
        Retention::DropFirst(offset) => shift_head_off(file, offset)?,
        Retention::DropAll => {
            file.set_len(0)?;
            file.flush()?;
        }
        Retention::Undated => {
            let modified = file
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .map(DateTime::<Utc>::from);
            if undated_should_truncate(modified, cutoff) {
                file.set_len(0)?;
                file.flush()?;
            }
        }
    }
    Ok(decision)
}

/// Enforce the retention window across the whole on-disk log set: `birdo.log`
/// AND the rotated `birdo.log.1` beside it.
///
/// BOTH, because rotation does not delete — it renames. A log that once crossed
/// 10 MiB leaves a full generation of history in `.1` that no other code path
/// has ever touched, so pruning only the live file would move the problem one
/// filename to the left. `.1` is dropped outright once it is empty; an empty
/// rotated log is not a diagnostic.
///
/// Best-effort by design: this runs before the tracing subscriber exists, and
/// no log-hygiene failure is worth refusing to start a VPN client over.
/// Diagnostics go to stderr, the only sink available this early.
///
/// MR-1945: both files are opened, and `.1` deleted, through `dir`
/// ([`OwnedDir`]), never by a plain path: see [`enforce_file`].
pub fn enforce(dir: &OwnedDir, log_name: &str, now: DateTime<Utc>) {
    let cutoff = cutoff(now);

    if let Err(e) = enforce_file(dir, log_name, cutoff) {
        eprintln!("birdo.log retention sweep failed (continuing): {}", e);
    }

    let rotated = rotated_path(Path::new(log_name));
    let Some(rotated) = rotated.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let pruned = dir.open_rw(rotated).and_then(|mut file| {
        prune(&mut file, cutoff)?;
        Ok(file.metadata()?.len() == 0)
    });
    match pruned {
        Ok(true) => {
            let _ = dir.remove_file(rotated);
        }
        Ok(false) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("birdo.log.1 retention sweep failed (continuing): {}", e),
    }
}

/// How many crash reports the crash directory keeps at most.
pub const KEEP_CRASH_REPORTS: usize = 5;

/// Whether `name` is a crash report's: the sweep below and the user's
/// "Delete Logs Now" (`file_log::delete_logs`) match the same files.
pub fn is_crash_report_name(name: &str) -> bool {
    name.starts_with("crash_") && name.ends_with(".txt")
}

/// When a crash report was written, from its name (`crash_YYYYMMDD_HHMMSS.txt`,
/// UTC — what `write_crash_report` mints). `None` for any other name.
fn crash_report_time(name: &str) -> Option<DateTime<Utc>> {
    let stamp = name.strip_prefix("crash_")?.strip_suffix(".txt")?;
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%d_%H%M%S")
        .ok()
        .map(|t| t.and_utc())
}

/// Prune the crash-report directory: every report older than the log's
/// retention window goes, and of the rest only the newest `keep` stay.
///
/// P6-CLI-D-05. A crash report is a timestamped record that this VPN client
/// was running at that minute, plus a backtrace. The count cap alone ran only
/// when the NEXT crash was written, so on a machine that stopped crashing the
/// last five stayed on disk for good. They now leave with the same window as
/// `birdo.log` (see the module docs before widening it), at every launch as
/// well as before each new report. A report dated by neither its name nor its
/// mtime is left alone, like an undated log. Best-effort: never worth failing
/// startup or a crash path over.
///
/// MR-1945: every delete goes through `dir` ([`OwnedDir::remove_file`]),
/// never a plain path: this runs elevated in the user's
/// `%LOCALAPPDATA%`, where a planted junction turned the sweep into a delete
/// of any file named like a crash report, anywhere.
pub fn prune_crash_reports(dir: &OwnedDir, now: DateTime<Utc>, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir.path()) else {
        return; // no crash yet
    };
    let cutoff = cutoff(now);
    let mut recent: Vec<(DateTime<Utc>, String)> = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_crash_report_name(&name) {
            continue;
        }
        let written = crash_report_time(&name).or_else(|| {
            std::fs::symlink_metadata(dir.join(&name))
                .and_then(|m| m.modified())
                .ok()
                .map(DateTime::<Utc>::from)
        });
        match written {
            Some(at) if at < cutoff => {
                let _ = dir.remove_file(&name);
            }
            Some(at) => recent.push((at, name)),
            None => {}
        }
    }
    recent.sort();
    let excess = recent.len().saturating_sub(keep);
    for (_, name) in &recent[..excess] {
        let _ = dir.remove_file(name);
    }
}

/// If `path` already exists and has grown past [`MAX_LOG_BYTES`], move it to
/// [`rotated_path`] (clobbering any previous generation) so the caller can open
/// a fresh, empty file at `path`. Best-effort: any failure here just means we
/// keep appending to the existing file, which is the pre-existing (unbounded)
/// behaviour — never worth failing startup over a log file.
///
/// Run this AFTER [`enforce`]: the sweep may well have taken the file back
/// under the size cap on its own, and rotating first would push expired content
/// into `.1` only to have to prune it there.
pub fn rotate_if_large(path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return; // doesn't exist yet (first run) — nothing to rotate
    };
    if meta.len() <= MAX_LOG_BYTES {
        return;
    }
    // std::fs::rename replaces an existing destination on both Windows
    // (MoveFileExW with MOVEFILE_REPLACE_EXISTING) and Unix, so this is a
    // single atomic step — no separate "delete old .1 first" required.
    if let Err(e) = std::fs::rename(path, rotated_path(path)) {
        // Can't log through tracing yet (this runs before the subscriber is
        // installed) — stderr is the best available diagnostic.
        eprintln!("birdo.log rotation failed (continuing to append): {}", e);
    }
}

/// Open `path` for appending, owner-only on multi-user Unix hosts.
///
/// P6-CLI-D-08: the log records which VPN nodes were used and when. On
/// Windows the file inherits its folder's ACL: the log and crash folders are
/// in the user's profile (`%APPDATA%`, `%LOCALAPPDATA%`), whose ACL grants the
/// user, SYSTEM and Administrators and no other local user (MR-843, pinned by
/// `tests::the_log_and_a_crash_report_are_not_readable_by_other_users_on_windows`).
pub fn open_for_append(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Create (or empty) `path` for writing, owner-only on multi-user Unix hosts:
/// the crash report's twin of [`open_for_append`] (P6-CLI-D-08).
pub fn create_owner_only(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// The persistent log's writer: rotates when the file passes its cap instead
/// of going silent (W1-019).
///
/// The cap used to be enforced by handing tracing an `io::sink()` once the
/// file passed 2 × [`MAX_LOG_BYTES`], so a session that hit it — exactly the
/// failure storms support needs logs for — recorded nothing more until the
/// next launch, the reconnect and give-up lines included. Now the file is moved
/// to [`rotated_path`] and a fresh one opened in its place, the same rotation
/// the start-up check performs. The sink survives only as the last resort for
/// a rotation the OS refuses (a scanner holding the file) on a file already
/// past twice the cap, so the disk stays bounded.
///
/// MR-808: it writes only while its gate (`file_log::LogGate`, the user's
/// "Save Diagnostic Logs") is on. Undecided, it holds lines in memory and
/// opens nothing; off, it closes the file and writes nothing. The file is
/// opened on the first line written while on, so a log that is off is never
/// created, and one that was deleted comes back only with new lines.
pub struct RotatingLog {
    path: PathBuf,
    cap: u64,
    gate: &'static LogGate,
    state: std::sync::Mutex<RotatingState>,
}

struct RotatingState {
    /// `None` until the first line written while on, and again whenever the
    /// gate turns off or the logs are deleted.
    file: Option<std::fs::File>,
    /// When a rotation last failed; it is not retried on every line.
    failed_at: Option<std::time::Instant>,
}

/// How long a refused rotation waits before it is tried again.
const ROTATION_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

/// The gate of a log that is not switchable ([`RotatingLog::open`]).
#[cfg(test)]
static ALWAYS_ON: LogGate = LogGate::on();

impl RotatingLog {
    /// A log that is always on, opened now.
    #[cfg(test)]
    pub fn open(path: &Path, cap: u64) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            cap,
            gate: &ALWAYS_ON,
            state: std::sync::Mutex::new(RotatingState {
                file: Some(open_for_append(path)?),
                failed_at: None,
            }),
        })
    }

    /// A log behind `gate`. Opens nothing; see the type's docs.
    pub fn gated(path: &Path, cap: u64, gate: &'static LogGate) -> Self {
        Self {
            path: path.to_path_buf(),
            cap,
            gate,
            state: std::sync::Mutex::new(RotatingState {
                file: None,
                failed_at: None,
            }),
        }
    }

    /// A writer for one log event. Never fails: losing one line beats taking
    /// the process down from inside the logging path.
    pub fn writer(&self) -> Box<dyn Write> {
        if self.gate.is_undecided() {
            return Box::new(Held(self.gate));
        }
        let mut state = self.lock();
        if !self.gate.is_on() {
            state.file = None;
            return Box::new(io::sink());
        }
        self.ensure_open(&mut state);
        let RotatingState {
            file: Some(file),
            failed_at,
        } = &mut *state
        else {
            return Box::new(io::sink());
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len > self.cap {
            let may_retry = failed_at.is_none_or(|at| at.elapsed() >= ROTATION_RETRY);
            if may_retry {
                match std::fs::rename(&self.path, rotated_path(&self.path))
                    .and_then(|()| open_for_append(&self.path))
                {
                    Ok(fresh) => {
                        *file = fresh;
                        *failed_at = None;
                    }
                    Err(e) => {
                        // WIN3-011: noted in the log itself, never on stderr.
                        // This runs on whichever thread logs, with the log's
                        // lock held, and a console that stopped taking output
                        // (a QuickEdit selection) held every logging thread
                        // behind one `eprintln!`. Dated like any line, so the
                        // retention sweep treats it like one.
                        let _ = writeln!(
                            file,
                            "{} WARN birdo.log rotation failed (continuing to append): {}",
                            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                            e
                        );
                        *failed_at = Some(std::time::Instant::now());
                    }
                }
            }
            if failed_at.is_some() && len > 2 * self.cap {
                return Box::new(io::sink());
            }
        }
        match file.try_clone() {
            Ok(f) => Box::new(f),
            Err(_) => Box::new(io::sink()),
        }
    }

    /// Bring the file in line with the gate now, rather than at the next line:
    /// on writes out what was held, off closes the file (`file_log::apply`).
    pub fn sync(&self) {
        let mut state = self.lock();
        if self.gate.is_on() {
            self.ensure_open(&mut state);
        } else if !self.gate.is_undecided() {
            state.file = None;
        }
    }

    /// Run `f` with this log's file closed and its lock held, so no line from
    /// this process can reach the disk until `f` returns; the next line opens
    /// a fresh file (`file_log::delete_logs`).
    pub fn closed_for<R>(&self, f: impl FnOnce() -> R) -> R {
        let mut state = self.lock();
        state.file = None;
        f()
    }

    /// Open the file if it is not open (creating its directory: nothing
    /// creates it at start-up any more), then write out whatever the gate held
    /// before it was decided.
    fn ensure_open(&self, state: &mut RotatingState) {
        if state.file.is_none() {
            if let Some(dir) = self.path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            state.file = open_for_append(&self.path).ok();
        }
        if let Some(file) = state.file.as_mut() {
            let held = self.gate.take_held();
            if !held.is_empty() {
                let _ = file.write_all(&held);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RotatingState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::io::Cursor;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, day, 12, 0, 0).unwrap()
    }

    fn line(day: u32, body: &str) -> String {
        format!("2026-06-{:02}T12:00:00.000001Z {}\n", day, body)
    }

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    /// `dir` standing in for one of the app's directories.
    fn here(dir: &Path) -> OwnedDir {
        OwnedDir::new(dir, &[])
    }

    /// [`enforce_file`] on the file at `p`.
    fn enforce_at(p: &Path, cutoff: DateTime<Utc>) -> io::Result<Retention> {
        let name = p.file_name().unwrap().to_str().unwrap();
        enforce_file(&here(p.parent().unwrap()), name, cutoff)
    }

    /// P6-CLI-D-08 (MR-843): the log, a rotated log's fresh file and a crash
    /// report are created owner-only on Unix. The modes were set, and nothing
    /// asserted them. Run by tests.yml's Linux and macOS job (its FILTER
    /// names `log_retention::tests`); the Windows half is
    /// `the_log_and_a_crash_report_are_not_readable_by_other_users_on_windows`.
    #[cfg(unix)]
    #[test]
    fn the_log_and_a_crash_report_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("birdo.log");
        let crash = dir.path().join("crash_20261008_120000.txt");
        let rotated = dir.path().join("rotating.log");
        drop(open_for_append(&log).unwrap());
        drop(create_owner_only(&crash).unwrap());
        // Past its cap, the next writer moves the file aside and opens a
        // fresh one in its place.
        let rotating = RotatingLog::open(&rotated, 4).unwrap();
        rotating
            .writer()
            .write_all(b"more than four bytes")
            .unwrap();
        drop(rotating.writer());
        assert!(rotated_path(&rotated).exists(), "the log was rotated");
        for p in [&log, &crash, &rotated] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} is {:o}", p.display(), mode);
        }
    }

    // ── the failure this module was written for ──────────────────────────

    /// THE FINDING. A log opened in append mode in June and still being
    /// appended to in September holds every connection since. Launching a
    /// build that redacts changes nothing about the lines already on disk —
    /// only this sweep does.
    #[test]
    fn months_of_pre_redaction_history_are_dropped_on_the_next_launch() {
        let dir = tempfile::tempdir().unwrap();
        let old = format!(
            "{}{}{}",
            line(
                1,
                "DEBUG vpn::manager: Tunnel config: endpoint=203.0.113.7:51820"
            ),
            line(2, "DEBUG vpn::wfp: VPN server IP set to: 203.0.113.7"),
            line(9, "DEBUG vpn::tunnel: DNS configured: [\"10.8.0.1\"]"),
        );
        let recent = line(20, "INFO  commands::vpn: Connected");
        let p = write(dir.path(), "birdo.log", &format!("{old}{recent}"));

        // "now" is 2026-06-21, so the window starts on the 14th.
        let applied = enforce_at(&p, cutoff(at(21))).unwrap();

        assert_eq!(applied, Retention::DropFirst(old.len() as u64));
        assert_eq!(read(&p), recent);
        let survivor = read(&p);
        assert!(
            !survivor.contains("203.0.113.7") && !survivor.contains("10.8.0.1"),
            "expired connection history survived the sweep: {survivor}"
        );
    }

    /// A user who has not launched in months: nothing is inside the window, so
    /// the file must end up EMPTY rather than merely shorter.
    #[test]
    fn a_log_entirely_older_than_the_window_is_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "birdo.log",
            &format!("{}{}", line(1, "INFO  a"), line(2, "INFO  b")),
        );
        assert_eq!(enforce_at(&p, cutoff(at(28))).unwrap(), Retention::DropAll);
        assert_eq!(read(&p), "");
    }

    /// The common case must be a no-op — the sweep runs on every launch and
    /// must not churn a healthy log.
    #[test]
    fn a_log_entirely_inside_the_window_is_left_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let contents = format!("{}{}", line(20, "INFO  a"), line(21, "INFO  b"));
        let p = write(dir.path(), "birdo.log", &contents);
        assert_eq!(enforce_at(&p, cutoff(at(21))).unwrap(), Retention::KeepAll);
        assert_eq!(read(&p), contents);
    }

    /// A panic backtrace is many lines with no timestamp of their own. They
    /// belong to the record above them: dropped with an expired record, kept
    /// with a retained one. Getting this wrong would strand a dropped panic's
    /// (path- and payload-bearing) backtrace at the top of the file.
    #[test]
    fn continuation_lines_travel_with_their_record() {
        let dir = tempfile::tempdir().unwrap();
        let expired = format!(
            "{}   at vpn::tunnel::connect (203.0.113.7)\n   at main\n",
            line(1, "ERROR PANIC at tunnel.rs:12")
        );
        let kept = format!(
            "{}   at fresh::frame\n",
            line(20, "ERROR PANIC at api.rs:8")
        );
        let p = write(dir.path(), "birdo.log", &format!("{expired}{kept}"));

        enforce_at(&p, cutoff(at(21))).unwrap();

        assert_eq!(read(&p), kept);
    }

    /// The head-shift moves more than one buffer's worth, and its source and
    /// destination ranges OVERLAP whenever the expired prefix is shorter than
    /// the 64 KiB copy buffer. A naive loop corrupts the tail here.
    #[test]
    fn shifting_a_large_log_preserves_the_tail_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let expired = line(1, "INFO  x"); // deliberately far shorter than the buffer
        let mut kept = String::new();
        for i in 0..4000 {
            kept.push_str(&line(
                20,
                &format!("INFO  record {i} ................................"),
            ));
        }
        assert!(kept.len() > 3 * 64 * 1024, "test must span several buffers");
        let p = write(dir.path(), "birdo.log", &format!("{expired}{kept}"));

        enforce_at(&p, cutoff(at(21))).unwrap();

        assert_eq!(read(&p), kept);
    }

    // ── the rotated generation: the parallel path ────────────────────────

    /// Rotation RENAMES, it does not delete. Pruning only the live file would
    /// leave a full generation of history one filename to the left.
    #[test]
    fn the_rotated_generation_is_pruned_too() {
        let dir = tempfile::tempdir().unwrap();
        let live = write(dir.path(), "birdo.log", &line(20, "INFO  fresh"));
        let rotated = write(
            dir.path(),
            "birdo.log.1",
            &line(1, "DEBUG vpn::manager: endpoint=203.0.113.7:51820"),
        );

        enforce(&here(dir.path()), "birdo.log", at(21));

        assert_eq!(read(&live), line(20, "INFO  fresh"));
        assert!(
            !rotated.exists(),
            "birdo.log.1 kept months of history that the live file was pruned of"
        );
    }

    /// A rotated file that still has fresh records is pruned, not deleted.
    #[test]
    fn a_rotated_generation_inside_the_window_survives() {
        let dir = tempfile::tempdir().unwrap();
        let live = write(dir.path(), "birdo.log", &line(21, "INFO  fresh"));
        let rotated = write(
            dir.path(),
            "birdo.log.1",
            &format!("{}{}", line(1, "INFO  old"), line(20, "INFO  recent")),
        );

        enforce(&here(dir.path()), "birdo.log", at(21));

        assert_eq!(read(&rotated), line(20, "INFO  recent"));
        assert_eq!(read(&live), line(21, "INFO  fresh"));
    }

    // ── a user-writable directory, an elevated sweep (MR-1945) ────────────

    /// THE FINDING. `logs` is a junction any process of the user can plant;
    /// the sweep runs elevated. Through it, the old code emptied an expired
    /// `birdo.log` and deleted an emptied `birdo.log.1` wherever the junction
    /// pointed (and, via `\RPC Control`, any file at all). Nothing behind it
    /// is touched now.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_log_directory_is_neither_truncated_nor_deleted() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let expired = format!("{}{}", line(1, "INFO  a"), line(2, "INFO  b"));
        let live = write(&elsewhere, "birdo.log", &expired);
        let rotated = write(&elsewhere, "birdo.log.1", &expired);
        crate::utils::safe_fs::tests::junction(&root.path().join("logs"), &elsewhere);

        enforce(&OwnedDir::new(root.path(), &["logs"]), "birdo.log", at(28));

        assert_eq!(
            read(&live),
            expired,
            "the sweep truncated through the junction"
        );
        assert_eq!(
            read(&rotated),
            expired,
            "the sweep deleted through the junction"
        );
    }

    /// A link named like the rotated log is the link, never its target.
    /// Needs the symlink privilege: a dev account without it skips, saying
    /// so; CI (an administrator) must not skip.
    #[cfg(windows)]
    #[test]
    fn a_symlinked_rotated_log_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let old = format!("{}{}", line(1, "INFO  a"), line(2, "INFO  b"));
        let precious = write(dir.path(), "precious.txt", &old);
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        if let Err(e) = std::os::windows::fs::symlink_file(&precious, logs.join("birdo.log.1")) {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI cannot create a symlink ({e}), so this test would test nothing"
            );
            eprintln!("SKIPPED: this account cannot create symlinks ({e})");
            return;
        }

        enforce(&OwnedDir::new(dir.path(), &["logs"]), "birdo.log", at(28));

        assert_eq!(
            read(&precious),
            old,
            "the sweep truncated the link's target"
        );
        assert!(std::fs::symlink_metadata(logs.join("birdo.log.1")).is_ok());
    }

    /// The crash sweep's twin of the finding.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_crash_directory_is_not_pruned() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let victim = write(&elsewhere, &crash_name(1, "120000"), "not the app's");
        std::fs::create_dir_all(root.path().join("Birdo VPN")).unwrap();
        crate::utils::safe_fs::tests::junction(
            &root.path().join("Birdo VPN").join("crashes"),
            &elsewhere,
        );

        let crashes = OwnedDir::new(root.path(), &["Birdo VPN", "crashes"]);
        prune_crash_reports(&crashes, at(20), 0);

        assert!(
            victim.exists(),
            "the crash sweep deleted through the junction"
        );
    }

    /// MR-843, the Windows half: the log and a crash report, created where
    /// the app creates them (the user's roaming and local profile folders),
    /// grant nothing to any other local user: only the user, SYSTEM and
    /// Administrators. The Unix half is the 0600 test above.
    #[cfg(windows)]
    #[test]
    fn the_log_and_a_crash_report_are_not_readable_by_other_users_on_windows() {
        use crate::utils::protected_dir::{current_user_sid, Security};
        use crate::utils::win_api::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};
        use std::os::windows::fs::OpenOptionsExt;

        let user = current_user_sid().unwrap();
        let allowed = ["S-1-5-18", "S-1-5-32-544", "S-1-3-4", user.as_str()];
        let roots = [dirs::data_dir().unwrap(), dirs::data_local_dir().unwrap()];
        for root in roots {
            let dir = tempfile::tempdir_in(&root).unwrap();
            let log = dir.path().join("birdo.log");
            let crash = dir.path().join("crash_20261013_120000.txt");
            drop(open_for_append(&log).unwrap());
            drop(create_owner_only(&crash).unwrap());
            for p in [dir.path(), log.as_path(), crash.as_path()] {
                let handle = std::fs::OpenOptions::new()
                    .access_mode(READ_CONTROL)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(p)
                    .unwrap();
                let granted = Security::of(&handle)
                    .unwrap()
                    .granted_sids()
                    .expect("a DACL (none would grant everyone everything)");
                assert!(
                    granted.iter().all(|sid| allowed.contains(&sid.as_str())),
                    "{} grants {granted:?}",
                    p.display()
                );
            }
        }
    }

    /// The sweep must target exactly the file rotation writes. If these two
    /// ever disagree, `.1` becomes a forever-file again.
    #[test]
    fn the_sweep_targets_the_file_rotation_actually_writes() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "birdo.log",
            &"x".repeat(MAX_LOG_BYTES as usize + 1),
        );
        rotate_if_large(&p);
        assert!(
            !p.exists(),
            "rotation should have moved the oversized log aside"
        );
        assert!(
            rotated_path(&p).exists(),
            "rotation wrote a name the sweep does not look at"
        );
    }

    /// WIN3-011: a rotation the OS refuses is noted in the log itself, never
    /// on stderr — the writer holds the log's lock on whichever thread logs,
    /// and a paused console blocked every one of them behind it.
    #[test]
    fn a_refused_rotation_is_noted_in_the_log_not_on_the_console() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "birdo.log", &line(20, &"x".repeat(64)));
        // A directory where the rotated file goes: the rename is refused.
        std::fs::create_dir(rotated_path(&p)).unwrap();
        let log = RotatingLog::open(&p, 16).unwrap();
        drop(log.writer());

        let text = read(&p);
        let note = text
            .lines()
            .find(|l| l.contains("birdo.log rotation failed"))
            .unwrap_or_else(|| panic!("the refusal is not in the log: {text}"));
        assert!(line_timestamp(note.as_bytes()).is_some(), "{note}");

        let source = include_str!("log_retention.rs");
        let writer = &source[source.find("pub fn writer(&self)").unwrap()..];
        let writer = &writer[..writer.find("\n    }").unwrap()];
        assert!(!writer.contains(concat!("eprint", "ln!(")), "{writer}");
    }

    #[test]
    fn rotation_leaves_a_log_under_the_size_cap_alone() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "birdo.log", "small\n");
        rotate_if_large(&p);
        assert_eq!(read(&p), "small\n");
        assert!(!rotated_path(&p).exists());
    }

    // ── edges ────────────────────────────────────────────────────────────

    #[test]
    fn a_missing_log_is_the_first_run_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("birdo.log");
        assert_eq!(enforce_at(&p, cutoff(at(21))).unwrap(), Retention::KeepAll);
        assert!(!p.exists(), "the sweep must not create the log");
    }

    #[test]
    fn an_empty_log_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "birdo.log", "");
        assert_eq!(enforce_at(&p, cutoff(at(21))).unwrap(), Retention::Undated);
        assert_eq!(read(&p), "");
    }

    /// An undated file is judged by its mtime, which is an upper bound on the
    /// age of everything in it.
    #[test]
    fn an_undated_file_is_judged_by_its_mtime() {
        let c = cutoff(at(21)); // 2026-06-14
        assert!(
            undated_should_truncate(Some(at(1)), c),
            "a stale unparseable log must go"
        );
        assert!(
            !undated_should_truncate(Some(at(20)), c),
            "a fresh one is kept"
        );
        assert!(
            !undated_should_truncate(None, c),
            "an unknown mtime must not destroy content on a guess"
        );
    }

    #[test]
    fn a_line_with_no_timestamp_never_dates_the_file() {
        let mut r = Cursor::new(b"not a log line at all\nnor this one\n".to_vec());
        assert_eq!(scan(&mut r, cutoff(at(21))).unwrap(), Retention::Undated);
    }

    #[test]
    fn invalid_utf8_does_not_abort_the_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("birdo.log");
        let mut bytes = line(1, "INFO  old").into_bytes();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
        bytes.extend_from_slice(line(20, "INFO  fresh").as_bytes());
        std::fs::write(&p, &bytes).unwrap();

        enforce_at(&p, cutoff(at(21))).unwrap();

        assert_eq!(
            std::fs::read(&p).unwrap(),
            line(20, "INFO  fresh").as_bytes()
        );
    }

    /// The window is the whole control. A silent widening (to "a year, for
    /// support") reintroduces the finding, so pin it.
    #[test]
    fn the_retention_window_stays_short() {
        assert!(
            (1..=14).contains(&MAX_LOG_AGE_DAYS),
            "birdo.log may not span more than a fortnight: it is connection history, \
             on a product whose policy says none is kept"
        );
        assert_eq!(cutoff(at(21)), at(14));
    }

    /// THE SWEEP MUST STAY WIRED. The call site is in `main.rs`, i.e. the BIN
    /// target, which CI's `cargo test --lib` never compiles — deleting the call
    /// would leave every test in this module green while the log went back to
    /// spanning the lifetime of the install. Same technique, and same reason,
    /// as `log_hygiene::the_on_disk_log_clamp_is_still_wired_into_main`.
    /// W1-019: past its cap the in-session log ROTATES and keeps recording;
    /// it used to drop every later line until the next launch.
    #[test]
    fn the_in_session_cap_rotates_instead_of_going_silent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("birdo.log");
        let log = RotatingLog::open(&path, 100).unwrap();
        log.writer().write_all(&[b'a'; 150]).unwrap();
        // The next event finds the file past the cap.
        log.writer()
            .write_all(b"reconnect attempt 3 of 10\n")
            .unwrap();
        assert_eq!(std::fs::read(rotated_path(&path)).unwrap(), vec![b'a'; 150]);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "reconnect attempt 3 of 10\n",
            "the line after the cap must be recorded, not sunk"
        );
    }

    #[test]
    fn the_retention_sweep_is_still_wired_into_main() {
        let main_rs = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("main.rs");
        let src = std::fs::read_to_string(&main_rs)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", main_rs.display()));

        assert!(
            src.contains("log_retention::enforce("),
            "main.rs no longer runs the retention sweep before opening birdo.log. \
             Without it the file keeps every line ever written to it, including the \
             months of unredacted connection history that pre-date the redaction work."
        );
        assert!(
            src.contains("log_retention::rotate_if_large("),
            "main.rs no longer rotates birdo.log at the size cap."
        );
    }

    // ── crash reports (P6-CLI-D-05) ───────────────────────────────────────

    fn crash_name(day: u32, hhmmss: &str) -> String {
        format!("crash_202606{day:02}_{hhmmss}.txt")
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// THE FINDING. The count cap ran only when the next crash was written,
    /// and never touched a directory under the cap, so the last reports
    /// stayed on disk for good. Anything older than the log's window now
    /// goes at launch, with no new crash needed — however few there are.
    #[test]
    fn crash_reports_older_than_the_window_go_without_a_new_crash() {
        let dir = tempfile::tempdir().unwrap();
        for name in [crash_name(1, "120000"), crash_name(12, "235959")] {
            write(dir.path(), &name, "BirdoVPN Crash Report\n");
        }
        let recent: Vec<String> = (0..3).map(|i| crash_name(14 + i, "080000")).collect();
        for name in &recent {
            write(dir.path(), name, "BirdoVPN Crash Report\n");
        }
        write(dir.path(), "notes.txt", "not ours");

        prune_crash_reports(&here(dir.path()), at(20), KEEP_CRASH_REPORTS);

        let mut want = recent.clone();
        want.push("notes.txt".into());
        assert_eq!(files_in(dir.path()), want, "only what is inside the window");
    }

    /// The cap still holds inside the window: the newest few stay.
    #[test]
    fn inside_the_window_only_the_newest_reports_stay() {
        let dir = tempfile::tempdir().unwrap();
        let recent: Vec<String> = (0..7).map(|i| crash_name(14 + i, "080000")).collect();
        for name in &recent {
            write(dir.path(), name, "BirdoVPN Crash Report\n");
        }
        prune_crash_reports(&here(dir.path()), at(20), KEEP_CRASH_REPORTS);
        assert_eq!(files_in(dir.path()), recent[2..].to_vec());
    }

    #[test]
    fn a_report_inside_the_window_is_kept_and_a_missing_directory_is_no_crash_yet() {
        let dir = tempfile::tempdir().unwrap();
        let name = crash_name(19, "101010");
        write(dir.path(), &name, "x");
        prune_crash_reports(&here(dir.path()), at(20), KEEP_CRASH_REPORTS);
        assert!(dir.path().join(&name).exists());
        prune_crash_reports(
            &OwnedDir::new(dir.path(), &["absent"]),
            at(20),
            KEEP_CRASH_REPORTS,
        );
    }

    #[test]
    fn a_crash_report_is_dated_by_its_name() {
        assert_eq!(crash_report_time(&crash_name(5, "120000")), Some(at(5)));
        assert_eq!(crash_report_time("crash_garbage.txt"), None);
        assert_eq!(crash_report_time("birdo.log"), None);
    }

    /// Both halves are wired: the launch sweep, and the cap before a write.
    #[test]
    fn the_crash_sweep_runs_at_launch_and_before_each_report() {
        let src = include_str!("../main.rs").replace('\r', "");
        let main_fn = &src[src.find("fn main() {").unwrap()..];
        let main_fn = &main_fn[..main_fn.find("\n}\n").unwrap()];
        assert!(
            main_fn.contains("log_retention::prune_crash_reports("),
            "main() no longer sweeps the crash directory at launch"
        );
        let writer = &src[src.find("fn write_crash_report(").unwrap()..];
        assert!(writer[..writer.find("\n}\n").unwrap()].contains("prune_crash_reports("));
    }
}
