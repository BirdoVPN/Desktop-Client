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

/// Apply the retention window to a single log file.
///
/// Returns the decision that was applied, or an IO error. Missing file is not
/// an error — it is the first-run case — and reports [`Retention::KeepAll`].
pub fn enforce_file(path: &Path, cutoff: DateTime<Utc>) -> io::Result<Retention> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Retention::KeepAll),
        Err(e) => return Err(e),
    };

    let decision = {
        let mut reader = BufReader::new(&file);
        scan(&mut reader, cutoff)?
    };

    match decision {
        Retention::KeepAll => {}
        Retention::DropFirst(offset) => shift_head_off(&mut file, offset)?,
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
pub fn enforce(log_path: &Path, now: DateTime<Utc>) {
    let cutoff = cutoff(now);

    if let Err(e) = enforce_file(log_path, cutoff) {
        eprintln!("birdo.log retention sweep failed (continuing): {}", e);
    }

    let rotated = rotated_path(log_path);
    match enforce_file(&rotated, cutoff) {
        Ok(_) => {
            let empty = std::fs::metadata(&rotated)
                .map(|m| m.len() == 0)
                .unwrap_or(false);
            if empty {
                let _ = std::fs::remove_file(&rotated);
            }
        }
        Err(e) => eprintln!("birdo.log.1 retention sweep failed (continuing): {}", e),
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
        let applied = enforce_file(&p, cutoff(at(21))).unwrap();

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
        assert_eq!(
            enforce_file(&p, cutoff(at(28))).unwrap(),
            Retention::DropAll
        );
        assert_eq!(read(&p), "");
    }

    /// The common case must be a no-op — the sweep runs on every launch and
    /// must not churn a healthy log.
    #[test]
    fn a_log_entirely_inside_the_window_is_left_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let contents = format!("{}{}", line(20, "INFO  a"), line(21, "INFO  b"));
        let p = write(dir.path(), "birdo.log", &contents);
        assert_eq!(
            enforce_file(&p, cutoff(at(21))).unwrap(),
            Retention::KeepAll
        );
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

        enforce_file(&p, cutoff(at(21))).unwrap();

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

        enforce_file(&p, cutoff(at(21))).unwrap();

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

        enforce(&live, at(21));

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

        enforce(&live, at(21));

        assert_eq!(read(&rotated), line(20, "INFO  recent"));
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
        assert_eq!(
            enforce_file(&p, cutoff(at(21))).unwrap(),
            Retention::KeepAll
        );
        assert!(!p.exists(), "the sweep must not create the log");
    }

    #[test]
    fn an_empty_log_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "birdo.log", "");
        assert_eq!(
            enforce_file(&p, cutoff(at(21))).unwrap(),
            Retention::Undated
        );
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

        enforce_file(&p, cutoff(at(21))).unwrap();

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
}
