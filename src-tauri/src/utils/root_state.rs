//! MR-2050 / MR-2089: where the root-run client keeps the state it acts on
//! after a crash, on Linux and macOS, and the no-follow file operations it
//! uses there.
//!
//! WHY THIS EXISTS. Off Windows the whole client runs as root
//! (`utils::elevation`). The DNS journal and macOS's pf reference record used
//! to live in `dirs::data_dir()/BirdoVPN`: root's own folder under pkexec, but
//! the USER's `~/.local/share` (`~/Library/Application Support`) whenever the
//! launch kept HOME (`sudo -E`). There any process of that user could plant a
//! journal, and root then pointed /etc/resolv.conf where it said; or plant a
//! symlink on the staging name, which root opened with O_TRUNC and wrote
//! THROUGH, over any file on the machine. This is the Linux/macOS twin of
//! Windows' admin-only `%ProgramData%\BirdoVPN` (MR-1721,
//! `utils::protected_dir`).
//!
//! THE RULE. The directory is a fixed system path, never one derived from
//! HOME or XDG variables, which the launching user controls. This process
//! creates it 0700 and uses it only while it is a real directory, owned by the
//! effective user, that nobody else can write; its parent is a system
//! directory only root can write, so it cannot be swapped between that check
//! and a use. Files in it are created NEW (O_CREAT|O_EXCL|O_NOFOLLOW) with
//! mode 0600 from the start, and read only through an O_NOFOLLOW open whose
//! file passes the same ownership check. Persistent storage, not /run: the
//! resolv.conf pin and the macOS service DNS survive a reboot, so the record
//! that undoes them has to as well.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

/// The root-only state directory.
#[cfg(target_os = "linux")]
pub(crate) const STATE_DIR: &str = "/var/lib/birdovpn";
/// The root-only state directory (`/var/db` is root's, mode 0755).
#[cfg(target_os = "macos")]
pub(crate) const STATE_DIR: &str = "/var/db/birdovpn";

/// The records kept here are a few kilobytes; a larger file is not one.
const MAX_LEGACY_BYTES: u64 = 1 << 20;

fn refused(what: &str, why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("{what} {why}"))
}

/// Owned by the effective user (root, for the elevated client) and writable
/// by nobody else.
fn check_owner(meta: &std::fs::Metadata, what: &str) -> io::Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(refused(what, "is owned by another user"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refused(what, "is writable by other users"));
    }
    Ok(())
}

/// `dir` is a real directory (not a link) that is ours alone.
pub(crate) fn check_private_dir(dir: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(refused("the folder", "is not a directory"));
    }
    check_owner(&meta, "the folder")
}

/// Create `dir` owner-only (0700) if it is absent, never its parents, and
/// verify it either way.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(dir) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    check_private_dir(dir)
}

/// Create `path` as a brand-new file for writing: O_CREAT|O_EXCL|O_NOFOLLOW,
/// mode 0600 from the start. Whatever is already at the name (a staging file
/// a crash left, or a link) is unlinked first, which never follows a link,
/// and is never opened.
pub(crate) fn create_new_private(path: &Path) -> io::Result<File> {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Open `path` for reading only if it is a regular file, not a link, that is
/// ours alone. `NotFound` when there is none. O_NONBLOCK so a FIFO at the name
/// cannot hang the open; it does nothing to a regular file's reads.
pub(crate) fn open_private(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refused("the file", "is not a regular file"));
    }
    check_owner(&meta, "the file")?;
    Ok(file)
}

/// What became of a record an older build left in its old folder.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Adopted {
    /// There was none.
    NoneThere,
    /// Moved into the state directory.
    Moved,
    /// Left where it is and never read: a newer record is already in the
    /// state directory, or it is not one root wrote (a link, a file or folder
    /// another user owns or can write), or `accept` refused its bytes.
    LeftInPlace,
    /// It could not be written into the state directory; tried again at the
    /// next start.
    Failed,
}

/// Take over `name` from `legacy` (the folder an older build kept it in) to
/// `dest` in the state directory, through `write`.
///
/// Only a record root itself wrote is taken: `legacy` a real directory and
/// the file a regular one, each owned by us and writable by nobody else, so
/// that even in a user's HOME nobody but root can have put those bytes there.
/// And only if `accept` takes the bytes. Anything else is left where it is,
/// unread from now on. The old file is deleted once the new one is written.
pub(crate) fn adopt_legacy(
    legacy: &Path,
    name: &str,
    dest: &Path,
    accept: impl FnOnce(&[u8]) -> bool,
    write: impl FnOnce(&Path, &[u8]) -> io::Result<()>,
) -> Adopted {
    let old = legacy.join(name);
    match std::fs::symlink_metadata(&old) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Adopted::NoneThere,
        Err(e) => {
            tracing::warn!(
                "The old {} could not be looked at ({}) — left in place",
                name,
                e
            );
            return Adopted::LeftInPlace;
        }
        Ok(_) => {}
    }
    if std::fs::symlink_metadata(dest).is_ok() {
        tracing::warn!(
            "Left the old {} in the old data folder in place, unused: the root-only one is newer",
            name
        );
        return Adopted::LeftInPlace;
    }
    let read = check_private_dir(legacy)
        .and_then(|()| open_private(&old))
        .and_then(|file| {
            let mut bytes = Vec::new();
            file.take(MAX_LEGACY_BYTES).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                "Left the old {} in place, unused: only one root wrote is taken over ({})",
                name,
                e
            );
            return Adopted::LeftInPlace;
        }
    };
    if !accept(&bytes) {
        tracing::warn!(
            "Left the old {} in place, unused: not a record of ours",
            name
        );
        return Adopted::LeftInPlace;
    }
    if let Err(e) = write(dest, &bytes) {
        tracing::warn!(
            "Could not move the old {} ({}) — retrying at the next start",
            name,
            e
        );
        return Adopted::Failed;
    }
    // unlink never follows a link, and the folder was checked above.
    if let Err(e) = std::fs::remove_file(&old) {
        tracing::warn!("The old {} was not deleted: {}", name, e);
    }
    tracing::info!("Moved the {} into the root-only state directory", name);
    Adopted::Moved
}

/// Run unprivileged on Linux and macOS (tests.yml's `root_write_tests`
/// filter); the test user plays root, owning its temp folders.
#[cfg(test)]
mod root_write_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn the_state_dir_is_made_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("birdovpn");
        ensure_private_dir(&dir).unwrap();
        assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
        assert_eq!(mode(&dir), 0o700);
        ensure_private_dir(&dir).expect("an existing one of ours is accepted");
    }

    #[test]
    fn a_state_dir_others_can_write_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("birdovpn");
        std::fs::create_dir(&dir).unwrap();
        for wider in [0o770, 0o707, 0o777, 0o1777] {
            set_mode(&dir, wider);
            assert_eq!(
                ensure_private_dir(&dir).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{wider:o}"
            );
        }
        set_mode(&dir, 0o755);
        ensure_private_dir(&dir).expect("readable by others is fine, writable is not");
    }

    #[test]
    fn a_linked_state_dir_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o700);
        let dir = root.path().join("birdovpn");
        std::os::unix::fs::symlink(&real, &dir).unwrap();
        assert!(ensure_private_dir(&dir).is_err());
        assert!(check_private_dir(&dir).is_err());
    }

    #[test]
    fn a_state_dir_owned_by_another_user_is_refused() {
        if is_root() {
            return; // "/" is the test user's own then
        }
        // A root-owned directory, seen by an unprivileged test user.
        assert_eq!(
            check_private_dir(Path::new("/")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn a_new_file_is_owner_only_and_never_written_through_a_link() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, "not ours").unwrap();
        let staging = root.path().join("record.tmp");
        std::os::unix::fs::symlink(&victim, &staging).unwrap();

        std::io::Write::write_all(&mut create_new_private(&staging).unwrap(), b"ours").unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "not ours");
        assert!(std::fs::symlink_metadata(&staging).unwrap().is_file());
        assert_eq!(mode(&staging), 0o600);
        assert_eq!(std::fs::read_to_string(&staging).unwrap(), "ours");
    }

    #[test]
    fn only_a_regular_file_of_ours_is_opened() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("record");
        std::fs::write(&file, "ours").unwrap();
        set_mode(&file, 0o600);
        assert!(open_private(&file).is_ok());

        set_mode(&file, 0o622);
        assert!(open_private(&file).is_err(), "writable by others");
        set_mode(&file, 0o600);

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(open_private(&link).is_err(), "a link");
        assert!(open_private(root.path()).is_err(), "a directory");
        assert_eq!(
            open_private(&root.path().join("absent"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    /// The old per-HOME folder and the new state directory, in one temp root.
    struct Dirs {
        _root: tempfile::TempDir,
        legacy: std::path::PathBuf,
        dest: std::path::PathBuf,
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let legacy = root.path().join("BirdoVPN");
        std::fs::create_dir(&legacy).unwrap();
        set_mode(&legacy, 0o755);
        let state = root.path().join("birdovpn");
        ensure_private_dir(&state).unwrap();
        Dirs {
            dest: state.join("record"),
            legacy,
            _root: root,
        }
    }

    fn adopt(d: &Dirs) -> Adopted {
        adopt_legacy(
            &d.legacy,
            "record",
            &d.dest,
            |bytes| bytes.starts_with(b"ours"),
            |dest, bytes| {
                let mut file = create_new_private(dest)?;
                std::io::Write::write_all(&mut file, bytes)
            },
        )
    }

    #[test]
    fn a_record_root_wrote_is_moved_once() {
        let d = dirs();
        assert_eq!(adopt(&d), Adopted::NoneThere);

        std::fs::write(d.legacy.join("record"), "ours, from an older build").unwrap();
        set_mode(&d.legacy.join("record"), 0o600);
        assert_eq!(adopt(&d), Adopted::Moved);
        assert_eq!(
            std::fs::read_to_string(&d.dest).unwrap(),
            "ours, from an older build"
        );
        assert_eq!(mode(&d.dest), 0o600);
        assert!(!d.legacy.join("record").exists(), "the old one is deleted");
        assert_eq!(adopt(&d), Adopted::NoneThere);
    }

    #[test]
    fn a_record_someone_else_could_have_written_is_left_unread() {
        // In a folder others can write.
        let d = dirs();
        std::fs::write(d.legacy.join("record"), "ours?").unwrap();
        set_mode(&d.legacy.join("record"), 0o600);
        set_mode(&d.legacy, 0o777);
        assert_eq!(adopt(&d), Adopted::LeftInPlace);
        assert!(!d.dest.exists());
        assert!(d.legacy.join("record").exists(), "left where it is");

        // Itself writable by others.
        let d = dirs();
        std::fs::write(d.legacy.join("record"), "ours?").unwrap();
        set_mode(&d.legacy.join("record"), 0o666);
        assert_eq!(adopt(&d), Adopted::LeftInPlace);
        assert!(!d.dest.exists());

        // A link to a record of ours elsewhere.
        let d = dirs();
        let elsewhere = d.legacy.with_file_name("elsewhere");
        std::fs::write(&elsewhere, "ours, but not here").unwrap();
        set_mode(&elsewhere, 0o600);
        std::os::unix::fs::symlink(&elsewhere, d.legacy.join("record")).unwrap();
        assert_eq!(adopt(&d), Adopted::LeftInPlace);
        assert!(!d.dest.exists());

        // A linked old folder.
        let d = dirs();
        let real = d.legacy.with_file_name("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o700);
        std::fs::write(real.join("record"), "ours, linked").unwrap();
        set_mode(&real.join("record"), 0o600);
        std::fs::remove_dir(&d.legacy).unwrap();
        std::os::unix::fs::symlink(&real, &d.legacy).unwrap();
        assert_eq!(adopt(&d), Adopted::LeftInPlace);
        assert!(!d.dest.exists());
        assert!(real.join("record").exists());
    }

    #[test]
    fn a_newer_record_or_foreign_bytes_keep_the_old_one_in_place() {
        let d = dirs();
        std::fs::write(d.legacy.join("record"), "ours, older").unwrap();
        set_mode(&d.legacy.join("record"), 0o600);
        std::fs::write(&d.dest, "ours, newer").unwrap();
        assert_eq!(adopt(&d), Adopted::LeftInPlace);
        assert_eq!(std::fs::read_to_string(&d.dest).unwrap(), "ours, newer");
        assert!(d.legacy.join("record").exists());

        let d = dirs();
        std::fs::write(d.legacy.join("record"), "not a record").unwrap();
        set_mode(&d.legacy.join("record"), 0o600);
        assert_eq!(adopt(&d), Adopted::LeftInPlace);
        assert!(!d.dest.exists());
    }

    #[test]
    fn a_failed_write_keeps_the_old_record_for_the_next_start() {
        let d = dirs();
        std::fs::write(d.legacy.join("record"), "ours").unwrap();
        set_mode(&d.legacy.join("record"), 0o600);
        let outcome = adopt_legacy(
            &d.legacy,
            "record",
            &d.dest,
            |_| true,
            |_, _| Err(io::Error::other("disk full")),
        );
        assert_eq!(outcome, Adopted::Failed);
        assert!(d.legacy.join("record").exists());
    }
}
