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
//!
//! THE CONFIG FOLDER. settings.json, its key and the consent record stay in
//! the config folder under HOME, where Tauri puts them; [`make_private`] makes
//! that folder ours alone before root reads or writes there (MR-2089).

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

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

/// What [`make_private`] did with one of the app's folders.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Made {
    /// There was none, or it was ours alone already.
    AsItWas,
    /// Ours, and writable by our own group too: made 0700.
    Tightened,
    /// Not ours alone: renamed to this name beside it, and made anew (0700)
    /// with the files root itself wrote in it carried over.
    SetAside(PathBuf),
}

/// MR-2089 (review of #327): make `dir`, one of the app's folders in a place
/// its user can write (the config folder under HOME), ours alone, so that
/// [`check_private_dir`] passes, instead of refusing it for good.
///
/// A folder of ours that our own group can write (the umask 002 of a Fedora
/// shell made it 0775) is made 0700 through a handle opened without following
/// a link. Anything else that is not ours alone (a folder another user owns,
/// such as the one an unprivileged launch from the desktop menu or Finder
/// made before a launch as root that kept HOME; one everyone can write; a
/// link) is, when this process is root, renamed aside (`<name>.untrusted-…`)
/// and made anew, 0700. Of what was in it, only `carry` (file names) are
/// carried over, and only those root itself wrote ([`carry_over`]): the rest,
/// which anyone could have put there, stays behind unread. A process that is
/// not root never moves anything: a folder root made is root's, and the
/// error says which folder to delete.
pub(crate) fn make_private(dir: &Path, carry: &[&str]) -> io::Result<Made> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    make_private_as(dir, carry, root)
}

/// [`make_private`]; `may_set_aside` says whether this process may move a
/// folder that is not ours alone (root). A parameter so the tests, where the
/// test user plays root, reach that path unprivileged.
fn make_private_as(dir: &Path, carry: &[&str], may_set_aside: bool) -> io::Result<Made> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Made::AsItWas),
        Err(e) => return Err(e),
    };
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let ours = meta.is_dir() && meta.uid() == euid;
    if ours && meta.mode() & 0o022 == 0 {
        return Ok(Made::AsItWas);
    }
    if ours && meta.mode() & 0o002 == 0 && meta.gid() == egid {
        tighten(dir, &meta)?;
        return Ok(Made::Tightened);
    }
    let why = if !meta.is_dir() {
        "is not a folder"
    } else if meta.uid() != euid {
        "is owned by another user"
    } else {
        "is writable by other users"
    };
    if !may_set_aside {
        return Err(refused(
            &format!("the folder {}", dir.display()),
            &format!("{why}: delete it (or move it away) and start BirdoVPN again"),
        ));
    }
    // The folder as it was looked at, held across the move: what is carried
    // over is read from THIS folder, whatever its old or new name is made to
    // point at meanwhile. A link, or a folder swapped since, carries nothing.
    let held = if meta.is_dir() {
        open_seen_dir(dir, &meta).ok()
    } else {
        None
    };
    let aside = set_aside(dir)?;
    ensure_private_dir(dir)?;
    // The new folder, too, through a handle from here on: its name is in a
    // folder the user can write, where it could be renamed away and a link
    // put in its place between the check above and a write.
    let fresh = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    check_owner(&fresh.metadata()?, "the new folder")?;
    if let Some(held) = &held {
        for name in carry {
            carry_over(held, &fresh, name);
        }
    }
    tracing::warn!(
        "A folder of the app's that was not root's alone ({why}) was set aside as {} and made anew",
        aside
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    );
    Ok(Made::SetAside(aside))
}

/// `dir` opened without following a link, and only while it is still the
/// folder `seen` described.
fn open_seen_dir(dir: &Path, seen: &std::fs::Metadata) -> io::Result<File> {
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    let meta = handle.metadata()?;
    if (meta.dev(), meta.ino()) != (seen.dev(), seen.ino()) {
        return Err(refused("the folder", "changed while it was looked at"));
    }
    Ok(handle)
}

/// Make `dir` 0700 through a handle to the folder `seen` described.
fn tighten(dir: &Path, seen: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // fchmod, on the handle.
    open_seen_dir(dir, seen)?.set_permissions(std::fs::Permissions::from_mode(0o700))
}

/// Rename `dir` to an unused `<name>.untrusted-<UTC time>` beside it.
/// rename(2) never follows a link at either name.
fn set_aside(dir: &Path) -> io::Result<PathBuf> {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| refused("the folder", "has no name"))?;
    let base = format!(
        "{name}.untrusted-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    for n in 1..100 {
        let candidate = if n == 1 {
            dir.with_file_name(&base)
        } else {
            dir.with_file_name(format!("{base}-{n}"))
        };
        if std::fs::symlink_metadata(&candidate).is_ok() {
            continue;
        }
        std::fs::rename(dir, &candidate)?;
        return Ok(candidate);
    }
    Err(refused(
        "the folder",
        "could not be set aside: no free name",
    ))
}

/// `name` as a C string: a plain name for the `*at` calls below.
fn c_name(name: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a file name"))
}

/// [`open_private`] for `name`, a plain name, in the folder `dir` is a
/// handle to (openat): never through a path that could be made to point
/// elsewhere.
fn open_private_in(dir: &File, name: &str) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c_name = c_name(name)?;
    // SAFETY: `dir` is an open directory and `c_name` a NUL-terminated string,
    // both alive for the call; openat takes no mode without O_CREAT.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor openat just returned, owned by nothing
    // else.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refused("the file", "is not a regular file"));
    }
    check_owner(&meta, "the file")?;
    Ok(file)
}

/// Unlink `name`, a plain name, in the folder `dir` is a handle to (unlinkat
/// never follows a link). `NotFound` when there is nothing there.
fn unlink_in(dir: &File, name: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let c_name = c_name(name)?;
    // SAFETY: `dir` is an open directory and `c_name` a NUL-terminated string,
    // both alive for the call.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// [`create_new_private`] for `name`, a plain name, in the folder `dir` is a
/// handle to: whatever is at the name is unlinked first ([`unlink_in`]), then
/// a new file is made, O_CREAT|O_EXCL|O_NOFOLLOW, 0600.
fn create_new_private_in(dir: &File, name: &str) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if let Err(e) = unlink_in(dir, name) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    let c_name = c_name(name)?;
    // SAFETY: `dir` is an open directory and `c_name` a NUL-terminated string,
    // both alive for the call; with O_CREAT openat takes the mode as its one
    // variadic argument, passed promoted as C does.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor openat just returned, owned by nothing
    // else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Rename `from` to `to`, both plain names, within the folder `dir` is a
/// handle to (renameat, which never follows a link at either name).
fn rename_in(dir: &File, from: &str, to: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let (from, to) = (c_name(from)?, c_name(to)?);
    let at = dir.as_raw_fd();
    // SAFETY: `dir` is an open directory and both names NUL-terminated
    // strings, all alive for the call.
    if unsafe { libc::renameat(at, from.as_ptr(), at, to.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Copy `name` from the folder set aside (`from`, a handle to it) into the
/// new one (`to`, a handle to it), only if root itself wrote it: a regular
/// file (not a link) that only we can write ([`open_private_in`]), with no
/// other name (a hard link could be any file of ours), and no larger than a
/// record of ours. Anything else stays behind, unread.
fn carry_over(from: &File, to: &File, name: &str) -> bool {
    let read = open_private_in(from, name).and_then(|file| {
        let meta = file.metadata()?;
        if meta.nlink() != 1 {
            return Err(refused("the file", "has other names"));
        }
        if meta.len() > MAX_LEGACY_BYTES {
            return Err(refused("the file", "is too large"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_LEGACY_BYTES).read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return false,
        Err(e) => {
            tracing::warn!("Left {} behind in the folder set aside ({})", name, e);
            return false;
        }
    };
    let staging = format!("{name}.tmp");
    let written = create_new_private_in(to, &staging)
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, &bytes)?;
            file.sync_all()
        })
        .and_then(|()| rename_in(to, &staging, name));
    if let Err(e) = written {
        let _ = unlink_in(to, &staging);
        tracing::warn!("Could not carry {} over into the new folder: {}", name, e);
        return false;
    }
    true
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
        // Not "birdovpn": macOS's default file system is case-insensitive,
        // so that would be the legacy folder itself.
        let state = root.path().join("state");
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

    /// The config folder's three files, as `settings` names them.
    const CARRY: [&str; 3] = ["settings.json", "settings_hmac.key", "consent.json"];

    /// `<temp>/uk.birdo.vpn.desktop`, made with `mode`, in our own group.
    fn app_folder(root: &Path, mode: u32) -> PathBuf {
        let dir = root.join("uk.birdo.vpn.desktop");
        std::fs::create_dir(&dir).unwrap();
        // SAFETY: getegid has no preconditions and cannot fail.
        std::os::unix::fs::chown(&dir, None, Some(unsafe { libc::getegid() })).unwrap();
        set_mode(&dir, mode);
        dir
    }

    fn write_private(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        set_mode(path, 0o600);
    }

    #[test]
    fn a_folder_ours_alone_is_left_as_it_is() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            make_private_as(&root.path().join("absent"), &CARRY, true).unwrap(),
            Made::AsItWas
        );
        for alone in [0o700, 0o755] {
            let root = tempfile::tempdir().unwrap();
            let dir = app_folder(root.path(), alone);
            assert_eq!(make_private_as(&dir, &CARRY, true).unwrap(), Made::AsItWas);
            assert_eq!(mode(&dir), alone);
        }
    }

    /// The umask 002 of a Fedora or RHEL shell made the folder 0775, which
    /// the write check refused for good. It is ours: it is made 0700, kept.
    #[test]
    fn a_folder_our_group_can_write_is_made_owner_only() {
        for wider in [0o770, 0o775] {
            let root = tempfile::tempdir().unwrap();
            let dir = app_folder(root.path(), wider);
            write_private(&dir.join("settings.json"), "ours");
            for may_set_aside in [true, false] {
                set_mode(&dir, wider);
                assert_eq!(
                    make_private_as(&dir, &CARRY, may_set_aside).unwrap(),
                    Made::Tightened,
                    "{wider:o}"
                );
                assert_eq!(mode(&dir), 0o700, "{wider:o}");
                check_private_dir(&dir).expect("ours alone now");
                assert_eq!(
                    std::fs::read_to_string(dir.join("settings.json")).unwrap(),
                    "ours",
                    "the folder is kept, not replaced"
                );
            }
        }
    }

    /// Root under a kept HOME, in a folder others could have filled: it is
    /// set aside and made anew, and of what was in it only what root itself
    /// wrote comes along.
    #[test]
    fn a_folder_not_ours_alone_is_set_aside_and_made_anew() {
        let root = tempfile::tempdir().unwrap();
        let dir = app_folder(root.path(), 0o700);
        write_private(&dir.join("settings.json"), "ours, signed");
        // Planted: writable by others, a link, a second name for a file.
        std::fs::write(dir.join("consent.json"), "theirs").unwrap();
        set_mode(&dir.join("consent.json"), 0o666);
        let victim = root.path().join("victim");
        write_private(&victim, "not the key's");
        std::os::unix::fs::symlink(&victim, dir.join("settings_hmac.key")).unwrap();
        set_mode(&dir, 0o777);

        let Made::SetAside(aside) = make_private_as(&dir, &CARRY, true).unwrap() else {
            panic!("not set aside");
        };

        assert!(aside
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("uk.birdo.vpn.desktop.untrusted-"));
        assert_eq!(aside.parent(), dir.parent());
        assert_eq!(mode(&aside), 0o777, "set aside as it was");
        assert_eq!(
            std::fs::read_to_string(aside.join("consent.json")).unwrap(),
            "theirs"
        );
        assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
        assert_eq!(mode(&dir), 0o700, "made anew, owner-only");
        check_private_dir(&dir).expect("ours alone now");
        assert_eq!(
            std::fs::read_to_string(dir.join("settings.json")).unwrap(),
            "ours, signed"
        );
        assert_eq!(mode(&dir.join("settings.json")), 0o600);
        assert!(!dir.join("consent.json").exists(), "others could write it");
        assert!(
            std::fs::symlink_metadata(dir.join("settings_hmac.key")).is_err(),
            "a link"
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "not the key's");
        assert!(!dir.join("settings.json.tmp").exists());

        // A file of ours under a second name could be any file of ours.
        let root = tempfile::tempdir().unwrap();
        let dir = app_folder(root.path(), 0o700);
        let elsewhere = root.path().join("elsewhere");
        write_private(&elsewhere, "some other file of ours");
        std::fs::hard_link(&elsewhere, dir.join("settings.json")).unwrap();
        set_mode(&dir, 0o777);
        assert!(matches!(
            make_private_as(&dir, &CARRY, true).unwrap(),
            Made::SetAside(_)
        ));
        assert!(!dir.join("settings.json").exists(), "a hard link");
    }

    /// A link at the folder's name is moved as a link, never followed.
    #[test]
    fn a_link_at_the_folders_name_is_set_aside_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o755);
        write_private(&real.join("settings.json"), "elsewhere");
        let dir = root.path().join("uk.birdo.vpn.desktop");
        std::os::unix::fs::symlink(&real, &dir).unwrap();

        let Made::SetAside(aside) = make_private_as(&dir, &CARRY, true).unwrap() else {
            panic!("not set aside");
        };

        assert!(std::fs::symlink_metadata(&aside)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
        assert!(
            !dir.join("settings.json").exists(),
            "nothing through a link"
        );
        assert_eq!(mode(&real), 0o755, "the link's target is untouched");
    }

    /// A process that is not root moves nothing (a folder root made is
    /// root's) and says which folder to delete.
    #[test]
    fn a_process_that_is_not_root_says_which_folder_to_delete() {
        let root = tempfile::tempdir().unwrap();
        let dir = app_folder(root.path(), 0o700);
        write_private(&dir.join("settings.json"), "ours?");
        for wider in [0o707, 0o777] {
            set_mode(&dir, wider);
            let e = make_private_as(&dir, &CARRY, false).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{wider:o}");
            let said = e.to_string();
            assert!(said.contains(&dir.display().to_string()), "{said}");
            assert!(said.contains("delete it"), "{said}");
            assert_eq!(mode(&dir), wider, "left as it was");
            assert!(dir.join("settings.json").exists());
        }
    }
}
