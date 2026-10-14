//! Deleting and truncating the app's own files in directories the signed-in
//! user can write, from a process that runs elevated (MR-1945).
//!
//! THE FINDING. The logs (`%APPDATA%\BirdoVPN\logs`), the crash reports
//! (`%LOCALAPPDATA%\Birdo VPN\crashes`) and the update-resume record live in
//! the user's profile, which any process of the user can write, and the client
//! that prunes and deletes them runs as an administrator. Deleting
//! `logs\birdo.log.1` BY PATH acts on whatever the user has put on that path
//! by then: a junction on `logs` (or on `BirdoVPN` above it) needs no
//! privilege, and pointed at `\RPC Control` it lets an object-manager symlink
//! name any file on the machine. A check that the path is not a link followed
//! by a delete of the same path is a race the user can win; the retention
//! sweep's truncation was the same, and could empty any old file.
//!
//! THE RULE. Nothing here acts on a path it has only looked at. The file is
//! OPENED without following a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`),
//! a link or a directory is refused, and the handle's final path
//! (`GetFinalPathNameByHandleW`) must be exactly the directory's own: the
//! root as the OS resolves it (folder redirection is the user's to choose and
//! names their own folder) followed by this app's directories, none of which
//! may be redirected, and the name. The delete is then a disposition set on
//! THAT handle (`SetFileInformationByHandle`), the truncate a write through
//! it: whatever the path names by the time the call lands, the object acted on
//! is the one that was checked.
//!
//! Off Windows the client runs as root with its state in root's own home, so
//! the same API keeps the older checks: no symlink anywhere below the root,
//! the file opened with `O_NOFOLLOW` for a truncate, and `unlink` (which never
//! follows the last component) for a delete.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// One of the app's directories: `root` (a folder the OS hands out, such as
/// `%APPDATA%`) and the app's own folders below it.
#[derive(Debug, Clone)]
pub struct OwnedDir {
    root: PathBuf,
    /// The app's folder names under `root`, outermost first.
    rel: Vec<String>,
    dir: PathBuf,
}

impl OwnedDir {
    /// `root` joined with `rel`, each a plain folder name.
    pub fn new(root: impl Into<PathBuf>, rel: &[&str]) -> Self {
        let root = root.into();
        debug_assert!(rel.iter().all(|part| is_plain_name(part)), "{rel:?}");
        let dir = rel.iter().fold(root.clone(), |dir, part| dir.join(part));
        Self {
            root,
            rel: rel.iter().map(|part| part.to_string()).collect(),
            dir,
        }
    }

    /// The directory's path, for listing it and for writers.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `name` in the directory.
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.dir.join(name)
    }

    /// Delete `name`, a regular file directly in this directory, through a
    /// handle that was checked to be exactly that file (see the module docs).
    /// A link, a directory, or a file that resolves anywhere else is refused
    /// with an error and left as it is. `NotFound` when there is none.
    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        imp::remove_file(self, name)
    }

    /// Open `name`, a regular file directly in this directory, for reading
    /// and writing, under the same checks as [`OwnedDir::remove_file`] plus a
    /// hard-link check (a write must not reach a file that shares this one's
    /// data under another name). Never creates it: `NotFound` when there is
    /// none.
    pub fn open_rw(&self, name: &str) -> io::Result<File> {
        imp::open_rw(self, name)
    }

    /// Create `name` as a brand-new regular file (fails if it exists), owner-
    /// only on Unix, for writing. The handle's final path must be this
    /// directory's own, so a directory swapped for a junction mid-call is
    /// caught (MR-1945 H1). Used for the uniquely-named staging files the
    /// atomic writers rename into place.
    pub fn create_new(&self, name: &str) -> io::Result<File> {
        imp::create_new(self, name)
    }

    /// Open `name` for appending, creating it owner-only if absent, with the
    /// link and reparse checks of [`OwnedDir::open_rw`]: a planted symlink or
    /// hard link at the name is refused rather than appended through
    /// (MR-1945 H1). Used by the log writer and the crash-report writer.
    pub fn open_append(&self, name: &str) -> io::Result<File> {
        imp::open_append(self, name)
    }

    /// Rename `from` to `to`, both plain names directly in this directory
    /// (a log rotation, or an atomic write's staging file into place).
    ///
    /// MR-1945 MEDIUM 1: on Windows the rename is performed relative to a
    /// freshly opened, verified handle to this directory (`FileRenameInfo` with
    /// `RootDirectory`), so a junction swapped onto the path between a check and
    /// the rename cannot redirect it to move the file elsewhere (e.g. through
    /// `\RPC Control`). `from` is opened without following a reparse point, and
    /// the directory handle's final path must be this directory's own.
    pub fn rename_within(&self, from: &str, to: &str) -> io::Result<()> {
        check_name(from)?;
        check_name(to)?;
        imp::rename_within(self, from, to)
    }

    /// Hold the directory open for as long as the returned guard lives, so no
    /// unprivileged process can rename or replace it with a junction while the
    /// app runs (MR-1945 H1). The whole chain is verified first: every
    /// component is a real directory, not a reparse point, and the leaf's
    /// final path is this directory's own. Creates the directory if absent.
    pub fn hold_open(&self) -> io::Result<DirGuard> {
        std::fs::create_dir_all(self.path())?;
        imp::hold_open(self)
    }

    /// [`OwnedDir::hold_open`], but only if the directory already exists; `None`
    /// when it does not. Unlike `hold_open` it never CREATES the directory —
    /// used for the logs and crash folders, which must not be brought into
    /// being while the on-device log is switched off (MR-808).
    pub fn hold_open_if_present(&self) -> io::Result<Option<DirGuard>> {
        match std::fs::symlink_metadata(self.path()) {
            Ok(_) => imp::hold_open(self).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// An open handle to an [`OwnedDir`], kept for the process lifetime so the
/// directory cannot be renamed or replaced out from under the elevated app.
/// On Unix it carries the verified directory handle too; dropping it releases
/// the hold.
pub struct DirGuard {
    #[allow(dead_code)]
    handle: File,
}

/// A single path component that names an entry in its directory: no
/// separator, no drive or stream colon, not `.` or `..`.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':'])
}

fn check_name(name: &str) -> io::Result<()> {
    if is_plain_name(name) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a plain file name",
        ))
    }
}

/// The error for a file that is not the app's to touch. Says which name,
/// never the path (the path carries the account's user name).
fn refused(name: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refused to touch {name}: {why}"),
    )
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::utils::win_api::{
        self, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    // winnt.h share-mode bits (std's OpenOptions has no setter for them).
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;

    pub(super) fn remove_file(dir: &OwnedDir, name: &str) -> io::Result<()> {
        let file = open_checked(
            dir,
            name,
            OpenOptions::new().access_mode(DELETE | FILE_READ_ATTRIBUTES),
            false,
        )?;
        win_api::delete_on_handle(&file)
    }

    pub(super) fn open_rw(dir: &OwnedDir, name: &str) -> io::Result<File> {
        open_checked(dir, name, OpenOptions::new().read(true).write(true), true)
    }

    const GENERIC_WRITE: u32 = 0x4000_0000;

    pub(super) fn create_new(dir: &OwnedDir, name: &str) -> io::Result<File> {
        check_name(name)?;
        // DELETE in the access mask so a file that turns out to be in the
        // wrong place (the directory was a junction) can be removed through
        // this very handle, before it is ever written to.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE | DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.join(name))?;
        if let Err(e) = verify(dir, name, &file, true) {
            // Undo the create: it landed somewhere it should not have.
            let _ = win_api::delete_on_handle(&file);
            return Err(e);
        }
        Ok(file)
    }

    pub(super) fn open_append(dir: &OwnedDir, name: &str) -> io::Result<File> {
        // Ensure the file exists in the checked directory WITHOUT writing to
        // it (create_new cleans up a file that lands behind a junction), then
        // open it for appending under the full checks: an existing reparse
        // point or hard link at the name is refused before anything is
        // appended.
        match create_new(dir, name) {
            Ok(_fresh) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        open_checked(dir, name, OpenOptions::new().append(true), true)
    }

    // FILE_LIST_DIRECTORY (0x1): required on the `RootDirectory` handle for
    // `FileRenameInfo` to resolve a relative target name.
    const FILE_LIST_DIRECTORY: u32 = 0x1;

    pub(super) fn hold_open(dir: &OwnedDir) -> io::Result<DirGuard> {
        // No FILE_SHARE_DELETE: while this handle lives, the directory cannot
        // be renamed or deleted, so it cannot be swapped for a junction.
        let handle = open_verified_dir(
            dir,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        Ok(DirGuard { handle })
    }

    /// A handle to this directory, verified to be exactly it: not a reparse
    /// point, a real directory, and resolving to its expected final path. Used
    /// both for the process-lifetime hold and, freshly each time, as the
    /// `RootDirectory` a rename is performed relative to.
    fn open_verified_dir(dir: &OwnedDir, access: u32, share: u32) -> io::Result<File> {
        let handle = OpenOptions::new()
            .access_mode(access)
            .share_mode(share)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.path())?;
        let attributes = handle.metadata()?.file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused("state directory", "it is a link"));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(refused("state directory", "it is not a directory"));
        }
        let actual = win_api::final_path(&handle)?;
        if !win_api::same_path(&actual, &final_dir(dir)?) {
            return Err(refused(
                "state directory",
                "it resolves somewhere unexpected",
            ));
        }
        Ok(handle)
    }

    pub(super) fn rename_within(dir: &OwnedDir, from: &str, to: &str) -> io::Result<()> {
        // The source, opened with DELETE (FileRenameInfo needs it) and the
        // usual reparse/final-path checks; not the single-link check — renaming
        // our own staging or rotated file is fine either way.
        let source = open_checked(
            dir,
            from,
            OpenOptions::new().access_mode(DELETE | FILE_READ_ATTRIBUTES),
            false,
        )?;
        // A fresh, verified handle to the directory; the rename is relative to
        // it, so the path is never re-walked (no junction can redirect it).
        // SHARE_DELETE here so a rename is not blocked by a held dir handle.
        let dir_handle = open_verified_dir(
            dir,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let wide = win_api::wide(std::ffi::OsStr::new(to));
        win_api::rename_by_handle(&source, &dir_handle, &wide)
    }

    /// `write`: the handle will be written through, so the name must be a
    /// single-link ordinary file (a hard link would reach the shared data,
    /// MR-1945 L3). A delete needs no such check — unlinking one name of a
    /// hard-linked file leaves the data under its other names.
    fn open_checked(
        dir: &OwnedDir,
        name: &str,
        opts: &mut OpenOptions,
        write: bool,
    ) -> io::Result<File> {
        check_name(name)?;
        let file = opts
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.join(name))?;
        verify(dir, name, &file, write)?;
        Ok(file)
    }

    /// The checks every opened handle must pass: not a reparse point, not a
    /// directory, resolving to exactly this app directory's own path, and —
    /// for a handle about to be written — a single hard link.
    fn verify(dir: &OwnedDir, name: &str, file: &File, write: bool) -> io::Result<()> {
        let attributes = file.metadata()?.file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused(name, "it is a link"));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(refused(name, "it is a directory"));
        }
        let expected = final_dir(dir)?.join(name);
        let actual = win_api::final_path(file)?;
        if !win_api::same_path(&actual, &expected) {
            return Err(refused(name, "it resolves outside the app's directory"));
        }
        if write && win_api::hard_link_count(file)? != 1 {
            return Err(refused(name, "it is a hard link to another file"));
        }
        Ok(())
    }

    /// Where the directory must really be: the root as the OS resolves it,
    /// then the app's own folder names, which may not be redirected.
    fn final_dir(dir: &OwnedDir) -> io::Result<PathBuf> {
        let root = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir.root)?;
        let mut path = win_api::final_path(&root)?;
        for part in &dir.rel {
            path.push(part);
        }
        Ok(path)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub(super) fn remove_file(dir: &OwnedDir, name: &str) -> io::Result<()> {
        check_name(name)?;
        check_dirs(dir)?;
        let path = dir.join(name);
        if !std::fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(refused(name, "it is not a regular file"));
        }
        std::fs::remove_file(path)
    }

    pub(super) fn open_rw(dir: &OwnedDir, name: &str) -> io::Result<File> {
        check_name(name)?;
        check_dirs(dir)?;
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        // A symlink in the name's place fails the open itself (ELOOP).
        let file = opts.open(dir.join(name))?;
        if !file.metadata()?.is_file() {
            return Err(refused(name, "it is not a regular file"));
        }
        Ok(file)
    }

    pub(super) fn create_new(dir: &OwnedDir, name: &str) -> io::Result<File> {
        check_name(name)?;
        check_dirs(dir)?;
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        opts.open(dir.join(name))
    }

    pub(super) fn open_append(dir: &OwnedDir, name: &str) -> io::Result<File> {
        check_name(name)?;
        check_dirs(dir)?;
        let mut opts = OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW rejects a symlink at the final component (ELOOP);
            // owner-only for a file this call creates.
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(dir.join(name))?;
        if !file.metadata()?.is_file() {
            return Err(refused(name, "it is not a regular file"));
        }
        Ok(file)
    }

    pub(super) fn hold_open(dir: &OwnedDir) -> io::Result<DirGuard> {
        check_dirs(dir)?;
        Ok(DirGuard {
            handle: File::open(dir.path())?,
        })
    }

    pub(super) fn rename_within(dir: &OwnedDir, from: &str, to: &str) -> io::Result<()> {
        // On Unix the client runs as root with its state in root's own home;
        // the chain is checked and the rename's last components are plain names
        // (rename never follows a symlink at the final component).
        check_dirs(dir)?;
        std::fs::rename(dir.join(from), dir.join(to))
    }

    /// Every one of the app's folders below the root is a real directory.
    fn check_dirs(dir: &OwnedDir) -> io::Result<()> {
        let mut at = dir.root.clone();
        for part in &dir.rel {
            at.push(part);
            if !std::fs::symlink_metadata(&at)?.is_dir() {
                return Err(refused(part, "a link where the app's directory should be"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn a_regular_file_is_deleted_and_a_missing_one_is_not_found() {
        let root = tempfile::tempdir().unwrap();
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        std::fs::create_dir_all(logs.path()).unwrap();
        write(&logs.join("birdo.log.1"), "old");
        logs.remove_file("birdo.log.1").unwrap();
        assert!(!logs.join("birdo.log.1").exists());
        assert_eq!(
            logs.remove_file("birdo.log.1").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            logs.open_rw("birdo.log").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn only_plain_names_are_accepted() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &[]);
        write(&root.path().join("x"), "x");
        for bad in ["", ".", "..", "../x", "a/b", r"a\b", "x:stream", "C:x"] {
            assert_eq!(
                dir.remove_file(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad}"
            );
        }
        assert!(root.path().join("x").exists());
    }

    #[test]
    fn a_directory_named_like_the_file_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &[]);
        std::fs::create_dir(root.path().join("birdo.log.1")).unwrap();
        assert!(dir.remove_file("birdo.log.1").is_err());
        assert!(dir.open_rw("birdo.log.1").is_err());
        assert!(root.path().join("birdo.log.1").is_dir());
    }

    /// `cmd /C mklink /J`: a junction needs no privilege, so any process
    /// running as the user can plant one in its own profile.
    #[cfg(windows)]
    pub(crate) fn junction(link: &Path, target: &Path) {
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed: {made:?}");
    }

    /// THE FINDING (MR-1945), at the folder above `logs`: a junction on
    /// `BirdoVPN` makes `BirdoVPN\logs` a real directory somewhere else, so a
    /// check of `logs` alone passes. The handle's final path is not the
    /// app's, so nothing is deleted or opened for a truncate.
    #[cfg(windows)]
    #[test]
    fn a_junction_above_the_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("logs")).unwrap();
        let victim = elsewhere.join("logs").join("birdo.log.1");
        write(&victim, "not the app's");
        junction(&root.path().join("BirdoVPN"), &elsewhere);

        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        assert!(
            logs.join("birdo.log.1").exists(),
            "the path does reach the victim"
        );
        let err = logs.remove_file("birdo.log.1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(logs.open_rw("birdo.log.1").is_err());
        assert!(victim.exists(), "the delete followed the junction");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "not the app's");
    }

    /// The same, on the directory itself.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let victim = elsewhere.join("crash_20260101_000000.txt");
        write(&victim, "not the app's");
        std::fs::create_dir(root.path().join("Birdo VPN")).unwrap();
        junction(&root.path().join("Birdo VPN").join("crashes"), &elsewhere);

        let crashes = OwnedDir::new(root.path(), &["Birdo VPN", "crashes"]);
        assert!(crashes.remove_file("crash_20260101_000000.txt").is_err());
        assert!(victim.exists());
    }

    /// A symlink named like the file is the link, never its target. Needs
    /// the symlink privilege (or Developer Mode): a dev account without it
    /// skips, saying so; CI (an administrator) must not skip.
    #[cfg(windows)]
    #[test]
    fn a_symlinked_file_is_refused_and_its_target_survives() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("precious.txt");
        write(&target, "precious");
        let logs = OwnedDir::new(root.path(), &["logs"]);
        std::fs::create_dir_all(logs.path()).unwrap();
        if let Err(e) = std::os::windows::fs::symlink_file(&target, logs.join("birdo.log.1")) {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI cannot create a symlink ({e}), so this test would test nothing"
            );
            eprintln!("SKIPPED: this account cannot create symlinks ({e})");
            return;
        }
        assert!(logs.remove_file("birdo.log.1").is_err());
        assert!(logs.open_rw("birdo.log.1").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
        assert!(std::fs::symlink_metadata(logs.join("birdo.log.1")).is_ok());
    }

    /// The root itself may be redirected (folder redirection, a junctioned
    /// profile folder): that is the OS's answer for where the user's data
    /// lives, and the app's folders below it are still checked.
    #[cfg(windows)]
    #[test]
    fn a_redirected_root_is_followed() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real-roaming");
        std::fs::create_dir_all(real.join("BirdoVPN").join("logs")).unwrap();
        let roaming = base.path().join("Roaming");
        junction(&roaming, &real);
        let logs = OwnedDir::new(&roaming, &["BirdoVPN", "logs"]);
        write(&logs.join("birdo.log.1"), "old");
        logs.remove_file("birdo.log.1").unwrap();
        assert!(!real
            .join("BirdoVPN")
            .join("logs")
            .join("birdo.log.1")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_below_the_root_or_on_the_file_is_refused_on_unix() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("logs")).unwrap();
        let victim = elsewhere.join("logs").join("birdo.log.1");
        write(&victim, "not the app's");
        std::os::unix::fs::symlink(&elsewhere, root.path().join("BirdoVPN")).unwrap();
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        assert!(logs.remove_file("birdo.log.1").is_err());
        assert!(logs.open_rw("birdo.log.1").is_err());
        assert!(victim.exists());

        let direct = OwnedDir::new(root.path(), &[]);
        std::os::unix::fs::symlink(&victim, root.path().join("birdo.log")).unwrap();
        assert!(direct.remove_file("birdo.log").is_err());
        assert!(direct.open_rw("birdo.log").is_err());
        assert!(direct.open_append("birdo.log").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "not the app's");
    }

    // ── MR-1945 H1: the create/append/truncate/hold path ──────────────────

    #[test]
    fn create_new_makes_a_file_and_refuses_an_existing_one() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &[]);
        let mut f = dir.create_new("settings.json.ab.tmp").unwrap();
        std::io::Write::write_all(&mut f, b"x").unwrap();
        assert!(dir.join("settings.json.ab.tmp").exists());
        assert_eq!(
            dir.create_new("settings.json.ab.tmp").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        // ..and a plain name only.
        assert_eq!(
            dir.create_new("../evil").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn open_append_creates_then_appends() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &[]);
        std::io::Write::write_all(&mut dir.open_append("birdo.log").unwrap(), b"one\n").unwrap();
        std::io::Write::write_all(&mut dir.open_append("birdo.log").unwrap(), b"two\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("birdo.log")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[test]
    fn rename_within_takes_plain_names_only() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &[]);
        write(&dir.join("a.tmp"), "data");
        dir.rename_within("a.tmp", "birdo.log").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("birdo.log")).unwrap(),
            "data"
        );
        assert!(dir.rename_within("birdo.log", "../evil").is_err());
    }

    /// L3: a write (truncate or append) must not reach a file that shares the
    /// leaf's data under another name. `open_rw`/`open_append` reject a hard
    /// link; `remove_file` does not (unlinking one name is harmless).
    #[cfg(windows)]
    #[test]
    fn a_hard_linked_leaf_is_refused_for_writing() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim.txt");
        write(&victim, "precious");
        let dir = OwnedDir::new(root.path(), &[]);
        if std::fs::hard_link(&victim, dir.join("birdo.log")).is_err() {
            eprintln!("SKIPPED: this filesystem has no hard links");
            return;
        }
        assert!(
            dir.open_rw("birdo.log").is_err(),
            "truncate followed a hard link"
        );
        assert!(dir.open_append("birdo.log").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        // Removing one name of a hard link is fine — the data keeps its others.
        dir.remove_file("birdo.log").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    }

    /// THE H1 FINDING, on the config dir: a junction swapped in for the app's
    /// directory makes a create/append/rename act somewhere else. The final-
    /// path check refuses it, so nothing is created or written through it.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_directory_is_refused_for_creating_and_appending() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        junction(&root.path().join("uk.birdo.vpn.desktop"), &elsewhere);

        let config = OwnedDir::new(root.path(), &["uk.birdo.vpn.desktop"]);
        assert!(config.create_new("settings.json.ab.tmp").is_err());
        assert!(config.open_append("birdo.log").is_err());
        // Nothing of ours landed behind the junction.
        assert!(!elsewhere.join("settings.json.ab.tmp").exists());
        assert!(!elsewhere.join("birdo.log").exists());
    }

    /// MR-1945 MEDIUM 1: a rename whose directory is a junction is refused —
    /// the directory handle it would rename relative to does not resolve to the
    /// expected path — so a planted junction (the "unheld dir, swap it in"
    /// attack) cannot move the file through, say, `\RPC Control`.
    #[cfg(windows)]
    #[test]
    fn rename_within_is_refused_when_the_directory_is_a_junction() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        // A real staging file reachable through the junction, to prove the
        // refusal is the directory check, not a missing source.
        write(&elsewhere.join("settings.json.ab.tmp"), "staged");
        junction(&root.path().join("uk.birdo.vpn.desktop"), &elsewhere);

        let config = OwnedDir::new(root.path(), &["uk.birdo.vpn.desktop"]);
        assert!(config
            .rename_within("settings.json.ab.tmp", "settings.json")
            .is_err());
        assert!(
            !elsewhere.join("settings.json").exists(),
            "renamed through the junction"
        );
    }

    /// The whole atomic replace (create new + rename within) round-trips in a
    /// real directory.
    #[test]
    fn create_then_rename_replaces_atomically() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &[]);
        write(&dir.join("settings.json"), "old");
        {
            use std::io::Write;
            let mut f = dir.create_new("settings.json.tmp").unwrap();
            f.write_all(b"new").unwrap();
        }
        dir.rename_within("settings.json.tmp", "settings.json")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("settings.json")).unwrap(),
            "new"
        );
        assert!(!dir.join("settings.json.tmp").exists());
    }

    /// `hold_open` refuses a junctioned directory (so the caller never trusts
    /// it) and accepts a real one.
    #[cfg(windows)]
    #[test]
    fn hold_open_refuses_a_junctioned_directory() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(root.path().join("BirdoVPN")).unwrap();
        // A real one holds.
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        let _guard = logs.hold_open().unwrap();
        // A junction on the leaf is refused.
        std::fs::remove_dir(logs.path()).unwrap();
        junction(logs.path(), &elsewhere);
        assert!(OwnedDir::new(root.path(), &["BirdoVPN", "logs"])
            .hold_open()
            .is_err());
    }
}
