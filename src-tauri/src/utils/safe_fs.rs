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
    /// and writing, under the same checks as [`OwnedDir::remove_file`]. Never
    /// creates it: `NotFound` when there is none.
    pub fn open_rw(&self, name: &str) -> io::Result<File> {
        imp::open_rw(self, name)
    }
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

    pub(super) fn remove_file(dir: &OwnedDir, name: &str) -> io::Result<()> {
        let file = open_checked(
            dir,
            name,
            OpenOptions::new().access_mode(DELETE | FILE_READ_ATTRIBUTES),
        )?;
        win_api::delete_on_handle(&file)
    }

    pub(super) fn open_rw(dir: &OwnedDir, name: &str) -> io::Result<File> {
        open_checked(dir, name, OpenOptions::new().read(true).write(true))
    }

    fn open_checked(dir: &OwnedDir, name: &str, opts: &mut OpenOptions) -> io::Result<File> {
        check_name(name)?;
        let file = opts
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.join(name))?;
        let attributes = file.metadata()?.file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused(name, "it is a link"));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(refused(name, "it is a directory"));
        }
        let expected = final_dir(dir)?.join(name);
        let actual = win_api::final_path(&file)?;
        if !win_api::same_path(&actual, &expected) {
            return Err(refused(name, "it resolves outside the app's directory"));
        }
        Ok(file)
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
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "not the app's");
    }
}
