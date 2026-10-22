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
    /// app runs (MR-1945 H1). Creates the directory if absent.
    ///
    /// R5 (#287 follow-up): never `create_dir_all` by path. On Windows each of
    /// the app's folders is created only inside its parent while that parent
    /// is held open (no `FILE_SHARE_DELETE`, so it cannot be renamed or
    /// swapped for a junction meanwhile), and is then opened without
    /// following a reparse point and verified — a real directory, not a link,
    /// at exactly the expected final path — before the next one is created in
    /// it. A junction anywhere in the chain is refused BEFORE anything is
    /// created behind it, so a user cannot steer where the elevated app makes
    /// a directory.
    pub fn hold_open(&self) -> io::Result<DirGuard> {
        imp::hold_open(self, true)
    }

    /// [`OwnedDir::hold_open`], but only if the directory already exists; `None`
    /// when it does not. Unlike `hold_open` it never CREATES anything —
    /// used for the logs and crash folders, which must not be brought into
    /// being while the on-device log is switched off (MR-808).
    pub fn hold_open_if_present(&self) -> io::Result<Option<DirGuard>> {
        match std::fs::symlink_metadata(self.path()) {
            Ok(_) => imp::hold_open(self, false).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Make sure the directory exists and is held for the rest of the
    /// process (R5): [`OwnedDir::hold_open`] the first time, then nothing —
    /// a held directory cannot have been replaced since. The writers call
    /// this instead of `create_dir_all` before they create a file in it, so a
    /// directory that did not exist at start-up (the logs, switched on later)
    /// is created verified and held too. An error means the directory could
    /// not be verified: the write must not go ahead.
    pub fn ensure_held(&self) -> io::Result<()> {
        held::ensure(self)
    }

    /// [`OwnedDir::ensure_held`] for a caller that is never inside the log
    /// writer or the panic hook: it WAITS for the held set when another
    /// thread has it, where `ensure_held` verifies the directory and lets it
    /// go. For a directory nothing else holds (MR-2049: the WebView2 user
    /// data folder, whose one hold is `webview2::create_environment`), a
    /// writer holding the set at that moment left it unheld for the run.
    #[cfg_attr(not(windows), allow(dead_code))] // its one caller is Windows-only
    pub fn keep_held(&self) -> io::Result<()> {
        held::keep_waiting(self)
    }

    /// Delete `name`, a real directory directly in this one, with everything
    /// in it (R2: the updater's `updates\`). The directory is opened without
    /// following a reparse point and must resolve to exactly this one's
    /// `name`; the removal then never follows a link inside it either
    /// (`std::fs::remove_dir_all` opens each entry without following one, and
    /// deletes a link as a link). `NotFound` when there is none.
    #[cfg_attr(not(windows), allow(dead_code))] // its callers are Windows-only
    pub fn remove_dir_tree(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        imp::verify_subdir(self, name)?;
        std::fs::remove_dir_all(self.join(name))
    }
}

/// The directories this process holds open for its lifetime (R5): the ones
/// `file_log::hold_app_dirs` holds at start, and any a writer created later.
pub(crate) mod held {
    use super::*;
    use std::sync::{Mutex, TryLockError};

    /// Held directories, by path.
    pub(crate) type Set = Mutex<Vec<(PathBuf, DirGuard)>>;

    static HELD: Set = Mutex::new(Vec::new());

    pub(super) fn ensure(dir: &OwnedDir) -> io::Result<()> {
        // A test's temp folders are verified the same way but not kept: kept,
        // they could not be removed (or swapped by the test's next step) for
        // the rest of the test binary. `ensure_in` itself is tested.
        if cfg!(test) {
            return dir.hold_open().map(drop);
        }
        ensure_in(&HELD, dir)
    }

    pub(crate) fn ensure_in(set: &Set, dir: &OwnedDir) -> io::Result<()> {
        // `try_lock`: this runs inside the log writer, which the panic hook
        // reaches; a panic that struck while this thread held the lock must
        // not deadlock it. Contended or not, the directory is still verified
        // (and held for the call's duration); it is just not kept.
        let held = match set.try_lock() {
            Ok(held) => held,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return dir.hold_open().map(drop),
        };
        keep_unless_held(held, dir)
    }

    /// `OwnedDir::keep_held`: [`ensure_in`], waiting for the set instead
    /// of skipping the keep when another thread has it.
    #[cfg_attr(not(windows), allow(dead_code))] // `keep_held`'s one caller is Windows-only
    pub(super) fn keep_waiting(dir: &OwnedDir) -> io::Result<()> {
        if cfg!(test) {
            return dir.hold_open().map(drop);
        }
        wait_and_ensure_in(&HELD, dir)
    }

    /// [`ensure_in`] for a caller outside the log writer and the panic hook.
    /// Safe to wait: the set is only ever held for one directory's
    /// verify-and-open, and nothing done under it waits for it again (a line
    /// logged meanwhile reaches the writer's `ensure_in`, which does not
    /// wait).
    pub(crate) fn wait_and_ensure_in(set: &Set, dir: &OwnedDir) -> io::Result<()> {
        keep_unless_held(set.lock().unwrap_or_else(|e| e.into_inner()), dir)
    }

    fn keep_unless_held(
        mut held: std::sync::MutexGuard<'_, Vec<(PathBuf, DirGuard)>>,
        dir: &OwnedDir,
    ) -> io::Result<()> {
        if held.iter().any(|(path, _)| path == dir.path()) {
            return Ok(());
        }
        let guard = dir.hold_open()?;
        held.push((dir.path().to_path_buf(), guard));
        Ok(())
    }

    /// Keep `guard` (for `dir`) for the process lifetime.
    pub(super) fn keep(dir: &OwnedDir, guard: DirGuard) {
        if cfg!(test) {
            return;
        }
        let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
        held.push((dir.path().to_path_buf(), guard));
    }
}

impl OwnedDir {
    /// [`OwnedDir::hold_open_if_present`], kept for the process lifetime
    /// (`file_log::hold_app_dirs`); `false` when there is no directory.
    pub fn keep_held_if_present(&self) -> io::Result<bool> {
        Ok(match self.hold_open_if_present()? {
            Some(guard) => {
                held::keep(self, guard);
                true
            }
            None => false,
        })
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

    /// No FILE_SHARE_DELETE: while such a handle lives, the directory cannot
    /// be renamed or deleted, so it cannot be swapped for a junction.
    const HOLD_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

    /// What a hold opens the directory for. FILE_LIST_DIRECTORY is what makes
    /// it a hold: NTFS applies share modes only to opens that ask for data or
    /// DELETE access, so a handle with FILE_READ_ATTRIBUTES alone (what #287
    /// held with) blocked nothing, and the "held" directory could still be
    /// renamed and replaced (R5; `a_held_directory_cannot_be_renamed`).
    const HOLD_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES;

    /// See [`OwnedDir::hold_open`]. `create`: make the missing folders (each
    /// inside its held, verified parent); otherwise a missing one is
    /// `NotFound`.
    pub(super) fn hold_open(dir: &OwnedDir, create: bool) -> io::Result<DirGuard> {
        if dir.rel.is_empty() {
            // The root alone is the OS's (or a test's) own folder.
            if create {
                std::fs::create_dir_all(&dir.root)?;
            }
            let handle = open_verified_dir(dir, HOLD_ACCESS, HOLD_SHARE)?;
            return Ok(DirGuard { handle });
        }
        // The root as the OS resolves it: folder redirection is the user's own
        // choice, so where it points is theirs to decide (and an OS folder
        // that is missing is made, as it always was). Opened for its final
        // path only, not held: the app's folders below it are.
        if create && !dir.root.exists() {
            std::fs::create_dir_all(&dir.root)?;
        }
        let root = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir.root)?;
        let mut expected = win_api::final_path(&root)?;
        drop(root);
        let mut path = dir.root.clone();
        // Every folder of the chain stays held until the leaf is verified.
        let mut chain: Vec<File> = Vec::with_capacity(dir.rel.len());
        for part in &dir.rel {
            path.push(part);
            expected.push(part);
            if create {
                match std::fs::create_dir(&path) {
                    Ok(()) => {}
                    // Whatever is there — a junction, a file, a squatted
                    // folder — is judged by the open below, not trusted.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            chain.push(open_dir_at(&path, &expected, HOLD_ACCESS, HOLD_SHARE)?);
        }
        let handle = chain.pop().expect("the chain has the leaf");
        Ok(DirGuard { handle })
    }

    /// `name` in `dir` is a real directory (not a link) at exactly its
    /// expected final path (R2).
    pub(super) fn verify_subdir(dir: &OwnedDir, name: &str) -> io::Result<()> {
        let expected = final_dir(dir)?.join(name);
        open_dir_at(
            &dir.join(name),
            &expected,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
        .map(drop)
    }

    /// A handle to this directory, verified to be exactly it: not a reparse
    /// point, a real directory, and resolving to its expected final path. Used
    /// for the hold of a root-only directory and, freshly each time, as the
    /// `RootDirectory` a rename is performed relative to.
    fn open_verified_dir(dir: &OwnedDir, access: u32, share: u32) -> io::Result<File> {
        open_dir_at(dir.path(), &final_dir(dir)?, access, share)
    }

    /// The directory at `path`, opened without following a reparse point and
    /// refused unless it is a real directory whose final path is `expected`.
    fn open_dir_at(path: &Path, expected: &Path, access: u32, share: u32) -> io::Result<File> {
        let handle = OpenOptions::new()
            .access_mode(access)
            .share_mode(share)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let attributes = handle.metadata()?.file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused("state directory", "it is a link"));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(refused("state directory", "it is not a directory"));
        }
        let actual = win_api::final_path(&handle)?;
        if !win_api::same_path(&actual, expected) {
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

    pub(super) fn hold_open(dir: &OwnedDir, create: bool) -> io::Result<DirGuard> {
        // Root's own home (the client runs as root here): the chain is checked
        // for links after creating it, and a link anywhere is refused.
        if create {
            std::fs::create_dir_all(&dir.root)?;
            // MR-2089 (review of #327): the app's own folders are owner-only
            // (0700) from creation, never what the umask leaves: under a
            // umask of 002 root made the config folder 0775, which the
            // config folder's write check then refused for good. The OS
            // folders above them (`root`) keep their usual mode: one made
            // 0700 in a user's HOME would lock that user out of it.
            let mut at = dir.root.clone();
            for part in &dir.rel {
                at.push(part);
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                match builder.create(&at) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
        }
        check_dirs(dir)?;
        Ok(DirGuard {
            handle: File::open(dir.path())?,
        })
    }

    pub(super) fn verify_subdir(dir: &OwnedDir, name: &str) -> io::Result<()> {
        check_dirs(dir)?;
        if std::fs::symlink_metadata(dir.join(name))?.is_dir() {
            Ok(())
        } else {
            Err(refused(name, "not a real directory"))
        }
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

    /// MR-2089 (review of #327): the app's own folders are made 0700, not
    /// what the umask leaves (0755 under 022, 0775 under 002), and the OS
    /// folder above them keeps its mode.
    #[cfg(unix)]
    #[test]
    fn the_apps_folders_are_made_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("config");
        let config = OwnedDir::new(&base, &["uk.birdo.vpn.desktop"]);
        let logs = OwnedDir::new(&base, &["BirdoVPN", "logs"]);
        config.ensure_held().unwrap();
        logs.ensure_held().unwrap();
        let birdo = base.join("BirdoVPN");
        for dir in [config.path(), logs.path(), birdo.as_path()] {
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        // Made as `create_dir_all` makes any folder: the umask's choice.
        let plain = root.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        assert_eq!(mode(&base), mode(&plain), "the OS folder is not the app's");
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

    /// R5: a hold is a hold. While the guard lives, the directory cannot be
    /// renamed (so not swapped for a junction either); #287's handle, opened
    /// for FILE_READ_ATTRIBUTES alone, is outside NTFS's share checks and let
    /// this rename through.
    #[cfg(windows)]
    #[test]
    fn a_held_directory_cannot_be_renamed() {
        let root = tempfile::tempdir().unwrap();
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        let guard = logs.hold_open().unwrap();
        let moved = root.path().join("BirdoVPN").join("moved");
        let err = std::fs::rename(logs.path(), &moved).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(32), "{err}"); // ERROR_SHARING_VIOLATION
        assert!(logs.path().is_dir() && !moved.exists());
        // The app's own work inside it is unaffected.
        std::io::Write::write_all(&mut logs.create_new("a.tmp").unwrap(), b"x").unwrap();
        logs.rename_within("a.tmp", "birdo.log").unwrap();
        logs.remove_file("birdo.log").unwrap();
        drop(guard);
        std::fs::rename(logs.path(), &moved).unwrap();
    }

    /// D6c BLOCKER (the mechanism behind the CI failure): while a directory is
    /// held open without `FILE_SHARE_DELETE` — as `hold_app_dirs` holds the
    /// per-user dirs — neither it nor the open files inside it can be deleted.
    /// So the uninstaller's `--with-app-data` sweep MUST run before those holds
    /// are taken (see `main.rs`), or it deletes nothing. This reproduces the
    /// "…\BirdoVPN\logs survived" failure and confirms dropping the hold frees
    /// the delete.
    #[cfg(windows)]
    #[test]
    fn a_held_directory_and_its_open_file_cannot_be_deleted() {
        let root = tempfile::tempdir().unwrap();
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        let guard = logs.hold_open().unwrap();
        // An open log file inside the held directory, as the file logger keeps.
        let mut f = logs.open_append("birdo.log").unwrap();
        std::io::Write::write_all(&mut f, b"x").unwrap();
        // While held, the directory cannot be removed (SHARING_VIOLATION).
        assert!(
            std::fs::remove_dir_all(logs.path()).is_err(),
            "a held directory was deleted"
        );
        // Release the hold and the open file: now it deletes.
        drop(f);
        drop(guard);
        std::fs::remove_dir_all(logs.path()).unwrap();
        assert!(!logs.path().exists());
    }

    /// D6c: the MS-FSA rule the design relies on — while a directory is held
    /// open, its PARENT (and any ancestor) cannot be renamed either, so the
    /// path to the held directory cannot be swapped out from under it between a
    /// check and a by-path write inside it.
    #[cfg(windows)]
    #[test]
    fn a_held_directorys_parent_cannot_be_renamed() {
        let root = tempfile::tempdir().unwrap();
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        let guard = logs.hold_open().unwrap();
        let parent = root.path().join("BirdoVPN");
        // ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32): either way
        // the parent is not moved while a descendant is held.
        let err = std::fs::rename(&parent, root.path().join("moved")).unwrap_err();
        assert!(matches!(err.raw_os_error(), Some(5) | Some(32)), "{err}");
        assert!(parent.is_dir() && !root.path().join("moved").exists());
        drop(guard);
        std::fs::rename(&parent, root.path().join("moved")).unwrap();
    }

    /// R5, THE FINDING: `create_dir_all` by path, with a junction planted on
    /// a parent (`BirdoVPN` -> somewhere else), made `logs` wherever the
    /// junction pointed before anything checked it. Now the junction is
    /// refused before anything is created behind it.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_parent_is_refused_before_anything_is_created_behind_it() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        junction(&root.path().join("BirdoVPN"), &elsewhere);

        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        assert!(logs.hold_open().is_err());
        assert!(logs.ensure_held().is_err());
        assert!(
            !elsewhere.join("logs").exists(),
            "a directory was created behind the junction"
        );
        // Nor is anything created through it by a writer that ensures first.
        assert!(logs
            .ensure_held()
            .and_then(|()| logs.create_new("birdo.log"))
            .is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// The same with the junction on the leaf's own name: refused, and the
    /// target is not entered.
    #[cfg(windows)]
    #[test]
    fn a_junction_on_the_leaf_is_refused_by_ensure_held() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::create_dir(root.path().join("BirdoVPN")).unwrap();
        junction(&root.path().join("BirdoVPN").join("logs"), &elsewhere);
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        assert!(logs.ensure_held().is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// `ensure_held` creates a missing chain, verified, and keeps it held: a
    /// second call is a no-op and the directory stays unrenameable. (The
    /// process-wide set, in a set of the test's own.)
    #[cfg(windows)]
    #[test]
    fn ensure_held_creates_the_chain_and_keeps_it_held() {
        let root = tempfile::tempdir().unwrap();
        let set: held::Set = std::sync::Mutex::new(Vec::new());
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        held::ensure_in(&set, &logs).unwrap();
        assert!(logs.path().is_dir());
        held::ensure_in(&set, &logs).unwrap();
        assert_eq!(set.lock().unwrap().len(), 1);
        assert!(std::fs::rename(logs.path(), root.path().join("moved")).is_err());
        // A refused one is not kept.
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        junction(&root.path().join("planted"), &elsewhere);
        assert!(held::ensure_in(&set, &OwnedDir::new(root.path(), &["planted", "x"])).is_err());
        assert_eq!(set.lock().unwrap().len(), 1);
        drop(set);
        std::fs::rename(logs.path(), root.path().join("moved")).unwrap();
    }

    /// MR-2049 (review of #335): `keep_held` keeps the directory even when
    /// another thread has the held set at that moment — a writer's
    /// `ensure_held` mid-call. `ensure_in` verifies and lets go then (right
    /// for the log writer, which the panic hook reaches); for the WebView2
    /// user data folder, which nothing else holds, that cost the hold for
    /// the whole run. (The process-wide set, in a set of the test's own.)
    #[test]
    fn a_kept_hold_waits_for_a_held_set_another_thread_has() {
        let root = tempfile::tempdir().unwrap();
        let set: held::Set = std::sync::Mutex::new(Vec::new());
        let user_data = OwnedDir::new(root.path(), &["uk.birdo.vpn.desktop"]);
        let writer = set.lock().unwrap();
        std::thread::scope(|s| {
            let keeper = s.spawn(|| held::wait_and_ensure_in(&set, &user_data));
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !keeper.is_finished(),
                "it did not wait for the set: the directory was verified and let go"
            );
            drop(writer);
            keeper.join().unwrap().unwrap();
        });
        let held = set.lock().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].0, user_data.path());
    }

    /// `hold_open_if_present` never creates: not the leaf, not a parent.
    #[test]
    fn hold_open_if_present_creates_nothing() {
        let root = tempfile::tempdir().unwrap();
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        assert!(logs.hold_open_if_present().unwrap().is_none());
        assert!(!logs.keep_held_if_present().unwrap());
        assert!(!root.path().join("BirdoVPN").exists());
    }

    /// R2: `remove_dir_tree` empties and removes a real subdirectory, and
    /// refuses one that is a junction, leaving its target's contents alone.
    #[cfg(windows)]
    #[test]
    fn remove_dir_tree_removes_a_real_folder_and_refuses_a_junction() {
        let root = tempfile::tempdir().unwrap();
        let dir = OwnedDir::new(root.path(), &["BirdoVPN"]);
        let updates = dir.join("updates");
        std::fs::create_dir_all(updates.join("BirdoVPN-1.4.48-updater-x")).unwrap();
        write(
            &updates
                .join("BirdoVPN-1.4.48-updater-x")
                .join("installer.exe"),
            "MZ",
        );
        dir.remove_dir_tree("updates").unwrap();
        assert!(!updates.exists());
        assert_eq!(
            dir.remove_dir_tree("updates").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        let victim = root.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        write(&victim.join("precious.txt"), "keep");
        junction(&updates, &victim);
        assert!(dir.remove_dir_tree("updates").is_err());
        assert_eq!(
            std::fs::read_to_string(victim.join("precious.txt")).unwrap(),
            "keep"
        );
        assert!(dir.remove_dir_tree("../victim").is_err());
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
        // A real one holds (and, held, cannot be removed: R5).
        let logs = OwnedDir::new(root.path(), &["BirdoVPN", "logs"]);
        let guard = logs.hold_open().unwrap();
        assert!(std::fs::remove_dir(logs.path()).is_err());
        drop(guard);
        // A junction on the leaf is refused.
        std::fs::remove_dir(logs.path()).unwrap();
        junction(logs.path(), &elsewhere);
        assert!(OwnedDir::new(root.path(), &["BirdoVPN", "logs"])
            .hold_open()
            .is_err());
    }
}
