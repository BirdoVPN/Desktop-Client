//! `%ProgramData%\BirdoVPN`: the directory only an elevated process can read
//! or write (MR-1721, MR-1722). Windows only.
//!
//! WHY IT EXISTS. On Windows the client runs elevated (`requireAdministrator`,
//! app.manifest), but `%APPDATA%` belongs to the signed-in user: any process
//! of theirs, at medium integrity and with no elevation, can read and replace
//! what is there. The key that signs settings.json sat beside it there (and in
//! the user's Credential Manager vault, which such a process reads just as
//! easily), so it could re-sign settings.json with the kill switch or lockdown
//! off. The DNS-restore journal, which tells the elevated client which routes
//! to delete and which resolvers to put on which adapter, sat there unsigned.
//! The updater's installer was written to the user's `%TEMP%` and launched
//! elevated from there.
//!
//! WHAT IT IS. Owned by Administrators, with a protected DACL that grants full
//! control to SYSTEM and Administrators only and nothing inherited from
//! ProgramData. A medium-integrity process carries Administrators as
//! deny-only, so it matches no grant. The DACL also holds an OWNER RIGHTS ACE
//! (S-1-3-4) worth READ_CONTROL alone, inherited by everything created in it:
//! under the non-default "default owner for objects created by members of the
//! Administrators group: object creator" policy a file made here would be
//! owned by the user, and an owner's implicit WRITE_DAC would let their
//! unelevated processes grant themselves access. OWNER RIGHTS replaces those
//! implicit rights.
//!
//! SQUATTING. ProgramData lets every user create a folder in it, so
//! `BirdoVPN` may already exist, made by someone else, or be a junction to a
//! folder the user can write, or a file. It is opened without following a
//! reparse point and its owner and every ACE are checked through that handle;
//! anything that is not exactly an admin-only folder is moved aside (never
//! read, never deleted: it is evidence) and a fresh one is created with its
//! security descriptor in the same call, so it never exists with an inherited
//! ACL. Once it is admin-only, a user can neither rename nor replace it: that
//! takes DELETE on it or FILE_DELETE_CHILD on ProgramData, which users do not
//! have.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsWellKnownSid,
    WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, WELL_KNOWN_SID_TYPE,
};

use super::win_api::{
    self, SecurityDescriptor, ERROR_ALREADY_EXISTS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, READ_CONTROL,
};

/// The directory's name under ProgramData.
pub const DIR_NAME: &str = "BirdoVPN";

/// Owner Administrators; a protected DACL: SYSTEM and Administrators full
/// control, OWNER RIGHTS read-permissions only, all inherited by files and
/// folders created inside.
const SDDL: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)";

/// How often a squatted or racing directory is moved aside before giving up.
const ATTEMPTS: usize = 3;

/// `%ProgramData%\BirdoVPN`, admin-only, created or repaired on first use and
/// remembered for the life of the process once verified. An error while this
/// process is not elevated: it can neither create nor read the directory, and
/// nothing is attempted.
pub fn ensure() -> io::Result<PathBuf> {
    static VERIFIED: OnceLock<PathBuf> = OnceLock::new();
    if let Some(dir) = VERIFIED.get() {
        return Ok(dir.clone());
    }
    if !super::elevation::is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the admin-only state directory needs an elevated process",
        ));
    }
    let dir = ensure_in(&win_api::program_data()?)?;
    Ok(VERIFIED.get_or_init(|| dir).clone())
}

/// [`ensure`] under `base` (ProgramData in the app; a temp dir in tests).
pub fn ensure_in(base: &Path) -> io::Result<PathBuf> {
    let dir = base.join(DIR_NAME);
    for _ in 0..ATTEMPTS {
        match inspect(&dir)? {
            State::AdminOnly => return Ok(dir),
            State::Missing => match create(&dir) {
                // Verified on the next pass, like anything found there.
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS) => {}
                Err(e) => return Err(e),
            },
            State::Untrusted => set_aside(&dir)?,
        }
    }
    Err(io::Error::other(
        "the admin-only state directory kept being replaced",
    ))
}

/// A fresh, empty `updates` folder in the admin-only directory, for the
/// installer the updater writes and launches elevated (MR-1722). Whatever an
/// earlier update left there (the plugin keeps the installer) is removed
/// first. Created with no descriptor of its own: it inherits the admin-only
/// DACL, as everything the updater then creates in it does.
pub fn fresh_updates_dir() -> io::Result<PathBuf> {
    fresh_updates_dir_in(&ensure()?)
}

/// [`fresh_updates_dir`] in the admin-only directory `admin_only`.
fn fresh_updates_dir_in(admin_only: &Path) -> io::Result<PathBuf> {
    let dir = admin_only.join("updates");
    // `remove_dir_all` deletes through handles and never follows a link; and
    // only an administrator could have put anything here.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The signed-in user's SID (`S-1-5-21-…`), from this process's token: the
/// per-user name of a file in the shared admin-only directory.
pub fn current_user_sid() -> io::Result<String> {
    static SID: OnceLock<String> = OnceLock::new();
    if let Some(sid) = SID.get() {
        return Ok(sid.clone());
    }
    let sid = read_user_sid()?;
    Ok(SID.get_or_init(|| sid).clone())
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Missing,
    AdminOnly,
    /// Exists and is not exactly what [`create`] makes: never used.
    Untrusted,
}

fn inspect(dir: &Path) -> io::Result<State> {
    let handle = match OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)
    {
        Ok(handle) => handle,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(State::Missing),
        // A DACL that keeps even an administrator from reading it is not one
        // this app wrote.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(State::Untrusted),
        Err(e) => return Err(e),
    };
    let attributes = handle.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Ok(State::Untrusted);
    }
    let security = Security::of(&handle)?;
    Ok(if security.is_admin_only() {
        State::AdminOnly
    } else {
        State::Untrusted
    })
}

fn create(dir: &Path) -> io::Result<()> {
    win_api::create_directory(dir, &SecurityDescriptor::from_sddl(SDDL)?)
}

/// Move what is at `dir` out of the way, keeping it: `BirdoVPN.untrusted-<ms>`.
/// A junction is renamed itself, not its target.
fn set_aside(dir: &Path) -> io::Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let aside = dir.with_file_name(format!("{DIR_NAME}.untrusted-{stamp}"));
    tracing::warn!(
        "%ProgramData%\\{DIR_NAME} was not an admin-only folder — moved aside, not used"
    );
    match std::fs::rename(dir, aside) {
        Ok(()) => Ok(()),
        // Someone else moved it first; the next pass sees what is there now.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// An object's owner and DACL, read through an open handle.
pub struct Security(Vec<u64>);

impl Security {
    /// `file` must be open with READ_CONTROL.
    pub fn of(file: &File) -> io::Result<Self> {
        let handle = HANDLE(file.as_raw_handle());
        let wanted = (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0;
        let mut needed = 0u32;
        // SAFETY: a size probe — no buffer, length 0; `needed` is written.
        let _ = unsafe { GetKernelObjectSecurity(handle, wanted, None, 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64s, so the self-relative descriptor is suitably aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` is writable for `buf.len() * 8` bytes, at least
        // `needed`; `handle` is open for as long as `file` lives.
        unsafe {
            GetKernelObjectSecurity(
                handle,
                wanted,
                Some(PSECURITY_DESCRIPTOR(buf.as_mut_ptr().cast())),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        }
        .map_err(|_| io::Error::last_os_error())?;
        Ok(Self(buf))
    }

    fn descriptor(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(self.0.as_ptr() as *mut c_void)
    }

    /// Owned by SYSTEM or Administrators, and a DACL with no grant to anyone
    /// else (OWNER RIGHTS limited to READ_CONTROL). An absent or NULL DACL —
    /// full access for everyone — is not admin-only.
    pub fn is_admin_only(&self) -> bool {
        self.owner_is_admin()
            && self
                .allowed_aces()
                .is_some_and(|aces| aces.iter().all(|&(sid, mask)| is_admin_grant(sid, mask)))
    }

    /// Every SID the DACL grants any access to, in string form (`S-1-5-18`);
    /// an ACE of a type this does not read is listed as `"?"`. `None` for an
    /// absent or NULL DACL, which grants everyone everything. (For tests:
    /// the app decides with [`Security::is_admin_only`].)
    #[cfg(test)]
    pub fn granted_sids(&self) -> Option<Vec<String>> {
        self.allowed_aces().map(|aces| {
            aces.iter()
                .map(|&(sid, _)| {
                    if sid.0.is_null() {
                        "?".to_string()
                    } else {
                        // SAFETY: a SID inside this descriptor's DACL.
                        unsafe { sid_string(sid) }
                    }
                })
                .collect()
        })
    }

    fn owner_is_admin(&self) -> bool {
        let mut owner = PSID::default();
        let mut defaulted = windows::core::BOOL::default();
        // SAFETY: the descriptor is the self-relative one in `self.0`; `owner`
        // points into it and is only read while `self` lives.
        let read =
            unsafe { GetSecurityDescriptorOwner(self.descriptor(), &mut owner, &mut defaulted) };
        read.is_ok()
            && !owner.0.is_null()
            && (is_sid(owner, WinBuiltinAdministratorsSid) || is_sid(owner, WinLocalSystemSid))
    }

    /// Every ACE of the DACL as `(sid, mask)`, with a deny ACE left out (it
    /// grants nothing) and an ACE of any other type reported as a grant to
    /// nobody we know, so it fails the checks. `None` for an absent or NULL
    /// DACL.
    fn allowed_aces(&self) -> Option<Vec<(PSID, u32)>> {
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;
        let mut present = windows::core::BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = windows::core::BOOL::default();
        // SAFETY: as in `owner_is_admin`; `dacl` points into `self.0`.
        let read = unsafe {
            GetSecurityDescriptorDacl(self.descriptor(), &mut present, &mut dacl, &mut defaulted)
        };
        if read.is_err() || !present.as_bool() || dacl.is_null() {
            return None;
        }
        // SAFETY: a present, non-NULL DACL inside the descriptor.
        let count = unsafe { (*dacl).AceCount };
        let mut aces = Vec::with_capacity(count as usize);
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` < AceCount; `ace` points into the DACL.
            if unsafe { windows::Win32::Security::GetAce(dacl, index, &mut ace) }.is_err() {
                return None;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { *(ace as *const ACE_HEADER) };
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => {
                    // SAFETY: the header says this is an ACCESS_ALLOWED_ACE,
                    // whose SID starts at SidStart.
                    let allowed = ace as *const ACCESS_ALLOWED_ACE;
                    let (mask, sid) = unsafe {
                        (
                            (*allowed).Mask,
                            PSID(std::ptr::addr_of!((*allowed).SidStart) as *mut c_void),
                        )
                    };
                    aces.push((sid, mask));
                }
                ACCESS_DENIED_ACE_TYPE => {}
                _ => aces.push((PSID::default(), u32::MAX)),
            }
        }
        Some(aces)
    }
}

fn is_sid(sid: PSID, kind: WELL_KNOWN_SID_TYPE) -> bool {
    // SAFETY: a valid SID pointer (or null, which the caller rules out).
    !sid.0.is_null() && unsafe { IsWellKnownSid(sid, kind) }.as_bool()
}

/// SYSTEM and Administrators with any rights; OWNER RIGHTS with at most
/// READ_CONTROL. Nothing else.
fn is_admin_grant(sid: PSID, mask: u32) -> bool {
    is_sid(sid, WinLocalSystemSid)
        || is_sid(sid, WinBuiltinAdministratorsSid)
        || (is_sid(sid, WinCreatorOwnerRightsSid) && mask & !READ_CONTROL == 0)
}

fn read_user_sid() -> io::Result<String> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle needs no closing; the token handle is closed
    // below on every path.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|_| io::Error::last_os_error())?;
    let mut needed = 0u32;
    // SAFETY: a size probe.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` is writable for at least `needed` bytes and aligned for
    // TOKEN_USER.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    // SAFETY: opened above, closed once.
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
    read.map_err(|_| io::Error::other("could not read the process token's user"))?;
    // SAFETY: GetTokenInformation(TokenUser) filled a TOKEN_USER whose SID
    // points into `buf`, which is still alive.
    Ok(unsafe { sid_string((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid) })
}

/// The string form of the binary SID at `sid`.
///
/// # Safety
/// `sid` must point at a valid SID: a revision, a sub-authority count, a
/// 6-byte authority, then that many little-endian u32 sub-authorities.
unsafe fn sid_string(sid: PSID) -> String {
    let count = *(sid.0 as *const u8).add(1) as usize;
    format_sid(std::slice::from_raw_parts(
        sid.0 as *const u8,
        8 + 4 * count,
    ))
}

/// A binary SID in its string form, `S-<revision>-<authority>-<sub>…`.
fn format_sid(bytes: &[u8]) -> String {
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut out = format!("S-{}-{}", bytes[0], authority);
    for sub in bytes[8..].chunks_exact(4) {
        out.push_str(&format!(
            "-{}",
            u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]])
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creating a folder owned by Administrators needs an elevated token. A
    /// developer's unelevated test run skips, saying so; CI (an elevated
    /// administrator) must not skip, or the test would pass there without
    /// testing anything.
    fn elevated_or_skip(test: &str) -> bool {
        if crate::utils::elevation::is_elevated() {
            return true;
        }
        assert!(
            std::env::var_os("CI").is_none(),
            "{test}: CI is not elevated, so this test would test nothing"
        );
        eprintln!("SKIPPED {test}: needs an elevated process");
        false
    }

    fn open_for_security(path: &Path) -> File {
        OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap()
    }

    fn icacls(path: &Path) -> String {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn a_sid_is_formatted_like_windows_does() {
        // S-1-5-32-544, BUILTIN\Administrators.
        let admins = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        assert_eq!(format_sid(&admins), "S-1-5-32-544");
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
    }

    /// The descriptor the directory is created with is admin-only by the
    /// same check every later start applies to it.
    #[test]
    fn the_directory_is_created_admin_only() {
        if !elevated_or_skip("the_directory_is_created_admin_only") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let dir = ensure_in(base.path()).unwrap();
        assert_eq!(dir, base.path().join(DIR_NAME));
        let security = Security::of(&open_for_security(&dir)).unwrap();
        assert!(security.is_admin_only(), "{}", icacls(&dir));
        // Users, Authenticated Users and Everyone get nothing; nothing is
        // inherited from the parent (a user-writable temp dir here, and
        // ProgramData's Users ACEs in the app).
        let listing = icacls(&dir);
        for nobody in ["Users", "Authenticated Users", "Everyone", "(I)"] {
            assert!(!listing.contains(nobody), "{nobody}: {listing}");
        }
        // A file created inside inherits it: SYSTEM, Administrators, and
        // owner rights cut to READ_CONTROL.
        let file = dir.join("inside.key");
        std::fs::write(&file, "00").unwrap();
        let inside = Security::of(&open_for_security(&file)).unwrap();
        let mut granted = inside.granted_sids().unwrap();
        granted.sort();
        assert_eq!(granted, ["S-1-3-4", "S-1-5-18", "S-1-5-32-544"]);
        // And a second start finds it as it was.
        assert_eq!(ensure_in(base.path()).unwrap(), dir);
        assert!(dir.join("inside.key").exists());
    }

    /// MR-1722: the folder the updater's installer is written to, and what
    /// the plugin creates in it the way it does (a temp dir, then the
    /// installer), are admin-only; and an earlier update's leftovers go.
    #[test]
    fn the_updates_folder_and_what_the_plugin_writes_there_are_admin_only() {
        if !elevated_or_skip("the_updates_folder_and_what_the_plugin_writes_there_are_admin_only") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let admin_only = ensure_in(base.path()).unwrap();
        let first = fresh_updates_dir_in(&admin_only).unwrap();
        std::fs::write(first.join("BirdoVPN-1.4.47-installer.exe"), "old").unwrap();
        let updates = fresh_updates_dir_in(&admin_only).unwrap();
        assert_eq!(updates, first);
        assert!(!updates.join("BirdoVPN-1.4.47-installer.exe").exists());

        let made = tempfile::Builder::new()
            .prefix("BirdoVPN-1.4.48-updater-")
            .tempdir_in(&updates)
            .unwrap();
        let installer = made.path().join("BirdoVPN-1.4.48-installer.exe");
        std::fs::write(&installer, "MZ").unwrap();
        for p in [updates.as_path(), made.path(), installer.as_path()] {
            let mut granted = Security::of(&open_for_security(p))
                .unwrap()
                .granted_sids()
                .unwrap();
            granted.sort();
            granted.dedup();
            assert_eq!(
                granted,
                ["S-1-3-4", "S-1-5-18", "S-1-5-32-544"],
                "{}",
                p.display()
            );
        }
    }

    /// THE SQUAT (MR-1721). ProgramData lets any user create `BirdoVPN`
    /// first, owning it and whatever they put in it. It is moved aside, kept,
    /// and never read; a fresh admin-only folder takes its place.
    #[test]
    fn a_squatted_directory_is_moved_aside_and_never_used() {
        let base = tempfile::tempdir().unwrap();
        let squat = base.path().join(DIR_NAME);
        std::fs::create_dir(&squat).unwrap();
        std::fs::write(squat.join("settings-hmac-S-1-5-21-1.key"), "planted").unwrap();
        // Created by this (possibly unelevated) process with an inherited,
        // user-writable ACL: exactly what a squatter leaves.
        assert_eq!(inspect(&squat).unwrap(), State::Untrusted);
        if !elevated_or_skip("a_squatted_directory_is_moved_aside_and_never_used") {
            return;
        }
        let dir = ensure_in(base.path()).unwrap();
        assert!(!dir.join("settings-hmac-S-1-5-21-1.key").exists());
        assert_eq!(inspect(&dir).unwrap(), State::AdminOnly);
        let aside: Vec<_> = std::fs::read_dir(base.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("BirdoVPN.untrusted-"))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert!(base
            .path()
            .join(&aside[0])
            .join("settings-hmac-S-1-5-21-1.key")
            .exists());
    }

    /// A junction where the folder should be (to a folder the user can
    /// write) is a squat too: renamed itself, its target untouched.
    #[test]
    fn a_junctioned_directory_is_moved_aside() {
        let base = tempfile::tempdir().unwrap();
        let elsewhere = base.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("dns-restore.json"), "{}").unwrap();
        let link = base.path().join(DIR_NAME);
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(&elsewhere)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed: {made:?}");
        assert_eq!(inspect(&link).unwrap(), State::Untrusted);
        if !elevated_or_skip("a_junctioned_directory_is_moved_aside") {
            return;
        }
        let dir = ensure_in(base.path()).unwrap();
        assert_eq!(inspect(&dir).unwrap(), State::AdminOnly);
        assert!(!dir.join("dns-restore.json").exists());
        assert!(elsewhere.join("dns-restore.json").exists());
    }

    /// A file where the folder should be is not a folder.
    #[test]
    fn a_file_in_its_place_is_untrusted() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join(DIR_NAME), "x").unwrap();
        assert_eq!(
            inspect(&base.path().join(DIR_NAME)).unwrap(),
            State::Untrusted
        );
        assert_eq!(
            inspect(&base.path().join("absent")).unwrap(),
            State::Missing
        );
    }
}
