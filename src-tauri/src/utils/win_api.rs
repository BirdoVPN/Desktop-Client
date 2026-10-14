//! The Win32 calls the elevated client's trust-boundary code needs (MR-1721,
//! MR-1722, MR-1945) that the `windows` features this crate enables do not
//! cover: `CreateDirectoryW`, `GetFinalPathNameByHandleW` and
//! `SetFileInformationByHandle` (`Win32_Storage_FileSystem`),
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`
//! (`Win32_Security_Authorization`) and `SHGetKnownFolderPath`
//! (`Win32_UI_Shell`).
//!
//! Declared by hand against kernel32, advapi32 and shell32, whose import
//! libraries every MSVC toolchain links, rather than turning on three more
//! `windows` features: no dependency, and no feature, changes. Everything the
//! enabled features do cover (`Win32_Security`, `Win32_Foundation`, ...) is
//! used from the `windows` crate as usual.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::core::GUID;
use windows::Win32::Security::SECURITY_ATTRIBUTES;

#[link(name = "kernel32")]
extern "system" {
    fn CreateDirectoryW(path: *const u16, security: *const SECURITY_ATTRIBUTES) -> i32;
    fn GetFinalPathNameByHandleW(file: *mut c_void, path: *mut u16, len: u32, flags: u32) -> u32;
    fn SetFileInformationByHandle(
        file: *mut c_void,
        class: i32,
        info: *const c_void,
        size: u32,
    ) -> i32;
    fn GetFileInformationByHandle(file: *mut c_void, info: *mut ByHandleFileInformation) -> i32;
}

/// The fields of `BY_HANDLE_FILE_INFORMATION` this crate reads, in layout
/// order; the tail it does not (`nFileIndex*`) is padded so the struct is the
/// size the API writes.
#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    attributes: u32,
    creation: [u32; 2],
    last_access: [u32; 2],
    last_write: [u32; 2],
    volume_serial: u32,
    size_high: u32,
    size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

/// How many hard links name the file `file` is open on. 1 for an ordinary
/// file; more means another name shares the data, so a write through this
/// handle would reach it (MR-1945 L3).
pub fn hard_link_count(file: &File) -> io::Result<u32> {
    let mut info = ByHandleFileInformation::default();
    // SAFETY: `file` is open for as long as the borrow lives; `info` is a
    // writable BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.number_of_links)
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn SHGetKnownFolderPath(
        id: *const GUID,
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
}

// winnt.h / winbase.h values, for `std::os::windows::fs::OpenOptionsExt`.
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// `ERROR_ALREADY_EXISTS`, what `CreateDirectoryW` answers for a name in use.
pub const ERROR_ALREADY_EXISTS: i32 = 183;

/// `path` as the NUL-terminated UTF-16 the W functions take.
pub fn wide(path: &OsStr) -> Vec<u16> {
    path.encode_wide().chain(std::iter::once(0)).collect()
}

/// A security descriptor built from SDDL, freed with `LocalFree`.
pub struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and outlives the call; on success
        // the API allocates the descriptor with LocalAlloc and hands ownership
        // to us (freed in Drop). Revision 1 is SDDL_REVISION_1.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // with LocalAlloc, freed exactly once.
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(self.0),
            ));
        }
    }
}

/// Create the directory `path` with `descriptor` as its security, in the one
/// call: there is no moment at which it exists with an inherited ACL.
pub fn create_directory(path: &Path, descriptor: &SecurityDescriptor) -> io::Result<()> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: false.into(),
    };
    let path = wide(path.as_os_str());
    // SAFETY: `path` is NUL-terminated; `attributes` and the descriptor it
    // points at outlive the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The path the OS resolved `file`'s handle to (`\\?\C:\...`): where the
/// object really is, after every junction, symlink and redirection on the way.
pub fn final_path(file: &File) -> io::Result<PathBuf> {
    let handle = file.as_raw_handle();
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `handle` is open for as long as `file` lives; `buf` is
        // writable for `buf.len()` units. Flags 0: FILE_NAME_NORMALIZED and
        // VOLUME_NAME_DOS.
        let n = unsafe { GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, 0) }
            as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        // Too small: `n` is the size needed, terminator included.
        buf.resize(n + 1, 0);
    }
}

/// Whether two final paths name the same file: equal up to ASCII case, which
/// NTFS folds too. Anything outside ASCII must match exactly, so a mismatch
/// can only ever cause a refusal, never a false match.
pub fn same_path(a: &Path, b: &Path) -> bool {
    let fold = |u: u16| match u {
        0x41..=0x5A => u + 0x20,
        _ => u,
    };
    a.as_os_str()
        .encode_wide()
        .map(fold)
        .eq(b.as_os_str().encode_wide().map(fold))
}

/// Delete the file `file` is open on — that object, whatever its path names
/// by now. `file` must be open with DELETE access.
///
/// POSIX semantics (FileDispositionInfoEx, Windows 10 1607+ on NTFS) take the
/// name away at once; where they are not available (FAT, some network shares)
/// the classic disposition deletes it when the last handle closes. The same
/// pair `std::fs::remove_dir_all` uses.
pub fn delete_on_handle(file: &File) -> io::Result<()> {
    const FILE_DISPOSITION_INFO: i32 = 4;
    const FILE_DISPOSITION_INFO_EX: i32 = 21;
    const FLAG_DELETE: u32 = 0x1;
    const FLAG_POSIX_SEMANTICS: u32 = 0x2;
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    let handle = file.as_raw_handle();
    let flags: u32 = FLAG_DELETE | FLAG_POSIX_SEMANTICS;
    // SAFETY: `handle` is open (owned by `file`); the buffer is a
    // FILE_DISPOSITION_INFO_EX (one ULONG) that outlives the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FILE_DISPOSITION_INFO_EX,
            (&flags as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER) => {
            let delete: u8 = 1;
            // SAFETY: as above; the buffer is a FILE_DISPOSITION_INFO (one
            // BOOLEAN).
            let ok = unsafe {
                SetFileInformationByHandle(
                    handle,
                    FILE_DISPOSITION_INFO,
                    (&delete as *const u8).cast(),
                    1,
                )
            };
            if ok != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        _ => Err(err),
    }
}

/// `%ProgramData%` (normally `C:\ProgramData`), from the known-folder API: a
/// machine-wide location set in HKLM, which a user cannot redirect the way
/// they can their own folders or the `PROGRAMDATA` environment variable.
pub fn program_data() -> io::Result<PathBuf> {
    // FOLDERID_ProgramData, {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}.
    const FOLDERID_PROGRAM_DATA: GUID = GUID::from_u128(0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97);
    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: the GUID outlives the call; on return `raw` is a CoTaskMem
    // string (also on failure, when it may be null), freed below exactly once.
    let hr =
        unsafe { SHGetKnownFolderPath(&FOLDERID_PROGRAM_DATA, 0, std::ptr::null_mut(), &mut raw) };
    let path = if hr >= 0 && !raw.is_null() {
        // SAFETY: on success `raw` is a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        // SAFETY: `len` units were just read up to the terminator.
        let units = unsafe { std::slice::from_raw_parts(raw, len) };
        Ok(PathBuf::from(OsString::from_wide(units)))
    } else {
        Err(io::Error::other(format!(
            "SHGetKnownFolderPath(ProgramData) failed: {hr:#x}"
        )))
    };
    // SAFETY: `raw` came from SHGetKnownFolderPath (null is allowed).
    unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(raw as *const c_void)) };
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_compare_equal_up_to_ascii_case_only() {
        assert!(same_path(
            Path::new(r"\\?\C:\Users\A\AppData\Roaming\BirdoVPN\logs\birdo.log.1"),
            Path::new(r"\\?\c:\users\a\appdata\roaming\birdovpn\LOGS\BIRDO.LOG.1"),
        ));
        assert!(!same_path(
            Path::new(r"\\?\C:\x\birdo.log"),
            Path::new(r"\\?\C:\x\birdo.log.1"),
        ));
        // KELVIN SIGN lowercases to 'k' under Unicode rules; NTFS keeps them
        // apart, and so must this.
        assert!(!same_path(Path::new("k"), Path::new("\u{212A}")));
    }

    #[test]
    fn program_data_is_a_machine_folder() {
        let dir = program_data().expect("ProgramData");
        assert!(dir.is_absolute(), "{}", dir.display());
        assert!(dir.is_dir(), "{}", dir.display());
    }

    #[test]
    fn a_handle_resolves_to_where_the_file_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.txt");
        std::fs::write(&path, "x").unwrap();
        let file = File::open(&path).unwrap();
        let resolved = final_path(&file).unwrap();
        let expected = final_path(&File::open(&path).unwrap()).unwrap();
        assert!(same_path(&resolved, &expected));
        assert!(resolved.ends_with("x.txt"), "{}", resolved.display());
    }

    #[test]
    fn delete_on_handle_deletes_the_open_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.txt");
        std::fs::write(&path, "x").unwrap();
        let file = std::fs::OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .open(&path)
            .unwrap();
        delete_on_handle(&file).unwrap();
        drop(file);
        assert!(!path.exists());
    }
}
