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

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
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
    let dir = resolve(&win_api::program_data()?)?;
    Ok(VERIFIED.get_or_init(|| dir).clone())
}

/// Where the protected directory ends up under `base` (M3).
///
/// Normally `BirdoVPN`. But any user may pre-create that name in ProgramData
/// and hold it open without `FILE_SHARE_DELETE`, so it can be neither secured
/// nor moved aside, and every start would then fail — no updates, no DNS
/// journal, no settings saves. So if the fixed name cannot be secured, the app
/// falls back to a RANDOMLY named protected directory the attacker could not
/// have pre-created, and records its name in HKLM (writable only by
/// administrators, so a user cannot poison it).
///
/// MEDIUM 2 (#287 review): once a fallback is recorded, it is used FIRST, before
/// the fixed name, on every later start. Otherwise a squatter who held the
/// fixed name at first run (so the key landed in the random dir) could release
/// it later; the next start would secure the now-free fixed name, find no key
/// there, and re-open the whole migration (unsigned settings adopted, journal
/// and resume markers re-armed). With the recorded folder preferred, the app
/// keeps using the directory that actually holds its key.
fn resolve(base: &Path) -> io::Result<PathBuf> {
    resolve_with(base, &recorded_dir_name, &record_dir_name)
}

/// [`resolve`] with the HKLM record read/write injected, so the preference
/// order is testable without touching the machine's registry (MEDIUM 2 seam).
fn resolve_with(
    base: &Path,
    recorded: &dyn Fn() -> Option<String>,
    record: &dyn Fn(&str),
) -> io::Result<PathBuf> {
    // A recorded fallback is authoritative: the key/markers live there.
    if let Some(name) = recorded() {
        // Only a name `mint_private` could have written, never a path a
        // crafted value could escape with (R7).
        if is_state_dir_name(&name) {
            match secure_named(base, &name) {
                Ok(dir) => return Ok(dir),
                Err(e) => tracing::warn!(
                    "The recorded state directory is unusable ({}); minting a new private one",
                    e
                ),
            }
        }
        // The recorded folder could not be secured: mint a fresh private one
        // (and re-record it) rather than fall back to the fixed name, which a
        // squatter could have freed to re-open the migration.
        return mint_private(base, record);
    }
    match secure_named(base, DIR_NAME) {
        Ok(dir) => return Ok(dir),
        Err(e) => tracing::warn!(
            "The fixed state directory could not be secured ({}); using a private name",
            e
        ),
    }
    mint_private(base, record)
}

/// Create a fresh randomly named admin-only directory and record it.
fn mint_private(base: &Path, record: &dyn Fn(&str)) -> io::Result<PathBuf> {
    for _ in 0..ATTEMPTS {
        let name = random_state_name();
        match create(&base.join(&name)) {
            Ok(()) => {
                record(&name);
                tracing::warn!("Created a privately named admin-only state directory");
                return Ok(base.join(name));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(
        "could not create a protected state directory",
    ))
}

/// A directory name no user could have pre-created to squat on.
fn random_state_name() -> String {
    format!("{DIR_NAME}-{:016x}", rand::random::<u64>())
}

/// Whether `name` is one [`random_state_name`] makes: `BirdoVPN-` and 16
/// lower-case hex digits (R7). Anything else read back from HKLM — `.`, `..`,
/// a separator, a drive or stream colon, trailing dots Win32 would strip, or
/// a different prefix — is not used as a directory name.
fn is_state_dir_name(name: &str) -> bool {
    name.strip_prefix(DIR_NAME)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|hex| {
            hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// HKLM's record for the app (admin-only to write), where the fallback
/// directory's name and the installer's legacy-upgrade marker live.
const STATE_KEY: &str = r"SOFTWARE\BirdoVPN";

/// The value the installer writes when it upgrades an install from before
/// MR-1721 (nsis-hooks.nsh, `BIRDO_LEGACY_UPGRADE_VALUE`). Pinned by a test.
pub const LEGACY_UPGRADE_VALUE: &str = "LegacyUpgradePending";

// ── R1: the legacy-trust window is an upgrade's, and only its first start ──
//
// MR-1721 migrated what the pre-#287 build had left in the user's reach — the
// settings key's old sources, an unsigned settings.json, the %APPDATA% DNS
// journal, the unsigned 1.4.47 resume record — the first time an account had
// no admin-only state yet. But "no admin-only state yet" is also a FRESH
// install, a new Windows account, and a key an administrator deleted: each of
// those adopted, once, whatever an unelevated process had put there.
//
// So the window now needs the installer's word that this IS an upgrade of a
// pre-#287 install: it writes `LEGACY_UPGRADE_VALUE` in HKLM (which only an
// administrator can write) when, and only when, it replaces such an install.
// Reading is not consuming (D6c LOW): the window is LATCHED read-only on the
// first call and used by every migration this run, but the marker is DELETED
// only by [`consume_legacy_upgrade_window`], which the primary instance calls
// in `setup()` AFTER the settings migration has succeeded. An auxiliary exit
// (`--reconcile-and-exit`, `--remove-leftovers-and-exit`), a second instance
// the single-instance plugin turns away, or a first-start crash therefore no
// longer burns the window: the marker survives for the real first start, and
// a crash mid-migration leaves it for the retry. Every later start, and every
// fresh install, finds no marker.

/// 0: not latched yet, 1: closed, 2: open.
static UPGRADE_WINDOW: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Whether this run may migrate (trust once) the state a pre-MR-1721 build
/// left in the user's reach (R1). Reads and latches the installer's marker on
/// the first call (read-only — it does not consume it); every later call
/// returns the latched value, so the whole run sees one answer even after
/// [`consume_legacy_upgrade_window`] has deleted the marker. Never blocks (the
/// panic hook reaches it through the DNS journal).
pub fn legacy_upgrade_window() -> bool {
    use std::sync::atomic::Ordering;
    match UPGRADE_WINDOW.load(Ordering::SeqCst) {
        0 => {
            let open = super::elevation::is_elevated() && legacy_upgrade_marker_present();
            // A race latches the same value, so `store` rather than a CAS loop.
            UPGRADE_WINDOW.store(if open { 2 } else { 1 }, Ordering::SeqCst);
            if open {
                tracing::info!(
                    "First start after an upgrade from before MR-1721: the old state may be \
                     migrated this run"
                );
            }
            open
        }
        2 => true,
        _ => false,
    }
}

/// Delete the installer's legacy-upgrade marker, once the migrations that were
/// allowed to read it have run (D6c LOW). Called by the PRIMARY instance in
/// `setup()`, not by `main()` or an auxiliary exit: see the note above. The
/// latched window value is unchanged, so anything later in this run still sees
/// the window it migrated under. Best-effort and `#[cfg(windows)]`-only; a
/// non-elevated process cannot write HKLM and never reaches here.
pub fn consume_legacy_upgrade_window() {
    if !legacy_upgrade_window() {
        return;
    }
    match consume_legacy_upgrade_marker() {
        Ok(()) => tracing::info!("The legacy-upgrade window is consumed"),
        Err(e) => tracing::warn!(
            "Could not consume the legacy-upgrade marker ({}); the next start would migrate again",
            e
        ),
    }
}

fn legacy_upgrade_marker_present() -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(STATE_KEY, KEY_READ)
        .and_then(|key| key.get_raw_value(LEGACY_UPGRADE_VALUE))
        .is_ok()
}

fn consume_legacy_upgrade_marker() -> io::Result<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(STATE_KEY, KEY_SET_VALUE)?
        .delete_value(LEGACY_UPGRADE_VALUE)
}

/// The fallback directory name recorded in HKLM, if any (M3). HKLM is writable
/// only by administrators, so a user cannot point this at a directory of
/// theirs.
#[cfg(windows)]
fn recorded_dir_name() -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(STATE_KEY, KEY_READ)
        .ok()?
        .get_value::<String, _>("ProtectedStateDir")
        .ok()
}

/// Record the fallback directory name in HKLM (M3). Best-effort: a start that
/// cannot record it mints a new private name next time, which still works.
#[cfg(windows)]
fn record_dir_name(name: &str) {
    use winreg::RegKey;
    match RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).create_subkey(STATE_KEY) {
        Ok((key, _)) => {
            if let Err(e) = key.set_value("ProtectedStateDir", &name.to_string()) {
                tracing::warn!("Could not record the state directory name: {}", e);
            }
        }
        Err(e) => tracing::warn!("Could not open HKLM to record the state directory: {}", e),
    }
}

/// [`ensure`] under `base` for the fixed name (a temp dir in tests).
#[cfg(test)]
fn ensure_in(base: &Path) -> io::Result<PathBuf> {
    secure_named(base, DIR_NAME)
}

/// Secure (create, or move a squatter aside and create) the directory `name`
/// under `base`, returning it once it is admin-only.
fn secure_named(base: &Path, name: &str) -> io::Result<PathBuf> {
    let dir = base.join(name);
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

/// The admin-only directory `dir` (a child of ProgramData) as an
/// [`OwnedDir`](super::safe_fs::OwnedDir): ProgramData as the root, the
/// directory's own name as the app's folder.
fn owned(dir: &Path) -> io::Result<super::safe_fs::OwnedDir> {
    let (Some(base), Some(name)) = (dir.parent(), dir.file_name().and_then(|n| n.to_str())) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a directory under ProgramData",
        ));
    };
    Ok(super::safe_fs::OwnedDir::new(base, &[name]))
}

/// R2 (#287 follow-up L2): the updater leaves the installer it launched in
/// `updates\` (the plugin never deletes it, and it is running when the app
/// exits). The next start removes the folder, through a handle checked to be
/// the admin-only directory's own `updates` (`OwnedDir::remove_dir_tree`).
/// Best-effort: an installer still finishing keeps its own file, and the next
/// start (or the next update's `fresh_updates_dir`) takes it.
pub fn remove_updates_at_start() {
    let removed = ensure().and_then(|dir| owned(&dir)?.remove_dir_tree(UPDATES));
    match removed {
        Ok(()) => tracing::info!("Removed the last update's installer"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::info!("The last update's installer is not removed yet ({})", e),
    }
}

/// The folder the updater's installer goes in.
const UPDATES: &str = "updates";

/// What [`remove_uninstall_leftovers_in`] removed, in counts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Leftovers {
    pub updates: u32,
    pub set_aside: u32,
    pub pq_keys: u32,
    /// Per-user app-data entries removed under `--with-app-data` (D6c HIGH).
    pub app_data: u32,
    pub failed: u32,
}

/// The uninstaller's cleanup (R2, `--remove-leftovers-and-exit` from
/// nsis-hooks.nsh's NSIS_HOOK_PREUNINSTALL): the updater's `updates\` and the
/// squatted folders moved aside as `BirdoVPN.untrusted-*`; with
/// `with_app_data` ("Delete the application data" ticked, D-23) also every
/// account's ML-KEM keypair (`pq-<SID>.bin`, R4) and the per-user app-data
/// folders (D6c HIGH — see [`remove_app_data_folders_in`]). NEVER the settings
/// keys or the migration markers: without a key a reinstall can no longer
/// verify (so quarantines) the user's settings.json, and the markers keep the
/// old %APPDATA% sources closed for good. Creates nothing (no `ensure()`).
pub fn remove_uninstall_leftovers(with_app_data: bool) -> Leftovers {
    let mut done = match win_api::program_data() {
        Ok(base) => remove_uninstall_leftovers_in(
            &base,
            recorded_dir_name().filter(|name| is_state_dir_name(name)),
            with_app_data,
        ),
        Err(e) => {
            tracing::warn!("No ProgramData to clean ({})", e);
            Leftovers::default()
        }
    };
    // D6c HIGH: the per-user folders. Done here, in the elevated exe, not by
    // NSIS — `RMDir /r` follows the junctions a user can plant in their own
    // %APPDATA% / %LOCALAPPDATA%, which would delete files anywhere on the
    // machine as administrator. `std::fs::remove_dir_all` never follows one.
    if with_app_data {
        match (dirs::config_dir(), dirs::config_local_dir()) {
            // config_dir() is %APPDATA% (Roaming), config_local_dir() is
            // %LOCALAPPDATA% (Local) on Windows.
            (Some(appdata), Some(localappdata)) => {
                let ad = remove_app_data_folders_in(&appdata, &localappdata);
                done.app_data += ad.app_data;
                done.failed += ad.failed;
            }
            _ => {
                tracing::warn!("No %APPDATA%/%LOCALAPPDATA% to clean");
                done.failed += 1;
            }
        }
    }
    done
}

/// The Tauri bundle identifier (tauri.conf.json), the folder the template's own
/// "delete the application data" removes under %APPDATA% and %LOCALAPPDATA%.
/// Pinned to tauri.conf.json by a test.
const APP_IDENTIFIER: &str = "uk.birdo.vpn.desktop";

/// A name the per-user sweep KEEPS in `%APPDATA%\BirdoVPN` (W1-008): the
/// DNS-restore journal and its variants (`dns-restore.json`, `.corrupt`,
/// `.tmp`). A reinstall's reconcile still needs it to put back resolvers a
/// killed session could not restore; the old hook round-tripped it through
/// `%TEMP%`, which was itself a user-writable path (D6c HIGH).
fn is_dns_journal_name(name: &str) -> bool {
    name.starts_with("dns-restore.json")
}

/// Remove `path` and everything under it WITHOUT following a link at any level
/// (D6c HIGH). `std::fs::remove_dir_all` opens every entry — and the top —
/// without following a reparse point and deletes a link as a link (verified
/// against NSIS 3.11's `RMDir /r`, which does follow them); a plain file or a
/// file link is unlinked. A missing path is success.
fn remove_tree_no_follow(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 => {
            std::fs::remove_dir_all(path)
        }
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The per-user "delete the application data" sweep (D6c HIGH), replacing the
/// hook's `RMDir /r` (and its `%TEMP%` journal round-trip) and the Tauri
/// template's own `RmDir /r` of the two identifier folders.
///
/// Four folders go entirely; `%APPDATA%\BirdoVPN` keeps only the DNS-restore
/// journal (W1-008). Nothing follows a link: the four use
/// [`remove_tree_no_follow`], and `%APPDATA%\BirdoVPN` is HELD open first
/// (verified not a reparse point, unrenameable while held) before it is listed,
/// so it cannot be swapped for a junction between the check and the delete; its
/// children are each removed with [`remove_tree_no_follow`]. A junction planted
/// in its place is unlinked, never entered.
///
/// D6c LOW-MEDIUM: the roots come from `SHGetKnownFolderPath`, which a same-user
/// process can REDIRECT via HKCU "User Shell Folders" — pointed at
/// `%ProgramData%`, a fixed-name target would resolve onto the admin-only
/// `BirdoVPN` and the sweep would delete the settings keys and markers,
/// re-arming the migration. Two guards: a root is swept only when its final
/// path resolves UNDER the token user's HKLM `ProfileList` profile directory
/// (which HKCU cannot move); and no target that `inspect` reports `AdminOnly`
/// is ever touched.
fn remove_app_data_folders_in(appdata: &Path, localappdata: &Path) -> Leftovers {
    remove_app_data_folders_under(appdata, localappdata, user_profile_dir().as_deref())
}

/// [`remove_app_data_folders_in`] with the profile directory injected, so a
/// test can place its fake roots under a profile it controls.
fn remove_app_data_folders_under(
    appdata: &Path,
    localappdata: &Path,
    profile: Option<&Path>,
) -> Leftovers {
    let mut done = Leftovers::default();
    let under_profile = |root: &Path| match profile {
        Some(p) => path_is_under(root, p),
        None => false,
    };
    let roam_ok = under_profile(appdata);
    let local_ok = under_profile(localappdata);
    if !roam_ok || !local_ok {
        tracing::warn!("A per-user data root is not under the user profile — refusing to sweep it");
        done.failed += 1;
    }
    let mut sweep = |path: &Path| {
        // Never an admin-only directory: a redirected root could resolve a
        // target onto %ProgramData%\BirdoVPN, whose keys and markers must stay.
        if matches!(inspect(path), Ok(State::AdminOnly)) {
            return;
        }
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            _ => match remove_tree_no_follow(path) {
                Ok(()) => done.app_data += 1,
                Err(_) => done.failed += 1,
            },
        }
    };
    if local_ok {
        sweep(&localappdata.join("BirdoVPN")); // device id, pre-R4 ML-KEM key
        sweep(&localappdata.join("Birdo VPN")); // crash reports
        sweep(&localappdata.join(APP_IDENTIFIER)); // the template's local folder
    }
    if roam_ok {
        sweep(&appdata.join(APP_IDENTIFIER)); // the template's roaming folder
    }

    // %APPDATA%\BirdoVPN: logs and the rest, but keep the DNS journal.
    let birdo = super::safe_fs::OwnedDir::new(appdata, &["BirdoVPN"]);
    if roam_ok && !matches!(inspect(birdo.path()), Ok(State::AdminOnly)) {
        match birdo.hold_open_if_present() {
            Ok(None) => {}
            Err(_) => {
                // A junction (or an unverifiable folder) in its place: unlink it
                // without entering. Nothing of ours is really behind a junction.
                match remove_tree_no_follow(birdo.path()) {
                    Ok(()) => done.app_data += 1,
                    Err(_) => done.failed += 1,
                }
            }
            Ok(Some(_guard)) => {
                let Ok(entries) = std::fs::read_dir(birdo.path()) else {
                    done.failed += 1;
                    return done;
                };
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    if is_dns_journal_name(name) {
                        continue;
                    }
                    match remove_tree_no_follow(&birdo.join(name)) {
                        Ok(()) => done.app_data += 1,
                        Err(_) => done.failed += 1,
                    }
                }
            }
        }
    }
    done
}

/// The token user's profile directory from HKLM `ProfileList` (which only an
/// administrator can write), so a redirected `%APPDATA%`/`%LOCALAPPDATA%` can
/// be refused. `ProfileImagePath` is `REG_EXPAND_SZ`, which `winreg` returns
/// unexpanded, so it is expanded here.
fn user_profile_dir() -> Option<PathBuf> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let sid = current_user_sid().ok()?;
    let raw: String = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
            KEY_READ,
        )
        .ok()?
        .get_value("ProfileImagePath")
        .ok()?;
    Some(PathBuf::from(win_api::expand_env(&raw)))
}

/// The final path of `p` (opened without following a reparse point), or `None`.
fn final_path_of(p: &Path) -> Option<PathBuf> {
    let handle = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(p)
        .ok()?;
    win_api::final_path(&handle).ok()
}

/// Whether `child` resolves to `ancestor` or a path beneath it, comparing
/// resolved final paths component-by-component, case-insensitively (NTFS folds
/// case). A root that does not resolve is not under anything.
fn path_is_under(child: &Path, ancestor: &Path) -> bool {
    let (Some(c), Some(a)) = (final_path_of(child), final_path_of(ancestor)) else {
        return false;
    };
    let a_comps: Vec<_> = a.components().collect();
    let c_comps: Vec<_> = c.components().collect();
    c_comps.len() >= a_comps.len()
        && a_comps
            .iter()
            .zip(&c_comps)
            .all(|(x, y)| x.as_os_str().eq_ignore_ascii_case(y.as_os_str()))
}

/// An account's ML-KEM keypair file in the admin-only directory
/// (`vpn::birdo_pq`, R4): `pq-S-<digits and dashes>.bin`.
fn is_pq_key_name(name: &str) -> bool {
    name.strip_prefix("pq-S-")
        .and_then(|rest| rest.strip_suffix(".bin"))
        .is_some_and(|sid| !sid.is_empty() && sid.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

/// [`remove_uninstall_leftovers`] under `base`, with the HKLM-recorded
/// fallback name `recorded` (already checked).
///
/// `updates\` (and the keypairs) go only from a directory that IS admin-only:
/// a squatter's own folder of that name is theirs, and is moved aside on the
/// next start anyway. The `BirdoVPN.untrusted-*` folders are a user's (that
/// is why they were set aside), so they may hold junctions and links: they
/// are removed with `std::fs::remove_dir_all`, which never follows one (it
/// opens every entry without following a reparse point and deletes a link as
/// a link). NSIS's own `RMDir /r` follows junctions, so the uninstaller must
/// not do this itself.
fn remove_uninstall_leftovers_in(
    base: &Path,
    recorded: Option<String>,
    with_app_data: bool,
) -> Leftovers {
    let mut done = Leftovers::default();
    for name in std::iter::once(DIR_NAME.to_string()).chain(recorded) {
        if !matches!(inspect(&base.join(&name)), Ok(State::AdminOnly)) {
            continue;
        }
        let owned = super::safe_fs::OwnedDir::new(base, &[name.as_str()]);
        match owned.remove_dir_tree(UPDATES) {
            Ok(()) => done.updates += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => done.failed += 1,
        }
        if !with_app_data {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(owned.path()) else {
            done.failed += 1;
            continue;
        };
        for entry in entries.flatten() {
            let file = entry.file_name();
            let Some(file) = file.to_str().filter(|f| is_pq_key_name(f)) else {
                continue;
            };
            match owned.remove_file(file) {
                Ok(()) => done.pq_keys += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => done.failed += 1,
            }
        }
    }
    let prefix = format!("{DIR_NAME}.untrusted-");
    let Ok(entries) = std::fs::read_dir(base) else {
        return done;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(|n| n.starts_with(&prefix)) {
            continue;
        }
        let path = base.join(&name);
        // A directory, or a junction/symlink to one (the link goes, not its
        // target), through remove_dir_all; a file or a file link by unlinking
        // the name. Each call opens without following a reparse point, so a
        // swap between the look and the call only makes it fail.
        let removed = match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 => {
                std::fs::remove_dir_all(&path)
            }
            Ok(_) => std::fs::remove_file(&path),
            Err(e) => Err(e),
        };
        match removed {
            Ok(()) => done.set_aside += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => done.failed += 1,
        }
    }
    done
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

/// SYSTEM, BUILTIN\Administrators, OWNER RIGHTS.
const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const OWNER_RIGHTS: &str = "S-1-3-4";

/// An object's owner and DACL, read through an open handle as the
/// self-relative security descriptor `GetKernelObjectSecurity` returns, and
/// parsed from those bytes with every offset bounds-checked: no pointer into
/// the descriptor is ever dereferenced.
pub struct Security(Vec<u8>);

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
        // u64s, so the buffer is suitably aligned for a descriptor.
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
        let bytes = buf
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .take(needed as usize)
            .collect();
        Ok(Self(bytes))
    }

    /// Owned by SYSTEM or Administrators, and a DACL with no grant to anyone
    /// else (OWNER RIGHTS limited to READ_CONTROL). An absent or NULL DACL —
    /// full access for everyone — or a descriptor that does not parse is not
    /// admin-only.
    pub fn is_admin_only(&self) -> bool {
        self.owner()
            .is_some_and(|owner| owner == SYSTEM || owner == ADMINISTRATORS)
            && self
                .allowed_aces()
                .is_some_and(|aces| aces.iter().all(|(sid, mask)| is_admin_grant(sid, *mask)))
    }

    /// Every SID the DACL grants any access to (`S-1-5-18`); an ACE of a
    /// type this does not read is listed as `"?"`. `None` for an absent or
    /// NULL DACL, which grants everyone everything. (For tests: the app
    /// decides with [`Security::is_admin_only`].)
    #[cfg(test)]
    pub fn granted_sids(&self) -> Option<Vec<String>> {
        self.allowed_aces()
            .map(|aces| aces.into_iter().map(|(sid, _)| sid).collect())
    }

    // SECURITY_DESCRIPTOR_RELATIVE: Revision u8, Sbz1 u8, Control u16,
    // then the offsets of Owner, Group, Sacl and Dacl (u32 each; 0 = none).

    fn owner(&self) -> Option<String> {
        let at = u32_at(&self.0, 4)? as usize;
        (at != 0).then(|| sid_at(&self.0, at)).flatten()
    }

    /// Every ACE of the DACL as `(sid, mask)`, with a deny ACE left out (it
    /// grants nothing) and an ACE of any other type reported as a grant to
    /// `"?"` with every right, so it fails the checks. `None` for an absent
    /// or NULL DACL, or one that does not parse.
    fn allowed_aces(&self) -> Option<Vec<(String, u32)>> {
        const SE_DACL_PRESENT: u16 = 0x0004;
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;
        let b = &self.0;
        if u16_at(b, 2)? & SE_DACL_PRESENT == 0 {
            return None;
        }
        let acl = u32_at(b, 16)? as usize;
        if acl == 0 {
            return None; // a NULL DACL
        }
        // ACL: AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16, Sbz2 u16.
        let count = u16_at(b, acl + 4)?;
        let mut at = acl + 8;
        let mut aces = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            // ACE_HEADER: AceType u8, AceFlags u8, AceSize u16.
            let kind = *b.get(at)?;
            let size = usize::from(u16_at(b, at + 2)?);
            if size < 8 {
                return None;
            }
            match kind {
                // ACCESS_ALLOWED_ACE: the header, Mask u32, then the SID.
                ACCESS_ALLOWED_ACE_TYPE => aces.push((sid_at(b, at + 8)?, u32_at(b, at + 4)?)),
                ACCESS_DENIED_ACE_TYPE => {}
                _ => aces.push(("?".to_string(), u32::MAX)),
            }
            at += size;
        }
        Some(aces)
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The string form of the binary SID at `at` in `b`, if it fits there.
fn sid_at(b: &[u8], at: usize) -> Option<String> {
    let count = usize::from(*b.get(at + 1)?);
    b.get(at..at + 8 + 4 * count).map(format_sid)
}

/// SYSTEM and Administrators with any rights; OWNER RIGHTS with at most
/// READ_CONTROL. Nothing else.
fn is_admin_grant(sid: &str, mask: u32) -> bool {
    sid == SYSTEM || sid == ADMINISTRATORS || (sid == OWNER_RIGHTS && mask & !READ_CONTROL == 0)
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
    // TOKEN_USER is a pointer to the SID, which the API placed in `buf`
    // after the struct: read the pointer, turn it into an offset into `buf`,
    // and parse the SID from those bytes.
    // SAFETY: GetTokenInformation(TokenUser) filled a TOKEN_USER at the
    // start of `buf`, which is aligned for it.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let bytes: Vec<u8> = buf
        .iter()
        .flat_map(|word| word.to_ne_bytes())
        .take(needed as usize)
        .collect();
    (sid.0 as usize)
        .checked_sub(buf.as_ptr() as usize)
        .and_then(|at| sid_at(&bytes, at))
        .ok_or_else(|| io::Error::other("the token's user SID is not where it should be"))
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

    const SY: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const BA: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
    const BU: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0];
    const OW: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
    const WD: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const FA: u32 = 0x001F_01FF;

    /// A self-relative security descriptor: `owner`, and a DACL of
    /// `(type, mask, sid)` ACEs — `None` for a NULL DACL.
    fn descriptor(owner: &[u8], aces: Option<&[(u8, u32, &[u8])]>) -> Security {
        let mut acl = Vec::new();
        for &(kind, mask, sid) in aces.unwrap_or(&[]) {
            acl.push(kind);
            acl.push(0x03); // OBJECT_INHERIT | CONTAINER_INHERIT
            acl.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
            acl.extend_from_slice(&mask.to_le_bytes());
            acl.extend_from_slice(sid);
        }
        let count = aces.map_or(0, <[_]>::len) as u16;
        let mut b = vec![1u8, 0];
        b.extend_from_slice(&(0x8004u16).to_le_bytes()); // SELF_RELATIVE | DACL_PRESENT
        b.extend_from_slice(&20u32.to_le_bytes()); // owner
        b.extend_from_slice(&[0; 8]); // no group, no SACL
        let dacl = if aces.is_some() {
            20 + owner.len() as u32
        } else {
            0
        };
        b.extend_from_slice(&dacl.to_le_bytes());
        b.extend_from_slice(owner);
        if aces.is_some() {
            b.extend_from_slice(&[2, 0]);
            b.extend_from_slice(&((8 + acl.len()) as u16).to_le_bytes());
            b.extend_from_slice(&count.to_le_bytes());
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&acl);
        }
        Security(b)
    }

    /// The check every start applies, on descriptors of each shape: only
    /// the one `create` makes (and an explicit deny on top) passes.
    #[test]
    fn only_an_administrators_owned_system_and_admins_dacl_is_admin_only() {
        let ours: &[(u8, u32, &[u8])] = &[(0, FA, SY), (0, FA, BA), (0, READ_CONTROL, OW)];
        assert!(descriptor(BA, Some(ours)).is_admin_only());
        assert!(descriptor(SY, Some(ours)).is_admin_only());
        assert_eq!(
            descriptor(BA, Some(ours)).granted_sids().unwrap(),
            [SYSTEM, ADMINISTRATORS, OWNER_RIGHTS]
        );
        // A deny grants nothing.
        assert!(descriptor(BA, Some(&[(1, FA, WD), (0, FA, SY)])).is_admin_only());

        // Owned by Users (a squatter's own folder).
        assert!(!descriptor(BU, Some(ours)).is_admin_only());
        // Users (or Everyone) granted anything.
        assert!(!descriptor(BA, Some(&[(0, FA, SY), (0, 0x0012_0089, BU)])).is_admin_only());
        assert!(!descriptor(BA, Some(&[(0, FA, SY), (0, 0x1, WD)])).is_admin_only());
        // Owner rights worth more than reading the permissions.
        assert!(!descriptor(BA, Some(&[(0, FA, SY), (0, FA, OW)])).is_admin_only());
        // An ACE type this does not read (an object ACE).
        assert!(!descriptor(BA, Some(&[(0, FA, SY), (5, FA, SY)])).is_admin_only());
        // A NULL DACL: everyone, everything.
        assert!(!descriptor(BA, None).is_admin_only());
        assert_eq!(descriptor(BA, None).granted_sids(), None);
        // Truncated: nothing parses, nothing passes.
        let Security(mut cut) = descriptor(BA, Some(ours));
        cut.truncate(cut.len() - 3);
        assert!(!Security(cut).is_admin_only());
    }

    /// The parser on a descriptor the OS wrote: a folder this process made
    /// with an inherited ACL grants this account, so it is not admin-only.
    #[test]
    fn a_folder_with_an_inherited_acl_is_not_admin_only() {
        let base = tempfile::tempdir().unwrap();
        let security = Security::of(&open_for_security(base.path())).unwrap();
        assert!(!security.is_admin_only());
        let user = current_user_sid().unwrap();
        assert!(security.granted_sids().unwrap().contains(&user));
    }

    #[test]
    fn a_random_state_name_is_a_plain_prefixed_name() {
        let name = random_state_name();
        assert!(name.starts_with("BirdoVPN-"), "{name}");
        assert!(!name.contains(['/', '\\', ':']), "{name}");
        assert!(is_state_dir_name(&name), "{name}");
        assert_ne!(random_state_name(), random_state_name());
    }

    /// R7: the HKLM-recorded name is used only when it is exactly what
    /// `random_state_name` writes.
    #[test]
    fn only_a_minted_name_is_accepted_from_hklm() {
        assert!(is_state_dir_name("BirdoVPN-0123456789abcdef"));
        for bad in [
            "",
            ".",
            "..",
            "BirdoVPN",
            "BirdoVPN-",
            "BirdoVPN-..",
            "BirdoVPN-0123456789abcdef.",
            "BirdoVPN-0123456789ABCDEF",
            "BirdoVPN-0123456789abcde",
            "BirdoVPN-0123456789abcdef0",
            r"BirdoVPN-0123456789abcd\x",
            "BirdoVPN-0123456789abcd/x",
            "BirdoVPN-0123456789abc:de",
            r"..\..\Windows",
            "Other-0123456789abcdef",
            "BirdoVPN.untrusted-0123456",
        ] {
            assert!(!is_state_dir_name(bad), "{bad:?} was accepted");
        }
    }

    /// D6c LOW: reading the window does not consume the marker. The marker's
    /// delete is `consume_legacy_upgrade_marker` (HKLM write), exercised only
    /// on a device; here we pin that the reader and the consumer are two
    /// separate operations, so an auxiliary exit that only reads cannot burn
    /// the window. (The real wiring is checked in `main.rs` by a source pin in
    /// `vpn::dns_journal::uninstall_tests`.)
    #[test]
    fn reading_the_window_is_separate_from_consuming_it() {
        let src = include_str!("protected_dir.rs");
        // `legacy_upgrade_window` never deletes; only `consume_*` does.
        let reader = &src[src.find("pub fn legacy_upgrade_window()").unwrap()
            ..src.find("pub fn consume_legacy_upgrade_window()").unwrap()];
        assert!(!reader.contains("delete_value"));
        assert!(!reader.contains("consume_legacy_upgrade_marker"));
        let consumer = &src[src.find("pub fn consume_legacy_upgrade_window()").unwrap()..];
        assert!(consumer.contains("consume_legacy_upgrade_marker()"));
    }

    /// The marker's name is the one nsis-hooks.nsh writes, in the key this
    /// module reads, in the 64-bit view the app reads (the template's
    /// SetContext sets SetRegView 64 before any hook runs).
    #[test]
    fn the_installer_writes_the_marker_this_reads() {
        let hooks = include_str!("../../nsis-hooks.nsh").replace('\r', "");
        assert!(hooks.contains(&format!(r#"!define BIRDO_STATE_KEY "{STATE_KEY}""#)));
        assert!(hooks.contains(&format!(
            r#"!define BIRDO_LEGACY_UPGRADE_VALUE "{LEGACY_UPGRADE_VALUE}""#
        )));
    }

    fn junction(link: &Path, target: &Path) {
        crate::utils::safe_fs::tests::junction(link, target);
    }

    /// R2: the uninstaller's cleanup removes the folders set aside as
    /// untrusted — a user's, so it may have planted junctions in them or BE
    /// one — without following any link: what the links point at survives.
    /// A `BirdoVPN` that is not admin-only keeps its `updates` (a squatter's
    /// folder is not this app's to empty), and nothing else is touched.
    #[test]
    fn the_uninstall_cleanup_removes_set_aside_folders_without_following_links() {
        let base = tempfile::tempdir().unwrap();
        let b = base.path();
        let victim = b.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("precious.txt"), "keep").unwrap();

        // A set-aside folder holding a junction out, and a file.
        let aside = b.join("BirdoVPN.untrusted-1");
        std::fs::create_dir(&aside).unwrap();
        std::fs::write(aside.join("planted.key"), "x").unwrap();
        junction(&aside.join("out"), &victim);
        // A set-aside junction (the squat was a junction, renamed itself).
        junction(&b.join("BirdoVPN.untrusted-2"), &victim);
        // A set-aside file.
        std::fs::write(b.join("BirdoVPN.untrusted-3"), "x").unwrap();
        // Not ours: other names.
        std::fs::create_dir(b.join("BirdoVPNx")).unwrap();
        std::fs::create_dir(b.join("Other.untrusted-1")).unwrap();
        // A `BirdoVPN` a user made (inherited ACL): not admin-only.
        std::fs::create_dir_all(b.join("BirdoVPN").join("updates")).unwrap();
        std::fs::write(b.join("BirdoVPN").join("updates").join("x.exe"), "MZ").unwrap();

        let done = remove_uninstall_leftovers_in(b, None, true);

        assert_eq!(done.set_aside, 3, "{done:?}");
        assert_eq!(done.updates, 0, "{done:?}");
        for gone in [
            "BirdoVPN.untrusted-1",
            "BirdoVPN.untrusted-2",
            "BirdoVPN.untrusted-3",
        ] {
            assert!(std::fs::symlink_metadata(b.join(gone)).is_err(), "{gone}");
        }
        assert_eq!(
            std::fs::read_to_string(victim.join("precious.txt")).unwrap(),
            "keep",
            "the cleanup followed a junction"
        );
        assert!(b.join("BirdoVPNx").is_dir() && b.join("Other.untrusted-1").is_dir());
        assert!(b.join("BirdoVPN").join("updates").join("x.exe").exists());
    }

    /// R2 (elevated): from the admin-only directory — the fixed one and the
    /// recorded fallback — only `updates\` goes; the keys and the migration
    /// markers stay (a reinstall still verifies the user's settings).
    #[test]
    fn the_uninstall_cleanup_keeps_the_keys_and_markers() {
        if !elevated_or_skip("the_uninstall_cleanup_keeps_the_keys_and_markers") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let fixed = ensure_in(base.path()).unwrap();
        let fallback = secure_named(base.path(), &random_state_name()).unwrap();
        let fallback_name = fallback.file_name().unwrap().to_str().unwrap().to_string();
        for dir in [&fixed, &fallback] {
            let updates = fresh_updates_dir_in(dir).unwrap();
            std::fs::create_dir(updates.join("BirdoVPN-1.4.48-updater-x")).unwrap();
            std::fs::write(
                updates
                    .join("BirdoVPN-1.4.48-updater-x")
                    .join("installer.exe"),
                "MZ",
            )
            .unwrap();
            std::fs::write(dir.join("settings-hmac-S-1-5-21-1.key"), "00").unwrap();
            std::fs::write(dir.join("dns-journal-migrated-S-1-5-21-1"), "").unwrap();
            std::fs::write(dir.join("pq-S-1-5-21-1.bin"), "k").unwrap();
        }

        let done = remove_uninstall_leftovers_in(base.path(), Some(fallback_name.clone()), false);

        assert_eq!(done.updates, 2, "{done:?}");
        assert_eq!(done.failed, 0, "{done:?}");
        for dir in [&fixed, &fallback] {
            assert!(!dir.join("updates").exists());
            for kept in [
                "settings-hmac-S-1-5-21-1.key",
                "dns-journal-migrated-S-1-5-21-1",
                "pq-S-1-5-21-1.bin",
            ] {
                assert!(dir.join(kept).exists(), "{kept} was deleted");
            }
        }

        // "Delete the application data" (D-23): the accounts' ML-KEM keys go
        // too; the settings keys and the markers still stay.
        let done = remove_uninstall_leftovers_in(base.path(), Some(fallback_name), true);
        assert_eq!(done.pq_keys, 2, "{done:?}");
        for dir in [&fixed, &fallback] {
            assert!(!dir.join("pq-S-1-5-21-1.bin").exists());
            for kept in [
                "settings-hmac-S-1-5-21-1.key",
                "dns-journal-migrated-S-1-5-21-1",
            ] {
                assert!(dir.join(kept).exists(), "{kept} was deleted");
            }
        }
    }

    /// Only an account keypair's name is one `--with-app-data` deletes — the
    /// name `vpn::birdo_pq` gives it.
    #[test]
    fn only_keypair_names_are_deleted_with_the_app_data() {
        assert!(is_pq_key_name(
            "pq-S-1-5-21-1004336348-1177238915-682003330-1001.bin"
        ));
        for not_ours in [
            "pq-.bin",
            "pq-S-.bin",
            "pq-S-1-5.bin.tmp",
            "pq-S-1-5-21-1.bin.0123456789abcdef.tmp",
            "settings-hmac-S-1-5-21-1.key",
            "pq-S-1-5-21-1.key",
            "pq-S-1-5-21-x.bin",
        ] {
            assert!(!is_pq_key_name(not_ours), "{not_ours}");
        }
        let source = include_str!("../vpn/birdo_pq.rs");
        assert!(source.contains(r#"name: format!("pq-{sid}.bin"),"#));
        assert!(is_pq_key_name(&format!(
            "pq-{}.bin",
            current_user_sid().unwrap()
        )));
    }

    /// D6c HIGH: the identifier the per-user sweep deletes is tauri.conf.json's.
    #[test]
    fn the_app_identifier_is_the_bundle_identifier() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"].as_str().unwrap(), APP_IDENTIFIER);
    }

    /// D6c HIGH: `--with-app-data` removes the five per-user folders, keeps the
    /// DNS journal in `%APPDATA%\BirdoVPN`, and follows NO junction — planted at
    /// the top of a folder or inside one — so files anywhere else survive.
    #[test]
    fn the_app_data_sweep_removes_the_folders_without_following_junctions() {
        let base = tempfile::tempdir().unwrap();
        let appdata = base.path().join("Roaming");
        let local = base.path().join("Local");
        let victim = base.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("precious.txt"), "keep").unwrap();

        // %APPDATA%\BirdoVPN: a journal to keep, logs to remove, and a junction
        // inside (logs\out -> victim) that must not be followed.
        let roam_birdo = appdata.join("BirdoVPN");
        std::fs::create_dir_all(roam_birdo.join("logs")).unwrap();
        std::fs::write(roam_birdo.join("dns-restore.json"), "{}").unwrap();
        std::fs::write(roam_birdo.join("dns-restore.json.corrupt"), "{}").unwrap();
        std::fs::write(roam_birdo.join("resume-after-update.json"), "x").unwrap();
        std::fs::write(roam_birdo.join("logs").join("birdo.log"), "x").unwrap();
        junction(&roam_birdo.join("logs").join("out"), &victim);

        // The four folders removed entirely; one holds a junction, one IS a
        // junction (the whole %LOCALAPPDATA%\Birdo VPN swapped for a link).
        std::fs::create_dir_all(local.join("BirdoVPN")).unwrap();
        std::fs::write(local.join("BirdoVPN").join("device_id"), "d").unwrap();
        junction(&local.join("BirdoVPN").join("out"), &victim);
        junction(&local.join("Birdo VPN"), &victim); // the folder itself is a junction
        std::fs::create_dir_all(appdata.join(APP_IDENTIFIER)).unwrap();
        std::fs::write(appdata.join(APP_IDENTIFIER).join("settings.json"), "{}").unwrap();
        std::fs::create_dir_all(local.join(APP_IDENTIFIER)).unwrap();

        let done = remove_app_data_folders_under(&appdata, &local, Some(base.path()));

        assert_eq!(done.failed, 0, "{done:?}");
        // The journal survives; everything else in %APPDATA%\BirdoVPN goes.
        assert!(roam_birdo.join("dns-restore.json").exists());
        assert!(roam_birdo.join("dns-restore.json.corrupt").exists());
        assert!(!roam_birdo.join("logs").exists());
        assert!(!roam_birdo.join("resume-after-update.json").exists());
        // The four folders are gone.
        assert!(!local.join("BirdoVPN").exists());
        assert!(std::fs::symlink_metadata(local.join("Birdo VPN")).is_err());
        assert!(!appdata.join(APP_IDENTIFIER).exists());
        assert!(!local.join(APP_IDENTIFIER).exists());
        // No junction was followed.
        assert_eq!(
            std::fs::read_to_string(victim.join("precious.txt")).unwrap(),
            "keep"
        );
    }

    /// D6c HIGH: a junction planted where `%APPDATA%\BirdoVPN` should be is
    /// unlinked, not entered, and its target's files survive.
    #[test]
    fn a_junctioned_appdata_folder_is_unlinked_not_entered() {
        let base = tempfile::tempdir().unwrap();
        let appdata = base.path().join("Roaming");
        let local = base.path().join("Local");
        std::fs::create_dir_all(&appdata).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let victim = base.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("precious.txt"), "keep").unwrap();
        junction(&appdata.join("BirdoVPN"), &victim);

        let done = remove_app_data_folders_under(&appdata, &local, Some(base.path()));

        assert_eq!(done.failed, 0, "{done:?}");
        assert!(std::fs::symlink_metadata(appdata.join("BirdoVPN")).is_err());
        assert!(
            std::fs::read_to_string(victim.join("precious.txt")).unwrap() == "keep",
            "the sweep entered a junctioned folder"
        );
    }

    /// D6c LOW-MEDIUM: a root that does not resolve under the user profile (a
    /// redirected %APPDATA%/%LOCALAPPDATA%) is refused — nothing is swept.
    #[test]
    fn a_root_outside_the_profile_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let appdata = base.path().join("Roaming");
        let local = base.path().join("Local");
        std::fs::create_dir_all(appdata.join("BirdoVPN")).unwrap();
        std::fs::create_dir_all(local.join("BirdoVPN")).unwrap();
        // A profile elsewhere: neither root is under it.
        let elsewhere = tempfile::tempdir().unwrap();

        let done = remove_app_data_folders_under(&appdata, &local, Some(elsewhere.path()));

        assert_eq!(done.app_data, 0);
        assert!(done.failed >= 1, "{done:?}");
        assert!(appdata.join("BirdoVPN").exists() && local.join("BirdoVPN").exists());
        // And with no profile at all, the same refusal.
        let done = remove_app_data_folders_under(&appdata, &local, None);
        assert_eq!(done.app_data, 0);
        assert!(appdata.join("BirdoVPN").exists());
    }

    /// D6c LOW-MEDIUM (elevated): a target that resolves onto an admin-only
    /// directory — e.g. a root redirected onto %ProgramData% so the fixed name
    /// hits the protected dir — is never swept, so the settings keys and markers
    /// survive.
    #[test]
    fn an_admin_only_target_is_never_swept() {
        if !elevated_or_skip("an_admin_only_target_is_never_swept") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let appdata = base.path().join("Roaming");
        let local = base.path().join("Local");
        std::fs::create_dir_all(&appdata).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        // Make %LOCALAPPDATA%\BirdoVPN an admin-only directory holding a key.
        let admin = secure_named(&local, "BirdoVPN").unwrap();
        std::fs::write(admin.join("settings-hmac-S-1-5-21-1.key"), "k").unwrap();

        let done = remove_app_data_folders_under(&appdata, &local, Some(base.path()));

        assert_eq!(done.failed, 0, "{done:?}");
        assert!(
            admin.join("settings-hmac-S-1-5-21-1.key").exists(),
            "an admin-only target was swept"
        );
        assert_eq!(inspect(&admin).unwrap(), State::AdminOnly);
    }

    /// Only the DNS-restore journal and its variants are kept.
    #[test]
    fn only_the_dns_journal_is_kept() {
        for keep in [
            "dns-restore.json",
            "dns-restore.json.corrupt",
            "dns-restore.json.tmp",
        ] {
            assert!(is_dns_journal_name(keep), "{keep}");
        }
        for go in [
            "birdo.log",
            "birdo.log.1",
            "resume-after-update.json",
            "device_id",
            "x.json",
        ] {
            assert!(!is_dns_journal_name(go), "{go}");
        }
    }

    /// M3: a fresh, privately named fallback directory is admin-only, the same
    /// as the fixed one. (The HKLM record is exercised by the real
    /// `resolve` path on a device; it is global machine state a unit test must
    /// not write.)
    #[test]
    fn a_fallback_named_directory_is_created_admin_only() {
        if !elevated_or_skip("a_fallback_named_directory_is_created_admin_only") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let dir = secure_named(base.path(), &random_state_name()).unwrap();
        assert!(Security::of(&open_for_security(&dir))
            .unwrap()
            .is_admin_only());
    }

    /// MEDIUM 2 (#287 review): once a fallback directory is recorded, `resolve`
    /// uses it FIRST and never touches the fixed `BirdoVPN` name — so a
    /// squatter who freed the fixed name later cannot make the app adopt it and
    /// re-open the migration. The HKLM read/write is injected here.
    #[test]
    fn resolve_prefers_the_recorded_fallback_over_the_fixed_name() {
        if !elevated_or_skip("resolve_prefers_the_recorded_fallback_over_the_fixed_name") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        // Pre-create the recorded fallback as a real admin-only directory.
        let recorded = secure_named(base.path(), &random_state_name()).unwrap();
        let name = recorded.file_name().unwrap().to_str().unwrap().to_string();

        let got = resolve_with(base.path(), &|| Some(name.clone()), &|_| {
            panic!("a new name must not be recorded when one already resolves")
        })
        .unwrap();
        assert_eq!(got, recorded, "the recorded fallback is used");
        assert!(
            !base.path().join(DIR_NAME).exists(),
            "the fixed name must not be secured or created"
        );
    }

    /// With nothing recorded, `resolve` uses the fixed name.
    #[test]
    fn resolve_uses_the_fixed_name_when_nothing_is_recorded() {
        if !elevated_or_skip("resolve_uses_the_fixed_name_when_nothing_is_recorded") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let got = resolve_with(base.path(), &|| None, &|_| {
            panic!("the fixed name must not record a fallback")
        })
        .unwrap();
        assert_eq!(got, base.path().join(DIR_NAME));
    }

    /// A recorded value that is not a plain name (a crafted HKLM value) is not
    /// used as a path; a fresh private one is minted and recorded instead, and
    /// the fixed name is still never used.
    #[test]
    fn a_crafted_recorded_value_mints_a_fresh_private_name() {
        if !elevated_or_skip("a_crafted_recorded_value_mints_a_fresh_private_name") {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let minted = std::cell::RefCell::new(None);
        let got = resolve_with(base.path(), &|| Some(r"..\..\Windows".to_string()), &|n| {
            *minted.borrow_mut() = Some(n.to_string())
        })
        .unwrap();
        let minted = minted.borrow().clone().expect("a fresh name was recorded");
        assert!(minted.starts_with("BirdoVPN-"), "{minted}");
        assert_eq!(got, base.path().join(&minted));
        assert!(
            !base.path().join(DIR_NAME).exists(),
            "the fixed name is untouched"
        );
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
        // (Names, not "Users" alone: icacls prints the path, C:\Users\….)
        for nobody in [r"BUILTIN\Users", "Authenticated Users", "Everyone", "(I)"] {
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
