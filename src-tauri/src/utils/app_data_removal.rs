//! MR-654: "delete the application data" on macOS and Linux, which have no
//! uninstaller to do it (owner decision 2026-10-07: yes). The twin of the
//! Windows uninstaller's sweep (`protected_dir::remove_uninstall_leftovers`,
//! D-23 / D6c): the exe run with `--remove-leftovers-and-exit
//! --with-app-data` removes what BirdoVPN keeps for an account on this
//! machine —
//!
//! - the keystore entries (macOS Keychain, Linux Secret Service; service
//!   `BirdoVPN`): the access and refresh tokens, the settings HMAC key and the
//!   biometric flag, the four the NSIS hook deletes from Credential Manager
//!   (pinned to it by a test);
//! - the folders: the ML-KEM keypair and the device id
//!   (`<config_local_dir>/BirdoVPN`), the log and the other records
//!   (`<data_dir>/BirdoVPN`), the crash reports (`<data_local_dir>/Birdo VPN`),
//!   settings.json, its key file and the consent record
//!   (`<config_dir>/<identifier>`), and the WebView's folders
//!   (`<identifier>` under the data, local data and cache folders, and
//!   `~/Library/WebKit/<identifier>` on macOS).
//!
//! WHO RUNS IT. The user, before deleting the app (macOS, the AppImage), the
//! same way they run the app (as root), so the folders and the keystore are
//! the ones the app itself used: docs/UNINSTALL.md. A .deb's `apt purge`
//! removes root's folders itself (src-tauri/linux/postrm.sh): dpkg has
//! deleted this exe before that script runs, so it cannot call it, and a test
//! here keeps its list the same as this one.
//!
//! NEVER FOLLOWS A LINK. A folder goes with `std::fs::remove_dir_all`, which
//! deletes a link standing in place of the folder as a link, opens every
//! folder below it without following one (`openat` with `O_NOFOLLOW`), and
//! deletes a link inside as a link; anything else is unlinked. So a link
//! planted in a folder the user can write never makes root delete what it
//! points at. The roots come from HOME and the XDG variables, which belong to
//! whoever runs this as root, who could delete anything anyway; the names
//! under them are fixed, the app's own.
//!
//! KEPT, as on Windows (W1-008): the root-only state directory
//! (`root_state::STATE_DIR`), whose DNS and route journals (and macOS's pf
//! reference record) are what a reinstall needs to put back what a killed
//! session changed. Nothing in it is secret.

use std::io;
use std::path::{Path, PathBuf};

use crate::utils::file_log::APP_IDENTIFIER;

/// The keystore service every entry below is stored under.
const KEYSTORE_SERVICE: &str = "BirdoVPN";

/// Every keystore entry the app writes: the tokens
/// (`storage::credentials`), the settings HMAC key (`commands::settings`)
/// and the biometric flag (`commands::biometric`). The NSIS hook deletes the
/// same four (pinned by `the_keystore_entries_are_the_windows_uninstallers`).
pub(crate) const KEYSTORE_ENTRIES: [&str; 4] = [
    "access_token",
    "refresh_token",
    "settings_hmac_key",
    "biometric_lock_enabled",
];

/// What [`remove_app_data`] did, in counts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// Folders (or links, or files, in a folder's place) removed.
    pub folders: u32,
    /// Keystore entries deleted.
    pub keystore_entries: u32,
    /// Folders or entries that could not be removed (each one is printed).
    pub failed: u32,
}

/// Where this platform keeps each kind of per-user folder (the `dirs`
/// crate's answers, which Tauri and the app use), or a scratch home's in a
/// test.
pub(crate) struct Roots {
    pub config: Option<PathBuf>,
    pub config_local: Option<PathBuf>,
    pub data: Option<PathBuf>,
    pub data_local: Option<PathBuf>,
    pub cache: Option<PathBuf>,
    /// macOS: the home folder, for `~/Library/WebKit`.
    pub home: Option<PathBuf>,
}

impl Roots {
    fn of_this_user() -> Self {
        Self {
            config: dirs::config_dir(),
            config_local: dirs::config_local_dir(),
            data: dirs::data_dir(),
            data_local: dirs::data_local_dir(),
            cache: dirs::cache_dir(),
            home: dirs::home_dir(),
        }
    }

    /// Every folder the sweep removes, each once (on macOS the config and
    /// data folders are one, so `BirdoVPN` would come up twice).
    pub(crate) fn folders(&self) -> Vec<PathBuf> {
        let under = |root: &Option<PathBuf>, rel: &[&str]| {
            root.as_ref()
                .map(|root| rel.iter().fold(root.clone(), |p, part| p.join(part)))
        };
        let mut folders = vec![
            // The ML-KEM keypair (birdo_pq.rs) and the device id.
            under(&self.config_local, &["BirdoVPN"]),
            // settings.json, settings_hmac.key, consent.json.
            under(&self.config, &[APP_IDENTIFIER]),
            // The log and the app's other records.
            under(&self.data, &["BirdoVPN"]),
            // The crash reports (file_log::crash_dir_in).
            under(&self.data_local, &["Birdo VPN"]),
            // Tauri's app data, local data and cache: the WebView's storage.
            under(&self.data, &[APP_IDENTIFIER]),
            under(&self.data_local, &[APP_IDENTIFIER]),
            under(&self.cache, &[APP_IDENTIFIER]),
        ];
        if cfg!(target_os = "macos") {
            folders.push(under(&self.home, &["Library", "WebKit", APP_IDENTIFIER]));
        }
        let mut unique: Vec<PathBuf> = Vec::new();
        for folder in folders.into_iter().flatten() {
            if !unique.contains(&folder) {
                unique.push(folder);
            }
        }
        unique
    }
}

/// Remove this user's BirdoVPN data: the keystore entries and the folders
/// (see the module docs). Prints each failure to stderr: it runs before any
/// log is set up, from a terminal.
pub fn remove_app_data() -> Removed {
    remove_app_data_with(&Roots::of_this_user(), delete_keystore_entry)
}

/// [`remove_app_data`] with the roots and the keystore injected, so a test
/// sweeps a scratch home and never the real keystore. `delete_entry` returns
/// whether there was an entry to delete.
pub(crate) fn remove_app_data_with(
    roots: &Roots,
    mut delete_entry: impl FnMut(&str) -> Result<bool, String>,
) -> Removed {
    let mut done = Removed::default();
    for name in KEYSTORE_ENTRIES {
        match delete_entry(name) {
            Ok(true) => done.keystore_entries += 1,
            Ok(false) => {}
            Err(e) => {
                eprintln!("could not delete the keystore entry {name}: {e}");
                done.failed += 1;
            }
        }
    }
    for folder in roots.folders() {
        match remove_no_follow(&folder) {
            Ok(true) => done.folders += 1,
            Ok(false) => {}
            Err(e) => {
                eprintln!("could not remove {}: {e}", folder.display());
                done.failed += 1;
            }
        }
    }
    done
}

/// Delete one keystore entry: `Ok(false)` when there was none.
fn delete_keystore_entry(name: &str) -> Result<bool, String> {
    let entry = keyring::Entry::new(KEYSTORE_SERVICE, name).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

/// Remove `path` and everything under it without following a link at any
/// level; `Ok(false)` when there is nothing there. A folder goes with
/// `remove_dir_all` (see the module docs); anything else in its place (a
/// link, to a folder or not, or a file) is unlinked.
fn remove_no_follow(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path).map(|()| true),
        Ok(_) => std::fs::remove_file(path).map(|()| true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    /// A Linux-shaped home under `home` (on macOS the same shape serves: the
    /// sweep only joins names onto whatever roots it is given).
    fn roots_in(home: &Path) -> Roots {
        Roots {
            config: Some(home.join(".config")),
            config_local: Some(home.join(".config")),
            data: Some(home.join(".local/share")),
            data_local: Some(home.join(".local/share")),
            cache: Some(home.join(".cache")),
            home: Some(home.to_path_buf()),
        }
    }

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// MR-654: the ML-KEM key, the device id, settings and their key, the
    /// consent record, the log, the crash reports and the WebView's folders
    /// go, and every keystore entry is asked for. What is next to them, and
    /// what a planted link points at, stays.
    #[test]
    fn the_sweep_removes_the_app_data_and_follows_no_link() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("home");
        let outside = scratch.path().join("outside");
        write(&outside.join("keep.txt"), "not ours");
        write(&outside.join("BirdoVPN/keep.txt"), "not ours either");

        let ours = [
            ".config/BirdoVPN/birdo_pq_v1.bin",
            ".config/BirdoVPN/device_id",
            ".config/uk.birdo.vpn.desktop/settings.json",
            ".config/uk.birdo.vpn.desktop/settings_hmac.key",
            ".config/uk.birdo.vpn.desktop/consent.json",
            ".local/share/BirdoVPN/logs/birdo.log",
            ".local/share/BirdoVPN/logs/birdo.log.1",
            ".local/share/Birdo VPN/crashes/crash_1.txt",
            ".local/share/uk.birdo.vpn.desktop/storage/localstorage",
        ];
        for rel in ours {
            write(&home.join(rel), "fake");
        }
        // Not ours: a neighbour in the same parent folders.
        write(&home.join(".config/other-app/settings.json"), "kept");
        write(&home.join(".local/share/other-app/data"), "kept");
        // Links a user could plant: inside a swept folder (to a folder and to
        // a file), and in place of a swept folder (the WebView cache).
        symlink(&outside, home.join(".local/share/BirdoVPN/logs/planted")).unwrap();
        symlink(
            outside.join("keep.txt"),
            home.join(".config/BirdoVPN/planted.bin"),
        )
        .unwrap();
        fs::create_dir_all(home.join(".cache")).unwrap();
        symlink(&outside, home.join(".cache/uk.birdo.vpn.desktop")).unwrap();

        let mut asked = Vec::new();
        let done = remove_app_data_with(&roots_in(&home), |name| {
            asked.push(name.to_string());
            Ok(name == "access_token")
        });

        for rel in ours {
            assert!(
                fs::symlink_metadata(home.join(rel)).is_err(),
                "{rel} survived"
            );
        }
        for rel in [
            ".config/BirdoVPN",
            ".config/uk.birdo.vpn.desktop",
            ".local/share/BirdoVPN",
            ".local/share/Birdo VPN",
            ".local/share/uk.birdo.vpn.desktop",
            ".cache/uk.birdo.vpn.desktop",
        ] {
            assert!(
                fs::symlink_metadata(home.join(rel)).is_err(),
                "{rel} survived"
            );
        }
        assert_eq!(
            fs::read_to_string(outside.join("keep.txt")).unwrap(),
            "not ours"
        );
        assert_eq!(
            fs::read_to_string(outside.join("BirdoVPN/keep.txt")).unwrap(),
            "not ours either",
            "the sweep followed a planted link"
        );
        assert!(home.join(".config/other-app/settings.json").exists());
        assert!(home.join(".local/share/other-app/data").exists());
        assert_eq!(asked, KEYSTORE_ENTRIES.to_vec());
        assert_eq!(
            done,
            Removed {
                folders: 6,
                keystore_entries: 1,
                failed: 0
            }
        );

        // Nothing left: a second run removes nothing and fails nothing.
        let again = remove_app_data_with(&roots_in(&home), |_| Ok(false));
        assert_eq!(again, Removed::default());
    }

    /// A keystore that cannot be reached (no session bus under sudo on
    /// Linux) is reported, and the folders still go.
    #[test]
    fn an_unreachable_keystore_is_reported_and_the_folders_still_go() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path();
        write(&home.join(".config/BirdoVPN/birdo_pq_v1.bin"), "fake");
        let done = remove_app_data_with(&roots_in(home), |_| Err("no keystore".into()));
        assert_eq!(done.failed, KEYSTORE_ENTRIES.len() as u32);
        assert_eq!(done.folders, 1);
        assert!(!home.join(".config/BirdoVPN").exists());
    }

    /// The four entries are the ones the Windows uninstaller deletes from
    /// Credential Manager ("<name>.BirdoVPN"), and the app's own writers name
    /// them so.
    #[test]
    fn the_keystore_entries_are_the_windows_uninstallers() {
        let hook = include_str!("../../nsis-hooks.nsh");
        let deleted: Vec<&str> = hook
            .lines()
            .filter_map(|line| line.split("CredDeleteW(w \"").nth(1))
            .filter_map(|rest| rest.split(".BirdoVPN\"").next())
            .collect();
        assert_eq!(deleted, KEYSTORE_ENTRIES.to_vec());

        let writers = [
            include_str!("../storage/credentials.rs"),
            include_str!("../commands/settings.rs"),
            include_str!("../commands/biometric.rs"),
        ]
        .concat();
        for name in KEYSTORE_ENTRIES {
            assert!(writers.contains(&format!("\"{name}\"")), "{name}");
        }
        assert!(writers.contains(&format!("\"{KEYSTORE_SERVICE}\"")));
    }

    /// Every place the app writes per-user data is inside a swept folder:
    /// the log, the crash reports and settings.json (the ML-KEM key and the
    /// device id are `<config_local_dir>/BirdoVPN` by construction).
    #[test]
    fn every_per_user_folder_of_the_app_is_swept() {
        let folders = Roots::of_this_user().folders();
        let swept = |path: &Path| folders.iter().any(|folder| path.starts_with(folder));
        let log = crate::utils::file_log::log_dir().unwrap();
        assert!(swept(log.path()), "{}", log.path().display());
        let crashes = crate::utils::file_log::crash_dir().unwrap();
        assert!(swept(crashes.path()), "{}", crashes.path().display());
        let settings = crate::utils::file_log::settings_path().unwrap();
        assert!(swept(&settings), "{}", settings.display());
        let pq = dirs::config_local_dir().unwrap().join("BirdoVPN");
        assert!(folders.contains(&pq));
        assert!(include_str!("../vpn/birdo_pq.rs").contains("OwnedDir::new(base, &[\"BirdoVPN\"])"));
    }

    /// The .deb's `apt purge` (linux/postrm.sh) removes the same folders, for
    /// root's home: it cannot run this exe, which dpkg deleted before it.
    #[test]
    fn the_deb_purge_removes_the_same_folders() {
        let script = include_str!("../../linux/postrm.sh");
        let home = Path::new("$home");
        let linux = Roots {
            home: None, // ~/Library/WebKit is macOS only
            ..roots_in(home)
        };
        let folders = linux.folders();
        assert_eq!(folders.len(), 6);
        for folder in folders {
            let quoted = format!("\"{}\"", folder.display());
            assert!(script.contains(&quoted), "postrm.sh lacks {quoted}");
        }
        assert_eq!(
            script.matches("\"$home/").count(),
            6,
            "postrm.sh removes more"
        );
    }
}
