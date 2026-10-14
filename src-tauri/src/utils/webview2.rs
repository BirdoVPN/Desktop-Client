//! WebView2, the engine that draws the app's window on Windows, and what it
//! leaves on this device (MR-1946).
//!
//! ITS CRASH REPORTS STAY HERE. At its default, WebView2 hands a crash of one
//! of its own processes (the page, the GPU process, the browser process) to
//! Windows, which sends it to Microsoft whenever the user's Windows
//! diagnostic-data settings allow: `IsCustomCrashReportingEnabled` defaults to
//! FALSE, and then "WebView will respect OS consent". The app sets it TRUE:
//! "Windows won't send crash data to Microsoft endpoint"
//! (`ICoreWebView2EnvironmentOptions3`, WebView2 1.0.1518.46 and later). The
//! dumps stay in WebView2's own Crashpad folder on this device, where the
//! app's delete and its launch sweep reach them (below). It changes nothing
//! about the required diagnostic data Windows itself may send about WebView2.
//!
//! HOW, AND WHY THIS WAY. Neither Tauri 2.12 nor wry 0.57 has a setting for
//! it. wry builds its options from `CoreWebView2EnvironmentOptions::default()`
//! and sets only the browser arguments, extensions, language and scroll-bar
//! style (wry-0.57.0/src/webview2/mod.rs, `create_environment`). What both do
//! take is a ready-made environment, which wry then uses instead of making its
//! own (`WebviewWindowBuilder::with_environment`; wry `new_in_hwnd`). So
//! [`create_environment`] makes the environment wry would have made, with the
//! same options, plus this one, and `main.rs` builds the main window with it
//! (tauri.conf.json says `"create": false` for it). A test holds the options
//! to wry's source, so a wry update that changes them fails here rather than
//! quietly changing the window.
//!
//! NOT `additionalBrowserArgs`. The runtime turns the option into a browser
//! switch, `--edge-webview-disable-crash-reporting=1` on the browser process
//! (seen with WebView2 155.0.4283.45). That switch is not documented, so the
//! app does not depend on it being spelled that way tomorrow; it is only how
//! a device can be checked (see the MR-1946 PR). The `WEBVIEW2_*` environment
//! variables cannot carry the option at all: they override the browser
//! folder, user data folder, release channels and browser arguments only.
//!
//! EVERY WEBVIEW MUST SHARE IT. WebView2 refuses a webview whose environment
//! options differ from those of the webviews already running in the shared
//! browser process (`ERROR_INVALID_STATE`). The app has one window; a second
//! one must be built with the same environment, not left to wry.
//!
//! THE DUMPS. Crashpad keeps them as `<uuid>.dmp` directly in
//! `<user data folder>\EBWebView\Crashpad\reports`, pending and uploaded alike:
//! on Windows a report's state lives in Crashpad's `metadata` file, not in a
//! `pending` directory (crashpad `client/crash_report_database_win.cc`).
//! Nothing sends them now, and nothing else clears them on the app's terms, so
//! the app deletes them itself: all of them on "Delete Logs Now"
//! (`file_log::delete_logs`), and at every launch those older than the log's
//! retention window, keeping at most the newest
//! `log_retention::KEEP_CRASH_REPORTS`, the same rule as the app's own crash
//! files. Only `<uuid>.dmp` files directly in that one folder, reached through
//! real directories only (never a link or a junction: the app runs elevated
//! and the folder is the user's to write). Crashpad's own files (`metadata`,
//! `settings.dat`, `attachments\`) are left to Crashpad, which drops the index
//! entry, and any attachments, of a report whose dump is gone the next time it
//! cleans its database.
//!
//! THE DELETES RUN ELEVATED (MR-1945), so they go through `safe_fs` like the
//! app's own logs and crash files: the folder is an [`OwnedDir`] (the local
//! data directory as its root, the four folders below it as the app's), held
//! open for the call once every level has been opened without following a
//! reparse point and found at its expected final path, and each dump is
//! deleted through a handle checked to be exactly that file
//! ([`OwnedDir::remove_file`]), never by path. On Windows the root itself is
//! checked first, with the uninstaller sweep's guard (D6c,
//! `protected_dir::hold_user_root`): opened by handle, refused if it is a
//! link, its final path under the user's own profile directory, then held
//! for the call, and the work goes on at that final path. A `%LOCALAPPDATA%`
//! redirected (or junctioned) onto another account's profile is refused.
//!
//! THE USER DATA FOLDER is made the same way (`OwnedDir::hold_open`, inside
//! its verified parent). If it cannot be verified (a junction in its place),
//! that is logged, and WebView2 still gets this environment, crash reports
//! kept on this device: refusing would only open the window on WebView2's
//! defaults, through the same folder, with crash upload left to Windows.

// Off Windows only the tests reach the dump helpers: WebKit keeps no such
// folder (see the MR-1946 PR), so nothing calls them there.
#![cfg_attr(not(windows), allow(dead_code))]

use std::io;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use chrono::{DateTime, Utc};

use super::file_log::{self, Deleted};
use super::log_retention;
use super::safe_fs::{DirGuard, OwnedDir};

/// The folder the app gives WebView2 as its user data folder:
/// `<local data dir>\uk.birdo.vpn.desktop`, which is Tauri's
/// `app_local_data_dir()`, the folder Tauri would have given it (tauri 2.12,
/// `manager/webview.rs`). WebView2 keeps everything in `EBWebView` inside it.
/// One of the app's directories ([`OwnedDir`]), so that the elevated app
/// creates it the way it creates any folder in the user's profile.
fn user_data_owned_dir(local_data: &Path) -> OwnedDir {
    OwnedDir::new(local_data, &[file_log::APP_IDENTIFIER])
}

/// [`user_data_owned_dir`]'s path.
#[cfg(test)]
fn user_data_dir_in(local_data: &Path) -> PathBuf {
    user_data_owned_dir(local_data).path().to_path_buf()
}

/// Where Crashpad keeps WebView2's dumps, below the local data directory.
const DUMP_DIR: [&str; 4] = [file_log::APP_IDENTIFIER, "EBWebView", "Crashpad", "reports"];

/// The dump folder below `local_data` as one of the app's directories: the
/// local data directory is the root the OS hands out, and the four folders
/// below it are the app's, checked by handle on every delete (`safe_fs`).
fn dump_dir_in(local_data: &Path) -> OwnedDir {
    OwnedDir::new(local_data, &DUMP_DIR)
}

/// A Crashpad dump's name: `<uuid>.dmp`, the UUID in its 8-4-4-4-12 hex form
/// (crashpad `crash_report_database_win.cc`, `kCrashReportFileExtension`).
/// Nothing else in the folder is the app's to delete.
pub fn is_dump_name(name: &str) -> bool {
    let Some(uuid) = name.strip_suffix(".dmp") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// What [`known_dir`] found.
enum KnownDir {
    /// Every part is a real directory.
    Found,
    /// A part does not exist: nothing was ever written below it.
    Absent,
    /// A link, a junction or a file where a directory should be, or a part
    /// that cannot be read.
    Refused,
}

/// `base` joined with `parts`, checking every part on the way down with
/// `symlink_metadata`, which follows neither a symlink nor a junction (std
/// reports a junction as a link: `file_log`'s junction test pins that). A link
/// at any level is refused, not only at the last one: the parts below
/// `%LOCALAPPDATA%` are the user's to create, and this runs elevated.
///
/// A first pass by path, which tells a folder that was never made from one
/// that is refused; [`open_dumps`] then checks every level again by handle.
fn known_dir(base: &Path, parts: &[&str]) -> KnownDir {
    let mut dir = base.to_path_buf();
    for part in parts {
        dir.push(part);
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return KnownDir::Refused,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return KnownDir::Absent,
            Err(_) => return KnownDir::Refused,
        }
    }
    KnownDir::Found
}

/// What [`open_dumps`] found.
enum Dumps {
    /// The dump folder, verified, and held open while the guard lives: it
    /// cannot be renamed or swapped for a junction meanwhile.
    Held(OwnedDir, DirGuard),
    /// No dump folder: nothing was ever written there.
    Absent,
    /// A link, a junction or a file where a folder should be, or a folder
    /// that cannot be verified.
    Refused,
}

/// The dump folder below `local_data`, held for the caller's deletes. After
/// [`known_dir`]'s pass by path, [`OwnedDir::hold_open_if_present`] (which
/// creates nothing) opens every level again without following a reparse
/// point, checks each one's final path, and holds the folder. A listing of it
/// is still only a snapshot, so each delete is [`OwnedDir::remove_file`],
/// through a handle checked to be exactly that file.
fn open_dumps(local_data: &Path) -> Dumps {
    match known_dir(local_data, &DUMP_DIR) {
        KnownDir::Found => {}
        KnownDir::Absent => return Dumps::Absent,
        KnownDir::Refused => return Dumps::Refused,
    }
    let dir = dump_dir_in(local_data);
    match dir.hold_open_if_present() {
        Ok(Some(guard)) => Dumps::Held(dir, guard),
        Ok(None) => Dumps::Absent,
        Err(_) => Dumps::Refused,
    }
}

/// Delete every WebView2 crash dump below `local_data` (the platform's local
/// data directory), adding to `tally`: counts only, never a path. The same
/// per-file rules as the rest of "Delete Logs Now" (`file_log::delete_in`):
/// regular files only, by name, never recursive, each through a checked
/// handle ([`OwnedDir::remove_file`]).
pub fn delete_dumps_in(local_data: &Path, tally: &mut Deleted) {
    match open_dumps(local_data) {
        Dumps::Held(dir, _held) => file_log::delete_in(&dir, is_dump_name, tally),
        Dumps::Absent => {}
        Dumps::Refused => tally.failed += 1,
    }
}

/// The local data directory, the root the dump folder is found under, held
/// for the caller's work if it is the user's own (see the module docs and
/// `protected_dir::hold_user_root`): `Some(Err)` when it is not, `None` when
/// the OS has none. The work goes on at the held root's final path.
#[cfg(windows)]
fn local_data_root() -> Option<std::io::Result<super::protected_dir::UserRoot>> {
    dirs::data_local_dir().map(|local_data| super::protected_dir::hold_user_root(&local_data))
}

/// "Delete Logs Now", WebView2's part: Windows only, where the dumps are. A
/// local data directory that is not the user's own is refused, and counted.
#[cfg(windows)]
pub fn delete_dumps(tally: &mut Deleted) {
    match local_data_root() {
        Some(Ok(root)) => delete_dumps_in(root.path(), tally),
        Some(Err(_)) => tally.failed += 1,
        None => {}
    }
}

/// The launch sweep for WebView2's dumps: every dump older than the log's
/// retention window goes, and of the rest only the newest `keep` stay, the
/// rule `log_retention::prune_crash_reports` applies to the app's own crash
/// files. A Crashpad name carries no date, so a dump is dated by when it was
/// last written; one whose time cannot be read is left alone, like an undated
/// log. Best-effort and silent: never worth failing a launch over. Every
/// delete goes through the held folder ([`OwnedDir::remove_file`]), never a
/// path, as `prune_crash_reports`'s do.
pub fn prune_dumps_in(local_data: &Path, now: DateTime<Utc>, keep: usize) {
    let Dumps::Held(dir, _held) = open_dumps(local_data) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir.path()) else {
        return;
    };
    let cutoff = log_retention::cutoff(now);
    let mut recent: Vec<(DateTime<Utc>, String)> = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_dump_name(&name) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(dir.join(&name)) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let Ok(written) = meta.modified().map(DateTime::<Utc>::from) else {
            continue;
        };
        if written < cutoff {
            let _ = dir.remove_file(&name);
        } else {
            recent.push((written, name));
        }
    }
    recent.sort();
    let excess = recent.len().saturating_sub(keep);
    for (_, name) in &recent[..excess] {
        let _ = dir.remove_file(name);
    }
}

/// The launch sweep, run by `main()` before Tauri starts, so before this
/// session's WebView2 (and its Crashpad handler) is running. Windows only; a
/// local data directory that is not the user's own is left alone.
#[cfg(windows)]
pub fn prune_dumps(now: DateTime<Utc>) {
    if let Some(Ok(root)) = local_data_root() {
        prune_dumps_in(root.path(), now, log_retention::KEEP_CRASH_REPORTS);
    }
}

/// Build the main window from its tauri.conf.json entry: on Windows with the
/// environment from [`create_environment`], elsewhere exactly as Tauri would.
///
/// If that environment cannot be made, the window is built on WebView2's
/// defaults rather than not at all, and the log says so: a WebView2 that
/// cannot start fails the same way either way, and an app with no window is
/// not the answer to where its engine's crash reports go.
pub fn build_main_window(
    app: &tauri::AppHandle,
    config: &tauri::utils::config::WindowConfig,
) -> tauri::Result<tauri::WebviewWindow> {
    let builder = tauri::WebviewWindowBuilder::from_config(app, config)?;
    #[cfg(windows)]
    let builder = match dirs::data_local_dir().map(|dir| create_environment(&dir)) {
        Some(Ok(environment)) => builder.with_environment(environment),
        Some(Err(e)) => {
            tracing::warn!(
                "WebView2: the environment could not be created ({e}); the window opens on WebView2's defaults, which may send its crash reports to Microsoft"
            );
            builder
        }
        None => {
            tracing::warn!(
                "WebView2: no local data directory; the window opens on WebView2's defaults, which may send its crash reports to Microsoft"
            );
            builder
        }
    };
    builder.build()
}

/// The browser arguments wry passes when the app sets none: its defaults
/// (wry-0.57.0/src/webview2/mod.rs, `create_environment`), with the autoplay
/// policy because wry's `autoplay` defaults to on and Tauri never changes it.
/// No `--proxy-server`: the app configures no proxy. Held to wry's source by
/// a test.
#[cfg(windows)]
const BROWSER_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
                            --autoplay-policy=no-user-gesture-required";

/// The WebView2 environment for the app's window: what wry would make for it
/// (its browser arguments, extensions off, the user's display language,
/// default scroll bars, the same user data folder), with WebView2's crash
/// reports kept on this device. `local_data` is the local data directory; the
/// user data folder is [`user_data_owned_dir`] in it. Must run on the main thread,
/// before the window is built: it pumps that thread's messages until WebView2
/// answers, as wry does.
#[cfg(windows)]
pub fn create_environment(
    local_data: &Path,
) -> webview2_com::Result<webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Environment> {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        CreateCoreWebView2EnvironmentWithOptions, ICoreWebView2EnvironmentOptions,
        COREWEBVIEW2_SCROLLBAR_STYLE_DEFAULT,
    };
    use webview2_com::{
        CoreWebView2EnvironmentOptions, CreateCoreWebView2EnvironmentCompletedHandler,
    };
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{E_POINTER, E_UNEXPECTED};
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};

    // Tauri creates the user data folder before it builds a webview; this
    // runs first, so it does the same, the way the elevated app makes any
    // folder in the user's profile (R5, `safe_fs`): never `create_dir_all` by
    // path, but inside its verified parent, and refused if a link or a
    // junction is in its place. A refusal does NOT stop the environment:
    // without it the window would open on WebView2's defaults, through the
    // very same folder (Tauri and wry use this path too), with crash upload
    // left to Windows. So it is logged (no path in it), and WebView2's crash
    // reports stay on this device regardless.
    let user_data = user_data_owned_dir(local_data);
    if let Err(e) = user_data.hold_open() {
        tracing::warn!(
            "WebView2: the user data folder could not be verified ({e}); its crash reports stay on this device all the same"
        );
    }

    // What wry's `new_in_hwnd` does first, result ignored the same way.
    let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };

    let options = CoreWebView2EnvironmentOptions::default();
    // SAFETY: the options object is not shared yet; these only store values.
    unsafe {
        options.set_additional_browser_arguments(BROWSER_ARGS.to_string());
        options.set_are_browser_extensions_enabled(false);
        options.set_language(user_display_language());
        options.set_scroll_bar_style(COREWEBVIEW2_SCROLLBAR_STYLE_DEFAULT);
        // MR-1946: WebView2's crash reports stay on this device.
        options.set_is_custom_crash_reporting_enabled(true);
    }
    let options = ICoreWebView2EnvironmentOptions::from(options);

    let (tx, rx) = std::sync::mpsc::channel();
    // SAFETY: called on the UI thread with valid arguments; the completion
    // handler is called back on this thread while `wait_with_pump` pumps it.
    unsafe {
        CreateCoreWebView2EnvironmentWithOptions(
            PCWSTR::null(),
            &HSTRING::from(user_data.path()),
            &options,
            &CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(
                move |error_code, environment| {
                    let result = error_code.and_then(|()| {
                        environment.ok_or_else(|| windows::core::Error::from(E_POINTER))
                    });
                    tx.send(result)
                        .map_err(|_| windows::core::Error::from(E_UNEXPECTED))
                },
            )),
        )?;
    }
    Ok(webview2_com::wait_with_pump(rx)??)
}

/// The user's Windows display language as a locale name, as wry sets it
/// (`GetUserDefaultUILanguage` + `LCIDToLocaleName`). Empty if Windows cannot
/// name it, which leaves WebView2 on its default, as wry's empty buffer does.
#[cfg(windows)]
fn user_display_language() -> String {
    use windows::Win32::Globalization::{
        GetUserDefaultUILanguage, LCIDToLocaleName, LOCALE_ALLOW_NEUTRAL_NAMES, MAX_LOCALE_NAME,
    };
    let mut name = [0u16; MAX_LOCALE_NAME as usize];
    // SAFETY: the buffer outlives the call, which writes at most its length.
    let written = unsafe {
        LCIDToLocaleName(
            u32::from(GetUserDefaultUILanguage()),
            Some(&mut name),
            LOCALE_ALLOW_NEUTRAL_NAMES,
        )
    };
    // `written` counts the terminating NUL; 0 is a failure.
    let len = usize::try_from(written).unwrap_or(0).saturating_sub(1);
    String::from_utf16_lossy(&name[..len.min(name.len())])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    const DUMP_A: &str = "0f8fad5b-d9cb-469f-a165-70867728950e.dmp";
    const DUMP_B: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7.dmp";
    const DUMP_C: &str = "C56A4180-65AA-42EC-A945-5FD21DEC0538.dmp";

    fn write(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"MDMP").unwrap();
        p
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A local data directory with WebView2's folders in it, as the runtime
    /// lays them out. Returns (local data dir, reports dir).
    fn webview_tree() -> (tempfile::TempDir, PathBuf) {
        let local = tempfile::tempdir().unwrap();
        let crashpad = user_data_dir_in(local.path())
            .join("EBWebView")
            .join("Crashpad");
        let reports = crashpad.join("reports");
        std::fs::create_dir_all(&reports).unwrap();
        (local, reports)
    }

    fn deleted(local: &Path) -> Deleted {
        let mut tally = Deleted::default();
        delete_dumps_in(local, &mut tally);
        tally
    }

    /// The scope: Crashpad's `<uuid>.dmp` files in `reports`, nothing else.
    /// Crashpad's bookkeeping, its attachments, the rest of WebView2's profile
    /// and anything else in `reports` stay.
    #[test]
    fn only_the_crashpad_dumps_are_deleted() {
        let (local, reports) = webview_tree();
        let crashpad = reports.parent().unwrap().to_path_buf();
        for name in [DUMP_A, DUMP_B, DUMP_C] {
            write(&reports, name);
        }
        for name in [
            "notes.txt",
            "x.dmp",
            "0f8fad5b-d9cb-469f-a165-70867728950e.dmp.tmp",
        ] {
            write(&reports, name);
        }
        for name in ["metadata", "settings.dat", "throttle_store.dat"] {
            write(&crashpad, name);
        }
        let attachment = crashpad
            .join("attachments")
            .join("0f8fad5b-d9cb-469f-a165-70867728950e");
        std::fs::create_dir_all(&attachment).unwrap();
        write(&attachment, DUMP_B);
        let profile = crashpad.parent().unwrap().join("Default");
        std::fs::create_dir_all(&profile).unwrap();
        let cookies = write(&profile, "Cookies");

        assert_eq!(
            deleted(local.path()),
            Deleted {
                deleted: 3,
                failed: 0
            }
        );
        assert_eq!(
            names(&reports),
            [
                "0f8fad5b-d9cb-469f-a165-70867728950e.dmp.tmp",
                "notes.txt",
                "x.dmp"
            ]
        );
        assert_eq!(
            names(&crashpad),
            [
                "attachments",
                "metadata",
                "reports",
                "settings.dat",
                "throttle_store.dat"
            ]
        );
        assert!(
            attachment.join(DUMP_B).exists(),
            "the walk went below reports"
        );
        assert!(cookies.exists());
    }

    #[test]
    fn a_dump_name_is_a_uuid_and_dmp() {
        for ours in [DUMP_A, DUMP_B, DUMP_C] {
            assert!(is_dump_name(ours), "{ours}");
        }
        for not_ours in [
            "",
            ".dmp",
            "x.dmp",
            "metadata",
            "settings.dat",
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            "0f8fad5b-d9cb-469f-a165-70867728950e.DMP",
            "0f8fad5b-d9cb-469f-a165-70867728950e.dmp.tmp",
            "0f8fad5bd9cb469fa16570867728950e.dmp",
            "0f8fad5b-d9cb-469f-a165-70867728950.dmp",
            "0f8fad5b-d9cb-469f-a165-70867728950g.dmp",
            "0f8fad5b_d9cb_469f_a165_70867728950e.dmp",
            "../0f8fad5b-d9cb-469f-a165-7086772895.dmp",
        ] {
            assert!(!is_dump_name(not_ours), "{not_ours}");
        }
    }

    /// No WebView2 folder (never started, or not Windows): nothing deleted,
    /// nothing failed, nothing created.
    #[test]
    fn missing_folders_delete_nothing_fail_nothing_and_create_nothing() {
        let local = tempfile::tempdir().unwrap();
        assert_eq!(deleted(local.path()), Deleted::default());
        assert_eq!(names(local.path()), Vec::<String>::new());

        let partial = user_data_dir_in(local.path()).join("EBWebView");
        std::fs::create_dir_all(&partial).unwrap();
        assert_eq!(deleted(local.path()), Deleted::default());
        assert!(!partial.join("Crashpad").exists());
    }

    /// A directory named like a dump is not a dump, and is not walked into.
    #[test]
    fn a_directory_named_like_a_dump_is_left_alone() {
        let (local, reports) = webview_tree();
        let dir = reports.join(DUMP_A);
        std::fs::create_dir_all(&dir).unwrap();
        write(&dir, DUMP_B);

        assert_eq!(deleted(local.path()), Deleted::default());
        assert!(dir.join(DUMP_B).exists());
    }

    /// A file where one of the folders should be is refused, and counted.
    #[test]
    fn a_file_where_a_folder_should_be_is_refused() {
        let local = tempfile::tempdir().unwrap();
        let ebwebview = user_data_dir_in(local.path()).join("EBWebView");
        std::fs::create_dir_all(&ebwebview).unwrap();
        write(&ebwebview, "Crashpad");

        assert_eq!(
            deleted(local.path()),
            Deleted {
                deleted: 0,
                failed: 1
            }
        );
    }

    /// Plant `link` -> a directory elsewhere holding a dump-named file, in
    /// place of each folder on the way down in turn; every one is refused and
    /// the file behind it survives. Junctions on Windows (no privilege needed,
    /// so any process running as the user can plant one, and the app runs
    /// elevated), symlinks on Unix.
    fn every_linked_folder_is_refused(link: fn(&Path, &Path)) {
        for depth in 1..=DUMP_DIR.len() {
            let local = tempfile::tempdir().unwrap();
            let elsewhere = local.path().join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            // Whatever is left of the path below the link, then a dump.
            let mut target = elsewhere.clone();
            for part in &DUMP_DIR[depth..] {
                target.push(part);
            }
            std::fs::create_dir_all(&target).unwrap();
            let victim = write(&target, DUMP_A);

            let mut at = local.path().to_path_buf();
            for part in &DUMP_DIR[..depth - 1] {
                at.push(part);
            }
            std::fs::create_dir_all(&at).unwrap();
            link(&at.join(DUMP_DIR[depth - 1]), &elsewhere);

            assert_eq!(
                deleted(local.path()),
                Deleted {
                    deleted: 0,
                    failed: 1
                },
                "a link in place of {}",
                DUMP_DIR[depth - 1]
            );
            prune_dumps_in(local.path(), Utc::now() + chrono::Duration::days(365), 0);
            assert!(
                victim.exists(),
                "followed a link in place of {}",
                DUMP_DIR[depth - 1]
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_anywhere_on_the_way_down_is_refused() {
        every_linked_folder_is_refused(|at, to| {
            let made = std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(at)
                .arg(to)
                .output()
                .unwrap();
            assert!(made.status.success(), "mklink /J failed: {made:?}");
            assert!(
                std::fs::symlink_metadata(at)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "std must see a junction as a link, or the refusal is luck"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_anywhere_on_the_way_down_is_refused() {
        every_linked_folder_is_refused(|at, to| std::os::unix::fs::symlink(to, at).unwrap());
    }

    /// MR-1945, for this folder: [`known_dir`]'s pass is by path, a snapshot,
    /// and a junction can be planted after it. The checks behind it refuse
    /// one on their own, at every level: the hold ([`open_dumps`]) and, for a
    /// listing made through the junction, each delete
    /// ([`OwnedDir::remove_file`], which checks its handle's final path).
    /// Driven here without the first pass.
    #[cfg(windows)]
    #[test]
    fn without_the_first_pass_the_handle_checks_still_refuse_a_junction() {
        use crate::utils::safe_fs::tests::junction;
        for depth in 1..=DUMP_DIR.len() {
            let local = tempfile::tempdir().unwrap();
            let elsewhere = local.path().join("elsewhere");
            let mut target = elsewhere.clone();
            for part in &DUMP_DIR[depth..] {
                target.push(part);
            }
            std::fs::create_dir_all(&target).unwrap();
            let victim = write(&target, DUMP_A);
            let mut at = local.path().to_path_buf();
            for part in &DUMP_DIR[..depth - 1] {
                at.push(part);
            }
            std::fs::create_dir_all(&at).unwrap();
            junction(&at.join(DUMP_DIR[depth - 1]), &elsewhere);
            let level = DUMP_DIR[depth - 1];

            let dir = dump_dir_in(local.path());
            assert!(
                dir.hold_open_if_present().is_err(),
                "held through a junction in place of {level}"
            );
            let mut tally = Deleted::default();
            file_log::delete_in(&dir, is_dump_name, &mut tally);
            assert_eq!(
                tally,
                Deleted {
                    deleted: 0,
                    failed: 1
                },
                "a junction in place of {level}"
            );
            assert!(dir.remove_file(DUMP_A).is_err(), "{level}");
            assert!(
                victim.exists(),
                "deleted through a junction in place of {level}"
            );
        }
    }

    /// The root behind [`delete_dumps`] and [`prune_dumps`] (D6c,
    /// `protected_dir::hold_user_root`, whose tests cover a junction as the
    /// root and a root outside the profile): this account's own local data
    /// directory passes, and the work goes on at its final path, the same
    /// folder.
    #[cfg(windows)]
    #[test]
    fn the_local_data_root_is_held_at_its_final_path() {
        use crate::utils::win_api::{self, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES};
        use std::os::windows::fs::OpenOptionsExt;

        let Some(Ok(root)) = local_data_root() else {
            panic!("this account's %LOCALAPPDATA% is not under its profile");
        };
        let local = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dirs::data_local_dir().unwrap())
            .unwrap();
        assert!(win_api::same_path(
            root.path(),
            &win_api::final_path(&local).unwrap()
        ));
    }

    /// MR-1946 review: a user data folder that cannot be verified (here a
    /// junction in its place) must not cost the crash option. Refusing it used
    /// to open the window on WebView2's defaults, through the same junction,
    /// with crash upload left to Windows; now the environment is still made,
    /// with crash reports kept on this device. (That the option is set
    /// unconditionally is pinned by
    /// `the_environment_is_the_one_wry_would_have_made`; the by-hand test
    /// checks the browser process of this case too.) A dev machine without
    /// the runtime skips, saying so; CI must not skip.
    #[cfg(windows)]
    #[test]
    fn an_unverified_user_data_folder_still_gets_the_environment() {
        let local = tempfile::tempdir().unwrap();
        let elsewhere = local.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        crate::utils::safe_fs::tests::junction(&user_data_dir_in(local.path()), &elsewhere);
        assert!(
            user_data_owned_dir(local.path()).hold_open().is_err(),
            "the junction was not refused, so this tests nothing"
        );

        match create_environment(local.path()) {
            Ok(_environment) => {}
            Err(e) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "no WebView2 environment on CI ({e}), so this test would test nothing"
                );
                // Only a missing runtime may skip: the environment for a
                // plain folder must work here, or the junction is the cause.
                assert!(
                    create_environment(tempfile::tempdir().unwrap().path()).is_err(),
                    "the environment fails only for the unverified folder: {e}"
                );
                eprintln!("SKIPPED: no WebView2 environment here ({e})");
            }
        }
    }

    /// Every delete and create in this file goes through `safe_fs` (MR-1945,
    /// R5), as the app's own logs' and crash files' do: outside the tests,
    /// nothing removes, creates or writes by path.
    #[test]
    fn nothing_here_deletes_or_creates_by_path() {
        let here = include_str!("webview2.rs").replace('\r', "");
        let code = &here[..here.find("#[cfg(test)]\nmod tests {").unwrap()];
        for by_path in [
            "fs::remove_file(",
            "fs::remove_dir(",
            "fs::remove_dir_all(",
            "fs::create_dir(",
            "fs::create_dir_all(",
            "fs::write(",
            "fs::rename(",
        ] {
            assert!(!code.contains(by_path), "webview2.rs calls {by_path}");
        }
        assert!(code.contains("file_log::delete_in(&dir, is_dump_name, tally)"));
        assert!(code.contains("let _ = dir.remove_file(&name);"));
        assert!(code.contains("let _ = dir.remove_file(name);"));
        // The folder is made verified, and a refusal is logged, not returned:
        // it must not cost the crash option (see the test above).
        assert!(code.contains("if let Err(e) = user_data.hold_open() {"));
    }

    /// A link named like a dump is skipped, and what it points at survives.
    /// (Windows: a file symlink needs a privilege or Developer Mode; a dev
    /// account without it skips, saying so; CI must not skip.)
    #[test]
    fn a_linked_dump_is_skipped_and_its_target_survives() {
        let (local, reports) = webview_tree();
        let target = write(local.path(), "precious.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, reports.join(DUMP_A)).unwrap();
        #[cfg(windows)]
        if let Err(e) = std::os::windows::fs::symlink_file(&target, reports.join(DUMP_A)) {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI cannot create a symlink ({e}), so this test would test nothing"
            );
            eprintln!("SKIPPED: this account cannot create symlinks ({e})");
            return;
        }
        write(&reports, DUMP_B);

        assert_eq!(
            deleted(local.path()),
            Deleted {
                deleted: 1,
                failed: 0
            }
        );
        prune_dumps_in(local.path(), Utc::now() + chrono::Duration::days(365), 0);
        assert!(target.exists(), "the link's target was deleted");
        assert!(std::fs::symlink_metadata(reports.join(DUMP_A)).is_ok());
    }

    // ── the launch sweep ──────────────────────────────────────────────────

    fn written_days_ago(path: &Path, now: DateTime<Utc>, days: u64) {
        let at = SystemTime::from(now) - Duration::from_secs(days * 24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }

    fn dump_named(i: usize) -> String {
        format!("{i:08x}-0000-4000-8000-000000000000.dmp")
    }

    /// Older than the log's window: gone at launch, with no new crash needed.
    /// Inside it: kept. Nothing that is not a dump is touched, however old.
    #[test]
    fn dumps_older_than_the_window_go_at_launch() {
        let (local, reports) = webview_tree();
        let now = Utc::now();
        let window = log_retention::MAX_LOG_AGE_DAYS as u64;
        let old = write(&reports, DUMP_A);
        written_days_ago(&old, now, window + 1);
        let recent = write(&reports, DUMP_B);
        written_days_ago(&recent, now, window - 1);
        let other = write(&reports, "notes.txt");
        written_days_ago(&other, now, 400);
        let metadata = write(reports.parent().unwrap(), "metadata");
        written_days_ago(&metadata, now, 400);

        prune_dumps_in(local.path(), now, log_retention::KEEP_CRASH_REPORTS);

        assert_eq!(names(&reports), [DUMP_B, "notes.txt"]);
        assert!(metadata.exists());
    }

    /// Inside the window the cap holds: only the newest few stay.
    #[test]
    fn inside_the_window_only_the_newest_dumps_stay() {
        let (local, reports) = webview_tree();
        let now = Utc::now();
        let keep = log_retention::KEEP_CRASH_REPORTS;
        // All inside the window, a minute apart: dump 0 the newest.
        let all: Vec<String> = (0..keep + 2).map(dump_named).collect();
        for (age, name) in all.iter().enumerate() {
            let at = SystemTime::from(now) - Duration::from_secs(60 * (age as u64 + 1));
            std::fs::File::options()
                .write(true)
                .open(write(&reports, name))
                .unwrap()
                .set_modified(at)
                .unwrap();
        }

        prune_dumps_in(local.path(), now, keep);

        let mut want = all[..keep].to_vec();
        want.sort();
        assert_eq!(names(&reports), want);
    }

    #[test]
    fn the_sweep_of_a_missing_folder_creates_nothing() {
        let local = tempfile::tempdir().unwrap();
        prune_dumps_in(local.path(), Utc::now(), log_retention::KEEP_CRASH_REPORTS);
        assert_eq!(names(local.path()), Vec::<String>::new());
    }

    // ── the wiring ────────────────────────────────────────────────────────

    /// The folder the app hands WebView2 is the one Tauri would have: its
    /// `app_local_data_dir()`, `<local data dir>/<identifier>`, with no
    /// override (`file_log`'s settings-path test pins the identifier and the
    /// absence of `appDirectoriesOverride` against tauri.conf.json).
    #[test]
    fn the_user_data_folder_is_tauris() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).expect("tauri.conf.json");
        let identifier = conf["identifier"].as_str().unwrap();
        let base = Path::new("local");
        assert_eq!(user_data_dir_in(base), base.join(identifier));
        assert_eq!(DUMP_DIR[0], identifier);
    }

    /// tauri.conf.json no longer creates the main window, so `setup()` must,
    /// first, through [`build_main_window`]; launch sweeps the dumps (before
    /// Tauri starts); "Delete Logs Now" deletes them. The call sites are in
    /// `main.rs` and `file_log.rs` (the same source-reading technique as
    /// `file_log::tests::the_switch_is_still_wired_into_main`).
    #[test]
    fn the_window_the_sweep_and_the_delete_are_wired() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).expect("tauri.conf.json");
        let windows = conf["app"]["windows"].as_array().unwrap();
        assert_eq!(
            windows.len(),
            1,
            "a second window must share the environment"
        );
        assert_eq!(windows[0]["label"], "main");
        assert_eq!(
            windows[0]["create"], false,
            "Tauri would build the main window itself, on WebView2's default crash reporting"
        );
        // The window's own environment settings would be silently ignored
        // now: wry does not read them once it is handed an environment.
        for setting in [
            "additionalBrowserArgs",
            "browserExtensionsEnabled",
            "extensionsPath",
            "scrollBarStyle",
            "proxyUrl",
            "dataDirectory",
        ] {
            assert!(
                windows[0].get(setting).is_none(),
                "tauri.conf.json sets {setting}: make create_environment() apply it"
            );
        }

        // Built right after the log and crash-report choices are applied, and
        // before anything else in setup(), all of which ran after Tauri had
        // built the window when tauri.conf.json created it.
        let main = include_str!("../main.rs").replace('\r', "");
        let setup = &main[main.find(".setup(|app| {").expect("setup")..];
        let at = |what: &str| {
            setup
                .find(what)
                .unwrap_or_else(|| panic!("setup() no longer has {what}"))
        };
        let built = at("webview2::build_main_window(");
        assert!(at("file_log::apply(") < built);
        assert!(at("crash_report::set_opted_in(") < built);
        assert!(
            built < at("restore_launch_at_login_task()"),
            "the main window must be built before the rest of setup()"
        );
        assert_eq!(
            setup.matches("build_main_window(").count(),
            1,
            "one main window"
        );

        let main_fn = &main[main.find("fn main() {").unwrap()..];
        let main_fn = &main_fn[..main_fn.find("\n}\n").unwrap()];
        let swept = main_fn
            .find("webview2::prune_dumps(")
            .expect("main() no longer sweeps WebView2's dumps at launch");
        assert!(swept < main_fn.find("tauri::Builder::default()").unwrap());

        let file_log = include_str!("file_log.rs").replace('\r', "");
        let delete = &file_log[file_log.find("pub fn delete_logs() -> Deleted {").unwrap()..];
        let delete = &delete[..delete.find("\n}\n").unwrap()];
        assert!(
            delete.contains("webview2::delete_dumps("),
            "Delete Logs Now no longer deletes WebView2's dumps"
        );
    }

    /// The environment must be the one wry would have made, plus the crash
    /// option: same browser arguments, same options set. Read from wry's own
    /// source (the version in Cargo.lock), so a wry update that changes its
    /// defaults fails here instead of quietly changing the window.
    #[cfg(windows)]
    #[test]
    fn the_environment_is_the_one_wry_would_have_made() {
        let lock = include_str!("../../Cargo.lock").replace('\r', "");
        let version = |name: &str| {
            let at = lock
                .find(&format!("\nname = \"{name}\"\nversion = \""))
                .unwrap_or_else(|| panic!("{name} is not in Cargo.lock"));
            let rest = &lock[at..];
            let rest = &rest[rest.find("version = \"").unwrap() + "version = \"".len()..];
            rest[..rest.find('"').unwrap()].to_string()
        };
        let wry = format!("wry-{}", version("wry"));
        let runtime = format!("tauri-runtime-wry-{}", version("tauri-runtime-wry"));
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".cargo")))
            .expect("CARGO_HOME");
        let find = |krate: &str, file: &str| -> Option<String> {
            let registries = std::fs::read_dir(cargo_home.join("registry").join("src")).ok()?;
            registries
                .flatten()
                .map(|r| r.path().join(krate).join(file))
                .find(|p| p.is_file())
                .map(|p| std::fs::read_to_string(p).unwrap().replace('\r', ""))
        };
        let (Some(webview2), Some(lib), Some(runtime_lib)) = (
            find(&wry, "src/webview2/mod.rs"),
            find(&wry, "src/lib.rs"),
            find(&runtime, "src/lib.rs"),
        ) else {
            assert!(
                std::env::var_os("CI").is_none(),
                "{wry} / {runtime} sources are not in the cargo registry, so this test would test nothing"
            );
            eprintln!("SKIPPED: {wry} / {runtime} sources are not in the cargo registry");
            return;
        };

        let create = &webview2[webview2.find("fn create_environment(").unwrap()..];
        let create = &create[..create.find("\n  }\n").unwrap()];
        let (features, autoplay) = BROWSER_ARGS.split_once(' ').unwrap();
        assert!(
            create.contains(&format!("let default_args = \"{features}\";")),
            "wry's default browser arguments changed"
        );
        assert!(create.contains(&format!("arguments.push_str(\" {autoplay}\");")));
        assert!(
            lib.contains("\n      autoplay: true,\n"),
            "wry's autoplay default changed"
        );
        assert!(
            !runtime_lib.contains(".with_autoplay("),
            "Tauri now sets autoplay itself"
        );

        // Every option wry sets, this sets; and wry still does not set the
        // crash option (if it ever can, use its setting instead).
        let mut wry_sets: Vec<&str> = create
            .match_indices("options.set_")
            .map(|(i, _)| {
                let rest = &create[i + "options.".len()..];
                &rest[..rest.find('(').unwrap()]
            })
            .collect();
        wry_sets.sort();
        assert_eq!(
            wry_sets,
            [
                "set_additional_browser_arguments",
                "set_are_browser_extensions_enabled",
                "set_language",
                "set_scroll_bar_style",
            ],
            "wry now sets other environment options: set them here too"
        );
        let here = include_str!("webview2.rs").replace('\r', "");
        let ours = &here[here.find("pub fn create_environment(").unwrap()..];
        let ours = &ours[..ours.find("\n}\n").unwrap()];
        for set in wry_sets {
            assert!(ours.contains(&format!("options.{set}(")), "{set}");
        }
        assert!(ours.contains(&format!(
            "options.{}(true);",
            "set_is_custom_crash_reporting_enabled"
        )));
    }

    /// Against the installed WebView2 runtime: the environment is created
    /// with these options, and the runtime's own answer to where it writes
    /// crash dumps (`ICoreWebView2Environment11::FailureReportFolderPath`) is
    /// the folder the delete and the sweep work in. Creating an environment
    /// starts no browser process. A dev machine without the runtime skips,
    /// saying so; CI must not skip.
    #[cfg(windows)]
    #[test]
    fn the_runtime_writes_its_dumps_where_the_delete_looks() {
        use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Environment11;
        use windows::core::{Interface, PWSTR};

        let local = tempfile::tempdir().unwrap();
        let environment = match create_environment(local.path()) {
            Ok(environment) => environment,
            Err(e) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "no WebView2 environment on CI ({e}), so this test would test nothing"
                );
                eprintln!("SKIPPED: no WebView2 environment here ({e})");
                return;
            }
        };
        let environment: ICoreWebView2Environment11 = environment
            .cast()
            .expect("a runtime that has IsCustomCrashReportingEnabled has this too");
        let mut folder = PWSTR::null();
        // SAFETY: `folder` is a valid out pointer; the string is taken below.
        unsafe { environment.FailureReportFolderPath(&mut folder) }.unwrap();
        let folder = PathBuf::from(webview2_com::take_pwstr(folder));

        let mut ours = local.path().to_path_buf();
        for part in DUMP_DIR {
            ours.push(part);
        }
        assert_eq!(folder, ours);
    }

    /// Run `during` with a webview on [`create_environment`] for `local`
    /// started, passing it the browser process's id; then close it all and
    /// wait for that process to go (it holds files in `local` until it exits).
    #[cfg(windows)]
    fn with_a_live_webview<R>(local: &Path, during: impl FnOnce(u32) -> R) -> R {
        use webview2_com::CreateCoreWebView2ControllerCompletedHandler;
        use windows::Win32::Foundation::{E_POINTER, E_UNEXPECTED};
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW,
        };

        let environment = create_environment(local).unwrap();
        // SAFETY: a hidden window of a system class, destroyed below.
        let window = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                windows::core::w!("STATIC"),
                windows::core::w!("MR-1946"),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                100,
                100,
                None,
                None,
                None,
                None,
            )
        }
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        // SAFETY: as in `create_environment`.
        unsafe {
            environment.CreateCoreWebView2Controller(
                window,
                &CreateCoreWebView2ControllerCompletedHandler::create(Box::new(
                    move |error_code, controller| {
                        let result = error_code.and_then(|()| {
                            controller.ok_or_else(|| windows::core::Error::from(E_POINTER))
                        });
                        tx.send(result)
                            .map_err(|_| windows::core::Error::from(E_UNEXPECTED))
                    },
                )),
            )
        }
        .unwrap();
        let controller = webview2_com::wait_with_pump(rx).unwrap().unwrap();
        let mut pid = 0u32;
        // SAFETY: `pid` is a valid out pointer.
        unsafe {
            controller
                .CoreWebView2()
                .unwrap()
                .BrowserProcessId(&mut pid)
        }
        .unwrap();

        let result = during(pid);

        // SAFETY: closing what this test created.
        unsafe { controller.Close() }.unwrap();
        // SAFETY: the window this test created.
        unsafe { DestroyWindow(window) }.unwrap();
        drop(controller);
        drop(environment);
        let _ = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("Wait-Process -Id {pid} -Timeout 20 -ErrorAction SilentlyContinue"),
            ])
            .status();
        result
    }

    /// Whether browser process `pid` carries the switch the runtime turns the
    /// crash option into. Only that: never the command line itself.
    #[cfg(windows)]
    fn carries_the_crash_switch(pid: u32) -> bool {
        let query = format!(
            "(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine \
             -match '--edge-webview-disable-crash-reporting=1'"
        );
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &query])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim() == "True"
    }

    /// End to end, by hand (`cargo test --lib webview2 -- --ignored`), on a
    /// Windows machine with WebView2: a webview on [`create_environment`]
    /// starts a browser process carrying the switch the runtime turns the
    /// crash option into. Ignored: the switch is the runtime's internal
    /// spelling, not an API, so it is a check to run, not one to gate on.
    #[cfg(windows)]
    #[test]
    #[ignore = "starts a WebView2 browser process; run by hand"]
    fn a_webview_on_the_environment_starts_with_crash_reporting_off() {
        let local = tempfile::tempdir().unwrap();
        let (switch, deleted_live, swept_live) = with_a_live_webview(local.path(), |pid| {
            let switch = carries_the_crash_switch(pid);
            // "Delete Logs Now" and the launch sweep with this webview's
            // browser process (and its Crashpad handler) running: holding the
            // folders open and checking them by handle must not collide with
            // WebView2.
            let reports = DUMP_DIR
                .iter()
                .fold(local.path().to_path_buf(), |dir, part| dir.join(part));
            std::fs::create_dir_all(&reports).unwrap();
            write(&reports, DUMP_A);
            let deleted_live = deleted(local.path());
            let old = write(&reports, DUMP_B);
            written_days_ago(&old, Utc::now(), 30);
            prune_dumps_in(local.path(), Utc::now(), log_retention::KEEP_CRASH_REPORTS);
            (switch, deleted_live, !old.exists())
        });
        assert!(
            switch,
            "the browser process does not carry the crash switch"
        );
        assert_eq!(
            deleted_live,
            Deleted {
                deleted: 1,
                failed: 0
            },
            "Delete Logs Now beside a running WebView2"
        );
        assert!(swept_live, "the sweep beside a running WebView2");
    }

    /// By hand, as above: with a junction in place of the user data folder
    /// (which the app refuses to verify), the browser process still carries
    /// the crash switch: the refusal no longer opens the window on WebView2's
    /// defaults (MR-1946 review).
    #[cfg(windows)]
    #[test]
    #[ignore = "starts a WebView2 browser process; run by hand"]
    fn a_webview_on_an_unverified_folder_still_starts_with_crash_reporting_off() {
        let local = tempfile::tempdir().unwrap();
        let elsewhere = local.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        crate::utils::safe_fs::tests::junction(&user_data_dir_in(local.path()), &elsewhere);
        assert!(user_data_owned_dir(local.path()).hold_open().is_err());
        assert!(
            with_a_live_webview(local.path(), carries_the_crash_switch),
            "the browser process does not carry the crash switch"
        );
    }
}
