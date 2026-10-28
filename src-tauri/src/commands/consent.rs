//! The consent text the user accepted, as Rust's own record (MR-1607).
//!
//! The consent screen (owner decision D7, versioned re-consent) lives in the
//! webview, and so did the only record of what the user accepted. Nothing in
//! Rust asked: the tray's Quick Connect dialled while the screen asking a
//! signed-in user to accept a NEWER text was showing, with that user not yet
//! having accepted it.
//!
//! So Rust keeps its own record, `consent.json` beside settings.json, and the
//! Quick Connect command refuses while it is older than [`CONSENT_VERSION`]
//! ([`require_consent`]) — the tray's, which needs no window, and the
//! window's when its server list has not loaded. The window's other connects
//! sit behind the consent screen, and the session controller — Auto-Connect,
//! the resume after an update — exists only once the webview holds the
//! current version, and asks this record before it dials
//! (`src/session/consent-sync.ts`). A refused tray connect brings the window
//! up, which shows the consent screen, and tells the UI
//! ([`CONSENT_REQUIRED_EVENT`]).
//!
//! The auto-reconnect loop is not gated: it only ever re-dials a session on
//! record, and only a connect through these gates puts one on record. Gating
//! its re-dial would strand a protected session behind the kill switch's
//! block if the record were lost mid-session.
//!
//! The UI writes the record through [`record_consent`]: when the user accepts,
//! and at every start, with the version the webview holds. That start-up
//! write is the migration: an install that accepted version 2 in an earlier
//! build has no record yet, and gets one from what the webview already holds,
//! at the first start — no second consent screen. The record never goes past
//! this build's version.
//!
//! MR-2016: and it follows the webview DOWN as well. It used to only rise, so
//! a webview that lost its storage (cleared site data, a reset profile) showed
//! the consent screen while this record still said "accepted" and the tray
//! dialled. The webview's version is what the screen asks about, so the
//! record is now set to it ([`held`]): the start-up write of a webview with
//! no consent lowers it, and the tray waits for the consent screen like the
//! window does.
//!
//! WHY A FILE OF ITS OWN and not a field of the signed settings: a field the
//! UI never sends would be reset by every whole-object `save_settings`; a
//! settings file that cannot be verified, a quarantine or a settings reset
//! would each lose it and refuse the tray until the next start; and a
//! settings.json carrying a key an older build does not know fails that
//! build's signature check (it re-serializes without the key), so a
//! downgrade would reset every user's settings. The record needs no
//! signature: anyone who can write it can accept the terms in the window just
//! as well, and it never connects anything by itself. It is still WRITTEN
//! through the checked config directory (`settings::write_atomically`,
//! MR-1945 H1), because the app writing it runs elevated in the user's folder.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::ipc_error::{IpcError, IpcErrorCode};

/// The consent text this build shows. MUST equal `CONSENT_VERSION` in
/// `src/lib/consent.ts`: both sides pin it (`the_rust_and_ui_versions_agree`
/// here, `consent.test.ts` there). Bump both with any change to the consent
/// copy.
pub const CONSENT_VERSION: u32 = 2;

/// Emitted when a connect is refused for want of consent. The UI repairs a
/// record that fell behind what it holds, or the consent screen is already
/// up (`src/session/consent-sync.ts`).
pub const CONSENT_REQUIRED_EVENT: &str = "consent-required";

/// Beside settings.json, in the app's config directory.
pub(crate) const FILE_NAME: &str = "consent.json";

/// The record is a few bytes; anything larger is not ours and reads as none.
const MAX_RECORD_BYTES: u64 = 1024;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Record {
    accepted_version: u32,
}

/// Serialises the read-modify-write of the record.
static RECORD_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether `accepted` is the current consent text.
pub fn has_current_consent(accepted: u32) -> bool {
    accepted >= CONSENT_VERSION
}

/// What Quick Connect gets while the recorded consent is `accepted`: nothing,
/// or the refusal.
pub(crate) fn refusal(accepted: u32) -> Option<IpcError> {
    (!has_current_consent(accepted)).then(|| {
        IpcError::new(
            IpcErrorCode::ConsentRequired,
            // MR-2016: true whichever way it fell behind. The screen asks for
            // the terms when they were never accepted (or the webview lost
            // them); when only this record's write failed, there is nothing
            // to review, and "review the privacy terms" sent the user looking.
            "Your privacy consent is not saved in BirdoVPN, so it did not connect.",
        )
    })
}

/// What the record holds once the webview says it holds `asked`: exactly
/// that, never higher than this build's version (MR-2016: lower too, see the
/// module doc).
fn held(asked: u32) -> u32 {
    asked.min(CONSENT_VERSION)
}

fn record_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {}", e))?
        .join(FILE_NAME))
}

/// The version recorded at `path`: 0 for no record, and for anything that
/// is not one (unreadable, oversized, not JSON).
fn read_at(path: &Path) -> u32 {
    let readable = std::fs::metadata(path).is_ok_and(|m| m.len() <= MAX_RECORD_BYTES);
    if !readable {
        return 0;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Record>(&text).ok())
        .map_or(0, |r| r.accepted_version)
}

/// Set the record at `path` to `asked` ([`held`]) and answer what it holds.
/// Writes only when that changes it.
fn record_at(path: &Path, asked: u32) -> Result<u32, String> {
    let _write = RECORD_WRITE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let stored = read_at(path);
    let accepted = held(asked);
    if accepted != stored {
        let json = serde_json::to_string(&Record {
            accepted_version: accepted,
        })
        .map_err(|e| format!("Failed to serialize the consent record: {e}"))?;
        crate::commands::settings::write_atomically(path, &json)?;
    }
    Ok(accepted)
}

/// Record the consent text `version` the webview holds (the consent screen's
/// accept, and every start: the migration, and MR-2016's lowering). Answers
/// the version now on record.
///
/// MR-1516 (owner decision 2026-10-28): crash reports follow what the
/// webview holds, written or not, and nothing else opens their gate: closed
/// from the start of the process (not opened from this record, which a
/// webview that lost its storage contradicts) until the webview says it holds
/// the current text, closed again while its consent screen is up.
#[tauri::command]
pub async fn record_consent(app: AppHandle, version: u32) -> Result<u32, IpcError> {
    crate::utils::crash_report::set_consent_current(has_current_consent(held(version)));
    tokio::task::spawn_blocking(move || {
        let path = record_path(&app).map_err(IpcError::unknown)?;
        record_at(&path, version).map_err(IpcError::unknown)
    })
    .await
    .map_err(|e| IpcError::unknown(format!("Consent task failed: {e}")))?
}

/// The version on record (0 for none).
async fn recorded(app: &AppHandle) -> u32 {
    let app = app.clone();
    tokio::task::spawn_blocking(move || record_path(&app).map_or(0, |p| read_at(&p)))
        .await
        .unwrap_or(0)
}

/// Refuse Quick Connect — the tray's, which needs no window — while the
/// recorded consent is older than this build's text, and tell the UI
/// ([`CONSENT_REQUIRED_EVENT`]). A missing or unreadable record is no
/// consent.
pub(crate) async fn require_consent(app: &AppHandle) -> Result<(), IpcError> {
    match refusal(recorded(app).await) {
        None => Ok(()),
        Some(error) => {
            tracing::info!("Connect refused: the current consent has not been accepted");
            let _ = app.emit(CONSENT_REQUIRED_EVENT, ());
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MR-1607: one version, defined once on each side and pinned together.
    /// A bump on one side alone fails here (and in `consent.test.ts`).
    #[test]
    fn the_rust_and_ui_versions_agree() {
        let ui = include_str!("../../../src/lib/consent.ts");
        let line = ui
            .lines()
            .find(|l| l.trim_start().starts_with("export const CONSENT_VERSION ="))
            .expect("CONSENT_VERSION in src/lib/consent.ts");
        let value: u32 = line
            .split('=')
            .nth(1)
            .and_then(|v| v.trim().trim_end_matches(';').trim().parse().ok())
            .unwrap_or_else(|| panic!("unparseable: {line}"));
        assert_eq!(value, CONSENT_VERSION);
    }

    #[test]
    fn only_the_current_text_lets_an_unattended_connect_through() {
        for old in [0, 1] {
            let error = refusal(old).expect("refused");
            assert_eq!(error.code, IpcErrorCode::ConsentRequired, "{old}");
            // Asking again, unchanged, cannot succeed: accepting does.
            assert!(!error.retryable, "{old}");
        }
        assert!(refusal(CONSENT_VERSION).is_none());
        assert!(refusal(CONSENT_VERSION + 1).is_none());
    }

    /// The record holds what the webview holds, never past this build's
    /// text; a missing, foreign or oversized file is no record.
    #[test]
    fn the_record_follows_the_webview_up_to_this_builds_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.birdo.test").join(FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        assert_eq!(read_at(&path), 0, "no record");
        assert_eq!(record_at(&path, 1).unwrap(), 1);
        assert_eq!(record_at(&path, CONSENT_VERSION).unwrap(), CONSENT_VERSION);
        assert_eq!(
            record_at(&path, 999).unwrap(),
            CONSENT_VERSION,
            "a future text this build never showed"
        );
        assert_eq!(read_at(&path), CONSENT_VERSION);

        std::fs::write(&path, "not json").unwrap();
        assert_eq!(read_at(&path), 0);
        std::fs::write(&path, " ".repeat(MAX_RECORD_BYTES as usize + 1)).unwrap();
        assert_eq!(read_at(&path), 0);
        // A record that is not ours is replaced, not trusted.
        assert_eq!(record_at(&path, CONSENT_VERSION).unwrap(), CONSENT_VERSION);
        assert_eq!(read_at(&path), CONSENT_VERSION);
    }

    /// MR-2016: a webview that lost its consent (its storage was cleared)
    /// shows the consent screen, and its start-up write takes the record down
    /// with it, so the tray's Quick Connect is refused until the user accepts
    /// again. On main the record only rose: the tray dialled while the screen
    /// asked for consent.
    #[test]
    fn a_webview_that_lost_its_consent_takes_the_record_down() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.birdo.test").join(FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        assert_eq!(record_at(&path, CONSENT_VERSION).unwrap(), CONSENT_VERSION);
        assert!(refusal(read_at(&path)).is_none());

        assert_eq!(record_at(&path, 0).unwrap(), 0, "the webview holds none");
        assert_eq!(read_at(&path), 0);
        assert!(
            refusal(read_at(&path)).is_some(),
            "the tray waits for consent"
        );

        assert_eq!(record_at(&path, CONSENT_VERSION).unwrap(), CONSENT_VERSION);
        assert!(refusal(read_at(&path)).is_none(), "accepted again");
    }

    /// MR-2016: the refusal does not send the user to "review the privacy
    /// terms": when only the record's write failed there is nothing to review.
    #[test]
    fn the_refusal_says_the_consent_is_not_saved() {
        let error = refusal(0).expect("refused");
        assert!(error.message.contains("not saved"), "{}", error.message);
        assert!(
            !error.message.to_lowercase().contains("review"),
            "{}",
            error.message
        );
    }

    /// The tray's Quick Connect asks the record first — before elevation is
    /// used, before the session is restored, before a settings read or a
    /// server list — and a refusal brings the window up, which shows the
    /// consent screen. A source pin: the menu handler and the command need an
    /// `AppHandle` (the rule itself is `refusal`, tested above).
    #[test]
    fn the_trays_quick_connect_asks_for_consent_first() {
        let vpn = include_str!("vpn.rs");
        let target = &vpn[vpn
            .find("async fn quick_connect_target(")
            .expect("quick_connect_target")..];
        let target = &target[..target.find("\n}").unwrap()];
        let gate = target
            .find("crate::commands::consent::require_consent(app).await?;")
            .expect("the consent gate");
        for later in [
            "ensure_signed_in(",
            "load_settings_off_runtime(",
            "api.get_servers()",
        ] {
            let at = target.find(later).unwrap_or_else(|| panic!("{later}"));
            assert!(gate < at, "{later} runs before the consent gate");
        }

        let main = include_str!("../main.rs");
        let tray = &main[main.find("\"connect\" => {").expect("the tray's connect")..];
        let tray = &tray[..tray.find("\"disconnect\" => {").unwrap()];
        let dial = tray.find("commands::vpn::quick_connect(").expect("dial");
        let restore = tray.find("restore_and_focus(&app)").expect("window up");
        assert!(dial < restore);
        assert!(
            tray.contains("e.code != commands::ipc_error::IpcErrorCode::Cancelled"),
            "a refusal (consent_required included) brings the window up"
        );
    }

    /// MR-1516 (owner decision 2026-10-28): crash reports are off while a
    /// consent screen is up, a re-consent included. Only what the webview
    /// says opens or closes the gate: every `record_consent` — the accept and
    /// each start (on), MR-2016's lowering (off). `setup()` applies the stored
    /// opt-in alone. Until the review of #364 it also opened the gate from
    /// consent.json, so a webview that had lost its storage (the consent
    /// screen up, the file still "accepted") sent reports from the start
    /// until its own write closed the gate again. A source pin: both need an
    /// `AppHandle` (the rule itself is `crash_report::reporting`, tested
    /// there).
    #[test]
    fn crash_reports_follow_the_consent_the_webview_holds() {
        let src = include_str!("consent.rs").replace('\r', "");
        let command = &src[src
            .find("pub async fn record_consent(")
            .expect("record_consent")..];
        let command = &command[..command.find("\n}").unwrap()];
        assert!(
            command
                .contains("crash_report::set_consent_current(has_current_consent(held(version)));"),
            "record_consent feeds the crash-report gate"
        );

        let main = include_str!("../main.rs").replace('\r', "");
        let setup = &main[main.find(".setup(|app| {").expect("setup")..];
        assert!(
            setup.contains("crash_report::set_opted_in("),
            "setup() applies the stored opt-in"
        );

        // Nothing but record_consent opens the gate: no other caller in src/.
        let gate_call = ["set_consent_current", "("].concat();
        let mut callers = Vec::new();
        let mut dirs = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("src/") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("source");
                    let calls = text.matches(gate_call.as_str()).count();
                    if calls > 0 {
                        let name = path.file_name().unwrap().to_string_lossy().into_owned();
                        callers.push((name, calls));
                    }
                }
            }
        }
        callers.sort();
        // crash_report.rs: its definition and a test that keeps it closed;
        // consent.rs: record_consent's call and the line above, which pins it.
        assert_eq!(
            callers,
            [
                ("consent.rs".to_string(), 2),
                ("crash_report.rs".to_string(), 2)
            ],
            "set_consent_current is called from more than record_consent"
        );
    }
}
