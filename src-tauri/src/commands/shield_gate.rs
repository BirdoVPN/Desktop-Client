//! MR-2373: the BirdoShield fleet gate, kept across launches.
//!
//! The gate (`api::client::dns_filtering_gate_on`) decides whether a dial
//! sends the `dnsFiltering` flag at all (owner 2026-11-13: only while the
//! gate is known to be on). It lived in memory only and started OFF at every
//! launch, so a cold-start Auto-Connect, which dials before the window's
//! first `GET /api/client-config` has answered, went out WITHOUT the flag,
//! and the BirdoShield row read ON a moment later: that session ran
//! unfiltered under a toggle that said otherwise, until the next connect.
//! Mobile keeps the last answer (Android's `dns_filtering_gate_on`
//! preference, iOS's UserDefaults twin); this is the desktop's.
//!
//! The record is the last answer a successful fetch gave, read once at
//! start-up ([`load`]) and written again whenever a fetch changes it. A
//! missing, unreadable, oversized or foreign file is OFF: no flag, the
//! behaviour before this record existed. The first fetch of every run
//! replaces it either way (`api::client::note_dns_filtering_gate`).
//!
//! A file of its own beside settings.json, for the reasons consent.json is
//! one (`commands::consent`): a field of the signed settings would be reset
//! by every whole-object save the UI makes, and a settings.json carrying a
//! key an older build does not know fails that build's signature check. It
//! needs no signature: anyone who can write it can turn BirdoShield on in
//! the window just as well, and the server still decides (it ignores the
//! flag while the fleet gate is off). It is written through the checked
//! config directory (`settings::write_atomically`, MR-1945 H1), because the
//! app writing it runs elevated in the user's folder. If root ever sets that
//! folder aside (`settings::make_config_dir_private`), the record is not
//! carried over: the gate starts OFF until the first fetch, which is safe.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// Beside settings.json, in the app's config directory.
pub(crate) const FILE_NAME: &str = "shield_gate.json";

/// The record is a few bytes; anything larger is not ours and reads as OFF.
const MAX_RECORD_BYTES: u64 = 256;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    /// The fleet gate the last successful config fetch reported.
    on: bool,
}

/// Serialises the writes, so the file always ends at the gate's latest value.
static RECORD_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The gate on record at `path`: OFF for no record, and for anything that is
/// not one.
fn read_at(path: &Path) -> bool {
    let readable = std::fs::metadata(path).is_ok_and(|m| m.len() <= MAX_RECORD_BYTES);
    readable
        && std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Record>(&text).ok())
            .is_some_and(|r| r.on)
}

/// Put `on` on record at `path`.
fn write_at(path: &Path, on: bool) -> Result<(), String> {
    let json = serde_json::to_string(&Record { on })
        .map_err(|e| format!("Failed to serialize the BirdoShield gate: {e}"))?;
    crate::commands::settings::write_atomically(path, &json)
}

/// Keep the gate's value NOW at `path` (it may have moved again since the
/// change that asked: the latest value is what the next launch needs).
fn keep_at(path: &Path) {
    let _write = RECORD_WRITE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err(e) = write_at(path, crate::api::client::dns_filtering_gate_on()) {
        tracing::warn!(
            "Could not keep the BirdoShield gate for the next launch: {}",
            crate::utils::redact::sanitize_error(&e)
        );
    }
}

fn record_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {}", e))?
        .join(FILE_NAME))
}

/// At start-up, before the window can dial anything: the gate is the last
/// answer an earlier run's fetch gave until this run's first fetch answers,
/// and every change a fetch makes is kept for the next launch (off the async
/// runtime: it is a file write).
pub fn load(app: &AppHandle) {
    let path = match record_path(app) {
        Ok(path) => path,
        Err(e) => {
            tracing::warn!("BirdoShield gate not restored: {e}");
            return;
        }
    };
    let on = read_at(&path);
    crate::api::client::restore_dns_filtering_gate(on, move || {
        let path = path.clone();
        tauri::async_runtime::spawn_blocking(move || keep_at(&path));
    });
    tracing::debug!("BirdoShield gate restored from the last launch: {on}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MR-2373: the last answer survives a restart; a missing, foreign,
    /// oversized or unreadable record is OFF, as before the record existed.
    #[test]
    fn the_gate_on_record_survives_a_restart_and_is_off_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.birdo.test").join(FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        assert!(!read_at(&path), "no record");
        write_at(&path, true).unwrap();
        assert!(read_at(&path), "kept ON");
        write_at(&path, false).unwrap();
        assert!(!read_at(&path), "kept OFF");

        for foreign in [
            "not json",
            "true",
            r#"{"on":"yes"}"#,
            r#"{"on":1}"#,
            r#"{"on":true,"extra":1}"#,
            r#"{"available":true}"#,
            "",
        ] {
            std::fs::write(&path, foreign).unwrap();
            assert!(!read_at(&path), "{foreign}");
        }
        std::fs::write(
            &path,
            format!(r#"{{"on":true}}{}"#, " ".repeat(MAX_RECORD_BYTES as usize)),
        )
        .unwrap();
        assert!(!read_at(&path), "oversized");
        // A record that is not ours is replaced, not trusted.
        write_at(&path, true).unwrap();
        assert!(read_at(&path));
    }

    /// MR-2373, the wiring: the record is read in `setup`, before the window
    /// exists, so a cold-start Auto-Connect (which the window starts) dials
    /// with the last-known gate, never with the in-memory default.
    #[test]
    fn the_gate_is_restored_before_the_window_can_dial() {
        let main = include_str!("../main.rs").replace('\r', "");
        let setup = main.find(".setup(|app| {").expect("the setup hook");
        let load = main
            .find("commands::shield_gate::load(app.handle());")
            .expect("the gate restored");
        let window = main
            .find("webview2::build_main_window(app.handle(), &config)")
            .expect("the window");
        assert!(setup < load, "restored outside setup");
        assert!(load < window, "restored after the window exists");
        assert_eq!(main.matches("shield_gate::load(").count(), 1);
    }
}
