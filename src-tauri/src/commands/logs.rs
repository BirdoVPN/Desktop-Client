//! Settings › Privacy & Security › "Delete Logs Now" (MR-808).
//!
//! The switch beside it ("Save Diagnostic Logs") is a setting,
//! `AppSettings::file_logging_enabled`, saved and applied with every other
//! one (`settings::save_settings`). What both act on is described in
//! `utils::file_log`.

use crate::commands::ipc_error::IpcError;
use crate::utils::file_log::{self, Deleted};

/// Delete the diagnostic log (`birdo.log` and its rotated generation) and the
/// local crash reports, now; on Windows also WebView2's crash dumps (MR-1946,
/// `utils::webview2`). Takes no path: the directories are the app's own, and
/// only the names written there are deleted. Answers counts, never a path.
/// Works with the log on or off; on, the next line starts a new file.
///
/// File I/O, so it runs on the blocking pool rather than parking a runtime
/// worker (P1-dk-blocking-io-on-async-runtime).
#[tauri::command]
pub async fn delete_logs() -> Result<Deleted, IpcError> {
    let done = tokio::task::spawn_blocking(file_log::delete_logs)
        .await
        .map_err(|e| IpcError::unknown(format!("Deleting the logs failed: {e}")))?;
    // Not at info: a line now would recreate birdo.log only to say it was
    // deleted. Release builds keep debug out of the file (`log_policy`).
    tracing::debug!(
        "Diagnostic logs deleted at the user's request: {} removed, {} not",
        done.deleted,
        done.failed
    );
    Ok(done)
}
