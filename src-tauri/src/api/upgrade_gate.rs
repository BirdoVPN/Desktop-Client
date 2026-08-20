//! Forced client-version floor (HTTP 426 Upgrade Required).
//!
//! The backend rejects clients below a minimum version with a STRUCTURED 426
//! carrying the version the user must move to:
//!
//! ```json
//! {
//!   "statusCode": 426,
//!   "error": "update_required",
//!   "message": "This version of Birdo VPN is no longer supported. Please update the app to reconnect.",
//!   "details": { "minVersion": "1.4.36", "currentVersion": "1.4.9", "updateUrl": "https://birdo.app/clients" }
//! }
//! ```
//!
//! NOT an assumed shape — this is the body the backend actually serialises,
//! captured from a real response and pinned as `CANONICAL_426` in
//! `api::tests`, with the matching assertion on the backend side
//! (`vpn-version-floor.wire.spec.ts`). It is `details` that carries the
//! structured fields: birdo-web's GlobalExceptionFilter REBUILDS every error
//! body and forwards only an explicit `details` opt-in, so top-level extras do
//! not survive to the wire.
//!
//! An earlier revision of this comment declared
//! `{ "requiredVersion", "downloadUrl" }` as an "ASSUMED SHAPE ... built in
//! parallel". Nobody ever agreed it, and the backend never sent those names, so
//! the released client could not read a single field. The tolerated fallbacks
//! below exist only so an OLD or unexpected body cannot weaken the gate — they
//! are not the contract.
//!
//! Every field is optional and the block is driven by the STATUS CODE, never by
//! the body: a 426 with an unparseable or empty body still blocks, it just
//! cannot name the version. The human sentence is read from `message` (never
//! from `error`, which is a machine token).
//!
//! This module is the process-wide latch. `BirdoApi::handle_response` sets it
//! the first time any request is refused; from then on:
//!
//!  * the UI shows a blocking "update required" screen (the `update-required`
//!    event, plus `get_required_update` for a client that started up already
//!    blocked), and
//!  * auto-reconnect stops instead of retrying. A version floor is a WALL, not
//!    a transient failure: every retry is refused identically, so a client that
//!    keeps retrying is a self-inflicted DoS on our own control plane and a
//!    battery drain on the user's machine.
//!
//! The latch is deliberately one-way for the life of the process. It clears on
//! restart — which is exactly what happens after the update installs.

use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

/// Event emitted once, when the floor is first hit.
pub const UPDATE_REQUIRED_EVENT: &str = "update-required";

/// What the backend told us we need. Serialised to the frontend as camelCase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredUpdate {
    /// Minimum version the backend accepts, e.g. "1.4.36". `None` when the 426
    /// body was missing or unparseable — the block still applies.
    pub required_version: Option<String>,
    /// Where to get it, when the backend supplies one.
    pub download_url: Option<String>,
    /// The backend's own explanation, shown verbatim when present.
    pub message: Option<String>,
}

static GATE: RwLock<Option<RequiredUpdate>> = RwLock::new(None);
static APP: OnceLock<AppHandle> = OnceLock::new();

/// Register the handle used to notify the UI. Called once from `setup()`.
pub fn set_app_handle(app: AppHandle) {
    let _ = APP.set(app);
}

/// Record that the backend refused this build, and tell the UI.
///
/// Idempotent: only the FIRST 426 emits the event, so a burst of refused
/// requests cannot spam the frontend.
pub fn latch(info: RequiredUpdate) {
    // A poisoned lock must not turn a hard security gate into a no-op, so
    // recover the guard instead of unwrapping (nothing here can panic while
    // holding it, but the gate must survive a panic elsewhere regardless).
    let mut guard = GATE.write().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return;
    }
    tracing::error!(
        "Backend requires a newer client version ({}) — blocking further use of this build",
        info.required_version.as_deref().unwrap_or("unknown")
    );
    *guard = Some(info.clone());
    drop(guard);

    if let Some(app) = APP.get() {
        let _ = app.emit(UPDATE_REQUIRED_EVENT, info);
    }
}

/// The latched requirement, if the floor has been hit.
pub fn required_update() -> Option<RequiredUpdate> {
    GATE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// True once the backend has refused this build.
pub fn is_blocked() -> bool {
    GATE.read().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Test-only: clear the latch between cases. Never called in production — the
/// gate is one-way for the life of the process.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    *GATE.write().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests share the process-wide latch, so they must not run
    // concurrently with each other. A mutex keeps them serialised without
    // affecting the rest of the suite.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn info(v: &str) -> RequiredUpdate {
        RequiredUpdate {
            required_version: Some(v.to_string()),
            download_url: None,
            message: None,
        }
    }

    #[test]
    fn starts_unblocked() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        assert!(!is_blocked());
        assert_eq!(required_update(), None);
    }

    #[test]
    fn latch_blocks_and_is_readable() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        latch(info("1.4.36"));
        assert!(is_blocked());
        assert_eq!(
            required_update().and_then(|i| i.required_version),
            Some("1.4.36".to_string())
        );
        reset_for_test();
    }

    #[test]
    fn first_latch_wins() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        latch(info("1.4.36"));
        latch(info("9.9.9"));
        assert_eq!(
            required_update().and_then(|i| i.required_version),
            Some("1.4.36".to_string())
        );
        reset_for_test();
    }
}
