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

/// Which origin a refused response came from.
///
/// The forced-version floor is a contract of the NestJS CONTROL PLANE
/// (`api.birdo.app`): it is the only thing that knows this build's version, the
/// only thing that enforces a minimum, and the only thing that emits the
/// structured 426 documented above. Until PR #162 it was also the only origin
/// whose responses reached `handle_response` at all, so "any 426 latches" and
/// "any control-plane 426 latches" were the same sentence.
///
/// `get_client_config` broke that by pointing the same response handler at the
/// WEB origin (`birdo.app`), which is a Next.js route behind a CDN. Nothing
/// there emits 426 today -- but the latch is a ONE-WAY, process-wide wall that
/// stops auto-reconnect and raises the blocking update screen, so an edge or
/// proxy response on an unrelated public route must not be able to arm it on a
/// build the backend is perfectly happy with. This enum keeps the old
/// invariant explicit now that two origins share the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `api.birdo.app` -- the NestJS backend that owns the version floor.
    ControlPlane,
    /// `birdo.app` -- the Next.js web app (public `/api/client-config`).
    Web,
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
///
/// DELIBERATELY PRIVATE (PR #162 review nit): `latch_from` is the only way in
/// from outside this module, so "only the control plane may arm the version
/// floor" holds by construction rather than by every caller remembering to
/// check the origin. The in-module tests below still call it directly to set up
/// state that is not reachable through the origin check.
fn latch(info: RequiredUpdate) {
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

/// Latch a 426, but only when it came from the control plane.
///
/// Returns whether it latched, so the policy is assertable without reaching
/// into the gate's internals. See `Origin` for why a web-origin 426 is
/// ignored rather than honoured.
pub fn latch_from(origin: Origin, info: RequiredUpdate) -> bool {
    if origin != Origin::ControlPlane {
        tracing::warn!(
            "Ignoring HTTP 426 from {:?}: the client version floor is a control-plane contract, and another origin must not arm the process-wide block",
            origin
        );
        return false;
    }
    latch(info);
    true
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

    /// PR #162 review: `get_client_config` routes WEB-origin responses through
    /// the same `handle_response`, so for the first time a non-control-plane
    /// 426 can reach the latch. It must not arm it -- the latch is one-way for
    /// the life of the process and stops auto-reconnect outright.
    #[test]
    fn web_origin_426_does_not_latch() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        assert!(!latch_from(Origin::Web, info("9.9.9")));
        assert!(!is_blocked());
        assert_eq!(required_update(), None);
    }

    #[test]
    fn control_plane_426_still_latches() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        assert!(latch_from(Origin::ControlPlane, info("1.4.36")));
        assert!(is_blocked());
        assert_eq!(
            required_update().and_then(|i| i.required_version),
            Some("1.4.36".to_string())
        );
        reset_for_test();
    }

    /// A web-origin 426 must not even poison a LATER control-plane one.
    #[test]
    fn web_origin_426_leaves_a_later_control_plane_426_free_to_latch() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        assert!(!latch_from(Origin::Web, info("9.9.9")));
        assert!(latch_from(Origin::ControlPlane, info("1.4.36")));
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
