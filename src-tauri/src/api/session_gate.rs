//! Contract §3.3: a refresh token the server REJECTS ends the sign-in session
//! everywhere at once.
//!
//! The rejection is detected deep in the API client — the 401 interceptor,
//! the explicit refresh, the GDPR delete's own retry — which has no app handle
//! and must not depend on the command layer. So the client only REPORTS it
//! here, and the handler registered at start-up (`commands::session::
//! handle_session_expired`) tears the VPN down, clears the tokens and emits
//! `session-expired`. Same shape as `upgrade_gate` for the 426 floor.
//!
//! Only a 401 from the refresh endpoint counts: a network error, a 5xx or a
//! 429 there may succeed on the next attempt, and discarding a live refresh
//! token over one of those costs the user their account session (see
//! `commands::auth::get_auth_state`).

use std::sync::OnceLock;

use super::error::ApiError;

type Handler = Box<dyn Fn() + Send + Sync>;

static HANDLER: OnceLock<Handler> = OnceLock::new();

/// Register the session-expiry handler. The first registration wins.
pub fn set_handler(handler: impl Fn() + Send + Sync + 'static) {
    let _ = HANDLER.set(Box::new(handler));
}

/// Whether a failed refresh means the refresh token is dead for good.
pub(crate) fn refresh_rejected(error: &ApiError) -> bool {
    matches!(error, ApiError::Unauthorized)
}

/// Report a failed refresh. Does nothing unless the server rejected the token.
pub(crate) fn report_refresh_failure(error: &ApiError) {
    if refresh_rejected(error) {
        if let Some(handler) = HANDLER.get() {
            handler();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_rejected_refresh_ends_the_session() {
        assert!(refresh_rejected(&ApiError::Unauthorized));
        for transient in [
            ApiError::Network("offline".into()),
            ApiError::ServerError(503),
            ApiError::RateLimited,
            ApiError::Parse("x".into()),
            ApiError::NotAuthenticated,
            ApiError::CertificatePinningFailed("x".into()),
        ] {
            assert!(!refresh_rejected(&transient), "{transient:?}");
        }
    }
}
