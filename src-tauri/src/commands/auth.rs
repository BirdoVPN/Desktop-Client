//! Authentication commands
//!
//! Handles login, logout, token refresh, and auth state management.

use crate::api::client::AccountDeletion;
use crate::api::error::ApiError;
use crate::api::types::{
    AccountNumber, LoginResult, RotateConfirmBody, RotatePrepareBody, UserProfile,
};
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::commands::session::{end_session, EndReason};
use crate::storage::CredentialStore;
use crate::utils::redact_email;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroize;

// FIX-2-5: Client-side rate limiting for login IPC command
use std::sync::Mutex;
use std::time::Instant;

/// FIX-2-5: Simple sliding-window rate limiter for login attempts.
/// Max 5 attempts per 60-second window. Prevents brute-force via compromised webview.
static LOGIN_ATTEMPTS: Mutex<Option<Vec<Instant>>> = Mutex::new(None);
const MAX_LOGIN_ATTEMPTS: usize = 5;
const LOGIN_WINDOW_SECS: u64 = 60;

/// SEC-2FA: Rate limiter for 2FA verification attempts.
/// Max 5 attempts per 120-second window. Prevents TOTP brute-force
/// (1,000,000 possible 6-digit codes) from a compromised webview.
static TOTP_ATTEMPTS: Mutex<Option<Vec<Instant>>> = Mutex::new(None);
const MAX_TOTP_ATTEMPTS: usize = 5;
const TOTP_WINDOW_SECS: u64 = 120;

#[derive(Serialize)]
pub struct AuthState {
    pub is_authenticated: bool,
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub plan: Option<String>,
    /// Mirrors `UserProfile::has_password` so the UI can avoid demanding a
    /// password from SSO accounts, which have none. `true` whenever the profile
    /// is unknown, so an unresolved identity never silently drops the prompt.
    pub has_password: bool,
    /// Account API contract item 86: whether the account is anonymous, from
    /// `isAnonymous` / `accountType`. `None` when the server did not say (an
    /// older backend, or no profile this cycle); the UI then reads the email's
    /// shape as before.
    pub is_anonymous: Option<bool>,
    /// Item 86: the anonymous account number, for the Profile card. A
    /// credential: redacted in `Debug`, never logged.
    pub account_number: Option<AccountNumber>,
}

/// Manual: phase 1's anonymous email carries the account number (see
/// `UserProfile`'s Debug, REVIEW-WIN2-027).
impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("is_authenticated", &self.is_authenticated)
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("account_id", &self.account_id)
            .field("plan", &self.plan)
            .field("has_password", &self.has_password)
            .field("is_anonymous", &self.is_anonymous)
            .field("account_number", &self.account_number)
            .finish()
    }
}

impl AuthState {
    /// A session whose identity is not known this cycle (or no session).
    fn unknown_identity(is_authenticated: bool) -> Self {
        Self {
            is_authenticated,
            email: None,
            account_id: None,
            plan: None,
            // Unknown → assume a password exists, so the delete dialog keeps
            // asking for it. Never drop a confirmation because a fetch failed.
            has_password: true,
            is_anonymous: None,
            account_number: None,
        }
    }

    /// The signed-in identity `GET /auth/me` returned.
    fn of(profile: UserProfile) -> Self {
        Self {
            is_authenticated: true,
            is_anonymous: profile.is_anonymous_account(),
            has_password: profile.has_password,
            email: profile.email,
            account_id: Some(profile.id),
            plan: None,
            account_number: profile.account_number,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// FIX-1-3: Zeroize password from heap memory when LoginRequest is dropped.
/// Prevents credential recovery from process memory dumps.
impl Drop for LoginRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: Option<String>,
    pub user: Option<UserInfo>,
    /// FIX C-2: When 2FA is required, this contains the challenge token.
    /// The frontend must prompt for TOTP code and call verify_2fa.
    pub requires_two_factor: bool,
    pub challenge_token: Option<String>,
    /// Why a sign-in did not complete, as an IPC contract code (§2): a
    /// refusal is answered `Ok` with `success:false`, so the code rides here
    /// for the UI to map to canonical copy. `None` on success.
    pub code: Option<IpcErrorCode>,
}

/// The code for a refused sign-in. A 401 from a sign-in endpoint means the
/// credentials were wrong — the generic mapping reads every 401 as an expired
/// session, which is only true for an authenticated call.
pub(crate) fn sign_in_failure_code(error: &ApiError) -> IpcErrorCode {
    match error {
        ApiError::Unauthorized | ApiError::Rejected { status: 401, .. } => {
            IpcErrorCode::InvalidCredentials
        }
        other => IpcError::from_api(other).code,
    }
}

/// The code for a refused 2FA verification: a 400/401 there is the code (or
/// its challenge) being wrong or expired.
fn two_factor_failure_code(error: &ApiError) -> IpcErrorCode {
    match error {
        ApiError::Unauthorized
        | ApiError::Rejected {
            status: 400 | 401, ..
        } => IpcErrorCode::TwoFactorInvalid,
        other => IpcError::from_api(other).code,
    }
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub plan: String,
    pub is_anonymous: bool,
}

/// Login with email and password
#[tauri::command]
pub async fn login(
    app: AppHandle,
    request: LoginRequest,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
    // MR-1861: a sign-in typed in by hand never resumes the session an
    // update ended — it belonged to whoever was signed in before.
    crate::commands::update_resume::discard();
    // FIX-2-5: Rate limit login attempts (max 5 per 60s window)
    {
        let mut guard = LOGIN_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = guard.get_or_insert_with(Vec::new);
        let now = Instant::now();
        let window = std::time::Duration::from_secs(LOGIN_WINDOW_SECS);
        // Remove expired attempts
        attempts.retain(|t| now.duration_since(*t) < window);
        // Hard cap on vector length (defense-in-depth): the decision below only
        // depends on the most recent MAX_LOGIN_ATTEMPTS timestamps, so never keep
        // more than that even under rapid bursts. Timestamps are pushed in
        // monotonic order, so draining the front retains the most recent ones.
        // No-op in the normal flow (the early return below prevents growth past
        // the cap); this purely bounds memory if that invariant ever changes.
        if attempts.len() > MAX_LOGIN_ATTEMPTS {
            let excess = attempts.len() - MAX_LOGIN_ATTEMPTS;
            attempts.drain(0..excess);
        }
        if attempts.len() >= MAX_LOGIN_ATTEMPTS {
            let oldest = attempts[0];
            let wait = window.saturating_sub(now.duration_since(oldest));
            tracing::warn!(
                "Login rate limit exceeded — {} attempts in {}s window",
                attempts.len(),
                LOGIN_WINDOW_SECS
            );
            return Err(IpcError::new(
                IpcErrorCode::RateLimited,
                format!(
                    "Too many login attempts. Please wait {} seconds.",
                    wait.as_secs()
                ),
            )
            .with_retry_after(wait.as_secs()));
        }
        attempts.push(now);
    }

    tracing::info!("Login attempt for: {}", redact_email(&request.email));

    // A-M77 / MR-2139: during a failed-sign-in spike the server may ask for a
    // proof of work, solved once and sent once (`api::pow::login_with_proof`).
    let (cancel, on_progress) = begin_proof(&app);
    let outcome = api
        .login(&request.email, &request.password, cancel, on_progress)
        .await;
    end_proof();
    match outcome {
        Ok(crate::api::pow::Registered::Cancelled) => Ok(cancelled_response()),
        Ok(crate::api::pow::Registered::Done(result)) => match result {
            LoginResult::Success { tokens, .. } => {
                // Store tokens in Windows Credential Manager for persistence
                if let Err(e) =
                    credentials.store_tokens(&tokens.access_token, &tokens.refresh_token)
                {
                    tracing::warn!(
                        "Failed to persist credentials to Windows Credential Manager: {}",
                        e
                    );
                }

                tracing::trace!(
                    "Login: tokens set in API client: is_authenticated={}",
                    api.is_authenticated().await
                );

                let user_info = UserInfo {
                    email: Some(request.email.clone()),
                    account_id: None,
                    plan: "unknown".to_string(),
                    is_anonymous: false,
                };

                tracing::info!("Login successful for: {}", redact_email(&request.email));
                Ok(LoginResponse {
                    success: true,
                    message: None,
                    user: Some(user_info),
                    requires_two_factor: false,
                    challenge_token: None,
                    code: None,
                })
            }
            LoginResult::TwoFactorChallenge {
                challenge_token, ..
            } => {
                // FIX C-2: 2FA is enabled — return challenge token to frontend
                tracing::info!("2FA required for: {}", redact_email(&request.email));
                Ok(LoginResponse {
                    success: false,
                    message: Some("Two-factor authentication required".to_string()),
                    user: None,
                    requires_two_factor: true,
                    challenge_token: Some(challenge_token),
                    code: Some(IpcErrorCode::TwoFactorRequired),
                })
            }
        },
        Err(e) => {
            tracing::warn!("Login failed for {}: {}", redact_email(&request.email), e);
            Ok(LoginResponse {
                success: false,
                message: Some(crate::utils::redact::sanitize_error(&e.to_string())),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
                code: Some(sign_in_failure_code(&e)),
            })
        }
    }
}

/// Logout and clear stored credentials
#[tauri::command]
pub async fn logout(
    app: AppHandle,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, IpcError> {
    tracing::info!("Logging out");

    // W1-009 / contract §3.2: end the VPN session in Rust BEFORE the
    // credentials go. The UI only disconnected first in some states, so a
    // lockdown block after a give-up, or a connect still in flight, survived
    // sign-out: the machine stayed firewalled at the login screen, or a tunnel
    // came up for a signed-out user and auto-reconnect kept re-dialling with
    // the previous account's session.
    end_session(&app, EndReason::SignOut).await;
    // The next account on this machine must not inherit this one's server
    // (REVIEW-WIN-007): tray Quick Connect reads it.
    crate::commands::settings::clear_account_choices(&app).await;

    // Try to logout on server (best effort)
    let _ = api.logout().await;

    // Clear local credentials
    credentials.clear_tokens().map_err(|e| {
        IpcError::unknown(format!(
            "Failed to clear credentials: {}",
            crate::utils::redact::sanitize_error(&e.to_string())
        ))
    })?;

    // Logout hygiene: since MR-703 / MR-1742 no ML-KEM key outlives a connect,
    // so there is no identity to reset. This only deletes any key file an older
    // build left (startup already does; this covers one written since by a
    // downgrade). Best-effort and idempotent.
    crate::vpn::birdo_pq::purge_legacy_keypair_files();
    crate::vpn::birdo_pq::record_disabled();

    // The device identifier is deliberately NOT rotated here (second-pass
    // #14), matching iOS and Android: it rotates on account DELETION only.
    // Rotating under a live account leaves the old device row behind (the
    // device list and GET /devices/limit/status count it), re-triggers 2FA on
    // every sign-in, and resets the per-device anonymous-register cap. The
    // ML-KEM reset above is what stops the post-quantum key linking the next
    // account on this machine to this one.

    Ok(true)
}

/// GDPR: Permanently delete account and all associated data.
/// Requires password confirmation to prevent accidental deletion from a
/// compromised webview (defense-in-depth).
// No `Debug`: it carries the password, the 2FA code, the account number and the
// e-mailed code, and a derived one would print them.
#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
    /// The TOTP or backup code, once the server has asked for it
    /// (`two_factor_required`, Account API contract item 85). Absent on the
    /// first attempt and for accounts without 2FA.
    #[serde(default)]
    pub two_factor_code: Option<String>,
    /// MR-179: the anonymous account's 24-digit number, once the server (or the
    /// preflight) asked for it. Absent otherwise.
    #[serde(default)]
    pub account_number: Option<String>,
    /// MR-179: the code e-mailed by `send_deletion_code` to an SSO account.
    #[serde(default)]
    pub email_code: Option<String>,
}

impl Drop for DeleteAccountRequest {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(code) = self.two_factor_code.as_mut() {
            code.zeroize();
        }
        if let Some(number) = self.account_number.as_mut() {
            number.zeroize();
        }
        if let Some(code) = self.email_code.as_mut() {
            code.zeroize();
        }
    }
}

/// What the UI needs after a successful deletion.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountResult {
    /// App Store / Google Play subscriptions the server reported as still
    /// billing (store names). Empty when there are none, and on a backend that
    /// does not report them yet — the dialog warns about store billing before
    /// the user confirms either way.
    pub store_subscriptions_still_billing: Vec<String>,
    /// MR-2483: this retry found the account already deleted (an earlier
    /// attempt's 2xx could not be read, MR-2370). Everything local was cleared
    /// exactly as for a confirmed deletion; the UI says the account is gone
    /// and the user is signed out. The store list is empty then: it rode on
    /// the answer that was lost.
    pub already_deleted: bool,
}

/// The error a refused deletion shows. The backend's own words when it gave
/// any (the password check's "Incorrect password", which classifies as
/// `invalid_credentials`), not the variant's generic "Unknown error: …"
/// framing.
fn delete_failure_message(error: &ApiError) -> IpcError {
    let (code, reason) = match error {
        // The dialog asks for the code / says it was wrong, by code alone.
        ApiError::TwoFactorRequired(_)
        | ApiError::TwoFactorInvalid(_)
        | ApiError::StepUp { .. } => {
            return IpcError::from_api(error);
        }
        ApiError::Rejected { message, .. } | ApiError::Unknown(message) => {
            (IpcError::from_api(error).code, message.clone())
        }
        ApiError::Unauthorized | ApiError::NotAuthenticated => (
            IpcErrorCode::SessionExpired,
            "Your session has expired. Sign in again, then retry.".to_string(),
        ),
        other => (IpcError::from_api(other).code, other.to_string()),
    };
    let failed = IpcError::new(code, format!("Account deletion failed: {}", reason));
    // MR-1808: a rate limit keeps the server's `Retry-After`, so the dialog
    // can say how long to wait.
    match IpcError::from_api(error).retry_after_secs {
        Some(secs) => failed.with_retry_after(secs),
        None => failed,
    }
}

/// The physical interface's address while a tunnel is up, for a request that
/// must not ride it (REVIEW-WIN2-007). Windows only: elsewhere the request
/// keeps today's path.
async fn around_the_tunnel(app: &AppHandle) -> Option<std::net::IpAddr> {
    #[cfg(target_os = "windows")]
    {
        use tauri::Manager;
        if app
            .state::<crate::vpn::manager::VpnManager>()
            .holds_tunnel()
            .await
        {
            return crate::vpn::network_events::physical_source_address();
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        None
    }
}

#[tauri::command]
pub async fn delete_account(
    request: DeleteAccountRequest,
    app: AppHandle,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<DeleteAccountResult, IpcError> {
    tracing::info!("Account deletion requested (GDPR)");

    // Nothing local is touched unless the server confirms the deletion: a
    // refused request (wrong password, expired session, offline) must leave
    // the user signed in to the account that still exists — and connected.
    let two_factor_code = request
        .two_factor_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    // REVIEW-WIN2-007: with a tunnel up, the request goes AROUND it. The
    // server removes the account's peers before it answers, so an answer
    // through the tunnel was dropped at the relay: a deletion that succeeded
    // was reported as failed, the dead tunnel's re-dial then hit a 401, and
    // the app fell to Login with "your session expired". Keeping the tunnel
    // until the server confirms is still the rule; only the request's path
    // changes.
    // MR-179: digits only for the number (the server ignores grouping, and a
    // pasted "1234 5678 ..." must not fail a length check there), the code as
    // typed; blank means not sent.
    let account_number: Option<zeroize::Zeroizing<String>> = request
        .account_number
        .as_deref()
        .map(|n| {
            zeroize::Zeroizing::new(n.chars().filter(char::is_ascii_digit).collect::<String>())
        })
        .filter(|n| !n.is_empty());
    let email_code = request
        .email_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    let around_the_tunnel = around_the_tunnel(&app).await;
    let deletion = api
        .delete_account(
            &request.password,
            two_factor_code,
            account_number.as_ref().map(|n| n.as_str()),
            email_code,
            around_the_tunnel,
        )
        .await
        .map_err(|e| delete_failure_message(&e))?;

    // The server has confirmed (a 2xx whose body says `success: true`; an
    // unreadable one came back above as an error the dialog offers to retry,
    // MR-2370), or the retry after that unreadable one found the account
    // already gone (MR-2483): the same ending either way. Only NOW take the
    // tunnel down, before the local state is
    // cleared (second-pass #15). This used to happen in
    // the dialog before the request, so a wrong password or an offline delete
    // left the user disconnected from an account that still existed. The
    // account's keys are gone server-side, so the tunnel could not carry
    // traffic anyway; ending the session also stops auto-reconnect and
    // disarms the kill switch, so nothing is left blocking. It skips the
    // backend disconnect call: the account is gone, and a 401 from it would
    // read as an expired session.
    end_session(&app, EndReason::AccountDeleted).await;
    crate::commands::settings::clear_account_choices(&app).await;

    // Clear all local credentials after successful server-side deletion,
    // including any key file an older build left (same hygiene as logout —
    // doubly so for a GDPR deletion) and the device identifier (C-8).
    let _ = credentials.clear_tokens();
    crate::vpn::birdo_pq::purge_legacy_keypair_files();
    crate::vpn::birdo_pq::record_disabled();
    crate::utils::device_id::rotate();

    let result = deletion_result(&deletion);
    if result.already_deleted {
        tracing::info!("Account already deleted by an earlier attempt — signed out");
    } else {
        tracing::info!("Account permanently deleted");
    }
    Ok(result)
}

/// What the dialog is told about a deletion that ended the account.
fn deletion_result(deletion: &AccountDeletion) -> DeleteAccountResult {
    match deletion {
        AccountDeletion::Deleted(response) => DeleteAccountResult {
            store_subscriptions_still_billing: response
                .store_subscriptions_still_billing
                .as_ref()
                .map(crate::api::types::store_subscription_labels)
                .unwrap_or_default(),
            already_deleted: false,
        },
        // MR-2483: the list rode on the answer that was lost.
        AccountDeletion::AlreadyDeleted => DeleteAccountResult {
            store_subscriptions_still_billing: Vec::new(),
            already_deleted: true,
        },
    }
}

/// What the deletion dialog shows BEFORE the user confirms (second-pass #9).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionPreflightResult {
    /// Store names ("Apple App Store", "Google Play") whose subscriptions will
    /// keep billing after the deletion. Empty when there are none.
    pub store_subscriptions_still_billing: Vec<String>,
    /// A web (Polar) subscription is billing and the deletion will cancel it.
    pub web_subscription_will_be_cancelled: bool,
    /// MR-179: the server's step-up factor tokens for this account
    /// (`password`, `account_number`, `email_code`, `apple_reauth`,
    /// `two_factor`). Empty from a backend older than birdo-web #766, or when
    /// the preflight said nothing.
    pub step_up_factors: Vec<String>,
    /// MR-179: the server refuses a deletion without them. Until then the
    /// number / code is optional, so a user whose code e-mail fails can still
    /// delete, as before.
    pub step_up_enforced: bool,
    /// MR-2335: the server takes a 24-hour hold instead of the number / code
    /// (`stepUp.holdAvailable === true`; its own switch, independent of
    /// `enforced`). False from an older backend.
    pub step_up_hold_available: bool,
}

/// What `send_deletion_code` returns: the masked address the code went to.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionCodeResult {
    pub sent_to: Option<String>,
    /// How long the code works, in minutes, when the server says.
    pub expires_in_minutes: Option<u64>,
}

/// MR-179: e-mail the one-time deletion code to an SSO account (no password,
/// no 2FA). Errors reach the dialog by code: `rate_limited` past 3 an hour,
/// `server_unavailable` when the mail could not be sent.
#[tauri::command]
pub async fn send_deletion_code(api: State<'_, BirdoApi>) -> Result<DeletionCodeResult, IpcError> {
    let response = api.send_deletion_code().await.map_err(IpcError::from)?;
    Ok(DeletionCodeResult {
        sent_to: response.sent_to,
        expires_in_minutes: response.expires_in_minutes,
    })
}

/// `GET /api/v1/gdpr/delete/preflight`: read-only, nothing local changes.
/// The dialog treats an error as "unknown" and keeps its static warning, so
/// a failed preflight never blocks a deletion.
#[tauri::command]
pub async fn deletion_preflight(
    api: State<'_, BirdoApi>,
) -> Result<DeletionPreflightResult, IpcError> {
    let response = api.deletion_preflight().await.map_err(IpcError::from)?;
    Ok(deletion_preflight_result(&response))
}

fn deletion_preflight_result(
    response: &crate::api::types::DeletionPreflightResponse,
) -> DeletionPreflightResult {
    DeletionPreflightResult {
        store_subscriptions_still_billing: response
            .store_subscriptions_still_billing
            .as_ref()
            .map(crate::api::types::store_subscription_labels)
            .unwrap_or_default(),
        web_subscription_will_be_cancelled: response
            .web_subscription_will_be_cancelled
            .unwrap_or(false),
        step_up_factors: response
            .step_up
            .as_ref()
            .map(|s| s.factors.clone())
            .unwrap_or_default(),
        step_up_enforced: response
            .step_up
            .as_ref()
            .map(|s| s.enforced)
            .unwrap_or(false),
        step_up_hold_available: response
            .step_up
            .as_ref()
            .is_some_and(|s| s.hold_available()),
    }
}

/// MR-2335: what the hold dialog sends. The password (or, for an account
/// without one, the typed confirmation, exactly as `delete_account`) and the
/// 2FA code once asked for. No number and no e-mailed code: the hold stands in
/// for them.
// No `Debug`: it carries the password and the 2FA code.
#[derive(Deserialize)]
pub struct DeletionHoldRequest {
    pub password: String,
    #[serde(default)]
    pub two_factor_code: Option<String>,
}

impl Drop for DeletionHoldRequest {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(code) = self.two_factor_code.as_mut() {
            code.zeroize();
        }
    }
}

/// A deletion on hold, for the dialog and the Profile banner.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionHoldResult {
    /// For `cancel_pending_change`.
    pub pending_change_id: String,
    /// ISO-8601 server time it applies at; the UI shows it in local time.
    pub apply_after: String,
    /// The server's sentence about the hold, when it sent one.
    pub message: Option<String>,
    /// It was filed before this request (409 `change_already_pending`).
    pub already_pending: bool,
}

impl From<crate::api::types::DeletionHold> for DeletionHoldResult {
    fn from(hold: crate::api::types::DeletionHold) -> Self {
        Self {
            pending_change_id: hold.pending_change_id,
            apply_after: hold.apply_after,
            message: hold.message,
            already_pending: hold.already_pending,
        }
    }
}

/// A refused hold, by code. The server's own sentence where it is the
/// explanation (`hold_unavailable`, and a 429 whose wait only the sentence
/// names), never "Account deletion failed: ...": nothing was deleted.
fn hold_failure(error: &ApiError) -> IpcError {
    match error {
        ApiError::Unauthorized | ApiError::NotAuthenticated => IpcError::session_expired(),
        // A 202 that could not be read, or any other 2xx: nothing is assumed.
        ApiError::Parse(_) => IpcError::new(
            IpcErrorCode::ServerError,
            "The server's answer to the hold request was not the expected one. Nothing is \
             assumed deleted.",
        ),
        ApiError::Rejected { message, .. } => {
            IpcError::new(IpcError::from_api(error).code, message)
        }
        other => IpcError::from_api(other),
    }
}

/// MR-2335 (MR-179 hold fallback, birdo-web #883): ask for the account to be
/// deleted in 24 hours, for a user who cannot present the account number or
/// the e-mailed code. Offered only when the preflight said
/// `holdAvailable: true`.
///
/// NOT a deletion: unlike `delete_account`, nothing local is touched on ANY
/// answer. No sign-out, no token wipe, no tunnel teardown, no device-id
/// rotation: the account still exists, the user can cancel, and the server
/// drops the hold when this app's session signs out.
///
/// A 409 `change_already_pending` whose body does not name the hold (the
/// server's error filter keeps only `details`) is answered from
/// `GET /auth/pending-changes`; only if that cannot say either is it a
/// `hold_unavailable` with the server's sentence.
#[tauri::command]
pub async fn request_deletion_hold(
    request: DeletionHoldRequest,
    api: State<'_, BirdoApi>,
) -> Result<DeletionHoldResult, IpcError> {
    tracing::info!("Account deletion hold requested (GDPR)");
    let two_factor_code = request
        .two_factor_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    match api
        .request_deletion_hold(&request.password, two_factor_code)
        .await
    {
        Ok(hold) => Ok(hold.into()),
        Err(ApiError::DeletionAlreadyOnHold(message)) => {
            match api
                .list_pending_changes()
                .await
                .ok()
                .and_then(|rows| held_deletion_in(&rows, message.trim()))
            {
                Some(hold) => Ok(hold.into()),
                None => Err(hold_failure(&ApiError::DeletionAlreadyOnHold(message))),
            }
        }
        Err(e) => Err(hold_failure(&e)),
    }
}

/// The account's held deletion among the pending changes, if one is listed
/// with a usable time.
fn held_deletion_in(
    rows: &[crate::api::types::PendingChange],
    message: &str,
) -> Option<crate::api::types::DeletionHold> {
    rows.iter()
        .find(|row| row.action == "account_delete" && row.apply_after.is_some())
        .map(|row| crate::api::types::DeletionHold {
            pending_change_id: row.id.clone(),
            apply_after: row.apply_after.clone().unwrap_or_default(),
            message: (!message.is_empty()).then(|| message.to_string()),
            already_pending: true,
        })
}

/// One pending change, for the Profile banner (MR-2335). The UI acts on
/// `action: "account_delete"` only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingChangeItem {
    pub id: String,
    pub action: String,
    pub description: Option<String>,
    pub apply_after: Option<String>,
    pub created_at: Option<String>,
    pub detail: Option<String>,
}

/// MR-2335: `GET /auth/pending-changes`, read on opening Profile and on window
/// focus. A hold can vanish between two reads (the server cancels it on a
/// sign-out elsewhere, a number rotation, a password or 2FA change), so an
/// empty list is an answer, not an error.
#[tauri::command]
pub async fn list_pending_changes(
    api: State<'_, BirdoApi>,
) -> Result<Vec<PendingChangeItem>, IpcError> {
    let rows = api.list_pending_changes().await.map_err(IpcError::from)?;
    Ok(rows
        .into_iter()
        .map(|row| PendingChangeItem {
            id: row.id,
            action: row.action,
            description: row.description,
            apply_after: row.apply_after,
            created_at: row.created_at,
            detail: row.detail,
        })
        .collect())
}

/// What `cancel_pending_change` did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelPendingChangeResult {
    /// Cancelled by this request.
    pub cancelled: bool,
    /// It was gone already (404 `pending_change_not_found`): nothing to do but
    /// read the list again.
    pub already_gone: bool,
}

/// MR-2335: `POST /auth/pending-changes/:id/cancel`. Cancelling a held
/// deletion keeps the account; nothing local changes either way.
#[tauri::command]
pub async fn cancel_pending_change(
    id: String,
    api: State<'_, BirdoApi>,
) -> Result<CancelPendingChangeResult, IpcError> {
    if !crate::api::types::pending_change_id_ok(&id) {
        return Err(IpcError::unknown("That change could not be found."));
    }
    let cancelled = api
        .cancel_pending_change(&id)
        .await
        .map_err(IpcError::from)?;
    tracing::info!(
        "Pending change {}",
        if cancelled {
            "cancelled"
        } else {
            "was already gone"
        }
    );
    Ok(CancelPendingChangeResult {
        cancelled,
        already_gone: !cancelled,
    })
}

/// GDPR: Export all user data (Right to Data Portability, Art. 20).
/// Returns a JSON blob the frontend can save to disk.
#[tauri::command]
pub async fn export_user_data(api: State<'_, BirdoApi>) -> Result<serde_json::Value, IpcError> {
    tracing::info!("GDPR data export requested");
    api.export_user_data().await.map_err(IpcError::from)
}

/// What `get_auth_state` answers when the stored session's profile could not
/// be fetched (MR-2550, review P469-L1). Decided from `get_profile`'s answer
/// alone: its 401 has already run the refresh, so there is nothing left to
/// try, and a second flight here would only present the same token again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileFailure {
    /// Signed in, the identity unknown this cycle: the token is not the
    /// problem, or may work next time.
    KeepSession,
    /// The server refused the session's refresh. The session gate has ended
    /// it (`commands::session::handle_session_expired`, which also discards
    /// the stored session when the refresh token itself was rejected).
    SignedOut,
    /// There was no session to ask with any more (a Sign Out, an expiry): the
    /// answer is what memory holds now.
    AsMemoryHolds,
}

/// `renewed`: the profile's 401 came back although the session was renewed
/// during the call (its refresh worked, or a sign-in landed), so the 401 is
/// no verdict on the session in memory now.
///
/// Only a DEFINITIVE rejection may end the stored session. Clearing it on
/// any error used to throw away a valid 30-day refresh token at a launch
/// with no connectivity (on a plane, behind a captive portal, mid-deploy),
/// and an anonymous account whose number was never written down with it.
/// The cost is asymmetric: keeping a dead token costs one failed request
/// next launch, discarding a live one costs the account.
///
/// - 429, a 5xx that named its wait, a held request (MR-1808): "come back
///   later", nothing about the token.
/// - 401 (`Unauthorized`) and not renewed: `request_with_retry` refreshed,
///   and the server refused it (MR-2500 / MR-1771: only a 401 ends a
///   session; `error_after_failed_refresh`): signed out.
/// - `NotAuthenticated`: as memory holds it.
/// - anything else (no answer, a 5xx, a refresh that failed transiently and
///   is held, a pin failure, an unreadable body): kept.
fn after_profile_failure(error: &ApiError, renewed: bool) -> ProfileFailure {
    match error {
        ApiError::Unauthorized if !renewed => ProfileFailure::SignedOut,
        ApiError::NotAuthenticated => ProfileFailure::AsMemoryHolds,
        _ => ProfileFailure::KeepSession,
    }
}

/// Get current authentication state
#[tauri::command]
pub async fn get_auth_state(
    credentials: State<'_, CredentialStore>,
    api: State<'_, BirdoApi>,
) -> Result<AuthState, IpcError> {
    match credentials.get_tokens() {
        Ok(tokens) => {
            // W1-028: only when memory holds no session. A session in memory
            // may carry a ROTATED refresh token the keystore does not have
            // yet; putting the keystore's consumed one back is what the server
            // reads as token theft.
            api.restore_tokens_if_absent(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;

            // MR-2550 (review P469-L1): the session `get_profile` starts
            // with, to tell a renewal during it from a refusal.
            let before = api.access_token_value().await;
            // Try to get user profile to validate token. Its 401 runs THE
            // refresh (`request_with_retry`: detached, adopt-checked, after
            // the "token changed while waiting" check), and the session gate
            // ends the session when the server rejects it. No second flight
            // here: one used to follow every failure but a 429/503, so a
            // launch could present a dead token twice, or rotate a renewed
            // pair again for nothing (each rotation one more lost-answer
            // window), and an offline launch spent a refresh on every
            // identity retry.
            match api.get_profile().await {
                Ok(profile) => Ok(AuthState::of(profile)),
                Err(e) => {
                    let renewed = matches!(e, ApiError::Unauthorized) && {
                        let now = api.access_token_value().await;
                        now.is_some() && now != before
                    };
                    Ok(match after_profile_failure(&e, renewed) {
                        ProfileFailure::KeepSession => {
                            tracing::warn!(
                                "Profile fetch failed ({e}) — session kept, identity unknown                                  this cycle"
                            );
                            AuthState::unknown_identity(true)
                        }
                        ProfileFailure::SignedOut => {
                            tracing::info!("The server refused the session's refresh — signed out");
                            AuthState::unknown_identity(false)
                        }
                        ProfileFailure::AsMemoryHolds => {
                            tracing::info!(
                                "The session ended while the start-up check ran — nothing                                  restored"
                            );
                            AuthState::unknown_identity(api.is_authenticated().await)
                        }
                    })
                }
            }
        }
        // No usable stored session. "No access/refresh token stored" is the normal
        // first-run case; anything else means the OS keystore itself refused us,
        // which silently ends every session and MUST be visible in the log. This
        // arm previously swallowed both cases without a word, which is why a
        // keystore that discarded every write produced no diagnostic at all.
        Err(e) => {
            if e.starts_with("No access token") || e.starts_with("No refresh token") {
                tracing::debug!("No stored session found ({e}) — starting signed out");
            } else {
                tracing::error!(
                    "OS keystore read failed ({e}) — cannot restore the session; the user \
                     will appear signed out despite having logged in"
                );
            }
            Ok(AuthState::unknown_identity(false))
        }
    }
}

/// FIX C-2: Verify a TOTP code for two-factor authentication.
/// Called after login returns `requires_two_factor: true` with a challenge token.
#[derive(Debug, Deserialize)]
pub struct TwoFactorRequest {
    pub challenge_token: String,
    pub code: String,
}

#[tauri::command]
pub async fn verify_2fa(
    request: TwoFactorRequest,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
    // MR-1861: a sign-in typed in by hand never resumes the session an
    // update ended — it belonged to whoever was signed in before.
    crate::commands::update_resume::discard();
    // SEC-2FA: Rate limit TOTP verification attempts (max 5 per 120s window)
    {
        let mut guard = TOTP_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = guard.get_or_insert_with(Vec::new);
        let now = Instant::now();
        let window = std::time::Duration::from_secs(TOTP_WINDOW_SECS);
        attempts.retain(|t| now.duration_since(*t) < window);
        // Hard cap on vector length (defense-in-depth): mirrors the login limiter.
        // Only the most recent MAX_TOTP_ATTEMPTS timestamps affect the decision
        // below, so never retain more than that even under rapid bursts. No-op in
        // the normal flow; purely bounds memory under pathological bursts.
        if attempts.len() > MAX_TOTP_ATTEMPTS {
            let excess = attempts.len() - MAX_TOTP_ATTEMPTS;
            attempts.drain(0..excess);
        }
        if attempts.len() >= MAX_TOTP_ATTEMPTS {
            let oldest = attempts[0];
            let wait = window.saturating_sub(now.duration_since(oldest));
            tracing::warn!(
                "2FA rate limit exceeded — {} attempts in {}s window",
                attempts.len(),
                TOTP_WINDOW_SECS
            );
            return Err(IpcError::new(
                IpcErrorCode::RateLimited,
                format!(
                    "Too many 2FA attempts. Please wait {} seconds.",
                    wait.as_secs()
                ),
            )
            .with_retry_after(wait.as_secs()));
        }
        attempts.push(now);
    }

    tracing::info!("2FA verification attempt");

    match api
        .verify_2fa(&request.challenge_token, &request.code)
        .await
    {
        Ok(response) => {
            if response.ok {
                // A successful (ok=true) response MUST carry tokens; otherwise the
                // user would be left unauthenticated (no creds in the store or the
                // in-memory client) while the frontend treats login as succeeded.
                let tokens = match response.tokens {
                    Some(ref tokens) => tokens,
                    None => {
                        tracing::warn!("2FA reported success but returned no tokens");
                        return Ok(LoginResponse {
                            success: false,
                            message: Some(
                                "2FA verification did not return credentials".to_string(),
                            ),
                            user: None,
                            requires_two_factor: true,
                            challenge_token: Some(request.challenge_token),
                            code: Some(IpcErrorCode::ServerError),
                        });
                    }
                };

                // Persist tokens to Windows Credential Manager
                if let Err(e) =
                    credentials.store_tokens(&tokens.access_token, &tokens.refresh_token)
                {
                    tracing::warn!("Failed to persist credentials after 2FA: {}", e);
                }

                tracing::info!("2FA verification successful");
                Ok(LoginResponse {
                    success: true,
                    message: None,
                    user: None, // Profile will be fetched via get_auth_state
                    requires_two_factor: false,
                    challenge_token: None,
                    code: None,
                })
            } else {
                Ok(LoginResponse {
                    success: false,
                    message: Some("Invalid 2FA code".to_string()),
                    user: None,
                    requires_two_factor: true,
                    challenge_token: Some(request.challenge_token),
                    code: Some(IpcErrorCode::TwoFactorInvalid),
                })
            }
        }
        Err(e) => {
            tracing::warn!("2FA verification failed: {}", e);
            Ok(LoginResponse {
                success: false,
                message: Some(format!("2FA verification failed: {}", e)),
                user: None,
                requires_two_factor: true,
                challenge_token: Some(request.challenge_token),
                code: Some(two_factor_failure_code(&e)),
            })
        }
    }
}

/// Anonymous login request from the frontend: the account's 24-digit ID plus
/// an optional password (set on the website). The endpoint never creates
/// accounts — the old device-ID-only flow could not succeed at all (the
/// backend requires anonymousId), which left the whole tab a dead end.
#[derive(Debug, Deserialize)]
pub struct AnonymousLoginCommandRequest {
    #[serde(rename = "anonymousId")]
    pub anonymous_id: String,
    #[serde(default)]
    pub password: Option<String>,
}

/// Zeroize the optional password from heap memory on drop (same rationale as
/// LoginRequest / FIX-1-3).
impl Drop for AnonymousLoginCommandRequest {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.password {
            p.zeroize();
        }
    }
}

/// Event the proof of work reports its progress on: a percentage (0-99) while
/// this device works a challenge out. Sign-up (MR-2152) and, during a
/// failed-sign-in spike, sign-in (A-M77 / MR-2139) share it, and so share
/// `cancel_signup_proof`: only one of them runs at a time.
const SIGNUP_PROOF_EVENT: &str = "signup-proof-progress";

/// The running sign-up's cancel flag, for `cancel_signup_proof`.
static SIGNUP_CANCEL: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

/// Stop the device check of a sign-up in progress; the sign-up then ends as
/// cancelled and sends nothing.
#[tauri::command]
pub fn cancel_signup_proof() {
    if let Some(flag) = SIGNUP_CANCEL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        flag.store(true, Ordering::Release);
    }
}

/// Progress reporter of a proof of work: (difficulty bits, hashes done).
type ProofProgress = Arc<dyn Fn(u32, u64) + Send + Sync>;

/// The cancel flag and the progress reporter of one proof of work. The flag is
/// registered for `cancel_signup_proof`; call `end_proof` when the request ends.
fn begin_proof(app: &AppHandle) -> (Arc<AtomicBool>, ProofProgress) {
    let cancel = Arc::new(AtomicBool::new(false));
    *SIGNUP_CANCEL.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&cancel));
    let on_progress: ProofProgress = {
        let app = app.clone();
        let throttle = Mutex::new(crate::api::pow::Throttle::new(Duration::from_millis(250)));
        Arc::new(move |bits, hashes| {
            let first = hashes == 0;
            if first || throttle.lock().unwrap_or_else(|e| e.into_inner()).ready() {
                // Expected work is 2^bits hashes; 99 until the nonce is found.
                let expected = 2f64.powi(bits as i32);
                let percent = ((hashes as f64 / expected) * 100.0).min(99.0) as u32;
                let _ = app.emit(SIGNUP_PROOF_EVENT, percent);
            }
        })
    };
    (cancel, on_progress)
}

fn end_proof() {
    *SIGNUP_CANCEL.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The answer to a sign-in or sign-up the user cancelled while the proof of
/// work ran: nothing was sent after the cancel.
fn cancelled_response() -> LoginResponse {
    LoginResponse {
        success: false,
        message: Some("Cancelled".to_string()),
        user: None,
        requires_two_factor: false,
        challenge_token: None,
        code: Some(IpcErrorCode::Cancelled),
    }
}

/// Create a BRAND-NEW anonymous account in-app and sign in.
///
/// Desktop could previously only LOG IN to an existing 24-digit anonymous ID;
/// creating one forced the user out to the website. Mobile can create one in
/// app (registerAnonymous). This closes that parity gap: the server mints the
/// ID and returns tokens, so the app is signed in immediately. The returned
/// 24-digit ID is the account's ONLY recovery credential — the frontend must
/// surface it prominently ("save this") before proceeding.
#[tauri::command]
pub async fn register_anonymous(
    app: AppHandle,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
    // MR-1861: a sign-in typed in by hand never resumes the session an
    // update ended — it belonged to whoever was signed in before.
    crate::commands::update_resume::discard();
    // Same client-side rate limit as login (compromised-webview guard). The
    // backend also enforces a strict per-IP creation cap.
    {
        let mut guard = LOGIN_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = guard.get_or_insert_with(Vec::new);
        let now = Instant::now();
        attempts.retain(|t| now.duration_since(*t).as_secs() < LOGIN_WINDOW_SECS);
        if attempts.len() >= MAX_LOGIN_ATTEMPTS {
            return Ok(LoginResponse {
                success: false,
                message: Some("Too many attempts. Please wait a minute.".to_string()),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
                code: Some(IpcErrorCode::RateLimited),
            });
        }
        attempts.push(now);
    }

    let device_id = crate::utils::get_device_id();
    tracing::info!("Anonymous account creation requested");

    // MR-2152: the sign-up proof of work. `cancel_signup_proof` sets this.
    let (cancel, on_progress) = begin_proof(&app);
    let outcome = api
        .register_anonymous(
            &device_id,
            Some(crate::commands::vpn::get_device_name()),
            cancel,
            on_progress,
        )
        .await;
    end_proof();

    match outcome {
        Ok(crate::api::pow::Registered::Cancelled) => Ok(cancelled_response()),
        Ok(crate::api::pow::Registered::Done(result)) if result.ok => {
            if let Some(ref tokens) = result.tokens {
                if let Err(e) =
                    credentials.store_tokens(&tokens.access_token, &tokens.refresh_token)
                {
                    tracing::warn!("Failed to persist new anonymous credentials: {}", e);
                }
            }
            tracing::info!("Anonymous account created and signed in");
            Ok(LoginResponse {
                success: true,
                message: None,
                user: Some(UserInfo {
                    // account_id carries the 24-digit ID for the "save this" step.
                    email: None,
                    account_id: result.anonymous_id.clone(),
                    plan: "RECON".to_string(),
                    is_anonymous: true,
                }),
                requires_two_factor: false,
                challenge_token: None,
                code: None,
            })
        }
        Ok(crate::api::pow::Registered::Done(_)) => Ok(LoginResponse {
            success: false,
            message: Some("Could not create an anonymous account. Please try again.".to_string()),
            user: None,
            requires_two_factor: false,
            challenge_token: None,
            code: Some(IpcErrorCode::ServerError),
        }),
        Err(e) => {
            tracing::warn!("Anonymous account creation failed: {}", e);
            Ok(LoginResponse {
                success: false,
                message: Some(crate::utils::redact::sanitize_error(&e.to_string())),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
                code: Some(IpcError::from_api(&e).code),
            })
        }
    }
}

/// What a number-replacement step answers (MR-1707). A refusal the user can
/// act on is an `Ok` with `refusal` set, so the UI words each one; anything
/// else (offline, a server error) is an `Err(IpcError)` as everywhere.
/// `refusal`: `disabled`, `unauthorized`, `not_pending`, `account_changed`,
/// `mismatch`, `bad_number`, `rate_limited`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationStep {
    pub refusal: Option<&'static str>,
    /// `prepare` only: the NEW number, shown once. A credential: never
    /// logged, redacted in `Debug`, and not kept here after the answer.
    pub new_number: Option<String>,
    pub expires_in_seconds: Option<u64>,
    pub retry_after_secs: Option<u64>,
}

impl std::fmt::Debug for RotationStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationStep")
            .field("refusal", &self.refusal)
            .field(
                "new_number",
                &self.new_number.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for RotationStep {
    fn drop(&mut self) {
        self.new_number.zeroize();
    }
}

impl RotationStep {
    fn refused(refusal: &'static str) -> Self {
        Self {
            refusal: Some(refusal),
            new_number: None,
            expires_in_seconds: None,
            retry_after_secs: None,
        }
    }
}

/// The refusals of the two rotation calls the UI words itself, by what
/// the server said. `None`: not one of them, so it is a plain `IpcError`.
fn rotation_refusal(error: &ApiError, wrong_number_is_400: bool) -> Option<RotationStep> {
    match error {
        ApiError::AnonNumberRefused(code) => Some(RotationStep::refused(match code.as_str() {
            "rotation_not_pending" => "not_pending",
            "rotation_account_changed" => "account_changed",
            _ => "disabled",
        })),
        ApiError::Unauthorized | ApiError::Rejected { status: 401, .. } => {
            Some(RotationStep::refused("unauthorized"))
        }
        ApiError::RateLimited { retry_after_secs } => Some(RotationStep {
            refusal: Some("rate_limited"),
            new_number: None,
            expires_in_seconds: None,
            retry_after_secs: *retry_after_secs,
        }),
        ApiError::Rejected { status: 400, .. } if wrong_number_is_400 => {
            Some(RotationStep::refused("mismatch"))
        }
        ApiError::Rejected { status: 400, .. } => Some(RotationStep::refused("bad_number")),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatePrepareCommandRequest {
    pub current_number: String,
    pub password: Option<String>,
    pub two_factor_code: Option<String>,
}

impl Drop for RotatePrepareCommandRequest {
    fn drop(&mut self) {
        self.current_number.zeroize();
        self.password.zeroize();
        self.two_factor_code.zeroize();
    }
}

fn digits_only(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// MR-1707 step 1: prove the CURRENT number (and the password / 2FA code the
/// account has) and get a replacement held pending for ten minutes. Nothing
/// on the account changes; the old number keeps working until `confirm`.
/// The numbers are credentials: not logged, and nothing is stored here.
#[tauri::command]
pub async fn rotate_anonymous_number_prepare(
    request: RotatePrepareCommandRequest,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<RotationStep, IpcError> {
    let current = digits_only(&request.current_number);
    if current.len() != 24 {
        return Ok(RotationStep::refused("bad_number"));
    }
    if let Ok(tokens) = credentials.get_tokens() {
        api.restore_tokens_if_absent(tokens.access_token.clone(), tokens.refresh_token.clone())
            .await;
    }
    tracing::info!("Account number replacement: prepare requested");
    let non_empty = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let body = RotatePrepareBody {
        current_number: current,
        password: request.password.clone().filter(|p| !p.is_empty()),
        two_factor_code: non_empty(&request.two_factor_code),
    };
    match api.rotate_number_prepare(&body).await {
        Ok(response) => Ok(RotationStep {
            refusal: None,
            new_number: Some(response.new_number.clone()),
            expires_in_seconds: response.expires_in_seconds,
            retry_after_secs: None,
        }),
        Err(e) => {
            tracing::warn!("Account number replacement: prepare refused ({})", e);
            match rotation_refusal(&e, false) {
                Some(step) => Ok(step),
                None => Err(IpcError::from_api(&e)),
            }
        }
    }
}

/// MR-1707 step 2: the user re-typed the whole new number. On success the
/// old number is dead, every other session is signed out, and this one
/// continues on the fresh tokens, stored exactly as a sign-in stores them.
#[tauri::command]
pub async fn rotate_anonymous_number_confirm(
    new_number: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<RotationStep, IpcError> {
    let mut new_number = new_number;
    let digits = digits_only(&new_number);
    new_number.zeroize();
    if digits.len() != 24 {
        return Ok(RotationStep::refused("mismatch"));
    }
    if let Ok(tokens) = credentials.get_tokens() {
        api.restore_tokens_if_absent(tokens.access_token.clone(), tokens.refresh_token.clone())
            .await;
    }
    tracing::info!("Account number replacement: confirm requested");
    let body = RotateConfirmBody {
        new_number: digits,
        device_id: crate::utils::get_device_id(),
        device_name: Some(crate::commands::vpn::get_device_name()),
        platform: crate::utils::device_platform().to_string(),
    };
    match api.rotate_number_confirm(&body).await {
        Ok(response) if response.ok => {
            if let Some(ref tokens) = response.tokens {
                if let Err(e) =
                    credentials.store_tokens(&tokens.access_token, &tokens.refresh_token)
                {
                    tracing::warn!(
                        "Failed to persist the credentials after a replacement: {}",
                        e
                    );
                }
            }
            tracing::info!("Account number replaced; this session continues");
            Ok(RotationStep {
                refusal: None,
                new_number: None,
                expires_in_seconds: None,
                retry_after_secs: None,
            })
        }
        Ok(_) => Err(IpcError::from_api(&ApiError::Parse(
            "unexpected confirm answer".to_string(),
        ))),
        Err(e) => {
            tracing::warn!("Account number replacement: confirm refused ({})", e);
            match rotation_refusal(&e, true) {
                Some(step) => Ok(step),
                None => Err(IpcError::from_api(&e)),
            }
        }
    }
}

/// Login to an existing anonymous account with its 24-digit ID
#[tauri::command]
pub async fn login_anonymous(
    app: AppHandle,
    request: AnonymousLoginCommandRequest,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
    // MR-1861: a sign-in typed in by hand never resumes the session an
    // update ended — it belonged to whoever was signed in before.
    crate::commands::update_resume::discard();
    // Same client-side rate limit as email login (compromised-webview guard).
    {
        let mut guard = LOGIN_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = guard.get_or_insert_with(Vec::new);
        let now = Instant::now();
        attempts.retain(|t| now.duration_since(*t).as_secs() < LOGIN_WINDOW_SECS);
        if attempts.len() >= MAX_LOGIN_ATTEMPTS {
            return Ok(LoginResponse {
                success: false,
                message: Some("Too many login attempts. Please wait a minute.".to_string()),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
                code: Some(IpcErrorCode::RateLimited),
            });
        }
        attempts.push(now);
    }

    let anonymous_id: String = request
        .anonymous_id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if anonymous_id.len() != 24 {
        return Ok(LoginResponse {
            success: false,
            message: Some("Anonymous ID must be exactly 24 digits.".to_string()),
            user: None,
            requires_two_factor: false,
            challenge_token: None,
            code: Some(IpcErrorCode::InvalidCredentials),
        });
    }

    // Device ID gives the backend trusted-device 2FA context (never identity).
    // The number is the account's only credential, so no part of it is logged
    // (Account API contract item 86); the last four used to be.
    let device_id = crate::utils::get_device_id();
    tracing::info!("Anonymous login attempt");

    // A-M77 / MR-2139: the spike-time proof of work, as in `login`.
    let (cancel, on_progress) = begin_proof(&app);
    let outcome = api
        .login_anonymous(
            &anonymous_id,
            request.password.clone(),
            &device_id,
            cancel,
            on_progress,
        )
        .await;
    end_proof();
    match outcome {
        Ok(crate::api::pow::Registered::Cancelled) => Ok(cancelled_response()),
        Ok(crate::api::pow::Registered::Done(result)) => {
            if result.requires_two_factor {
                tracing::info!("Anonymous login requires 2FA");
                return Ok(LoginResponse {
                    success: false,
                    message: None,
                    user: None,
                    requires_two_factor: true,
                    challenge_token: result.challenge_token,
                    code: Some(IpcErrorCode::TwoFactorRequired),
                });
            }
            if result.ok {
                if let Some(ref tokens) = result.tokens {
                    if let Err(e) =
                        credentials.store_tokens(&tokens.access_token, &tokens.refresh_token)
                    {
                        tracing::warn!("Failed to persist anonymous credentials: {}", e);
                    }
                }

                let user_info = UserInfo {
                    email: None,
                    account_id: result.anonymous_id.clone(),
                    plan: "RECON".to_string(),
                    is_anonymous: true,
                };

                tracing::info!("Anonymous login successful");
                Ok(LoginResponse {
                    success: true,
                    message: None,
                    user: Some(user_info),
                    requires_two_factor: false,
                    challenge_token: None,
                    code: None,
                })
            } else {
                Ok(LoginResponse {
                    success: false,
                    message: Some("Anonymous login failed".to_string()),
                    user: None,
                    requires_two_factor: false,
                    challenge_token: None,
                    code: Some(IpcErrorCode::InvalidCredentials),
                })
            }
        }
        Err(e) => {
            tracing::warn!("Anonymous login failed: {}", e);
            Ok(LoginResponse {
                success: false,
                message: Some(crate::utils::redact::sanitize_error(&e.to_string())),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
                code: Some(sign_in_failure_code(&e)),
            })
        }
    }
}

/// Source pins for the account-boundary ordering in `logout` and
/// `delete_account`. Tauri commands take `State`, which a unit test cannot
/// build, so these read this file the way `ipv6_binding_tests` reads
/// `src/vpn`.
#[cfg(test)]
mod account_boundary_tests {
    const SOURCE: &str = include_str!("auth.rs");

    /// The body of `pub async fn <name>(`, up to its closing brace at column 0.
    fn body(name: &str) -> &'static str {
        let start = SOURCE
            .find(&format!("pub async fn {name}("))
            .unwrap_or_else(|| panic!("fn {name} not found"));
        let rest = &SOURCE[start..];
        let end = rest.find("\n}").expect("closing brace at column 0");
        &rest[..end]
    }

    /// The body of the fn whose signature starts `signature`.
    fn body_of(signature: &str) -> &'static str {
        let start = SOURCE
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} not found"));
        let rest = &SOURCE[start..];
        &rest[..rest.find("\n}").expect("closing brace at column 0")]
    }

    #[test]
    fn sign_out_does_not_rotate_the_device_id() {
        // Second-pass #14: same policy as iOS and Android (deletion only).
        let needle = ["device_id", "::rotate()"].concat();
        assert!(!body("logout").contains(&needle));
        assert!(body("delete_account").contains(&needle));
    }

    /// Second-pass #15: a refused deletion (wrong password, offline) must
    /// leave the tunnel up; a confirmed one takes it down before the local
    /// state is cleared. (W1-009 moved the teardown to `end_session`, the one
    /// Rust teardown every sign-out path shares.)
    ///
    /// REVIEW-WIN2-007: the request itself goes around a live tunnel, so the
    /// confirmation can arrive at all (the client half is tested in
    /// `api::client`).
    #[test]
    fn deletion_disconnects_only_after_the_server_confirmed() {
        let del = body("delete_account");
        let around = del
            .find("let around_the_tunnel = around_the_tunnel(&app).await;")
            .expect("the path around the tunnel");
        let confirmed = del.find(".delete_account(").expect("the server call");
        assert!(around < confirmed);
        let path = body_of("async fn around_the_tunnel(");
        assert!(
            path.contains(".holds_tunnel()"),
            "only while a tunnel is up"
        );
        assert!(path.contains("network_events::physical_source_address()"));
        let disconnect = del
            .find("end_session(&app, EndReason::AccountDeleted)")
            .expect("the disconnect after the 2xx");
        let cleared = del
            .find("credentials.clear_tokens()")
            .expect("local state cleared");
        assert!(
            confirmed < disconnect,
            "disconnect runs before the server confirmed"
        );
        assert!(
            disconnect < cleared,
            "local state is cleared before the disconnect"
        );
    }

    /// W1-009 / contract §3.2: logout ends the VPN session in Rust BEFORE the
    /// credentials are cleared.
    #[test]
    fn logout_ends_the_session_before_clearing_credentials() {
        let out = body("logout");
        let ended = out
            .find("end_session(&app, EndReason::SignOut)")
            .expect("logout ends the session");
        let cleared = out
            .find("credentials.clear_tokens()")
            .expect("credentials cleared");
        assert!(
            ended < cleared,
            "credentials cleared before the session ended"
        );
    }

    /// REVIEW-WIN-007: both account boundaries forget the account's server,
    /// after the session is over.
    #[test]
    fn account_boundaries_forget_the_accounts_server() {
        for (name, ended) in [
            ("logout", "end_session(&app, EndReason::SignOut)"),
            (
                "delete_account",
                "end_session(&app, EndReason::AccountDeleted)",
            ),
        ] {
            let b = body(name);
            let end = b.find(ended).expect("the session ends");
            let forget = b
                .find("settings::clear_account_choices(&app)")
                .unwrap_or_else(|| panic!("{name} keeps the account's server"));
            assert!(end < forget, "{name}");
        }
    }

    /// MR-2370: a 2xx whose body does not confirm the deletion reaches the
    /// dialog as `server_error`, which it words "Something went wrong on our
    /// side. Please try again in a moment." and stays open for the retry
    /// (DeleteAccountDialog's DELETION_CODES); never `session_expired`, which
    /// would send the user to sign in. `delete_account` returns it before
    /// anything local is touched (see
    /// `deletion_disconnects_only_after_the_server_confirmed`).
    #[test]
    fn an_unreadable_deletion_answer_reaches_the_dialog_as_a_retry() {
        use crate::api::client::{BirdoApi, GdprDeleteOutcome};
        use reqwest::StatusCode;
        for body in ["", "<html></html>", "{}", r#"{"success":false}"#] {
            let outcome = BirdoApi::classify_gdpr_delete_response(StatusCode::OK, body);
            let error = match outcome {
                GdprDeleteOutcome::Refused(error) => error,
                other => panic!("{body:?} was read as {other:?}"),
            };
            let shown = super::delete_failure_message(&error);
            assert_eq!(shown.code, super::IpcErrorCode::ServerError, "{body:?}");
            assert!(shown.retryable, "{body:?}");
            assert_eq!(shown.retry_after_secs, None);
        }
    }

    /// MR-2483 review L1: after an unreadable 2xx, a 404 that is not the
    /// API's own (an HTML page, an empty body, another responder's JSON) is no
    /// deletion. `delete_account` returns it as an error before anything local
    /// is touched (never `Ok` with `alreadyDeleted`, so the dialog never says
    /// "deleted"), and the dialog offers to retry it (`server_unavailable`,
    /// "Couldn't delete your account. Please try again.").
    #[test]
    fn a_404_that_is_not_the_apis_after_an_unreadable_2xx_reaches_the_dialog_as_a_retry() {
        use crate::api::client::{BirdoApi, GdprDeleteOutcome};
        use reqwest::StatusCode;
        for body in [
            "",
            "<html><body><h1>404 Not Found</h1></body></html>",
            "{}",
            r#"{"message":"Not Found"}"#,
        ] {
            let outcome = BirdoApi::after_unconfirmed(
                true,
                BirdoApi::classify_gdpr_delete_response(StatusCode::NOT_FOUND, body),
            );
            let GdprDeleteOutcome::Refused(error) = outcome else {
                panic!("{body:?} was not read as a refusal");
            };
            let shown = super::delete_failure_message(&error);
            assert_eq!(
                shown.code,
                super::IpcErrorCode::ServerUnavailable,
                "{body:?}"
            );
            assert!(shown.retryable, "{body:?}");
        }
    }

    /// MR-2483: a retry that found the account already deleted reaches the
    /// dialog as a deletion (`Ok`), flagged `alreadyDeleted`, with no store
    /// list (it rode on the answer that was lost). `delete_account` clears
    /// everything local for it exactly as for a confirmed deletion: one path
    /// after the server call (`deletion_disconnects_only_after_the_server_confirmed`).
    #[test]
    fn a_deletion_found_already_done_tells_the_dialog_so() {
        use crate::api::client::AccountDeletion;
        use crate::api::types::DeleteAccountResponse;
        let gone = super::deletion_result(&AccountDeletion::AlreadyDeleted);
        assert!(gone.already_deleted);
        assert!(gone.store_subscriptions_still_billing.is_empty());
        assert_eq!(
            serde_json::to_value(&gone).unwrap(),
            serde_json::json!({ "storeSubscriptionsStillBilling": [], "alreadyDeleted": true })
        );

        let confirmed = DeleteAccountResponse::confirmation(
            r#"{"success":true,"storeSubscriptionsStillBilling":["GOOGLE_PLAY"]}"#,
        )
        .expect("a confirmation");
        let deleted = super::deletion_result(&AccountDeletion::Deleted(confirmed));
        assert!(!deleted.already_deleted);
        assert_eq!(
            deleted.store_subscriptions_still_billing,
            vec!["Google Play"]
        );
        assert_eq!(
            serde_json::to_value(&deleted).unwrap()["alreadyDeleted"],
            serde_json::json!(false)
        );

        // Both endings run the same local clean-up: nothing between the
        // server call and the session's end tells them apart.
        let del = body("delete_account");
        let confirmed = del.find(".delete_account(").unwrap();
        let ended = del
            .find("end_session(&app, EndReason::AccountDeleted)")
            .unwrap();
        assert!(!del[confirmed..ended].contains("AlreadyDeleted"));
        assert!(!del[confirmed..ended].contains("already_deleted"));
    }

    #[test]
    fn a_wrong_password_on_deletion_is_invalid_credentials() {
        let wrong = super::delete_failure_message(&super::ApiError::Rejected {
            status: 401,
            message: "Incorrect password".into(),
        });
        assert_eq!(wrong.code, super::IpcErrorCode::InvalidCredentials);
        assert!(wrong.message.contains("Incorrect password"));
        assert_eq!(
            super::delete_failure_message(&super::ApiError::Unauthorized).code,
            super::IpcErrorCode::SessionExpired
        );
    }

    /// Sign-in refusals carry a contract code: a 401 from a sign-in endpoint
    /// is wrong credentials (never "session expired"), and a 2FA refusal is
    /// `two_factor_invalid`.
    #[test]
    fn sign_in_refusals_carry_their_codes() {
        use super::{sign_in_failure_code, two_factor_failure_code, ApiError, IpcErrorCode};
        assert_eq!(
            sign_in_failure_code(&ApiError::Unauthorized),
            IpcErrorCode::InvalidCredentials
        );
        assert_eq!(
            sign_in_failure_code(&ApiError::Rejected {
                status: 401,
                message: "Invalid credentials".into()
            }),
            IpcErrorCode::InvalidCredentials
        );
        assert_eq!(
            sign_in_failure_code(&ApiError::RateLimited {
                retry_after_secs: Some(60)
            }),
            IpcErrorCode::RateLimited
        );
        assert_eq!(
            sign_in_failure_code(&ApiError::Network("x".into())),
            IpcErrorCode::NetworkOffline
        );
        assert_eq!(
            two_factor_failure_code(&ApiError::Rejected {
                status: 400,
                message: "Invalid code".into()
            }),
            IpcErrorCode::TwoFactorInvalid
        );
        assert_eq!(
            two_factor_failure_code(&ApiError::ServerError(502)),
            IpcErrorCode::ServerError
        );
    }

    /// Account API contract item 85: a 2FA refusal reaches the dialog as its
    /// own code, so it can ask for the code or say it was wrong; a rate limit
    /// is a rate limit. Old servers' refusals map as before.
    #[test]
    fn two_factor_refusals_on_deletion_keep_their_codes() {
        use super::{delete_failure_message, ApiError, IpcErrorCode};
        assert_eq!(
            delete_failure_message(&ApiError::TwoFactorRequired("Enter your code".into())).code,
            IpcErrorCode::TwoFactorRequired
        );
        assert_eq!(
            delete_failure_message(&ApiError::TwoFactorInvalid("Wrong".into())).code,
            IpcErrorCode::TwoFactorInvalid
        );
        assert_eq!(
            delete_failure_message(&ApiError::Rejected {
                status: 429,
                message: "Too many attempts".into()
            })
            .code,
            IpcErrorCode::RateLimited
        );
        assert_eq!(
            delete_failure_message(&ApiError::RateLimited {
                retry_after_secs: None
            })
            .code,
            IpcErrorCode::RateLimited
        );
        // MR-1808: the server's wait reaches the dialog.
        let limited = delete_failure_message(&ApiError::RateLimited {
            retry_after_secs: Some(30),
        });
        assert_eq!(limited.code, IpcErrorCode::RateLimited);
        assert_eq!(limited.retry_after_secs, Some(30));
    }

    /// The UI sends `two_factor_code` only on the retry; today's dialog sends
    /// no such key and must still parse.
    #[test]
    fn the_delete_request_takes_an_optional_two_factor_code() {
        let first: super::DeleteAccountRequest =
            serde_json::from_value(serde_json::json!({ "password": "pw" })).unwrap();
        assert_eq!(first.two_factor_code, None);
        let retry: super::DeleteAccountRequest = serde_json::from_value(
            serde_json::json!({ "password": "pw", "two_factor_code": "123456" }),
        )
        .unwrap();
        assert_eq!(retry.two_factor_code.as_deref(), Some("123456"));
    }

    /// Item 86 on an old server (no new fields) and a new one; the account
    /// number never appears in a `{:?}`.
    #[test]
    fn the_auth_state_reads_old_and_new_auth_me() {
        use crate::api::types::UserProfile;
        let old: UserProfile = serde_json::from_value(serde_json::json!({
            "id": "u1", "email": "anon_123456789012345678901234@anonymous.local"
        }))
        .unwrap();
        // Phase 1's email IS the number: no `{:?}` may print it
        // (REVIEW-WIN2-027).
        assert!(!format!("{old:?}").contains("123456789012345678901234"));
        let state = super::AuthState::of(old);
        assert_eq!(state.is_anonymous, None, "an old server says nothing");
        assert!(state.account_number.is_none());
        assert!(!format!("{state:?}").contains("123456789012345678901234"));
        assert_eq!(
            serde_json::to_value(&state).unwrap()["email"],
            "anon_123456789012345678901234@anonymous.local",
            "passed through as sent; the UI never parses it (MR-918)"
        );

        // Phase 2 of the contract: the email no longer carries the number.
        let new: UserProfile = serde_json::from_value(serde_json::json!({
            "id": "u2",
            "email": "account-u2@anonymous.local",
            "accountType": "anonymous",
            "isAnonymous": true,
            "accountNumber": "123456789012345678901234"
        }))
        .unwrap();
        let state = super::AuthState::of(new);
        assert_eq!(state.is_anonymous, Some(true));
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["account_number"], "123456789012345678901234");
        assert_eq!(json["is_anonymous"], true);
        assert!(
            !format!("{state:?}").contains("123456789012345678901234"),
            "the account number reached a Debug string"
        );

        // A server that no longer returns the number (`accountNumber: null`,
        // the email carrying none): still anonymous, and no number at all
        // rather than an empty or made-up one.
        let unnumbered: UserProfile = serde_json::from_value(serde_json::json!({
            "id": "u3",
            "email": "member@anonymous.local",
            "accountType": "anonymous",
            "isAnonymous": true,
            "accountNumber": null
        }))
        .unwrap();
        let state = super::AuthState::of(unnumbered);
        assert_eq!(state.is_anonymous, Some(true));
        assert!(state.account_number.is_none());
        assert_eq!(
            serde_json::to_value(&state).unwrap()["account_number"],
            serde_json::Value::Null
        );
    }

    /// REVIEW-WIN2-009: phase 2 of the contract really sends `email: null`
    /// for an anonymous account (the test above only changed its shape). The
    /// whole profile must still parse — the identity, the number and
    /// `hasPassword` with it — and a missing email reads the same.
    #[test]
    fn phase_two_email_null_still_reads_the_identity() {
        use crate::api::types::UserProfile;
        for body in [
            serde_json::json!({
                "id": "u4",
                "email": null,
                "accountType": "anonymous",
                "isAnonymous": true,
                "accountNumber": "123456789012345678901234",
                "hasPassword": false
            }),
            serde_json::json!({
                "id": "u4",
                "isAnonymous": true,
                "accountNumber": "123456789012345678901234",
                "hasPassword": false
            }),
        ] {
            let profile: UserProfile =
                serde_json::from_value(body).expect("email: null must not fail the parse");
            let state = super::AuthState::of(profile);
            assert!(state.is_authenticated);
            assert_eq!(state.email, None);
            assert_eq!(state.account_id.as_deref(), Some("u4"));
            assert_eq!(state.is_anonymous, Some(true));
            assert!(state.account_number.is_some());
            assert!(
                !state.has_password,
                "an anonymous account is not asked for a password"
            );
            assert_eq!(
                serde_json::to_value(&state).unwrap()["email"],
                serde_json::Value::Null
            );
        }
    }

    /// Item 86: "never log it". No part of the number reaches a log line on
    /// the anonymous sign-in path (it used to log the last four digits).
    #[test]
    fn the_anonymous_sign_in_logs_no_part_of_the_number() {
        let login = body("login_anonymous");
        for line in login.lines().filter(|l| l.contains("tracing::")) {
            assert!(!line.contains("anonymous_id"), "{line}");
        }
        assert!(!login.contains("&anonymous_id[20..]"));
    }

    /// Second-pass #9: the preflight the dialog shows before confirming.
    #[test]
    fn preflight_names_the_stores_and_defaults_to_nothing() {
        let named =
            super::deletion_preflight_result(&crate::api::types::DeletionPreflightResponse {
                store_subscriptions_still_billing: Some(serde_json::json!([
                    { "store": "GOOGLE_PLAY", "productId": "birdo_operative", "expiresAt": null }
                ])),
                web_subscription_will_be_cancelled: Some(true),
                step_up: Some(crate::api::types::DeletionStepUp {
                    factors: vec!["account_number".into()],
                    enforced: false,
                    hold_available: Some(serde_json::json!(true)),
                }),
            });
        assert_eq!(named.store_subscriptions_still_billing, vec!["Google Play"]);
        assert!(named.web_subscription_will_be_cancelled);
        assert_eq!(named.step_up_factors, vec!["account_number"]);
        assert!(!named.step_up_enforced);
        // MR-2335: independent of `enforced`.
        assert!(named.step_up_hold_available);

        let nothing = super::deletion_preflight_result(&Default::default());
        assert!(nothing.store_subscriptions_still_billing.is_empty());
        assert!(!nothing.web_subscription_will_be_cancelled);
        assert!(nothing.step_up_factors.is_empty());
        assert!(!nothing.step_up_enforced);
        assert!(!nothing.step_up_hold_available);
    }

    /// MR-2335: only a JSON `true` offers the hold; a string, a number, null
    /// or no key at all do not, and none of them fails the preflight.
    #[test]
    fn the_hold_is_offered_only_for_hold_available_true() {
        for (raw, want) in [
            (
                r#"{"factors":["account_number"],"enforced":true,"holdAvailable":true}"#,
                true,
            ),
            (
                r#"{"factors":["account_number"],"enforced":false,"holdAvailable":true}"#,
                true,
            ),
            (
                r#"{"factors":["account_number"],"enforced":true,"holdAvailable":false}"#,
                false,
            ),
            (
                r#"{"factors":["account_number"],"enforced":true,"holdAvailable":"true"}"#,
                false,
            ),
            (
                r#"{"factors":["account_number"],"enforced":true,"holdAvailable":1}"#,
                false,
            ),
            (
                r#"{"factors":["account_number"],"enforced":true,"holdAvailable":null}"#,
                false,
            ),
            (r#"{"factors":["account_number"],"enforced":true}"#, false),
        ] {
            let preflight: crate::api::types::DeletionPreflightResponse =
                serde_json::from_str(&format!(r#"{{"success":true,"stepUp":{raw}}}"#))
                    .unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(
                super::deletion_preflight_result(&preflight).step_up_hold_available,
                want,
                "{raw}"
            );
        }
    }

    /// MR-2335: a hold is NOT a deletion. Its command touches nothing local on
    /// any answer: no session end, no token wipe, no device-id rotation, no
    /// settings reset, no PQ purge. (`delete_account` does all of these, after
    /// a 2xx.)
    #[test]
    fn a_deletion_hold_never_signs_out_or_tears_down() {
        let hold = body("request_deletion_hold");
        for forbidden in [
            "end_session",
            "clear_tokens",
            "clear_account_choices",
            "device_id::rotate",
            "purge_legacy_keypair_files",
            "record_disabled",
            "logout",
            "around_the_tunnel",
        ] {
            assert!(
                !hold.contains(forbidden),
                "request_deletion_hold: {forbidden}"
            );
        }
        let del = body("delete_account");
        assert!(del.contains("end_session(&app, EndReason::AccountDeleted)"));
        assert!(del.contains("credentials.clear_tokens()"));
        // Neither the listing nor the cancel touches local state either.
        for name in ["list_pending_changes", "cancel_pending_change"] {
            let b = body(name);
            assert!(
                !b.contains("end_session") && !b.contains("clear_tokens"),
                "{name}"
            );
        }
    }

    /// MR-2335: the hold's request carries the password and the 2FA code, so it
    /// is wiped on drop and never printable.
    #[test]
    fn the_hold_request_is_wiped_and_not_debug() {
        let source = include_str!("auth.rs");
        let at = source
            .find("pub struct DeletionHoldRequest")
            .expect("DeletionHoldRequest");
        let derive = &source[source[..at].rfind("#[derive(").unwrap()..at];
        assert_eq!(derive.trim_end(), "#[derive(Deserialize)]");
        assert!(source.contains("impl Drop for DeletionHoldRequest"));
    }

    /// MR-2335: a 409 `change_already_pending` the body did not name is read
    /// from the pending-change list; a list without a held deletion is not
    /// mistaken for one.
    #[test]
    fn an_unnamed_existing_hold_is_found_in_the_pending_list() {
        use crate::api::types::PendingChange;
        let row = |id: &str, action: &str, at: Option<&str>| PendingChange {
            id: id.into(),
            action: action.into(),
            description: None,
            apply_after: at.map(str::to_string),
            created_at: None,
            detail: None,
        };
        let rows = [
            row("pc_pw", "password_set", Some("2026-11-15T09:00:00.000Z")),
            row("pc_del", "account_delete", Some("2026-11-15T10:00:00.000Z")),
        ];
        let hold = super::held_deletion_in(&rows, "A deletion is already on hold.").unwrap();
        assert_eq!(hold.pending_change_id, "pc_del");
        assert_eq!(hold.apply_after, "2026-11-15T10:00:00.000Z");
        assert!(hold.already_pending);
        assert_eq!(
            hold.message.as_deref(),
            Some("A deletion is already on hold.")
        );
        assert!(super::held_deletion_in(&rows[..1], "").is_none());
        assert!(super::held_deletion_in(&[row("pc_x", "account_delete", None)], "").is_none());
    }

    /// MR-2335: a refused hold reaches the dialog by code, with the server's
    /// sentence where it is the explanation, and never reads "Account deletion
    /// failed".
    #[test]
    fn a_refused_hold_keeps_its_code_and_sentence() {
        use crate::api::error::{ApiError, StepUpKind};
        use crate::commands::ipc_error::IpcErrorCode;
        let unavailable = super::hold_failure(&ApiError::StepUp {
            kind: StepUpKind::HoldUnavailable,
            message: "A delayed deletion is not available. Nothing was deleted.".into(),
        });
        assert_eq!(unavailable.code, IpcErrorCode::HoldUnavailable);
        assert_eq!(
            unavailable.message,
            "A delayed deletion is not available. Nothing was deleted."
        );
        let capped = super::hold_failure(&ApiError::Rejected {
            status: 429,
            message: "You have asked for a delayed deletion too many times today. Please try again tomorrow.".into(),
        });
        assert_eq!(capped.code, IpcErrorCode::RateLimited);
        assert!(capped.message.contains("tomorrow"), "{}", capped.message);
        let wrong = super::hold_failure(&ApiError::Rejected {
            status: 401,
            message: "Incorrect password".into(),
        });
        assert_eq!(wrong.code, IpcErrorCode::InvalidCredentials);
        assert_eq!(
            super::hold_failure(&ApiError::Unauthorized).code,
            IpcErrorCode::SessionExpired
        );
        let busy = super::hold_failure(&ApiError::StepUp {
            kind: StepUpKind::Unavailable,
            message: "We could not check your code just now.".into(),
        });
        assert_eq!(busy.code, IpcErrorCode::StepUpUnavailable);
        assert!(busy.retryable);
        // An unexpected 2xx / unreadable 202: an error that assumes nothing.
        let odd = super::hold_failure(&ApiError::Parse("x".into()));
        assert_eq!(odd.code, IpcErrorCode::ServerError);
        assert!(
            odd.message.contains("Nothing is assumed deleted"),
            "{}",
            odd.message
        );
        for e in [unavailable, capped, wrong, busy] {
            assert!(
                !e.message.starts_with("Account deletion failed"),
                "{}",
                e.message
            );
        }
    }

    /// MR-2550 (review P469-L1): `get_auth_state` runs no refresh of its own.
    /// `get_profile`'s 401 already ran THE refresh (`request_with_retry`:
    /// detached, adopt-checked, after the "token changed while waiting"
    /// check), so a second flight could only present a dead token again or
    /// rotate a renewed pair for nothing. MR-2538's rule stands: nothing here
    /// writes the keystore. On main it ran `api.refresh_session()` after
    /// every failure but a 429/503.
    #[test]
    fn the_startup_check_runs_no_refresh_of_its_own() {
        let state = body("get_auth_state");
        for refresh in [
            "refresh_session",
            "refresh_detached",
            ".refresh_token()",
            // Split, or this file would read as one that calls it (the
            // "called on a timer" pin in api::client).
            concat!("retry_held", "_refresh"),
        ] {
            assert!(!state.contains(refresh), "{refresh}");
        }
        assert!(!state.contains("store_tokens("), "stored outside the lock");
        assert!(
            !state.contains("credentials.clear_tokens()"),
            "the gate's to clear, for the session it ended"
        );
        let before = state
            .find("let before = api.access_token_value().await;")
            .expect("the session it starts with");
        let fetched = state.find("api.get_profile().await").expect("the fetch");
        assert!(before < fetched);
        assert!(state.contains("after_profile_failure(&e, renewed)"));
        assert_eq!(
            state.matches("api.get_profile()").count(),
            1,
            "a second fetch"
        );
    }

    /// MR-2550: what the start-up check answers, from `get_profile`'s error
    /// alone. Only a 401 the refresh could not answer signs out; a 401 after
    /// a renewal, no answer, a 5xx, a held or rate-limited request, a pin
    /// failure or an unreadable body keeps the session; a session already
    /// gone is answered as memory holds it.
    #[test]
    fn the_startup_check_decides_from_the_profile_answer() {
        use super::{after_profile_failure, ProfileFailure};
        use crate::api::error::ApiError;
        assert_eq!(
            after_profile_failure(&ApiError::Unauthorized, false),
            ProfileFailure::SignedOut
        );
        assert_eq!(
            after_profile_failure(&ApiError::Unauthorized, true),
            ProfileFailure::KeepSession,
            "renewed during the call"
        );
        for renewed in [false, true] {
            assert_eq!(
                after_profile_failure(&ApiError::NotAuthenticated, renewed),
                ProfileFailure::AsMemoryHolds
            );
        }
        for kept in [
            ApiError::Network("offline".into()),
            ApiError::RateLimited {
                retry_after_secs: Some(30),
            },
            ApiError::ServerBusy {
                status: 503,
                retry_after_secs: 1,
            },
            ApiError::Held {
                status: 503,
                retry_after_secs: 1,
            },
            ApiError::ServerError(502),
            ApiError::Forbidden,
            ApiError::CertificatePinningFailed("x".into()),
            ApiError::Parse("eof".into()),
        ] {
            assert_eq!(
                after_profile_failure(&kept, false),
                ProfileFailure::KeepSession
            );
        }
    }

    /// MR-179: the proof rides the deletion call (number as digits, code
    /// trimmed), is wiped on drop, and a step-up refusal reaches the dialog by
    /// code, not as "Account deletion failed: ...".
    #[test]
    fn deletion_forwards_the_step_up_proof_and_keeps_refusal_codes() {
        let del = body("delete_account");
        assert!(
            del.contains("request\n        .account_number") || del.contains(".account_number")
        );
        assert!(del.contains("account_number.as_ref()"));
        assert!(del.contains("email_code,"));
        let request_drop = include_str!("auth.rs");
        assert!(request_drop.contains("number.zeroize()"));

        use crate::api::error::StepUpKind;
        for (kind, code) in [
            (
                StepUpKind::AccountNumberRequired,
                crate::commands::ipc_error::IpcErrorCode::AccountNumberRequired,
            ),
            (
                StepUpKind::AccountNumberInvalid,
                crate::commands::ipc_error::IpcErrorCode::AccountNumberInvalid,
            ),
            (
                StepUpKind::EmailCodeRequired,
                crate::commands::ipc_error::IpcErrorCode::EmailCodeRequired,
            ),
            (
                StepUpKind::EmailCodeInvalid,
                crate::commands::ipc_error::IpcErrorCode::EmailCodeInvalid,
            ),
        ] {
            let err = super::delete_failure_message(&crate::api::error::ApiError::StepUp {
                kind,
                message: "Enter your 24-digit account number to delete your account.".into(),
            });
            assert_eq!(err.code, code);
            assert!(
                !err.message.starts_with("Account deletion failed"),
                "{}",
                err.message
            );
        }
    }
}
