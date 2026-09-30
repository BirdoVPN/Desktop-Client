//! Authentication commands
//!
//! Handles login, logout, token refresh, and auth state management.

use crate::api::error::ApiError;
use crate::api::types::LoginResult;
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::commands::session::{end_session, EndReason};
use crate::storage::CredentialStore;
use crate::utils::redact_email;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthState {
    pub is_authenticated: bool,
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub plan: Option<String>,
    /// Mirrors `UserProfile::has_password` so the UI can avoid demanding a
    /// password from SSO accounts, which have none. `true` whenever the profile
    /// is unknown, so an unresolved identity never silently drops the prompt.
    pub has_password: bool,
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
    request: LoginRequest,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
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

    match api.login(&request.email, &request.password).await {
        Ok(result) => match result {
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

    // Try to logout on server (best effort)
    let _ = api.logout().await;

    // Clear local credentials
    credentials.clear_tokens().map_err(|e| {
        IpcError::unknown(format!(
            "Failed to clear credentials: {}",
            crate::utils::redact::sanitize_error(&e.to_string())
        ))
    })?;

    // Logout hygiene (documented contract of the persistent ML-KEM identity):
    // the keypair is a globally-unique, machine-stable linkage primitive, so it
    // must not survive an account boundary. Best-effort — a delete failure must
    // not block the logout itself. Deliberately NOT called on the
    // rejected-refresh auto-sign-out path (get_auth_state): that is a session
    // expiry on the same account, not the user leaving it.
    if let Err(e) = crate::vpn::birdo_pq::reset_persisted_keypair() {
        tracing::warn!("Failed to reset BirdoPQ keypair on logout: {}", e);
    }

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
#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

impl Drop for DeleteAccountRequest {
    fn drop(&mut self) {
        self.password.zeroize();
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
}

/// The error a refused deletion shows. The backend's own words when it gave
/// any (the password check's "Incorrect password", which classifies as
/// `invalid_credentials`), not the variant's generic "Unknown error: …"
/// framing.
fn delete_failure_message(error: &ApiError) -> IpcError {
    let (code, reason) = match error {
        ApiError::Rejected { message, .. } | ApiError::Unknown(message) => {
            (IpcError::from_api(error).code, message.clone())
        }
        ApiError::Unauthorized | ApiError::NotAuthenticated => (
            IpcErrorCode::SessionExpired,
            "Your session has expired. Sign in again, then retry.".to_string(),
        ),
        other => (IpcError::from_api(other).code, other.to_string()),
    };
    IpcError::new(code, format!("Account deletion failed: {}", reason))
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
    let response = api
        .delete_account(&request.password)
        .await
        .map_err(|e| delete_failure_message(&e))?;

    // The server has confirmed (2xx). Only NOW take the tunnel down, before
    // the local state is cleared (second-pass #15). This used to happen in
    // the dialog before the request, so a wrong password or an offline delete
    // left the user disconnected from an account that still existed. The
    // account's keys are gone server-side, so the tunnel could not carry
    // traffic anyway; ending the session also stops auto-reconnect and
    // disarms the kill switch, so nothing is left blocking. It skips the
    // backend disconnect call: the account is gone, and a 401 from it would
    // read as an expired session.
    end_session(&app, EndReason::AccountDeleted).await;

    // Clear all local credentials after successful server-side deletion,
    // including the persistent ML-KEM identity (same hygiene as logout —
    // doubly so for a GDPR deletion) and the device identifier (C-8).
    let _ = credentials.clear_tokens();
    if let Err(e) = crate::vpn::birdo_pq::reset_persisted_keypair() {
        tracing::warn!("Failed to reset BirdoPQ keypair on account deletion: {}", e);
    }
    crate::utils::device_id::rotate();

    let store_subscriptions_still_billing = response
        .store_subscriptions_still_billing
        .as_ref()
        .map(crate::api::types::store_subscription_labels)
        .unwrap_or_default();

    tracing::info!("Account permanently deleted");
    Ok(DeleteAccountResult {
        store_subscriptions_still_billing,
    })
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
    }
}

/// GDPR: Export all user data (Right to Data Portability, Art. 20).
/// Returns a JSON blob the frontend can save to disk.
#[tauri::command]
pub async fn export_user_data(api: State<'_, BirdoApi>) -> Result<serde_json::Value, IpcError> {
    tracing::info!("GDPR data export requested");
    api.export_user_data().await.map_err(IpcError::from)
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

            // Try to get user profile to validate token
            match api.get_profile().await {
                Ok(profile) => Ok(AuthState {
                    is_authenticated: true,
                    email: Some(profile.email),
                    account_id: Some(profile.id),
                    plan: None,
                    has_password: profile.has_password,
                }),
                // Rate limited — the token is FINE, the server is just asking us
                // to slow down. Refreshing here would spend another request on
                // the same exhausted budget (and `/auth/refresh` is itself in the
                // strict bucket), so a 429 would amplify into two. Keep the
                // session and report the identity as unknown for this cycle; the
                // next poll succeeds once the window rolls over.
                Err(crate::api::error::ApiError::RateLimited) => {
                    tracing::warn!(
                        "Profile fetch rate limited (429) — NOT refreshing; session kept, \
                         identity unknown this cycle"
                    );
                    Ok(AuthState {
                        is_authenticated: true,
                        email: None,
                        account_id: None,
                        plan: None,
                        has_password: true,
                    })
                }
                Err(e) => {
                    tracing::info!("Profile fetch failed ({e}) — attempting token refresh");
                    // Token might be expired, try refresh
                    match api.refresh_token().await {
                        Ok(new_tokens) => {
                            // Use rotated refresh token if server returned one, else keep existing
                            let refresh_to_store = new_tokens
                                .refresh_token
                                .as_deref()
                                .unwrap_or(&tokens.refresh_token);
                            if let Err(e) =
                                credentials.store_tokens(&new_tokens.access_token, refresh_to_store)
                            {
                                // Not fatal for THIS call (the in-memory tokens still
                                // work), but it means the session dies at the next
                                // launch — so say so instead of discarding it.
                                tracing::error!(
                                    "Refreshed tokens could not be persisted to the OS keystore \
                                     ({e}) — this session will not survive a restart"
                                );
                            }
                            // Re-fetch the profile with the refreshed access token so the
                            // identity is populated. Previously this returned email:None,
                            // so any auth check that hit the refresh path (e.g. app restart
                            // once the access token had expired) made the app show
                            // "Anonymous" for a real signed-in account.
                            match api.get_profile().await {
                                Ok(profile) => Ok(AuthState {
                                    is_authenticated: true,
                                    email: Some(profile.email),
                                    account_id: Some(profile.id),
                                    plan: None,
                                    has_password: profile.has_password,
                                }),
                                // The refresh succeeded, so the session IS valid — do
                                // not sign the user out over what is almost always a
                                // transient network error. The identity is reported as
                                // unknown (not as "no account"); the UI must render
                                // that as a pending state rather than inventing one.
                                Err(e) => {
                                    tracing::warn!(
                                        "Profile fetch failed after a successful token refresh \
                                         ({e}) — session kept, identity unknown this cycle"
                                    );
                                    Ok(AuthState {
                                        is_authenticated: true,
                                        email: None,
                                        account_id: None,
                                        plan: None,
                                        // Unknown → assume a password exists, so the
                                        // delete dialog keeps asking for it. Never drop
                                        // a confirmation because a fetch failed.
                                        has_password: true,
                                    })
                                }
                            }
                        }
                        // Only a DEFINITIVE rejection may destroy the stored session.
                        //
                        // This arm used to clear the keystore on ANY refresh error, so
                        // launching with no connectivity — on a plane, behind a captive
                        // portal, or simply while the backend was mid-deploy — threw
                        // away a valid 30-day refresh token and signed the user out for
                        // good. They had to type their password again, and an anonymous
                        // account whose 24-digit ID they had not written down was gone
                        // permanently. The cost is asymmetric: keeping a dead token
                        // costs one failed request next launch, discarding a live one
                        // costs the account.
                        //
                        // ApiError::Unauthorized specifically means the server rejected
                        // the refresh token — that token will never work again, so
                        // clearing is right. Everything else (Network, ServerError,
                        // RateLimited, CertificatePinningFailed, Parse) may well succeed
                        // on the next attempt, so the session is kept and reported as
                        // signed-in-with-unknown-identity, exactly as the profile-fetch
                        // failure above already does.
                        //
                        // NOTE: this distinction only became reliable once
                        // classify_error_response stopped collapsing every backend 401
                        // into ApiError::Unknown. Before that, Unauthorized was
                        // unreachable and this arm could not have told the cases apart.
                        Err(ApiError::Unauthorized) => {
                            tracing::info!(
                                "Refresh token rejected by the server — clearing stored session"
                            );
                            let _ = credentials.clear_tokens();
                            Ok(AuthState {
                                is_authenticated: false,
                                email: None,
                                account_id: None,
                                plan: None,
                                has_password: true,
                            })
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Token refresh failed transiently ({e}) — KEEPING the stored \
                                 session; identity unknown this cycle"
                            );
                            Ok(AuthState {
                                is_authenticated: true,
                                email: None,
                                account_id: None,
                                plan: None,
                                has_password: true,
                            })
                        }
                    }
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
            Ok(AuthState {
                is_authenticated: false,
                email: None,
                account_id: None,
                plan: None,
                has_password: true,
            })
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
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
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

    match api
        .register_anonymous(&device_id, Some(crate::commands::vpn::get_device_name()))
        .await
    {
        Ok(result) if result.ok => {
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
        Ok(_) => Ok(LoginResponse {
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

/// Login to an existing anonymous account with its 24-digit ID
#[tauri::command]
pub async fn login_anonymous(
    request: AnonymousLoginCommandRequest,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
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
    let device_id = crate::utils::get_device_id();
    tracing::info!("Anonymous login attempt (id: …{})", &anonymous_id[20..]);

    match api
        .login_anonymous(&anonymous_id, request.password.clone(), &device_id)
        .await
    {
        Ok(result) => {
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
    #[test]
    fn deletion_disconnects_only_after_the_server_confirmed() {
        let del = body("delete_account");
        let confirmed = del
            .find(".delete_account(&request.password)")
            .expect("the server call");
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
            sign_in_failure_code(&ApiError::RateLimited),
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

    /// Second-pass #9: the preflight the dialog shows before confirming.
    #[test]
    fn preflight_names_the_stores_and_defaults_to_nothing() {
        let named =
            super::deletion_preflight_result(&crate::api::types::DeletionPreflightResponse {
                store_subscriptions_still_billing: Some(serde_json::json!([
                    { "store": "GOOGLE_PLAY", "productId": "birdo_operative", "expiresAt": null }
                ])),
                web_subscription_will_be_cancelled: Some(true),
            });
        assert_eq!(named.store_subscriptions_still_billing, vec!["Google Play"]);
        assert!(named.web_subscription_will_be_cancelled);

        let nothing = super::deletion_preflight_result(&Default::default());
        assert!(nothing.store_subscriptions_still_billing.is_empty());
        assert!(!nothing.web_subscription_will_be_cancelled);
    }
}
