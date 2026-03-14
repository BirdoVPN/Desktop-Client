//! Authentication commands
//!
//! Handles login, logout, token refresh, and auth state management.

use crate::api::BirdoApi;
use crate::api::types::LoginResult;
use crate::storage::CredentialStore;
use crate::utils::redact_email;
use serde::{Deserialize, Serialize};
use tauri::State;
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
) -> Result<LoginResponse, String> {
    // FIX-2-5: Rate limit login attempts (max 5 per 60s window)
    {
        let mut guard = LOGIN_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = guard.get_or_insert_with(Vec::new);
        let now = Instant::now();
        let window = std::time::Duration::from_secs(LOGIN_WINDOW_SECS);
        // Remove expired attempts
        attempts.retain(|t| now.duration_since(*t) < window);
        if attempts.len() >= MAX_LOGIN_ATTEMPTS {
            let oldest = attempts[0];
            let wait = window.saturating_sub(now.duration_since(oldest));
            tracing::warn!("Login rate limit exceeded — {} attempts in {}s window", attempts.len(), LOGIN_WINDOW_SECS);
            return Err(format!("Too many login attempts. Please wait {} seconds.", wait.as_secs()));
        }
        attempts.push(now);
    }

    tracing::info!("Login attempt for: {}", redact_email(&request.email));

    match api.login(&request.email, &request.password).await {
        Ok(result) => match result {
            LoginResult::Success { tokens, .. } => {
                // Store tokens in Windows Credential Manager for persistence
                if let Err(e) = credentials.store_tokens(&tokens.access_token, &tokens.refresh_token) {
                    tracing::warn!("Failed to persist credentials to Windows Credential Manager: {}", e);
                }

                tracing::trace!("Login: tokens set in API client: is_authenticated={}", api.is_authenticated().await);

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
                })
            }
            LoginResult::TwoFactorChallenge { challenge_token, .. } => {
                // FIX C-2: 2FA is enabled — return challenge token to frontend
                tracing::info!("2FA required for: {}", redact_email(&request.email));
                Ok(LoginResponse {
                    success: false,
                    message: Some("Two-factor authentication required".to_string()),
                    user: None,
                    requires_two_factor: true,
                    challenge_token: Some(challenge_token),
                })
            }
        },
        Err(e) => {
            tracing::warn!("Login failed for {}: {}", redact_email(&request.email), e);
            Ok(LoginResponse {
                success: false,
                message: Some(e.to_string()),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
            })
        }
    }
}

/// Logout and clear stored credentials
#[tauri::command]
pub async fn logout(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, String> {
    tracing::info!("Logging out");

    // Try to logout on server (best effort)
    let _ = api.logout().await;

    // Clear local credentials
    credentials
        .clear_tokens()
        .map_err(|e| format!("Failed to clear credentials: {}", e))?;

    Ok(true)
}

/// Get current authentication state
#[tauri::command]
pub async fn get_auth_state(
    credentials: State<'_, CredentialStore>,
    api: State<'_, BirdoApi>,
) -> Result<AuthState, String> {
    match credentials.get_tokens() {
        Ok(tokens) => {
            // Set tokens in API client
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
            
            // Try to get user profile to validate token
            match api.get_profile().await {
                Ok(profile) => Ok(AuthState {
                    is_authenticated: true,
                    email: Some(profile.email),
                    account_id: Some(profile.id),
                    plan: None,
                }),
                Err(_) => {
                    // Token might be expired, try refresh
                    match api.refresh_token().await {
                        Ok(new_tokens) => {
                            // Use rotated refresh token if server returned one, else keep existing
                            let refresh_to_store = new_tokens.refresh_token
                                .as_deref()
                                .unwrap_or(&tokens.refresh_token);
                            let _ = credentials.store_tokens(&new_tokens.access_token, refresh_to_store);
                            Ok(AuthState {
                                is_authenticated: true,
                                email: None,
                                account_id: None,
                                plan: None,
                            })
                        }
                        Err(_) => {
                            let _ = credentials.clear_tokens();
                            Ok(AuthState {
                                is_authenticated: false,
                                email: None,
                                account_id: None,
                                plan: None,
                            })
                        }
                    }
                }
            }
        }
        Err(_) => Ok(AuthState {
            is_authenticated: false,
            email: None,
            account_id: None,
            plan: None,
        }),
    }
}

/// Refresh the access token
#[tauri::command]
pub async fn refresh_token(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, String> {
    let tokens = credentials
        .get_tokens()
        .map_err(|_| "Not authenticated".to_string())?;

    // Set tokens in API client first
    api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;

    match api.refresh_token().await {
        Ok(new_tokens) => {
            // FIX C-1: Use updated refresh token if server returned one, else keep existing
            let refresh_to_store = new_tokens.refresh_token
                .as_deref()
                .unwrap_or(&tokens.refresh_token);
            credentials
                .store_tokens(&new_tokens.access_token, refresh_to_store)
                .map_err(|e| format!("Failed to store new tokens: {}", e))?;
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("Token refresh failed: {}", e);
            Err(format!("Token refresh failed: {}", e))
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
) -> Result<LoginResponse, String> {
    // SEC-2FA: Rate limit TOTP verification attempts (max 5 per 120s window)
    {
        let mut guard = TOTP_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = guard.get_or_insert_with(Vec::new);
        let now = Instant::now();
        let window = std::time::Duration::from_secs(TOTP_WINDOW_SECS);
        attempts.retain(|t| now.duration_since(*t) < window);
        if attempts.len() >= MAX_TOTP_ATTEMPTS {
            let oldest = attempts[0];
            let wait = window.saturating_sub(now.duration_since(oldest));
            tracing::warn!("2FA rate limit exceeded — {} attempts in {}s window", attempts.len(), TOTP_WINDOW_SECS);
            return Err(format!("Too many 2FA attempts. Please wait {} seconds.", wait.as_secs()));
        }
        attempts.push(now);
    }

    tracing::info!("2FA verification attempt");

    match api.verify_2fa(&request.challenge_token, &request.code).await {
        Ok(response) => {
            if response.ok {
                if let Some(ref tokens) = response.tokens {
                    // Persist tokens to Windows Credential Manager
                    if let Err(e) = credentials.store_tokens(&tokens.access_token, &tokens.refresh_token) {
                        tracing::warn!("Failed to persist credentials after 2FA: {}", e);
                    }
                }

                tracing::info!("2FA verification successful");
                Ok(LoginResponse {
                    success: true,
                    message: None,
                    user: None, // Profile will be fetched via get_auth_state
                    requires_two_factor: false,
                    challenge_token: None,
                })
            } else {
                Ok(LoginResponse {
                    success: false,
                    message: Some("Invalid 2FA code".to_string()),
                    user: None,
                    requires_two_factor: true,
                    challenge_token: Some(request.challenge_token),
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
            })
        }
    }
}

/// Login anonymously (creates a new anonymous account with device ID)
#[tauri::command]
pub async fn login_anonymous(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, String> {
    // Generate a stable device ID from machine identity
    let device_id = crate::utils::get_device_id();

    tracing::info!("Anonymous login attempt (device: {}...)", &device_id[..8.min(device_id.len())]);

    match api.login_anonymous(&device_id).await {
        Ok(result) => {
            if result.ok {
                if let Some(ref tokens) = result.tokens {
                    if let Err(e) = credentials.store_tokens(&tokens.access_token, &tokens.refresh_token) {
                        tracing::warn!("Failed to persist anonymous credentials: {}", e);
                    }
                }

                let user_info = UserInfo {
                    email: None,
                    account_id: result.anonymous_id.clone(),
                    plan: "RECON".to_string(),
                    is_anonymous: true,
                };

                tracing::info!("Anonymous login successful: {:?}", result.anonymous_id);
                Ok(LoginResponse {
                    success: true,
                    message: None,
                    user: Some(user_info),
                    requires_two_factor: false,
                    challenge_token: None,
                })
            } else {
                Ok(LoginResponse {
                    success: false,
                    message: Some("Anonymous login failed".to_string()),
                    user: None,
                    requires_two_factor: false,
                    challenge_token: None,
                })
            }
        }
        Err(e) => {
            tracing::warn!("Anonymous login failed: {}", e);
            Ok(LoginResponse {
                success: false,
                message: Some(e.to_string()),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
            })
        }
    }
}
