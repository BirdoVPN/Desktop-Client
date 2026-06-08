//! Voucher commands
//!
//! In-app redemption of 30/90-day time-extension codes — parity with the
//! mobile client's `VoucherRedeemDialog`. Backend: `POST /vouchers/redeem`
//! (Bearer-authenticated, so it bypasses the server's CSRF guard).

use tauri::State;

use crate::api::error::ApiError;
use crate::api::types::RedeemVoucherResponse;
use crate::api::BirdoApi;
use crate::storage::CredentialStore;

/// Maps a redeem failure to a user-facing message.
///
/// The backend signals failure with an HTTP status + `{ error: <slug> }` body:
///   400 invalid_format · 404 not_found · 409 already_redeemed | plan_downgrade ·
///   410 expired · 429 rate-limited. The shared API layer collapses the body to
///   an `ApiError`, so we map by variant / status here. 409 can mean either
///   already-redeemed or a plan downgrade, so its copy covers both.
fn friendly_redeem_error(err: &ApiError) -> String {
    match err {
        ApiError::NotFound => "We couldn't find that voucher code. Double-check it and try again.".to_string(),
        ApiError::RateLimited => "Too many attempts. Please wait a minute and try again.".to_string(),
        ApiError::Unauthorized | ApiError::NotAuthenticated => {
            "Your session has expired. Please sign in again to redeem a voucher.".to_string()
        }
        ApiError::Unknown(msg) if msg.contains("400") => {
            "That code doesn't look right. Check the format (BIRD-XXXX-XXXX-XXXX) and try again.".to_string()
        }
        ApiError::Unknown(msg) if msg.contains("409") => {
            "This code can't be applied — it may already have been redeemed, or it would downgrade your current plan.".to_string()
        }
        ApiError::Unknown(msg) if msg.contains("410") => {
            "This voucher has expired and can no longer be redeemed.".to_string()
        }
        // Network / server / parse / pinning errors keep their own descriptive text.
        other => other.to_string(),
    }
}

/// Redeem a voucher code. Returns the updated plan + days added on success.
#[tauri::command]
pub async fn redeem_voucher(
    code: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<RedeemVoucherResponse, String> {
    // Trim + basic shape check before hitting the network (defense-in-depth;
    // the backend is the real validator). A renderer can bypass TS, so re-check.
    let code = code.trim().to_uppercase();
    if code.is_empty() {
        return Err("Enter a voucher code.".to_string());
    }
    if code.len() > 64 {
        return Err("That code doesn't look right. Check the format and try again.".to_string());
    }

    // Rehydrate tokens the same way every other authenticated command does.
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.redeem_voucher(&code)
        .await
        .map_err(|e| friendly_redeem_error(&e))
}
