//! MR-2532 [SIGNOUT-DURING-REFRESH-HOLD]: how a Sign Out ends its session on
//! the server.
//!
//! Owner decision 2026-11-20 (option a): `POST /auth/logout` also takes the
//! REFRESH token, in the body as `/auth/refresh` takes it, and the server
//! revokes exactly that session, issuing and consuming nothing and never
//! answering with the reuse response (birdo-web). A Sign Out NEVER refreshes:
//! a refresh held by a 429 or a backoff cannot run, and one sent only to sign
//! out risks the reuse response (a token a racing refresh already presented
//! revokes every session of the account past the server's 30 s rotation
//! grace). `logout` used to go through `request_with_retry`: an expired
//! access token's 401 started a refresh, and during a hold that refresh was
//! answered at once with the hold, so nothing reached the server and the
//! session lived on until it expired.
//!
//! Owner decision 2026-11-24 ("never refresh at sign-out"): that holds for
//! EVERY request of the Sign Out flow, not only `/auth/logout`. The peer
//! release, the held-deletion read and the cancel-first each go ONCE with the
//! access token on file, never refreshed on a 401, and are not sent at all
//! when that token is unusable (`BirdoApi::sign_out_request`). The server's
//! stale-connection sweep frees an unreleased peer in about 5-10 minutes.
//!
//! Mobile twins: Android `BirdoRepository.endServerSession` and
//! `releasePeerForSignOut`, iOS `SignOutRevocation` (Mobile-Client).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use zeroize::Zeroizing;

/// An access token this close to its `exp` is not presented: it may expire on
/// the way. The same 30 s as Android and iOS.
pub(crate) const ACCESS_TOKEN_SKEW_SECS: u64 = 30;

/// What a Sign Out sends first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignOutPlan {
    /// The bearer; the refresh token follows only if the bearer is answered 401.
    BearerThenRefreshTokenOn401,
    /// The refresh token at once: the access token cannot be presented, or a
    /// refresh is held or owed.
    RefreshToken,
    /// Nothing the server could act on.
    Nothing,
}

/// One `POST /auth/logout`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum LogoutWith {
    /// The access token as the bearer, an empty body.
    Bearer,
    /// No bearer; `{ "refresh_token": … }` in the body. Zeroized on drop, as
    /// the session's own slots are (F-23).
    RefreshToken(Zeroizing<String>),
}

/// Never prints the refresh token (review of #475, N1), as iOS's
/// `SignOutTokens` and Android's `RefreshRequest` do not.
impl std::fmt::Debug for LogoutWith {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer => f.write_str("Bearer"),
            Self::RefreshToken(_) => f.write_str("RefreshToken(<redacted>)"),
        }
    }
}

/// The plan for a session holding `access` (if any) and a refresh token (if
/// `has_refresh`), with a refresh `held_or_owed` (`RetryGate`), at
/// `now_unix` seconds.
pub(crate) fn sign_out_plan(
    access: Option<&str>,
    has_refresh: bool,
    held_or_owed: bool,
    now_unix: u64,
) -> SignOutPlan {
    let bearer_usable = access.is_some_and(|token| access_token_usable(token, now_unix));
    if bearer_usable && !held_or_owed {
        SignOutPlan::BearerThenRefreshTokenOn401
    } else if has_refresh {
        SignOutPlan::RefreshToken
    } else if bearer_usable {
        // A hold with no refresh token on file: the bearer is all there is.
        SignOutPlan::BearerThenRefreshTokenOn401
    } else {
        SignOutPlan::Nothing
    }
}

/// The JWT's `exp` is more than [`ACCESS_TOKEN_SKEW_SECS`] after `now_unix`.
/// A token whose payload or `exp` cannot be read is not usable.
pub(crate) fn access_token_usable(jwt: &str, now_unix: u64) -> bool {
    let mut parts = jwt.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Some(exp) = claims.get("exp").and_then(serde_json::Value::as_f64) else {
        return false;
    };
    exp - now_unix as f64 > ACCESS_TOKEN_SKEW_SECS as f64
}

/// Seconds since the Unix epoch, for [`sign_out_plan`].
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A JWT whose payload carries `exp` (the header and signature are not read),
/// for the tests here and in `client.rs`.
#[cfg(test)]
pub(crate) fn test_jwt(exp: Option<u64>) -> String {
    let claims = match exp {
        Some(exp) => serde_json::json!({ "sub": "user-1", "exp": exp }),
        None => serde_json::json!({ "sub": "user-1" }),
    };
    format!(
        "eyJhbGciOiJIUzI1NiJ9.{}.sig",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_000_000;

    fn jwt(exp: Option<u64>) -> String {
        test_jwt(exp)
    }

    #[test]
    fn a_usable_bearer_goes_first_while_nothing_is_held() {
        let live = jwt(Some(NOW + 600));
        assert_eq!(
            sign_out_plan(Some(&live), true, false, NOW),
            SignOutPlan::BearerThenRefreshTokenOn401
        );
    }

    /// The case the row is about: the access token has expired (or will on
    /// the way), or a refresh is held or owed. The refresh token goes at once.
    #[test]
    fn an_expired_bearer_or_a_held_refresh_sends_the_refresh_token() {
        let live = jwt(Some(NOW + 600));
        let expired = jwt(Some(NOW - 10));
        let expiring = jwt(Some(NOW + ACCESS_TOKEN_SKEW_SECS - 5));
        assert_eq!(
            sign_out_plan(Some(&expired), true, false, NOW),
            SignOutPlan::RefreshToken
        );
        assert_eq!(
            sign_out_plan(Some(&expiring), true, false, NOW),
            SignOutPlan::RefreshToken
        );
        assert_eq!(
            sign_out_plan(None, true, false, NOW),
            SignOutPlan::RefreshToken
        );
        assert_eq!(
            sign_out_plan(Some(&live), true, true, NOW),
            SignOutPlan::RefreshToken
        );
    }

    #[test]
    fn nothing_is_sent_without_a_token_the_server_could_act_on() {
        assert_eq!(sign_out_plan(None, false, false, NOW), SignOutPlan::Nothing);
        assert_eq!(
            sign_out_plan(Some(&jwt(Some(NOW - 10))), false, true, NOW),
            SignOutPlan::Nothing
        );
        // Held, but the bearer is all there is: it still goes.
        assert_eq!(
            sign_out_plan(Some(&jwt(Some(NOW + 600))), false, true, NOW),
            SignOutPlan::BearerThenRefreshTokenOn401
        );
    }

    #[test]
    fn the_refresh_token_never_prints() {
        let with = LogoutWith::RefreshToken(Zeroizing::new("r-secret-123".to_string()));
        for printed in [format!("{with:?}"), format!("{with:#?}")] {
            assert!(!printed.contains("r-secret-123"), "{printed}");
            assert!(printed.contains("RefreshToken"), "{printed}");
        }
    }

    #[test]
    fn an_unreadable_access_token_is_never_usable() {
        let no_exp = jwt(None);
        for bad in [
            "",
            "not-a-jwt",
            "a.b",
            "a.%%%.c",
            "a.b.c.d",
            no_exp.as_str(),
        ] {
            assert!(!access_token_usable(bad, NOW), "{bad}");
        }
        assert!(access_token_usable(
            &jwt(Some(NOW + ACCESS_TOKEN_SKEW_SECS + 1)),
            NOW
        ));
        assert!(!access_token_usable(
            &jwt(Some(NOW + ACCESS_TOKEN_SKEW_SECS)),
            NOW
        ));
    }
}
