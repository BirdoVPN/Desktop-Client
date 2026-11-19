//! Unit tests for the API module
//!
//! Tests cover:
//! - API type serialization / deserialization
//! - Endpoint path construction
//! - Error display formatting
//! - VpnConfig secrets: no private key, nothing printed (MR-822)
//! - AppSettings defaults and serialization

#[cfg(test)]
mod endpoint_tests {
    use super::super::endpoints;

    #[test]
    fn auth_endpoints_start_with_auth() {
        assert!(endpoints::auth::LOGIN_DESKTOP.starts_with("/auth/"));
        assert!(endpoints::auth::LOGOUT.starts_with("/auth/"));
        assert!(endpoints::auth::REFRESH.starts_with("/auth/"));
        assert!(endpoints::auth::ME.starts_with("/auth/"));
    }

    /// The client-config path is a WEB-app route, so unlike every other
    /// constant in this file it is joined to `WEB_BASE_URL`, not the NestJS
    /// `API_BASE_URL`. Pinning the literal here is the cheap guard against
    /// someone "tidying" it into the backend base, where it 404s.
    #[test]
    fn client_config_endpoint_is_the_web_api_route() {
        assert_eq!(endpoints::config::CLIENT_CONFIG, "/api/client-config");
    }

    #[test]
    fn vpn_connection_path_includes_key_id() {
        let path = endpoints::vpn::connection("key-abc-123");
        assert_eq!(path, "/vpn/connections/key-abc-123");
    }

    #[test]
    fn vpn_heartbeat_path_includes_key_id() {
        let path = endpoints::vpn::heartbeat("key-xyz");
        assert_eq!(path, "/vpn/heartbeat/key-xyz");
    }

    #[test]
    fn vpn_server_endpoints_are_correct() {
        assert_eq!(endpoints::vpn::SERVERS, "/vpn/servers");
        assert_eq!(endpoints::vpn::CONNECT, "/vpn/connect");
    }

    #[test]
    fn attestation_nonce_endpoint_is_correct() {
        assert_eq!(endpoints::vpn::ATTESTATION_NONCE, "/vpn/attestation/nonce");
    }

    #[test]
    fn user_endpoints_are_correct() {
        assert_eq!(endpoints::users::SUBSCRIPTION, "/auth/me");
    }

    #[test]
    fn connection_path_handles_special_characters() {
        let path = endpoints::vpn::connection("key-with-dashes-and_underscores");
        assert!(path.starts_with("/vpn/connections/"));
        assert!(path.contains("key-with-dashes-and_underscores"));
    }

    /// C-2 / P0-6 (audit 2026-09-29). The backend serves the GDPR routes from
    /// `@Controller('api/v1/gdpr')` and api.birdo.app rewrites nothing, so the
    /// `/api` prefix is part of the path. The client sent `/v1/gdpr/*` for
    /// months and every desktop deletion and export 404'd.
    #[test]
    fn gdpr_paths_carry_the_api_prefix_the_backend_serves() {
        assert_eq!(endpoints::auth::GDPR_DELETE, "/api/v1/gdpr/delete");
        assert_eq!(endpoints::auth::GDPR_EXPORT, "/api/v1/gdpr/export");
        // Second-pass #9: `@Get('delete/preflight')` on the same controller.
        assert_eq!(
            endpoints::auth::GDPR_DELETE_PREFLIGHT,
            "/api/v1/gdpr/delete/preflight"
        );
    }

    /// Second-pass #9: the preflight body the backend sends
    /// (gdpr.controller.ts `deletePreflight`), and a sparse one.
    #[test]
    fn deletion_preflight_decodes_the_backend_shape() {
        use super::super::types::{store_subscription_labels, DeletionPreflightResponse};
        let body = r#"{"success":true,
            "storeSubscriptionsStillBilling":[
              {"store":"GOOGLE_PLAY","productId":"birdo_operative","expiresAt":"2026-11-01T00:00:00.000Z"},
              {"store":"APPLE_APP_STORE","productId":"app.birdo.vpn.sovereign.yearly","expiresAt":null}
            ],
            "webSubscriptionWillBeCancelled":true}"#;
        let parsed: DeletionPreflightResponse = serde_json::from_str(body).expect("decodes");
        assert_eq!(
            store_subscription_labels(parsed.store_subscriptions_still_billing.as_ref().unwrap()),
            vec!["Google Play", "Apple App Store"]
        );
        assert_eq!(parsed.web_subscription_will_be_cancelled, Some(true));

        let sparse: DeletionPreflightResponse =
            serde_json::from_str(r#"{"success":true}"#).expect("decodes");
        assert!(sparse.store_subscriptions_still_billing.is_none());
        assert!(sparse.web_subscription_will_be_cancelled.is_none());
    }
}

/// The deletion request itself — method, URL, headers and body — built by the
/// same function the app sends through, not a hand-typed twin.
#[cfg(test)]
mod gdpr_request_tests {
    use super::super::client::{BirdoApi, GdprDeleteOutcome, DESKTOP_CLIENT_HEADER};
    use super::super::error::ApiError;
    use super::super::types::{store_subscription_labels, DeleteAccountBody};
    use reqwest::StatusCode;
    use serde_json::json;

    #[test]
    fn gdpr_delete_is_a_delete_to_the_api_prefixed_route() {
        let api = BirdoApi::new();
        let request = api
            .gdpr_delete_request(
                "tok",
                &DeleteAccountBody {
                    password: "pw",
                    two_factor_code: None,
                    account_number: None,
                    email_code: None,
                    step_up_method: None,
                },
            )
            .build()
            .expect("request builds");

        assert_eq!(
            request.method(),
            reqwest::Method::DELETE,
            "the backend route is @Delete('delete'); POST 404s"
        );
        assert_eq!(
            request.url().as_str(),
            "https://api.birdo.app/api/v1/gdpr/delete"
        );
        assert_eq!(
            request.headers().get("authorization").unwrap(),
            "Bearer tok",
            "Bearer auth is also what lets the backend's CsrfGuard pass"
        );
        assert_eq!(
            request.headers().get("x-desktop-client").unwrap(),
            DESKTOP_CLIENT_HEADER
        );
        let body: serde_json::Value =
            serde_json::from_slice(request.body().and_then(|b| b.as_bytes()).unwrap()).unwrap();
        assert_eq!(
            body,
            json!({ "password": "pw" }),
            "the body deleteAccountSchema validates: an optional password, at most 256 chars"
        );
    }

    /// Account API contract item 85: the code rides as `twoFactorCode`, and
    /// only once the server asked for it, so today's servers never see a key
    /// they do not know.
    #[test]
    fn the_two_factor_code_rides_only_when_there_is_one() {
        let api = BirdoApi::new();
        let body_of = |code: Option<&str>| -> serde_json::Value {
            let request = api
                .gdpr_delete_request(
                    "tok",
                    &DeleteAccountBody {
                        password: "pw",
                        two_factor_code: code,
                        account_number: None,
                        email_code: None,
                        step_up_method: None,
                    },
                )
                .build()
                .unwrap();
            serde_json::from_slice(request.body().and_then(|b| b.as_bytes()).unwrap()).unwrap()
        };
        assert_eq!(body_of(None), json!({ "password": "pw" }));
        assert_eq!(
            body_of(Some("123456")),
            json!({ "password": "pw", "twoFactorCode": "123456" })
        );
    }

    /// MR-179: the account number and the e-mailed code ride only when there is
    /// one, so a backend older than the step-up never sees either key.
    #[test]
    fn the_step_up_proof_rides_only_when_there_is_one() {
        let api = BirdoApi::new();
        let body_of = |number: Option<&str>, mailed: Option<&str>| -> serde_json::Value {
            let request = api
                .gdpr_delete_request(
                    "tok",
                    &DeleteAccountBody {
                        password: "pw",
                        two_factor_code: None,
                        account_number: number,
                        email_code: mailed,
                        step_up_method: None,
                    },
                )
                .build()
                .unwrap();
            serde_json::from_slice(request.body().and_then(|b| b.as_bytes()).unwrap()).unwrap()
        };
        assert_eq!(body_of(None, None), json!({ "password": "pw" }));
        assert_eq!(
            body_of(Some("123456789012345678901234"), None),
            json!({ "password": "pw", "accountNumber": "123456789012345678901234" })
        );
        assert_eq!(
            body_of(None, Some("654321")),
            json!({ "password": "pw", "emailCode": "654321" })
        );
    }

    /// MR-179: the step-up refusals are told apart by `error`, never by the
    /// sentence, and a 429 `too_many_attempts` stays a rate limit.
    #[test]
    fn deletion_step_up_refusals_map_by_error() {
        use super::super::error::StepUpKind;
        for (code, want) in [
            ("account_number_required", StepUpKind::AccountNumberRequired),
            ("account_number_invalid", StepUpKind::AccountNumberInvalid),
            ("email_code_required", StepUpKind::EmailCodeRequired),
            ("email_code_invalid", StepUpKind::EmailCodeInvalid),
        ] {
            let body = format!(
                r#"{{"statusCode":403,"error":"{code}","message":"Anything at all. If your app cannot ask for this, update the app, or delete your account on the website.","stepUp":["account_number"]}}"#
            );
            match BirdoApi::classify_gdpr_delete_response(StatusCode::FORBIDDEN, &body) {
                GdprDeleteOutcome::Refused(ApiError::StepUp { kind, message }) => {
                    assert_eq!(kind, want, "{code}");
                    assert!(message.contains("update the app"), "{message}");
                }
                _ => panic!("{code} was not a StepUp refusal"),
            }
        }
        let locked = r#"{"statusCode":429,"error":"too_many_attempts","message":"Too many attempts. Please wait 15 minutes and try again."}"#;
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::TOO_MANY_REQUESTS, locked),
            GdprDeleteOutcome::Refused(ApiError::RateLimited { .. })
        ));
    }

    /// MR-179: the preflight's `stepUp` and the code reply decode, and an older
    /// backend's preflight (no `stepUp`) still does.
    #[test]
    fn the_step_up_preflight_and_code_reply_decode() {
        use super::super::types::{DeletionCodeResponse, DeletionPreflightResponse};
        let with: DeletionPreflightResponse = serde_json::from_str(
            r#"{"success":true,"storeSubscriptionsStillBilling":[],"stepUp":{"factors":["email_code"],"enforced":true}}"#,
        )
        .unwrap();
        let step_up = with.step_up.unwrap();
        assert_eq!(step_up.factors, vec!["email_code"]);
        assert!(step_up.enforced);
        let old: DeletionPreflightResponse = serde_json::from_str(r#"{"success":true}"#).unwrap();
        assert!(old.step_up.is_none());
        let sent: DeletionCodeResponse = serde_json::from_str(
            r#"{"success":true,"sentTo":"o***@example.com","expiresInMinutes":10}"#,
        )
        .unwrap();
        assert_eq!(sent.sent_to.as_deref(), Some("o***@example.com"));
    }

    /// Item 85: the server's 403s are told apart by `error`, never by the
    /// sentence; a 403 without it (a plan refusal on any server) maps as
    /// before, and a 429 is a rate limit.
    #[test]
    fn deletion_two_factor_refusals_map_by_error() {
        let required = r#"{"error":"two_factor_required","message":"Enter your two-factor code to delete your account."}"#;
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::FORBIDDEN, required),
            GdprDeleteOutcome::Refused(ApiError::TwoFactorRequired(_))
        ));
        let invalid = r#"{"error":"two_factor_invalid","message":"Invalid two-factor code."}"#;
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::FORBIDDEN, invalid),
            GdprDeleteOutcome::Refused(ApiError::TwoFactorInvalid(_))
        ));
        let plan =
            r#"{"statusCode":403,"message":"Stealth mode requires a plan","error":"Forbidden"}"#;
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::FORBIDDEN, plan),
            GdprDeleteOutcome::Refused(ApiError::Rejected { status: 403, .. })
        ));
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::TOO_MANY_REQUESTS, ""),
            GdprDeleteOutcome::Refused(ApiError::RateLimited {
                retry_after_secs: None
            })
        ));
    }

    #[test]
    fn gdpr_export_is_the_api_prefixed_route() {
        assert_eq!(
            BirdoApi::gdpr_export_url(),
            "https://api.birdo.app/api/v1/gdpr/export"
        );
    }

    /// birdo-web `GdprController.deleteData`'s 200, word for word (origin/main
    /// a5a4ad3b): the confirmation of a deletion.
    const DELETED: &str = r#"{"success":true,"message":"Your data has been deleted. Some records may have been anonymized for legal compliance.","deletedItems":7,"anonymizedItems":2,"storeSubscriptionsStillBilling":[]}"#;

    /// 2xx bodies that cannot be read as that confirmation: none of them is
    /// what the server sends for a deletion.
    const UNREADABLE: &[&str] = &[
        "",
        "not json",
        "<html><body>Sign in to this network</body></html>",
        "null",
        "true",
        "[]",
        r#"[{"success":true}]"#,
        "{}",
        r#"{"message":"Your data has been deleted."}"#,
        r#"{"success":false,"message":"Your data has been deleted."}"#,
        r#"{"success":"true"}"#,
        r#"{"success":1}"#,
        r#"{"success":null}"#,
        // Cut off mid-body.
        r#"{"success":true,"message":"Your data has been del"#,
    ];

    /// MR-2370: a 2xx is a deletion only when its body confirms one
    /// (`success: true`); the store-subscription list stays as lenient as
    /// before (`store_subscription_labels_tolerate_every_plausible_shape`).
    #[test]
    fn a_2xx_is_a_deletion_only_when_its_body_confirms_it() {
        for status in [StatusCode::OK, StatusCode::CREATED] {
            for body in [
                DELETED,
                r#"{"success":true}"#,
                r#"{"success":true,"storeSubscriptionsStillBilling":"odd"}"#,
            ] {
                assert!(
                    matches!(
                        BirdoApi::classify_gdpr_delete_response(status, body),
                        GdprDeleteOutcome::Deleted(_)
                    ),
                    "{status} {body}"
                );
            }
        }
    }

    /// MR-2370: an unreadable non-202 2xx is NOT a deletion. Before, any 2xx
    /// body (`unwrap_or_default`) was read as one, and `delete_account` wiped
    /// the sign-in, the device id and the PQ state on it. Now it is an error
    /// (`ApiError::Parse`), which the dialog words as `server_error` ("Please
    /// try again") and leaves open for the retry.
    #[test]
    fn an_unreadable_2xx_is_an_error_not_a_deletion() {
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            for body in UNREADABLE {
                match BirdoApi::classify_gdpr_delete_response(status, body) {
                    GdprDeleteOutcome::Refused(ApiError::Parse(why)) => {
                        assert!(why.contains("nothing is assumed deleted"), "{why}")
                    }
                    other => panic!("{status} {body:?} was read as {other:?}"),
                }
            }
        }
    }

    /// MR-2370, by behaviour: a signed-in client handed an unreadable 2xx
    /// through `finish_gdpr_delete` (the ending `delete_account` uses) keeps
    /// its session; only the confirmation clears it.
    #[tokio::test]
    async fn an_unreadable_2xx_leaves_the_session_signed_in() {
        let api = BirdoApi::new();
        api.set_tokens("access-1".into(), "refresh-1".into()).await;
        for body in UNREADABLE {
            let outcome = BirdoApi::classify_gdpr_delete_response(StatusCode::OK, body);
            assert!(
                matches!(
                    api.finish_gdpr_delete(outcome).await,
                    Err(ApiError::Parse(_))
                ),
                "{body:?}"
            );
            assert!(api.is_authenticated().await, "{body:?} signed the user out");
            assert_eq!(
                api.access_token_value().await.as_deref(),
                Some("access-1"),
                "{body:?}"
            );
        }
        let outcome = BirdoApi::classify_gdpr_delete_response(StatusCode::OK, DELETED);
        assert!(api.finish_gdpr_delete(outcome).await.is_ok());
        assert!(!api.is_authenticated().await);
    }

    /// birdo-web `GdprController.deleteData`'s 401 when the guard admitted the
    /// token but no account was there to check (origin/main a5a4ad3b).
    const IDENTITY_UNVERIFIED: &str =
        r#"{"statusCode":401,"message":"Unable to verify identity","error":"Unauthorized"}"#;

    /// One deletion attempt's ending, as `delete_account` concludes it.
    fn after(unconfirmed_before: bool, status: StatusCode, body: &str) -> GdprDeleteOutcome {
        BirdoApi::after_unconfirmed(
            unconfirmed_before,
            BirdoApi::classify_gdpr_delete_response(status, body),
        )
    }

    /// MR-2483: only MR-2370's answer (a non-202 2xx whose body does not
    /// confirm) marks a deletion unconfirmed. A hold, a 2xx that says
    /// pending, a confirmation and every refusal do not.
    #[test]
    fn only_an_unreadable_2xx_leaves_the_deletion_unconfirmed() {
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            for body in UNREADABLE {
                assert!(
                    BirdoApi::classify_gdpr_delete_response(status, body).is_unconfirmed(),
                    "{status} {body:?}"
                );
            }
        }
        for (status, body) in [
            (StatusCode::OK, DELETED),
            (StatusCode::ACCEPTED, ""),
            (StatusCode::OK, r#"{"success":true,"pending":true}"#),
            (StatusCode::OK, r#"{"code":"change_pending"}"#),
            (StatusCode::NOT_FOUND, ""),
            (StatusCode::NOT_FOUND, API_NOT_FOUND),
            (StatusCode::UNAUTHORIZED, IDENTITY_UNVERIFIED),
            (StatusCode::INTERNAL_SERVER_ERROR, ""),
            (StatusCode::TOO_MANY_REQUESTS, ""),
        ] {
            assert!(
                !BirdoApi::classify_gdpr_delete_response(status, body).is_unconfirmed(),
                "{status} {body:?}"
            );
        }
    }

    /// birdo-web's `GlobalExceptionFilter` body for a 404, every field it
    /// writes (origin/main a5a4ad3b).
    const API_NOT_FOUND: &str = r#"{"statusCode":404,"message":"User not found","error":"Not Found","timestamp":"2026-11-19T21:00:00.000Z","path":"/api/v1/gdpr/delete"}"#;

    /// 404s that are not the API's own: what a Cloudflare challenge, an HTML
    /// error page, an empty answer or another responder's JSON looks like
    /// (MR-2483 review L1). None of them says the account is gone.
    const FOREIGN_404: &[&str] = &[
        "",
        "   ",
        "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body></body></html>",
        "<html><body><h1>404 Not Found</h1></body></html>",
        "not json",
        "null",
        "[]",
        "{}",
        r#"{"message":"Not Found"}"#,
        r#"{"error":"Not Found"}"#,
        r#"{"statusCode":404}"#,
        r#"{"statusCode":404,"message":""}"#,
        r#"{"statusCode":404,"message":"  "}"#,
        r#"{"statusCode":404,"message":null}"#,
        r#"{"statusCode":"404","message":"Not Found"}"#,
        r#"{"statusCode":404.5,"message":"Not Found"}"#,
        r#"{"statusCode":200,"message":"Not Found"}"#,
        r#"[{"statusCode":404,"message":"Not Found"}]"#,
        r#"{"success":false,"errors":[{"code":1000,"message":"Not Found"}]}"#,
    ];

    /// The 404 a deletion meets, as `ApiError`: the generic mapping's
    /// `NotFound`, or `Rejected` with the body's sentence.
    fn is_plain_404(error: &ApiError) -> bool {
        matches!(
            error,
            ApiError::NotFound | ApiError::Rejected { status: 404, .. }
        )
    }

    /// The same 404 error: variant, status and sentence.
    fn same_404(a: &ApiError, b: &ApiError) -> bool {
        match (a, b) {
            (ApiError::NotFound, ApiError::NotFound) => true,
            (
                ApiError::Rejected {
                    status: s1,
                    message: m1,
                },
                ApiError::Rejected {
                    status: s2,
                    message: m2,
                },
            ) => s1 == s2 && m1 == m2,
            _ => false,
        }
    }

    /// MR-2483 review L1: the API's own 404 is the `GlobalExceptionFilter`
    /// shape, `statusCode` 404 and a `message`; nothing else is.
    #[test]
    fn only_the_apis_error_shape_is_its_404() {
        use super::super::client::is_api_not_found;
        for body in [
            API_NOT_FOUND,
            r#"{"statusCode":404,"message":"User not found","error":"Not Found"}"#,
            r#"{"statusCode":404,"message":"Cannot DELETE /api/v1/gdpr/delete"}"#,
            r#" {"message":"Not Found","statusCode":404} "#,
        ] {
            assert!(is_api_not_found(body), "{body}");
        }
        for body in FOREIGN_404 {
            assert!(!is_api_not_found(body), "{body:?}");
        }
    }

    /// MR-2483: after an unreadable 2xx, a retry that meets an account that
    /// is gone (the API's own 404, or the handler's "Unable to verify
    /// identity" 401) is the deletion: `AlreadyDeleted`. On main it was a
    /// generic 404 error or `Rejected { 401 }`, which the dialog words as a
    /// WRONG PASSWORD (`invalid_credentials`).
    #[test]
    fn after_an_unreadable_2xx_a_gone_account_is_already_deleted() {
        let not_found = r#"{"statusCode":404,"message":"User not found","error":"Not Found"}"#;
        for (status, body) in [
            (StatusCode::NOT_FOUND, API_NOT_FOUND),
            (StatusCode::NOT_FOUND, not_found),
            (StatusCode::UNAUTHORIZED, IDENTITY_UNVERIFIED),
            (
                StatusCode::UNAUTHORIZED,
                r#"{"statusCode":401,"message":"  unable to verify identity "}"#,
            ),
        ] {
            assert!(
                matches!(after(true, status, body), GdprDeleteOutcome::AlreadyDeleted),
                "{status} {body}"
            );
            // Without the unreadable 2xx before: today's mapping, unchanged.
            assert!(
                matches!(after(false, status, body), GdprDeleteOutcome::Refused(_)),
                "{status} {body}"
            );
        }
    }

    /// MR-2483 review L1: the unreadable 2xx is exactly what a Cloudflare
    /// challenge, an HTML page or a misrouted response produces, and the same
    /// responder can answer the retry with a 404. A 404 that is not the API's
    /// own stays the error it always was, which the dialog offers to retry
    /// (`server_unavailable`): never `AlreadyDeleted`, and it does not mark
    /// the deletion unconfirmed either.
    #[test]
    fn after_an_unreadable_2xx_a_404_that_is_not_the_apis_stays_an_error() {
        for body in FOREIGN_404 {
            let outcome = after(true, StatusCode::NOT_FOUND, body);
            assert!(!outcome.is_unconfirmed(), "{body:?}");
            match outcome {
                GdprDeleteOutcome::Refused(error) => {
                    assert!(is_plain_404(&error), "{body:?} is not a 404 error");
                    let GdprDeleteOutcome::Refused(before) =
                        after(false, StatusCode::NOT_FOUND, body)
                    else {
                        panic!("{body:?} without an unreadable 2xx is no refusal");
                    };
                    assert!(same_404(&error, &before), "{body:?} changed");
                }
                GdprDeleteOutcome::AlreadyDeleted => panic!("{body:?} read as deleted"),
                _ => panic!("{body:?} is no refusal"),
            }
        }
    }

    /// MR-2483 review L1: without an unreadable 2xx before, every 404 (the
    /// API's own included) is exactly what it was before MR-2483: the generic
    /// mapping (`classify_error_response`), `Refused`.
    #[test]
    fn without_an_unreadable_2xx_a_404_is_what_it_always_was() {
        for body in FOREIGN_404.iter().copied().chain([API_NOT_FOUND]) {
            let GdprDeleteOutcome::Refused(now) = after(false, StatusCode::NOT_FOUND, body) else {
                panic!("{body:?} is no refusal");
            };
            let generic = BirdoApi::classify_error_response(StatusCode::NOT_FOUND, body);
            assert!(same_404(&now, &generic), "{body:?} changed");
        }
        match after(false, StatusCode::NOT_FOUND, API_NOT_FOUND) {
            GdprDeleteOutcome::Refused(ApiError::Rejected { status, message }) => {
                assert_eq!(status, 404);
                assert_eq!(message, "User not found");
            }
            _ => panic!("the API's 404 is no longer its sentence"),
        }
        // A hold request reads it as the error it always was, too.
        assert!(matches!(
            BirdoApi::deletion_hold_from(BirdoApi::classify_gdpr_delete_response(
                StatusCode::NOT_FOUND,
                API_NOT_FOUND
            )),
            Err(ApiError::Rejected { status: 404, .. })
        ));
    }

    /// MR-2483: everything else keeps its meaning after an unreadable 2xx.
    /// The password check's 401s read the account's password, so the account
    /// exists and the sentence is the answer; the guard's bare 401 still
    /// refreshes first (the refresh decides, `refresh_says_gone`); a
    /// confirmation is a deletion; another unreadable 2xx stays one.
    #[test]
    fn after_an_unreadable_2xx_the_password_check_is_still_the_answer() {
        for (body, sentence) in [
            (
                r#"{"statusCode":401,"message":"Incorrect password","error":"Unauthorized","details":{"stepUp":["password"]}}"#,
                "Incorrect password",
            ),
            (
                r#"{"statusCode":401,"message":"Password confirmation is required to delete your account","error":"Unauthorized"}"#,
                "Password confirmation is required to delete your account",
            ),
        ] {
            match after(true, StatusCode::UNAUTHORIZED, body) {
                GdprDeleteOutcome::Refused(ApiError::Rejected { status, message }) => {
                    assert_eq!(status, 401);
                    assert_eq!(message, sentence);
                }
                other => panic!("{body} was read as {other:?}"),
            }
        }
        for bare in [
            r#"{"statusCode":401,"message":"Unauthorized","error":"Unauthorized"}"#,
            "",
        ] {
            assert!(matches!(
                after(true, StatusCode::UNAUTHORIZED, bare),
                GdprDeleteOutcome::SessionExpired
            ));
        }
        assert!(matches!(
            after(true, StatusCode::TOO_MANY_REQUESTS, ""),
            GdprDeleteOutcome::Refused(ApiError::RateLimited { .. })
        ));
        assert!(matches!(
            after(true, StatusCode::BAD_GATEWAY, ""),
            GdprDeleteOutcome::Refused(ApiError::ServerError(502))
        ));
        assert!(matches!(
            after(true, StatusCode::OK, DELETED),
            GdprDeleteOutcome::Deleted(_)
        ));
        assert!(after(true, StatusCode::OK, "").is_unconfirmed());
    }

    /// MR-2483: on the retry, the guard's bare 401 led to a refresh. Only a
    /// refresh the server refused with 401 (the token itself is dead) says
    /// the session went with the account; nothing transient does, and a 403
    /// says nothing about the account either.
    #[test]
    fn only_a_401_from_the_refresh_says_the_session_went_with_the_account() {
        assert!(BirdoApi::refresh_says_gone(&ApiError::Unauthorized));
        assert!(BirdoApi::refresh_says_gone(&ApiError::Rejected {
            status: 401,
            message: "Invalid refresh token".into(),
        }));
        for kept in [
            ApiError::Forbidden,
            ApiError::Rejected {
                status: 403,
                message: "Forbidden".into(),
            },
            ApiError::RateLimited {
                retry_after_secs: Some(60),
            },
            ApiError::Held {
                status: 429,
                retry_after_secs: 30,
            },
            ApiError::ServerError(503),
            ApiError::ServerBusy {
                status: 503,
                retry_after_secs: 10,
            },
            ApiError::Network("connection reset".into()),
            ApiError::Parse("eof".into()),
            ApiError::NotAuthenticated,
        ] {
            assert!(!BirdoApi::refresh_says_gone(&kept), "{kept:?}");
        }
    }

    /// MR-2483, by behaviour: a signed-in client whose deletion got an
    /// unreadable 2xx keeps its session and remembers it; the retry's 404
    /// (the API's own) then signs it out, as a confirmed deletion does, and
    /// reports `AlreadyDeleted`. On main the retry's 404 left it signed in to
    /// a deleted account behind a generic error.
    #[tokio::test]
    async fn a_retry_that_finds_the_account_gone_signs_out() {
        use super::super::client::AccountDeletion;
        let api = BirdoApi::new();
        api.set_tokens("access-1".into(), "refresh-1".into()).await;
        assert!(!api.deletion_unconfirmed());

        let first = BirdoApi::classify_gdpr_delete_response(StatusCode::OK, "");
        assert!(matches!(
            api.conclude_gdpr_delete(api.deletion_unconfirmed(), first)
                .await,
            Err(ApiError::Parse(_))
        ));
        assert!(
            api.is_authenticated().await,
            "the unreadable 2xx signed out"
        );
        assert!(api.deletion_unconfirmed());

        let retry = BirdoApi::classify_gdpr_delete_response(StatusCode::NOT_FOUND, API_NOT_FOUND);
        assert!(matches!(
            api.conclude_gdpr_delete(api.deletion_unconfirmed(), retry)
                .await,
            Ok(AccountDeletion::AlreadyDeleted)
        ));
        assert!(
            !api.is_authenticated().await,
            "still signed in to a deleted account"
        );
        assert!(!api.deletion_unconfirmed());
    }

    /// MR-2483 review L1, by behaviour: after an unreadable 2xx (here the
    /// HTML a Cloudflare challenge answers with), a 404 that is not the API's
    /// own (HTML, empty, foreign JSON) is the error it always was: the user
    /// stays signed in, nothing is cleared, and the deletion stays
    /// unconfirmed, so the user can retry. Only the API's own 404 then ends
    /// it as `AlreadyDeleted`.
    #[tokio::test]
    async fn after_an_unreadable_2xx_only_the_apis_404_signs_out() {
        use super::super::client::AccountDeletion;
        let api = BirdoApi::new();
        api.set_tokens("access-1".into(), "refresh-1".into()).await;
        let challenge = "<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>";
        let first = BirdoApi::classify_gdpr_delete_response(StatusCode::OK, challenge);
        assert!(matches!(
            api.conclude_gdpr_delete(api.deletion_unconfirmed(), first)
                .await,
            Err(ApiError::Parse(_))
        ));
        assert!(api.deletion_unconfirmed());

        for body in FOREIGN_404 {
            let retry = BirdoApi::classify_gdpr_delete_response(StatusCode::NOT_FOUND, body);
            let ended = api
                .conclude_gdpr_delete(api.deletion_unconfirmed(), retry)
                .await;
            match ended {
                Err(error) => assert!(is_plain_404(&error), "{body:?} is not a 404 error"),
                Ok(_) => panic!("{body:?} ended the account"),
            }
            assert!(api.is_authenticated().await, "{body:?} signed out");
            assert!(api.deletion_unconfirmed(), "{body:?} forgot the 2xx");
        }

        let retry = BirdoApi::classify_gdpr_delete_response(StatusCode::NOT_FOUND, API_NOT_FOUND);
        assert!(matches!(
            api.conclude_gdpr_delete(api.deletion_unconfirmed(), retry)
                .await,
            Ok(AccountDeletion::AlreadyDeleted)
        ));
        assert!(!api.is_authenticated().await);
        assert!(!api.deletion_unconfirmed());
    }

    /// MR-2483: the memory of an unreadable 2xx is its session's. Without
    /// it a 404, even the API's own, signs nobody out; a new sign-in and a
    /// sign-out forget it.
    #[tokio::test]
    async fn an_unreadable_2xx_is_remembered_for_its_session_only() {
        let api = BirdoApi::new();
        api.set_tokens("access-1".into(), "refresh-1".into()).await;
        let not_found =
            || BirdoApi::classify_gdpr_delete_response(StatusCode::NOT_FOUND, API_NOT_FOUND);
        let unreadable = || BirdoApi::classify_gdpr_delete_response(StatusCode::OK, "{}");

        assert!(matches!(
            api.conclude_gdpr_delete(api.deletion_unconfirmed(), not_found())
                .await,
            Err(ApiError::Rejected { status: 404, .. })
        ));
        assert!(api.is_authenticated().await);

        let _ = api
            .conclude_gdpr_delete(api.deletion_unconfirmed(), unreadable())
            .await;
        assert!(api.deletion_unconfirmed());
        api.set_tokens("access-2".into(), "refresh-2".into()).await;
        assert!(!api.deletion_unconfirmed(), "a new sign-in inherited it");
        assert!(matches!(
            api.conclude_gdpr_delete(api.deletion_unconfirmed(), not_found())
                .await,
            Err(ApiError::Rejected { status: 404, .. })
        ));
        assert!(api.is_authenticated().await);

        let _ = api
            .conclude_gdpr_delete(api.deletion_unconfirmed(), unreadable())
            .await;
        assert!(api.deletion_unconfirmed());
        api.clear_tokens().await;
        assert!(!api.deletion_unconfirmed(), "a sign-out kept it");
        api.set_tokens("access-3".into(), "refresh-3".into()).await;
        let _ = api
            .conclude_gdpr_delete(api.deletion_unconfirmed(), unreadable())
            .await;
        let expired = api.access_token_value().await;
        assert!(api.clear_tokens_if(expired.as_deref()).await);
        assert!(!api.deletion_unconfirmed(), "an expired session kept it");
    }

    /// MR-2483, the wiring `delete_account` cannot be driven through without
    /// a server: the memory is read BEFORE the attempt, a refresh refused
    /// after it ends as `AlreadyDeleted`, any other refresh failure still
    /// answers through the session gate, and every answer is concluded
    /// through `conclude_gdpr_delete`.
    #[test]
    fn delete_account_reads_the_unreadable_2xx_before_it_sends() {
        const SOURCE: &str = include_str!("client.rs");
        let start = SOURCE.find("pub async fn delete_account(").unwrap();
        let body = &SOURCE[start..];
        let body = &body[..body.find("\n    }").unwrap()];
        let read = body
            .find("let unconfirmed_before = self.deletion_unconfirmed();")
            .expect("the memory is read");
        let sent = body.find("self.send_gdpr_delete(").expect("the request");
        assert!(read < sent, "read after the attempt that may set it");
        assert!(body.contains("if unconfirmed_before && Self::refresh_says_gone(&refused) =>"));
        assert!(body.contains(".finish_gdpr_delete(GdprDeleteOutcome::AlreadyDeleted)"));
        assert!(body.contains("session_gate::error_after_failed_refresh(e)"));
        assert!(body.contains("self.conclude_gdpr_delete(unconfirmed_before, outcome)"));
    }

    /// The password check's 401 is the ANSWER and must reach the user
    /// verbatim; passport's bare "Unauthorized" is an expired token and must
    /// trigger a refresh instead.
    #[test]
    fn the_two_401s_are_told_apart() {
        let wrong_password =
            r#"{"statusCode":401,"message":"Incorrect password","error":"Unauthorized"}"#;
        match BirdoApi::classify_gdpr_delete_response(StatusCode::UNAUTHORIZED, wrong_password) {
            GdprDeleteOutcome::Refused(ApiError::Rejected { status, message }) => {
                assert_eq!(status, 401);
                assert_eq!(message, "Incorrect password");
            }
            other => panic!("wrong password must be shown, got {other:?}"),
        }

        let expired = r#"{"statusCode":401,"message":"Unauthorized","error":"Unauthorized"}"#;
        for body in [expired, ""] {
            assert!(matches!(
                BirdoApi::classify_gdpr_delete_response(StatusCode::UNAUTHORIZED, body),
                GdprDeleteOutcome::SessionExpired
            ));
        }
    }

    #[test]
    fn other_refusals_keep_the_backend_message() {
        let body = r#"{"statusCode":409,"message":"A deletion is already in progress"}"#;
        match BirdoApi::classify_gdpr_delete_response(StatusCode::CONFLICT, body) {
            GdprDeleteOutcome::Refused(ApiError::Rejected { status, message }) => {
                assert_eq!(status, 409);
                assert_eq!(message, "A deletion is already in progress");
            }
            other => panic!("{other:?}"),
        }
        // MR-1808: a 429 is a rate limit whatever its body says — the dialog
        // words it by its code, and its wait has to travel with it.
        let body = r#"{"statusCode":429,"message":"Slow down"}"#;
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::TOO_MANY_REQUESTS, body),
            GdprDeleteOutcome::Refused(ApiError::RateLimited { .. })
        ));
        assert!(matches!(
            BirdoApi::classify_gdpr_delete_response(StatusCode::NOT_FOUND, ""),
            GdprDeleteOutcome::Refused(ApiError::NotFound)
        ));
    }

    /// A-8 / C-9: the store subscriptions deletion cannot cancel. The backend
    /// field is new and its shape is not settled, so every plausible shape must
    /// produce a warning, and its absence must produce none.
    #[test]
    fn store_subscription_labels_tolerate_every_plausible_shape() {
        let body =
            r#"{"success":true,"storeSubscriptionsStillBilling":["APP_STORE","GOOGLE_PLAY"]}"#;
        match BirdoApi::classify_gdpr_delete_response(StatusCode::OK, body) {
            GdprDeleteOutcome::Deleted(r) => assert_eq!(
                store_subscription_labels(r.store_subscriptions_still_billing.as_ref().unwrap()),
                vec!["Apple App Store", "Google Play"]
            ),
            other => panic!("{other:?}"),
        }

        assert_eq!(
            store_subscription_labels(&json!([
                { "store": "APPLE", "productId": "x" },
                { "provider": "google_play" },
                { "store": "APPLE" }
            ])),
            vec!["Apple App Store", "Google Play"],
            "objects are named by their store field and de-duplicated"
        );
        assert_eq!(
            store_subscription_labels(&json!([{ "productId": "x" }])),
            vec!["App Store or Google Play subscription"],
            "an unnamed subscription still warns"
        );
        assert_eq!(
            store_subscription_labels(&json!(true)),
            vec!["App Store or Google Play subscription"]
        );
        for none in [json!([]), json!(null), json!(false), json!(0)] {
            assert!(store_subscription_labels(&none).is_empty(), "{none}");
        }

        // Today's backend does not send the field at all.
        let today = r#"{"success":true,"message":"Your data has been deleted."}"#;
        match BirdoApi::classify_gdpr_delete_response(StatusCode::OK, today) {
            GdprDeleteOutcome::Deleted(r) => assert!(r.store_subscriptions_still_billing.is_none()),
            other => panic!("{other:?}"),
        }
    }
}

/// MR-2335 (MR-179 hold fallback, birdo-web #883 @ dd14f5ec): the 24-hour
/// deletion hold. Every status and `stepUp` shape the server sends is decoded
/// here, and none of them is ever a deletion.
#[cfg(test)]
mod deletion_hold_tests {
    use super::super::client::{BirdoApi, GdprDeleteOutcome};
    use super::super::endpoints;
    use super::super::error::{ApiError, StepUpKind};
    use super::super::types::{pending_changes_from, DeleteAccountBody, DeletionHold};
    use reqwest::StatusCode;
    use serde_json::json;

    const APPLY_AFTER: &str = "2026-11-15T12:00:00.000Z";
    const HOLD_ID: &str = "cmhold0000000000000000001";
    // birdo-web gdpr.controller.ts holdDeletion, word for word.
    const FILED: &str = "Your account will be deleted in 24 hours unless the request is \
                         cancelled first: cancel it in the app or on the website, or sign out \
                         of this app. Any verified e-mail address on the account was alerted.";
    const ALREADY: &str =
        "A deletion is already on hold. Cancel it first to ask for a different one.";

    fn step_up_object() -> serde_json::Value {
        json!({ "methods": ["hold"], "pendingChangeId": HOLD_ID, "applyAfter": APPLY_AFTER })
    }

    fn classify(status: StatusCode, body: &serde_json::Value) -> GdprDeleteOutcome {
        BirdoApi::classify_gdpr_delete_response(status, &body.to_string())
    }

    fn held(outcome: GdprDeleteOutcome) -> DeletionHold {
        match outcome {
            GdprDeleteOutcome::Held(hold) => hold,
            other => panic!("not a hold: {other:?}"),
        }
    }

    /// The hold rides the same DELETE as the deletion, with
    /// `stepUpMethod: "hold"`, the password and (once asked) the 2FA code, and
    /// never the number or the e-mailed code it stands in for.
    #[test]
    fn the_hold_is_the_deletion_route_with_step_up_method_hold() {
        let api = BirdoApi::new();
        let body_of = |code: Option<&str>| -> serde_json::Value {
            let request = api
                .gdpr_delete_request(
                    "tok",
                    &DeleteAccountBody {
                        password: "pw",
                        two_factor_code: code,
                        account_number: None,
                        email_code: None,
                        step_up_method: Some("hold"),
                    },
                )
                .build()
                .unwrap();
            assert_eq!(request.method(), reqwest::Method::DELETE);
            assert!(request.url().path().ends_with("/api/v1/gdpr/delete"));
            serde_json::from_slice(request.body().and_then(|b| b.as_bytes()).unwrap()).unwrap()
        };
        assert_eq!(
            body_of(None),
            json!({ "password": "pw", "stepUpMethod": "hold" })
        );
        assert_eq!(
            body_of(Some("123456")),
            json!({ "password": "pw", "twoFactorCode": "123456", "stepUpMethod": "hold" })
        );
    }

    /// 202 `change_pending`: the hold, with its id and time. NOT `Deleted`:
    /// before this, any 2xx was a deletion, and `delete_account` cleared the
    /// tokens on it.
    #[test]
    fn a_202_is_a_hold_never_a_deletion() {
        let body = json!({
            "success": true,
            "pending": true,
            "code": "change_pending",
            "message": FILED,
            "stepUp": step_up_object(),
        });
        let hold = held(classify(StatusCode::ACCEPTED, &body));
        assert_eq!(hold.pending_change_id, HOLD_ID);
        assert_eq!(hold.apply_after, APPLY_AFTER);
        assert_eq!(hold.message.as_deref(), Some(FILED));
        assert!(!hold.already_pending);
        // Only a 202 is a hold. The same body under any other 2xx is
        // unexpected: an error, and above all not a deletion (no wipe).
        let mut by_code = body.clone();
        by_code.as_object_mut().unwrap().remove("pending");
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            for unexpected in [&body, &by_code] {
                assert!(
                    matches!(
                        classify(status, unexpected),
                        GdprDeleteOutcome::Refused(ApiError::Parse(_))
                    ),
                    "{status}"
                );
            }
        }
        // A deletion's own 200 is unchanged.
        assert!(matches!(
            classify(
                StatusCode::OK,
                &json!({ "success": true, "message": "Your data has been deleted." })
            ),
            GdprDeleteOutcome::Deleted(_)
        ));
    }

    /// A 202 whose hold cannot be read is an error: never a deletion, never
    /// a hold with a made-up id. (The pending-change list still shows it.)
    #[test]
    fn an_unreadable_202_is_an_error_not_a_success() {
        for step_up in [
            json!(["account_number"]),
            json!(null),
            json!({ "methods": ["hold"], "applyAfter": APPLY_AFTER }),
            json!({ "methods": ["hold"], "pendingChangeId": HOLD_ID }),
            json!({ "pendingChangeId": "../../admin", "applyAfter": APPLY_AFTER }),
            json!({ "pendingChangeId": "", "applyAfter": APPLY_AFTER }),
            json!({ "pendingChangeId": HOLD_ID, "applyAfter": "soon <b>" }),
            json!({ "pendingChangeId": 42, "applyAfter": APPLY_AFTER }),
        ] {
            let body = json!({ "success": true, "pending": true, "code": "change_pending", "stepUp": step_up });
            assert!(
                matches!(
                    classify(StatusCode::ACCEPTED, &body),
                    GdprDeleteOutcome::Refused(ApiError::Parse(_))
                ),
                "{step_up}"
            );
        }
        for raw in ["", "not json", "[]", "{}"] {
            assert!(
                matches!(
                    BirdoApi::classify_gdpr_delete_response(StatusCode::ACCEPTED, raw),
                    GdprDeleteOutcome::Refused(ApiError::Parse(_))
                ),
                "{raw:?}"
            );
        }
    }

    /// 409 `change_already_pending`: `stepUp` is an OBJECT. birdo-web's
    /// GlobalExceptionFilter keeps only `details` of a thrown body, so it is
    /// read at the top (as #883 throws it), under `details.stepUp`, and as
    /// `details`; with none of them it is a "find it in the list" refusal.
    #[test]
    fn a_409_already_pending_names_the_existing_hold_wherever_it_is() {
        let top = json!({ "statusCode": 409, "error": "change_already_pending", "message": ALREADY, "stepUp": step_up_object() });
        let nested = json!({ "statusCode": 409, "error": "change_already_pending", "message": ALREADY, "details": { "stepUp": step_up_object() } });
        let flat = json!({ "statusCode": 409, "error": "change_already_pending", "message": ALREADY, "details": step_up_object() });
        for body in [top, nested, flat] {
            let hold = held(classify(StatusCode::CONFLICT, &body));
            assert_eq!(hold.pending_change_id, HOLD_ID, "{body}");
            assert_eq!(hold.apply_after, APPLY_AFTER);
            assert!(hold.already_pending);
            assert_eq!(hold.message.as_deref(), Some(ALREADY));
        }
        // What the filter sends today: no stepUp, no details.
        let filtered = json!({
            "statusCode": 409, "message": ALREADY, "error": "change_already_pending",
            "timestamp": "2026-11-14T12:00:00.000Z", "path": "api/v1/gdpr/delete",
        });
        match classify(StatusCode::CONFLICT, &filtered) {
            GdprDeleteOutcome::Refused(ApiError::DeletionAlreadyOnHold(message)) => {
                assert_eq!(message, ALREADY)
            }
            other => panic!("{other:?}"),
        }
    }

    /// Every refusal's `stepUp` is the factor ARRAY (when it reaches the wire
    /// at all); it is never read, and the refusal maps by `error` exactly as
    /// before. Nothing here is a hold or a deletion.
    #[test]
    fn refusals_with_a_factor_array_map_by_error() {
        let factors = json!(["account_number"]);
        let refusal = |status: u16, error: &str, message: &str| json!({ "statusCode": status, "error": error, "message": message, "stepUp": factors, "details": { "stepUp": factors } });
        // 409 hold_unavailable: the switch is off, or no session to tie it to.
        for message in [
            "A delayed deletion is not available. Nothing was deleted.",
            "We could not tie this request to your signed-in session. Sign in to the app again, then try again. Nothing was deleted.",
        ] {
            match classify(StatusCode::CONFLICT, &refusal(409, "hold_unavailable", message)) {
                GdprDeleteOutcome::Refused(ApiError::StepUp { kind, message: got }) => {
                    assert_eq!(kind, StepUpKind::HoldUnavailable);
                    assert_eq!(got, message);
                }
                other => panic!("{other:?}"),
            }
        }
        // 403 step_up_no_factor.
        assert!(matches!(
            classify(StatusCode::FORBIDDEN, &refusal(403, "step_up_no_factor", "We cannot verify this account for an in-app deletion. Please contact support to delete it.")),
            GdprDeleteOutcome::Refused(ApiError::StepUp { kind: StepUpKind::NoFactor, .. })
        ));
        // 503 step_up_unavailable: nothing was filed; not "server unavailable".
        assert!(matches!(
            classify(
                StatusCode::SERVICE_UNAVAILABLE,
                &refusal(
                    503,
                    "step_up_unavailable",
                    "We could not check your code just now. Please try again in a minute."
                )
            ),
            GdprDeleteOutcome::Refused(ApiError::StepUp {
                kind: StepUpKind::Unavailable,
                ..
            })
        ));
        // 403 two_factor_required / 401 wrong password: as #432 handles them.
        assert!(matches!(
            classify(
                StatusCode::FORBIDDEN,
                &refusal(
                    403,
                    "two_factor_required",
                    "Enter your two-factor code to delete your account."
                )
            ),
            GdprDeleteOutcome::Refused(ApiError::TwoFactorRequired(_))
        ));
        match classify(
            StatusCode::UNAUTHORIZED,
            &refusal(401, "Unauthorized", "Incorrect password"),
        ) {
            GdprDeleteOutcome::Refused(ApiError::Rejected {
                status: 401,
                message,
            }) => {
                assert_eq!(message, "Incorrect password")
            }
            other => panic!("{other:?}"),
        }
        // 429 too_many_attempts: a rate limit on the deletion path ...
        let capped = refusal(
            429,
            "too_many_attempts",
            "You have asked for a delayed deletion too many times today. Please try again tomorrow.",
        );
        let limited = classify(StatusCode::TOO_MANY_REQUESTS, &capped);
        assert!(matches!(
            limited,
            GdprDeleteOutcome::Refused(ApiError::RateLimited {
                retry_after_secs: None
            })
        ));
        // ... and on the hold path it keeps the sentence, which alone says
        // "tomorrow" (the 2FA lockout has the same `error`).
        match BirdoApi::hold_refusal_keeps_its_sentence(limited, &capped.to_string()) {
            GdprDeleteOutcome::Refused(ApiError::Rejected {
                status: 429,
                message,
            }) => {
                assert!(message.contains("tomorrow"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        // A 429 without a sentence stays the plain rate limit.
        assert!(matches!(
            BirdoApi::hold_refusal_keeps_its_sentence(
                GdprDeleteOutcome::Refused(ApiError::RateLimited {
                    retry_after_secs: None
                }),
                ""
            ),
            GdprDeleteOutcome::Refused(ApiError::RateLimited {
                retry_after_secs: None
            })
        ));
    }

    /// The hold request's own reading of a classified answer: a hold (a 202)
    /// is the result; any other 2xx, even a deletion-shaped one, is
    /// "unexpected, nothing assumed deleted", never a wipe and never a hold;
    /// refusals pass through.
    #[test]
    fn the_hold_request_accepts_only_a_hold() {
        let hold = DeletionHold {
            pending_change_id: HOLD_ID.into(),
            apply_after: APPLY_AFTER.into(),
            message: None,
            already_pending: false,
        };
        assert_eq!(
            BirdoApi::deletion_hold_from(GdprDeleteOutcome::Held(hold.clone())).unwrap(),
            hold
        );
        assert!(matches!(
            BirdoApi::deletion_hold_from(GdprDeleteOutcome::Deleted(Default::default())),
            Err(ApiError::Parse(_))
        ));
        assert!(matches!(
            BirdoApi::deletion_hold_from(GdprDeleteOutcome::SessionExpired),
            Err(ApiError::Unauthorized)
        ));
    }

    /// A session in memory, still exactly as `set_tokens` left it.
    async fn still_signed_in(api: &BirdoApi) -> bool {
        api.is_authenticated().await
            && api.access_token_value().await.as_deref() == Some("access-1")
    }

    /// No sign-out on a hold, by behaviour: with a session in memory, the
    /// server's real answers are classified and handed to the two methods of
    /// that signed-in client that end the requests (`finish_deletion_hold` for
    /// the hold request, `finish_gdpr_delete` for `delete_account`). Every hold
    /// answer (202, the 409s, an unreadable 202, an unexpected 2xx) leaves the
    /// access token and the session exactly as they were, through both; only a
    /// confirmed deletion (a plain 200) clears them. Either method clearing on
    /// a hold fails this test.
    #[tokio::test]
    async fn a_hold_leaves_the_tokens_and_the_session_untouched() {
        let api = BirdoApi::new();
        api.set_tokens("access-1".into(), "refresh-1".into()).await;
        assert!(still_signed_in(&api).await);
        let filed = json!({ "success": true, "pending": true, "code": "change_pending", "message": FILED, "stepUp": step_up_object() });
        let already = json!({ "statusCode": 409, "error": "change_already_pending", "message": ALREADY, "details": { "stepUp": step_up_object() } });
        let unnamed =
            json!({ "statusCode": 409, "error": "change_already_pending", "message": ALREADY });
        let unavailable = json!({ "statusCode": 409, "error": "hold_unavailable", "message": "x", "details": { "stepUp": ["account_number"] } });
        let unreadable = json!({ "success": true, "pending": true, "stepUp": ["account_number"] });
        for (status, body) in [
            (StatusCode::ACCEPTED, &filed),
            (StatusCode::CONFLICT, &already),
            (StatusCode::CONFLICT, &unnamed),
            (StatusCode::CONFLICT, &unavailable),
            (StatusCode::ACCEPTED, &unreadable),
            // Not the contract's answer to anything: nothing is assumed.
            (StatusCode::OK, &filed),
        ] {
            // The hold request's ending, on the signed-in client.
            let _ = api.finish_deletion_hold(classify(status, body)).await;
            assert!(still_signed_in(&api).await, "hold request: {status} {body}");
            // `delete_account`'s ending, given the same answer.
            assert!(
                api.finish_gdpr_delete(classify(status, body))
                    .await
                    .is_err(),
                "{status} {body} was accepted as a deletion"
            );
            assert!(
                still_signed_in(&api).await,
                "delete_account: {status} {body}"
            );
        }
        // A deletion-shaped 200 to a HOLD request: unexpected, nothing wiped.
        let deleted = json!({ "success": true, "message": "Your data has been deleted." });
        assert!(api
            .finish_deletion_hold(classify(StatusCode::OK, &deleted))
            .await
            .is_err());
        assert!(still_signed_in(&api).await);
        // The one answer that ends the session: a confirmed deletion.
        assert!(api
            .finish_gdpr_delete(classify(StatusCode::OK, &deleted))
            .await
            .is_ok());
        assert!(!api.is_authenticated().await);
        // And the hold request ends in the method driven above, never in
        // `delete_account`'s.
        const SOURCE: &str = include_str!("client.rs");
        let start = SOURCE.find("pub async fn request_deletion_hold(").unwrap();
        let hold = &SOURCE[start..];
        let hold = &hold[..hold.find("\n    }").unwrap()];
        assert!(hold.contains("self.finish_deletion_hold(outcome).await"));
        assert!(hold.contains("step_up_method: Some(\"hold\")"));
        assert!(!hold.contains("finish_gdpr_delete") && !hold.contains("clear_tokens"));
    }

    /// `GET /auth/pending-changes`, row by row; a row it cannot use is
    /// dropped, never the whole list.
    #[test]
    fn the_pending_change_list_decodes_leniently() {
        let rows = pending_changes_from(&json!({
            "pendingChanges": [
                { "id": HOLD_ID, "action": "account_delete", "description": "delete the account",
                  "applyAfter": APPLY_AFTER, "createdAt": "2026-11-14T12:00:00.000Z", "extra": 1 },
                { "id": "cmlink1", "action": "oauth_link", "description": "connect a new sign-in method",
                  "applyAfter": APPLY_AFTER, "createdAt": "2026-11-14T12:00:00.000Z", "detail": "Google j***@example.com" },
                { "action": "account_delete", "applyAfter": APPLY_AFTER },
                { "id": "a/b", "action": "account_delete" },
                { "id": "cmnoaction" },
                "not a row",
            ]
        }))
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, HOLD_ID);
        assert_eq!(rows[0].action, "account_delete");
        assert_eq!(rows[0].apply_after.as_deref(), Some(APPLY_AFTER));
        assert_eq!(rows[0].detail, None);
        assert_eq!(rows[1].detail.as_deref(), Some("Google j***@example.com"));
        assert_eq!(
            pending_changes_from(&json!({ "pendingChanges": [] })).unwrap(),
            vec![]
        );
        for bad in [
            json!([]),
            json!({}),
            json!({ "pendingChanges": {} }),
            json!(null),
        ] {
            assert!(pending_changes_from(&bad).is_none(), "{bad}");
        }
    }

    /// Cancel: the id goes into the path only once checked, and a 404
    /// `pending_change_not_found` (gone already) is told apart from any other
    /// 404.
    #[test]
    fn the_cancel_route_and_its_404() {
        assert_eq!(
            endpoints::pending_change_cancel(HOLD_ID),
            format!("/auth/pending-changes/{HOLD_ID}/cancel")
        );
        let gone = r#"{"statusCode":404,"error":"pending_change_not_found","message":"There is no such pending change on this account."}"#;
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::NOT_FOUND, gone),
            ApiError::PendingChangeNotFound
        ));
        let route_missing = r#"{"statusCode":404,"message":"Cannot POST /auth/pending-changes/x/cancel","error":"Not Found"}"#;
        assert!(!matches!(
            BirdoApi::classify_error_response(StatusCode::NOT_FOUND, route_missing),
            ApiError::PendingChangeNotFound
        ));
    }

    /// An id that could not be the server's never reaches the request.
    #[tokio::test]
    async fn a_malformed_id_is_never_sent() {
        let api = BirdoApi::new();
        let long = "x".repeat(65);
        for id in ["", "../x", "a b", "a?b=1", long.as_str()] {
            assert!(
                matches!(
                    api.cancel_pending_change(id).await,
                    Err(ApiError::Unknown(_))
                ),
                "{id:?}"
            );
        }
    }
}

#[cfg(test)]
mod error_display_tests {
    use super::super::error::ApiError;

    #[test]
    fn network_error_displays_message() {
        let err = ApiError::Network("timeout".to_string());
        assert_eq!(err.to_string(), "Network error: timeout");
    }

    #[test]
    fn not_authenticated_displays_message() {
        let err = ApiError::NotAuthenticated;
        assert_eq!(err.to_string(), "Not authenticated");
    }

    #[test]
    fn unauthorized_displays_message() {
        let err = ApiError::Unauthorized;
        assert_eq!(err.to_string(), "Authentication failed");
    }

    #[test]
    fn forbidden_displays_message() {
        let err = ApiError::Forbidden;
        assert_eq!(err.to_string(), "Access denied");
    }

    #[test]
    fn not_found_displays_message() {
        let err = ApiError::NotFound;
        assert_eq!(err.to_string(), "Not found");
    }

    #[test]
    fn rate_limited_displays_message() {
        let err = ApiError::RateLimited {
            retry_after_secs: Some(30),
        };
        assert_eq!(err.to_string(), "Too many requests, please slow down");
    }

    #[test]
    fn server_error_includes_status_code() {
        let err = ApiError::ServerError(503);
        assert_eq!(err.to_string(), "Server error (503)");
    }

    #[test]
    fn parse_error_displays_message() {
        let err = ApiError::Parse("invalid JSON".to_string());
        assert_eq!(err.to_string(), "Failed to parse response: invalid JSON");
    }

    #[test]
    fn unknown_error_displays_message() {
        let err = ApiError::Unknown("something broke".to_string());
        assert_eq!(err.to_string(), "Unknown error: something broke");
    }

    #[test]
    fn api_error_converts_to_string() {
        let err = ApiError::NotAuthenticated;
        let s: String = err.into();
        assert_eq!(s, "Not authenticated");
    }

    #[test]
    fn api_error_implements_std_error() {
        let err = ApiError::Unauthorized;
        // Verify it satisfies the std::error::Error trait bound
        let _: &dyn std::error::Error = &err;
    }
}

#[cfg(test)]
mod types_serialization_tests {
    use super::super::types::*;

    #[test]
    fn login_request_serializes_correctly() {
        let req = LoginRequest::new("user@test.com", "s3cret");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "user@test.com");
        assert_eq!(json["password"], "s3cret");
    }

    /// The desktop login body MUST carry a deviceId. Without it the backend's
    /// `isTrustedDevice` returns false unconditionally (trusted-device 2FA skip
    /// dead) and it falls back to hashing the User-Agent, which embeds the app
    /// version — so every update forked a new device row.
    ///
    /// Asserting equality with `utils::get_device_id()` (not merely "non-empty")
    /// is the point: it pins the login body to the SAME identity the SSO
    /// exchange and the anonymous flows send, so all of a machine's sign-ins
    /// land on one row that "revoke this device" can actually target.
    #[test]
    fn login_request_sends_the_shared_stable_device_id() {
        let json = serde_json::to_value(LoginRequest::new("user@test.com", "s3cret")).unwrap();
        let sent = json["deviceId"].as_str().expect("deviceId must be sent");

        assert!(!sent.is_empty(), "deviceId must not be blank");
        assert_eq!(
            sent,
            crate::utils::get_device_id(),
            "login must reuse the client-wide device identity, not a second scheme"
        );
        // DeviceInfoSchema caps deviceId at 128 chars; a body over the cap is
        // rejected with a 400 before the password is ever checked.
        assert!(sent.chars().count() <= 128);
    }

    /// The identity has to survive an app update and a restart. Re-deriving it
    /// must produce the same string, and it must not embed the app version —
    /// version-derived ids were exactly how the duplicate device rows appeared.
    #[test]
    fn login_device_id_is_stable_across_calls_and_app_versions() {
        let first = serde_json::to_value(LoginRequest::new("user@test.com", "s3cret")).unwrap();
        let second = serde_json::to_value(LoginRequest::new("user@test.com", "s3cret")).unwrap();
        assert_eq!(first["deviceId"], second["deviceId"]);

        let id = first["deviceId"].as_str().unwrap();
        assert!(
            !id.contains(env!("CARGO_PKG_VERSION")),
            "deviceId must not change when the app version does"
        );
    }

    /// `registerDevice` refreshes deviceName/platform on every upsert, so a
    /// login that sent only the id would relabel the row with the backend's
    /// generic "Desktop client" / UNKNOWN placeholders. The descriptors must
    /// ride along, in the exact camelCase keys DeviceInfoSchema expects, and
    /// within its length limits.
    #[test]
    fn login_request_sends_device_descriptors_within_schema_limits() {
        let json = serde_json::to_value(LoginRequest::new("user@test.com", "s3cret")).unwrap();

        assert_eq!(json["deviceType"], "DESKTOP");
        assert_eq!(json["platform"], crate::utils::device_platform());
        assert_eq!(json["appVersion"], env!("CARGO_PKG_VERSION"));

        let name = json["deviceName"]
            .as_str()
            .expect("deviceName must be sent");
        assert!(
            !name.is_empty() && name.chars().count() <= 100,
            "deviceName must satisfy DeviceInfoSchema's 1..=100 chars, got {} chars",
            name.chars().count()
        );
    }

    /// A hostname longer than the schema's 100-char cap, or a blank one, must
    /// not turn a valid login into a 400. Non-ASCII names must be cut on a char
    /// boundary rather than panicking on a byte slice.
    #[test]
    fn device_name_is_clamped_to_schema_bounds() {
        assert_eq!(super::super::types::clamp_device_name("  ", 100), "Desktop");
        assert_eq!(
            super::super::types::clamp_device_name("MACBOOK-PRO", 100),
            "MACBOOK-PRO"
        );

        let long = "é".repeat(200);
        let clamped = super::super::types::clamp_device_name(&long, 100);
        assert_eq!(clamped.chars().count(), 100);
    }

    #[test]
    fn refresh_request_serializes_correctly() {
        let req = RefreshRequest {
            refresh_token: "rt_abc123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("rt_abc123"));
    }

    #[test]
    fn token_pair_deserializes() {
        let json = r#"{"access_token":"at_xyz","refresh_token":"rt_xyz"}"#;
        let pair: TokenPair = serde_json::from_str(json).unwrap();
        assert_eq!(pair.access_token, "at_xyz");
        assert_eq!(pair.refresh_token, "rt_xyz");
    }

    #[test]
    fn login_result_deserializes_success() {
        let json = r#"{"ok":true,"tokens":{"access_token":"at","refresh_token":"rt"}}"#;
        let result: LoginResult = serde_json::from_str(json).unwrap();
        match result {
            LoginResult::Success { ok, tokens } => {
                assert!(ok);
                assert_eq!(tokens.access_token, "at");
            }
            _ => panic!("Expected LoginResult::Success"),
        }
    }

    #[test]
    fn login_result_deserializes_2fa_challenge() {
        let json = r#"{"requiresTwoFactor":true,"challengeToken":"ct_abc"}"#;
        let result: LoginResult = serde_json::from_str(json).unwrap();
        match result {
            LoginResult::TwoFactorChallenge {
                requires_two_factor,
                challenge_token,
            } => {
                assert!(requires_two_factor);
                assert_eq!(challenge_token, "ct_abc");
            }
            _ => panic!("Expected LoginResult::TwoFactorChallenge"),
        }
    }

    #[test]
    fn refresh_response_deserializes() {
        let json = r#"{"access_token":"new_at","expires_in":3600}"#;
        let resp: RefreshResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "new_at");
        assert_eq!(resp.expires_in, Some(3600));
    }

    /// Account API contract item 86: an old server's `/auth/me` (no new
    /// fields) says nothing about anonymity; a new one says it either way, and
    /// only the documented 24 digits count as an account number.
    #[test]
    fn auth_me_anonymity_fields_are_optional_and_validated() {
        let old: UserProfile = serde_json::from_str(r#"{"id":"u1","email":"a@b.com"}"#).unwrap();
        assert_eq!(old.is_anonymous_account(), None);
        assert!(old.account_number.is_none());

        let standard: UserProfile = serde_json::from_str(
            r#"{"id":"u2","email":"a@b.com","accountType":"standard","isAnonymous":false,"accountNumber":null}"#,
        )
        .unwrap();
        assert_eq!(standard.is_anonymous_account(), Some(false));
        assert!(standard.account_number.is_none());

        // accountType alone is enough.
        let typed: UserProfile =
            serde_json::from_str(r#"{"id":"u3","email":"x","accountType":"anonymous"}"#).unwrap();
        assert_eq!(typed.is_anonymous_account(), Some(true));

        let anon: UserProfile = serde_json::from_str(
            r#"{"id":"u4","email":"x","isAnonymous":true,"accountNumber":"123456789012345678901234"}"#,
        )
        .unwrap();
        assert_eq!(
            anon.account_number,
            super::super::types::AccountNumber::parse("123456789012345678901234")
        );
        assert!(!format!("{anon:?}").contains("123456789012345678901234"));

        for bad in [
            r#""12345""#,
            r#""1234 5678 9012 3456 7890 1234""#,
            "42",
            r#""abcdefghijklmnopqrstuvwx""#,
        ] {
            let user: UserProfile = serde_json::from_str(&format!(
                r#"{{"id":"u5","email":"x","accountNumber":{bad}}}"#
            ))
            .expect("a malformed number must not blank the identity");
            assert!(user.account_number.is_none(), "{bad}");
        }
    }

    /// MR-2258: the app no longer shows terms-change notices (owner,
    /// 2026-11-07: terms changes go out by e-mail and on the website). A
    /// server that still sends `termsNotices` must not cost the profile:
    /// the key is ignored whatever it holds.
    #[test]
    fn a_profile_that_still_names_terms_notices_parses_as_before() {
        let notice = r#"{"version":"2026-10-30","text":"We have changed our Terms.","effectiveAt":"2026-12-05T00:00:00.000Z","path":"/legal/changes"}"#;
        for value in [
            format!("[{notice}]"),
            "[]".to_string(),
            "null".to_string(),
            r#""soon""#.to_string(),
            notice.to_string(),
        ] {
            let user: UserProfile = serde_json::from_str(&format!(
                r#"{{"id":"u6","email":"a@b.com","plan":"OPERATIVE","termsNotices":{value}}}"#
            ))
            .unwrap_or_else(|e| panic!("termsNotices {value} failed the profile: {e}"));
            assert_eq!(user.id, "u6", "{value}");
            assert_eq!(user.email.as_deref(), Some("a@b.com"), "{value}");
            assert!(
                !serde_json::to_string(&user)
                    .unwrap()
                    .contains("termsNotices"),
                "{value}"
            );
        }
    }

    #[test]
    fn user_profile_uses_camel_case() {
        let json = r#"{
            "id": "u1",
            "email": "a@b.com",
            "name": "Alice",
            "emailVerified": true,
            "createdAt": "2026-01-01"
        }"#;
        let user: UserProfile = serde_json::from_str(json).unwrap();
        assert!(user.email_verified);
        assert_eq!(user.created_at, Some("2026-01-01".to_string()));
    }

    /// Parse the EXACT shape the live `GET /auth/me` returns.
    ///
    /// The test above is a fiction: it feeds a hand-written payload containing
    /// `name` and `createdAt`, neither of which the real endpoint sends. A test
    /// that only ever sees an invented payload cannot catch a contract drift
    /// between client and server, so this one pins the real thing instead.
    ///
    /// Keep this payload in lock-step with `auth.controller.ts` `@Get("me")`:
    /// it omits `name`/`createdAt` and carries extra subscription fields that
    /// the client must ignore rather than choke on. If someone later adds a
    /// field to `UserProfile` WITHOUT a default, or the server drops a field
    /// this struct requires, this test fails instead of the app silently
    /// rendering a signed-in user with a blank identity.
    #[test]
    fn user_profile_parses_real_auth_me_payload() {
        let json = r#"{
            "id": "cmnz74oyc0000o001dgr9gwec",
            "email": "someone@gmail.com",
            "role": "USER",
            "emailVerified": true,
            "plan": "recon",
            "status": "active",
            "expiresAt": null,
            "devicesUsed": 1,
            "devicesLimit": 1,
            "bandwidthLimit": 10737418240,
            "hasPassword": false,
            "isSSO": true
        }"#;
        let user: UserProfile = serde_json::from_str(json)
            .expect("the live /auth/me payload must deserialize — a strict field here blanks the user's identity");
        // The identity the whole app hangs off of.
        assert_eq!(user.email.as_deref(), Some("someone@gmail.com"));
        assert_eq!(user.id, "cmnz74oyc0000o001dgr9gwec");
        // Absent optional fields must degrade to None, not fail the parse.
        assert_eq!(user.name, None);
        assert_eq!(user.created_at, None);
        assert!(user.email_verified);
        // Casing traps: the backend sends `hasPassword` (matches camelCase) but
        // `isSSO` (does NOT — camelCase derives `isSso`). Both are `#[serde(default)]`,
        // so a mismatch yields a silently WRONG value rather than an error. Assert
        // the values, not just that parsing succeeded.
        assert!(
            !user.has_password,
            "hasPassword must be read, not defaulted"
        );
        assert!(
            user.is_sso,
            "isSSO must be read via alias — camelCase alone derives `isSso` and would \
             silently leave every SSO account looking like a password account"
        );
    }

    #[test]
    fn vpn_server_deserializes_with_camel_case() {
        let json = r#"{
            "id": "s1", "name": "US East", "country": "United States",
            "countryCode": "US", "city": "New York", "hostname": "us-east.birdo.app",
            "ipAddress": "1.2.3.4", "port": 51820, "load": 45,
            "minPlan": "OPERATIVE", "isPremium": true,
            "isHighSpeed": true, "isPortForwarding": true, "isOnline": true
        }"#;
        let server: VpnServer = serde_json::from_str(json).unwrap();
        assert_eq!(server.country_code, "US");
        assert!(server.is_premium);
        assert_eq!(server.min_plan.as_deref(), Some("OPERATIVE"));
        assert!(server.is_high_speed);
        assert!(server.is_port_forwarding);
        assert!(server.is_online);
        assert_eq!(server.port, Some(51820));
    }

    #[test]
    fn vpn_server_deserializes_public_listing_shape() {
        // `tier` is derived+deprecated and `isStreaming`/`isP2p` are hard-coded
        // deprecated literals the backend still emits for already-shipped
        // clients. All three must decode-and-ignore cleanly here.
        let json = r#"{
            "id": "s1", "name": "US East", "region": "us-east",
            "country": "United States", "countryCode": "US", "city": "New York",
            "load": 45, "tier": "FREE", "minPlan": "RECON", "isPremium": false,
            "isHighSpeed": true, "isPortForwarding": false,
            "isStreaming": false, "isP2p": false,
            "isOnline": true, "accessible": true
        }"#;
        let server: VpnServer = serde_json::from_str(json).unwrap();
        assert_eq!(server.country_code, "US");
        assert_eq!(server.hostname, None);
        assert_eq!(server.ip_address, None);
        assert_eq!(server.port, None);
        assert_eq!(server.min_plan.as_deref(), Some("RECON"));
        assert!(server.is_high_speed);
        assert!(!server.is_port_forwarding);
        assert!(server.accessible);
    }

    /// A pre-minPlan backend omits every new field. The client must still
    /// decode, fail closed on the tags, and leave `accessible` at its default.
    #[test]
    fn vpn_server_tolerates_legacy_payload_without_new_fields() {
        let json = r#"{
            "id": "s1", "name": "US East", "country": "United States",
            "countryCode": "US", "city": "New York", "load": 45,
            "isStreaming": true, "isP2p": true, "isOnline": true
        }"#;
        let server: VpnServer = serde_json::from_str(json).unwrap();
        assert_eq!(server.min_plan, None);
        assert!(!server.is_high_speed);
        assert!(!server.is_port_forwarding);
        assert!(server.accessible);
    }

    // MR-822: `vpn_config_optional_fields_default_correctly` decoded a
    // `VpnConfig` (private key included) from JSON. Nothing does that in the
    // app: the server sends a `ConnectResponse`, and the config is built from
    // it. `VpnConfig` is no longer `Deserialize`, so the test went with it.

    #[test]
    fn connect_request_skips_none_fields() {
        let req = ConnectRequest {
            server_node_id: Some("node-1".to_string()),
            device_name: None,
            preferred_region: None,
            device_id: None,
            client_public_key: None,
            stealth_mode: None,
            fallback_reason: None,
            quantum_protection: None,
            pq_client_public_key: None,
            pq_client_can_decapsulate: None,
            dns_filtering: None,
            desktop_attest_nonce: None,
            desktop_attest_kid: None,
            desktop_attest_sig: None,
            desktop_attest_platform: None,
            desktop_attest_version: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["serverNodeId"], "node-1");
        assert!(json.get("deviceName").is_none());
        assert!(json.get("preferredRegion").is_none());
        // An ordinary connect must not carry the Adaptive Transport signal.
        assert!(json.get("fallbackReason").is_none());
    }

    /// ADAPTIVE TRANSPORT: the fallback signal must serialize under the exact
    /// camelCase key and wire value the backend's ConnectDto enum pins —
    /// anything else 400s the retry and strands a censored user.
    #[test]
    fn connect_request_serializes_fallback_reason_in_camel_case() {
        let req = ConnectRequest {
            server_node_id: Some("node-1".to_string()),
            device_name: None,
            preferred_region: None,
            device_id: None,
            client_public_key: None,
            stealth_mode: None,
            fallback_reason: Some(crate::commands::vpn::FALLBACK_HANDSHAKE_TIMEOUT.to_string()),
            quantum_protection: None,
            pq_client_public_key: None,
            pq_client_can_decapsulate: None,
            dns_filtering: None,
            desktop_attest_nonce: None,
            desktop_attest_kid: None,
            desktop_attest_sig: None,
            desktop_attest_platform: None,
            desktop_attest_version: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["fallbackReason"], "handshake-timeout");
    }

    /// A build without the attestation key must emit the pre-attestation body
    /// byte-for-byte — no empty/null desktopAttest* keys.
    #[test]
    fn connect_request_without_attestation_omits_all_attest_fields() {
        let req = ConnectRequest {
            server_node_id: Some("node-1".to_string()),
            device_name: Some("desktop".to_string()),
            preferred_region: None,
            device_id: None,
            client_public_key: Some("pub=".to_string()),
            stealth_mode: Some(false),
            fallback_reason: None,
            quantum_protection: Some(false),
            pq_client_public_key: None,
            pq_client_can_decapsulate: None,
            dns_filtering: None,
            desktop_attest_nonce: None,
            desktop_attest_kid: None,
            desktop_attest_sig: None,
            desktop_attest_platform: None,
            desktop_attest_version: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"serverNodeId":"node-1","deviceName":"desktop","clientPublicKey":"pub=","stealthMode":false,"quantumProtection":false}"#
        );
    }

    #[test]
    fn connect_request_serializes_attestation_in_camel_case() {
        let req = ConnectRequest {
            server_node_id: Some("node-1".to_string()),
            device_name: None,
            preferred_region: None,
            device_id: None,
            client_public_key: None,
            stealth_mode: None,
            fallback_reason: None,
            quantum_protection: None,
            pq_client_public_key: None,
            pq_client_can_decapsulate: None,
            dns_filtering: None,
            desktop_attest_nonce: Some("nonce".to_string()),
            desktop_attest_kid: Some("desk-2026-07".to_string()),
            desktop_attest_sig: Some("sig".to_string()),
            desktop_attest_platform: Some("windows".to_string()),
            desktop_attest_version: Some("1.4.11".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["desktopAttestNonce"], "nonce");
        assert_eq!(json["desktopAttestKid"], "desk-2026-07");
        assert_eq!(json["desktopAttestSig"], "sig");
        assert_eq!(json["desktopAttestPlatform"], "windows");
        assert_eq!(json["desktopAttestVersion"], "1.4.11");
    }

    #[test]
    fn multi_hop_request_without_attestation_omits_all_attest_fields() {
        let req = MultiHopConnectRequest {
            entry_node_id: "entry".to_string(),
            exit_node_id: "exit".to_string(),
            device_id: None,
            device_name: None,
            client_public_key: None,
            stealth_mode: None,
            quantum_protection: None,
            pq_client_public_key: None,
            pq_client_can_decapsulate: None,
            dns_filtering: None,
            desktop_attest_nonce: None,
            desktop_attest_kid: None,
            desktop_attest_sig: None,
            desktop_attest_platform: None,
            desktop_attest_version: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"entryNodeId":"entry","exitNodeId":"exit"}"#);
    }

    // ------------------------------------------------------------------
    // OPEN-WORK G5: BirdoPQ HNDL opt-in. These assert the SERIALIZED body,
    // not the struct — the backend whitelist (connect.dto.ts) and the
    // multi-hop zod schema (vpn.controller.ts) both pin the exact key
    // `pqClientCanDecapsulate`; a snake_case or misspelt key is silently
    // stripped by class-validator and the server falls back to returning the
    // PSK over TLS, which is the very hole the flag closes.
    // ------------------------------------------------------------------

    fn pq_connect_request(pq: Option<String>, can: Option<bool>) -> ConnectRequest {
        ConnectRequest {
            server_node_id: Some("node-1".to_string()),
            device_name: None,
            preferred_region: None,
            device_id: None,
            client_public_key: None,
            stealth_mode: None,
            fallback_reason: None,
            quantum_protection: pq.as_ref().map(|_| true),
            pq_client_public_key: pq,
            pq_client_can_decapsulate: can,
            dns_filtering: None,
            desktop_attest_nonce: None,
            desktop_attest_kid: None,
            desktop_attest_sig: None,
            desktop_attest_platform: None,
            desktop_attest_version: None,
        }
    }

    fn pq_multi_hop_request(pq: Option<String>, can: Option<bool>) -> MultiHopConnectRequest {
        MultiHopConnectRequest {
            entry_node_id: "entry".to_string(),
            exit_node_id: "exit".to_string(),
            device_id: None,
            device_name: None,
            client_public_key: None,
            stealth_mode: None,
            quantum_protection: pq.as_ref().map(|_| true),
            pq_client_public_key: pq,
            pq_client_can_decapsulate: can,
            dns_filtering: None,
            desktop_attest_nonce: None,
            desktop_attest_kid: None,
            desktop_attest_sig: None,
            desktop_attest_platform: None,
            desktop_attest_version: None,
        }
    }

    #[test]
    fn connect_request_carries_pq_can_decapsulate_when_set() {
        let req = pq_connect_request(Some("pk".to_string()), Some(true));
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["pqClientCanDecapsulate"], true);
        assert_eq!(json["pqClientPublicKey"], "pk");
        // Exact key spelling — the only spelling the backend whitelist accepts.
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert!(
            keys.contains(&&"pqClientCanDecapsulate".to_string()),
            "{keys:?}"
        );
        assert!(!json.to_string().contains("pq_client_can_decapsulate"));
    }

    /// A non-PQ connect body must stay byte-identical to the 1.4.41 body —
    /// no `pqClientCanDecapsulate:null` / `false` key for the backend to trip on.
    #[test]
    fn connect_request_omits_pq_can_decapsulate_when_none() {
        let req = pq_connect_request(None, None);
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"serverNodeId":"node-1"}"#);
    }

    #[test]
    fn multi_hop_request_carries_pq_can_decapsulate_when_set() {
        let req = pq_multi_hop_request(Some("pk".to_string()), Some(true));
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["pqClientCanDecapsulate"], true);
        assert_eq!(json["pqClientPublicKey"], "pk");
        assert!(!json.to_string().contains("pq_client_can_decapsulate"));
    }

    #[test]
    fn multi_hop_request_omits_pq_can_decapsulate_when_none() {
        let req = pq_multi_hop_request(None, None);
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"entryNodeId":"entry","exitNodeId":"exit"}"#);
    }

    /// The single rule both builders use: the flag follows the key exactly.
    #[test]
    fn pq_can_decapsulate_follows_public_key() {
        use super::super::client::pq_can_decapsulate;
        assert_eq!(pq_can_decapsulate(&None), None);
        assert_eq!(pq_can_decapsulate(&Some("x".to_string())), Some(true));
        // Never Some(false): the backend's compat default IS "absent".
        assert_ne!(pq_can_decapsulate(&Some(String::new())), Some(false));
    }

    #[test]
    fn attestation_nonce_response_deserializes() {
        let resp: AttestationNonceResponse = serde_json::from_str(r#"{"nonce":"abc123"}"#).unwrap();
        assert_eq!(resp.nonce, "abc123");
    }

    #[test]
    fn connect_response_handles_all_optional_fields() {
        let json = r#"{"success":true}"#;
        let resp: ConnectResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert!(resp.key_id.is_none());
        assert!(resp.dns.is_none());
        assert!(resp.server_node.is_none());
    }

    #[test]
    fn subscription_status_deserializes() {
        let json = r#"{
            "plan": "OPERATIVE", "status": "ACTIVE",
            "expiresAt": "2026-12-31", "devicesUsed": 2,
            "devicesLimit": 5,
            "bandwidthLimit": 10737418240
        }"#;
        let status: SubscriptionStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.plan, "OPERATIVE");
        assert_eq!(status.devices_used, 2);
        assert_eq!(status.bandwidth_limit, Some(10737418240));
    }

    /// `GET /api/client-config` → `dnsFilteringAvailable` (the BirdoShield
    /// fleet gate). Three shapes, and the difference between them is the whole
    /// point of the field being `Option<bool>`:
    ///
    ///   true  -> gate on, the toggle can do something
    ///   false -> gate off, the toggle must read OFF and be disabled
    ///   absent -> UNKNOWN (older web deploy), which is NOT false
    ///
    /// If the absent case ever deserialized as `Some(false)` — or failed to
    /// deserialize, which the UI treats the same way as a network error — every
    /// client talking to a pre-#465 web deploy would hide a feature that works.
    #[test]
    fn client_config_dns_filtering_available_distinguishes_false_from_absent() {
        let on: ClientConfigResponse =
            serde_json::from_str(r#"{"dnsFilteringAvailable":true}"#).unwrap();
        assert_eq!(on.dns_filtering_available, Some(true));

        let off: ClientConfigResponse =
            serde_json::from_str(r#"{"dnsFilteringAvailable":false}"#).unwrap();
        assert_eq!(off.dns_filtering_available, Some(false));

        // Pre-#465 web deploy: the key does not exist at all.
        let absent: ClientConfigResponse = serde_json::from_str(r#"{"version":1}"#).unwrap();
        assert_eq!(absent.dns_filtering_available, None);
    }

    /// The real payload carries cert pins, per-plan feature maps and consent
    /// copy this client does not model. Unknown fields must be IGNORED, not
    /// rejected: a strict struct here would turn every future web-side addition
    /// into a silent "gate unknown" for every shipped desktop build.
    #[test]
    fn client_config_ignores_the_fields_it_does_not_model() {
        let json = r#"{
            "version": 1,
            "certPins": { "hosts": { "birdo.app": {} } },
            "dnsFilteringAvailable": false,
            "features": { "RECON": { "dnsFiltering": true } },
            "consent": { "vpnDisclaimer": "..." },
            "minimumVersions": { "windows": "1.0.0" }
        }"#;
        let cfg: ClientConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_filtering_available, Some(false));
    }

    /// Account API contract item 40 (owner decision D6): `features.<PLAN>.
    /// customDns`. Today's server sends no such flag, which must read as "not
    /// said" (enabled); a new one sends `true` for every plan; only an explicit
    /// `false` is a `false`, and a flag of an unexpected shape never takes the
    /// rest of the config down with it.
    #[test]
    fn client_config_custom_dns_is_per_plan_and_optional() {
        let today: ClientConfigResponse = serde_json::from_str(
            r#"{"dnsFilteringAvailable":true,"features":{"RECON":{"dnsFiltering":true}}}"#,
        )
        .unwrap();
        assert_eq!(today.features.unwrap()["RECON"], PlanFeatures::default());
        let no_map: ClientConfigResponse = serde_json::from_str(r#"{"version":1}"#).unwrap();
        assert!(no_map.features.is_none());

        let new: ClientConfigResponse = serde_json::from_str(
            r#"{"features":{"RECON":{"customDns":true},"OPERATIVE":{"customDns":true},"SOVEREIGN":{"customDns":false}}}"#,
        )
        .unwrap();
        let features = new.features.as_ref().unwrap();
        assert_eq!(features["RECON"].custom_dns, Some(true));
        assert_eq!(features["SOVEREIGN"].custom_dns, Some(false));

        let odd: ClientConfigResponse = serde_json::from_str(
            r#"{"dnsFilteringAvailable":false,"features":{"RECON":{"customDns":"yes"},"OPERATIVE":7}}"#,
        )
        .unwrap();
        assert_eq!(odd.dns_filtering_available, Some(false));
        let features = odd.features.unwrap();
        assert_eq!(features["RECON"].custom_dns, None);
        assert_eq!(features["OPERATIVE"].custom_dns, None);
        let not_a_map: ClientConfigResponse =
            serde_json::from_str(r#"{"dnsFilteringAvailable":true,"features":[1]}"#).unwrap();
        assert_eq!(not_a_map.dns_filtering_available, Some(true));
        assert!(not_a_map.features.is_none());

        // What the UI receives: the same camelCase shape the server sent.
        assert_eq!(
            serde_json::to_value(&new).unwrap()["features"]["SOVEREIGN"],
            serde_json::json!({ "customDns": false })
        );
    }

    /// MR-1517: the server's plan-gating table reaches the UI, flag by flag,
    /// as the server sent it (birdo-web route.ts: Stealth from OPERATIVE,
    /// Multi-Hop and Port Forwarding on SOVEREIGN). A flag it did not send, or
    /// one of another shape, is "not said" and leaves the UI's own default.
    #[test]
    fn client_config_carries_the_plan_gating_table() {
        let cfg: ClientConfigResponse = serde_json::from_str(
            r#"{"features":{
                "RECON":{"customDns":true,"stealthMode":false,"multiHop":false,"portForwarding":false,"splitTunneling":true},
                "OPERATIVE":{"customDns":true,"stealthMode":true,"multiHop":false,"portForwarding":false},
                "SOVEREIGN":{"customDns":true,"stealthMode":true,"multiHop":true,"portForwarding":"yes"}
            }}"#,
        )
        .unwrap();
        let features = cfg.features.as_ref().unwrap();
        assert_eq!(features["RECON"].stealth_mode, Some(false));
        assert_eq!(features["OPERATIVE"].stealth_mode, Some(true));
        assert_eq!(features["OPERATIVE"].multi_hop, Some(false));
        assert_eq!(features["SOVEREIGN"].multi_hop, Some(true));
        assert_eq!(features["SOVEREIGN"].port_forwarding, None, "not a boolean");
        let wire = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            wire["features"]["OPERATIVE"],
            serde_json::json!({
                "customDns": true,
                "stealthMode": true,
                "multiHop": false,
                "portForwarding": false
            })
        );
        assert_eq!(
            wire["features"]["SOVEREIGN"],
            serde_json::json!({ "customDns": true, "stealthMode": true, "multiHop": true })
        );
    }

    /// birdo-web #708 serialises `plans` like this (lib/plans.ts through
    /// app/api/client-config/route.ts): one entry per plan, the yearly price
    /// an ANNUAL total, a `null` cap for unlimited.
    const PLANS_708: &str = r#"{
        "dnsFilteringAvailable": true,
        "plans": {
            "RECON": { "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP", "bandwidthLimitGb": 50 },
            "OPERATIVE": { "monthlyPrice": 3.99, "yearlyPrice": 38, "currency": "GBP", "bandwidthLimitGb": null },
            "SOVEREIGN": { "monthlyPrice": 9.99, "yearlyPrice": 99, "currency": "GBP", "bandwidthLimitGb": null }
        }
    }"#;

    /// MR-132 / MR-630 / MR-1767 / MR-1979: the server's prices reach the UI
    /// as sent, in the camelCase shape the Pricing screen reads, with a
    /// `null` cap kept as `null` (unlimited), never dropped or zeroed.
    #[test]
    fn client_config_plans_present_parse_and_reach_the_ui_unchanged() {
        let cfg: ClientConfigResponse = serde_json::from_str(PLANS_708).unwrap();
        let plans = cfg.plans.as_ref().unwrap();
        assert_eq!(plans.len(), 3);
        assert_eq!(
            plans["RECON"],
            PlanPrice {
                monthly_price: 0.0,
                yearly_price: 0.0,
                currency: "GBP".into(),
                bandwidth_limit_gb: Some(50),
            }
        );
        assert_eq!(plans["OPERATIVE"].monthly_price, 3.99);
        assert_eq!(plans["OPERATIVE"].yearly_price, 38.0);
        assert_eq!(plans["SOVEREIGN"].bandwidth_limit_gb, None);
        assert_eq!(cfg.dns_filtering_available, Some(true));

        let ui = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            ui["plans"]["RECON"],
            serde_json::json!({ "monthlyPrice": 0.0, "yearlyPrice": 0.0, "currency": "GBP", "bandwidthLimitGb": 50 })
        );
        assert_eq!(
            ui["plans"]["SOVEREIGN"],
            serde_json::json!({ "monthlyPrice": 9.99, "yearlyPrice": 99.0, "currency": "GBP", "bandwidthLimitGb": null })
        );
    }

    /// An older web deploy has no `plans`: that is "not said" (the UI falls
    /// back to its built-in prices), and the rest of the config still parses.
    #[test]
    fn client_config_plans_absent_or_not_an_object_reads_as_not_said() {
        let absent: ClientConfigResponse =
            serde_json::from_str(r#"{"dnsFilteringAvailable":false}"#).unwrap();
        assert!(absent.plans.is_none());
        assert_eq!(absent.dns_filtering_available, Some(false));
        assert!(serde_json::to_value(&absent).unwrap()["plans"].is_null());

        for odd in [r#"null"#, r#"[1,2]"#, r#""GBP""#, r#"7"#] {
            let json = format!(r#"{{"dnsFilteringAvailable":true,"plans":{odd}}}"#);
            let cfg: ClientConfigResponse = serde_json::from_str(&json).unwrap();
            assert!(cfg.plans.is_none(), "plans = {odd}");
            assert_eq!(cfg.dns_filtering_available, Some(true), "plans = {odd}");
        }
    }

    /// A malformed entry is dropped on its own: the other plans, and the rest
    /// of the config, survive it. Each case breaks exactly one rule.
    #[test]
    fn client_config_plans_malformed_entries_are_dropped_not_fatal() {
        let ok = r#"{ "monthlyPrice": 3.99, "yearlyPrice": 38, "currency": "GBP", "bandwidthLimitGb": null }"#;
        let bad = [
            // prices: missing, negative, not a number
            r#"{ "yearlyPrice": 38, "currency": "GBP", "bandwidthLimitGb": null }"#,
            r#"{ "monthlyPrice": -1, "yearlyPrice": 38, "currency": "GBP", "bandwidthLimitGb": null }"#,
            r#"{ "monthlyPrice": 3.99, "yearlyPrice": "38", "currency": "GBP", "bandwidthLimitGb": null }"#,
            r#"{ "monthlyPrice": 3.99, "yearlyPrice": null, "currency": "GBP", "bandwidthLimitGb": null }"#,
            // the cap: missing, zero, negative, fractional, absurd, not a number
            r#"{ "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP" }"#,
            r#"{ "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP", "bandwidthLimitGb": 0 }"#,
            r#"{ "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP", "bandwidthLimitGb": -50 }"#,
            r#"{ "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP", "bandwidthLimitGb": 50.5 }"#,
            r#"{ "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP", "bandwidthLimitGb": 100001 }"#,
            r#"{ "monthlyPrice": 0, "yearlyPrice": 0, "currency": "GBP", "bandwidthLimitGb": "50" }"#,
            // not an object at all
            r#"null"#,
            r#"[3.99, 38]"#,
        ];
        for entry in bad {
            let json = format!(
                r#"{{"dnsFilteringAvailable":false,"plans":{{"RECON":{entry},"OPERATIVE":{ok}}}}}"#
            );
            let cfg: ClientConfigResponse = serde_json::from_str(&json).unwrap();
            let plans = cfg.plans.unwrap();
            assert!(
                !plans.contains_key("RECON"),
                "kept a malformed entry: {entry}"
            );
            assert_eq!(
                plans["OPERATIVE"].yearly_price, 38.0,
                "lost a good entry beside {entry}"
            );
            assert_eq!(cfg.dns_filtering_available, Some(false));
        }

        // The edges that ARE valid: a cap at the limit, a whole-number cap
        // written as a float, and a zero price.
        let json = format!(
            r#"{{"plans":{{"RECON":{{"monthlyPrice":0,"yearlyPrice":0.0,"currency":"GBP","bandwidthLimitGb":{MAX_PLAN_BANDWIDTH_GB}}},"SOVEREIGN":{{"monthlyPrice":9.99,"yearlyPrice":99,"currency":"GBP","bandwidthLimitGb":50.0}}}}}}"#
        );
        let plans = serde_json::from_str::<ClientConfigResponse>(&json)
            .unwrap()
            .plans
            .unwrap();
        assert_eq!(
            plans["RECON"].bandwidth_limit_gb,
            Some(MAX_PLAN_BANDWIDTH_GB)
        );
        assert_eq!(plans["SOVEREIGN"].bandwidth_limit_gb, Some(50));
    }

    /// Only RECON, OPERATIVE and SOVEREIGN are read; any other key is
    /// ignored, including a known plan in the wrong case.
    #[test]
    fn client_config_plans_unknown_keys_are_ignored() {
        let entry = r#"{ "monthlyPrice": 1, "yearlyPrice": 10, "currency": "GBP", "bandwidthLimitGb": null }"#;
        let json = format!(
            r#"{{"plans":{{"OPERATIVE":{entry},"ENTERPRISE":{entry},"operative":{entry},"":{entry}}}}}"#
        );
        let plans = serde_json::from_str::<ClientConfigResponse>(&json)
            .unwrap()
            .plans
            .unwrap();
        assert_eq!(plans.keys().collect::<Vec<_>>(), ["OPERATIVE"]);
    }

    /// The currency is ISO 4217's shape, three letters, upper-cased on the
    /// way through; anything else drops the entry (the UI hands it to
    /// `Intl.NumberFormat`, which throws on a malformed code).
    #[test]
    fn client_config_plans_currency_is_three_letters() {
        let with = |currency: &str| {
            let json = format!(
                r#"{{"plans":{{"OPERATIVE":{{"monthlyPrice":4.5,"yearlyPrice":45,"currency":{currency},"bandwidthLimitGb":null}}}}}}"#
            );
            serde_json::from_str::<ClientConfigResponse>(&json)
                .unwrap()
                .plans
                .unwrap()
                .get("OPERATIVE")
                .map(|p| p.currency.clone())
        };
        assert_eq!(with(r#""EUR""#).as_deref(), Some("EUR"));
        assert_eq!(with(r#""usd""#).as_deref(), Some("USD"));
        for bad in [
            r#""""#,
            r#""GB""#,
            r#""GBPX""#,
            r#""£££""#,
            r#""G1P""#,
            r#""€""#,
            r#"null"#,
            r#"826"#,
        ] {
            assert_eq!(with(bad), None, "currency {bad}");
        }
    }

    /// The in-app anonymous-registration body must serialize with the exact
    /// camelCase keys the backend's DeviceInfoSchema expects.
    #[test]
    fn anonymous_register_request_serializes_camel_case() {
        let req = AnonymousRegisterRequest {
            device_id: "dev-123".to_string(),
            device_name: Some("Birdo PC".to_string()),
            device_type: "DESKTOP".to_string(),
            platform: "WINDOWS".to_string(),
            app_version: Some("1.4.18".to_string()),
            pow: None,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        // No proof, no `pow` key: the server reads that as the legacy tier.
        assert!(v.get("pow").is_none());
        assert_eq!(v["deviceId"], "dev-123");
        assert_eq!(v["deviceName"], "Birdo PC");
        assert_eq!(v["deviceType"], "DESKTOP");
        assert_eq!(v["platform"], "WINDOWS");
        assert_eq!(v["appVersion"], "1.4.18");
    }

    /// The /vpn/stats usage payload must deserialize, and its bandwidth fields
    /// must stay nullable — a plan with no cap / a node that never synced leaves
    /// them null so the UI can show "unlimited" / "awaiting first sync" rather
    /// than a misleading 0.
    #[test]
    fn usage_stats_deserializes_with_nullable_bandwidth() {
        let full = r#"{
            "plan": "RECON", "status": "ACTIVE",
            "bandwidthLimitGb": 10.0, "bandwidthUsedGb": 3.5,
            "bandwidthPeriodEnd": "2026-08-01T00:00:00Z",
            "bandwidthLastSyncAt": "2026-07-19T12:00:00Z",
            "bandwidthIsFresh": true
        }"#;
        let s: UsageStats = serde_json::from_str(full).unwrap();
        assert_eq!(s.bandwidth_limit_gb, Some(10.0));
        assert_eq!(s.bandwidth_used_gb, Some(3.5));
        assert_eq!(s.bandwidth_is_fresh, Some(true));

        // Unlimited plan / never-synced node: bandwidth fields absent or null.
        let sparse = r#"{ "plan": "SOVEREIGN", "bandwidthLimitGb": null }"#;
        let s2: UsageStats = serde_json::from_str(sparse).unwrap();
        assert_eq!(s2.bandwidth_limit_gb, None);
        assert_eq!(s2.bandwidth_used_gb, None);
        assert_eq!(s2.bandwidth_is_fresh, None);
    }
}

#[cfg(test)]
mod vpn_config_security_tests {
    //! MR-822. What a type can say is asserted at compile time beside the
    //! types: `VpnConfig` has no private-key field and is not `Clone` or
    //! `Serialize`; `WgPrivateKey` is not `Clone`, `Copy`, `Serialize` or
    //! `Deserialize`. These tests cover what a type cannot say: what `Debug`
    //! prints.
    use super::super::types::VpnConfig;
    use crate::vpn::WgPrivateKey;
    use zeroize::Zeroize;

    fn make_test_config() -> VpnConfig {
        VpnConfig {
            server_id: "s1".to_string(),
            key_id: "k1".to_string(),
            public_key: "pub".to_string(),
            server_public_key: "server_pub".to_string(),
            preshared_key: Some("PRESHARED_SECRET".to_string()),
            endpoint: "1.2.3.4:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            dns: vec!["1.1.1.1".to_string()],
            custom_dns: false,
            client_ip: "10.0.0.2".to_string(),
            client_ipv6: None,
            allowed_ips_v6: Vec::new(),
            mtu: 1420,
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn debug_prints_no_secret_and_no_connection_history() {
        let config = make_test_config();
        for printed in [format!("{config:?}"), format!("{config:#?}")] {
            for hidden in ["PRESHARED_SECRET", "1.2.3.4", "10.0.0.2", "private_key"] {
                assert!(!printed.contains(hidden), "`{hidden}` in {printed}");
            }
            assert!(printed.contains("\"s1\""), "the ids still print: {printed}");
        }
    }

    /// The attempt's key travels beside the config, not inside it
    /// (`VpnManager::connect`). Printed together, as a careless
    /// `tracing::debug!(?config, ?key)` would print them, neither leaks.
    /// (`vpn::wireguard_new::private_key_tests` checks the key's own bytes
    /// against what it prints.)
    #[test]
    fn the_key_beside_the_config_prints_redacted() {
        let key = WgPrivateKey::generate();
        assert_eq!(format!("{key:?}"), "[REDACTED]");
        let pair = format!("{:#?}", (make_test_config(), &key));
        assert!(pair.contains("[REDACTED]"), "{pair}");
        assert!(!pair.contains("PRESHARED_SECRET"), "{pair}");
    }

    #[test]
    fn drop_zeroes_all_key_material() {
        // We can't directly test Drop, but we can test that zeroize works
        let mut key = "test_key_material".to_string();
        key.zeroize();
        assert!(key.bytes().all(|b| b == 0));
    }
}

#[cfg(test)]
mod client_construction_tests {
    use super::super::client::BirdoApi;

    #[tokio::test]
    async fn new_client_is_unauthenticated() {
        let api = BirdoApi::new();
        assert!(!api.is_authenticated().await);
    }

    #[tokio::test]
    async fn set_tokens_makes_authenticated() {
        let api = BirdoApi::new();
        api.set_tokens("access".to_string(), "refresh".to_string())
            .await;
        assert!(api.is_authenticated().await);
    }

    #[tokio::test]
    async fn clear_tokens_makes_unauthenticated() {
        let api = BirdoApi::new();
        api.set_tokens("access".to_string(), "refresh".to_string())
            .await;
        assert!(api.is_authenticated().await);

        api.clear_tokens().await;
        assert!(!api.is_authenticated().await);
    }

    #[tokio::test]
    async fn clone_shares_token_state() {
        let api1 = BirdoApi::new();
        let api2 = api1.clone();

        api1.set_tokens("at".to_string(), "rt".to_string()).await;
        // Cloned instance should see the same tokens (Arc-shared)
        assert!(api2.is_authenticated().await);
    }

    #[tokio::test]
    async fn default_creates_same_as_new() {
        let api = BirdoApi::default();
        assert!(!api.is_authenticated().await);
    }
}

/// Regression tests for HTTP error classification.
///
/// These exist because a 401 stopped mapping to `ApiError::Unauthorized` and
/// nothing caught it. That variant is the ONLY thing `request_with_retry`
/// matches on to run the transparent token refresh, so the refresh interceptor
/// became unreachable code and every desktop user lost API access roughly an
/// hour after launch — when the 1h access token expired — with a valid 30-day
/// refresh token sitting unused in the keystore. Restarting the app was the
/// only recovery.
///
/// The trap: the backend registers GlobalExceptionFilter globally and it puts a
/// non-empty `message` on EVERY error response, so the "use the backend's
/// message" shortcut swallowed 401s before the status was ever consulted.
#[cfg(test)]
mod error_classification_tests {
    use super::super::client::BirdoApi;
    use super::super::error::ApiError;
    use reqwest::StatusCode;

    /// Exactly what the backend's GlobalExceptionFilter emits for a 401.
    const REAL_401_BODY: &str = r#"{"statusCode":401,"message":"Unauthorized","error":"Unauthorized","timestamp":"2026-07-29T18:00:00.000Z","path":"/vpn/connect"}"#;

    #[test]
    fn a_401_carrying_a_message_still_maps_to_unauthorized() {
        // THE REGRESSION. Before the fix this returned Unknown("Unauthorized").
        let err = BirdoApi::classify_error_response(StatusCode::UNAUTHORIZED, REAL_401_BODY);
        assert!(
            matches!(err, ApiError::Unauthorized),
            "401 must map to Unauthorized so request_with_retry refreshes the token, got {err:?}"
        );
    }

    #[test]
    fn a_401_with_an_empty_body_maps_to_unauthorized() {
        let err = BirdoApi::classify_error_response(StatusCode::UNAUTHORIZED, "");
        assert!(matches!(err, ApiError::Unauthorized));
    }

    /// MR-1707 (birdo-web #850): the number-replacement refusals are told
    /// apart by the body's `error`, because two of them share a status and a
    /// bare 403 would read as a plan refusal.
    #[test]
    fn the_number_replacement_refusals_are_told_apart_by_code() {
        for (status, code) in [
            (StatusCode::FORBIDDEN, "anon_number_rotation_disabled"),
            (StatusCode::CONFLICT, "rotation_not_pending"),
            (StatusCode::CONFLICT, "rotation_account_changed"),
        ] {
            let body = format!(
                r#"{{"statusCode":{},"error":"{code}","message":"x"}}"#,
                status.as_u16()
            );
            match BirdoApi::classify_error_response(status, &body) {
                ApiError::AnonNumberRefused(got) => assert_eq!(got, code),
                other => panic!("{code} should be its own refusal, got {other:?}"),
            }
        }
        // A 400 mismatch keeps the generic path, a 401 stays Unauthorized.
        let bad = r#"{"statusCode":400,"message":"That is not the pending number"}"#;
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::BAD_REQUEST, bad),
            ApiError::Rejected { status: 400, .. }
        ));
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::UNAUTHORIZED, bad),
            ApiError::Unauthorized
        ));
    }

    /// MR-1707: a wrong proof's 401 is the handler's answer (one request, no
    /// refresh); only the JWT guard's bare "Unauthorized" means refresh and
    /// retry once. The machine code is checked first, then the message.
    #[test]
    fn a_proof_401_is_not_refreshed_but_a_bare_unauthorized_is() {
        use super::super::client::ProofPostOutcome;
        let classify = |body: &str| {
            BirdoApi::classify_proof_post_response_after(StatusCode::UNAUTHORIZED, body, None)
        };
        // The code wins, even with the guard's own wording.
        for body in [
            r#"{"statusCode":401,"error":"rotation_proof_invalid","message":"Unauthorized"}"#,
            r#"{"statusCode":401,"error":"rotation_proof_invalid"}"#,
            r#"{"statusCode":401,"message":"Incorrect account number or password"}"#,
            r#"{"statusCode":401,"error":"Unauthorized","message":"Invalid proof"}"#,
        ] {
            assert!(
                matches!(
                    classify(body),
                    ProofPostOutcome::Refused(ApiError::Rejected { status: 401, .. })
                ),
                "{body}"
            );
        }
        for body in [
            r#"{"statusCode":401,"message":"Unauthorized"}"#,
            r#"{"statusCode":401,"error":"Unauthorized","message":"Unauthorized"}"#,
            r#"{"statusCode":401}"#,
            "",
        ] {
            assert!(
                matches!(classify(body), ProofPostOutcome::SessionExpired),
                "{body}"
            );
        }
        assert!(matches!(
            BirdoApi::classify_proof_post_response_after(StatusCode::OK, "{}", None),
            ProofPostOutcome::Done(_)
        ));
        let disabled = r#"{"statusCode":403,"error":"anon_number_rotation_disabled"}"#;
        assert!(matches!(
            BirdoApi::classify_proof_post_response_after(StatusCode::FORBIDDEN, disabled, None),
            ProofPostOutcome::Refused(ApiError::AnonNumberRefused(_))
        ));
    }

    /// The structure that makes the above mean "one request": both rotation
    /// calls go through `post_proof_checked`, which refreshes only on
    /// `SessionExpired`, never through the generic retrying POST.
    #[test]
    fn the_rotation_calls_use_the_discriminating_post() {
        // A Windows checkout has CRLF; the search below is for LF.
        let source = include_str!("client.rs").replace("\r\n", "\n");
        let section = |name: &str| {
            let start = source.find(name).expect(name);
            let rest = &source[start..];
            rest[..rest.find("\n    }\n").expect("end of fn body")].to_string()
        };
        for name in [
            "pub async fn rotate_number_prepare(",
            "pub async fn rotate_number_confirm(",
        ] {
            let body = section(name);
            assert!(body.contains("post_proof_checked("), "{name}");
            assert!(!body.contains("self.post("), "{name}");
        }
        let checked = section("async fn post_proof_checked<");
        assert_eq!(checked.matches("send_proof_post(").count(), 2);
        assert!(checked.contains("ProofPostOutcome::SessionExpired"));
        assert!(checked.contains("self.refresh_detached(lock)"));
    }

    /// The bodies the two endpoints take and answer (fake numbers), and that
    /// none of them prints a number.
    #[test]
    fn the_number_replacement_bodies_match_the_contract() {
        use super::super::types::{
            RotateConfirmBody, RotateConfirmResponse, RotatePrepareBody, RotatePrepareResponse,
        };
        let prepare = RotatePrepareBody {
            current_number: "111122223333444455556666".into(),
            password: None,
            two_factor_code: Some("123456".into()),
        };
        assert_eq!(
            serde_json::to_value(&prepare).unwrap(),
            serde_json::json!({"currentNumber": "111122223333444455556666", "twoFactorCode": "123456"})
        );
        assert!(!format!("{prepare:?}").contains("1111"));
        let confirm = RotateConfirmBody {
            new_number: "777788889999000011112222".into(),
            device_id: "dev".into(),
            device_name: None,
            platform: "WINDOWS".into(),
        };
        assert_eq!(
            serde_json::to_value(&confirm).unwrap(),
            serde_json::json!({"newNumber": "777788889999000011112222", "deviceId": "dev", "platform": "WINDOWS"})
        );
        assert!(!format!("{confirm:?}").contains("7777"));
        let answer: RotatePrepareResponse = serde_json::from_str(
            r#"{"ok":true,"newNumber":"777788889999000011112222","expiresInSeconds":600}"#,
        )
        .unwrap();
        assert_eq!(answer.expires_in_seconds, Some(600));
        assert!(!format!("{answer:?}").contains("7777"));
        let done: RotateConfirmResponse = serde_json::from_str(
            r#"{"ok":true,"tokens":{"access_token":"a","refresh_token":"r"}}"#,
        )
        .unwrap();
        assert!(done.ok && done.tokens.is_some());
        assert!(!format!("{done:?}").contains("refresh_token"));
    }

    /// MR-1707: with `ANON_NUMBER_MASKING` on, `/auth/me` carries the mask in
    /// `accountNumber`. It is kept (the Profile card shows it); anything that
    /// is neither 24 digits nor stars-then-digits is still dropped.
    #[test]
    fn a_masked_account_number_is_kept_and_a_malformed_one_is_not() {
        use super::super::types::{AccountNumber, UserProfile};
        let mask = "********************6666";
        assert!(AccountNumber::parse(mask).is_some());
        assert!(AccountNumber::parse("123456789012345678901234").is_some());
        for bad in [
            "",
            "****",
            "********************66",
            "66********************",
            "********************abcd",
            "*********************6666",
        ] {
            assert!(AccountNumber::parse(bad).is_none(), "{bad}");
        }
        let user: UserProfile = serde_json::from_str(&format!(
            r#"{{"id":"u6","email":"anon_{mask}@anonymous.local","isAnonymous":true,"accountNumber":"{mask}"}}"#
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(&user.account_number).unwrap(), mask);
        assert!(!format!("{user:?}").contains("6666"));
    }

    #[test]
    fn other_statuses_keep_the_backend_message() {
        // Load-bearing the other way: these variants carry no payload, so
        // mapping them by status alone would replace a specific, actionable
        // explanation with a generic one.
        let body = r#"{"statusCode":403,"message":"Stealth mode requires an Operative or Sovereign subscription"}"#;
        let err = BirdoApi::classify_error_response(StatusCode::FORBIDDEN, body);
        match err {
            ApiError::Rejected { status, message } => {
                assert_eq!(status, 403);
                assert!(message.contains("Stealth mode requires"));
            }
            other => panic!("403 should surface the backend's explanation, got {other:?}"),
        }
    }

    #[test]
    fn a_status_without_a_message_falls_back_to_its_variant() {
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::FORBIDDEN, ""),
            ApiError::Forbidden
        ));
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::NOT_FOUND, ""),
            ApiError::NotFound
        ));
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::TOO_MANY_REQUESTS, ""),
            ApiError::RateLimited {
                retry_after_secs: None
            }
        ));
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::BAD_GATEWAY, ""),
            ApiError::ServerError(502)
        ));
    }

    #[test]
    fn a_blank_message_does_not_shadow_the_status_variant() {
        let err = BirdoApi::classify_error_response(StatusCode::FORBIDDEN, r#"{"message":"   "}"#);
        assert!(matches!(err, ApiError::Forbidden));
    }

    // ── Forced client-version floor (426) ────────────────────────────────

    /// The CANONICAL 426 body, captured verbatim from the backend.
    ///
    /// This is not a hand-written guess. It is the exact bytes emitted by
    /// birdo-web's /vpn/connect after passing through the real, globally
    /// registered GlobalExceptionFilter (only `timestamp` is a fixed sample).
    /// The same shape is asserted on the backend side by
    /// `backend/src/vpn/vpn-version-floor.wire.spec.ts`, so if either side
    /// drifts, one of the two test suites fails.
    ///
    /// Note what is NOT here: no `requiredVersion`, no `downloadUrl`. This
    /// client shipped a parser for those invented names against a body that
    /// never contained them — and, at the time, could not have contained
    /// anything at all, because the filter was stripping the payload before the
    /// wire. Hence a real capture rather than a plausible-looking literal.
    const CANONICAL_426: &str = r#"{"statusCode":426,"message":"This version of Birdo VPN is no longer supported. Please update the app to reconnect.","error":"update_required","timestamp":"2026-08-20T18:51:59.920Z","path":"/vpn/connect","details":{"minVersion":"1.4.36","currentVersion":"1.4.9","updateUrl":"https://birdo.app/clients"}}"#;

    #[test]
    fn the_canonical_426_body_is_read_in_full() {
        match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, CANONICAL_426) {
            ApiError::UpgradeRequired(info) => {
                assert_eq!(info.required_version.as_deref(), Some("1.4.36"));
                // The manual-download escape hatch. UpdateRequired.tsx gates the
                // "Download manually" button on this being present; without it a
                // blocked user has only the in-app updater.
                assert_eq!(
                    info.download_url.as_deref(),
                    Some("https://birdo.app/clients")
                );
                // The HUMAN sentence, from `message` — never the token in `error`.
                assert_eq!(
                    info.message.as_deref(),
                    Some(
                        "This version of Birdo VPN is no longer supported. Please update the app to reconnect."
                    )
                );
            }
            other => panic!("canonical 426 must map to UpgradeRequired, got {other:?}"),
        }
    }

    #[test]
    fn the_machine_token_is_never_shown_to_a_user() {
        // REGRESSION GUARD. `message` used to be filled from `error`, so the
        // entire explanation a blocked user received was "update_required".
        let err = BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, CANONICAL_426);
        let shown = err.to_string();
        assert!(
            !shown.contains("update_required"),
            "user-facing text leaked the machine token: {shown}"
        );
        assert!(shown.contains("no longer supported"), "got: {shown}");

        // And when the backend sends ONLY the token, we must fall back to our
        // own wording rather than surfacing the identifier.
        let token_only = r#"{"error":"update_required","details":{"minVersion":"1.4.36"}}"#;
        let err = BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, token_only);
        match &err {
            ApiError::UpgradeRequired(info) => assert_eq!(info.message, None),
            other => panic!("expected UpgradeRequired, got {other:?}"),
        }
        let shown = err.to_string();
        assert!(
            !shown.contains("update_required"),
            "user-facing text leaked the machine token: {shown}"
        );
        assert!(shown.contains("1.4.36"), "got: {shown}");
    }

    #[test]
    fn all_four_body_shapes_still_block() {
        // The gate is the STATUS CODE. Parsing may only ever affect the MESSAGE.
        // The first two shapes must also keep the manual-download URL, because
        // that button is the escape hatch that does not depend on the in-app
        // updater (which has never completed a real end-to-end install).
        let legacy = r#"{"error":"Client too old","requiredVersion":"1.4.36","downloadUrl":"https://birdo.app/download"}"#;

        let cases: [(&str, Option<&str>, Option<&str>); 4] = [
            (
                CANONICAL_426,
                Some("1.4.36"),
                Some("https://birdo.app/clients"),
            ),
            (legacy, Some("1.4.36"), Some("https://birdo.app/download")),
            ("{}", None, None),
            ("<html>502 Bad Gateway</html>", None, None),
        ];

        for (body, want_version, want_url) in cases {
            match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, body) {
                ApiError::UpgradeRequired(info) => {
                    assert_eq!(
                        info.required_version.as_deref(),
                        want_version,
                        "body {body:?}"
                    );
                    assert_eq!(info.download_url.as_deref(), want_url, "body {body:?}");
                }
                other => panic!("426 must block for body {body:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn details_outrank_the_tolerated_top_level_fallbacks() {
        // If a backend ever sends both, `details` is the agreed contract and
        // must win — otherwise a stale top-level key silently pins the client to
        // the wrong version.
        let body = r#"{"minVersion":"1.0.0","updateUrl":"https://old.example",
                       "requiredVersion":"0.9.0","downloadUrl":"https://older.example",
                       "details":{"minVersion":"1.4.36","updateUrl":"https://birdo.app/clients"}}"#;
        match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, body) {
            ApiError::UpgradeRequired(info) => {
                assert_eq!(info.required_version.as_deref(), Some("1.4.36"));
                assert_eq!(
                    info.download_url.as_deref(),
                    Some("https://birdo.app/clients")
                );
            }
            other => panic!("expected UpgradeRequired, got {other:?}"),
        }
    }

    #[test]
    fn a_426_carries_the_required_version_and_download_url() {
        let body = r#"{"error":"Client too old","requiredVersion":"1.4.36","downloadUrl":"https://birdo.app/download"}"#;
        match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, body) {
            ApiError::UpgradeRequired(info) => {
                assert_eq!(info.required_version.as_deref(), Some("1.4.36"));
                assert_eq!(
                    info.download_url.as_deref(),
                    Some("https://birdo.app/download")
                );
                assert_eq!(info.message.as_deref(), Some("Client too old"));
            }
            other => panic!("426 must map to UpgradeRequired, got {other:?}"),
        }
    }

    #[test]
    fn a_426_with_an_unreadable_body_still_blocks() {
        // The gate is decided by the STATUS CODE. A body shape we cannot parse
        // must degrade the message shown, never the block itself — otherwise a
        // backend that changes its error envelope silently disables the floor.
        for body in ["", "not json at all", "{}"] {
            match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, body) {
                ApiError::UpgradeRequired(info) => {
                    assert_eq!(info.required_version, None, "body {body:?}");
                }
                other => panic!("426 must map to UpgradeRequired for {body:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_426_wins_over_a_message_and_ignores_an_unknown_error_code() {
        // Ordering guard: the generic message branch would discard the payload
        // the update screen needs, so the 426 check must run before it.
        //
        // The body still carries `errorCode` on purpose. It used to select a
        // third branch, via ProtocolErrorCode, which was retired on 2026-09-20
        // because the server never sent that key (see api/types.rs). Keeping it
        // here now asserts the OTHER half of that decision: an unknown field
        // must be ignored rather than fail the parse, so a server that one day
        // starts sending `errorCode` degrades to the message, and never to a
        // dropped 426.
        let body = r#"{"errorCode":"SUBSCRIPTION_REQUIRED","message":"Upgrade required","requiredVersion":"2.0.0"}"#;
        match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, body) {
            ApiError::UpgradeRequired(info) => {
                assert_eq!(info.required_version.as_deref(), Some("2.0.0"))
            }
            other => panic!("426 must outrank the message branch, got {other:?}"),
        }
    }

    #[test]
    fn a_426_accepts_a_snake_case_body_too() {
        let body = r#"{"required_version":"1.4.36","download_url":"https://birdo.app/download"}"#;
        match BirdoApi::classify_error_response(StatusCode::UPGRADE_REQUIRED, body) {
            ApiError::UpgradeRequired(info) => {
                assert_eq!(info.required_version.as_deref(), Some("1.4.36"));
                assert_eq!(
                    info.download_url.as_deref(),
                    Some("https://birdo.app/download")
                );
            }
            other => panic!("426 must parse snake_case too, got {other:?}"),
        }
    }

    #[test]
    fn the_upgrade_required_message_names_the_version() {
        let err = BirdoApi::classify_error_response(
            StatusCode::UPGRADE_REQUIRED,
            r#"{"requiredVersion":"1.4.36"}"#,
        );
        let shown = err.to_string();
        assert!(
            shown.contains("1.4.36"),
            "the user-visible message must name the version, got {shown:?}"
        );
    }
}
