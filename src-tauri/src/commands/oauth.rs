//! Native SSO (Google / GitHub) login via the brokered PKCE flow.
//!
//! The desktop app is a public PKCE client of BIRDO, not of Google/GitHub
//! directly. Flow:
//!   1. generate a PKCE verifier/challenge + anti-CSRF state
//!   2. bind a ONE-SHOT loopback listener on 127.0.0.1:<random port>
//!   3. open the system browser at the web broker `/native/oauth/start`
//!   4. the browser completes Google/GitHub and redirects to our loopback
//!      `/callback?code=<handoff>&state=...`
//!   5. exchange the handoff code (+ our verifier) at the backend
//!      `/auth/native/exchange` for real tokens — same result shape as password
//!      login, so 2FA is handled by the identical downstream path.
//!
//! A stolen handoff code is useless without the verifier, which never leaves
//! this process; the loopback redirect (RFC 8252) is not hijackable the way a
//! global custom scheme is.

use crate::api::types::LoginResult;
use crate::api::BirdoApi;
use crate::storage::CredentialStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tauri::{Manager, State};
use tauri_plugin_shell::ShellExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::auth::{LoginResponse, UserInfo};

/// Web origin hosting the `/native/oauth/*` broker routes (the Next.js app host,
/// NOT the API host — the exchange goes to api.birdo.app via the reqwest client).
const OAUTH_WEB_BASE: &str = "https://birdo.app";

/// How long to wait for the user to finish in the browser before giving up.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(300);

const RESPONSE_OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<!doctype html><meta charset=utf-8><title>Birdo VPN</title><body style=\"font-family:system-ui;background:#0a0a0a;color:#e5e5e5;display:grid;place-items:center;height:100vh;margin:0\"><div style=\"text-align:center\"><h2>Signed in to Birdo VPN</h2><p>You can close this window and return to the app.</p></div>";
const RESPONSE_ERR: &str = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nMissing sign-in code. You can close this window.";
const RESPONSE_IGNORE: &str = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 7636 PKCE pair: verifier = base64url(32 random bytes) (= 43 chars),
/// challenge = base64url(SHA-256(verifier)).
fn generate_pkce() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);
    let verifier = b64url(&verifier_bytes);
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn random_token(len: usize) -> String {
    let mut b = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b64url(&b)
}

/// Percent-encode a value for use as a query-string component (encode anything
/// outside the RFC 3986 unreserved set).
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Minimal percent-decoder for the loopback query values.
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Open a URL in the system browser via the shell plugin (the app's established
/// browser-open mechanism — see Login.tsx). `Shell::open` is deprecated in favour
/// of tauri-plugin-opener, but adding that plugin means a new dep + capability +
/// cargo-deny review; the shell path still works and matches the frontend.
#[allow(deprecated)]
fn open_in_browser(app: &tauri::AppHandle, url: String) -> Result<(), String> {
    app.shell()
        .open(url, None)
        .map_err(|e| format!("Could not open the browser: {e}"))
}

/// Parse `code` and `state` out of the loopback request's first line:
/// `GET /callback?code=...&state=... HTTP/1.1`.
fn parse_callback(request_line: &str) -> Option<(String, String)> {
    let path = request_line.split_whitespace().nth(1)?;
    let query = path.split_once('?')?.1;
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(urldecode(v)),
                "state" => state = Some(urldecode(v)),
                _ => {}
            }
        }
    }
    Some((code?, state?))
}

/// Start native SSO for `provider` ("google" | "github"). Blocks (async) until
/// the browser flow completes, times out, or fails.
#[tauri::command]
pub async fn native_oauth_login(
    provider: String,
    app: tauri::AppHandle,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, String> {
    if provider != "google" && provider != "github" {
        return Err("Unsupported sign-in provider".into());
    }

    // 1. One-shot loopback listener on a random free port.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("Could not start local sign-in listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Could not read local port: {e}"))?
        .port();

    // 2. PKCE + anti-CSRF state.
    let (verifier, challenge) = generate_pkce();
    let state = random_token(16);
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    // 3. Open the system browser at the web broker's start route.
    let start_url = format!(
        "{OAUTH_WEB_BASE}/native/oauth/start?provider={provider}&code_challenge={challenge}&redirect_uri={}&state={state}",
        urlencode(&redirect_uri),
    );
    open_in_browser(&app, start_url)?;

    // 4. Wait for the loopback redirect carrying the handoff code.
    let (code, returned_state) = tokio::time::timeout(OAUTH_TIMEOUT, async {
        loop {
            let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");
            // Ignore stray requests (e.g. favicon) — only /callback matters.
            if !first_line.contains("/callback") {
                let _ = stream.write_all(RESPONSE_IGNORE.as_bytes()).await;
                continue;
            }
            match parse_callback(first_line) {
                Some(pair) => {
                    let _ = stream.write_all(RESPONSE_OK.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return Ok::<(String, String), String>(pair);
                }
                None => {
                    let _ = stream.write_all(RESPONSE_ERR.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return Err("Sign-in response was missing the code.".into());
                }
            }
        }
    })
    .await
    .map_err(|_| "Sign-in timed out. Please try again.".to_string())??;

    // 5. Anti-CSRF: the state we sent must come back unchanged.
    if returned_state != state {
        return Err("Sign-in could not be verified (state mismatch).".into());
    }

    // The browser now holds focus; bring our window back to the foreground so the
    // user lands in the app after signing in rather than behind the browser.
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }

    // 6. Exchange the handoff code (+ our verifier) for real tokens.
    let device_id = crate::utils::get_device_id();
    match api.native_exchange(&code, &verifier, &device_id).await {
        Ok(LoginResult::Success { tokens, .. }) => {
            if let Err(e) = credentials.store_tokens(&tokens.access_token, &tokens.refresh_token) {
                tracing::warn!("Failed to persist SSO credentials: {e}");
            }
            tracing::info!("Native SSO login successful via {provider}");
            Ok(LoginResponse {
                success: true,
                message: None,
                user: Some(UserInfo {
                    email: None,
                    account_id: None,
                    plan: "unknown".to_string(),
                    is_anonymous: false,
                }),
                requires_two_factor: false,
                challenge_token: None,
            })
        }
        Ok(LoginResult::TwoFactorChallenge {
            challenge_token, ..
        }) => Ok(LoginResponse {
            success: false,
            message: Some("Two-factor authentication required".to_string()),
            user: None,
            requires_two_factor: true,
            challenge_token: Some(challenge_token),
        }),
        Err(e) => {
            tracing::warn!("Native SSO exchange failed: {e}");
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
