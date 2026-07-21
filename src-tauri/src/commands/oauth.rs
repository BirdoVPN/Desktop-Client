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

// Branded loopback pages shown in the system browser after the SSO round-trip.
// Fully self-contained (inline CSS + inline SVG, no external resources) because
// the loopback closes immediately after serving them — nothing else can load.
const RESPONSE_OK: &str = concat!(
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
    r##"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Signed in · Birdo VPN</title><style>
:root{color-scheme:dark}*{margin:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px;color:#e9ebea;background:#060707;background:radial-gradient(1100px 720px at 50% -12%,#0c1c16 0%,#060707 62%)}
.card{position:relative;width:100%;max-width:390px;text-align:center;padding:46px 34px 34px;border-radius:24px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08);box-shadow:0 30px 80px -28px rgba(0,0,0,.75);overflow:hidden}
.card::before{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:linear-gradient(90deg,transparent,#10b981,transparent);opacity:.7}
.badge{position:relative;width:80px;height:80px;margin:0 auto 26px;border-radius:50%;display:grid;place-items:center;background:rgba(5,150,105,.15);border:1px solid rgba(16,185,129,.5);box-shadow:0 0 0 7px rgba(16,185,129,.06),0 12px 30px -10px rgba(16,185,129,.45);animation:pop .55s cubic-bezier(.2,.9,.3,1.35) both}
.badge svg{width:38px;height:38px;fill:none;stroke:#10b981;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}
.badge path{stroke-dasharray:30;stroke-dashoffset:30;animation:draw .5s .28s ease forwards}
h1{font-size:23px;font-weight:700;letter-spacing:-.015em;margin-bottom:11px}
p{font-size:14.5px;line-height:1.55;color:rgba(233,235,234,.62)}
.foot{margin-top:28px;padding-top:18px;border-top:1px solid rgba(255,255,255,.06);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:rgba(233,235,234,.36)}
.foot b{color:#10b981;font-weight:800}
@keyframes pop{0%{transform:scale(.5);opacity:0}70%{transform:scale(1.07)}100%{transform:scale(1);opacity:1}}
@keyframes draw{to{stroke-dashoffset:0}}
@media(prefers-reduced-motion:reduce){.badge{animation:none}.badge path{animation:none;stroke-dashoffset:0}.card::before{opacity:.4}}
</style></head><body><main class=card>
<div class=badge><svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg></div>
<h1>Signed in to Birdo VPN</h1>
<p>You&rsquo;re all set. You can close this tab and head back to the app &mdash; it&rsquo;s already signing you in.</p>
<div class=foot><b>Birdo</b> VPN &middot; secure by default</div>
</main></body></html>"##
);
const RESPONSE_ERR: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
    r##"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Sign-in problem · Birdo VPN</title><style>
:root{color-scheme:dark}*{margin:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px;color:#e9ebea;background:#060707;background:radial-gradient(1100px 720px at 50% -12%,#241605 0%,#060707 62%)}
.card{position:relative;width:100%;max-width:390px;text-align:center;padding:46px 34px 34px;border-radius:24px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08);box-shadow:0 30px 80px -28px rgba(0,0,0,.75);overflow:hidden}
.card::before{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:linear-gradient(90deg,transparent,#f59e0b,transparent);opacity:.7}
.badge{width:80px;height:80px;margin:0 auto 26px;border-radius:50%;display:grid;place-items:center;background:rgba(245,158,11,.14);border:1px solid rgba(245,158,11,.5);box-shadow:0 0 0 7px rgba(245,158,11,.06);animation:pop .5s cubic-bezier(.2,.9,.3,1.3) both}
.badge svg{width:36px;height:36px;fill:none;stroke:#f59e0b;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
h1{font-size:23px;font-weight:700;letter-spacing:-.015em;margin-bottom:11px}
p{font-size:14.5px;line-height:1.55;color:rgba(233,235,234,.62)}
.foot{margin-top:28px;padding-top:18px;border-top:1px solid rgba(255,255,255,.06);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:rgba(233,235,234,.36)}
.foot b{color:#f59e0b;font-weight:800}
@keyframes pop{0%{transform:scale(.5);opacity:0}70%{transform:scale(1.06)}100%{transform:scale(1);opacity:1}}
@media(prefers-reduced-motion:reduce){.badge{animation:none}.card::before{opacity:.4}}
</style></head><body><main class=card>
<div class=badge><svg viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg></div>
<h1>Sign-in didn&rsquo;t finish</h1>
<p>Something interrupted the sign-in. Close this tab and try again from the Birdo VPN app.</p>
<div class=foot><b>Birdo</b> VPN</div>
</main></body></html>"##
);
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
                // ERROR, not warn: the login itself succeeded, but a session that
                // cannot be persisted is one the user must repeat on every launch.
                // Logged at warn this was invisible in the shipped log level, which
                // is precisely how a keystore that discarded every write went
                // unnoticed. Surfacing it is the difference between a diagnosable
                // bug and a silent one.
                tracing::error!(
                    "SSO succeeded but credentials could NOT be persisted to the OS keystore \
                     ({e}) — the user will have to sign in again after restarting"
                );
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
