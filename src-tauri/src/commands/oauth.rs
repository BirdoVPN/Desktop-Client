//! Native SSO (Google / GitHub / Apple) login via the brokered PKCE flow.
//!
//! The desktop app is a public PKCE client of BIRDO, not of the provider
//! directly. Flow:
//!   1. generate a PKCE verifier/challenge + anti-CSRF state
//!   2. bind a loopback listener on 127.0.0.1:<random port>
//!   3. open the system browser at the web broker `/native/oauth/start`
//!   4. the browser completes the provider and redirects to our loopback
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
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::storage::CredentialStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tauri::{Manager, State};
use tauri_plugin_shell::ShellExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::auth::{LoginResponse, UserInfo};

/// Web origin hosting the `/native/oauth/*` broker routes (the Next.js app host,
/// NOT the API host — the exchange goes to api.birdo.app via the reqwest client).
const OAUTH_WEB_BASE: &str = "https://birdo.app";

/// How long to wait for the user to finish in the browser before giving up.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-connection budget to send the request line and receive the page. A
/// local process that connects and sends nothing must not stall the sign-in
/// (W1-042); the real browser redirect needs milliseconds.
const CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The providers the web broker serves. Apple is included for parity with
/// Android, which uses the same broker for accounts created with Sign in with
/// Apple on iPhone (P1-parity-008); iOS signs in with Apple natively.
const SSO_PROVIDERS: [&str; 3] = ["google", "github", "apple"];

// Branded loopback pages shown in the system browser after the SSO round-trip.
// Fully self-contained (inline CSS + inline SVG, no external resources) because
// the loopback closes immediately after serving them — nothing else can load.
const RESPONSE_OK: &str = concat!(
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
    r##"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Signed in · BirdoVPN</title><style>
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
<h1>Signed in to BirdoVPN</h1>
<p>You&rsquo;re all set. You can close this tab and head back to the app &mdash; it&rsquo;s already signing you in.</p>
<div class=foot><b>Birdo</b> VPN &middot; secure by default</div>
</main></body></html>"##
);
const RESPONSE_ERR: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
    r##"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Sign-in problem · BirdoVPN</title><style>
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
<p>Something interrupted the sign-in. Close this tab and try again from the BirdoVPN app.</p>
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
            // Decode from the BYTE slice: `&s[i + 1..i + 3]` slices the &str and
            // panics when a multibyte character follows a '%', which any local
            // process can trigger by hitting the loopback callback (release builds
            // are panic = "abort", so that kills the privileged client).
            b'%' if i + 2 < bytes.len() => {
                if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                {
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

/// What one loopback request means for the sign-in in progress.
#[derive(Debug, PartialEq, Eq)]
enum CallbackVerdict {
    /// Not the callback of THIS sign-in: a favicon, a stray request, or
    /// another local process. Answered with 204 and otherwise ignored.
    Ignore,
    /// Our callback, but the provider sent the user back without a code.
    Failed,
    /// The handoff code.
    Code(String),
}

/// Classify the request line `GET /callback?code=...&state=... HTTP/1.1`.
///
/// W1-042: the FIRST request to `/callback` used to end the flow whatever it
/// carried, so any local process could abort a sign-in with one request. Only
/// a request carrying the state WE generated can end it now — which is also
/// the anti-CSRF check, done before anything is believed.
fn classify_callback(request_line: &str, expected_state: &str) -> CallbackVerdict {
    let Some(path) = request_line.split_whitespace().nth(1) else {
        return CallbackVerdict::Ignore;
    };
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    if route != "/callback" {
        return CallbackVerdict::Ignore;
    }
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
    if state.as_deref() != Some(expected_state) {
        return CallbackVerdict::Ignore;
    }
    match code {
        Some(code) if !code.is_empty() => CallbackVerdict::Code(code),
        _ => CallbackVerdict::Failed,
    }
}

/// Serve one loopback connection. `Some` when it ended the sign-in.
async fn serve_callback(
    mut stream: TcpStream,
    expected_state: &str,
    io_timeout: Duration,
) -> Option<Result<String, String>> {
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(io_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let (page, outcome) = match classify_callback(first_line, expected_state) {
        CallbackVerdict::Ignore => (RESPONSE_IGNORE, None),
        CallbackVerdict::Failed => (
            RESPONSE_ERR,
            Some(Err("Sign-in response was missing the code.".to_string())),
        ),
        CallbackVerdict::Code(code) => (RESPONSE_OK, Some(Ok(code))),
    };
    let _ = tokio::time::timeout(io_timeout, async {
        let _ = stream.write_all(page.as_bytes()).await;
        let _ = stream.shutdown().await;
    })
    .await;
    outcome
}

/// Start native SSO for `provider` (one of [`SSO_PROVIDERS`]). Blocks (async)
/// until the browser flow completes, times out, or fails.
#[tauri::command]
pub async fn native_oauth_login(
    provider: String,
    app: tauri::AppHandle,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<LoginResponse, IpcError> {
    if !SSO_PROVIDERS.contains(&provider.as_str()) {
        return Err(IpcError::unknown("Unsupported sign-in provider"));
    }

    // 1. Loopback listener on a random free port, for this sign-in only.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| IpcError::unknown(format!("Could not start local sign-in listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| IpcError::unknown(format!("Could not read local port: {e}")))?
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
    open_in_browser(&app, start_url).map_err(IpcError::unknown)?;

    // 4. Wait for the loopback redirect carrying the handoff code. Every
    //    connection is served on its own task with its own I/O budget, so a
    //    connection that sends nothing (or a flood of them) cannot hold up
    //    the real redirect (W1-042); only a request with our state ends it.
    let (outcomes, mut outcome) = tokio::sync::mpsc::channel::<Result<String, String>>(1);
    let code = tokio::time::timeout(OAUTH_TIMEOUT, async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.map_err(|e| e.to_string())?;
                    let outcomes = outcomes.clone();
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Some(result) =
                            serve_callback(stream, &state, CALLBACK_IO_TIMEOUT).await
                        {
                            let _ = outcomes.send(result).await;
                        }
                    });
                }
                Some(result) = outcome.recv() => return result,
            }
        }
    })
    .await
    .map_err(|_| IpcError::unknown("Sign-in timed out. Please try again."))?
    .map_err(IpcError::unknown)?;

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
                code: None,
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
            code: Some(IpcErrorCode::TwoFactorRequired),
        }),
        Err(e) => {
            tracing::warn!("Native SSO exchange failed: {e}");
            Ok(LoginResponse {
                success: false,
                message: Some(e.to_string()),
                user: None,
                requires_two_factor: false,
                challenge_token: None,
                code: Some(super::auth::sign_in_failure_code(&e)),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_callback, urldecode, CallbackVerdict, SSO_PROVIDERS};

    const STATE: &str = "s3cr3t-state";

    #[test]
    fn only_our_state_can_end_the_sign_in() {
        assert_eq!(
            classify_callback("GET /callback?code=abc&state=s3cr3t-state HTTP/1.1", STATE),
            CallbackVerdict::Code("abc".into())
        );
        // A forged or stale callback is ignored, not fatal (W1-042).
        for line in [
            "GET /callback?code=evil&state=other HTTP/1.1",
            "GET /callback?code=evil HTTP/1.1",
            "GET /callback HTTP/1.1",
            "GET /favicon.ico HTTP/1.1",
            "GET /callbackx?code=a&state=s3cr3t-state HTTP/1.1",
            "garbage",
            "",
        ] {
            assert_eq!(
                classify_callback(line, STATE),
                CallbackVerdict::Ignore,
                "{line}"
            );
        }
        // Our state without a code: the provider ended the flow.
        assert_eq!(
            classify_callback(
                "GET /callback?state=s3cr3t-state&error=denied HTTP/1.1",
                STATE
            ),
            CallbackVerdict::Failed
        );
    }

    /// P1-parity-008: Apple accounts sign in on Windows through the broker.
    #[test]
    fn apple_is_a_broker_provider() {
        assert!(SSO_PROVIDERS.contains(&"apple"));
        assert!(SSO_PROVIDERS.contains(&"google"));
        assert!(SSO_PROVIDERS.contains(&"github"));
    }

    /// A connection that never sends a byte is dropped after its budget
    /// instead of holding the sign-in (W1-042). Loopback only.
    #[tokio::test]
    async fn a_silent_connection_is_dropped_after_its_budget() {
        let budget = std::time::Duration::from_millis(200);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let _silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let served = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::serve_callback(stream, STATE, budget),
        )
        .await
        .expect("serve_callback must give up on a silent connection");
        assert_eq!(served, None);
    }

    /// The real redirect still completes while a silent connection is open.
    #[tokio::test]
    async fn the_real_callback_is_served() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let mut browser = tokio::net::TcpStream::connect(addr).await.unwrap();
        browser
            .write_all(b"GET /callback?code=handoff&state=s3cr3t-state HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let served = super::serve_callback(stream, STATE, std::time::Duration::from_secs(5)).await;
        assert_eq!(served, Some(Ok("handoff".to_string())));
        let mut page = String::new();
        let _ = browser.read_to_string(&mut page).await;
        assert!(page.starts_with("HTTP/1.1 200 OK"));
    }

    /// `urldecode` used to byte-slice the &str (`&s[i + 1..i + 3]`), so a '%'
    /// immediately followed by a multibyte character panicked the whole process
    /// — reachable by any local process posting to the loopback callback.
    #[test]
    fn urldecode_multibyte_after_percent_does_not_panic() {
        assert_eq!(urldecode("code=%世界"), "code=%世界");
        assert_eq!(urldecode("%é"), "%é");
    }

    #[test]
    fn urldecode_decodes_normal_escapes() {
        assert_eq!(urldecode("a%20b+c"), "a b c");
        assert_eq!(urldecode("%2Fpath%3Fq%3D1"), "/path?q=1");
        // Trailing partial escapes are passed through, not decoded.
        assert_eq!(urldecode("done%2"), "done%2");
    }
}
