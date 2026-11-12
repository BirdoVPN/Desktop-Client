//! A-M50: a new-version NOTICE for Linux.
//!
//! The in-app updater endpoint (`api.birdo.app/updates/{target}/...`) answers
//! 204 for Linux and there is no apt repository, so a Linux user had no signal
//! that a newer `.deb` exists. This asks the same host's
//! `GET /updates/linux/latest` (the backend reads GitHub Releases server-side
//! and caches it) and reports the newer version, if any. It never downloads or
//! installs anything: the notice sends the user to the release page.
//!
//! Privacy: one anonymous GET to the host the updater already uses, so no new
//! recipient. No auth, no cookies (the client is built without a cookie
//! store), no account data, no device identifier, no version in the URL. Every failure is `None`: the notice is a
//! courtesy and must never block startup, the VPN, or show an error.
//!
//! The release page is opened from Rust, from a constant, so the webview's
//! `opener:allow-open-url` scope does not have to grow a github.com entry.

use serde::Deserialize;
use tauri_plugin_opener::OpenerExt;

/// First-party endpoint: `{ "version": "1.4.55", "url": "..." }`, or 204 when
/// there is no Linux release. The same host the updater uses (cert-pinned).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LATEST_LINUX_URL: &str = "https://api.birdo.app/updates/linux/latest";

/// What the "Download" button opens.
const RELEASE_PAGE_URL: &str = "https://github.com/BirdoVPN/Desktop-Client/releases/latest";

/// The one field of the endpoint's answer this reads.
#[derive(Debug, Deserialize)]
struct Latest {
    version: String,
}

/// `v1.4.55` or `1.4.55` as (major, minor, patch). Anything else (a suffix such
/// as `-rc1`, a missing or extra part, a non-number) is `None`.
fn parse_version(tag: &str) -> Option<(u64, u64, u64)> {
    let tag = tag.trim();
    let tag = tag.strip_prefix('v').unwrap_or(tag);
    let mut parts = tag.split('.');
    let mut next = || -> Option<u64> {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let version = (next()?, next()?, next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(version)
}

/// The endpoint's version (a leading `v` tolerated, then dropped) when it is
/// strictly newer than `current`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn newer_version(body: &str, current: &str) -> Option<String> {
    let latest: Latest = serde_json::from_str(body).ok()?;
    let version = latest.version.trim();
    let version = version.strip_prefix('v').unwrap_or(version);
    if parse_version(version)? > parse_version(current)? {
        Some(version.to_string())
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
async fn fetch_latest() -> Option<String> {
    use std::time::Duration;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(15))
        .use_preconfigured_tls(crate::api::cert_pin::rustls_config_pinning_birdo_hosts_only())
        .build()
        .ok()?;
    let response = client.get(LATEST_LINUX_URL).send().await.ok()?;
    // 200 only: 204 (no Linux release) and 404 (endpoint not live yet) are None.
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    // The answer is a few dozen bytes of JSON; refuse anything absurd.
    if response.content_length().is_some_and(|n| n > 1_048_576) {
        return None;
    }
    response.text().await.ok()
}

/// The version of a newer published release, or `None` when the app is up to
/// date, the check failed, or this is not Linux.
#[tauri::command]
pub async fn check_linux_release() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let body = fetch_latest().await?;
        newer_version(&body, env!("CARGO_PKG_VERSION"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Open the GitHub release page in the system browser. Takes no argument: the
/// URL is the constant above.
#[tauri::command]
pub fn open_linux_release_page(app: tauri::AppHandle) -> Result<(), String> {
    app.opener()
        .open_url(RELEASE_PAGE_URL, None::<&str>)
        .map_err(|e| format!("Could not open the browser: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(version: &str) -> String {
        format!(r#"{{"version":"{version}","url":"{RELEASE_PAGE_URL}"}}"#)
    }

    #[test]
    fn parses_tags_with_and_without_v() {
        assert_eq!(parse_version("v1.4.55"), Some((1, 4, 55)));
        assert_eq!(parse_version("1.4.55"), Some((1, 4, 55)));
        assert_eq!(parse_version(" v10.0.2 "), Some((10, 0, 2)));
    }

    #[test]
    fn malformed_tags_are_none() {
        for bad in [
            "",
            "v",
            "latest",
            "v1.4",
            "v1.4.5.6",
            "v1.4.x",
            "v1.4.5-rc1",
            "v1..5",
            "vv1.4.5",
            "v1.4.-5",
            "v1.4.5+b",
        ] {
            assert_eq!(parse_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn compares_numerically_not_lexically() {
        assert_eq!(
            newer_version(&body("1.4.55"), "1.4.9"),
            Some("1.4.55".into())
        );
        assert_eq!(
            newer_version(&body("1.10.0"), "1.9.9"),
            Some("1.10.0".into())
        );
        assert_eq!(
            newer_version(&body("v2.0.0"), "1.99.99"),
            Some("2.0.0".into())
        );
    }

    #[test]
    fn equal_and_older_are_not_a_notice() {
        assert_eq!(newer_version(&body("1.4.55"), "1.4.55"), None);
        assert_eq!(newer_version(&body("1.4.54"), "1.4.55"), None);
    }

    #[test]
    fn malformed_version_or_body_is_not_a_notice() {
        assert_eq!(newer_version(&body("nightly"), "1.4.55"), None);
        assert_eq!(newer_version(&body("1.4.56-rc1"), "1.4.55"), None);
        assert_eq!(newer_version("not json", "1.4.55"), None);
        assert_eq!(newer_version("{}", "1.4.55"), None);
        assert_eq!(newer_version(&body("9.9.9"), "garbage"), None);
    }

    #[test]
    fn the_request_stays_on_the_first_party_host() {
        assert_eq!(
            LATEST_LINUX_URL,
            "https://api.birdo.app/updates/linux/latest"
        );
        assert!(!LATEST_LINUX_URL.contains('?') && !LATEST_LINUX_URL.contains('@'));
        assert!(RELEASE_PAGE_URL.starts_with("https://github.com/BirdoVPN/"));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn not_linux_never_checks() {
        assert_eq!(check_linux_release().await, None);
    }
}
