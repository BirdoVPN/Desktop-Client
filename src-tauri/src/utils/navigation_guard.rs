//! MR-2011: the main window shows the app and nothing else.
//!
//! A navigation of the main window away from the app's own origin is
//! cancelled. The app never navigates its window anywhere: links open in the
//! system browser through the opener plugin (`capabilities/default.json`,
//! `OpenerLinks.test.tsx`), and its routes change in-page. So a top-level
//! navigation elsewhere is content the app did not ship (a link that skipped
//! the opener, a redirect, an injected script), and the window keeps the app
//! instead of rendering it. Tauri already treats such a page as a remote
//! origin, which no capability grants an app command to (MR-2011's other
//! half, `commands/app_permission_tests.rs`); this keeps the app's own,
//! elevated window from showing that page at all.
//!
//! The app's origin is where Tauri serves it (`Webview::is_local_url`, tauri
//! 2.12): `http://tauri.localhost` on Windows (`https://` when a window sets
//! `useHttpsScheme`), `tauri://localhost` elsewhere, on the default port, plus
//! the `devUrl` in a development build (tauri without `custom-protocol`, the
//! same switch Tauri loads the dev server by).

use tauri::Url;

/// The scheme and host Tauri serves the app from on this platform.
#[cfg(windows)]
const APP_ORIGINS: &[(&str, &str)] = &[("http", "tauri.localhost"), ("https", "tauri.localhost")];
#[cfg(not(windows))]
const APP_ORIGINS: &[(&str, &str)] = &[("tauri", "localhost")];

/// Whether `url` is the app itself: the origin Tauri serves it from, or the
/// origin of `dev_url` when there is one. No credentials, and no port but
/// the default for the served origin.
pub fn is_app_url(url: &Url, dev_url: Option<&Url>) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let served = APP_ORIGINS.iter().any(|&(scheme, host)| {
        url.scheme() == scheme && url.host_str() == Some(host) && url.port().is_none()
    });
    served
        || dev_url.is_some_and(|dev| {
            url.scheme() == dev.scheme()
                && url.host_str().is_some()
                && url.host_str() == dev.host_str()
                && url.port_or_known_default() == dev.port_or_known_default()
        })
}

/// The main window's navigation handler: let the app navigate within itself,
/// cancel anything else.
pub fn guard(app: &tauri::AppHandle) -> impl Fn(&Url) -> bool + Send + 'static {
    let dev_url = if tauri::is_dev() {
        app.config().build.dev_url.clone()
    } else {
        None
    };
    move |url| {
        let allowed = is_app_url(url, dev_url.as_ref());
        if !allowed {
            // The scheme only: where the page wanted to go is not the log's
            // business.
            tracing::warn!(
                "MR-2011: a navigation of the main window away from the app was cancelled (a {} URL)",
                url.scheme()
            );
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    /// Where the app is served on this platform, as the window loads it.
    fn app_pages() -> Vec<Url> {
        let mut pages = Vec::new();
        for (scheme, host) in APP_ORIGINS {
            for path in ["/", "/index.html", "/settings?tab=about#licences"] {
                pages.push(url(&format!("{scheme}://{host}{path}")));
            }
        }
        pages
    }

    #[test]
    fn the_app_may_navigate_within_itself() {
        for page in app_pages() {
            assert!(is_app_url(&page, None), "{page} is the app");
        }
    }

    #[cfg(windows)]
    #[test]
    fn on_windows_the_app_is_tauri_localhost() {
        assert!(is_app_url(&url("http://tauri.localhost/"), None));
        assert!(is_app_url(&url("https://tauri.localhost/"), None));
        assert!(!is_app_url(&url("tauri://localhost/"), None));
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_app_is_tauri_scheme_localhost() {
        assert!(is_app_url(&url("tauri://localhost/"), None));
        assert!(!is_app_url(&url("http://tauri.localhost/"), None));
        assert!(!is_app_url(&url("https://tauri.localhost/"), None));
    }

    #[test]
    fn every_other_origin_is_cancelled() {
        for other in [
            "https://evil.example/",
            "http://evil.example/index.html",
            // Birdo's own sites open in the browser, never in this window.
            "https://birdo.app/",
            "https://auth.birdo.app/login",
            // Lookalikes of the served origin.
            "http://tauri.localhost.evil.example/",
            "https://evil.example/tauri.localhost/",
            "http://tauri.localhost@evil.example/",
            "http://evil.localhost/",
            "tauri://evil.example/",
            "tauri://localhost.evil.example/",
            // The served host on another port is not the app.
            "http://tauri.localhost:8080/",
            "https://tauri.localhost:4443/",
            "tauri://localhost:1420/",
            // Credentials in front of the served host.
            "http://user:pass@tauri.localhost/",
            "tauri://user@localhost/",
            // Not a page the app serves at all.
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "data:text/html,not-the-app",
            "javascript:alert(1)",
            "about:blank",
            "birdo://auth/callback?code=x",
            // The dev server, in a build that is not a dev build.
            "http://localhost:1420/",
        ] {
            assert!(!is_app_url(&url(other), None), "{other} must be cancelled");
        }
    }

    #[test]
    fn a_dev_build_may_also_load_its_dev_server_and_nothing_near_it() {
        let dev = url("http://localhost:1420");
        assert!(is_app_url(&url("http://localhost:1420/"), Some(&dev)));
        assert!(is_app_url(
            &url("http://localhost:1420/index.html?x=1"),
            Some(&dev)
        ));
        for page in app_pages() {
            assert!(is_app_url(&page, Some(&dev)), "{page} is still the app");
        }
        for other in [
            "http://localhost:1421/",
            "https://localhost:1420/",
            "http://localhost/",
            "http://127.0.0.1:1420/",
            "http://localhost.evil.example:1420/",
            "http://user@localhost:1420/",
            "https://evil.example/",
        ] {
            assert!(
                !is_app_url(&url(other), Some(&dev)),
                "{other} must be cancelled"
            );
        }
    }
}
