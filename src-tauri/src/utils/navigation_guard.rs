//! MR-2011: the main window shows the app and nothing else.
//!
//! A navigation of the main window away from the app's own origin is
//! cancelled. The app never navigates its window to a page: links open in the
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
//!
//! One navigation the app does make: the data export (GDPR Art. 20,
//! `screens/Profile.tsx`) saves its file by clicking an `<a download>` at a
//! `blob:` URL it minted. WebKitGTK hands that click to this handler as a
//! navigation (wry 0.57 `webkitgtk/mod.rs`, `decide-policy`, which does not
//! set downloads aside first as the macOS path does), so cancelling it would
//! leave Linux without the file. A `blob:` URL carries the origin of the page
//! that minted it, and only script already running in that origin can mint
//! one, so a `blob:` URL of the app's own origin is the app too. Any other
//! `blob:` URL is cancelled.

use tauri::Url;

/// The scheme and host Tauri serves the app from on this platform.
#[cfg(windows)]
const APP_ORIGINS: &[(&str, &str)] = &[("http", "tauri.localhost"), ("https", "tauri.localhost")];
#[cfg(not(windows))]
const APP_ORIGINS: &[(&str, &str)] = &[("tauri", "localhost")];

/// Whether `url` is the app itself: the origin Tauri serves it from, or the
/// origin of `dev_url` when there is one, or a `blob:` URL minted by either.
/// No credentials, and no port but the default for the served origin.
pub fn is_app_url(url: &Url, dev_url: Option<&Url>) -> bool {
    if url.scheme() == "blob" {
        // `blob:<origin>/<uuid>`: the minting page's URL is the blob URL's
        // path. An opaque origin (`blob:null/…`) does not parse, and a blob
        // of a blob is not a URL any page mints.
        return Url::parse(url.path()).is_ok_and(|minted_by| {
            minted_by.scheme() != "blob" && is_app_url(&minted_by, dev_url)
        });
    }
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

    /// A blob URL's tail, as `URL.createObjectURL` names one.
    const BLOB_ID: &str = "00000000-0000-4000-8000-000000000001";

    #[cfg(windows)]
    #[test]
    fn on_windows_the_app_is_tauri_localhost() {
        assert!(is_app_url(&url("http://tauri.localhost/"), None));
        assert!(is_app_url(&url("https://tauri.localhost/"), None));
        assert!(!is_app_url(&url("tauri://localhost/"), None));
        assert!(is_app_url(
            &url(&format!("blob:http://tauri.localhost/{BLOB_ID}")),
            None
        ));
        assert!(!is_app_url(
            &url(&format!("blob:tauri://localhost/{BLOB_ID}")),
            None
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_app_is_tauri_scheme_localhost() {
        assert!(is_app_url(&url("tauri://localhost/"), None));
        assert!(!is_app_url(&url("http://tauri.localhost/"), None));
        assert!(!is_app_url(&url("https://tauri.localhost/"), None));
        assert!(is_app_url(
            &url(&format!("blob:tauri://localhost/{BLOB_ID}")),
            None
        ));
        assert!(!is_app_url(
            &url(&format!("blob:http://tauri.localhost/{BLOB_ID}")),
            None
        ));
    }

    /// The data export saves its file through an `<a download>` at a `blob:`
    /// URL the app minted (`screens/Profile.tsx`), which WebKitGTK puts
    /// through the guard as a navigation: a blob of the app's own origin is
    /// the app, and no other blob is.
    #[test]
    fn a_blob_the_app_minted_is_the_app_and_no_other_blob_is() {
        for (scheme, host) in APP_ORIGINS {
            let blob = url(&format!("blob:{scheme}://{host}/{BLOB_ID}"));
            assert!(is_app_url(&blob, None), "{blob} is the app's own");
        }
        for other in [
            format!("blob:https://evil.example/{BLOB_ID}"),
            // An opaque origin (a sandboxed frame, a `data:` page).
            format!("blob:null/{BLOB_ID}"),
            // The same lookalikes, ports and credentials as a page.
            format!("blob:http://tauri.localhost.evil.example/{BLOB_ID}"),
            format!("blob:http://tauri.localhost:8080/{BLOB_ID}"),
            format!("blob:tauri://localhost:1420/{BLOB_ID}"),
            format!("blob:http://user@tauri.localhost/{BLOB_ID}"),
            format!("blob:tauri://user@localhost/{BLOB_ID}"),
            format!("blob:file:///C:/{BLOB_ID}"),
            // No origin at all, or a blob of a blob.
            format!("blob:/{BLOB_ID}"),
            format!("blob://tauri.localhost/{BLOB_ID}"),
            format!("blob:blob:http://tauri.localhost/{BLOB_ID}"),
            format!("blob:blob:tauri://localhost/{BLOB_ID}"),
            // The dev server's, in a build that is not a dev build.
            format!("blob:http://localhost:1420/{BLOB_ID}"),
        ] {
            assert!(!is_app_url(&url(&other), None), "{other} must be cancelled");
        }
    }

    /// The tests above hold the decision; this holds the guard on the main
    /// window. `build_main_window` (webview2.rs) is how `setup()` builds the
    /// one main window on every platform
    /// (`webview2::tests::the_window_the_sweep_and_the_delete_are_wired`),
    /// and it must chain the guard onto that window's builder.
    #[test]
    fn the_main_window_is_built_with_the_guard() {
        let webview2 = include_str!("webview2.rs").replace('\r', "");
        let build = &webview2[webview2
            .find("pub fn build_main_window(")
            .expect("webview2.rs no longer has build_main_window")..];
        let build: String = build[..build.find("\n}\n").unwrap()]
            .split_whitespace()
            .collect();
        assert!(
            build.contains(
                "letbuilder=tauri::WebviewWindowBuilder::from_config(app,config)?\
                 .on_navigation(crate::utils::navigation_guard::guard(app));"
            ),
            "build_main_window no longer puts the navigation guard on the main window"
        );
        assert_eq!(
            build.matches("WebviewWindowBuilder::").count(),
            1,
            "build_main_window makes a second builder, without the guard"
        );
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
        assert!(is_app_url(
            &url(&format!("blob:http://localhost:1420/{BLOB_ID}")),
            Some(&dev)
        ));
        assert!(!is_app_url(
            &url(&format!("blob:http://localhost:1421/{BLOB_ID}")),
            Some(&dev)
        ));
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
