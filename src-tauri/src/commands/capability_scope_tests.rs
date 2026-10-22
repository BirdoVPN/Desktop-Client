//! MR-713: what the webview may open in the system browser.
//!
//! The shell plugin this replaced checked every webview `open` against one
//! regex, `^https://(birdo\.app|[a-zA-Z0-9-]+\.birdo\.app)(/.*)?$`. The opener
//! plugin's equivalent is the scope on `opener:allow-open-url` in
//! `capabilities/default.json`, and its entries are GLOBS, matched by
//! tauri-plugin-opener 2.7.2 `scope.rs` as `glob::Pattern::new(url)` then
//! `pattern.matches(u)`. These tests run the scope through that same crate
//! (the `glob` dev-dependency unifies with the plugin's), so they test the
//! matcher the app uses, not a re-implementation of it.
//!
//! WHY the scope names exact hosts: `Pattern::matches` uses
//! `MatchOptions::new()`, where `*` also matches `/`. A subdomain wildcard such
//! as `https://*.birdo.app/*` therefore admits `https://evil.example/.birdo.app/`
//! (the `*` swallows `evil.example/`). `glob` has no one-or-more repetition, so
//! the old regex's `[a-zA-Z0-9-]+` cannot be written; the scope lists the hosts
//! the app actually opens instead (birdo.app, auth., dashboard.), which is
//! narrower than the regex, never wider.
//!
//! The URL lists live in `src/__tests__/fixtures/opener-urls.json`, shared with
//! `OpenerLinks.test.tsx`, which clicks every link in the UI and requires the
//! URLs it sees to be exactly the `opened` list. Together: every link the app
//! has is one this scope allows.

use serde_json::Value;
use std::path::Path;

const URLS: &str = include_str!("../../../src/__tests__/fixtures/opener-urls.json");

/// Every capability file, parsed. Read from the directory, not a fixed name,
/// because tauri-build loads every file in `capabilities/` and a second file
/// granting `opener:default` would widen the scope without touching
/// default.json.
fn capabilities() -> Vec<(String, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut out = Vec::new();
    for entry in
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("could not list {}: {e}", dir.display()))
    {
        let path = entry.expect("directory entry").path();
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("json"),
            "{} is not JSON; extend this test before adding a TOML capability",
            path.display()
        );
        let value: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
        out.push((path.display().to_string(), value));
    }
    assert!(
        out.iter().any(|(p, _)| p.ends_with("default.json")),
        "capabilities/default.json not found: {out:?}"
    );
    out
}

fn permissions(capability: &Value) -> &Vec<Value> {
    capability["permissions"]
        .as_array()
        .expect("a capability's `permissions` is an array")
}

fn identifier(permission: &Value) -> &str {
    match permission {
        Value::String(s) => s,
        Value::Object(o) => o["identifier"]
            .as_str()
            .expect("a scoped permission has a string `identifier`"),
        other => panic!("unexpected permission entry: {other}"),
    }
}

/// The allow and deny URL globs of every `opener:allow-open-url` grant.
fn open_url_scope() -> (Vec<glob::Pattern>, Vec<glob::Pattern>) {
    let compile = |entries: Option<&Value>| -> Vec<glob::Pattern> {
        entries
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|e| {
                        let url = e["url"].as_str().expect("scope entry has a string `url`");
                        glob::Pattern::new(url)
                            .unwrap_or_else(|err| panic!("scope url {url} is not a glob: {err}"))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    for (_, cap) in capabilities() {
        for p in permissions(&cap) {
            if identifier(p) == "opener:allow-open-url" {
                allow.extend(compile(p.get("allow")));
                deny.extend(compile(p.get("deny")));
            }
        }
    }
    (allow, deny)
}

/// tauri-plugin-opener 2.7.2 `Scope::is_url_allowed` for `with = None` (a
/// `url`-only entry is `Application::Default`, which matches only `None`).
fn allowed(url: &str, (allow, deny): &(Vec<glob::Pattern>, Vec<glob::Pattern>)) -> bool {
    !deny.iter().any(|p| p.matches(url)) && allow.iter().any(|p| p.matches(url))
}

fn url_list(key: &str) -> Vec<String> {
    let fixture: Value = serde_json::from_str(URLS).expect("opener-urls.json");
    let list: Vec<String> = fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("opener-urls.json has no `{key}` array"))
        .iter()
        .map(|v| v.as_str().expect("a URL string").to_owned())
        .collect();
    assert!(!list.is_empty(), "opener-urls.json `{key}` is empty");
    list
}

#[test]
fn no_shell_permission_and_the_only_opener_grant_is_a_scoped_open_url() {
    let mut open_url_grants = 0;
    for (file, cap) in capabilities() {
        for p in permissions(&cap) {
            let id = identifier(p);
            assert!(
                !id.starts_with("shell:"),
                "{file}: {id} - the shell plugin was removed (MR-713)"
            );
            if !id.starts_with("opener:") {
                continue;
            }
            // A bare `opener:*` string is either unscoped or a scope-only set:
            // `opener:default` and `opener:allow-default-urls` allow every
            // http(s), mailto: and tel: URL. Path and reveal commands are not
            // used by this app at all.
            assert_eq!(
                id, "opener:allow-open-url",
                "{file}: {id} - the app needs only opener:allow-open-url"
            );
            let entry = p
                .as_object()
                .unwrap_or_else(|| panic!("{file}: opener:allow-open-url must carry an `allow` scope, not be a bare string"));
            let allow = entry
                .get("allow")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{file}: opener:allow-open-url has no `allow` list"));
            assert!(!allow.is_empty(), "{file}: empty `allow` list");
            for scope in allow {
                let keys: Vec<&str> = scope
                    .as_object()
                    .expect("scope entry object")
                    .keys()
                    .map(String::as_str)
                    .collect();
                // `app` would let the webview pick the program that opens the
                // URL (`with`); a url-only entry permits only the default
                // browser.
                assert_eq!(keys, vec!["url"], "{file}: scope entry {scope}");
            }
            open_url_grants += 1;
        }
    }
    assert_eq!(
        open_url_grants, 1,
        "exactly one opener:allow-open-url grant expected"
    );
}

#[test]
fn every_url_the_app_opens_is_inside_the_scope() {
    let scope = open_url_scope();
    for url in url_list("opened") {
        assert!(
            allowed(&url, &scope),
            "{url} is opened by the UI (OpenerLinks.test.tsx) but the opener scope refuses it"
        );
    }
}

#[test]
fn foreign_lookalike_and_non_https_urls_are_refused() {
    let scope = open_url_scope();
    for url in url_list("refused") {
        assert!(
            !allowed(&url, &scope),
            "{url} must not pass the opener scope"
        );
    }
}

#[test]
fn every_scope_entry_is_an_exact_https_birdo_host() {
    let (allow, deny) = open_url_scope();
    assert!(deny.is_empty(), "no deny list is expected: {deny:?}");
    for pattern in &allow {
        let url = pattern.as_str();
        let rest = url
            .strip_prefix("https://")
            .unwrap_or_else(|| panic!("{url}: only https:// may be opened"));
        let host = rest.split('/').next().unwrap_or_default();
        assert!(
            host == "birdo.app" || host.ends_with(".birdo.app"),
            "{url}: not a birdo.app host"
        );
        assert!(
            !host.contains(['*', '?', '[', ']', '{', '}', '@', '\\']),
            "{url}: the host must be literal - a glob `*` also matches `/`"
        );
        // The path part is either absent or exactly `/*`.
        assert!(
            rest == host || rest == format!("{host}/*"),
            "{url}: expected `https://<host>` or `https://<host>/*`"
        );
    }
}

/// The reason for the rule above, demonstrated with the real matcher: if
/// this ever starts failing, `glob` changed how `*` treats `/`, and the
/// exact-host rule should be re-read rather than deleted.
#[test]
fn a_subdomain_wildcard_would_admit_a_foreign_host() {
    let wildcard = glob::Pattern::new("https://*.birdo.app/*").expect("glob");
    assert!(wildcard.matches("https://evil.example/.birdo.app/"));
}
