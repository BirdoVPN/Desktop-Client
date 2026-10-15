//! MR-2011: the app's own IPC commands answer the main window only, and only
//! the ones the UI calls.
//!
//! Before this, the app had no permission manifest for its commands, and
//! Tauri consults the capabilities for an app command only when it has one
//! (tauri 2.12 `webview/mod.rs`, `on_message`: the ACL is checked when
//! `plugin_command.is_some() || has_app_acl_manifest || !is_local`), so every
//! registered command could be invoked from any local window or webview.
//! build.rs now declares every command (`APP_COMMANDS`, one `allow-`/`deny-`
//! permission each), and `capabilities/default.json` grants the ones the UI
//! calls to the window labelled `main`.
//!
//! These tests resolve the ACL the way the app does at startup: from the
//! manifests and capabilities tauri-build wrote to OUT_DIR (the files
//! `generate_context!` compiles in), through Tauri's own `Resolved::resolve`
//! and `RuntimeAuthority::resolve_access`, the call `on_message` makes for
//! every invoke. So they test the resolver the app runs, not a reading of the
//! JSON. Which commands the UI calls is `src/__tests__/ipc-contracts.test.ts`'s
//! job: it scans `src/` and pins this capability's grants to that list.

use std::collections::{BTreeMap, BTreeSet};

use tauri::ipc::{Origin, RuntimeAuthority};
use tauri::utils::acl::{
    capability::Capability, manifest::Manifest, resolved::Resolved, APP_ACL_KEY,
};
use tauri::utils::platform::Target;

const ACL_MANIFESTS: &str = include_str!(concat!(env!("OUT_DIR"), "/acl-manifests.json"));
const CAPABILITIES: &str = include_str!(concat!(env!("OUT_DIR"), "/capabilities.json"));
const MAIN_RS: &str = include_str!("../main.rs");

fn acl() -> BTreeMap<String, Manifest> {
    serde_json::from_str(ACL_MANIFESTS).expect("tauri-build's acl-manifests.json")
}

fn capabilities() -> BTreeMap<String, Capability> {
    serde_json::from_str(CAPABILITIES).expect("tauri-build's capabilities.json")
}

/// Whether Tauri checks the app's own commands at all, and the authority it
/// checks them against.
fn authority() -> (bool, RuntimeAuthority) {
    let acl = acl();
    let resolved =
        Resolved::resolve(&acl, capabilities(), Target::current()).expect("the ACL resolves");
    (resolved.has_app_acl, RuntimeAuthority::new(acl, resolved))
}

/// The commands `ipc_handler` in main.rs registers, read from its
/// `generate_handler![...]` block (comments dropped, paths cut to the name).
fn registered_commands() -> BTreeSet<String> {
    let marker = "generate_handler![";
    let start = MAIN_RS.find(marker).expect("generate_handler![ in main.rs") + marker.len();
    let end = start
        + MAIN_RS[start..]
            .find(']')
            .expect("generate_handler! closes");
    let mut out = BTreeSet::new();
    for line in MAIN_RS[start..end].lines() {
        let code = line.split("//").next().unwrap_or_default();
        for entry in code.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let name = entry.rsplit("::").next().unwrap_or(entry).trim();
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "unexpected entry in generate_handler!: {entry}"
            );
            assert!(out.insert(name.to_owned()), "{name} is registered twice");
        }
    }
    // Guards the parser: an empty set would make every check below vacuous.
    assert!(
        out.len() > 40,
        "only {} commands parsed from main.rs",
        out.len()
    );
    out
}

/// The app manifest's permissions: for each command it names, its `allow-`
/// permission id.
fn app_manifest() -> BTreeMap<String, String> {
    let acl = acl();
    let manifest = acl
        .get(APP_ACL_KEY)
        .expect("no app permission manifest: build.rs must pass AppManifest::commands");
    assert!(
        manifest.default_permission.is_none() && manifest.permission_sets.is_empty(),
        "the app grants its commands one by one; a default or a set would grant them in bulk"
    );
    let mut allowed = BTreeMap::new();
    for (id, permission) in &manifest.permissions {
        assert!(
            permission.scope.allow.is_none() && permission.scope.deny.is_none(),
            "{id} carries a scope"
        );
        let commands = &permission.commands;
        if let Some(slug) = id.strip_prefix("allow-") {
            assert!(
                commands.deny.is_empty(),
                "{id} also denies {:?}",
                commands.deny
            );
            let [command] = commands.allow.as_slice() else {
                panic!("{id} allows {:?}, not exactly one command", commands.allow);
            };
            assert_eq!(command.replace('_', "-"), slug, "{id} allows {command}");
            allowed.insert(command.clone(), id.clone());
        } else if id.starts_with("deny-") {
            assert!(
                commands.allow.is_empty(),
                "{id} allows {:?}",
                commands.allow
            );
        } else {
            panic!("unexpected app permission {id}");
        }
    }
    allowed
}

/// The app commands granted by any capability, with that capability.
fn granted() -> BTreeMap<String, Capability> {
    let manifest = app_manifest();
    let by_id: BTreeMap<&str, &str> = manifest
        .iter()
        .map(|(cmd, id)| (id.as_str(), cmd.as_str()))
        .collect();
    let mut out = BTreeMap::new();
    for capability in capabilities().into_values() {
        for entry in &capability.permissions {
            let id = entry.identifier();
            if id.get_prefix().is_some() {
                continue; // a plugin's permission (`core:`, `opener:`, ...)
            }
            let command = by_id.get(id.get()).unwrap_or_else(|| {
                panic!(
                    "{} grants {}, which allows no app command",
                    capability.identifier,
                    id.get()
                )
            });
            out.insert((*command).to_owned(), capability.clone());
        }
    }
    out
}

#[test]
fn the_app_has_a_command_manifest_so_tauri_checks_its_commands() {
    let (has_app_acl, _) = authority();
    assert!(
        has_app_acl,
        "no app ACL: Tauri lets every local window and webview call every app command"
    );
}

#[test]
fn every_registered_command_has_exactly_one_allow_permission() {
    let declared: BTreeSet<String> = app_manifest().into_keys().collect();
    let registered = registered_commands();
    assert_eq!(
        declared, registered,
        "build.rs APP_COMMANDS and main.rs generate_handler! differ"
    );
}

#[test]
fn every_app_grant_is_for_the_main_window_and_local_content_only() {
    let granted = granted();
    assert!(
        !granted.is_empty(),
        "no app command is granted to any window"
    );
    for (command, capability) in &granted {
        assert_eq!(
            capability.windows,
            ["main"],
            "{command}: granted by {} to windows {:?}",
            capability.identifier,
            capability.windows
        );
        assert!(
            capability.webviews.is_empty(),
            "{command}: granted to webviews {:?}",
            capability.webviews
        );
        assert!(
            capability.remote.is_none(),
            "{command}: granted to remote content"
        );
        assert!(
            capability.platforms.is_none(),
            "{command}: granted per platform"
        );
    }
}

#[test]
fn the_main_window_may_call_exactly_the_granted_commands() {
    let (_, authority) = authority();
    let granted = granted();
    for command in app_manifest().keys() {
        let allowed = authority
            .resolve_access(command, "main", "main", &Origin::Local)
            .is_some();
        assert_eq!(
            allowed,
            granted.contains_key(command),
            "{command}: the main window's access does not match the capability"
        );
    }
}

#[test]
fn no_other_window_webview_or_origin_may_call_an_app_command() {
    let (_, authority) = authority();
    let remote = Origin::Remote {
        url: "https://evil.example/".parse().expect("url"),
    };
    for command in app_manifest().keys() {
        for (window, webview, origin) in [
            ("other", "other", &Origin::Local),
            ("main", "main", &remote),
        ] {
            assert!(
                authority
                    .resolve_access(command, window, webview, origin)
                    .is_none(),
                "{command} is callable from window {window}, webview {webview}, origin {origin}"
            );
        }
    }
}
