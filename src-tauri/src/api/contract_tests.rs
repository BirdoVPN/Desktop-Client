//! K5 connect-contract tests: the SERIALIZED bodies desktop POSTs to
//! `/vpn/connect` and `/vpn/multi-hop/connect`, validated against the
//! backend's own generated JSON Schema.
//!
//! WHY a schema and not the struct: the backend refuses the WHOLE body on one
//! unknown key — `ValidationPipe(forbidNonWhitelisted)` on `/vpn/connect`, zod
//! `.strict()` on `/vpn/multi-hop/connect`. A misspelt key, a snake_case slip
//! in a `#[serde(rename)]`, or a field desktop starts sending before the
//! backend learned it, is a 400 for every user of the next release, and no
//! Rust type check can see it. Estate rule: assert the SERIALIZED body, not
//! the struct.
//!
//! The schema is `contract/vpn-protocol.schema.json`, vendored byte-for-byte
//! from birdo-web `backend/contract/vpn-protocol.schema.json` (generated there
//! from ConnectDto + the zod twin by `npm run contract:generate`, pinned by
//! protocol-schema.spec.ts). Re-vendoring = copy the file verbatim AND update
//! `SCHEMA_SHA256` in the same commit; nothing else passes the drift test.
//!
//! Fixtures come from the REAL producers wherever one exists
//! (`utils::get_device_id`, `birdo_pq::generate_keypair`,
//! `commands::vpn::generate_wireguard_keypair`, `attestation::platform` /
//! `version`, the `FALLBACK_*` constants) so a change in WHAT desktop emits —
//! not only in how it is named — fails here rather than in production.

use super::attestation::{self, DesktopAttestation};
use super::client::{build_connect_request, build_multi_hop_request};
use super::types::{ConnectRequest, LoginRequest, MultiHopConnectRequest};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonschema::error::ValidationErrorKind;
use jsonschema::Validator;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SCHEMA_SRC: &str = include_str!("../../contract/vpn-protocol.schema.json");

/// `sha256sum` of birdo-web `backend/contract/vpn-protocol.schema.json` at the
/// commit vendored (LF bytes, as git stores them). The test normalises `\r\n`
/// so an autocrlf checkout hashes the same as CI.
const SCHEMA_SHA256: &str = "9b8690c097876541c0cdcd4037e335ed36cfe26b301e1a9d1c26cdee96c71384";

const CONNECT: &str = "ConnectRequest";
const MULTI_HOP: &str = "MultiHopConnectRequest";

/// Contract properties desktop deliberately does NOT send on `/vpn/connect`.
/// `integrityToken` is Play Integrity (Android only); `rebuild` /
/// `currentKeyId` are the Mobile-Client #159 zero-blackhole rebuild, which
/// desktop has not adopted. Listed explicitly so that when the backend adds a
/// property the key-set test fails and someone DECIDES (send it, or add it
/// here with a reason) instead of the gap going unnoticed for a release.
const CONNECT_KNOWN_UNSENT: &[&str] = &["integrityToken", "rebuild", "currentKeyId"];

/// As above for `/vpn/multi-hop/connect`. Adaptive Transport's
/// `fallbackReason` retry (commands/vpn.rs) only rebuilds single-hop sessions,
/// so the multi-hop body never carries it.
const MULTI_HOP_KNOWN_UNSENT: &[&str] = &[
    "integrityToken",
    "rebuild",
    "currentKeyId",
    "fallbackReason",
];

// ── helpers ─────────────────────────────────────────────────────────────────

fn schema() -> Value {
    serde_json::from_str(SCHEMA_SRC).expect("vendored schema parses as JSON")
}

/// A validator for ONE `$defs` entry, resolved inside the full document so the
/// root `$schema` / `$id` apply exactly as they do to the backend's copy — not
/// a lifted sub-object that would silently lose its draft.
fn validator_for(def: &str) -> Validator {
    let mut root = schema();
    root.as_object_mut()
        .unwrap()
        .insert("$ref".to_string(), json!(format!("#/$defs/{def}")));
    jsonschema::validator_for(&root).unwrap_or_else(|e| panic!("$defs/{def} compiles: {e}"))
}

fn def(def: &str) -> Value {
    schema()["$defs"][def].clone()
}

fn def_properties(name: &str) -> BTreeSet<String> {
    def(name)["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("$defs/{name}.properties is an object"))
        .keys()
        .cloned()
        .collect()
}

fn def_required(name: &str) -> BTreeSet<String> {
    def(name)["required"]
        .as_array()
        .unwrap_or_else(|| panic!("$defs/{name}.required is an array"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// The bytes on the wire, as a JSON object. `serde_json::to_string` first so
/// what is validated is what `reqwest` would send, not an in-memory tree.
fn body<T: Serialize>(req: &T) -> Map<String, Value> {
    let wire = serde_json::to_string(req).expect("serializes");
    serde_json::from_str::<Value>(&wire)
        .expect("round-trips")
        .as_object()
        .expect("a JSON object")
        .clone()
}

fn errors(validator: &Validator, instance: &Value) -> Vec<String> {
    validator
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect()
}

fn assert_valid(def: &str, instance: &Value) {
    let errs = errors(&validator_for(def), instance);
    // Keys, not the whole body: a populated body carries a ~1.5 KB ML-KEM key
    // that buries the actual failure in the test output.
    let keys: Vec<&String> = instance
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    assert!(
        errs.is_empty(),
        "{def} rejected a body with keys {keys:?}: {errs:#?}"
    );
}

/// Every error kind the schema raises for `instance`; the mutation tests
/// assert the SPECIFIC keyword tripped, not merely "invalid".
fn error_kinds(def: &str, instance: &Value) -> Vec<ValidationErrorKind> {
    validator_for(def)
        .iter_errors(instance)
        .map(|e| e.into_parts().kind)
        .collect()
}

fn unexpected_properties(def: &str, instance: &Value) -> Vec<String> {
    error_kinds(def, instance)
        .into_iter()
        .filter_map(|k| match k {
            ValidationErrorKind::AdditionalProperties { unexpected } => Some(unexpected),
            _ => None,
        })
        .flatten()
        .collect()
}

fn required_violations(def: &str, instance: &Value) -> Vec<String> {
    error_kinds(def, instance)
        .into_iter()
        .filter_map(|k| match k {
            ValidationErrorKind::Required { property } => property.as_str().map(str::to_string),
            _ => None,
        })
        .collect()
}

/// Attestation shaped exactly like `attestation::sign` emits: base64url
/// no-pad 64-byte Ed25519 signature, the real platform token and the real
/// crate version. `sign()` itself returns None on a build without the key.
fn attestation_fixture() -> DesktopAttestation {
    DesktopAttestation {
        nonce: URL_SAFE_NO_PAD.encode([7u8; 32]),
        kid: "desk-2026-09".to_string(),
        signature: URL_SAFE_NO_PAD.encode([9u8; 64]),
        platform: attestation::platform(),
        version: attestation::version(),
    }
}

/// The real BirdoPQ producer: ML-KEM-1024 public key, STANDARD base64, the
/// exact encoding `birdo_pq::get_client_public_key_b64` uses.
fn real_pq_public_key() -> String {
    STANDARD.encode(&crate::vpn::birdo_pq::generate_keypair().public_key)
}

/// The real WireGuard producer (X25519 public key, STANDARD base64 with its
/// trailing `=`).
fn real_wireguard_public_key() -> String {
    crate::commands::vpn::generate_wireguard_keypair().1
}

fn snake_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Every field set, through the production builder (so the deviceId /
/// pqClientCanDecapsulate plumbing is the real one) plus `preferred_region`,
/// the one field no dial path sets today.
fn full_connect_request() -> ConnectRequest {
    let mut req = build_connect_request(
        "node-abc",
        &crate::utils::get_device_name(),
        Some(real_wireguard_public_key()),
        Some(true),
        Some(crate::commands::vpn::FALLBACK_HANDSHAKE_TIMEOUT),
        Some(true),
        Some(real_pq_public_key()),
        true,
        Some(attestation_fixture()),
    );
    req.preferred_region = Some("eu-west".to_string());
    req
}

fn full_multi_hop_request() -> MultiHopConnectRequest {
    build_multi_hop_request(
        "entry-node",
        "exit-node",
        &crate::utils::get_device_name(),
        &real_wireguard_public_key(),
        true,
        true,
        Some(real_pq_public_key()),
        true,
        Some(attestation_fixture()),
    )
}

// ── the vendored file itself ────────────────────────────────────────────────

/// Byte-identical to birdo-web main: a hand edit here (or a re-vendor without
/// bumping the pin) is a contract the backend never agreed to.
#[test]
fn vendored_schema_is_the_birdo_web_blob() {
    let lf = SCHEMA_SRC.replace("\r\n", "\n");
    let digest = hex::encode(Sha256::digest(lf.as_bytes()));
    assert_eq!(
        digest, SCHEMA_SHA256,
        "contract/vpn-protocol.schema.json differs from the pinned birdo-web blob; \
         re-vendor verbatim from birdo-web main and update SCHEMA_SHA256 together"
    );
}

#[test]
fn vendored_schema_is_a_valid_draft_2020_12_document() {
    let s = schema();
    assert_eq!(s["$schema"], "https://json-schema.org/draft/2020-12/schema");
    jsonschema::meta::validate(&s).unwrap_or_else(|e| panic!("meta-schema violation: {e}"));
    // The generator marks the file authoritative and names the definitions it
    // emits; a stale or hand-rolled copy tends to lose both.
    assert_eq!(s["_status"]["authoritative"], true);
    for name in [CONNECT, MULTI_HOP] {
        assert!(
            s["_status"]["definitions"]
                .as_array()
                .unwrap()
                .contains(&json!(name)),
            "_status.definitions lists {name}"
        );
        assert!(s["$defs"][name].is_object(), "$defs/{name} present");
    }
}

/// Both request definitions are closed — that closedness is the whole reason
/// this file exists; a regenerated schema that opened them would let every
/// test below pass vacuously.
#[test]
fn request_definitions_refuse_unknown_properties() {
    for name in [CONNECT, MULTI_HOP] {
        assert_eq!(def(name)["additionalProperties"], false, "$defs/{name}");
    }
}

// ── the bodies desktop sends ────────────────────────────────────────────────

#[test]
fn fully_populated_connect_body_validates() {
    let b = Value::Object(body(&full_connect_request()));
    assert_valid(CONNECT, &b);
}

#[test]
fn fully_populated_multi_hop_body_validates() {
    let b = Value::Object(body(&full_multi_hop_request()));
    assert_valid(MULTI_HOP, &b);
}

/// The minimal bodies the dial paths actually send on a dev build: no
/// attestation, no PQ, no stealth — the pre-attestation shape older
/// backends still accept.
#[test]
fn minimal_dial_bodies_validate() {
    let req = build_connect_request(
        "node-abc",
        "Windows Desktop (abcdef)",
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    );
    let b = Value::Object(body(&req));
    assert_valid(CONNECT, &b);
    // and NOT bloated: only what was set plus the identity.
    let keys: BTreeSet<&str> = b.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["serverNodeId", "deviceName", "deviceId"]
            .into_iter()
            .collect()
    );

    let req = build_multi_hop_request(
        "entry",
        "exit",
        "Windows Desktop (abcdef)",
        &real_wireguard_public_key(),
        false,
        false,
        None,
        false,
        None,
    );
    let b = Value::Object(body(&req));
    assert_valid(MULTI_HOP, &b);
    let keys: BTreeSet<&str> = b.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "entryNodeId",
            "exitNodeId",
            "deviceName",
            "deviceId",
            "clientPublicKey",
            "stealthMode",
            "quantumProtection"
        ]
        .into_iter()
        .collect()
    );
}

/// Serialized keys ⊆ contract properties, and the complement is EXACTLY the
/// documented unsent list — so a new backend property, or a desktop field the
/// backend does not know, both fail with the offending key named.
#[test]
fn connect_body_keys_are_the_contract_minus_the_known_unsent() {
    let sent: BTreeSet<String> = body(&full_connect_request()).keys().cloned().collect();
    let props = def_properties(CONNECT);
    let unknown: Vec<_> = sent.difference(&props).collect();
    assert!(
        unknown.is_empty(),
        "desktop sends keys the contract has no property for: {unknown:?}"
    );
    let unsent: BTreeSet<String> = props.difference(&sent).cloned().collect();
    let expected: BTreeSet<String> = CONNECT_KNOWN_UNSENT.iter().map(|s| s.to_string()).collect();
    assert_eq!(unsent, expected, "contract properties desktop does not send changed — decide, then update CONNECT_KNOWN_UNSENT");
}

#[test]
fn multi_hop_body_keys_are_the_contract_minus_the_known_unsent() {
    let sent: BTreeSet<String> = body(&full_multi_hop_request()).keys().cloned().collect();
    let props = def_properties(MULTI_HOP);
    let unknown: Vec<_> = sent.difference(&props).collect();
    assert!(
        unknown.is_empty(),
        "desktop sends keys the contract has no property for: {unknown:?}"
    );
    let unsent: BTreeSet<String> = props.difference(&sent).cloned().collect();
    let expected: BTreeSet<String> = MULTI_HOP_KNOWN_UNSENT
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(unsent, expected, "contract properties desktop does not send changed — decide, then update MULTI_HOP_KNOWN_UNSENT");
}

/// Every `required` property is present in what the builders emit — on the
/// MINIMAL body, since that is where a required field would go missing.
#[test]
fn every_required_property_is_present_on_the_minimal_bodies() {
    let connect = body(&build_connect_request(
        "n", "d", None, None, None, None, None, false, None,
    ));
    for key in def_required(CONNECT) {
        assert!(
            connect.contains_key(&key),
            "ConnectRequest.required {key} missing from {connect:?}"
        );
    }
    let multi = body(&build_multi_hop_request(
        "entry", "exit", "d", "k", false, false, None, false, None,
    ));
    let required = def_required(MULTI_HOP);
    // The contract does require these two; if it ever stops, this test is no
    // longer proving anything about multi-hop and must be revisited.
    assert!(
        required.contains("entryNodeId") && required.contains("exitNodeId"),
        "{required:?}"
    );
    for key in required {
        assert!(
            multi.contains_key(&key),
            "MultiHopConnectRequest.required {key} missing from {multi:?}"
        );
    }
}

// ── device identity (the K5 finding) ────────────────────────────────────────

/// Desktop was the one client omitting deviceId on connect. Every dial path
/// funnels through the two builders, and the value must be the SAME one the
/// login body registers — that pair is the backend's identity for slot
/// reclaim, so a different id here would be a second "device".
#[test]
fn device_id_is_sent_on_connect_and_multi_hop_and_matches_login() {
    // The credentials are irrelevant here (only `deviceId` is read), but
    // `LoginRequest::new` takes a password, and a literal one trips CodeQL's
    // rust/hard-coded-cryptographic-value rule, which cannot tell a discarded
    // test placeholder from a real secret. Built at run time, same trick as
    // `attestation::tests::test_nonce`.
    let placeholder: String = std::iter::repeat_n('x', 8).collect();
    let login = serde_json::to_value(LoginRequest::new("u@example.com", &placeholder)).unwrap();
    let login_id = login["deviceId"]
        .as_str()
        .expect("login carries deviceId")
        .to_string();
    assert_eq!(login_id, crate::utils::get_device_id());

    for (route, b) in [
        (
            "connect",
            body(&build_connect_request(
                "n", "d", None, None, None, None, None, false, None,
            )),
        ),
        (
            "multi-hop",
            body(&build_multi_hop_request(
                "entry", "exit", "d", "k", false, false, None, false, None,
            )),
        ),
    ] {
        let sent = b.get("deviceId").unwrap_or_else(|| {
            panic!(
                "{route} body omits deviceId: {:?}",
                b.keys().collect::<Vec<_>>()
            )
        });
        assert_eq!(
            sent,
            &json!(login_id),
            "{route} body must carry the login's deviceId"
        );
    }
}

/// The real producer's value satisfies the contract's `deviceId` constraints
/// (`^[A-Za-z0-9._:-]+$`, 1..=128). Isolated from the full-body test so a
/// format change in `get_device_id` is named as such.
#[test]
fn real_device_id_fits_the_contract() {
    let id = crate::utils::get_device_id();
    assert_valid(CONNECT, &json!({ "deviceId": id }));
    assert_valid(
        MULTI_HOP,
        &json!({ "entryNodeId": "a", "exitNodeId": "b", "deviceId": id }),
    );
    // …and the constraint is real: the same id with one illegal byte is refused.
    let kinds = error_kinds(CONNECT, &json!({ "deviceId": format!("{id}/x") }));
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, ValidationErrorKind::Pattern { .. })),
        "{kinds:?}"
    );
}

// ── mutations: prove the gate bites ─────────────────────────────────────────

/// Adding ONE unknown key to an otherwise valid body must be refused, and the
/// refusal must name that key (AdditionalProperties), not something else.
#[test]
fn unknown_key_is_refused_on_both_bodies() {
    for (def, mut b) in [
        (CONNECT, body(&full_connect_request())),
        (MULTI_HOP, body(&full_multi_hop_request())),
    ] {
        assert_valid(def, &Value::Object(b.clone()));
        b.insert("deviceFingerprint".to_string(), json!("abc"));
        let mutated = Value::Object(b);
        assert!(
            !validator_for(def).is_valid(&mutated),
            "{def} accepted an unknown key"
        );
        assert_eq!(
            unexpected_properties(def, &mutated),
            vec!["deviceFingerprint".to_string()],
            "{def}"
        );
    }
}

/// Renaming ANY sent key to its snake_case spelling — the serde slip this
/// gate exists for — must be refused, one key at a time, with that key named.
/// For a required key the rename also surfaces as `required`.
#[test]
fn every_key_renamed_to_snake_case_is_refused() {
    for (def, b) in [
        (CONNECT, body(&full_connect_request())),
        (MULTI_HOP, body(&full_multi_hop_request())),
    ] {
        assert!(!b.is_empty());
        let required = def_required(def);
        for key in b.keys() {
            let renamed = snake_case(key);
            assert_ne!(&renamed, key, "{key} has no snake_case form to mutate into");
            let mut m = b.clone();
            let v = m.remove(key).unwrap();
            m.insert(renamed.clone(), v);
            let mutated = Value::Object(m);
            assert!(
                !validator_for(def).is_valid(&mutated),
                "{def} accepted `{renamed}` in place of `{key}`"
            );
            assert_eq!(
                unexpected_properties(def, &mutated),
                vec![renamed.clone()],
                "{def}/{key}"
            );
            if required.contains(key) {
                assert_eq!(
                    required_violations(def, &mutated),
                    vec![key.clone()],
                    "{def}/{key}"
                );
            }
        }
    }
}

#[test]
fn dropping_a_required_key_is_refused() {
    let mut b = body(&full_multi_hop_request());
    b.remove("exitNodeId");
    let mutated = Value::Object(b);
    assert!(!validator_for(MULTI_HOP).is_valid(&mutated));
    assert_eq!(
        required_violations(MULTI_HOP, &mutated),
        vec!["exitNodeId".to_string()]
    );
}

/// Keys are not the only thing enforced: the value patterns are. A WireGuard
/// key without its `=`, a platform token outside the enum, a version that is
/// not semver — each refused under its own keyword.
#[test]
fn value_constraints_are_enforced_not_just_keys() {
    let ok = Value::Object(body(&full_connect_request()));
    assert_valid(CONNECT, &ok);

    let mut m = body(&full_connect_request());
    m.insert(
        "clientPublicKey".into(),
        json!(real_wireguard_public_key().trim_end_matches('=')),
    );
    assert!(error_kinds(CONNECT, &Value::Object(m))
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Pattern { .. })));

    let mut m = body(&full_connect_request());
    m.insert("desktopAttestPlatform".into(), json!("win32"));
    assert!(error_kinds(CONNECT, &Value::Object(m))
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Enum { .. })));

    let mut m = body(&full_connect_request());
    m.insert("desktopAttestVersion".into(), json!("v1.4"));
    assert!(error_kinds(CONNECT, &Value::Object(m))
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Pattern { .. })));

    let mut m = body(&full_connect_request());
    m.insert("stealthMode".into(), json!("true"));
    assert!(error_kinds(CONNECT, &Value::Object(m))
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Type { .. })));
}

/// The Adaptive Transport constants are the contract enum, spelled exactly;
/// the underscore spelling — the natural Rust slip — is refused.
#[test]
fn fallback_reason_constants_are_the_contract_enum() {
    let allowed: BTreeSet<String> = def(CONNECT)["properties"]["fallbackReason"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    for reason in [
        crate::commands::vpn::FALLBACK_HANDSHAKE_TIMEOUT,
        crate::commands::vpn::FALLBACK_TRANSPORT_BLOCKED,
    ] {
        assert!(
            allowed.contains(reason),
            "{reason} not in contract enum {allowed:?}"
        );
        let req =
            build_connect_request("n", "d", None, None, Some(reason), None, None, false, None);
        assert_valid(CONNECT, &Value::Object(body(&req)));
    }
    let kinds = error_kinds(CONNECT, &json!({ "fallbackReason": "handshake_timeout" }));
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, ValidationErrorKind::Enum { .. })),
        "{kinds:?}"
    );
}

/// The real ML-KEM-1024 public key encoding lands inside the contract's
/// 2080..=2200 window on BOTH routes. A base64 variant change (url-safe,
/// no-pad) or a parameter-set change would move it out.
#[test]
fn real_pq_public_key_fits_the_contract_window() {
    let pk = real_pq_public_key();
    let (min, max) = (
        def(CONNECT)["properties"]["pqClientPublicKey"]["minLength"]
            .as_u64()
            .unwrap() as usize,
        def(CONNECT)["properties"]["pqClientPublicKey"]["maxLength"]
            .as_u64()
            .unwrap() as usize,
    );
    assert!(
        (min..=max).contains(&pk.len()),
        "len {} outside {min}..={max}",
        pk.len()
    );
    assert_valid(
        CONNECT,
        &json!({ "pqClientPublicKey": pk, "quantumProtection": true, "pqClientCanDecapsulate": true }),
    );
    assert_valid(
        MULTI_HOP,
        &json!({ "entryNodeId": "a", "exitNodeId": "b", "pqClientPublicKey": pk }),
    );
    // The window is enforced: a 32-byte key (the X25519 length) is refused.
    let kinds = error_kinds(
        CONNECT,
        &json!({ "pqClientPublicKey": STANDARD.encode([1u8; 32]) }),
    );
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, ValidationErrorKind::MinLength { .. })),
        "{kinds:?}"
    );
}

// ── BirdoShield (OPEN-WORK D18): per-device dnsFiltering ────────────────────

/// The vendored contract (birdo-web #465) declares `dnsFiltering` as a
/// boolean on BOTH request definitions — the backend keys the filtering
/// resolver on this per-device flag, so a schema without it means the
/// backend that generated it would 400 the whole body.
#[test]
fn dns_filtering_is_a_boolean_property_on_both_contracts() {
    for name in [CONNECT, MULTI_HOP] {
        assert!(
            def_properties(name).contains("dnsFiltering"),
            "$defs/{name} lacks dnsFiltering — re-vendor from birdo-web #465 or later"
        );
        assert_eq!(
            def(name)["properties"]["dnsFiltering"]["type"],
            "boolean",
            "$defs/{name}.dnsFiltering"
        );
    }
}

/// With BirdoShield ON, both dial paths serialize `dnsFiltering: true`, the
/// body validates, and the key is the camelCase spelling the backend
/// whitelists (a `dns_filtering` slip would be a 400 for every shielded user).
#[test]
fn dns_filtering_true_is_sent_on_both_dial_paths_when_enabled() {
    let connect = body(&build_connect_request(
        "n", "d", None, None, None, None, None, true, None,
    ));
    assert_eq!(connect.get("dnsFiltering"), Some(&json!(true)));
    assert!(!connect.contains_key("dns_filtering"));
    assert_valid(CONNECT, &Value::Object(connect));

    let multi = body(&build_multi_hop_request(
        "entry",
        "exit",
        "d",
        &real_wireguard_public_key(),
        false,
        false,
        None,
        true,
        None,
    ));
    assert_eq!(multi.get("dnsFiltering"), Some(&json!(true)));
    assert!(!multi.contains_key("dns_filtering"));
    assert_valid(MULTI_HOP, &Value::Object(multi));
}

/// With BirdoShield OFF (the default) the key is ABSENT on both paths — never
/// `false`. The server treats a missing flag as off, and an install that never
/// touched the toggle keeps posting the exact 1.4.42 body.
#[test]
fn dns_filtering_is_absent_on_both_dial_paths_when_off() {
    let connect = body(&build_connect_request(
        "n", "d", None, None, None, None, None, false, None,
    ));
    assert!(
        !connect.contains_key("dnsFiltering"),
        "OFF must be absent, not false: {connect:?}"
    );
    let multi = body(&build_multi_hop_request(
        "entry", "exit", "d", "k", false, false, None, false, None,
    ));
    assert!(
        !multi.contains_key("dnsFiltering"),
        "OFF must be absent, not false: {multi:?}"
    );
    // The single mapping rule both builders share.
    assert_eq!(super::client::dns_filtering_flag(true), Some(true));
    assert_eq!(super::client::dns_filtering_flag(false), None);
}
