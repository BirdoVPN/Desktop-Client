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
//! The same schema pins the connect routes' error vocabulary
//! (`$defs/ErrorCode`, MR-1639): every code has a decided handling, and a
//! sample body in the server's envelope decodes to it.
//!
//! And the heartbeat reply (`$defs/HeartbeatResponse`, MR-1638): every
//! `$defs/HeartbeatReason` has a decided handling on both paths that read a
//! reply, a body per reason (the quota fields included) decodes into desktop's
//! model, and every property is either read or listed as deliberately unread.
//!
//! And the refused connect (`$defs/ConnectRefusal`, MR-139): every
//! `refusalReason` has a decided error on both dial paths, and a reason this
//! build does not know is handled as a refusal without one.
//!
//! Fixtures come from the REAL producers wherever one exists
//! (`utils::get_device_id`, `birdo_pq::generate_keypair`,
//! `commands::vpn::generate_wireguard_keypair`, `attestation::platform` /
//! `version`, the `FALLBACK_*` constants) so a change in WHAT desktop emits —
//! not only in how it is named — fails here rather than in production.

use super::attestation::{self, DesktopAttestation};
use super::client::{build_connect_request, build_multi_hop_request};
use super::types::{ConnectRequest, HeartbeatResponse, LoginRequest, MultiHopConnectRequest};
use super::{ApiError, BirdoApi};
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::vpn::reconnect_policy::{self, HeartbeatVerdict};
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
const SCHEMA_SHA256: &str = "c3a77432a48d81759193b37f5d0555b2527281bbfd17f741055a87aa6f0208d6";

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

/// `schema` itself, or the `$defs` entry it names when it is a local `$ref`
/// (`{"$ref": "#/$defs/RetryableDetails"}`, MR-1637).
fn resolved(schema: &Value) -> Value {
    match schema["$ref"].as_str() {
        Some(target) => def(target
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("a local $defs reference: {target}"))),
        None => schema.clone(),
    }
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

// ── connect error codes (MR-1639) ───────────────────────────────────────────

/// One machine-readable `error` code the connect routes emit, with a body
/// exactly as birdo-web's GlobalExceptionFilter writes it
/// ({statusCode, message, error, timestamp, path, requestId?, details?}) and
/// what desktop decided to make of it.
struct ErrorCodeCase {
    code: &'static str,
    body: Value,
    ipc: IpcErrorCode,
    /// The wait the dial paths honour (`IpcError::server_asked_to_wait`).
    wait_secs: Option<u64>,
}

fn envelope(status: u16, code: &str, message: &str, details: Option<Value>) -> Value {
    let mut body = json!({
        "statusCode": status,
        "message": message,
        "error": code,
        "timestamp": "2026-10-13T09:00:00.000Z",
        "path": "/api/v1/vpn/connect",
        "requestId": "4f1c2a",
    });
    if let Some(details) = details {
        body["details"] = details;
    }
    body
}

/// Every code in `$defs/ErrorCode`, decided. The 503s carry birdo-web's
/// `RETRY_AFTER_SECONDS` (30, QuotaCheckUnavailableError and
/// PskOverSshRefusedError alike; 15, TunnelAddressUnavailableError).
fn error_code_cases() -> Vec<ErrorCodeCase> {
    let retry = Some(json!({ "retryable": true, "retryAfterSeconds": 30 }));
    vec![
        ErrorCodeCase {
            code: "update_required",
            body: envelope(
                426,
                "update_required",
                "This version of BirdoVPN is no longer supported. Please update the app to \
                 reconnect.",
                Some(json!({
                    "minVersion": "1.4.45",
                    "currentVersion": "1.4.40",
                    "updateUrl": "https://birdo.app/clients",
                })),
            ),
            ipc: IpcErrorCode::UpgradeRequired,
            wait_secs: None,
        },
        // MR-1944: its own code and copy. It used to be mapped by its 403
        // status alone and read as `subscription_required` ("upgrade your
        // plan"), which cannot help a build the attestation policy refused.
        ErrorCodeCase {
            code: "client_attestation_required",
            body: envelope(
                403,
                "client_attestation_required",
                "This VPN requires an official, unmodified BirdoVPN client.",
                None,
            ),
            ipc: IpcErrorCode::ClientAttestationRequired,
            wait_secs: None,
        },
        ErrorCodeCase {
            code: "quota_check_unavailable",
            body: envelope(
                503,
                "quota_check_unavailable",
                "We could not check your free data allowance just now. Please try again in a \
                 moment.",
                retry.clone(),
            ),
            ipc: IpcErrorCode::ServerError,
            wait_secs: Some(30),
        },
        ErrorCodeCase {
            code: "psk_delivery_unavailable",
            body: envelope(
                503,
                "psk_delivery_unavailable",
                "We could not set up a secure connection to this server just now. Please try \
                 again in a moment.",
                retry,
            ),
            ipc: IpcErrorCode::ServerError,
            wait_secs: Some(30),
        },
        // MR-2057 (birdo-web #711): the allocator could not prove a tunnel
        // address free and failed closed. Retryable after the server's wait,
        // like the two above; before this it read as `server_unavailable`.
        ErrorCodeCase {
            code: "tunnel_address_unavailable",
            body: envelope(
                503,
                "tunnel_address_unavailable",
                "We could not assign your connection an address on this server just now.                  Please try again in a moment.",
                Some(json!({ "retryable": true, "retryAfterSeconds": 15 })),
            ),
            ipc: IpcErrorCode::ServerError,
            wait_secs: Some(15),
        },
    ]
}

fn classify(status: u16, body: &Value) -> ApiError {
    BirdoApi::classify_error_response(
        reqwest::StatusCode::from_u16(status).expect("a valid status"),
        &body.to_string(),
    )
}

fn contract_error_codes() -> BTreeSet<String> {
    def("ErrorCode")["enum"]
        .as_array()
        .expect("$defs/ErrorCode.enum is an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// A re-vendored contract with a code desktop has not decided on fails HERE,
/// naming it — not in production as a generic "server unavailable" (which is
/// how `psk_delivery_unavailable` arrived).
#[test]
fn every_contract_error_code_has_a_decided_handling() {
    let decided: BTreeSet<String> = error_code_cases()
        .iter()
        .map(|c| c.code.to_string())
        .collect();
    assert_eq!(
        contract_error_codes(),
        decided,
        "$defs/ErrorCode changed: decide how desktop handles the new code, then add it to \
         error_code_cases"
    );
}

/// Each sample IS the contract's shape (validated against `$defs/<code>`,
/// under the status the contract pins), and decodes to the decided code and
/// wait. The two retryable 503s are retryable, never a hard refusal, and
/// never a transport failure (no Adaptive Transport switch can follow them).
#[test]
fn each_error_code_body_is_the_contracts_shape_and_maps_as_decided() {
    for case in error_code_cases() {
        let code = case.code;
        assert_valid(code, &case.body);
        let status = def(code)["properties"]["statusCode"]["const"]
            .as_u64()
            .unwrap_or_else(|| panic!("$defs/{code}.statusCode is a const"));
        assert_eq!(case.body["statusCode"], json!(status), "{code}");

        let err = IpcError::from_api(&classify(status as u16, &case.body));
        assert_eq!(err.code, case.ipc, "{code}");
        assert_eq!(err.retry_after_secs, case.wait_secs, "{code}");
        assert_eq!(
            err.server_asked_to_wait(),
            case.wait_secs.map(std::time::Duration::from_secs),
            "{code}"
        );
        if case.wait_secs.is_some() {
            assert_eq!(status, 503, "{code}");
            assert!(err.retryable, "{code}");
            assert!(!err.code.is_hard_refusal(), "{code}");
            assert_eq!(
                crate::commands::vpn::transport_fallback_reason(&err),
                None,
                "{code}"
            );
            // The key the parser reads is the one the contract requires.
            // MR-1637: `details` is a `$ref` to the one shared definition.
            let details = resolved(&def(code)["properties"]["details"]);
            assert_eq!(
                details["properties"]["retryAfterSeconds"]["type"], "integer",
                "{code}"
            );
            assert!(
                details["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("retryAfterSeconds")),
                "{code}"
            );
        }
    }
}

/// The gate bites: a `retryAfterSeconds` that is not an integer is refused by
/// the contract — and still decodes, leniently, to the same retryable
/// refusal without a wait rather than failing.
#[test]
fn a_malformed_retry_after_is_refused_by_the_contract_but_still_decodes() {
    let mut body = error_code_cases()
        .into_iter()
        .find(|c| c.code == "psk_delivery_unavailable")
        .unwrap()
        .body;
    body["details"]["retryAfterSeconds"] = json!("30");
    assert!(error_kinds("psk_delivery_unavailable", &body)
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Type { .. })));
    assert!(matches!(
        classify(503, &body),
        ApiError::PskDeliveryUnavailable {
            retry_after_secs: None
        }
    ));
}

/// A code outside `$defs/ErrorCode` — the next one the server adds, before
/// desktop re-vendors — is not in the enum, and decodes to the generic
/// fallback by status: never a failed decode, never a borrowed wait.
#[test]
fn an_unknown_error_code_decodes_to_the_fallback() {
    let code = "some_future_code";
    assert!(!contract_error_codes().contains(code));
    assert!(!validator_for("ErrorCode").is_valid(&json!(code)));
    let body = envelope(
        503,
        code,
        "Something new is down.",
        Some(json!({ "retryable": true, "retryAfterSeconds": 30 })),
    );
    let api = classify(503, &body);
    assert!(
        matches!(&api, ApiError::Rejected { status: 503, message } if message == "Something new is down."),
        "{api:?}"
    );
    let err = IpcError::from_api(&api);
    assert_eq!(err.code, IpcErrorCode::ServerUnavailable);
    assert!(err.retryable);
    assert_eq!(err.server_asked_to_wait(), None);
}

// ── connect refusal reasons (MR-139) ────────────────────────────────────────

const CONNECT_RESPONSE: &str = "ConnectResponse";
const CONNECT_REFUSAL: &str = "ConnectRefusal";

/// Every `$defs/ConnectRefusal` value, decided: a refused connect (HTTP 200,
/// `success:false`) as birdo-web sends it, with its own sentence
/// (`vpn.service.ts`), and the code desktop answers it with.
fn connect_refusal_cases() -> Vec<(&'static str, Value, IpcErrorCode)> {
    let refused = |reason: &str, message: &str| {
        let mut body = json!({ "success": false, "message": message });
        body["refusalReason"] = json!(reason);
        body
    };
    let mut quota = refused(
        "quota_exceeded",
        "Free-tier data limit reached (50.0 / 50 GB this period). Your allowance resets after \
         12 Nov. Upgrade to Operative for unlimited data.",
    );
    quota["quotaExceeded"] = json!(true);
    vec![
        (
            "device_limit",
            refused(
                "device_limit",
                "Device limit reached (3 devices for OPERATIVE plan)",
            ),
            IpcErrorCode::DeviceLimit,
        ),
        (
            "plan",
            refused(
                "plan",
                "Selected server is not included in your RECON plan. Upgrade to access more \
                 locations.",
            ),
            IpcErrorCode::SubscriptionRequired,
        ),
        ("quota_exceeded", quota, IpcErrorCode::QuotaExceeded),
        (
            "server_capacity",
            refused(
                "server_capacity",
                "Selected server is currently at capacity. Please try another server.",
            ),
            IpcErrorCode::ServerUnavailable,
        ),
        (
            "server_unavailable",
            refused("server_unavailable", "Server not found"),
            IpcErrorCode::ServerUnavailable,
        ),
    ]
}

fn contract_connect_refusals() -> BTreeSet<String> {
    def(CONNECT_REFUSAL)["enum"]
        .as_array()
        .expect("$defs/ConnectRefusal.enum is an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// What desktop answers a refused connect with, through both response types
/// as the two dial paths decode them (single-hop, and Multi-Hop converted).
fn connect_refusal_codes(body: &Value) -> [IpcErrorCode; 2] {
    use super::types::{ConnectResponse, MultiHopConnectResponse};
    let single: ConnectResponse = serde_json::from_str(&body.to_string())
        .unwrap_or_else(|e| panic!("desktop's ConnectResponse refused {body}: {e}"));
    let multi: MultiHopConnectResponse = serde_json::from_str(&body.to_string())
        .unwrap_or_else(|e| panic!("desktop's MultiHopConnectResponse refused {body}: {e}"));
    [single, ConnectResponse::from(multi)].map(|response| {
        assert!(!response.success, "{body}");
        IpcError::connect_refused(
            response.message.as_deref().unwrap_or_default(),
            response.quota_exceeded,
            response.refusal_reason.as_deref(),
        )
        .code
    })
}

/// A re-vendored contract with a refusal reason desktop has not decided on
/// fails HERE, naming it, not in production as whatever its wording reads as.
#[test]
fn every_contract_connect_refusal_has_a_decided_handling() {
    let s = schema();
    for name in [CONNECT_RESPONSE, CONNECT_REFUSAL] {
        assert!(
            s["_status"]["definitions"]
                .as_array()
                .unwrap()
                .contains(&json!(name)),
            "_status.definitions lists {name}"
        );
    }
    let reasons = contract_connect_refusals();
    // The response's own enum IS $defs/ConnectRefusal.
    let inline: BTreeSet<String> = def(CONNECT_RESPONSE)["properties"]["refusalReason"]["enum"]
        .as_array()
        .expect("$defs/ConnectResponse.refusalReason.enum is an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(inline, reasons);
    let decided: BTreeSet<String> = connect_refusal_cases()
        .iter()
        .map(|(reason, ..)| reason.to_string())
        .collect();
    assert_eq!(
        reasons, decided,
        "$defs/ConnectRefusal changed: decide which error desktop shows for the new reason \
         (IpcError::connect_refused), then add it to connect_refusal_cases"
    );
}

/// Each body IS the contract's shape, decodes on both dial paths, and is
/// answered with the decided code: by its reason, not by its wording.
#[test]
fn each_connect_refusal_body_is_the_contracts_shape_and_maps_as_decided() {
    for (reason, body, code) in connect_refusal_cases() {
        assert_valid(CONNECT_RESPONSE, &body);
        assert!(
            validator_for(CONNECT_REFUSAL).is_valid(&body["refusalReason"]),
            "{reason}"
        );
        assert_eq!(connect_refusal_codes(&body), [code, code], "{reason}");
    }
}

/// A reason newer than this build is refused by the contract (the next one
/// the server adds, before desktop re-vendors) but still decodes, and, like
/// a refusal from a server that sends none, is handled as before: by the
/// `quotaExceeded` flag, then the wording.
#[test]
fn an_unknown_or_absent_connect_refusal_is_handled_as_before() {
    let future = json!({
        "success": false,
        "refusalReason": "some_future_reason",
        "message": "Device limit reached (3 devices for OPERATIVE plan)",
    });
    assert!(!contract_connect_refusals().contains("some_future_reason"));
    assert!(!validator_for(CONNECT_RESPONSE).is_valid(&future));
    assert_eq!(
        connect_refusal_codes(&future),
        [IpcErrorCode::DeviceLimit, IpcErrorCode::DeviceLimit]
    );
    for (body, code) in [
        (
            json!({ "success": false, "message": "Device limit reached (3 devices for OPERATIVE plan)" }),
            IpcErrorCode::DeviceLimit,
        ),
        (
            json!({ "success": false, "message": "Selected server is currently at capacity." }),
            IpcErrorCode::ServerUnavailable,
        ),
        (
            json!({ "success": false, "quotaExceeded": true, "message": "Free-tier data limit reached" }),
            IpcErrorCode::QuotaExceeded,
        ),
    ] {
        assert_valid(CONNECT_RESPONSE, &body);
        assert_eq!(connect_refusal_codes(&body), [code, code], "{body}");
    }
}

// ── heartbeat replies (MR-1638) ─────────────────────────────────────────────

const HEARTBEAT: &str = "HeartbeatResponse";
const HEARTBEAT_REASON: &str = "HeartbeatReason";

/// Heartbeat-reply properties desktop deliberately does NOT read.
/// `quotaGraceEndsAt` is the end of the Free grace window as a wall-clock
/// instant; desktop counts down from `quotaGraceSecondsRemaining` instead,
/// which a skewed local clock cannot move. Listed explicitly so that when the
/// backend adds a property the key-set test fails and someone DECIDES (read
/// it, or add it here with a reason).
const HEARTBEAT_KNOWN_UNREAD: &[&str] = &["quotaGraceEndsAt"];

// birdo-web `VpnService.heartbeat`'s own sentences (`freeTierCapMessage` for
// the ended quota one; `in_grace` words the grace one by its seconds).
const HB_REVOKED: &str = "Connection has been revoked. Please reconnect.";
const HB_NOT_FOUND: &str = "Connection not found. Please reconnect.";
const HB_OFFLINE: &str =
    "Your current VPN server is offline. Please reconnect to a different server.";
const HB_ENDED: &str = "Free-tier data limit reached (50.2 / 50 GB this period). This \
                        connection has ended. Upgrade to Operative for unlimited data.";

/// One heartbeat reply, shaped as birdo-web's `VpnService.heartbeat` writes
/// it, and what desktop decided to make of it on BOTH paths that read one.
struct HeartbeatCase {
    reason: &'static str,
    body: Value,
    /// `reconnect_policy::heartbeat_verdict`: the check-in of a live session.
    live: HeartbeatVerdict,
    /// `reconnect_policy::after_teardown`: the old key's answer after a dead
    /// tunnel's teardown (`None` = re-dial), for a session confirmed alive
    /// within the reap window, and for one that was not (or slept since).
    probe_alive: Option<IpcErrorCode>,
    probe_not_alive: Option<IpcErrorCode>,
}

/// The reply for a key whose row is gone: the reason comes from the removal
/// record (`readKeyRemoval`); the sentence stays the one every shipped client
/// already handles.
fn key_gone(reason: &str) -> Value {
    json!({
        "valid": false,
        "serverOnline": false,
        "message": HB_NOT_FOUND,
        "reason": reason,
    })
}

/// A live reply inside an over-cap Free session's grace window
/// (`VpnService.withQuota`): the reason stays ok / server_offline, and the
/// three quota fields announce the end.
fn in_grace(mut reply: Value, seconds: u64) -> Value {
    reply["quotaExceeded"] = json!(true);
    reply["quotaGraceEndsAt"] = json!("2026-10-15T12:15:00.000Z");
    reply["quotaGraceSecondsRemaining"] = json!(seconds);
    // `freeTierCapMessage(bw, 'grace', ceil(seconds / 60))`.
    let mins = seconds.div_ceil(60).max(1);
    let plural = if mins == 1 { "" } else { "s" };
    reply["message"] = json!(format!(
        "Free-tier data limit reached (50.2 / 50 GB this period). This connection will end in \
         {mins} minute{plural}. Upgrade to Operative for unlimited data."
    ));
    reply
}

/// Every reason in `$defs/HeartbeatReason`, decided, in each shape the server
/// sends it.
fn heartbeat_cases() -> Vec<HeartbeatCase> {
    use reconnect_policy::{quota_exceeded_error, revoked_error};
    let revoked = Some(IpcErrorCode::Revoked);
    let quota = Some(IpcErrorCode::QuotaExceeded);
    // On a live session every valid:false ends it, in the server's words.
    // For reaped and server_offline that answer is rare: the server removes
    // the node's peer BEFORE it answers and the check-in rides the tunnel, so
    // it arrives as the teardown probe's, which re-dials as the contract
    // allows.
    let ended = |message: &str| HeartbeatVerdict::End(revoked_error(Some(message)));
    let ok = json!({ "valid": true, "serverOnline": true, "reason": "ok" });
    let offline = json!({
        "valid": true,
        "serverOnline": false,
        "message": HB_OFFLINE,
        "reason": "server_offline",
    });
    let mut quota_record = key_gone("quota_exceeded");
    quota_record["quotaExceeded"] = json!(true);
    vec![
        HeartbeatCase {
            reason: "ok",
            body: ok.clone(),
            live: HeartbeatVerdict::Fine,
            probe_alive: None,
            probe_not_alive: None,
        },
        // Over the Free cap, still live: tell the user, keep the tunnel.
        HeartbeatCase {
            reason: "ok",
            body: in_grace(ok, 540),
            live: HeartbeatVerdict::QuotaGrace {
                seconds_remaining: Some(540),
            },
            probe_alive: None,
            probe_not_alive: None,
        },
        // valid:true: the key lives, its server is not ONLINE.
        HeartbeatCase {
            reason: "server_offline",
            body: offline.clone(),
            live: HeartbeatVerdict::ServerGoingOffline,
            probe_alive: None,
            probe_not_alive: None,
        },
        // The grace warning outranks the offline notice.
        HeartbeatCase {
            reason: "server_offline",
            body: in_grace(offline, 60),
            live: HeartbeatVerdict::QuotaGrace {
                seconds_remaining: Some(60),
            },
            probe_alive: None,
            probe_not_alive: None,
        },
        // valid:false: the key went with a drained or deleted server.
        HeartbeatCase {
            reason: "server_offline",
            body: key_gone("server_offline"),
            live: ended(HB_NOT_FOUND),
            probe_alive: None,
            probe_not_alive: None,
        },
        // A deactivated row, then a removal record: stop, never re-dial.
        HeartbeatCase {
            reason: "revoked",
            body: json!({
                "valid": false,
                "serverOnline": false,
                "message": HB_REVOKED,
                "reason": "revoked",
            }),
            live: ended(HB_REVOKED),
            probe_alive: revoked,
            probe_not_alive: revoked,
        },
        HeartbeatCase {
            reason: "revoked",
            body: key_gone("revoked"),
            live: ended(HB_NOT_FOUND),
            probe_alive: revoked,
            probe_not_alive: revoked,
        },
        // A newer connection took the slot: a re-dial would evict it back.
        HeartbeatCase {
            reason: "evicted",
            body: key_gone("evicted"),
            live: ended(HB_NOT_FOUND),
            probe_alive: revoked,
            probe_not_alive: revoked,
        },
        // Housekeeping released it and nobody holds the slot: one re-dial.
        HeartbeatCase {
            reason: "reaped",
            body: key_gone("reaped"),
            live: ended(HB_NOT_FOUND),
            probe_alive: None,
            probe_not_alive: None,
        },
        // The allowance ended the session at a live check-in, then the record
        // a later one finds: terminal, and not a revocation.
        HeartbeatCase {
            reason: "quota_exceeded",
            body: json!({
                "valid": false,
                "serverOnline": true,
                "quotaExceeded": true,
                "reason": "quota_exceeded",
                "message": HB_ENDED,
            }),
            live: HeartbeatVerdict::End(quota_exceeded_error()),
            probe_alive: quota,
            probe_not_alive: quota,
        },
        HeartbeatCase {
            reason: "quota_exceeded",
            body: quota_record,
            live: HeartbeatVerdict::End(quota_exceeded_error()),
            probe_alive: quota,
            probe_not_alive: quota,
        },
        // No record of why: a reply without a reason. Taken from a session
        // that was just checking in, reaped from one that was not.
        HeartbeatCase {
            reason: "not_found",
            body: key_gone("not_found"),
            live: ended(HB_NOT_FOUND),
            probe_alive: revoked,
            probe_not_alive: None,
        },
    ]
}

fn contract_heartbeat_reasons() -> BTreeSet<String> {
    def(HEARTBEAT_REASON)["enum"]
        .as_array()
        .expect("$defs/HeartbeatReason.enum is an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// The reply as desktop's model holds it, decoded from the wire text as
/// `BirdoApi::heartbeat` decodes it.
fn heartbeat_reply(body: &Value) -> HeartbeatResponse {
    serde_json::from_str(&body.to_string())
        .unwrap_or_else(|e| panic!("desktop's HeartbeatResponse refused {body}: {e}"))
}

/// What both paths make of one reply: the live check-in's verdict, then the
/// teardown probe's for a session confirmed alive and for one that was not.
fn heartbeat_decisions(
    body: &Value,
) -> (HeartbeatVerdict, Option<IpcErrorCode>, Option<IpcErrorCode>) {
    let reply = heartbeat_reply(body);
    (
        reconnect_policy::heartbeat_verdict(&reply),
        reconnect_policy::after_teardown(Some(&reply), true).map(|e| e.code),
        reconnect_policy::after_teardown(Some(&reply), false).map(|e| e.code),
    )
}

/// A re-vendored contract with a reason desktop has not decided on fails
/// HERE, naming it, not in production as whatever a reply without a reason
/// happens to do.
#[test]
fn every_contract_heartbeat_reason_has_a_decided_handling() {
    let s = schema();
    for name in [HEARTBEAT, HEARTBEAT_REASON] {
        assert!(
            s["_status"]["definitions"]
                .as_array()
                .unwrap()
                .contains(&json!(name)),
            "_status.definitions lists {name}"
        );
    }
    let reasons = contract_heartbeat_reasons();
    // The reply's own enum IS $defs/HeartbeatReason: were they to drift, this
    // test would be checking the wrong list.
    let inline: BTreeSet<String> = def(HEARTBEAT)["properties"]["reason"]["enum"]
        .as_array()
        .expect("$defs/HeartbeatResponse.reason.enum is an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(inline, reasons);
    let decided: BTreeSet<String> = heartbeat_cases()
        .iter()
        .map(|c| c.reason.to_string())
        .collect();
    assert_eq!(
        reasons, decided,
        "$defs/HeartbeatReason changed: decide what desktop does with the new reason on a live \
         check-in and after a teardown, then add it to heartbeat_cases"
    );
}

/// Each body IS the contract's shape, decodes into desktop's model, and is
/// decided as listed on both paths.
#[test]
fn each_heartbeat_body_is_the_contracts_shape_and_decides_as_listed() {
    for case in heartbeat_cases() {
        let body = &case.body;
        assert_valid(HEARTBEAT, body);
        assert_eq!(body["reason"], json!(case.reason), "{body}");
        assert!(
            validator_for(HEARTBEAT_REASON).is_valid(&body["reason"]),
            "{body}"
        );
        assert_eq!(
            heartbeat_decisions(body),
            (case.live, case.probe_alive, case.probe_not_alive),
            "{body}"
        );
    }
}

/// Between them the bodies carry EVERY property of the reply, the three quota
/// fields included, so none is left to a shape no test decodes.
#[test]
fn the_heartbeat_bodies_carry_every_contract_property() {
    let carried: BTreeSet<String> = heartbeat_cases()
        .iter()
        .flat_map(|c| {
            c.body
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(carried, def_properties(HEARTBEAT));
}

/// Values for one property's schema: every enum value, both booleans, a
/// count, or an ISO-8601 instant.
fn property_samples(schema: &Value) -> Vec<Value> {
    if let Some(values) = schema["enum"].as_array() {
        return values.clone();
    }
    match schema["type"].as_str() {
        Some("boolean") => vec![json!(true), json!(false)],
        Some("number" | "integer") => vec![json!(540)],
        Some("string") => vec![json!("2026-10-15T12:15:00.000Z")],
        other => panic!("no sample for a heartbeat property of type {other:?}: add one"),
    }
}

/// The reply properties desktop's model READS: setting one changes what the
/// model decodes. A serde rename slip shows up here as a property no longer
/// read.
fn heartbeat_properties_read() -> BTreeSet<String> {
    let base = json!({ "valid": true, "serverOnline": true });
    let decoded = |b: &Value| format!("{:?}", heartbeat_reply(b));
    let reference = decoded(&base);
    def(HEARTBEAT)["properties"]
        .as_object()
        .expect("$defs/HeartbeatResponse.properties is an object")
        .iter()
        .filter(|(key, schema)| {
            property_samples(schema).into_iter().any(|sample| {
                let mut b = base.clone();
                b[key.as_str()] = sample;
                decoded(&b) != reference
            })
        })
        .map(|(key, _)| key.clone())
        .collect()
}

/// What the model reads ⊆ the contract's properties, and the complement is
/// EXACTLY the documented unread list, so a new backend property, or a field
/// the model stops reading, both fail with the property named.
#[test]
fn every_heartbeat_property_is_read_or_known_unread() {
    let read = heartbeat_properties_read();
    let props = def_properties(HEARTBEAT);
    let unread: BTreeSet<String> = props.difference(&read).cloned().collect();
    let expected: BTreeSet<String> = HEARTBEAT_KNOWN_UNREAD
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        unread, expected,
        "heartbeat properties desktop does not read changed — decide, then update \
         HEARTBEAT_KNOWN_UNREAD"
    );
    for key in def_required(HEARTBEAT) {
        assert!(read.contains(&key), "required {key} is not read");
    }
}

/// The contract's rule: an absent or unknown `reason` (an older server, or a
/// reason added after this build) is a reply without one, on both paths; and
/// so is not_found.
#[test]
fn an_unknown_or_absent_heartbeat_reason_is_a_reply_without_one() {
    let future = "some_future_reason";
    assert!(!contract_heartbeat_reasons().contains(future));
    for case in heartbeat_cases() {
        let mut without = case.body.clone();
        without.as_object_mut().unwrap().remove("reason");
        assert_valid(HEARTBEAT, &without);
        let mut unknown = case.body.clone();
        unknown["reason"] = json!(future);
        // The contract refuses the value; desktop still decodes the reply.
        assert!(
            error_kinds(HEARTBEAT, &unknown)
                .iter()
                .any(|k| matches!(k, ValidationErrorKind::Enum { .. })),
            "{unknown}"
        );
        assert_eq!(
            heartbeat_decisions(&unknown),
            heartbeat_decisions(&without),
            "{}",
            case.body
        );
        if case.reason == "not_found" {
            assert_eq!(
                heartbeat_decisions(&case.body),
                heartbeat_decisions(&without)
            );
        }
    }
}

/// The gate bites: a reply without `valid`, a reason outside the enum, a
/// count sent as text: each refused under its own keyword. Desktop's model
/// stays lenient where the contract is strict (a text count is "no count",
/// never a failed heartbeat, which would also hide a valid:false), and the
/// unknown keys the contract allows are ignored.
#[test]
fn heartbeat_mutations_are_refused_by_the_contract_and_decoded_leniently() {
    let grace = heartbeat_cases()
        .into_iter()
        .find(|c| c.body["quotaGraceSecondsRemaining"].is_number())
        .expect("a grace-window case")
        .body;
    assert_valid(HEARTBEAT, &grace);

    let mut m = grace.clone();
    m.as_object_mut().unwrap().remove("valid");
    assert_eq!(
        required_violations(HEARTBEAT, &m),
        vec!["valid".to_string()]
    );

    let mut m = grace.clone();
    m["reason"] = json!("Evicted");
    assert!(error_kinds(HEARTBEAT, &m)
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Enum { .. })));

    let mut m = grace.clone();
    m["quotaGraceSecondsRemaining"] = json!("540");
    assert!(error_kinds(HEARTBEAT, &m)
        .iter()
        .any(|k| matches!(k, ValidationErrorKind::Type { .. })));
    assert_eq!(
        reconnect_policy::heartbeat_verdict(&heartbeat_reply(&m)),
        HeartbeatVerdict::QuotaGrace {
            seconds_remaining: None
        }
    );

    assert_eq!(def(HEARTBEAT)["additionalProperties"], true);
    let mut m = grace.clone();
    m["someFutureField"] = json!({ "nested": [1, 2] });
    assert_valid(HEARTBEAT, &m);
    assert_eq!(
        format!("{:?}", heartbeat_reply(&m)),
        format!("{:?}", heartbeat_reply(&grace))
    );
}
