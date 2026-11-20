//! NIST ACVP vectors for ML-KEM-1024 against the linked RustCrypto `ml-kem`
//! (MR-1432, PQ-CRYPTO-REVIEW-RFP §2.10: "no NIST ACVP / FIPS 203 vector runs
//! against the pinned libraries").
//!
//! `kat_vs_noble` (in `birdo_pq.rs`) proves this client and the production
//! server agree on ONE vector. It cannot show that both are right: two
//! libraries that share a mistake agree on it. These are NIST's own vectors,
//! the ones a FIPS 140-3 module is validated with, for every ML-KEM-1024
//! operation the client performs or depends on:
//!
//! | ACVP group | what it pins |
//! |---|---|
//! | keyGen AFT (25) | `ML-KEM.KeyGen_internal(d, z)`: the seed this client keeps is `d \|\| z`, and the 1568-byte `ek` it sends and the expanded `dk` match NIST's |
//! | encapsulation AFT (25) | `ML-KEM.Encaps_internal(ek, m)`: what the server does with the client's key, here with RustCrypto |
//! | decapsulation VAL (10) | `ML-KEM.Decaps_internal(dk, c)`, valid ciphertexts and modified ones: implicit rejection gives NIST's `K-bar`, not an error |
//! | encapsulationKeyCheck VAL (10) | FIPS 203 §7.2: a key whose coefficients are not reduced mod q is refused |
//! | decapsulationKeyCheck VAL (10) | FIPS 203 §7.3: a `dk` whose embedded `H(ek)` is wrong is refused |
//!
//! The fixture (`fixtures/acvp-ml-kem-1024.json`) is the ML-KEM-1024 subset
//! of NIST ACVP-Server's `internalProjection.json` files at a pinned commit,
//! cut by `scripts/extract-acvp-ml-kem-1024.py` (which checks the upstream
//! files' sha256). Its own sha256 is pinned below, and every group's size and
//! pass/fail split is asserted, so an emptied or edited fixture fails rather
//! than passing vacuously.

use super::*;
use ml_kem::array::sizes::{U3168, U32};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{EncapsulationKey, Key, TryKeyInit, B32};
use sha2::Digest;

const ACVP_JSON: &str = include_str!("fixtures/acvp-ml-kem-1024.json");
/// sha256 of the fixture's LF bytes (CRs are dropped first, so a CRLF
/// checkout hashes the same as the blob git stores).
const ACVP_SHA256: &str = "519d9eaf9095c38b57be034be2002990014504abf677abc6a4282bce8e1c042f";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex in the ACVP fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("ACVP fixture hex"))
        .collect()
}

/// The tests of the fixture's one group for `function`.
fn tests_of(function: &str) -> Vec<serde_json::Value> {
    let doc: serde_json::Value = serde_json::from_str(ACVP_JSON).expect("ACVP fixture parses");
    let groups: Vec<&serde_json::Value> = doc["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|g| g["function"] == function)
        .collect();
    assert_eq!(groups.len(), 1, "one ML-KEM-1024 {function} group");
    groups[0]["tests"].as_array().expect("tests").clone()
}

fn bytes(t: &serde_json::Value, key: &str) -> Vec<u8> {
    unhex(
        t[key]
            .as_str()
            .unwrap_or_else(|| panic!("tcId {} has no {key}", t["tcId"])),
    )
}

fn tc(t: &serde_json::Value) -> u64 {
    t["tcId"].as_u64().expect("tcId")
}

fn encapsulation_key(ek: &[u8]) -> Option<EncapsulationKey<MlKem1024>> {
    let k: Key<EncapsulationKey<MlKem1024>> = Array::<u8, U1568>::try_from(ek).ok()?;
    <EncapsulationKey<MlKem1024> as TryKeyInit>::new(&k).ok()
}

#[allow(deprecated)]
fn expanded_decapsulation_key(dk: &[u8]) -> Option<DecapsulationKey<MlKem1024>> {
    let a = Array::<u8, U3168>::try_from(dk).ok()?;
    <DecapsulationKey<MlKem1024> as ExpandedKeyEncoding>::from_expanded_bytes(&a).ok()
}

#[test]
fn acvp_fixture_is_the_pinned_one() {
    let lf: Vec<u8> = ACVP_JSON.bytes().filter(|b| *b != b'\r').collect();
    let got: String = sha2::Sha256::digest(&lf)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        got, ACVP_SHA256,
        "fixtures/acvp-ml-kem-1024.json is not the pinned cut of NIST's vectors: \
         regenerate it with scripts/extract-acvp-ml-kem-1024.py, never edit it by hand"
    );
    for (function, n, passed) in [
        ("keyGen", 25, None),
        ("encapsulation", 25, None),
        ("decapsulation", 10, None),
        ("encapsulationKeyCheck", 10, Some(5)),
        ("decapsulationKeyCheck", 10, Some(5)),
    ] {
        let tests = tests_of(function);
        assert_eq!(tests.len(), n, "{function}: test count");
        if let Some(p) = passed {
            let ok = tests.iter().filter(|t| t["testPassed"] == true).count();
            assert_eq!(ok, p, "{function}: valid cases");
            assert_eq!(tests.len() - ok, n - p, "{function}: invalid cases");
        }
    }
}

/// ML-KEM.KeyGen_internal(d, z): the 64-byte seed this client generates and
/// keeps is `d || z`, so `decapsulation_key` must give NIST's ek and dk.
#[test]
#[allow(deprecated)]
fn acvp_keygen() {
    for t in tests_of("keyGen") {
        let mut seed = [0u8; SEED_BYTES];
        seed[..32].copy_from_slice(&bytes(&t, "d"));
        seed[32..].copy_from_slice(&bytes(&t, "z"));
        let dk = decapsulation_key(&seed);
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            bytes(&t, "ek").as_slice(),
            "keyGen tcId {}: ek",
            tc(&t)
        );
        let mut expanded = dk.to_expanded_bytes();
        assert_eq!(
            expanded.as_slice(),
            bytes(&t, "dk").as_slice(),
            "keyGen tcId {}: dk",
            tc(&t)
        );
        expanded.as_mut_slice().zeroize();
        seed.zeroize();
    }
}

/// ML-KEM.Encaps_internal(ek, m): what the server does with the client's key.
#[test]
fn acvp_encapsulation() {
    for t in tests_of("encapsulation") {
        let ek = encapsulation_key(&bytes(&t, "ek"))
            .unwrap_or_else(|| panic!("encapsulation tcId {}: ek refused", tc(&t)));
        let m: B32 = Array::<u8, U32>::try_from(bytes(&t, "m").as_slice()).expect("32-byte m");
        let (c, k) = ek.encapsulate_deterministic(&m);
        assert_eq!(
            c.as_slice(),
            bytes(&t, "c").as_slice(),
            "encapsulation tcId {}: c",
            tc(&t)
        );
        assert_eq!(
            k.as_slice(),
            bytes(&t, "k").as_slice(),
            "encapsulation tcId {}: k",
            tc(&t)
        );
    }
}

/// ML-KEM.Decaps_internal(dk, c), the client's side of every connect. NIST's
/// "modified ciphertext" cases expect the implicit-rejection key K-bar: no
/// error, and not the encapsulated key.
#[test]
fn acvp_decapsulation() {
    let tests = tests_of("decapsulation");
    let mut reasons = std::collections::BTreeSet::new();
    for t in &tests {
        let dk = expanded_decapsulation_key(&bytes(t, "dk"))
            .unwrap_or_else(|| panic!("decapsulation tcId {}: dk refused", tc(t)));
        let c: MlCiphertext<MlKem1024> =
            Array::<u8, U1568>::try_from(bytes(t, "c").as_slice()).expect("1568-byte c");
        let mut k = dk.decapsulate(&c);
        assert_eq!(
            k.as_slice(),
            bytes(t, "k").as_slice(),
            "decapsulation tcId {}: k",
            tc(t)
        );
        k.as_mut_slice().zeroize();
        reasons.insert(t["reason"].as_str().unwrap_or("").to_string());
    }
    assert!(
        reasons.contains("modified ciphertext") && reasons.contains("valid decapsulation"),
        "the decapsulation group must hold both valid and modified ciphertexts: {reasons:?}"
    );
}

/// FIPS 203 §7.2 (modulus check), run where the server's key arrives.
#[test]
fn acvp_encapsulation_key_check() {
    for t in tests_of("encapsulationKeyCheck") {
        let want = t["testPassed"].as_bool().expect("testPassed");
        assert_eq!(
            encapsulation_key(&bytes(&t, "ek")).is_some(),
            want,
            "encapsulationKeyCheck tcId {} ({}): accepted != testPassed",
            tc(&t),
            t["reason"]
        );
    }
}

/// FIPS 203 §7.3 (the embedded H(ek) check), the property
/// `pq_impl_name_matches_linked_crate` relies on.
#[test]
fn acvp_decapsulation_key_check() {
    for t in tests_of("decapsulationKeyCheck") {
        let want = t["testPassed"].as_bool().expect("testPassed");
        assert_eq!(
            expanded_decapsulation_key(&bytes(&t, "dk")).is_some(),
            want,
            "decapsulationKeyCheck tcId {} ({}): accepted != testPassed",
            tc(&t),
            t["reason"]
        );
    }
}
