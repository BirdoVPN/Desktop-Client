//! Ed25519 desktop client attestation (`BIRDO-DESKTOP-ATTEST-v1`)
//!
//! The desktop client cannot use Play Integrity, so it proves "official build"
//! with a signing key that only the release pipeline holds. The private seed is
//! baked in at COMPILE time from the `BIRDO_DESKTOP_ATTEST_SK` secret (base64 of
//! the 32-byte Ed25519 seed) and identified by `BIRDO_DESKTOP_ATTEST_KID`, the
//! same `option_env!` pattern `SENTRY_DSN` uses in main.rs. Dev builds and forks
//! compile without the secret and simply send no attestation fields — the server
//! policy (`off` / `log` / `enforce`) decides what that means.
//!
//! The wire format is shared with the backend and MUST stay byte-identical to
//! `birdo-web` `docs/CLIENT-ATTESTATION.md`:
//!
//! ```text
//! payload = "BIRDO-DESKTOP-ATTEST-v1\n" + nonce + "\n" + platform + "\n" + version + "\n" + kid
//! sig     = base64url_nopad(Ed25519(payload))   // UTF-8 payload, 64-byte signature
//! ```
//!
//! Signing uses `ring` (already in the dependency graph via rustls/boringtun).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

/// Domain-separation prefix. Bump the version suffix only in lock-step with the
/// backend verifier — a mismatch silently invalidates every signature.
const PAYLOAD_PREFIX: &str = "BIRDO-DESKTOP-ATTEST-v1";

/// Ed25519 seed length (RFC 8032 §5.1.5).
const SEED_LEN: usize = 32;

/// Base64 of the 32-byte Ed25519 seed, injected by the release workflows.
const ATTEST_SEED_B64: Option<&str> = option_env!("BIRDO_DESKTOP_ATTEST_SK");
/// Key id the backend uses to select the verifying public key (rotation).
const ATTEST_KID: Option<&str> = option_env!("BIRDO_DESKTOP_ATTEST_KID");

/// The five fields a signed client attaches to a connect request.
#[derive(Debug, Clone)]
pub struct DesktopAttestation {
    pub nonce: String,
    pub kid: String,
    pub signature: String,
    pub platform: &'static str,
    pub version: &'static str,
}

/// Platform token, constrained to the three values the backend accepts.
pub const fn platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Client version — the same source as the User-Agent in client.rs.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Whether this binary was built with an attestation key. Callers use this to
/// skip the nonce round-trip entirely on dev/fork builds.
pub fn is_configured() -> bool {
    keys().is_some()
}

/// The canonical payload. Signed here, re-derived byte-for-byte by the backend
/// from the request fields before verifying.
pub fn canonical_payload(nonce: &str, platform: &str, version: &str, kid: &str) -> String {
    format!("{PAYLOAD_PREFIX}\n{nonce}\n{platform}\n{version}\n{kid}")
}

/// Sign `nonce` with the compile-time key. `None` on builds without a key.
pub fn sign(nonce: &str) -> Option<DesktopAttestation> {
    let (seed_b64, kid) = keys()?;
    let signature = sign_with(seed_b64, nonce, platform(), version(), kid)?;

    Some(DesktopAttestation {
        nonce: nonce.to_string(),
        kid: kid.to_string(),
        signature,
        platform: platform(),
        version: version(),
    })
}

/// Compile-time key material, `None` unless BOTH env vars were set and non-empty.
fn keys() -> Option<(&'static str, &'static str)> {
    let seed_b64 = ATTEST_SEED_B64?.trim();
    let kid = ATTEST_KID?.trim();
    if seed_b64.is_empty() || kid.is_empty() {
        return None;
    }
    Some((seed_b64, kid))
}

/// Build the canonical payload and return `base64url_nopad(Ed25519(payload))`.
/// Split out from [`sign`] so the wire format can be tested against a fixed
/// vector without a compile-time key.
fn sign_with(
    seed_b64: &str,
    nonce: &str,
    platform: &str,
    version: &str,
    kid: &str,
) -> Option<String> {
    // Zeroizing so the raw seed is wiped on every exit path, not just success.
    let seed = Zeroizing::new(decode_seed(seed_b64)?);
    if seed.len() != SEED_LEN {
        return None;
    }

    let keypair = Ed25519KeyPair::from_seed_unchecked(seed.as_slice()).ok()?;
    // Key material now lives only inside `keypair`.
    drop(seed);

    let payload = canonical_payload(nonce, platform, version, kid);
    let signature = keypair.sign(payload.as_bytes());
    Some(URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

/// Accept the seed in standard base64 (how the secret is generated) and in
/// base64url, so a URL-safe paste of the same key still produces a signing
/// client instead of silently shipping unattested.
fn decode_seed(seed_b64: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(seed_b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(seed_b64))
        .ok()
}

/// The public key for a seed — used by the release pipeline / tests, never sent.
#[cfg(test)]
fn public_key_bytes(seed_b64: &str) -> Option<Vec<u8>> {
    let seed = Zeroizing::new(decode_seed(seed_b64)?);
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed.as_slice()).ok()?;
    Some(keypair.public_key().as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIXED WIRE-FORMAT VECTOR — pinned identically in birdo-web's
    // docs/CLIENT-ATTESTATION.md. Both repos must reproduce SIG exactly.
    // Seed is RFC 8032 §7.1 TEST 1 (public key d75a98…511a); the signature was
    // produced independently with Node's crypto (the backend's runtime).
    const SEED_B64: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const NONCE: &str = "nonce-0123456789abcdef";
    const PLATFORM: &str = "windows";
    const VERSION: &str = "1.4.11";
    const KID: &str = "desk-2026-07";
    const PAYLOAD: &str =
        "BIRDO-DESKTOP-ATTEST-v1\nnonce-0123456789abcdef\nwindows\n1.4.11\ndesk-2026-07";
    const SIG: &str =
        "O4vQ_iekQEu7trbwQ2MX57I4_QliaGDW5RFVYG5RAd2Uke36CThiMHImNdmqXZISiO9QkTwGTs6OfaE1VANrBA";
    const PUBLIC_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    #[test]
    fn canonical_payload_matches_fixed_vector() {
        assert_eq!(canonical_payload(NONCE, PLATFORM, VERSION, KID), PAYLOAD);
    }

    #[test]
    fn seed_derives_the_expected_public_key() {
        let public = public_key_bytes(SEED_B64).expect("seed decodes");
        assert_eq!(hex::encode(public), PUBLIC_KEY_HEX);
    }

    #[test]
    fn signature_matches_fixed_vector() {
        let sig = sign_with(SEED_B64, NONCE, PLATFORM, VERSION, KID).expect("signs");
        assert_eq!(sig, SIG);
    }

    #[test]
    fn signature_round_trips_against_the_public_key() {
        let sig = sign_with(SEED_B64, NONCE, PLATFORM, VERSION, KID).expect("signs");
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig).expect("base64url");
        assert_eq!(sig_bytes.len(), 64);

        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            public_key_bytes(SEED_B64).expect("seed decodes"),
        );
        public
            .verify(PAYLOAD.as_bytes(), &sig_bytes)
            .expect("signature verifies");
    }

    #[test]
    fn signature_is_bound_to_the_nonce() {
        let sig = sign_with(SEED_B64, NONCE, PLATFORM, VERSION, KID).expect("signs");
        let other = sign_with(SEED_B64, "different-nonce", PLATFORM, VERSION, KID).expect("signs");
        assert_ne!(sig, other);
    }

    #[test]
    fn seed_also_decodes_from_base64url() {
        let url_safe = SEED_B64
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "");
        assert_eq!(
            sign_with(&url_safe, NONCE, PLATFORM, VERSION, KID),
            Some(SIG.to_string())
        );
    }

    #[test]
    fn malformed_seed_yields_no_signature() {
        assert!(sign_with("not base64!!", NONCE, PLATFORM, VERSION, KID).is_none());
        // Right encoding, wrong length (31 bytes) — must not sign with a padded key.
        let short = STANDARD.encode([7u8; 31]);
        assert!(sign_with(&short, NONCE, PLATFORM, VERSION, KID).is_none());
    }

    #[test]
    fn platform_is_one_of_the_three_accepted_tokens() {
        assert!(matches!(platform(), "windows" | "macos" | "linux"));
    }
}
