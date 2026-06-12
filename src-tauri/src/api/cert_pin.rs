//! TLS certificate pinning for the Birdo API client.
//!
//! Pins the **CA-chain SPKI** (SubjectPublicKeyInfo SHA-256), matching the
//! Android client (OkHttp `CertificatePinner` in `NetworkModule.kt`). Because we
//! pin the stable intermediate/root public keys — not the volatile leaf — the
//! edge cert can rotate every ~90 days WITHOUT a new desktop release. A release
//! is only needed if the CA chain itself changes (years), and a cross-CA backup
//! pin guards against a provider migration bricking installed clients.
//!
//! Implemented as a custom rustls `ServerCertVerifier` that WRAPS the default
//! WebPKI verifier: standard validation (chain-to-trusted-root, hostname,
//! validity period) runs first and unchanged; the SPKI pin is layered on top.
//! reqwest only exposes the leaf via `TlsInfo`, so chain pinning must happen
//! here, inside the TLS handshake.

use std::sync::Arc;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

/// SPKI SHA-256 pins (base64). Kept in sync with the Android client
/// (`app/.../di/NetworkModule.kt`) and `birdo-shared/cert-pins.json`.
///
/// A connection is accepted if ANY certificate in the presented chain
/// (intermediate OR root) matches one of these. Verified against the live
/// `api.birdo.app` chain 2026-06-08: WE1 + GTS Root R4 are present.
const PINNED_SPKI_SHA256: &[&str] = &[
    // Google Trust Services "WE1" intermediate — the cert api.birdo.app chains
    // through today; stable for years. PRIMARY pin (also pinned on Android).
    "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
    // GTS Root R4 — the actual trust anchor in the live chain (2026-06-08).
    "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
    // GlobalSign ECC Root CA - R4 — alternate Google cross-sign anchor (kept for
    // chains that present GlobalSign instead of GTS Root R4; also on Android).
    "CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk=",
    // ISRG Root X1 (Let's Encrypt) — cross-CA backup so a Google -> Let's Encrypt
    // migration cannot brick installed clients (also pinned on Android).
    "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
];

/// base64(SHA-256(DER SubjectPublicKeyInfo)) for a certificate.
///
/// Identical to `openssl x509 -pubkey | openssl pkey -pubin -outform DER |
/// openssl dgst -sha256 -binary | base64` and OkHttp's `sha256/...` pin.
/// Returns `None` if the certificate cannot be parsed as X.509.
fn spki_sha256_b64(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let spki_der = parsed.tbs_certificate.subject_pki.raw;
    Some(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki_der)))
}

#[derive(Debug)]
struct SpkiPinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for SpkiPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // 1) Full standard validation first — chain to a trusted root, hostname
        //    match, validity period. A failure here rejects the connection.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // 2) SPKI pin check across the presented chain (leaf + intermediates).
        let mut parsed_any = false;
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            if let Some(spki) = spki_sha256_b64(cert) {
                parsed_any = true;
                if PINNED_SPKI_SHA256.contains(&spki.as_str()) {
                    return Ok(ServerCertVerified::assertion());
                }
            }
        }

        if !parsed_any {
            // No certificate in the chain could be parsed. Standard validation
            // already passed; log loudly but allow, so a parser edge-case cannot
            // brick the client (pinning is defence-in-depth, not the sole gate).
            tracing::error!(
                "cert-pin: could not parse any certificate SPKI in the chain — allowing (WebPKI validation passed)"
            );
            return Ok(ServerCertVerified::assertion());
        }

        tracing::error!(
            "cert-pin: no pinned SPKI matched the presented chain — refusing connection (possible MITM or un-pinned CA change)"
        );
        Err(TlsError::General("certificate SPKI pin mismatch".to_string()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a rustls `ClientConfig` that performs full standard validation PLUS
/// CA-chain SPKI pinning. Fed to reqwest via `ClientBuilder::use_preconfigured_tls`.
pub fn rustls_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let inner = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("cert-pin: failed to build WebPKI verifier from Mozilla roots");

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("cert-pin: ring provider must support default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinningVerifier { inner }))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ISRG Root X1 (Let's Encrypt) DER — a stable public root cert. Its SPKI
    // SHA-256 is the well-known pin asserted below, proving our extraction
    // matches OkHttp / openssl byte-for-byte.
    const ISRG_X1_DER: &[u8] = include_bytes!("isrg_root_x1.der");
    const ISRG_X1_SPKI: &str = "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=";

    #[test]
    fn spki_extraction_matches_known_pin() {
        let cert = CertificateDer::from(ISRG_X1_DER.to_vec());
        let spki = spki_sha256_b64(&cert).expect("ISRG X1 should parse");
        assert_eq!(spki, ISRG_X1_SPKI, "SPKI extraction must match the canonical pin");
    }

    #[test]
    fn isrg_pin_is_in_the_pinned_set() {
        assert!(PINNED_SPKI_SHA256.contains(&ISRG_X1_SPKI));
    }

    #[test]
    fn malformed_der_returns_none_and_does_not_panic() {
        let cert = CertificateDer::from(vec![0u8, 1, 2, 3, 4]);
        assert!(spki_sha256_b64(&cert).is_none());
    }

    #[test]
    fn config_builds_without_panicking() {
        let _ = rustls_config();
    }
}
