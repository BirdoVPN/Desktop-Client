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
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
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
    //
    // NOTE: a standard Let's Encrypt server chain presents the LEAF + one
    // ISSUING INTERMEDIATE (R10/R11/E5/E6) — NOT ISRG Root X1 itself. Since we
    // pin against the PRESENTED chain, the root pin alone can never match a
    // default LE deployment, so the four current issuing intermediates are
    // pinned below to make this backup real (computed 2026-08-18 from
    // https://letsencrypt.org/certs/2024/{r10,r11,e5,e6}.pem).
    "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
    // Let's Encrypt R10 (RSA issuing intermediate)
    "K7rZOrXHknnsEhUH8nLL4MZkejquUuIvOIr6tCa0rbo=",
    // Let's Encrypt R11 (RSA issuing intermediate)
    "bdrBhpj38ffhxpubzkINl0rG+UyossdhcBYj+Zx2fcc=",
    // Let's Encrypt E5 (ECDSA issuing intermediate)
    "NYbU7PBwV4y9J67c4guWTki8FJ+uudrXL0a4V4aRcrg=",
    // Let's Encrypt E6 (ECDSA issuing intermediate)
    "0Bbh/jEZSKymTy3kTOhsmlHKBB32EDu1KojrP3YfV9c=",
];

/// base64(SHA-256(DER SubjectPublicKeyInfo)) for a certificate.
///
/// Identical to `openssl x509 -pubkey | openssl pkey -pubin -outform DER |
/// openssl dgst -sha256 -binary | base64` and OkHttp's `sha256/...` pin.
/// Returns `None` if the certificate cannot be parsed as X.509.
///
/// pub(crate): the DoH resolver's pinning verifier (vpn/doh.rs) reuses this
/// exact extraction so its pins stay byte-compatible with the API pins.
pub(crate) fn spki_sha256_b64(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let spki_der = parsed.tbs_certificate.subject_pki.raw;
    Some(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki_der)))
}

/// Apex domain whose certificates are covered by [`PINNED_SPKI_SHA256`].
const BIRDO_APEX: &str = "birdo.app";

/// Which hosts a config enforces the SPKI pin for.
///
/// The pins above are the CA chain *Birdo's own* edge is issued from. They say
/// nothing about anybody else's CA, so enforcing them against a third-party
/// host does not harden that connection — it makes it permanently impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinScope {
    /// Pin every host. Correct for a client that only ever dials Birdo, and the
    /// strictest possible setting: an unexpected host is refused outright.
    AllHosts,
    /// Pin `birdo.app` and its subdomains; every other host gets full, ordinary
    /// WebPKI validation (chain-to-trusted-root, hostname, validity) and no pin.
    BirdoHostsOnly,
}

/// Is this connection going to a host our pins actually cover?
///
/// Matching is exact-or-dot-suffix so a lookalike registration such as
/// `notbirdo.app` or `birdo.app.example.com` does NOT count as a Birdo host.
/// `server_name` is the name WebPKI has just validated the certificate against
/// (step 1 runs first), so it cannot be steered independently of the cert.
fn is_birdo_host(server_name: &ServerName<'_>) -> bool {
    match server_name {
        ServerName::DnsName(name) => {
            let host = name.as_ref().to_ascii_lowercase();
            host == BIRDO_APEX || host.ends_with(&format!(".{BIRDO_APEX}"))
        }
        // Birdo is only ever reached by name; an IP literal is never one of our
        // pinned hosts.
        _ => false,
    }
}

#[derive(Debug)]
struct SpkiPinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    scope: PinScope,
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
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // 2) Is this host in scope for the pin at all? Under `BirdoHostsOnly`
        //    a third-party host stops here with standard WebPKI validation —
        //    see `PinScope` for why pinning it would be a brick, not a lock.
        if self.scope == PinScope::BirdoHostsOnly && !is_birdo_host(server_name) {
            return Ok(ServerCertVerified::assertion());
        }

        // 3) SPKI pin check across the presented chain (leaf + intermediates).
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
            // No certificate in the chain could be parsed by x509-parser. FAIL
            // CLOSED: WebPKI just parsed and validated this same chain, so a
            // chain our SPKI extractor cannot read at all is either a crafted
            // chain or a parser bug — and treating it as "pinned OK" would turn
            // the pin from a hard gate into advisory exactly when it matters.
            tracing::error!(
                "cert-pin: could not parse any certificate SPKI in the chain — refusing connection (fail closed)"
            );
            return Err(TlsError::General(
                "certificate chain SPKI unparseable — pin check impossible".to_string(),
            ));
        }

        tracing::error!(
            "cert-pin: no pinned SPKI matched the presented chain — refusing connection (possible MITM or un-pinned CA change)"
        );
        Err(TlsError::General(
            "certificate SPKI pin mismatch".to_string(),
        ))
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
/// CA-chain SPKI pinning on EVERY host. Fed to reqwest via
/// `ClientBuilder::use_preconfigured_tls`.
///
/// This is the strict configuration and the right one for the API client, which
/// only ever dials `api.birdo.app`.
pub fn rustls_config() -> ClientConfig {
    build_config(PinScope::AllHosts)
}

/// Like [`rustls_config`], but the SPKI pin is enforced only on `birdo.app` and
/// its subdomains; other hosts get full WebPKI validation and no pin.
///
/// Used by the auto-updater, and ONLY by the auto-updater. Its two requests do
/// not go to the same place:
///
///  * the manifest check hits `api.birdo.app` (the endpoint is compiled into
///    `tauri.conf.json`, so it is not attacker-steerable) — that request is IN
///    scope and stays fully pinned, which is the request that matters: it is
///    the one a MITM would suppress to keep a client below the version floor.
///  * the installer download goes wherever the manifest's `url` points, which
///    today is a GitHub release asset (the backend builds the manifest from
///    `browser_download_url`, see birdo-web `updates.controller.ts`).
///
/// GitHub does not chain through our CAs, and never promised to. Measured
/// 2026-08-20: `github.com` presents Sectigo Public Server Authentication CA DV
/// E36 / Root E46, and `objects.githubusercontent.com` (where the asset URL
/// redirects) presents Let's Encrypt **YR1** / ISRG **Root YR** — none of which
/// is in [`PINNED_SPKI_SHA256`] (we pin LE R10/R11/E5/E6 and ISRG Root X1).
/// Pinning that leg therefore does not secure the download, it makes it
/// impossible: every install would fail the handshake, on every platform,
/// forever. With a hard version floor in front of it (`api::upgrade_gate`) that
/// is not a safe failure — it is a blocked user with an Update button that can
/// never succeed.
///
/// Adding GitHub's CAs to the pin set would be worse: GitHub can rotate CAs
/// whenever it likes, and every already-installed client would be bricked the
/// day it happened, with no way to ship them the fix.
///
/// The download does not need the pin, because TLS is not what protects it. The
/// bundle is verified with the minisign public key baked into the binary
/// (`tauri.conf.json` → `plugins.updater.pubkey`), which is what actually
/// decides whether the downloaded installer is allowed to run. A MITM on the
/// download leg can deny the update; it cannot substitute one. Denial is
/// already covered by pinning the check.
pub fn rustls_config_pinning_birdo_hosts_only() -> ClientConfig {
    build_config(PinScope::BirdoHostsOnly)
}

fn build_config(scope: PinScope) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Select the ring CryptoProvider EXPLICITLY (for both the verifier and the
    // client config) instead of relying on rustls' process-level default.
    // Other dependencies (e.g. sentry's transport) may enable the aws-lc-rs
    // feature too, and with both features enabled rustls refuses to guess.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("cert-pin: failed to build WebPKI verifier from Mozilla roots");

    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("cert-pin: ring provider must support default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinningVerifier { inner, scope }))
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
        assert_eq!(
            spki, ISRG_X1_SPKI,
            "SPKI extraction must match the canonical pin"
        );
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

    #[test]
    fn scoped_config_builds_without_panicking() {
        let _ = rustls_config_pinning_birdo_hosts_only();
    }

    fn name(host: &str) -> ServerName<'static> {
        ServerName::try_from(host.to_string()).expect("valid server name")
    }

    #[test]
    fn birdo_hosts_are_in_pin_scope() {
        for host in ["birdo.app", "api.birdo.app", "updates.birdo.app"] {
            assert!(is_birdo_host(&name(host)), "{host} must stay pinned");
        }
    }

    #[test]
    fn third_party_download_hosts_are_out_of_pin_scope() {
        // The installer download leg. Pinning these against Birdo's CA set
        // cannot succeed — see `rustls_config_pinning_birdo_hosts_only`.
        for host in ["github.com", "objects.githubusercontent.com"] {
            assert!(!is_birdo_host(&name(host)), "{host} must not be pinned");
        }
    }

    #[test]
    fn lookalike_domains_are_not_treated_as_birdo_hosts() {
        // The suffix match is dot-anchored, so a registerable lookalike must
        // NOT inherit Birdo's scope. (Being in scope would only ever make a
        // connection stricter, but the predicate is security-relevant enough
        // that its boundaries are worth pinning down in a test.)
        for host in [
            "notbirdo.app",
            "birdo.app.example.com",
            "birdo.apple",
            "xbirdo.app",
        ] {
            assert!(!is_birdo_host(&name(host)), "{host} is not a Birdo host");
        }
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        assert!(is_birdo_host(&name("API.BIRDO.APP")));
    }

    #[test]
    fn ip_literals_are_not_birdo_hosts() {
        assert!(!is_birdo_host(&name("203.0.113.7")));
    }
}
