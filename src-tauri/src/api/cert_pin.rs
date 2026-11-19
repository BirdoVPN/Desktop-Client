//! TLS certificate pinning for the Birdo API client.
//!
//! Pins the **CA-chain SPKI** (SubjectPublicKeyInfo SHA-256), matching the
//! Android client (OkHttp `CertificatePinner` in `NetworkModule.kt`). Because we
//! pin the stable intermediate/root public keys — not the volatile leaf — the
//! edge cert can rotate every ~90 days WITHOUT a new desktop release. A release
//! IS needed the moment the presented chain stops matching these pins, and a
//! CA can do that without notice: on 2026-09-06 Google Trust Services was
//! serving `dns.google` from a second hierarchy on some anycast edges and the
//! DoH pin set `vpn/doh.rs` then carried for it went dark there. Do not read
//! "years" into it.
//!
//! What the backups below do and do not buy: the live `birdo.app` chain is ONE
//! lineage (WE1 and the GTS Root R4 that signed it vanish from the same
//! handshake together), and the Let's Encrypt pins cover exactly one migration
//! — to Let's Encrypt via R10/R11/E5/E6 — not a second live path. That is the
//! position `scripts/check-cert-pins.sh` check 2b holds this host to: it fails
//! unless the SSOT carries an explicit, dated `_overlap_risk` for `birdo.app`.
//!
//! Implemented as a custom rustls `ServerCertVerifier` that WRAPS the default
//! WebPKI verifier: standard validation (chain-to-trusted-root, hostname,
//! validity period) runs first and unchanged; the SPKI pin is layered on top.
//! reqwest only exposes the leaf via `TlsInfo`, so chain pinning must happen
//! here, inside the TLS handshake.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, OtherError,
    RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};

/// SPKI SHA-256 pins (base64) for `birdo.app` and its subdomains.
///
/// SOURCE OF TRUTH: `third_party/cert-pins.json` (vendored from
/// `birdo-shared/cert-pins.json`). This array must equal the `birdo.app` pin
/// set declared there, and so must the Android and iOS copies:
///   - `app/src/main/java/app/birdo/vpn/di/NetworkModule.kt`
///   - `app/src/main/res/xml/network_security_config.xml`
///   - `iosApp/iosApp/Services/APIClient.swift`
///
/// That equality is ENFORCED, not merely asserted: `scripts/check-cert-pins.sh`
/// (CI workflow `cert-pins.yml`, on every PR and daily) parses this array and
/// fails the build if it diverges from the SSOT by so much as one character.
/// An earlier version of this comment claimed the copies were "kept in sync"
/// with no mechanism behind the claim, and they had in fact diverged: this file
/// carried 8 pins while the Android and iOS clients carried 3.
///
/// A connection is accepted if ANY certificate in the presented chain
/// (intermediate OR root) matches one of these. Re-measured against the live
/// `api.birdo.app` chain 2026-08-22: leaf CN=birdo.app -> WE1 -> GTS Root R4,
/// so the first two pins below are live and the rest are dormant backups.
const PINNED_SPKI_SHA256: &[&str] = &[
    // Google Trust Services "WE1" intermediate — the cert api.birdo.app chained
    // through when it was last measured (2026-09-08, both vantages). PRIMARY
    // pin (also pinned on Android). NOT "stable for years": that is what this
    // comment used to say, and dns.google's set was described the same way
    // three days before a GTS hierarchy change took it dark on every ECDSA
    // edge, with no CA change and no announcement. What is true is narrower —
    // it is what the CA served the last time anyone looked.
    "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
    // GTS Root R4 — the actual trust anchor in the live chain (2026-06-08).
    "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
    // GlobalSign ECC Root CA - R4 — alternate Google cross-sign anchor (kept for
    // chains that present GlobalSign instead of GTS Root R4; also on Android).
    "CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk=",
    // ISRG Root X1 (Let's Encrypt) — cross-CA backup for ONE migration: Google
    // -> Let's Encrypt via the four issuing intermediates pinned below (also
    // pinned on Android). It does not cover a migration to any other CA, and
    // Cloudflare's Universal SSL pool includes SSL.com, which is NOT pinned —
    // so "cannot brick installed clients", which is what this comment used to
    // say, is false. A renewal that lands outside these pins bricks every
    // installed client's API access with no remote recovery path. That risk is
    // recorded, dated and machine-checked as the SSOT's `_overlap_risk`
    // "birdo-app-single-live-lineage" (check 2b of scripts/check-cert-pins.sh
    // fails this host if the waiver is dropped, expires, or stops matching).
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

/// Why the pin refused a chain that WebPKI had just accepted (MR-2537).
///
/// The verifier hands it to rustls as
/// `Error::InvalidCertificate(CertificateError::Other(..))`, the variant
/// rustls keeps for a custom verifier's own reason, and rustls aborts the
/// handshake with it, before any HTTP byte is written. The API client then
/// finds it again BY TYPE in the failed request's error chain
/// ([`PinRejection::in_chain`]) and tells the user a pin failure
/// (`ApiError::CertificatePinningFailed`, `cert_pin_failed`).
///
/// It used to be a `TlsError::General(String)`, which nothing told apart
/// from any other failed connection: a real pin failure reached the user as
/// `network_offline`, "Couldn't reach BirdoVPN. Check your internet
/// connection." `CertificatePinningFailed` was built only in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinRejection {
    /// Not one certificate in the chain could be parsed, so the pin could not
    /// be checked: refused (fail closed).
    Unparseable,
    /// The chain parsed, and no certificate in it carries a pinned SPKI.
    Mismatch,
}

impl PinRejection {
    /// A fixed description: no host, no URL, nothing taken from the chain.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unparseable => "certificate chain SPKI unparseable — pin check impossible",
            Self::Mismatch => "certificate SPKI pin mismatch",
        }
    }

    /// The error the verifier fails the handshake with.
    pub(crate) fn into_tls_error(self) -> TlsError {
        TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(self))))
    }

    /// The pin's refusal `error` is, if it is one: matched on the type the
    /// verifier put in it, never on any text.
    pub(crate) fn of(error: &TlsError) -> Option<Self> {
        match error {
            TlsError::InvalidCertificate(CertificateError::Other(OtherError(reason))) => {
                (**reason).downcast_ref::<Self>().copied()
            }
            _ => None,
        }
    }

    /// The pin's refusal anywhere in `error` and the errors under it: what a
    /// request whose handshake the pin refused fails with. reqwest 0.12
    /// hands it up as `reqwest::Error` → `hyper_util` `Error` (Connect) →
    /// `io::Error` (hyper-rustls, kind Other) → `io::Error` (tokio-rustls,
    /// InvalidData) → `rustls::Error`; through a proxy, with one `io::Error`
    /// fewer.
    pub(crate) fn in_chain(error: &(dyn StdError + 'static)) -> Option<Self> {
        find_rejection(error, CHAIN_DEPTH)
    }
}

impl fmt::Display for PinRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl StdError for PinRejection {}

/// How many errors deep [`PinRejection::in_chain`] looks. The chain of a
/// failed request is five; the bound only keeps a chain that loops (someone
/// else's bug) from looping here.
const CHAIN_DEPTH: u8 = 16;

fn find_rejection(error: &(dyn StdError + 'static), depth: u8) -> Option<PinRejection> {
    let depth = depth.checked_sub(1)?;
    if let Some(found) = error.downcast_ref::<TlsError>().and_then(PinRejection::of) {
        return Some(found);
    }
    // `io::Error::source()` skips the error an `io::Error` wraps (it answers
    // that error's own source), and the rustls error comes up inside two of
    // them. So each `io::Error` is looked into as well as past.
    if let Some(found) = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
        .and_then(|wrapped| find_rejection(wrapped, depth))
    {
        return Some(found);
    }
    find_rejection(error.source()?, depth)
}

/// Step 3 of the verifier, on the chain's SPKI pins in order (`None` for a
/// certificate x509-parser cannot read): accepted when any one is pinned.
/// Otherwise refused: [`PinRejection::Mismatch`] when the chain could be
/// read, and [`PinRejection::Unparseable`] when not one certificate could
/// (FAIL CLOSED, see the verifier). Lazy: nothing after the first pinned
/// certificate is parsed.
fn pin_verdict(chain: impl IntoIterator<Item = Option<String>>) -> Result<(), PinRejection> {
    let mut parsed_any = false;
    for spki in chain.into_iter().flatten() {
        parsed_any = true;
        if PINNED_SPKI_SHA256.contains(&spki.as_str()) {
            return Ok(());
        }
    }
    Err(if parsed_any {
        PinRejection::Mismatch
    } else {
        PinRejection::Unparseable
    })
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
        let chain = std::iter::once(end_entity).chain(intermediates.iter());
        let Err(rejection) = pin_verdict(chain.map(spki_sha256_b64)) else {
            return Ok(ServerCertVerified::assertion());
        };
        match rejection {
            // No certificate in the chain could be parsed by x509-parser. FAIL
            // CLOSED: WebPKI just parsed and validated this same chain, so a
            // chain our SPKI extractor cannot read at all is either a crafted
            // chain or a parser bug — and treating it as "pinned OK" would turn
            // the pin from a hard gate into advisory exactly when it matters.
            PinRejection::Unparseable => tracing::error!(
                "cert-pin: could not parse any certificate SPKI in the chain — refusing connection (fail closed)"
            ),
            PinRejection::Mismatch => tracing::error!(
                "cert-pin: no pinned SPKI matched the presented chain — refusing connection (possible MITM or un-pinned CA change)"
            ),
        }
        // Refused either way. The API client tells it from a network failure
        // by this error's type (`PinRejection::in_chain`, MR-2537).
        Err(rejection.into_tls_error())
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
/// This is the strict configuration and the right one for the API client.
///
/// It used to say the API client "only ever dials `api.birdo.app`". PR #162 is
/// what made that false: `BirdoApi::get_client_config` dials the `birdo.app`
/// apex for `/api/client-config`. Nothing here needs to change — `AllHosts`
/// pins whatever the client dials, and both hosts chain through pinned CAs —
/// but left standing, that sentence read as a promise about the caller that a
/// future reader could rely on and a future caller could quietly break.
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

/// SPKI SHA-256 pins (base64, same form as [`PINNED_SPKI_SHA256`]) of every
/// trust anchor in the compiled-in webpki-roots store.
///
/// A `TrustAnchor` carries the SubjectPublicKeyInfo with its outer SEQUENCE
/// stripped; re-wrapping it gives exactly the bytes [`spki_sha256_b64`]
/// hashes (proved by ISRG Root X1 matching below).
#[cfg(test)]
pub(crate) fn webpki_root_spki_pins() -> Vec<String> {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|anchor| {
            let body: &[u8] = anchor.subject_public_key_info.as_ref();
            let len = body.len();
            let mut der = vec![0x30];
            if len < 0x80 {
                der.push(len as u8);
            } else if len <= 0xff {
                der.extend([0x81, len as u8]);
            } else {
                der.extend([0x82, (len >> 8) as u8, len as u8]);
            }
            der.extend_from_slice(body);
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&der))
        })
        .collect()
}

/// Tests: a request's error when its TLS handshake failed with `tls`, built
/// the way reqwest 0.12 hands one up. Read from the sources this lockfile
/// builds (reqwest 0.12.28, hyper-util 0.1.19, hyper-rustls 0.27.7,
/// tokio-rustls 0.26.4), outermost first:
/// - `reqwest::Error`, "error sending request for url (…)", whose `source()`
///   is
/// - `hyper_util::client::legacy::Error` (kind Connect), whose `source()` is
/// - `io::Error::new(Other, e)` (hyper-rustls `HttpsConnector`), wrapping
/// - `io::Error::new(InvalidData, e)` (tokio-rustls, the handshake), wrapping
/// - the `rustls::Error` the verifier returned.
///
/// The two outer layers cannot be built by hand, so they are stand-ins with
/// the same `source()`. The URL is a heartbeat's: its path carries the
/// session's key id, which nothing told to the user may repeat.
#[cfg(test)]
pub(crate) fn failed_handshake(tls: TlsError) -> Box<dyn StdError + Send + Sync> {
    #[derive(Debug)]
    struct Layer {
        text: &'static str,
        source: Box<dyn StdError + Send + Sync>,
    }
    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.text)
        }
    }
    impl StdError for Layer {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&*self.source)
        }
    }
    let handshake = std::io::Error::new(std::io::ErrorKind::InvalidData, tls);
    Box::new(Layer {
        text: "error sending request for url (https://api.birdo.app/vpn/heartbeat/key-123)",
        source: Box::new(Layer {
            text: "client error (Connect)",
            source: Box::new(std::io::Error::other(handshake)),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The WebPKI verifier runs BEFORE the pin check, against the
    /// webpki-roots store. A root missing from that store fails every chain
    /// that ends at it, pinned or not. So a webpki-roots bump that drops the
    /// anchor the live api.birdo.app chain ends at (birdo.app <- WE1 <- GTS
    /// Root R4, measured 2026-10-07) would brick every installed client, and
    /// nothing else in CI would notice. 1.0.9 dropped 19 roots, among them
    /// GTS Root R2 and three DigiCert roots, so this is not hypothetical.
    #[test]
    fn the_live_birdo_app_anchors_are_in_the_webpki_root_store() {
        let roots = webpki_root_spki_pins();
        // Self-check of the re-wrapping: the ISRG Root X1 anchor hashes to
        // the pin spki_sha256_b64() extracts from the real certificate.
        assert!(roots.iter().any(|r| r == ISRG_X1_SPKI));
        // GTS Root R4 (the live anchor) and GlobalSign ECC Root CA - R4 (the
        // pinned cross-sign backup).
        for pin in [
            "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
            "CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk=",
        ] {
            assert!(PINNED_SPKI_SHA256.contains(&pin));
            assert!(
                roots.iter().any(|r| r == pin),
                "pinned root {pin} is no longer a webpki-roots trust anchor"
            );
        }
    }

    /// Every OTHER host the app's rustls clients dial (all of them validate
    /// against webpki-roots) must still chain to a root in the store. Chains
    /// measured 2026-10-07 and verified with `openssl s_client -CAfile`
    /// against ONLY the 1.0.9 roots. api.birdo.app / birdo.app and
    /// cloudflare-dns.com (DoH, also over 1.1.1.1, 1.0.0.1, 104.16.248.249,
    /// 104.16.249.249) are asserted above and in vpn/doh.rs. A host passes if
    /// ANY root its chain can end at is present (cross-signed roots give
    /// more than one valid path).
    #[test]
    fn every_other_host_the_app_dials_still_chains_to_a_webpki_root() {
        let roots = webpki_root_spki_pins();
        let hosts: &[(&str, &[(&str, &str)])] = &[
            // Update download: the manifest's github.com URL redirects here.
            // ECDSA: github.com <- Sectigo ... CA DV E36 <- Sectigo ... Root E46
            // (cross-signed by USERTrust ECC); RSA: ... DV R36 <- Root R46
            // (cross-signed by USERTrust RSA).
            (
                "github.com (ECDSA)",
                &[
                    (
                        "sLVjNUaFYfW7n6EtgBeEpjOlcnBdNPMrZDRF36iwBdE=",
                        "Sectigo Public Server Authentication Root E46",
                    ),
                    (
                        "ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs=",
                        "USERTrust ECC Certification Authority",
                    ),
                ],
            ),
            (
                "github.com (RSA)",
                &[
                    (
                        "Douxi77vs4G+Ib/BogbTFymEYq0QSFXwSgVCaZcI09Q=",
                        "Sectigo Public Server Authentication Root R46",
                    ),
                    (
                        "x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4=",
                        "USERTrust RSA Certification Authority",
                    ),
                ],
            ),
            // release-assets / objects.githubusercontent.com: <- YR1 <- Root YR
            // (cross-signed by ISRG Root X1; Root YR itself is not in the store).
            (
                "release-assets.githubusercontent.com",
                &[(ISRG_X1_SPKI, "ISRG Root X1")],
            ),
            // Sentry ingest (sentry.io, us. and de. regions alike):
            // <- DigiCert Global G2 TLS RSA SHA256 2020 CA1 <- DigiCert Global Root G2.
            (
                "*.ingest.sentry.io",
                &[(
                    "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
                    "DigiCert Global Root G2",
                )],
            ),
        ];
        for (host, anchors) in hosts {
            assert!(
                anchors
                    .iter()
                    .any(|(pin, _)| roots.iter().any(|r| r == pin)),
                "{host}: none of {:?} is a webpki-roots trust anchor any more",
                anchors.iter().map(|(_, name)| *name).collect::<Vec<_>>()
            );
        }
    }

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

    /// Sectigo Public Server Authentication Root E46, which github.com
    /// chains to: a real SPKI pin, and not one of ours.
    const UNPINNED_SPKI: &str = "sLVjNUaFYfW7n6EtgBeEpjOlcnBdNPMrZDRF36iwBdE=";

    /// MR-2537, step 3 of the verifier, unchanged by the refusal getting a
    /// type: accepted when any certificate in the chain is pinned; refused
    /// when none is; refused (fail closed) when not one could be read.
    #[test]
    fn the_pin_accepts_a_pinned_chain_and_refuses_every_other() {
        assert!(!PINNED_SPKI_SHA256.contains(&UNPINNED_SPKI));
        let pinned = || Some(ISRG_X1_SPKI.to_string());
        let unpinned = || Some(UNPINNED_SPKI.to_string());
        let cases = [
            ("pinned", vec![pinned()], Ok(())),
            ("pinned further up", vec![unpinned(), pinned()], Ok(())),
            (
                "pinned past an unreadable one",
                vec![None, pinned()],
                Ok(()),
            ),
            ("unpinned", vec![unpinned()], Err(PinRejection::Mismatch)),
            (
                "unpinned and unreadable",
                vec![None, unpinned()],
                Err(PinRejection::Mismatch),
            ),
            (
                "unreadable",
                vec![None, None],
                Err(PinRejection::Unparseable),
            ),
            ("empty", vec![], Err(PinRejection::Unparseable)),
        ];
        for (case, chain, verdict) in cases {
            assert_eq!(pin_verdict(chain), verdict, "{case}");
        }
        // Through the real extraction.
        let isrg = CertificateDer::from(ISRG_X1_DER.to_vec());
        let junk = CertificateDer::from(vec![0u8, 1, 2, 3, 4]);
        assert_eq!(pin_verdict([&junk, &isrg].map(spki_sha256_b64)), Ok(()));
        assert_eq!(
            pin_verdict([&junk].map(spki_sha256_b64)),
            Err(PinRejection::Unparseable)
        );
    }

    /// MR-2537: the verifier's refusal is an `InvalidCertificate` carrying
    /// its own type, and is recognised by that type, never by its words.
    #[test]
    fn the_pin_refusal_is_recognised_by_its_type() {
        for rejection in [PinRejection::Mismatch, PinRejection::Unparseable] {
            let tls = rejection.into_tls_error();
            assert!(matches!(
                tls,
                TlsError::InvalidCertificate(CertificateError::Other(_))
            ));
            assert_eq!(PinRejection::of(&tls), Some(rejection));
        }
        let others = [
            (
                "the same words, untyped",
                TlsError::General(PinRejection::Mismatch.label().to_string()),
            ),
            (
                "an issuer WebPKI does not trust",
                TlsError::InvalidCertificate(CertificateError::UnknownIssuer),
            ),
            (
                "another verifier's own reason",
                TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
                    std::io::Error::other("x"),
                )))),
            ),
        ];
        for (case, other) in others {
            assert_eq!(PinRejection::of(&other), None, "{case}");
        }
    }

    /// MR-2537: the refusal is found where a failed request carries it: two
    /// `io::Error`s down (whose `source()` skips what they wrap) under
    /// reqwest's and hyper-util's layers, or, through a proxy, one down. A
    /// handshake that failed for any other reason is not a pin refusal.
    #[test]
    fn the_pin_refusal_is_found_in_a_failed_requests_chain() {
        for rejection in [PinRejection::Mismatch, PinRejection::Unparseable] {
            let failed = failed_handshake(rejection.into_tls_error());
            assert_eq!(PinRejection::in_chain(&*failed), Some(rejection));
            let proxied =
                std::io::Error::new(std::io::ErrorKind::InvalidData, rejection.into_tls_error());
            assert_eq!(PinRejection::in_chain(&proxied), Some(rejection));
        }
        let others: [(&str, Box<dyn StdError + Send + Sync>); 3] = [
            (
                "the same words, untyped",
                failed_handshake(TlsError::General(
                    PinRejection::Mismatch.label().to_string(),
                )),
            ),
            (
                "an issuer WebPKI does not trust",
                failed_handshake(TlsError::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                )),
            ),
            (
                "connection refused",
                Box::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            ),
        ];
        for (case, other) in others {
            assert_eq!(PinRejection::in_chain(&*other), None, "{case}");
        }
    }

    /// MR-2537, the wiring: the verifier refuses with the typed refusal and
    /// nothing else, so no refusal of the pin's can reach the client as an
    /// error it cannot tell from the network's.
    #[test]
    fn the_verifier_refuses_with_the_typed_refusal() {
        const SOURCE: &str = include_str!("cert_pin.rs");
        let verifier = &SOURCE[SOURCE.find("fn verify_server_cert(").unwrap()..];
        let verifier = &verifier[..verifier.find("\n    }").unwrap()];
        assert!(verifier.contains("pin_verdict(chain.map(spki_sha256_b64))"));
        assert!(verifier.contains("Err(rejection.into_tls_error())"));
        assert!(!verifier.contains("General"));
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
