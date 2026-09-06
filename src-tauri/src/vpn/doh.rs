//! DNS-over-HTTPS (DoH) resolver to prevent DNS leaks
//!
//! Resolves VPN server hostnames via encrypted HTTPS requests to prevent
//! ISPs from observing DNS queries for VPN servers.
//!
//! SEC-002: This is critical for preventing DNS leaks during VPN connection.
//!
//! PROD-HARDENING: certificate pinning is enforced for all DoH providers as
//! **CA-chain SPKI** pinning inside the TLS handshake — the same model and
//! machinery as `api/cert_pin.rs` (a custom rustls `ServerCertVerifier`
//! wrapping the standard WebPKI verifier). The previous implementation hashed
//! the LEAF certificate DER via reqwest's `TlsInfo` — which exposes only the
//! leaf — so every ~90-day provider cert rotation silently expired the pins
//! and the hardening self-disabled. SPKI pins on the stable intermediate/root
//! survive leaf rotation; each provider carries >= 2 overlapping pins
//! (intermediate + its root) so even an intermediate re-issue under the same
//! root keeps working. If a provider fails pinning, it is skipped and the
//! next provider is tried; this is safe because only 1-of-N must succeed.
//! Unlike the API pinning, an unparseable chain fails CLOSED here — DoH has
//! independent fallback providers, the API host does not.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use serde::Deserialize;

/// DoH response format (Cloudflare JSON API)
#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: i32,
    data: String,
}

/// DNS record types
const DNS_TYPE_A: i32 = 1; // IPv4
const _DNS_TYPE_AAAA: i32 = 28; // IPv6 (reserved for future use)

/// DoH provider configuration with certificate pinning.
/// Each provider specifies one or more CA-chain SPKI SHA-256 pin hashes.
/// The connection succeeds if ANY pin matches ANY certificate in the chain
/// the server presents (leaf + intermediates).
///
/// Pin generation (SPKI hash, identical to api/cert_pin.rs and OkHttp):
///   echo | openssl s_client -connect <host>:443 -servername <host> -showcerts \
///     2>/dev/null   # then, for the intermediate (2nd cert) / root:
///   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER \
///     | openssl dgst -sha256 -binary | base64
///
/// Because the pinned keys are the stable intermediate + root — not the
/// volatile leaf — routine provider cert renewal does NOT invalidate them; a
/// release is only needed if a provider changes CA (years, announced).
struct DoHProvider {
    url: &'static str,
    /// Hostname in `url` — the key for the bootstrap resolver override below.
    host: &'static str,
    /// Hardcoded bootstrap addresses (LEAK-6).
    ///
    /// Without these, resolving the provider's own hostname goes through
    /// `getaddrinfo`, which Windows transmits from svchost (Dnscache) — a process
    /// the kill switch does NOT permit (only our own exe is). Under an active
    /// block-all the bootstrap lookup therefore needs the very UDP/53 that is
    /// blocked, DoH fails, and `resolve_via_doh` fails OPEN. Pinning the addresses
    /// keeps resolution inside our permitted process.
    ///
    /// MULTIPLE addresses per provider: a single pinned anycast IP would take the
    /// provider down globally for us if it were ever retired. TLS still uses SNI +
    /// the hostname, so the certificate pin below is unaffected by which address
    /// is dialled. IPv4 only — the client blocks IPv6 while connecting.
    bootstrap: &'static [Ipv4Addr],
    /// CA-chain SPKI SHA-256 pin hashes (base64-encoded). At least one must
    /// match a certificate in the presented chain. Each provider lists >= 2
    /// OVERLAPPING pins — the current intermediate AND its root — so a leaf
    /// rotation never matters and even an intermediate re-issue under the
    /// same root keeps one pin valid.
    /// Set to empty slice to disable pinning for this provider (emergency only).
    pins: &'static [&'static str],
}

/// DoH providers with CA-chain SPKI pins for MITM protection.
///
/// SECURITY MODEL:
/// - Pinning runs INSIDE the TLS handshake (DohSpkiPinningVerifier below),
///   after full WebPKI validation, and sees the whole presented chain — the
///   same model as api/cert_pin.rs and the Android OkHttp pinner.
/// - If a provider's chain matches no pin (or cannot be parsed), the
///   handshake is refused and that provider is skipped.
/// - An intermediate and the root that signed it are ONE lineage: a CA move
///   kills both in the same handshake, so they are not overlap. A provider
///   may also serve SEVERAL lineages at once, chosen per anycast edge —
///   dns.google does, see below — and measuring from one machine only ever
///   shows you one of them.
/// - Availability guaranteed as long as 1 provider passes pinning.
/// - If all 3 providers fail pinning simultaneously, resolution fails CLOSED.
///
/// PIN ROTATION PROCEDURE (needed only for a CA-chain change, not cert renewal):
/// 1. When a provider announces a CA migration, add the new intermediate+root
///    pins alongside the old ones.
/// 2. After the migration is confirmed fleet-wide, remove the old pins in a
///    subsequent release.
/// 3. Never remove all pins for a provider without adding new ones first.
/// 4. Never remove a pin merely because your own machine no longer sees it
///    in the chain: another user's edge may still be serving exactly that
///    chain, and a bricked pin cannot be fixed remotely.
const DOH_PROVIDERS: &[DoHProvider] = &[
    DoHProvider {
        url: "https://cloudflare-dns.com/dns-query",
        host: "cloudflare-dns.com",
        // 104.16.248.249/104.16.249.249 are the published A records; 1.1.1.1 and
        // 1.0.0.1 serve the same DoH endpoint and present the cloudflare-dns.com
        // certificate for that SNI.
        bootstrap: &[
            Ipv4Addr::new(104, 16, 248, 249),
            Ipv4Addr::new(104, 16, 249, 249),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 0, 0, 1),
        ],
        // Chain: cloudflare-dns.com → SSL.com SSL Intermediate CA ECC R2
        //        → SSL.com Root Certification Authority ECC
        // SPKI pins re-measured against the live chain 2026-08-22 (dialled via
        // 1.1.1.1: the hostname itself is what a hostile resolver hijacks).
        pins: &[
            // SSL.com SSL Intermediate CA ECC R2 (presented intermediate)
            "zGgA4OU4DjJdvpRYUqbi5Vh2g9W5Oc/PgKihy9mkLsE=",
            // SSL.com Root Certification Authority ECC (trust anchor, not sent)
            "oyD01TTXvpfBro3QSZc1vIlcMjrdLTiL/M9mLCPX+Zo=",
            // DigiCert High Assurance EV Root CA — Cloudflare's legacy anchor,
            // kept as migration overlap and to match the Android pin set.
            // Dormant: Cloudflare serves SSL.com today.
            "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
        ],
    },
    DoHProvider {
        url: "https://dns.google/resolve",
        host: "dns.google",
        bootstrap: &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        // TWO LINEAGES, NOT ONE — and an intermediate plus the root that
        // signed it does not count as two.
        //
        // 8.8.8.8/8.8.4.4 are anycast, so which Google edge answers depends on
        // the caller's network path, and on 2026-09-06 dns.google was serving
        // two different Google Trust Services lineages at the same minute over
        // those same addresses:
        //
        //   ECDSA : leaf → WE2 → GTS Root R4   (US cloud edge)
        //   RSA   : leaf → WR2 → GTS Root R1   (consumer-ISP edge)
        //
        // Until this commit only the second one was pinned. WE2 and GTS Root R4
        // are a DIFFERENT lineage, so neither of the two pins was in that chain
        // and the handshake was refused outright: every user routed to a
        // migrated edge lost this provider, with the log saying "possible MITM
        // attack" about a stale pin set. WR2 + GTS Root R1 looked like two
        // overlapping pins but was one lineage — when the CA moved, both went
        // dark in the same handshake.
        //
        // That matters precisely on the networks DoH exists for: with 1.1.1.1
        // hijacked by a captive portal and 9.9.9.9 blocked by a corporate
        // filter, dns.google is the last provider standing, and under an
        // engaged kill switch the system-resolver fallback is blocked too.
        //
        // INVARIANT: pin every lineage the provider SERVES, not the one chain
        // your own vantage point returned. A liveness probe runs from a single
        // vantage point and goes green as soon as ANY one chain matches, so it
        // cannot tell you this list is half-empty. Do NOT drop the WR2/R1 pair
        // because your machine only ever sees WE2/R4 (or the reverse) — that is
        // the edit that caused this outage, and there is no remote kill switch
        // for a bricked pin. Retire a lineage only once it is unmeasurable from
        // several independent networks.
        //
        // All four values re-measured 2026-09-06 against Google's published CA
        // certificates at https://i.pki.goog/.
        pins: &[
            // WE2 — Google Trust Services intermediate, new lineage
            "vh78KSg1Ry4NaqGDV10w/cTb9VH3BQUZoCWNa93W/EY=",
            // GTS Root R4 — anchor of the new lineage, presented in that chain;
            // the same anchor api/cert_pin.rs already pins for birdo.app
            "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
            // WR2 — Google Trust Services intermediate, legacy lineage,
            // STILL LIVE from un-migrated edges
            "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=",
            // GTS Root R1 — anchor of the legacy lineage, presented in that chain
            "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=",
        ],
    },
    DoHProvider {
        url: "https://dns.quad9.net/dns-query",
        host: "dns.quad9.net",
        bootstrap: &[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        // Chain: dns.quad9.net → DigiCert Global G3 TLS ECC SHA384 2020 CA1
        //        → DigiCert Global Root G3
        // SPKI pins verified against the live chain 2026-08-12.
        pins: &[
            // DigiCert Global G3 TLS ECC SHA384 2020 CA1 (presented intermediate)
            "qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=",
            // DigiCert Global Root G3 (trust anchor)
            "uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=",
        ],
    },
];

/// Marker embedded in every pin-rejection `TlsError` so `resolve_single_provider`
/// can classify a reqwest connect failure as a PIN failure (vs plain network
/// trouble) by walking the error source chain. rustls carries a custom
/// verifier's rejection only as `Error::General(String)`, so a distinctive
/// substring is the only channel that survives reqwest's error wrapping.
const PIN_MISMATCH_MARKER: &str = "DoH-SPKI-pin-rejected";

/// The pin set for a provider hostname, or None if the host is not a known
/// DoH provider (the DoH client never legitimately handshakes with anything
/// else — a redirect off-provider must fail closed, not get pinless TLS).
fn pins_for_host(host: &str) -> Option<&'static [&'static str]> {
    DOH_PROVIDERS
        .iter()
        .find(|p| p.host.eq_ignore_ascii_case(host))
        .map(|p| p.pins)
}

/// Does a presented chain — reduced to the SPKI pin hashes of its
/// certificates — satisfy `pins`? Any single match accepts, which is what
/// makes overlapping pins work: several CA lineages pinned at once.
///
/// Split out of `verify_server_cert` so a pin set can be regression-tested
/// against real, measured chains without standing up a TLS handshake. Nothing
/// in the suite could previously see that dns.google's pin set covered its
/// GTS Root R1 lineage and none of the GTS Root R4 one it had begun serving.
fn chain_satisfies_pins(chain_spkis: &[String], pins: &[&str]) -> bool {
    chain_spkis.iter().any(|s| pins.contains(&s.as_str()))
}

/// Did this reqwest error originate from our pinning verifier? The marker is
/// embedded in the `TlsError` the verifier returns; reqwest/hyper wrap it in
/// several layers, so walk the source chain looking for it.
fn is_pin_rejection(e: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if err.to_string().contains(PIN_MISMATCH_MARKER) {
            return true;
        }
        source = err.source();
    }
    false
}

/// CA-chain SPKI pinning for the DoH providers, layered inside the TLS
/// handshake exactly like `api/cert_pin.rs`: the wrapped WebPKI verifier runs
/// full standard validation first, then the presented chain must contain a
/// certificate whose SPKI hash is pinned for the SNI hostname's provider.
///
/// Unlike the API verifier, this one fails CLOSED when the chain cannot be
/// parsed: the API has a single host and availability wins there, while DoH
/// has two more independent fallback providers, so refusing one unparseable
/// chain costs nothing and keeps the pinning guarantee honest.
#[derive(Debug)]
struct DohSpkiPinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for DohSpkiPinningVerifier {
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

        // 2) Select the pin set by SNI hostname. The client dials providers by
        //    hostname only (the bootstrap addresses are attached to those same
        //    hostnames via resolve_to_addrs), so a non-DNS or unknown name can
        //    only be a redirect off-provider or a misuse — fail CLOSED.
        let ServerName::DnsName(dns) = server_name else {
            return Err(TlsError::General(format!(
                "{PIN_MISMATCH_MARKER}: non-DNS server name"
            )));
        };
        let host = dns.as_ref();
        let Some(pins) = pins_for_host(host) else {
            return Err(TlsError::General(format!(
                "{PIN_MISMATCH_MARKER}: {host} is not a pinned DoH provider"
            )));
        };

        // Empty pin set = pinning disabled for this provider (emergency
        // bypass, same semantics as before). WebPKI validation still applies.
        if pins.is_empty() {
            tracing::warn!("DoH pinning disabled for {host} — emergency bypass active");
            return Ok(ServerCertVerified::assertion());
        }

        // 3) SPKI pin check across the PRESENTED chain (leaf + intermediates),
        //    reusing the exact extraction api/cert_pin.rs uses. Any match passes.
        let mut parse_failures = 0usize;
        let mut chain_spkis: Vec<String> = Vec::new();
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            match crate::api::cert_pin::spki_sha256_b64(cert) {
                Some(spki) => chain_spkis.push(spki),
                None => parse_failures += 1,
            }
        }
        // A match still wins over an unparseable sibling certificate, exactly as
        // it did when this was a short-circuiting loop.
        if chain_satisfies_pins(&chain_spkis, pins) {
            tracing::debug!("DoH SPKI pin matched for {host}");
            return Ok(ServerCertVerified::assertion());
        }

        // FAIL CLOSED — on mismatch AND on parse failure (see type-level doc).
        if parse_failures > 0 {
            tracing::error!(
                "DoH pinning: {parse_failures} unparseable certificate(s) in {host}'s chain — refusing"
            );
            return Err(TlsError::General(format!(
                "{PIN_MISMATCH_MARKER}: unparseable certificate in chain for {host}"
            )));
        }
        tracing::warn!(
            "DoH pinning: no pinned CA SPKI matched {host}'s presented chain — refusing"
        );
        Err(TlsError::General(format!(
            "{PIN_MISMATCH_MARKER}: no pinned SPKI matched for {host}"
        )))
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

/// Build the rustls `ClientConfig` for the DoH client: full standard WebPKI
/// validation PLUS per-provider CA-chain SPKI pinning. Fed to reqwest via
/// `ClientBuilder::use_preconfigured_tls`, mirroring `api/cert_pin.rs` —
/// including the explicit ring provider selection (see that file for why).
fn doh_rustls_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("doh-pin: failed to build WebPKI verifier from Mozilla roots");

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("doh-pin: ring provider must support default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DohSpkiPinningVerifier { inner }))
        .with_no_client_auth();
    // Advertise ALPN http/1.1 — exactly what reqwest's own rustls setup sends
    // for this crate (our reqwest has no `http2` feature). A preconfigured
    // config otherwise sends NO ALPN at all, which dns.quad9.net answers with
    // HTTP 505 (verified live 2026-08-12): the provider would silently degrade.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Resolve a hostname to IPv4 address using DNS-over-HTTPS
///
/// This prevents the ISP from observing the VPN server hostname in DNS queries.
/// Falls back to multiple DoH providers for reliability.
/// Certificate pinning is enforced — if a provider's cert doesn't match any
/// known pin, the provider is skipped and the next one is tried.
///
/// # Arguments
/// * `hostname` - The hostname to resolve (e.g., "vpn.example.com")
///
/// # Returns
/// * `Ok(Ipv4Addr)` - The resolved IPv4 address
/// * `Err(String)` - Error message if resolution fails
pub async fn resolve_via_doh(hostname: &str) -> Result<Ipv4Addr, String> {
    // Skip DoH for already-IP addresses
    if let Ok(ip) = hostname.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    // Validate hostname before sending it to DoH providers as a query parameter.
    // A DNS name is 1..=253 chars; empty or oversized input is rejected early to
    // avoid unexpected provider behavior or parse failures. This is purely an
    // additive guard and does not alter resolution of valid hostnames.
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(format!(
            "Invalid hostname for DoH resolution: length {} out of bounds (1..=253)",
            hostname.len()
        ));
    }

    let client = doh_client()?;

    let mut last_error = String::new();
    let mut pinning_failures = 0u32;

    for provider in DOH_PROVIDERS {
        match resolve_single_provider(client, provider, hostname).await {
            Ok(ip) => {
                tracing::debug!(
                    "DoH resolved {} via {}",
                    crate::utils::redact::redact_hostname(hostname),
                    provider.url
                );
                return Ok(ip);
            }
            Err(DoHError::PinningFailed(msg)) => {
                pinning_failures += 1;
                tracing::error!("DoH provider {} CERT PIN MISMATCH: {}", provider.url, msg);
                last_error = msg;
                // Continue to next provider — do NOT trust this connection
            }
            Err(DoHError::Network(msg)) => {
                tracing::warn!("DoH provider {} network error: {}", provider.url, msg);
                last_error = msg;
            }
            Err(DoHError::Parse(msg)) => {
                tracing::warn!("DoH provider {} parse error: {}", provider.url, msg);
                last_error = msg;
            }
        }
    }

    // If ALL providers failed due to pinning, this is likely a MITM attack
    if pinning_failures == DOH_PROVIDERS.len() as u32 {
        tracing::error!(
            "ALL DoH providers failed certificate pinning — possible MITM attack. \
             DNS resolution refused for safety."
        );
        return Err(
            "DNS resolution blocked: all providers failed certificate verification. \
             This may indicate a network-level attack."
                .to_string(),
        );
    }

    Err(format!(
        "All DoH providers failed. Last error: {}",
        last_error
    ))
}

/// The process-wide DoH client.
///
/// PWR-6: previously a fresh `reqwest::Client` (and therefore a fresh TLS
/// handshake and connection pool) was built on EVERY resolution. Hoisting it also
/// lets the bootstrap overrides be installed exactly once.
static DOH_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Build (once) the DoH client with hardcoded bootstrap addresses for every
/// provider, so resolving a provider's own hostname never falls back to the
/// system resolver (see `DoHProvider::bootstrap`).
fn doh_client() -> Result<&'static reqwest::Client, String> {
    if let Some(client) = DOH_CLIENT.get() {
        return Ok(client);
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .https_only(true) // Enforce HTTPS only
        // WebPKI validation + CA-chain SPKI pinning, INSIDE the handshake.
        // Replaces the old tls_info(true) + leaf-hash-after-the-fact check
        // (reqwest's TlsInfo exposes only the leaf, so those pins expired on
        // every provider cert rotation and the hardening self-disabled).
        // The rustls config also enforces TLS >= 1.2 and rejects invalid certs.
        .use_preconfigured_tls(doh_rustls_config());

    for provider in DOH_PROVIDERS {
        let addrs: Vec<SocketAddr> = provider
            .bootstrap
            .iter()
            .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 443))
            .collect();
        builder = builder.resolve_to_addrs(provider.host, &addrs);
    }

    let client = builder
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // A concurrent caller may have won the race; either client is equivalent.
    let _ = DOH_CLIENT.set(client);
    DOH_CLIENT
        .get()
        .ok_or_else(|| "DoH client unavailable".to_string())
}

/// Internal error type to distinguish pinning failures from network errors
enum DoHError {
    PinningFailed(String),
    Network(String),
    Parse(String),
}

/// Resolve using a single DoH provider. Certificate pinning happens INSIDE
/// the TLS handshake (DohSpkiPinningVerifier) — a pin rejection surfaces here
/// as a connect error carrying PIN_MISMATCH_MARKER in its source chain, and
/// is classified as PinningFailed so resolve_via_doh can count possible MITM.
async fn resolve_single_provider(
    client: &reqwest::Client,
    provider: &DoHProvider,
    hostname: &str,
) -> Result<Ipv4Addr, DoHError> {
    let resp = client
        .get(provider.url)
        .query(&[("name", hostname), ("type", "A")])
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| {
            if is_pin_rejection(&e) {
                DoHError::PinningFailed(format!(
                    "Certificate pin validation failed for {}: {}",
                    provider.url, e
                ))
            } else {
                DoHError::Network(format!("DoH request failed: {}", e))
            }
        })?;

    if !resp.status().is_success() {
        return Err(DoHError::Network(format!(
            "DoH response status: {}",
            resp.status()
        )));
    }

    let doh_resp: DohResponse = resp
        .json()
        .await
        .map_err(|e| DoHError::Parse(format!("Failed to parse DoH response: {}", e)))?;

    // DNS status 0 = NOERROR
    if doh_resp.status != 0 {
        return Err(DoHError::Parse(format!(
            "DNS error status: {}",
            doh_resp.status
        )));
    }

    // Find the first A record
    let answers = doh_resp
        .answer
        .ok_or_else(|| DoHError::Parse("No DNS answers received".to_string()))?;

    for answer in answers {
        if answer.record_type == DNS_TYPE_A {
            let ip = answer
                .data
                .parse::<Ipv4Addr>()
                .map_err(|e| DoHError::Parse(format!("Invalid IP in DNS response: {}", e)))?;

            // SECURITY: Reject private/reserved IPs in DNS responses (anti-rebinding)
            if is_private_ip(ip) {
                return Err(DoHError::Parse(format!(
                    "DNS response contained private IP {} — possible DNS rebinding attack",
                    ip
                )));
            }

            return Ok(ip);
        }
    }

    Err(DoHError::Parse(
        "No A record found in DNS response".to_string(),
    ))
}

/// Check if an IPv4 address is in a private/reserved range.
/// Used to prevent DNS rebinding attacks where a malicious DNS server
/// returns a private IP to redirect VPN traffic to a local network.
fn is_private_ip(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        // 100.64.0.0/10 (Carrier-grade NAT)
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64)
        // 192.0.0.0/24 (IETF Protocol Assignments)
        || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_address() {
        // IP addresses should be returned directly without DNS lookup
        let ip = "192.168.1.1".parse::<Ipv4Addr>();
        assert!(ip.is_ok());
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_ip(Ipv4Addr::new(100, 64, 0, 1))); // CGNAT
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(104, 16, 0, 1)));
    }

    #[test]
    fn test_doh_provider_pins_overlapping() {
        // Every provider MUST carry >= 2 OVERLAPPING pins (intermediate + its
        // root) in production — a single pin turns any CA-side re-issue into a
        // silent one-provider outage, which is exactly how the old leaf pins
        // self-disabled.
        for provider in DOH_PROVIDERS {
            assert!(
                provider.pins.len() >= 2,
                "Provider {} needs >= 2 overlapping SPKI pins (intermediate + root)",
                provider.url
            );
            // Each pin must be valid base64 and 44 chars (SHA-256 = 32 bytes =
            // 44 base64 chars with padding).
            for pin in provider.pins {
                assert!(
                    pin.len() == 44 && pin.ends_with('='),
                    "Pin '{}' for {} has invalid format (expected 44-char padded base64 SHA-256)",
                    pin,
                    provider.url
                );
            }
        }
    }

    /// The verifier dispatches pin sets by SNI hostname; every provider host
    /// must resolve to its own pins, and anything else must resolve to None
    /// (which the verifier fails CLOSED).
    #[test]
    fn test_pins_for_host_dispatch() {
        for provider in DOH_PROVIDERS {
            let pins = pins_for_host(provider.host)
                .unwrap_or_else(|| panic!("no pin set for provider host {}", provider.host));
            assert_eq!(pins, provider.pins);
        }
        // Case-insensitive (SNI hostnames are case-insensitive per RFC 4343).
        assert!(pins_for_host("DNS.GOOGLE").is_some());
        assert!(pins_for_host("evil.example").is_none());
        assert!(pins_for_host("").is_none());
    }

    /// The pinned rustls config must build (panics here would make every DoH
    /// resolution fail at client construction).
    #[test]
    fn test_doh_rustls_config_builds() {
        let _ = doh_rustls_config();
    }

    /// LEAK-6: every provider needs bootstrap addresses (the system resolver is
    /// unreachable under an active kill switch), and MORE THAN ONE — a single
    /// pinned anycast IP would kill the provider for us if it were ever retired.
    #[test]
    fn test_doh_providers_have_multiple_bootstrap_addrs() {
        for provider in DOH_PROVIDERS {
            assert!(
                provider.bootstrap.len() >= 2,
                "Provider {} needs >= 2 bootstrap addresses (single-IP pinning is a global outage risk)",
                provider.url
            );
            for ip in provider.bootstrap {
                assert!(
                    !is_private_ip(*ip),
                    "Bootstrap address {} for {} is not a public resolver address",
                    ip,
                    provider.url
                );
            }
        }
    }

    /// REGRESSION — dns.google was pinned to ONE of the two CA lineages it
    /// serves.
    ///
    /// Google Trust Services was serving dns.google out of two lineages on the
    /// same anycast addresses on 2026-09-06, the edge deciding which one you
    /// get. The shipped pin set held only WR2 → GTS Root R1 — one lineage, so
    /// when an edge answered with WE2 → GTS Root R4 BOTH pins were absent, the
    /// handshake was refused, the provider was skipped, and the leak-proof
    /// resolver pool quietly shrank from three providers to two — on exactly
    /// the hostile networks DoH is there for, with the kill switch blocking the
    /// system-resolver fallback as designed.
    ///
    /// Both chains below are REAL, measured on 2026-09-06 with SNI dns.google.
    #[test]
    fn test_dns_google_pins_cover_both_gts_lineages() {
        let pins = pins_for_host("dns.google").expect("dns.google must be a pinned provider");

        // Observed via 8.8.8.8 and 8.8.4.4 from a consumer-ISP path.
        let rsa_chain = [
            "qW3FYuXf0SK210sV5lcUYE1NGTmBA398Ee6LXLqneUY=".to_string(), // leaf (rotates)
            "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=".to_string(), // WR2
            "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=".to_string(), // GTS Root R1
        ];
        // Observed the same day via 8.8.8.8 from a US cloud edge — the daily
        // cert-pins liveness job, which is where this failure surfaced.
        let ecdsa_chain = [
            "wyib/Zb8QzNvhqZ9QF7LzXCMzYApj7PsLe/ZjlfJzuI=".to_string(), // leaf (rotates)
            "vh78KSg1Ry4NaqGDV10w/cTb9VH3BQUZoCWNa93W/EY=".to_string(), // WE2
            "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=".to_string(), // GTS Root R4
        ];

        assert!(
            chain_satisfies_pins(&rsa_chain, pins),
            "dns.google GTS Root R1 lineage (WR2) is no longer pinned — users on \
             an un-migrated Google edge lose this DoH provider entirely"
        );
        assert!(
            chain_satisfies_pins(&ecdsa_chain, pins),
            "dns.google GTS Root R4 lineage (WE2) is not pinned — users on a \
             migrated Google edge lose this DoH provider entirely"
        );

        // Name both anchors explicitly: a future tidy-up that drops either
        // lineage re-creates the outage, and the message has to say so.
        for (label, anchor) in [
            (
                "GTS Root R1 (legacy lineage)",
                "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=",
            ),
            (
                "GTS Root R4 (new lineage)",
                "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
            ),
        ] {
            assert!(
                pins.contains(&anchor),
                "dns.google no longer pins {label}; both lineages were live on the \
                 same anycast IPs on 2026-09-06, so dropping one bricks the \
                 provider for whoever is routed to that edge"
            );
        }

        // Pins are on the CA chain: a leaf alone must satisfy nothing, or a
        // ~90-day leaf rotation would brick the client (the old leaf-DER scheme).
        assert!(!chain_satisfies_pins(&[rsa_chain[0].clone()], pins));
        assert!(!chain_satisfies_pins(&[ecdsa_chain[0].clone()], pins));

        // Pin sets are per-host, not a shared pool: Quad9's chain must never
        // authenticate dns.google.
        let quad9_chain = [
            "qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=".to_string(),
            "uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=".to_string(),
        ];
        assert!(!chain_satisfies_pins(&quad9_chain, pins));
    }

    /// An empty chain — or one whose every certificate failed to parse — must
    /// never satisfy a pin set: `verify_server_cert` depends on that to fail
    /// CLOSED rather than accept a chain it could not read.
    #[test]
    fn test_chain_satisfies_pins_is_false_for_an_empty_chain() {
        for provider in DOH_PROVIDERS {
            assert!(!chain_satisfies_pins(&[], provider.pins));
        }
    }

    /// The bootstrap override is keyed by host, so `host` must be exactly the
    /// authority in `url` or the override silently never applies.
    #[test]
    fn test_doh_provider_host_matches_url() {
        for provider in DOH_PROVIDERS {
            let expected = provider
                .url
                .strip_prefix("https://")
                .and_then(|rest| rest.split('/').next())
                .expect("provider URL must be https with a host");
            assert_eq!(
                provider.host, expected,
                "host '{}' does not match the authority in {}",
                provider.host, provider.url
            );
        }
    }
}
