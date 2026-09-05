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
/// - Availability guaranteed as long as 1 provider passes pinning.
/// - If all 3 providers fail pinning simultaneously, resolution fails CLOSED.
///
/// PIN ROTATION PROCEDURE (needed only for a CA-chain change, not cert renewal):
/// 1. When a provider announces a CA migration, add the new intermediate+root
///    pins alongside the old ones.
/// 2. After the migration is confirmed fleet-wide, remove the old pins in a
///    subsequent release.
/// 3. Never remove all pins for a provider without adding new ones first.
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
        // Chain: dns.google → WR2 (Google Trust Services) → GTS Root R1
        // SPKI pins verified against the live chain 2026-08-12; the GTS Root R1
        // value also matches Google's published pin list (pki.goog).
        pins: &[
            // WR2, Google Trust Services (presented intermediate)
            "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=",
            // GTS Root R1 (trust anchor, presented in the live chain)
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
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            match crate::api::cert_pin::spki_sha256_b64(cert) {
                Some(spki) if pins.contains(&spki.as_str()) => {
                    tracing::debug!("DoH SPKI pin matched for {host}");
                    return Ok(ServerCertVerified::assertion());
                }
                Some(_) => {}
                None => parse_failures += 1,
            }
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
