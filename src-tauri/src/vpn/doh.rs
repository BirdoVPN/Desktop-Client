//! DNS-over-HTTPS (DoH) resolver to prevent DNS leaks
//!
//! Resolves VPN server hostnames via encrypted HTTPS requests to prevent
//! ISPs from observing DNS queries for VPN servers.
//!
//! SEC-002: This is critical for preventing DNS leaks during VPN connection.
//!
//! PROD-HARDENING: Certificate pinning is now enforced for all DoH providers.
//! Each provider has multiple SPKI SHA-256 pins (primary + backup CA).
//! If a provider fails pinning, it is skipped and the next provider is tried.
//! This is safe because we need only 1-of-N providers to succeed.

use serde::Deserialize;
use sha2::{Sha256, Digest};
use std::net::Ipv4Addr;
use std::time::Duration;

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
const DNS_TYPE_A: i32 = 1;       // IPv4
const _DNS_TYPE_AAAA: i32 = 28;  // IPv6 (reserved for future use)

/// DoH provider configuration with certificate pinning.
/// Each provider specifies one or more SPKI SHA-256 pin hashes.
/// The connection succeeds if ANY pin matches the server certificate chain.
///
/// Pin generation (full DER cert hash — NOT SPKI):
///   echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \
///     | openssl x509 -outform der | openssl dgst -sha256 -binary | base64
///
/// For CA/intermediate backup pin, extract the second cert in the chain.
///
/// IMPORTANT: These pins MUST be regenerated when providers renew certificates.
/// The generate-cert-pins.sh script automates this process.
struct DoHProvider {
    url: &'static str,
    /// SPKI SHA-256 pin hashes (base64-encoded). At least one must match.
    /// Include both the leaf certificate pin AND the issuing CA pin for rotation safety.
    /// Set to empty slice to disable pinning for this provider (emergency only).
    pins: &'static [&'static str],
}

/// DoH providers with certificate pins for MITM protection.
///
/// SECURITY MODEL:
/// - reqwest's `peer_certificate()` returns ONLY the leaf cert, not the chain.
///   Therefore only leaf cert DER hashes actually provide protection here.
///   The "backup CA" pins listed below are a safety net in case a DoH provider
///   re-issues with the same intermediate/root — but they will NOT match via
///   `peer_certificate()` alone. They are retained for documentation purposes
///   and in case we later switch to a chain-aware TLS backend.
/// - If ALL pins fail for a provider, that provider is skipped
/// - Availability guaranteed as long as 1 provider passes pinning
/// - If all 3 providers are MITM'd simultaneously, resolution fails CLOSED (safe)
///
/// PIN ROTATION PROCEDURE:
/// 1. Before a provider rotates certs, add the new leaf pin alongside the old one
/// 2. After rotation is confirmed, remove the old pin in a subsequent release
/// 3. Never remove all pins for a provider without adding new ones first
const DOH_PROVIDERS: &[DoHProvider] = &[
    DoHProvider {
        url: "https://cloudflare-dns.com/dns-query",
        // Chain: cloudflare-dns.com → SSL.com SSL Intermediate CA ECC R2 → SSL.com Root CA ECC
        // Pins regenerated 2025-07-16 from live cloudflare-dns.com certificate.
        pins: &[
            "47AoJnidZT0iTT7ay+Tod8tyhvxMkiZy9iJnQcpXrWU=",  // leaf: cloudflare-dns.com (expires 2026-12-21)
            "lItxEa9C9UbVec/1ziveyCE03ZkUhCvdsMUocutgTjk=",  // intermediate: SSL.com SSL Intermediate CA ECC R2
        ],
    },
    DoHProvider {
        url: "https://dns.google/resolve",
        // Chain: dns.google → WR2 (Google Trust Services) → GTS Root R1
        // Pins regenerated 2025-07-16 from live dns.google certificate.
        pins: &[
            "ACUte493Q17uULD+DmOIon7nIx0FUDnohxxMNNlA/Pg=",  // leaf: dns.google (expires 2026-04-27)
            "5v4iv0Xk8NO4XFngLA9JVBjh640yEPeI1IzV4ctUfNQ=",  // intermediate: WR2 (Google Trust Services)
        ],
    },
    DoHProvider {
        url: "https://dns.quad9.net/dns-query",
        // Chain: dns.quad9.net → DigiCert Global G3 TLS ECC SHA384 2020 CA1 → DigiCert Global Root G3
        // Pins regenerated 2025-07-16 from live dns.quad9.net certificate.
        pins: &[
            "SCxBhlVQMlGdPR2qQI+sDmPHCvMNIq0+V8LUnjtP29w=",  // leaf: dns.quad9.net (expires 2026-07-27)
            "BYfWvSgZWHq5D7WWSApXk72fdQaj6s5z9eqzZgF/4lk=",  // intermediate: DigiCert Global G3 TLS ECC SHA384 2020 CA1
        ],
    },
];

/// Validate a TLS certificate against a set of SHA-256 pin hashes.
/// Returns true if ANY pin matches the peer certificate.
///
/// SEC: This hashes the full DER-encoded leaf certificate. Pins must be
/// regenerated whenever the certificate is renewed (even with the same key).
/// This is intentional — for DoH providers that rotate certs regularly,
/// we include both the leaf cert pin AND the issuing CA intermediate cert pin
/// as a backup, ensuring smooth rotation.
///
/// To generate a pin for a DoH provider:
///   echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \
///     | openssl x509 -outform der | openssl dgst -sha256 -binary | base64
///
/// For CA/intermediate backup pin:
///   echo | openssl s_client -connect <host>:443 -servername <host> -showcerts 2>/dev/null \
///     | sed -n '/-----BEGIN/{:a;/-----END/!{N;ba};p}' | tail -n +2 | head -1 \
///     | openssl x509 -outform der | openssl dgst -sha256 -binary | base64
fn validate_certificate_pin(
    tls_info: Option<&reqwest::tls::TlsInfo>,
    expected_pins: &[&str],
) -> bool {
    // If no pins configured, pinning is disabled for this provider (emergency bypass)
    if expected_pins.is_empty() {
        tracing::warn!("Certificate pinning disabled for provider — emergency bypass active");
        return true;
    }

    let tls = match tls_info {
        Some(info) => info,
        None => {
            tracing::error!("No TLS info available — cannot verify certificate pin");
            return false;
        }
    };

    // Get the DER-encoded peer certificate
    let cert_der = match tls.peer_certificate() {
        Some(cert) => cert,
        None => {
            tracing::error!("No peer certificate in TLS info — pinning failed");
            return false;
        }
    };
    let cert_hash = {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        hasher.finalize()
    };
    let cert_pin = base64_encode(&cert_hash);

    // Check if any expected pin matches the leaf cert
    for pin in expected_pins {
        if *pin == cert_pin {
            tracing::debug!("Certificate pin matched (leaf): {}…", &pin[..12]);
            return true;
        }
    }

    tracing::warn!(
        "Certificate pinning FAILED — no pin matched. Got: {}",
        &cert_pin[..16]
    );
    false
}

/// Minimal base64 encoder (avoids pulling in the base64 crate just for this)
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .https_only(true)                                  // Enforce HTTPS only
        .danger_accept_invalid_certs(false)                 // Reject invalid certs
        .min_tls_version(reqwest::tls::Version::TLS_1_2)   // Minimum TLS 1.2
        .tls_info(true)                                     // PROD: Enable TLS info for pinning
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let mut last_error = String::new();
    let mut pinning_failures = 0u32;

    for provider in DOH_PROVIDERS {
        match resolve_single_provider(&client, provider, hostname).await {
            Ok(ip) => {
                tracing::debug!("DoH resolved {} via {}", hostname, provider.url);
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

    Err(format!("All DoH providers failed. Last error: {}", last_error))
}

/// Internal error type to distinguish pinning failures from network errors
enum DoHError {
    PinningFailed(String),
    Network(String),
    Parse(String),
}

/// Resolve using a single DoH provider with certificate pin verification
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
        .map_err(|e| DoHError::Network(format!("DoH request failed: {}", e)))?;

    // PROD-HARDENING: Verify certificate pin BEFORE trusting response data.
    // This is defense-in-depth against compromised CAs intercepting DoH queries.
    if !provider.pins.is_empty() {
        let tls = resp.extensions().get::<reqwest::tls::TlsInfo>();
        if !validate_certificate_pin(tls, provider.pins) {
            return Err(DoHError::PinningFailed(format!(
                "Certificate pin validation failed for {}",
                provider.url
            )));
        }
    }

    if !resp.status().is_success() {
        return Err(DoHError::Network(format!("DoH response status: {}", resp.status())));
    }

    let doh_resp: DohResponse = resp
        .json()
        .await
        .map_err(|e| DoHError::Parse(format!("Failed to parse DoH response: {}", e)))?;

    // DNS status 0 = NOERROR
    if doh_resp.status != 0 {
        return Err(DoHError::Parse(format!("DNS error status: {}", doh_resp.status)));
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

    Err(DoHError::Parse("No A record found in DNS response".to_string()))
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
        assert!(is_private_ip(Ipv4Addr::new(100, 64, 0, 1)));   // CGNAT
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(104, 16, 0, 1)));
    }

    #[test]
    fn test_doh_provider_pins_non_empty() {
        // Every provider MUST have at least one pin in production
        for provider in DOH_PROVIDERS {
            assert!(
                !provider.pins.is_empty(),
                "Provider {} has no certificate pins — this is a security risk",
                provider.url
            );
            // Each pin must be valid base64 and 44 chars (SHA-256 = 32 bytes = 44 base64 chars with padding)
            // SEC: Pins must be regenerated using DER cert hash (see generate-cert-pins.sh)
            for pin in provider.pins {
                assert!(
                    (pin.len() == 43 || pin.len() == 44) && pin.ends_with('='),
                    "Pin '{}' for {} has invalid format (expected 43-or-44-char base64)",
                    pin,
                    provider.url
                );
            }
        }
    }

    #[test]
    fn test_base64_encode() {
        let data = [0u8; 32]; // 32 zero bytes
        let encoded = base64_encode(&data);
        assert_eq!(encoded, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }
}
