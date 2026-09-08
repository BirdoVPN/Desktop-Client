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
//! survive leaf rotation. If a provider fails pinning, it is skipped and the
//! next provider is tried; this is safe because only 1-of-N must succeed.
//! Unlike the API pinning, an unparseable chain fails CLOSED here — DoH has
//! independent fallback providers, the API host does not.
//!
//! WHAT THE PIN SETS DO **NOT** GUARANTEE. This paragraph used to claim that
//! "each provider carries >= 2 overlapping pins (intermediate + its root) so
//! even an intermediate re-issue under the same root keeps working". That was
//! false, and believing it is what took dns.google dark:
//!
//!   * An intermediate and the root that signed it are ONE lineage. When the CA
//!     serves the host out of a different hierarchy, BOTH pins are absent from
//!     the same handshake. Two pins, zero overlap.
//!   * A pin is only worth anything if the server actually SENDS the
//!     certificate it hashes. `cloudflare-dns.com` and `dns.quad9.net` both
//!     send a shortened chain — leaf + intermediate, no root (measured
//!     2026-09-06 and again 2026-09-08 from a UK consumer ISP and from the
//!     production hub, over every published IPv4 address and, from the hub,
//!     IPv6) — so of their 3 and 2 pins respectively, exactly ONE can ever
//!     match. Each is one CA-side re-issue away from the dns.google failure,
//!     and that is stated here because it is true, not fixed: no second
//!     matchable certificate exists to pin.
//!
//! The real per-host position is machine-checked, not asserted in prose:
//! `scripts/check-cert-pins.sh` check 2b counts the LINEAGES each host is
//! observed to present live — an intermediate and the root that signed it are
//! one — and fails any host with a single live lineage that has no explicit,
//! dated `_overlap_risk` waiver in the SSOT, and any waived host that has
//! outgrown its waiver. `test_live_lineages_per_provider` below does the same
//! count over real measured chains. Do not restore a blanket ">= 2 overlapping
//! pins" claim here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
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
/// Because the pinned keys are the intermediate + root — not the volatile
/// leaf — routine provider cert renewal does NOT invalidate them. A release
/// IS needed whenever a provider presents a chain none of these pins match,
/// and that happens with no CA change and no announcement: on 2026-09-06
/// dns.google was serving a second Google Trust Services hierarchy from some
/// anycast edges while the pins covered only the first. The daily liveness
/// check (`scripts/check-cert-pins.sh` check 3) can detect that from the edges
/// a runner happens to reach; nothing here prevents it.
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
    /// match a certificate in the PRESENTED chain.
    ///
    /// Counting entries in this slice tells you nothing about safety, and the
    /// doc that used to live here got that wrong: it promised ">= 2 OVERLAPPING
    /// pins — the current intermediate AND its root", which is one lineage and
    /// therefore one failure. What matters is how many INDEPENDENT LINEAGES
    /// the server is actually observed to serve: a certificate the server
    /// never presents can never satisfy a handshake, and an intermediate plus
    /// the root that signed it vanish from the same handshake together.
    /// Measured 2026-09-06 and again 2026-09-08 from two networks (a UK
    /// consumer ISP and the production hub in Hetzner DE):
    ///
    ///   dns.google           2 live lineages — WR2 + GTS Root R1 (RSA edges)
    ///                        and WE2 + GTS Root R4 (ECDSA edges); 4 of 4
    ///                        pins presented
    ///   cloudflare-dns.com   1 live lineage, 1 of 3 pins presented — SINGLE
    ///                        POINT OF FAILURE, waived in the SSOT with a date
    ///   dns.quad9.net        1 live lineage, 1 of 2 pins presented — SINGLE
    ///                        POINT OF FAILURE, waived in the SSOT with a date
    ///
    /// Those counts are enforced by `scripts/check-cert-pins.sh` check 2b
    /// against `third_party/cert-pins.json`, and by
    /// `test_live_lineages_per_provider` below against real measured chains.
    /// Changing a pin set changes one of them.
    ///
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
/// PIN ROTATION PROCEDURE (needed for a CA-chain change, not cert renewal —
/// and a CA-chain change is NOT announced: Google did not announce the second
/// dns.google hierarchy, a scheduled liveness run found it):
/// 1. When a provider is MEASURED serving a new lineage, add its
///    intermediate+root pins alongside the old ones — in birdo-shared first.
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
        // Chain: cloudflare-dns.com → SSL.com SSL Intermediate CA ECC R2 — and
        // nothing else: Cloudflare sends a SHORTENED chain, leaf + intermediate,
        // NO root. The SSOT records it measured 2026-09-06 from a UK consumer
        // ISP, the production hub and a GitHub runner in Azure westus2 under
        // default, RSA-only and ECDSA-only offers (chain_shape.vantages). It
        // was re-measured 2026-09-08 from the UK ISP and the production hub
        // over 1.1.1.1, 1.0.0.1, 104.16.248.249 and 104.16.249.249 (plus
        // 2606:4700:4700::1111 from the hub), under the default offer, an
        // RSA-only signature-algorithm offer and a TLS 1.2-only offer: the
        // same single intermediate every time, and an RSA-cipher-only TLS 1.2
        // offer is refused outright (alert 40) — there is no RSA certificate
        // behind this name. The hostname itself is what a hostile resolver
        // hijacks, hence dialling by address.
        //
        // SINGLE POINT OF FAILURE — ONE of these three pins can ever match. The
        // SSL.com root and the legacy DigiCert anchor are dormant: they protect
        // a future migration, but cannot satisfy today's handshake. An SSL.com
        // re-issue of the intermediate takes this provider dark with no
        // warning: the exact shape that took dns.google dark, and the reason
        // `>= 2 pins` was never the right test. There is NO genuine second
        // matchable certificate to pin today — no sibling SSL.com issuing CA
        // was observed serving this host from either vantage — and a
        // speculative pin is permanent under the SSOT's _rotation_rule. So
        // this is carried as an explicit, dated `_overlap_risk` waiver in
        // birdo-shared, which scripts/check-cert-pins.sh check 2b fails on the
        // day it lapses, is dropped, or stops matching reality.
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
        // two different Google Trust Services lineages at the same time over
        // those same addresses:
        //
        //   RSA   : leaf → WR2 → GTS Root R1   (UK consumer ISP, both
        //                                       addresses; Azure northcentralus,
        //                                       Mobile-Client run 34028683100)
        //   ECDSA : leaf → WE2 → GTS Root R4   (production hub in Hetzner DE,
        //                                       both addresses; Azure
        //                                       centralus, Desktop-Client run
        //                                       34028720220 — the run that
        //                                       failed and exposed this)
        //
        // Until this change only the first was pinned. WE2 and GTS Root R4 are
        // a DIFFERENT lineage, so neither of the two pins was in that chain
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
        // INVARIANT: pin every lineage the provider is MEASURED serving, not
        // the one chain your own vantage point returned. A liveness probe runs
        // from a single vantage point and goes green as soon as ANY one chain
        // matches, so it cannot tell you this list is half-empty. Do NOT drop
        // the WR2/R1 pair because your machine only ever sees WE2/R4 (or the
        // reverse) — that is the edit that caused this outage, and there is
        // no remote kill switch for a bricked pin. Retire a lineage only once
        // it is unmeasurable from several independent networks.
        //
        // EXACTLY THE FOUR MEASURED PINS, BY DECISION. An earlier revision of
        // this change also pinned Google's six other published issuing
        // intermediates (WR1/WR3/WR4, WE1/WE3/WE4) "in case an edge ever sends
        // a shortened chain". They came out: not one of them has been observed
        // in any dns.google chain from any vantage; a pin is effectively
        // PERMANENT under the SSOT's _rotation_rule and must be transcribed
        // identically into every enforcing client under an exact-set-equality
        // gate; and the two ROOT pins already absorb a sibling rotation for as
        // long as Google presents the root — which both measured chains do.
        // The residual risk is real and named: an edge that sends leaf + a
        // sibling intermediate and NO root would match nothing. Check 3 of
        // scripts/check-cert-pins.sh is the detector for that (it fails when a
        // root the SSOT says is presented goes missing); nothing here prevents
        // it.
        //
        // This set is the SSOT's, not a local judgement call: it is
        // third_party/cert-pins.json, which is vendored verbatim from
        // birdo-shared and stamped (scripts/check-cert-pins.sh checks 1, 1b
        // and 2). Do not add, drop or reorder a pin here alone — change
        // birdo-shared/cert-pins.json, re-vendor, re-stamp.
        //
        // All four values verified 2026-09-06 by fetching Google's published
        // CA certificates from https://i.pki.goog/{wr2,r1,we2,r4}.crt and
        // hashing the SPKI locally; subjects confirmed CN=WR2, CN=GTS Root R1,
        // CN=WE2, CN=GTS Root R4. (The published we2.crt is the GlobalSign ECC
        // Root CA - R4 cross-sign of the same key; the WE2 actually served is
        // issued by GTS Root R4. Same SPKI, so one pin covers both.)
        pins: &[
            // --- RSA hierarchy (GTS Root R1) ---
            // WR2 — presented from un-migrated edges (UK ISP; Azure northcentralus)
            "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=",
            // GTS Root R1 — anchor of that hierarchy, presented in that chain
            "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=",
            // --- ECDSA hierarchy (GTS Root R4) ---
            // WE2 — presented from migrated edges (production hub; Azure centralus)
            "vh78KSg1Ry4NaqGDV10w/cTb9VH3BQUZoCWNa93W/EY=",
            // GTS Root R4 — anchor of that hierarchy, presented in that chain;
            // the same anchor api/cert_pin.rs already pins for birdo.app
            "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
        ],
    },
    DoHProvider {
        url: "https://dns.quad9.net/dns-query",
        host: "dns.quad9.net",
        bootstrap: &[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        // Chain: dns.quad9.net → DigiCert Global G3 TLS ECC SHA384 2020 CA1 —
        // and nothing else: Quad9 sends a SHORTENED chain, leaf + intermediate,
        // NO root. Measured 2026-09-06 via 9.9.9.9 from a UK consumer ISP, the
        // production hub and a GitHub runner in Azure westus2 (SSOT
        // chain_shape.vantages), and re-measured 2026-09-08 via 9.9.9.9 and
        // 149.112.112.112 from the UK ISP and the hub: the same single
        // intermediate every time.
        //
        // SINGLE POINT OF FAILURE — ONE of these two pins can ever match: the
        // DigiCert Global Root G3 pin is dormant, and the two pins are one
        // lineage anyway (an intermediate and the root that signed it). No
        // second lineage has been observed serving this host, so nothing is
        // added on a guess; the SSOT carries it as a dated `_overlap_risk`
        // waiver ("quad9-single-lineage") that scripts/check-cert-pins.sh
        // check 2b fails on the day it lapses, is dropped, or stops matching
        // reality.
        pins: &[
            // DigiCert Global G3 TLS ECC SHA384 2020 CA1 (presented intermediate)
            "qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=",
            // DigiCert Global Root G3 (trust anchor)
            "uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=",
        ],
    },
];

/// Substring `api::doh_resolver` matches on to tell "every provider failed
/// PINNING" apart from "the network was unreachable".
///
/// `resolve_via_doh` returns `Result<_, String>`, so the caller has no typed
/// channel; it was matching on a free-text literal, which is a coupling that
/// breaks silently the first time somebody rewords the message. Naming the
/// substring here makes the two ends move together, and the test below pins the
/// message to it.
pub(crate) const ALL_PROVIDERS_PINNING_FAILED: &str =
    "all providers failed certificate verification";

/// Marker embedded in every pin-rejection `TlsError` so `resolve_single_provider`
/// can classify a reqwest connect failure as a PIN failure (vs plain network
/// trouble) by walking the error source chain. rustls carries a custom
/// verifier's rejection only as `Error::General(String)`, so a distinctive
/// substring is the only channel that survives reqwest's error wrapping.
const PIN_MISMATCH_MARKER: &str = "DoH-SPKI-pin-rejected";

/// One bit per `DOH_PROVIDERS` entry: has this provider's pin failure already
/// been reported this process? A pin mismatch repeats on every single
/// resolution — the API resolver alone re-resolves every 5 minutes — so an
/// un-deduplicated report would be a flood, and a flood gets muted, which puts
/// us back where we started. Compile-time guard below keeps this honest if a
/// 33rd provider is ever added.
static PIN_FAILURE_REPORTED: AtomicU32 = AtomicU32::new(0);

/// Reported once per process: every provider failed pinning at the same time.
static ALL_PROVIDERS_PIN_FAILURE_REPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

const _: () = assert!(
    DOH_PROVIDERS.len() <= 32,
    "PIN_FAILURE_REPORTED is a 32-bit mask; widen it before adding a 33rd DoH provider"
);

/// Send a provider's pin failure to Sentry the FIRST time it happens in this
/// process, and never again. Returns without doing anything on repeats.
fn report_pin_failure_once(provider: &DoHProvider) {
    let Some(idx) = DOH_PROVIDERS.iter().position(|p| p.host == provider.host) else {
        return;
    };
    let bit = 1u32 << idx;
    if (PIN_FAILURE_REPORTED.fetch_or(bit, Ordering::Relaxed) & bit) != 0 {
        return;
    }
    // provider.url is a compile-time constant. Nothing about the query goes out.
    crate::utils::crash_report::report_security_event(&format!(
        "DoH certificate pin mismatch for provider {} — this provider is \
         unusable for this client until its pins are updated. Most likely a \
         stale pin set (a CA moved), not an attack.",
        provider.url
    ));
}

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
                // BREAK THE SILENCE. A pin mismatch used to be `tracing::error!`
                // and nothing else, and nothing bridges tracing to Sentry in
                // this app (see utils::crash_report::report_security_event), so
                // a provider going dark in the field was invisible until
                // somebody asked a user for a log file. dns.google was dark on
                // every ECDSA Google edge and the only reason anyone found out
                // was a scheduled CI job.
                //
                // NO PII: the message carries the provider's hardcoded URL and
                // nothing about what was being resolved.
                report_pin_failure_once(provider);
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
        // ...or a stale pin set, which is the far more common cause and the one
        // this file exists to stop being silent about. Either way it is a total
        // loss of encrypted resolution for this client and must leave the
        // device. Reported once per process, no PII.
        if !ALL_PROVIDERS_PIN_FAILURE_REPORTED.swap(true, Ordering::Relaxed) {
            crate::utils::crash_report::report_security_event(
                "DoH: ALL providers failed certificate pinning — either a \
                 network-level attack or (more often) a stale pin set that has \
                 taken every provider dark",
            );
        }
        return Err(format!(
            "DNS resolution blocked: {ALL_PROVIDERS_PINNING_FAILED}. \
             This may indicate a network-level attack."
        ));
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

    /// Chains this repo has ACTUALLY MEASURED, per provider host:
    /// (host, the SSOT lineage slug the chain belongs to, where and when it
    /// was measured, the chain — leaf first, then whatever the server sent
    /// after it). Every entry is a real `openssl s_client -showcerts` run
    /// against the provider's pinned bootstrap address with its own SNI. Where
    /// a chain has only two entries that is not an omission: the server sends
    /// no root.
    ///
    /// A presented chain is ONE lineage by definition, so the number of
    /// distinct lineage slugs a pin set accepts here is the number of
    /// independently-failing paths it actually covers — the count that
    /// `pins.len()` was standing in for when dns.google went dark.
    ///
    /// This table is the input to the tests below, and it is the thing that
    /// makes them mechanical rather than decorative. Adding a chain here means
    /// having measured it.
    const MEASURED_CHAINS: &[(&str, &str, &str, &[&str])] = &[
        (
            "dns.google",
            "gts-r1",
            "2026-09-06 and again 2026-09-08, 8.8.8.8 and 8.8.4.4 from a UK \
             consumer ISP under default, RSA-only and ECDSA-only offers, and from \
             the production hub under an RSA-only offer; also what Azure \
             northcentralus saw in Mobile-Client run 34028683100. The root \
             arrives CROSS-SIGNED (issuer GlobalSign Root CA), same SPKI",
            &[
                "qW3FYuXf0SK210sV5lcUYE1NGTmBA398Ee6LXLqneUY=", // leaf (rotates)
                "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=", // WR2
                "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=", // GTS Root R1
            ],
        ),
        (
            "dns.google",
            "gts-r4",
            "2026-09-06 and again 2026-09-08 (6 of 6 samples), 8.8.8.8 and \
             8.8.4.4 from the production hub (Hetzner, DE) under default and \
             ECDSA-only offers — byte-identical to the chain Azure centralus saw \
             in the Desktop-Client liveness run 34028720220 that failed",
            &[
                "wyib/Zb8QzNvhqZ9QF7LzXCMzYApj7PsLe/ZjlfJzuI=", // leaf (rotates)
                "vh78KSg1Ry4NaqGDV10w/cTb9VH3BQUZoCWNa93W/EY=", // WE2
                "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=", // GTS Root R4
            ],
        ),
        (
            "cloudflare-dns.com",
            "sslcom-ecc",
            "2026-09-06 (SSOT chain_shape.vantages) and again 2026-09-08: \
             1.1.1.1 / 1.0.0.1 / 104.16.248.249 / 104.16.249.249 from a UK \
             consumer ISP and from the production hub (plus 2606:4700:4700::1111 \
             from the hub), default, RSA-only and TLS 1.2-only offers — TWO \
             certificates, NO root, every time",
            &[
                "ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew=", // leaf (rotates)
                "zGgA4OU4DjJdvpRYUqbi5Vh2g9W5Oc/PgKihy9mkLsE=", // SSL.com ECC R2
            ],
        ),
        (
            "dns.quad9.net",
            "digicert-global-g3",
            "2026-09-06 and again 2026-09-08, 9.9.9.9 and 149.112.112.112 from a \
             UK consumer ISP and from the production hub — TWO certificates, NO \
             root",
            &[
                "i2kObfz0qIKCGNWt7MjBUeSrh0Dyjb0/zWINImZES+I=", // leaf (rotates)
                "qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=", // DigiCert G3 ECC
            ],
        ),
    ];

    /// Which distinct lineages, among the chains measured for `host`, does
    /// `pins` accept? Sorted, deduplicated.
    fn accepted_lineages(host: &str, pins: &[&str]) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for (h, lineage, _, chain) in MEASURED_CHAINS {
            if *h != host {
                continue;
            }
            let owned: Vec<String> = chain.iter().map(|c| (*c).to_string()).collect();
            if chain_satisfies_pins(&owned, pins) && !out.contains(lineage) {
                out.push(*lineage);
            }
        }
        out.sort_unstable();
        out
    }

    #[test]
    fn test_doh_provider_pin_format() {
        // Format only. This test used to ALSO assert `pins.len() >= 2` under the
        // heading "every provider MUST carry >= 2 OVERLAPPING pins (intermediate
        // + its root)". It was green throughout the dns.google outage, because
        // counting entries in a slice cannot see that both of them belong to the
        // same CA lineage — or that the server never sends one of them. The
        // question it was pretending to answer is answered for real by
        // `test_live_lineages_per_provider` below.
        for provider in DOH_PROVIDERS {
            assert!(
                !provider.pins.is_empty(),
                "Provider {} has an EMPTY pin set — that is the emergency bypass, \
                 not a configuration",
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
            // No duplicates: a repeated hash pads the list and makes a pin set
            // look wider than it is.
            for (i, pin) in provider.pins.iter().enumerate() {
                assert!(
                    !provider.pins[i + 1..].contains(pin),
                    "Pin {pin} is listed twice for {} — a duplicate inflates the \
                     apparent size of the set without adding any coverage",
                    provider.url
                );
            }
        }
    }

    /// THE TEST THAT WOULD HAVE CAUGHT THE OUTAGE.
    ///
    /// A pin only protects a handshake if the server actually SENDS the
    /// certificate it hashes, and an intermediate plus the root that signed it
    /// are absent from the same handshake together. So the number that matters
    /// per provider is not `pins.len()`, and not even "pins ever seen on the
    /// wire" — it is how many distinct LINEAGES the measured chains belong to
    /// that the pin set accepts.
    ///
    /// Those lineages are asserted EXACTLY, against the measured chains above,
    /// with the known single-lineage providers named rather than waived away.
    /// Any edit to a pin set moves one of these:
    ///   * trimming dns.google back to "the chain I just measured" drops it to
    ///     one lineage and fails here;
    ///   * a second lineage measured for cloudflare-dns.com or dns.quad9.net
    ///     raises theirs to two and fails here too, which is the prompt to add
    ///     the chain to MEASURED_CHAINS, update EXPECTED, and delete the
    ///     `_overlap_risk` waiver in birdo-shared/cert-pins.json.
    ///
    /// The same invariant is enforced offline over the SSOT by check 2b of
    /// scripts/check-cert-pins.sh, from the SSOT's own `lineage` flags; this is
    /// the half that runs in `cargo test` and does not trust those flags.
    #[test]
    fn test_live_lineages_per_provider() {
        // host -> (lineages the pin set must accept, why that is not >= 2;
        // None means it is)
        const EXPECTED: &[(&str, &[&str], Option<&str>)] = &[
            ("dns.google", &["gts-r1", "gts-r4"], None),
            (
                "cloudflare-dns.com",
                &["sslcom-ecc"],
                Some(
                    "Cloudflare sends leaf + SSL.com intermediate and NO root from \
                     every address and vantage measured, so the SSL.com root pin \
                     and the legacy DigiCert anchor are both dormant and there is \
                     no second lineage to pin. One SSL.com re-issue takes this \
                     provider dark. Waived, dated, in birdo-shared/cert-pins.json.",
                ),
            ),
            (
                "dns.quad9.net",
                &["digicert-global-g3"],
                Some(
                    "Quad9 sends leaf + DigiCert G3 ECC intermediate and NO root, \
                     and the two pins are one lineage regardless. Waived, dated, \
                     in birdo-shared/cert-pins.json.",
                ),
            ),
        ];

        for provider in DOH_PROVIDERS {
            let (_, expected_lineages, debt) = EXPECTED
                .iter()
                .find(|(h, _, _)| *h == provider.host)
                .unwrap_or_else(|| {
                    panic!(
                        "provider {} has no entry in EXPECTED — a new DoH provider \
                         must declare which measured lineages its pins cover, or it \
                         ships with the dns.google hole",
                        provider.host
                    )
                });

            let measured: Vec<_> = MEASURED_CHAINS
                .iter()
                .filter(|(h, _, _, _)| *h == provider.host)
                .collect();
            assert!(
                !measured.is_empty(),
                "no measured chain recorded for {} — MEASURED_CHAINS must cover \
                 every provider or this test silently checks nothing",
                provider.host
            );

            let accepted = accepted_lineages(provider.host, provider.pins);
            let mut want: Vec<&str> = expected_lineages.to_vec();
            want.sort_unstable();
            assert_eq!(
                accepted,
                want,
                "{} now accepts lineages {:?} of its measured chains, not {:?}. {} \
                 Update EXPECTED here and MEASURED_CHAINS together with the SSOT — \
                 and if a lineage DISAPPEARED, do not: a chain the provider still \
                 serves has just been un-pinned and there is no remote kill switch \
                 for a bricked pin.",
                provider.host,
                accepted,
                want,
                debt.unwrap_or("")
            );

            // Every measured chain must authenticate — that is the outage itself,
            // restated as an assertion — and its leaf alone must not.
            for (host, lineage, provenance, chain) in &measured {
                let owned: Vec<String> = chain.iter().map(|c| (*c).to_string()).collect();
                assert!(
                    chain_satisfies_pins(&owned, provider.pins),
                    "{host}: the {lineage} chain measured {provenance} matches NO \
                     pin — every user routed to that edge loses this DoH provider \
                     outright, with the log calling a stale pin set a MITM attack"
                );
                assert!(
                    !chain_satisfies_pins(&owned[..1], provider.pins),
                    "{host}: the LEAF certificate satisfies a pin — leaf pinning \
                     self-disables on every renewal"
                );
            }
        }

        // Pin sets are per-host, not a shared pool: no provider's measured chain
        // may authenticate a different provider.
        for provider in DOH_PROVIDERS {
            for (host, _, _, chain) in MEASURED_CHAINS {
                if *host == provider.host {
                    continue;
                }
                let owned: Vec<String> = chain.iter().map(|c| (*c).to_string()).collect();
                assert!(
                    !chain_satisfies_pins(&owned, provider.pins),
                    "{}'s pin set accepts {host}'s chain — pin sets must not pool",
                    provider.host
                );
            }
        }
    }

    /// The three dns.google pin sets this repo has shipped or proposed, and
    /// what counting PINS said about each versus what counting MEASURED
    /// LINEAGES says. This is the evidence behind pinning exactly the four
    /// measured hashes and not Google's six other published intermediates.
    #[test]
    fn test_dns_google_lineage_count_is_what_the_pin_count_hid() {
        const WR2: &str = "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=";
        const R1: &str = "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=";
        const WE2: &str = "vh78KSg1Ry4NaqGDV10w/cTb9VH3BQUZoCWNa93W/EY=";
        const R4: &str = "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=";
        // Google's other published issuing intermediates, SPKI-hashed on
        // 2026-09-06 from https://i.pki.goog/{wr1,wr3,wr4,we1,we3,we4}.crt.
        const SIBLINGS: &[&str] = &[
            "yDu9og255NN5GEf+Bwa9rTrqFQ0EydZ0r1FCh9TdAW4=", // WR1
            "OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE=", // WR3
            "hZe1OerqJ1Pnq6F4N0gVjjpHqm037Ndf4aLLVpZZdAE=", // WR4
            "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=", // WE1
            "daBIAnKdRIX3bqM85I6We7wBUh0DPycNFBMvYkXGX2Q=", // WE3
            "O5TQDB/wa4SkRjBrQL2Aq9CG317H9MDDgpTVcrpJDa4=", // WE4
        ];

        // Shipped until 2026-09-06: two pins, ONE lineage. `pins.len() >= 2`
        // was green; every ECDSA edge was dark.
        let pre_outage = [WR2, R1];
        assert_eq!(accepted_lineages("dns.google", &pre_outage), ["gts-r1"]);

        // Proposed in an earlier revision of this change: ten pins, still TWO
        // lineages. The six siblings appear in no measured chain, so they add
        // nothing this test can see — and under the SSOT's _rotation_rule each
        // would have been permanent in every enforcing client.
        let mut ten: Vec<&str> = vec![WR2, R1, WE2, R4];
        ten.extend_from_slice(SIBLINGS);
        assert_eq!(accepted_lineages("dns.google", &ten), ["gts-r1", "gts-r4"]);
        for (host, _, _, chain) in MEASURED_CHAINS {
            if *host != "dns.google" {
                continue;
            }
            for sibling in SIBLINGS {
                assert!(
                    !chain.contains(sibling),
                    "{sibling} was observed in a measured dns.google chain — then it \
                     is no longer speculative and belongs in the SSOT"
                );
            }
        }

        // Shipped now: the four measured pins, TWO lineages — the same coverage
        // of every measured chain as the ten, with nothing unmeasured in it.
        let shipped = pins_for_host("dns.google").expect("dns.google must be pinned");
        assert_eq!(
            shipped.len(),
            4,
            "dns.google pins exactly the four measured hashes (owner decision, \
             2026-09-06); a different count means the SSOT changed — re-vendor"
        );
        assert_eq!(
            accepted_lineages("dns.google", shipped),
            ["gts-r1", "gts-r4"]
        );
    }

    /// `api::doh_resolver` classifies a DoH failure by looking for
    /// `ALL_PROVIDERS_PINNING_FAILED` in the error string, and logs a different,
    /// louder message when it finds it. That is a string contract across two
    /// modules with no type to hold it, so assert it here: reword the error and
    /// this fails, instead of the classification silently going dead.
    #[test]
    fn test_all_providers_pinning_failed_marker_is_in_the_error() {
        let rendered = format!(
            "DNS resolution blocked: {ALL_PROVIDERS_PINNING_FAILED}. \
             This may indicate a network-level attack."
        );
        assert!(
            rendered.contains(ALL_PROVIDERS_PINNING_FAILED),
            "api::doh_resolver would stop recognising the all-providers-failed-\
             pinning case and log it as an ordinary network failure"
        );
    }

    /// The pin sets compiled into this binary must be exactly the ones the
    /// SSOT declares, host by host. `scripts/check-cert-pins.sh` check 2
    /// already enforces that, but only in the Cert Pins workflow and only when
    /// it runs; this puts the same comparison in front of `cargo test`, so a
    /// hand-edit that trims a lineage back out cannot reach main through a
    /// green test suite alone.
    #[test]
    fn test_doh_pin_sets_match_the_vendored_ssot() {
        let raw = include_str!("../../../third_party/cert-pins.json");
        let ssot: serde_json::Value =
            serde_json::from_str(raw).expect("third_party/cert-pins.json must be valid JSON");
        let hosts = ssot["hosts"]
            .as_object()
            .expect("third_party/cert-pins.json must have a hosts map");
        for provider in DOH_PROVIDERS {
            let entry = hosts
                .get(provider.host)
                .unwrap_or_else(|| panic!("the SSOT does not declare {}", provider.host));
            let mut want: Vec<&str> = entry["pins"]
                .as_array()
                .expect("pins must be an array")
                .iter()
                .map(|p| p["hash"].as_str().expect("every pin has a hash"))
                .collect();
            let mut have: Vec<&str> = provider.pins.to_vec();
            want.sort_unstable();
            have.sort_unstable();
            assert_eq!(
                have, want,
                "{}: doh.rs and third_party/cert-pins.json declare different pin \
                 sets. Change birdo-shared/cert-pins.json, re-vendor, re-stamp, and \
                 then update doh.rs to match — never one side alone.",
                provider.host
            );
        }
    }

    /// The SSOT's own `in_live_chain` and `lineage` labels, held against the
    /// chains this repo has measured. Check 2b of scripts/check-cert-pins.sh
    /// counts live LINEAGES from those labels, so a pin mislabelled upstream
    /// would hand it a false green with nothing downstream to notice. This is
    /// the downstream notice, for every chain in `MEASURED_CHAINS`:
    ///   * a pin presented in a measured chain must be marked
    ///     `in_live_chain: true` and must carry that chain's lineage;
    ///   * a pin marked `in_live_chain: true` must appear in at least one
    ///     measured chain for its host — a flag this repo has never seen on the
    ///     wire is a claim, not a measurement;
    ///   * a pin marked dormant must appear in NO measured chain.
    ///
    /// It cannot see a mislabelled pin for a lineage nobody has measured; that
    /// limit is stated in cert-pins.yml rather than papered over.
    #[test]
    fn test_ssot_live_lineage_flags_match_measured_chains() {
        let raw = include_str!("../../../third_party/cert-pins.json");
        let ssot: serde_json::Value =
            serde_json::from_str(raw).expect("third_party/cert-pins.json must be valid JSON");
        let hosts = ssot["hosts"]
            .as_object()
            .expect("third_party/cert-pins.json must have a hosts map");
        for provider in DOH_PROVIDERS {
            let entry = hosts
                .get(provider.host)
                .unwrap_or_else(|| panic!("the SSOT does not declare {}", provider.host));
            let measured: Vec<_> = MEASURED_CHAINS
                .iter()
                .filter(|(h, _, _, _)| *h == provider.host)
                .collect();
            for pin in entry["pins"].as_array().expect("pins must be an array") {
                let hash = pin["hash"].as_str().expect("every pin has a hash");
                let live = pin["in_live_chain"]
                    .as_bool()
                    .expect("every pin has a boolean in_live_chain");
                let lineage = pin["lineage"].as_str().expect("every pin has a lineage");
                let seen_in: Vec<&str> = measured
                    .iter()
                    .filter(|(_, _, _, chain)| chain.contains(&hash))
                    .map(|(_, l, _, _)| *l)
                    .collect();
                if live {
                    assert!(
                        !seen_in.is_empty(),
                        "{}: the SSOT marks pin {hash} in_live_chain: true, but it appears \
                         in no chain this repo has measured (MEASURED_CHAINS). Either \
                         measure it and record the chain, or the flag is a claim — and \
                         check 2b counts lineages from that flag.",
                        provider.host
                    );
                    for seen in &seen_in {
                        assert_eq!(
                            *seen, lineage,
                            "{}: pin {hash} is filed under lineage {lineage} in the SSOT \
                             but was presented in a measured {seen} chain. A chain is one \
                             lineage; the label is wrong and check 2b over-counts.",
                            provider.host
                        );
                    }
                } else {
                    assert!(
                        seen_in.is_empty(),
                        "{}: the SSOT marks pin {hash} in_live_chain: false, but it was \
                         presented in the measured {} chain. The flag is wrong.",
                        provider.host,
                        seen_in[0]
                    );
                }
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
