//! DNS-over-HTTPS resolver adapter for the control-plane API client.
//!
//! F5 HARDENING: Previously the `BirdoApi` reqwest client delegated DNS to the
//! operating-system resolver. On a censoring ISP or captive portal that hijacks
//! or blocks DNS for `api.birdo.app`, desktop login/connect would fail — while
//! the Android client survived because it already resolves the control plane via
//! DoH. This adapter closes that gap by routing the desktop control-plane client
//! through the SAME cert-pinned DoH resolver the VPN layer uses
//! (`crate::vpn::doh`), matching the Android client's behaviour: Cloudflare
//! only (owner decision D5, 2026-10-01).
//!
//! SECURITY MODEL (defense-in-depth):
//!   1. DoH (Cloudflare) is tried first, pinned by CA-CHAIN SPKI inside the
//!      TLS handshake — NOT leaf-pinned, which this
//!      comment claimed long after `vpn::doh` moved off leaf-DER hashing
//!      precisely because leaf pins self-disable on every ~90-day renewal. This
//!      defeats plain DNS blocking/poisoning because the providers are reached
//!      over HTTPS via its own pinned certificates.
//!   2. If DoH fails, we fall back to the system resolver rather
//!      than failing closed — so we never REGRESS a network that works today.
//!      NOT while a Windows kill-switch block is up (a reconnect gap, a held
//!      lockdown block): it lets out only this executable's HTTPS, and port-53
//!      DNS is blocked off the tunnel (REVIEW-WIN2-031). There Cloudflare DoH
//!      is the ONLY way to find the API once the cache below expires — with a
//!      single provider (owner decision D5), a network that blocks Cloudflare
//!      keeps a lockdown reconnect from resolving the API at all.
//!      READ THIS BEFORE RELYING ON `vpn::doh`'s FAIL-CLOSED GUARANTEE: that
//!      guarantee is `vpn::doh`'s, and it ends here. Step 3 explains why that is
//!      an accepted trade rather than an oversight, but it IS a trade — the
//!      fallback fires even when the provider failed *pinning* specifically
//!      (`resolve_via_doh`'s "all providers failed certificate verification"),
//!      which is the case that looks most like an attack. It is also, far more
//!      often, a stale pin set (what happened to dns.google, a former provider),
//!      and with a single provider failing closed would brick the control plane
//!      every time Cloudflare's chain moves. That case is reported to Sentry
//!      from `vpn::doh` so it cannot be silent.
//!   3. A poisoned IP obtained through the fallback cannot mount a MITM: the
//!      `BirdoApi` client still enforces CA-chain SPKI certificate pinning
//!      (see `super::cert_pin`) during the TLS handshake, so a forged
//!      `api.birdo.app` certificate is rejected regardless of which resolver
//!      produced the address.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// HTTPS port — the control plane is HTTPS-only (`https_only(true)`).
const HTTPS_PORT: u16 = 443;

/// How long a successful resolution is reused before we re-resolve. Short enough
/// to follow backend IP changes (Cloudflare anycast / failover) quickly, long
/// enough that we are not issuing a DoH query on every new pooled connection.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Fallback (system-resolver) answers are cached only briefly: they may come
/// from a hostile/captive-portal resolver, so we re-attempt DoH soon (cert
/// pinning still prevents any MITM in the meantime). DoH-success answers use the
/// full CACHE_TTL.
const FALLBACK_TTL: Duration = Duration::from_secs(30);

type CacheMap = HashMap<String, (Instant, Vec<SocketAddr>, Duration)>;

/// A `reqwest` DNS resolver that resolves via DoH first and the system resolver
/// second. Cheap to clone; the cache is shared.
#[derive(Clone)]
pub struct DohApiResolver {
    cache: Arc<Mutex<CacheMap>>,
}

impl DohApiResolver {
    /// Every resolver shares ONE cache, process-wide. A one-off client (the
    /// deletion around the tunnel, the old-key probe's fresh connections)
    /// then finds the address the main client already resolved, instead of
    /// needing DoH at the worst moment: behind a block, just after a
    /// teardown, where a failed DoH lookup has no fallback that works
    /// (WIN3-001).
    pub fn new() -> Self {
        Self {
            cache: Arc::clone(shared_cache()),
        }
    }
}

/// The one process-wide cache every [`DohApiResolver`] shares.
fn shared_cache() -> &'static Arc<Mutex<CacheMap>> {
    static SHARED: std::sync::OnceLock<Arc<Mutex<CacheMap>>> = std::sync::OnceLock::new();
    SHARED.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Where an answer came from. Only DoH answers may enter the macOS kill
/// switch's control-plane table (P3-1): the system resolver's are unfiltered
/// (no anti-rebinding check) and come from whatever network the user is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Doh,
    System,
}

/// How long a DoH answer for one of our hosts is still permitted after it
/// was last seen. Every API call through an expired cache entry refreshes
/// it, so this only bounds how long a retired address stays permitted.
const CONTROL_PLANE_MEMORY: Duration = Duration::from_secs(24 * 3600);

/// At most this many addresses per host are remembered (the newest).
const CONTROL_PLANE_PER_HOST: usize = 8;

/// Every IPv4 address a DoH answer gave one of our own hosts, with when it
/// was last seen (P2-4, P3-1). The kill switch's table is their union, not
/// the cache's current entry: api.birdo.app publishes two A records, and a
/// pooled connection may still be on an address a newer answer dropped.
type ControlPlaneMemory = HashMap<String, Vec<(std::net::Ipv4Addr, Instant)>>;

fn control_plane_memory() -> &'static Mutex<ControlPlaneMemory> {
    static MEMORY: std::sync::OnceLock<Mutex<ControlPlaneMemory>> = std::sync::OnceLock::new();
    MEMORY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `birdo.app` or one of its subdomains: the only hosts whose addresses the
/// kill switch may let root reach.
fn is_control_plane_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "birdo.app" || host.ends_with(".birdo.app")
}

/// Remember an answer for `host`. True when it brought an address not
/// remembered before — a held macOS block must then be re-loaded BEFORE the
/// connection that needs it is dialled. A system-resolver answer, or one for
/// a host that is not ours, is never admitted.
fn remember_in(
    memory: &mut ControlPlaneMemory,
    host: &str,
    addrs: &[SocketAddr],
    source: Source,
    now: Instant,
) -> bool {
    if source != Source::Doh || !is_control_plane_host(host) {
        return false;
    }
    let seen = memory.entry(host.to_ascii_lowercase()).or_default();
    seen.retain(|(_, at)| now.saturating_duration_since(*at) < CONTROL_PLANE_MEMORY);
    let mut new_address = false;
    for ip in addrs.iter().filter_map(|a| match a.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }) {
        match seen.iter_mut().find(|(known, _)| *known == ip) {
            Some(entry) => entry.1 = now,
            None => {
                seen.push((ip, now));
                new_address = true;
            }
        }
    }
    seen.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
    seen.truncate(CONTROL_PLANE_PER_HOST);
    new_address
}

fn remember(host: &str, addrs: &[SocketAddr], source: Source) -> bool {
    match control_plane_memory().lock() {
        Ok(mut memory) => remember_in(&mut memory, host, addrs, source, Instant::now()),
        Err(_) => false,
    }
}

/// Every IPv4 address a DoH answer gave our own hosts within the memory
/// window: what the macOS kill switch's control-plane table holds besides
/// the DoH provider itself (`vpn::pf_policy::control_plane_addresses`).
/// IPv4 only: the macOS block admits no IPv6 at all.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn control_plane_v4() -> Vec<std::net::Ipv4Addr> {
    match control_plane_memory().lock() {
        Ok(memory) => remembered(&memory, Instant::now()),
        Err(_) => Vec::new(),
    }
}

#[cfg(any(target_os = "macos", test))]
fn remembered(memory: &ControlPlaneMemory, now: Instant) -> Vec<std::net::Ipv4Addr> {
    memory
        .values()
        .flatten()
        .filter(|(_, at)| now.saturating_duration_since(*at) < CONTROL_PLANE_MEMORY)
        .map(|(ip, _)| *ip)
        .collect()
}

impl Default for DohApiResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolve for DohApiResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let cache = Arc::clone(&self.cache);

        Box::pin(async move {
            // 1) Fresh cache entry?
            if let Some(addrs) = cache_get(&cache, &host) {
                return Ok(boxed(addrs));
            }

            // 2) DNS-over-HTTPS (cert-pinned, anti-rebinding). This is the path
            //    that survives ISP/captive-portal DNS interference.
            match crate::vpn::doh::resolve_all_via_doh(&host).await {
                Ok(ips) => {
                    let addrs: Vec<SocketAddr> = ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(IpAddr::V4(ip), HTTPS_PORT))
                        .collect();
                    cache_put(&cache, &host, addrs.clone(), CACHE_TTL);
                    // P2-4: an address the macOS block does not permit yet is
                    // let through BEFORE this connection is dialled. The user's
                    // Connect under a held block used to meet `block drop all`
                    // until the next re-dial happened to re-load it.
                    let new_address = remember(&host, &addrs, Source::Doh);
                    #[cfg(target_os = "macos")]
                    if new_address {
                        crate::commands::killswitch::control_plane_learned().await;
                    }
                    #[cfg(not(target_os = "macos"))]
                    let _ = new_address;
                    Ok(boxed(addrs))
                }
                Err(e) => {
                    // 3) DoH unreachable — fall back to the system resolver so we
                    //    never regress a working-but-restrictive network. A
                    //    poisoned answer here is still defeated by TLS cert
                    //    pinning on the API client (see module docs).
                    //
                    //    Say which of the two it was. "DoH failed" reads as a
                    //    network problem; a pin failure is a different incident
                    //    with a different fix (re-vendor the pin set), and it
                    //    was previously indistinguishable in the log.
                    if e.contains(crate::vpn::doh::ALL_PROVIDERS_PINNING_FAILED) {
                        tracing::error!(
                            "DoH resolution for {host} failed CERTIFICATE PINNING, \
                             not because the network was unreachable. Falling back to the system resolver anyway: \
                             api.birdo.app is itself CA-chain SPKI pinned \
                             (api::cert_pin), so a poisoned address cannot mount a \
                             MITM — but encrypted resolution is GONE for this client \
                             and the pin sets need checking \
                             (scripts/check-cert-pins.sh)."
                        );
                    } else {
                        tracing::warn!(
                            "DoH resolution for {host} failed ({e}); \
                             falling back to system resolver (TLS pinning still enforced)"
                        );
                    }
                    let addrs = system_resolve(&host).await?;
                    // Cache the fallback result too, but only briefly (FALLBACK_TTL).
                    // On the network this branch exists for (DoH endpoints blocked,
                    // local resolver working) the DoH attempt costs ~15s; without
                    // caching, EVERY new connection re-paid it. The short TTL means a
                    // possibly-hostile system answer is re-checked against DoH soon
                    // (cert pinning prevents any MITM in the meantime).
                    cache_put(&cache, &host, addrs.clone(), FALLBACK_TTL);
                    // P3-1: never admitted to the kill switch's table — this
                    // answer had no anti-rebinding check and came from the
                    // network the user is on. Stated, so it stays that way.
                    remember(&host, &addrs, Source::System);
                    Ok(boxed(addrs))
                }
            }
        })
    }
}

/// Box a resolved address list into the iterator `reqwest` expects.
fn boxed(addrs: Vec<SocketAddr>) -> Addrs {
    Box::new(addrs.into_iter())
}

/// Return cached addresses for `host` if the entry is still within its TTL.
/// The lock is never held across an `.await`.
fn cache_get(cache: &Mutex<CacheMap>, host: &str) -> Option<Vec<SocketAddr>> {
    let map = cache.lock().ok()?;
    let (stamped_at, addrs, ttl) = map.get(host)?;
    if stamped_at.elapsed() < *ttl {
        Some(addrs.clone())
    } else {
        None
    }
}

/// Insert/refresh the cache entry for `host` with a per-entry TTL.
fn cache_put(cache: &Mutex<CacheMap>, host: &str, addrs: Vec<SocketAddr>, ttl: Duration) {
    if let Ok(mut map) = cache.lock() {
        map.insert(host.to_owned(), (Instant::now(), addrs, ttl));
    }
}

/// System-resolver fallback. Uses the async resolver Tokio provides.
async fn system_resolve(
    host: &str,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, HTTPS_PORT)).await?.collect();
    if addrs.is_empty() {
        return Err(format!("system resolver returned no addresses for {host}").into());
    }
    // PREFER IPv4 — this is a self-inflicted-stall fix, not a policy choice.
    //
    // Our own F-001 IPv6 leak block (pf on macOS, ip6tables on Linux) blackholes
    // routable IPv6 for the whole tunnel session and across a server switch. The
    // control plane is dual-stack (api.birdo.app publishes an AAAA), and the
    // system resolver returns IPv6 FIRST under RFC 6724. reqwest tries addresses
    // in order with no Happy-Eyeballs race, so it would open the AAAA first and
    // sit on a silently-dropped connection until the request timeout — a server
    // switch then never fetches its new config and the UI appears frozen.
    //
    // The control plane is always IPv4-reachable, so drop IPv6 when we have any
    // IPv4. IPv6 is kept as the tail fallback so an IPv6-only network still
    // resolves (there the block is not what stands in the way).
    let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs.into_iter().partition(|a| a.is_ipv4());
    Ok(if v4.is_empty() { v6 } else { v4 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)), HTTPS_PORT)
    }

    #[test]
    fn cache_roundtrip_returns_fresh_entry() {
        let cache = Mutex::new(CacheMap::new());
        assert!(cache_get(&cache, "api.birdo.app").is_none());
        cache_put(&cache, "api.birdo.app", vec![sample_addr()], CACHE_TTL);
        let got = cache_get(&cache, "api.birdo.app").expect("entry should be cached");
        assert_eq!(got, vec![sample_addr()]);
    }

    /// WIN3-001: what one client resolved, every other client finds.
    #[test]
    fn every_resolver_shares_one_cache() {
        let main = DohApiResolver::new();
        let one_off = DohApiResolver::new();
        let host = "shared-cache.test.invalid";
        cache_put(&main.cache, host, vec![sample_addr()], CACHE_TTL);
        assert_eq!(cache_get(&one_off.cache, host), Some(vec![sample_addr()]));
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), HTTPS_PORT)
    }

    /// P3-1: a system-resolver answer never enters the kill switch's table,
    /// nor does any host that is not ours.
    #[test]
    fn only_doh_answers_for_our_hosts_are_remembered() {
        let mut memory = ControlPlaneMemory::new();
        let now = Instant::now();
        assert!(!remember_in(
            &mut memory,
            "api.birdo.app",
            &[v4(203, 0, 113, 66)],
            Source::System,
            now
        ));
        assert!(!remember_in(
            &mut memory,
            "example.com",
            &[v4(93, 184, 215, 14)],
            Source::Doh,
            now
        ));
        assert!(!remember_in(
            &mut memory,
            "evilbirdo.app",
            &[v4(198, 51, 100, 9)],
            Source::Doh,
            now
        ));
        assert!(remembered(&memory, now).is_empty());

        let v6 = SocketAddr::new("2606:4700::1".parse().unwrap(), HTTPS_PORT);
        assert!(remember_in(
            &mut memory,
            "API.birdo.app",
            &[v4(104, 21, 32, 1), v6],
            Source::Doh,
            now
        ));
        assert_eq!(
            remembered(&memory, now),
            vec![Ipv4Addr::new(104, 21, 32, 1)]
        );
    }

    /// P2-4: the table is the UNION of recent DoH answers per host — both A
    /// records, and an address a newer answer dropped — until it ages out.
    #[test]
    fn the_control_plane_is_the_union_of_recent_doh_answers() {
        let mut memory = ControlPlaneMemory::new();
        let t0 = Instant::now();
        assert!(remember_in(
            &mut memory,
            "api.birdo.app",
            &[v4(104, 21, 32, 1), v4(172, 67, 150, 2)],
            Source::Doh,
            t0
        ));
        let hour = Duration::from_secs(3600);
        assert!(remember_in(
            &mut memory,
            "api.birdo.app",
            &[v4(104, 21, 40, 3)],
            Source::Doh,
            t0 + hour
        ));
        assert!(remember_in(
            &mut memory,
            "birdo.app",
            &[v4(104, 21, 50, 4)],
            Source::Doh,
            t0 + hour
        ));

        let mut all = remembered(&memory, t0 + hour);
        all.sort_unstable();
        assert_eq!(
            all,
            vec![
                Ipv4Addr::new(104, 21, 32, 1),
                Ipv4Addr::new(104, 21, 40, 3),
                Ipv4Addr::new(104, 21, 50, 4),
                Ipv4Addr::new(172, 67, 150, 2),
            ]
        );
        // The first answer ages out a day after it was last seen.
        let mut later = remembered(&memory, t0 + 24 * hour + hour / 2);
        later.sort_unstable();
        assert_eq!(
            later,
            vec![Ipv4Addr::new(104, 21, 40, 3), Ipv4Addr::new(104, 21, 50, 4)]
        );
    }

    /// Only a NEW address asks for a re-load; a repeat answer refreshes it.
    #[test]
    fn a_repeat_answer_is_not_a_new_address() {
        let mut memory = ControlPlaneMemory::new();
        let t0 = Instant::now();
        let answer = [v4(104, 21, 32, 1), v4(172, 67, 150, 2)];
        assert!(remember_in(
            &mut memory,
            "api.birdo.app",
            &answer,
            Source::Doh,
            t0
        ));
        assert!(!remember_in(
            &mut memory,
            "api.birdo.app",
            &answer,
            Source::Doh,
            t0
        ));
        let refreshed = t0 + CONTROL_PLANE_MEMORY - Duration::from_secs(1);
        assert!(!remember_in(
            &mut memory,
            "api.birdo.app",
            &answer,
            Source::Doh,
            refreshed
        ));
        assert_eq!(
            remembered(&memory, t0 + CONTROL_PLANE_MEMORY).len(),
            2,
            "refreshed, not aged out"
        );
    }

    #[test]
    fn the_memory_per_host_is_bounded() {
        let mut memory = ControlPlaneMemory::new();
        let t0 = Instant::now();
        for i in 0..20u8 {
            remember_in(
                &mut memory,
                "api.birdo.app",
                &[v4(104, 21, 0, i)],
                Source::Doh,
                t0 + Duration::from_secs(u64::from(i)),
            );
        }
        let kept = remembered(&memory, t0 + Duration::from_secs(20));
        assert_eq!(kept.len(), CONTROL_PLANE_PER_HOST);
        assert!(
            kept.contains(&Ipv4Addr::new(104, 21, 0, 19)),
            "the newest are kept"
        );
    }

    #[test]
    fn cache_miss_for_unknown_host() {
        let cache = Mutex::new(CacheMap::new());
        cache_put(&cache, "api.birdo.app", vec![sample_addr()], CACHE_TTL);
        assert!(cache_get(&cache, "other.example").is_none());
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let cache = Mutex::new(CacheMap::new());
        // A zero-TTL entry is expired the instant it is stored: cache_get keeps
        // an entry only while `stamped_at.elapsed() < ttl`, and elapsed() is
        // always >= 0, so ttl == 0 is never fresh. This is deterministic and,
        // unlike Instant::now().checked_sub(CACHE_TTL) — which returns None and
        // panics on a freshly-booted machine whose uptime < CACHE_TTL (the CI
        // flake this replaces) — it never underflows the monotonic clock.
        cache.lock().unwrap().insert(
            "api.birdo.app".to_owned(),
            (Instant::now(), vec![sample_addr()], Duration::ZERO),
        );
        assert!(cache_get(&cache, "api.birdo.app").is_none());
    }

    #[test]
    fn boxed_preserves_addresses_and_https_port() {
        let addrs = vec![sample_addr()];
        let collected: Vec<SocketAddr> = boxed(addrs.clone()).collect();
        assert_eq!(collected, addrs);
        assert_eq!(collected[0].port(), HTTPS_PORT);
    }
}
