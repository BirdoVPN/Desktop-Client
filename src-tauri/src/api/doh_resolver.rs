//! DNS-over-HTTPS resolver adapter for the control-plane API client.
//!
//! F5 HARDENING: Previously the `BirdoApi` reqwest client delegated DNS to the
//! operating-system resolver. On a censoring ISP or captive portal that hijacks
//! or blocks DNS for `api.birdo.app`, desktop login/connect would fail — while
//! the Android client survived because it already resolves the control plane via
//! DoH. This adapter closes that gap by routing the desktop control-plane client
//! through the SAME cert-pinned, multi-provider DoH resolver the VPN layer uses
//! (`crate::vpn::doh`), matching the Android client's behaviour.
//!
//! SECURITY MODEL (defense-in-depth):
//!   1. DoH (Cloudflare → Google → Quad9, each leaf-cert-pinned, anti-rebinding)
//!      is tried first. This defeats plain DNS blocking/poisoning because the
//!      providers are reached over HTTPS via their own pinned certificates.
//!   2. If EVERY DoH provider is unreachable (e.g. a network that blocks
//!      1.1.1.1/8.8.8.8/9.9.9.9:443 outright but has a working local resolver),
//!      we fall back to the system resolver rather than failing closed — so we
//!      never REGRESS a network that works today.
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
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
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
            match crate::vpn::doh::resolve_via_doh(&host).await {
                Ok(ip) => {
                    let addrs = vec![SocketAddr::new(IpAddr::V4(ip), HTTPS_PORT)];
                    cache_put(&cache, &host, addrs.clone(), CACHE_TTL);
                    Ok(boxed(addrs))
                }
                Err(e) => {
                    // 3) DoH unreachable — fall back to the system resolver so we
                    //    never regress a working-but-restrictive network. A
                    //    poisoned answer here is still defeated by TLS cert
                    //    pinning on the API client (see module docs).
                    tracing::warn!(
                        "DoH resolution for {host} failed ({e}); \
                         falling back to system resolver (TLS pinning still enforced)"
                    );
                    let addrs = system_resolve(&host).await?;
                    // Cache the fallback result too, but only briefly (FALLBACK_TTL).
                    // On the network this branch exists for (DoH endpoints blocked,
                    // local resolver working) the DoH attempt costs ~15s; without
                    // caching, EVERY new connection re-paid it. The short TTL means a
                    // possibly-hostile system answer is re-checked against DoH soon
                    // (cert pinning prevents any MITM in the meantime).
                    cache_put(&cache, &host, addrs.clone(), FALLBACK_TTL);
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
    Ok(addrs)
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

    #[test]
    fn cache_miss_for_unknown_host() {
        let cache = Mutex::new(CacheMap::new());
        cache_put(&cache, "api.birdo.app", vec![sample_addr()], CACHE_TTL);
        assert!(cache_get(&cache, "other.example").is_none());
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let cache = Mutex::new(CacheMap::new());
        // Stamp an entry in the past, beyond the TTL, by inserting directly.
        let past = Instant::now()
            .checked_sub(CACHE_TTL + Duration::from_secs(1))
            .expect("clock far enough from boot for the test");
        cache
            .lock()
            .unwrap()
            .insert("api.birdo.app".to_owned(), (past, vec![sample_addr()], CACHE_TTL));
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
