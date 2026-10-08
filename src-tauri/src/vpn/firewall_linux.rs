//! Linux firewall (iptables) kill switch implementation
//!
//! Blocks all non-VPN traffic using iptables when the VPN disconnects unexpectedly.
//! Uses dedicated chains to avoid conflicting with user rules.
//!
//! Equivalent to WFP on Windows and pf on macOS.
//!
//! Two design rules this module now follows, both learned from audit findings:
//!
//! 1. **Never flush a chain that is still hooked.** Re-arming used to `-F` the
//!    live chain while its OUTPUT/INPUT jumps were in place, so every reconnect
//!    tick opened a full allow-all window for as long as it took to re-append
//!    ~20 rules (one process spawn each). Activation now builds a *second*
//!    generation of chains off to the side and swaps the jumps onto it, then
//!    tears the old generation down — the equivalent of the WFP transaction on
//!    Windows.
//!
//! 2. **Separate OUT and IN chains.** One chain hooked into OUTPUT, INPUT and
//!    FORWARD forced every rule to be written for all three directions at once.
//!    That produced a blanket `ESTABLISHED,RELATED` accept (which let
//!    pre-existing plaintext flows keep running straight through the block) and
//!    an `-m owner` rule in a chain hooked into INPUT/FORWARD, where xt_owner is
//!    not valid at all.
//!
//! WHAT the chains permit is decided in `vpn::iptables_policy`, as plain data
//! unit-tested on every OS; this module only loads it. In particular root's
//! tcp/443 self-permit goes to the control-plane addresses alone (the DoH
//! provider and every address a DoH answer gave our own hosts — macOS's
//! `<birdo_control>` table), and a held block is re-armed the moment a DoH
//! answer brings an address it does not cover yet, before that address is
//! cached or dialled ([`refresh_control_plane`]).

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicI8, AtomicU64, Ordering};

use crate::vpn::iptables_policy;

/// Tracks whether iptables blocking rules are active
pub(crate) static IPTABLES_BLOCKING: AtomicBool = AtomicBool::new(false);

/// Which generation of chains is currently hooked into the built-in chains:
/// `-1` = none, `0`/`1` = the live generation. Activation always builds the
/// OTHER generation and swaps the jumps onto it.
static LIVE_GEN: AtomicI8 = AtomicI8::new(-1);

/// The control-plane generation the live chains' self-permits cover
/// (`doh_resolver`'s generation, N5 on macOS): `u64::MAX` while no chain of
/// ours is live, so every address gets through as far as we are concerned.
static PERMITTED_GEN: AtomicU64 = AtomicU64::new(u64::MAX);

/// The live chains are missing a control-plane self-permit that would not
/// load (no `-m owner` on this host, say). See
/// `killswitch::learn_control_plane`.
static SELF_PERMITS_MISSING: AtomicBool = AtomicBool::new(false);

/// Serialises every change to our chains: an activation, a lift, and the
/// re-arm a newly learned control-plane address asks for (which comes from
/// the API resolver, concurrently with the reconnect loop's own re-arms). Two
/// activations at once would both build — and flush — the same staging
/// generation. Never held across anything but our own iptables runs; the
/// panic path ([`emergency_cleanup`]) does not take it.
static CHAINS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Chain carrying the OUTPUT policy for generation `gen`.
fn chain_out(gen: i8) -> String {
    format!("BIRDO_KS_OUT{gen}")
}

/// Chain carrying the INPUT/FORWARD policy for generation `gen`.
fn chain_in(gen: i8) -> String {
    format!("BIRDO_KS_IN{gen}")
}

/// Every chain name we may ever have installed, including the single-chain name
/// used before the OUT/IN split — an upgrade over a build that crashed while
/// blocking must still be able to clean up.
fn all_chain_names() -> Vec<String> {
    vec![
        chain_out(0),
        chain_in(0),
        chain_out(1),
        chain_in(1),
        "BIRDO_KILLSWITCH".to_string(),
    ]
}

/// Built-in chains we hook into.
const HOOKS: [&str; 3] = ["OUTPUT", "INPUT", "FORWARD"];

/// Run an iptables command, returning Ok on success.
///
/// `-w` waits for the xtables lock instead of failing instantly when another
/// process (firewalld, docker, ...) holds it — a transient insert failure
/// mid-swap is exactly what used to poison LIVE_GEN.
fn iptables(args: &[&str]) -> Result<(), String> {
    let output = crate::utils::hidden_cmd("iptables")
        .arg("-w")
        .args(args)
        .output()
        .map_err(|e| format!("iptables command failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // P6-CLI-D-03: the argument list carries the relay address (`-d <ip>` in
        // build_chains, `-s <ip>` in the return path), and five release-level
        // sinks print this Err verbatim. Redact HERE — the sinks cannot know the
        // string came from a command line.
        return Err(format!(
            "iptables {} failed: {}",
            crate::utils::redact::sanitize_error(&args.join(" ")),
            crate::utils::redact::sanitize_error(&stderr)
        ));
    }
    Ok(())
}

/// AUDIT-N5: Run an ip6tables command. We tolerate ip6tables being absent on
/// IPv4-only hosts (older systems / containers without IPv6 support) by
/// returning Ok on `command not found`; presence of ip6tables but failure on
/// a specific rule is still surfaced as an error.
fn ip6tables(args: &[&str]) -> Result<(), String> {
    let output = match crate::utils::hidden_cmd("ip6tables")
        .arg("-w")
        .args(args)
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("ip6tables not present — skipping IPv6 rule (host is IPv4-only)");
            return Ok(());
        }
        Err(e) => return Err(format!("ip6tables command failed: {}", e)),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // P6-CLI-D-03: same as the IPv4 twin above.
        return Err(format!(
            "ip6tables {} failed: {}",
            crate::utils::redact::sanitize_error(&args.join(" ")),
            crate::utils::redact::sanitize_error(&stderr)
        ));
    }
    Ok(())
}

/// Check if one of our chains exists in the IPv4 table.
fn chain_exists(name: &str) -> bool {
    crate::utils::hidden_cmd("iptables")
        .args(["-w", "-L", name, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// AUDIT-N5: Check if one of our chains exists in the IPv6 table.
fn chain_exists_v6(name: &str) -> bool {
    crate::utils::hidden_cmd("ip6tables")
        .args(["-w", "-L", name, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether a jump from `hook` to `name` is currently installed (IPv4).
fn jump_present(hook: &str, name: &str) -> bool {
    crate::utils::hidden_cmd("iptables")
        .args(["-w", "-C", hook, "-j", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Create (or empty) a chain that is NOT currently hooked. Safe to flush
/// precisely because nothing jumps to it yet.
fn reset_chain(name: &str) -> Result<(), String> {
    if !chain_exists(name) {
        iptables(&["-N", name])?;
    } else {
        iptables(&["-F", name])?;
    }
    Ok(())
}

/// IPv6 twin of [`reset_chain`].
fn reset_chain_v6(name: &str) -> Result<(), String> {
    if !chain_exists_v6(name) {
        ip6tables(&["-N", name])?;
    } else {
        ip6tables(&["-F", name])?;
    }
    Ok(())
}

/// Load `rules` into `chain` (IPv4 or IPv6, by `run`), in order.
///
/// A self-permit that will not load is logged and skipped: the block still
/// goes up, only narrower (no control plane). Any other rule failing abandons
/// the generation. Returns whether every self-permit loaded.
fn load_chain(
    run: fn(&[&str]) -> Result<(), String>,
    chain: &str,
    rules: &[iptables_policy::Rule],
) -> Result<bool, String> {
    let mut self_permits_loaded = true;
    for rule in rules {
        let mut args = vec!["-A", chain];
        args.extend(rule.iter().map(String::as_str));
        match run(&args) {
            Ok(()) => {}
            Err(e) if iptables_policy::is_self_permit(rule) => {
                // Loudly, like Windows does — a kill switch the client cannot
                // escape is a support incident, not a silent degradation.
                tracing::error!(
                    "Kill switch: could NOT install a control-plane self-permit ({}). \
                     Auto-reconnect may not be able to reach the control plane while \
                     the block is armed.",
                    e
                );
                self_permits_loaded = false;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(self_permits_loaded)
}

/// Build the fully-populated rule set for `gen` in both address families, as
/// `iptables_policy::block_all` decides it. `Ok`: whether every control-plane
/// self-permit loaded.
///
/// Nothing here is reachable from a built-in chain yet, so a failure part-way
/// through cannot leave a half-armed policy in the packet path: the caller
/// deletes the staging chains and the previous generation (if any) is untouched.
fn build_chains(gen: i8, inputs: &iptables_policy::BlockAll<'_>) -> Result<bool, String> {
    let out = chain_out(gen);
    let inn = chain_in(gen);
    let chains = iptables_policy::block_all(inputs);

    reset_chain(&out)?;
    let self_permits_loaded = load_chain(iptables, &out, &chains.out_v4)?;
    reset_chain(&inn)?;
    load_chain(iptables, &inn, &chains.in_v4)?;

    // AUDIT-N5: IPv6 parity — dual-stack hosts must not leak IPv6 around the
    // IPv4-only tunnel (Windows closes the same gap with block_all_v6).
    reset_chain_v6(&out)?;
    load_chain(ip6tables, &out, &chains.out_v6)?;
    reset_chain_v6(&inn)?;
    load_chain(ip6tables, &inn, &chains.in_v6)?;

    if inputs.lan_sharing {
        tracing::info!("Kill switch: LAN sharing permitted (RFC1918 + link-local)");
    }
    if self_permits_loaded {
        tracing::info!(
            "Kill switch: self-permit for uid {} on tcp/443 to {} control-plane addresses",
            inputs.euid,
            inputs.control_plane.len()
        );
    }
    Ok(self_permits_loaded)
}

/// Hook generation `gen` into OUTPUT/INPUT/FORWARD in both families.
fn hook_chains(gen: i8) -> Result<(), String> {
    let out = chain_out(gen);
    let inn = chain_in(gen);

    iptables(&["-I", "OUTPUT", "1", "-j", &out])?;
    iptables(&["-I", "INPUT", "1", "-j", &inn])?;
    iptables(&["-I", "FORWARD", "1", "-j", &inn])?;

    ip6tables(&["-I", "OUTPUT", "1", "-j", &out])?;
    ip6tables(&["-I", "INPUT", "1", "-j", &inn])?;
    ip6tables(&["-I", "FORWARD", "1", "-j", &inn])?;
    Ok(())
}

/// Remove every jump to generation `gen`, then delete its chains.
fn retire_chains(gen: i8) {
    if gen < 0 {
        return;
    }
    for name in [chain_out(gen), chain_in(gen)] {
        remove_chain(&name);
    }
}

/// Delete `name` in whichever family it exists in: every jump to it first (a
/// chain cannot be deleted while referenced), then the chain itself.
///
/// A jump can only exist if its target chain does, so the existence probe also
/// tells us whether the unhook attempts are worth spawning at all.
fn remove_chain(name: &str) {
    let v4 = chain_exists(name);
    let v6 = chain_exists_v6(name);
    if !v4 && !v6 {
        return;
    }

    for hook in HOOKS {
        // `-D` removes ONE matching rule; loop (bounded) so a duplicate jump
        // left by an interrupted activation cannot survive teardown. The first
        // failure means there is nothing left to delete.
        if v4 {
            for _ in 0..8 {
                if iptables(&["-D", hook, "-j", name]).is_err() {
                    break;
                }
            }
        }
        if v6 {
            for _ in 0..8 {
                if ip6tables(&["-D", hook, "-j", name]).is_err() {
                    break;
                }
            }
        }
    }

    if v4 {
        let _ = iptables(&["-F", name]);
        let _ = iptables(&["-X", name]);
    }
    if v6 {
        let _ = ip6tables(&["-F", name]);
        let _ = ip6tables(&["-X", name]);
    }
}

/// Unhook and delete every chain we know about, in both families.
fn remove_all_chains() {
    for name in all_chain_names() {
        remove_chain(&name);
    }
}

/// Chains that survived a teardown attempt (empty == fully removed).
fn leftover_chains() -> Vec<String> {
    all_chain_names()
        .into_iter()
        .filter(|n| chain_exists(n) || chain_exists_v6(n))
        .collect()
}

/// Activate blocking: block all traffic except what `iptables_policy`
/// permits (loopback, DHCP, the relay, the tunnel, the LAN with sharing on,
/// and our uid's tcp/443 to the control plane).
///
/// Builds a fresh generation of chains, swaps the built-in jumps onto it, and
/// only then tears down the previous generation — so re-arming (which happens on
/// every reconnect tick) never opens a window where traffic is unfiltered.
pub async fn activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    let _chains = CHAINS.lock().await;
    activate_locked(server_ip)
}

/// [`activate_blocking`] with [`CHAINS`] held.
fn activate_locked(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    tracing::info!("Activating Linux iptables kill switch");

    // Read under the lock: a re-arm for a newly learned control-plane address
    // must be built from a set that includes it.
    let (control_plane, control_plane_gen) = crate::api::doh_resolver::control_plane();
    let inputs = iptables_policy::BlockAll {
        relay: server_ip,
        control_plane: &control_plane,
        euid: unsafe { libc::geteuid() },
        lan_sharing: crate::commands::killswitch::lan_sharing_enabled(),
    };
    // Review of #259 (L3): `permits` is lock-free, and PERMITTED_GEN is
    // u64::MAX while nothing is live — so on a FIRST activation an address
    // DoH learns while this runs would read as permitted, and be cached
    // without a self-permit. From here on it reads as what this generation
    // will cover (a no-op on a re-arm: the live one covers no more).
    PERMITTED_GEN.fetch_min(control_plane_gen, Ordering::SeqCst);

    let live = LIVE_GEN.load(Ordering::SeqCst);
    if live < 0 {
        // First activation of this process. Anything still installed is debris
        // from a crash or a previous build; clear it before we start, so the
        // staging generation we are about to flush cannot be one that is still
        // referenced from a built-in chain.
        let stale = leftover_chains();
        if !stale.is_empty() {
            tracing::warn!(
                "Found kill-switch chains from a previous run ({}) — removing before re-arming",
                stale.join(", ")
            );
        }
        remove_all_chains();
    }
    let next: i8 = if live == 0 { 1 } else { 0 };

    let self_permits_loaded = match build_chains(next, &inputs) {
        Ok(loaded) => loaded,
        Err(e) => {
            // Nothing was hooked, so this cannot leak: drop the staging chains
            // and leave the previous generation (if any) exactly as it was.
            retire_chains(next);
            if live < 0 {
                // Nothing of ours is live, so nothing restricts any address.
                PERMITTED_GEN.store(u64::MAX, Ordering::SeqCst);
            }
            tracing::error!("Kill switch: rule build failed, block NOT changed: {}", e);
            return Err(e);
        }
    };
    let covered = iptables_policy::covered_generation(control_plane_gen, self_permits_loaded);

    if let Err(e) = hook_chains(next) {
        // INVARIANT: the generation LIVE_GEN does NOT name is never referenced
        // from a built-in chain — it is the one the next activation flushes and
        // rebuilds. While an older generation is live, LIVE_GEN must therefore
        // keep naming it (fully hooked) rather than a partially-hooked `next`:
        // otherwise the following re-arm would flush the old, still-hooked
        // chains, and an empty hooked chain falls through to the default ACCEPT
        // policy for the whole per-rule rebuild (defect #1 all over again).
        if live >= 0 {
            // The old generation is still fully hooked underneath, every chain
            // DROP-terminated — so unhooking whatever next-gen jumps landed is
            // fail-closed. Retire the staging generation and keep LIVE_GEN on
            // the old one (and PERMITTED_GEN on what the old one covers).
            retire_chains(next);
            IPTABLES_BLOCKING.store(true, Ordering::SeqCst);
            tracing::error!(
                "Kill switch: re-arm could not hook the new rule set ({}); \
                 previous generation left armed",
                e
            );
        } else {
            // First arm: part of the swap landed and there is no previous
            // generation to fall back on. Do NOT roll back into an unprotected
            // state — every chain involved terminates in DROP, so leaving them
            // hooked fails closed, and the retry path is safe (the next
            // activation builds the OTHER generation). Report the truth:
            // `blocking` reflects whether OUTPUT is actually filtered, not
            // whether we finished.
            let blocking = jump_present("OUTPUT", &chain_out(next));
            LIVE_GEN.store(next, Ordering::SeqCst);
            PERMITTED_GEN.store(covered, Ordering::SeqCst);
            SELF_PERMITS_MISSING.store(!self_permits_loaded, Ordering::SeqCst);
            IPTABLES_BLOCKING.store(blocking, Ordering::SeqCst);
            tracing::error!(
                "Kill switch: only part of the rule set could be hooked ({}); blocking={}",
                e,
                blocking
            );
        }
        return Err(e);
    }

    // New generation is live in every hook — retire the old one.
    retire_chains(live);

    LIVE_GEN.store(next, Ordering::SeqCst);
    PERMITTED_GEN.store(covered, Ordering::SeqCst);
    SELF_PERMITS_MISSING.store(!self_permits_loaded, Ordering::SeqCst);
    IPTABLES_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch activated");
    Ok(())
}

/// Whether control-plane addresses of `generation` get through our chains:
/// none of ours is live, or the live one's self-permits cover them (N5).
pub fn permits(generation: u64) -> bool {
    PERMITTED_GEN.load(Ordering::SeqCst) >= generation
}

/// Whether the live chains lack a control-plane self-permit that would not
/// load. False while nothing of ours is live.
pub fn self_permits_missing() -> bool {
    SELF_PERMITS_MISSING.load(Ordering::SeqCst)
}

/// A DoH answer brought control-plane addresses of `generation`. If a block of
/// ours is live and its self-permits do not cover them, re-arm it NOW around
/// the current control-plane set — the same generation swap as any re-arm, so
/// it never opens a window — before the resolver caches or dials them.
///
/// `Ok(true)`: re-armed. `Ok(false)`: nothing to do — no block of ours is live
/// (the next activation reads the set), or the live one covers `generation`
/// already. Whether a block is WANTED is the caller's to decide
/// (`killswitch::control_plane_learned`, under the one rule for the intent);
/// this never puts up a block that is not already up.
pub async fn refresh_control_plane(
    server_ip: Option<Ipv4Addr>,
    generation: u64,
) -> Result<bool, String> {
    let _chains = CHAINS.lock().await;
    if permits(generation) || LIVE_GEN.load(Ordering::SeqCst) < 0 {
        return Ok(false);
    }
    activate_locked(server_ip).map(|()| true)
}

/// Deactivate blocking: remove our chains from both filter tables.
///
/// VERIFIES the removal before reporting success. Clearing the flag on an
/// unchecked `let _ =` teardown is how a machine ends up fully firewalled while
/// the app believes it is not blocking: every later lift is gated on that flag,
/// so nothing ever retries.
pub async fn deactivate_blocking() -> Result<(), String> {
    let _chains = CHAINS.lock().await;
    tracing::info!("Deactivating Linux iptables kill switch");

    remove_all_chains();

    // `iptables -X` refuses to delete a chain that is still referenced, so an
    // absent chain proves both its rules and every jump to it are gone.
    let leftover = leftover_chains();
    if !leftover.is_empty() {
        // Keep the flag TRUE: the kernel is (or may still be) filtering, and the
        // caller must be able to retry rather than assume success.
        IPTABLES_BLOCKING.store(true, Ordering::SeqCst);
        let msg = format!(
            "Kill switch teardown incomplete — these chains are still installed: {}",
            leftover.join(", ")
        );
        tracing::error!("{}", msg);
        return Err(msg);
    }

    LIVE_GEN.store(-1, Ordering::SeqCst);
    PERMITTED_GEN.store(u64::MAX, Ordering::SeqCst);
    SELF_PERMITS_MISSING.store(false, Ordering::SeqCst);
    IPTABLES_BLOCKING.store(false, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch deactivated");
    Ok(())
}

/// Check if iptables blocking is currently active.
pub fn is_blocking() -> bool {
    IPTABLES_BLOCKING.load(Ordering::SeqCst)
}

/// Emergency cleanup — called from panic handler.
/// Synchronous, so it needs no async runtime.
pub fn emergency_cleanup() {
    remove_all_chains();
    LIVE_GEN.store(-1, Ordering::SeqCst);
    PERMITTED_GEN.store(u64::MAX, Ordering::SeqCst);
    SELF_PERMITS_MISSING.store(false, Ordering::SeqCst);
    IPTABLES_BLOCKING.store(false, Ordering::SeqCst);
}

/// The chains as the KERNEL holds them. `iptables_policy`'s unit tests prove
/// what we ask for; this proves what iptables actually loaded from it.
#[cfg(test)]
mod iptables_chain_tests {
    use super::*;
    use crate::vpn::iptables_policy::check::{self, Packet};
    use std::net::{IpAddr, Ipv6Addr};

    /// Whether a jump from `hook` to `name` is installed in the IPv6 table.
    fn jump_present_v6(hook: &str, name: &str) -> bool {
        crate::utils::hidden_cmd("ip6tables")
            .args(["-w", "-C", hook, "-j", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// `<cmd> -S <chain>`: the kernel's own listing.
    fn listing(cmd: &str, chain: &str) -> Result<String, String> {
        let out = crate::utils::hidden_cmd(cmd)
            .args(["-w", "-S", chain])
            .output()
            .map_err(|e| format!("{cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{cmd} -S {chain}: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Builds one generation for real and reads it back, then removes it. It
    /// is NEVER hooked into OUTPUT/INPUT/FORWARD, so it filters none of the
    /// runner's own traffic. Root only: tests.yml's Linux root step runs it.
    #[test]
    #[ignore = "needs root and iptables: run by tests.yml's kill-switch chain step"]
    fn the_kernel_holds_only_scoped_tcp_443_permits() {
        let control = [
            Ipv4Addr::new(1, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(104, 16, 0, 1),
        ];
        let euid = unsafe { libc::geteuid() };
        let inputs = iptables_policy::BlockAll {
            relay: Some(Ipv4Addr::new(203, 0, 113, 7)),
            control_plane: &control,
            euid,
            lan_sharing: true,
        };
        let want = iptables_policy::block_all(&inputs);
        // Not 0 or 1, the generations the kill switch itself swaps between,
        // so this can never flush chains a live block is using.
        let gen = 7;
        let (out, inn) = (chain_out(gen), chain_in(gen));

        retire_chains(gen); // a previous run that died part-way
        let built = build_chains(gen, &inputs);
        let v4 = listing("iptables", &out);
        let v6 = listing("ip6tables", &out);
        let hooked: Vec<&str> = HOOKS
            .into_iter()
            .filter(|h| {
                jump_present(h, &out)
                    || jump_present(h, &inn)
                    || jump_present_v6(h, &out)
                    || jump_present_v6(h, &inn)
            })
            .collect();
        retire_chains(gen);
        let left: Vec<&String> = [&out, &inn]
            .into_iter()
            .filter(|c| chain_exists(c) || chain_exists_v6(c))
            .collect();

        assert!(hooked.is_empty(), "the test hooked {hooked:?}");
        assert!(left.is_empty(), "the test left {left:?} behind");
        assert_eq!(built, Ok(true), "every rule, every self-permit, loaded");

        let v4 = v4.expect("iptables -S");
        println!("{v4}");
        let rules = check::parse_listing(&v4, &out);
        assert_eq!(rules.len(), want.out_v4.len(), "{v4}");
        assert!(check::port_443_is_scoped(&rules, &control, euid), "{v4}");
        assert_eq!(
            rules.last().map(|r| r.join(" ")),
            Some("-j DROP".to_string()),
            "{v4}"
        );
        let tcp443 = |dst: IpAddr, uid: u32| Packet {
            proto: "tcp",
            dst,
            dport: 443,
            oif: "eth0",
            uid,
        };
        for ip in control {
            let to = IpAddr::V4(ip);
            assert_eq!(check::verdict(&rules, &tcp443(to, euid)), Some("ACCEPT"));
            assert_eq!(check::verdict(&rules, &tcp443(to, euid + 1)), Some("DROP"));
        }
        for to in [
            Ipv4Addr::new(140, 82, 112, 3),    // github.com
            Ipv4Addr::new(185, 199, 108, 133), // release-assets.githubusercontent.com
            Ipv4Addr::new(93, 184, 216, 34),
        ] {
            assert_eq!(
                check::verdict(&rules, &tcp443(IpAddr::V4(to), euid)),
                Some("DROP"),
                "{to}\n{v4}"
            );
        }

        let v6 = v6.expect("ip6tables -S");
        println!("{v6}");
        let rules6 = check::parse_listing(&v6, &out);
        assert_eq!(rules6.len(), want.out_v6.len(), "{v6}");
        assert!(check::port_443_is_scoped(&rules6, &[], euid), "{v6}");
        let cloudflare_v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
        assert_eq!(
            check::verdict(&rules6, &tcp443(cloudflare_v6, euid)),
            Some("DROP"),
            "{v6}"
        );
    }
}
