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

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicI8, Ordering};

/// Tracks whether iptables blocking rules are active
pub(crate) static IPTABLES_BLOCKING: AtomicBool = AtomicBool::new(false);

/// Which generation of chains is currently hooked into the built-in chains:
/// `-1` = none, `0`/`1` = the live generation. Activation always builds the
/// OTHER generation and swaps the jumps onto it.
static LIVE_GEN: AtomicI8 = AtomicI8::new(-1);

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

/// Build the fully-populated rule set for `gen` in both address families.
///
/// Nothing here is reachable from a built-in chain yet, so a failure part-way
/// through cannot leave a half-armed policy in the packet path: the caller
/// deletes the staging chains and the previous generation (if any) is untouched.
fn build_chains(gen: i8, server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    let out = chain_out(gen);
    let inn = chain_in(gen);
    let lan = crate::commands::killswitch::lan_sharing_enabled();

    // ---------------------------------------------------------------- IPv4 OUT
    reset_chain(&out)?;
    iptables(&["-A", &out, "-o", "lo", "-j", "ACCEPT"])?;
    // DHCP client → server, so the machine can keep its lease.
    iptables(&["-A", &out, "-p", "udp", "--dport", "67", "-j", "ACCEPT"])?;
    // Traffic to the VPN relay (WireGuard handshake + stealth fallback).
    if let Some(ip) = server_ip {
        iptables(&["-A", &out, "-d", &ip.to_string(), "-j", "ACCEPT"])?;
    }
    // Traffic on the TUN interface.
    iptables(&["-A", &out, "-o", "birdo0", "-j", "ACCEPT"])?;

    // LAN PERMIT: honour Local Network Sharing while the block is engaged, so a
    // dropped tunnel does not also take out the printer, the NAS and SSH.
    // 169.254/16 is included for mDNS/Bonjour discovery.
    if lan {
        for cidr in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ] {
            iptables(&["-A", &out, "-d", cidr, "-j", "ACCEPT"])?;
        }
        tracing::info!("Kill switch: LAN sharing permitted (RFC1918 + link-local)");
    }

    // SELF-PERMIT: let OUR OWN process reach the control plane.
    //
    // Without this the kill switch makes reconnection impossible, which is the
    // opposite of what it is for: auto_reconnect arms the block and then calls
    // https://api.birdo.app for a fresh config — a DIFFERENT host from the
    // permitted relay — with DoH (tcp/443) for name resolution.
    //
    // Windows keys the equivalent permit on ALE_APP_ID. iptables has no app
    // identity, so we match the euid we run as; but the client runs as root, so
    // `--uid-owner 0` on its own exempts EVERY root-owned process on every port
    // and protocol — plaintext DNS, http, any daemon that phones home. It is
    // scoped to tcp/443 to match what the control plane actually needs (and what
    // the macOS pf rule already did). A cgroup2 match (`-m cgroup --path`) would
    // narrow this to our own process and is the obvious follow-up.
    //
    // Note this permit deliberately does NOT cover the WireGuard handshake: the
    // relay is permitted by address above, and `update_vpn_server` re-arms with
    // the new relay before a reconnect uses it.
    let euid = unsafe { libc::geteuid() };
    let uid_str = euid.to_string();
    match iptables(&[
        "-A",
        &out,
        "-p",
        "tcp",
        "--dport",
        "443",
        "-m",
        "owner",
        "--uid-owner",
        &uid_str,
        "-j",
        "ACCEPT",
    ]) {
        Ok(()) => tracing::info!(
            "Kill switch: self-permit installed for uid {} (tcp/443 only)",
            euid
        ),
        Err(e) => {
            // Loudly, like Windows does — a kill switch the client cannot escape
            // is a support incident, not a silent degradation.
            tracing::error!(
                "Kill switch: could NOT install the self-permit for uid {} ({}). \
                 Auto-reconnect will not be able to reach the control plane while \
                 the block is armed.",
                euid,
                e
            );
        }
    }

    iptables(&["-A", &out, "-j", "DROP"])?;

    // ----------------------------------------------------------- IPv4 IN/FWD
    reset_chain(&inn)?;
    iptables(&["-A", &inn, "-i", "lo", "-j", "ACCEPT"])?;
    // DHCP server → client.
    iptables(&["-A", &inn, "-p", "udp", "--dport", "68", "-j", "ACCEPT"])?;
    if let Some(ip) = server_ip {
        iptables(&["-A", &inn, "-s", &ip.to_string(), "-j", "ACCEPT"])?;
    }
    iptables(&["-A", &inn, "-i", "birdo0", "-j", "ACCEPT"])?;
    if lan {
        for cidr in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ] {
            iptables(&["-A", &inn, "-s", cidr, "-j", "ACCEPT"])?;
        }
    }
    // Replies to traffic we permitted outbound (control plane, relay, LAN).
    //
    // This used to be an unscoped `ESTABLISHED,RELATED` accept in the single
    // shared chain, i.e. it also applied to OUTPUT — so any plaintext flow
    // opened over the physical NIC before the block kept running through it for
    // the whole outage. Accepting established traffic INBOUND only is enough for
    // replies while still killing those flows, because their outbound direction
    // (including the TCP ACKs) now hits the DROP.
    iptables(&[
        "-A",
        &inn,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED",
        "-j",
        "ACCEPT",
    ])?;
    iptables(&["-A", &inn, "-j", "DROP"])?;

    // ---------------------------------------------------------------- IPv6
    // AUDIT-N5: parity rules for IPv6. Without these, dual-stack Linux hosts
    // leak IPv6 traffic outside the tunnel — a real-IP leak the WFP code on
    // Windows explicitly closes via block_all_v6. The WireGuard tunnel itself is
    // IPv4-only on this client, so nothing but link-local housekeeping survives.
    reset_chain_v6(&out)?;
    ip6tables(&["-A", &out, "-o", "lo", "-j", "ACCEPT"])?;
    ip6tables(&["-A", &out, "-p", "udp", "--dport", "547", "-j", "ACCEPT"])?;
    // ICMPv6 NDP / RA / RS — required for IPv6 to function at all on the LAN,
    // but scoped to link-local and multicast destinations. A blanket
    // `-p ipv6-icmp -j ACCEPT` here would sit in front of the tunnel's
    // BIRDO_IPV6_LEAK_BLOCK chain (see tunnel_linux.rs) and re-permit ICMPv6 to
    // GLOBAL destinations, disclosing the host's real IPv6 address at exactly
    // the moment protection matters most.
    for dst in ["fe80::/10", "ff02::/16"] {
        ip6tables(&["-A", &out, "-p", "ipv6-icmp", "-d", dst, "-j", "ACCEPT"])?;
    }
    ip6tables(&["-A", &out, "-j", "DROP"])?;

    reset_chain_v6(&inn)?;
    ip6tables(&["-A", &inn, "-i", "lo", "-j", "ACCEPT"])?;
    ip6tables(&["-A", &inn, "-p", "udp", "--dport", "546", "-j", "ACCEPT"])?;
    for src in ["fe80::/10", "ff02::/16"] {
        ip6tables(&["-A", &inn, "-p", "ipv6-icmp", "-s", src, "-j", "ACCEPT"])?;
    }
    ip6tables(&["-A", &inn, "-j", "DROP"])?;

    Ok(())
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

/// Activate blocking: block all traffic except loopback, DHCP, and VPN server.
///
/// Builds a fresh generation of chains, swaps the built-in jumps onto it, and
/// only then tears down the previous generation — so re-arming (which happens on
/// every reconnect tick) never opens a window where traffic is unfiltered.
pub async fn activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    tracing::info!("Activating Linux iptables kill switch");

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

    if let Err(e) = build_chains(next, server_ip) {
        // Nothing was hooked, so this cannot leak: drop the staging chains and
        // leave the previous generation (if any) exactly as it was.
        retire_chains(next);
        tracing::error!("Kill switch: rule build failed, block NOT changed: {}", e);
        return Err(e);
    }

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
            // the old one.
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
    IPTABLES_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch activated");
    Ok(())
}

/// Re-arm the live block around a NEW relay address.
///
/// The relay is permitted by address, and the self-permit is scoped to tcp/443,
/// so a reconnect that lands on a different server would have its WireGuard
/// handshake dropped until the next re-arm. Windows has `wfp::update_vpn_server`
/// for exactly this; this is the iptables equivalent. No-op when not blocking.
pub async fn update_vpn_server(ip: Ipv4Addr) -> Result<(), String> {
    if !IPTABLES_BLOCKING.load(Ordering::SeqCst) {
        return Ok(());
    }
    activate_blocking(Some(ip)).await
}

/// Deactivate blocking: remove our chains from both filter tables.
///
/// VERIFIES the removal before reporting success. Clearing the flag on an
/// unchecked `let _ =` teardown is how a machine ends up fully firewalled while
/// the app believes it is not blocking: every later lift is gated on that flag,
/// so nothing ever retries.
pub async fn deactivate_blocking() -> Result<(), String> {
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
    IPTABLES_BLOCKING.store(false, Ordering::SeqCst);
}
