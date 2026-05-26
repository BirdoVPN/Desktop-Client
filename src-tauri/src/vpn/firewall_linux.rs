//! Linux firewall (iptables) kill switch implementation
//!
//! Blocks all non-VPN traffic using iptables when the VPN disconnects unexpectedly.
//! Uses a dedicated chain (BIRDO_KILLSWITCH) to avoid conflicting with user rules.
//!
//! Equivalent to WFP on Windows and pf on macOS.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tracks whether iptables blocking rules are active
pub(crate) static IPTABLES_BLOCKING: AtomicBool = AtomicBool::new(false);

/// Custom chain name for Birdo VPN kill switch rules
const CHAIN_NAME: &str = "BIRDO_KILLSWITCH";

/// Run an iptables command, returning Ok on success.
fn iptables(args: &[&str]) -> Result<(), String> {
    let output = crate::utils::hidden_cmd("iptables")
        .args(args)
        .output()
        .map_err(|e| format!("iptables command failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("iptables {} failed: {}", args.join(" "), stderr));
    }
    Ok(())
}

/// AUDIT-N5: Run an ip6tables command. We tolerate ip6tables being absent on
/// IPv4-only hosts (older systems / containers without IPv6 support) by
/// returning Ok on `command not found`; presence of ip6tables but failure on
/// a specific rule is still surfaced as an error.
fn ip6tables(args: &[&str]) -> Result<(), String> {
    let output = match crate::utils::hidden_cmd("ip6tables").args(args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("ip6tables not present — skipping IPv6 rule (host is IPv4-only)");
            return Ok(());
        }
        Err(e) => return Err(format!("ip6tables command failed: {}", e)),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ip6tables {} failed: {}", args.join(" "), stderr));
    }
    Ok(())
}

/// Check if our custom chain exists.
fn chain_exists() -> bool {
    crate::utils::hidden_cmd("iptables")
        .args(["-L", CHAIN_NAME, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// AUDIT-N5: Check if our custom chain exists in the IPv6 table.
fn chain_exists_v6() -> bool {
    crate::utils::hidden_cmd("ip6tables")
        .args(["-L", CHAIN_NAME, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Create the BIRDO_KILLSWITCH chain if it doesn't exist.
fn ensure_chain() -> Result<(), String> {
    if !chain_exists() {
        iptables(&["-N", CHAIN_NAME])?;
    }
    Ok(())
}

/// AUDIT-N5: Create the BIRDO_KILLSWITCH chain in ip6tables if it doesn't exist.
fn ensure_chain_v6() -> Result<(), String> {
    if !chain_exists_v6() {
        ip6tables(&["-N", CHAIN_NAME])?;
    }
    Ok(())
}

/// Activate blocking: block all traffic except loopback, DHCP, and VPN server.
pub async fn activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    tracing::info!("Activating Linux iptables kill switch");

    ensure_chain()?;

    // Flush our chain first (idempotent)
    let _ = iptables(&["-F", CHAIN_NAME]);

    // Allow loopback
    iptables(&["-A", CHAIN_NAME, "-o", "lo", "-j", "ACCEPT"])?;
    iptables(&["-A", CHAIN_NAME, "-i", "lo", "-j", "ACCEPT"])?;

    // Allow DHCP (UDP 67/68) so the system can maintain its network lease
    iptables(&[
        "-A", CHAIN_NAME, "-p", "udp", "--dport", "67", "-j", "ACCEPT",
    ])?;
    iptables(&[
        "-A", CHAIN_NAME, "-p", "udp", "--dport", "68", "-j", "ACCEPT",
    ])?;

    // Allow traffic to VPN server IP
    if let Some(ip) = server_ip {
        iptables(&["-A", CHAIN_NAME, "-d", &ip.to_string(), "-j", "ACCEPT"])?;
        iptables(&["-A", CHAIN_NAME, "-s", &ip.to_string(), "-j", "ACCEPT"])?;
    }

    // Allow traffic on the TUN interface (birdo0)
    iptables(&["-A", CHAIN_NAME, "-o", "birdo0", "-j", "ACCEPT"])?;
    iptables(&["-A", CHAIN_NAME, "-i", "birdo0", "-j", "ACCEPT"])?;

    // Allow established/related connections (for responses to allowed traffic)
    iptables(&[
        "-A",
        CHAIN_NAME,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;

    // Drop everything else
    iptables(&["-A", CHAIN_NAME, "-j", "DROP"])?;

    // Insert our chain into the OUTPUT and INPUT chains at the top
    // First remove any existing references (ignore errors)
    let _ = iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "FORWARD", "-j", CHAIN_NAME]);

    iptables(&["-I", "OUTPUT", "1", "-j", CHAIN_NAME])?;
    iptables(&["-I", "INPUT", "1", "-j", CHAIN_NAME])?;
    iptables(&["-I", "FORWARD", "1", "-j", CHAIN_NAME])?;

    // AUDIT-N5: parity rules for IPv6 (ip6tables). Without these, dual-stack
    // Linux hosts leak IPv6 traffic outside the tunnel — a real-IP leak the
    // WFP code on Windows explicitly closes via block_all_v6. The WireGuard
    // tunnel itself is IPv4-only on this client, so the policy is: allow
    // loopback + DHCPv6 + ICMPv6 (NDP), drop everything else on the wire.
    ensure_chain_v6()?;
    let _ = ip6tables(&["-F", CHAIN_NAME]);
    ip6tables(&["-A", CHAIN_NAME, "-o", "lo", "-j", "ACCEPT"])?;
    ip6tables(&["-A", CHAIN_NAME, "-i", "lo", "-j", "ACCEPT"])?;
    // DHCPv6 client/server (UDP 546/547) so the host can keep a v6 lease
    // without leaking app traffic.
    ip6tables(&[
        "-A", CHAIN_NAME, "-p", "udp", "--dport", "546", "-j", "ACCEPT",
    ])?;
    ip6tables(&[
        "-A", CHAIN_NAME, "-p", "udp", "--dport", "547", "-j", "ACCEPT",
    ])?;
    // ICMPv6 NDP / RA / RS — required for IPv6 to function at all on the LAN.
    ip6tables(&["-A", CHAIN_NAME, "-p", "ipv6-icmp", "-j", "ACCEPT"])?;
    // Drop everything else (no v6 traffic survives the kill switch).
    ip6tables(&["-A", CHAIN_NAME, "-j", "DROP"])?;
    let _ = ip6tables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = ip6tables(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = ip6tables(&["-D", "FORWARD", "-j", CHAIN_NAME]);
    ip6tables(&["-I", "OUTPUT", "1", "-j", CHAIN_NAME])?;
    ip6tables(&["-I", "INPUT", "1", "-j", CHAIN_NAME])?;
    ip6tables(&["-I", "FORWARD", "1", "-j", CHAIN_NAME])?;

    IPTABLES_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch activated");
    Ok(())
}

/// Deactivate blocking: remove our chain from the filter table.
pub async fn deactivate_blocking() -> Result<(), String> {
    tracing::info!("Deactivating Linux iptables kill switch");

    // Remove jumps to our chain
    let _ = iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "FORWARD", "-j", CHAIN_NAME]);

    // Flush and delete our chain
    if chain_exists() {
        let _ = iptables(&["-F", CHAIN_NAME]);
        let _ = iptables(&["-X", CHAIN_NAME]);
    }

    // AUDIT-N5: tear down IPv6 chain too.
    let _ = ip6tables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = ip6tables(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = ip6tables(&["-D", "FORWARD", "-j", CHAIN_NAME]);
    if chain_exists_v6() {
        let _ = ip6tables(&["-F", CHAIN_NAME]);
        let _ = ip6tables(&["-X", CHAIN_NAME]);
    }

    IPTABLES_BLOCKING.store(false, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch deactivated");
    Ok(())
}

/// Check if iptables blocking is currently active.
pub fn is_blocking() -> bool {
    IPTABLES_BLOCKING.load(Ordering::SeqCst)
}

/// Emergency cleanup — called from panic handler.
/// Uses raw Command to avoid async runtime dependency.
pub fn emergency_cleanup() {
    let _ = std::process::Command::new("iptables")
        .args(["-D", "OUTPUT", "-j", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "INPUT", "-j", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "FORWARD", "-j", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-F", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-X", CHAIN_NAME])
        .output();

    // AUDIT-N5: tear down IPv6 chain in panic handler too.
    for chain in ["OUTPUT", "INPUT", "FORWARD"] {
        let _ = std::process::Command::new("ip6tables")
            .args(["-D", chain, "-j", CHAIN_NAME])
            .output();
    }
    let _ = std::process::Command::new("ip6tables")
        .args(["-F", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("ip6tables")
        .args(["-X", CHAIN_NAME])
        .output();
}
