//! DNS management for WintunTunnel
//!
//! Extracted from tunnel.rs — handles DNS configuration, snapshot/restore,
//! and non-VPN adapter enumeration.

use std::process::Command;

use super::tunnel::{AdapterDnsSnapshot, WintunTunnel};

/// Hidden command helper
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// SEC-C4 FIX: Encode PowerShell script as Base64 UTF-16LE
fn base64_encode_utf16le(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

impl WintunTunnel {
    /// List connected non-VPN adapter names.
    ///
    /// PERF: parse `netsh interface ipv4 show interfaces` instead of PowerShell
    /// `Get-NetAdapter` — the PowerShell cold-start cost ~9s on AV-heavy
    /// machines and was the single slowest step of a connect. netsh is ~50ms.
    /// Columns are: Idx  Met  MTU  State  Name — Name is everything from the 5th
    /// token on, so multi-word names like "WiFi 2" are preserved.
    pub(super) fn get_non_vpn_adapters() -> Vec<String> {
        let parsed: Vec<String> = match cmd("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout
                    .lines()
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        // Data rows start with a numeric Idx and have >= 5 cols.
                        if parts.len() < 5 || parts[0].parse::<u32>().is_err() {
                            return None;
                        }
                        // State is col 4 ("connected"/"disconnected"); name is the rest.
                        if !parts[3].eq_ignore_ascii_case("connected") {
                            return None;
                        }
                        let name = parts[4..].join(" ");
                        if name.eq_ignore_ascii_case(super::tunnel::ADAPTER_NAME)
                            || name.contains("Loopback")
                        {
                            None
                        } else {
                            Some(name)
                        }
                    })
                    .collect()
            }
            Err(_) => Vec::new(),
        };
        if !parsed.is_empty() {
            return parsed;
        }

        // Fallback: PowerShell Get-NetAdapter (only if netsh parsing found none).
        let ps_script = format!(
            "Get-NetAdapter -Physical | Where-Object {{ $_.Name -ne '{}' -and $_.Status -eq 'Up' }} | Select-Object -ExpandProperty Name",
            super::tunnel::ADAPTER_NAME
        );
        let encoded = base64_encode_utf16le(&ps_script);
        match cmd("powershell")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .output()
        {
            Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Capture current DNS configuration for an adapter before modification.
    pub(super) fn snapshot_adapter_dns(adapter_name: &str) -> Option<AdapterDnsSnapshot> {
        let output = match cmd("netsh")
            .args(["interface", "ipv4", "show", "dns", adapter_name])
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                // Returning None here causes the caller to fall back to DHCP for
                // this adapter on restore, silently dropping any static DNS the
                // user had configured. Surface the failure so incomplete DNS
                // restoration is debuggable.
                tracing::warn!(
                    "snapshot_adapter_dns: netsh failed for adapter '{}': {} — DNS for this adapter may not be restored",
                    adapter_name,
                    e
                );
                return None;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);

        let servers: Vec<String> = stdout
            .lines()
            // Scan EVERY token on EVERY line, exactly as the v6 twin below does.
            //
            // The previous filter required the trimmed line to START with a digit,
            // which silently dropped the PRIMARY resolver on every adapter. netsh
            // puts the first server on the label line and only the rest on their
            // own:
            //
            //     Statically Configured DNS Servers:    1.1.1.1
            //                                           8.8.8.8
            //
            // The first line starts with 'S', so it never matched; only 8.8.8.8 was
            // captured. On disconnect we then restored a strict subset of the user's
            // DNS — losing the resolver they had listed first, permanently, with no
            // error anywhere. A single-server adapter (the common case) snapshotted
            // as EMPTY, which is worse: restore had nothing to write back.
            //
            // The v6 twin has always used the token scan and is unaffected. This is
            // the same bug shape the estate keeps hitting: a fix applied to one of
            // two parallel code paths.
            //
            // Still require a parseable IPv4 per token, because these values are fed
            // back verbatim into `netsh set/add dns static <ip>` on restore, so a
            // non-IP would silently break restoration. Annotations such as
            // "1.1.1.1 (Preferred)" are handled naturally: the address token parses,
            // the annotation token does not.
            .filter_map(|line| {
                line.split_whitespace().find_map(|token| {
                    token
                        .parse::<std::net::Ipv4Addr>()
                        .ok()
                        .map(|_| token.to_string())
                })
            })
            .collect();

        if servers.is_empty() {
            // Not fatal — an adapter genuinely on DHCP has no static servers — but
            // it is the signature of the parsing bug above, so make it visible.
            tracing::debug!(
                "snapshot_adapter_dns: adapter '{}' yielded no IPv4 DNS servers",
                adapter_name
            );
        }

        Some(AdapterDnsSnapshot {
            adapter_name: adapter_name.to_string(),
            dns_servers: servers,
            dns_servers_v6: Self::snapshot_adapter_dns_v6(adapter_name),
        })
    }

    /// Capture an adapter's IPv6 resolvers before we disable them.
    ///
    /// Separate from the IPv4 snapshot because netsh's `ipv4`/`ipv6` contexts hold
    /// separate resolver lists — the IPv6 one (usually a link-local from
    /// RA/RDNSS) was previously neither disabled nor restored, so SMHNR kept
    /// querying it on the physical NIC.
    ///
    /// Any token on the line may be the address (netsh prints the first server on
    /// the same line as the label and the rest on continuation lines), so match on
    /// parseability rather than position. The zone suffix on a link-local
    /// (`fe80::1%13`) is preserved: it is part of the address netsh accepts back.
    fn snapshot_adapter_dns_v6(adapter_name: &str) -> Vec<String> {
        let output = match cmd("netsh")
            .args(["interface", "ipv6", "show", "dns", adapter_name])
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                tracing::warn!(
                    "snapshot_adapter_dns_v6: netsh failed for adapter '{}': {} — IPv6 DNS for this adapter may not be restored",
                    adapter_name,
                    e
                );
                return Vec::new();
            }
        };

        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                line.split_whitespace().find_map(|token| {
                    let bare = token.split('%').next()?;
                    bare.parse::<std::net::Ipv6Addr>()
                        .ok()
                        .map(|_| token.to_string())
                })
            })
            .collect()
    }
}
