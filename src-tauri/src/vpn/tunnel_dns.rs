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
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
                    return None;
                }
                // netsh may annotate entries (e.g. "1.1.1.1 (Preferred)") or, on
                // localized Windows, emit non-IP rows that happen to start with a
                // digit. Take only the first whitespace token and require it to be a
                // valid IP — these values are fed back verbatim into
                // `netsh set/add dns static <ip>` on restore, so storing anything
                // that is not a bare IP would silently break DNS restoration.
                let candidate = trimmed.split_whitespace().next()?;
                if candidate.parse::<std::net::IpAddr>().is_ok() {
                    Some(candidate.to_string())
                } else {
                    // A row started with a digit but its first token is not a
                    // valid IP. Dropping it (by design) means one fewer DNS
                    // server is restored on disconnect; log it so partial DNS
                    // restoration is diagnosable.
                    tracing::warn!(
                        "snapshot_adapter_dns: adapter '{}' had a digit-prefixed line that is not a valid IP ('{}'); skipping — DNS restoration may be incomplete",
                        adapter_name,
                        candidate
                    );
                    None
                }
            })
            .collect();

        Some(AdapterDnsSnapshot {
            adapter_name: adapter_name.to_string(),
            dns_servers: servers,
        })
    }
}
