//! Logging utilities with PII redaction
//!
//! Provides helper functions to redact sensitive information from logs
//! to protect user privacy in production builds.
//!
//! LOG-001: All error messages and logs should use these functions
//! to prevent PII exposure.

/// Redact an IP address for logging (no IPv4 octet in production, see
/// [`mask_ip`]). In debug builds, returns the full IP for troubleshooting.
#[inline]
pub fn redact_ip(ip: &str) -> String {
    #[cfg(debug_assertions)]
    {
        ip.to_string()
    }

    #[cfg(not(debug_assertions))]
    {
        mask_ip(ip)
    }
}

/// What [`redact_ip`] writes in a release build. Split out of the
/// `not(debug_assertions)` branch so it is reachable from tests.
///
/// - IPv4 (with or without `:port`): every octet masked, the port kept
///   (`x.x.x.x:51820`). P6-CLI-D-06: this used to keep the first octet. That
///   is a /8, and for a fleet of ten known relays it is often enough to tell
///   which one a customer used.
/// - IPv6: the first segment only (`2001:x:x:x:x:x:x:x`), a /16 allocation
///   block, not a host.
#[cfg_attr(debug_assertions, allow(dead_code))]
fn mask_ip(ip: &str) -> String {
    if ip.contains("::") || ip.matches(':').count() >= 2 {
        let first = ip.split(':').next().unwrap_or_default();
        format!("{first}:x:x:x:x:x:x:x")
    } else if let Some((_, port)) = ip.split_once(':') {
        format!("x.x.x.x:{port}")
    } else {
        "x.x.x.x".to_string()
    }
}

/// Redact an email address for logging (shows first 2 chars + domain)
#[inline]
pub fn redact_email(email: &str) -> String {
    #[cfg(debug_assertions)]
    {
        email.to_string()
    }

    #[cfg(not(debug_assertions))]
    {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() == 2 {
            let name = parts[0];
            let domain = parts[1];
            // Take first 2 chars (char-boundary safe to avoid panic on multibyte UTF-8)
            let prefix: String = name.chars().take(2).collect();
            let redacted_name = if name.chars().count() > 2 {
                format!("{}***", prefix)
            } else {
                "***".to_string()
            };
            format!("{}@{}", redacted_name, domain)
        } else {
            "[invalid-email]".to_string()
        }
    }
}

/// Redact a hostname for logging
/// LOG-001: VPN server hostnames are sensitive and should not be logged
#[inline]
pub fn redact_hostname(hostname: &str) -> String {
    #[cfg(debug_assertions)]
    {
        hostname.to_string()
    }

    #[cfg(not(debug_assertions))]
    {
        // Check if it looks like an IP address
        if hostname.parse::<std::net::Ipv4Addr>().is_ok() {
            return redact_ip(hostname);
        }

        // Check for IPv6
        if hostname.contains("::") || hostname.matches(':').count() >= 2 {
            return redact_ip(hostname);
        }

        // Hostname: show only TLD for privacy
        // vpn.example.com -> ***.com
        // eu-west-1.vpn.example.com -> ***.com
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() >= 2 {
            format!("***.{}", parts[parts.len() - 1])
        } else {
            "[redacted-host]".to_string()
        }
    }
}

/// Redact a VPN endpoint (hostname:port or ip:port) for logging
/// LOG-001: Specifically designed for VPN endpoints
#[inline]
pub fn redact_endpoint(endpoint: &str) -> String {
    // Split host and port — delegates to redact_ip / redact_hostname
    // which each handle debug-vs-release logic internally.
    if let Some(colon_pos) = endpoint.rfind(':') {
        // Check if this is IPv6 (has multiple colons)
        if endpoint.matches(':').count() > 1 {
            // IPv6 with port: [2001:db8::1]:51820
            if endpoint.starts_with('[') {
                if let Some(bracket_pos) = endpoint.find(']') {
                    let ipv6 = &endpoint[1..bracket_pos];
                    let port = &endpoint[bracket_pos + 1..];
                    return format!("[{}]{}", redact_ip(ipv6), port);
                }
            }
            // Plain IPv6 without port
            return redact_ip(endpoint);
        }

        let host = &endpoint[..colon_pos];
        let port = &endpoint[colon_pos..];

        // Check if host is IP or hostname
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            format!("{}{}", redact_ip(host), port)
        } else {
            format!("{}{}", redact_hostname(host), port)
        }
    } else {
        // No port, just host
        redact_hostname(endpoint)
    }
}

/// Cap a sanitized message at 200 characters, cutting on a CHARACTER boundary.
///
/// Byte-slicing (`s[..197]`) panics whenever the cut lands inside a multibyte
/// sequence, and `sanitize_error` is called from the panic hook (main.rs) — a
/// panic there aborts the process (release profile is `panic = "abort"`), which
/// takes the tunnel and the kill switch down with it. Any non-ASCII text in an
/// OS error message was enough to trigger it.
///
/// Split out of the `not(debug_assertions)` branch so it is reachable from tests.
#[cfg_attr(debug_assertions, allow(dead_code))]
fn truncate_for_display(result: String) -> String {
    if result.chars().count() > 200 {
        let mut truncated: String = result.chars().take(197).collect();
        truncated.push_str("...");
        truncated
    } else {
        result
    }
}

/// Sanitize an error message by redacting any embedded PII (IP addresses, emails, hostnames).
///
/// P3-FIX-17: Error messages returned to users or logged may accidentally contain
/// raw IP addresses, emails, or server hostnames embedded in nested error strings.
/// This function applies regex-based scrubbing to ensure no PII leaks through error paths.
///
/// Usage: wrap any `impl Display` error before logging or returning to the frontend:
///   `let safe_msg = sanitize_error(&err.to_string());`
pub fn sanitize_error(msg: &str) -> String {
    #[cfg(debug_assertions)]
    {
        // In debug builds, return as-is for easier troubleshooting
        msg.to_string()
    }

    #[cfg(not(debug_assertions))]
    {
        sanitize_always(msg)
    }
}

/// The error of an IPC command that still answers `Result<_, String>`, on its
/// way to the renderer (P1-dk-redaction-incomplete).
///
/// Redacted in every build, like `IpcError::new`'s message and for the same
/// reason: this text is shown, copied and pasted into support mail, not
/// written to a developer's console. A raw reqwest or OS error carries the
/// URL, host or address it failed on.
pub fn for_ipc(error: impl std::fmt::Display) -> String {
    sanitize_always(&error.to_string())
}

/// File extensions this app's errors and backtraces name that are NOT also
/// top-level domains: a dotted name ending in one is a file wherever it
/// appears (`tauri.conf.json`, `birdo-vpn.exe`).
const FILE_EXTENSIONS: &[&str] = &[
    "bat", "cfg", "conf", "crt", "dat", "dll", "exe", "html", "ico", "ini", "js", "json", "lock",
    "log", "msi", "pem", "plist", "png", "ps1", "svg", "sys", "tmp", "toml", "ts", "tsx", "txt",
    "xml", "yaml", "yml",
];

/// File extensions that ARE also top-level domains. A name ending in one is a
/// file only straight after a path separator (`src\vpn\tunnel.rs` in a
/// backtrace); anywhere else (`example.rs`) it may be a host, and is redacted.
const EXTENSIONS_THAT_ARE_TLDS: &[&str] = &["md", "rs", "zip"];

/// Code namespaces whose dotted names are identifiers, not hosts: .NET and
/// WinRT (`Windows.Security.Credentials.UI`, `System.IO.IOException`).
const CODE_NAMESPACES: &[&str] = &["Windows", "System", "Microsoft"];

/// Whether `name`, a dotted name the hostname pattern matched ending in `tld`,
/// is a host. Review of #222: file names and code identifiers used to come out
/// as `[redacted-host]`; round 3: only what is KNOWN not to be a host is let
/// through — a name in a code namespace, or one ending in a file extension
/// (one that is also a TLD only right after a path separator). Case does not
/// decide: hosts are case-insensitive, and `vpn.example.NET` is a host.
#[cfg_attr(debug_assertions, allow(dead_code))]
fn looks_like_a_host(name: &str, tld: &str, after_separator: bool) -> bool {
    let tld = tld.to_ascii_lowercase();
    let first = name.split('.').next().unwrap_or(name);
    !(CODE_NAMESPACES.contains(&first)
        || FILE_EXTENSIONS.contains(&tld.as_str())
        || (after_separator && EXTENSIONS_THAT_ARE_TLDS.contains(&tld.as_str())))
}

/// Whether a name that starts right after `before` follows a path separator:
/// a `/`, or a run of `\` (a path printed with `{:?}` doubles them, and one
/// printed twice doubles them again) with a path component before it. Not
/// the `//` of a URL's `scheme://` (round 4 of the review of #222), and not
/// the leading `\\` of a UNC path (`\\nas.example.zip\share`, round 5):
/// what follows those is a host. A single `\` is a separator wherever it
/// stands (` \notes.md`, a path from the drive's root; round 6): only a
/// run of two or more can open a UNC path.
#[cfg_attr(debug_assertions, allow(dead_code))]
fn follows_a_path_separator(before: &str) -> bool {
    if let Some(rest) = before.strip_suffix('/') {
        return !rest.ends_with('/');
    }
    let rest = before.trim_end_matches('\\');
    match before.len() - rest.len() {
        0 => false,
        1 => true,
        _ => rest
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_whitespace() && !"\"'`([<{=,".contains(c)),
    }
}

/// The redaction itself, with NO `debug_assertions` escape hatch.
///
/// [`sanitize_error`] is deliberately a pass-through in debug builds so a
/// developer reading their own console sees real addresses. That is the right
/// trade for a LOCAL log and the wrong one for anything that leaves the
/// machine, so the crash reporter calls this instead — see
/// `utils::crash_report`. A developer who sets a DSN on a debug build must
/// still not be able to post a customer's exit node to Sentry.
///
/// One implementation, two thin wrappers: the same shape
/// `tunnel_dns::parse_dns_config` uses for the v4/v6 twins, and for the same
/// reason — a second copy of a scrubber is a second thing to keep in step,
/// and this estate has paid for that shape repeatedly.
///
/// Being reachable in debug is also what makes it TESTABLE: `cargo test` runs
/// with `debug_assertions` on, so every assertion about what
/// `sanitize_error` removes was previously unwritable and the tests below it
/// could only assert that the output was non-empty.
pub fn sanitize_always(msg: &str) -> String {
    {
        use once_cell::sync::Lazy;
        use regex::Regex;

        // Compiled once, reused across calls
        static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").expect("IPv4 regex")
        });
        static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("email regex")
        });
        // Matches common hostname patterns. P1-dk-redaction-incomplete: two
        // labels are enough ("birdo.app" is as identifying as "api.birdo.app"),
        // so the repeated-label group is now optional. The last label is
        // captured for `looks_like_a_host`.
        static HOST_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){0,}\.([a-zA-Z]{2,})\b").expect("hostname regex")
        });
        // P1-dk-redaction-incomplete: IPv6 literals. Two shapes — an expanded
        // run of >= 5 hex groups (>= 5 avoids matching hh:mm:ss timestamps),
        // and anything containing "::" flanked by hex groups.
        static IPV6_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                r"(?i)\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*",
            )
            .expect("IPv6 regex")
        });
        // P1-dk-redaction-incomplete / P6-CLI-D-06: JWTs and long unbroken
        // base64/base64url runs (WireGuard keys are 44 chars of base64; bearer
        // tokens and API keys are similar). Over-redaction of a long opaque id
        // is an acceptable trade in a privacy sink.
        static JWT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{4,}){1,2}\b").expect("JWT regex")
        });
        static TOKEN_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"[A-Za-z0-9+/_-]{32,}={0,2}").expect("token regex"));
        // P2-13: Strip HTML tags
        static HTML_TAG_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"<[^>]{1,200}>").expect("HTML tag regex"));
        // Round 3 of the review of #222: the account name in a home folder
        // (`C:\Users\Jane.Doe\…`, `/Users/jane/…`, `/home/jane/…`).
        static USER_DIR_RE: Lazy<Regex> = Lazy::new(|| {
            // Any run of backslashes: `{path:?}` prints `C:\\Users\\Jane\\…`
            // (round 4 of the review), and a message quoted twice doubles
            // them again (round 5).
            Regex::new(r#"(?i)(\b[a-z]:\\+users\\+)[^\\/:*?"<>|\r\n]+|(/(?:Users|home)/)[^/\s:]+"#)
                .expect("user folder regex")
        });
        // P2-13: Strip stack traces (lines starting with "at " or Java-style exception patterns)
        static STACK_TRACE_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?m)^\s*at .*$").expect("stack trace regex"));

        // P2-13: If the message looks like raw HTML, replace entirely
        if msg.contains("<html") || msg.contains("<HTML") || msg.contains("<!DOCTYPE") {
            return "[server error]".to_string();
        }

        // Strip HTML tags
        let result = HTML_TAG_RE.replace_all(msg, "").to_string();

        // Strip stack trace lines
        let result = STACK_TRACE_RE.replace_all(&result, "").to_string();

        let result = USER_DIR_RE
            .replace_all(&result, |caps: &regex::Captures| {
                let folder = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map_or("", |m| m.as_str());
                format!("{folder}[redacted-user]")
            })
            .to_string();

        // Tokens/keys first, before the host/IP passes fragment them.
        let result = JWT_RE.replace_all(&result, "[redacted-token]").to_string();
        let result = TOKEN_RE
            .replace_all(&result, "[redacted-token]")
            .to_string();
        // IPv4 BEFORE IPv6 (review of #222): an IPv4 address embedded in an
        // IPv6 one (`::ffff:185.199.110.153`, NAT64 `64:ff9b::…`) went the
        // other way round: the IPv6 pass took `::ffff:185` as a whole
        // address and left `.199.110.153`, which no longer matched the IPv4
        // pattern — three octets out. Now the dotted quad goes first and the
        // IPv6 prefix after it.
        let result = IPV4_RE
            .replace_all(&result, |caps: &regex::Captures| {
                // Only redact if all four octets are valid (0-255); otherwise
                // leave the (non-IP) text untouched to preserve message clarity.
                // Every octet goes (P6-CLI-D-06, see `mask_ip`).
                let valid = (1..=4).all(|i| caps[i].parse::<u8>().is_ok());
                if valid {
                    "[redacted-ipv4]".to_string()
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        let result = IPV6_RE.replace_all(&result, "[redacted-ipv6]").to_string();

        let result = EMAIL_RE
            .replace_all(&result, "[redacted-email]")
            .to_string();

        let result = HOST_RE
            .replace_all(&result, |caps: &regex::Captures| {
                let start = caps.get(0).map_or(0, |m| m.start());
                let after_separator = follows_a_path_separator(&result[..start]);
                if looks_like_a_host(&caps[0], &caps[1], after_separator) {
                    "[redacted-host]".to_string()
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        // P2-20: Truncate to 200 chars (aligned with Android InputValidator.sanitizeErrorMessage)
        truncate_for_display(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_ip_v4() {
        // In release builds, this would be "x.x.x.x" (`mask_ip`)
        let result = redact_ip("192.168.1.100");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_redact_email() {
        let result = redact_email("john.doe@example.com");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_redact_hostname() {
        let result = redact_hostname("vpn.example.com");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_redact_endpoint() {
        let result = redact_endpoint("vpn.example.com:51820");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_sanitize_error_preserves_non_pii() {
        let msg = "Connection timed out after 30 seconds";
        let result = sanitize_error(msg);
        // In debug builds, returns as-is
        assert_eq!(result, msg);
    }

    /// The release-build truncation used to byte-slice at 197 and panicked on any
    /// message whose cut point landed inside a multibyte character. Exercised
    /// directly because the truncation itself is `not(debug_assertions)`-only.
    #[test]
    fn test_truncate_for_display_multibyte_does_not_panic() {
        // 300 three-byte characters: every byte index in 195..=197 is mid-character.
        let msg = "世".repeat(300);
        let result = truncate_for_display(msg);
        assert_eq!(result.chars().count(), 200);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_for_display_short_message_untouched() {
        let msg = "Connection timed out — retrying".to_string();
        assert_eq!(truncate_for_display(msg.clone()), msg);
    }

    #[test]
    fn test_sanitize_error_with_ip() {
        // In debug builds this returns as-is; in release it would redact
        let msg = "Failed to connect to 192.168.1.100:51820";
        let result = sanitize_error(msg);
        assert!(!result.is_empty());
    }

    /// What `sanitize_always` actually removes. Every assertion here was
    /// unwritable while the implementation lived inside
    /// `#[cfg(not(debug_assertions))]`: `cargo test` builds with
    /// `debug_assertions` ON, so the tests above it can only check that the
    /// output is non-empty. This is the redaction the crash reporter relies
    /// on, so it is asserted per class rather than in aggregate — a scrubber
    /// that handles three of four classes must fail, not pass.
    #[test]
    fn sanitize_always_removes_every_address_class() {
        let out = sanitize_always("node de-fra-01.birdo.app 185.199.110.153");
        assert!(!out.contains("birdo.app"), "hostname: {}", out);
        assert!(!out.contains("185.199.110.153"), "ipv4: {}", out);

        let v6 = sanitize_always("peer 2606:4700:4700::1111 unreachable");
        assert!(!v6.contains("2606:4700:4700::1111"), "ipv6: {}", v6);

        let mail = sanitize_always("login failed for user@example.com");
        assert!(!mail.contains("user@example.com"), "email: {}", mail);

        // WireGuard public keys are 44 chars of base64; the token rule takes
        // any unbroken run of 32+.
        let key = sanitize_always("key xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= rejected");
        assert!(
            !key.contains("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg"),
            "key: {}",
            key
        );
    }

    /// P6-CLI-D-06: no octet of an IPv4 address survives, in the log helper
    /// or the scrubber. The first one used to: a /8, which for a fleet of ten
    /// known relays often names the relay.
    #[test]
    fn an_ipv4_address_keeps_none_of_its_octets() {
        assert_eq!(mask_ip("185.199.110.153"), "x.x.x.x");
        assert_eq!(mask_ip("185.199.110.153:51820"), "x.x.x.x:51820");
        assert_eq!(mask_ip("2001:db8::1"), "2001:x:x:x:x:x:x:x");

        let out = sanitize_always("relay 185.199.110.153:51820 did not answer");
        assert_eq!(out, "relay [redacted-ipv4]:51820 did not answer");
        // Not an address (an octet over 255): left readable.
        assert_eq!(sanitize_always("build 1.4.300.2"), "build 1.4.300.2");
    }

    /// Review of #222 (P3.5): an IPv4 address inside an IPv6 one loses every
    /// octet too. `[::ffff:185.199.110.153]:443` used to come out as
    /// `[[redacted-ipv6].199.110.153]:443`.
    #[test]
    fn an_ipv4_mapped_ipv6_address_keeps_none_of_its_octets() {
        for raw in [
            "connect [::ffff:185.199.110.153]:443 refused",
            "via ::ffff:185.199.110.153 timed out",
            "nat64 64:ff9b::185.199.110.153 unreachable",
        ] {
            let out = sanitize_always(raw);
            for octet in ["185", "199", "110", "153"] {
                assert!(!out.contains(octet), "{octet} survived in {out}");
            }
        }
        assert_eq!(
            sanitize_always("connect [::ffff:185.199.110.153]:443 refused"),
            "connect [[redacted-ipv6]:[redacted-ipv4]]:443 refused"
        );
        assert_eq!(mask_ip("::ffff:185.199.110.153"), ":x:x:x:x:x:x:x");
    }

    /// Review of #222 (P3.6): file names and dotted code identifiers are not
    /// hosts. They used to come out as `[redacted-host]`, which emptied
    /// errors of what made them useful (and crash backtraces of their source
    /// paths), while hosts are still redacted.
    #[test]
    fn file_names_and_code_identifiers_are_not_hosts() {
        for readable in [
            r"Failed to read C:\ProgramData\BirdoVPN\settings.json: access denied",
            "birdo-vpn.exe exited with code 1",
            "Windows.Security.Credentials.UI.UserConsentVerifier failed",
            "System.IO.IOException: The process cannot access the file",
            r"panicked at src\vpn\tunnel.rs:1182:9",
            "tauri.conf.json is missing frontendDist",
        ] {
            assert_eq!(sanitize_always(readable), readable);
        }
        for host in [
            "api.birdo.app",
            "de-fra-01.birdo.app",
            "vpn.example.com",
            "birdo.app",
        ] {
            let out = sanitize_always(&format!("could not reach {host}: timed out"));
            assert_eq!(out, "could not reach [redacted-host]: timed out", "{host}");
        }
    }

    /// Round 3 of the review (P3.5): what round 2 let through. A host is a
    /// host whatever its case or TLD — `.rs`, `.md` and `.zip` are TLDs too,
    /// file extensions only straight after a path separator.
    #[test]
    fn hosts_are_redacted_whatever_their_case_or_tld() {
        for host in [
            "vpn.example.NET",
            "Api.Birdo.App",
            "relay.example.rs",
            "notes.example.md",
            "mirror.example.zip",
        ] {
            let out = sanitize_always(&format!("could not reach {host}: timed out"));
            assert_eq!(out, "could not reach [redacted-host]: timed out", "{host}");
        }
        assert_eq!(
            sanitize_always(r"panicked at src\vpn\tunnel.rs:1182:9"),
            r"panicked at src\vpn\tunnel.rs:1182:9",
            "after a separator, .rs is a file"
        );
    }

    /// Round 3 of the review (P3.5): a home folder names its account. The
    /// name goes, the rest of the path stays readable.
    #[test]
    fn a_home_folder_names_no_one() {
        assert_eq!(
            sanitize_always(r"Failed to open C:\Users\Jane.Doe\AppData\Roaming\birdo: denied"),
            r"Failed to open C:\Users\[redacted-user]\AppData\Roaming\birdo: denied"
        );
        assert_eq!(
            sanitize_always(r"open \\?\c:\users\Jane Doe\x.txt failed"),
            r"open \\?\c:\users\[redacted-user]\x.txt failed"
        );
        assert_eq!(
            sanitize_always("open /Users/jane/Library/Logs/x.log failed"),
            "open /Users/[redacted-user]/Library/Logs/x.log failed"
        );
        assert_eq!(
            sanitize_always("open /home/jane.doe/.config/x.json failed"),
            "open /home/[redacted-user]/.config/x.json failed"
        );
    }

    /// Round 4 of the review (P3-2): a host in a URL is a host, though the
    /// `//` before it is a slash — `.rs` and `.zip` counted as files there —
    /// and a home folder printed with `{:?}` (escaped backslashes, as the PQ
    /// key and device-id errors print their paths) names no one either.
    #[test]
    fn urls_and_escaped_paths_are_redacted_too() {
        assert_eq!(
            sanitize_always("DoH query to https://dns.example.rs/dns-query failed"),
            "DoH query to https://[redacted-host]/dns-query failed"
        );
        assert_eq!(
            sanitize_always("mirror http://mirror.example.zip:8080 refused"),
            "mirror http://[redacted-host]:8080 refused"
        );
        assert_eq!(
            sanitize_always(
                r#"read "C:\\Users\\Jane.Doe\\AppData\\Local\\pq_keypair.json": denied"#
            ),
            r#"read "C:\\Users\\[redacted-user]\\AppData\\Local\\pq_keypair.json": denied"#
        );
        assert_eq!(
            sanitize_always(r#"create "C:\\Users\\Jane\\AppData\\device_id": denied"#),
            r#"create "C:\\Users\\[redacted-user]\\AppData\\device_id": denied"#,
            "a name with no dot is not even a host-looking word"
        );
        // A real path separator still makes .rs a file.
        assert_eq!(
            sanitize_always("open file:///home/dev/src/main.rs failed"),
            "open file:///home/[redacted-user]/src/main.rs failed"
        );
    }

    /// Round 5 of the review (N6): a home folder in a message escaped twice
    /// (`\\\\` between components) names no one either, and a UNC server is
    /// a host even when its name ends in a file extension that is a TLD.
    #[test]
    fn doubly_escaped_home_folders_and_unc_hosts_are_redacted() {
        assert_eq!(
            sanitize_always(r#"save "C:\\\\Users\\\\jdoe\\\\AppData\\\\x.json" failed"#),
            r#"save "C:\\\\Users\\\\[redacted-user]\\\\AppData\\\\x.json" failed"#
        );
        assert_eq!(
            sanitize_always(r"open \\nas.example.zip\share\config.json failed"),
            r"open \\[redacted-host]\share\config.json failed"
        );
        assert_eq!(
            sanitize_always(r#"open "\\\\nas.example.rs\\share" failed"#),
            r#"open "\\\\[redacted-host]\\share" failed"#
        );
        // A file after a separator, however escaped, is still a file.
        for path in [r"src\vpn\tunnel.rs", r"src\\vpn\\tunnel.rs", r"C:\notes.md"] {
            let msg = format!("panicked at {path}:12");
            assert_eq!(sanitize_always(&msg), msg, "{path}");
        }
    }

    /// Round 6 of the review (nit): a file at a drive's root, after a single
    /// backslash that follows a space or a bracket, is a file, not a host.
    #[test]
    fn a_file_after_a_lone_backslash_is_a_file() {
        for msg in [r"open \notes.md failed", r"read (\notes.md) failed"] {
            assert_eq!(sanitize_always(msg), msg);
        }
    }

    /// The point of splitting the two: a message with no address in it comes
    /// through readable, or a crash report is a wall of markers.
    #[test]
    fn sanitize_always_leaves_an_ordinary_message_alone() {
        let msg = "Wintun adapter creation failed: access denied";
        assert_eq!(sanitize_always(msg), msg);
    }
}
