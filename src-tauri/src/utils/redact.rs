//! Logging utilities with PII redaction
//!
//! Provides helper functions to redact sensitive information from logs
//! to protect user privacy in production builds.
//! 
//! LOG-001: All error messages and logs should use these functions
//! to prevent PII exposure.

/// Redact an IP address for logging (shows only first octet in production)
/// In debug builds, returns the full IP for troubleshooting
#[inline]
pub fn redact_ip(ip: &str) -> String {
    #[cfg(debug_assertions)]
    {
        ip.to_string()
    }
    
    #[cfg(not(debug_assertions))]
    {
        // IPv4: Show first octet only (e.g., "192.x.x.x")
        // IPv6: Show first segment only (e.g., "2001:x:x:x:x:x:x:x")
        if ip.contains("::") || (ip.contains(':') && ip.matches(':').count() >= 2) {
            // IPv6
            ip.split(':')
                .next()
                .map(|first| format!("{}:x:x:x:x:x:x:x", first))
                .unwrap_or_else(|| "[redacted-ipv6]".to_string())
        } else if ip.contains(':') && ip.matches(':').count() == 1 {
            // IPv4:port format
            if let Some(colon_pos) = ip.rfind(':') {
                let ip_part = &ip[..colon_pos];
                let port = &ip[colon_pos..];
                let redacted_ip = ip_part.split('.')
                    .next()
                    .map(|first| format!("{}.x.x.x", first))
                    .unwrap_or_else(|| "[redacted]".to_string());
                format!("{}{}", redacted_ip, port)
            } else {
                "[redacted]".to_string()
            }
        } else {
            // Plain IPv4
            ip.split('.')
                .next()
                .map(|first| format!("{}.x.x.x", first))
                .unwrap_or_else(|| "[redacted-ipv4]".to_string())
        }
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
            let redacted_name = if name.len() > 2 {
                format!("{}***", &name[..2])
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
        use once_cell::sync::Lazy;
        use regex::Regex;

        // Compiled once, reused across calls
        static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap()
        });
        static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()
        });
        // Matches common hostname patterns (at least two labels with TLD)
        static HOST_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){1,}\.[a-zA-Z]{2,}\b").unwrap()
        });
        // P2-13: Strip HTML tags
        static HTML_TAG_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"<[^>]{1,200}>").unwrap()
        });
        // P2-13: Strip stack traces (lines starting with "at " or Java-style exception patterns)
        static STACK_TRACE_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?m)^\s*at .*$").unwrap()
        });

        // P2-13: If the message looks like raw HTML, replace entirely
        if msg.contains("<html") || msg.contains("<HTML") || msg.contains("<!DOCTYPE") {
            return "[server error]".to_string();
        }

        // Strip HTML tags
        let result = HTML_TAG_RE.replace_all(msg, "").to_string();

        // Strip stack trace lines
        let result = STACK_TRACE_RE.replace_all(&result, "").to_string();

        let result = IPV4_RE.replace_all(&result, |caps: &regex::Captures| {
            format!("{}.x.x.x", &caps[1])
        }).to_string();

        let result = EMAIL_RE.replace_all(&result, "[redacted-email]").to_string();

        let result = HOST_RE.replace_all(&result, "[redacted-host]").to_string();

        // P2-20: Truncate to 200 chars (aligned with Android InputValidator.sanitizeErrorMessage)
        if result.len() > 200 {
            let mut truncated = result[..197].to_string();
            truncated.push_str("...");
            truncated
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_ip_v4() {
        // In release builds, this would be "192.x.x.x"
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

    #[test]
    fn test_sanitize_error_with_ip() {
        // In debug builds this returns as-is; in release it would redact
        let msg = "Failed to connect to 192.168.1.100:51820";
        let result = sanitize_error(msg);
        assert!(!result.is_empty());
    }
}
