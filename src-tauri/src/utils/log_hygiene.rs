//! Compile-time-adjacent guard: no address-shaped value reaches a logging macro
//! without passing through a redactor.
//!
//! WHY A SOURCE SCAN. The redaction controls in this crate keep drifting apart
//! one platform at a time — the estate's signature defect shape. `redact_ip` was
//! applied on the Linux and macOS tunnel paths and missed on the Windows one
//! (`tunnel.rs`); `redact_endpoint` was applied at two of five sites in
//! `wireguard_new.rs`; the WFP kill switch logged the exit node raw while
//! `commands/killswitch.rs`, doing the same job, logged only whether one was
//! set. Every one of those was a `#[cfg(target_os = ...)]` sibling of a line
//! that was already correct, so no compiler and no single-platform test run can
//! see the pair. A text scan over the whole `src/` tree can, because it reads
//! every platform's code on every platform's CI.
//!
//! WHAT IT ENFORCES. Inside the argument list of `trace!/debug!/info!/warn!/
//! error!` (with or without the `tracing::` prefix), no identifier whose name
//! ends in `_ip`/`ip`, `_addr`/`addr`, `_address`, `_endpoint`/`endpoint`,
//! `_gateway`, `_host`/`host` or `_hostname` may appear as a VALUE unless it is
//! inside a `redact_*`/`sanitize_*` call, or is only tested for presence
//! (`.is_some()`/`.is_none()`). String literals and comments are stripped first,
//! so prose and format strings never trip it.
//!
//! The check deliberately covers `debug!` too. "Debug never ships" was the
//! stated reason several raw values were left in place, and `RUST_LOG` made that
//! untrue; `main.rs` now clamps the on-disk log, and this guard closes the other
//! half so the console cannot carry a raw value into a screenshot either.
//! `utils::redact` is a pass-through under `debug_assertions`, so complying
//! costs a developer nothing.

use std::path::{Path, PathBuf};

/// Identifier suffixes that name an address-shaped value.
const SENSITIVE_SUFFIXES: &[&str] = &[
    "ip",
    "ips",
    "addr",
    "address",
    "endpoint",
    "endpoints",
    "gateway",
    // `gw` is how the gateway is actually spelled at most call sites in this
    // crate (`default_gw` in tunnel_linux.rs and tunnel_macos.rs). Without it
    // the guard silently exempted the very identifier the "gateway" entry was
    // written for.
    "gw",
    "host",
    "hostname",
];

/// The logging macros whose arguments are scanned.
const LOG_MACROS: &[&str] = &["trace", "debug", "info", "warn", "error"];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Does `name` end in one of the sensitive suffixes, at a `_` boundary or as the
/// whole identifier? `client_ip` and `ip` match; `pinning` and `chip` do not.
fn names_an_address(name: &str) -> bool {
    SENSITIVE_SUFFIXES.iter().any(|suffix| {
        name == *suffix
            || (name.len() > suffix.len() + 1
                && name.ends_with(suffix)
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'_')
    })
}

/// Advance past a Rust string literal (plain or raw) that starts at `bytes[i]`.
/// Returns the index just past the closing quote.
fn skip_string(bytes: &[u8], i: usize) -> usize {
    // Raw string: r"..." / r#"..."# / r##"..."## ...
    if bytes[i] == b'r' {
        let mut hashes = 0usize;
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] == b'#' {
            hashes += 1;
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'"' {
            let mut k = j + 1;
            while k < bytes.len() {
                if bytes[k] == b'"' {
                    let mut closing = 0usize;
                    while closing < hashes && k + 1 + closing < bytes.len() {
                        if bytes[k + 1 + closing] != b'#' {
                            break;
                        }
                        closing += 1;
                    }
                    if closing == hashes {
                        return k + 1 + hashes;
                    }
                }
                k += 1;
            }
            return bytes.len();
        }
        return i + 1; // a bare `r` identifier, not a raw string
    }

    // Plain string: "..." with backslash escapes.
    let mut k = i + 1;
    while k < bytes.len() {
        if bytes[k] == b'\\' {
            k += 2;
            continue;
        }
        if bytes[k] == b'"' {
            return k + 1;
        }
        k += 1;
    }
    bytes.len()
}

/// Is `bytes[i] == '\''` the start of a char literal (rather than a lifetime)?
fn char_literal_end(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i + 1) == Some(&b'\\') {
        let mut k = i + 2;
        while k < bytes.len() && bytes[k] != b'\'' {
            k += 1;
        }
        return Some((k + 1).min(bytes.len()));
    }
    if bytes.get(i + 2) == Some(&b'\'') {
        return Some(i + 3);
    }
    None
}

/// Replace every comment, string literal and char literal in `src` with spaces,
/// leaving all other bytes (and therefore every byte offset) untouched.
fn blank_comments_and_literals(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = src[i..]
                    .find("*/")
                    .map(|p| i + p + 2)
                    .unwrap_or(bytes.len());
                for slot in out.iter_mut().take(end).skip(i) {
                    if *slot != b'\n' {
                        *slot = b' ';
                    }
                }
                i = end;
            }
            b'"' => {
                let end = skip_string(bytes, i);
                for slot in out.iter_mut().take(end).skip(i) {
                    if *slot != b'\n' {
                        *slot = b' ';
                    }
                }
                i = end;
            }
            b'r' if !(i > 0 && is_ident_char(bytes[i - 1] as char)) => {
                let end = skip_string(bytes, i);
                if end > i + 1 {
                    for slot in out.iter_mut().take(end).skip(i) {
                        if *slot != b'\n' {
                            *slot = b' ';
                        }
                    }
                    i = end;
                } else {
                    i += 1;
                }
            }
            b'\'' => {
                if let Some(end) = char_literal_end(bytes, i) {
                    for slot in out.iter_mut().take(end.min(bytes.len())).skip(i) {
                        if *slot != b'\n' {
                            *slot = b' ';
                        }
                    }
                    i = end;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A raw value that reached a logging macro.
#[derive(Debug)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub ident: String,
    pub snippet: String,
}

/// Scan one file's source text. `blanked` must be `blank_comments_and_literals`
/// of the same text (same length, same offsets).
fn scan_source(file: &str, src: &str) -> Vec<Finding> {
    let blanked = blank_comments_and_literals(src);
    let b = blanked.as_bytes();
    let mut findings = Vec::new();
    let mut i = 0usize;

    while i < b.len() {
        if b[i] != b'!' {
            i += 1;
            continue;
        }
        // `!` then optional whitespace then `(`
        let mut open = i + 1;
        while open < b.len() && (b[open] as char).is_whitespace() {
            open += 1;
        }
        if open >= b.len() || b[open] != b'(' {
            i += 1;
            continue;
        }
        // Walk back over the macro path to its last segment.
        let mut start = i;
        while start > 0 && is_ident_char(b[start - 1] as char) {
            start -= 1;
        }
        let name = &blanked[start..i];
        if !LOG_MACROS.contains(&name) {
            i += 1;
            continue;
        }

        // Extract the balanced argument list.
        let mut depth = 0usize;
        let mut j = open;
        let mut close = b.len();
        while j < b.len() {
            match b[j] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = j;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let args = &blanked[open + 1..close.min(blanked.len())];
        let line = blanked[..start].matches('\n').count() + 1;

        findings.extend(scan_args(file, line, args));
        i = close.saturating_add(1);
    }

    findings
}

/// Flag every sensitive identifier in one macro's (already blanked) argument
/// list that is not routed through a redactor.
fn scan_args(file: &str, line: usize, args: &str) -> Vec<Finding> {
    let bytes = args.as_bytes();
    let mut findings = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if !is_ident_char(bytes[i] as char) || bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if i > 0 && is_ident_char(bytes[i - 1] as char) {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < bytes.len() && is_ident_char(bytes[end] as char) {
            end += 1;
        }
        let ident = &args[i..end];
        if !names_an_address(ident) {
            i = end;
            continue;
        }

        let after = &args[end..];

        // A call, not a value: `redact_ip(...)` is itself named `..._ip`.
        if after.trim_start().starts_with('(') {
            i = end;
            continue;
        }
        // A presence test discloses nothing.
        if after.starts_with(".is_some()") || after.starts_with(".is_none()") {
            i = end;
            continue;
        }
        // Inside a `redact_*(` / `sanitize_*(` call: walk back over the path
        // expression (`&self.config.client_ip`) and check what opened it.
        if opened_by_redactor(args, i) {
            i = end;
            continue;
        }
        // The rest of THIS argument routes the value through a redactor, e.g.
        // `snapshot.default_gateway.as_deref().map(|s| redact_ip(s))`.
        let rest = rest_of_argument(after);
        if rest.contains("redact") || rest.contains("sanitize") {
            i = end;
            continue;
        }

        findings.push(Finding {
            file: file.to_string(),
            line,
            ident: ident.to_string(),
            snippet: args.split_whitespace().collect::<Vec<_>>().join(" "),
        });
        i = end;
    }

    findings
}

/// Is the identifier starting at `idx` the argument of a `redact_*`/`sanitize_*`
/// call?
fn opened_by_redactor(args: &str, idx: usize) -> bool {
    let b = args.as_bytes();
    let mut j = idx;
    // back over the path expression: `self.config.client_ip`, `crate::x::y`
    while j > 0 && (is_ident_char(b[j - 1] as char) || b[j - 1] == b'.' || b[j - 1] == b':') {
        j -= 1;
    }
    // back over borrows/derefs/whitespace
    while j > 0 && matches!(b[j - 1], b'&' | b'*' | b' ' | b'\t' | b'\n' | b'\r') {
        j -= 1;
    }
    if j == 0 || b[j - 1] != b'(' {
        return false;
    }
    let mut k = j - 1;
    let call_end = k;
    while k > 0 && (is_ident_char(b[k - 1] as char) || b[k - 1] == b':') {
        k -= 1;
    }
    let callee = &args[k..call_end];
    let last = callee.rsplit("::").next().unwrap_or(callee);
    last.starts_with("redact") || last.starts_with("sanitize")
}

/// The remainder of the current top-level macro argument (up to the next comma
/// at bracket depth zero).
fn rest_of_argument(after: &str) -> &str {
    let mut depth = 0i32;
    for (idx, c) in after.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return &after[..idx],
            _ => {}
        }
    }
    after
}

/// Every `.rs` file under `src/`, except this guard's own source (its literals
/// name the very macros and identifiers it looks for).
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().is_some_and(|n| n != "log_hygiene.rs")
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE GUARD. Every address-shaped value in every logging macro in the tree,
    /// on every platform's code, must pass through a redactor.
    #[test]
    fn no_unredacted_address_reaches_a_logging_macro() {
        let files = source_files();
        assert!(
            files.len() > 10,
            "source walk found only {} files — the guard is not scanning the tree",
            files.len()
        );

        let mut findings = Vec::new();
        for path in &files {
            let src = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
            let rel = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(path)
                .display()
                .to_string()
                .replace('\\', "/");
            findings.extend(scan_source(&rel, &src));
        }

        if !findings.is_empty() {
            let report = findings
                .iter()
                .map(|f| format!("  {}:{}  `{}` in: {}", f.file, f.line, f.ident, f.snippet))
                .collect::<Vec<_>>()
                .join("\n");
            panic!(
                "{} address-shaped value(s) reach a logging macro unredacted.\n\
                 Wrap each in utils::redact_ip / redact_endpoint / redact_hostname \
                 (they are pass-throughs in debug builds, so local diagnosis is unaffected):\n{}",
                findings.len(),
                report
            );
        }
    }

    // ── the scanner itself ───────────────────────────────────────────────

    #[test]
    fn flags_a_bare_address_argument() {
        let src = r#"fn f() { tracing::debug!("Configuring adapter IP: {}", client_ip); }"#;
        let hits = scan_source("t.rs", src);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].ident, "client_ip");
    }

    #[test]
    fn accepts_a_redacted_argument() {
        let src =
            r#"fn f() { tracing::debug!("Configuring adapter IP: {}", redact_ip(client_ip)); }"#;
        assert!(scan_source("t.rs", src).is_empty());
    }

    #[test]
    fn accepts_a_redacted_path_expression() {
        let src = r#"fn f() { tracing::debug!("{} {}",
            crate::utils::redact_endpoint(&self.config.endpoint),
            crate::utils::redact_ip(&config.client_ip)); }"#;
        assert!(scan_source("t.rs", src).is_empty());
    }

    #[test]
    fn accepts_a_redactor_reached_through_a_method_chain() {
        let src = r#"fn f() { tracing::info!("{:?}",
            snapshot.default_gateway.as_deref().map(|s| redact_ip(s))); }"#;
        assert!(scan_source("t.rs", src).is_empty());
    }

    /// The on-disk log level clamp must stay WIRED, not merely exist.
    ///
    /// `log_policy::file_log_max_level()` is what keeps `debug!` off disk in a
    /// release build, and it is the reason the module docs above can claim the
    /// console guard closes "the other half". But the wiring lives in `main.rs`,
    /// i.e. in the BIN target, which CI's `cargo test --lib` never compiles — so
    /// no ordinary unit test can reach it, and deleting the `.with_filter(...)`
    /// would leave every test green while release builds quietly wrote raw
    /// addresses to disk again.
    ///
    /// This is a text-level assertion, which is weaker than executing the code.
    /// It is the same technique this module already uses for the cross-platform
    /// redaction problem, it costs nothing, and it fails on exactly the mutation
    /// that matters: removing the filter from the file layer.
    #[test]
    fn the_on_disk_log_clamp_is_still_wired_into_main() {
        let main_rs = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("main.rs");
        let src = std::fs::read_to_string(&main_rs)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", main_rs.display()));

        assert!(
            src.contains("log_policy::file_log_max_level"),
            "main.rs no longer applies log_policy::file_log_max_level() to the file              layer. Without it the on-disk log falls back to the subscriber's level,              so a release build can persist debug-level records — including the              address-shaped values this module's guard exists to keep out of logs."
        );
    }

    #[test]
    fn accepts_a_presence_test() {
        let src = r#"fn f() { tracing::debug!("VPN server IP {}",
            if ip.is_some() { "set" } else { "cleared" }); }"#;
        assert!(scan_source("t.rs", src).is_empty());
    }

    #[test]
    fn ignores_the_format_string_and_comments() {
        // Both mention client_ip and endpoint; neither is a value.
        let src = r#"fn f() {
            // endpoint and client_ip are both sensitive
            tracing::info!("Tunnel config: endpoint={}, client_ip={}", a, b);
        }"#;
        assert!(scan_source("t.rs", src).is_empty());
    }

    #[test]
    fn ignores_non_logging_macros() {
        let src = r#"fn f() { let s = format!("{}", client_ip); }"#;
        assert!(scan_source("t.rs", src).is_empty());
    }

    #[test]
    fn flags_a_nested_format_inside_a_log_macro() {
        let src = r#"fn f() { tracing::warn!("{}", format!("to {}", endpoint_ip)); }"#;
        let hits = scan_source("t.rs", src);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].ident, "endpoint_ip");
    }

    #[test]
    fn suffix_rule_does_not_match_a_coincidental_ending() {
        assert!(names_an_address("client_ip"));
        assert!(names_an_address("ip"));
        assert!(names_an_address("default_gateway"));
        assert!(names_an_address("local_addr"));
        assert!(!names_an_address("chip"));
        assert!(!names_an_address("pinning"));
        assert!(!names_an_address("ghost"));
        assert!(!names_an_address("skip"));
    }

    #[test]
    fn reports_the_line_of_the_macro() {
        let src = "fn f() {\n    let x = 1;\n    tracing::debug!(\"{}\", client_ip);\n}\n";
        let hits = scan_source("t.rs", src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 3);
    }
}
