//! Structural regression pins for the desktop client's VERIFIED-CLEAN privacy
//! boundaries. Std-only on purpose: this test target never links the app lib,
//! so — unlike `cargo test --lib`, which dies at process load with 0xC0000139
//! on dev Windows hosts — this binary runs everywhere.
//!
//! P6-CLI-D-09: the panic hook sanitizes the panic message BEFORE the local
//!              log line and the crash file, and the crash file's backtrace is
//!              sanitized too.
//! P6-CLI-D-10: Xray is configured with no access log (loglevel warning only)
//!              and sniffing disabled — no per-connection destination data is
//!              produced client-side.
//! P6-CLI-D-11: the attestation payload is exactly nonce/platform/version/kid
//!              under the domain prefix, and attestation.rs references no
//!              device or hardware fingerprint source.
//!
//! These read the REAL shipped sources from `CARGO_MANIFEST_DIR` at runtime —
//! never a local copy — so the refactor that breaks a promise breaks the test.

use std::fs;
use std::path::PathBuf;

fn src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The body of `fn name` — from its `fn` line to the next item at column zero.
/// Column-zero scanning keeps nested closures/items inside the extracted body.
fn fn_body(source: &str, name: &str) -> String {
    let needle = format!("fn {name}");
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("{needle} not found — the function moved; follow it"));
    let rest = &source[start..];
    let end = rest[needle.len()..]
        .find("\nfn ")
        .or_else(|| rest[needle.len()..].find("\npub fn "))
        .map(|i| i + needle.len())
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

// ── P6-CLI-D-09 ───────────────────────────────────────────────────────────

/// The panic hook must run the message through `sanitize_error` BEFORE the
/// `error!("PANIC …")` log line and BEFORE `write_crash_report`. Reordering —
/// or dropping the call — is exactly the refactor that would put raw panic
/// payloads (IPs, emails, hostnames from error chains) into the local log and
/// crash file.
#[test]
fn panic_hook_sanitizes_before_logging_and_crash_file() {
    let main = src("main.rs");
    let hook = fn_body(&main, "setup_panic_hook");

    let sanitize = hook
        .find("redact::sanitize_error")
        .expect("P6-CLI-D-09 broken: setup_panic_hook no longer sanitizes the panic message");
    let log_line = hook
        .find(r#"error!("PANIC"#)
        .expect("setup_panic_hook no longer logs the panic — the shape changed; re-pin it");
    let crash = hook
        .find("write_crash_report(")
        .expect("setup_panic_hook no longer writes a crash report — the shape changed; re-pin it");

    assert!(
        sanitize < log_line,
        "P6-CLI-D-09 broken: the panic message is logged BEFORE sanitize_error runs"
    );
    assert!(
        sanitize < crash,
        "P6-CLI-D-09 broken: the crash report is written BEFORE sanitize_error runs"
    );
}

/// The crash file's backtrace is sanitized too — backtraces embed absolute
/// paths (which carry the username on Windows) and panic payload fragments.
#[test]
fn crash_report_sanitizes_the_backtrace() {
    let main = src("main.rs");
    let writer = fn_body(&main, "write_crash_report");
    assert!(
        writer.contains("sanitize_error(&backtrace)"),
        "P6-CLI-D-09 broken: write_crash_report no longer sanitizes the backtrace \
         before writing it to the crash file"
    );
}

// ── P6-CLI-D-10 ───────────────────────────────────────────────────────────

/// The Xray config's `log` object must stay exactly `loglevel: warning` — an
/// `access` path is Xray's per-connection destination log, and turning
/// sniffing on makes Xray parse and expose destination domains. This is the
/// text of the real `build_xray_config`; its behavioral twin
/// (`xray_config_has_no_access_log_and_sniffing_stays_disabled`) asserts on
/// the generated JSON and runs in CI where lib tests can execute.
#[test]
fn xray_config_source_has_no_access_log_and_sniffing_disabled() {
    let xray = src("vpn/xray.rs");
    let build = fn_body(&xray, "build_xray_config");

    assert!(
        build.contains(r#""loglevel": "warning""#),
        "P6-CLI-D-10 broken: build_xray_config's log block no longer pins loglevel=warning"
    );
    assert!(
        !build.contains(r#""access""#),
        "P6-CLI-D-10 broken: build_xray_config grew an `access` log — that is a \
         per-connection destination log on the customer's machine"
    );
    let sniff = build
        .find(r#""sniffing""#)
        .expect("P6-CLI-D-10 broken: the inbound lost its explicit sniffing block");
    let after_sniff = &build[sniff..];
    assert!(
        after_sniff.contains(r#""enabled": false"#),
        "P6-CLI-D-10 broken: sniffing is no longer explicitly disabled"
    );
    assert!(
        !build.contains(r#""enabled": true"#),
        "P6-CLI-D-10 broken: something in the Xray config was switched on — \
         if legitimate, prove it produces no per-connection data and re-pin"
    );
}

// ── P6-CLI-D-11 ───────────────────────────────────────────────────────────

/// The attestation payload format string is the whole wire promise: prefix +
/// nonce + platform + version + kid, nothing else. The byte-exact vector test
/// in attestation.rs pins the output; this pins the SOURCE so a new field
/// cannot ride in via a helper. And the module must never grow a device or
/// hardware fingerprint source.
#[test]
fn attestation_module_has_no_fingerprint_source() {
    let attest = src("api/attestation.rs");

    assert!(
        attest.contains(r#"format!("{PAYLOAD_PREFIX}\n{nonce}\n{platform}\n{version}\n{kid}")"#),
        "P6-CLI-D-11 broken: canonical_payload's format string changed — the \
         payload must stay exactly prefix/nonce/platform/version/kid (and the \
         backend verifier must change in lock-step)"
    );

    // Identifiers a hardware/device fingerprint would need. `hostname` etc.
    // appearing even in a comment is worth a conscious re-pin.
    for forbidden in [
        "hostname",
        "machine_uid",
        "machine-id",
        "MachineGuid",
        "sysinfo",
        "whoami",
        "get_mac",
        "serial_number",
        "env::var",
    ] {
        assert!(
            !attest.contains(forbidden),
            "P6-CLI-D-11 broken: attestation.rs mentions `{forbidden}` — the \
             attestation payload must carry no device or hardware fingerprint"
        );
    }
}
