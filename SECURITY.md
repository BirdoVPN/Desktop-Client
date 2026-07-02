# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the BirdoVPN desktop client, **please
do not open a public GitHub issue**. Report it privately so we can fix it before
disclosure.

### Preferred channel

Use GitHub's private vulnerability reporting:

> Repository → **Security** tab → **Report a vulnerability**

### Alternate channel

Email: **security@birdo.app** (PGP key available on request).

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, ideally with a minimal proof-of-concept.
- Affected version(s) / commit hash(es).
- Whether you are willing to be credited in the public disclosure.

### What to expect

| Stage              | Target time            |
| ------------------ | ---------------------- |
| Acknowledgement    | Within 48 hours        |
| Initial assessment | Within 7 days          |
| Patch development  | Severity-dependent     |
| Public disclosure  | After patch is shipped |

We follow a 90-day coordinated-disclosure window by default, and may request an
extension for complex issues. We will keep you informed throughout.

## Supported Versions

Only the **latest released version** (the `Latest` GitHub Release) receives
security fixes. The built-in updater delivers signed updates automatically.

## Scope

In scope:

- Source code under this repository (`src/` TypeScript UI, `src-tauri/` Rust
  core — tunnel, kill switch, cert pinning, credential storage, IPC).
- The CI/CD workflows under `.github/workflows/`.
- The update channel (Tauri updater manifest + signature verification).
- Installers and update packages published on GitHub Releases.

Out of scope (please report to the appropriate vendor/repository):

- Vulnerabilities in third-party dependencies (report upstream first; we bump
  versions promptly once a patch is released).
- Backend APIs / server infrastructure (separate repository).
- Issues requiring an already-compromised machine (local admin/root attacker).
- Denial of service against your own device.

## Hardening Practices

This client is built with defence-in-depth:

- **TLS certificate pinning** — API traffic pins the CA-chain SPKI (SHA-256)
  inside the TLS handshake, layered on top of full WebPKI validation, with a
  cross-CA backup pin. A daily CI watchdog verifies the live chain still
  matches the pins.
- **Credential storage** — auth tokens live in the OS credential store
  (Windows Credential Manager / macOS Keychain / Secret Service) via the
  `keyring` crate, wrapped in `Zeroizing` so old values are wiped from memory.
  WireGuard key material is zeroized after session creation and never
  persisted.
- **Signed releases** — Windows binaries are Authenticode-signed via Azure
  Trusted Signing (OIDC, no stored keys), every artifact gets a Sigstore
  keyless attestation, and auto-updates are verified with the Tauri
  (minisign) updater signature. See [docs/VERIFICATION.md](docs/VERIFICATION.md)
  to verify downloads yourself.
- **Supply-chain pinning** — bundled binaries (Wintun, Xray) are fetched at
  build time and verified against pinned SHA-256 hashes before bundling; the
  client re-verifies the Xray binary hash before every execution. All GitHub
  Actions are pinned to commit SHAs. `Cargo.lock`/`package-lock.json` are
  committed; `cargo deny` (advisories/licenses/bans/sources) and CodeQL run
  on a schedule and on every PR.
- **Strict runtime policy** — Tauri CSP locked to `'self'` + `*.birdo.app`,
  no `unsafe-eval`, shell-open allowlisted to Birdo domains by regex,
  HTTPS-only HTTP client, DNS-over-HTTPS fallback resolver.
- **Kill switch** — Windows Filtering Platform native filters added in a
  single atomic transaction (with equivalent pf/iptables implementations on
  macOS/Linux).
- **Log hygiene** — production logs redact IPs and sanitise panic messages;
  private keys and tokens are never logged.

Thank you for helping keep BirdoVPN users safe.
