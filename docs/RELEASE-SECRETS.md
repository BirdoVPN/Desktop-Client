# Release signing secrets

This document lists every GitHub Actions secret required for the three
production release pipeline (`release.yml` — one workflow builds and signs
Windows, Linux and macOS from a single `v*` tag; the per-platform
`build-*.yml` files were retired) and how to provision each secret.

> Configure each secret under **Repo -> Settings -> Secrets and variables ->
> Actions -> New repository secret**.

---

## 1. Updater (all three platforms)

The Tauri updater uses minisign to verify the bundle signature on the
client side. The keypair was generated once with `tauri signer generate`.

| Secret | Description |
| ------ | ----------- |
| `TAURI_SIGNING_PRIVATE_KEY` | Contents of `~/.tauri/birdo.key` (multi-line) |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password used at key generation |

The matching public key is hard-coded into
[`src-tauri/tauri.conf.json`](../src-tauri/tauri.conf.json) under
`plugins.updater.pubkey` and **must not** be rotated without also bumping
all installed clients.

---

## 2. Windows — Azure Trusted Signing

| Secret / Variable | Type | Description |
| ----------------- | ---- | ----------- |
| `AZURE_TENANT_ID` | secret | Entra tenant ID |
| `AZURE_CLIENT_ID` | secret | Federated identity client ID |
| `AZURE_TRUSTED_SIGNING_ACCOUNT_NAME` | variable | `Birdo` |
| `AZURE_TRUSTED_SIGNING_ENDPOINT` | variable | `https://neu.codesigning.azure.net/` |
| `AZURE_TRUSTED_SIGNING_CERT_PROFILE` | variable | `BirdoVPNCertProfile` |

Authentication is OIDC-federated, so no client secret is stored — the
GitHub OIDC token is exchanged for an Azure access token at runtime.

---

## 3. macOS — Apple Developer ID + Notarization

Generate the `.p12` from Xcode -> Settings -> Accounts -> Manage Certificates
-> "Developer ID Application" -> right-click -> Export. Then base64-encode:

```bash
base64 -i developer_id.p12 -o developer_id.b64
```

| Secret | Description |
| ------ | ----------- |
| `APPLE_CERTIFICATE` | Contents of `developer_id.b64` |
| `APPLE_CERTIFICATE_PASSWORD` | Export password set in Xcode |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Birdo Ltd (ABCDE12345)` |
| `APPLE_ID` | Apple-ID email account |
| `APPLE_ID_PASSWORD` | App-specific password from <https://appleid.apple.com> -> Sign-In and Security |
| `APPLE_TEAM_ID` | 10-character team identifier |
| `APPLE_KEYCHAIN_PASSWORD` | Random ≥20-char string — used only inside the runner |

When all of the above are present the workflow performs:
1. `codesign` with hardened runtime + entitlements
2. `notarytool submit --wait` (Apple notarization service)
3. `stapler staple` — embeds the notarization ticket into the DMG so the
   user can install offline without contacting Apple.

If `APPLE_CERTIFICATE` is **missing** the workflow gracefully degrades to
an unsigned DMG (Gatekeeper will quarantine — used for dev branches only).

---

## 4. Linux — Sigstore keyless

No secrets required. Sigstore signing uses GitHub's OIDC identity to
issue a short-lived certificate via Fulcio. Verification on the client
side uses `cosign verify-blob` against the published transparency-log
entry.

Optional:

| Secret | Description |
| ------ | ----------- |
| `LINUX_GPG_PRIVATE_KEY` | (future) detached `.asc` signing key for AppImage |
| `LINUX_GPG_KEY_ID` | (future) long-form GPG key ID |

---

## 5. Crash reporting — Sentry

| Secret | Description |
| ------ | ----------- |
| `SENTRY_DSN` | Sentry ingest DSN for the **desktop** project. Consumed at
build time by `option_env!` and compiled into the binary. |

Set at **job** level by every build job in `release.yml`,
the Windows and Linux jobs of `release.yml`. Unlike every other secret here,
a **missing** one now FAILS the release build (`src-tauri/build.rs`) rather
than degrading quietly — an artifact that cannot report a crash is worse
than a build that stops.

It must be the DSN of the desktop project, not the Android
(`4510869977497680`) or backend (`4510932258390096`) one: mixed crash
streams cannot be un-mixed after the fact. Full click path, verification
and privacy posture in
[`docs/SENTRY-SETUP.md`](SENTRY-SETUP.md).

---

## 6. Client attestation — Ed25519 signer (a tagged build HARD-FAILS without these)

| Secret | Description |
| ------ | ----------- |
| `BIRDO_DESKTOP_ATTEST_SK` | Raw Ed25519 **private** key, base64. Compiled into the binary and used to sign the connect attestation. |
| `BIRDO_DESKTOP_ATTEST_KID` | Key id for the above, matched against `DESKTOP_ATTESTATION_PUBKEYS` on the backend. |

Both are read at **job** level by every platform job in `release.yml`
(Windows, macOS ×2, Linux) and each job asserts them explicitly:

```
if (-not $env:BIRDO_DESKTOP_ATTEST_SK) { throw "… a tagged release cannot ship unattestable" }
```

So a `refs/tags/v*` build **fails on all three platforms** if either is
missing — which is the intended behaviour, and exactly why they must be
documented here. This file omitted them entirely until 2026-09-14
(OPEN-WORK J10).

The public half goes into the backend's `DESKTOP_ATTESTATION_PUBKEYS` as
`kid:base64pub`. That list is comma-separated so a new release line's key can
be added **before** the old one is dropped — rotate in that order, never the
reverse, or in-flight clients signed with the old key are rejected. Ladder and
semantics: [`docs/CLIENT-ATTESTATION.md`](CLIENT-ATTESTATION.md) here and
`birdo-web/docs/CLIENT-ATTESTATION.md` for the server side.

---

## Local rotation procedure

1. Generate the new credential per the section above.
2. Open <https://github.com/birdo-vpn/desktop/settings/secrets/actions>.
3. Update the secret value (the secret name stays the same).
4. Trigger a `workflow_dispatch` run of the relevant build to verify.
5. Record the rotation in this file's table below. `birdo-shared/SECURITY-LOG.md`
   — which step 5 named until 2026-09-14 — **does not exist in any repo**, so
   every rotation recorded "there" went nowhere (OPEN-WORK J10).

### Rotation log

Append one line per rotation. Secret **names** only, never values.

| Date | Secret | Reason | By |
| ---- | ------ | ------ | -- |
| 2026-09-14 | — | Log created; no rotation. Prior rotations were recorded in a file that did not exist. | — |
