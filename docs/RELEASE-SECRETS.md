# Release signing secrets

This document lists every GitHub Actions secret required for the three
production release pipelines (`build-windows.yml`, `build-macos.yml`,
`build-linux.yml`) and how to provision each one.

> Configure each secret under **Repo → Settings → Secrets and variables →
> Actions → New repository secret**.

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

Generate the `.p12` from Xcode → Settings → Accounts → Manage Certificates
→ "Developer ID Application" → right-click → Export. Then base64-encode:

```bash
base64 -i developer_id.p12 -o developer_id.b64
```

| Secret | Description |
| ------ | ----------- |
| `APPLE_CERTIFICATE` | Contents of `developer_id.b64` |
| `APPLE_CERTIFICATE_PASSWORD` | Export password set in Xcode |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Birdo Ltd (ABCDE12345)` |
| `APPLE_ID` | Apple-ID email account |
| `APPLE_ID_PASSWORD` | App-specific password from <https://appleid.apple.com> → Sign-In and Security |
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

## Local rotation procedure

1. Generate the new credential per the section above.
2. Open <https://github.com/birdo-vpn/desktop/settings/secrets/actions>.
3. Update the secret value (the secret name stays the same).
4. Trigger a `workflow_dispatch` run of the relevant build to verify.
5. Record the rotation in `birdo-shared/SECURITY-LOG.md`.
