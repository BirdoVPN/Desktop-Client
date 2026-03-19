# Code Signing with Sigstore

## Overview

Birdo VPN uses [Sigstore](https://www.sigstore.dev/) for keyless code signing.
Since all clients are open-source, Sigstore provides **free, transparent, verifiable
signatures** tied to our GitHub Actions CI — no paid certificates required.

Every release artifact (`.exe`, `.msi`, `.dmg`) is signed with `cosign sign-blob` using
GitHub's OIDC identity token. This produces a `.sigstore` bundle containing:

- A **Fulcio certificate** proving the artifact was built by GitHub Actions from this repo
- A **Rekor transparency log entry** — a tamper-proof public record of the signing event

## How It Works

```
GitHub Actions triggers → Tauri builds installers
  → cosign sign-blob --yes --bundle <file>.sigstore <file>
    → Fulcio issues short-lived cert (GitHub OIDC identity)
    → Signature recorded in Rekor transparency log
    → .sigstore bundle attached to GitHub Release
```

No private keys to manage. No certificates to purchase or renew.

## What Users See

### Windows SmartScreen

Sigstore does **not** replace Windows Authenticode. Windows users will still see:

1. **SmartScreen:** "Windows protected your PC" → click "More info" → "Run anyway"
2. **UAC prompt:** "Unknown publisher" (yellow shield)

This is normal for open-source software. The Sigstore signature lets users
**cryptographically verify** the download came from our CI — something SmartScreen
can't tell them.

### macOS Gatekeeper

macOS users will see a Gatekeeper warning for unsigned apps. To bypass:
1. Right-click → Open → "Open" (first launch only)
2. Or: System Settings → Privacy & Security → "Open Anyway"

If macOS code signing (Apple Developer ID) becomes needed, it can be layered
on top of Sigstore in the `build-macos.yml` workflow.

### Why Not Authenticode?

Traditional Authenticode OV certificates ($60–500/year) require identity verification
and annual renewal. Sigstore is free, automated, and provides **stronger provenance
guarantees** — you can verify exactly which repo, commit, and workflow produced a binary.

If SmartScreen warnings become a user adoption issue, we can layer Authenticode on top
later (the workflow supports it as an optional step).

## Verifying Signatures

Users can verify any release artifact with:

```bash
# Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/
cosign verify-blob \
  --bundle BirdoVPN-Setup-1.0.0.exe.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/BirdoVPN/" \
  BirdoVPN-Setup-1.0.0.exe
```

See [VERIFICATION.md](./VERIFICATION.md) for detailed instructions.

## CI Configuration

The `build-windows.yml` and `build-macos.yml` workflows handle signing automatically:

| Trigger | Action |
|---------|--------|
| Push tag `win-v*` | Build Windows + Sigstore sign + draft GitHub Release |
| Push tag `mac-v*` | Build macOS (arm64 + x64) + Sigstore sign + upload artifacts |
| Manual dispatch | Build + Sigstore sign + upload artifacts |

### Required GitHub Settings

1. **Repository Settings → Actions → General:**
   - Under "Workflow permissions", the `id-token: write` permission must be allowed
   - This is set per-job in the workflow file

2. **Secrets** (for Tauri updater signing, separate from Sigstore):

| Secret | Purpose |
|--------|---------|
| `TAURI_SIGNING_PRIVATE_KEY` | Minisign key for Tauri updater signatures |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password for the minisign key |

No Sigstore-specific secrets needed — it uses GitHub's built-in OIDC.

## Release Artifacts

Each release includes:

| File | Purpose |
|------|---------|
| `BirdoVPN-Setup-X.Y.Z.exe` | NSIS installer (Windows) |
| `BirdoVPN-Setup-X.Y.Z.exe.sigstore` | Sigstore signature bundle |
| `BirdoVPN-X.Y.Z.msi` | MSI installer (Windows) |
| `BirdoVPN-X.Y.Z.msi.sigstore` | Sigstore signature bundle |
| `BirdoVPN-X.Y.Z.dmg` | DMG installer (macOS) |
| `BirdoVPN-X.Y.Z.dmg.sigstore` | Sigstore signature bundle |
| `SHA256SUMS.txt` | Checksums for all artifacts |
| `SHA256SUMS.txt.sigstore` | Signed checksums |

## References

- [Sigstore](https://www.sigstore.dev/)
- [Cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [GitHub OIDC for Sigstore](https://docs.sigstore.dev/cosign/signing/signing_with_github_actions/)
- [Rekor Transparency Log](https://docs.sigstore.dev/logging/overview/)
- [Tauri v2 Code Signing — Windows](https://v2.tauri.app/distribute/sign/windows/)
- [Tauri v2 Code Signing — macOS](https://v2.tauri.app/distribute/sign/macos/)
