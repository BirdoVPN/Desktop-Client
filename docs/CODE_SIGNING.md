# Code Signing

> **What is actually signed today (checked 2026-09-29 against `release.yml`):**
> - **Windows:** tag builds are Authenticode-signed through Azure Trusted Signing
>   (see `azure-trusted-signing-setup.md`).
> - **Every release:** one `SHA256SUMS.txt` over all installers and packages, plus
>   one Sigstore bundle (`SHA256SUMS.txt.sigstore`) signing it. There are no
>   per-file `.sigstore` bundles any more. Verify: [VERIFICATION.md](./VERIFICATION.md).
> - **macOS (Tauri DMG/app):** **unsigned and un-notarised.** There is no Apple
>   Developer account, so the job always takes the unsigned path. Gatekeeper
>   will warn. Signing and notarising it, or no longer shipping it, is an open
>   owner decision (audit D-22).
> - **Linux:** covered by the checksums file and its Sigstore bundle only.
> - **PGP:** no release artefact is PGP-signed.
>
> The body below was rewritten to this list on 2026-10-08 (MR-1369). It used to
> describe a Sigstore-only setup that signed every artefact with its own
> `.sigstore` bundle.

## Overview

A tagged release carries three kinds of signature. Each does a different job,
and none of them stands in for another:

| Signature | Over | Checked by |
|---|---|---|
| **Authenticode** (Azure Trusted Signing) | the Windows installer and the binaries it installs (`BirdoVPN.exe`, `xray.exe`) | Windows itself, at download and at the UAC prompt |
| **Tauri updater signature** (`.sig`, minisign) | each updater bundle: the Windows setup `.exe`, the AppImage, the macOS `.app.tar.gz` | the installed app, against `plugins.updater.pubkey`, before it installs an update |
| **Sigstore** (cosign keyless) | **one** file, `SHA256SUMS.txt`, which lists every release asset except the `.sig` files | anyone, by hand: [VERIFICATION.md](./VERIFICATION.md) |

Sigstore signs no installer directly. The release job writes `SHA256SUMS.txt`
over the final asset names and signs that one file with `cosign sign-blob`,
using GitHub's OIDC identity token. That produces `SHA256SUMS.txt.sigstore`, a
bundle containing:

- A **Fulcio certificate** proving the checksums file was signed by this repo's
  `release.yml`, at the release tag
- A **Rekor transparency log entry** — a tamper-proof public record of the signing event

So a download is verified in two steps: the bundle against `SHA256SUMS.txt`,
then the download against its line in `SHA256SUMS.txt`. Because the client
source is public (source-available, CC BY-NC 4.0 — not an OSI open-source
licence), anyone can tie a download to the workflow run that built it.

## How It Works

```
Push tag v* → release.yml (test gate first)
  → Windows: xray.exe signed (Authenticode) → Tauri build signs BirdoVPN.exe
             and the NSIS installer (Authenticode) → updater .sig (minisign)
  → Linux:   Tauri build → AppImage + .deb → updater .sig for the AppImage
  → macOS:   Tauri build, unsigned and un-notarised → DMGs + .app.tar.gz → updater .sig
  → release job: every updater .sig verified against plugins.updater.pubkey
                 (tauri.conf.json); any mismatch and nothing is published
    → SHA256SUMS.txt over every asset except the .sig files
    → cosign sign-blob --yes --bundle SHA256SUMS.txt.sigstore SHA256SUMS.txt
      → Fulcio issues a short-lived cert (GitHub OIDC identity)
      → the signature is recorded in the Rekor transparency log
    → SHA256SUMS.txt + SHA256SUMS.txt.sigstore published with the assets
```

No Sigstore key to manage. The Authenticode certificate is issued per run by
Azure Trusted Signing (`azure-trusted-signing-setup.md`); the updater key is a
minisign key held in the repository secrets (below). A manual dispatch builds
unsigned binaries and no Sigstore bundle: only a tag's release job signs.

## What Users See

### Windows SmartScreen

Tag builds are Authenticode-signed with a PublicTrust certificate, so
SmartScreen and the UAC prompt name the verified publisher rather than
"Unknown publisher". If SmartScreen still warns, see the troubleshooting
table in `azure-trusted-signing-setup.md`. The Sigstore bundle answers a
different question, which neither prompt can: whether the download is the
file this repo's release workflow built at that tag.

### macOS Gatekeeper

The macOS build is unsigned and un-notarised, so macOS users will see a
Gatekeeper warning. To bypass:
1. Right-click -> Open -> "Open" (first launch only)
2. Or: System Settings -> Privacy & Security -> "Open Anyway"

If macOS code signing (Apple Developer ID) becomes needed, it goes into the
macOS job of `release.yml`; the Sigstore step is unchanged by it.

### Authenticode and Sigstore

Authenticode is what Windows checks: without it the UAC prompt says "Unknown
publisher". Sigstore is what a person checks: it ties the published checksums
to the exact repository, workflow and tag that produced them. Releases carry
both, and Linux and macOS have only the second.

## Verifying Signatures

Users can verify any release artifact with:

```bash
# Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/
# Pin the signer to THIS repo's release workflow at THIS tag (vX.Y.Z).
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/BirdoVPN/Desktop-Client/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt --ignore-missing
```

See [VERIFICATION.md](./VERIFICATION.md) for detailed instructions.

## CI Configuration

The `release.yml` workflow (the single release pipeline; the per-platform
`build-*.yml` files were retired) handles signing automatically:

| Trigger | Action |
|---------|--------|
| Push tag `v*` (e.g. `v1.4.45`) | Test gate, then Windows + Linux + macOS builds, then ONE published GitHub Release with `SHA256SUMS.txt` + its Sigstore bundle |
| Manual dispatch | Same builds, uploaded as workflow artifacts only: no release, no Sigstore signature |

### Required GitHub Settings

1. **Repository Settings -> Actions -> General:**
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
| `BirdoVPN_X.Y.Z_Windows_x64-setup.exe` (+ `.sig`) | NSIS installer, Authenticode-signed (+ updater signature) |
| `BirdoVPN_X.Y.Z_Linux_amd64.AppImage` (+ `.sig`), `..._Linux_amd64.deb` | Linux packages (+ updater signature) |
| `BirdoVPN_X.Y.Z_macOS_{aarch64,x64}.dmg` | DMG installers (macOS, unsigned and un-notarised) |
| `BirdoVPN-macos-{arm64,x64}.app.tar.gz` (+ `.sig`) | macOS updater bundles (+ updater signature) |
| `SHA256SUMS.txt` | Checksums for every asset above except the `.sig` files |
| `SHA256SUMS.txt.sigstore` | Sigstore bundle signing `SHA256SUMS.txt` |

## References

- [Sigstore](https://www.sigstore.dev/)
- [Cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [GitHub OIDC for Sigstore](https://docs.sigstore.dev/cosign/signing/signing_with_github_actions/)
- [Rekor Transparency Log](https://docs.sigstore.dev/logging/overview/)
- [Tauri v2 Code Signing — Windows](https://v2.tauri.app/distribute/sign/windows/)
- [Tauri v2 Code Signing — macOS](https://v2.tauri.app/distribute/sign/macos/)

---

# Decisions of record and standing warnings

Moved out of the open-work register on 2026-09-20. None of these is a task.
They are here so they are not rediscovered as bugs and turned back into tickets.

## Windows "split tunnelling" does not exist, and the name is the honest part

True split tunnelling on Windows needs a **signed WFP redirect callout driver**.
We do not have one. WFP can only *exempt* an app from the block — an exempt app
is not routed outside the tunnel, it is simply not blocked.

So the feature was relabelled to **"Kill Switch Exceptions"** on 2026-07-29. That
was an honesty decision, not a rename for its own sake: calling it split
tunnelling would promise routing behaviour the platform cannot deliver without a
driver.

## 🔴 Never rotate `plugins.updater.pubkey` without bumping every installed client

In `tauri.conf.json`. Rotating it **orphans every existing installation** — they
reject the new signature and silently stop updating. There is no error a user
would notice; their client simply never updates again.

If it ever has to change, every installed client must be bumped first, which in
practice means the rotation ships *after* a release everyone has already taken.

## Deliberately deferred, and the UI says so

**Kill Switch Exceptions on macOS and Linux** are deferred; Windows has them
(see above for why they are not split tunnelling). Off Windows the nav row is
hidden and the screen reads "Windows only (for now)" — that label is the
commitment, and removing it is a product decision rather than a tidy-up.

Desktop post-quantum is **not** deferred. An earlier version of this section
said bilateral PQ was deferred and only one-way PQ was active (MR-1869); that
is stale. The BirdoPQ v1 ML-KEM-1024 PSK ships and Quantum Protection is on by
default: the client uploads its public key, decapsulates the server's
ciphertext and derives the PSK itself (`src-tauri/src/vpn/birdo_pq.rs`), and
since v1.4.42 it asks the server to withhold the PSK from the connect
response. What remains open is not a deferred feature but the limits of that
protection: the client key is long-lived, the server-to-relay leg is classical
TLS, and multi-hop's entry-to-exit leg has no PQ PSK. See that file's module
docs and birdo-web `docs/PQ-THREAT-MODEL.md`.

## The IPv6 leak-test procedure

Preserved from the IPv6 activation runbook, and it is the same shape as the
F-001 bench in `release/patches/`:

- `test-ipv6.com` and `ipleak.net` must show the **node's** v6 address
- use a **non-activated node as the control** — without one you cannot tell "the
  tunnel carries v6" from "this line has no v6 today"
- instant rollback, no release needed:
  `UPDATE "ServerNode" SET "ipv6Enabled" = false WHERE name = '<node>';`

⚠ The runbook's protected-infrastructure list is stale: it calls `89.167.6.86`
"crypto server, leave alone", and that box has since been **wiped and
reimaged**.

## macOS and Linux release the block when reconnecting gives up (2026-10-07)

On Windows, the Always-on Kill Switch (lockdown, the default there) keeps
traffic blocked after auto-reconnect gives up, until the user disconnects or
turns the kill switch off. macOS and Linux release the block at that point,
and that is decided, not missing: on 2026-10-07 the owner chose **not** to port
keep-blocked-after-give-up to them, so that Unix users are never stranded
behind the firewall (MR-708).

They do hold the block for the whole connected session whenever the kill
switch is on (`killswitch::holds_block_while_connected`). What they release is
the block for a session that is over. The rule, as `commands/settings.rs`
states it at the `lockdown_mode` default:

> What they do NOT have is lockdown's keep-blocked-after-give-up semantics,
> which is what this flag governs: on Unix the give-up/offline-cap branches
> still release the block so a dead session cannot strand the machine.

`killswitch::is_lockdown_mode()` is hard `false` off Windows, and
`reconnect_policy::give_up_keeps_block` keeps the block only under lockdown.
The Kill Switch row in Settings says so ("If reconnecting keeps failing, the
app stops blocking."). Do not file the difference as a gap.

## macOS and Linux have no packet-path stall rule (MR-1117)

The auto-reconnect loop's packet-path stall rule (WIN-FIX-3), like its fast
dead-path and send-path rules, is Windows-only: each sits behind
`#[cfg(target_os = "windows")]` in `vpn/auto_reconnect.rs`. On macOS and Linux
a tunnel whose packet path stops is caught by the handshake-age backstop
instead: 180 s without a completed handshake
(`reconnect_policy::MAX_HANDSHAKE_AGE`; an idle session is nudged at 150 s, so
a quiet tunnel does not trip it). Until then the app can show Protected over a
dead tunnel. With the kill switch on, the session-long block (above) holds
through it, so nothing leaves outside the tunnel. A stall rule for macOS and
Linux would be new work, not a fix.
