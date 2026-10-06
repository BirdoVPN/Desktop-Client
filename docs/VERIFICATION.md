# Verifying Birdo VPN Downloads

Every desktop release is built by this repository's
[`release.yml`](../.github/workflows/release.yml) workflow from a `vX.Y.Z` tag. The
release carries one `SHA256SUMS.txt` (the SHA-256 of every installer and package in
the release) and one `SHA256SUMS.txt.sigstore` bundle: a [Sigstore](https://www.sigstore.dev/)
keyless signature over that checksums file, made by that workflow run and recorded
in the public Rekor transparency log.

Verifying is two steps: prove the checksums file came from this repository's release
workflow at that tag, then prove your download matches it.

## 1. Verify the checksums file

Install cosign (<https://docs.sigstore.dev/cosign/system_config/installation/>):
`winget install sigstore.cosign` (Windows), `brew install cosign` (macOS), or a release
binary (Linux).

Download `SHA256SUMS.txt` and `SHA256SUMS.txt.sigstore` from the release, then run
this, with `vX.Y.Z` replaced by the release's tag (e.g. `v1.4.45`):

```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/BirdoVPN/Desktop-Client/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  SHA256SUMS.txt
```

It prints `Verified OK`. Both identity flags matter: they pin the signer to **this
repository's release workflow at this tag**. A looser pattern such as
`github.com/BirdoVPN/` would also accept a signature made by any workflow in any
BirdoVPN repository. Without either flag, cosign refuses to verify at all.

To accept any release tag rather than one specific tag:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/BirdoVPN/Desktop-Client/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  SHA256SUMS.txt
```

## 2. Verify your download against it

Linux / macOS (in the folder holding the download and `SHA256SUMS.txt`):

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing      # Linux
shasum -a 256 -c SHA256SUMS.txt --ignore-missing  # macOS
```

Windows (PowerShell):

```powershell
Get-Content SHA256SUMS.txt | ForEach-Object {
    $expected, $file = $_ -split '  ', 2
    if (Test-Path $file) {
        $actual = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLower()
        if ($actual -eq $expected) { Write-Host "OK: $file" -ForegroundColor Green }
        else { Write-Host "MISMATCH: $file" -ForegroundColor Red }
    }
}
```

## What else is signed

| Layer | Covers | Checked by |
|---|---|---|
| Sigstore bundle over `SHA256SUMS.txt` | every installer and package in the release | you, with the commands above |
| Authenticode (Azure Trusted Signing) | the Windows installer, the app `.exe` inside it, and the bundled `xray.exe` | Windows, automatically |
| Tauri updater signature (`*.sig`, minisign) | each auto-update bundle | the in-app updater, against the public key built into the app |

The updater `.sig` files are deliberately not listed in `SHA256SUMS.txt`: the updater
verifies them itself. The macOS build is not Apple-signed or notarised (there is no
Apple Developer account), so Gatekeeper warns on first launch; the checksum above is
how to confirm a DMG is genuine.

## What does this prove?

| Guarantee | How |
|---|---|
| **Built by this repo's release workflow, at that tag** | The Fulcio certificate names the repository, the workflow file and the tag ref; the two identity flags check them |
| **Not tampered with** | Any changed byte in `SHA256SUMS.txt` breaks the signature; any changed byte in a download breaks its checksum |
| **Publicly auditable** | Every signing event is recorded in [Rekor](https://search.sigstore.dev/) |
| **No trust in our keys needed** | Verification uses Sigstore's public infrastructure |

## Inspect the certificate

To see exactly which workflow run, commit and tag produced a release:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/BirdoVPN/Desktop-Client/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --output-certificate cert.pem \
  SHA256SUMS.txt

openssl x509 -in cert.pem -noout -text | grep -A1 "Subject Alternative Name"
```

## Troubleshooting

| Error | Fix |
|---|---|
| `cosign: command not found` | Install cosign (see step 1) |
| `--certificate-identity or --certificate-identity-regexp is required` | Add both identity flags exactly as shown in step 1 |
| `no matching CertificateIdentity found` | The tag in `--certificate-identity` must be the release you downloaded, e.g. `v1.4.45` (the error shows the identity actually signed) |
| `invalid signature` | `SHA256SUMS.txt` is not the file that was signed: download both files from the same release again |
| `MISMATCH` in step 2 | The download is corrupt or not the published file: download it again from the GitHub release |
