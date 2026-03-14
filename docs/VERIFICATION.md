# Verifying Birdo VPN Downloads

All release artifacts are signed with [Sigstore](https://www.sigstore.dev/) using
keyless signing from GitHub Actions. This lets you cryptographically verify that
a download was built from this repository's source code — not tampered with.

## Quick Verify

```bash
# 1. Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/)
#    Windows:  winget install sigstore.cosign
#    macOS:    brew install cosign
#    Linux:    go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# 2. Download the installer AND its .sigstore bundle from the GitHub Release

# 3. Verify
cosign verify-blob \
  --bundle BirdoVPN-Setup-1.0.0.exe.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/.*birdo-client-win" \
  BirdoVPN-Setup-1.0.0.exe
```

If valid, you'll see:
```
Verified OK
```

## Verify Checksums

Each release includes a `SHA256SUMS.txt` that is itself Sigstore-signed:

```bash
# 1. Verify the checksums file is authentic
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/.*birdo-client-win" \
  SHA256SUMS.txt

# 2. Verify file checksums (PowerShell)
Get-Content SHA256SUMS.txt | ForEach-Object {
    $parts = $_ -split '  '
    $expected = $parts[0]
    $file = $parts[1]
    $actual = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $expected) {
        Write-Host "OK: $file" -ForegroundColor Green
    } else {
        Write-Host "MISMATCH: $file" -ForegroundColor Red
    }
}

# Or on Linux/macOS:
sha256sum -c SHA256SUMS.txt
```

## What Does This Prove?

| Guarantee | How |
|-----------|-----|
| **Built from this repo** | Fulcio certificate contains the GitHub repo URL and workflow |
| **Not tampered with** | Cosign verifies the cryptographic signature matches the file |
| **Publicly auditable** | Every signing event is recorded in [Rekor](https://search.sigstore.dev/) |
| **No trust in us needed** | You verify against Sigstore's public infrastructure, not our keys |

## Inspect the Certificate

To see exactly which commit and workflow produced a binary:

```bash
cosign verify-blob \
  --bundle BirdoVPN-Setup-1.0.0.exe.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/.*birdo-client-win" \
  --output-certificate cert.pem \
  BirdoVPN-Setup-1.0.0.exe

openssl x509 -in cert.pem -noout -text | grep -A1 "Subject Alternative Name"
```

This shows the GitHub Actions identity that signed the artifact, including the
repository, workflow, and ref.

## Lookup in Rekor

Every signing event is recorded in Sigstore's public transparency log:

1. Go to [https://search.sigstore.dev/](https://search.sigstore.dev/)
2. Search by the artifact hash or the email/identity from the certificate
3. You'll see the full log entry including timestamp, signature, and certificate

## Troubleshooting

| Error | Fix |
|-------|-----|
| `cosign: command not found` | Install cosign: `winget install sigstore.cosign` |
| `no matching signatures` | Ensure you downloaded the `.sigstore` bundle from the same release |
| `certificate identity mismatch` | Check the `--certificate-identity-regexp` matches the repo URL |
| `BUNDLE_NOT_FOUND` | The `.sigstore` file must be next to the artifact being verified |
