#!/usr/bin/env pwsh
# ============================================================
# Birdo VPN — Sigstore Code Signing Setup
# ============================================================
#
# Verifies that cosign is installed and ready for local signing.
# CI signing happens automatically via GitHub Actions OIDC — this
# script is for local dev/testing only.
#
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "`n=== Birdo VPN Sigstore Setup ===" -ForegroundColor Cyan

# Check if cosign is installed
$cosign = Get-Command cosign -ErrorAction SilentlyContinue
if (-not $cosign) {
    Write-Host "`n[!] cosign not found. Installing via winget..." -ForegroundColor Yellow
    winget install sigstore.cosign --accept-package-agreements --accept-source-agreements
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if (-not $cosign) {
        Write-Host "[ERROR] Failed to install cosign. Install manually:" -ForegroundColor Red
        Write-Host "  winget install sigstore.cosign" -ForegroundColor Gray
        Write-Host "  # or: go install github.com/sigstore/cosign/v2/cmd/cosign@latest" -ForegroundColor Gray
        exit 1
    }
}

Write-Host "`ncosign found at: $($cosign.Source)" -ForegroundColor Green

# Show version
$version = & cosign version 2>&1 | Select-String "cosign" | Select-Object -First 1
Write-Host "Version: $version" -ForegroundColor Cyan

Write-Host "`n=== How Signing Works ===" -ForegroundColor Cyan
Write-Host @"

  CI (GitHub Actions):
    Automatic keyless signing via OIDC — no secrets needed.
    Each build creates .sigstore bundles alongside installers.

  Local signing:
    Run scripts/sign-local.ps1 after building.
    This uses cosign sign-blob with browser-based OIDC login
    (GitHub, Google, or Microsoft account).

  Verification:
    cosign verify-blob --bundle <file>.sigstore \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "github.com/.*birdo-client-win" \
      <file>

"@ -ForegroundColor Gray

Write-Host "=== Setup Complete ===" -ForegroundColor Green

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Run 'npm run tauri build' to build and sign the application" -ForegroundColor Gray
Write-Host "  2. Verify the main exe (UAC 'Verified publisher'):" -ForegroundColor Gray
Write-Host "     Get-AuthenticodeSignature src-tauri\target\release\birdo-vpn.exe" -ForegroundColor Gray
Write-Host "  3. Verify the installer:" -ForegroundColor Gray
Write-Host "     Get-AuthenticodeSignature src-tauri\target\release\bundle\nsis\*.exe" -ForegroundColor Gray
Write-Host "  4. Set TAURI_SIGNING_PRIVATE_KEY in CI for automated builds" -ForegroundColor Gray
Write-Host ""
