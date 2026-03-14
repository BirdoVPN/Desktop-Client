#!/usr/bin/env pwsh
# ============================================================
# Sign release binaries with Sigstore (cosign) — local dev use
# ============================================================
# CI uses GitHub OIDC for keyless signing automatically.
# For local signing, cosign opens a browser for OIDC login
# (GitHub, Google, or Microsoft account).
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "`n=== Birdo VPN Local Sigstore Signing ===" -ForegroundColor Cyan

# Verify cosign is installed
$cosign = Get-Command cosign -ErrorAction SilentlyContinue
if (-not $cosign) {
    Write-Host "cosign not found. Run: winget install sigstore.cosign" -ForegroundColor Red
    exit 1
}

Write-Host "Using cosign at: $($cosign.Source)" -ForegroundColor Green

# Collect artifacts to sign
$artifacts = @()

$nsisExe = Get-ChildItem "W:\vpn\birdo-client-win\src-tauri\target\release\bundle\nsis\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($nsisExe) { $artifacts += $nsisExe }

$msiFile = Get-ChildItem "W:\vpn\birdo-client-win\src-tauri\target\release\bundle\msi\*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($msiFile) { $artifacts += $msiFile }

if ($artifacts.Count -eq 0) {
    Write-Host "No build artifacts found. Run 'npx tauri build' first." -ForegroundColor Red
    exit 1
}

Write-Host "`nFound $($artifacts.Count) artifact(s) to sign:" -ForegroundColor Yellow
foreach ($a in $artifacts) { Write-Host "  $($a.Name)" -ForegroundColor Gray }

# Sign each artifact
Write-Host "`nSigning with Sigstore (browser will open for OIDC login)..." -ForegroundColor Yellow
$failed = $false

foreach ($artifact in $artifacts) {
    $bundlePath = "$($artifact.FullName).sigstore"
    Write-Host "`nSigning $($artifact.Name)..." -ForegroundColor Yellow

    & cosign sign-blob --yes --bundle $bundlePath $artifact.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED to sign $($artifact.Name)" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "  Signed → $($artifact.Name).sigstore" -ForegroundColor Green
    }
}

# Generate checksums
Write-Host "`nGenerating SHA256 checksums..." -ForegroundColor Yellow
$checksumFile = "W:\vpn\birdo-client-win\src-tauri\target\release\bundle\SHA256SUMS.txt"
$checksums = @()
foreach ($artifact in $artifacts) {
    $hash = (Get-FileHash -Path $artifact.FullName -Algorithm SHA256).Hash.ToLower()
    $checksums += "$hash  $($artifact.Name)"
    Write-Host "  $hash  $($artifact.Name)" -ForegroundColor Cyan
}
$checksums | Out-File -FilePath $checksumFile -Encoding utf8

& cosign sign-blob --yes --bundle "$checksumFile.sigstore" $checksumFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAILED to sign SHA256SUMS.txt" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "  Signed → SHA256SUMS.txt.sigstore" -ForegroundColor Green
}

# Verify
Write-Host "`n=== Verification ===" -ForegroundColor Cyan
foreach ($artifact in $artifacts) {
    $bundlePath = "$($artifact.FullName).sigstore"
    if (Test-Path $bundlePath) {
        & cosign verify-blob --bundle $bundlePath --certificate-oidc-issuer "https://accounts.google.com" --certificate-identity-regexp ".*" $artifact.FullName 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  $($artifact.Name): VERIFIED" -ForegroundColor Green
        } else {
            # Try GitHub issuer (if signed in CI)
            & cosign verify-blob --bundle $bundlePath --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity-regexp ".*" $artifact.FullName 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  $($artifact.Name): VERIFIED (GitHub Actions)" -ForegroundColor Green
            } else {
                Write-Host "  $($artifact.Name): SIGNATURE PRESENT (verify with correct OIDC issuer)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  $($artifact.Name): No .sigstore bundle found" -ForegroundColor Red
    }
}

if ($failed) {
    Write-Host "`n=== Some signatures failed ===" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
