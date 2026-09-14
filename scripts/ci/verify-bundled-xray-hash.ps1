#!/usr/bin/env pwsh
# ============================================================================
# Post-bundle gate: the xray.exe INSIDE the NSIS installer must hash to the
# value the app was compiled with (XRAY_BINARY_SHA256).
#
# WHY THIS EXISTS (OPEN-WORK F4): v1.4.40 and v1.4.41 both shipped a Windows
# installer whose resources\xray.exe did NOT match the compiled-in hash. The
# build captured XRAY_BINARY_SHA256 from the freshly downloaded xray.exe, and
# tauri-bundler then Authenticode-signed that same file IN PLACE during
# `tauri build` (tauri-bundler 2.11.4 nsis/mod.rs generate_resource_data():
# `if can_sign() && should_sign(&resource_path) { try_sign(...) }` for every
# .exe/.dll resource). Signing appends a PKCS#7 blob, so the shipped bytes
# hash differently, xray.rs verify_xray_integrity() returns Err on every
# stealth connect, and Windows stealth has been dead on every signed release
# since the integrity check landed (v1.3.2). Nothing in the pipeline compared
# the SHIPPED file against the COMPILED-IN value - this script is that check.
#
# Standalone usage (any Windows box with 7-Zip):
#   pwsh scripts/ci/verify-bundled-xray-hash.ps1 `
#       -Installer 'BirdoVPN_1.4.42_x64-setup.exe' -ExpectedSha256 <64 hex>
# Exit 0 only when the extracted resources\xray.exe hashes to ExpectedSha256
# (and, with -RequireAuthenticode, carries a Valid Authenticode signature).
# Every other outcome - missing 7z, missing installer, no/ambiguous inner
# xray.exe, EMPTY expected hash (the GITHUB_ENV-never-set case), mismatch -
# exits 1 with a ::error:: line so the CI job fails loudly.
#
# The self-test in scripts/ci/verify-bundled-xray-hash.tests.ps1 feeds this
# script fake installers (zip archives - 7z x reads them exactly like NSIS
# payloads) and proves each failure path actually fails.
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    # Deliberately NOT Mandatory: an empty string must reach the validation
    # below and fail with a clear message, not a PowerShell prompt/exception.
    [string]$ExpectedSha256 = '',
    [string]$SevenZip = '7z',
    [switch]$RequireAuthenticode,
    # Where to extract. Default: a fresh directory under $env:RUNNER_TEMP
    # (CI) or the user temp dir. Removed on success, kept on failure so the
    # bad file can be inspected.
    [string]$ExtractDir = ''
)

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Host "::error::verify-bundled-xray-hash: $msg"
    exit 1
}

# --- Inputs ------------------------------------------------------------------
if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    Fail "ExpectedSha256 is not a 64-hex SHA-256 (got '$ExpectedSha256'). An empty value means the build never captured XRAY_BINARY_SHA256 - the app would refuse xray at runtime, refusing the bundle."
}
$expected = $ExpectedSha256.ToLowerInvariant()

if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    Fail "installer not found: $Installer"
}
$installerPath = (Resolve-Path -LiteralPath $Installer).Path

$sevenZipCmd = Get-Command $SevenZip -ErrorAction SilentlyContinue
if (-not $sevenZipCmd) {
    $fallback = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    if (Test-Path -LiteralPath $fallback) {
        $sevenZipCmd = Get-Command $fallback
    } else {
        Fail "7-Zip not found: '${SevenZip}' is not on PATH and ${fallback} does not exist"
    }
}

if (-not $ExtractDir) {
    $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
    $ExtractDir = Join-Path $base ("xray-gate-" + [System.IO.Path]::GetRandomFileName())
}
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null

# --- Extract -----------------------------------------------------------------
# Full extraction rather than a single-member pull: NSIS member names vary in
# separator/prefix between 7-Zip versions, and the whole installer is ~40 MB.
& $sevenZipCmd.Source x $installerPath "-o$ExtractDir" -y | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "7z x exited $LASTEXITCODE extracting $installerPath"
}

# The shipped layout is <install dir>\resources\xray.exe (xray.rs resolves it
# next to the app exe). Match on the parent directory name so a same-named
# file elsewhere in the payload can neither satisfy nor confuse the gate.
$candidates = @(Get-ChildItem -Path $ExtractDir -Recurse -File -Filter 'xray.exe' |
    Where-Object { $_.Directory.Name -ieq 'resources' })
if ($candidates.Count -eq 0) {
    Fail "no resources\xray.exe inside $installerPath (extracted to $ExtractDir) - the installer ships no stealth engine"
}
if ($candidates.Count -gt 1) {
    Fail ("ambiguous: " + $candidates.Count + " resources\xray.exe members inside the installer: " + (($candidates | ForEach-Object { $_.FullName }) -join '; '))
}
$inner = $candidates[0]

# --- Compare -----------------------------------------------------------------
$actual = (Get-FileHash -LiteralPath $inner.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "bundled  : $($inner.FullName) ($($inner.Length) bytes)"
Write-Host "expected : $expected"
Write-Host "actual   : $actual"
if ($actual -ne $expected) {
    Fail "bundled resources\xray.exe hash $actual != compiled-in XRAY_BINARY_SHA256 $expected. The app's integrity check would refuse this xray on every stealth connect (this is the v1.4.40/v1.4.41 defect: something rewrote xray.exe after the hash was captured). Extracted copy kept at $($inner.FullName)."
}

if ($RequireAuthenticode) {
    $sig = Get-AuthenticodeSignature -LiteralPath $inner.FullName
    if ($sig.Status -ne 'Valid') {
        Fail "bundled resources\xray.exe Authenticode status is '$($sig.Status)' (expected Valid on a signed release)"
    }
    Write-Host "authenticode: Valid - $($sig.SignerCertificate.Subject)"
}

Write-Host "OK: bundled resources\xray.exe matches XRAY_BINARY_SHA256 ($actual)"
Remove-Item -LiteralPath $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
