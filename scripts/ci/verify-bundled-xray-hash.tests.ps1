#!/usr/bin/env pwsh
# ============================================================================
# Self-test for verify-bundled-xray-hash.ps1 (OPEN-WORK F4).
#
# Builds FAKE installers as zip archives - `7z x` extracts a zip exactly the
# way it extracts an NSIS payload, so the gate script runs its real code path
# (7z extraction -> locate resources\xray.exe -> SHA-256 compare) against a
# controlled payload - and asserts the exit code of each scenario:
#
#   1. matching hash                         -> 0   (the only passing case)
#   2. one byte rewritten after hashing      -> 1   (v1.4.40/v1.4.41: signing
#                                                   rewrote xray.exe post-hash)
#   3. installer ships no resources\xray.exe -> 1
#   4. xray.exe present but NOT under resources\ -> 1 (wrong layout, the app
#                                                   would not find it)
#   5. EMPTY expected hash                   -> 1   (GITHUB_ENV never set)
#   6. -RequireAuthenticode on unsigned data -> 1
#   7. missing installer path                -> 1
#
# Each scenario runs the gate in a CHILD PowerShell process so `exit` codes
# are observed the way GitHub Actions observes them. Runs under Windows
# PowerShell 5.1 and pwsh 7 (tests.yml `xray-gate-selftest` uses pwsh).
# ============================================================================
$ErrorActionPreference = 'Stop'

$script = Join-Path $PSScriptRoot 'verify-bundled-xray-hash.ps1'
if (-not (Test-Path -LiteralPath $script)) { throw "gate script missing: $script" }
$hostExe = (Get-Process -Id $PID).Path

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("xray-gate-selftest-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $work | Out-Null

# A deterministic pseudo-binary payload; Get-FileHash is what the gate uses,
# so compute the expectation with the same primitive.
$payload = [byte[]](0..4095 | ForEach-Object { ($_ * 7 + 13) -band 0xFF })

function New-FakeInstaller {
    param([string]$Name, [string]$InnerRelativePath, [byte[]]$Bytes)
    $stage = Join-Path $work ("stage-" + $Name)
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    if ($InnerRelativePath) {
        $file = Join-Path $stage $InnerRelativePath
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $file) | Out-Null
        [System.IO.File]::WriteAllBytes($file, $Bytes)
    } else {
        # An installer with SOME payload but no xray at all.
        [System.IO.File]::WriteAllBytes((Join-Path $stage 'app.exe'), $Bytes)
    }
    # Compress-Archive insists on a .zip name; rename to the NSIS-style
    # *-setup.exe afterwards - 7z sniffs the format from the bytes, not the
    # extension, so the gate sees exactly what it sees in CI.
    $zip = Join-Path $work ($Name + '.zip')
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    $fake = Join-Path $work ($Name + '-setup.exe')
    Move-Item -LiteralPath $zip -Destination $fake -Force
    return $fake
}

function Invoke-Gate {
    param([string[]]$GateArgs)
    $extract = Join-Path $work ("extract-" + [System.IO.Path]::GetRandomFileName())
    $allArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script) + $GateArgs + @('-ExtractDir', $extract)
    # Capture via a log file rather than 2>&1: under Windows PowerShell 5.1
    # with $ErrorActionPreference='Stop', a child's stderr line redirected
    # into the pipeline becomes a terminating NativeCommandError.
    $log = Join-Path $work ("log-" + [System.IO.Path]::GetRandomFileName() + ".txt")
    # One pre-quoted command line: Start-Process rejects an ARRAY holding an
    # empty element, and scenario 5 must pass an EMPTY -ExpectedSha256.
    $cmdline = ($allArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $p = Start-Process -FilePath $hostExe -ArgumentList $cmdline -NoNewWindow -Wait -PassThru -RedirectStandardOutput $log
    return @{ Code = $p.ExitCode; Output = (Get-Content -LiteralPath $log -Raw) }
}

$failures = 0
function Assert-Exit {
    param([string]$Case, [hashtable]$Result, [int]$Expected, [string]$MustMention = '')
    $ok = ($Result.Code -eq $Expected)
    if ($ok -and $MustMention -and ($Result.Output -notmatch [regex]::Escape($MustMention))) { $ok = $false }
    if ($ok) {
        Write-Host ("PASS  {0} (exit {1})" -f $Case, $Result.Code)
    } else {
        $script:failures++
        Write-Host ("FAIL  {0}: expected exit {1}{2}, got exit {3}`n----- output -----`n{4}------------------" -f `
            $Case, $Expected, $(if ($MustMention) { " mentioning '$MustMention'" } else { '' }), $Result.Code, $Result.Output)
    }
}

$good = New-FakeInstaller -Name 'good' -InnerRelativePath 'resources\xray.exe' -Bytes $payload
$goodSha = (Get-FileHash -LiteralPath (Join-Path $work 'stage-good\resources\xray.exe') -Algorithm SHA256).Hash.ToLowerInvariant()

# 1. the only passing case
Assert-Exit 'matching hash passes' (Invoke-Gate @('-Installer', $good, '-ExpectedSha256', $goodSha)) 0 'OK: bundled'
# Case-insensitive compare (Get-FileHash emits upper-case; GITHUB_ENV carries lower-case).
Assert-Exit 'matching hash passes (upper-case expected)' (Invoke-Gate @('-Installer', $good, '-ExpectedSha256', $goodSha.ToUpperInvariant())) 0

# 2. the shipped defect: bytes rewritten AFTER the hash was captured
$tampered = [byte[]]$payload.Clone(); $tampered[100] = $tampered[100] -bxor 0xFF
$signedLater = New-FakeInstaller -Name 'rewritten' -InnerRelativePath 'resources\xray.exe' -Bytes $tampered
Assert-Exit 'one byte rewritten after hashing fails' (Invoke-Gate @('-Installer', $signedLater, '-ExpectedSha256', $goodSha)) 1 'v1.4.40/v1.4.41'

# 3. no xray at all
$none = New-FakeInstaller -Name 'noxray' -InnerRelativePath '' -Bytes $payload
Assert-Exit 'installer without resources\xray.exe fails' (Invoke-Gate @('-Installer', $none, '-ExpectedSha256', $goodSha)) 1 'no resources\xray.exe'

# 4. right bytes, wrong place - xray.rs looks in <app dir>\resources\
$misplaced = New-FakeInstaller -Name 'misplaced' -InnerRelativePath 'bin\xray.exe' -Bytes $payload
Assert-Exit 'xray.exe outside resources\ fails' (Invoke-Gate @('-Installer', $misplaced, '-ExpectedSha256', $goodSha)) 1 'no resources\xray.exe'

# 5. empty expectation must not pass vacuously
Assert-Exit 'empty expected hash fails' (Invoke-Gate @('-Installer', $good, '-ExpectedSha256', '')) 1 'never captured XRAY_BINARY_SHA256'
Assert-Exit 'non-hex expected hash fails' (Invoke-Gate @('-Installer', $good, '-ExpectedSha256', 'not-a-sha')) 1

# 6. signed-release mode on an unsigned payload
Assert-Exit '-RequireAuthenticode on unsigned payload fails' (Invoke-Gate @('-Installer', $good, '-ExpectedSha256', $goodSha, '-RequireAuthenticode')) 1 'Authenticode status'

# IN-PROCESS invocation, the exact form release.yml uses (`& script @hashtable`).
# Every scenario above spawns a child `pwsh -File`, whose argv binding accepts a
# bare '-RequireAuthenticode'; an in-process ARRAY splat does not, and the
# v1.4.42 tag build died on exactly that difference while the child-process
# harness stayed green. This scenario binds the switch the way the workflow
# does, so the harness and the workflow can no longer disagree.
$inproc = @{ Installer = $good; ExpectedSha256 = $goodSha; RequireAuthenticode = $true; ExtractDir = (Join-Path $work 'extract-inproc') }
$inprocOut = & $script @inproc 2>&1 | Out-String
$inprocCode = $LASTEXITCODE
if ($inprocCode -ne 1 -or $inprocOut -notmatch 'Authenticode status') {
    Write-Host "FAIL in-process hashtable splat with -RequireAuthenticode: expected exit 1 mentioning 'Authenticode status', got exit $inprocCode"
    Write-Host $inprocOut
    $failures++
} else {
    Write-Host "PASS in-process hashtable splat binds -RequireAuthenticode (exit 1, refused unsigned payload)"
}
$inprocOk = @{ Installer = $good; ExpectedSha256 = $goodSha; ExtractDir = (Join-Path $work 'extract-inproc-ok') }
$null = & $script @inprocOk 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL in-process hashtable splat without the switch: expected exit 0, got $LASTEXITCODE"
    $failures++
} else {
    Write-Host "PASS in-process hashtable splat passes a matching unsigned payload"
}

# 7. missing installer
Assert-Exit 'missing installer fails' (Invoke-Gate @('-Installer', (Join-Path $work 'does-not-exist-setup.exe'), '-ExpectedSha256', $goodSha)) 1 'installer not found'

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

if ($failures -gt 0) {
    Write-Host "::error::verify-bundled-xray-hash self-test: $failures scenario(s) failed"
    exit 1
}
Write-Host "verify-bundled-xray-hash self-test: all scenarios behaved as specified"
exit 0
