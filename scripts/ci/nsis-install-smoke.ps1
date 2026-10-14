#!/usr/bin/env pwsh
# ============================================================================
# Silent install + silent uninstall of the NSIS installer a CI build just
# produced (.github/workflows/nsis-installer.yml).
#
# THROWAWAY RUNNERS ONLY. This installs BirdoVPN machine-wide and then
# uninstalls it, which on a workstation would be the user's own BirdoVPN. It
# refuses to run anywhere but a GitHub-hosted runner, and refuses if any trace
# of BirdoVPN is already on the machine.
#
# What it proves, beyond "the installer runs":
#   - the installer lays down the app and its resources, the third-party
#     notices among them (and no dotfile such
#     as resources\.gitkeep), the Apps & features entry (version and
#     publisher as tauri.conf.json says) and birdo://;
#   - the hooks in src-tauri/nsis-hooks.nsh are compiled in AND run:
#       NSIS_HOOK_POSTINSTALL    writes the pre-D8 mirror HKLM\Software\Birdo VPN\BirdoVPN
#       NSIS_HOOK_PREUNINSTALL   runs "$INSTDIR\<exe>" --reconcile-and-exit, whose
#                                log line proves the exe started from the install dir
#       NSIS_HOOK_POSTUNINSTALL  drops the mirror again;
#   - the silent uninstaller removes the files, the entry and birdo://;
#   - R1: a FRESH install writes no legacy-upgrade marker
#     (HKLM\SOFTWARE\BirdoVPN LegacyUpgradePending), so the app trusts nothing
#     an older build could have left in the user's reach;
#   - R2: the uninstall (NSIS_HOOK_PREUNINSTALL's --remove-leftovers-and-exit)
#     removes %ProgramData%\BirdoVPN\updates and the set-aside
#     %ProgramData%\BirdoVPN.untrusted-* folders WITHOUT following a junction
#     planted in them, and keeps the admin-only directory's keys and markers.
#
# Safe on a runner, and checked rather than assumed. No VPN is started: a
# silent install without /R never launches the app. --reconcile-and-exit
# (main.rs) runs vpn::dns_journal::reconcile(), which returns before touching
# anything when %APPDATA%\BirdoVPN\dns-restore.json does not exist: no WFP
# filter, route or DNS setting is read or written, and it exits before any
# window, tray or network client. So this script requires that no journal
# exists beforehand, that the app logs "DNS restored: false", and that the
# routing table and DNS servers are the same before and after.
#
# Usage, from the repo root after the build:
#   pwsh scripts/ci/nsis-install-smoke.ps1 -Installer <...>_x64-setup.exe
# Exit 0 only when every check passes; otherwise ::error:: and exit 1.
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [string]$MainBinaryName = 'birdo-vpn-desktop',
    [int]$TimeoutSec = 120 # per wait; three waits stay inside the step's 10 min
)

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Host "::error::nsis-install-smoke: $msg"
    exit 1
}
function Step([string]$msg) { Write-Host "-- $msg" }
function Get-DefaultValue([string]$key) {
    if (Test-Path -LiteralPath $key) { return (Get-Item -LiteralPath $key).GetValue('') }
    return $null
}
function Get-NetSnapshot {
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
            ForEach-Object { '{0} via {1} if{2} metric {3}' -f $_.DestinationPrefix, $_.NextHop, $_.ifIndex, $_.RouteMetric } |
            Sort-Object)
    $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses } |
            ForEach-Object { '{0}/{1}: {2}' -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ',') } |
            Sort-Object)
    return @($routes + '--' + $dns)
}
# Start a process and wait for it, bounded. Returns its exit code.
function Invoke-Bounded([string]$file, [string[]]$arguments, [string]$what) {
    $p = Start-Process -FilePath $file -ArgumentList $arguments -PassThru
    $null = $p.Handle # hold the handle, or ExitCode is unreadable once it exits
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill($true) } catch { Write-Host "could not kill $what`: $_" }
        Fail "$what did not finish within $TimeoutSec s"
    }
    return $p.ExitCode
}

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    Fail 'refusing to run outside a GitHub-hosted runner: this installs and then UNINSTALLS BirdoVPN machine-wide'
}
if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) { Fail "installer not found: $Installer" }
$Installer = (Resolve-Path -LiteralPath $Installer).Path

$conf = Get-Content -Raw -LiteralPath 'src-tauri/tauri.conf.json' | ConvertFrom-Json
$product = $conf.productName
$version = $conf.version
$publisher = $conf.bundle.publisher
if ($conf.bundle.windows.nsis.installMode -ne 'perMachine') {
    Fail "expected bundle.windows.nsis.installMode perMachine (the hooks write HKLM), tauri.conf.json says '$($conf.bundle.windows.nsis.installMode)'"
}
$schemes = @($conf.plugins.'deep-link'.desktop.schemes)
if ($schemes.Count -eq 0) { Fail 'tauri.conf.json declares no deep-link scheme to check' }

$instDir = Join-Path $env:ProgramFiles $product              # $PROGRAMFILES64\<product>, the template's default
$exe = Join-Path $instDir "$MainBinaryName.exe"
$uninstaller = Join-Path $instDir 'uninstall.exe'
$uninstKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$product"
$recordKey = "HKLM:\SOFTWARE\$publisher\$product"            # the template's MANUPRODUCTKEY
$mirrorParent = 'HKLM:\SOFTWARE\Birdo VPN'                   # nsis-hooks.nsh BIRDO_LEGACY_MANUKEY
$mirrorKey = "$mirrorParent\$product"                        # nsis-hooks.nsh BIRDO_LEGACY_MANUPRODUCTKEY
$appData = Join-Path $env:APPDATA 'BirdoVPN'
$log = Join-Path $appData 'logs\birdo.log'
$journal = Join-Path $appData 'dns-restore.json'
$reconciled = '--reconcile-and-exit done (DNS restored: false)'
$stateKey = 'HKLM:\SOFTWARE\BirdoVPN'                         # utils/protected_dir.rs STATE_KEY
$markerValue = 'LegacyUpgradePending'                        # nsis-hooks.nsh BIRDO_LEGACY_UPGRADE_VALUE
$protected = Join-Path $env:ProgramData 'BirdoVPN'           # the admin-only state directory
function Get-LegacyMarker {
    $p = Get-ItemProperty -LiteralPath $stateKey -Name $markerValue -ErrorAction SilentlyContinue
    if ($p) { return $p.$markerValue }
    return $null
}

# -- a clean runner -----------------------------------------------------------
Step 'the runner has no BirdoVPN'
$traces = @($instDir, $uninstKey, $recordKey, $mirrorParent, $appData, $protected, $stateKey) +
    @($schemes | ForEach-Object { "HKLM:\SOFTWARE\Classes\$_" })
foreach ($t in $traces) {
    if (Test-Path -LiteralPath $t) { Fail "$t already exists: not a clean runner, refusing to install over or uninstall anything" }
}
$wv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue
Write-Host ('   WebView2 runtime: {0}' -f $(if ($wv -and $wv.pv) { $wv.pv } else { 'absent (the installer downloads the bootstrapper)' }))
$netBefore = Get-NetSnapshot
# Both cmdlets swallow their errors (-ErrorAction SilentlyContinue), so a
# snapshot that came back (nearly) empty would make "unchanged" below prove
# nothing. A runner has loopback and default routes and DNS servers: require
# at least one entry on EACH side of the '--' separator (routes, then DNS).
# A total count alone let an empty DNS half through.
$sep = [array]::IndexOf($netBefore, '--')
$routeCount = $sep
$dnsCount = $netBefore.Count - $sep - 1
Write-Host "   network snapshot: $routeCount routes, $dnsCount DNS server entries"
if (-not ($sep -ge 1 -and $dnsCount -ge 1)) {
    Fail "the network snapshot before the install has $routeCount routes and $dnsCount DNS server entries (want at least one of each): Get-NetRoute or Get-DnsClientServerAddress returned nothing usable, so the no-network-change check would be vacuous"
}

# -- install ------------------------------------------------------------------
Step "silent install: $Installer /S"
$code = Invoke-Bounded $Installer @('/S') 'the installer'
if ($code -ne 0) { Fail "the installer exited $code" }

Step "installed files under $instDir"
# THIRD-PARTY-NOTICES.txt: the licence notices that Settings > About >
# Licences reads from the install dir (MR-1685).
foreach ($f in @($exe, $uninstaller, (Join-Path $instDir 'resources\xray.exe'), (Join-Path $instDir 'resources\wintun.dll'), (Join-Path $instDir 'resources\THIRD-PARTY-NOTICES.txt'))) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Fail "missing after install: $f" }
}
Get-ChildItem -LiteralPath $instDir -Recurse -File -Force |
    ForEach-Object { Write-Host ('   {0,10}  {1}' -f $_.Length, $_.FullName.Substring($instDir.Length + 1)) }
# bundle.resources is the glob "resources/*", which matches dotfiles too: the
# tracked src-tauri/resources/.gitkeep (there so builds that stage nothing
# still match it) was installed as resources\.gitkeep until the bundling
# builds started dropping it after staging the real files.
$dotfiles = @(Get-ChildItem -LiteralPath $instDir -Recurse -File -Force | Where-Object { $_.Name.StartsWith('.') })
if ($dotfiles.Count -ne 0) {
    Fail "the installer put repository placeholder files in ${instDir}: $(($dotfiles | ForEach-Object { $_.FullName.Substring($instDir.Length + 1) }) -join ', ')"
}
Write-Host '   no dotfiles (resources\.gitkeep is not installed)'

Step "Apps & features entry $uninstKey"
if (-not (Test-Path -LiteralPath $uninstKey)) { Fail "no Apps & features entry at $uninstKey" }
$entry = Get-ItemProperty -LiteralPath $uninstKey
$want = [ordered]@{
    DisplayName     = $product
    DisplayVersion  = $version
    Publisher       = $publisher
    UninstallString = "`"$uninstaller`""
    InstallLocation = "`"$instDir`""
}
foreach ($k in $want.Keys) {
    $actual = $entry.PSObject.Properties[$k]
    $actual = if ($actual) { $actual.Value } else { '<missing>' }
    if ($actual -ne $want[$k]) { Fail "Apps & features $k is '$actual', expected '$($want[$k])'" }
    Write-Host "   $k = $actual"
}

Step 'install records'
if ((Get-DefaultValue $recordKey) -ne $instDir) { Fail "$recordKey does not name $instDir (the template's install record)" }
if ((Get-DefaultValue $mirrorKey) -ne $instDir) {
    Fail "$mirrorKey does not name ${instDir}: NSIS_HOOK_POSTINSTALL did not run, so the hooks are not in this installer"
}
Write-Host "   $recordKey = $instDir"
Write-Host "   $mirrorKey = $instDir (NSIS_HOOK_POSTINSTALL ran)"
foreach ($s in $schemes) {
    $cmd = Get-DefaultValue "HKLM:\SOFTWARE\Classes\$s\shell\open\command"
    if ($cmd -ne "`"$exe`" `"%1`"") { Fail "${s}:// opens '$cmd', expected the installed exe" }
    Write-Host "   ${s}:// -> $cmd"
}

Step 'R1: a fresh install writes no legacy-upgrade marker'
$marker = Get-LegacyMarker
if ($null -ne $marker) { Fail "$stateKey $markerValue = $marker after a FRESH install: the app would migrate (trust) state an older build never left" }
Write-Host "   $stateKey $markerValue absent"

# -- D6c HIGH: --with-app-data removes the per-user folders without following
#    a junction planted at the top of, or inside, any of them.
Step 'D6c HIGH: --with-app-data deletes the per-user folders and follows no junction'
$victim0 = Join-Path $env:RUNNER_TEMP 'birdo-appdata-victim'
Remove-Item -LiteralPath $victim0 -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $victim0 | Out-Null
Set-Content -LiteralPath (Join-Path $victim0 'precious.txt') -Value 'keep'
$roamBirdo = Join-Path $env:APPDATA 'BirdoVPN'
$localBirdo = Join-Path $env:LOCALAPPDATA 'BirdoVPN'
$localBirdoSpace = Join-Path $env:LOCALAPPDATA 'Birdo VPN'
$roamId = Join-Path $env:APPDATA 'uk.birdo.vpn.desktop'
$localId = Join-Path $env:LOCALAPPDATA 'uk.birdo.vpn.desktop'
# %APPDATA%\BirdoVPN: a journal to KEEP, logs to remove, a junction inside.
New-Item -ItemType Directory -Force -Path (Join-Path $roamBirdo 'logs') | Out-Null
Set-Content -LiteralPath (Join-Path $roamBirdo 'dns-restore.json') -Value '{}'
Set-Content -LiteralPath (Join-Path $roamBirdo 'logs\birdo.log') -Value 'x'
New-Item -ItemType Junction -Path (Join-Path $roamBirdo 'logs\out') -Target $victim0 | Out-Null
# Removed entirely; one holds a junction, one IS a junction.
New-Item -ItemType Directory -Force -Path $localBirdo | Out-Null
Set-Content -LiteralPath (Join-Path $localBirdo 'device_id') -Value 'd'
New-Item -ItemType Junction -Path (Join-Path $localBirdo 'out') -Target $victim0 | Out-Null
New-Item -ItemType Junction -Path $localBirdoSpace -Target $victim0 | Out-Null
New-Item -ItemType Directory -Force -Path $roamId | Out-Null
Set-Content -LiteralPath (Join-Path $roamId 'settings.json') -Value '{}'
New-Item -ItemType Directory -Force -Path $localId | Out-Null
$code = Invoke-Bounded $exe @('--remove-leftovers-and-exit', '--with-app-data') 'the exe (--with-app-data)'
if ($code -ne 0) { Fail "$exe --remove-leftovers-and-exit --with-app-data exited $code" }
if (-not (Test-Path -LiteralPath (Join-Path $roamBirdo 'dns-restore.json'))) { Fail 'the DNS journal was not kept (W1-008)' }
foreach ($g in @((Join-Path $roamBirdo 'logs'), $localBirdo, $localBirdoSpace, $roamId, $localId)) {
    if (Test-Path -LiteralPath $g) { Fail "$g survived --with-app-data" }
}
if ((Get-Content -LiteralPath (Join-Path $victim0 'precious.txt') -ErrorAction SilentlyContinue) -ne 'keep') {
    Fail 'the --with-app-data sweep followed a junction: a file outside the app folders was deleted'
}
Write-Host '   per-user folders removed, dns-restore.json kept, no junction followed'
# Tidy the runner: the journal we kept, and the victim.
Remove-Item -LiteralPath $roamBirdo -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $victim0 -Recurse -Force -ErrorAction SilentlyContinue

# -- R2: what the uninstall must remove from %ProgramData%, and what it must keep
Step 'R2: plant the leftovers the uninstall removes, and the state it keeps'
# The admin-only directory, made by the app the way every start makes it (the
# reconcile is a no-op on a runner, as below). The exe is a GUI-subsystem
# binary, so it is waited for explicitly.
$code = Invoke-Bounded $exe @('--reconcile-and-exit') 'the exe (--reconcile-and-exit)'
if ($code -ne 0) { Fail "$exe --reconcile-and-exit exited $code" }
if (-not (Test-Path -LiteralPath $protected -PathType Container)) { Fail "the app did not create $protected" }
Write-Host "   $protected  $((Get-Acl -LiteralPath $protected).Sddl)"
# The log this run wrote must not stand in for the uninstaller's run below.
if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
# The updater's leftovers: its temp folder and the installer it launched.
$updater = Join-Path $protected 'updates\BirdoVPN-0.0.0-updater-ci'
New-Item -ItemType Directory -Force -Path $updater | Out-Null
Set-Content -LiteralPath (Join-Path $updater 'BirdoVPN_0.0.0_x64-setup.exe') -Value 'MZ'
# What must survive: a settings key, an ML-KEM key (a silent uninstall does
# not tick "Delete the application data") and the app's own markers.
$kept = @(
    (Join-Path $protected 'settings-hmac-S-1-5-21-0-0-0-1001.key'),
    (Join-Path $protected 'pq-S-1-5-21-0-0-0-1001.bin')
)
foreach ($k in $kept) { Set-Content -LiteralPath $k -Value '00' }
$kept += @(Get-ChildItem -LiteralPath $protected -File -Filter 'dns-journal-migrated-*' | ForEach-Object { $_.FullName })
if ($kept.Count -lt 3) { Fail "the app wrote no dns-journal-migrated marker in $protected" }
# Two squats the app set aside: a folder with a junction out of it, and a
# junction itself. The junctions point at a folder that must survive.
$victim = Join-Path $env:RUNNER_TEMP 'birdo-r2-victim'
New-Item -ItemType Directory -Force -Path $victim | Out-Null
Set-Content -LiteralPath (Join-Path $victim 'precious.txt') -Value 'keep'
$aside1 = Join-Path $env:ProgramData 'BirdoVPN.untrusted-1'
$aside2 = Join-Path $env:ProgramData 'BirdoVPN.untrusted-2'
New-Item -ItemType Directory -Force -Path $aside1 | Out-Null
Set-Content -LiteralPath (Join-Path $aside1 'planted.key') -Value 'x'
New-Item -ItemType Junction -Path (Join-Path $aside1 'out') -Target $victim | Out-Null
New-Item -ItemType Junction -Path $aside2 -Target $victim | Out-Null
Get-ChildItem -LiteralPath $protected -Recurse -Force | ForEach-Object { Write-Host "   $($_.FullName)" }

# -- uninstall ----------------------------------------------------------------
Step "silent uninstall: $uninstaller /S"
$code = Invoke-Bounded $uninstaller @('/S') 'the uninstaller'
if ($code -ne 0) { Fail "the uninstaller exited $code" }
# An NSIS uninstaller copies itself to %TEMP% and runs from there (Un_A.exe),
# so the process waited for above only started the real one. Wait for the
# copy, and for the uninstall's last act (NSIS_HOOK_POSTUNINSTALL drops the
# mirror), bounded; the checks below then say what did not happen.
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
do {
    $copies = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^(Un_[A-Z]|Au_)$' })
    if ($copies.Count -eq 0 -and -not (Test-Path -LiteralPath $uninstKey) -and -not (Test-Path -LiteralPath $mirrorKey)) { break }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $deadline)

Step 'NSIS_HOOK_PREUNINSTALL ran the installed exe with --reconcile-and-exit'
if (-not (Test-Path -LiteralPath $log -PathType Leaf)) {
    Fail "no ${log}: the uninstaller never started $exe --reconcile-and-exit"
}
Get-Content -LiteralPath $log | ForEach-Object { Write-Host "   | $_" }
if (-not (Select-String -LiteralPath $log -SimpleMatch -Pattern $reconciled -Quiet)) {
    Fail "the app log has no '$reconciled': the reconcile did not run to the end, or found something to restore on a clean runner"
}
if (Test-Path -LiteralPath $journal) { Fail "$journal exists after the uninstall: the reconcile wrote a DNS journal on a runner that had none" }

Step 'R2: the uninstall removed the leftovers, kept the keys and markers, and followed no junction'
foreach ($gone in @((Join-Path $protected 'updates'), $aside1, $aside2)) {
    if (Test-Path -LiteralPath $gone) { Fail "$gone is still there after the uninstall (--remove-leftovers-and-exit)" }
}
if ((Get-Content -LiteralPath (Join-Path $victim 'precious.txt') -ErrorAction SilentlyContinue) -ne 'keep') {
    Fail "$victim\precious.txt is gone: the uninstall followed a junction planted in a set-aside folder"
}
foreach ($k in $kept) {
    if (-not (Test-Path -LiteralPath $k -PathType Leaf)) { Fail "$k was deleted: the uninstall must keep the keys and markers" }
}
if ($null -ne (Get-LegacyMarker)) { Fail "$stateKey $markerValue exists after the uninstall" }
Write-Host "   gone: updates\, BirdoVPN.untrusted-1, BirdoVPN.untrusted-2; kept: $(($kept | ForEach-Object { Split-Path -Leaf $_ }) -join ', '); $victim intact"
Remove-Item -LiteralPath $victim -Recurse -Force
foreach ($k in $kept) { if ($k -notlike '*dns-journal-migrated-*') { Remove-Item -LiteralPath $k -Force } }

Step 'the uninstall removed what the install added'
$left = @(Get-Process -Name $MainBinaryName -ErrorAction SilentlyContinue)
if ($left.Count -ne 0) { Fail "$MainBinaryName is still running (pid $($left.Id -join ', ')) after the uninstall" }
if (Test-Path -LiteralPath $instDir) {
    Get-ChildItem -LiteralPath $instDir -Recurse -Force | ForEach-Object { Write-Host "   left: $($_.FullName)" }
    Fail "$instDir still exists after the uninstall"
}
if (Test-Path -LiteralPath $uninstKey) { Fail "the Apps & features entry $uninstKey is still there" }
if (Test-Path -LiteralPath $mirrorParent) { Fail "$mirrorParent is still there: NSIS_HOOK_POSTUNINSTALL did not run" }
foreach ($s in $schemes) {
    if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\$s") { Fail "${s}:// is still registered" }
}
Write-Host "   gone: $instDir, $uninstKey, $mirrorParent (NSIS_HOOK_POSTUNINSTALL ran), $($schemes -join ', '):// handler"

Step 'no network change'
$netAfter = Get-NetSnapshot
$diff = @(Compare-Object -ReferenceObject $netBefore -DifferenceObject $netAfter)
if ($diff.Count -ne 0) {
    $diff | ForEach-Object { Write-Host ('   {0} {1}' -f $_.SideIndicator, $_.InputObject) }
    Fail 'the routing table or DNS servers changed between before the install and after the uninstall'
}
Write-Host "   $($netBefore.Count - 1) routes and DNS server entries, unchanged"

Write-Host 'OK - the installer installs, the hooks run, and the uninstaller removes it all, with no network change'
exit 0
