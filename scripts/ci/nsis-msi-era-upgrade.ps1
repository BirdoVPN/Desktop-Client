#!/usr/bin/env pwsh
# ============================================================================
# WIN2-012: an upgrade over an MSI-era install leaves ONE Apps & features entry
# and no MSI, so that uninstalling a leftover MSI can never delete files this
# install owns (.github/workflows/nsis-installer.yml).
#
# THROWAWAY RUNNERS ONLY. This installs an MSI and two NSIS builds of BirdoVPN
# machine-wide, plants Apps & features entries, and removes it all again. It
# refuses to run anywhere but a GitHub-hosted runner, and refuses to start if
# BirdoVPN is already on the machine.
#
# The MSI is the one builds b15aece..79fd4ae shipped (no release keeps one
# now): Tauri's default WiX template, publisher "Birdo VPN", built by the
# workflow from this tree with `tauri bundle --bundles msi`. Its tables are
# checked against what that era's MSIs carry (the UpgradeCode, which Tauri
# derives from productName alone, the manufacturer and the folder).
#
# Phase A - MSI-era install only, then this build silently (/S): the case the
#   template never migrated, even before D8. Planted beside it:
#     - a leftover MSI-era entry that Windows Installer does not know, whose
#       UninstallString is a stub that leaves a marker file if it ever runs;
#     - an entry with DisplayName "BirdoVPN" from another publisher;
#     - an entry for the 1.0.0 product ("Birdo VPN", publisher "Birdo VPN").
#   The MSI is uninstalled and the leftover deleted, with the stub never run;
#   the other two are byte-for-byte untouched. Then two keys with a GUID's
#   length and braces but not a GUID (one carries " /qb"), with every other
#   MSI-era mark: running this build over itself must never start msiexec.
# Phase B - MSI-era install plus v1.4.46 over it: the TWO entries that the
#   shipped release leaves (the bug, reproduced). Then this build as the in-app
#   updater runs it (/P /UPDATE): one entry, and the shortcuts the MSI took
#   with it are re-created even in update mode.
# After each upgrade:
#   - Windows Installer no longer knows the product;
#   - exactly one BirdoVPN entry (ours) remains;
#   - every file is in place, so the MSI ran BEFORE the files were laid down;
#   - birdo:// points at the installed exe;
#   - `msiexec /x {ProductCode}` - the leftover uninstall that used to delete
#     shared files - now finds no product (1605) and the exe survives it;
#   - our silent uninstaller then removes everything.
#
# No VPN is started: msiexec /qn does not launch the app, nor does a silent or
# passive install without /R. The uninstall runs the same
# --reconcile-and-exit as nsis-install-smoke.ps1, which is a no-op on a runner.
#
# Usage, from the repo root after the build:
#   pwsh scripts/ci/nsis-msi-era-upgrade.ps1 -Installer <this build's setup.exe> `
#        -Msi <the MSI-era .msi> -Previous <v1.4.46 setup.exe>
# Exit 0 only when every check passes; otherwise ::error:: and exit 1.
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Msi,
    [Parameter(Mandatory = $true)][string]$Previous,
    [string]$MainBinaryName = 'birdo-vpn-desktop',
    [int]$TimeoutSec = 180 # per wait
)

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Host "::error::nsis-msi-era-upgrade: $msg"
    exit 1
}
function Step([string]$msg) { Write-Host "-- $msg" }
function Get-DefaultValue([string]$key) {
    if (Test-Path -LiteralPath $key) { return (Get-Item -LiteralPath $key).GetValue('') }
    return $null
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
    Fail 'refusing to run outside a GitHub-hosted runner: this installs, plants Apps & features entries and uninstalls BirdoVPN machine-wide'
}
foreach ($f in @($Installer, $Msi, $Previous)) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Fail "not found: $f" }
}
$Installer = (Resolve-Path -LiteralPath $Installer).Path
$Msi = (Resolve-Path -LiteralPath $Msi).Path
$Previous = (Resolve-Path -LiteralPath $Previous).Path

$conf = Get-Content -Raw -LiteralPath 'src-tauri/tauri.conf.json' | ConvertFrom-Json
$product = $conf.productName
$version = $conf.version
$publisher = $conf.bundle.publisher
$schemes = @($conf.plugins.'deep-link'.desktop.schemes)
if ($schemes.Count -eq 0) { Fail 'tauri.conf.json declares no deep-link scheme to check' }

# What every MSI-era MSI carried (nsis-hooks.nsh, WIN2-012).
$msiEraPublisher = 'Birdo VPN'
$msiEraUpgradeCode = '{A5391D09-4F7F-5D63-841B-D35670681DB4}' # UUID v5 (DNS) of "BirdoVPN.exe.app.x64"

$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$uninstRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$instDir = Join-Path $env:ProgramFiles $product
$exe = Join-Path $instDir "$MainBinaryName.exe"
$uninstaller = Join-Path $instDir 'uninstall.exe'
$nsisKey = "$uninstRoot\$product"
$msiUninstallLnk = Join-Path $instDir "Uninstall $product.lnk"
$hkcuRecord = "HKCU:\Software\$msiEraPublisher\$product" # the MSI's InstallDir value
# NSIS_HOOK_POSTINSTALL's pre-D8 mirror lives under this key. POSTUNINSTALL
# drops the mirror and then this parent (if it is empty), as its last act.
$mirrorKey = "HKLM:\SOFTWARE\$msiEraPublisher"
$desktopLnk = Join-Path $env:PUBLIC "Desktop\$product.lnk"
$programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$msiStartFolder = Join-Path $programs $product
$nsisStartLnk = Join-Path $programs "$product.lnk"
$hookLog = Join-Path $env:TEMP 'BirdoVPN-msi-era-uninstall.log' # nsis-hooks.nsh BirdoRemoveMsiEraEntry
$work = Join-Path $env:RUNNER_TEMP 'msi-era'
New-Item -ItemType Directory -Force -Path $work | Out-Null

Add-Type -Namespace BirdoCi -Name Msi -MemberDefinition @'
[DllImport("msi.dll", CharSet = CharSet.Unicode)]
public static extern int MsiQueryProductStateW(string product);
[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern uint GetLongPathNameW(string shortPath, System.Text.StringBuilder longPath, uint size);
'@
function Get-ProductState([string]$code) { return [BirdoCi.Msi]::MsiQueryProductStateW($code) } # 5 installed, -1 unknown
function Get-LongPath([string]$path) {
    $sb = New-Object System.Text.StringBuilder 1024
    if ([BirdoCi.Msi]::GetLongPathNameW($path, $sb, 1024) -gt 0) { return $sb.ToString() }
    return $path
}

# One value from the MSI's Property table, read without installing anything.
function Get-MsiProperty([string]$path, [string]$name) {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($path, [int]0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'"))
    $null = $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    $value = if ($null -ne $rec) { $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @([int]1)) } else { $null }
    $null = $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
    $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($db)
    return $value
}

# Every Apps & features entry that calls itself BirdoVPN or Birdo VPN.
function Get-BirdoEntries {
    @(Get-ChildItem -LiteralPath $uninstRoot | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath
            $dn = $p.PSObject.Properties['DisplayName']
            if ($dn -and ($dn.Value -ceq $product -or $dn.Value -ceq $msiEraPublisher)) {
                $get = { param($n) $v = $p.PSObject.Properties[$n]; if ($v) { "$($v.Value)" } else { '' } }
                [pscustomobject]@{
                    Key              = $_.PSChildName
                    DisplayName      = & $get 'DisplayName'
                    Publisher        = & $get 'Publisher'
                    DisplayVersion   = & $get 'DisplayVersion'
                    WindowsInstaller = & $get 'WindowsInstaller'
                    UninstallString  = & $get 'UninstallString'
                    InstallLocation  = & $get 'InstallLocation'
                }
            }
        })
}
function Show-Entries([string]$title) {
    Write-Host "   Apps & features, $title`:"
    Get-BirdoEntries | ForEach-Object {
        Write-Host ('     {0}  "{1}" / "{2}" {3} WindowsInstaller={4} Uninstall: {5}' -f $_.Key, $_.DisplayName, $_.Publisher, $_.DisplayVersion, $_.WindowsInstaller, $_.UninstallString)
    }
}
# Ours and the MSI era's: the entries the closure counts.
function Get-ProductEntries {
    @(Get-BirdoEntries | Where-Object { $_.DisplayName -ceq $product -and ($_.Publisher -ceq $publisher -or $_.Publisher -ceq $msiEraPublisher) })
}
function Get-KeySnapshot([string]$key) {
    $p = Get-ItemProperty -LiteralPath $key
    return (@($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) | Sort-Object) -join '; '
}

function Assert-Clean([string]$when) {
    Step "no BirdoVPN on the runner ($when)"
    # Not HKLM\SOFTWARE\<publisher>\<product>: a silent uninstall keeps that
    # record of the folder (the template drops it only with "Delete the
    # application data"), and nsis-install-smoke.ps1 has just run one.
    $traces = @($instDir, $nsisKey, 'HKLM:\SOFTWARE\Birdo VPN', $desktopLnk, $msiStartFolder, $nsisStartLnk) +
        @($schemes | ForEach-Object { "HKLM:\SOFTWARE\Classes\$_" })
    foreach ($t in $traces) {
        if (Test-Path -LiteralPath $t) { Fail "$t exists ($when)" }
    }
    $left = Get-BirdoEntries
    if ($left.Count -ne 0) { Show-Entries $when; Fail "$($left.Count) BirdoVPN Apps & features entries exist ($when)" }
    $installDir = (Get-ItemProperty -LiteralPath $hkcuRecord -ErrorAction SilentlyContinue).InstallDir
    if ($installDir) { Fail "$hkcuRecord InstallDir is still '$installDir' ($when): the MSI's record" }
}

function Install-MsiEra([string]$code) {
    Step "install the MSI-era MSI: msiexec /i $(Split-Path -Leaf $Msi) /qn"
    $log = Join-Path $work 'msi-install.log'
    $rc = Invoke-Bounded $msiexec @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$log`"") 'msiexec /i'
    if ($rc -ne 0) {
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 40 | ForEach-Object { Write-Host "   | $_" } }
        Fail "msiexec /i exited $rc"
    }
    if ((Get-ProductState $code) -ne 5) { Fail "Windows Installer does not report $code as installed (state $(Get-ProductState $code))" }
    $e = @(Get-BirdoEntries | Where-Object { $_.Key -eq $code })
    if ($e.Count -ne 1) { Show-Entries 'after msiexec /i'; Fail "no Apps & features entry $code" }
    $e = $e[0]
    $want = [ordered]@{ DisplayName = $product; Publisher = $msiEraPublisher; WindowsInstaller = '1' }
    foreach ($k in $want.Keys) { if ($e.$k -cne $want[$k]) { Fail "the MSI's entry has $k '$($e.$k)', expected '$($want[$k])'" } }
    if ($e.UninstallString -notmatch '(?i)^msiexec\.exe /x\{') { Fail "the MSI's UninstallString is '$($e.UninstallString)'" }
    if ((Get-LongPath $e.InstallLocation.TrimEnd('\')) -ne $instDir) { Fail "the MSI installed into '$($e.InstallLocation)', not $instDir" }
    # What it shares with this installer: the exe's path, birdo://, the
    # desktop shortcut. Plus what only it has.
    foreach ($f in @($exe, $msiUninstallLnk, $desktopLnk, (Join-Path $msiStartFolder "$product.lnk"))) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Fail "the MSI did not install $f" }
    }
    # The MSI writes the exe's SHORT path (Tauri's WiX template uses [!Path]):
    # the same file, the same key.
    foreach ($s in $schemes) {
        $cmd = Get-DefaultValue "HKLM:\SOFTWARE\Classes\$s\shell\open\command"
        if ($cmd -notmatch '^"([^"]+)" "%1"$' -or (Get-LongPath $Matches[1]) -ne $exe) { Fail "after the MSI, ${s}:// opens '$cmd'" }
        Write-Host "   ${s}:// -> $cmd (the MSI's short path for $exe)"
    }
    $rec = (Get-ItemProperty -LiteralPath $hkcuRecord -ErrorAction SilentlyContinue).InstallDir
    if (-not $rec -or (Get-LongPath $rec.TrimEnd('\')) -ne $instDir) { Fail "$hkcuRecord InstallDir is '$rec'" }
    Write-Host "   $code  ""$($e.DisplayName)"" / ""$($e.Publisher)"" $($e.DisplayVersion) WindowsInstaller=$($e.WindowsInstaller)"
    Write-Host "   UninstallString: $($e.UninstallString); InstallLocation: $($e.InstallLocation)"
    Write-Host "   shares with this installer: $exe, birdo://, $desktopLnk; only its own: $msiUninstallLnk, $msiStartFolder\, $hkcuRecord InstallDir"
}

function Invoke-Upgrade([string[]]$arguments) {
    if (Test-Path -LiteralPath $hookLog) { Remove-Item -LiteralPath $hookLog -Force }
    Step "this build: $(Split-Path -Leaf $Installer) $($arguments -join ' ')"
    $rc = Invoke-Bounded $Installer $arguments 'the installer'
    if ($rc -ne 0) { Fail "the installer exited $rc" }
}

function Assert-Upgraded([string]$code) {
    Step 'the MSI is gone, before our files were laid down'
    $state = Get-ProductState $code
    if ($state -ne -1) { Fail "Windows Installer still knows $code (state $state): the installer did not uninstall the MSI" }
    if (Test-Path -LiteralPath "$uninstRoot\$code") { Fail "the MSI's Apps & features entry $code is still there" }
    if (-not (Test-Path -LiteralPath $hookLog -PathType Leaf)) { Fail "no $hookLog`: NSIS_HOOK_PREINSTALL never ran msiexec /x" }
    $done = @(Select-String -LiteralPath $hookLog -Pattern 'Removal success or error status: (\d+)' | ForEach-Object { $_.Matches[0].Groups[1].Value })
    if ($done.Count -eq 0 -or @($done | Where-Object { $_ -ne '0' }).Count -ne 0) {
        Get-Content -LiteralPath $hookLog -Tail 40 | ForEach-Object { Write-Host "   | $_" }
        Fail "the hook's msiexec log reports removal status [$($done -join ',')], expected 0"
    }
    Select-String -LiteralPath $hookLog -SimpleMatch -Pattern 'Removal success or error status' | ForEach-Object { Write-Host "   | $($_.Line.Trim())" }
    foreach ($f in @($exe, $uninstaller, (Join-Path $instDir 'resources\xray.exe'), (Join-Path $instDir 'resources\wintun.dll'))) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Fail "missing after the upgrade: $f (the MSI's uninstall ran after the files were laid down?)" }
    }
    if (Test-Path -LiteralPath $msiUninstallLnk) { Fail "$msiUninstallLnk (msiexec /x) is still there" }
    if (Test-Path -LiteralPath $msiStartFolder) { Fail "the MSI's Start-menu folder $msiStartFolder is still there" }
    $rec = (Get-ItemProperty -LiteralPath $hkcuRecord -ErrorAction SilentlyContinue).InstallDir
    if ($rec) { Fail "$hkcuRecord InstallDir is still '$rec'" }

    Step 'exactly one BirdoVPN entry: ours'
    Show-Entries 'after the upgrade'
    $mine = Get-ProductEntries
    if ($mine.Count -ne 1) { Fail "$($mine.Count) BirdoVPN entries (want 1)" }
    $e = $mine[0]
    if ($e.Key -ne $product -or $e.Publisher -cne $publisher -or $e.DisplayVersion -ne $version) {
        Fail "the one entry is $($e.Key) ""$($e.Publisher)"" $($e.DisplayVersion), expected $product ""$publisher"" $version"
    }

    Step 'what the MSI took with it is back'
    foreach ($s in $schemes) {
        $cmd = Get-DefaultValue "HKLM:\SOFTWARE\Classes\$s\shell\open\command"
        if ($cmd -ne "`"$exe`" `"%1`"") { Fail "${s}:// opens '$cmd', expected the installed exe" }
        Write-Host "   ${s}:// -> $cmd"
    }
    foreach ($l in @($desktopLnk, $nsisStartLnk)) {
        if (-not (Test-Path -LiteralPath $l -PathType Leaf)) { Fail "no $l after the upgrade" }
        Write-Host "   $l"
    }

    Step "the leftover uninstall can no longer delete our files: msiexec /x $code /qn"
    $rc = Invoke-Bounded $msiexec @('/x', $code, '/qn', '/norestart') 'msiexec /x'
    if ($rc -ne 1605) { Fail "msiexec /x $code exited $rc, expected 1605 (ERROR_UNKNOWN_PRODUCT)" }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail "$exe is gone after msiexec /x" }
    if ((Get-ProductEntries).Count -ne 1) { Fail 'the entry count changed after msiexec /x' }
    Write-Host "   msiexec /x $code -> 1605; $exe still there"
}

function Invoke-OurUninstall {
    Step "our silent uninstall: $uninstaller /S"
    $rc = Invoke-Bounded $uninstaller @('/S') 'the uninstaller'
    if ($rc -ne 0) { Fail "the uninstaller exited $rc" }
    # It re-runs itself from %TEMP% (Un_A.exe). Wait for that copy, the entry,
    # the folder, and the uninstall's LAST act: NSIS_HOOK_POSTUNINSTALL drops
    # the mirror key after the template has removed the entry and the folder
    # (as nsis-install-smoke.ps1 waits for it too).
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    do {
        $copies = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^(Un_[A-Z]|Au_)$' })
        if ($copies.Count -eq 0 -and -not (Test-Path -LiteralPath $nsisKey) -and -not (Test-Path -LiteralPath $instDir) -and
            -not (Test-Path -LiteralPath $mirrorKey)) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    if (Test-Path -LiteralPath $nsisKey) { Fail "$nsisKey is still there after our uninstall" }
    if (Test-Path -LiteralPath $mirrorKey) { Fail "$mirrorKey is still there: NSIS_HOOK_POSTUNINSTALL did not finish" }
    if (Test-Path -LiteralPath $instDir) {
        Get-ChildItem -LiteralPath $instDir -Recurse -Force | ForEach-Object { Write-Host "   left: $($_.FullName)" }
        Fail "$instDir is still there after our uninstall"
    }
}

# -- the MSI ------------------------------------------------------------------
Step "the MSI-era MSI: $Msi"
$props = [ordered]@{}
foreach ($n in @('ProductName', 'Manufacturer', 'ProductVersion', 'ProductCode', 'UpgradeCode', 'ALLUSERS')) {
    $props[$n] = Get-MsiProperty $Msi $n
    Write-Host "   $n = $($props[$n])"
}
if ($props.ProductName -cne $product) { Fail "ProductName '$($props.ProductName)', expected '$product'" }
if ($props.Manufacturer -cne $msiEraPublisher) { Fail "Manufacturer '$($props.Manufacturer)', expected '$msiEraPublisher'" }
if ($props.UpgradeCode -ne $msiEraUpgradeCode) { Fail "UpgradeCode $($props.UpgradeCode), expected the MSI era's $msiEraUpgradeCode" }
if ($props.ALLUSERS -ne '1') { Fail "ALLUSERS '$($props.ALLUSERS)': the MSI era's MSIs were per-machine" }
$code = $props.ProductCode
if ($code -notmatch '^\{[0-9A-F-]{36}\}$') { Fail "ProductCode '$code'" }

# -- phase A ------------------------------------------------------------------
Write-Host ''
Write-Host '== Phase A: MSI-era install (+ planted entries) -> this build, silent'
Assert-Clean 'before phase A'
Install-MsiEra $code

Step 'plant: a leftover MSI-era entry, and two entries that are not ours to touch'
$stub = Join-Path $work 'uninstall-stub.cmd'
Set-Content -LiteralPath $stub -Encoding ascii -Value "@echo off`r`necho ran %* > `"$work\stub-ran-%1.txt`"`r`n"
$planted = [ordered]@{
    leftover = @{ Key = '{0E1D2C3B-4A59-4687-9A6B-1C2D3E4F5A6B}'; DisplayName = $product; Publisher = $msiEraPublisher } # Windows Installer: unknown
    other    = @{ Key = '{1F2E3D4C-5B6A-4798-8B7C-2D3E4F5A6B7C}'; DisplayName = $product; Publisher = 'Someone Else' }
    v100     = @{ Key = '{2A3B4C5D-6E7F-4809-9C8D-3E4F5A6B7C8D}'; DisplayName = $msiEraPublisher; Publisher = $msiEraPublisher } # the 1.0.0 product
}
foreach ($name in $planted.Keys) {
    $p = $planted[$name]
    if ((Get-ProductState $p.Key) -ne -1) { Fail "$($p.Key) is a product Windows Installer knows: pick another GUID" }
    $k = New-Item -Path "$uninstRoot\$($p.Key)" -Force
    New-ItemProperty -LiteralPath $k.PSPath -Name DisplayName -Value $p.DisplayName | Out-Null
    New-ItemProperty -LiteralPath $k.PSPath -Name Publisher -Value $p.Publisher | Out-Null
    New-ItemProperty -LiteralPath $k.PSPath -Name DisplayVersion -Value '1.4.20' | Out-Null
    New-ItemProperty -LiteralPath $k.PSPath -Name WindowsInstaller -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -LiteralPath $k.PSPath -Name UninstallString -Value "`"$stub`" $name" | Out-Null
}
$untouched = @{}
foreach ($name in @('other', 'v100')) { $untouched[$name] = Get-KeySnapshot "$uninstRoot\$($planted[$name].Key)" }
Show-Entries 'before the upgrade'

Invoke-Upgrade @('/S')
Assert-Upgraded $code

Step 'the planted entries: the leftover deleted, the others untouched, the stub never run'
if (Test-Path -LiteralPath "$uninstRoot\$($planted.leftover.Key)") { Fail "the leftover MSI-era entry $($planted.leftover.Key) is still there" }
foreach ($name in $untouched.Keys) {
    $key = "$uninstRoot\$($planted[$name].Key)"
    if (-not (Test-Path -LiteralPath $key)) { Fail "the $name entry $($planted[$name].Key) was deleted: it is not ours" }
    if ((Get-KeySnapshot $key) -ne $untouched[$name]) { Fail "the $name entry $($planted[$name].Key) was changed" }
}
$ran = @(Get-ChildItem -LiteralPath $work -Filter 'stub-ran-*.txt')
if ($ran.Count -ne 0) { Fail "an entry's UninstallString ran: $($ran.Name -join ', ')" }
Write-Host "   leftover $($planted.leftover.Key) deleted; other and 1.0.0 entries unchanged; stub never ran"

# A key that has a {GUID}'s length and braces but is no GUID, with every
# other MSI-era mark. Before IIDFromString, it passed the shape check:
#   - where MsiQueryProductStateW answers -2 (INVALIDARG), it reached
#     `msiexec /x` unquoted, able to pass arguments or leave a silent install
#     on msiexec's usage dialog;
#   - where it answers -1, as it does on the runner (printed below), it was
#     deleted as a "leftover".
# Now nothing matches it, so both checks hold: the hook's msiexec log never
# appears, and the entry is byte-for-byte unchanged. Planted with the .NET
# API, because the provider would split the "/" into a sub-key. Checked on
# their own, with the MSI already gone, by running this build over itself.
Step 'a 38-character key that is not a GUID never reaches msiexec'
$hklm64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$uninstPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
function Get-RawSnapshot([string]$name) {
    $k = $hklm64.OpenSubKey("$uninstPath\$name")
    if ($null -eq $k) { return $null }
    try { return (@($k.GetValueNames() | Sort-Object | ForEach-Object { "$_=$($k.GetValue($_))" }) -join '; ') } finally { $k.Close() }
}
$malformed = @('{BIRDOVPN-NOTA-GUID-0000-000000000000}', '{00000000-0000-0000-0000-00000000 /qb}')
$rawBefore = @{}
foreach ($m in $malformed) {
    if ($m.Length -ne 38) { Fail "test bug: '$m' has $($m.Length) characters, not 38" }
    $k = $hklm64.CreateSubKey("$uninstPath\$m")
    $k.SetValue('DisplayName', $product)
    $k.SetValue('Publisher', $msiEraPublisher)
    $k.SetValue('DisplayVersion', '1.4.20')
    $k.SetValue('WindowsInstaller', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
    $k.SetValue('UninstallString', "`"$stub`" malformed")
    $k.Close()
    $rawBefore[$m] = Get-RawSnapshot $m
    Write-Host "   planted $m (Windows Installer state $(Get-ProductState $m))"
}
Invoke-Upgrade @('/S')
if (Test-Path -LiteralPath $hookLog) {
    Get-Content -LiteralPath $hookLog -Tail 20 | ForEach-Object { Write-Host "   | $_" }
    Fail "msiexec ran for a key that is not a GUID ($hookLog exists)"
}
foreach ($m in $malformed) {
    if ((Get-RawSnapshot $m) -ne $rawBefore[$m]) { Fail "the entry '$m' was changed or deleted" }
    $hklm64.DeleteSubKeyTree("$uninstPath\$m")
}
$ran = @(Get-ChildItem -LiteralPath $work -Filter 'stub-ran-*.txt')
if ($ran.Count -ne 0) { Fail "an entry's UninstallString ran: $($ran.Name -join ', ')" }
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail "$exe is missing after the re-run" }
Write-Host "   no msiexec log, both entries untouched, stub never ran"

Invoke-OurUninstall
foreach ($name in $untouched.Keys) { Remove-Item -LiteralPath "$uninstRoot\$($planted[$name].Key)" -Recurse -Force }

# -- phase B ------------------------------------------------------------------
Write-Host ''
Write-Host '== Phase B: MSI-era install + v1.4.46 over it -> this build as the in-app updater runs it'
Assert-Clean 'before phase B'
Install-MsiEra $code

Step "v1.4.46 over it, silently: $(Split-Path -Leaf $Previous) /S"
$rc = Invoke-Bounded $Previous @('/S') 'the v1.4.46 installer'
if ($rc -ne 0) { Fail "the v1.4.46 installer exited $rc" }
Show-Entries 'after v1.4.46'
$both = Get-ProductEntries
if ($both.Count -ne 2 -or (Get-ProductState $code) -ne 5) {
    Fail "expected v1.4.46 to leave the MSI installed beside it, two entries (WIN2-012 as shipped); found $($both.Count), MSI state $(Get-ProductState $code)"
}
Write-Host '   two entries and the MSI still installed: WIN2-012 as v1.4.46 ships it'

# The in-app updater's arguments (tauri-plugin-updater: /P /R /UPDATE /ARGS),
# without /R and /ARGS, which only relaunch the app.
Invoke-Upgrade @('/P', '/UPDATE')
Assert-Upgraded $code

Invoke-OurUninstall
Assert-Clean 'after phase B'

Write-Host ''
Write-Host 'OK - an upgrade over an MSI-era install leaves one entry and no MSI, matches nothing else, never runs an UninstallString, and survives the old msiexec /x'
exit 0
