#!/usr/bin/env pwsh
# ============================================================
# Birdo VPN — Windows QA Checklist\n# (For macOS QA, see qa-checklist-macos.sh when available)
# ============================================================
# Run this script to walk through the manual QA test matrix.
# Mark each test as PASS / FAIL / SKIP with notes.
# Results are written to qa-results-<date>.json
# ============================================================

param(
    [string]$OutputPath = ".\qa-results-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').json"
)

$ErrorActionPreference = 'Stop'

# Detect Windows version
$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$osBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
Write-Host "=== Birdo VPN QA Test Matrix ===" -ForegroundColor Cyan
Write-Host "OS: $osVersion (Build $osBuild)" -ForegroundColor Gray
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

$testCases = @(
    @{ id = "INSTALL-01"; category = "Installation"; name = "Clean install via NSIS installer"; details = "Run the NSIS installer. Verify no errors. Verify files are installed to %LOCALAPPDATA%\birdo-vpn." }
    @{ id = "INSTALL-02"; category = "Installation"; name = "UAC prompt appears only for Wintun driver"; details = "During first launch, UAC should prompt ONLY for wintun.dll driver installation, not for the app itself." }
    @{ id = "LAUNCH-01"; category = "Launch"; name = "App launches and system tray icon appears"; details = "Launch the app. Verify main window opens. Verify system tray icon appears (disconnected state)." }
    @{ id = "LAUNCH-02"; category = "Launch"; name = "App starts within 3 seconds"; details = "Measure time from double-click to window visible. Should be under 3 seconds." }
    @{ id = "AUTH-01"; category = "Authentication"; name = "Login with email/password"; details = "Enter valid credentials. Verify login succeeds. Verify dashboard/server list loads." }
    @{ id = "AUTH-02"; category = "Authentication"; name = "Login with invalid credentials shows error"; details = "Enter wrong password. Verify clear error message. Verify no crash." }
    @{ id = "AUTH-03"; category = "Authentication"; name = "Logout clears state"; details = "Log out. Verify return to login screen. Verify VPN disconnects if connected." }
    @{ id = "SERVER-01"; category = "Server List"; name = "Server list loads"; details = "After login, verify server list populates with at least 1 server. Verify country codes, city names, and load percentages display." }
    @{ id = "SERVER-02"; category = "Server List"; name = "Search filter works"; details = "Type a country or city name in search. Verify list filters correctly." }
    @{ id = "SERVER-03"; category = "Server List"; name = "Favorite toggle works"; details = "Click the star icon on a server. Verify it toggles. Switch to Favorites tab. Verify it appears." }
    @{ id = "VPN-01"; category = "VPN Connection"; name = "VPN connects successfully"; details = "Click the connection button. Verify state goes connecting -> connected. Verify tray icon updates." }
    @{ id = "VPN-02"; category = "VPN Connection"; name = "IP address changes when connected"; details = "Before connecting, note your IP. After connecting, visit https://ipleak.net and verify IP has changed." }
    @{ id = "VPN-03"; category = "VPN Connection"; name = "Graceful disconnect"; details = "Click disconnect. Verify state goes disconnecting -> disconnected. Verify IP reverts to original." }
    @{ id = "VPN-04"; category = "VPN Connection"; name = "Server switching"; details = "Connect to server A. Then click server B. Verify disconnect from A and connect to B." }
    @{ id = "KS-01"; category = "Kill Switch"; name = "Kill switch blocks traffic on disconnect"; details = "Connect to VPN. Pull network cable or disable adapter briefly. Verify no traffic leaks (DNS, WebRTC)." }
    @{ id = "KS-02"; category = "Kill Switch"; name = "Kill switch releases on reconnect"; details = "After kill switch engages, reconnect VPN. Verify full connectivity restores." }
    @{ id = "KS-03"; category = "Kill Switch"; name = "Kill switch can be disabled"; details = "Go to Settings. Toggle kill switch off. Verify traffic flows even when VPN disconnects unexpectedly." }
    @{ id = "TRAY-01"; category = "System Tray"; name = "System tray context menu works"; details = "Right-click tray icon. Verify menu shows Connect/Disconnect, Show Window, Quit options." }
    @{ id = "TRAY-02"; category = "System Tray"; name = "Tray icon reflects connection state"; details = "Verify icon changes between disconnected (red/gray) and connected (green) states." }
    @{ id = "STAB-01"; category = "Stability"; name = "App survives sleep/wake cycle"; details = "Put PC to sleep for 30 seconds while connected. Wake up. Verify VPN reconnects or shows clear status." }
    @{ id = "STAB-02"; category = "Stability"; name = "App survives network change (WiFi→Ethernet)"; details = "Connect via WiFi. Then plug in Ethernet. Verify VPN stays connected or gracefully reconnects." }
    @{ id = "STAB-03"; category = "Stability"; name = "App handles server unavailable gracefully"; details = "Try connecting to an offline server (if available). Verify clear error message, no crash." }
    @{ id = "SETTINGS-01"; category = "Settings"; name = "Settings persist across app restart"; details = "Change kill switch, auto-connect, and notifications settings. Close and reopen app. Verify settings retained." }
    @{ id = "SETTINGS-02"; category = "Settings"; name = "Auto-start toggle works"; details = "Enable auto-start in settings. Restart PC or check startup entries. Verify app launches on boot." }
    @{ id = "UPDATE-01"; category = "Updates"; name = "Update check runs without crash"; details = "If update server is live, verify update check completes without error. If no update, verify 'up to date' message." }
    @{ id = "UNINSTALL-01"; category = "Uninstall"; name = "Uninstall removes all files and tray icon"; details = "Run uninstaller. Verify app files removed from %LOCALAPPDATA%. Verify system tray icon removed. Verify no orphaned services." }
)

$results = @()

foreach ($test in $testCases) {
    Write-Host ""
    Write-Host "[$($test.id)] $($test.category): $($test.name)" -ForegroundColor Yellow
    Write-Host "  $($test.details)" -ForegroundColor Gray
    Write-Host ""
    
    $status = Read-Host "  Result (P=pass, F=fail, S=skip)"
    $notes = ""
    if ($status -eq 'F' -or $status -eq 'f') {
        $notes = Read-Host "  Failure notes"
    }
    
    $results += @{
        id = $test.id
        category = $test.category
        name = $test.name
        status = switch ($status.ToUpper()) {
            'P' { 'PASS' }
            'F' { 'FAIL' }
            'S' { 'SKIP' }
            default { 'UNKNOWN' }
        }
        notes = $notes
        timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

# Summary
$passed = ($results | Where-Object { $_.status -eq 'PASS' }).Count
$failed = ($results | Where-Object { $_.status -eq 'FAIL' }).Count
$skipped = ($results | Where-Object { $_.status -eq 'SKIP' }).Count

Write-Host ""
Write-Host "=== QA Summary ===" -ForegroundColor Cyan
Write-Host "  PASS:  $passed" -ForegroundColor Green
Write-Host "  FAIL:  $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
Write-Host "  SKIP:  $skipped" -ForegroundColor Yellow
Write-Host "  TOTAL: $($testCases.Count)" -ForegroundColor White

# Save results
$report = @{
    os = $osVersion
    osBuild = $osBuild
    date = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    summary = @{ passed = $passed; failed = $failed; skipped = $skipped; total = $testCases.Count }
    results = $results
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host ""
Write-Host "Results saved to: $OutputPath" -ForegroundColor Green

if ($failed -gt 0) {
    Write-Host ""
    Write-Host "FAILURES:" -ForegroundColor Red
    $results | Where-Object { $_.status -eq 'FAIL' } | ForEach-Object {
        Write-Host "  [$($_.id)] $($_.name): $($_.notes)" -ForegroundColor Red
    }
}
