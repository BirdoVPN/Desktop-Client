# Desktop Windows on-device leak validation

The WFP, route and DNS behaviour below cannot be exercised in CI (no Wintun
driver, no elevation, no real network). It **must be run on a real Windows box
before a release ships it**. Every step is a concrete command with the result
that passes it. Part A changes nothing; every Part B step names its rollback,
and a dead-man's switch (B0) undoes everything if a step leaves the machine in
a bad state.

Applies to the build that replaced DNS parking with the WFP DNS guard
(W1-007), scoped the kill-switch permits to the app (W1-013), added the inbound
block (W1-014), the event-driven data plane (W1-006), in-place roaming (W1-003),
fast dead-path detection, the route journal (W1-041) and the uninstall heal
(W1-008), and to every build since #287 (MR-1721), which moved that journal
into the admin-only `%ProgramData%\BirdoVPN`.

---

## What this build does

**It never changes any adapter's DNS settings.** Older builds set every
physical adapter to `static none` for the session ("parking"). An unclean exit
left the machine without DNS, and on an adapter with *static* resolvers the
park erased them for good (seen on 1.4.45). This build leaves adapter DNS
alone and enforces DNS with filters in a **dynamic** WFP session — Windows
deletes them when the process ends, however it ends.

**The DNS guard** is installed on every connect, kill switch on or off, before
the first tunnel route. A connect whose guard cannot be installed fails.

| Filter (as `netsh wfp show filters` names it) | Layer | Weight | Effect |
|---|---|---|---|
| `Birdo: Permit DNS to the tunnel resolvers` | connect v4 | 13 | UDP/TCP 53 + 853 to the tunnel's resolvers, **over the tunnel interface only** |
| `Birdo: Permit DNS on loopback` | connect v4, v6 | 13 | a local DNS proxy (127/8, ::1) |
| `Birdo: Block DNS outside the tunnel` | connect v4, v6 | 12 | UDP/TCP 53 and 853 (DNS, DoT, DoQ) to any other resolver, on any interface |
| `Birdo: Block LLMNR, mDNS and NetBIOS name queries` | connect v4, v6 | 12 | UDP 5355, 5353, 137 — only while **Local Network Sharing is off** |
| `Birdo: Permit DNS to your own network's resolver (Custom DNS, Local Network Sharing)` | connect v4 | 13 | only when a Custom DNS server is in a private range AND Local Network Sharing is on: that resolver, any interface |
| `Birdo: Permit the relay (WireGuard) on a DNS port` | connect v4 | 13 | only when the WireGuard port is 53: BirdoVPN.exe + relay/32 + UDP 53 |

The block (12) and the loopback permit (13) are also carried by the kill
switch's block-all, so they hold through a reconnect gap and behind a held
lockdown block, after the tunnel's guard is lifted (REVIEW-WIN2-004). With both
up there is one set, not two.

Why each:

- **SMHNR.** Smart Multi-Homed Name Resolution sends every query to every
  adapter's resolvers in parallel. The block stops the physical (and virtual)
  adapters' copies, whatever their resolvers are and however they were
  configured (DHCP or static).
- **LLMNR, mDNS, NetBIOS.** Windows broadcasts single-label lookups to the LAN
  with these, so they are blocked unless the user asked for the LAN.
- **DNS-over-HTTPS (443)** is not blocked: it is encrypted and routed through
  the tunnel like any HTTPS.
- **Virtual adapters** (VirtualBox host-only, the WSL / Hyper-V switch) are
  treated like every other interface for the host's own DNS: port-53 traffic
  that is not to the tunnel resolver is blocked. A VM's own traffic is
  forwarded, not host-originated, so the ALE filters do not see it; it is
  routed into the tunnel.

**The kill switch** has two modes. Lockdown, the Windows default, keeps the
block on for the whole connected session. Reactive mode installs it only during
a reconnect gap. In both, these filters go in at the connect and the
receive-accept (inbound) layers:

| Filter | Layers | Weight |
|---|---|---|
| `Birdo: Block all outbound IPv4` / `IPv6`, `Birdo: Block all inbound IPv4` / `IPv6` | connect v4/v6, recv-accept v4/v6 | 1 |
| `Birdo: Permit IPv4 localhost (outbound)` / `(inbound)`, `Birdo: Permit IPv6 localhost (outbound)` / `(inbound)` | all four | 10 |
| `Birdo: Permit DHCP`, `Birdo: Permit DHCP (inbound)`, `Birdo: Permit DHCPv6`, `Birdo: Permit DHCPv6 (inbound)` | | 10 |
| `Birdo: Permit IPv6 neighbor discovery` | connect v6, recv-accept v6 | 10 |
| `Birdo: Permit the relay (WireGuard)` and `… (inbound)`: **BirdoVPN.exe + relay/32 + UDP + the WireGuard port** | connect v4, recv-accept v4 | 10 |
| `Birdo: Permit the relay (stealth)`: **xray.exe + relay/32 + TCP + the Reality port** (stealth sessions) | connect v4 | 10 |
| `Birdo: Permit the app's own HTTPS (control plane)`: **BirdoVPN.exe + TCP 443** | connect v4, v6 | 10 |
| `Birdo: Permit the tunnel interface` (lockdown, tunnel up) | all four | 10 |
| `Birdo: Permit inbound on a host-only virtual network` (up adapters with no default gateway) | recv-accept v4, v6 | 10 |
| `Birdo: Permit LAN 10.0.0.0/8`, `… 172.16.0.0/12`, `… 192.168.0.0/16`, `… link-local` (LAN sharing) | connect v4, recv-accept v4 | 10 |
| `Birdo: Permit kill-switch exception (<exe>)` | all four | 10 |
| `Birdo: Block STUN/UDP`, `Birdo: Block TURN/TCP`, `Birdo: Block Google STUN` | connect v4, v6 | 15 |

There is no longer a permit for "anything to the relay's address" (D-24), or
for "BirdoVPN.exe / xray.exe to anywhere". If an executable's app id cannot be
resolved, birdo.log says so at ERROR and the relay permit falls back to
address + protocol + port; its name then ends `any app — app id unavailable`.

**Routes.** The endpoint `/32` and the LAN-sharing routes go via the physical
gateway. They are written to `%ProgramData%\BirdoVPN\dns-restore.json`
(admin-only: only an elevated process can read or write it) with the boot
time, and a start after a crash in the same boot deletes exactly those rows. The tunnel address is `/32`, and every tunnel resolver gets an on-link
`/32` route on `Birdo VPN`.

**Roaming.** When the default route moves to another gateway or interface,
the client moves its gateway routes to the new path, rebinds the WireGuard
socket and forces a handshake on the SAME session. If no handshake completes
within 10 s, it falls back to a full re-dial.

**Dead path.** Four unanswered handshake initiations over 15 s, while traffic
is waiting, declare the tunnel dead and start the reconnect. Before this
build, that took up to ~3 min.

---

## Conventions

Run everything in an **elevated** PowerShell. Set these once per session:

```powershell
$Exe   = "$env:ProgramFiles\BirdoVPN\BirdoVPN.exe"      # adjust for a dev build
$Log   = "$env:APPDATA\BirdoVPN\logs\birdo.log"
$Jrnl  = "$env:ProgramData\BirdoVPN\dns-restore.json"   # the route/DNS journal (admin-only, since #287)
$LegacyJrnl = "$env:APPDATA\BirdoVPN\dns-restore.json"  # where builds before #287 wrote it; A1 only
$Base  = "$env:TEMP\birdo-baseline"
$Ifaces = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
$Phys  = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
$PhysGuid = (Get-NetAdapter -Name $Phys).InterfaceGuid
$PhysDns  = (Get-DnsClientServerAddress -InterfaceAlias $Phys -AddressFamily IPv4).ServerAddresses
New-Item -ItemType Directory -Force $Base | Out-Null

function Birdo-Filters {
  $f = "$env:TEMP\birdo-wfp.xml"
  netsh wfp show filters file="$f" | Out-Null
  ([xml](Get-Content $f)).SelectNodes('//item[displayData/name[starts-with(.,"Birdo:")]]') |
    ForEach-Object { '{0,-42} w{1,-3} {2}' -f $_.layerKey, $_.weight.uint8, $_.displayData.name } |
    Sort-Object
}
function Birdo-LogMark { (Get-Content $Log | Measure-Object -Line).Lines }
function Birdo-LogSince($mark) { Get-Content $Log | Select-Object -Skip $mark }
# Keeps traffic waiting (a ping a second) until birdo.log has $pattern after
# $mark: $true, or $false after about $seconds seconds.
function Birdo-WaitLog($mark, $pattern, $seconds = 90) {
  foreach ($i in 1..$seconds) {
    if (Birdo-LogSince $mark | Select-String -Quiet $pattern) { return $true }
    Test-Connection 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep 1
  }
  $false
}
```

**Where the journal is.** Since #287 (MR-1721) the record of the routes and
DNS a session changed is machine-wide, in the admin-only
`%ProgramData%\BirdoVPN` (`src-tauri/src/utils/protected_dir.rs`). Only an
elevated process can read it, so check it from the elevated window. The log
stays per-user in `%APPDATA%`. If `HKLM:\SOFTWARE\BirdoVPN` has a
`ProtectedStateDir` value, the app found `BirdoVPN` squatted at its first
start and uses `%ProgramData%\<that value>` instead: point `$Jrnl` there.
`$LegacyJrnl` is where builds before #287 wrote the journal. The first start of
a newer build moves one it finds there into `$Jrnl`, once per account: as
written on the first start after an upgrade from such a build, otherwise with
its routes dropped and its adapters set back to automatic DNS. It never reads
that folder for a journal again; only A1 looks at it.

On the owner's PC, `$Phys` is `WiFi 3` and `$PhysDns` is `8.8.8.8, 8.8.4.4`
(static). `Ethernet 2` (VirtualBox host-only) and `vEthernet (WSL (Hyper-V
firewall))` are up virtual adapters. `Birdo-Filters` prints one line per filter
(`layer`, weight, name).

While connected, read the relay and the tunnel resolvers like this:

```powershell
$Relay = (Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -like '*/32' -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -eq $Phys } | Select-Object -First 1).DestinationPrefix -replace '/32',''
$TunnelDns = (Get-DnsClientServerAddress -InterfaceAlias 'Birdo VPN' -AddressFamily IPv4).ServerAddresses
```

---

## Part A — safe (reads only, no network impact)

### A1. Baseline (before installing or connecting)

```powershell
Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses | Export-Clixml "$Base\dns.xml"
Get-ChildItem $Ifaces | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath
  [pscustomobject]@{ Guid = $_.PSChildName; NameServer = $p.NameServer; DhcpNameServer = $p.DhcpNameServer }
} | Export-Clixml "$Base\nameserver.xml"
route print -4 | Out-File "$Base\routes.txt"
Birdo-Filters | Out-File "$Base\filters.txt"
Test-Path $Jrnl
Test-Path $LegacyJrnl
```

**Pass:** `filters.txt` is empty (no `Birdo:` filter exists). Note whether
either journal exists. `$Jrnl` means a killed session of a build since #287
left routes or DNS behind; `$LegacyJrnl` means an older build did. The first
start of the build under test heals either (a legacy one is first moved into
`$Jrnl`, logged as `Moved the DNS journal to the admin-only directory`). B9
part 1 tests that heal on a record you plant.

### A2. The comparison every Part B step uses

```powershell
function Birdo-Compare {
  $line = { "$($_.InterfaceAlias)|$($_.AddressFamily)|$($_.ServerAddresses -join ',')" }
  Compare-Object (Import-Clixml "$Base\dns.xml" | ForEach-Object $line) `
                 (Get-DnsClientServerAddress | ForEach-Object $line)
  Compare-Object (Import-Clixml "$Base\nameserver.xml" | ForEach-Object { "$($_.Guid)|$($_.NameServer)" }) `
                 (Get-ChildItem $Ifaces | ForEach-Object { "$($_.PSChildName)|$((Get-ItemProperty $_.PSPath).NameServer)" })
}
Birdo-Compare
```

**Pass:** no output. The adapters' DNS is exactly the baseline, including
every static `NameServer`.

---

## Part B — network-affecting (each step undoes itself)

### B0. Dead-man's switch (start before B1, stop after W15)

```powershell
$Rollback = "$Base\rollback.ps1"
@'
taskkill /F /IM BirdoVPN.exe 2>$null
taskkill /F /IM xray.exe 2>$null
Get-NetFirewallRule -DisplayName 'BirdoTest-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$ifaces = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
foreach ($b in Import-Clixml "$env:TEMP\birdo-baseline\nameserver.xml") {
  $now = (Get-ItemProperty "$ifaces\$($b.Guid)" -ErrorAction SilentlyContinue).NameServer
  if ("$now" -eq "$($b.NameServer)") { continue }
  $a = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid -eq $b.Guid }
  if (-not $a) { continue }
  if ($b.NameServer) {
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ($b.NameServer -split '[, ]+' | Where-Object { $_ })
  } else {
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
  }
}
ipconfig /flushdns | Out-Null
'@ | Set-Content -Encoding UTF8 $Rollback
function Birdo-ArmDeadMan {
  if ($global:DeadMan) { Stop-Process $global:DeadMan -ErrorAction SilentlyContinue }
  $global:DeadMan = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile','-Command',"Start-Sleep 1800; & '$Rollback'"
}
Birdo-ArmDeadMan
```

The switch fires 30 minutes after it was last armed, and Part B takes longer
than that. Run `Birdo-ArmDeadMan` again at the start of every step: it replaces
the switch already running.

The rollback does four things:

- It kills the app; Windows then deletes every `Birdo:` filter with its dynamic
  session.
- It removes the `BirdoTest-*` firewall rules.
- It puts back the IPv4 `NameServer` of any adapter that differs from the
  baseline (static list, or back to DHCP), and touches no other adapter.
- It flushes the DNS cache.

If anything looks wrong mid-step, run `& $Rollback` at once.
**When Part B is done:** `Stop-Process $DeadMan`.

### B1. Connect: the filter set and the DNS guard (lockdown on, LAN sharing off)

Connect to any server in the app (single-hop). Then:

```powershell
Birdo-Filters
Get-DnsClientServerAddress -InterfaceAlias $Phys -AddressFamily IPv4
Resolve-DnsName example.com -Type A -DnsOnly
Resolve-DnsName example.com -Type A -DnsOnly -Server $TunnelDns[0]
Resolve-DnsName example.com -Type A -DnsOnly -Server 8.8.8.8 -QuickTimeout
Resolve-DnsName example.com -Type A -DnsOnly -Server 1.1.1.1 -QuickTimeout -TcpOnly
nslookup example.com
nslookup example.com 8.8.8.8
Test-NetConnection 1.1.1.1 -Port 853 -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded
Find-NetRoute -RemoteIPAddress $TunnelDns[0] | Select-Object -First 1 InterfaceAlias
Get-NetIPAddress -InterfaceAlias 'Birdo VPN' -AddressFamily IPv4 | Select-Object IPAddress, PrefixLength
Birdo-Compare
```

**Pass**, all of:

- `Birdo-Filters` lists exactly these names. The host-only permit repeats once
  per virtual adapter.
  - Blocks: `Block DNS outside the tunnel` (v4, v6), `Block LLMNR, mDNS and
    NetBIOS name queries` (v4, v6), `Block STUN/UDP`, `Block TURN/TCP`, `Block
    Google STUN` (v4, v6), `Block all outbound IPv4`, `Block all outbound IPv6`,
    `Block all inbound IPv4`, `Block all inbound IPv6`.
  - Permits: `Permit DHCP`, `Permit DHCP (inbound)`, `Permit DHCPv6`, `Permit
    DHCPv6 (inbound)`, `Permit DNS on loopback` (v4, v6), `Permit DNS to the
    tunnel resolvers`, `Permit IPv4 localhost (outbound)`, `Permit IPv4
    localhost (inbound)`, `Permit IPv6 localhost (outbound)`, `Permit IPv6
    localhost (inbound)`, `Permit IPv6 neighbor discovery` (v6 connect and
    inbound), `Permit the app's own HTTPS (control plane)` (v4, v6), `Permit
    the relay (WireGuard)`, `Permit the relay (WireGuard) (inbound)`, `Permit
    the tunnel interface` (all four layers), `Permit inbound on a host-only
    virtual network` (inbound v4/v6; on the owner's PC: one pair each for
    VirtualBox and WSL).
  - **Absent:** `Permit VPN server` and `Permit split-tunnel app (BirdoVPN.exe)`
    (the old unscoped permits).
- The physical adapter still shows its own resolvers (`8.8.8.8, 8.8.4.4`
  here). It is not parked any more.
- The first two `Resolve-DnsName` answer. The `-Server 8.8.8.8` one and the
  `-TcpOnly` one **fail** (any error); an answer is a FAIL.
- `nslookup example.com` answers, and its `Server:` / `Address:` lines name the
  tunnel resolver. `nslookup example.com 8.8.8.8` prints `DNS request timed out`
  and no address.
- Port 853 shows `TcpTestSucceeded : False`.
- `Find-NetRoute` resolves the tunnel resolver to `Birdo VPN` (W1-040).
- The tunnel address has `PrefixLength 32`.
- `Birdo-Compare` prints nothing.

**Rollback:** disconnect in the app.

### B2. Reactive mode: the DNS guard without the block-all

Settings › Privacy & Security › turn **Always-on Kill Switch** off (leave
**Kill Switch** on), then reconnect.

```powershell
Birdo-Filters
Resolve-DnsName example.com -DnsOnly
Resolve-DnsName example.com -DnsOnly -Server 8.8.8.8 -QuickTimeout
Invoke-WebRequest https://example.com -UseBasicParsing -TimeoutSec 10 | Select-Object StatusCode
```

**Pass:**

- `Birdo-Filters` lists exactly these:
  - the DNS guard: `Block DNS outside the tunnel` (v4, v6), `Block LLMNR, mDNS
    and NetBIOS name queries` (v4, v6), `Permit DNS on loopback` (v4, v6),
    `Permit DNS to the tunnel resolvers`;
  - the IPv6 block of an IPv4-only node: `Block all outbound IPv6`, `Permit IPv6
    localhost`, `Permit DHCPv6`.
- The default resolution works, and the `-Server 8.8.8.8` one fails.
- The web request returns `200`.

**Rollback:** turn the setting back on, then disconnect.

### B3. The 1.4.45 data-loss regression: static DNS survives sessions

Run three connect → browse → disconnect cycles (lockdown on), then:

```powershell
Birdo-Compare
Get-ItemProperty "$Ifaces\$PhysGuid" | Select-Object NameServer, DhcpNameServer
```

**Pass:** `Birdo-Compare` prints nothing, and `NameServer` is still
`8.8.8.8,8.8.4.4`.
**Rollback:** none needed, since nothing changed. On a failure, run
`& $Rollback`.

### B4. Hard kill: nothing is left behind (W1-007, W1-041)

Connect with lockdown on (then repeat with Local Network Sharing on), and run:

```powershell
taskkill /F /IM BirdoVPN.exe
Start-Sleep 2
Birdo-Filters
Resolve-DnsName example.com -DnsOnly -Server 8.8.8.8
Birdo-Compare
route print -4 | Select-String $Relay
Get-NetAdapter -Name 'Birdo VPN' -ErrorAction SilentlyContinue
Get-Content $Jrnl
```

**Pass:**

- There is no `Birdo:` filter.
- The query to 8.8.8.8 answers.
- `Birdo-Compare` is empty.

The relay `/32` host route MAY still be listed. With LAN sharing, the
`10.0.0.0`, `172.16.0.0`, `192.168.0.0` and `169.254.0.0` routes via the
gateway may also remain. The journal lists them under `routes`, with a `boot`
value. Record whether the `Birdo VPN` adapter is still present: Wintun 0.14
should remove it with the process, but this has never been observed.

Then start BirdoVPN again (do not connect) and run:

```powershell
route print -4 | Select-String $Relay
Test-Path $Jrnl
Select-String -Path $Log -Pattern 'route\(s\) a previous session left behind' | Select-Object -Last 1
```

**Pass:** no relay route, no journal, and the log line `Removing N route(s) a
previous session left behind`.
**Rollback:** if a route remains, run `& $Rollback` and then
`route delete $Relay`.

### B5. App-scoped relay permit (W1-013, D-24)

The relay permit is `BirdoVPN.exe` + the relay's `/32` + UDP + the WireGuard
port (51820, see "Accepted residuals"). The one flow that tells an app-scoped
permit from an address- or port-scoped one is that same flow from another
process: a UDP datagram to the relay on 51820. TCP probes to other ports prove
nothing here (any port-scoped permit blocks them too), so B5 does not use them.

Connect with lockdown on. The relay's `/32` route goes via the physical
gateway, so the probe below leaves on `$Phys`, not through the tunnel. Run, in
the elevated PowerShell (a process that is not BirdoVPN):

```powershell
Birdo-Filters | Select-String 'Permit the relay'
Select-String -Path $Log -Pattern 'no WFP app id' | Select-Object -Last 1
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
$t0 = Get-Date
$u = [System.Net.Sockets.UdpClient]::new()
try { $u.Send([byte[]](1..32), 32, $Relay, 51820) | Out-Null } catch { $_.Exception.Message } finally { $u.Close() }
Start-Sleep 2
netsh wfp show filters file="$env:TEMP\birdo-wfp.xml" | Out-Null
$FilterName = @{}
([xml](Get-Content "$env:TEMP\birdo-wfp.xml")).SelectNodes('//item[filterId]') |
  ForEach-Object { $FilterName[$_.filterId] = $_.displayData.name }
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $t0 } -ErrorAction SilentlyContinue |
  ForEach-Object { $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }; [pscustomobject]$d } |
  Where-Object { $_.DestAddress -eq $Relay -and $_.DestPort -eq '51820' } |
  ForEach-Object { '{0} -> {1}:{2} protocol {3}: {4}' -f $_.Application, $_.DestAddress, $_.DestPort, $_.Protocol, $FilterName[$_.FilterRTID] }
Invoke-WebRequest https://example.com -UseBasicParsing -TimeoutSec 10 | Select-Object StatusCode
```

**Pass**, all of:

- The permits are `Birdo: Permit the relay (WireGuard)` and `… (inbound)`.
  Neither name ends `any app — app id unavailable`, and birdo.log has no
  `Kill switch: no WFP app id` line.
- The Security log has a blocked connection (event 5157) from
  `…\powershell.exe` (or `pwsh.exe`) to the relay, port `51820`, protocol
  `17`, and the filter it names is `Birdo: Block all outbound IPv4`. The
  `Send` itself may print nothing or an "access forbidden" error; UDP has no
  answer to wait for, so only the event decides. (`netsh wfp show netevents`
  shows the same drop, as a `CLASSIFY_DROP` with the same `filterId`, if you
  prefer it.)
- The web request returns `200`: in the same seconds, BirdoVPN.exe still
  reaches the same relay on the same port.

**FAIL:** no such event while `auditpol /get /subcategory:"Filtering Platform
Connection"` shows Failure auditing on. The datagram then left: the relay
permit is not scoped to the app (D-24, MR-655).
**Rollback:** `auditpol /set /subcategory:"Filtering Platform Connection" /failure:disable`
and the same for `"Filtering Platform Packet Drop"` (skip either that was on
before you started).

Stealth sessions put xray.exe in the relay permit instead: W10 tests that.

### B6. Inbound block (W1-014)

Connect with lockdown on and LAN sharing off. On this PC:

```powershell
$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 8765); $l.Start()
(Get-NetIPAddress -InterfaceAlias $Phys -AddressFamily IPv4).IPAddress
```

From ANOTHER device on the same LAN, connect to `<PC IP>:8765`. Use a phone
port-check app, or `curl -m 5 http://<PC IP>:8765` from another computer.

**Pass:** the connection times out while connected, and connects after you
disconnect in the app. It also connects while connected once Local Network
Sharing is on.

If WSL has a distro, also run this while connected (lockdown on, LAN sharing
off):
`wsl -e sh -c "getent hosts example.com && curl -s -o /dev/null -m 10 -w '%{http_code}\n' https://example.com"`.
It must print an address and `200`, which shows the host-only exemption and
the guard's tunnel permit working.
**Rollback:** `$l.Stop()`.

### B7. Fast dead-path detection (live finding: "the VPN just stops working")

Connect with lockdown on, with traffic running:

```powershell
$m = Birdo-LogMark
New-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay' -Direction Outbound -RemoteAddress $Relay -Protocol UDP -Action Block | Out-Null
$t0 = Get-Date
1..90 | ForEach-Object { Test-Connection 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue | Out-Null; Start-Sleep 1 }
Birdo-LogSince $m | Select-String 'stopped answering handshakes|declared dead|Auto-reconnect attempt'
Remove-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay'
```

**Pass:**

- The log shows `The relay stopped answering handshakes while traffic is
  waiting — declaring the tunnel dead`, then `Tunnel declared dead
  (HandshakeStale)`, then `Auto-reconnect attempt 1`.
- The first of those comes **within 60 s** of `$t0`.
- The tray and the UI show Reconnecting…, with the kill-switch chip.
- After the rule is removed, the session comes back (`Auto-reconnect
  successful`).

**Rollback:** the `Remove-NetFirewallRule` line (`$Rollback` also removes it).

### B8. In-place roaming (W1-003)

This needs a second uplink: Ethernet, a USB tether, or the PC's Wi-Fi moved to
a phone hotspot. Connect on the first uplink, keep `ping -t 1.1.1.1` running in
another window, and run:

```powershell
$m = Birdo-LogMark
$udpBefore = Get-NetUDPEndpoint -OwningProcess (Get-Process BirdoVPN).Id | Select-Object -ExpandProperty LocalPort
$ipBefore  = (Get-NetIPAddress -InterfaceAlias 'Birdo VPN' -AddressFamily IPv4).IPAddress
# now plug in the Ethernet / switch the Wi-Fi network, wait 15 s
Birdo-LogSince $m | Select-String 'Default route moved|Tunnel moved to|In-place roam|API response received|declared dead'
Get-NetUDPEndpoint -OwningProcess (Get-Process BirdoVPN).Id | Select-Object -ExpandProperty LocalPort
(Get-NetIPAddress -InterfaceAlias 'Birdo VPN' -AddressFamily IPv4).IPAddress
Get-NetRoute -DestinationPrefix "$Relay/32" | Select-Object NextHop, InterfaceAlias
```

**Pass:**

- The log shows `Default route moved — the tunnel followed it; re-proving the
  path` and `Tunnel moved to the new network path (N route(s))`.
- There is **no** `API response received` (no new `/vpn/connect`) and no
  `declared dead`.
- The WireGuard UDP port changed, and the tunnel address did not.
- The relay route now points at the new gateway and interface.
- `ping` lost at most a few replies.

A fallback is acceptable, but it must be visible: `In-place roam not possible
(…) — re-dialling`, followed by a reconnect. A stealth session always takes
the fallback; xray owns its relay connection.
**Rollback:** unplug or switch back (the same path in reverse), or disconnect.

### B9. Uninstall and the heal of older builds (W1-008)

**Part 1: an older build's park, healed by `--reconcile-and-exit`** (the step
the uninstaller runs). Do this while not connected.

The record is planted where this build reads it: `$Jrnl`, in the admin-only
folder. That folder exists once the app has started elevated (any earlier step
did that). Never create it by hand: a `BirdoVPN` folder the app did not create
admin-only is moved aside as `BirdoVPN.untrusted-*` and a fresh one is made
(the squatting guard), and the planted record goes with the old folder. A
record planted at `$LegacyJrnl` tests nothing here, because this account's
legacy folder was looked at once, at its first start, and is not read again.

```powershell
$json = @{ os = 'windows'; adapters = @(@{ adapter_name = $Phys; adapter_guid = $PhysGuid.ToUpper(); v4_was_dhcp = $false; v6_was_dhcp = $true; dns_servers = @($PhysDns); dns_servers_v6 = @() }) } |
  ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($Jrnl, $json)   # UTF-8 WITHOUT a BOM: the journal reader refuses one
netsh interface ip set dns name="$Phys" static none validate=no     # what 1.4.45 did
Get-DnsClientServerAddress -InterfaceAlias $Phys -AddressFamily IPv4
(Start-Process $Exe -ArgumentList '--reconcile-and-exit' -Wait -PassThru).ExitCode
Get-DnsClientServerAddress -InterfaceAlias $Phys -AddressFamily IPv4
Test-Path $Jrnl
Birdo-Compare
```

**Pass:**

- After the `netsh` line, the adapter shows DHCP resolvers (or none).
- `--reconcile-and-exit` exits with code `0` and opens no window.
- After it, the adapter shows `8.8.8.8, 8.8.4.4` again.
- The journal is gone, and `Birdo-Compare` is empty.
- birdo.log has `WiFi 3: DNS restored to its pre-connect configuration`.

**Rollback:** `Set-DnsClientServerAddress -InterfaceAlias $Phys -ServerAddresses $PhysDns`.

**Part 2: uninstalling a killed session.** Connect, run
`taskkill /F /IM BirdoVPN.exe`, then uninstall from Settings › Apps with
**Delete the application data** ticked.

**Pass:**

- `route print -4 | Select-String $Relay` is empty.
- `Birdo-Compare` is empty.
- `Test-Path $Jrnl` is `False`: the uninstaller's reconcile put everything
  back and dropped the record. The uninstaller never removes
  `%ProgramData%\BirdoVPN` itself (the settings keys and migration markers stay
  there), so a journal is left there only when a restore could not be
  verified; birdo.log said why before the logs went.
- `Get-ChildItem $env:APPDATA\BirdoVPN` lists nothing, or only a
  `dns-restore.json*` an older build left (the sweep keeps those names, and
  nothing reads them). `$env:LOCALAPPDATA\BirdoVPN` is gone.

Repeat with the box unticked: the same route, DNS and journal results, and
`$env:APPDATA\BirdoVPN\logs` remains.
**Rollback:** reinstall.

### B10. Local Network Sharing

Turn it on, then reconnect (lockdown on):

```powershell
Find-NetRoute -RemoteIPAddress $TunnelDns[0] | Select-Object -First 1 InterfaceAlias
Resolve-DnsName example.com -DnsOnly
$Router = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias $Phys | Select-Object -First 1).NextHop
Resolve-DnsName example.com -DnsOnly -Server $Router -QuickTimeout
Birdo-Filters | Select-String 'LAN|LLMNR'
```

**Pass:**

- The tunnel resolver still routes via `Birdo VPN`, and default resolution
  works.
- A query to the router's DNS fails: DNS stays in the tunnel even with the LAN
  open.
- The four `Permit LAN …` filters exist on both connect v4 and recv-accept v4.
- There is **no** `Block LLMNR, mDNS and NetBIOS name queries`.
- A LAN printer or NAS stays reachable.

**Rollback:** turn it off, then disconnect.

### B11. Idle cost of the data plane (W1-006)

Connect, use nothing, wait 2 minutes, then run:

```powershell
$p = Get-Process BirdoVPN; $a = $p.TotalProcessorTime; Start-Sleep 60; $p.Refresh()
'{0:N0} ms CPU in 60 s' -f ($p.TotalProcessorTime - $a).TotalMilliseconds
```

**Pass:** well under 1 000 ms. The old loop woke ~64 to 200 times a second
while idle; the new one wakes 4 times a second, for boringtun's timers. For
throughput, run `iperf3 -c <server> -R -P4` through the tunnel before and after
the upgrade, if an iperf3 server is available.

### B12. Disconnect and quit

Disconnect, then quit from the tray, and run:

```powershell
Birdo-Filters
Birdo-Compare
route print -4 | Out-File "$Base\routes-after.txt"; Compare-Object (Get-Content "$Base\routes.txt") (Get-Content "$Base\routes-after.txt")
Test-Path $Jrnl
```

**Pass:** no `Birdo:` filter, `Birdo-Compare` is empty, and there is no
journal. The route comparison shows no difference beyond ones the OS made on
its own.
**Then W7, W9, W10 and W15.** Keep the dead-man's switch armed until W15 ends.

### The Windows release checks W7, W9, W10 and W15

These four had no step in this checklist (AUD-DOC-14). They keep the numbers
of the Windows device-check list. Start the app again for W7 and sign in;
lockdown (Always-on Kill Switch) is on unless a step says otherwise. After
each connect, read `$Relay` again (Conventions): another server is another
relay.

### W7. Kill Switch Exceptions (split tunnelling)

The Windows app has no route-based split tunnelling. Its "split tunnelling" is
**Kill Switch Exceptions** (Settings › VPN Settings › Kill Switch Exceptions):
an excepted app is exempt from the kill switch's block, in both directions,
while the tunnel is down. While the VPN is connected, its traffic still goes
through the tunnel like everything else.

Before connecting, read the line's own address:
`curl.exe -s -m 10 https://1.1.1.1/cdn-cgi/trace | Select-String '^ip='`.
Then turn **Kill Switch Exceptions** on, type `C:\Windows\System32\curl.exe`
under "Add by path or name" and add it. Connect, and run:

```powershell
Birdo-Filters | Select-String 'kill-switch exception'
curl.exe -s -m 10 https://1.1.1.1/cdn-cgi/trace | Select-String '^ip='
(Invoke-RestMethod https://1.1.1.1/cdn-cgi/trace -TimeoutSec 10) -split "`n" | Select-String '^ip='
```

Then open a reconnect gap and keep it open (B7's rule), and run the probes
again while the app shows Reconnecting…:

```powershell
$m = Birdo-LogMark
New-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay' -Direction Outbound -RemoteAddress $Relay -Protocol UDP -Action Block | Out-Null
Birdo-WaitLog $m 'Tunnel declared dead'
Birdo-Filters | Select-String 'kill-switch exception|Block all outbound IPv4|Permit the tunnel interface'
curl.exe -s -m 10 https://1.1.1.1/cdn-cgi/trace | Select-String '^ip='
Invoke-WebRequest https://1.1.1.1/cdn-cgi/trace -UseBasicParsing -TimeoutSec 10 | Select-Object StatusCode
Remove-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay'
Birdo-WaitLog $m 'Auto-reconnect successful' 180
curl.exe -s -m 10 https://1.1.1.1/cdn-cgi/trace | Select-String '^ip='
```

**Pass:**

- Connected: `Birdo: Permit kill-switch exception (curl.exe)` is listed on all
  four layers (connect v4/v6, recv-accept v4/v6). curl.exe and PowerShell
  print the same `ip=`, the relay's exit address, not the line's own.
- In the gap: the first `Birdo-WaitLog` prints `True`; `Block all outbound
  IPv4` and the exception permits are listed, and `Permit the tunnel
  interface` is not. curl.exe still answers, now with the line's own `ip=`:
  the exception keeps it online outside the tunnel, which is what the user
  asked for. The PowerShell request fails (any error).
- After the rule is removed, the second `Birdo-WaitLog` prints `True`
  (`Auto-reconnect successful`) and curl.exe's `ip=` is the relay's again.

Not a failure: in the gap an excepted app still cannot look up a name the DNS
cache does not hold, because the DNS block outranks every permit ("What this
build does"). That is why this step uses an address.
**Rollback:** remove the curl.exe entry, turn Kill Switch Exceptions off (the
`kill-switch exception` filters go after the brief reconnect), and remove the
rule if it is still there (`$Rollback` also removes it).

### W9. Reactive mode through a reconnect gap

Settings › Privacy & Security: **Kill Switch** on, **Always-on Kill Switch**
off, then reconnect. B2's filter set is the connected state. Now open a gap:

```powershell
$m = Birdo-LogMark
New-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay' -Direction Outbound -RemoteAddress $Relay -Protocol UDP -Action Block | Out-Null
Birdo-WaitLog $m 'Tunnel declared dead'
Birdo-Filters
Invoke-WebRequest https://1.1.1.1/cdn-cgi/trace -UseBasicParsing -TimeoutSec 10 | Select-Object StatusCode
Resolve-DnsName example.com -DnsOnly -Server 8.8.8.8 -QuickTimeout
Remove-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay'
Birdo-WaitLog $m 'Reconnection successful' 180
Birdo-LogSince $m | Select-String 'Auto-reconnect successful|Reconnection successful'
Birdo-Filters
```

**Pass:**

- The first `Birdo-WaitLog` prints `True`, and in the gap the block is up:
  `Block all outbound IPv4`, `Block all outbound IPv6`, `Block all inbound
  IPv4`, `Block all inbound IPv6`, with `Permit the relay (WireGuard)` and its
  `(inbound)` twin and `Permit the app's own HTTPS (control plane)`. There is
  no `Permit the tunnel interface`.
- The web request and the 8.8.8.8 query both fail.
- After the rule is removed, the log has `Auto-reconnect successful on attempt
  N` and then `Reconnection successful`, and the last `Birdo-Filters` is
  exactly B2's set again: in reactive mode the block is released as soon as
  the tunnel is back. (With Always-on, it stays for the whole session.)

Then the give-up. The app tries ten times with a growing back-off, so allow
15 minutes, and re-arm the dead-man's switch first:

```powershell
Birdo-ArmDeadMan
$m = Birdo-LogMark
New-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay' -Direction Outbound -RemoteAddress $Relay -Protocol UDP -Action Block | Out-Null
Birdo-WaitLog $m 'Auto-reconnect gave up' 900
Birdo-Filters
Invoke-WebRequest https://example.com -UseBasicParsing -TimeoutSec 10 | Select-Object StatusCode
Remove-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay'
```

**Pass:** `Birdo-WaitLog` prints `True` and the app shows the error, not
Reconnecting…; there is no `Birdo:` filter; and the request returns `200`,
outside the tunnel. In reactive mode a session that is over does not hold the
machine offline. With Always-on, the same give-up keeps the block until you
disconnect.
**Rollback:** `Remove-NetFirewallRule -DisplayName 'BirdoTest-BlockRelay'`,
turn **Always-on Kill Switch** back on, and disconnect.

### W10. Stealth Mode with lockdown

This needs an account whose plan includes Stealth Mode. Read the line's own
address first (W7). Then Settings › VPN Settings › turn **Stealth Mode** on,
keep Always-on Kill Switch on, and connect.

```powershell
Birdo-Filters | Select-String 'Permit the relay|Block all outbound IPv4|Permit the tunnel interface'
Select-String -Path $Log -Pattern 'no WFP app id' | Select-Object -Last 1
(Get-Process xray).Path
$x = Get-NetTCPConnection -OwningProcess (Get-Process xray).Id -State Established |
  Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$)' } | Select-Object -First 1
$StealthRelay = $x.RemoteAddress; $StealthPort = $x.RemotePort
"$StealthRelay port $StealthPort"
Find-NetRoute -RemoteIPAddress $StealthRelay | Select-Object -First 1 InterfaceAlias
Test-NetConnection $StealthRelay -Port $StealthPort -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded
(Invoke-RestMethod https://1.1.1.1/cdn-cgi/trace -TimeoutSec 10) -split "`n" | Select-String '^ip='
Resolve-DnsName example.com -DnsOnly
Resolve-DnsName example.com -DnsOnly -Server 8.8.8.8 -QuickTimeout
```

**Pass**, connected:

- `Birdo-Filters` shows `Birdo: Permit the relay (stealth)` (connect v4 only)
  and neither `Permit the relay (WireGuard)` nor its `(inbound)` twin, plus
  `Block all outbound IPv4` and `Permit the tunnel interface`. No name ends
  `any app — app id unavailable`, and birdo.log has no `Kill switch: no WFP app
  id` line.
- xray runs from under `$env:ProgramFiles\BirdoVPN\`.
- `Find-NetRoute` resolves the stealth relay to `$Phys`, not `Birdo VPN`:
  xray's connection, and the probe after it, leave on the physical adapter.
- `TcpTestSucceeded` is `False`. The port is open (xray holds a connection to
  it), so this is the stealth permit's app scoping: only xray.exe may reach
  the relay.
- The `ip=` is the relay's exit address, not the line's own. The default
  resolution works and the 8.8.8.8 query fails.

Then kill the transport and keep the gap open by blocking xray's relay:

```powershell
$m = Birdo-LogMark
New-NetFirewallRule -DisplayName 'BirdoTest-BlockStealth' -Direction Outbound -RemoteAddress $StealthRelay -Protocol TCP -Action Block | Out-Null
$oldXray = (Get-Process xray).Id
Stop-Process -Name xray -Force
Birdo-WaitLog $m 'Tunnel declared dead' 60
Birdo-LogSince $m | Select-String 'Xray exited under the session|Tunnel declared dead'
Birdo-Filters | Select-String 'Permit the relay|Block all outbound IPv4|Permit the tunnel interface'
Invoke-WebRequest https://1.1.1.1/cdn-cgi/trace -UseBasicParsing -TimeoutSec 10 | Select-Object StatusCode
Resolve-DnsName example.com -DnsOnly -Server 8.8.8.8 -QuickTimeout
Remove-NetFirewallRule -DisplayName 'BirdoTest-BlockStealth'
Birdo-WaitLog $m 'Auto-reconnect successful' 180
(Get-Process xray).Id -ne $oldXray
(Invoke-RestMethod https://1.1.1.1/cdn-cgi/trace -TimeoutSec 10) -split "`n" | Select-String '^ip='
```

**Pass**, in the gap (the app shows Reconnecting…):

- The log has `Xray exited under the session — reporting a dead transport`
  and then `Tunnel declared dead (TransportDied)`.
- `Block all outbound IPv4` and `Permit the relay (stealth)` are listed, and
  `Permit the tunnel interface` is not.
- The web request and the 8.8.8.8 query fail.

After the rule is removed: the last `Birdo-WaitLog` prints `True`
(`Auto-reconnect successful`), xray is a new process (`True`), and the `ip=`
is the relay's again.
**Rollback:** remove the rule if it is still there, turn Stealth Mode off, and
disconnect (`$Rollback` also removes the rule and stops xray).

### W15. Quit and Task Manager cleanup

**Part 1: Quit while connected.** Connect (lockdown on) and do not
disconnect. Run `$p = Get-Process BirdoVPN`, choose **Quit BirdoVPN** in the
tray menu, and then at once:

```powershell
$p.WaitForExit(20000)
Get-Process BirdoVPN, xray -ErrorAction SilentlyContinue
Birdo-Filters
Get-NetAdapter -Name 'Birdo VPN' -ErrorAction SilentlyContinue
route print -4 | Select-String $Relay
Test-Path $Jrnl
Birdo-Compare
Resolve-DnsName example.com -DnsOnly
Select-String -Path $Log -Pattern 'Application exit requested|Exit teardown' | Select-Object -Last 3
```

**Pass:**

- `WaitForExit` prints `True` (the app is gone within about 20 s of the
  click), and no BirdoVPN or xray process is left.
- No `Birdo:` filter, no relay route, no journal.
- `Birdo-Compare` is empty and the default resolution works.
- Record whether `Birdo VPN` is still listed. Wintun removes the adapter with
  the handle that created it, so one a session reused (after B4) can stay;
  the next connect reuses it again.
- The log has `Application exit requested — tearing down VPN + kill switch
  first`, and neither `Exit teardown timed out` nor `Exit teardown never ran
  to its end`.

**Part 2: End task.** Start the app again and connect. Open Task Manager **as
administrator** (the app runs elevated; an unelevated Task Manager cannot end
it), go to **Details**, select `BirdoVPN.exe` and choose **End task**. Then run
B4's two command blocks (skip its `taskkill` line).

**Pass:** B4's criteria. Also, `Get-Process xray` finds nothing: xray runs in a
kill-on-close job and goes with the app.
**Rollback:** start BirdoVPN once (do not connect) if a relay route remains,
as in B4.
**Then stop the dead-man's switch:** `Stop-Process $DeadMan`.

---

## Accepted residuals — not failures

Three behaviours a run of this checklist can show that were accepted by
design in the client overhaul (WIN-RUST-B, residuals 8 and 9, and the relay
port check of 2026-10-01). Record them if seen; do not file them.

- **WireGuard runs on UDP 51820 only.** All ten relays were checked: nothing
  listens on a public 53 and there is no DNAT to 51820. The app no longer
  offers a port, and a "53" or custom port saved by an older build is never
  dialled (`commands/vpn.rs`, `dialable_wireguard_port`). A network that
  blocks UDP 51820 cannot carry a plain WireGuard session; Stealth Mode is the
  answer there.
- **DNS-over-HTTPS on 443 over the physical adapter is not blocked.** The DNS
  guard filters the DNS ports (53, 853). DoH is HTTPS like any other, and while
  connected it is routed into the tunnel with everything else (see "What this
  build does"). Through a kill-switch block, 443 is open only to BirdoVPN.exe
  (`Birdo: Permit the app's own HTTPS (control plane)`) and to any Kill Switch
  Exception the user added.
- **Static DNS that 1.4.45 already erased cannot be recovered.** Its heal
  judged such an adapter foreign and dropped the journal record, so nothing on
  the machine still holds the old resolvers. This build never erases them (B3)
  and heals what older builds parked while the record survives (B9); users who
  lost theirs under 1.4.45 have to re-enter them.

---

## Results

| Step | Result | Notes |
|---|---|---|
| A1 | | |
| B1 | | |
| B2 | | |
| B3 | | |
| B4 | | |
| B5 | | |
| B6 | | |
| B7 | | |
| B8 | | |
| B9 | | |
| B10 | | |
| B11 | | |
| B12 | | |
| W7 | | |
| W9 | | |
| W10 | | |
| W15 | | |
