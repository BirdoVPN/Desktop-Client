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
(W1-008).

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
gateway. They are written to `%APPDATA%\BirdoVPN\dns-restore.json` with the
boot time, and a start after a crash in the same boot deletes exactly those
rows. The tunnel address is `/32`, and every tunnel resolver gets an on-link
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
$Jrnl  = "$env:APPDATA\BirdoVPN\dns-restore.json"
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
```

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
```

**Pass:** `filters.txt` is empty (no `Birdo:` filter exists). Note whether
`dns-restore.json` exists. If it does, an older build left something behind,
and B9 part 1 is the step that heals it.

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

### B0. Dead-man's switch (start before B1, stop after B12)

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
$DeadMan = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile','-Command',"Start-Sleep 1800; & '$Rollback'"
```

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

Settings › Security › turn **Always-on kill switch** off, then reconnect.

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

### B5. App-scoped permits (W1-013, D-24)

Connect with lockdown on, then run from PowerShell (a process that is not
BirdoVPN):

```powershell
Test-NetConnection $Relay -Port 22 -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded
Test-NetConnection $Relay -Port 443 -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded
```

**Pass:** both are `False`. The old unscoped relay permit let any process
reach the relay on any port.

A closed port also reads `False`. To tell the two apart, enable the drop audit
first (`auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable`).
Then look for a drop naming `Birdo: Block all outbound IPv4` in
`netsh wfp show netevents file=$env:TEMP\ne.xml`.
**Rollback:** `auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:disable`.

Stealth: enable Stealth Mode and reconnect.

- `Birdo-Filters` shows `Permit the relay (stealth)` instead of the WireGuard
  pair.
- Read xray's relay connection with
  `$StealthRelay = (Get-NetTCPConnection -OwningProcess (Get-Process xray).Id -State Established | Select-Object -First 1).RemoteAddress`.
- From PowerShell, `Test-NetConnection $StealthRelay -Port 8443` is `False`
  while the tunnel carries traffic.

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
the uninstaller runs). Do this while not connected:

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
- `$env:APPDATA\BirdoVPN` is gone. It may hold only `dns-restore.json` if a
  restore could not be verified; birdo.log then said why before the folder went.

Repeat with the box unticked: the same results, and `$env:APPDATA\BirdoVPN\logs`
remains.
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
**Then stop the dead-man's switch:** `Stop-Process $DeadMan`.

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
