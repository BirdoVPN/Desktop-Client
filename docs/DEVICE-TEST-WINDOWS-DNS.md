# Device test: the Windows DNS subsystem (#105)

The Windows DNS cluster — **#98**, **#99**, **#100**, **#102** — merged as **#114**
and is on `main`. It is gated, mutation-checked and structurally sound. **Nothing
in it has run on a real machine.** No real `netsh`, no real adapter, no real
updater relaunch, no real crash.

Issue #105 states each invariant so that a violation is *observable on a real
machine*. This document turns those observations into a checklist: preconditions,
exact commands, the one thing that decides pass or fail, what a failure means, and
how to put the machine back.

**Do not tag a release until sections S1–S7 have a result written next to them.**

---

## Contents

| | Scenario | Invariant | Issue |
|---|---|---|---|
| **S0** | Baseline and instrumentation | — | — |
| **S1** | Reconnect WITHOUT teardown | I1 SINGLE OWNER, I3 LIVENESS | #98 |
| **S2** | User action during the orphan window | I2 NO ORPHANS | #105 §2 |
| **S3** | An adapter that appears mid-session | I6 REFRESH | #99 |
| **S4** | `show dns` fails while `set dns` succeeds | I4 RECORD ⊇ MUTATED, I5 OBSERVED | #102 |
| **S5** | Updater relaunch (`RESTART_EXIT_CODE`) | I13 NO PARK AFTER UN-PARK | — |
| **S6** | Hard kill and power loss | journal + `adopt_unrestored` | — |
| **S7** | Another VPN's split-default route | I10 OWNER-QUALIFIED DELETE | #100 |
| **A** | Appendix: the `netsh` fault-injection shim | | |
| **B** | Appendix: a gap found while writing this | | |
| **C** | Appendix: results sheet | | |

---

# S0. Baseline and instrumentation

Everything below depends on this section. Skip it and a failure will be
indistinguishable from the machine you started with.

## S0.1 The machine

* Windows 10 1809+ or Windows 11 (`pktmon` ships in-box from 1809).
* **A machine you can afford to lose DNS on.** Several scenarios deliberately
  leave adapters parked on `static none`; S4 and appendix B can do so
  permanently if the fix is broken. A VM with a checkpoint is strongly
  preferred — it also makes S6's power-loss half possible at all.
* At least **two** network adapters, one of which can be brought up and down
  without losing the machine's connectivity. See S0.3.
* An elevated PowerShell window, kept open for the whole session. The app runs
  elevated (`src-tauri/src/main.rs:281`), and so must every `netsh` you use to
  check it.

## S0.2 Which build to test, and what it can tell you

Test the **release installer** — that is the artifact being tagged.

But know what a release build will and will not print. `birdo.log`'s file layer
is clamped to `INFO` in release builds regardless of `RUST_LOG`
(`src-tauri/src/utils/log_policy.rs:39-50`), and a release build is
`windows_subsystem = "windows"` (`src-tauri/src/main.rs:8-11`, gated on
`not(debug_assertions)`) so there is no console for the unclamped layer to write
to.

| line | level | in a release `birdo.log`? |
| --- | --- | --- |
| `Tearing down the existing tunnel before connecting …` (`manager.rs:386`) | INFO | **yes** |
| `Disconnecting from VPN` (`manager.rs:678`) | INFO | **yes** |
| `<adapter>: DNS origin unreadable (…) — NOT parked …` (`win_machine_state.rs:681`) | ERROR | **yes** |
| `<adapter>: DNS suppression recovered on retry` (`win_machine_state.rs:662`) | INFO | **yes** |
| `Restored DNS left moved aside by a previous session` (`main.rs:408`) | WARN | **yes** |
| `N adapter(s) recorded as parked by a previous session …` (`win_machine_state.rs:1519`) | WARN | **yes** |
| `Adopting N adapter(s) a previous session left parked …` (`win_machine_state.rs:1445`) | WARN | **yes** |
| `Restart requested — skipping exit teardown (DNS restored: …)` (`main.rs:659`) | INFO | **yes** |
| `Parked IPv4 + IPv6 DNS on <adapter>` (`win_machine_state.rs:711`) | DEBUG | **NO** |
| `Already disconnected or disconnecting` (`manager.rs:670`) | DEBUG | **NO** |

**Consequence:** the two DEBUG lines are not available to you. Every scenario
below therefore decides on the **machine**, not on the log — `netsh` output,
`route print`, a packet capture — and uses the log only as corroboration. That
is the right way round anyway: #105's whole point is that a claim made inside the
process is not evidence about the machine.

If you want the DEBUG lines for diagnosis, build a debug binary
(`npm run tauri dev`, or `cargo tauri build --debug`) — it gets a console and a
TRACE-level file layer. **A debug build is not the artifact being shipped;
never sign off a scenario on one.**

## S0.3 Create a test adapter

Most scenarios need an adapter you can park, break, disable and rename without
losing the machine. Use a **Microsoft KM-TEST Loopback Adapter**: it reports
`Up` permanently with no cable, it carries no real traffic, and you can give it
a sentinel resolver that cannot be confused with anything else on the box.

```powershell
# Elevated. hdwwiz is interactive:
#   Add legacy hardware -> Install the hardware I manually select -> Network adapters
#   -> Microsoft -> Microsoft KM-TEST Loopback Adapter
hdwwiz.exe

# Then name it and give it a sentinel configuration
# (substitute the name Windows actually assigned it):
Rename-NetAdapter -Name "Ethernet 3" -NewName "BIRDO-TEST"
netsh interface ip   set address name="BIRDO-TEST" static 192.0.2.2 255.255.255.0
netsh interface ip   set dns     name="BIRDO-TEST" static 203.0.113.53 validate=no
netsh interface ipv6 set dns     name="BIRDO-TEST" static 2001:db8::53 validate=no

# Confirm the sentinel, and that Windows reports it Up:
netsh interface ipv4 show dns name="BIRDO-TEST"
netsh interface ipv6 show dns name="BIRDO-TEST"
Get-NetAdapter -Name "BIRDO-TEST" | Format-List Name,Status,ifIndex,InterfaceGuid
```

`203.0.113.53` and `2001:db8::53` are RFC 5737 / RFC 3849 documentation
addresses. They resolve nothing, which is exactly what you want: if they come
back after a disconnect the restore worked; if the adapter reads
`Statically Configured DNS Servers: None`, it is stranded.

**Write down the `ifIndex` and `InterfaceGuid`.** The park record is keyed by
adapter GUID and route ownership by interface index
(`OwnedRoute.if_index`, `src-tauri/src/vpn/win_machine_state.rs:1323`).

*Not practical on your machine?* Any spare adapter works — a second NIC, a USB
Ethernet dongle with a link, a Hyper-V or VirtualBox host-only adapter. It must
report `Up`: `park_pass` filters on `adapter.up`
(`win_machine_state.rs:640`), so a NIC with no link is invisible to this
subsystem and proves nothing.

## S0.4 Take the baseline

```powershell
$B = "C:\birdo-test"; New-Item -ItemType Directory -Force $B | Out-Null
netsh interface ipv4 show dns | Out-File -Encoding utf8 "$B\baseline-dns-v4.txt"
netsh interface ipv6 show dns | Out-File -Encoding utf8 "$B\baseline-dns-v6.txt"
Get-NetAdapter | Format-Table -AutoSize | Out-File -Encoding utf8 "$B\baseline-adapters.txt"
route print -4 | Out-File -Encoding utf8 "$B\baseline-routes.txt"
Get-Content "$B\baseline-dns-v4.txt"
```

**These files are how you put the machine back.** Nothing below is safe to run
without them.

## S0.5 The four places you will look

| what | where |
| --- | --- |
| DNS on every adapter | `netsh interface ipv4 show dns` / `netsh interface ipv6 show dns` |
| the split-default pair and owned routes | `route print -4`, or `Get-NetRoute -DestinationPrefix 0.0.0.0/1,128.0.0.0/1` |
| the crash-durable park record | `%APPDATA%\BirdoVPN\dns-restore.json` (`src-tauri/src/vpn/mod.rs:252`, `:294`) |
| the app log | `%APPDATA%\BirdoVPN\logs\birdo.log` (`src-tauri/src/main.rs:143`) |

Both files sit under `dirs::data_dir()` = `%APPDATA%` (Roaming). The app is
elevated via UAC on **your** account, so it writes **your** `%APPDATA%`. If you
launch it as a *different* administrator, look under that account's profile
instead.

Two watch loops worth leaving running in their own windows:

```powershell
# W1 - DNS on every adapter, once a second
while ($true) { Clear-Host; Get-Date -Format o; netsh interface ipv4 show dns; Start-Sleep 1 }

# W2 - the journal, once a second
while ($true) { Clear-Host; Get-Date -Format o;
  Get-Content "$env:APPDATA\BirdoVPN\dns-restore.json" -ErrorAction SilentlyContinue
  Start-Sleep 1 }
```

## S0.6 Sanity round trip — run this before anything else

1. Launch the app, sign in, **Connect**.
2. W1: every physical adapter, and `BIRDO-TEST`, now read
   `Statically Configured DNS Servers: None` on both families.
3. W2: `dns-restore.json` exists and lists those adapters **with their original
   resolvers** — `BIRDO-TEST` must show `203.0.113.53` / `2001:db8::53`.
4. Browsing works; `Resolve-DnsName www.example.com` succeeds (through the
   tunnel adapter's own resolvers).
5. **Disconnect.**
6. W1 matches `baseline-dns-v4.txt` exactly. `BIRDO-TEST` has its sentinels back.
7. W2: `dns-restore.json` is **gone**.
8. Dashboard shows **no** amber `DNS not fully protected` banner
   (`src/components/Dashboard.tsx:1070`).

**If S0.6 fails, stop.** Nothing below is interpretable, and the subsystem is
broken on the happy path.

---

# S1. Reconnect WITHOUT teardown — I1 SINGLE OWNER

> #98. `connect()` used to overwrite `self.tunnel` while the old tunnel was
> live. Dropping it there ran the old tunnel's unwind against machine state the
> *new* tunnel had taken over: physical adapters un-parked, the `0.0.0.0/1` +
> `128.0.0.0/1` pair deleted, the IPv6 block lifted — **while the UI read
> Connected**. The fix takes the tunnel out of the `Option` unconditionally
> (`src-tauri/src/vpn/manager.rs:355`) and holds the park in force across the gap
> (`begin_transition`, `manager.rs:377`).

There are two ways to reach `connect()`-with-a-live-tunnel. Run **both**: S1a is
one click and covers the handover; S1b is the path #98 was actually reported on.

## S1a — server switch (cheap, run first)

**Preconditions:** S0.6 green. Two servers available in the picker.

**Steps**

1. Connect to server A. Confirm the parked state in W1.
2. Note the `/1` pair:
   `route print -4 | Select-String "^\s+0\.0\.0\.0\s+128\.0\.0\.0"`
3. Start the DNS watch, and the capture (S1c) if you are doing it in this run.
4. In the app, pick **server B**. Do not press Disconnect first.
5. Watch W1 continuously across the whole switch.

**PASS**

* W1 never shows a resolver reappearing on any physical adapter — not for one
  tick. `BIRDO-TEST` stays on `None` throughout.
* `dns-restore.json` is present continuously and still names those adapters.
* After the switch settles, the `/1` pair is installed (on the new tunnel's
  interface) and traffic flows.
* `birdo.log` contains
  `Tearing down the existing tunnel before connecting (state Connected, tunnel present: true)`
  (`manager.rs:386`). **`tunnel present: true` is the line that proves the
  displaced tunnel was found and disposed of rather than leaked.**

**FAIL**

* Any physical adapter shows real resolvers at any point during the switch —
  even for one second. That is the leak.
* `dns-restore.json` disappears and reappears.
* `tunnel present: false` while the app was connected: the `Option` and the
  state have diverged, and a tunnel exists that the manager does not know about.

**If this fails, here is what it means.** The displaced tunnel's `Drop` still
owns machine state — `is_owner` in `Drop` (`src-tauri/src/vpn/tunnel.rs:2208`) returned
true for a generation that had already handed over, or `begin_transition` did not
move ownership before the old tunnel was dropped. Everything else in this
document is downstream of that; do not continue to S2–S7.

## S1b — auto-reconnect after a dead tunnel (the #98 path)

The watchdog needs **two** signals before it declares the tunnel dead
(`src-tauri/src/vpn/auto_reconnect.rs:494`): the most recent heartbeat failed,
**and** inbound tunnel bytes were flat for `RX_STALL_LIMIT` ticks. At
`health_check_interval_ms = 5000` (`auto_reconnect.rs:80`), `RX_STALL_LIMIT = 6`
and `HEARTBEAT_EVERY_N_TICKS = 6` (`auto_reconnect.rs:355`, `:339`) that is
**roughly 30–60 s** after you cut the peer.

**Preconditions:** S1a green. You know the exit node's IP (Dashboard, or the /32
host route to the endpoint in `route print -4`).

**Steps**

```powershell
# 1. Connect. Confirm parked. Start W1 and the capture.

# 2. Blackhole the peer so the data plane dies but the machine stays usable.
#    Substitute the node IP.
netsh advfirewall firewall add rule name="BIRDO-TEST-PEER" dir=out action=block `
  remoteip=<NODE_IP> protocol=udp

# 3. Wait for the watchdog (~30-60 s). birdo.log:
#    "Tunnel liveness watchdog: heartbeat failing AND no inbound traffic for ~30s
#     - treating tunnel as dropped and reconnecting"

# 4. Once the watchdog has tripped, remove the rule so the reconnect can complete:
netsh advfirewall firewall delete rule name="BIRDO-TEST-PEER"
```

**PASS** — identical to S1a, plus:

* Between the watchdog trip and the second `Tunnel started successfully`
  (`tunnel.rs:875`), **W1 never shows a resolver on a physical adapter**.
* `route print -4` shows the `/1` pair present throughout, or absent only while
  no tunnel exists at all — never absent while the UI reads Connected.
* The reconnect's own teardown line reads `tunnel present: true`.

**FAIL** — the #98 signature exactly: after the *second*
`Tunnel started successfully`, the physical NIC has its resolvers **back**, the
`/1` pair is **gone**, and the UI reads **Connected**.

**If this fails, here is what it means.** `connect()` is still disposing of the
old tunnel from a path that lets its `Drop` act — or `ConnectionState` is being
consulted somewhere it must not be (I3). The machine is unprotected while
claiming to be protected, which is the worst state in this subsystem: the user
gets no signal at all.

## S1c — the packet capture

The DNS watch (W1) is the **primary** observable and it is sufficient on its own.
The capture is what #105 asks for, and it is what converts "the adapter had
resolvers" into "queries went out in the clear".

### Turn the kill switch OFF for this run

This is the single most important instruction in this section.

With the kill switch on, `activate_killswitch` installs a WFP block-all and
permits only localhost, DHCP, the VPN server `/32`, the tunnel interface and the
Birdo process itself (`src-tauri/src/vpn/wfp.rs:1084-1140`). A DNS query from the
**DNS Client service** — a different process — over the physical NIC is therefore
**dropped by WFP before it reaches the wire**, even when the DNS park has
completely failed.

**A clean capture with the kill switch on is not evidence about the DNS park.**
It would have been green during the outage #98 describes.

So:

* **S1c run 1 — Settings → Kill Switch OFF.** This isolates the DNS park as the
  only thing between the resolver and the wire (Settings.tsx:480-483: the Rust
  connect path only arms the firewall block when this is on). This is the run
  that tests the invariant.
* **S1c run 2 — Kill Switch ON (default).** Expect zero packets. This tests
  defence in depth, not the park.

Record both. A leak in run 1 and silence in run 2 means the DNS subsystem is
broken and the kill switch is currently hiding it.

### pktmon (in-box, nothing to install)

The syntax below was verified against Windows 11 26200 (`pktmon help`,
`pktmon filter add help`, `pktmon start help`).

```powershell
# Find the component id of the PHYSICAL adapter - not the Birdo VPN adapter.
# Ids change across reboots; re-run this every session.
pktmon list

# UDP port 53 only.
pktmon filter remove
pktmon filter add DNS53 -t UDP -p 53

# Capture whole packets, on the physical NIC only, to a file.
pktmon start --capture --comp <PHYSICAL_COMP_ID> --pkt-size 0 `
  --file-name C:\birdo-test\dnsleak.etl --log-mode multi-file

#   ... run S1a / S1b now, while generating DNS traffic (below) ...

pktmon stop
pktmon etl2txt  C:\birdo-test\dnsleak.etl -o C:\birdo-test\dnsleak.txt
pktmon etl2pcap C:\birdo-test\dnsleak.etl -o C:\birdo-test\dnsleak.pcapng
pktmon filter remove
```

Prefer to watch live? `pktmon start --capture --comp <id> --log-mode real-time`
prints to the console and Ctrl-C stops it; no file is written.

### Wireshark alternative

Capture on the **physical** interface with capture filter `udp port 53`, or
display filter `udp.port == 53 && !(ip.addr == <tunnel DNS>)`.

### Generate the traffic

A leak only appears if something is asking. Use unique labels so the resolver
cache cannot answer:

```powershell
while ($true) {
  Resolve-DnsName -Name "$(Get-Random)-leaktest.example.com" -DnsOnly `
    -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep -Milliseconds 500
}
```

Failing lookups are expected and fine — you are watching the wire, not the
answer.

**PASS:** zero UDP/53 frames on the physical component for the whole window.

**FAIL:** any UDP/53 frame on the physical component while the UI reads
Connected. Open it and read the destination — it will be the LAN router or the
ISP resolver, and the QNAME will be one of your `leaktest` labels.

**If this fails, here is what it means.** The park was lifted while a tunnel was
live, and real queries left the machine unencrypted with the user's real source
address. This is the user-visible harm the whole cluster exists to prevent.

## Restore after S1

```powershell
netsh advfirewall firewall delete rule name="BIRDO-TEST-PEER"   # if still present
pktmon stop; pktmon filter remove; pktmon unload
# Disconnect in the app, then compare against the baseline:
netsh interface ipv4 show dns | Out-File -Encoding utf8 C:\birdo-test\after-s1.txt
Compare-Object (Get-Content C:\birdo-test\baseline-dns-v4.txt) `
               (Get-Content C:\birdo-test\after-s1.txt)
# Turn the Kill Switch back ON in Settings if you turned it off for S1c.
```

`Compare-Object` returning nothing is the restore check. If it returns
differences, fix them by hand from the baseline before continuing.

---

# S2. User action during the orphan window — I2 NO ORPHANS

> #105 §2: "the tunnel is now unreachable by any user action."

**Read this before running it — the control you press is not the obvious one.**

`can_disconnect()` is false only in `Disconnected`, `Disconnecting` and
`KillSwitchActive` (`manager.rs:76-83`), so the `holds_tunnel()` addition
(`manager.rs:669`, `:766`) changes the outcome only in those three states. Three
facts about the shipped tree decide how you exercise it:

* The Dashboard's toggle offers **Disconnect** only when the state is
  `connected` or `kill_switch_active` (`src/components/Dashboard.tsx:698`); in
  every other state it offers **Connect**.
* The tray's **Disconnect** item is enabled only in `connected` / `connecting`
  (`src-tauri/src/commands/tray.rs:84-88`).
* `ConnectionState::KillSwitchActive` is **never written by any code path** in
  this tree — every `set_state` call passes `Error`, `Reconnecting` or
  `Disconnected` (`auto_reconnect.rs`, `commands/vpn.rs:1400`).

So the orphan state you can actually reach is **`Disconnected` with a live tunnel
still in the `Option`**, produced by an auto-reconnect give-up
(`auto_reconnect.rs:722`, `:755`, `:769`, `:786`, `:858`, `:872`, `:1069`,
`:1102` all set `Disconnected` without touching `self.tunnel`). In that state the
UI offers **Connect**, and the two user actions that must recover the machine are
**Connect** and **Quit**. Both are tested below.

**Preconditions:** S1 green. You can block `api.birdo.app` at the firewall.

**Steps**

```powershell
# 0. BEFORE connecting, resolve the control plane so you can block every A record:
Resolve-DnsName api.birdo.app

# 1. Connect. Confirm parked in W1. Note the adapter and the /1 pair:
netsh interface show interface name="Birdo VPN"
route print -4 | Select-String "^\s+0\.0\.0\.0\s+128\.0\.0\.0"

# 2. Kill the data plane AND the control plane, so the reconnect gives up
#    instead of succeeding.
netsh advfirewall firewall add rule name="BIRDO-TEST-PEER" dir=out action=block `
  remoteip=<NODE_IP> protocol=udp
netsh advfirewall firewall add rule name="BIRDO-TEST-API" dir=out action=block `
  remoteip=<API_IPS> protocol=tcp remoteport=443

# 3. Wait for the watchdog (~30-60 s), then for the reconnect attempts to give up.
```

**The orphan window.** When the UI reads **Disconnected**, check the machine:

```powershell
netsh interface show interface name="Birdo VPN"     # still Connected?
route print -4 | Select-String "^\s+0\.0\.0\.0\s+128\.0\.0\.0"
netsh interface ipv4 show dns                       # still parked?
```

If the adapter is still up, the `/1` pair is still installed and the adapters are
still parked while the UI says Disconnected — **you are in the orphan window.**
That state is expected here; the only question is whether a user action gets out
of it.

Now press **Connect** (the toggle, or tray → Quick Connect).

**PASS**

* `birdo.log` contains
  `Tearing down the existing tunnel before connecting (state Disconnected, tunnel present: true)`
  (`manager.rs:386`). **`tunnel present: true` from state `Disconnected` is the
  whole of I2** — the `Option` was consulted, not the state.
* The old adapter goes down, the old `/1` rows go away, and the new connect
  proceeds (delete the firewall rules first if you want it to succeed).
* No physical adapter ever regains resolvers while the new tunnel is live.

Then repeat the setup and use the **other** user action: tray → **Quit**.

* `birdo.log` contains `Disconnecting from VPN` (`manager.rs:678`) — reached only
  because `holds_tunnel()` returned true from state `Disconnected`.
* Every adapter is back to baseline after the process exits.
* `dns-restore.json` is gone.

**FAIL**

* Connect logs `tunnel present: false` while the Birdo adapter is still up — the
  manager has lost the tunnel. On a release build `panic = "abort"`
  (`src-tauri/Cargo.toml:179`) means even a panic will not run its `Drop`.
* Quit exits without `Disconnecting from VPN` and leaves the adapters parked.
* Either action un-parks the adapters *while the replacement tunnel is live*
  (that is an S1 failure surfacing here).

**If this fails, here is what it means.** A live tunnel exists that no user
action can reach. Its only exit on a release build is a clean process exit; a
crash aborts without running `Drop`, and the machine is left parked with the UI
showing Disconnected — a machine-wide DNS blackhole with no visible cause. That
is design R5's rejection reached through the front door.

**Honest limitation.** The `disconnect()` fix is *also* meant to cover
`KillSwitchActive`, and that state is unreachable in this tree, so that half
cannot be exercised on a device at all. The next-best proxy is the unit test;
record it as "not reachable", never as "passed".

## Restore after S2

```powershell
netsh advfirewall firewall delete rule name="BIRDO-TEST-PEER"
netsh advfirewall firewall delete rule name="BIRDO-TEST-API"
# Disconnect, then Compare-Object against the baseline as in S1.
```

---

# S3. An adapter that appears mid-session — I6 / #99

> An adapter that comes up after `configure_dns` has run was never parked, so
> Windows' Smart Multi-Homed Name Resolution raced the tunnel on it. The fix is a
> refresh ticker: `REFRESH_INTERVAL` = **10 s**
> (`win_machine_state.rs:110`), a thread spawned per session at
> `src-tauri/src/vpn/tunnel.rs:820-826`, running `park_pass` — idempotent per
> adapter GUID and gated on `owner == live_session == Some(gen)` (I13).

**Preconditions:** S0.6 green. `BIRDO-TEST` exists (S0.3) and is currently
**disabled**.

```powershell
Disable-NetAdapter -Name "BIRDO-TEST" -Confirm:$false
netsh interface ipv4 show dns name="BIRDO-TEST"     # sentinel 203.0.113.53 still recorded
```

**Steps**

1. **Connect.** Confirm in W1 that the other adapters are parked and that
   `BIRDO-TEST` is untouched — it is down, and `park_pass` filters on
   `adapter.up` (`win_machine_state.rs:640`).
2. Confirm `dns-restore.json` does **not** mention `BIRDO-TEST`.
3. With the tunnel live, bring it up and time the park:
   ```powershell
   $t = [Diagnostics.Stopwatch]::StartNew()
   Enable-NetAdapter -Name "BIRDO-TEST"
   while ($t.Elapsed.TotalSeconds -lt 60) {
     $o = netsh interface ipv4 show dns name="BIRDO-TEST" | Out-String
     if ($o -match 'None') { "PARKED after $([math]::Round($t.Elapsed.TotalSeconds,1))s"; break }
     Start-Sleep -Milliseconds 250
   }
   $t.Elapsed.TotalSeconds
   ```
4. A USB NIC is the more realistic article — plug it in at this step instead. It
   must get a link, or Windows reports it Down and this subsystem correctly
   ignores it.

**PASS**

* `BIRDO-TEST` reads `Statically Configured DNS Servers: None` on **both**
  families within **~10–20 s** of coming up (one ticker interval, plus up to one
  more for the adapter to register as `Up`).
* `dns-restore.json` now contains `BIRDO-TEST` **with `203.0.113.53` and
  `2001:db8::53`** — the sentinels, not `None`. This is I5b: a mid-session park
  must record the adapter's *own* configuration, never the parked shape.
* On **Disconnect**, `BIRDO-TEST` gets both sentinels back and the journal is
  deleted.

**FAIL**

* `BIRDO-TEST` still shows `203.0.113.53` after 60 s → it was never parked. #99
  is not fixed, or the ticker is not running for this generation.
* `BIRDO-TEST` shows `None` but the journal records it with **no servers** → I5b
  violated: the parked shape was captured as the adapter's origin. On disconnect
  the restore will correctly refuse to act (`restore_family`,
  `win_machine_state.rs:455-463`, *"was static with no servers before connect —
  leaving as-is"*) and the adapter is stranded **permanently**. This is #102's
  terminal state reached through #99's door — the most dangerous outcome in this
  document.
* The adapter is parked but the journal has no entry for it → the mutation has no
  record, and a crash from here is unrecoverable.

**If this fails, here is what it means.** Case 1 is a live DNS leak on the new
adapter for the rest of the session. Cases 2 and 3 are worse than the leak: the
machine loses that adapter's resolvers with no way for the app, or the user, to
know what they used to be.

**Also verify the ticker stops.** Disconnect, wait 60 s with the app still
running, then re-check `BIRDO-TEST` — it must keep its sentinels. If it goes back
to `None` after a disconnect, I13 is violated: a park followed an un-park, and
you are watching the machine-wide blackhole build itself one tick at a time.

## Restore after S3

```powershell
netsh interface ip   set dns name="BIRDO-TEST" static 203.0.113.53 validate=no
netsh interface ipv6 set dns name="BIRDO-TEST" static 2001:db8::53 validate=no
Disable-NetAdapter -Name "BIRDO-TEST" -Confirm:$false
```

---

# S4. `show dns` fails while `set dns static none` succeeds — I4 / #102

> #102. `configure_dns` parked every adapter but recorded only the ones it had
> successfully snapshotted, so `parked \ recorded` was a set of adapters no
> restore path would ever look at. The fix makes the loop strictly per-adapter
> **READ → PERSIST → PARK → READ BACK** (`win_machine_state.rs:625-716`), and a
> failed read means *never mutate what you could not read*: the adapter is
> skipped entirely.

**The observation to make:** an adapter whose `show dns` fails is **neither
parked nor recorded**, keeps its own resolvers for the session, and is reported
to the user rather than being silent.

## How to force exactly that failure

You need `netsh … show dns <adapter>` to fail while
`netsh … set dns name=<adapter> static none` still succeeds. There is no natural
Windows configuration that does this reliably, so inject it.

**Method: a `netsh` shim in the app's own directory.** Verified, not assumed:
`hidden_cmd` builds `Command::new("netsh")` with a bare program name
(`src-tauri/src/utils/mod.rs:24-33`), and Windows' `CreateProcess` search order
puts **the calling executable's own directory first**. Measured on Windows 11
26200: a `netsh.exe` placed beside the caller was resolved ahead of
`C:\Windows\System32\netsh.exe`, from an unrelated working directory.

The shim source and build command are in **Appendix A**. It fails `show` for one
sentinel adapter name and passes every other invocation straight through to the
real `netsh`, so nothing else on the machine changes behaviour.

```powershell
# Build it (Appendix A) and verify it standalone FIRST, then:
$dir = Split-Path (Get-Process BirdoVPN).Path      # the app's install directory
Copy-Item C:\birdo-test\netsh.exe $dir
```

Three things to know before you do this:

* **Close the app first.** The directory is under `%ProgramFiles%` and the
  binary may be locked.
* **Windows Application Control / SmartScreen may block an unsigned exe** — the
  #114 gate hit exactly this (`os error 4551`). If the app then fails *every*
  netsh, that is the shim being blocked, not a subsystem failure. The tell is
  `DNS origin unreadable` in `birdo.log` for **all** adapters at once.
* **Delete it the moment you are done.** A `netsh.exe` in the install directory
  hijacks every netsh the elevated app runs for as long as it is there.
  (`%ProgramFiles%` is admin-writable only, so this is not a privilege-boundary
  problem — but it is a landmine to leave behind.)

## Steps

1. Close the app. Install the shim. Ensure `BIRDO-TEST` is **enabled** and has
   its sentinels (S0.3).
2. Launch the app. **Connect.**
3. Observe.

**PASS**

* `netsh interface ipv4 show dns name="BIRDO-TEST"` — run from your own shell,
  which uses the real netsh — still reports **`203.0.113.53`**. The adapter was
  **not parked**.
* `dns-restore.json` contains **no entry** for `BIRDO-TEST`. It was **not
  recorded**.
* Every *other* adapter is parked and recorded normally. One adapter failing must
  not take the pass down with it.
* `birdo.log`, at ERROR so it is present in a release build:
  `BIRDO-TEST: DNS origin unreadable (netsh interface ipv4 show dns 'BIRDO-TEST' exited Some(1): …) — NOT parked, so this adapter keeps its resolvers for this session`
  (`win_machine_state.rs:681`).
* The Dashboard shows the amber banner
  **`DNS not fully protected — BIRDO-TEST: DNS origin unreadable …`**
  (`src/components/Dashboard.tsx:1070-1085`, fed by `degradation_report`,
  `win_machine_state.rs:1352`). The banner is rendered in **every** connection
  state, so it must still be there after you disconnect.
* **Disconnect.** `BIRDO-TEST` still reads `203.0.113.53`. Nothing touched it in
  either direction.

**FAIL**

* `BIRDO-TEST` reads `Statically Configured DNS Servers: None` after the connect
  → it was parked despite an unreadable origin. Check the journal: if there is no
  entry for it, **it is now stranded permanently** and no future disconnect will
  restore it. That is #102, verbatim.
* The banner does not appear → the degradation is silent, and a user with a
  leaking adapter gets no signal. `degradation_report` is `try_lock` over a
  last-good cache (`win_machine_state.rs:1352-1367`), so give the Dashboard a few
  poll cycles — but it must appear.
* The whole connect fails, or *no* adapter is parked → one adapter's read failure
  aborted the pass. `parked ⊆ recorded` still holds, so this is safe, but it is
  not the intended behaviour: the residual risk is meant to be one adapter, not
  all of them.

**If this fails, here is what it means.** The read guard is not honoured: the
process is mutating adapters whose configuration it never observed, and the
record it keeps of them is fiction. Every adapter this happens to loses its
resolvers permanently, across every subsequent connect/disconnect cycle, and
`restore_family`'s deliberate no-op on the `static`-with-no-servers shape
(`win_machine_state.rs:455-463`) means the app will correctly refuse to fix it
for the rest of that machine's life.

## Restore after S4

```powershell
# With the app closed, delete the shim from the install directory:
Remove-Item "C:\Program Files\BirdoVPN\netsh.exe" -ErrorAction SilentlyContinue
Get-ChildItem "C:\Program Files\BirdoVPN\netsh.exe" -ErrorAction SilentlyContinue  # MUST be gone
```

Then re-run S0.6 to confirm the machine is back to normal behaviour.

---

# S5. The updater relaunch — the door that escaped twice

> `RunEvent::ExitRequested` carrying `RESTART_EXIT_CODE` does not run the normal
> teardown (`prevent_exit()` is a documented no-op for it), so
> `src-tauri/src/main.rs:634-664` un-parks through `release_dns_at_exit`
> (`win_machine_state.rs:1381`) instead, and that un-park is what shuts the
> refresh ticker down on this path (I13). This is the door r3's `AtomicBool`
> could not see, and it is the failure design R5 was rejected for, reached a
> second time.

## Read this first: the code says this door may not fire on Windows

Following the shipped call chain:

* `install_update` (`src-tauri/src/commands/updater.rs:135`) awaits
  `update.download_and_install(...)`.
* In **tauri-plugin-updater 2.9.0**, the Windows `install_inner`
  (`src/updater.rs:674-752`) runs the optional `on_before_exit` hook, calls
  `ShellExecuteW` on the NSIS/MSI installer, and then calls
  **`std::process::exit(0)` (`src/updater.rs:752`)**. No branch returns early.
* The app registers **no** `on_before_exit` hook — `pinned_updater`
  (`src-tauri/src/commands/updater.rs:89-105`) builds the updater without one.
* `std::process::exit(0)` raises no `RunEvent`, runs no `Drop`, and never reaches
  the panic hook. So `main.rs:634`'s `RESTART_EXIT_CODE` branch — and therefore
  `restore_dns_blocking()` → `release_dns_at_exit()` — **never runs on the
  Windows in-app update path.**
* The frontend's `relaunch()` (`src/components/UpdateChecker.tsx:117`), which
  *is* what raises `RESTART_EXIT_CODE`, sits **after** the awaited
  `install_update` and is therefore unreachable on Windows.

**This is a code reading, not a measurement.** The scenario below is precisely
what settles it. Run it and record which of the two outcomes you see.

**Preconditions**

* A published release **newer** than the build under test, reachable at
  `https://api.birdo.app/updates/{target}/{arch}/{current_version}`
  (`src-tauri/tauri.conf.json:91-95`).
* Install the **older** build (N-1) from the GitHub release page.

**Steps**

1. Launch N-1. **Connect.** Confirm every adapter is parked (W1) and
   `dns-restore.json` lists them with their real resolvers.
2. Leave W1 running.
3. Open the update panel and install the update. Follow the installer prompts.
4. Watch W1 across the whole install and relaunch.
5. When the new build is running, check the machine and the log.

**PASS — outcome A (the door fires)**

* `birdo.log` contains
  `Restart requested — skipping exit teardown (DNS restored: true)`
  (`main.rs:659`).
* Every adapter has its resolvers back **before** the process is replaced.
* `dns-restore.json` is gone.
* No adapter is re-parked at any point after that — watch for at least **30 s**
  (three ticker intervals). A single re-park after the un-park is the I13
  blackhole.

**PASS — outcome B (the door does not fire, but the journal heals it)**

* That log line is **absent** — the process exited at `updater.rs:752`.
* The adapters stay parked across the install (expected: nothing un-parked them).
* The **relaunched** instance logs
  `N adapter(s) recorded as parked by a previous session — checking whether they still are`
  (`win_machine_state.rs:1519`) and
  `Restored DNS left moved aside by a previous session` (`main.rs:407-408`).
* Every adapter is back to baseline **within seconds of the new build starting**,
  and `dns-restore.json` is gone.

Outcome B is an acceptable *user* outcome — the machine heals — but it means the
`RESTART_EXIT_CODE` handling is dead code on Windows and the real recovery is the
crash journal. **Record which outcome you saw; it decides whether a follow-up
issue is needed.**

**FAIL**

* The adapters are still parked after the new build has been running for a
  minute, and `dns-restore.json` still exists → neither door worked. The machine
  has **no resolvers**, and the relaunched instance cannot resolve
  `api.birdo.app` to reconnect. This is the user-facing disaster this path exists
  to prevent.
* Any adapter is re-parked *after* being un-parked with no tunnel up → I13
  violated on the relaunch door. That is R5's rejection, live.
* The installer does not relaunch the app at all and the adapters stay parked →
  same outcome as the first bullet with a longer fuse: it heals only when the
  user next launches the app.

**If this fails, here is what it means.** A user who clicks "Update" while
connected loses DNS on their machine, and the app that would fix it cannot
resolve its own API. There is no self-service recovery short of the user
reconfiguring adapters by hand.

**Honest limitation.** This scenario needs a real published update. If no newer
release exists you cannot run it, and there is **no proxy** — the tray Quit path
goes through `teardown_for_exit` (`main.rs:667` onwards), a completely different
door, and proves nothing about this one. Do not substitute it. If you cannot run
S5, write "not run — no newer release available" and treat the release as **not
cleared**.

## Restore after S5

Compare against the baseline (S1's `Compare-Object`). If adapters are stranded,
restore them by hand from `baseline-dns-v4.txt` / `-v6.txt`, then delete
`%APPDATA%\BirdoVPN\dns-restore.json` **only after** the machine's DNS is
correct — while it exists it is the only description of what to put back.

---

# S6. Hard kill, and power loss

> Release builds are `panic = "abort"` (`src-tauri/Cargo.toml:179`), so `Drop`
> does not run on a panic; a `TerminateProcess`, an OOM kill or a power cut do
> not even reach the panic hook. Nothing was un-parked, so a last ticker pass is
> harmless (I12). Recovery is entirely the on-disk journal, reconciled at the
> next `setup()` (`main.rs:407`), and whatever cannot be restored is **adopted**
> into the new process (`adopt_unrestored`, `win_machine_state.rs:1429`).

## S6a — hard kill (Task Manager)

**Preconditions:** S0.6 green. `BIRDO-TEST` enabled with its sentinels.

**Steps**

1. **Connect.** Confirm every adapter parked, and note the full contents of
   `dns-restore.json`. **Copy that file somewhere safe** — it is your ground
   truth for this scenario.
2. Open Task Manager **as administrator** (the app is elevated; an unelevated
   Task Manager cannot end it). Details → `BirdoVPN.exe` → **End task**. Or:
   ```powershell
   Stop-Process -Name BirdoVPN -Force
   ```
3. **Immediately** check the machine — do not relaunch yet:
   ```powershell
   netsh interface ipv4 show dns          # everything still None - expected
   Get-Content "$env:APPDATA\BirdoVPN\dns-restore.json"
   netsh interface show interface name="Birdo VPN"
   ```
4. Now launch the app. Do **not** connect.

**PASS**

* Immediately after the kill: adapters parked, journal present and complete.
  **The machine is broken at this point and that is correct** — the record is
  what makes it recoverable.
* On the next launch, `birdo.log` shows
  `N adapter(s) recorded as parked by a previous session — checking whether they still are`
  (`win_machine_state.rs:1519`) and
  `Restored DNS left moved aside by a previous session` (`main.rs:408`).
* Within seconds, `netsh interface ipv4 show dns` matches `baseline-dns-v4.txt`.
  `BIRDO-TEST` has `203.0.113.53` back.
* `dns-restore.json` is gone.
* No amber banner, or a banner naming only adapters that genuinely could not be
  restored.

**PASS — the partial-restore variant.** If one adapter could not be verifiably
restored, its entry must **stay** in `dns-restore.json` and the log must show
`Adopting N adapter(s) a previous session left parked and could not restore …`
(`win_machine_state.rs:1445`). Then: **connect and disconnect again.** The
adopted adapter must be restored on that disconnect, and it must **not** be
re-snapshotted on the connect — its journal entry must still hold its *original*
resolvers, not `None`. That round trip is the whole point of `adopt_unrestored`;
run it whenever you see an adoption.

**FAIL**

* The journal is **absent** immediately after the kill while adapters are parked
  → the record was not written before the mutation (I4). Nothing can recover this
  machine; restore by hand from the baseline.
* The next launch does not restore, and the journal is **deleted anyway** → the
  only description of the real resolvers has been destroyed.
* The next **connect** re-snapshots a still-parked adapter — its journal entry
  changes from real resolvers to `None` → I5b violated from the recovery path.
  That adapter is now permanently stranded.

**If this fails, here is what it means.** Every abnormal exit — a crash, an OOM
kill, an antivirus terminate, a forced reboot — permanently costs the user the
resolvers on every adapter, with no diagnosis available afterwards because the
record is gone.

## S6b — power loss

**On a VM (do this if you possibly can):**

```powershell
# Hyper-V, from the host. This is a real power cut to the guest.
Stop-VM -Name <guest> -TurnOff -Force
```

Take a checkpoint first. Connect in the guest, wait for the parked state, then
`-TurnOff`. Boot, launch the app, and apply S6a's PASS criteria.

**Repeat it 3–5 times, cutting power at different points** — a few seconds after
Connect completes, and *during* the connect while the park pass is running. The
second is the interesting one.

**On physical hardware:** hold the power button. Same criteria.

**Honest limitation, and it is a real one.** The journal is written with
`write_all` and no `sync_all` / `FlushFileBuffers`
(`src-tauri/src/vpn/mod.rs:328`). The bytes are in the OS cache when `park_pass`
proceeds to the mutation, so a power cut in the window between the write and the
flush leaves adapters parked with **no record on disk**. That window is small and
you cannot aim at it; a handful of repetitions is a sampling test, not a proof.
`Stop-Process -Force` (S6a) does **not** exercise it at all — the cache survives
the process. If you see a parked machine with a missing journal after a power
cut, that is this window, and it is a design gap rather than a regression in
#114.

**If this fails, here is what it means.** The same as S6a, but reachable by a
laptop battery running out.

## Restore after S6

If any adapter is stranded, restore by hand from the baseline:

```powershell
# DHCP-sourced adapter:
netsh interface ip   set dns name="<adapter>" dhcp
netsh interface ipv6 set dns name="<adapter>" dhcp
# Statically configured adapter:
netsh interface ip   set dns name="<adapter>" static <first> validate=no
netsh interface ip   add dns name="<adapter>" <second> index=2
```

Delete `%APPDATA%\BirdoVPN\dns-restore.json` only after the machine's DNS is
correct.

---

# S7. Another VPN's split-default route survives — I10 / #100

> Route deletion used to match on destination alone, so disconnecting Birdo
> removed **any** `0.0.0.0/1` or `128.0.0.0/1` row — including another VPN
> product's. Routes are now recorded as
> `OwnedRoute { dest, prefix_len, next_hop, if_index }` and deleted
> owner-qualified; an unattributable route (`if_index == 0`) is never recorded
> and never deleted (`win_machine_state.rs:1323-1331`, `:1671-1675`).

## S7a — with a real second VPN (preferred)

**Preconditions:** [WireGuard for Windows](https://www.wireguard.com/install/)
installed, with a tunnel configuration whose `AllowedIPs = 0.0.0.0/0` and whose
endpoint is **bogus and unreachable**. WireGuard installs its `/1` pair when the
tunnel is activated regardless of whether a handshake ever completes, which is
exactly what you need and costs no second VPN subscription.

**Steps**

```powershell
# 1. Activate the OTHER tunnel first. Record its rows and its interface index:
Get-NetRoute -DestinationPrefix 0.0.0.0/1,128.0.0.0/1 |
  Format-Table DestinationPrefix,NextHop,ifIndex,RouteMetric -AutoSize |
  Out-File -Encoding utf8 C:\birdo-test\routes-other-vpn.txt
Get-Content C:\birdo-test\routes-other-vpn.txt

# 2. Connect Birdo. Both products' /1 rows now coexist:
Get-NetRoute -DestinationPrefix 0.0.0.0/1,128.0.0.0/1 |
  Format-Table DestinationPrefix,NextHop,ifIndex,RouteMetric -AutoSize

# 3. Disconnect Birdo. Re-check:
Get-NetRoute -DestinationPrefix 0.0.0.0/1,128.0.0.0/1 |
  Format-Table DestinationPrefix,NextHop,ifIndex,RouteMetric -AutoSize
```

**PASS**

* After step 3, **every row whose `ifIndex` belongs to the other VPN is still
  present**, with the same `NextHop`.
* Every row whose `ifIndex` was the Birdo VPN adapter is gone.
* The other VPN client still reports itself up, with no route error of its own.

**FAIL**

* The other product's `/1` rows are gone after Birdo disconnects. That is #100:
  Birdo silently broke another VPN's tunnel, and the user will blame the other
  product.
* Birdo's own `/1` rows survive the disconnect → the owner-qualified delete is
  too strict, and Birdo is stranding the machine's default routing.

## S7b — cheap proxy, no second VPN

Install a foreign split-default pair by hand on `BIRDO-TEST`, so the tuple
(next hop and interface index) cannot collide with Birdo's:

```powershell
Enable-NetAdapter -Name "BIRDO-TEST"
$ifx = (Get-NetAdapter -Name "BIRDO-TEST").ifIndex
route add 0.0.0.0   mask 128.0.0.0 192.0.2.1 metric 9999 if $ifx
route add 128.0.0.0 mask 128.0.0.0 192.0.2.1 metric 9999 if $ifx
Get-NetRoute -DestinationPrefix 0.0.0.0/1,128.0.0.0/1 | Format-Table -AutoSize

# Connect Birdo, then Disconnect, then:
Get-NetRoute -DestinationPrefix 0.0.0.0/1,128.0.0.0/1 | Format-Table -AutoSize
```

**PASS:** both `192.0.2.1` rows on `ifIndex $ifx` survive Birdo's disconnect.
**FAIL:** either is gone.

This proxy is weaker than S7a in one specific way: it does not exercise the
`if_index == 0` arm — an *unattributable* route — because `route add … if <idx>`
always produces a real interface index. Getting a genuinely unattributable row on
a real machine is not something you can arrange, so treat that arm as covered by
the unit tests only, and say so.

**If this fails, here is what it means.** Installing Birdo breaks other VPN
products on the same machine, intermittently and invisibly, whenever a Birdo
session ends. It also makes Birdo the prime suspect in support tickets that are
not about Birdo.

## Restore after S7

```powershell
route delete 0.0.0.0   mask 128.0.0.0 192.0.2.1
route delete 128.0.0.0 mask 128.0.0.0 192.0.2.1
Disable-NetAdapter -Name "BIRDO-TEST" -Confirm:$false
# Deactivate the WireGuard test tunnel and delete it.
Compare-Object (Get-Content C:\birdo-test\baseline-routes.txt) (route print -4)
```

---

# S8. Tear the test machine down

```powershell
# 1. App disconnected and closed.

# 2. Shim removed (S4) - check explicitly, it is the one thing that persists:
Get-ChildItem "C:\Program Files\BirdoVPN\netsh.exe" -ErrorAction SilentlyContinue

# 3. Firewall rules:
netsh advfirewall firewall delete rule name="BIRDO-TEST-PEER"
netsh advfirewall firewall delete rule name="BIRDO-TEST-API"

# 4. pktmon:
pktmon stop; pktmon filter remove; pktmon unload

# 5. Test routes and the test adapter:
route delete 0.0.0.0   mask 128.0.0.0 192.0.2.1
route delete 128.0.0.0 mask 128.0.0.0 192.0.2.1
#    Remove the KM-TEST Loopback Adapter in Device Manager (Network adapters).

# 6. DNS back to baseline - the check that matters:
netsh interface ipv4 show dns | Out-File -Encoding utf8 C:\birdo-test\final-v4.txt
netsh interface ipv6 show dns | Out-File -Encoding utf8 C:\birdo-test\final-v6.txt
Compare-Object (Get-Content C:\birdo-test\baseline-dns-v4.txt) (Get-Content C:\birdo-test\final-v4.txt)
Compare-Object (Get-Content C:\birdo-test\baseline-dns-v6.txt) (Get-Content C:\birdo-test\final-v6.txt)

# 7. Journal gone:
Get-Item "$env:APPDATA\BirdoVPN\dns-restore.json" -ErrorAction SilentlyContinue

# 8. Kill Switch back ON in Settings if S1c turned it off.
```

Both `Compare-Object` calls returning nothing, and steps 2 and 7 finding nothing,
is the end of the test.

---

# Appendix A — the `netsh` fault-injection shim (S4)

Save as `C:\birdo-test\netsh.rs`. Built and behaviour-verified on Windows 11
26200 with this repo's `rustc`.

```rust
//! I4 fault injector for docs/DEVICE-TEST-WINDOWS-DNS.md.
//! Fails `show dns` for ONE adapter; passes everything else through unchanged.
const SENTINEL: &str = "BIRDO-TEST";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let is_show = args.iter().any(|a| a.eq_ignore_ascii_case("show"));
    let names_sentinel = args.iter().any(|a| {
        a.eq_ignore_ascii_case(SENTINEL)
            || a.eq_ignore_ascii_case(&format!("name={}", SENTINEL))
    });
    if is_show && names_sentinel {
        eprintln!("netsh-shim: forced failure for {}", SENTINEL);
        std::process::exit(1);
    }
    let root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".to_string());
    let real = format!(r"{}\System32\netsh.exe", root);
    let status = std::process::Command::new(real).args(&args).status();
    std::process::exit(match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("netsh-shim: could not run the real netsh: {}", e);
            1
        }
    });
}
```

```powershell
rustc -O -o C:\birdo-test\netsh.exe C:\birdo-test\netsh.rs

# Verify it BEFORE installing it - all three must behave as shown:
C:\birdo-test\netsh.exe interface ipv4 show dns "BIRDO-TEST"   # -> exit 1, "forced failure"
C:\birdo-test\netsh.exe interface ipv4 show dns "Ethernet"     # -> real netsh output, exit 0
C:\birdo-test\netsh.exe interface ipv4 show interface          # -> real netsh output, exit 0
```

It deliberately does **not** intercept `set`, so
`netsh interface ip set dns name=BIRDO-TEST static none validate=no` still
reaches the real netsh and still succeeds. That asymmetry — the read fails, the
write would have succeeded — is precisely #102's condition.

Enumeration is unaffected: it uses `GetAdaptersAddresses` natively
(`enumerate_adapters_native`, `win_machine_state.rs`), not netsh, so the shim
cannot hide the adapter from the pass.

**Remove it when you are done.** See S4's restore step and S8 step 2.

---

# Appendix B — a gap found while writing this document

While deriving S4's fault injection, an alternative was considered: rename an
adapter so its name contains `=`, on the theory that netsh's positional `show`
parser would choke on it while the `name=` write form would not. It was measured
rather than assumed, and the result is worse than a failed idea.

**Measured on Windows 11 26200:**

```
> netsh interface ipv4 show dns "Ethernet 2=Z"
'Ethernet 2' is not a valid argument for this command.
The syntax supplied for this command is not valid. Check help for the correct syntax.

Usage: show dnsservers [[name=]string]
...
Remarks: Displays DNS server configuration for a specific interface or
         interfaces.
...
> exit code
0
```

netsh **failed**, printed a usage message, and **exited 0**.

`read_dns_family` guards on exactly two things: `!output.status.success()`
(`src-tauri/src/vpn/tunnel_dns.rs:46`) and `stdout.trim().is_empty()` (`:57`).
This output passes both. That text was then fed to the shipped `parse_dns_config`
(`tunnel_dns.rs:118`), compiled standalone under `rustc`:

```
stdout.trim().is_empty() = false
parse_dns_config_v4      = (false, [])
```

`(false, [])` is `static`-with-no-servers — **the terminal shape** #102 exists to
make unmanufacturable. netsh's own help text contains a line with a colon and the
token "DNS" and no "DHCP" (`Remarks: Displays DNS server configuration …`), so
the parser's label rule starts capturing on it and then finds no addresses.

An adapter whose name contains `=` would therefore be **recorded** as
static-with-no-servers, **parked** (the `name=` write form is unaffected), and on
restore `restore_family` would take its *"was static with no servers before
connect — leaving as-is"* branch (`win_machine_state.rs:455-463`) while
`matches_intent` confirmed it as correctly restored. Permanent resolver loss,
reported green.

**What is measured and what is not:**

* **Measured:** netsh exits 0 on that usage error; the shipped parser turns that
  output into `(false, [])`; the restore path no-ops on that shape.
* **Not measured:** that Windows permits `=` in an adapter name, and that the
  `name=Home=Office` *write* form then succeeds against a real adapter so named.
  Confirming those requires renaming a real adapter, and would leave the machine
  damaged if the theory holds.

**Do not run this as a test scenario** on any machine you care about. It is
recorded here so that it becomes an issue and a unit test — a captured corpus
entry of netsh's usage text, asserting `read_dns_family` returns `Err` — rather
than a discovery someone makes in production. `read_dns_family`'s own docstring
(`tunnel_dns.rs:19-31`) states that "a netsh that runs and fails prints nothing";
the measurement above is a netsh that runs, fails, prints, and exits 0.

---

# Appendix C — results sheet

Copy this into the release checklist and fill it in. `not run` is a legitimate
answer; `assumed` is not.

| | Scenario | Build tested | Result | Evidence | Notes |
|---|---|---|---|---|---|
| S0.6 | Sanity round trip | | | | |
| S1a | Server switch | | | | |
| S1b | Auto-reconnect (#98 path) | | | | |
| S1c-1 | Capture, **kill switch OFF** | | | `dnsleak.pcapng` | |
| S1c-2 | Capture, kill switch ON | | | | |
| S2 | Orphan window → Connect | | | `birdo.log` line | |
| S2 | Orphan window → Quit | | | | |
| S2 | `KillSwitchActive` arm | — | **not reachable** | state is never set | |
| S3 | Mid-session adapter parked ≤20 s | | | | |
| S3 | Journal holds the SENTINELS, not `None` | | | | |
| S3 | Ticker stops after disconnect | | | | |
| S4 | Not parked, not recorded, banner shown | | | log + screenshot | |
| S5 | Updater relaunch — outcome **A** or **B** | | | | |
| S6a | Hard kill → next start heals | | | | |
| S6a | Adoption round trip (if adoption seen) | | | | |
| S6b | Power loss ×N | | | | N = |
| S7a | Other VPN's `/1` rows survive | | | | |
| S7b | Proxy, if S7a not possible | | | | |
| S7 | `if_index == 0` arm | — | **not reachable** | unit tests only | |
| S8 | Machine restored to baseline | | | both `Compare-Object` | |

---

*Derived from the invariants in issue #105 and from the code merged as #114
(`b33e784`). Every command in S0.5, S1c, S4 and appendices A and B that is
described as measured was run on Windows 11 26200 while this document was
written; the scenarios themselves have **not** been run — that is the work this
document exists to make possible.*
