# Birdo VPN — Windows release smoke test

This is the **device-only** verification that cannot be done in CI or by static
review. It must be run on a **real, elevated Windows machine with a real Birdo
account**, against a freshly built/installed release. It exists because the most
important properties of a VPN client — that the tunnel actually carries traffic,
that the kill switch actually blocks on a drop, and that login survives hostile
DNS — are only observable at runtime.

> Run elevated (the app manifest requires Administrator). Have a second network
> path (phone hotspot) handy in case a test leaves the firewall armed; worst case,
> end `BirdoVPN.exe` in Task Manager — the WFP session is dynamic, so killing the
> process auto-removes every Birdo filter and restores networking.

## 0. Build & install

```powershell
cd src-tauri
# Download wintun.dll + xray.exe first (see .github/workflows/build-windows.yml
# steps "Download Wintun" / "Download pinned Xray Reality engine"), then:
cargo tauri build --bundles nsis
# Installer: src-tauri/target/release/bundle/nsis/*-setup.exe
```
Install it. Launch from the Start menu (elevation prompt should appear).

## 1. Login (control plane + DoH — F5)

1. Log in with a real account. Expect success and the dashboard.
2. **DoH proof** — block plain DNS for the API and confirm login still works:
   ```powershell
   # Poison the system resolver for api.birdo.app, then try to log in.
   Add-Content C:\Windows\System32\drivers\etc\hosts "0.0.0.0 api.birdo.app"
   ipconfig /flushdns
   # Restart the app, log in. It MUST still work (resolves via cert-pinned DoH).
   # Clean up afterwards:
   #   (remove the line you added) ; ipconfig /flushdns
   ```
   PASS = login succeeds with the poisoned hosts entry. (Confirms the new
   `DohApiResolver` is doing the resolution, not the system resolver.)

## 2. Connect (data plane)

1. Note your public IP first: `(Invoke-RestMethod https://api.ipify.org?format=json).ip`
2. Connect to a server. State → Connected.
3. Re-check public IP — it must now be the **VPN server's** IP.
4. Confirm the WFP filters and Wintun adapter exist:
   ```powershell
   Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Wintun' }
   netsh wfp show state | Select-String -Pattern 'Birdo' | Select-Object -First 5
   ```

## 3. Kill switch — the critical test (AUDIT-2026-06-19 fix)

This verifies the fix that armed the previously-dead kill switch. While
**connected**, force the tunnel down out from under the client and confirm
IPv4 does **not** leak before reconnect.

```powershell
# Terminal A: hammer a request loop so any leak is observable.
while ($true) {
  try { "{0}  {1}" -f (Get-Date -Format HH:mm:ss), (Invoke-RestMethod -TimeoutSec 3 https://api.ipify.org?format=json).ip }
  catch { "{0}  BLOCKED/timeout" -f (Get-Date -Format HH:mm:ss) }
  Start-Sleep -Milliseconds 800
}
```

Now, in another window, simulate an **unexpected drop** (do NOT use the app's
Disconnect button — that's a clean user disconnect):

- **3a. Detected drop:** disable the Wintun adapter:
  `Disable-NetAdapter -InterfaceDescription "*Wintun*" -Confirm:$false`
  - EXPECT: Terminal A flips to `BLOCKED/timeout` (kill switch engaged on the
    next ~5s health tick) — it must **never** print your real ISP IP. Then the
    client auto-reconnects and the loop resumes showing the **server** IP.
  - While blocked, confirm the block-all filters are live:
    `netsh wfp show state | Select-String 'Birdo'` (expect block-all + the
    server-IP permit).

- **3b. Silent drop (watchdog):** with the tunnel up, black-hole the server at
  the gateway/router (or pull Wi-Fi for >60s) so the adapter stays "up" but no
  packets return.
  - EXPECT: within ~30–60s the **liveness watchdog** flips state to Error
    ("Tunnel unreachable (no inbound traffic)") and a reconnect is attempted.
    Watch the app log for `Tunnel liveness watchdog: heartbeat failing AND no
    inbound traffic`. The watchdog requires BOTH a failed heartbeat (control
    plane) AND flat inbound bytes (data plane), so it will not false-trip a
    healthy idle or upload-only tunnel.
  - Before this fix the UI would have stayed "Connected" forever with frozen
    byte counters.
  - **False-positive guard test:** leave a healthy tunnel **idle** for 5 minutes
    (no browsing). EXPECT: it stays Connected, NO spurious reconnect (heartbeat
    keeps succeeding → watchdog never fires).

- **3c. Clean disconnect releases the firewall:** press Disconnect in the app.
  - EXPECT: Terminal A returns to your **real** IP (kill switch disarmed,
    `netsh wfp show state` shows no Birdo filters). This proves `disarm()` runs
    on user disconnect and you are never stranded behind the firewall.

- **3d. Give-up does not strand you (lockout-regression guard):** connect, then
  make the server **permanently** unreachable (keep it black-holed) so every
  reconnect attempt fails. EXPECT: the client retries with backoff, and after the
  max attempts it **gives up AND releases the kill switch** (clear internet
  returns, `netsh wfp show state` shows no Birdo filters) — it must NOT leave you
  offline indefinitely behind an un-removable block. (Both the Disconnected and
  Error give-up paths now deactivate symmetrically.)

## 3e. Lockdown / always-on mode (OPT-IN — verify before enabling by default)

Lockdown mode (`lockdown_mode` setting, **off by default**) keeps the WFP
block-all active the *entire* time you're connected and permits tunneled traffic
by the Wintun interface LUID — eliminating the ~5–30s reactive window. It **must**
pass this test before being shipped on, because a wrong interface LUID would
block your own tunneled traffic.

Enable it: set `"lockdown_mode": true` in the persisted settings JSON (or via the
UI toggle once exposed), then connect.

- **3e-1. Browsing still works (the critical check):** while connected in lockdown
  mode, browse normally for a few minutes (load several sites, stream something).
  - EXPECT: **everything works.** If pages hang/fail, the tunnel-interface permit
    is wrong (LUID not resolved) — do NOT ship lockdown on. Confirm the permit
    exists: `netsh wfp show state | Select-String 'tunnel interface'`.
- **3e-2. Block is continuously active:** while connected (no drop), check
  `netsh wfp show state | Select-String 'Birdo'` — the block-all + permits
  (including "Permit tunnel interface v4/v6") must be present **the whole time**
  (in reactive mode they're absent in steady state).
- **3e-3. Zero-window on drop:** run the Terminal-A loop from §3, then force a drop
  (disable Wintun). EXPECT: traffic is blocked **immediately** (no ~5s window —
  the block was already active), then reconnects. It must never print your real IP.
- **3e-4. Disconnect releases everything:** Disconnect → real IP returns, no Birdo
  filters remain (`disarm()` → `wfp::cleanup()`).

If all four pass on real hardware, lockdown is safe to enable by default.

## 4. Reconnect & server switch

1. Connect, then pick a **different** server while connected.
   - EXPECT: clean switch (old tunnel torn down, new one up), new server IP, no
     leak during the switch (block-all re-permits the new server before the new
     handshake).
2. Connect, then sleep/resume the laptop. EXPECT: auto-reconnect restores the
   tunnel.

## 5. Stealth + post-quantum (if a stealth/PQ node is available)

1. Enable stealth + quantum in settings, connect to a stealth/PQ-capable node.
2. EXPECT: connection succeeds (xray.exe spawns; the app aborts rather than
   downgrading if stealth/PQ was requested but the server didn't grant it).
3. Confirm `XRAY_BINARY_SHA256` was injected at build time — otherwise stealth
   fails closed at runtime (see build-windows.yml). A successful stealth connect
   from a signed release confirms this.

## 6. Updater + signing (release artifact only)

1. Confirm the installed `BirdoVPN.exe` and the NSIS installer are Authenticode
   signed: `Get-AuthenticodeSignature <path>` → Status `Valid`, publisher Birdo.
   (Authenticode is applied by the **tag** build via Tauri `signCommand`; a local
   `cargo tauri build` is unsigned — that's expected.)
2. Confirm crash reporting: set the `SENTRY_DSN` repo secret, cut a tagged
   build, force a panic, and verify the event lands in Sentry. Without the
   secret, Sentry is a no-op (option_env! is None).

---

### Pass criteria summary

| # | Check | Pass = |
|---|-------|--------|
| 1 | Login under poisoned DNS | succeeds (DoH) |
| 2 | Connect | public IP becomes server IP |
| 3a | Adapter-disable drop | traffic BLOCKED then reconnects; never real IP |
| 3b | Silent black-hole | watchdog reconnects within ~30s |
| 3c | Clean disconnect | firewall released, real IP returns |
| 4 | Server switch / resume | clean, no leak |
| 5 | Stealth + PQ | connects or fails closed (never downgrades) |
| 6 | Signing + Sentry | signed artifact; Sentry receives events |
