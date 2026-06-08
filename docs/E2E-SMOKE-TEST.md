# Windows Client — E2E Smoke-Test Checklist

The automated suite (vitest + Rust unit tests + tsc/eslint/clippy gates) verifies
logic in isolation. The items below can **only** be verified on a real Windows
machine, because they depend on admin elevation, the WFP firewall, the wintun
driver, the bundled Xray engine, and live VPN nodes — none of which exist in CI.

Run this on a clean Windows 10/11 box (ideally not the dev machine) after
installing the signed `win-v1.3.x` build, **as Administrator**. Tick each box.

## 0. Install & launch
- [ ] Installer runs; SmartScreen shows the signed publisher (not "Unknown").
- [ ] App launches and prompts for / runs with **Administrator** elevation (required for WFP + wintun).
- [ ] Login works (email + password). 2FA challenge appears for a 2FA account and verifies.
- [ ] Anonymous login creates/loads a device account.

## 1. Kill switch — ALWAYS ON (highest priority)
- [ ] Settings → Security: **Kill Switch shows "Always on", toggle is locked off-limits** (cannot be disabled).
- [ ] Connect to any server. Pull the network / kill the tunnel process abruptly → **internet is fully blocked** (no leak): `ping 1.1.1.1` fails, browser fails.
- [ ] Now click **Disconnect** deliberately → **internet returns** (kill switch releases on intentional disconnect).
- [ ] Restart the app while disconnected → kill-switch row still locked on; settings file shows `killswitch_enabled: true` even if hand-edited to false.

## 2. Connect / disconnect / stats (single-hop)
- [ ] Quick-connect connects; status pill shows **Protected**; live up/down/duration stats tick.
- [ ] `curl https://api.ipify.org` (or whatismyip) shows the **VPN server's** IP, not your real one.
- [ ] Disconnect returns to normal routing.

## 3. Stealth (Xray Reality) — paid feature
- [ ] On a **paid (Operative/Sovereign)** account, enable Stealth, connect → connects successfully and the **"Stealth" chip appears under the status pill**.
- [ ] On a **free (Recon)** account, Stealth is labelled **Premium**; connect still works (stealth simply not provisioned).

## 4. Post-Quantum — ON by default
- [ ] Fresh install: Settings shows **Quantum Protection ON** by default.
- [ ] Connect → the **"Post-Quantum" chip appears under the status pill** (proves ML-KEM PSK is active, `pq_mode == bilateral`).

## 5. Multi-hop (Sovereign)
- [ ] Multi-hop arm toggle is gated to Sovereign; entry + exit pickers work; same-server is rejected.
- [ ] Connects through both hops; egress IP is the **exit** node.

## 6. IPv6 (per-node — test once a node has IPv6 activated)
- [ ] **Dual-stack node, single-hop:** adapter gets an IPv6 address; `ping -6 2606:4700:4700::1111` succeeds; an IPv6 leak test (e.g. test-ipv6.com) shows the **VPN** IPv6, not your ISP's.
- [ ] **Dual-stack node, multi-hop:** same as above (this release added multi-hop IPv6 — previously IPv4-only).
- [ ] **IPv4-only node:** IPv6 is **blocked, not leaked** — `ping -6` fails and test-ipv6.com shows no native IPv6. (Fail-closed: the tunnel blocks v6 when the node has none.)
- [ ] Kill switch active → **both** IPv4 and IPv6 are blocked (WFP v4 + v6 filters).

## 7. Split tunnel (Operative+)
- [ ] Add an app (e.g. a browser) to the exclude list; connect → that app's traffic uses the **physical** interface (real IP) while everything else is tunnelled. Verify for both IPv4 and IPv6.

## 8. Port forwarding
- [ ] Create a TCP and a UDP forward → appears with an external port; delete removes it.

## 9. Custom DNS
- [ ] Set a custom DNS; connect → DNS queries use it (dnsleaktest.com shows no ISP DNS leak).

## 10. Voucher redemption (new — in-app)
- [ ] Profile → **Redeem voucher** opens the in-app dialog (no longer kicks to the web).
- [ ] A valid 30/90-day code → success message with days added; the **subscription card refreshes** in place.
- [ ] An invalid code → friendly error ("couldn't find that voucher code"); an already-used code → the 409 message; an expired code → the expired message.

## 11. Notifications
- [ ] With notifications on, connect/disconnect fire native toasts.
- [ ] Toggling **Show IP** / **Show location** changes the connect notification body accordingly.
- [ ] A tunnel drop fires **Connection Lost** then **Reconnected** (auto-reconnect); kill-switch activation fires its toast.

## 12. Account / lifecycle
- [ ] Subscription screen shows plan/devices/bandwidth; "manage/upgrade" opens the web.
- [ ] GDPR **Export my data** downloads a JSON file.
- [ ] **Delete account** requires password + typing DELETE, then signs out.
- [ ] Auto-connect on launch (if enabled), tray connect/disconnect, autostart, start-minimized all behave.

## 13. Updater
- [ ] With an older version installed, the updater detects the new release, downloads, installs, and relaunches.

---

### Sign-off
Build version tested: `win-v1.3.____`  ·  Tester: __________  ·  Date: __________

If every box is ticked, publish the draft: `gh release edit win-v1.3.x --draft=false`.
