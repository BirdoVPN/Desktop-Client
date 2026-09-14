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

## 1. Kill switch — ON BY DEFAULT (highest priority)
- [ ] Settings -> Security: **Kill Switch is ON** on a fresh install. It IS
      user-toggleable — turning it off shows a confirm dialog explaining the leak
      risk (`Settings.tsx`; `settings.rs`: "user turned it off — must be
      respected"). Turning it off and confirming must work; a tester who files
      "the toggle can be disabled" is filing correct behaviour.
- [ ] Connect to any server. Pull the network / kill the tunnel process abruptly -> **internet is fully blocked** (no leak): `ping 1.1.1.1` fails, browser fails.
- [ ] Now click **Disconnect** deliberately -> **internet returns** (kill switch releases on intentional disconnect).
- [ ] Restart the app while disconnected -> the kill-switch state persists exactly as the user left it (on stays on; a deliberate off stays off).

## 2. Connect / disconnect / stats (single-hop)
- [ ] Quick-connect connects; status pill shows **Protected**; live up/down/duration stats tick.
- [ ] `curl https://api.ipify.org` (or whatismyip) shows the **VPN server's** IP, not your real one.
- [ ] Disconnect returns to normal routing.

## 3. Stealth (Xray Reality) — paid feature
- [ ] On a **paid (Operative/Sovereign)** account, enable Stealth, connect -> connects successfully and the **"Stealth" chip appears under the status pill**.
- [ ] On a **free (Recon)** account, Stealth is labelled **Premium**; connect still works (stealth simply not provisioned).

## 4. Post-Quantum — ON by default
- [ ] Fresh install: Settings shows **Quantum Protection ON** by default.
- [ ] Connect -> the **"Post-Quantum" chip appears under the status pill** (proves ML-KEM PSK is active, `pq_mode == bilateral`).

## 5. Multi-hop (Sovereign)
- [ ] Multi-hop arm toggle is gated to Sovereign; entry + exit pickers work; same-server is rejected.
- [ ] Connects through both hops; egress IP is the **exit** node.

## 6. IPv6

> **Re-measured against the live fleet on 2026-09-14 (OPEN-WORK F14).** This
> section had three rows that would each have wasted a tester's evening. What is
> below is what the fleet and the backend actually do.
>
> * **All ten nodes are dual-stack.** `server_nodes.ipv6Enabled` is true for
>   every one of them, each with `fd00:b1d0::/64`. There is **no IPv4-only node
>   to test against**, so the old "IPv4-only node" row named a target that does
>   not exist — the reason F14 was raised. It is retargeted below rather than
>   retired: the fail-closed path it was checking is real and is still reachable,
>   just by a different route.
> * **The tunnel address is a ULA, not a global address.** Clients get
>   `fd00:b1d0::<last octet of their v4>`; the node NAT66-masquerades it out of
>   its own global `2001:19f0:…` (verified on Amsterdam and London: global v6 on
>   `enp1s0`, `net.ipv6.conf.all.forwarding=1`, one MASQUERADE rule in
>   `ip6tables -t nat`, and `ping6` to `2606:4700:4700::1111` succeeds from the
>   node). So an adapter showing `fd00:…` is **correct** — do not report it.
> * **Multi-hop is IPv4-only, deliberately.** The old row claimed "this release
>   added multi-hop IPv6", which is backwards. `deriveClientIpv6()` takes
>   `multiHop` as a REQUIRED argument and returns `null` for it, and
>   `vpn.service.ts` gates the derivation on `!params.multiHop` as well. The
>   reason is in the code: the wg-mesh fabric carries IPv4 only (10.99.0.0/24)
>   and the entry node's policy routing diverts IPv4 alone, so a multi-hop
>   client holding a v6 address would egress over the **entry** node's v6 — the
>   wrong country, from the one hop that also knows who the customer is, which
>   is the exact property multi-hop is sold to prevent. Happy Eyeballs prefers
>   v6, so most traffic to dual-stack destinations would take that leaking path.

- [ ] **Dual-stack node, single-hop:** the adapter gets an IPv6 address in `fd00:b1d0::/64`; `ping -6 2606:4700:4700::1111` succeeds; an IPv6 leak test (e.g. test-ipv6.com) shows an address in the **node's** `2001:19f0:…` range — not your ISP's, and not the `fd00:` ULA (that one is inside the tunnel and never appears to a website).
- [ ] **Multi-hop — IPv6 is BLOCKED, not leaked.** This is the fail-closed check the old "IPv4-only node" row was after, on a target that exists. Connect multi-hop and confirm: the adapter has **no** IPv6 tunnel address, `ping -6 2606:4700:4700::1111` **fails**, and test-ipv6.com reports no IPv6 connectivity at all. A **leak here is critical** — if test-ipv6.com shows any address, and especially one in the **entry** node's country, stop and report it.
- [ ] Kill switch active -> **both** IPv4 and IPv6 are blocked (WFP v4 + v6 filters).
- [ ] **Windows, dual-stack node — IPv6 MTU (W11):** `netsh interface ipv6 show subinterfaces` must list the Birdo adapter at the WireGuard MTU (1420 by default; `wireGuardMtu` in Settings if changed), not 1500 — before the F7 fix only the IPv4 row was written and `ping -6 -l 1400 -f 2606:4700:4700::1111` blackholed. `ping -6 -l 1380 -f` must succeed (1380 + 40 v6 + 8 ICMP = 1428 > 1420 would correctly fail).
- [ ] **Windows, dual-stack node — no unblocked window (W15):** with `pktmon` (or Wireshark) capturing on the **physical** NIC, connect; there must be no outbound global-IPv6 packet from the physical NIC between the connect click and the tunnel's `::/1` route landing (`Get-NetRoute -AddressFamily IPv6 | ? DestinationPrefix -eq '::/1'`). The address + routes now go in BEFORE the WFP v6 block is lifted (the Linux order); previously the block was lifted first.

**Already covered by automated tests — do not spend manual time re-checking:**
the `null`-for-multi-hop rule and the octet/prefix maths
(`wireguard.service.spec.ts`, 14 assertions over `deriveClientIpv6`); that an
absent `client_ipv6` is accepted as fail-closed rather than treated as a partial
scope (`validate_tunnel_scope`, `vpn/mod.rs` tests); and that a dual-stack
tunnel clears the pre-emptive v6 block while an IPv4-only one leaves it standing
(`wfp.rs`, LEAK-2). The manual rows above exist to check the **real network**
behaviour those tests cannot reach.

## 7. Split tunnel (Operative+)
- [ ] Add an app (e.g. a browser) to the exclude list; connect -> that app's traffic uses the **physical** interface (real IP) while everything else is tunnelled. Verify for both IPv4 and IPv6.

## 8. Port forwarding
- [ ] Create a TCP and a UDP forward -> appears with an external port; delete removes it.

## 9. Custom DNS
- [ ] Set a custom DNS; connect -> DNS queries use it (dnsleaktest.com shows no ISP DNS leak).

## 10. Voucher redemption (new — in-app)
- [ ] Profile -> **Redeem voucher** opens the in-app dialog (no longer kicks to the web).
- [ ] A valid 30/90-day code -> success message with days added; the **subscription card refreshes** in place.
- [ ] An invalid code -> friendly error ("couldn't find that voucher code"); an already-used code -> the 409 message; an expired code -> the expired message.

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
