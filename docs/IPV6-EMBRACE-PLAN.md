# IPv6 Embrace — Dual-Stack the BirdoVPN Fleet

**Status:** Proposal / roadmap (not yet implemented)
**Author:** drafted 2026-06-06
**Goal:** Stop *blocking* IPv6 on the client and instead route it through the
tunnel, so users keep full IPv6 connectivity with no leak. Today the client
blocks all outbound IPv6 (native WFP filter) because the nodes are IPv4-only;
sending IPv6 out the physical NIC would leak the user's real address.

This is an **infrastructure project**, not a client tweak — it touches every
node, the backend, and the desktop/mobile clients. It must be all-or-nothing
*per node*: a node either fully supports IPv6 (and advertises it) or the client
keeps blocking IPv6 for that node.

---

## 1. Server / node changes (per VPN node, ×8)

1. **Allocate IPv6.** Confirm each VPS has a routed IPv6 block (most providers
   give a /64). Vultr/most providers: a /64 routed to the instance.
2. **WireGuard interface dual-stack.** Add an IPv6 address to `wg0`:
   - `Address = 10.13.13.1/24, fd00:birdo::1/64` (ULA for the tunnel) **or** a
     routed GUA /64 split per-peer.
   - Decide tunnel addressing: simplest is a **ULA** (`fd00::/8`) inside the
     tunnel + NAT66 to the node's GUA, mirroring how IPv4 uses 10.13.13.0/24 +
     NAT44. This avoids per-peer GUA assignment.
3. **Enable forwarding + NAT66.**
   - `sysctl net.ipv6.conf.all.forwarding=1`
   - `ip6tables -t nat -A POSTROUTING -s fd00:birdo::/64 -o eth0 -j MASQUERADE`
   - Persist via the node provisioning script / systemd.
4. **Per-peer AllowedIPs.** When the backend adds a peer, include an IPv6
   tunnel address: `AllowedIPs = 10.13.13.X/32, fd00:birdo::X/128`.
5. **Firewall.** Allow the WG UDP port over IPv6 too (if clients reach the node
   via IPv6); permit forwarded tunnel IPv6.
6. **Capability flag.** Node provisioning marks the node `ipv6: true` only after
   all of the above is verified (a self-test: ping6 out of the tunnel namespace).

## 2. Backend changes (`birdo-web/backend`)

1. **Peer creation** (`wireguard.service.ts`): assign an IPv6 tunnel address
   alongside the IPv4 one; add both to the peer's `AllowedIPs`.
2. **`/vpn/connect` response**: extend `VpnConfig` with:
   - `client_ipv6` (e.g. `fd00:birdo::X/128`)
   - `dns_ipv6` (e.g. `2606:4700:4700::1111`, `2606:4700:4700::1001`)
   - `node_supports_ipv6: boolean`
3. **Node model / DB**: persist the node's IPv6 capability + tunnel prefix.
4. **Backward compatibility**: older clients ignore the new fields and keep
   blocking IPv6 — safe. New clients only enable IPv6 when
   `node_supports_ipv6 === true`.

## 3. Client changes (desktop — `tunnel.rs`)

Gate everything on `node_supports_ipv6`:

1. **Adapter IPv6 address**: `CreateUnicastIpAddressEntry` for `client_ipv6` on
   the Wintun LUID (native, mirrors the IPv4 path we're building).
2. **Routes**: add `::/1` and `8000::/1` via the Wintun interface (the IPv6
   equivalent of the `0.0.0.0/1 + 128.0.0.0/1` split) so IPv6 default routes
   into the tunnel. Add an IPv6 host route to the node endpoint via the real
   gateway if the node is reached over IPv6.
3. **DNS**: set IPv6 resolvers (`dns_ipv6`) on the adapter too.
4. **Do NOT call `wfp::block_ipv6()`** for IPv6-capable nodes. For IPv4-only
   nodes, keep blocking exactly as today.
5. **WireGuard**: `boringtun` already carries any inner IP version; ensure the
   tun read/write path forwards IPv6 packets (it should — it's payload-agnostic).
6. **Leak test on connect**: optional — verify the egress IPv6 is the node's,
   not the user's, before declaring connected (belt-and-suspenders).

## 4. Mobile (parity)

Mirror the client logic in `birdo-client-mobile` (the WireGuard/Android VpnService
already supports IPv6 addresses + routes; add them when `node_supports_ipv6`).

## 5. Rollout

1. Dual-stack **one** node end-to-end; mark it `ipv6: true`.
2. Ship a client build that honors `node_supports_ipv6` (blocks otherwise).
3. Verify on that node: full IPv6 connectivity, no leak (test-ipv6.com,
   ipleak.net), kill-switch still blocks on disconnect.
4. Roll the node change across the remaining 7 nodes.
5. Flip all nodes to `ipv6: true` once verified.

## 6. Risks / notes

- **Leak safety is paramount**: the client must default to BLOCK and only route
  IPv6 when the node explicitly advertises support — never assume.
- **NAT66 vs routed GUA**: NAT66 (ULA + masquerade) is simplest and matches the
  existing IPv4 NAT model; routed per-peer GUA is "cleaner" but needs prefix
  delegation and more bookkeeping. Recommend NAT66 for v1.
- **MTU**: keep 1420 (WG overhead); IPv6 min MTU is 1280, so fine.
- **Kill switch**: the WFP kill switch already has `add_block_all_v6` +
  `add_permit_localhost_v6` + STUN/TURN v6 blocks — when IPv6 is embraced, the
  kill switch must permit the tunnel's IPv6 egress (add a permit for the node's
  IPv6 endpoint), same as it permits the IPv4 server today.

## 7. Effort estimate

- Node provisioning + NAT66: ~1 day (script + test on one node).
- Backend peer/IPv6 config + response fields: ~1 day.
- Desktop client IPv6 address/routes/DNS (native): ~1-2 days.
- Mobile parity: ~1 day.
- Fleet rollout + leak testing: ~1 day.

**~1 week of focused work**, sequenced so production is never at risk (one node
first, client gated on capability).
