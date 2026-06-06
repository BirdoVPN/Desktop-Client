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
**✅ Done — see §8** (commit `e8f9bc1`, gated on `clientIpv6`, held local).

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

---

## 8. IMPLEMENTATION STATUS — 2026-06-06

The **code is done and gated across all repos** (every path defaults to today's
behaviour; nothing changes until a node is flagged). Committed locally, **not yet
deployed**.

Done:
- **DB** (`birdo-web` migration `20270606000000_add_ipv6_dualstack`): additive +
  safe. `ServerNode.ipv6Enabled` (default false), `ServerNode.ipv6Subnet`,
  `WireguardKey.assignedIpv6` (+ unique per node).
- **Backend** (`vpn.service.ts`, `wireguard.service.ts`): `deriveClientIpv6`
  (IPv6 = `<prefix>::<ipv4-octet>`), dual-stack `buildConfigFile` + peer
  allowed-ips, and the connect response returns `clientIpv6` **only** when
  `node.ipv6Enabled`. Typechecks (prisma generate run).
- **Desktop client** (`tunnel.rs`): `configure_ipv6` (native IP Helper — assigns
  the IPv6 address + ::/1 + 8000::/1 routes on Wintun) runs when `client_ipv6`
  is present; otherwise the WFP IPv6 block stays. Falls back to blocking on any
  error (never leaks). cargo-check clean. **Dormant** until backend sends it.
- **Node-agent** (`reconcile.rs`, `config.rs`): `BIRDO_AGENT_IPV6_ENABLED`
  (default false) → ensures `ip6tables` MASQUERADE on egress. cargo-check clean.
- **Mobile client** (`birdo-client-mobile`, commit `e8f9bc1`, local): `clientIpv6`
  added to the shared `ConnectResponse`/`MultiHopConnectResponse` (defaulted →
  older payloads safe). `WireGuardConfigBuilder` assigns the IPv6 address on the
  wg-go Interface and `BirdoVpnService.buildVpnInterface` adds it to the Android
  `VpnService.Builder` — both only when `clientIpv6` is present. Routes already
  capture `::/0` in both tunnel branches, so IPv6 is blackholed (leak-safe) until
  a node is flagged. **Dormant** until backend sends it. Build not run locally
  (mobile gradle toolchain is parked post-launch — see launch CI landmines);
  changes are additive and mirror the proven desktop path.

### Pilot rollout (one node — all prod-touching, do with the owner)

1. **Deploy backend** with the migration (adds nullable/defaulted columns — safe;
   no node enabled yet → identical behaviour).
2. **Release a desktop client** containing the dormant IPv6 code (next `win-v*`).
3. **Pick a pilot node.** Provision IPv6 on it:
   - Confirm the VPS has a routed IPv6 (/64).
   - Give `wg0` an IPv6: `ip -6 addr add fd00:b1d0::1/64 dev wg0`.
   - Stop disabling IPv6: remove `net.ipv6.conf.all.disable_ipv6=1` (init-server.sh
     / docker-compose sysctls) and set `net.ipv6.conf.all.forwarding=1`.
   - Deploy the updated **node-agent** with `BIRDO_AGENT_IPV6_ENABLED=true`
     (it then adds the `ip6tables` MASQUERADE; forwarding is already reconciled).
4. **Flip the flag in the DB** for that node only:
   `UPDATE "ServerNode" SET "ipv6Enabled"=true, "ipv6Subnet"='fd00:b1d0::/64' WHERE name='<pilot>';`
5. **Test** on the pilot: connect, then verify on test-ipv6.com / ipleak.net that
   IPv6 shows the **node's** address (not the user's) — and on a NON-pilot node,
   confirm IPv6 is still blocked. Check kill-switch + disconnect.
6. **Roll out** node-by-node, flipping `ipv6Enabled` per node only after each is
   verified. (Mobile client parity is already implemented — §8 — so an Android
   release picks it up the same way as the desktop build.)

Rollback for any node: `UPDATE "ServerNode" SET "ipv6Enabled"=false …` — clients
immediately go back to blocking IPv6 for it on the next connect.
