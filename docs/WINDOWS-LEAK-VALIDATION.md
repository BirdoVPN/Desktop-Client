# Desktop Windows on-device leak validation

The desktop firewall/routing changes below cannot be exercised in CI (no WFP,
no real adapter). They **must be validated on a real Windows box before the next
release tag is published**. This one checklist covers the shipped
lockdown-default change *and* the IPv6 hardening items (now implemented in #37).

## Validation status (2026-07-12)

Machine-level pieces that DON'T need a live elevated tunnel have been confirmed on
a Windows 11 box, and CI runs the compiled Rust suite on `windows-latest`:

- ✅ **LEAK-1 kill-switch state machine** — the `v6_state` intent-flag logic
  (block → kill switch → teardown → reconnect, plus the auto-reconnect give-up
  path and `cleanup`) passes as a standalone harness, incl. a control asserting
  the pre-fix path would have leaked. CI's "Rust unit tests (Windows)" runs the
  in-tree version green.
- ✅ **LEAK-3 is a real condition here** — `netsh interface ipv6 show dnsservers`
  shows live IPv6 resolvers (`fec0:0:0:ffff::1%1`) that a v4-only suppression
  would leave registered; the `netsh interface ipv6 set dns … static none` form
  parses on this OS build.
- ✅ **LEAK-6 DoH bootstrap** — resolving via the hardcoded bootstrap IPs returns
  200 from Cloudflare + Google (Quad9 reachable), i.e. resolution works without
  the system resolver.

Still REQUIRES an elevated, interactive session with a live tunnel (cannot be done
non-elevated — `netsh wfp show` and running the VPN both need admin): every
checkbox in sections A and B below. Run them on install of the release build.

## A. Already merged — must be validated before release

### A1. Lockdown kill switch is default-on (TunnelVision, desktop #34)
`lockdown_mode` now defaults **on**, making the always-on interface-scoped WFP
block-all the default posture (closes the TunnelVision / CVE-2024-3661 rogue-DHCP
option-121 decloak window).

- [ ] Fresh install (no prior settings file) connects successfully and traffic flows.
- [ ] With the tunnel up, a rogue DHCP server offering option-121 classless routes
      pointing at the physical gateway does **not** decloak traffic (verify with a
      packet capture on the physical NIC — no plaintext egress).
- [ ] LAN devices are unreachable by default; enabling **local network sharing**
      restores LAN access without leaking WAN traffic.
- [ ] Kill the wg process / pull the network mid-session → no plaintext egress
      during the gap; reconnect restores cleanly.
- [ ] Disconnect fully restores connectivity (no stranded block-all filters).

### A2. arm() degrades to reactive instead of disabling all protection (#9)
If lockdown activation fails at `arm()` (e.g. tunnel LUID not yet published),
the kill switch now falls back to **reactive** for the session instead of
disarming entirely. `set_lockdown_mode(false)` here is an in-memory session flag
only — the user's saved preference is untouched.

- [ ] Force an `activate_killswitch()` failure at arm time → session continues with
      reactive protection; a subsequent drop still fails closed (block-all on drop).
- [ ] The persisted `lockdown_mode` setting is unchanged after such a session.

## B. Deferred — implement + validate in the same pass (do NOT ship blind)

These were surfaced by the leak sweep (each 2/3 adversarially confirmed, medium
regression risk). They are genuine but reorder WFP/route setup, so they need
on-device verification that a failed connect never strands IPv6 blocked and that
DNS restore stays symmetric.

### B1. Block IPv6 at the *start* of `tunnel.rs::start()` (finding #10)
Today `block_ipv6_leaks()` runs **last** in `start()`, so IPv6 stays routable on
the physical adapter for the whole tunnel-setup window (configure_adapter →
routes → dns). Under reactive mode (lockdown off) that is a real sub-second IPv6
leak below the tunnel.

- Implement: call `wfp::block_ipv6()` as the **first** network step in `start()`.
  For dual-stack nodes (`config.client_ipv6.is_some()`) call `unblock_ipv6()`
  immediately before `configure_ipv6()`. Add `unblock_ipv6()` on **every** early
  return / error path so a failed connect never leaves IPv6 blocked.
- [ ] Connect on an IPv6-enabled host → no IPv6 egress on the physical NIC at any
      point during setup (packet capture).
- [ ] A **failed** connect (bad config / unreachable endpoint) leaves IPv6
      connectivity fully restored — nothing stranded.
- [ ] Dual-stack node (if/when deployed) still routes IPv6 through the tunnel.

### B2. Mirror SMHNR DNS suppression on IPv6 (finding #11)
The DNS-disable loop (`tunnel.rs` ~1263) only runs `netsh interface ip set dns`
(IPv4) on non-VPN adapters. On a dual-stack adapter the IPv6 resolvers stay
active, a latent AAAA DNS leak. (Largely masked today because nodes are IPv4-only
and IPv6 is blocked, but should be symmetric.)

- Implement: also run `netsh interface ipv6 set dns name=<adapter> static none
  validate=no`; capture IPv6 DNS in `snapshot_adapter_dns` and restore it in
  `restore_dns()` so disconnect is symmetric.
- [ ] On a dual-stack adapter, AAAA queries cannot reach a physical resolver while
      connected.
- [ ] Disconnect restores both IPv4 **and** IPv6 DNS exactly as before connect.

---

*Generated from the adversarially-verified client leak sweep. B1/B2 are tracked
here rather than shipped so they land with test coverage on a real Windows host.*
