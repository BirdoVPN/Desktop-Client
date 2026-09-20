# F-001 — desktop IPv6 leak bench

**Audience: the operator running the bench.** One session, about an hour of active
work. Follow it top to bottom and write the result into the Results table at the
bottom of this file, then commit it.

> **This file did not exist until 2026-09-20.** The open-work register has told
> several sessions to "run `release/patches/F-001-desktop-ipv6-leak.md`, steps 1–9".
> A search of every repository's full history finds no such file, ever. That is why
> this blocker never moved: the instruction was unactionable, and each session
> recorded it as "needs a device" rather than noticing the document was missing.
> The steps below are derived from the shipped code, named at each step so you can
> check the derivation rather than trust it.

---

## What is actually being proved

Three separate things, and it matters that they are separate — two of them can pass
while the third fails.

1. **`configure_ipv6()` executes without error.** Since the change that made route
   failures fatal, every Linux and Windows single-hop connect calls it for real.
   It has never been executed on a machine with working IPv6, anywhere.
   (`src-tauri/src/vpn/tunnel_linux.rs`, `configure_ipv6`, from line 1081.)
2. **IPv6 traffic actually leaves through the tunnel**, not the ISP. This is the
   leak itself.
3. **The kill switch still blocks IPv6 after disconnect.** A tunnel that routes v6
   correctly while up, and leaks it the moment it drops, is the failure users
   would never notice.

## Prerequisites — read before travelling to a machine

| | |
|---|---|
| Hardware | x86_64 Linux. An ARM box will not run the `.deb`. |
| **Network** | **A line with real, working IPv6.** A UK mobile hotspot usually has one; most home broadband does not. **Verify this before anything else — step 1.** |
| Build | v1.4.42 or later `.deb` from the GitHub release |
| Privileges | root, or passwordless sudo — the client runs elevated |
| Tools | `ip`, `ip6tables`, `curl`, and a browser |

**If step 1 fails, stop.** A bench on an IPv4-only line proves nothing: every step
below passes trivially because there is no IPv6 to leak. That is the single most
likely way to come away believing this is done when it is not.

---

## Step 1 — prove the host has working IPv6, before installing anything

```bash
ip -6 addr show scope global
ip -6 route show default
curl -6 -s --max-time 10 https://ifconfig.co && echo
```

**Pass:** a global address, a default route, and `curl -6` prints an address.
Write that address down — call it **ISP_V6**. Everything later compares against it.

**Fail:** no global address, or `curl -6` times out. **Stop and find a different
line.** Do not continue.

---

## Step 2 — install and capture the pre-connect baseline

```bash
sudo dpkg -i birdo-vpn_1.4.42_amd64.deb || sudo apt-get -f install -y
ip -6 route show            > /tmp/f001-routes-before.txt
sudo ip6tables -S           > /tmp/f001-ip6tables-before.txt
```

Keep both files. They are half the evidence.

---

## Step 3 — connect to a node that has IPv6 enabled

Use a single-hop connection. Multi-hop is a different path and is out of scope here.

**The node must have `ipv6Enabled = true`.** If you are unsure, pick one from the
IPv6 activation list; a node without it will hand out no `client_ipv6`, and
`configure_ipv6()` returns `Ok(())` immediately without doing anything
(`tunnel_linux.rs:1085`). The bench would then pass while testing nothing.

---

## Step 4 — prove `configure_ipv6()` actually ran

```bash
ip -6 addr show dev $(ip -o link show | grep -o 'birdo[0-9]*' | head -1)
```

**Pass:** the tunnel interface carries a global IPv6 address, the one the server
issued as `client_ipv6`.

**Fail:** no address on the tunnel. The client either never called the function or
it errored. Capture the client log — the error text is `ip -6 addr add failed: …`.

---

## Step 5 — prove the v6 route is the tunnel's, and not a pre-existing one

This is the step with the known trap, and it is worth doing carefully.

```bash
ip -6 route show | grep -E '^default|^::/0'
```

**Pass:** the default v6 route points at the tunnel interface.

**Fail, and the specific hazard:** if the host already had a `::/0` default, then
`ip -6 route add ::/0 dev <tun>` returns **"File exists"**. The code comments at
`tunnel_linux.rs:1121` record exactly this: treating that as success would leave
**no tunnel route installed** while the caller goes on to lift the IPv6 block —
"strictly worse than never having routed v6 at all". So if you see the old ISP
route still there while the client reports connected, that is the bug, not a
cosmetic mismatch.

---

## Step 6 — the leak test itself

Open **both** of these in a browser, and run the curl as well:

- `https://test-ipv6.com`
- `https://ipleak.net`

```bash
curl -6 -s --max-time 10 https://ifconfig.co && echo
```

**Pass:** every one of them reports the **node's** IPv6 address. Not ISP_V6 from
step 1.

**Fail:** any of them shows ISP_V6. That is the leak, and it is a No-Go.

**Control, and do not skip it:** disconnect, connect to a node that does **not**
have IPv6 enabled, and repeat. You should see IPv6 either blocked entirely or
absent — never ISP_V6 flowing while connected. A bench with no control cannot tell
"the tunnel is carrying v6" from "this line has no v6 today".

---

## Step 7 — MTU

```bash
ping6 -c 3 -M do -s 1372 ipv6.google.com
```

1372 payload plus 48 bytes of headers is 1420, the default tunnel MTU.

**Pass:** replies. **Fail:** "message too long" means the interface MTU was not
written and large v6 packets will black-hole rather than fragment.

---

## Step 8 — the kill switch, after disconnect

Disconnect the client, then immediately:

```bash
curl -6 -s --max-time 8 https://ifconfig.co ; echo "exit=$?"
sudo ip6tables -S > /tmp/f001-ip6tables-after.txt
diff /tmp/f001-ip6tables-before.txt /tmp/f001-ip6tables-after.txt
```

**Pass:** the curl fails or times out — IPv6 is blocked — and the rules differ from
the baseline in the expected direction.

**Fail:** the curl returns ISP_V6. IPv6 leaks the moment the tunnel drops, which is
the worst of the three failures because nothing on screen indicates it.

**Note for an IPv4-only host:** `ip6tables` may be absent, and the code tolerates
that deliberately, returning Ok and skipping the rule
(`firewall_linux.rs:91–103`). On a genuine IPv6 line it will be present. If it is
absent here, you are on the wrong line — go back to step 1.

---

## Step 9 — restore

```bash
sudo dpkg -r birdo-vpn
ip -6 route show
sudo ip6tables -S
```

Confirm routes and rules match `/tmp/f001-*-before.txt`. If they do not, the
uninstall left state behind, which is itself a finding worth recording.

---

## Evidence to capture

Attach or paste all of it into the Results table:

- ISP_V6 from step 1, and the node address from step 6
- `/tmp/f001-routes-before.txt`, `/tmp/f001-ip6tables-before.txt`, `/tmp/f001-ip6tables-after.txt`
- Screenshots of test-ipv6.com and ipleak.net while connected
- The client log for the connect, whether or not it passed
- The node name and whether it had IPv6 enabled

## If something fails

Instant rollback for a node, from the IPv6 activation runbook:

```sql
UPDATE "ServerNode" SET "ipv6Enabled" = false WHERE name = '<node>';
```

That disables v6 for that node without a release. Record the failure here first —
a rollback with no record is how this comes back as a surprise.

---

## Results

| Step | Result | Date | Notes |
|---|---|---|---|
| 1 host has IPv6 | | | ISP_V6 = |
| 2 baseline captured | | | |
| 3 connected to v6 node | | | node = |
| 4 configure_ipv6 ran | | | |
| 5 route is the tunnel's | | | |
| 6 no leak | | | observed = |
| 7 MTU | | | |
| 8 kill switch after disconnect | | | |
| 9 clean restore | | | |

**Overall: not yet run.**

Once every row passes, this closes F-001, records the first-ever execution of
`configure_ipv6()`, and clears F-010 on the same bench. Re-issue the public-launch
Go/No-Go afterwards.
