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
# The release asset is named BirdoVPN_<version>_Linux_amd64.deb — NOT
# birdo-vpn_*.deb, which is what this step used to say and which does not
# exist. Desktop-Client is public, so no token is needed.
VER=1.4.44
curl -fsSLO "https://github.com/BirdoVPN/Desktop-Client/releases/download/v${VER}/BirdoVPN_${VER}_Linux_amd64.deb"
sudo dpkg -i "BirdoVPN_${VER}_Linux_amd64.deb" || sudo apt-get -f install -y

# Ask the package what it calls itself rather than guessing. Step 9 removes
# exactly this name, and a wrong guess there leaves the client installed while
# the bench reports a clean restore.
PKG=$(dpkg-deb -f "BirdoVPN_${VER}_Linux_amd64.deb" Package); echo "package: $PKG"

ip -6 route show            > /tmp/f001-routes-before.txt
sudo ip6tables -S           > /tmp/f001-ip6tables-before.txt
ip route show               > /tmp/f001-routes4-before.txt
```

The third capture is for **P3** at the end — it compares IPv4 routes, and
without it that parity step has nothing to diff against.

Keep both files. They are half the evidence.

---

## Step 3 — connect to a node that has IPv6 enabled

Use a single-hop connection. Multi-hop is a different path and is out of scope here.

**The node must have `ipv6Enabled = true` in the database.** This is the single
prerequisite most likely to waste the session, because a node without it hands
out no `client_ipv6`, `configure_ipv6()` returns `Ok(())` immediately without
doing anything (`tunnel_linux.rs:1085`), and **the bench passes while testing
nothing**.

Confirm before travelling:

```sql
SELECT name, "ipv6Enabled" FROM "ServerNode" WHERE "ipv6Enabled" = true;
```

**The relays themselves are not the risk.** All ten were swept read-only on
2026-09-20 and every one has two global IPv6 addresses, a default v6 route,
`ip6tables`, and **working v6 egress** — the last proven by an actual
`curl -6` to the internet, not merely by the presence of an address. That
distinction matters here: a Vultr instance created *without* `enable_ipv6`
still shows an address and an RA default route while routing nothing, and
turning the flag on afterwards does not fix it. The current fleet was rebuilt
dual-stack, so it is clear of that trap. What is *not* proven from outside the
database is which `ServerNode` rows carry the flag.

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

> **Corrected 2026-09-20. The earlier version of this step was wrong**, and
> wrong in the direction that produces a false failure: it told you to look for
> a **default** v6 route on the tunnel and to treat the host's surviving `::/0`
> as the bug. Correct code never installs a `::/0`, so an operator following
> that instruction would have reported a working client as broken. The step
> below describes what `configure_ipv6()` actually does.

```bash
ip -6 route show | grep -E '^(::/1|8000::/1)'
ip -6 route get 2606:4700:4700::1111
```

**Pass:** `::/1` **and** `8000::/1` are both present on the tunnel device, and
`route get` names the tunnel device.

**The host's own `::/0` is still there, and that is correct.** The client
deliberately routes the two halves instead of a default
(`tunnel_linux.rs:1078-1080`, and the long comment from line 1129). Two
more-specific prefixes win on longest-prefix match without deleting anything, so
teardown has nothing to restore — the same trick the IPv4 path uses. The
comments there spell out why the obvious approach was rejected: on a normal
SLAAC host the kernel already holds a `::/0`, so `ip -6 route add ::/0 dev <tun>`
returns **"File exists"**, and swallowing that would report success with **no
tunnel route installed** while the caller went on to lift the IPv6 leak block —
"strictly worse than never having routed v6 at all".

**Fail:** either half missing, or `route get` naming the physical interface.

**Note what a failure here means.** The function makes both of these checks
itself before returning — a missing half is a hard error, and the `route get`
probe exists precisely because a route can install and still lose on metric. So
a client that reports **Connected** while this step fails is not a routing
mismatch; it means the fatal check did not fire, which is a deeper bug than the
leak this bench is looking for.

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
sudo dpkg -r "$PKG"          # the name captured in step 2
ip -6 route show
sudo ip6tables -S
```

**Pass:** routes and rules match `/tmp/f001-*-before.txt`.

**Fail:** any difference. The uninstall left state behind, which is itself a
finding worth recording — and on a machine you are about to stop using, it is
the finding most easily lost.

---

## What CI now covers, so you do not re-test it by hand

Since `configure_ipv6_tests` landed in `src-tauri/src/vpn/tunnel_linux.rs`, the
following run as root on ubuntu-latest on **every push**, and the coverage gate
in `tests.yml` fails the build if either stops being executed:

| Proved in CI | Still needs this bench |
|---|---|
| `configure_ipv6()` executes without error — **its first execution anywhere** | That IPv6 traffic actually **leaves** through the tunnel (step 6) |
| It installs `::/1` + `8000::/1`, never a `::/0` | MTU behaviour on a real path (step 7) |
| The host's pre-existing v6 default survives untouched | The kill switch after disconnect (step 8) |
| The kernel agrees the tunnel won, via `ip -6 route get` | |
| A collision on one half is **refused**, not swallowed | |

That is goal 1 of the three this document opens with. Goals 2 and 3 are about
traffic and firewall state on a real dual-stack line, and no amount of CI
substitutes for them.

## Why this cannot be run on a production relay

The obvious thought — the fleet is Linux, so use a relay — does not survive
contact with what the steps do, and the reason is worth writing down so it is not
re-proposed.

**Step 1 was run on the fleet on 2026-09-20, read-only, and all ten relays
pass:** two global IPv6 addresses each, a default v6 route, working v6 egress,
`ip6tables` present. So a relay is a perfectly valid *environment* for this
bench. That is not the problem.

The problem is everything after step 1. Steps 2–9 install a VPN client, and
`configure_ipv6()` installs `::/1` + `8000::/1` — which between them cover the
entire IPv6 address space. On a relay that means **every customer's IPv6 egress
is pulled into the test tunnel**. Step 8 then verifies that the kill switch
*blocks* IPv6 after disconnect, which deliberately leaves the box in a
v6-blocking state, and step 9 removes a package. P2 goes further and provokes a
route conflict on purpose to prove the client refuses to connect.

So: step 1 on a relay, yes, and it is done. Steps 2 onwards need a Linux machine
on a dual-stack line that is **not carrying customer traffic**. A laptop on a UK
mobile hotspot is the cheapest thing that qualifies.

A network namespace would isolate routing and firewall state well enough to make
a relay safe, but the client is a Tauri desktop application with no headless
binary — there is no `[[bin]]` target to run under `ip netns exec`. Building one
purely for this would be a larger job than borrowing a laptop for an hour.

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

## Also in this session — F-008 parity checks (Linux half)

F-008 records that **nothing** from the five-platform parity audit has ever been
run, and that the changes it covers deliberately made previously-silent failures
**loud**: route-add failures and the endpoint host-route are now fatal. The risk
is the mirror of a leak — a wrong assumption turns a silent leak into a **hard
connect failure for every user on that platform**.

The five platforms are Windows, macOS, Linux, Android and iOS. **Linux is the
only one this session can cover**, and it is the one that shares an environment
with the IPv6 bench, so do it here rather than booking a second session.

### P1 — the endpoint host-route is pinned

While connected:

```bash
ip route get $(ip route show | grep -oP 'via \K[0-9.]+' | head -1)
ip route show | grep -E "<node-ip>"
```

**Pass:** a host route to the node's IP exists, pointing at the physical
interface, not the tunnel.

**Why it is fatal in the code, and what its absence looks like:** without it,
WireGuard's own outer UDP goes back into the tunnel — an encapsulation loop that
**reaches Connected and carries zero traffic**
(`src-tauri/src/vpn/tunnel_linux.rs:1275`). The client would look connected and
nothing would work, which is precisely the failure the fatal check exists to make
visible.

### P2 — a route-add failure is loud, not silent

Provoke it. With the client disconnected, install a conflicting host route to the
node by hand, then connect:

```bash
sudo ip route add <node-ip>/32 dev lo
# connect the client — expect it to FAIL, visibly
sudo ip route del <node-ip>/32 dev lo
```

**Pass:** the client refuses to connect and says why. **Fail:** it reports
Connected. That is the silent-failure regression this audit exists to catch.

Note the deliberate exception in the code: an **existing identical** route is
tolerated, and only that. Pinning to `lo` is not identical, so it must fail.

### P3 — disconnect leaves no routes behind

```bash
ip route show > /tmp/f008-routes-after.txt
diff /tmp/f001-routes4-before.txt /tmp/f008-routes-after.txt
```

(`f001-routes4-before.txt` is the IPv4 capture added to step 2. The earlier
version of this step diffed against the **IPv6** baseline, which would have
reported every IPv4 route in the table as a difference and made P3 look failed
no matter what the client did.)

**Pass:** no difference. **Fail:** any leftover host route or tunnel route is a
teardown defect — the next connect may then hit P2's conflicting-route path for
real.

### What this session does NOT cover

**macOS, Windows, Android and iOS remain unaudited.** macOS in particular needs a
real Mac: its route behaviour differs and the same fatal checks apply there. Do
not record F-008 as closed on the strength of the Linux third of it — record
exactly which platforms were covered.

---

## Results

| Step | Result | Date | Notes |
|---|---|---|---|
| 1 host has IPv6 | n/a for the fleet | 2026-09-20 | **Fleet sweep: 10/10 relays pass** (2 global addrs, default route, v6 egress, ip6tables). Still to be captured on the bench machine: ISP_V6 = |
| 2 baseline captured | | | |
| 3 connected to v6 node | | | node = |
| 4 configure_ipv6 ran | | | |
| 5 route is the tunnel's | | | |
| 6 no leak | | | observed = |
| 7 MTU | | | |
| 8 kill switch after disconnect | | | |
| 9 clean restore | | | |
| P1 endpoint host-route pinned | | | |
| P2 route-add failure is loud | | | |
| P3 clean teardown | | | |

**Overall: not yet run on a client machine.** Step 1's prerequisite is proven
across the fleet, and goal 1 — that `configure_ipv6()` executes and installs the
route shape it claims — is now proven in CI on every push. What remains is the
part that needs a real dual-stack client: the leak test itself, MTU, and the kill
switch after disconnect.

Once every row passes, this closes F-001, records the first-ever execution of
`configure_ipv6()`, and clears F-010 on the same bench. Re-issue the public-launch
Go/No-Go afterwards.
