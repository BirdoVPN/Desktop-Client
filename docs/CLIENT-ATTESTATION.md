# Desktop client attestation (Ed25519)

The desktop client cannot use Play Integrity, so it proves it is an official
build by signing a server-issued nonce with an Ed25519 key that only the release
pipeline holds.

**Source of truth for the protocol, the server policy (`off` / `log` / `enforce`)
and the rollout order is `birdo-web` `docs/CLIENT-ATTESTATION.md`.** This note
only covers the desktop side: where the key lives and how to rotate it.

## What the client sends

`GET /vpn/attestation/nonce` immediately before a connect, then five OPTIONAL
fields on `POST /vpn/connect` and `POST /vpn/multi-hop/connect`:

| Field | Value |
|-------|-------|
| `desktopAttestNonce` | the nonce just fetched |
| `desktopAttestKid` | `BIRDO_DESKTOP_ATTEST_KID` (selects the verifying public key) |
| `desktopAttestSig` | base64url (no padding) of the 64-byte Ed25519 signature |
| `desktopAttestPlatform` | `windows` \| `linux` \| `macos` |
| `desktopAttestVersion` | `CARGO_PKG_VERSION` of the build |

Signed payload (UTF-8, `\n` separated — the backend re-derives it byte-for-byte
from the request fields):

```text
BIRDO-DESKTOP-ATTEST-v1\n<nonce>\n<platform>\n<version>\n<kid>
```

The signature is produced inside `BirdoApi::connect_vpn` / `connect_multi_hop`
(`src-tauri/src/api/attestation.rs`), not in the command layer, so quick-connect
and auto-reconnect's unattended re-dial are attested too.

Attestation is **best-effort**: a build without the key sends none of the five
fields (the JSON body is byte-identical to a pre-attestation client), and a
failed nonce fetch never blocks a connect. Whether an unattested connect is
allowed is a server-side policy decision.

## Keys

| Secret | Value |
|--------|-------|
| `BIRDO_DESKTOP_ATTEST_SK` | base64 of the 32-byte Ed25519 **seed** (private — repo secret only) |
| `BIRDO_DESKTOP_ATTEST_KID` | short key id, e.g. `desk-2026-07` |

Both are baked in at compile time via `option_env!` (the `SENTRY_DSN` pattern)
by the Windows, Linux and macOS release workflows. A `refs/tags/` build **fails**
if either secret is empty, so an official release can never silently ship
unattestable. Non-tag CI, local dev builds and forks compile without them.

Generate a key pair (the public half goes to the backend, keyed by the kid):

```bash
openssl genpkey -algorithm ed25519 -out desk.pem
# seed (private) → BIRDO_DESKTOP_ATTEST_SK
openssl pkey -in desk.pem -outform DER | tail -c 32 | base64
# public key → backend
openssl pkey -in desk.pem -pubout -outform DER | tail -c 32 | base64
```

## Rotation

1. Generate a new pair with a **new** kid (e.g. `desk-2026-10`).
2. Add the public key to the backend's key map *alongside* the current one —
   the backend selects by `desktopAttestKid`, so both are valid during overlap.
3. Update the `BIRDO_DESKTOP_ATTEST_SK` / `BIRDO_DESKTOP_ATTEST_KID` repo secrets
   and cut a release. Clients signing with the old kid keep verifying.
4. Retire the old public key only once the old clients are below the floor you
   are willing to refuse (an `enforce` policy would otherwise lock them out).

Because the client is open source, the key is only as secret as the CI secret
store — it distinguishes "built by our release pipeline" from "rebuilt by anyone
else", which is exactly the same guarantee bound as the Play channel, and it does
not gate entitlements (plan/device limits are enforced server-side regardless).

## Wire-format test vector

Pinned identically by the unit tests in `src-tauri/src/api/attestation.rs` and by
the backend spec. Seed is RFC 8032 §7.1 TEST 1; the expected signature below was
produced with Node's `crypto` (the backend's runtime), so a match proves both
implementations agree byte-for-byte.

```text
seed (base64)  nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=
public key     d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
nonce          nonce-0123456789abcdef
platform       windows
version        1.4.11
kid            desk-2026-07
payload        BIRDO-DESKTOP-ATTEST-v1\nnonce-0123456789abcdef\nwindows\n1.4.11\ndesk-2026-07
signature      O4vQ_iekQEu7trbwQ2MX57I4_QliaGDW5RFVYG5RAd2Uke36CThiMHImNdmqXZISiO9QkTwGTs6OfaE1VANrBA
```
