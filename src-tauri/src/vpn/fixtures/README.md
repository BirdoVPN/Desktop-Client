# BirdoPQ test fixtures

Three committed vector sets guard the ML-KEM-1024 (FIPS 203) path in
`src-tauri/src/vpn/birdo_pq.rs`. All are consumed by `#[cfg(test)]` tests in
that file or its test-only child module `birdo_pq_acvp.rs`, which CI runs (`.github/workflows/tests.yml` -> `cargo test --lib`).
The crate and feature set those tests run against are themselves gated by
`scripts/ci/check-pq-features.sh` in the same workflow, which also checks the
KAT fixture against its pin (below). The gate has its own self-test,
`scripts/ci/check-pq-features.tests.sh`.

## `birdo-pq-ml-kem-1024.kat.json` — the interop guard

A byte-for-byte copy of birdo-web's
`backend/src/vpn/__fixtures__/birdo-pq-ml-kem-1024.kat.json`, generated with
`@noble/post-quantum` — **the library the production server actually
encapsulates with** (`backend/src/vpn/birdo-pq.service.ts`).

The two copies must stay identical, and CI holds them to it (MR-2421). Neither
repo can read the other's copy (birdo-web is private; no cross-repo token), so
both pin the same sha256 in `birdo-pq-ml-kem-1024.kat.json.sha256`, a file
that is the same in both repos, and each CI fails if its own copy does not hash
to it: `scripts/ci/check-pq-features.sh` (section 7) here,
`scripts/ci/pq-kat-fixture-pin.mjs` in birdo-web. If the backend regenerates
its fixture: change it in birdo-web first, copy the file here, and move the
pin in both repos, in two pull requests that link each other.

`kat_vs_noble` asserts, from the fixture's 64-byte `keygenSeed`:

| leg | assertion |
|---|---|
| keygen | `ek == publicKeyB64` (1568 B), `dk == secretKeyB64` (3168 B) |
| encapsulate | `ct == cipherTextB64`, `ss == sharedSecretB64` |
| decapsulate | `decapsulate(ct, dk) == sharedSecretB64` |
| PSK | `HKDF-SHA-256(IKM=ss, salt="BirdoPQ-v1-PSK", info=nonce)[..32] == presharedKeyB64` |

Why it exists: every other test in `birdo_pq.rs` is a self-consistent round
trip, and a KEM that is internally correct but byte-incompatible with the
server passes all of them. FIPS 203 implicit rejection then makes the failure
**silent** — a wrong key yields a plausible shared secret and the WireGuard
handshake simply never completes. This is the only test that can catch that.

## `acvp-ml-kem-1024.json` — NIST's own vectors (MR-1432)

These are the ML-KEM-1024 test groups of NIST's ACVP-Server vector sets, the
vectors a FIPS 140-3 module is validated with. `birdo_pq_acvp.rs` runs them
against the linked RustCrypto `ml-kem`:

| group | count |
|---|---|
| keyGen, from `d || z` (the seed this client keeps) | 25 |
| encapsulation | 25 |
| decapsulation, valid and modified ciphertexts (implicit rejection) | 10 |
| FIPS 203 §7.2 key check | 10 (5 valid, 5 invalid) |
| FIPS 203 §7.3 key check | 10 (5 valid, 5 invalid) |

The KAT above shows that this client and the server agree. This set shows that
the KEM itself matches the standard. Without it, two libraries that share one
mistake would still agree.

**It is a cut of NIST's files, not a copy.**
- `scripts/extract-acvp-ml-kem-1024.py` keeps the ML-KEM-1024 groups' inputs
  and expected results from
  `gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203/internalProjection.json`
  at usnistgov/ACVP-Server `ad33b3d9504491767f1aa76382464f3b3fa2359e`.
- The script refuses upstream files whose sha256 is not the one it pins.
- The test pins the fixture's own sha256 (of its LF bytes), every group's
  size, and each key check's valid/invalid split. An edited or emptied fixture
  fails.
- Regenerate it; never hand-edit it. The commands are in the script's
  docstring.

The keys in it are NIST's published test keys, not anyone's.

## `birdo-pq-pqclean-stored-key.json` — the linked-KEM guard

A real ML-KEM-1024 keypair and ciphertext produced by **PQClean CLEAN C**
(`pqcrypto-mlkem 0.1.1`), the implementation the desktop client shipped up to
and including v1.4.43.

It was the install-base guard while the client kept a long-lived keypair in
`birdo_pq_v1.bin`: two tests proved that the RustCrypto `ml-kem` migration
still loaded such a stored key and re-keyed on a corrupt one. Per-connect keys
(MR-703 / MR-1742, #429) removed that path, and those two tests with it: the
client now makes one keypair per connect, in memory only, never reads a stored
key, and deletes the old files on first run (`the_legacy_keypair_file_is_purged`).

Its one remaining test is `pq_impl_name_matches_linked_crate`. The untouched
PQClean key must load; the same key with one bit flipped inside its embedded
`H(ek)` field (offset 3110, in `dk[3104..3136]`) must be REJECTED. Only
RustCrypto `ml-kem` performs that FIPS 203 §7.3 check (`pqcrypto-mlkem`'s
length-only `from_bytes` accepted the key), so the test proves which KEM is
linked, and that `PQ_IMPL_NAME` says so truthfully.

### These secret keys are PUBLISHED

`birdo-pq-pqclean-stored-key.json` contains a **real 3168-byte ML-KEM-1024
decapsulation key**, and `birdo-pq-ml-kem-1024.kat.json` a real one plus the
64-byte keygen seed that produced it. Desktop-Client is a **public** repo, so
both are world-readable and always will be, including in every past commit.

That is fine, and intended: they are throwaway vectors that exist only to be
compared against. It is only a problem if someone later mistakes one for a
spare identity. So, explicitly: **never install either key as a client
identity, never reuse them anywhere outside these tests, and never copy the
shape of this directory for a key that protects anything.** A PSK derived from
a published decapsulation key protects nothing.

### Regenerating

Don't, unless the format changes: the whole point is that these bytes are old.
The PQClean fixture was produced by a throwaway crate depending on
`pqcrypto-mlkem = "0.1"` that called `mlkem1024::keypair()` / `encapsulate()`
and wrote the base64 out; `nonceAscii` is the literal ASCII nonce, not base64.
Regenerating it with the *current* implementation would make it prove nothing.
