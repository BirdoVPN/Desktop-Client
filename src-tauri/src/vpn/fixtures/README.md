# BirdoPQ test fixtures

Two committed vectors guard the ML-KEM-1024 (FIPS 203) path in
`src-tauri/src/vpn/birdo_pq.rs`. Both are consumed by `#[cfg(test)]` tests in
that file, which CI runs (`.github/workflows/tests.yml` -> `cargo test --lib`).

## `birdo-pq-ml-kem-1024.kat.json` — the interop guard

A byte-for-byte copy of birdo-web's
`backend/src/vpn/__fixtures__/birdo-pq-ml-kem-1024.kat.json`, generated with
`@noble/post-quantum` — **the library the production server actually
encapsulates with** (`backend/src/vpn/birdo-pq.service.ts`). Keep the two copies
identical; if the backend regenerates its fixture, copy it here in the same PR.

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

## `birdo-pq-pqclean-stored-key.json` — the install-base guard

A real ML-KEM-1024 keypair and ciphertext produced by **PQClean CLEAN C**
(`pqcrypto-mlkem 0.1.1`), the implementation the desktop client shipped up to
and including v1.4.43. Every install created before the RustCrypto `ml-kem`
migration has a `birdo_pq_v1.bin` holding exactly this kind of 3168-byte
decapsulation key.

`stored_pqclean_dk_loads_and_derives_same_psk` asserts the current
implementation still loads it, re-exports it unchanged, decapsulates the
PQClean-produced ciphertext, and derives the same PSK. A future KEM swap that
breaks stored-key reading would otherwise brick every existing install with no
error anyone would see before release.

`corrupt_dk_returns_invalid_key_and_rekeys` flips one bit inside the key's
embedded `H(ek)` field (offset 3110, in `dk[3104..3136]`) to exercise the
FIPS 203 §7.3 validation that `ml-kem` performs and `pqcrypto-mlkem`'s
length-only `from_bytes` did not — and to prove the caller re-keys instead of
failing forever.

### Regenerating

Don't, unless the format changes: the whole point is that these bytes are old.
The PQClean fixture was produced by a throwaway crate depending on
`pqcrypto-mlkem = "0.1"` that called `mlkem1024::keypair()` / `encapsulate()`
and wrote the base64 out; `nonceAscii` is the literal ASCII nonce, not base64.
Regenerating it with the *current* implementation would make it prove nothing.
