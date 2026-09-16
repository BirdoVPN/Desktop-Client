//! BirdoPQ v1 — ML-KEM-1024 KEM-only PSK derivation for desktop.
//!
//! Wire-format twin of `birdo-client-mobile/native/rosenpass-jni/src/handshake.rs`
//! and `birdo-web/backend/src/vpn/birdo-pq.service.ts`. All three derive
//! exactly the same 32-byte WireGuard PSK from the same `(sk, ct, nonce)`
//! triple. If you change the HKDF salt or info encoding here, change them
//! in the other two too — and add a cross-implementation round-trip test.
//!
//! ## Implementation
//!
//! RustCrypto `ml-kem` 0.3.2 — a pure-Rust ML-KEM with no C or assembly of its
//! own, though its dependency GRAPH has both: that qualifier belongs in the
//! same sentence, because the half before it is the half that gets quoted. It
//! replaced `pqcrypto-mlkem` (PQClean's portable CLEAN C) in 2026-09: PQClean
//! upstream is archived read-only and the three `pqcrypto-*` crates carry
//! unmaintained advisories (RUSTSEC-2026-0161/-0162/-0163), whose own
//! remediation text says to migrate to `ml-kem`.
//!
//! Two things that swap did NOT do, and that nothing here should claim:
//!
//! * It did not remove extended-ISA code from the build. `ml-kem` hashes with
//!   `sha3` -> `keccak`, which ships an ARMv8.2 FEAT_SHA3 backend (`eor3`,
//!   `rax1`, `xar`, `bcax`) — the same four mnemonics PQClean's `keccak2x`
//!   assembly contributed to the Android 1.4.25 SIGILL. What changed is that
//!   `keccak` compiles that backend on every aarch64 target
//!   (`keccak-0.2.2/src/backends.rs:7`) and selects it behind a
//!   `cpufeatures` check (`lib.rs:18,82`), where PQClean's AArch64 gate was a
//!   literal `if true`.
//!
//!   That check is only a *runtime* one where `sha3` is absent from the
//!   target's default feature set — which is the Android case
//!   (`aarch64-linux-android`, `getauxval(AT_HWCAP)`), and that is the
//!   estate-wide point. It is NOT what happens on `aarch64-apple-darwin`, the
//!   only aarch64 target this client itself ships: `rustc --print cfg` for
//!   that target already emits `target_feature="sha3"`, so `cpufeatures`'
//!   `__unless_target_features!` (`cpufeatures-0.3.0/src/aarch64.rs:11-21`)
//!   compiles down to a literal `true` and no detection runs. Correct there
//!   — every Apple Silicon part has FEAT_SHA3 — but it is a compile-time
//!   gate, not a runtime one. Of the four targets this client releases
//!   (x86_64 Windows/Linux/macOS, aarch64-apple-darwin) only the last reaches
//!   that code at all.
//!
//!   Nor is `sha3` the only assembly the swap introduces. `ml-kem` itself
//!   contains no C and no assembly; its graph does. Besides `keccak`, the
//!   unconditional chain `ml-kem -> module-lattice[ctutils] -> ctutils ->
//!   cmov 0.5.4` compiles inline `asm!` on both architectures this client
//!   ships: `csel` on aarch64 (`cmov-0.5.4/src/backends/aarch64.rs:8,27`) and
//!   `cmovnz`/`cmovz` on x86 (`backends/x86.rs:16,33`). Both are baseline
//!   ISA, present on every CPU either target can run on, so this is a
//!   constant-time ASSET rather than a SIGILL risk — but it is assembly,
//!   and it is the reason "no C or assembly" above is said of the crate and
//!   must never be said of the graph.
//! * It did not change one byte of the wire format or the on-disk encoding.
//!   Verified against the production server's own KAT fixture and against a
//!   PQClean-produced stored key — see `fixtures/README.md` and the tests at
//!   the bottom of this file.
//!
//! `ml-kem`'s README carries an explicit "never been independently audited"
//! warning. So did the C it replaced; neither implementation is audited, and
//! that is a known, accepted property of this path, not a surprise.
//!
//! ## Algorithm
//!
//! ```text
//! ss = ML-KEM-1024.Decap(sk_client, ct_server)         (32 B)
//! psk = HKDF-SHA-256(IKM = ss, salt = "BirdoPQ-v1-PSK", info = nonce)[..32]
//! ```
//!
//! ## Threat model for persisted client secret key
//!
//! The ML-KEM secret key is the LONG-LIVED client identity for BirdoPQ. An
//! attacker who steals it can decrypt any future server-encapsulated PSK
//! they observe but CANNOT derive PSKs from sessions that happened before
//! the theft (the server uses fresh randomness in every encapsulation).
//!
//! Storage location: `<config_local_dir>/BirdoVPN/birdo_pq_v1.bin`.
//! Format: 4-byte magic "BPQ1" + 4-byte version (=1) + 1568 B pk + 3168 B sk.
//! Total: 4744 B. Permissions:
//!   - Unix: chmod 0600 (owner-read-write only).
//!   - Windows: file inherits the user-profile ACL which is already
//!     restricted to the user. Cannot fit in Windows Credential Manager
//!     (5 KiB cap on CRED_BLOB; sk alone is 3168 B).
//!
//! Same-uid local malware running as the user can read it. This is the same
//! threat boundary as for the user's WireGuard private key on disk and is
//! out of scope for the VPN protocol; mitigations live in OS hardening.
//!
//! The 3168-byte secret-key encoding is FIPS 203's *expanded* decapsulation
//! key. `ml-kem` reaches it only through the `#[deprecated]`
//! `ExpandedKeyEncoding` trait, because the crate would rather callers stored
//! the 64-byte seed. We cannot: every install from v1.4.43 and earlier already
//! has 3168 bytes on disk, and changing the encoding would invalidate every
//! one of them. The deprecation is therefore suppressed deliberately at each
//! call site, not worked around.

use base64::Engine as _;
use hkdf::Hkdf;
use ml_kem::array::sizes::{U1568, U3168, U64};
use ml_kem::array::Array;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    Ciphertext as MlCiphertext, Decapsulate, DecapsulationKey, KeyExport, MlKem1024, Seed,
};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use sha2::Sha256;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

use crate::api::types::ConnectResponse;

/// FIPS 203 ML-KEM-1024 sizes — must match server + Android constants.
pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const SECRET_KEY_BYTES: usize = 3168;
pub const CIPHERTEXT_BYTES: usize = 1568;
/// FIPS 203 keygen randomness `(d || z)`. Never persisted — the expanded
/// decapsulation key is what goes to disk (see the module docs).
const SEED_BYTES: usize = 64;
const PSK_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"BirdoPQ-v1-PSK";

/// Which ML-KEM implementation is linked into this binary.
///
/// The Android JNI surfaces the same kind of string as `nativeImplName` into
/// Sentry; the desktop had no equivalent, so a native fault in the KEM path
/// could not be attributed to an implementation from a log alone — which is
/// exactly how the 1.4.25 Android SIGILL took as long as it did to pin on
/// PQClean's AArch64 assembly. It is emitted on every successful bilateral
/// derivation. Change it whenever the KEM crate changes;
/// `pq_impl_name_matches_linked_crate` enforces that it names the crate that
/// is actually linked.
pub const PQ_IMPL_NAME: &str = "mlkem1024-rustcrypto";

const FILE_MAGIC: &[u8; 4] = b"BPQ1";
const FILE_VERSION: u32 = 1;
const KEYPAIR_FILENAME: &str = "birdo_pq_v1.bin";
const KEYPAIR_FILE_BYTES: usize = FILE_MAGIC.len() + 4 + PUBLIC_KEY_BYTES + SECRET_KEY_BYTES;
/// One-shot reservation for the keypair read. The buffer holds the ML-KEM
/// SECRET key, so it must never reallocate mid-read: a realloc leaves an
/// unscrubbed copy of those bytes in freed heap.
const READ_RESERVE_BYTES: usize = KEYPAIR_FILE_BYTES + 64;
/// Hard bound on that read — one byte more than a valid file, which is enough
/// for the size check to reject a too-long file and nothing more.
const READ_CAP_BYTES: usize = KEYPAIR_FILE_BYTES + 1;
/// The no-realloc property above, proved at compile time instead of asserted
/// in prose. A test can only observe the cap; this observes the headroom.
const _: () = assert!(READ_CAP_BYTES < READ_RESERVE_BYTES);
// PFA-M5: legacy DEFAULT_NONCE_BYTES constant removed — `try_decapsulate`
// now refuses to derive a PSK against a missing/empty per-connect nonce.

/// Operating mode reported to the UI.
///
/// Mirrors the Android `RosenpassManager.Mode` enum so the same telemetry
/// dashboards / strings work on both platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqMode {
    /// No PSK at all. Tunnel runs without preshared-key.
    Disabled,
    /// Server-provided classical PSK (TLS-delivered, NOT HNDL-safe).
    ServerProvided,
    /// Genuine bilateral ML-KEM-1024 — HNDL-safe.
    Bilateral,
}

pub struct StaticKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Why a persisted keypair could not be used.
///
/// The distinction is load-bearing: an I/O failure must NOT throw the user's
/// long-lived identity key away, but a file whose contents this build cannot
/// use is unrecoverable and must be replaced, or the install stops connecting
/// at all. `commands::vpn::derive_quantum_psk` fails CLOSED — when the server
/// sets `quantum_enabled` and `try_decapsulate` yields `None` it returns
/// `Err("… Connection aborted to prevent a silent downgrade.")`, and all three
/// callers (`commands::vpn`, `commands::vpn_multi_hop`, `vpn::auto_reconnect`)
/// propagate it. So the cost of keeping an unusable file is an aborted
/// connect, not a quiet demotion: worse than a downgrade, and just as
/// permanent, because nothing else ever rewrites the file.
#[derive(Debug)]
enum KeypairReadError {
    /// The file could not be read at all. Transient — keep the file.
    Io(String),
    /// The file was read but is not a usable keypair: wrong magic, wrong size,
    /// unsupported version, a decapsulation key that fails FIPS 203 §7.3, or a
    /// stored public key that disagrees with the one embedded in the secret
    /// key. Discard and re-key.
    Unusable(String),
}

impl std::fmt::Display for KeypairReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) | Self::Unusable(m) => f.write_str(m),
        }
    }
}

static CACHED_KEYPAIR: OnceCell<Mutex<Option<StaticKeypair>>> = OnceCell::new();
static CURRENT_MODE: OnceCell<Mutex<PqMode>> = OnceCell::new();

fn cache() -> &'static Mutex<Option<StaticKeypair>> {
    CACHED_KEYPAIR.get_or_init(|| Mutex::new(None))
}
fn mode_cell() -> &'static Mutex<PqMode> {
    CURRENT_MODE.get_or_init(|| Mutex::new(PqMode::Disabled))
}

/// Returns the current mode, latched by the most recent `try_decapsulate`
/// or `record_server_provided` call.
pub fn current_mode() -> PqMode {
    *mode_cell().lock()
}

fn set_mode(m: PqMode) {
    *mode_cell().lock() = m;
}

// ── Crypto primitives ─────────────────────────────────────────────────────

/// Deterministic FIPS 203 key generation from 64 bytes of `(d || z)`.
///
/// Split out from [`generate_keypair`] so the known-answer test can drive it
/// from the server fixture's `keygenSeed` — that identity (same seed in, same
/// 1568/3168 bytes out as `@noble/post-quantum`) is the strongest available
/// proof that this client and the production server speak the same ML-KEM.
#[allow(deprecated)] // ExpandedKeyEncoding — the 3168-byte stored encoding.
fn keypair_from_seed(seed_bytes: &[u8; SEED_BYTES]) -> StaticKeypair {
    let seed: Seed = Array::<u8, U64>::from(*seed_bytes);
    // `DecapsulationKey` is ZeroizeOnDrop (ml-kem's `zeroize` feature).
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);

    let ek = dk.encapsulation_key().to_bytes();
    // NOT `dk.to_bytes()`: `KeyExport for DecapsulationKey` returns the 64-byte
    // SEED, and panics outright for a key loaded from the expanded encoding.
    // Silently writing 64 bytes where 3168 belong would brick the install.
    let mut expanded = dk.to_expanded_bytes();

    assert_eq!(
        ek.len(),
        PUBLIC_KEY_BYTES,
        "ML-KEM-1024 encapsulation key must be {PUBLIC_KEY_BYTES} bytes"
    );
    assert_eq!(
        expanded.len(),
        SECRET_KEY_BYTES,
        "ML-KEM-1024 stored decapsulation key must be {SECRET_KEY_BYTES} bytes \
         (a 64-byte value here means `to_bytes()` crept in where \
         `to_expanded_bytes()` belongs)"
    );

    let kp = StaticKeypair {
        public_key: ek.to_vec(),
        secret_key: Zeroizing::new(expanded.to_vec()),
    };
    expanded.as_mut_slice().zeroize();
    kp
}

pub fn generate_keypair() -> StaticKeypair {
    use rand::RngCore;
    // Straight from the OS CSPRNG: this is a long-lived identity key, so it
    // does not go through a userspace PRNG that could be forked or reseeded.
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut_slice());
    keypair_from_seed(&seed)
}

/// Parse a stored 3168-byte expanded decapsulation key.
///
/// Unlike `pqcrypto-mlkem`'s `SecretKey::from_bytes`, which only checked the
/// length, `ml-kem` also enforces FIPS 203 §7.3: the key's embedded `H(ek)`
/// must match the hash of its embedded encapsulation key. A key that fails is
/// not recoverable — callers must discard it and re-key (see
/// [`load_or_generate_at`]), never retry it.
#[allow(deprecated)]
fn load_decapsulation_key(sk: &[u8]) -> Result<DecapsulationKey<MlKem1024>, String> {
    // `Array` has no Drop of its own, so this stack copy of the decapsulation
    // key is scrubbed by hand. It is taken on every load AND every
    // `derive_psk`, i.e. on every connect — everything around it is
    // `Zeroizing`, and this one was not.
    let mut arr = Array::<u8, U3168>::try_from(sk).map_err(|_| {
        format!(
            "malformed client secret key: expected {SECRET_KEY_BYTES} bytes, got {}",
            sk.len()
        )
    })?;
    let dk = <DecapsulationKey<MlKem1024> as ExpandedKeyEncoding>::from_expanded_bytes(&arr)
        .map_err(|_| "client secret key failed FIPS 203 validation (H(ek) mismatch)".to_string());
    arr.as_mut_slice().zeroize();
    dk
}

/// Decapsulate the server-supplied ciphertext into a 32-byte PSK.
///
/// ML-KEM is implicit-rejection: a malformed ciphertext doesn't error here,
/// it returns a deterministic random shared secret. The resulting PSK then
/// won't match the server's, and the WireGuard handshake fails later. This
/// is the desired behaviour — it prevents oracle attacks based on whether
/// decapsulation "succeeded".
pub fn derive_psk(
    client_secret_key: &Zeroizing<Vec<u8>>,
    server_ciphertext: &[u8],
    server_nonce: &[u8],
) -> Result<Zeroizing<[u8; PSK_LEN]>, String> {
    let dk = load_decapsulation_key(client_secret_key.as_slice())?;
    let ct: MlCiphertext<MlKem1024> =
        Array::<u8, U1568>::try_from(server_ciphertext).map_err(|_| {
            format!(
                "malformed server ciphertext: expected {CIPHERTEXT_BYTES} bytes, got {}",
                server_ciphertext.len()
            )
        })?;
    // Infallible by design (implicit rejection), exactly as the pqcrypto
    // binding was — do NOT "improve" this into a Result: turning a rejection
    // into an observable error would build the decapsulation oracle the
    // FIPS 203 construction exists to deny.
    let mut ss = dk.decapsulate(&ct);
    let psk = hkdf_to_psk(ss.as_slice(), server_nonce);
    // `SharedKey` is a plain array with no Drop impl of its own.
    ss.as_mut_slice().zeroize();
    psk
}

fn hkdf_to_psk(shared_secret: &[u8], nonce: &[u8]) -> Result<Zeroizing<[u8; PSK_LEN]>, String> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut psk = Zeroizing::new([0u8; PSK_LEN]);
    // PFA-D1: HKDF expansion size of 32 bytes is always within the
    // L = 8160-byte maximum for SHA-256, so this branch should never
    // trigger; we still propagate Err rather than panicking so a future
    // refactor that bumps PSK_LEN cannot turn this into a DoS panic.
    hk.expand(nonce, psk.as_mut_slice())
        .map_err(|e| format!("HKDF expand failed: {e}"))?;
    Ok(psk)
}

// ── Persistence ───────────────────────────────────────────────────────────

fn keypair_path() -> Result<PathBuf, String> {
    let base = dirs::config_local_dir()
        .ok_or_else(|| "no config_local_dir on this platform".to_string())?;
    let dir = base.join("BirdoVPN");
    fs::create_dir_all(&dir).map_err(|e| format!("create dir {dir:?}: {e}"))?;
    Ok(dir.join(KEYPAIR_FILENAME))
}

fn write_keypair(path: &PathBuf, kp: &StaticKeypair) -> Result<(), String> {
    // The length check IS the guard against `ml_kem::KeyExport::to_bytes()`,
    // which hands back a 64-byte seed rather than the 3168-byte expanded key.
    if kp.public_key.len() != PUBLIC_KEY_BYTES || kp.secret_key.len() != SECRET_KEY_BYTES {
        return Err(format!(
            "invalid keypair sizes: pk {} (want {PUBLIC_KEY_BYTES}), sk {} (want {SECRET_KEY_BYTES})",
            kp.public_key.len(),
            kp.secret_key.len()
        ));
    }
    // Zeroizing so the secret-key copy is scrubbed on EVERY exit path — the
    // old manual `buf.fill(0)` at the end was skipped whenever the write,
    // fsync, or rename errored out early.
    let mut buf = Zeroizing::new(Vec::with_capacity(KEYPAIR_FILE_BYTES));
    buf.extend_from_slice(FILE_MAGIC);
    buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
    buf.extend_from_slice(&kp.public_key);
    buf.extend_from_slice(kp.secret_key.as_slice());

    // Write atomically via tmp + rename so a crash mid-write can't leave a
    // half-truncated file that bricks the client.
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = open_owner_only(&tmp)?;
        f.write_all(&buf)
            .map_err(|e| format!("write {tmp:?}: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync {tmp:?}: {e}"))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename {tmp:?} -> {path:?}: {e}"))?;
    buf.fill(0);
    Ok(())
}

#[cfg(unix)]
fn open_owner_only(path: &PathBuf) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {path:?}: {e}"))
}

#[cfg(not(unix))]
fn open_owner_only(path: &PathBuf) -> Result<fs::File, String> {
    // Windows: relies on the user-profile ACL inherited via config_local_dir.
    // Same posture as the existing settings file; full DACL hardening lives
    // in a separate audit follow-up if/when needed.
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("open {path:?}: {e}"))
}

fn read_keypair(path: &PathBuf) -> Result<Option<StaticKeypair>, KeypairReadError> {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(KeypairReadError::Io(format!("open {path:?}: {e}"))),
    };
    // Zeroizing + pre-sized: the buffer holds the ML-KEM SECRET key, so (a) it
    // must be scrubbed on EVERY exit path, not only the manual `buf.fill(0)`
    // ones, and (b) it must never reallocate mid-read — a realloc leaves an
    // unscrubbed copy of the key bytes in freed heap.
    //
    // (b) takes the `take()` as well as the reservation: a bare
    // `read_to_end` grows the buffer to whatever is on disk, so a corrupt or
    // appended file bigger than the reservation would realloc and leave
    // exactly the copy this comment warns about. `READ_CAP_BYTES <
    // READ_RESERVE_BYTES` is a `const` assert, so "the read can never exhaust
    // the reservation" is checked by the compiler rather than trusted here.
    let mut buf = Zeroizing::new(Vec::with_capacity(READ_RESERVE_BYTES));
    (&mut f)
        .take(READ_CAP_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|e| KeypairReadError::Io(format!("read {path:?}: {e}")))?;
    if buf.len() != KEYPAIR_FILE_BYTES {
        let n = buf.len();
        buf.fill(0);
        return Err(KeypairReadError::Unusable(format!(
            "unexpected keypair file size {n} (expected {KEYPAIR_FILE_BYTES})"
        )));
    }
    if &buf[..FILE_MAGIC.len()] != FILE_MAGIC {
        buf.fill(0);
        return Err(KeypairReadError::Unusable("bad keypair magic".to_string()));
    }
    let mut ver = [0u8; 4];
    ver.copy_from_slice(&buf[FILE_MAGIC.len()..FILE_MAGIC.len() + 4]);
    let v = u32::from_le_bytes(ver);
    if v != FILE_VERSION {
        buf.fill(0);
        return Err(KeypairReadError::Unusable(format!(
            "unsupported keypair file version {v}"
        )));
    }
    let pk_off = FILE_MAGIC.len() + 4;
    let sk_off = pk_off + PUBLIC_KEY_BYTES;
    let pk = buf[pk_off..sk_off].to_vec();
    let sk = Zeroizing::new(buf[sk_off..].to_vec());
    buf.fill(0);

    // Validate against the KEM implementation that is actually linked, here,
    // once, rather than at every connect. Two things can be wrong in a file
    // that is structurally perfect:
    //
    //  1. FIPS 203 §7.3 — `ml-kem` verifies the key's embedded `H(ek)`, which
    //     `pqcrypto-mlkem` never did. A key that fails cannot decapsulate
    //     correctly, and because ML-KEM rejects implicitly the only symptom
    //     would be a WireGuard handshake that silently never completes.
    //  2. The stored public key disagreeing with the one inside the secret
    //     key. We would then hand the server a public key we cannot
    //     decapsulate for — same silent failure.
    let dk = load_decapsulation_key(sk.as_slice()).map_err(KeypairReadError::Unusable)?;
    if dk.encapsulation_key().to_bytes().as_slice() != pk.as_slice() {
        return Err(KeypairReadError::Unusable(
            "stored public key does not match the one embedded in the secret key".to_string(),
        ));
    }

    Ok(Some(StaticKeypair {
        public_key: pk,
        secret_key: sk,
    }))
}

/// Read the persisted keypair from `path`, or generate + persist a fresh one.
///
/// A file this build cannot use is REPLACED, not reported. Reporting it would
/// abort every connect the server enables BirdoPQ on, permanently: nothing
/// else rewrites the file, and `commands::vpn::derive_quantum_psk` fails
/// closed on a decapsulation that never happens. Re-keying is free on the
/// server side — birdo-web `backend/src/vpn/birdo-pq.service.ts`
/// `encapsulate()` reads `clientPublicKeyB64` off the request and persists no
/// per-device PQ key — so the fresh key is simply used from the next connect.
/// A file that merely failed to read (I/O) is left alone: discarding a
/// long-lived identity key on a transient error is the worse trade.
fn load_or_generate_at(path: &PathBuf) -> Result<StaticKeypair, String> {
    match read_keypair(path) {
        Ok(Some(kp)) => return Ok(kp),
        Ok(None) => {
            tracing::info!("BirdoPQ: no persisted ML-KEM keypair — generating fresh (~10–50 ms)");
        }
        Err(KeypairReadError::Io(e)) => {
            return Err(format!("persisted ML-KEM keypair unreadable: {e}"));
        }
        Err(KeypairReadError::Unusable(e)) => {
            tracing::warn!(
                "BirdoPQ: persisted ML-KEM keypair is unusable ({e}) — discarding and re-keying. \
                 The server learns the new public key on the next connect."
            );
        }
    }
    let fresh = generate_keypair();
    if let Err(e) = write_keypair(path, &fresh) {
        tracing::warn!(
            "BirdoPQ: failed to persist keypair to {path:?}: {e} — \
             continuing in-memory; will regenerate next launch"
        );
    }
    Ok(fresh)
}

/// Returns a reference to the cached keypair, generating + persisting one
/// on first call. Errors are logged + returned and reach the caller as
/// "PQ unavailable" — which means the server's classical PSK only while the
/// server left `quantum_enabled` off. With it on, `derive_quantum_psk` turns
/// the same condition into an aborted connect (fail-closed, by design).
fn load_or_generate() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    let cell = cache();
    {
        let g = cell.lock();
        if let Some(kp) = g.as_ref() {
            return Ok((
                kp.public_key.clone(),
                Zeroizing::new(kp.secret_key.to_vec()),
            ));
        }
    }
    let path = keypair_path()?;
    let kp = load_or_generate_at(&path)?;
    let pk = kp.public_key.clone();
    let sk = Zeroizing::new(kp.secret_key.to_vec());
    *cell.lock() = Some(kp);
    Ok((pk, sk))
}

/// Permanently delete the persisted keypair. Use on user logout.
#[allow(dead_code)]
pub fn reset_persisted_keypair() -> Result<(), String> {
    *cache().lock() = None;
    set_mode(PqMode::Disabled);
    let path = keypair_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete {path:?}: {e}")),
    }
}

// ── Public API used by the connect command ────────────────────────────────

/// Returns the Base64 ML-KEM-1024 client public key, generating + persisting
/// the keypair on first call. Returns `None` only if persistence + in-memory
/// generation both fail (extremely unlikely outside CI).
pub fn get_client_public_key_b64() -> Option<String> {
    match load_or_generate() {
        Ok((pk, _)) => Some(base64::engine::general_purpose::STANDARD.encode(&pk)),
        Err(e) => {
            tracing::error!("BirdoPQ: cannot get client public key: {e}");
            None
        }
    }
}

/// Try to derive a bilateral PQ PSK from the server response. Returns
/// `None` when the server did not include a ciphertext (legacy path) or
/// when our local keypair is missing.
///
/// What the caller does with `None` depends entirely on `quantum_enabled`:
/// with it OFF this is the legacy path and `derive_quantum_psk` takes the
/// server-provided PSK (`record_server_provided`); with it ON the same `None`
/// aborts the connection. `None` is therefore never a silent downgrade.
///
/// On success, latches `current_mode() == Bilateral` so the UI can display
/// the genuine HNDL-safe state.
pub fn try_decapsulate(response: &ConnectResponse) -> Option<String> {
    if !response.quantum_enabled.unwrap_or(false) {
        return None;
    }
    // Field name re-use, matching the wire-format contract with Android +
    // backend: `rosenpassPublicKey` carries the ML-KEM ciphertext,
    // `rosenpassEndpoint` carries the per-connect nonce.
    let ct_b64 = response.rosenpass_public_key.as_ref()?;
    let ct = match base64::engine::general_purpose::STANDARD.decode(ct_b64) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("BirdoPQ: malformed PQ ciphertext: {e}");
            return None;
        }
    };
    if ct.len() != CIPHERTEXT_BYTES {
        tracing::error!(
            "BirdoPQ: ciphertext wrong size: {} != {}",
            ct.len(),
            CIPHERTEXT_BYTES
        );
        return None;
    }

    // PFA-M5: refuse to derive a PSK against a missing nonce. ML-KEM gives
    // a fresh shared secret per encapsulation so the previous fallback to a
    // hard-coded constant did NOT cause cryptographic nonce reuse, but it
    // removed per-connect domain separation and let a misconfigured server
    // silently weaken the protocol. Fail closed: we only reach this line with
    // `quantum_enabled` set, so the `None` below makes `derive_quantum_psk`
    // abort the connect — it is not a demotion to the server-provided PSK.
    let nonce: Vec<u8> = match response.rosenpass_endpoint.as_deref() {
        None | Some("") => {
            tracing::error!(
                "BirdoPQ: server omitted per-connect nonce — bilateral PQ aborted (PFA-M5)"
            );
            return None;
        }
        Some(n) => match base64::engine::general_purpose::STANDARD.decode(n) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("BirdoPQ: malformed PQ nonce: {e}");
                return None;
            }
        },
    };

    let (_pk, sk) = match load_or_generate() {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("BirdoPQ: no client keypair available: {e}");
            return None;
        }
    };

    let psk = match derive_psk(&sk, &ct, &nonce) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("BirdoPQ: derive_psk failed: {e}");
            return None;
        }
    };
    set_mode(PqMode::Bilateral);
    tracing::info!(
        "BirdoPQ v1 BILATERAL — quantum-resistant PSK derived (32 B, mode=bilateral, impl={PQ_IMPL_NAME})"
    );
    Some(base64::engine::general_purpose::STANDARD.encode(psk.as_slice()))
}

/// Latch mode for telemetry when we end up using the server's classical PSK
/// (still useful, but not HNDL-safe).
pub fn record_server_provided() {
    set_mode(PqMode::ServerProvided);
}

/// Latch DISABLED mode (no PSK at all).
pub fn record_disabled() {
    set_mode(PqMode::Disabled);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::array::sizes::U32;
    use ml_kem::{EncapsulationKey, Key, TryKeyInit, B32};

    // No suite-wide file lock: every file-touching test below owns a
    // `tempfile::tempdir()`, so none of them can reach the shared
    // `config_local_dir` keypair the lock was introduced to serialise. A lock
    // whose stated reason no longer holds is worse than no lock — the next
    // reader assumes some shared file still needs protecting.

    /// The production server's own known-answer fixture, byte-identical to
    /// birdo-web `backend/src/vpn/__fixtures__/birdo-pq-ml-kem-1024.kat.json`.
    const KAT_JSON: &str = include_str!("fixtures/birdo-pq-ml-kem-1024.kat.json");
    /// A keypair + ciphertext produced by PQClean CLEAN C (`pqcrypto-mlkem`),
    /// i.e. exactly what every install up to v1.4.43 has on disk.
    const PQCLEAN_JSON: &str = include_str!("fixtures/birdo-pq-pqclean-stored-key.json");

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .expect("fixture field is valid base64")
    }

    fn field(json: &str, key: &str) -> Vec<u8> {
        let v: serde_json::Value = serde_json::from_str(json).expect("fixture parses");
        b64(v[key]
            .as_str()
            .unwrap_or_else(|| panic!("fixture key {key}")))
    }

    /// Server-side encapsulation, deterministic so the test vectors are fixed.
    /// This is the only place the client ever encapsulates; in production the
    /// server does it with `@noble/post-quantum`.
    fn encapsulate_with(pk: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let k: Key<EncapsulationKey<MlKem1024>> =
            Array::<u8, U1568>::try_from(pk).expect("1568-byte encapsulation key");
        let ek = <EncapsulationKey<MlKem1024> as TryKeyInit>::new(&k)
            .expect("encapsulation key passes FIPS 203 §7.2 validation");
        let mb: B32 = Array::<u8, U32>::try_from(m).expect("32-byte encapsulation randomness");
        let (ct, ss) = ek.encapsulate_deterministic(&mb);
        (ct.to_vec(), ss.to_vec())
    }

    fn pqclean_secret_key() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(field(PQCLEAN_JSON, "secretKeyB64"))
    }

    fn pqclean_nonce() -> Vec<u8> {
        let v: serde_json::Value = serde_json::from_str(PQCLEAN_JSON).expect("fixture parses");
        v["nonceAscii"]
            .as_str()
            .expect("nonceAscii")
            .as_bytes()
            .to_vec()
    }

    // ── Cross-implementation vectors ──────────────────────────────────────

    /// The ONE test that can detect byte-incompatibility with the production
    /// server. Everything else in this module is a self-consistent round trip:
    /// a KEM that is internally correct but speaks a different ML-KEM encoding
    /// passes all of them, and FIPS 203 implicit rejection means the only
    /// field symptom is a WireGuard handshake that silently never completes.
    ///
    /// Fixture generated with `@noble/post-quantum` — the library the backend
    /// actually encapsulates with (`backend/src/vpn/birdo-pq.service.ts`).
    #[test]
    fn kat_vs_noble() {
        let seed: [u8; SEED_BYTES] = field(KAT_JSON, "keygenSeedB64")
            .try_into()
            .expect("64-byte keygen seed");
        let want_pk = field(KAT_JSON, "publicKeyB64");
        let want_sk = field(KAT_JSON, "secretKeyB64");
        let want_ct = field(KAT_JSON, "cipherTextB64");
        let want_ss = field(KAT_JSON, "sharedSecretB64");
        let want_psk = field(KAT_JSON, "presharedKeyB64");
        let encaps_m = field(KAT_JSON, "encapsRandomnessB64");
        let nonce = field(KAT_JSON, "nonceB64");

        // keygen leg: FIPS 203 keygen is deterministic in (d || z), so the same
        // 64-byte seed must produce the server's exact 1568/3168 bytes.
        let kp = keypair_from_seed(&seed);
        assert_eq!(kp.public_key, want_pk, "encapsulation key (ek) mismatch");
        assert_eq!(
            kp.secret_key.as_slice(),
            want_sk.as_slice(),
            "expanded decapsulation key (dk) mismatch"
        );

        // encapsulate leg
        let (ct, ss) = encapsulate_with(&want_pk, &encaps_m);
        assert_eq!(ct, want_ct, "ciphertext mismatch");
        assert_eq!(ss, want_ss, "shared secret from encapsulate mismatch");

        // decapsulate + HKDF legs, through the real production entry point.
        let psk = derive_psk(&Zeroizing::new(want_sk), &want_ct, &nonce)
            .expect("decapsulating the server's own ciphertext must succeed");
        assert_eq!(
            psk.as_slice(),
            want_psk.as_slice(),
            "PSK mismatch — the HKDF construction or the shared secret drifted \
             from the server's"
        );
    }

    /// The install-base guard: a decapsulation key generated by the PQClean C
    /// implementation the client shipped up to v1.4.43 must keep working
    /// forever. A swap that breaks stored-key reading would brick every
    /// existing install, silently.
    #[test]
    fn stored_pqclean_dk_loads_and_derives_same_psk() {
        let sk = pqclean_secret_key();
        let pk = field(PQCLEAN_JSON, "publicKeyB64");
        let ct = field(PQCLEAN_JSON, "cipherTextB64");
        let want_psk = field(PQCLEAN_JSON, "presharedKeyB64");
        let nonce = pqclean_nonce();

        // It loads, and the embedded encapsulation key round-trips unchanged.
        let dk =
            load_decapsulation_key(sk.as_slice()).expect("a PQClean-generated dk must still load");
        assert_eq!(dk.encapsulation_key().to_bytes().as_slice(), pk.as_slice());

        // And it derives the PSK PQClean itself derived from that ciphertext.
        let psk = derive_psk(&sk, &ct, &nonce).expect("decapsulate PQClean ciphertext");
        assert_eq!(psk.as_slice(), want_psk.as_slice());
    }

    /// `KeyExport::to_bytes()` returns a 64-byte *seed* for a seed-generated
    /// key and PANICS for one loaded from the expanded encoding. Nothing in
    /// the type system stops it being used where `to_expanded_bytes()` belongs,
    /// so the byte count is asserted explicitly, in memory and on disk.
    #[test]
    fn stored_key_length_is_3168() {
        let kp = generate_keypair();
        assert_eq!(kp.secret_key.len(), SECRET_KEY_BYTES);
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_BYTES);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);
        write_keypair(&path, &kp).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len() as usize,
            KEYPAIR_FILE_BYTES,
            "on-disk keypair must stay 4744 B: magic + version + 1568 + 3168"
        );

        // A 64-byte "secret key" must be refused rather than persisted.
        let short = StaticKeypair {
            public_key: kp.public_key.clone(),
            secret_key: Zeroizing::new(vec![0u8; 64]),
        };
        assert!(write_keypair(&path, &short).is_err());
    }

    /// ml-kem enforces FIPS 203 §7.3 where `pqcrypto-mlkem`'s `from_bytes` was
    /// a length check only, so a new hard-error path exists on an install base
    /// that never had one. It must lead to a re-key: surfacing the error
    /// instead would abort every BirdoPQ-enabled connect for the life of the
    /// install, because `derive_quantum_psk` fails closed — see
    /// `undecapsulatable_pq_aborts_even_when_a_server_psk_is_offered` in
    /// `commands::vpn`.
    #[test]
    fn corrupt_dk_returns_invalid_key_and_rekeys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);

        // Structurally perfect — right magic, version and sizes — but one bit
        // flipped inside the embedded H(ek) field at dk[3104..3136].
        let mut sk = pqclean_secret_key().to_vec();
        sk[3110] ^= 0x01;
        let corrupt = StaticKeypair {
            public_key: field(PQCLEAN_JSON, "publicKeyB64"),
            secret_key: Zeroizing::new(sk.clone()),
        };
        write_keypair(&path, &corrupt).unwrap();

        assert!(
            load_decapsulation_key(&sk).is_err(),
            "a dk whose H(ek) does not match must be rejected"
        );
        match read_keypair(&path) {
            Err(KeypairReadError::Unusable(_)) => {}
            Err(e) => panic!("expected Unusable, got {e:?}"),
            Ok(_) => panic!("corrupt H(ek) must not be accepted"),
        }

        // The recovery: a fresh, valid, persisted keypair.
        let fresh = load_or_generate_at(&path).expect("must re-key rather than fail");
        assert_eq!(fresh.secret_key.len(), SECRET_KEY_BYTES);
        assert_ne!(fresh.secret_key.as_slice(), sk.as_slice());
        let reread = read_keypair(&path)
            .expect("the re-keyed file must be readable")
            .expect("the re-keyed file must exist");
        assert_eq!(reread.secret_key.as_slice(), fresh.secret_key.as_slice());
    }

    /// The stored public key is handed to the server as-is — it is never
    /// re-derived at connect time — so a file whose pk half disagrees with
    /// the key embedded in the dk makes the server encapsulate to a key this
    /// client cannot decapsulate for. ML-KEM rejects implicitly, so the only
    /// symptom is a WireGuard handshake that silently never completes: exactly
    /// the failure mode this module exists to make impossible.
    ///
    /// Review of #163: of sixteen mutations run against this module, replacing
    /// the `dk.encapsulation_key() != pk` condition in `read_keypair` with
    /// `if false {` was the ONLY one that left every test green. It cannot be
    /// caught by any dk-only assertion — the secret key here is perfectly
    /// valid and passes FIPS 203 §7.3 on its own.
    #[test]
    fn read_keypair_rejects_public_key_that_disagrees_with_secret_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);

        let kp = generate_keypair();
        let mut wrong_pk = kp.public_key.clone();
        wrong_pk[0] ^= 0x01; // one byte off; magic, version and both sizes stay perfect
        write_keypair(
            &path,
            &StaticKeypair {
                public_key: wrong_pk.clone(),
                secret_key: Zeroizing::new(kp.secret_key.to_vec()),
            },
        )
        .unwrap();

        // The dk half is untouched and still validates, so nothing about the
        // secret key can reveal this — only comparing the two halves can.
        load_decapsulation_key(kp.secret_key.as_slice())
            .expect("the secret-key half is valid; only the stored pk is wrong");

        match read_keypair(&path) {
            Err(KeypairReadError::Unusable(m)) => assert!(
                m.contains("stored public key"),
                "wrong Unusable reason: {m}"
            ),
            Err(e) => panic!("expected Unusable, got {e:?}"),
            Ok(_) => panic!("a pk that disagrees with the dk must not be accepted"),
        }

        // Unusable means re-key, not fail-forever: the replacement file must
        // be readable and its halves must agree.
        let fresh = load_or_generate_at(&path).expect("must re-key rather than fail");
        assert_ne!(fresh.public_key, wrong_pk);
        let reread = read_keypair(&path)
            .expect("the re-keyed file must be readable")
            .expect("the re-keyed file must exist");
        assert_eq!(reread.public_key, fresh.public_key);
        assert_eq!(reread.secret_key.as_slice(), fresh.secret_key.as_slice());
    }

    /// A file LONGER than a valid keypair must be rejected without the read
    /// buffer ever growing past its reservation — a realloc mid-read leaves
    /// an unscrubbed copy of the secret key in freed heap, which is precisely
    /// what the pre-sized buffer exists to prevent. `read_to_end` alone would
    /// have grown to the file's real size.
    #[test]
    fn read_keypair_rejects_oversized_file_without_reading_it_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);

        let kp = generate_keypair();
        write_keypair(&path, &kp).unwrap();
        // Append a megabyte of junk to an otherwise valid file.
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&vec![0xAAu8; 1 << 20]).unwrap();
        drop(f);

        match read_keypair(&path) {
            // The reported size is the CAP (4745), not the file's real size:
            // proof the read stopped inside the reservation.
            Err(KeypairReadError::Unusable(m)) => assert!(
                m.contains(&format!("size {}", KEYPAIR_FILE_BYTES + 1)),
                "expected the bounded-read size in the message, got: {m}"
            ),
            Err(e) => panic!("expected Unusable, got {e:?}"),
            Ok(_) => panic!("an oversized keypair file must not be accepted"),
        }

        // The size above proves the CAP. The property `read_keypair`'s comment
        // actually sells is that the capped read never reallocates the
        // Zeroizing buffer (a realloc would leave an unscrubbed copy of the
        // secret key in freed heap). Replay the same reservation and the same
        // bound against the same oversized file and watch the allocation stay
        // put; the `const` assert `READ_CAP_BYTES < READ_RESERVE_BYTES` is the
        // other half of the proof.
        let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(READ_RESERVE_BYTES));
        let (ptr_before, cap_before) = (buf.as_ptr(), buf.capacity());
        let mut f2 = fs::File::open(&path).unwrap();
        (&mut f2)
            .take(READ_CAP_BYTES as u64)
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(buf.len(), READ_CAP_BYTES, "the bound must stop the read");
        assert_eq!(buf.capacity(), cap_before, "the bounded read reallocated");
        assert!(
            std::ptr::eq(buf.as_ptr(), ptr_before),
            "the bounded read moved the secret-key buffer"
        );
    }

    /// Nobody may later "fix" implicit rejection into a `Result`: a wrong key
    /// must yield a stable, different shared secret with no error and no panic.
    /// Making the failure observable would hand an attacker a decapsulation
    /// oracle.
    #[test]
    fn implicit_rejection_is_deterministic_and_silent() {
        let ours = keypair_from_seed(&[0x11; SEED_BYTES]);
        let theirs = keypair_from_seed(&[0x22; SEED_BYTES]);
        let (ct, _ss) = encapsulate_with(&ours.public_key, &[0x33; 32]);

        let good = derive_psk(&ours.secret_key, &ct, b"nonce").unwrap();
        let bad1 = derive_psk(&theirs.secret_key, &ct, b"nonce")
            .expect("a wrong key must NOT error — that is the oracle");
        let bad2 = derive_psk(&theirs.secret_key, &ct, b"nonce").unwrap();

        assert_ne!(good.as_slice(), bad1.as_slice());
        assert_eq!(bad1.as_slice(), bad2.as_slice(), "must be deterministic");
    }

    /// `PQ_IMPL_NAME` is the only signal that could attribute a native fault in
    /// this path to an implementation, so it must not drift from the crate that
    /// is linked. The discriminator is behavioural, not a string compare: only
    /// RustCrypto `ml-kem` rejects a decapsulation key whose embedded `H(ek)`
    /// is wrong (FIPS 203 §7.3). `pqcrypto-mlkem`'s `from_bytes` accepts it.
    #[test]
    fn pq_impl_name_matches_linked_crate() {
        let mut sk = pqclean_secret_key().to_vec();
        sk[3110] ^= 0x01;
        assert!(
            load_decapsulation_key(&sk).is_err(),
            "the linked KEM does not enforce FIPS 203 §7.3 — it is not RustCrypto \
             ml-kem, so PQ_IMPL_NAME is lying"
        );
        assert_eq!(PQ_IMPL_NAME, "mlkem1024-rustcrypto");
        assert_ne!(
            PQ_IMPL_NAME, "mlkem1024-clean",
            "PQClean is no longer what is linked"
        );
    }

    // ── Round trips and I/O ───────────────────────────────────────────────

    #[test]
    fn generate_keypair_correct_sizes() {
        let kp = generate_keypair();
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(kp.secret_key.len(), SECRET_KEY_BYTES);
    }

    #[test]
    fn server_encap_then_client_decap_match() {
        // Round-trip: simulate the server encapsulating against our pk, then
        // decap with our sk + the same nonce. PSKs MUST match.
        let kp = generate_keypair();
        let (ct, ss_server) = encapsulate_with(&kp.public_key, &[0x5A; 32]);
        let nonce = b"connect-2026-05-10T12:00:00Z";
        let server_psk = hkdf_to_psk(&ss_server, nonce).unwrap();

        let client_psk = derive_psk(&kp.secret_key, &ct, nonce).unwrap();

        assert_eq!(
            client_psk.as_slice(),
            server_psk.as_slice(),
            "client and server MUST derive identical PSK from (sk, ct, nonce)"
        );
    }

    #[test]
    fn different_nonces_produce_different_psks() {
        let kp = generate_keypair();
        let (ct, _ss) = encapsulate_with(&kp.public_key, &[0x5A; 32]);
        let a = derive_psk(&kp.secret_key, &ct, b"nonce-A").unwrap();
        let b = derive_psk(&kp.secret_key, &ct, b"nonce-B").unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn malformed_inputs_error_cleanly() {
        let r1 = derive_psk(
            &Zeroizing::new(vec![0u8; 16]),
            &[0u8; CIPHERTEXT_BYTES],
            b"n",
        );
        assert!(r1.is_err());
        let kp = generate_keypair();
        let r2 = derive_psk(&kp.secret_key, &[0u8; 16], b"n");
        assert!(r2.is_err());
    }

    #[test]
    fn keypair_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);
        let kp = generate_keypair();
        let pk_clone = kp.public_key.clone();
        let sk_clone = kp.secret_key.to_vec();
        write_keypair(&path, &kp).unwrap();
        let loaded = read_keypair(&path).unwrap().unwrap();
        assert_eq!(loaded.public_key, pk_clone);
        assert_eq!(loaded.secret_key.as_slice(), sk_clone.as_slice());
    }

    #[test]
    fn read_keypair_rejects_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&[0u8; KEYPAIR_FILE_BYTES]).unwrap();
        let r = read_keypair(&path);
        assert!(r.is_err());
    }

    #[test]
    fn read_keypair_rejects_short_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"BPQ1\x01\x00\x00\x00").unwrap();
        let r = read_keypair(&path);
        assert!(r.is_err());
    }

    #[test]
    fn try_decapsulate_returns_none_when_pq_disabled() {
        // Build a synthetic ConnectResponse with quantum_enabled=false
        let resp = ConnectResponse {
            success: true,
            message: None,
            error_code: None,
            config: None,
            key_id: None,
            private_key: None,
            public_key: None,
            preshared_key: None,
            assigned_ip: None,
            client_ipv6: None,
            server_public_key: None,
            endpoint: None,
            dns: None,
            allowed_ips: None,
            mtu: None,
            persistent_keepalive: None,
            server_node: None,
            stealth_enabled: None,
            xray_endpoint: None,
            xray_uuid: None,
            xray_public_key: None,
            xray_short_id: None,
            xray_sni: None,
            xray_flow: None,
            quantum_enabled: Some(false),
            rosenpass_public_key: Some("anything".into()),
            rosenpass_endpoint: None,
        };
        assert!(try_decapsulate(&resp).is_none());
    }

    #[test]
    fn mode_default_is_disabled() {
        // Don't depend on test ordering: just confirm the latches exist
        // and the setter changes them.
        set_mode(PqMode::Disabled);
        assert_eq!(current_mode(), PqMode::Disabled);
        set_mode(PqMode::Bilateral);
        assert_eq!(current_mode(), PqMode::Bilateral);
        set_mode(PqMode::ServerProvided);
        assert_eq!(current_mode(), PqMode::ServerProvided);
    }
}
