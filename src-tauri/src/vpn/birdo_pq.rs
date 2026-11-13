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
//! ## Threat model: what BirdoPQ v1 protects, and what it does not
//!
//! The full analysis is birdo-web `docs/PQ-THREAT-MODEL.md` (§4 leg by leg,
//! §6.2 the claims); this is the desktop's share of it (MR-743, MR-1364).
//!
//! **What it gives.** This client uploads only its ML-KEM public key and,
//! since v1.4.42, asks the server to withhold the derived PSK from the
//! connect response (`pq_client_can_decapsulate`), so the app-to-API leg
//! carries a KEM ciphertext and a nonce, never the PSK. Every connect derives
//! its PSK from a fresh server encapsulation, so one session's KEM output says
//! nothing about another's. A recording of this app's API traffic and its
//! WireGuard tunnel, made by someone who never obtains the secret key, stays
//! confidential against a future quantum computer that breaks X25519 alone:
//! the tunnel keys mix in the PSK, and recovering the PSK from that recording
//! means breaking ML-KEM-1024. (The WireGuard handshake's metadata is not
//! covered: the PSK is mixed in only after the first message.)
//!
//! **What it does not give:**
//!
//! * **Protection against a thief who is already inside the process.** The
//!   ML-KEM secret exists for one connect only (MR-703 / MR-1742): a
//!   64-byte seed in a [`PqSession`], in memory, wiped when the connect is done.
//!   It is not on disk, so stealing the device's files or its backups yields
//!   nothing for any past or later session, and the client's public key is no
//!   longer a stable per-install identifier the server sees on every connect.
//!   What is NOT covered is someone who can read this process's memory DURING
//!   the connect window (between the keypair and the decapsulation): they
//!   recover that one session's PSK. An older build (which kept one long-lived
//!   key per install) is not forward-secret in either direction; that is why
//!   this build deletes its file (see [`purge_legacy_keypair_files`]).
//! * **The relay leg.** The server derives the same PSK and sends it on to
//!   the VPN relay over TLS that is not yet post-quantum, so a recording of
//!   that link plus a future quantum computer recovers the PSK without
//!   touching ML-KEM (MR-1444). One recorder at a relay's hosting provider
//!   sees both that link and the tunnel, so against "record now, decrypt
//!   later" the PQ layer is today only as strong as that classical link.
//! * **Multi-hop's entry-to-exit leg.** The relay-to-relay mesh carries no PQ
//!   PSK at all: between the entry and the exit relay, traffic is protected
//!   by classical X25519 only. The PSK derived here covers this client's leg
//!   to the entry relay and nothing beyond it.
//!
//! ## Where the secret key lives
//!
//! Nowhere on disk. [`PqSession::begin`] draws a fresh seed for each
//! `/vpn/connect` request, [`PqSession::finish`] decapsulates and consumes it,
//! and `Drop` wipes it. The 3168-byte expanded decapsulation key that earlier
//! builds stored (`birdo_pq_v1.bin`, 4744 B: "BPQ1" + version + pk + sk) is
//! gone, and with it the reason to use ml-kem's `#[deprecated]`
//! `ExpandedKeyEncoding`: the secret is the FIPS 203 seed, expanded on use.
//! The wire format is unchanged (pk 1568 B, ct 1568 B, same HKDF inputs).

use base64::Engine as _;
use hkdf::Hkdf;
use ml_kem::array::sizes::{U1568, U64};
use ml_kem::array::Array;
use ml_kem::{
    Ciphertext as MlCiphertext, Decapsulate, DecapsulationKey, KeyExport, MlKem1024, Seed,
};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::api::types::ConnectResponse;
use crate::utils::safe_fs::OwnedDir;

/// FIPS 203 ML-KEM-1024 sizes: must match server + Android constants.
pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const CIPHERTEXT_BYTES: usize = 1568;
/// FIPS 203 keygen randomness `(d || z)`: the whole client secret. Never
/// persisted.
const SEED_BYTES: usize = 64;

const PSK_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"BirdoPQ-v1-PSK";
/// Upper bound for the server's per-connect nonce, the same as Android's
/// `BirdoPqManager.MAX_NONCE_BYTES` (the server mints 32 bytes).
const MAX_NONCE_BYTES: usize = 64;

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

/// The file older builds kept the keypair in (see [`purge_legacy_keypair_files`]).
const KEYPAIR_FILENAME: &str = "birdo_pq_v1.bin";
// PFA-M5: legacy DEFAULT_NONCE_BYTES constant removed: `try_decapsulate`
// now refuses to derive a PSK against a missing/empty per-connect nonce.

/// Operating mode reported to the UI.
///
/// Shares its `disabled` / `bilateral` values with Android's
/// `BirdoPqManager.Mode` (formerly `RosenpassManager.Mode`) so the same
/// telemetry dashboards / strings work on both platforms. Android no longer
/// has `ServerProvided` (A1-039 removed it there as unreachable); the desktop
/// still latches it when a session the server did not make post-quantum
/// carries the server's PSK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqMode {
    /// No PSK at all. Tunnel runs without preshared-key.
    Disabled,
    /// Server-provided classical PSK for a session the server did not make
    /// post-quantum (TLS-delivered; no post-quantum protection at all).
    ServerProvided,
    /// Bilateral ML-KEM-1024: this client decapsulated the server's ciphertext
    /// and derived the PSK itself. Post-quantum on the app-to-API leg only; NOT
    /// a complete "record now, decrypt later" defence (long-lived key, classical
    /// relay leg, multi-hop's middle leg — see the module docs).
    Bilateral,
}

static CURRENT_MODE: OnceCell<Mutex<PqMode>> = OnceCell::new();

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

/// A keygen for ONE connect request, and nothing else (MR-703 / MR-1742).
///
/// [`PqSession::begin`] draws a fresh 64-byte FIPS 203 seed `(d || z)` from the
/// OS CSPRNG, derives the ML-KEM-1024 encapsulation key from it and keeps only
/// the seed, in memory, for the one request the public key goes out with. The
/// secret is never written anywhere: there is no file, no keyring item, and no
/// `Clone`, `Serialize` or `Debug` that could copy or print it. It is wiped
/// when the value drops, and [`PqSession::finish`] consumes it, so a pair
/// cannot decapsulate twice.
///
/// Lifetime rule (the part callers must keep): ONE session per `/vpn/connect`
/// request. The same session is held across the retries of that same request
/// (the server's retryable refusals re-send the same body, so its ciphertext
/// still fits the key), and a NEW connect or re-dial calls `begin()` again.
/// A pair is never reused by a later connect.
pub struct PqSession {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    public_key: Vec<u8>,
}

// The wipe is the whole point; stop the build if a dependency change drops it.
const _: fn() = || {
    fn wipes_itself_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_itself_on_drop::<Zeroizing<[u8; SEED_BYTES]>>();
};

impl std::fmt::Debug for PqSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The seed is the secret key; print only that a session exists.
        f.write_str("PqSession { .. }")
    }
}

impl PqSession {
    /// A fresh keypair for one connect. The seed comes straight from the OS
    /// CSPRNG, not a userspace PRNG that could be forked or reseeded.
    pub fn begin() -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        crate::utils::os_rng::fill(seed.as_mut_slice());
        Self::from_seed(seed)
    }

    /// Deterministic FIPS 203 key generation from `(d || z)`.
    ///
    /// Split out from [`PqSession::begin`] so the known-answer test can drive
    /// it from the server fixture's `keygenSeed`: the same seed in, the same
    /// 1568 bytes out as `@noble/post-quantum`, is the strongest available proof
    /// that this client and the production server speak the same ML-KEM.
    fn from_seed(seed: Zeroizing<[u8; SEED_BYTES]>) -> Self {
        let dk = decapsulation_key(&seed);
        let ek = dk.encapsulation_key().to_bytes();
        assert_eq!(
            ek.len(),
            PUBLIC_KEY_BYTES,
            "ML-KEM-1024 encapsulation key must be {PUBLIC_KEY_BYTES} bytes"
        );
        Self {
            seed,
            public_key: ek.to_vec(),
        }
    }

    /// The 1568-byte public key, for the connect request.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The Base64 public key the `/vpn/connect` body carries.
    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public_key())
    }

    /// Decapsulate the server's ciphertext into the 32-byte WireGuard PSK and
    /// wipe the secret. Consuming `self` is the "wiped after finish" guarantee:
    /// the seed is zeroized as this function returns, on the error path too.
    ///
    /// ML-KEM is implicit-rejection: a malformed ciphertext of the right size
    /// does not error here, it yields a deterministic random shared secret; the
    /// resulting PSK then does not match the server's and the WireGuard
    /// handshake fails later. That is the desired behaviour: it prevents an
    /// oracle on whether decapsulation "succeeded". A ciphertext of the WRONG
    /// SIZE is not a KEM question at all and is refused outright.
    pub fn finish(
        self,
        server_ciphertext: &[u8],
        server_nonce: &[u8],
    ) -> Result<Zeroizing<[u8; PSK_LEN]>, String> {
        derive_psk(&self.seed, server_ciphertext, server_nonce)
    }
}

/// The decapsulation key for a seed. `DecapsulationKey` is `ZeroizeOnDrop`
/// (ml-kem's `zeroize` feature), so the expanded key built here is wiped when
/// the caller drops it; the stack copy of the seed handed to `from_seed` is
/// wiped by hand because `Array` has no `Drop` of its own.
fn decapsulation_key(seed_bytes: &[u8; SEED_BYTES]) -> DecapsulationKey<MlKem1024> {
    let mut seed: Seed = Array::<u8, U64>::from(*seed_bytes);
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
    seed.as_mut_slice().zeroize();
    dk
}

/// Decapsulate `server_ciphertext` with the key for `seed` and derive the PSK.
fn derive_psk(
    seed: &[u8; SEED_BYTES],
    server_ciphertext: &[u8],
    server_nonce: &[u8],
) -> Result<Zeroizing<[u8; PSK_LEN]>, String> {
    let ct: MlCiphertext<MlKem1024> =
        Array::<u8, U1568>::try_from(server_ciphertext).map_err(|_| {
            format!(
                "malformed server ciphertext: expected {CIPHERTEXT_BYTES} bytes, got {}",
                server_ciphertext.len()
            )
        })?;
    let dk = decapsulation_key(seed);
    // Infallible by design (implicit rejection) — do NOT "improve" this into a
    // Result: turning a rejection into an observable error would build the
    // decapsulation oracle the FIPS 203 construction exists to deny.
    let mut ss = dk.decapsulate(&ct);
    let psk = hkdf_to_psk(ss.as_slice(), server_nonce);
    // `SharedKey` is a plain array with no Drop impl of its own.
    ss.as_mut_slice().zeroize();
    psk
}

fn hkdf_to_psk(shared_secret: &[u8], nonce: &[u8]) -> Result<Zeroizing<[u8; PSK_LEN]>, String> {
    // MR-2112 (AUD-1016-CRYPTO-5): extract + expand, not `Hkdf::new`. `new`
    // is `let (_, hkdf) = Self::extract(..)` (hkdf 0.13): it dropped the PRK,
    // HMAC(salt, ss), unwiped, and from it and the nonce anyone gets this
    // session's PSK. The PRK is wiped here, on the error path too; the HMAC
    // keyed with it wipes its own state on drop (sha2's `zeroize`, held at
    // compile time below).
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), shared_secret);
    let mut psk = Zeroizing::new([0u8; PSK_LEN]);
    // PFA-D1: HKDF expansion size of 32 bytes is always within the
    // L = 8160-byte maximum for SHA-256, so this branch should never
    // trigger; we still propagate Err rather than panicking so a future
    // refactor that bumps PSK_LEN cannot turn this into a DoS panic.
    let expanded = hk.expand(nonce, psk.as_mut_slice());
    prk.as_mut_slice().zeroize();
    expanded.map_err(|e| format!("HKDF expand failed: {e}"))?;
    Ok(psk)
}

// MR-2112, held at compile time. The HMAC that HKDF keeps (`hk` above) holds
// two SHA-256 states keyed with the PRK (hmac 0.13 `HmacCore`: the inner and
// outer digests, each `<Sha256 as EagerHash>::Core`). They wipe themselves on
// drop only when sha2's `zeroize` feature is on (sha2 0.11 `block_api.rs`,
// `Sha256VarCore`'s Drop). A dependency change that turned the wipe off stops
// the build here instead of shipping.
const _: fn() = || {
    fn wipes_itself_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_itself_on_drop::<<Sha256 as hmac::EagerHash>::Core>();
};

// ── Legacy key files ──────────────────────────────────────────────────────

/// Where this account's keypair file lived before per-connect keys (MR-703):
/// `name` in the app directory `dir`.
///
/// On WINDOWS it was `pq-<account SID>.bin` in the admin-only
/// `%ProgramData%\BirdoVPN` (R4, `utils::protected_dir`), and `birdo_pq_v1.bin`
/// in `%LOCALAPPDATA%\BirdoVPN` in builds before R4. On macOS and Linux it was
/// `<config_local_dir>/BirdoVPN/birdo_pq_v1.bin`. Nothing writes any of them
/// any more; they exist only to be deleted.
struct LegacyKeypairFile {
    dir: OwnedDir,
    name: String,
}

/// This account's legacy keypair file in the admin-only directory `protected`.
#[cfg_attr(not(windows), allow(dead_code))]
fn protected_legacy_file(
    protected: &std::path::Path,
    sid: &str,
) -> Result<LegacyKeypairFile, String> {
    let (Some(base), Some(folder)) = (
        protected.parent(),
        protected.file_name().and_then(|n| n.to_str()),
    ) else {
        return Err("the admin-only directory has no parent".to_string());
    };
    Ok(LegacyKeypairFile {
        dir: OwnedDir::new(base, &[folder]),
        name: format!("pq-{sid}.bin"),
    })
}

/// The per-user file every build before R4 (Windows) and every Unix build kept
/// the keypair in.
fn per_user_legacy_file() -> Result<LegacyKeypairFile, String> {
    let base = dirs::config_local_dir()
        .ok_or_else(|| "no config_local_dir on this platform".to_string())?;
    Ok(LegacyKeypairFile {
        dir: OwnedDir::new(base, &["BirdoVPN"]),
        name: KEYPAIR_FILENAME.to_string(),
    })
}

/// Delete one legacy keypair file, and any staging file an interrupted write
/// of it left (`<name>.<hex>.tmp`: that held the same secret). Each delete goes
/// through the checked handle (MR-1945): a link planted at the name is refused,
/// never followed. A file that is not there is fine. Returns how many files
/// were deleted.
fn purge_legacy_file(file: &LegacyKeypairFile) -> usize {
    let mut names = vec![file.name.clone()];
    if let Ok(entries) = std::fs::read_dir(file.dir.path()) {
        let staging_prefix = format!("{}.", file.name);
        names.extend(entries.flatten().filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            (name.starts_with(&staging_prefix) && name.ends_with(".tmp")).then_some(name)
        }));
    }
    let mut deleted = 0;
    for name in names {
        match file.dir.remove_file(&name) {
            Ok(()) => deleted += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("BirdoPQ: legacy key file {name} was not deleted: {e}"),
        }
    }
    deleted
}

/// Every place a persisted keypair could be: this account's file in the
/// admin-only directory on Windows, and the per-user file everywhere.
fn legacy_keypair_files() -> Vec<LegacyKeypairFile> {
    let mut files = Vec::new();
    #[cfg(windows)]
    {
        match crate::utils::protected_dir::ensure()
            .map_err(|e| format!("admin-only state directory: {e}"))
            .and_then(|protected| {
                let sid = crate::utils::protected_dir::current_user_sid()
                    .map_err(|e| format!("account SID: {e}"))?;
                protected_legacy_file(&protected, &sid)
            }) {
            Ok(file) => files.push(file),
            Err(e) => tracing::warn!("BirdoPQ: the admin-only key location is unavailable: {e}"),
        }
    }
    match per_user_legacy_file() {
        Ok(file) => files.push(file),
        Err(e) => tracing::warn!("BirdoPQ: the per-user key location is unavailable: {e}"),
    }
    files
}

/// Delete the long-lived ML-KEM keypair files older builds persisted (MR-703 /
/// MR-1742: this build keeps no secret on disk). Idempotent and best-effort: a
/// failure is logged and never blocks the caller.
///
/// Called on every start (the first run after the upgrade does the work; the
/// rest find nothing) and on logout and account deletion, where it stays as the
/// hygiene it always was. Also resets the latched mode. Keep it for as long as
/// a build with a stored key can still be installed over; nothing else removes
/// those files.
pub fn purge_legacy_keypair_files() {
    set_mode(PqMode::Disabled);
    let deleted: usize = legacy_keypair_files().iter().map(purge_legacy_file).sum();
    if deleted > 0 {
        tracing::info!("BirdoPQ: deleted {deleted} legacy ML-KEM key file(s) (per-connect keys)");
    }
}

// ── Public API used by the connect command ────────────────────────────────

/// The per-connect nonce the server sends in `rosenpassEndpoint` (base64),
/// decoded and bounded to 1..=[`MAX_NONCE_BYTES`] bytes.
///
/// Proposed row 13: the length was unbounded here while Android caps it at
/// 64 before the nonce crosses into Rust. It is the HKDF `info`, so no length
/// is unsafe for the KDF itself; the bound keeps a malformed or hostile
/// response from having this process decode and hash a field of any size,
/// and makes both clients refuse the same responses. The text is bounded
/// before it is decoded (64 bytes are 88 characters of padded base64).
fn server_nonce(field: Option<&str>) -> Result<Vec<u8>, String> {
    let encoded = match field {
        None | Some("") => return Err("server omitted per-connect nonce".into()),
        Some(encoded) => encoded,
    };
    if encoded.len() > MAX_NONCE_BYTES.div_ceil(3) * 4 {
        return Err(format!(
            "PQ nonce out of bounds ({} base64 characters)",
            encoded.len()
        ));
    }
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("malformed PQ nonce: {e}"))?;
    if nonce.is_empty() || nonce.len() > MAX_NONCE_BYTES {
        return Err(format!("PQ nonce out of bounds ({} B)", nonce.len()));
    }
    Ok(nonce)
}

/// Try to derive a bilateral PQ PSK from the server response, with the
/// connect's own [`PqSession`]. Returns `None` when the server did not enable
/// BirdoPQ or include a ciphertext (legacy path), or when the response is
/// unusable. The session is consumed (and so wiped) here either way.
///
/// What the caller does with `None` depends entirely on `quantum_enabled`:
/// with it OFF this is the legacy path and `derive_quantum_psk` takes the
/// server-provided PSK (`record_server_provided`); with it ON the same `None`
/// aborts the connection. `None` is therefore never a silent downgrade.
///
/// On success, latches `current_mode() == Bilateral`, which `get_vpn_status`
/// reports as `quantum_active` / `pq_mode`. That state means "this client
/// derived the PSK itself", not a complete "record now, decrypt later"
/// defence: see the module docs for what it does not cover.
///
/// The PSK comes back `Zeroizing`: it is the WireGuard preshared key, base64
/// for the config file, and it used to be a plain `String` that was dropped
/// un-wiped at the end of `commands::vpn::connect` after being cloned into the
/// `VpnConfig` (which does wipe its copy). Now both copies are wiped.
pub fn try_decapsulate(
    response: &ConnectResponse,
    session: Option<PqSession>,
) -> Option<Zeroizing<String>> {
    if !response.quantum_enabled.unwrap_or(false) {
        return None;
    }
    // Quantum is on but this connect made no keypair: it cannot decapsulate.
    // Fail closed (the caller aborts), never derive from some other key.
    let Some(session) = session else {
        tracing::error!("BirdoPQ: the server enabled BirdoPQ but this connect made no keypair");
        return None;
    };
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
    let nonce = match server_nonce(response.rosenpass_endpoint.as_deref()) {
        Ok(nonce) => nonce,
        Err(e) => {
            tracing::error!("BirdoPQ: {e} — bilateral PQ aborted (PFA-M5)");
            return None;
        }
    };

    let psk = match session.finish(&ct, &nonce) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("BirdoPQ: decapsulation failed: {e}");
            return None;
        }
    };
    set_mode(PqMode::Bilateral);
    tracing::info!(
        "BirdoPQ v1 BILATERAL — quantum-resistant PSK derived (32 B, mode=bilateral, impl={PQ_IMPL_NAME})"
    );
    Some(Zeroizing::new(
        base64::engine::general_purpose::STANDARD.encode(psk.as_slice()),
    ))
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
    // Test-only: the expanded 3168-byte encoding is no longer used by the
    // client, but the server's KAT fixture and the PQClean install-base
    // fixture are in it, and they are the cross-implementation proof.
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::{EncapsulationKey, Key, TryKeyInit, B32};

    /// The production server's own known-answer fixture, byte-identical to
    /// birdo-web `backend/src/vpn/__fixtures__/birdo-pq-ml-kem-1024.kat.json`.
    const KAT_JSON: &str = include_str!("fixtures/birdo-pq-ml-kem-1024.kat.json");
    /// A keypair + ciphertext produced by PQClean CLEAN C (`pqcrypto-mlkem`):
    /// what installs up to v1.4.43 had on disk. Kept only to prove which
    /// ML-KEM is linked (`pq_impl_name_matches_linked_crate`).
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

    fn seed_of(byte: u8) -> Zeroizing<[u8; SEED_BYTES]> {
        Zeroizing::new([byte; SEED_BYTES])
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

    // ── Cross-implementation vectors ──────────────────────────────────────

    /// The ONE test that can detect byte-incompatibility with the production
    /// server. Everything else in this module is a self-consistent round trip:
    /// a KEM that is internally correct but speaks a different ML-KEM encoding
    /// passes all of them, and FIPS 203 implicit rejection means the only
    /// field symptom is a WireGuard handshake that silently never completes.
    ///
    /// Fixture generated with `@noble/post-quantum`, the library the backend
    /// actually encapsulates with (`backend/src/vpn/birdo-pq.service.ts`).
    /// Per-connect keys changed where the secret lives, not one byte of this.
    #[test]
    #[allow(deprecated)]
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
        // 64-byte seed must produce the server's exact 1568 bytes (and the
        // expanded key the fixture records).
        let session = PqSession::from_seed(Zeroizing::new(seed));
        assert_eq!(
            session.public_key(),
            want_pk,
            "encapsulation key (ek) mismatch"
        );
        let mut expanded = decapsulation_key(&seed).to_expanded_bytes();
        assert_eq!(
            expanded.as_slice(),
            want_sk.as_slice(),
            "expanded decapsulation key (dk) mismatch"
        );
        expanded.as_mut_slice().zeroize();

        // encapsulate leg
        let (ct, ss) = encapsulate_with(&want_pk, &encaps_m);
        assert_eq!(ct, want_ct, "ciphertext mismatch");
        assert_eq!(ss, want_ss, "shared secret from encapsulate mismatch");

        // decapsulate + HKDF legs, through the real production entry point.
        let psk = session
            .finish(&want_ct, &nonce)
            .expect("decapsulating the server's own ciphertext must succeed");
        assert_eq!(
            psk.as_slice(),
            want_psk.as_slice(),
            "PSK mismatch: the HKDF construction or the shared secret drifted \
             from the server's"
        );
    }

    /// Implicit rejection, with a wrong key: no error, no panic, a stable but
    /// different PSK. Making the failure observable would hand an attacker a
    /// decapsulation oracle.
    #[test]
    fn implicit_rejection_is_deterministic_and_silent() {
        let ours = PqSession::from_seed(seed_of(0x11));
        let (ct, _ss) = encapsulate_with(ours.public_key(), &[0x33; 32]);

        let good = ours.finish(&ct, b"nonce").unwrap();
        let bad1 = PqSession::from_seed(seed_of(0x22))
            .finish(&ct, b"nonce")
            .expect("a wrong key must NOT error: that is the oracle");
        let bad2 = PqSession::from_seed(seed_of(0x22))
            .finish(&ct, b"nonce")
            .unwrap();

        assert_ne!(good.as_slice(), bad1.as_slice());
        assert_eq!(bad1.as_slice(), bad2.as_slice(), "must be deterministic");
    }

    /// `PQ_IMPL_NAME` is the only signal that could attribute a native fault in
    /// this path to an implementation, so it must not drift from the crate that
    /// is linked. The discriminator is behavioural, not a string compare: only
    /// RustCrypto `ml-kem` rejects a decapsulation key whose embedded `H(ek)`
    /// is wrong (FIPS 203 §7.3). `pqcrypto-mlkem`'s `from_bytes` accepts it.
    #[test]
    #[allow(deprecated)]
    fn pq_impl_name_matches_linked_crate() {
        let mut sk = field(PQCLEAN_JSON, "secretKeyB64");
        let good = Array::<u8, ml_kem::array::sizes::U3168>::try_from(sk.as_slice()).unwrap();
        assert!(
            <DecapsulationKey<MlKem1024> as ExpandedKeyEncoding>::from_expanded_bytes(&good)
                .is_ok(),
            "the untouched PQClean key must load"
        );
        sk[3110] ^= 0x01;
        let bad = Array::<u8, ml_kem::array::sizes::U3168>::try_from(sk.as_slice()).unwrap();
        assert!(
            <DecapsulationKey<MlKem1024> as ExpandedKeyEncoding>::from_expanded_bytes(&bad)
                .is_err(),
            "the linked KEM does not enforce FIPS 203 §7.3: it is not RustCrypto \
             ml-kem, so PQ_IMPL_NAME is lying"
        );
        assert_eq!(PQ_IMPL_NAME, "mlkem1024-rustcrypto");
        assert_ne!(
            PQ_IMPL_NAME, "mlkem1024-clean",
            "PQClean is no longer what is linked"
        );
    }

    // ── Per-connect keys (MR-703 / MR-1742) ───────────────────────────────

    #[test]
    fn a_session_has_the_wire_sizes() {
        let s = PqSession::begin();
        assert_eq!(s.public_key().len(), PUBLIC_KEY_BYTES);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(s.public_key_b64())
                .unwrap(),
            s.public_key()
        );
    }

    /// Two connects never share a key: the property this change exists for.
    #[test]
    fn two_connects_give_different_public_keys() {
        let a = PqSession::begin();
        let b = PqSession::begin();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.public_key_b64(), b.public_key_b64());
    }

    /// The retries of ONE request re-send the same public key (the server's
    /// ciphertext must still fit the key it is decapsulated with), and the
    /// session that sent it can still finish after any number of reads.
    #[test]
    fn a_retry_of_the_same_request_reuses_the_pair() {
        let session = PqSession::begin();
        let first = session.public_key_b64();
        let retry = session.public_key_b64();
        assert_eq!(first, retry);

        let (ct, ss_server) = encapsulate_with(session.public_key(), &[0x5A; 32]);
        let nonce = b"connect-2026-05-10T12:00:00Z";
        let server_psk = hkdf_to_psk(&ss_server, nonce).unwrap();
        let client_psk = session.finish(&ct, nonce).unwrap();
        assert_eq!(
            client_psk.as_slice(),
            server_psk.as_slice(),
            "client and server MUST derive identical PSK from (sk, ct, nonce)"
        );
    }

    /// The secret is wiped when the session ends, by `finish` and by a plain
    /// drop (a failed or cancelled connect). The bytes are read back out of a
    /// `ManuallyDrop` so the check sees the wiped memory, not a moved-from one.
    #[test]
    fn the_secret_is_wiped_on_drop() {
        let mut s = std::mem::ManuallyDrop::new(PqSession::from_seed(seed_of(0xA5)));
        assert!(s.seed.iter().all(|b| *b == 0xA5));
        // SAFETY: dropped exactly once, and `s` is not used as a PqSession again;
        // only the (plain-array) seed bytes are read back.
        unsafe { std::mem::ManuallyDrop::drop(&mut s) };
        assert!(
            s.seed.iter().all(|b| *b == 0),
            "the ML-KEM seed survived the drop"
        );
    }

    #[test]
    fn a_session_never_prints_its_secret() {
        let s = PqSession::from_seed(seed_of(0xA5));
        let shown = format!("{s:?}");
        assert_eq!(shown, "PqSession { .. }");
    }

    /// `finish` consumes the session and nothing can copy it: the type has no
    /// `Clone`, `Copy` or `Serialize`, so "decapsulates twice" and "written to
    /// disk" do not compile. Pinned at the source so a derive cannot slip in.
    #[test]
    fn the_session_cannot_be_copied_or_serialized() {
        let source = include_str!("birdo_pq.rs").replace('\r', "");
        let decl = source.find("pub struct PqSession").unwrap();
        let before = &source[decl.saturating_sub(40)..decl];
        for bad in ["derive", "Clone", "Copy", "Serialize"] {
            assert!(!before.contains(bad), "PqSession must not derive {bad}");
        }
        // Built at run time: this test's own source must not name the impl.
        for bad in ["Clone", "Serialize"] {
            let production_end = source.find("#[cfg(test)]").unwrap();
            assert!(!source[..production_end].contains(&format!("impl {bad} for PqSession")));
        }
    }

    // ── Round trips ───────────────────────────────────────────────────────

    #[test]
    fn server_encap_then_client_decap_match() {
        let session = PqSession::begin();
        let (ct, ss_server) = encapsulate_with(session.public_key(), &[0x5A; 32]);
        let nonce = b"connect-2026-05-10T12:00:00Z";
        let server_psk = hkdf_to_psk(&ss_server, nonce).unwrap();
        let client_psk = session.finish(&ct, nonce).unwrap();
        assert_eq!(client_psk.as_slice(), server_psk.as_slice());
    }

    /// A ciphertext made for ANOTHER connect's key does not decapsulate to the
    /// server's PSK: a new connect never reuses an old pair's secret.
    #[test]
    fn a_ciphertext_for_an_earlier_connect_does_not_fit_a_new_one() {
        let old = PqSession::begin();
        let (ct, ss_server) = encapsulate_with(old.public_key(), &[0x5A; 32]);
        let server_psk = hkdf_to_psk(&ss_server, b"n").unwrap();
        let new = PqSession::begin();
        let psk = new.finish(&ct, b"n").unwrap();
        assert_ne!(psk.as_slice(), server_psk.as_slice());
    }

    #[test]
    fn different_nonces_produce_different_psks() {
        let kp = PqSession::from_seed(seed_of(0x44));
        let (ct, _ss) = encapsulate_with(kp.public_key(), &[0x5A; 32]);
        // Two nonces that differ in one bit, derived here rather than written
        // out as constants (CodeQL rust/hard-coded-cryptographic-value, MR-2132).
        let nonce_a = ct[..16].to_vec();
        let mut nonce_b = nonce_a.clone();
        nonce_b[0] ^= 1;
        let a = derive_psk(&kp.seed, &ct, &nonce_a).unwrap();
        let b = derive_psk(&kp.seed, &ct, &nonce_b).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    /// A-M76: pins the exact SHA-256 / HKDF-SHA-256 outputs. The expected hex
    /// was captured from the sha2 0.10 / hkdf 0.12 build (Mobile-Client #586)
    /// and must not change across the sha2 0.11 / hkdf 0.13 / digest 0.11
    /// move. The same constants are asserted in the Mobile native crates.
    #[test]
    fn hash_stack_outputs_are_pinned() {
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        let digest = <Sha256 as sha2::Digest>::digest(b"abc");
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // RFC 5869 appendix A.1 (HKDF-SHA-256 test case 1).
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .expect("length OK");
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // The BirdoPQ derivation (salt "BirdoPQ-v1-PSK") on a fixed input.
        // Test vector input, decoded from hex (not a hard-coded nonce in use).
        let ss = hex::decode("42".repeat(32)).expect("hex");
        let nonce = hex::decode("24".repeat(32)).expect("hex");
        let psk = hkdf_to_psk(&ss, &nonce).expect("derive");
        assert_eq!(
            hex::encode(psk.as_slice()),
            "7b7fad70ecc0971d17b32a8409159faf20014e168e816c02b7739572a1fab11c"
        );
    }

    /// MR-2112: the PRK HKDF extracts from the shared secret is wiped before
    /// any return, not dropped unwiped inside `Hkdf::new`. No test can see
    /// a stack value's wipe after the fact, so the shape is pinned here
    /// (`kat_vs_noble` pins that the PSK is unchanged; the HMAC's own wipe is
    /// the compile-time assertion beside `hkdf_to_psk`).
    #[test]
    fn the_hkdf_prk_is_wiped_before_any_return() {
        let source = include_str!("birdo_pq.rs").replace('\r', "");
        let body = &source[source.find("fn hkdf_to_psk(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(!body.contains("Hkdf::<Sha256>::new("), "{body}");
        let extract = body
            .find("let (mut prk, hk) = Hkdf::<Sha256>::extract(")
            .expect("the PRK is kept to be wiped");
        let wipe = body
            .find("prk.as_mut_slice().zeroize();")
            .expect("the PRK is wiped");
        let first_return = body.find("?;").expect("the expand error is returned");
        assert!(
            extract < wipe && wipe < first_return,
            "the PRK must be wiped before the first return: {body}"
        );
    }

    /// A wrong-sized ciphertext fails closed: an error, never a PSK.
    #[test]
    fn malformed_inputs_error_cleanly() {
        assert!(PqSession::begin().finish(&[0u8; 16], b"n").is_err());
        assert!(PqSession::begin()
            .finish(&[0u8; CIPHERTEXT_BYTES + 1], b"n")
            .is_err());
    }

    // ── Legacy key files ──────────────────────────────────────────────────

    fn legacy_in(base: &std::path::Path, name: &str) -> LegacyKeypairFile {
        LegacyKeypairFile {
            dir: OwnedDir::new(base.to_path_buf(), &[]),
            name: name.to_string(),
        }
    }

    /// First run after the upgrade: the stored keypair file goes, and so do the
    /// staging files an interrupted write left (they held the same secret).
    /// Unrelated files, and files that merely start like it, stay.
    #[test]
    fn the_legacy_keypair_file_is_purged() {
        let dir = tempfile::tempdir().unwrap();
        let name = KEYPAIR_FILENAME;
        let staging = format!("{name}.00ff00ff00ff00ff.tmp");
        std::fs::write(dir.path().join(name), [7u8; 4744]).unwrap();
        std::fs::write(dir.path().join(&staging), [7u8; 100]).unwrap();
        std::fs::write(dir.path().join("settings.json"), b"{}").unwrap();
        std::fs::write(dir.path().join(format!("{name}.bak")), b"x").unwrap();

        assert_eq!(purge_legacy_file(&legacy_in(dir.path(), name)), 2);

        assert!(!dir.path().join(name).exists());
        assert!(!dir.path().join(&staging).exists());
        assert!(dir.path().join("settings.json").exists());
        assert!(dir.path().join(format!("{name}.bak")).exists());
        // Idempotent: the second run finds nothing and does not fail.
        assert_eq!(purge_legacy_file(&legacy_in(dir.path(), name)), 0);
    }

    /// The Windows location is the admin-only directory, one file per account.
    #[test]
    fn the_windows_legacy_file_is_per_account_in_the_admin_only_directory() {
        let base = tempfile::tempdir().unwrap();
        let protected = base.path().join("ProgramData").join("BirdoVPN");
        std::fs::create_dir_all(&protected).unwrap();
        let alice = protected_legacy_file(&protected, "S-1-5-21-1-2-3-1001").unwrap();
        let bob = protected_legacy_file(&protected, "S-1-5-21-1-2-3-1002").unwrap();
        assert_eq!(alice.name, "pq-S-1-5-21-1-2-3-1001.bin");
        assert_eq!(alice.dir.path(), bob.dir.path());

        std::fs::write(alice.dir.join(&alice.name), [7u8; 10]).unwrap();
        std::fs::write(bob.dir.join(&bob.name), [7u8; 10]).unwrap();
        // One account's purge never touches another account's file.
        assert_eq!(purge_legacy_file(&alice), 1);
        assert!(!alice.dir.join(&alice.name).exists());
        assert!(bob.dir.join(&bob.name).exists());

        let source = include_str!("birdo_pq.rs").replace('\r', "");
        let body = &source[source.find("fn legacy_keypair_files()").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("crate::utils::protected_dir::ensure()"));
        assert!(body.contains("protected_legacy_file(&protected, &sid)"));
    }

    /// Nothing in this module writes a keypair any more.
    #[test]
    fn nothing_persists_a_secret() {
        let source = include_str!("birdo_pq.rs").replace('\r', "");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        for forbidden in [
            "create_new(",
            "fs::write(",
            "File::create(",
            "write_all(",
            "open_rw(",
        ] {
            assert!(
                !production.contains(forbidden),
                "{forbidden} in production code"
            );
        }
    }

    fn response_with(ct: Option<String>, nonce: Option<String>, quantum: bool) -> ConnectResponse {
        ConnectResponse {
            success: true,
            message: None,
            quota_exceeded: false,
            refusal_reason: None,
            account_restriction: None,
            device_notice: None,
            key_id: None,
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
            quantum_enabled: Some(quantum),
            rosenpass_public_key: ct,
            rosenpass_endpoint: nonce,
        }
    }

    #[test]
    fn try_decapsulate_returns_none_when_pq_disabled() {
        let resp = response_with(Some("anything".into()), None, false);
        assert!(try_decapsulate(&resp, Some(PqSession::begin())).is_none());
    }

    /// The server turned BirdoPQ on, so a response WITHOUT a usable ciphertext
    /// or nonce, or a connect with no session, derives nothing: `None` is what
    /// makes `derive_quantum_psk` abort rather than demote.
    #[test]
    fn try_decapsulate_fails_closed_on_an_unusable_response() {
        let session = PqSession::begin();
        let (ct, _ss) = encapsulate_with(session.public_key(), &[0x5A; 32]);
        let std_b64 = base64::engine::general_purpose::STANDARD;
        let nonce = std_b64.encode([9u8; 32]);
        let ct_b64 = std_b64.encode(&ct);

        // A good response, but this connect made no keypair.
        let good = response_with(Some(ct_b64.clone()), Some(nonce.clone()), true);
        assert!(try_decapsulate(&good, None).is_none());
        // Wrong-size ciphertext, missing nonce.
        let short = response_with(Some(std_b64.encode([1u8; 16])), Some(nonce.clone()), true);
        assert!(try_decapsulate(&short, Some(PqSession::begin())).is_none());
        let no_nonce = response_with(Some(ct_b64), None, true);
        assert!(try_decapsulate(&no_nonce, Some(PqSession::begin())).is_none());
        // And the good one works with its own session.
        assert!(try_decapsulate(&good, Some(session)).is_some());
    }

    /// Proposed row 13: the server nonce is bounded like Android's
    /// (`MAX_NONCE_BYTES = 64`). Missing, empty, oversized and malformed are
    /// refused — an oversized text before it is decoded at all.
    #[test]
    fn the_server_nonce_is_bounded_like_android() {
        let b64 = |n: usize| base64::engine::general_purpose::STANDARD.encode(vec![7u8; n]);
        assert_eq!(
            server_nonce(Some(&b64(32))).unwrap().len(),
            32,
            "what the server mints"
        );
        assert_eq!(server_nonce(Some(&b64(1))).unwrap().len(), 1);
        assert_eq!(server_nonce(Some(&b64(64))).unwrap().len(), 64);
        assert!(
            server_nonce(Some(&b64(65))).is_err(),
            "decoded past the cap"
        );
        assert!(
            server_nonce(Some(&b64(1 << 20))).is_err(),
            "text past the cap"
        );
        assert!(server_nonce(Some("")).is_err());
        assert!(server_nonce(None).is_err());
        assert!(server_nonce(Some("not base64!")).is_err());
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
