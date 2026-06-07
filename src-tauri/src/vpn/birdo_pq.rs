//! BirdoPQ v1 — ML-KEM-1024 KEM-only PSK derivation for desktop.
//!
//! Wire-format twin of `birdo-client-mobile/native/rosenpass-jni/src/handshake.rs`
//! and `birdo-web/backend/src/vpn/birdo-pq.service.ts`. All three derive
//! exactly the same 32-byte WireGuard PSK from the same `(sk, ct, nonce)`
//! triple. If you change the HKDF salt or info encoding here, change them
//! in the other two too — and add a cross-implementation round-trip test.
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

use base64::Engine as _;
use hkdf::Hkdf;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::Sha256;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::api::types::ConnectResponse;

/// FIPS 203 ML-KEM-1024 sizes — must match server + Android constants.
pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const SECRET_KEY_BYTES: usize = 3168;
pub const CIPHERTEXT_BYTES: usize = 1568;
const PSK_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"BirdoPQ-v1-PSK";

const FILE_MAGIC: &[u8; 4] = b"BPQ1";
const FILE_VERSION: u32 = 1;
const KEYPAIR_FILENAME: &str = "birdo_pq_v1.bin";
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

pub fn generate_keypair() -> StaticKeypair {
    let (pk, sk) = mlkem1024::keypair();
    StaticKeypair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: Zeroizing::new(sk.as_bytes().to_vec()),
    }
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
    let sk = mlkem1024::SecretKey::from_bytes(client_secret_key.as_slice())
        .map_err(|e| format!("malformed client secret key: {e}"))?;
    let ct = mlkem1024::Ciphertext::from_bytes(server_ciphertext)
        .map_err(|e| format!("malformed server ciphertext: {e}"))?;
    let ss = mlkem1024::decapsulate(&ct, &sk);
    let mut ss_bytes = Zeroizing::new(ss.as_bytes().to_vec());
    let psk = hkdf_to_psk(&ss_bytes, server_nonce)?;
    ss_bytes.fill(0);
    Ok(psk)
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
    if kp.public_key.len() != PUBLIC_KEY_BYTES || kp.secret_key.len() != SECRET_KEY_BYTES {
        return Err("invalid keypair sizes".to_string());
    }
    let mut buf = Vec::with_capacity(FILE_MAGIC.len() + 4 + PUBLIC_KEY_BYTES + SECRET_KEY_BYTES);
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

fn read_keypair(path: &PathBuf) -> Result<Option<StaticKeypair>, String> {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("open {path:?}: {e}")),
    };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| format!("read {path:?}: {e}"))?;
    if buf.len() != FILE_MAGIC.len() + 4 + PUBLIC_KEY_BYTES + SECRET_KEY_BYTES {
        let n = buf.len();
        buf.fill(0);
        return Err(format!(
            "unexpected keypair file size {} (expected {})",
            n,
            FILE_MAGIC.len() + 4 + PUBLIC_KEY_BYTES + SECRET_KEY_BYTES
        ));
    }
    if &buf[..FILE_MAGIC.len()] != FILE_MAGIC {
        buf.fill(0);
        return Err("bad keypair magic".to_string());
    }
    let mut ver = [0u8; 4];
    ver.copy_from_slice(&buf[FILE_MAGIC.len()..FILE_MAGIC.len() + 4]);
    let v = u32::from_le_bytes(ver);
    if v != FILE_VERSION {
        buf.fill(0);
        return Err(format!("unsupported keypair file version {v}"));
    }
    let pk_off = FILE_MAGIC.len() + 4;
    let sk_off = pk_off + PUBLIC_KEY_BYTES;
    let pk = buf[pk_off..sk_off].to_vec();
    let sk = Zeroizing::new(buf[sk_off..].to_vec());
    buf.fill(0);
    Ok(Some(StaticKeypair {
        public_key: pk,
        secret_key: sk,
    }))
}

/// Returns a reference to the cached keypair, generating + persisting one
/// on first call. Errors are logged + returned; callers should treat error
/// as "PQ unavailable, fall back to server-provided PSK".
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
    let kp = match read_keypair(&path)? {
        Some(kp) => kp,
        None => {
            tracing::info!("BirdoPQ: no persisted ML-KEM keypair — generating fresh (~10–50 ms)");
            let fresh = generate_keypair();
            if let Err(e) = write_keypair(&path, &fresh) {
                tracing::warn!(
                    "BirdoPQ: failed to persist keypair to {path:?}: {e} — \
                     continuing in-memory; will regenerate next launch"
                );
            }
            fresh
        }
    };
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
/// when our local keypair is missing — caller should then fall back to the
/// server-provided classical PSK and call `record_server_provided`.
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
    // silently weaken the protocol. Fail closed (returns None ⇒ caller falls
    // back to server-provided classical PSK, mode latched to ServerProvided).
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
    tracing::info!("BirdoPQ v1 BILATERAL — quantum-resistant PSK derived (32 B, mode=bilateral)");
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
    use std::sync::Mutex as StdMutex;

    // Serialise file-touching tests so they don't race on the shared
    // config_local_dir keypair file when the suite runs threaded.
    static FS_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn generate_keypair_correct_sizes() {
        let kp = generate_keypair();
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(kp.secret_key.len(), SECRET_KEY_BYTES);
    }

    #[test]
    fn server_encap_then_client_decap_match() {
        // Round-trip: simulate the server's `mlkem1024::encapsulate` against
        // our pk, then decap with our sk + the same nonce. PSKs MUST match.
        let kp = generate_keypair();
        let pk = mlkem1024::PublicKey::from_bytes(&kp.public_key).unwrap();
        let (ss_server, ct) = mlkem1024::encapsulate(&pk);
        let nonce = b"connect-2026-05-10T12:00:00Z";
        let server_psk = hkdf_to_psk(ss_server.as_bytes(), nonce).unwrap();

        let client_psk = derive_psk(&kp.secret_key, ct.as_bytes(), nonce).unwrap();

        assert_eq!(
            client_psk.as_slice(),
            server_psk.as_slice(),
            "client and server MUST derive identical PSK from (sk, ct, nonce)"
        );
    }

    #[test]
    fn different_nonces_produce_different_psks() {
        let kp = generate_keypair();
        let pk = mlkem1024::PublicKey::from_bytes(&kp.public_key).unwrap();
        let (_ss, ct) = mlkem1024::encapsulate(&pk);
        let a = derive_psk(&kp.secret_key, ct.as_bytes(), b"nonce-A").unwrap();
        let b = derive_psk(&kp.secret_key, ct.as_bytes(), b"nonce-B").unwrap();
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
        let _g = FS_LOCK.lock().unwrap();
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
        let _g = FS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYPAIR_FILENAME);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&[0u8; 4744]).unwrap();
        let r = read_keypair(&path);
        assert!(r.is_err());
    }

    #[test]
    fn read_keypair_rejects_short_file() {
        let _g = FS_LOCK.lock().unwrap();
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
            error_code: None,
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
