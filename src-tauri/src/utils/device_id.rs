//! The desktop client's device identifier: a random, per-install ID.
//!
//! # Why it is random now (audit 2026-09-29, C-8)
//!
//! It used to be `SHA-256(hostname | OS | USERNAME)`, unsalted. That value was
//! the same for EVERY account ever used on the machine, survived uninstall and
//! account deletion, could not be rotated, and — hostnames and usernames being
//! low-entropy — could be reversed by guessing. The backend stores it beside the
//! account (`devices.device_id`, `sessions`, `wireguard_keys`), so it linked
//! anonymous accounts created on one computer to each other and to any email
//! account used there.
//!
//! Android and iOS already use a random ID. Desktop now does the same:
//! `desktop_<uuid-v4>`, generated on first use and persisted beside the ML-KEM
//! key (`<config_local_dir>/BirdoVPN/device_id`), and ROTATED on sign-out and on
//! account deletion so the next account on the machine is a new device.
//!
//! # What the backend does with a new ID
//!
//! Identity there is the pair `(userId, deviceId)`. Registration is an upsert
//! with no device-count wall (`DeviceService.registerDevice`), and the plan's
//! connection cap is enforced at CONNECT time by evicting the oldest active
//! keys (`VpnService.evictForConnect`). So a new ID never blocks sign-in or
//! connect. Its visible effects are: one extra row in the account's device list
//! (the old row stays until removed), a trusted-device 2FA skip that has to be
//! re-earned, and — only while the previous session's key is still live — that
//! key occupying a slot until the heartbeat reaper or the cap eviction frees it.
//!
//! The first launch of this version is exactly such a rotation for every
//! existing install: the old hash is never read again, never migrated.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

const FILE_NAME: &str = "device_id";
const PREFIX: &str = "desktop_";

/// The contract's `deviceId` constraint (`contract/vpn-protocol.schema.json`,
/// backend `DeviceInfoSchema`): `^[A-Za-z0-9._:-]+$`, 1..=128.
fn is_valid(id: &str) -> bool {
    id.starts_with(PREFIX)
        && id.len() <= 128
        && id.len() > PREFIX.len()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// A fresh `desktop_<uuid-v4>` from the OS CSPRNG (`rand::thread_rng` is a
/// ChaCha stream seeded from it). RFC 4122 layout, version 4, variant 10.
fn generate() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{PREFIX}{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Write `id` to `path` via a temp file + rename, so a crash mid-write can
/// never leave a truncated ID that would then read as invalid and rotate.
fn persist(path: &Path, id: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, id).map_err(|e| format!("write {tmp:?}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename to {path:?}: {e}")
    })
}

/// The persisted-and-cached identifier. A struct (rather than bare statics) so
/// the tests can drive a private instance in a temp dir without touching the
/// process-wide one every other test reads.
struct DeviceIdStore {
    /// `None` = memory only (unit tests, or a platform without a config dir).
    path: Option<PathBuf>,
    cache: Mutex<Option<String>>,
}

impl DeviceIdStore {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
        }
    }

    fn get(&self) -> String {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(id) = cache.as_ref() {
            return id.clone();
        }
        let id = self.load_or_create();
        *cache = Some(id.clone());
        id
    }

    fn load_or_create(&self) -> String {
        let Some(path) = self.path.as_deref() else {
            return generate();
        };
        if let Ok(stored) = fs::read_to_string(path) {
            let stored = stored.trim();
            if is_valid(stored) {
                return stored.to_string();
            }
            tracing::warn!("Stored device identifier is malformed; generating a new one");
        }
        let id = generate();
        if let Err(e) = persist(path, &id) {
            // Keep working with the in-memory value; the next launch will
            // generate again, which is a new device row, not a failure.
            tracing::warn!("Could not persist the device identifier: {}", e);
        }
        id
    }

    /// Replace the identifier. The new value is in force for this process
    /// immediately, even if the disk write fails; in that case the stale file
    /// is removed so the next launch cannot resurrect the old identity.
    fn rotate(&self) -> String {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let id = generate();
        if let Some(path) = self.path.as_deref() {
            if let Err(e) = persist(path, &id) {
                tracing::warn!("Could not persist the rotated device identifier: {}", e);
                if let Err(e) = fs::remove_file(path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::error!(
                            "Could not remove the previous device identifier either: {}",
                            e
                        );
                    }
                }
            }
        }
        *cache = Some(id.clone());
        id
    }
}

/// Beside `birdo_pq_v1.bin` (see `vpn::birdo_pq::keypair_path`). Memory-only
/// under `cfg(test)`, so `cargo test` never writes into the developer's
/// profile and never rotates their real install's identity.
fn default_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    dirs::config_local_dir().map(|d| d.join("BirdoVPN").join(FILE_NAME))
}

static STORE: LazyLock<DeviceIdStore> = LazyLock::new(|| DeviceIdStore::new(default_path()));

/// This install's device identifier (see the module docs).
pub fn get() -> String {
    STORE.get()
}

/// Rotate the identifier: called on sign-out and after a confirmed account
/// deletion. Never fails; problems are logged.
pub fn rotate() {
    STORE.rotate();
    tracing::info!("Device identifier rotated");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_random_prefixed_uuid_v4_within_the_contract() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b, "two installs must not share an identifier");
        for id in [&a, &b] {
            assert!(is_valid(id), "{id}");
            let uuid = id.strip_prefix(PREFIX).unwrap();
            assert_eq!(uuid.len(), 36, "{id}");
            assert_eq!(&uuid[14..15], "4", "version nibble: {id}");
            assert!(
                matches!(&uuid[19..20], "8" | "9" | "a" | "b"),
                "variant: {id}"
            );
        }
    }

    /// The old scheme was a pure function of hostname, OS and username. The new
    /// value must not be derivable from any of them.
    #[test]
    fn the_identifier_is_not_derived_from_machine_facts() {
        use sha2::{Digest, Sha256};
        let host = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(host.as_bytes());
        hasher.update(b"|");
        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(b"|");
        hasher.update(std::env::var("USERNAME").unwrap_or_default().as_bytes());
        let legacy = hex::encode(hasher.finalize());

        let id = generate();
        assert!(!id.contains(&legacy));
        assert!(host.is_empty() || !id.contains(&host));
    }

    #[test]
    fn persists_across_loads_and_survives_a_fresh_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("BirdoVPN").join(FILE_NAME);

        let first = DeviceIdStore::new(Some(path.clone()));
        let id = first.get();
        assert_eq!(first.get(), id, "cached within a process");
        assert_eq!(fs::read_to_string(&path).unwrap(), id, "written to disk");

        // A new process (new store, empty cache) reads the same value back.
        let second = DeviceIdStore::new(Some(path.clone()));
        assert_eq!(second.get(), id, "stable across launches and app updates");
    }

    #[test]
    fn rotation_replaces_the_identifier_in_memory_and_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let store = DeviceIdStore::new(Some(path.clone()));

        let before = store.get();
        let after = store.rotate();
        assert_ne!(before, after);
        assert_eq!(store.get(), after, "the new ID is in force immediately");
        assert_eq!(fs::read_to_string(&path).unwrap(), after);

        // And the next launch sees the rotated value, never the old one.
        assert_eq!(DeviceIdStore::new(Some(path)).get(), after);
    }

    /// Migration: whatever an older build left (nothing, or garbage) yields a
    /// fresh random ID rather than an error or the old hash.
    #[test]
    fn a_missing_or_malformed_file_yields_a_fresh_valid_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);

        fs::write(&path, "not an id / with spaces").unwrap();
        let id = DeviceIdStore::new(Some(path.clone())).get();
        assert!(is_valid(&id), "{id}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            id,
            "the bad file is replaced"
        );

        // A legacy 64-hex hash is not accepted as an identifier either.
        let legacy = "a".repeat(64);
        fs::write(&path, &legacy).unwrap();
        let id = DeviceIdStore::new(Some(path)).get();
        assert_ne!(id, legacy);
        assert!(is_valid(&id));
    }

    #[test]
    fn the_process_wide_store_never_touches_disk_under_test() {
        assert!(default_path().is_none());
        assert!(is_valid(&get()));
    }
}
