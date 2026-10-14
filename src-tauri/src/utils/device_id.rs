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
//! key (`<config_local_dir>/BirdoVPN/device_id`), and ROTATED after a confirmed
//! account deletion, so the erased account's device identity dies with it.
//!
//! # Not on sign-out (second-pass #14)
//!
//! It is deliberately NOT rotated on sign-out, the same policy as iOS
//! (`APIClient.resetDeviceIdentity`) and Android (`BirdoRepository`, deletion
//! only). Rotating under a live account leaves the old device row behind,
//! re-triggers 2FA on every sign-in, and resets the per-device
//! anonymous-register cap (`rl:anon-register:dev:*`). On sign-out the ML-KEM
//! keypair is reset instead (`commands::auth::logout`), so the post-quantum key
//! does not link the next account on the machine to this one.
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

use crate::utils::safe_fs::OwnedDir;
#[cfg(test)]
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

/// A fresh `desktop_<uuid-v4>` from the OS CSPRNG (`rand::rng()` is a
/// ChaCha stream seeded from it). RFC 4122 layout, version 4, variant 10.
fn generate() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b[..]);
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

/// Write `id` to `name` in `dir` via a uniquely-named staging file + rename,
/// so a crash mid-write can never leave a truncated ID that would then read as
/// invalid and rotate.
///
/// MR-1945 H1 (#287 review): through `dir` ([`OwnedDir`], held open for the
/// process lifetime), never a raw path. The elevated client rewrites this file
/// whenever the user deletes it, so a by-path create could otherwise be
/// redirected by a junction to overwrite an arbitrary file; here the staging
/// file is created new through a checked handle and renamed within the held
/// directory, owner-only on Unix.
fn persist(dir: &OwnedDir, name: &str, id: &str) -> Result<(), String> {
    // R5: created inside verified, held parents and held from then on; a
    // folder that cannot be verified is not written to.
    dir.ensure_held()
        .map_err(|e| format!("device id folder: {e}"))?;
    let tmp = format!("{name}.{:016x}.tmp", rand::random::<u64>());
    let written = dir
        .create_new(&tmp)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(id.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| dir.rename_within(&tmp, name));
    written.map_err(|e| {
        let _ = dir.remove_file(&tmp);
        format!("persist device id: {e}")
    })
}

/// The persisted-and-cached identifier. A struct (rather than bare statics) so
/// the tests can drive a private instance in a temp dir without touching the
/// process-wide one every other test reads.
struct DeviceIdStore {
    /// `None` = memory only (unit tests, or a platform without a config dir).
    loc: Option<(OwnedDir, String)>,
    cache: Mutex<Option<String>>,
}

impl DeviceIdStore {
    /// The store at `path` (tests, and a generic location). The directory the
    /// file sits in is the held/checked unit; the file's own name is the leaf.
    #[cfg(test)]
    fn new(path: Option<PathBuf>) -> Self {
        let loc = path.map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(FILE_NAME)
                .to_string();
            let root = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            (OwnedDir::new(root, &[]), name)
        });
        Self {
            loc,
            cache: Mutex::new(None),
        }
    }

    /// The store at `name` inside the app directory `dir` (production).
    fn new_in(dir: Option<OwnedDir>, name: &str) -> Self {
        Self {
            loc: dir.map(|dir| (dir, name.to_string())),
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
        let Some((dir, name)) = self.loc.as_ref() else {
            return generate();
        };
        if let Some(stored) = read_trimmed(dir, name) {
            if is_valid(&stored) {
                return stored;
            }
            tracing::warn!("Stored device identifier is malformed; generating a new one");
        }
        let id = generate();
        if let Err(e) = persist(dir, name, &id) {
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
        if let Some((dir, name)) = self.loc.as_ref() {
            if let Err(e) = persist(dir, name, &id) {
                tracing::warn!("Could not persist the rotated device identifier: {}", e);
                // Remove the stale file through the checked handle so the next
                // launch cannot resurrect the old identity.
                if let Err(e) = dir.remove_file(name) {
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

/// Read `name` in `dir` through the checked handle and trim it; `None` if it is
/// missing, unreadable, or not this app's file (a planted link is refused).
fn read_trimmed(dir: &OwnedDir, name: &str) -> Option<String> {
    use std::io::Read;
    let mut file = dir.open_rw(name).ok()?;
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    Some(text.trim().to_string())
}

/// The app directory holding the device id, beside `birdo_pq_v1.bin`
/// (`<config_local_dir>/BirdoVPN`). Memory-only under `cfg(test)`, so
/// `cargo test` never writes into the developer's profile and never rotates
/// their real install's identity.
///
/// Deliberately PER-USER, not the machine-wide `%ProgramData%`: the device id
/// is what the audit (C-8) made random precisely so it does NOT link the
/// Windows accounts on one machine, and a shared location would re-link them.
/// The MR-1945 risk is the elevated REWRITE by a crafted path, not the value's
/// location, so the directory is held open and every write goes through
/// [`OwnedDir`] (`file_log::hold_app_dirs` holds this same directory).
fn default_dir() -> Option<OwnedDir> {
    if cfg!(test) {
        return None;
    }
    dirs::config_local_dir().map(|base| OwnedDir::new(base, &["BirdoVPN"]))
}

static STORE: LazyLock<DeviceIdStore> =
    LazyLock::new(|| DeviceIdStore::new_in(default_dir(), FILE_NAME));

/// This install's device identifier (see the module docs).
pub fn get() -> String {
    STORE.get()
}

/// Rotate the identifier: called after a confirmed account deletion only,
/// never on sign-out (see the module docs). Never fails; problems are logged.
pub fn rotate() {
    STORE.rotate();
    tracing::info!("Device identifier rotated");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        assert!(default_dir().is_none());
        assert!(is_valid(&get()));
    }

    /// MR-1945 H1 (#287 review): a user can delete `device_id` to force the
    /// elevated client to rewrite it. If the directory is a junction, the
    /// create is refused and nothing lands behind it — the by-path rewrite can
    /// no longer be redirected into an arbitrary file.
    #[cfg(windows)]
    #[test]
    fn a_junctioned_directory_refuses_the_rewrite() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        crate::utils::safe_fs::tests::junction(&root.path().join("BirdoVPN"), &elsewhere);

        let dir = OwnedDir::new(root.path(), &["BirdoVPN"]);
        assert!(persist(&dir, FILE_NAME, "desktop_x").is_err());
        assert!(
            !elsewhere.join(FILE_NAME).exists(),
            "the id landed behind the junction"
        );
        // No stray staging file behind it either.
        let strays: Vec<_> = std::fs::read_dir(&elsewhere)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
    }

    /// A planted symlink at the id's name is not followed on the rewrite, and
    /// the id round-trips through the checked read.
    #[test]
    fn the_id_round_trips_through_the_checked_handle() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("BirdoVPN")).unwrap();
        let store =
            DeviceIdStore::new_in(Some(OwnedDir::new(root.path(), &["BirdoVPN"])), FILE_NAME);
        let id = store.get();
        assert!(is_valid(&id));
        let back =
            DeviceIdStore::new_in(Some(OwnedDir::new(root.path(), &["BirdoVPN"])), FILE_NAME);
        assert_eq!(back.get(), id, "stable across launches through OwnedDir");
    }
}
