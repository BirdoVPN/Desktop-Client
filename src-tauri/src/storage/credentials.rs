//! Native keystore integration
//!
//! Securely stores authentication tokens and VPN keys in the platform keystore
//! (Windows Credential Manager / macOS Keychain / Linux Secret Service).

use keyring::Entry;
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroize;

// Build-time guard: refuse to compile against keyring's `mock` backend.
//
// keyring 3.x ships NO default features and picks its backend at compile time.
// With no `windows-native`/`apple-native`/secret-service feature enabled it
// resolves silently to `mock` — an in-memory store whose writes all succeed and
// whose reads all return NoEntry. Nothing errors; credentials simply evaporate.
// That is exactly what shipped as `keyring = "3.2"` (no features): tokens never
// reached any OS keystore, so every launch found no session, and the UI rendered
// a signed-in user with a blank identity ("Anonymous").
//
// These modules exist ONLY when the corresponding native backend is enabled, so
// referencing them turns that misconfiguration into a COMPILE error on every
// platform instead of a silent, ship-able data-loss bug. Do not delete: the
// runtime symptom is invisible without it.
#[allow(unused_imports)]
#[cfg(target_os = "macos")]
use keyring::macos as _keyring_native_backend_required;
#[allow(unused_imports)]
#[cfg(target_os = "linux")]
use keyring::secret_service as _keyring_native_backend_required;
#[allow(unused_imports)]
#[cfg(target_os = "windows")]
use keyring::windows as _keyring_native_backend_required;

const SERVICE_NAME: &str = "BirdoVPN";

/// Keys stored in credential manager
/// FIX-2-7: Removed stale WireguardPrivateKey variant. WireGuard private keys
/// are now generated client-side (FIX-1-1) and managed per-session, not persisted
/// in the credential store.
pub enum CredentialKey {
    AccessToken,
    RefreshToken,
}

impl CredentialKey {
    fn as_str(&self) -> &'static str {
        match self {
            CredentialKey::AccessToken => "access_token",
            CredentialKey::RefreshToken => "refresh_token",
        }
    }
}

/// Token pair for authentication
#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// CR-1 FIX: Zeroize auth tokens from heap memory when TokenPair is dropped.
impl Drop for TokenPair {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

pub struct CredentialStore;

impl CredentialStore {
    /// Store a string value securely
    pub fn store(key: CredentialKey, value: &str) -> Result<(), String> {
        let key_name = key.as_str();
        let entry = Entry::new(SERVICE_NAME, key_name)
            .map_err(|e| format!("Failed to create credential entry: {}", e))?;

        entry
            .set_password(value)
            .map_err(|e| format!("Failed to store credential: {}", e))?;

        tracing::debug!("Stored credential: {} (len={})", key_name, value.len());

        // Verify the write actually landed, in EVERY build, THROUGH A FRESH HANDLE.
        //
        // Two deliberate details, both learned from a real failure:
        //
        // 1. Not `#[cfg(debug_assertions)]`. This check used to be debug-only, so
        //    the builds users actually run never performed it. Credentials are
        //    written only at login and token refresh — a handful of times per
        //    session, never on a hot path — so the cost is irrelevant next to
        //    shipping a client that cannot remember a login.
        //
        // 2. A NEW `Entry`, not the one we just wrote through. keyring's in-memory
        //    `mock` backend keeps the secret inside the handle object, so reading
        //    back through the SAME handle succeeds even when nothing reached the
        //    OS keystore — a same-handle check would have sailed straight past the
        //    very bug this exists to catch. Only a second handle proves the value
        //    left the process.
        //
        // Callers treat a store failure as non-fatal (in-memory tokens still serve
        // the current session), so the worst case here is a loud log rather than
        // silent data loss.
        {
            let verifier = Entry::new(SERVICE_NAME, key_name)
                .map_err(|e| format!("Failed to open credential for verification: {}", e))?;
            match verifier.get_password() {
                Ok(mut stored) => {
                    // Verify content equality, not just length, then zeroize the
                    // read-back copy so the credential does not linger on the heap.
                    let matches = stored == value;
                    stored.zeroize();
                    if !matches {
                        tracing::error!(
                            "Credential verification failed: stored value != original (len {})",
                            value.len()
                        );
                        return Err("Credential verification failed".to_string());
                    }
                    tracing::debug!("Verified credential stored successfully: {}", key_name);
                }
                Err(e) => {
                    tracing::error!("Credential verification failed - could not re-read: {}", e);
                    return Err(format!("Failed to verify credential storage: {}", e));
                }
            }
        }

        Ok(())
    }

    /// Retrieve a string value
    pub fn retrieve(key: CredentialKey) -> Result<Option<String>, String> {
        let entry = Entry::new(SERVICE_NAME, key.as_str())
            .map_err(|e| format!("Failed to create credential entry: {}", e))?;

        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("Failed to retrieve credential: {}", e)),
        }
    }

    /// Delete a credential
    pub fn delete(key: CredentialKey) -> Result<(), String> {
        let entry = Entry::new(SERVICE_NAME, key.as_str())
            .map_err(|e| format!("Failed to create credential entry: {}", e))?;

        match entry.delete_credential() {
            Ok(_) => {
                tracing::debug!("Deleted credential: {}", key.as_str());
                Ok(())
            }
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(format!("Failed to delete credential: {}", e)),
        }
    }

    /// Clear all stored credentials
    #[allow(dead_code)] // Reserved: bulk wipe (logout uses clear_tokens; not yet wired)
    pub fn clear_all() -> Result<(), String> {
        let keys = [CredentialKey::AccessToken, CredentialKey::RefreshToken];

        for key in keys {
            Self::delete(key)?;
        }

        tracing::info!("Cleared all stored credentials");
        Ok(())
    }

    // ========================================================================
    // Instance methods for Tauri State compatibility
    // ========================================================================

    /// Store access and refresh tokens (instance method for State<CredentialStore>)
    pub fn store_tokens(&self, access: &str, refresh: &str) -> Result<(), String> {
        Self::store(CredentialKey::AccessToken, access)?;
        Self::store(CredentialKey::RefreshToken, refresh)?;
        Ok(())
    }

    /// Get stored tokens (instance method for State<CredentialStore>)
    pub fn get_tokens(&self) -> Result<TokenPair, String> {
        tracing::trace!("get_tokens: retrieving access_token");
        let access = match Self::retrieve(CredentialKey::AccessToken) {
            Ok(Some(token)) => {
                tracing::trace!("get_tokens: got access_token (len={})", token.len());
                token
            }
            Ok(None) => {
                tracing::trace!("get_tokens: access_token is None");
                return Err("No access token stored".to_string());
            }
            Err(e) => {
                tracing::warn!("get_tokens: error retrieving access_token: {}", e);
                return Err(e);
            }
        };

        tracing::trace!("get_tokens: retrieving refresh_token");
        let mut access = access;
        let refresh = match Self::retrieve(CredentialKey::RefreshToken) {
            Ok(Some(token)) => {
                tracing::trace!("get_tokens: got refresh_token (len={})", token.len());
                token
            }
            Ok(None) => {
                tracing::trace!("get_tokens: refresh_token is None");
                // Zeroize the already-retrieved access token: the early return
                // bypasses TokenPair's Drop impl that would normally wipe it.
                access.zeroize();
                return Err("No refresh token stored".to_string());
            }
            Err(e) => {
                tracing::warn!("get_tokens: error retrieving refresh_token: {}", e);
                access.zeroize();
                return Err(e);
            }
        };

        tracing::trace!("get_tokens: successfully retrieved both tokens");
        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
        })
    }

    /// Clear stored tokens (instance method for State<CredentialStore>)
    pub fn clear_tokens(&self) -> Result<(), String> {
        Self::delete(CredentialKey::AccessToken)?;
        Self::delete(CredentialKey::RefreshToken)?;
        Ok(())
    }

    /// Store a serializable value as JSON
    #[allow(dead_code)] // Reserved: generic JSON credential storage (not yet wired)
    pub fn store_json<T: Serialize>(key: CredentialKey, value: &T) -> Result<(), String> {
        let json = serde_json::to_string(value)
            .map_err(|e| format!("Failed to serialize value: {}", e))?;
        Self::store(key, &json)
    }

    /// Retrieve and deserialize a JSON value
    #[allow(dead_code)] // Reserved: generic JSON credential retrieval (not yet wired)
    pub fn retrieve_json<T: DeserializeOwned>(key: CredentialKey) -> Result<Option<T>, String> {
        match Self::retrieve(key)? {
            Some(json) => {
                let value = serde_json::from_str(&json)
                    .map_err(|e| format!("Failed to deserialize value: {}", e))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    /// A credential written through one `Entry` handle must be readable through
    /// a DIFFERENT handle — i.e. it actually reached the OS keystore.
    ///
    /// This is the test that would have caught the mock-backend bug. keyring's
    /// `mock` builder hands back a brand-new empty credential for every
    /// `Entry::new`, so a write via one handle is invisible to the next and this
    /// assertion fails. Against a real keystore it passes. The previous version
    /// of this test was an empty body with a "run manually on Windows" comment,
    /// so it passed unconditionally while credentials were being discarded.
    ///
    /// Uses a dedicated probe service so it can never disturb the user's real
    /// stored tokens, and deletes what it writes. Gated to Windows/macOS: a
    /// headless Linux CI runner has no D-Bus session for Secret Service, and a
    /// skipped test is better than a flaky one that trains people to ignore it.
    #[test]
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn credentials_survive_a_new_entry_handle() {
        const PROBE_SERVICE: &str = "BirdoVPN-backend-probe";
        const PROBE_USER: &str = "keystore-roundtrip";
        const PROBE_VALUE: &str = "birdo-probe-value-do-not-reuse";

        let writer = Entry::new(PROBE_SERVICE, PROBE_USER).expect("create probe entry");
        writer
            .set_password(PROBE_VALUE)
            .expect("write probe credential");

        // Deliberately a separate handle — this is the part the mock fails.
        let reader = Entry::new(PROBE_SERVICE, PROBE_USER).expect("reopen probe entry");
        let read_back = reader.get_password();

        // Clean up before asserting so a failure never leaves the probe behind.
        let _ = reader.delete_credential();

        assert_eq!(
            read_back.as_deref().ok(),
            Some(PROBE_VALUE),
            "credential did not survive a new Entry handle — keyring resolved to its \
             in-memory `mock` backend, meaning no login will ever persist. Enable the \
             platform's native backend feature in Cargo.toml."
        );
    }
}
