//! Windows Credential Manager integration
//!
//! Securely stores authentication tokens and VPN keys.

#![allow(dead_code)]

use keyring::Entry;
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroize;

const SERVICE_NAME: &str = "BirdoVPN";

/// Keys stored in credential manager
/// FIX-2-7: Removed stale WireguardPrivateKey variant. WireGuard private keys
/// are now generated client-side (FIX-1-1) and managed per-session, not persisted
/// in the credential store.
pub enum CredentialKey {
    AccessToken,
    RefreshToken,
    LastServer,
}

impl CredentialKey {
    fn as_str(&self) -> &'static str {
        match self {
            CredentialKey::AccessToken => "access_token",
            CredentialKey::RefreshToken => "refresh_token",
            CredentialKey::LastServer => "last_server",
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
        
        // Verify it was actually stored (debug builds only — avoid redundant
        // read-back in production since the Windows Credential Manager API is
        // atomic and the read blocks the calling thread).
        #[cfg(debug_assertions)]
        {
            match entry.get_password() {
                Ok(stored) => {
                    if stored.len() != value.len() {
                        tracing::error!("Credential verification failed: stored len {} != original len {}", stored.len(), value.len());
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
    pub fn clear_all() -> Result<(), String> {
        let keys = [
            CredentialKey::AccessToken,
            CredentialKey::RefreshToken,
            CredentialKey::LastServer,
        ];

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
            },
            Ok(None) => {
                tracing::trace!("get_tokens: access_token is None");
                return Err("No access token stored".to_string());
            },
            Err(e) => {
                tracing::warn!("get_tokens: error retrieving access_token: {}", e);
                return Err(e);
            }
        };
        
        tracing::trace!("get_tokens: retrieving refresh_token");
        let refresh = match Self::retrieve(CredentialKey::RefreshToken) {
            Ok(Some(token)) => {
                tracing::trace!("get_tokens: got refresh_token (len={})", token.len());
                token
            },
            Ok(None) => {
                tracing::trace!("get_tokens: refresh_token is None");
                return Err("No refresh token stored".to_string());
            },
            Err(e) => {
                tracing::warn!("get_tokens: error retrieving refresh_token: {}", e);
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
    pub fn store_json<T: Serialize>(key: CredentialKey, value: &T) -> Result<(), String> {
        let json = serde_json::to_string(value)
            .map_err(|e| format!("Failed to serialize value: {}", e))?;
        Self::store(key, &json)
    }

    /// Retrieve and deserialize a JSON value
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

    #[test]
    fn test_store_and_retrieve() {
        // This test requires Windows Credential Manager access
        // Run manually when testing on Windows
    }
}
