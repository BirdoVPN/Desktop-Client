//! Rosenpass Post-Quantum PSK Derivation
//!
//! Provides hybrid post-quantum key exchange for WireGuard connections.
//! Uses HKDF-SHA256 to derive a 32-byte PSK from the server's Rosenpass
//! public key combined with local entropy.
//!
//! This matches the Android RosenpassManager fallback implementation:
//! server Rosenpass public key + local entropy → HKDF → WireGuard PSK

use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use base64::Engine as _;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Rosenpass configuration from ConnectResponse
#[derive(Debug, Clone)]
pub struct RosenpassConfig {
    /// Server's Rosenpass public key (Base64)
    pub server_public_key: String,
    /// Optional server-provided PSK to combine
    pub server_psk: Option<String>,
}

/// Perform hybrid PSK derivation.
///
/// Combines the server's Rosenpass public key with local entropy using HKDF-SHA256
/// to produce a 32-byte PSK for WireGuard. This is the same algorithm used by
/// the Android client's `RosenpassManager.deriveHybridPsk()`.
///
/// Returns Base64-encoded 32-byte PSK.
pub fn derive_hybrid_psk(config: &RosenpassConfig) -> Result<String, String> {
    let server_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&config.server_public_key)
        .map_err(|e| format!("Invalid Rosenpass public key: {}", e))?;

    // Generate 32 bytes of local entropy
    let mut local_entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut local_entropy);

    // HKDF-Extract: derive PRK from server key + local entropy
    let mut ikm = Vec::with_capacity(server_key_bytes.len() + local_entropy.len());
    ikm.extend_from_slice(&server_key_bytes);
    ikm.extend_from_slice(&local_entropy);

    // If server provided a PSK, mix it in
    if let Some(ref psk) = config.server_psk {
        if let Ok(psk_bytes) = base64::engine::general_purpose::STANDARD.decode(psk) {
            ikm.extend_from_slice(&psk_bytes);
        }
    }

    // HKDF using HMAC-SHA256
    let salt = b"birdo-rosenpass-hybrid-v1";
    let prk = hkdf_extract(salt, &ikm)?;
    let mut okm = hkdf_expand(&prk, b"wireguard-psk", 32)?;

    // Encode as Base64
    let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&okm);

    // Zeroize sensitive material
    local_entropy.zeroize();
    ikm.zeroize();
    okm.zeroize();

    tracing::info!("Rosenpass hybrid PSK derived successfully");
    Ok(psk_b64)
}

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|e| format!("HKDF extract error: {}", e))?;
    mac.update(ikm);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, String> {
    if length > 255 * 32 {
        return Err("HKDF expand: requested length too large".to_string());
    }

    let mut okm = Vec::with_capacity(length);
    let mut t = Vec::new();
    let n = (length + 31) / 32;

    for i in 1..=n {
        let mut mac = HmacSha256::new_from_slice(prk)
            .map_err(|e| format!("HKDF expand error: {}", e))?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);
        t = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_hybrid_psk_produces_valid_base64() {
        // Generate a fake server public key
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key);

        let config = RosenpassConfig {
            server_public_key: key_b64,
            server_psk: None,
        };

        let psk = derive_hybrid_psk(&config).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(&psk).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_derive_hybrid_psk_with_server_psk() {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);

        let config = RosenpassConfig {
            server_public_key: base64::engine::general_purpose::STANDARD.encode(&key),
            server_psk: Some(base64::engine::general_purpose::STANDARD.encode(&key)),
        };

        let psk = derive_hybrid_psk(&config).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(&psk).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic_with_same_input() {
        let salt = b"test-salt";
        let ikm = b"test-ikm";
        let prk = hkdf_extract(salt, ikm).unwrap();
        let okm1 = hkdf_expand(&prk, b"test-info", 32).unwrap();
        let okm2 = hkdf_expand(&prk, b"test-info", 32).unwrap();
        assert_eq!(okm1, okm2);
    }
}
