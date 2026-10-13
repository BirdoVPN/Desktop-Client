//! Randomness straight from the operating system's CSPRNG.
//!
//! Every key, seed and token that rand 0.8 drew from `rand::rngs::OsRng` comes
//! from here: the WireGuard X25519 secret, the ML-KEM seed, the OAuth PKCE
//! verifier and state. rand 0.10 renamed `OsRng` to `SysRng` and left it
//! fallible only (`TryRng`, no `fill_bytes`). The source is unchanged: both are
//! getrandom (`ProcessPrng` on Windows, `getentropy` on macOS, `getrandom(2)`
//! on Linux), so no userspace PRNG sits between the OS and the key.

use rand::TryRng;

/// Fill `dest` from the OS CSPRNG.
///
/// Panics if the OS cannot supply randomness, as `OsRng::fill_bytes` did.
/// No caller can recover from that, and none may go on with a buffer that is
/// only partly random.
pub fn fill(dest: &mut [u8]) {
    rand::rngs::SysRng
        .try_fill_bytes(dest)
        .expect("the operating system's random number generator failed");
}

/// A fresh X25519 static secret from the OS CSPRNG.
///
/// This is what `StaticSecret::random_from_rng(OsRng)` did: 32 random bytes,
/// clamped when the key is used (x25519-dalek 2.0.1, `x25519.rs`). It cannot
/// take rand 0.10's generator itself, because boringtun 0.7 builds
/// x25519-dalek 2 on rand_core 0.6.
pub fn x25519_static_secret() -> boringtun::x25519::StaticSecret {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    fill(bytes.as_mut_slice());
    boringtun::x25519::StaticSecret::from(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::PublicKey;

    #[test]
    fn fill_writes_every_byte() {
        // An all-zero 64-byte result has probability 2^-512: seeing one
        // means the call did not write the buffer.
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill(&mut a);
        fill(&mut b);
        assert_ne!(a, [0u8; 64]);
        assert_ne!(a, b, "two fills returned the same bytes");
    }

    #[test]
    fn fill_accepts_an_empty_buffer() {
        fill(&mut []);
    }

    #[test]
    fn x25519_secrets_are_fresh_and_agree() {
        let ours = x25519_static_secret();
        let theirs = x25519_static_secret();
        assert_ne!(ours.to_bytes(), theirs.to_bytes());
        // A usable key pair: Diffie-Hellman agrees from both sides.
        let shared_a = ours.diffie_hellman(&PublicKey::from(&theirs));
        let shared_b = theirs.diffie_hellman(&PublicKey::from(&ours));
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }
}
