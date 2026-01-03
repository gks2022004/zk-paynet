//! Encryption/decryption utilities using ChaCha20-Poly1305
//!
//! This module provides AEAD encryption for message payloads.
//! Session keys are derived from X25519 shared secrets.

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a ChaCha20-Poly1305 key from X25519 shared secret
///
/// Uses HKDF-SHA256 with domain separation
pub fn derive_encryption_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"zkpay-chacha20poly1305-v1", &mut okm)
        .expect("HKDF expand should never fail with valid output length");
    okm
}

/// Encrypt plaintext using ChaCha20-Poly1305
///
/// Returns (ciphertext, nonce)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext using ChaCha20-Poly1305
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"secret message";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"secret";

        let (ciphertext, nonce) = encrypt(&key1, plaintext).unwrap();
        
        // Wrong key should fail
        assert!(decrypt(&key2, &ciphertext, &nonce).is_err());
    }

    #[test]
    fn test_key_derivation() {
        let secret = [42u8; 32];
        let key1 = derive_encryption_key(&secret);
        let key2 = derive_encryption_key(&secret);

        // Same secret should produce same key
        assert_eq!(key1, key2);

        // Different secret should produce different key
        let different_secret = [43u8; 32];
        let key3 = derive_encryption_key(&different_secret);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = [42u8; 32];
        let plaintext = b"test";

        let (_, nonce1) = encrypt(&key, plaintext).unwrap();
        let (_, nonce2) = encrypt(&key, plaintext).unwrap();

        // Nonces should be different (random)
        assert_ne!(nonce1, nonce2);
    }
}
