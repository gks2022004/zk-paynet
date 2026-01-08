//! Nullifier System for Double-Spend Prevention
//!
//! A nullifier is computed as:
//! N = Hash(secret_key, commitment, nonce)
//!
//! Properties:
//! - Each commitment can only be spent once
//! - Nullifiers reveal nothing about the commitment
//! - Cannot compute nullifier without secret_key

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

/// A nullifier that prevents double-spending
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Compute nullifier from secret key and commitment data
    pub fn compute(secret_key: &[u8; 32], commitment_bytes: &[u8], nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zkpay-nullifier-v1");
        hasher.update(secret_key);
        hasher.update(commitment_bytes);
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self(bytes)
    }

    /// Convert to field element for circuit use
    pub fn to_field(&self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.0)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl serde::Serialize for Nullifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Nullifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(Self(bytes))
    }
}

/// Registry for tracking spent nullifiers
pub struct NullifierRegistry {
    /// Set of spent nullifiers
    nullifiers: std::collections::HashSet<Nullifier>,
}

impl NullifierRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            nullifiers: std::collections::HashSet::new(),
        }
    }

    /// Check if a nullifier has been spent
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Mark a nullifier as spent
    /// Returns false if already spent (double-spend attempt)
    pub fn mark_spent(&mut self, nullifier: Nullifier) -> bool {
        self.nullifiers.insert(nullifier)
    }

    /// Get number of spent nullifiers
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

impl Default for NullifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_computation() {
        let secret_key = [42u8; 32];
        let commitment = [1u8; 64];
        let nonce = 12345u64;

        let n1 = Nullifier::compute(&secret_key, &commitment, nonce);
        let n2 = Nullifier::compute(&secret_key, &commitment, nonce);

        // Same inputs should give same nullifier
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nullifier_uniqueness() {
        let secret_key = [42u8; 32];
        let commitment = [1u8; 64];

        // Different nonces should give different nullifiers
        let n1 = Nullifier::compute(&secret_key, &commitment, 1);
        let n2 = Nullifier::compute(&secret_key, &commitment, 2);

        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_hex_roundtrip() {
        let secret_key = [42u8; 32];
        let commitment = [1u8; 64];
        let nullifier = Nullifier::compute(&secret_key, &commitment, 1);

        let hex = nullifier.to_hex();
        let recovered = Nullifier::from_hex(&hex).unwrap();

        assert_eq!(nullifier, recovered);
    }

    #[test]
    fn test_nullifier_registry() {
        let mut registry = NullifierRegistry::new();

        let n1 = Nullifier([1u8; 32]);
        let n2 = Nullifier([2u8; 32]);

        // First spend should succeed
        assert!(!registry.is_spent(&n1));
        assert!(registry.mark_spent(n1));
        assert!(registry.is_spent(&n1));

        // Double-spend should fail
        assert!(!registry.mark_spent(n1));

        // Different nullifier should work
        assert!(!registry.is_spent(&n2));
        assert!(registry.mark_spent(n2));

        assert_eq!(registry.len(), 2);
    }
}
