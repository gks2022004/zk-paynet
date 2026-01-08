//! Identity module for Ed25519-based node identity and X25519 key derivation.
//!
//! This module implements deterministic key derivation from a master seed:
//! - Ed25519 keypair for signing and NodeID derivation
//! - X25519 keypair for ECDH key agreement (derived via HKDF)
//!
//! NodeID = SHA256(ed25519_pubkey)

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

// Derive serde traits directly for bincode compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create NodeID from Ed25519 public key via SHA256
    pub fn from_ed25519_pubkey(pubkey: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.as_bytes());
        let hash = hasher.finalize();
        NodeId(hash.into())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }

    /// Encode as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short hex representation (first 8 chars)
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Decode from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).context("invalid hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("NodeID must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(NodeId(arr))
    }

    /// Encode as base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// Decode from base58 string
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s).into_vec().context("invalid base58")?;
        if bytes.len() != 32 {
            anyhow::bail!("NodeID must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(NodeId(arr))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Complete node identity with Ed25519 and X25519 keys
#[derive(Clone)]
pub struct Identity {
    /// Master seed (32 bytes)
    seed: [u8; 32],
    /// Ed25519 signing key (for identity and signatures)
    ed25519_signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    ed25519_verifying_key: VerifyingKey,
    /// X25519 static secret (derived from seed for ECDH)
    x25519_secret: X25519StaticSecret,
    /// X25519 public key
    x25519_public: X25519PublicKey,
    /// NodeID derived from Ed25519 public key
    node_id: NodeId,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Derive identity from a master seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        // Derive Ed25519 keypair directly from seed
        let ed25519_signing_key = SigningKey::from_bytes(&seed);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        // Derive X25519 secret key using HKDF
        let x25519_secret_bytes = derive_x25519_key(&seed);
        let x25519_secret = X25519StaticSecret::from(x25519_secret_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Compute NodeID
        let node_id = NodeId::from_ed25519_pubkey(&ed25519_verifying_key);

        Identity {
            seed,
            ed25519_signing_key,
            ed25519_verifying_key,
            x25519_secret,
            x25519_public,
            node_id,
        }
    }

    /// Get the seed (for backup/export)
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get NodeID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get Ed25519 public key (for handshake)
    pub fn ed25519_public_key(&self) -> &VerifyingKey {
        &self.ed25519_verifying_key
    }

    /// Alias for ed25519_public_key (compatibility)
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.ed25519_verifying_key
    }

    /// Get X25519 public key (for key agreement)
    pub fn x25519_public_key(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    /// Sign a message with Ed25519
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.ed25519_signing_key.sign(message)
    }

    /// Derive shared secret with peer's X25519 public key
    pub fn derive_shared_secret(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        self.x25519_secret.diffie_hellman(peer_public).to_bytes()
    }
}

/// Derive X25519 private key from master seed using HKDF
///
/// Domain separation: "zkpay-x25519-v1"
fn derive_x25519_key(seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(b"zkpay-x25519-v1", &mut okm)
        .expect("HKDF expand should never fail with valid output length");
    okm
}

/// Verify an Ed25519 signature
pub fn verify_signature(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    public_key
        .verify(message, signature)
        .context("signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let seed = [42u8; 32];
        let identity1 = Identity::from_seed(seed);
        let identity2 = Identity::from_seed(seed);

        // Same seed should produce same identity
        assert_eq!(identity1.node_id(), identity2.node_id());
        assert_eq!(
            identity1.ed25519_public_key().as_bytes(),
            identity2.ed25519_public_key().as_bytes()
        );
        assert_eq!(
            identity1.x25519_public_key().as_bytes(),
            identity2.x25519_public_key().as_bytes()
        );
    }

    #[test]
    fn test_key_separation() {
        let identity = Identity::generate();
        
        // Ed25519 and X25519 keys should be different
        let ed_bytes = identity.ed25519_public_key().as_bytes();
        let x_bytes = identity.x25519_public_key().as_bytes();
        assert_ne!(ed_bytes, x_bytes);
    }

    #[test]
    fn test_signature_verification() {
        let identity = Identity::generate();
        let message = b"test message";
        
        let signature = identity.sign(message);
        assert!(verify_signature(identity.ed25519_public_key(), message, &signature).is_ok());
        
        // Wrong message should fail
        assert!(verify_signature(identity.ed25519_public_key(), b"wrong", &signature).is_err());
    }

    #[test]
    fn test_shared_secret() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let alice_shared = alice.derive_shared_secret(bob.x25519_public_key());
        let bob_shared = bob.derive_shared_secret(alice.x25519_public_key());

        // Both should derive same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_node_id_encoding() {
        let identity = Identity::generate();
        let node_id = identity.node_id();

        // Test hex round-trip
        let hex = node_id.to_hex();
        let decoded_hex = NodeId::from_hex(&hex).unwrap();
        assert_eq!(node_id, decoded_hex);

        // Test base58 round-trip
        let b58 = node_id.to_base58();
        let decoded_b58 = NodeId::from_base58(&b58).unwrap();
        assert_eq!(node_id, decoded_b58);
    }
}
