//! Protocol message types for ZK-Paynet
//!
//! This module defines all message types exchanged between nodes.
//! Messages are transport-agnostic and use bincode serialization.

use crypto::NodeId;
use serde::{Deserialize, Serialize};

// Support for serializing large arrays
use serde_big_array::BigArray;

/// Handshake message for peer authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// Ed25519 public key (32 bytes)
    pub ed25519_pubkey: [u8; 32],
    /// X25519 public key for key agreement (32 bytes)
    pub x25519_pubkey: [u8; 32],
    /// Signature over nonce (64 bytes)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Timestamp nonce (prevents replay)
    pub nonce: u64,
}

impl Handshake {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

/// Encrypted message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Recipient NodeID
    pub recipient: NodeId,
    /// Sender NodeID
    pub sender: NodeId,
    /// Encrypted payload
    pub ciphertext: Vec<u8>,
    /// Expiry timestamp (Unix seconds)
    pub expiry: u64,
    /// Nonce for AEAD (12 bytes for ChaCha20-Poly1305)
    pub nonce: [u8; 12],
}

impl Envelope {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Check if envelope has expired
    pub fn is_expired(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expiry
    }
}

/// Application-level message (before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Simple text message
    Text { content: String },
    /// Ping message
    Ping { timestamp: u64 },
    /// Pong response
    Pong { timestamp: u64 },
    /// Request stored messages from relay
    FetchMessages { requester: NodeId },
    /// Payment message (Phase 4)
    Payment {
        // Placeholder for ZK payment data
        data: Vec<u8>,
    },
}

impl Message {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;

    #[test]
    fn test_handshake_serialization() {
        let handshake = Handshake {
            ed25519_pubkey: [1u8; 32],
            x25519_pubkey: [2u8; 32],
            signature: [3u8; 64],
            nonce: 12345,
        };

        let bytes = handshake.to_bytes().unwrap();
        let decoded = Handshake::from_bytes(&bytes).unwrap();

        assert_eq!(handshake.ed25519_pubkey, decoded.ed25519_pubkey);
        assert_eq!(handshake.nonce, decoded.nonce);
    }

    #[test]
    fn test_envelope_serialization() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let envelope = Envelope {
            recipient: bob.node_id(),
            sender: alice.node_id(),
            ciphertext: vec![1, 2, 3, 4],
            expiry: 9999999999,
            nonce: [0u8; 12],
        };

        let bytes = envelope.to_bytes().unwrap();
        let decoded = Envelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope.recipient, decoded.recipient);
        assert_eq!(envelope.sender, decoded.sender);
        assert_eq!(envelope.ciphertext, decoded.ciphertext);
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::Text {
            content: "hello world".to_string(),
        };

        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();

        match decoded {
            Message::Text { content } => assert_eq!(content, "hello world"),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_envelope_expiry() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let alice = Identity::generate();
        let bob = Identity::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Expired envelope
        let expired = Envelope {
            recipient: bob.node_id(),
            sender: alice.node_id(),
            ciphertext: vec![],
            expiry: now - 1000,
            nonce: [0u8; 12],
        };
        assert!(expired.is_expired());

        // Valid envelope
        let valid = Envelope {
            recipient: bob.node_id(),
            sender: alice.node_id(),
            ciphertext: vec![],
            expiry: now + 3600,
            nonce: [0u8; 12],
        };
        assert!(!valid.is_expired());
    }
}
