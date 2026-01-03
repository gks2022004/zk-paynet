//! Relay node implementation for store-and-forward messaging
//!
//! This module provides a relay that:
//! - Accepts encrypted envelopes
//! - Stores them by recipient NodeID
//! - Enforces TTL and storage limits
//! - Provides replay protection

use anyhow::Result;
use crypto::NodeId;
use protocol::Envelope;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Maximum messages per recipient
const MAX_MESSAGES_PER_RECIPIENT: usize = 1000;

/// Default TTL for messages (24 hours)
const DEFAULT_TTL_SECONDS: u64 = 86400;

/// In-memory relay storage
pub struct Relay {
    /// Messages indexed by recipient NodeID
    messages: Arc<RwLock<HashMap<NodeId, Vec<StoredMessage>>>>,
    /// Seen message hashes for replay protection
    seen_hashes: Arc<RwLock<HashMap<[u8; 32], u64>>>,
}

/// Message with metadata
#[derive(Debug, Clone)]
struct StoredMessage {
    envelope: Envelope,
    received_at: u64,
}

impl Relay {
    /// Create a new relay
    pub fn new() -> Self {
        Self {
            messages: Arc::new(RwLock::new(HashMap::new())),
            seen_hashes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a message for later retrieval
    pub async fn store_message(&self, envelope: Envelope) -> Result<()> {
        // Check if already expired
        if envelope.is_expired() {
            warn!("Rejecting expired envelope for {}", envelope.recipient);
            anyhow::bail!("envelope expired");
        }

        // Compute hash for replay protection
        let hash = Self::hash_envelope(&envelope);

        // Check if we've seen this message
        {
            let seen = self.seen_hashes.read().await;
            if seen.contains_key(&hash) {
                warn!("Rejecting duplicate envelope (replay attack)");
                anyhow::bail!("duplicate envelope");
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        // Store the message
        {
            let mut messages = self.messages.write().await;
            let recipient_messages = messages.entry(envelope.recipient).or_insert_with(Vec::new);

            // Enforce storage limit
            if recipient_messages.len() >= MAX_MESSAGES_PER_RECIPIENT {
                warn!(
                    "Storage limit reached for {}, dropping oldest message",
                    envelope.recipient
                );
                recipient_messages.remove(0);
            }

            recipient_messages.push(StoredMessage {
                envelope: envelope.clone(),
                received_at: now,
            });

            info!(
                "Stored message for {} (total: {})",
                envelope.recipient,
                recipient_messages.len()
            );
        }

        // Mark as seen
        {
            let mut seen = self.seen_hashes.write().await;
            seen.insert(hash, now);
        }

        Ok(())
    }

    /// Retrieve all messages for a recipient
    pub async fn retrieve_messages(&self, node_id: &NodeId) -> Vec<Envelope> {
        let mut messages = self.messages.write().await;

        if let Some(stored) = messages.remove(node_id) {
            info!("Retrieved {} messages for {}", stored.len(), node_id);
            stored.into_iter().map(|m| m.envelope).collect()
        } else {
            vec![]
        }
    }

    /// Clean up expired messages
    pub async fn cleanup_expired(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut total_removed = 0;

        // Clean up expired messages
        {
            let mut messages = self.messages.write().await;
            for (node_id, stored_messages) in messages.iter_mut() {
                let before = stored_messages.len();
                stored_messages.retain(|m| !m.envelope.is_expired());
                let removed = before - stored_messages.len();
                if removed > 0 {
                    debug!("Removed {} expired messages for {}", removed, node_id);
                    total_removed += removed;
                }
            }

            // Remove empty entries
            messages.retain(|_, v| !v.is_empty());
        }

        // Clean up old seen hashes (older than TTL)
        {
            let mut seen = self.seen_hashes.write().await;
            let before = seen.len();
            seen.retain(|_, timestamp| now - *timestamp < DEFAULT_TTL_SECONDS);
            let removed = before - seen.len();
            if removed > 0 {
                debug!("Removed {} old seen hashes", removed);
            }
        }

        if total_removed > 0 {
            info!("Cleanup complete: {} expired messages removed", total_removed);
        }

        total_removed
    }

    /// Get statistics
    pub async fn stats(&self) -> RelayStats {
        let messages = self.messages.read().await;
        let seen = self.seen_hashes.read().await;

        let total_messages: usize = messages.values().map(|v| v.len()).sum();
        let num_recipients = messages.len();

        RelayStats {
            total_messages,
            num_recipients,
            seen_hashes: seen.len(),
        }
    }

    /// Hash an envelope for replay protection
    fn hash_envelope(envelope: &Envelope) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(envelope.sender.as_bytes());
        hasher.update(envelope.recipient.as_bytes());
        hasher.update(&envelope.ciphertext);
        hasher.update(&envelope.nonce);
        hasher.finalize().into()
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay statistics
#[derive(Debug, Clone)]
pub struct RelayStats {
    pub total_messages: usize,
    pub num_recipients: usize,
    pub seen_hashes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let relay = Relay::new();
        let alice = Identity::generate();
        let bob = Identity::generate();

        let envelope = Envelope {
            recipient: bob.node_id(),
            sender: alice.node_id(),
            ciphertext: vec![1, 2, 3],
            expiry: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            nonce: [0u8; 12],
        };

        relay.store_message(envelope.clone()).await.unwrap();

        let retrieved = relay.retrieve_messages(&bob.node_id()).await;
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].ciphertext, envelope.ciphertext);
    }

    #[tokio::test]
    async fn test_replay_protection() {
        let relay = Relay::new();
        let alice = Identity::generate();
        let bob = Identity::generate();

        let envelope = Envelope {
            recipient: bob.node_id(),
            sender: alice.node_id(),
            ciphertext: vec![1, 2, 3],
            expiry: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            nonce: [0u8; 12],
        };

        relay.store_message(envelope.clone()).await.unwrap();
        
        // Second attempt should fail
        assert!(relay.store_message(envelope).await.is_err());
    }
}
