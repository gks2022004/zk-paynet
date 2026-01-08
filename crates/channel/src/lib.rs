//! Payment Channel Implementation
//!
//! This crate implements off-chain payment channels for the ZK-Paynet protocol.
//! Payment channels allow instant, low-cost transactions between two parties
//! without requiring on-chain settlement for every payment.
//!
//! ## Features
//!
//! - **Two-party channels**: Direct channels between peers
//! - **State updates**: Off-chain balance updates with dual signatures
//! - **HTLCs**: Hash Time-Locked Contracts for conditional payments
//! - **Cooperative close**: Mutual agreement on final balances
//! - **Dispute resolution**: Ability to settle disputes on-chain
//!
//! ## Channel Lifecycle
//!
//! ```text
//! 1. OPEN
//!    Alice ──OpenChannel──> Bob
//!    Alice <──AcceptChannel── Bob
//!    Alice ──ChannelReady──> Bob
//!
//! 2. UPDATE (repeated)
//!    Alice ──UpdateState──> Bob    (Alice sends payment)
//!    Alice <──AcceptState── Bob
//!
//! 3. CLOSE
//!    Alice ──CloseChannel──> Bob
//!    Alice <──AcceptClose── Bob
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use channel::{ChannelManager, ChannelConfig};
//! use crypto::identity::Identity;
//!
//! // Create channel manager
//! let identity = Identity::generate();
//! let mut manager = ChannelManager::new(identity, ChannelConfig::default());
//!
//! // Open channel with peer
//! let open_msg = manager.open_channel(peer_node_id, 1000, 0)?;
//!
//! // Send payment
//! let update_msg = manager.send_payment(&channel_id, 100)?;
//!
//! // Close channel
//! let close_msg = manager.close_channel(&channel_id)?;
//! ```
//!
//! ## HTLC Flow
//!
//! HTLCs enable trustless multi-hop payments:
//!
//! ```text
//! 1. Sender creates payment_hash = SHA256(preimage)
//! 2. Sender adds HTLC with payment_hash
//! 3. Receiver reveals preimage to claim funds
//! 4. If timeout expires, sender reclaims funds
//! ```

pub mod state;
pub mod operations;
pub mod messages;
pub mod manager;

// Re-export commonly used types
pub use state::{
    Channel, ChannelConfig, ChannelId, ChannelRole, ChannelState, ChannelStatus,
    Htlc, HtlcState, SignedChannelState,
};
pub use operations::{ChannelOperations, generate_payment_pair, compute_payment_hash};
pub use messages::{
    ChannelMessage, OpenChannel, AcceptChannel, ChannelReady,
    UpdateState, AcceptState, AddHtlc, FulfillHtlc, FailHtlc,
    CloseChannel, AcceptClose, ErrorMessage, ErrorCode, HtlcFailReason,
};
pub use manager::{ChannelManager, ChannelEvent};

/// Channel error types
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("Channel not found: {0}")]
    NotFound(ChannelId),

    #[error("Channel not open")]
    NotOpen,

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("HTLC not found: {0}")]
    HtlcNotFound(u64),

    #[error("HTLC expired")]
    HtlcExpired,

    #[error("Invalid preimage")]
    InvalidPreimage,

    #[error("Too many pending HTLCs")]
    TooManyHtlcs,

    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::identity::{Identity, NodeId};

    #[test]
    fn test_full_channel_lifecycle() {
        // Setup two parties
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();

        let alice_node = NodeId::from_ed25519_pubkey(&alice_id.verifying_key());
        let bob_node = NodeId::from_ed25519_pubkey(&bob_id.verifying_key());

        let mut alice_mgr = ChannelManager::new(alice_id.clone(), ChannelConfig::default());
        let mut bob_mgr = ChannelManager::new(bob_id.clone(), ChannelConfig::default());

        // 1. Alice opens channel
        let open_msg = alice_mgr.open_channel(bob_node, 1000, 500).unwrap();
        let open = match open_msg {
            ChannelMessage::OpenChannel(o) => o,
            _ => panic!("expected OpenChannel"),
        };

        // 2. Bob accepts
        let accept_msg = bob_mgr.handle_open_channel(alice_node, open).unwrap();
        let accept = match accept_msg {
            ChannelMessage::AcceptChannel(a) => a,
            _ => panic!("expected AcceptChannel"),
        };

        // 3. Alice finalizes
        let ready_msg = alice_mgr.handle_accept_channel(accept).unwrap();
        let ready = match ready_msg {
            ChannelMessage::ChannelReady(r) => r,
            _ => panic!("expected ChannelReady"),
        };

        // 4. Bob receives ready
        bob_mgr.handle_channel_ready(ready).unwrap();

        // Both have open channels
        assert_eq!(alice_mgr.active_channels().count(), 1);
        assert_eq!(bob_mgr.active_channels().count(), 1);

        let alice_channel = alice_mgr.active_channels().next().unwrap();
        let channel_id = alice_channel.channel_id();

        // Initial balances: Alice=1000, Bob=500
        assert_eq!(alice_channel.our_balance(), 1000);
        assert_eq!(alice_channel.peer_balance(), 500);
    }

    #[test]
    fn test_htlc_payment_hash() {
        let (payment_hash, preimage) = generate_payment_pair();
        
        // Verify hash matches
        assert_eq!(compute_payment_hash(&preimage), payment_hash);
        
        // Different preimage gives different hash
        let other_preimage = [0u8; 32];
        assert_ne!(compute_payment_hash(&other_preimage), payment_hash);
    }

    #[test]
    fn test_channel_config_defaults() {
        let config = ChannelConfig::default();
        
        assert!(config.min_funding > 0);
        assert!(config.max_funding > config.min_funding);
        assert!(config.dispute_window_secs > 0);
        assert!(config.max_pending_htlcs > 0);
    }
}
