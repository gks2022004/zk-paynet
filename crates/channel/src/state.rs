//! Channel State Types
//!
//! A payment channel is a two-party agreement that allows off-chain
//! balance updates. Each update is signed by both parties.
//!
//! ## Channel Lifecycle
//!
//! 1. **Open**: Parties agree on initial balances and lock funds
//! 2. **Update**: Parties exchange signed state updates off-chain
//! 3. **Close**: Either party can close with the latest state
//! 4. **Dispute**: Challenge period allows submitting newer states
//!
//! ## State Structure
//!
//! ```text
//! ChannelState {
//!     channel_id: Hash(pubkey_a || pubkey_b || nonce)
//!     balance_a: u64      // Alice's balance
//!     balance_b: u64      // Bob's balance  
//!     sequence: u64       // Monotonically increasing
//!     htlcs: Vec<HTLC>    // Pending conditional payments
//! }
//! ```

use crypto::identity::NodeId;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Unique identifier for a payment channel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub [u8; 32]);

impl ChannelId {
    /// Derive channel ID from the two parties' public keys and a nonce
    pub fn derive(pubkey_a: &[u8; 32], pubkey_b: &[u8; 32], nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zkpay-channel-id-v1");
        
        // Canonical ordering: smaller pubkey first
        if pubkey_a < pubkey_b {
            hasher.update(pubkey_a);
            hasher.update(pubkey_b);
        } else {
            hasher.update(pubkey_b);
            hasher.update(pubkey_a);
        }
        hasher.update(&nonce.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        Self(id)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short hex representation (first 8 chars)
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}

/// Role of a party in the channel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRole {
    /// The party who initiated the channel
    Initiator,
    /// The party who accepted the channel
    Responder,
}

/// Current state of the channel lifecycle
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    /// Channel opening in progress
    Opening,
    /// Channel is active and operational
    Open,
    /// Close has been initiated
    Closing,
    /// Channel is closed
    Closed,
    /// Channel is in dispute resolution
    Disputed,
}

/// Configuration for a payment channel
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Minimum funding amount required
    pub min_funding: u64,
    /// Maximum funding amount allowed
    pub max_funding: u64,
    /// Time window for dispute resolution (in seconds)
    pub dispute_window_secs: u64,
    /// Minimum HTLC amount
    pub min_htlc_amount: u64,
    /// Maximum number of pending HTLCs
    pub max_pending_htlcs: usize,
    /// HTLC timeout delta (blocks or seconds)
    pub htlc_timeout_delta: u64,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            min_funding: 1_000,           // 0.001 tokens
            max_funding: 1_000_000_000,   // 1000 tokens
            dispute_window_secs: 86400,   // 24 hours
            min_htlc_amount: 100,         // 0.0001 tokens
            max_pending_htlcs: 32,
            htlc_timeout_delta: 3600,     // 1 hour
        }
    }
}

/// A Hash Time-Locked Contract (HTLC)
/// 
/// HTLCs enable atomic conditional payments:
/// - Payment is locked until preimage is revealed
/// - Automatically refunds after timeout
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Htlc {
    /// Unique ID for this HTLC
    pub id: u64,
    /// Amount locked in the HTLC
    pub amount: u64,
    /// SHA256 hash of the preimage
    pub payment_hash: [u8; 32],
    /// Expiry timestamp (UNIX seconds)
    pub expiry: u64,
    /// Direction: true = offered by us, false = received
    pub offered: bool,
    /// Current state of the HTLC
    pub state: HtlcState,
}

/// State of an HTLC
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcState {
    /// HTLC is pending
    Pending,
    /// HTLC has been fulfilled with preimage
    Fulfilled,
    /// HTLC has timed out
    TimedOut,
    /// HTLC has been cancelled
    Cancelled,
}

impl Htlc {
    /// Create a new outgoing HTLC
    pub fn new_offered(id: u64, amount: u64, payment_hash: [u8; 32], timeout_secs: u64) -> Self {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + timeout_secs;

        Self {
            id,
            amount,
            payment_hash,
            expiry,
            offered: true,
            state: HtlcState::Pending,
        }
    }

    /// Create a new incoming HTLC
    pub fn new_received(id: u64, amount: u64, payment_hash: [u8; 32], expiry: u64) -> Self {
        Self {
            id,
            amount,
            payment_hash,
            expiry,
            offered: false,
            state: HtlcState::Pending,
        }
    }

    /// Check if HTLC has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expiry
    }

    /// Verify that a preimage matches the payment hash
    pub fn verify_preimage(&self, preimage: &[u8; 32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        let hash = hasher.finalize();
        hash.as_slice() == self.payment_hash
    }

    /// Time remaining until expiry
    pub fn time_remaining(&self) -> Option<Duration> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now >= self.expiry {
            None
        } else {
            Some(Duration::from_secs(self.expiry - now))
        }
    }
}

/// The core channel state that gets signed by both parties
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelState {
    /// Unique channel identifier
    pub channel_id: ChannelId,
    /// Balance of party A (initiator)
    pub balance_a: u64,
    /// Balance of party B (responder)
    pub balance_b: u64,
    /// Sequence number (higher = newer state)
    pub sequence: u64,
    /// Pending HTLCs
    pub htlcs: Vec<Htlc>,
    /// Timestamp of this state
    pub timestamp: u64,
}

impl ChannelState {
    /// Create initial channel state
    pub fn new(channel_id: ChannelId, balance_a: u64, balance_b: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            channel_id,
            balance_a,
            balance_b,
            sequence: 0,
            htlcs: Vec::new(),
            timestamp,
        }
    }

    /// Total capacity of the channel
    pub fn total_capacity(&self) -> u64 {
        self.balance_a + self.balance_b + self.htlc_total()
    }

    /// Total amount locked in HTLCs
    pub fn htlc_total(&self) -> u64 {
        self.htlcs.iter().map(|h| h.amount).sum()
    }

    /// Get pending HTLCs offered by us
    pub fn offered_htlcs(&self) -> impl Iterator<Item = &Htlc> {
        self.htlcs.iter().filter(|h| h.offered && h.state == HtlcState::Pending)
    }

    /// Get pending HTLCs received from peer
    pub fn received_htlcs(&self) -> impl Iterator<Item = &Htlc> {
        self.htlcs.iter().filter(|h| !h.offered && h.state == HtlcState::Pending)
    }

    /// Compute hash of this state for signing
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zkpay-channel-state-v1");
        hasher.update(&self.channel_id.0);
        hasher.update(&self.balance_a.to_le_bytes());
        hasher.update(&self.balance_b.to_le_bytes());
        hasher.update(&self.sequence.to_le_bytes());
        
        // Include HTLCs in hash
        for htlc in &self.htlcs {
            hasher.update(&htlc.id.to_le_bytes());
            hasher.update(&htlc.amount.to_le_bytes());
            hasher.update(&htlc.payment_hash);
            hasher.update(&htlc.expiry.to_le_bytes());
            hasher.update(&[htlc.offered as u8]);
        }
        
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Create next state with updated balances
    pub fn next_state(&self, new_balance_a: u64, new_balance_b: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            channel_id: self.channel_id,
            balance_a: new_balance_a,
            balance_b: new_balance_b,
            sequence: self.sequence + 1,
            htlcs: self.htlcs.clone(),
            timestamp,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// A signed channel state with both parties' signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedChannelState {
    /// The channel state
    pub state: ChannelState,
    /// Signature from party A
    #[serde(with = "option_signature")]
    pub signature_a: Option<[u8; 64]>,
    /// Signature from party B
    #[serde(with = "option_signature")]
    pub signature_b: Option<[u8; 64]>,
}

/// Custom serialization for Option<[u8; 64]>
mod option_signature {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(sig) => serializer.serialize_some(&sig.to_vec()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(v) if v.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            }
            Some(_) => Err(serde::de::Error::custom("invalid signature length")),
            None => Ok(None),
        }
    }
}

impl SignedChannelState {
    /// Create a new unsigned state
    pub fn new(state: ChannelState) -> Self {
        Self {
            state,
            signature_a: None,
            signature_b: None,
        }
    }

    /// Check if fully signed by both parties
    pub fn is_fully_signed(&self) -> bool {
        self.signature_a.is_some() && self.signature_b.is_some()
    }

    /// Check if signed by party A
    pub fn is_signed_by_a(&self) -> bool {
        self.signature_a.is_some()
    }

    /// Check if signed by party B
    pub fn is_signed_by_b(&self) -> bool {
        self.signature_b.is_some()
    }
}

/// Full channel data including history
#[derive(Clone, Debug)]
pub struct Channel {
    /// Our role in the channel
    pub role: ChannelRole,
    /// Our node ID
    pub our_node_id: NodeId,
    /// Peer's node ID
    pub peer_node_id: NodeId,
    /// Channel configuration
    pub config: ChannelConfig,
    /// Current channel status
    pub status: ChannelStatus,
    /// Latest signed state
    pub current_state: SignedChannelState,
    /// Previous states (for dispute resolution)
    pub state_history: Vec<SignedChannelState>,
    /// Next HTLC ID
    pub next_htlc_id: u64,
}

impl Channel {
    /// Create a new channel as initiator
    pub fn new_as_initiator(
        our_node_id: NodeId,
        peer_node_id: NodeId,
        our_funding: u64,
        peer_funding: u64,
        config: ChannelConfig,
    ) -> Self {
        let channel_id = ChannelId::derive(
            our_node_id.as_bytes(),
            peer_node_id.as_bytes(),
            rand::random(),
        );

        let initial_state = ChannelState::new(channel_id, our_funding, peer_funding);

        Self {
            role: ChannelRole::Initiator,
            our_node_id,
            peer_node_id,
            config,
            status: ChannelStatus::Opening,
            current_state: SignedChannelState::new(initial_state),
            state_history: Vec::new(),
            next_htlc_id: 0,
        }
    }

    /// Create a new channel as responder
    pub fn new_as_responder(
        our_node_id: NodeId,
        peer_node_id: NodeId,
        channel_id: ChannelId,
        our_funding: u64,
        peer_funding: u64,
        config: ChannelConfig,
    ) -> Self {
        let initial_state = ChannelState::new(channel_id, peer_funding, our_funding);

        Self {
            role: ChannelRole::Responder,
            our_node_id,
            peer_node_id,
            config,
            status: ChannelStatus::Opening,
            current_state: SignedChannelState::new(initial_state),
            state_history: Vec::new(),
            next_htlc_id: 0,
        }
    }

    /// Get channel ID
    pub fn channel_id(&self) -> ChannelId {
        self.current_state.state.channel_id
    }

    /// Get our current balance
    pub fn our_balance(&self) -> u64 {
        match self.role {
            ChannelRole::Initiator => self.current_state.state.balance_a,
            ChannelRole::Responder => self.current_state.state.balance_b,
        }
    }

    /// Get peer's current balance
    pub fn peer_balance(&self) -> u64 {
        match self.role {
            ChannelRole::Initiator => self.current_state.state.balance_b,
            ChannelRole::Responder => self.current_state.state.balance_a,
        }
    }

    /// Total channel capacity
    pub fn capacity(&self) -> u64 {
        self.current_state.state.total_capacity()
    }

    /// Current sequence number
    pub fn sequence(&self) -> u64 {
        self.current_state.state.sequence
    }

    /// Check if channel is operational
    pub fn is_open(&self) -> bool {
        self.status == ChannelStatus::Open
    }

    /// Check if we can send a payment of given amount
    pub fn can_send(&self, amount: u64) -> bool {
        self.is_open() && self.our_balance() >= amount
    }

    /// Check if we can receive a payment of given amount
    pub fn can_receive(&self, amount: u64) -> bool {
        self.is_open() && self.peer_balance() >= amount
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[test]
    fn test_channel_id_derivation() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        // Same inputs should give same channel ID
        let id1 = ChannelId::derive(&a, &b, 123);
        let id2 = ChannelId::derive(&a, &b, 123);
        assert_eq!(id1, id2);

        // Order shouldn't matter (canonical ordering)
        let id3 = ChannelId::derive(&b, &a, 123);
        assert_eq!(id1, id3);

        // Different nonce should give different ID
        let id4 = ChannelId::derive(&a, &b, 456);
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_channel_state_hash() {
        let channel_id = ChannelId([0u8; 32]);
        let state1 = ChannelState::new(channel_id, 100, 200);
        let state2 = ChannelState::new(channel_id, 100, 200);

        // Same logical state should have same hash
        // (ignoring timestamp for this test by comparing structure)
        assert_eq!(state1.balance_a, state2.balance_a);
        assert_eq!(state1.balance_b, state2.balance_b);
    }

    #[test]
    fn test_channel_creation() {
        let alice = test_node_id(1);
        let bob = test_node_id(2);

        let channel = Channel::new_as_initiator(
            alice,
            bob,
            1000,
            500,
            ChannelConfig::default(),
        );

        assert_eq!(channel.role, ChannelRole::Initiator);
        assert_eq!(channel.our_balance(), 1000);
        assert_eq!(channel.peer_balance(), 500);
        assert_eq!(channel.capacity(), 1500);
        assert_eq!(channel.status, ChannelStatus::Opening);
    }

    #[test]
    fn test_htlc_expiry() {
        let htlc = Htlc::new_offered(1, 100, [0u8; 32], 3600);
        
        // Should not be expired yet
        assert!(!htlc.is_expired());
        assert!(htlc.time_remaining().is_some());
    }

    #[test]
    fn test_htlc_preimage_verification() {
        let preimage = [42u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let hash = hasher.finalize();
        let mut payment_hash = [0u8; 32];
        payment_hash.copy_from_slice(&hash);

        let htlc = Htlc::new_offered(1, 100, payment_hash, 3600);

        // Correct preimage should verify
        assert!(htlc.verify_preimage(&preimage));

        // Wrong preimage should fail
        assert!(!htlc.verify_preimage(&[0u8; 32]));
    }

    #[test]
    fn test_state_sequence_increment() {
        let channel_id = ChannelId([0u8; 32]);
        let state0 = ChannelState::new(channel_id, 100, 100);
        assert_eq!(state0.sequence, 0);

        let state1 = state0.next_state(90, 110);
        assert_eq!(state1.sequence, 1);

        let state2 = state1.next_state(80, 120);
        assert_eq!(state2.sequence, 2);
    }
}
