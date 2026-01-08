//! Channel Operations
//!
//! Core operations for managing payment channel state:
//! - Open channel
//! - Send payment (update state)
//! - Add/fulfill/cancel HTLCs
//! - Close channel (cooperative or unilateral)

use crate::state::{
    Channel, ChannelRole, ChannelState,
    ChannelStatus, Htlc, HtlcState, SignedChannelState,
};
use crypto::identity::Identity;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// Result of a channel operation
#[derive(Debug)]
pub enum OperationResult {
    /// Operation succeeded, state updated
    Success {
        new_state: SignedChannelState,
    },
    /// Operation requires peer signature
    NeedsPeerSignature {
        state_to_sign: ChannelState,
    },
    /// Operation failed
    Failed {
        reason: String,
    },
}

/// Channel manager for handling channel lifecycle
pub struct ChannelOperations;

impl ChannelOperations {
    /// Sign a channel state with our identity
    pub fn sign_state(identity: &Identity, state: &ChannelState) -> [u8; 64] {
        let hash = state.compute_hash();
        let sig = identity.sign(&hash);
        sig.to_bytes()
    }

    /// Verify a signature on a channel state
    pub fn verify_signature(
        pubkey: &ed25519_dalek::VerifyingKey,
        state: &ChannelState,
        signature: &[u8; 64],
    ) -> bool {
        use ed25519_dalek::Verifier;
        let hash = state.compute_hash();
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        pubkey.verify(&hash, &sig).is_ok()
    }

    /// Update channel state with a payment (transfer balance)
    pub fn send_payment(
        channel: &mut Channel,
        identity: &Identity,
        amount: u64,
    ) -> Result<SignedChannelState> {
        // Validate channel state
        if channel.status != ChannelStatus::Open {
            bail!("channel is not open");
        }

        if amount == 0 {
            bail!("payment amount must be positive");
        }

        // Check balance
        let our_balance = channel.our_balance();
        if our_balance < amount {
            bail!(
                "insufficient balance: have {}, need {}",
                our_balance,
                amount
            );
        }

        // Calculate new balances
        let (new_balance_a, new_balance_b) = match channel.role {
            ChannelRole::Initiator => {
                let state = &channel.current_state.state;
                (state.balance_a - amount, state.balance_b + amount)
            }
            ChannelRole::Responder => {
                let state = &channel.current_state.state;
                (state.balance_a + amount, state.balance_b - amount)
            }
        };

        // Create new state
        let new_state = channel.current_state.state.next_state(new_balance_a, new_balance_b);

        // Sign the new state
        let signature = Self::sign_state(identity, &new_state);

        // Create signed state with our signature
        let mut signed_state = SignedChannelState::new(new_state);
        match channel.role {
            ChannelRole::Initiator => signed_state.signature_a = Some(signature),
            ChannelRole::Responder => signed_state.signature_b = Some(signature),
        }

        Ok(signed_state)
    }

    /// Receive and process a state update from peer
    pub fn receive_state_update(
        channel: &mut Channel,
        identity: &Identity,
        peer_pubkey: &ed25519_dalek::VerifyingKey,
        incoming_state: SignedChannelState,
    ) -> Result<SignedChannelState> {
        let state = &incoming_state.state;

        // Verify sequence number
        if state.sequence <= channel.current_state.state.sequence {
            bail!(
                "stale state: incoming seq {} <= current seq {}",
                state.sequence,
                channel.current_state.state.sequence
            );
        }

        // Verify channel ID
        if state.channel_id != channel.channel_id() {
            bail!("channel ID mismatch");
        }

        // Verify total capacity is preserved
        if state.total_capacity() != channel.capacity() {
            bail!(
                "capacity changed: {} != {}",
                state.total_capacity(),
                channel.capacity()
            );
        }

        // Verify peer's signature
        let peer_sig = match channel.role {
            ChannelRole::Initiator => incoming_state.signature_b,
            ChannelRole::Responder => incoming_state.signature_a,
        };

        match peer_sig {
            Some(sig) => {
                if !Self::verify_signature(peer_pubkey, state, &sig) {
                    bail!("invalid peer signature");
                }
            }
            None => bail!("missing peer signature"),
        }

        // Counter-sign the state
        let our_sig = Self::sign_state(identity, state);

        let mut fully_signed = incoming_state.clone();
        match channel.role {
            ChannelRole::Initiator => fully_signed.signature_a = Some(our_sig),
            ChannelRole::Responder => fully_signed.signature_b = Some(our_sig),
        }

        // Archive current state and update
        channel.state_history.push(channel.current_state.clone());
        channel.current_state = fully_signed.clone();

        Ok(fully_signed)
    }

    /// Apply a fully-signed state update
    pub fn apply_signed_state(
        channel: &mut Channel,
        signed_state: SignedChannelState,
    ) -> Result<()> {
        // Verify both signatures are present
        if !signed_state.is_fully_signed() {
            bail!("state is not fully signed");
        }

        // Archive current state
        channel.state_history.push(channel.current_state.clone());

        // Apply new state
        channel.current_state = signed_state;

        Ok(())
    }

    /// Add an outgoing HTLC (Hash Time-Locked Contract)
    pub fn add_htlc(
        channel: &mut Channel,
        identity: &Identity,
        amount: u64,
        payment_hash: [u8; 32],
        timeout_secs: u64,
    ) -> Result<(SignedChannelState, Htlc)> {
        // Validate
        if channel.status != ChannelStatus::Open {
            bail!("channel is not open");
        }

        if amount < channel.config.min_htlc_amount {
            bail!(
                "HTLC amount {} below minimum {}",
                amount,
                channel.config.min_htlc_amount
            );
        }

        let pending_htlcs: Vec<_> = channel
            .current_state
            .state
            .htlcs
            .iter()
            .filter(|h| h.state == HtlcState::Pending)
            .collect();

        if pending_htlcs.len() >= channel.config.max_pending_htlcs {
            bail!("too many pending HTLCs");
        }

        // Check we have enough balance
        if channel.our_balance() < amount {
            bail!(
                "insufficient balance for HTLC: have {}, need {}",
                channel.our_balance(),
                amount
            );
        }

        // Create HTLC
        let htlc_id = channel.next_htlc_id;
        channel.next_htlc_id += 1;

        let htlc = Htlc::new_offered(htlc_id, amount, payment_hash, timeout_secs);

        // Create new state with HTLC (deduct from our balance)
        let (new_balance_a, new_balance_b) = match channel.role {
            ChannelRole::Initiator => {
                let state = &channel.current_state.state;
                (state.balance_a - amount, state.balance_b)
            }
            ChannelRole::Responder => {
                let state = &channel.current_state.state;
                (state.balance_a, state.balance_b - amount)
            }
        };

        let mut new_state = channel.current_state.state.next_state(new_balance_a, new_balance_b);
        new_state.htlcs.push(htlc.clone());

        // Sign
        let signature = Self::sign_state(identity, &new_state);
        let mut signed_state = SignedChannelState::new(new_state);
        match channel.role {
            ChannelRole::Initiator => signed_state.signature_a = Some(signature),
            ChannelRole::Responder => signed_state.signature_b = Some(signature),
        }

        Ok((signed_state, htlc))
    }

    /// Fulfill an HTLC with the preimage
    pub fn fulfill_htlc(
        channel: &mut Channel,
        identity: &Identity,
        htlc_id: u64,
        preimage: [u8; 32],
    ) -> Result<SignedChannelState> {
        // Find the HTLC
        let htlc_idx = channel
            .current_state
            .state
            .htlcs
            .iter()
            .position(|h| h.id == htlc_id && h.state == HtlcState::Pending)
            .ok_or_else(|| anyhow::anyhow!("HTLC not found or not pending"))?;

        let htlc = &channel.current_state.state.htlcs[htlc_idx];

        // Verify preimage
        if !htlc.verify_preimage(&preimage) {
            bail!("invalid preimage");
        }

        // Must be a received HTLC (we can only fulfill HTLCs sent to us)
        if htlc.offered {
            bail!("cannot fulfill our own offered HTLC");
        }

        let amount = htlc.amount;

        // Create new state: HTLC amount goes to us
        let (new_balance_a, new_balance_b) = match channel.role {
            ChannelRole::Initiator => {
                let state = &channel.current_state.state;
                (state.balance_a + amount, state.balance_b)
            }
            ChannelRole::Responder => {
                let state = &channel.current_state.state;
                (state.balance_a, state.balance_b + amount)
            }
        };

        let mut new_state = channel.current_state.state.next_state(new_balance_a, new_balance_b);
        
        // Update HTLC state
        new_state.htlcs[htlc_idx].state = HtlcState::Fulfilled;

        // Sign
        let signature = Self::sign_state(identity, &new_state);
        let mut signed_state = SignedChannelState::new(new_state);
        match channel.role {
            ChannelRole::Initiator => signed_state.signature_a = Some(signature),
            ChannelRole::Responder => signed_state.signature_b = Some(signature),
        }

        Ok(signed_state)
    }

    /// Timeout an expired HTLC (refund to sender)
    pub fn timeout_htlc(
        channel: &mut Channel,
        identity: &Identity,
        htlc_id: u64,
    ) -> Result<SignedChannelState> {
        // Find the HTLC
        let htlc_idx = channel
            .current_state
            .state
            .htlcs
            .iter()
            .position(|h| h.id == htlc_id && h.state == HtlcState::Pending)
            .ok_or_else(|| anyhow::anyhow!("HTLC not found or not pending"))?;

        let htlc = &channel.current_state.state.htlcs[htlc_idx];

        // Check if expired
        if !htlc.is_expired() {
            bail!("HTLC has not expired yet");
        }

        // Must be our offered HTLC to timeout
        if !htlc.offered {
            bail!("cannot timeout received HTLC");
        }

        let amount = htlc.amount;

        // Create new state: refund HTLC amount back to us
        let (new_balance_a, new_balance_b) = match channel.role {
            ChannelRole::Initiator => {
                let state = &channel.current_state.state;
                (state.balance_a + amount, state.balance_b)
            }
            ChannelRole::Responder => {
                let state = &channel.current_state.state;
                (state.balance_a, state.balance_b + amount)
            }
        };

        let mut new_state = channel.current_state.state.next_state(new_balance_a, new_balance_b);
        new_state.htlcs[htlc_idx].state = HtlcState::TimedOut;

        // Sign
        let signature = Self::sign_state(identity, &new_state);
        let mut signed_state = SignedChannelState::new(new_state);
        match channel.role {
            ChannelRole::Initiator => signed_state.signature_a = Some(signature),
            ChannelRole::Responder => signed_state.signature_b = Some(signature),
        }

        Ok(signed_state)
    }

    /// Initiate cooperative close
    pub fn initiate_close(
        channel: &mut Channel,
        identity: &Identity,
    ) -> Result<SignedChannelState> {
        if channel.status == ChannelStatus::Closed {
            bail!("channel is already closed");
        }

        // Check no pending HTLCs
        let pending_htlcs: Vec<_> = channel
            .current_state
            .state
            .htlcs
            .iter()
            .filter(|h| h.state == HtlcState::Pending)
            .collect();

        if !pending_htlcs.is_empty() {
            bail!("cannot close with {} pending HTLCs", pending_htlcs.len());
        }

        channel.status = ChannelStatus::Closing;

        // Create final state (same balances, incremented sequence)
        let state = &channel.current_state.state;
        let final_state = state.next_state(state.balance_a, state.balance_b);

        // Sign
        let signature = Self::sign_state(identity, &final_state);
        let mut signed_state = SignedChannelState::new(final_state);
        match channel.role {
            ChannelRole::Initiator => signed_state.signature_a = Some(signature),
            ChannelRole::Responder => signed_state.signature_b = Some(signature),
        }

        Ok(signed_state)
    }

    /// Complete cooperative close
    pub fn complete_close(
        channel: &mut Channel,
        final_state: SignedChannelState,
    ) -> Result<()> {
        if !final_state.is_fully_signed() {
            bail!("final state is not fully signed");
        }

        channel.current_state = final_state;
        channel.status = ChannelStatus::Closed;

        Ok(())
    }

    /// Mark channel as open (after funding confirmation)
    pub fn mark_open(channel: &mut Channel) {
        channel.status = ChannelStatus::Open;
    }
}

/// Generate a payment hash and preimage pair
pub fn generate_payment_pair() -> ([u8; 32], [u8; 32]) {
    let preimage: [u8; 32] = rand::random();
    let payment_hash = compute_payment_hash(&preimage);
    (payment_hash, preimage)
}

/// Compute payment hash from preimage
pub fn compute_payment_hash(preimage: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Channel, ChannelConfig, ChannelId};
    use crypto::identity::{Identity, NodeId};

    fn create_test_identity() -> Identity {
        Identity::generate()
    }

    fn create_test_channel() -> (Channel, Identity, Identity) {
        let alice_id = create_test_identity();
        let bob_id = create_test_identity();

        let alice_node_id = NodeId::from_ed25519_pubkey(alice_id.verifying_key());
        let bob_node_id = NodeId::from_ed25519_pubkey(bob_id.verifying_key());

        let mut channel = Channel::new_as_initiator(
            alice_node_id,
            bob_node_id,
            1000,
            500,
            ChannelConfig::default(),
        );
        ChannelOperations::mark_open(&mut channel);

        (channel, alice_id, bob_id)
    }

    #[test]
    fn test_sign_and_verify() {
        let identity = create_test_identity();
        let channel_id = ChannelId([0u8; 32]);
        let state = ChannelState::new(channel_id, 100, 200);

        let signature = ChannelOperations::sign_state(&identity, &state);
        
        assert!(ChannelOperations::verify_signature(
            identity.verifying_key(),
            &state,
            &signature
        ));
    }

    #[test]
    fn test_send_payment() {
        let (mut channel, alice_id, _bob_id) = create_test_channel();

        // Alice sends 100 to Bob
        let result = ChannelOperations::send_payment(&mut channel, &alice_id, 100);
        assert!(result.is_ok());

        let signed_state = result.unwrap();
        assert_eq!(signed_state.state.balance_a, 900);
        assert_eq!(signed_state.state.balance_b, 600);
        assert_eq!(signed_state.state.sequence, 1);
    }

    #[test]
    fn test_insufficient_balance() {
        let (mut channel, alice_id, _bob_id) = create_test_channel();

        // Try to send more than balance
        let result = ChannelOperations::send_payment(&mut channel, &alice_id, 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_payment_hash_preimage() {
        let (payment_hash, preimage) = generate_payment_pair();
        
        // Verify the hash
        let computed = compute_payment_hash(&preimage);
        assert_eq!(payment_hash, computed);
    }

    #[test]
    fn test_htlc_flow() {
        let (mut channel, alice_id, _bob_id) = create_test_channel();

        let (payment_hash, _preimage) = generate_payment_pair();

        // Add HTLC
        let result = ChannelOperations::add_htlc(
            &mut channel,
            &alice_id,
            100,
            payment_hash,
            3600,
        );
        assert!(result.is_ok());

        let (signed_state, htlc) = result.unwrap();
        assert_eq!(htlc.amount, 100);
        assert_eq!(signed_state.state.balance_a, 900); // 100 locked in HTLC
        assert_eq!(signed_state.state.htlcs.len(), 1);
    }
}
