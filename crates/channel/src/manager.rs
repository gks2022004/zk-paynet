//! Channel Manager
//!
//! High-level API for managing multiple payment channels.
//! Handles channel lifecycle, state management, and event routing.

use crate::messages::{
    AcceptChannel, AcceptClose, AcceptState, ChannelMessage, ChannelReady,
    CloseChannel, HtlcFailReason, OpenChannel, RejectChannel, UpdateState,
};
use crate::operations::ChannelOperations;
use crate::state::{
    Channel, ChannelConfig, ChannelId, ChannelRole,
};
use crypto::identity::{Identity, NodeId};
use anyhow::{bail, Result};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Events emitted by the channel manager
#[derive(Clone, Debug)]
pub enum ChannelEvent {
    /// New channel opened
    ChannelOpened {
        channel_id: ChannelId,
        peer: NodeId,
        capacity: u64,
    },
    /// Channel state updated
    StateUpdated {
        channel_id: ChannelId,
        sequence: u64,
        our_balance: u64,
        peer_balance: u64,
    },
    /// Payment received
    PaymentReceived {
        channel_id: ChannelId,
        amount: u64,
    },
    /// Payment sent
    PaymentSent {
        channel_id: ChannelId,
        amount: u64,
    },
    /// HTLC added
    HtlcAdded {
        channel_id: ChannelId,
        htlc_id: u64,
        amount: u64,
        payment_hash: [u8; 32],
    },
    /// HTLC fulfilled
    HtlcFulfilled {
        channel_id: ChannelId,
        htlc_id: u64,
        preimage: [u8; 32],
    },
    /// HTLC failed
    HtlcFailed {
        channel_id: ChannelId,
        htlc_id: u64,
        reason: HtlcFailReason,
    },
    /// Channel closing
    ChannelClosing {
        channel_id: ChannelId,
    },
    /// Channel closed
    ChannelClosed {
        channel_id: ChannelId,
        final_balance_ours: u64,
        final_balance_peer: u64,
    },
    /// Error occurred
    Error {
        channel_id: Option<ChannelId>,
        message: String,
    },
}

/// Pending channel open request
#[derive(Clone)]
struct PendingChannel {
    temp_channel_id: [u8; 32],
    peer_node_id: NodeId,
    our_funding: u64,
    peer_funding: u64,
    config: ChannelConfig,
    peer_pubkey: [u8; 32],
}

/// Channel manager for handling multiple channels
pub struct ChannelManager {
    /// Our identity for signing
    identity: Identity,
    /// Our node ID
    node_id: NodeId,
    /// Active channels by ID
    channels: HashMap<ChannelId, Channel>,
    /// Pending channel opens by temp ID
    pending_opens: HashMap<[u8; 32], PendingChannel>,
    /// Default channel configuration
    default_config: ChannelConfig,
    /// Event sender
    event_tx: Option<mpsc::UnboundedSender<ChannelEvent>>,
    /// Pending payments waiting for preimage (payment_hash -> channel_id, htlc_id)
    pending_payments: HashMap<[u8; 32], (ChannelId, u64)>,
}

impl ChannelManager {
    /// Create a new channel manager
    pub fn new(identity: Identity, config: ChannelConfig) -> Self {
        let node_id = NodeId::from_ed25519_pubkey(identity.verifying_key());
        
        Self {
            identity,
            node_id,
            channels: HashMap::new(),
            pending_opens: HashMap::new(),
            default_config: config,
            event_tx: None,
            pending_payments: HashMap::new(),
        }
    }

    /// Set event channel for receiving notifications
    pub fn set_event_channel(&mut self, tx: mpsc::UnboundedSender<ChannelEvent>) {
        self.event_tx = Some(tx);
    }


    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get a channel by ID
    pub fn get_channel(&self, channel_id: &ChannelId) -> Option<&Channel> {
        self.channels.get(channel_id)
    }

    /// Get all active channels
    pub fn active_channels(&self) -> impl Iterator<Item = &Channel> {
        self.channels.values().filter(|c| c.is_open())
    }

    /// Total balance across all channels
    pub fn total_balance(&self) -> u64 {
        self.channels.values().map(|c| c.our_balance()).sum()
    }

    /// Emit an event
    fn emit_event(&self, event: ChannelEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }

    // ========================================
    // Channel Open Flow
    // ========================================

    /// Initiate opening a new channel
    pub fn open_channel(
        &mut self,
        peer_node_id: NodeId,
        our_funding: u64,
        peer_funding: u64,
    ) -> Result<ChannelMessage> {
        // Validate funding amounts
        if our_funding < self.default_config.min_funding {
            bail!("funding amount too low");
        }
        if our_funding > self.default_config.max_funding {
            bail!("funding amount too high");
        }

        // Generate temporary channel ID
        let temp_channel_id: [u8; 32] = rand::random();

        // Create pending channel
        let pending = PendingChannel {
            temp_channel_id,
            peer_node_id,
            our_funding,
            peer_funding,
            config: self.default_config.clone(),
            peer_pubkey: [0u8; 32], // Will be filled by peer
        };

        self.pending_opens.insert(temp_channel_id, pending);

        // Create open message
        let open = OpenChannel {
            temp_channel_id,
            funding_amount: our_funding,
            push_amount: peer_funding,
            config: self.default_config.clone(),
            node_pubkey: *self.node_id.as_bytes(),
            first_commitment_point: rand::random(),
        };

        info!(
            "Opening channel with {} (funding: {})",
            peer_node_id.short_hex(),
            our_funding
        );

        Ok(ChannelMessage::OpenChannel(open))
    }

    /// Handle incoming open channel request
    pub fn handle_open_channel(
        &mut self,
        peer_node_id: NodeId,
        open: OpenChannel,
    ) -> Result<ChannelMessage> {
        // Validate
        if open.funding_amount < self.default_config.min_funding {
            return Ok(ChannelMessage::RejectChannel(RejectChannel {
                temp_channel_id: open.temp_channel_id,
                reason: "funding too low".into(),
            }));
        }

        // Store pending
        let pending = PendingChannel {
            temp_channel_id: open.temp_channel_id,
            peer_node_id,
            our_funding: open.push_amount, // They push to us
            peer_funding: open.funding_amount,
            config: open.config,
            peer_pubkey: open.node_pubkey,
        };

        self.pending_opens.insert(open.temp_channel_id, pending);

        // Accept
        let accept = AcceptChannel {
            temp_channel_id: open.temp_channel_id,
            funding_amount: open.push_amount,
            config: self.default_config.clone(),
            node_pubkey: *self.node_id.as_bytes(),
            first_commitment_point: rand::random(),
        };

        info!(
            "Accepting channel from {} (capacity: {})",
            peer_node_id.short_hex(),
            open.funding_amount + open.push_amount
        );

        Ok(ChannelMessage::AcceptChannel(accept))
    }

    /// Handle channel accept response
    pub fn handle_accept_channel(
        &mut self,
        accept: AcceptChannel,
    ) -> Result<ChannelMessage> {
        let pending = self.pending_opens.remove(&accept.temp_channel_id)
            .ok_or_else(|| anyhow::anyhow!("unknown channel"))?;

        // Create the channel
        let channel_id = ChannelId::derive(
            self.node_id.as_bytes(),
            &accept.node_pubkey,
            u64::from_le_bytes(accept.temp_channel_id[..8].try_into().unwrap()),
        );

        let mut channel = Channel::new_as_initiator(
            self.node_id,
            pending.peer_node_id,
            pending.our_funding,
            pending.peer_funding,
            pending.config,
        );

        // Update channel ID
        channel.current_state.state.channel_id = channel_id;

        // Sign initial state
        let signature = ChannelOperations::sign_state(&self.identity, &channel.current_state.state);
        channel.current_state.signature_a = Some(signature);

        // Mark as open
        ChannelOperations::mark_open(&mut channel);

        let ready = ChannelReady {
            channel_id,
            initial_state: channel.current_state.clone(),
        };

        self.channels.insert(channel_id, channel);

        self.emit_event(ChannelEvent::ChannelOpened {
            channel_id,
            peer: pending.peer_node_id,
            capacity: pending.our_funding + pending.peer_funding,
        });

        info!("Channel {} opened", channel_id.short_hex());

        Ok(ChannelMessage::ChannelReady(ready))
    }

    /// Handle channel ready message
    pub fn handle_channel_ready(&mut self, ready: ChannelReady) -> Result<()> {
        // Find pending channel
        let pending = self.pending_opens
            .values()
            .find(|p| {
                let derived_id = ChannelId::derive(
                    &p.peer_pubkey,
                    self.node_id.as_bytes(),
                    u64::from_le_bytes(p.temp_channel_id[..8].try_into().unwrap()),
                );
                derived_id == ready.channel_id
            })
            .cloned();

        if let Some(pending) = pending {
            self.pending_opens.remove(&pending.temp_channel_id);

            let mut channel = Channel::new_as_responder(
                self.node_id,
                pending.peer_node_id,
                ready.channel_id,
                pending.our_funding,
                pending.peer_funding,
                pending.config,
            );

            // Counter-sign
            let signature = ChannelOperations::sign_state(&self.identity, &ready.initial_state.state);
            channel.current_state = ready.initial_state;
            channel.current_state.signature_b = Some(signature);

            ChannelOperations::mark_open(&mut channel);

            self.emit_event(ChannelEvent::ChannelOpened {
                channel_id: ready.channel_id,
                peer: pending.peer_node_id,
                capacity: pending.our_funding + pending.peer_funding,
            });

            self.channels.insert(ready.channel_id, channel);
            info!("Channel {} ready", ready.channel_id.short_hex());
        }

        Ok(())
    }

    // ========================================
    // Payment Flow
    // ========================================

    /// Send a direct payment (no HTLC)
    pub fn send_payment(
        &mut self,
        channel_id: &ChannelId,
        amount: u64,
    ) -> Result<ChannelMessage> {
        let channel = self.channels.get_mut(channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let signed_state = ChannelOperations::send_payment(channel, &self.identity, amount)?;

        let update = UpdateState {
            channel_id: *channel_id,
            signed_state,
        };

        debug!(
            "Sending {} to channel {}",
            amount,
            channel_id.short_hex()
        );

        Ok(ChannelMessage::UpdateState(update))
    }

    /// Handle incoming state update
    pub fn handle_update_state(
        &mut self,
        peer_pubkey: &ed25519_dalek::VerifyingKey,
        update: UpdateState,
    ) -> Result<ChannelMessage> {
        let channel = self.channels.get_mut(&update.channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        // Process and counter-sign
        let fully_signed = ChannelOperations::receive_state_update(
            channel,
            &self.identity,
            peer_pubkey,
            update.signed_state,
        )?;

        let our_balance = channel.our_balance();
        let peer_balance = channel.peer_balance();
        let sequence = channel.sequence();
        let role = channel.role;

        // Return acceptance with our signature
        let our_sig = match role {
            ChannelRole::Initiator => fully_signed.signature_a.unwrap(),
            ChannelRole::Responder => fully_signed.signature_b.unwrap(),
        };

        self.emit_event(ChannelEvent::StateUpdated {
            channel_id: update.channel_id,
            sequence,
            our_balance,
            peer_balance,
        });

        Ok(ChannelMessage::AcceptState(AcceptState {
            channel_id: update.channel_id,
            sequence: fully_signed.state.sequence,
            signature: our_sig.to_vec(),
        }))
    }

    /// Handle state acceptance
    pub fn handle_accept_state(&mut self, accept: AcceptState) -> Result<()> {
        let channel = self.channels.get_mut(&accept.channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        // Convert Vec<u8> to [u8; 64]
        let sig: [u8; 64] = accept.signature.try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?;

        // Apply peer's counter-signature
        match channel.role {
            ChannelRole::Initiator => {
                channel.current_state.signature_b = Some(sig);
            }
            ChannelRole::Responder => {
                channel.current_state.signature_a = Some(sig);
            }
        }

        self.emit_event(ChannelEvent::PaymentSent {
            channel_id: accept.channel_id,
            amount: 0, // Would need to track this
        });

        debug!(
            "State {} accepted for channel {}",
            accept.sequence,
            accept.channel_id.short_hex()
        );

        Ok(())
    }

    // ========================================
    // Channel Close Flow
    // ========================================

    /// Initiate cooperative close
    pub fn close_channel(&mut self, channel_id: &ChannelId) -> Result<ChannelMessage> {
        let channel = self.channels.get_mut(channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let final_state = ChannelOperations::initiate_close(channel, &self.identity)?;

        self.emit_event(ChannelEvent::ChannelClosing {
            channel_id: *channel_id,
        });

        Ok(ChannelMessage::CloseChannel(CloseChannel {
            channel_id: *channel_id,
            final_state,
        }))
    }

    /// Handle close request
    pub fn handle_close_channel(
        &mut self,
        peer_pubkey: &ed25519_dalek::VerifyingKey,
        close: CloseChannel,
    ) -> Result<ChannelMessage> {
        let channel = self.channels.get_mut(&close.channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        // Verify and counter-sign
        let mut final_state = ChannelOperations::receive_state_update(
            channel,
            &self.identity,
            peer_pubkey,
            close.final_state,
        )?;

        // Complete close
        let final_balance_ours = channel.our_balance();
        let final_balance_peer = channel.peer_balance();
        
        ChannelOperations::complete_close(channel, final_state.clone())?;

        self.emit_event(ChannelEvent::ChannelClosed {
            channel_id: close.channel_id,
            final_balance_ours,
            final_balance_peer,
        });

        Ok(ChannelMessage::AcceptClose(AcceptClose {
            channel_id: close.channel_id,
            final_state,
        }))
    }

    /// Handle close acceptance
    pub fn handle_accept_close(&mut self, accept: AcceptClose) -> Result<()> {
        let channel = self.channels.get_mut(&accept.channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let final_balance_ours = channel.our_balance();
        let final_balance_peer = channel.peer_balance();

        ChannelOperations::complete_close(channel, accept.final_state)?;

        self.emit_event(ChannelEvent::ChannelClosed {
            channel_id: accept.channel_id,
            final_balance_ours,
            final_balance_peer,
        });

        info!("Channel {} closed", accept.channel_id.short_hex());

        Ok(())
    }

    // ========================================
    // Message Router
    // ========================================

    /// Process an incoming channel message
    pub fn process_message(
        &mut self,
        peer_node_id: NodeId,
        peer_pubkey: &ed25519_dalek::VerifyingKey,
        message: ChannelMessage,
    ) -> Result<Option<ChannelMessage>> {
        debug!("Processing {} from {}", message.message_type(), peer_node_id.short_hex());

        match message {
            ChannelMessage::OpenChannel(open) => {
                Ok(Some(self.handle_open_channel(peer_node_id, open)?))
            }
            ChannelMessage::AcceptChannel(accept) => {
                Ok(Some(self.handle_accept_channel(accept)?))
            }
            ChannelMessage::RejectChannel(reject) => {
                warn!("Channel rejected: {}", reject.reason);
                self.pending_opens.remove(&reject.temp_channel_id);
                Ok(None)
            }
            ChannelMessage::ChannelReady(ready) => {
                self.handle_channel_ready(ready)?;
                Ok(None)
            }
            ChannelMessage::UpdateState(update) => {
                Ok(Some(self.handle_update_state(peer_pubkey, update)?))
            }
            ChannelMessage::AcceptState(accept) => {
                self.handle_accept_state(accept)?;
                Ok(None)
            }
            ChannelMessage::RejectState(reject) => {
                warn!("State rejected: {}", reject.reason);
                Ok(None)
            }
            ChannelMessage::CloseChannel(close) => {
                Ok(Some(self.handle_close_channel(peer_pubkey, close)?))
            }
            ChannelMessage::AcceptClose(accept) => {
                self.handle_accept_close(accept)?;
                Ok(None)
            }
            ChannelMessage::Ping(nonce) => {
                Ok(Some(ChannelMessage::Pong(nonce)))
            }
            ChannelMessage::Pong(_) => {
                // Pong received, update last seen
                Ok(None)
            }
            ChannelMessage::Error(error) => {
                error!("Received error: {} - {}", error.code as u32, error.message);
                self.emit_event(ChannelEvent::Error {
                    channel_id: Some(error.channel_id),
                    message: error.message,
                });
                Ok(None)
            }
            _ => {
                // HTLC messages would be handled here
                debug!("Unhandled message type: {}", message.message_type());
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> ChannelManager {
        let identity = Identity::generate();
        ChannelManager::new(identity, ChannelConfig::default())
    }

    #[test]
    fn test_manager_creation() {
        let manager = create_test_manager();
        assert_eq!(manager.total_balance(), 0);
        assert_eq!(manager.active_channels().count(), 0);
    }

    #[test]
    fn test_channel_open_flow() {
        let mut alice = create_test_manager();
        let mut bob = create_test_manager();

        // Alice initiates
        let open_msg = alice.open_channel(bob.node_id(), 1000, 500).unwrap();

        // Bob receives and accepts
        let accept_msg = match open_msg {
            ChannelMessage::OpenChannel(open) => {
                bob.handle_open_channel(alice.node_id(), open).unwrap()
            }
            _ => panic!("expected OpenChannel"),
        };

        // Alice receives accept
        let ready_msg = match accept_msg {
            ChannelMessage::AcceptChannel(accept) => {
                alice.handle_accept_channel(accept).unwrap()
            }
            _ => panic!("expected AcceptChannel"),
        };

        // Bob receives ready
        match ready_msg {
            ChannelMessage::ChannelReady(ready) => {
                bob.handle_channel_ready(ready).unwrap();
            }
            _ => panic!("expected ChannelReady"),
        }

        // Both should have the channel now
        assert_eq!(alice.active_channels().count(), 1);
        assert_eq!(bob.active_channels().count(), 1);
    }
}
