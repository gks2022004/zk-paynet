//! Channel Protocol Messages
//!
//! Wire protocol for channel management between peers.
//! All messages are serialized with bincode and encrypted.

use crate::state::{ChannelConfig, ChannelId, SignedChannelState};
use serde::{Deserialize, Serialize};

/// Channel protocol message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChannelMessage {
    // ============================================
    // Channel Establishment
    // ============================================
    
    /// Request to open a new channel
    OpenChannel(OpenChannel),
    
    /// Accept channel open request
    AcceptChannel(AcceptChannel),
    
    /// Reject channel open request
    RejectChannel(RejectChannel),
    
    /// Channel is funded and ready
    ChannelReady(ChannelReady),

    // ============================================
    // State Updates
    // ============================================
    
    /// Propose a new channel state
    UpdateState(UpdateState),
    
    /// Accept proposed state update
    AcceptState(AcceptState),
    
    /// Reject proposed state update
    RejectState(RejectState),

    // ============================================
    // HTLC Management
    // ============================================
    
    /// Add a new HTLC
    AddHtlc(AddHtlc),
    
    /// Fulfill an HTLC with preimage
    FulfillHtlc(FulfillHtlc),
    
    /// Fail/cancel an HTLC
    FailHtlc(FailHtlc),

    // ============================================
    // Channel Close
    // ============================================
    
    /// Request cooperative close
    CloseChannel(CloseChannel),
    
    /// Accept close request
    AcceptClose(AcceptClose),
    
    /// Force close notification
    ForceClose(ForceClose),

    // ============================================
    // Misc
    // ============================================
    
    /// Ping for keepalive
    Ping(u64),
    
    /// Pong response
    Pong(u64),
    
    /// Error message
    Error(ErrorMessage),
}

impl ChannelMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization should not fail")
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get message type name for logging
    pub fn message_type(&self) -> &'static str {
        match self {
            ChannelMessage::OpenChannel(_) => "OpenChannel",
            ChannelMessage::AcceptChannel(_) => "AcceptChannel",
            ChannelMessage::RejectChannel(_) => "RejectChannel",
            ChannelMessage::ChannelReady(_) => "ChannelReady",
            ChannelMessage::UpdateState(_) => "UpdateState",
            ChannelMessage::AcceptState(_) => "AcceptState",
            ChannelMessage::RejectState(_) => "RejectState",
            ChannelMessage::AddHtlc(_) => "AddHtlc",
            ChannelMessage::FulfillHtlc(_) => "FulfillHtlc",
            ChannelMessage::FailHtlc(_) => "FailHtlc",
            ChannelMessage::CloseChannel(_) => "CloseChannel",
            ChannelMessage::AcceptClose(_) => "AcceptClose",
            ChannelMessage::ForceClose(_) => "ForceClose",
            ChannelMessage::Ping(_) => "Ping",
            ChannelMessage::Pong(_) => "Pong",
            ChannelMessage::Error(_) => "Error",
        }
    }
}

// ============================================
// Channel Establishment Messages
// ============================================

/// Request to open a new payment channel
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenChannel {
    /// Temporary channel ID (before funding)
    pub temp_channel_id: [u8; 32],
    /// Our funding amount
    pub funding_amount: u64,
    /// Requested peer funding amount
    pub push_amount: u64,
    /// Channel configuration we want
    pub config: ChannelConfig,
    /// Our node public key
    pub node_pubkey: [u8; 32],
    /// First commitment point
    pub first_commitment_point: [u8; 32],
}

/// Accept a channel open request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptChannel {
    /// Temporary channel ID from open request
    pub temp_channel_id: [u8; 32],
    /// Our funding contribution
    pub funding_amount: u64,
    /// Accepted configuration
    pub config: ChannelConfig,
    /// Our node public key  
    pub node_pubkey: [u8; 32],
    /// First commitment point
    pub first_commitment_point: [u8; 32],
}

/// Reject a channel open request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectChannel {
    /// Temporary channel ID
    pub temp_channel_id: [u8; 32],
    /// Reason for rejection
    pub reason: String,
}

/// Channel is funded and ready for use
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelReady {
    /// Final channel ID
    pub channel_id: ChannelId,
    /// Initial signed state
    pub initial_state: SignedChannelState,
}

// ============================================
// State Update Messages
// ============================================

/// Propose a new channel state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateState {
    /// Channel ID
    pub channel_id: ChannelId,
    /// New proposed state (with our signature)
    pub signed_state: SignedChannelState,
}

/// Accept a proposed state update
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptState {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Sequence number we're accepting
    pub sequence: u64,
    /// Our counter-signature (64 bytes)
    pub signature: Vec<u8>,
}

/// Reject a proposed state update
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectState {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Sequence number we're rejecting
    pub sequence: u64,
    /// Reason for rejection
    pub reason: String,
}

// ============================================
// HTLC Messages
// ============================================

/// Add a new HTLC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddHtlc {
    /// Channel ID
    pub channel_id: ChannelId,
    /// HTLC ID
    pub htlc_id: u64,
    /// Amount in smallest unit
    pub amount: u64,
    /// Payment hash (SHA256)
    pub payment_hash: [u8; 32],
    /// Expiry timestamp
    pub expiry: u64,
    /// Signed state with this HTLC
    pub signed_state: SignedChannelState,
}

/// Fulfill an HTLC with preimage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FulfillHtlc {
    /// Channel ID
    pub channel_id: ChannelId,
    /// HTLC ID being fulfilled
    pub htlc_id: u64,
    /// Preimage that hashes to payment_hash
    pub preimage: [u8; 32],
    /// Signed state after fulfillment
    pub signed_state: SignedChannelState,
}

/// Fail/cancel an HTLC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailHtlc {
    /// Channel ID
    pub channel_id: ChannelId,
    /// HTLC ID being failed
    pub htlc_id: u64,
    /// Failure reason
    pub reason: HtlcFailReason,
    /// Signed state after failure
    pub signed_state: SignedChannelState,
}

/// Reason for HTLC failure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HtlcFailReason {
    /// HTLC has expired
    Expired,
    /// Unknown payment hash
    UnknownPaymentHash,
    /// Insufficient funds
    InsufficientFunds,
    /// Route not found
    RouteNotFound,
    /// Temporary failure, can retry
    TemporaryFailure,
    /// Permanent failure
    PermanentFailure,
    /// Other reason
    Other(String),
}

// ============================================
// Channel Close Messages
// ============================================

/// Request cooperative channel close
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseChannel {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Final state with our signature
    pub final_state: SignedChannelState,
}

/// Accept cooperative close
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptClose {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Fully signed final state
    pub final_state: SignedChannelState,
}

/// Force close notification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForceClose {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Reason for force close
    pub reason: String,
    /// Latest state we have
    pub latest_state: SignedChannelState,
}

// ============================================
// Error Message
// ============================================

/// Generic error message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Channel ID (all zeros for connection-level errors)
    pub channel_id: ChannelId,
    /// Error code
    pub code: ErrorCode,
    /// Human-readable message
    pub message: String,
}

/// Error codes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Unknown error
    Unknown = 0,
    /// Invalid message format
    InvalidMessage = 1,
    /// Channel not found
    ChannelNotFound = 2,
    /// Invalid state
    InvalidState = 3,
    /// Invalid signature
    InvalidSignature = 4,
    /// Insufficient funds
    InsufficientFunds = 5,
    /// Protocol violation
    ProtocolViolation = 6,
    /// Timeout
    Timeout = 7,
    /// Channel closed
    ChannelClosed = 8,
}

impl ErrorMessage {
    /// Create a new error message
    pub fn new(channel_id: ChannelId, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            channel_id,
            code,
            message: message.into(),
        }
    }

    /// Create a connection-level error (no specific channel)
    pub fn connection_error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            channel_id: ChannelId([0u8; 32]),
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChannelState, SignedChannelState};

    #[test]
    fn test_message_serialization() {
        let msg = ChannelMessage::Ping(12345);
        let bytes = msg.to_bytes();
        let recovered = ChannelMessage::from_bytes(&bytes).unwrap();
        
        match recovered {
            ChannelMessage::Ping(n) => assert_eq!(n, 12345),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_open_channel_message() {
        let open = OpenChannel {
            temp_channel_id: [1u8; 32],
            funding_amount: 1000,
            push_amount: 0,
            config: ChannelConfig::default(),
            node_pubkey: [2u8; 32],
            first_commitment_point: [3u8; 32],
        };

        let msg = ChannelMessage::OpenChannel(open);
        let bytes = msg.to_bytes();
        let recovered = ChannelMessage::from_bytes(&bytes).unwrap();

        match recovered {
            ChannelMessage::OpenChannel(o) => {
                assert_eq!(o.funding_amount, 1000);
                assert_eq!(o.temp_channel_id, [1u8; 32]);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_error_message() {
        let error = ErrorMessage::new(
            ChannelId([1u8; 32]),
            ErrorCode::InvalidSignature,
            "signature verification failed",
        );

        let msg = ChannelMessage::Error(error);
        let bytes = msg.to_bytes();
        let recovered = ChannelMessage::from_bytes(&bytes).unwrap();

        match recovered {
            ChannelMessage::Error(e) => {
                assert_eq!(e.code, ErrorCode::InvalidSignature);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_message_types() {
        let msg = ChannelMessage::Ping(0);
        assert_eq!(msg.message_type(), "Ping");

        let msg = ChannelMessage::Pong(0);
        assert_eq!(msg.message_type(), "Pong");
    }
}
