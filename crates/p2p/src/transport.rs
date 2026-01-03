//! P2P transport abstraction
//!
//! This module defines a trait for transport implementations.
//! Keeps protocol logic decoupled from specific transport (QUIC, UDP, etc.)

use anyhow::Result;
use async_trait::async_trait;
use crypto::NodeId;
use protocol::Envelope;

/// Trait for P2P transport implementations
#[async_trait]
pub trait Transport: Send + Sync {
    /// Start listening for incoming connections
    async fn listen(&mut self, addr: &str) -> Result<()>;

    /// Connect to a peer
    async fn connect(&mut self, addr: &str, expected_node_id: NodeId) -> Result<()>;

    /// Send an envelope to a peer
    async fn send(&mut self, envelope: Envelope) -> Result<()>;

    /// Receive an envelope (blocking)
    async fn receive(&mut self) -> Result<Envelope>;

    /// Get local listening address
    fn local_addr(&self) -> Option<String>;

    /// Check if connected to a specific peer
    fn is_connected(&self, node_id: &NodeId) -> bool;

    /// Disconnect from a peer
    async fn disconnect(&mut self, node_id: &NodeId) -> Result<()>;

    /// Shutdown the transport
    async fn shutdown(&mut self) -> Result<()>;
}
