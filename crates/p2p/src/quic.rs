//! QUIC transport implementation with identity verification
//!
//! Uses Quinn for QUIC with self-signed certificates.
//! Identity verification is performed post-connection via handshake.

use anyhow::{Context, Result};
use async_trait::async_trait;
use crypto::{Identity, NodeId, verify_signature};
use ed25519_dalek::{Signature, VerifyingKey};
use protocol::{Envelope, Handshake, derive_encryption_key, encrypt, decrypt};
use quinn::{Endpoint, Connection, ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};

use crate::transport::Transport;

/// QUIC-based transport with identity verification
pub struct QuicTransport {
    identity: Identity,
    endpoint: Option<Endpoint>,
    connections: Arc<Mutex<HashMap<NodeId, PeerConnection>>>,
    incoming_envelopes: Arc<Mutex<Vec<Envelope>>>,
}

/// Per-peer connection state
struct PeerConnection {
    node_id: NodeId,
    connection: Connection,
    encryption_key: [u8; 32],
}

impl QuicTransport {
    /// Create a new QUIC transport with the given identity
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            endpoint: None,
            connections: Arc::new(Mutex::new(HashMap::new())),
            incoming_envelopes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Generate self-signed certificate for QUIC
    fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("failed to generate self-signed cert")?;
        
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .map_err(|e| anyhow::anyhow!("failed to serialize private key: {}", e))?;

        Ok((cert_der, key_der))
    }

    /// Create server config for Quinn
    fn create_server_config() -> Result<ServerConfig> {
        let (cert, key) = Self::generate_self_signed_cert()?;

        let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
            .context("failed to create server config")?;

        // Disable certificate verification - we'll do manual identity verification
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(0_u8.into());
        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Create client config for Quinn
    fn create_client_config() -> Result<ClientConfig> {
        // Create a client config that skips certificate verification
        // We perform manual NodeID verification instead
        let mut roots = rustls::RootCertStore::empty();
        
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(0_u8.into());
        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
    }

    /// Perform handshake with peer after QUIC connection
    async fn perform_handshake(&self, conn: &Connection, is_initiator: bool) -> Result<(NodeId, [u8; 32])> {
        let (mut send, mut recv) = conn.open_bi().await?;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        if is_initiator {
            // Send our handshake
            let handshake = Handshake {
                ed25519_pubkey: *self.identity.ed25519_public_key().as_bytes(),
                x25519_pubkey: *self.identity.x25519_public_key().as_bytes(),
                signature: self.identity.sign(&nonce.to_le_bytes()).to_bytes(),
                nonce,
            };

            let handshake_bytes = handshake.to_bytes()?;
            send.write_all(&(handshake_bytes.len() as u32).to_le_bytes()).await?;
            send.write_all(&handshake_bytes).await?;
            send.finish()?;

            // Receive peer's handshake
            let mut len_bytes = [0u8; 4];
            recv.read_exact(&mut len_bytes).await?;
            let len = u32::from_le_bytes(len_bytes) as usize;

            let mut handshake_data = vec![0u8; len];
            recv.read_exact(&mut handshake_data).await?;

            let peer_handshake = Handshake::from_bytes(&handshake_data)?;

            // Verify peer's signature
            let peer_ed25519_pubkey = VerifyingKey::from_bytes(&peer_handshake.ed25519_pubkey)?;
            let peer_signature = Signature::from_bytes(&peer_handshake.signature);
            verify_signature(&peer_ed25519_pubkey, &peer_handshake.nonce.to_le_bytes(), &peer_signature)?;

            // Derive NodeID and shared secret
            let peer_node_id = NodeId::from_ed25519_pubkey(&peer_ed25519_pubkey);
            let peer_x25519_pubkey = x25519_dalek::PublicKey::from(peer_handshake.x25519_pubkey);
            let shared_secret = self.identity.derive_shared_secret(&peer_x25519_pubkey);
            let encryption_key = derive_encryption_key(&shared_secret);

            Ok((peer_node_id, encryption_key))
        } else {
            // Receive peer's handshake first
            let mut len_bytes = [0u8; 4];
            recv.read_exact(&mut len_bytes).await?;
            let len = u32::from_le_bytes(len_bytes) as usize;

            let mut handshake_data = vec![0u8; len];
            recv.read_exact(&mut handshake_data).await?;

            let peer_handshake = Handshake::from_bytes(&handshake_data)?;

            // Verify peer's signature
            let peer_ed25519_pubkey = VerifyingKey::from_bytes(&peer_handshake.ed25519_pubkey)?;
            let peer_signature = Signature::from_bytes(&peer_handshake.signature);
            verify_signature(&peer_ed25519_pubkey, &peer_handshake.nonce.to_le_bytes(), &peer_signature)?;

            // Send our handshake
            let handshake = Handshake {
                ed25519_pubkey: *self.identity.ed25519_public_key().as_bytes(),
                x25519_pubkey: *self.identity.x25519_public_key().as_bytes(),
                signature: self.identity.sign(&nonce.to_le_bytes()).to_bytes(),
                nonce,
            };

            let handshake_bytes = handshake.to_bytes()?;
            send.write_all(&(handshake_bytes.len() as u32).to_le_bytes()).await?;
            send.write_all(&handshake_bytes).await?;
            send.finish()?;

            // Derive NodeID and shared secret
            let peer_node_id = NodeId::from_ed25519_pubkey(&peer_ed25519_pubkey);
            let peer_x25519_pubkey = x25519_dalek::PublicKey::from(peer_handshake.x25519_pubkey);
            let shared_secret = self.identity.derive_shared_secret(&peer_x25519_pubkey);
            let encryption_key = derive_encryption_key(&shared_secret);

            Ok((peer_node_id, encryption_key))
        }
    }

    /// Handle incoming connection
    async fn handle_incoming_connection(&self, conn: Connection) -> Result<()> {
        info!("Incoming QUIC connection from {}", conn.remote_address());

        let (peer_node_id, encryption_key) = self.perform_handshake(&conn, false).await?;

        info!("Handshake complete with peer: {}", peer_node_id);

        // Store connection
        let peer_conn = PeerConnection {
            node_id: peer_node_id,
            connection: conn.clone(),
            encryption_key,
        };

        self.connections.lock().await.insert(peer_node_id, peer_conn);

        // Spawn task to receive messages
        let connections = self.connections.clone();
        let incoming = self.incoming_envelopes.clone();
        
        tokio::spawn(async move {
            loop {
                match conn.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        // Read envelope
                        let mut len_bytes = [0u8; 4];
                        if recv.read_exact(&mut len_bytes).await.is_err() {
                            break;
                        }
                        let len = u32::from_le_bytes(len_bytes) as usize;

                        let mut envelope_data = vec![0u8; len];
                        if recv.read_exact(&mut envelope_data).await.is_err() {
                            break;
                        }

                        match Envelope::from_bytes(&envelope_data) {
                            Ok(envelope) => {
                                incoming.lock().await.push(envelope);
                            }
                            Err(e) => {
                                error!("Failed to decode envelope: {}", e);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            // Connection closed, cleanup
            connections.lock().await.remove(&peer_node_id);
            info!("Connection closed with peer: {}", peer_node_id);
        });

        Ok(())
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn listen(&mut self, addr: &str) -> Result<()> {
        let server_config = Self::create_server_config()?;
        let endpoint = Endpoint::server(server_config, addr.parse()?)?;

        info!("QUIC transport listening on {}", endpoint.local_addr()?);

        let connections_clone = self.connections.clone();
        let incoming_clone = self.incoming_envelopes.clone();
        let identity_clone = self.identity.clone();
        let endpoint_clone = endpoint.clone();

        // Spawn task to accept connections
        tokio::spawn(async move {
            let transport = QuicTransport {
                identity: identity_clone,
                endpoint: None,
                connections: connections_clone,
                incoming_envelopes: incoming_clone,
            };

            while let Some(incoming) = endpoint_clone.accept().await {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = transport.handle_incoming_connection(conn).await {
                            error!("Failed to handle incoming connection: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn connect(&mut self, addr: &str, expected_node_id: NodeId) -> Result<()> {
        let client_config = Self::create_client_config()?;
        
        let mut endpoint = self.endpoint.take().unwrap_or_else(|| {
            Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap()
        });

        endpoint.set_default_client_config(client_config);

        info!("Connecting to {}", addr);
        let conn = endpoint.connect(addr.parse()?, "localhost")?.await?;

        let (peer_node_id, encryption_key) = self.perform_handshake(&conn, true).await?;

        // Verify NodeID matches expected
        if peer_node_id != expected_node_id {
            anyhow::bail!("NodeID mismatch: expected {}, got {}", expected_node_id, peer_node_id);
        }

        info!("Connected to peer: {}", peer_node_id);

        let peer_conn = PeerConnection {
            node_id: peer_node_id,
            connection: conn,
            encryption_key,
        };

        self.connections.lock().await.insert(peer_node_id, peer_conn);
        self.endpoint = Some(endpoint);

        Ok(())
    }

    async fn send(&mut self, envelope: Envelope) -> Result<()> {
        let connections = self.connections.lock().await;
        let peer_conn = connections.get(&envelope.recipient)
            .ok_or_else(|| anyhow::anyhow!("not connected to {}", envelope.recipient))?;

        let envelope_bytes = envelope.to_bytes()?;

        let (mut send, _recv) = peer_conn.connection.open_bi().await?;
        send.write_all(&(envelope_bytes.len() as u32).to_le_bytes()).await?;
        send.write_all(&envelope_bytes).await?;
        send.finish()?;

        debug!("Sent envelope to {}", envelope.recipient);
        Ok(())
    }

    async fn receive(&mut self) -> Result<Envelope> {
        loop {
            {
                let mut incoming = self.incoming_envelopes.lock().await;
                if !incoming.is_empty() {
                    return Ok(incoming.remove(0));
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    fn local_addr(&self) -> Option<String> {
        self.endpoint.as_ref()
            .and_then(|e| e.local_addr().ok())
            .map(|addr| addr.to_string())
    }

    fn is_connected(&self, node_id: &NodeId) -> bool {
        // Note: This is not async, so we can't lock the mutex here
        // In a real implementation, this would need refactoring
        false
    }

    async fn disconnect(&mut self, node_id: &NodeId) -> Result<()> {
        let mut connections = self.connections.lock().await;
        if let Some(peer_conn) = connections.remove(node_id) {
            peer_conn.connection.close(0u32.into(), b"disconnect");
            info!("Disconnected from peer: {}", node_id);
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"shutdown");
        }
        info!("QUIC transport shutdown");
        Ok(())
    }
}

/// Certificate verifier that accepts all certificates
/// We do manual identity verification via Ed25519 handshake
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
