use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// ZK-Paynet CLI - Private P2P Payment Protocol
#[derive(Parser)]
#[command(name = "zkpay")]
#[command(about = "ZK-private P2P payment protocol", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new identity
    Keygen {
        /// Output path for identity (default: ~/.zkpay/mnemonic.txt)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show your NodeID
    Id,

    /// Start a P2P node
    Node {
        /// Listen address (default: 0.0.0.0:9000)
        #[arg(short, long, default_value = "0.0.0.0:9000")]
        listen: String,

        /// Run in relay mode (store-and-forward)
        #[arg(long)]
        relay: bool,
    },

    /// Send a message to a peer  
    Send {
        /// Recipient NodeID (base58 or hex)
        recipient: String,

        /// Message content
        message: String,

        /// Peer address to connect to
        #[arg(short, long)]
        addr: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            keygen(output.as_deref()).await?;
        }
        Commands::Id => {
            show_id().await?;
        }
        Commands::Node { listen, relay } => {
            start_node(&listen, relay).await?;
        }
        Commands::Send {
            recipient,
            message,
            addr,
        } => {
            send_message(&recipient, &message, &addr).await?;
        }
    }

    Ok(())
}

async fn keygen(output: Option<&str>) -> anyhow::Result<()> {
    let path = output.map(PathBuf::from);
    let (identity, mnemonic) = crypto::generate_with_mnemonic(path.as_deref())?;

    println!("✅ Identity generated successfully!");
    println!("\n🔑 Mnemonic (SAVE THIS SECURELY):");
    println!("{}", mnemonic);
    println!("\n🆔 NodeID: {}", identity.node_id());
    println!("\n📁 Saved to: {}", path.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
            .join(".zkpay/mnemonic.txt")
    }).display());

    Ok(())
}

async fn show_id() -> anyhow::Result<()> {
    let identity = crypto::load_identity(None)?;
    println!("🆔 Your NodeID: {}", identity.node_id());
    println!("   (hex: {})", identity.node_id().to_hex());
    Ok(())
}

async fn start_node(listen_addr: &str, relay_mode: bool) -> anyhow::Result<()> {
    let identity = crypto::load_identity(None)?;
    
    println!("🚀 Starting ZK-Paynet node...");
    println!("🆔 NodeID: {}", identity.node_id());
    println!("📡 Listening on: {}", listen_addr);

    if relay_mode {
        println!("🔄 Mode: RELAY (store-and-forward)");
        start_relay_node(listen_addr, identity).await?;
    } else {
        println!("👤 Mode: PEER (normal node)");
        start_peer_node(listen_addr, identity).await?;
    }

    Ok(())
}

async fn start_peer_node(listen_addr: &str, identity: crypto::Identity) -> anyhow::Result<()> {
    use p2p::{QuicTransport, Transport};

    let mut transport = QuicTransport::new(identity);
    transport.listen(listen_addr).await?;

    println!("✅ Node started successfully!");
    println!("💡 Waiting for messages... (Ctrl+C to stop)");

    // Keep running
    loop {
        match transport.receive().await {
            Ok(envelope) => {
                println!("\n📨 Received message from: {}", envelope.sender);
                println!("   Encrypted payload: {} bytes", envelope.ciphertext.len());
            }
            Err(e) => {
                tracing::warn!("Error receiving message: {}", e);
            }
        }
    }
}

async fn start_relay_node(listen_addr: &str, identity: crypto::Identity) -> anyhow::Result<()> {
    use p2p::{QuicTransport, Transport};
    use std::sync::Arc;

    let relay = Arc::new(relay::Relay::new());
    let mut transport = QuicTransport::new(identity);
    
    transport.listen(listen_addr).await?;
    println!("✅ Relay started successfully!");
    
    // Spawn cleanup task
    let relay_clone = relay.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            relay_clone.cleanup_expired().await;
        }
    });

    // Handle messages
    loop {
        match transport.receive().await {
            Ok(envelope) => {
                if let Err(e) = relay.store_message(envelope).await {
                    tracing::warn!("Failed to store message: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Error receiving: {}", e);
            }
        }
    }
}

async fn send_message(recipient_str: &str, message: &str, addr: &str) -> anyhow::Result<()> {
    use crypto::NodeId;
    use p2p::{QuicTransport, Transport};
    use protocol::{encrypt, Envelope, Message};
    use std::time::{SystemTime, UNIX_EPOCH};

    let identity = crypto::load_identity(None)?;
    
    // Parse recipient NodeID
    let recipient = if recipient_str.len() == 64 {
        NodeId::from_hex(recipient_str)?
    } else {
        NodeId::from_base58(recipient_str)?
    };

    println!("📤 Sending to: {}", recipient);
    println!("🔗 Connecting to: {}", addr);

    let mut transport = QuicTransport::new(identity.clone());
    transport.connect(addr, recipient).await?;

    // Create message
    let msg = Message::Text {
        content: message.to_string(),
    };
    let plaintext = msg.to_bytes()?;

    // Placeholder encryption (will use proper session key later)
    let encryption_key = [0u8; 32];
    let (ciphertext, nonce) = encrypt(&encryption_key, &plaintext)?;

    let envelope = Envelope {
        recipient,
        sender: identity.node_id(),
        ciphertext,
        expiry: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600,
        nonce,
    };

    transport.send(envelope).await?;
    println!("✅ Message sent successfully!");

    Ok(())
}
