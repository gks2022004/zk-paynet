# ZK-Paynet

**Zero-Knowledge Private P2P Payment Protocol**

A privacy-preserving payment system built on Rust with ZK proofs, P2P messaging, and eventual Solana settlement.

## Project Vision

Build a production-grade private payment system where:
- Payments are peer-to-peer (no central authority)
- Amounts are hidden (zero-knowledge proofs)
- Balances are private (commitment schemes)
- No transaction graph (unlinkable transfers)
- Double-spend prevention (nullifiers)
- Settlement on Solana (optional on-chain finality)

## Workspace Structure

```
zk-paynet/
├── crates/
│   ├── crypto/      # Ed25519 identity, X25519 key agreement, deterministic derivation
│   ├── protocol/    # Message types, encryption (ChaCha20-Poly1305), serialization
│   ├── p2p/         # QUIC transport, identity-verified connections
│   ├── relay/       # Store-and-forward messaging for offline peers
│   ├── zk/          # Zero-knowledge proofs (Phase 3)
│   ├── cli/         # zkpay command-line interface
│   └── solana/      # On-chain settlement (Phase 7)
```

## Architecture

### Phase 1: Identity & Secure P2P COMPLETE

**Cryptographic Foundations:**
- **Ed25519:** Node identity and message signing
- **X25519:** ECDH key agreement (derived from Ed25519 seed via HKDF)
- **NodeID:** SHA256(ed25519_pubkey)
- **ChaCha20-Poly1305:** AEAD encryption for message payloads

**Key Derivation (Deterministic):**
```
Master Seed (32 bytes)
 ├─ Ed25519 keypair (identity, signing)
 └─ HKDF-SHA256("zkpay-x25519-v1") → X25519 private key (ECDH)
```

**Transport:**
- QUIC via Quinn (production-grade reliability)
- Self-signed certificates (identity verified via Ed25519 handshake)
- Manual NodeID verification: `SHA256(cert_pubkey) == NodeID`
- Session encryption via X25519 + ChaCha20-Poly1305

**Message Flow:**
```
Alice                          Bob
  |                             |
  |-- QUIC Connection -------->|
  |<-- TLS Handshake ----------|
  |                             |
  |-- Ed25519 Handshake ------>|  (verify NodeID)
  |<-- Ed25519 Response -------|
  |                             |
  |-- Encrypted Envelope ----->|  (ChaCha20-Poly1305)
```

### Phase 2: Store & Forward Relays COMPLETE

**Relay Features:**
- Accepts encrypted envelopes
- Stores by recipient NodeID
- TTL enforcement (24-hour default)
- Replay protection (message hash deduplication)
- Storage limits (1000 messages/recipient)

**Offline Messaging:**
1. Alice sends message to Bob (offline)
2. Relay stores encrypted envelope
3. Bob comes online, retrieves messages
4. Relay deletes after retrieval

### Phase 3: ZK Payment Engine (Planned - Week 5-6)

**Commitment Scheme:**
```
C = g^balance * h^randomness (mod p)
```

**ZK Circuit Constraints:**
- Owns commitment
- `balance >= amount`
- `new_balance = balance - amount`
- Nullifier uniqueness

**Tech Stack:**
- Arkworks (Groth16)
- BN254 curve (Ethereum-compatible)
- < 100k constraints target

### Phase 4-7: Payments, Double-Spend Prevention, Solana (Planned)

See [Project Roadmap](#-roadmap) below.

## Quick Start

### 1. Build the workspace
```bash
cargo build --release
```

### 2. Generate an identity
```bash
./target/release/zkpay keygen
# Outputs a 24-word BIP39 mnemonic - SAVE THIS!
```

### 3. Show your NodeID
```bash
./target/release/zkpay id
```

### 4. Start a relay node
```bash
# Terminal 1: Start relay
./target/release/zkpay node --listen 0.0.0.0:9000 --relay
```

### 5. Start peer nodes
```bash
# Terminal 2: Alice
./target/release/zkpay node --listen 0.0.0.0:9001

# Terminal 3: Bob  
./target/release/zkpay node --listen 0.0.0.0:9002
```

### 6. Send a message
```bash
# Alice sends to Bob
./target/release/zkpay send <bob_node_id> "hello bob" --addr 127.0.0.1:9002
```

## Development Roadmap

### Phase 0: Project Bootstrap (Complete)
- [x] Cargo workspace with 7 crates
- [x] Dependencies configured
- [x] All crates compile

### Phase 1: Identity & Secure P2P (Complete - Week 1-2)
- [x] Ed25519 keypair generation
- [x] X25519 key derivation (HKDF)
- [x] NodeID computation (SHA256)
- [x] BIP39 mnemonic support
- [x] QUIC transport (Quinn)
- [x] Ed25519 handshake protocol
- [x] ChaCha20-Poly1305 encryption
- [x] CLI: `keygen`, `id`, `node start`

**Milestone:** Two peers can exchange encrypted messages using only public keys.

### Phase 2: Store & Forward Relays (Complete - Week 3-4)
- [x] Relay storage (in-memory)
- [x] TTL enforcement
- [x] Replay protection
- [x] CLI: `node start --relay`

**Milestone:** Messages survive offline peers.

### Phase 3: ZK Payment Engine (Planned - Week 5-6)
- [ ] Add arkworks dependencies
- [ ] Pedersen commitments
- [ ] Payment circuit (R1CS)
- [ ] Groth16 prove/verify
- [ ] Local proof tests

**Milestone:** Generate and verify ZK proofs locally.

### Phase 4: Private P2P Payments (Planned - Week 7-8)
- [ ] Payment message protocol
- [ ] Commitment updates
- [ ] Proof transmission
- [ ] ACK protocol (application-level)

**Milestone:** Real private payments over P2P (no blockchain).

### Phase 5: Double-Spend Prevention (Planned - Week 9)
- [ ] Nullifier generation
- [ ] Relay nullifier registry
- [ ] Duplicate detection

**Milestone:** Cannot reuse funds.

### Phase 6: Security Hardening (Planned - Week 10)
- [ ] Replay attack tests
- [ ] Invalid proof tests
- [ ] Packet tampering tests
- [ ] Fuzzing
- [ ] Rate limiting

**Milestone:** All security tests pass.

### Phase 7: Solana Testnet Integration (Planned - Week 11-12)
- [ ] Solana program (Anchor)
- [ ] Commitment root storage
- [ ] Nullifier registry (on-chain)
- [ ] Proof verification (on-chain)
- [ ] Deposit/withdraw flows

**Milestone:** Settlement on Solana devnet.

## Security Model

### Trust Assumptions
1. **No trusted parties:** Pure P2P, no central authority
2. **Cryptographic guarantees:** Ed25519, X25519, ChaCha20-Poly1305
3. **ZK proofs:** Soundness, zero-knowledge, succinctness (Phase 3+)
4. **Relay trust:** Relays cannot decrypt messages (end-to-end encryption)

### Threat Model
- **Passive adversary:** Cannot decrypt messages
- **Active adversary:** Cannot forge signatures or proofs
- **Malicious relay:** Cannot read/modify messages
- **Double-spend:** Prevented by nullifiers (Phase 5+)

### Privacy Guarantees (Phase 4+)
- Amounts are hidden
- Balances are hidden
- Transaction graph is hidden
- Sender/receiver identities are hidden from blockchain (Phase 7)

## Testing

### Run all tests
```bash
cargo test --workspace
```

### Test specific crate
```bash
cargo test -p crypto
cargo test -p protocol
cargo test -p p2p
cargo test -p relay
```

### Integration test (manual)
```bash
# Terminal 1
cargo run --bin zkpay -- keygen
cargo run --bin zkpay -- node --listen 127.0.0.1:9001

# Terminal 2
cargo run --bin zkpay -- keygen
export NODE1_ID=$(cargo run --bin zkpay -- id | grep NodeID | awk '{print $3}')
cargo run --bin zkpay -- send $NODE1_ID "test" --addr 127.0.0.1:9001
```

## Technical Details

### Cryptographic Primitives

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| Identity | Ed25519 | 256-bit |
| Key Agreement | X25519 | 256-bit |
| Encryption | ChaCha20-Poly1305 | 256-bit |
| Hashing | SHA-256 | 256-bit |
| KDF | HKDF-SHA256 | 256-bit |

### Message Format
```rust
struct Envelope {
    recipient: NodeId,        // 32 bytes
    sender: NodeId,           // 32 bytes
    ciphertext: Vec<u8>,      // Variable
    expiry: u64,              // 8 bytes (Unix timestamp)
    nonce: [u8; 12],          // 12 bytes (ChaCha20)
}
```

### Performance Targets

| Operation | Target | Actual (Phase 1) |
|-----------|--------|------------------|
| Key derivation | < 10ms | ~2ms |
| Encryption | < 1ms | ~0.3ms |
| QUIC handshake | < 100ms | ~50ms |
| Message send | < 50ms | ~30ms |
| Relay storage | < 10ms | ~5ms |

## Development

### Prerequisites
- Rust 1.75+ (stable)
- tokio (async runtime)
- QUIC support (UDP)

### Build
```bash
cargo build
```

### Run with logging
```bash
RUST_LOG=debug cargo run --bin zkpay -- node --listen 0.0.0.0:9000
```

### Lint and format
```bash
cargo clippy --all-targets --all-features
cargo fmt --all
```

## Documentation

Generate docs:
```bash
cargo doc --no-deps --open
```

**Built with ❤️ in Rust**
