# ZK crate - Zero-Knowledge Proof System

**Status:** Phase 3 (Planned)

This crate will implement the zero-knowledge proof system for private payments.

## Overview

The ZK proof system will enable users to prove payment validity without revealing:
- Transaction amounts
- Sender balances
- Receiver balances
- Transaction graph

## Architecture (Planned)

### Commitment Scheme
Pedersen commitments for hiding balances:
```
C = g^balance * h^randomness (mod p)
```

### ZK Circuit
Proves the following properties:
1. Sender owns the commitment
2. Sender has sufficient balance (`balance >= amount`)
3. New commitment is correctly computed
4. Nullifier is unique (prevents double-spending)

### Proof System
- **Backend:** Groth16 (arkworks)
- **Curve:** BN254 (Ethereum-compatible)
- **Setup:** Trusted ceremony or transparent alternative

## Dependencies (Phase 3)

Add to `Cargo.toml`:
```toml
ark-ff = "0.4"
ark-ec = "0.4"
ark-groth16 = "0.4"
ark-bn254 = "0.4"
ark-r1cs-std = "0.4"
ark-relations = "0.4"
ark-std = "0.4"
```

## Implementation Roadmap

### Week 5-6: Core Primitives
- [ ] Pedersen commitment implementation
- [ ] Commitment opening/verification
- [ ] Randomness generation

### Week 5-6: Circuit Definition
- [ ] Define R1CS constraints
- [ ] Balance constraint
- [ ] Range proof (balance >= amount)
- [ ] Commitment correctness
- [ ] Nullifier generation

### Week 5-6: Proof Generation
- [ ] Circuit witness generation
- [ ] Groth16 prove function
- [ ] Groth16 verify function
- [ ] Batch verification (optimization)

### Week 5-6: Testing
- [ ] Unit tests for commitments
- [ ] Circuit constraint tests
- [ ] Proof generation tests
- [ ] Verification tests
- [ ] Malleability attack tests

## Security Considerations

### Trusted Setup
- Use existing BN254 ceremony (Perpetual Powers of Tau)
- Or migrate to Halo2/Plonky2 (transparent)

### Nullifier System
- Ensure uniqueness across all transactions
- Store nullifier hashes only (privacy)
- Reject duplicate nullifiers

### Range Proofs
- Prove `balance >= amount` without revealing values
- Use lookup tables or range gadgets

## Performance Targets

| Operation | Target Time |
|-----------|-------------|
| Commitment generation | < 1ms |
| Proof generation | < 2s |
| Proof verification | < 50ms |
| Circuit size | < 100k constraints |

## Integration Points

### Protocol Integration (Phase 4)
```rust
// In protocol crate
pub struct PaymentMessage {
    pub commitment_sender_new: zk::Commitment,
    pub commitment_receiver_new: zk::Commitment,
    pub nullifier: zk::Nullifier,
    pub proof: zk::Proof,
}
```

### Solana Integration (Phase 7)
- On-chain proof verification
- Nullifier registry
- Commitment root storage

## References

- [Zcash Protocol Spec](https://zips.z.cash/protocol/protocol.pdf)
- [Tornado Cash Circuits](https://github.com/tornadocash/tornado-core)
- [Arkworks Documentation](https://arkworks.rs/)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)

## Deferred Until Phase 3

This crate intentionally remains minimal until Phase 1-2 (P2P messaging and relay) are proven stable.
