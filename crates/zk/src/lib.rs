//! Zero-Knowledge proof system for private payments
//!
//! This crate provides:
//! - Pedersen commitments for balance hiding
//! - R1CS circuits for payment validity
//! - Groth16 proof generation and verification
//! - Nullifier system for double-spend prevention
//!
//! ## Architecture
//!
//! ```text
//! zk/
//!  ├─ commitment.rs  # Pedersen commitments on BN254
//!  ├─ circuit.rs     # R1CS constraint systems  
//!  ├─ proof.rs       # Groth16 prove/verify
//!  └─ nullifier.rs   # Double-spend prevention
//! ```
//!
//! ## Cryptographic Primitives
//!
//! ### Commitment Scheme (Pedersen)
//! ```text
//! C = g^balance * h^randomness (in G1)
//! ```
//!
//! ### ZK Circuit
//! ```text
//! Public inputs:
//!   - commitment_old (serialized)
//!   - commitment_new (serialized)
//!   - nullifier
//!
//! Private inputs:
//!   - balance_old
//!   - balance_new
//!   - randomness_old
//!   - randomness_new
//!   - amount
//!
//! Constraints:
//!   - balance_new == balance_old - amount
//!   - balance_old >= amount (range check via unsigned arithmetic)
//! ```
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use zk::{commitment::{PedersenParams, BalanceCommitment}, proof::{PaymentKeys, PaymentProof}};
//!
//! // Setup parameters (one-time, trusted setup)
//! let pedersen_params = PedersenParams::new();
//! let payment_keys = PaymentKeys::setup()?;
//!
//! // Commit to balances
//! let old_balance = BalanceCommitment::new(&pedersen_params, 100);
//! let new_balance = BalanceCommitment::new(&pedersen_params, 70);
//!
//! // Generate proof
//! let proof = PaymentProof::prove(&payment_keys, 100, 70, 30)?;
//!
//! // Verify proof
//! assert!(proof.verify(&payment_keys)?);
//! ```

pub mod commitment;
pub mod circuit;
pub mod proof;
pub mod nullifier;

// Re-export commonly used types
pub use commitment::{PedersenParams, Commitment, CommitmentOpening, BalanceCommitment};
pub use circuit::{PaymentCircuit, SimplePaymentCircuit};
pub use proof::{PaymentKeys, PaymentProof};
pub use nullifier::{Nullifier, NullifierRegistry};

/// Error types for ZK operations
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("Nullifier already spent")]
    NullifierAlreadySpent,

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_pedersen_commitment() {
        let mut rng = thread_rng();
        let params = PedersenParams::new();
        let balance = BalanceCommitment::new(&params, 100, &mut rng);
        
        // Verify commitment opens correctly
        assert!(balance.commitment.verify(&params, 100, &balance.opening.randomness));
    }

    #[test]
    fn test_nullifier_double_spend_prevention() {
        let mut registry = NullifierRegistry::new();
        let nullifier = Nullifier::compute(&[1u8; 32], &[2u8; 64], 1);
        
        // First spend succeeds
        assert!(registry.mark_spent(nullifier));
        
        // Double spend fails
        assert!(!registry.mark_spent(nullifier));
    }

    #[test]
    fn test_simple_payment_circuit() {
        use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

        let circuit = SimplePaymentCircuit {
            balance_old: Some(100u64),
            balance_new: Some(70u64),
            amount: Some(30u64),
        };

        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
