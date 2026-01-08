//! Groth16 Proof Generation and Verification
//!
//! This module provides:
//! - Trusted setup (key generation)
//! - Proof generation
//! - Proof verification

use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, Rng};
use anyhow::{Context, Result};

use crate::circuit::SimplePaymentCircuit;

/// Proving and verifying keys for the payment circuit
pub struct PaymentKeys {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
    pub prepared_vk: PreparedVerifyingKey<Bn254>,
}

impl PaymentKeys {
    /// Generate keys for the payment circuit (trusted setup)
    pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        let circuit = SimplePaymentCircuit::empty();
        
        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
            .map_err(|e| anyhow::anyhow!("setup failed: {:?}", e))?;
        
        let prepared_vk = prepare_verifying_key(&verifying_key);
        
        Ok(Self {
            proving_key,
            verifying_key,
            prepared_vk,
        })
    }

    /// Serialize proving key to bytes
    pub fn proving_key_to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.proving_key
            .serialize_compressed(&mut bytes)
            .context("failed to serialize proving key")?;
        Ok(bytes)
    }

    /// Serialize verifying key to bytes
    pub fn verifying_key_to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.verifying_key
            .serialize_compressed(&mut bytes)
            .context("failed to serialize verifying key")?;
        Ok(bytes)
    }

    /// Deserialize proving key from bytes
    pub fn proving_key_from_bytes(bytes: &[u8]) -> Result<ProvingKey<Bn254>> {
        ProvingKey::deserialize_compressed(bytes)
            .context("failed to deserialize proving key")
    }

    /// Deserialize verifying key from bytes
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
        VerifyingKey::deserialize_compressed(bytes)
            .context("failed to deserialize verifying key")
    }
}

/// A serializable proof
#[derive(Clone, Debug)]
pub struct PaymentProof {
    pub proof: Proof<Bn254>,
    pub public_inputs: Vec<Fr>,
}

impl PaymentProof {
    /// Generate a proof for a payment
    pub fn prove<R: Rng + CryptoRng>(
        proving_key: &ProvingKey<Bn254>,
        balance_old: u64,
        amount: u64,
        rng: &mut R,
    ) -> Result<Self> {
        if balance_old < amount {
            anyhow::bail!("insufficient balance");
        }

        let balance_new = balance_old - amount;
        let circuit = SimplePaymentCircuit::new(balance_old, amount);

        let proof = Groth16::<Bn254>::prove(proving_key, circuit, rng)
            .map_err(|e| anyhow::anyhow!("proof generation failed: {:?}", e))?;

        // Public input is balance_new
        let public_inputs = vec![Fr::from(balance_new)];

        Ok(Self {
            proof,
            public_inputs,
        })
    }

    /// Verify a proof
    pub fn verify(&self, prepared_vk: &PreparedVerifyingKey<Bn254>) -> Result<bool> {
        let result = Groth16::<Bn254>::verify_with_processed_vk(
            prepared_vk,
            &self.public_inputs,
            &self.proof,
        )
        .map_err(|e| anyhow::anyhow!("verification failed: {:?}", e))?;

        Ok(result)
    }

    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        
        // Serialize proof
        self.proof
            .serialize_compressed(&mut bytes)
            .context("failed to serialize proof")?;
        
        // Serialize public inputs count
        let num_inputs = self.public_inputs.len() as u32;
        bytes.extend_from_slice(&num_inputs.to_le_bytes());
        
        // Serialize public inputs
        for input in &self.public_inputs {
            input
                .serialize_compressed(&mut bytes)
                .context("failed to serialize public input")?;
        }
        
        Ok(bytes)
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(bytes);
        
        // Deserialize proof
        let proof = Proof::deserialize_compressed(&mut cursor)
            .context("failed to deserialize proof")?;
        
        // Read remaining bytes for public inputs
        let pos = cursor.position() as usize;
        let remaining = &bytes[pos..];
        
        if remaining.len() < 4 {
            anyhow::bail!("truncated public inputs");
        }
        
        let num_inputs = u32::from_le_bytes(remaining[..4].try_into()?) as usize;
        let mut cursor = Cursor::new(&remaining[4..]);
        
        let mut public_inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            let input = Fr::deserialize_compressed(&mut cursor)
                .context("failed to deserialize public input")?;
            public_inputs.push(input);
        }
        
        Ok(Self {
            proof,
            public_inputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup_and_prove() {
        let mut rng = thread_rng();
        
        // Setup (trusted ceremony)
        let keys = PaymentKeys::setup(&mut rng).unwrap();
        println!("Setup complete!");

        // Prove: spending 30 from balance of 100
        let proof = PaymentProof::prove(&keys.proving_key, 100, 30, &mut rng).unwrap();
        println!("Proof generated!");

        // Verify
        let is_valid = proof.verify(&keys.prepared_vk).unwrap();
        assert!(is_valid, "proof should be valid");
        println!("Proof verified!");
    }

    #[test]
    fn test_proof_serialization() {
        let mut rng = thread_rng();
        
        let keys = PaymentKeys::setup(&mut rng).unwrap();
        let proof = PaymentProof::prove(&keys.proving_key, 50, 20, &mut rng).unwrap();
        
        // Serialize
        let bytes = proof.to_bytes().unwrap();
        println!("Proof size: {} bytes", bytes.len());
        
        // Deserialize
        let recovered = PaymentProof::from_bytes(&bytes).unwrap();
        
        // Verify recovered proof
        let is_valid = recovered.verify(&keys.prepared_vk).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut rng = thread_rng();
        
        let keys = PaymentKeys::setup(&mut rng).unwrap();
        
        // Try to spend more than balance
        let result = PaymentProof::prove(&keys.proving_key, 50, 100, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_proof() {
        let mut rng = thread_rng();
        
        let keys = PaymentKeys::setup(&mut rng).unwrap();
        
        // Generate valid proof
        let mut proof = PaymentProof::prove(&keys.proving_key, 100, 30, &mut rng).unwrap();
        
        // Tamper with public input (claim different balance_new)
        proof.public_inputs[0] = Fr::from(999u64);
        
        // Should fail verification
        let is_valid = proof.verify(&keys.prepared_vk).unwrap();
        assert!(!is_valid, "tampered proof should be invalid");
    }
}
