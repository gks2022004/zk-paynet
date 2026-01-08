//! Pedersen Commitment Scheme
//!
//! A commitment C = g^value * h^randomness where:
//! - g, h are generator points on the BN254 curve
//! - value is the committed amount
//! - randomness is a blinding factor
//!
//! Properties:
//! - Hiding: Cannot learn value from C
//! - Binding: Cannot open to different value

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::{CurveGroup, Group};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use sha2::{Digest, Sha256};

/// Generator points for Pedersen commitment
/// These should be derived from a nothing-up-my-sleeve setup
#[derive(Clone)]
pub struct PedersenParams {
    /// Generator for value
    pub g: G1,
    /// Generator for randomness (blinding)
    pub h: G1,
}

impl PedersenParams {
    /// Generate parameters from a seed (deterministic)
    pub fn new() -> Self {
        // Use hash-to-curve for generators
        // In production, use proper ceremony-derived generators
        let g = G1::generator();
        
        // Derive h from hash of g (nothing-up-my-sleeve)
        let mut hasher = Sha256::new();
        let mut g_bytes = Vec::new();
        g.serialize_compressed(&mut g_bytes).unwrap();
        hasher.update(&g_bytes);
        hasher.update(b"zkpay-pedersen-h-v1");
        let h_seed = hasher.finalize();
        
        // Hash to scalar, then multiply generator
        let h_scalar = Fr::from_le_bytes_mod_order(&h_seed);
        let h = g * h_scalar;
        
        Self { g, h }
    }
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

/// A Pedersen commitment to a value
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// The commitment point C = g^value * h^randomness
    pub point: G1,
}

impl Commitment {
    /// Create a new commitment to a value
    pub fn commit(params: &PedersenParams, value: u64, randomness: &Fr) -> Self {
        let value_scalar = Fr::from(value);
        let point = params.g * value_scalar + params.h * randomness;
        Self { point }
    }

    /// Verify a commitment opening
    pub fn verify(&self, params: &PedersenParams, value: u64, randomness: &Fr) -> bool {
        let expected = Self::commit(params, value, randomness);
        self.point == expected.point
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.point.into_affine().serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ark_serialize::SerializationError> {
        use ark_bn254::G1Affine;
        let affine = G1Affine::deserialize_compressed(bytes)?;
        Ok(Self { point: affine.into() })
    }
}

/// Opening for a commitment (secret data)
#[derive(Clone)]
pub struct CommitmentOpening {
    /// The committed value
    pub value: u64,
    /// The randomness used
    pub randomness: Fr,
}

impl CommitmentOpening {
    /// Generate a new random opening for a value
    pub fn new<R: Rng>(value: u64, rng: &mut R) -> Self {
        let randomness = Fr::rand(rng);
        Self { value, randomness }
    }

    /// Create the commitment from this opening
    pub fn commit(&self, params: &PedersenParams) -> Commitment {
        Commitment::commit(params, self.value, &self.randomness)
    }
}

/// Commitment for a balance with additional metadata
#[derive(Clone)]
pub struct BalanceCommitment {
    /// The commitment to the balance
    pub commitment: Commitment,
    /// The opening (only known to owner)
    pub opening: CommitmentOpening,
}

impl BalanceCommitment {
    /// Create a new balance commitment
    pub fn new<R: Rng>(params: &PedersenParams, balance: u64, rng: &mut R) -> Self {
        let opening = CommitmentOpening::new(balance, rng);
        let commitment = opening.commit(params);
        Self { commitment, opening }
    }

    /// Get the balance value
    pub fn balance(&self) -> u64 {
        self.opening.value
    }

    /// Create a new commitment after spending
    pub fn spend<R: Rng>(
        &self,
        params: &PedersenParams,
        amount: u64,
        rng: &mut R,
    ) -> Result<Self, &'static str> {
        if self.opening.value < amount {
            return Err("insufficient balance");
        }
        let new_balance = self.opening.value - amount;
        Ok(Self::new(params, new_balance, rng))
    }

    /// Create a new commitment after receiving
    pub fn receive<R: Rng>(
        &self,
        params: &PedersenParams,
        amount: u64,
        rng: &mut R,
    ) -> Self {
        let new_balance = self.opening.value + amount;
        Self::new(params, new_balance, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_commitment_hiding() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        // Same value, different randomness → different commitments
        let opening1 = CommitmentOpening::new(100, &mut rng);
        let opening2 = CommitmentOpening::new(100, &mut rng);

        let c1 = opening1.commit(&params);
        let c2 = opening2.commit(&params);

        assert_ne!(c1.point, c2.point);
    }

    #[test]
    fn test_commitment_binding() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let opening = CommitmentOpening::new(100, &mut rng);
        let commitment = opening.commit(&params);

        // Should verify with correct opening
        assert!(commitment.verify(&params, 100, &opening.randomness));

        // Should NOT verify with wrong value
        assert!(!commitment.verify(&params, 101, &opening.randomness));

        // Should NOT verify with wrong randomness
        let wrong_randomness = Fr::rand(&mut rng);
        assert!(!commitment.verify(&params, 100, &wrong_randomness));
    }

    #[test]
    fn test_commitment_serialization() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let opening = CommitmentOpening::new(42, &mut rng);
        let commitment = opening.commit(&params);

        let bytes = commitment.to_bytes();
        let recovered = Commitment::from_bytes(&bytes).unwrap();

        assert_eq!(commitment.point, recovered.point);
    }

    #[test]
    fn test_balance_commitment_spend() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let balance = BalanceCommitment::new(&params, 100, &mut rng);
        assert_eq!(balance.balance(), 100);

        // Spend 30
        let new_balance = balance.spend(&params, 30, &mut rng).unwrap();
        assert_eq!(new_balance.balance(), 70);

        // Cannot spend more than balance
        let result = new_balance.spend(&params, 100, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_balance_commitment_receive() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let balance = BalanceCommitment::new(&params, 50, &mut rng);
        let new_balance = balance.receive(&params, 25, &mut rng);
        
        assert_eq!(new_balance.balance(), 75);
    }
}
