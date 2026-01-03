//! Filesystem-based identity storage

use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use std::fs;
use std::path::{Path, PathBuf};

use crate::identity::Identity;

/// Default directory for storing identity
fn default_identity_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkpay")
}

/// Load identity from seed file or mnemonic
pub fn load_identity(path: Option<&Path>) -> Result<Identity> {
    let identity_dir = default_identity_dir();
    
    // Try multiple file locations in order of preference
    let possible_paths = if let Some(p) = path {
        vec![p.to_path_buf()]
    } else {
        vec![
            identity_dir.join("mnemonic.txt"),  // Preferred: BIP39 mnemonic
            identity_dir.join("seed"),           // Legacy: hex seed
        ]
    };

    for seed_path in &possible_paths {
        if seed_path.exists() {
            let content = fs::read_to_string(seed_path)
                .context("failed to read identity file")?;

            let seed = if content.contains(' ') {
                // BIP39 mnemonic
                seed_from_mnemonic(&content)?
            } else {
                // Hex-encoded seed
                seed_from_hex(&content)?
            };

            return Ok(Identity::from_seed(seed));
        }
    }

    anyhow::bail!(
        "Identity file not found. Please run 'zkpay keygen' first.\nLooked in: {}",
        identity_dir.display()
    )
}

/// Save identity seed to file
pub fn save_identity(identity: &Identity, path: Option<&Path>) -> Result<()> {
    let identity_dir = path
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_identity_dir);

    fs::create_dir_all(&identity_dir)
        .context("failed to create identity directory")?;

    let seed_path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| identity_dir.join("seed"));

    // Save as hex
    let hex_seed = hex::encode(identity.seed());
    fs::write(&seed_path, hex_seed)
        .context("failed to write seed file")?;

    Ok(())
}

/// Generate and save a new identity with BIP39 mnemonic
pub fn generate_with_mnemonic(path: Option<&Path>) -> Result<(Identity, String)> {
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&seed)
        .context("failed to create mnemonic")?;

    let identity = Identity::from_seed(seed);

    // Save mnemonic to file
    let identity_dir = path
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_identity_dir);

    fs::create_dir_all(&identity_dir)
        .context("failed to create identity directory")?;

    let mnemonic_path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| identity_dir.join("mnemonic.txt"));

    fs::write(&mnemonic_path, mnemonic.to_string())
        .context("failed to write mnemonic file")?;

    Ok((identity, mnemonic.to_string()))
}

/// Restore identity from BIP39 mnemonic phrase
fn seed_from_mnemonic(phrase: &str) -> Result<[u8; 32]> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())
        .context("invalid mnemonic phrase")?;

    let entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        anyhow::bail!("mnemonic must be 24 words (256-bit entropy)");
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&entropy);
    Ok(seed)
}

/// Parse hex-encoded seed
fn seed_from_hex(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex.trim())
        .context("invalid hex encoding")?;

    if bytes.len() != 32 {
        anyhow::bail!("seed must be 32 bytes");
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_hex_seed_roundtrip() {
        let seed = [42u8; 32];
        let hex = hex::encode(seed);
        let decoded = seed_from_hex(&hex).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_mnemonic_generation() {
        let temp_dir = env::temp_dir().join("zkpay_test_mnemonic");
        let mnemonic_path = temp_dir.join("mnemonic.txt");

        let (identity1, mnemonic) = generate_with_mnemonic(Some(&mnemonic_path)).unwrap();

        // Verify it's a valid 24-word mnemonic
        assert_eq!(mnemonic.split_whitespace().count(), 24);

        // Restore from mnemonic
        let seed = seed_from_mnemonic(&mnemonic).unwrap();
        let identity2 = Identity::from_seed(seed);

        assert_eq!(identity1.node_id(), identity2.node_id());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
