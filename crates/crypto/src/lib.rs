pub mod identity;
pub mod storage;

// Re-export main types
pub use identity::{Identity, NodeId, verify_signature};
pub use storage::{load_identity, save_identity, generate_with_mnemonic};
