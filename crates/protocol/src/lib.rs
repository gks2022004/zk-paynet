pub mod messages;
pub mod encryption;

// Re-export main types
pub use messages::{Handshake, Envelope, Message};
pub use encryption::{encrypt, decrypt, derive_encryption_key};
