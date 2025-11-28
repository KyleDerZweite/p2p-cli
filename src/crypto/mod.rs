//! Cryptography module for P2P CLI
//! 
//! This module provides:
//! - Session encryption (ephemeral RSA keys for message encryption)
//! - Identity management (permanent Ed25519 keys for TOFU authentication)
//! - Storage encryption (AES-256-GCM for persistent message storage)

mod session;
mod identity;

pub use session::CryptoManager;
pub use identity::IdentityManager;
