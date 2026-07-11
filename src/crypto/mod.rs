//! Cryptography module for P2P CLI
//!
//! This module provides:
//! - Noise transport support and local encrypted-storage state
//! - Identity management (permanent Ed25519 keys for TOFU authentication)
//! - Storage encryption (AES-256-GCM for persistent message storage)

mod identity;
mod session;

pub use identity::IdentityManager;
pub use session::CryptoManager;
