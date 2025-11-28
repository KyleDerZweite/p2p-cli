use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use std::path::Path;
use std::fs;

use crate::error::{P2PError, P2PResult};

/// Manages identity keys for TOFU (Trust on First Use) authentication
pub struct IdentityManager {
    /// Our permanent Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Our permanent Ed25519 verifying key (public)
    verifying_key: VerifyingKey,
    /// Path to the identity key file
    identity_path: String,
}

impl IdentityManager {
    /// Create or load identity manager
    pub fn new<P: AsRef<Path>>(identity_path: P) -> P2PResult<Self> {
        let path = identity_path.as_ref();
        
        if path.exists() {
            Self::load_from_file(identity_path)
        } else {
            Self::generate_new(identity_path)
        }
    }

    /// Generate a new identity key pair
    fn generate_new<P: AsRef<Path>>(identity_path: P) -> P2PResult<Self> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let manager = Self {
            signing_key,
            verifying_key,
            identity_path: identity_path.as_ref().to_string_lossy().to_string(),
        };

        // Save the new identity
        manager.save_to_file()?;
        
        Ok(manager)
    }

    /// Load identity from file
    fn load_from_file<P: AsRef<Path>>(identity_path: P) -> P2PResult<Self> {
        let key_bytes = fs::read(identity_path.as_ref())
            .map_err(|e| P2PError::IoError(e))?;
        
        if key_bytes.len() != 32 {
            return Err(P2PError::CryptoError("Invalid identity key length".to_string()));
        }

        let signing_key = SigningKey::from_bytes(
            key_bytes.as_slice().try_into()
                .map_err(|_| P2PError::CryptoError("Invalid key bytes".to_string()))?
        );
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
            identity_path: identity_path.as_ref().to_string_lossy().to_string(),
        })
    }

    /// Save identity to file
    fn save_to_file(&self) -> P2PResult<()> {
        let key_bytes = self.signing_key.to_bytes();
        fs::write(&self.identity_path, key_bytes)
            .map_err(|e| P2PError::IoError(e))?;
        Ok(())
    }

    /// Get our public key as base64
    pub fn get_public_key_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.verifying_key.as_bytes())
    }

    /// Get our fingerprint (first 16 bytes of SHA256 hash, formatted)
    pub fn get_fingerprint(&self) -> String {
        Self::compute_fingerprint(&self.verifying_key)
    }

    /// Compute fingerprint from a verifying key
    pub fn compute_fingerprint(key: &VerifyingKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();
        
        // Format as XXXX-XXXX-XXXX-XXXX (first 8 bytes = 16 hex chars)
        let hex = hex::encode(&hash[..8]);
        format!(
            "{}-{}-{}-{}",
            &hex[0..4].to_uppercase(),
            &hex[4..8].to_uppercase(),
            &hex[8..12].to_uppercase(),
            &hex[12..16].to_uppercase()
        )
    }

    /// Compute fingerprint from base64 public key
    pub fn fingerprint_from_base64(public_key_b64: &str) -> P2PResult<String> {
        let key_bytes = general_purpose::STANDARD.decode(public_key_b64)
            .map_err(|e| P2PError::InvalidPublicKey(e.to_string()))?;
        
        if key_bytes.len() != 32 {
            return Err(P2PError::InvalidPublicKey("Invalid key length".to_string()));
        }

        let verifying_key = VerifyingKey::from_bytes(
            key_bytes.as_slice().try_into()
                .map_err(|_| P2PError::InvalidPublicKey("Invalid key bytes".to_string()))?
        ).map_err(|e| P2PError::InvalidPublicKey(e.to_string()))?;

        Ok(Self::compute_fingerprint(&verifying_key))
    }

    /// Sign a message with our identity key
    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        general_purpose::STANDARD.encode(signature.to_bytes())
    }

    /// Sign a string message
    pub fn sign_string(&self, message: &str) -> String {
        self.sign(message.as_bytes())
    }

    /// Verify a signature from a peer
    pub fn verify_signature(
        public_key_b64: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> P2PResult<bool> {
        let key_bytes = general_purpose::STANDARD.decode(public_key_b64)
            .map_err(|e| P2PError::InvalidPublicKey(e.to_string()))?;
        
        let verifying_key = VerifyingKey::from_bytes(
            key_bytes.as_slice().try_into()
                .map_err(|_| P2PError::InvalidPublicKey("Invalid key bytes".to_string()))?
        ).map_err(|e| P2PError::InvalidPublicKey(e.to_string()))?;

        let sig_bytes = general_purpose::STANDARD.decode(signature_b64)
            .map_err(|e| P2PError::SignatureError(e.to_string()))?;
        
        let signature = Signature::from_bytes(
            sig_bytes.as_slice().try_into()
                .map_err(|_| P2PError::SignatureError("Invalid signature bytes".to_string()))?
        );

        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the identity file path (as a string) where this identity is stored
    pub fn get_identity_path(&self) -> &str {
        &self.identity_path
    }
}

impl Drop for IdentityManager {
    fn drop(&mut self) {
        // Zeroize the signing key on drop for security
        let mut key_bytes = self.signing_key.to_bytes();
        key_bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_identity_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let temp_path = tmp.path().join("test_identity_key");
        
        let manager = IdentityManager::new(temp_path).unwrap();
        let fingerprint = manager.get_fingerprint();
        
        // Fingerprint should be in format XXXX-XXXX-XXXX-XXXX
        assert_eq!(fingerprint.len(), 19);
        assert!(fingerprint.chars().filter(|c| *c == '-').count() == 3);
        
        // NamedTempFile will be cleaned up automatically
    }

    #[test]
    fn test_identity_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let temp_path = tmp.path().join("test_identity_persist");
        
        // Generate new identity
        let manager1 = IdentityManager::new(&temp_path).unwrap();
        let fingerprint1 = manager1.get_fingerprint();
        let pubkey1 = manager1.get_public_key_base64();
        drop(manager1);
        
        // Load the same identity
        let manager2 = IdentityManager::new(&temp_path).unwrap();
        let fingerprint2 = manager2.get_fingerprint();
        let pubkey2 = manager2.get_public_key_base64();
        
        assert_eq!(fingerprint1, fingerprint2);
        assert_eq!(pubkey1, pubkey2);
        
        // NamedTempFile will be cleaned up automatically
    }

    #[test]
    fn test_signature_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let temp_path = tmp.path().join("test_identity_sig");
        
        let manager = IdentityManager::new(&temp_path).unwrap();
        let message = b"Hello, World!";
        
        // Sign the message
        let signature = manager.sign(message);
        let pubkey = manager.get_public_key_base64();
        
        // Verify the signature
        let is_valid = IdentityManager::verify_signature(&pubkey, message, &signature).unwrap();
        assert!(is_valid);
        
        // Verify with wrong message fails
        let is_valid_wrong = IdentityManager::verify_signature(&pubkey, b"Wrong message", &signature).unwrap();
        assert!(!is_valid_wrong);
        
        // NamedTempFile will be cleaned up automatically
    }

    #[test]
    fn test_fingerprint_from_base64() {
        let tmp = tempfile::tempdir().unwrap();
        let temp_path = tmp.path().join("test_identity_fp");
        
        let manager = IdentityManager::new(&temp_path).unwrap();
        let pubkey = manager.get_public_key_base64();
        let fingerprint1 = manager.get_fingerprint();
        
        let fingerprint2 = IdentityManager::fingerprint_from_base64(&pubkey).unwrap();
        
        assert_eq!(fingerprint1, fingerprint2);
        
        // NamedTempFile will be cleaned up automatically
    }
}
