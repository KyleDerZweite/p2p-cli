use base64::{Engine as _, engine::general_purpose};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey, 
    pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey, LineEnding},
    Pkcs1v15Encrypt,
    traits::PublicKeyParts,
};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key, Nonce,
};
use std::env;
use directories::ProjectDirs;

pub struct CryptoManager {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    storage_cipher: Aes256Gcm,
}

impl CryptoManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Load .env file if it exists
        // Let dotenv load a .env from current dir first, then load from platform-specific config dir
        dotenv::dotenv().ok();
        if let Some(proj_dirs) = ProjectDirs::from("com", "kylederzweite", "p2p-cli") {
            let env_path = proj_dirs.config_dir().join(".env");
            if env_path.exists() {
                let _ = dotenv::from_path(env_path);
            }
        }
        
        // Generate ephemeral RSA keys for this session
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        
        // Get or generate storage key from environment
        let storage_key = Self::get_or_create_storage_key()?;
        let storage_cipher = Aes256Gcm::new(&storage_key);
        
        Ok(Self {
            private_key,
            public_key,
            storage_cipher,
        })
    }
    
    fn get_or_create_storage_key() -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
        match env::var("DB_KEY") {
            Ok(key_hex) => {
                // Decode existing key from hex
                let key_bytes = hex::decode(key_hex)?;
                if key_bytes.len() != 32 {
                    return Err("DB_KEY must be 32 bytes (64 hex chars)".into());
                }
                Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
            }
            Err(_) => {
                // Generate new key and save to .env
                let key = Aes256Gcm::generate_key(&mut AesRng);
                let key_hex = hex::encode(&key);
                
                // Create or append to .env file in the platform config dir
                let env_content = format!("DB_KEY={}\n", key_hex);
                if let Some(proj_dirs) = ProjectDirs::from("com", "kylederzweite", "p2p-cli") {
                    let config_dir = proj_dirs.config_dir();
                    std::fs::create_dir_all(config_dir)?;
                    let env_path = config_dir.join(".env");
                    std::fs::write(env_path, env_content)?;
                } else {
                    std::fs::write(".env", env_content)?;
                }
                
                eprintln!("Generated new storage key in .env file");
                Ok(key)
            }
        }
    }

    pub fn get_public_key_base64(&self) -> Result<String, Box<dyn std::error::Error>> {
        let pem = self.public_key.to_pkcs1_pem(LineEnding::LF)?;
        Ok(general_purpose::STANDARD.encode(pem.as_bytes()))
    }

    pub fn encrypt_message(&self, message: &str, peer_public_key_base64: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Decode the peer's public key from base64
        let pem_bytes = general_purpose::STANDARD.decode(peer_public_key_base64)?;
        let pem_str = String::from_utf8(pem_bytes)?;
        let peer_public_key = RsaPublicKey::from_pkcs1_pem(&pem_str)?;
        
        // RSA can only encrypt small messages, so we'll chunk the message if needed
        let message_bytes = message.as_bytes();
        let key_size = self.public_key.size();
        let max_chunk_size = key_size - 11; // PKCS#1 v1.5 padding overhead
        
        let mut encrypted_chunks = Vec::new();
        let mut rng = OsRng;
        
        for chunk in message_bytes.chunks(max_chunk_size) {
            let encrypted_chunk = peer_public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk)?;
            encrypted_chunks.push(general_purpose::STANDARD.encode(&encrypted_chunk));
        }
        
        // Join chunks with a delimiter
        Ok(encrypted_chunks.join("|"))
    }

    pub fn decrypt_message(&self, encrypted_message: &str) -> Result<String, Box<dyn std::error::Error>> {
        let chunks: Vec<&str> = encrypted_message.split('|').collect();
        let mut decrypted_message = Vec::new();
        
        for chunk in chunks {
            let encrypted_bytes = general_purpose::STANDARD.decode(chunk)?;
            let decrypted_chunk = self.private_key.decrypt(Pkcs1v15Encrypt, &encrypted_bytes)?;
            decrypted_message.extend_from_slice(&decrypted_chunk);
        }
        
        Ok(String::from_utf8(decrypted_message)?)
    }

    // Storage encryption (AES-256-GCM with local key)
    pub fn encrypt_for_storage(&self, plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
        let nonce = Aes256Gcm::generate_nonce(&mut AesRng);
        let ciphertext = self.storage_cipher.encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("AES encryption failed: {}", e))?;
        
        // Combine nonce + ciphertext and encode as base64
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);
        Ok(general_purpose::STANDARD.encode(&combined))
    }

    pub fn decrypt_from_storage(&self, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let combined = general_purpose::STANDARD.decode(encrypted_data)?;
        
        if combined.len() < 12 {
            return Err("Invalid encrypted data length".into());
        }
        
        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext_bytes = self.storage_cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES decryption failed: {}", e))?;
        Ok(String::from_utf8(plaintext_bytes)?)
    }

    pub fn get_private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    pub fn get_public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        // Create two crypto managers (simulating two peers)
        let alice = CryptoManager::new()?;
        let bob = CryptoManager::new()?;
        
        // Alice encrypts a message for Bob
        let original_message = "Hello, Bob! This is a secret message.";
        let bob_public_key = bob.get_public_key_base64()?;
        let encrypted = alice.encrypt_message(original_message, &bob_public_key)?;
        
        // Bob decrypts the message
        let decrypted = bob.decrypt_message(&encrypted)?;
        
        assert_eq!(original_message, decrypted);
        Ok(())
    }

    #[test]
    fn test_long_message_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let alice = CryptoManager::new()?;
        let bob = CryptoManager::new()?;
        
        // Test with a longer message that requires chunking
        let long_message = "This is a very long message that will definitely exceed the RSA key size limit for encryption. ".repeat(10);
        let bob_public_key = bob.get_public_key_base64()?;
        let encrypted = alice.encrypt_message(&long_message, &bob_public_key)?;
        let decrypted = bob.decrypt_message(&encrypted)?;
        
        assert_eq!(long_message, decrypted);
        Ok(())
    }
}