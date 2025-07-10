use base64::{Engine as _, engine::general_purpose};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey, 
    pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey, LineEnding},
    Pkcs1v15Encrypt,
    traits::PublicKeyParts,
};

pub struct CryptoManager {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl CryptoManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        
        Ok(Self {
            private_key,
            public_key,
        })
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