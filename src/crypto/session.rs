use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use directories::ProjectDirs;
use rand_core::{OsRng, RngCore};
use std::{env, fs, path::Path};

/// Local cryptographic state. Wire confidentiality and integrity are provided
/// by the Noise transport; this type owns only a per-process session identifier
/// and the at-rest cipher.
pub struct CryptoManager {
    session_id: [u8; 32],
    storage_cipher: Aes256Gcm,
}

impl CryptoManager {
    pub fn new(persistent_storage: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Never read secrets from the current working directory. Environment
        // variables set by the process owner take precedence over the private
        // application configuration file.
        let mut session_id = [0u8; 32];
        OsRng.fill_bytes(&mut session_id);
        let storage_key = if persistent_storage {
            Self::get_or_create_storage_key()?
        } else {
            Aes256Gcm::generate_key(&mut AesRng)
        };
        Ok(Self {
            session_id,
            storage_cipher: Aes256Gcm::new(&storage_key),
        })
    }

    fn get_or_create_storage_key() -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
        let configured_key = env::var("DB_KEY").ok().or_else(|| {
            let dirs = ProjectDirs::from("com", "kylederzweite", "p2p-cli")?;
            let path = dirs.config_dir().join(".env");
            #[cfg(unix)]
            if path.exists() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
            let content = fs::read_to_string(path).ok()?;
            content
                .lines()
                .find_map(|line| line.strip_prefix("DB_KEY=").map(str::to_owned))
        });
        if let Some(key_hex) = configured_key {
            let key_bytes = hex::decode(key_hex)?;
            if key_bytes.len() != 32 {
                return Err("DB_KEY must be 32 bytes (64 hex chars)".into());
            }
            return Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes));
        }

        let key = Aes256Gcm::generate_key(&mut AesRng);
        let proj_dirs = ProjectDirs::from("com", "kylederzweite", "p2p-cli")
            .ok_or("could not determine application config directory")?;
        fs::create_dir_all(proj_dirs.config_dir())?;
        let env_path = proj_dirs.config_dir().join(".env");
        write_secret(
            &env_path,
            format!("DB_KEY={}\n", hex::encode(key)).as_bytes(),
        )?;
        Ok(key)
    }

    pub fn get_public_key_base64(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(general_purpose::STANDARD.encode(self.session_id))
    }

    /// Payloads are already protected by the authenticated Noise channel.
    pub fn encrypt_message(
        &self,
        message: &str,
        _peer_key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Ok(message.to_owned())
    }

    pub fn decrypt_message(&self, message: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(message.to_owned())
    }

    pub fn encrypt_for_storage(
        &self,
        plaintext: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let nonce = Aes256Gcm::generate_nonce(&mut AesRng);
        let ciphertext = self
            .storage_cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| "AES-GCM storage encryption failed")?;
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);
        Ok(general_purpose::STANDARD.encode(combined))
    }

    pub fn decrypt_from_storage(
        &self,
        encrypted_data: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let combined = general_purpose::STANDARD.decode(encrypted_data)?;
        if combined.len() < 12 + 16 {
            return Err("invalid encrypted storage record".into());
        }
        let (nonce, ciphertext) = combined.split_at(12);
        let plaintext = self
            .storage_cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| "AES-GCM storage authentication failed")?;
        Ok(String::from_utf8(plaintext)?)
    }
}

#[cfg(unix)]
pub(crate) fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}
