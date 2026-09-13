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
        match env::var("DB_KEY") {
            Ok(value) => return parse_storage_key(&value),
            Err(env::VarError::NotUnicode(_)) => return Err("DB_KEY is not valid text".into()),
            Err(env::VarError::NotPresent) => {}
        }
        let dirs = ProjectDirs::from("com", "kylederzweite", "p2p-cli")
            .ok_or("could not determine application config directory")?;
        fs::create_dir_all(dirs.config_dir())?;
        load_or_create_storage_key(&dirs.config_dir().join(".env"))
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

fn parse_storage_key(value: &str) -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
    let bytes = zeroize::Zeroizing::new(hex::decode(value)?);
    if bytes.len() != 32 {
        return Err("DB_KEY must be 32 bytes (64 hex chars)".into());
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&bytes))
}

fn load_or_create_storage_key(path: &Path) -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err("Storage key must be a regular file, not a symlink or directory".into())
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    match fs::read_to_string(path) {
        Ok(content) => {
            let content = zeroize::Zeroizing::new(content);
            let keys: Vec<_> = content
                .lines()
                .filter_map(|line| line.strip_prefix("DB_KEY="))
                .collect();
            if keys.len() != 1 {
                return Err(format!(
                    "{} must contain exactly one DB_KEY; refusing to replace existing history key",
                    path.display()
                )
                .into());
            }
            let key = parse_storage_key(keys[0])?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = Aes256Gcm::generate_key(&mut AesRng);
            let content = zeroize::Zeroizing::new(format!("DB_KEY={}\n", hex::encode(key)));
            match write_secret(path, content.as_bytes()) {
                Ok(()) => Ok(key),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    load_or_create_storage_key(path)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Publish a complete private secret atomically, never replacing an existing key.
pub(crate) fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corrupt_key_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        for content in [
            "",
            "OTHER=value\n",
            "DB_KEY=broken\n",
            "DB_KEY=00\nDB_KEY=11\n",
        ] {
            fs::write(&path, content).unwrap();
            assert!(load_or_create_storage_key(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), content);
        }
    }
    #[test]
    fn concurrent_creators_share_one_durable_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_storage_key(&path).unwrap()
                })
            })
            .collect();
        let keys: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(keys.iter().all(|k| k == &keys[0]));
        assert_eq!(load_or_create_storage_key(&path).unwrap(), keys[0]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn dangling_symlink_fails_without_replacing_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        let target = dir.path().join("absent");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(load_or_create_storage_key(&path).is_err());
        assert!(!target.exists());
    }
    #[test]
    fn secret_write_cannot_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, b"original").unwrap();
        assert_eq!(
            write_secret(&path, b"replacement").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(path).unwrap(), b"original");
    }
}
