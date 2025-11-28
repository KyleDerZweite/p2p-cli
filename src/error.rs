use thiserror::Error;

/// Main error type for the P2P CLI application
#[derive(Error, Debug)]
pub enum P2PError {
    // Crypto errors
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("RSA key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    // Identity errors
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Identity verification failed: peer fingerprint mismatch")]
    IdentityMismatch {
        expected: String,
        received: String,
    },

    #[error("Untrusted peer: {0}")]
    UntrustedPeer(String),

    // Network errors
    #[error("Connection failed: {0}")]
    ConnectionError(String),

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Peer disconnected")]
    PeerDisconnected,

    // Storage errors
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Storage encryption error: {0}")]
    StorageError(String),

    // Configuration errors
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("Invalid security level: {0}")]
    InvalidSecurityLevel(String),

    // UI errors
    #[error("Terminal error: {0}")]
    TerminalError(String),

    #[error("Render error: {0}")]
    RenderError(String),

    // General errors
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Unknown command: {0}")]
    UnknownCommand(String),
}

/// Result type alias for P2P operations
pub type P2PResult<T> = Result<T, P2PError>;

// Conversion implementations for common error types
impl From<rusqlite::Error> for P2PError {
    fn from(err: rusqlite::Error) -> Self {
        P2PError::DatabaseError(err.to_string())
    }
}

impl From<rsa::Error> for P2PError {
    fn from(err: rsa::Error) -> Self {
        P2PError::CryptoError(err.to_string())
    }
}

impl From<rsa::pkcs1::Error> for P2PError {
    fn from(err: rsa::pkcs1::Error) -> Self {
        P2PError::InvalidPublicKey(err.to_string())
    }
}

impl From<base64::DecodeError> for P2PError {
    fn from(err: base64::DecodeError) -> Self {
        P2PError::InvalidMessage(format!("Base64 decode error: {}", err))
    }
}

impl From<std::string::FromUtf8Error> for P2PError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        P2PError::InvalidMessage(format!("UTF-8 decode error: {}", err))
    }
}

impl From<ed25519_dalek::SignatureError> for P2PError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        P2PError::SignatureError(err.to_string())
    }
}

impl From<hex::FromHexError> for P2PError {
    fn from(err: hex::FromHexError) -> Self {
        P2PError::InvalidMessage(format!("Hex decode error: {}", err))
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for P2PError {
    fn from(err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        P2PError::NetworkError(format!("Channel send error: {}", err))
    }
}
