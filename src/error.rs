use thiserror::Error;

/// Main error type for the P2P CLI application
#[derive(Error, Debug)]
pub enum P2PError {
    // Crypto errors
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    // Identity errors
    // Network errors
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    // Storage errors
    #[error("Database error: {0}")]
    DatabaseError(String),

    // Configuration errors
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

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
}

/// Result type alias for P2P operations
pub type P2PResult<T> = Result<T, P2PError>;

// Conversion implementations for common error types
impl From<rusqlite::Error> for P2PError {
    fn from(err: rusqlite::Error) -> Self {
        P2PError::DatabaseError(err.to_string())
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
