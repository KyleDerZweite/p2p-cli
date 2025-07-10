use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Network message types that can be sent between peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    pub id: Uuid,
    pub msg_type: MessageType,
    pub from_ip: String,
    pub content: String,
    pub public_key: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Types of messages that can be sent over the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    ConnectionRequest,
    ConnectionAccept,
    ConnectionDecline,
    Disconnect,
    TextMessage,
    Ping,
    PingResponse,
    // Future security-related message types
    KeyRotationRequest,
    KeyRotationResponse,
    IdentityVerification,
}

impl NetworkMessage {
    /// Create a new network message
    pub fn new(
        msg_type: MessageType,
        from_ip: String,
        content: String,
        public_key: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            msg_type,
            from_ip,
            content,
            public_key,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a connection request message
    pub fn connection_request(from_ip: String, public_key: String) -> Self {
        Self::new(
            MessageType::ConnectionRequest,
            from_ip,
            "Connection request".to_string(),
            Some(public_key),
        )
    }

    /// Create a connection accept message
    pub fn connection_accept(from_ip: String, public_key: String) -> Self {
        Self::new(
            MessageType::ConnectionAccept,
            from_ip,
            "Connection accepted".to_string(),
            Some(public_key),
        )
    }

    /// Create a connection decline message
    pub fn connection_decline(from_ip: String) -> Self {
        Self::new(
            MessageType::ConnectionDecline,
            from_ip,
            "Connection declined".to_string(),
            None,
        )
    }

    /// Create a disconnect message
    pub fn disconnect(from_ip: String) -> Self {
        Self::new(
            MessageType::Disconnect,
            from_ip,
            "Peer disconnected".to_string(),
            None,
        )
    }

    /// Create a text message
    pub fn text_message(from_ip: String, content: String) -> Self {
        Self::new(
            MessageType::TextMessage,
            from_ip,
            content,
            None,
        )
    }

    /// Create a ping message
    pub fn ping(from_ip: String) -> Self {
        Self::new(
            MessageType::Ping,
            from_ip,
            "ping".to_string(),
            None,
        )
    }

    /// Create a ping response message
    pub fn ping_response(from_ip: String, ping_id: Uuid) -> Self {
        let mut msg = Self::new(
            MessageType::PingResponse,
            from_ip,
            "pong".to_string(),
            None,
        );
        msg.id = ping_id; // Use the same ID as the ping for correlation
        msg
    }

    /// Serialize the message to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a message from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}