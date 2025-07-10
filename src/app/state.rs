use std::time::Instant;
use std::collections::VecDeque;
use uuid::Uuid;

use crate::ui::{InputMode, ConnectionStatus, ChatMessage, IncomingConnection};

/// Application state that persists between UI updates
#[derive(Debug)]
pub struct AppState {
    // UI state
    pub input_mode: InputMode,
    pub connect_input: String,
    pub message_input: String,

    // Connection state
    pub connection_status: ConnectionStatus,
    pub peer_ip: Option<String>,
    pub peer_public_key: Option<String>,
    pub peer_security_level: Option<super::SecurityLevel>,
    pub negotiated_security_level: Option<super::SecurityLevel>,
    pub connected_at: Option<Instant>,
    pub previous_peer_ip: Option<String>,

    // Session management
    pub last_activity: Instant,
    pub last_ping_sent: Option<Instant>,
    pub pending_ping: Option<Uuid>,

    // Database
    pub current_peer_id: Option<String>,

    // Messages
    pub messages: VecDeque<ChatMessage>,
    pub incoming_connection: Option<IncomingConnection>,

    // Application control
    pub should_quit: bool,
    pub port: u16,
    pub show_security_selection: bool,
}

impl AppState {
    /// Create new application state
    pub fn new(port: u16, _security_level: super::SecurityLevel) -> Self {
        let now = Instant::now();

        Self {
            input_mode: InputMode::ConnectField,
            connect_input: String::new(),
            message_input: String::new(),
            connection_status: ConnectionStatus::Online,
            peer_ip: None,
            peer_public_key: None,
            peer_security_level: None,
            negotiated_security_level: None,
            connected_at: None,
            previous_peer_ip: None,
            last_activity: now,
            last_ping_sent: None,
            pending_ping: None,
            current_peer_id: None,
            messages: VecDeque::new(),
            incoming_connection: None,
            should_quit: false,
            port,
            show_security_selection: false,
        }
    }

    /// Reset connection-related state
    pub fn reset_connection(&mut self) {
        self.connection_status = ConnectionStatus::Online;
        self.peer_ip = None;
        self.peer_public_key = None;
        self.peer_security_level = None;
        self.negotiated_security_level = None;
        self.current_peer_id = None;
        self.connected_at = None;
        self.last_activity = Instant::now();
        self.last_ping_sent = None;
        self.pending_ping = None;
        self.input_mode = InputMode::ConnectField;
        self.messages.clear();
    }

    /// Check if currently connected to a peer
    pub fn is_connected(&self) -> bool {
        matches!(self.connection_status, ConnectionStatus::Connected)
    }

    /// Check if there's an incoming connection waiting for response
    pub fn has_incoming_connection(&self) -> bool {
        self.incoming_connection.is_some()
    }
}