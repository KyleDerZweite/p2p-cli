use std::collections::VecDeque;
use std::time::Instant;
use uuid::Uuid;

use crate::ui::{ChatMessage, ConnectionStatus, IdentityStatus, IncomingConnection, InputMode};

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
    pub show_security_selection: bool,

    // Identity (TOFU)
    /// Our identity fingerprint
    pub our_fingerprint: Option<String>,
    /// Peer's identity key (Ed25519 public key, base64)
    pub peer_identity_key: Option<String>,
    /// Peer's identity fingerprint
    pub peer_fingerprint: Option<String>,
    /// Peer's alias (if set in trust database)
    pub peer_alias: Option<String>,
    /// Current identity verification status
    pub identity_status: IdentityStatus,
    /// Whether the connection is via localhost (127.0.0.1 or ::1)
    pub is_localhost: bool,

    // Own addresses (for sharing with peers out-of-band)
    /// Our LAN IP address, if detectable
    pub local_ip: Option<String>,

    // Scrolling
    /// Current scroll offset in messages (0 = showing latest)
    pub message_scroll: usize,
}

impl AppState {
    /// Create new application state
    pub fn new(_port: u16, _security_level: super::SecurityLevel) -> Self {
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
            show_security_selection: false,
            // Identity
            our_fingerprint: None,
            peer_identity_key: None,
            peer_fingerprint: None,
            peer_alias: None,
            identity_status: IdentityStatus::None,
            is_localhost: false,
            local_ip: None,
            // Scrolling
            message_scroll: 0,
        }
    }

    /// Scroll messages up (towards older messages)
    pub fn scroll_up(&mut self, lines: usize) {
        let max_scroll = self.messages.len().saturating_sub(1);
        self.message_scroll = (self.message_scroll + lines).min(max_scroll);
    }

    /// Scroll messages down (towards newer messages)
    pub fn scroll_down(&mut self, lines: usize) {
        self.message_scroll = self.message_scroll.saturating_sub(lines);
    }

    /// Scroll to top (oldest messages)
    pub fn scroll_top(&mut self) {
        self.message_scroll = self.messages.len().saturating_sub(1);
    }

    /// Scroll to bottom (newest messages)
    pub fn scroll_bottom(&mut self) {
        self.message_scroll = 0;
    }
}
