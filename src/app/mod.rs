use std::time::Instant;
use std::collections::VecDeque;
use uuid::Uuid;

pub mod state;
pub mod config;

pub use state::AppState;
pub use config::{AppConfig, SecurityLevel};

use crate::crypto::CryptoManager;
use crate::messagedb::{MessageDB, StoredMessage};
use crate::network::{NetworkMessage, MessageType, NetworkEvent};
use crate::ui::{UiEvent, UiState, InputMode, ConnectionStatus, ChatMessage, IncomingConnection};

/// Main application logic coordinator
pub struct App {
    config: AppConfig,
    state: AppState,
    crypto_manager: CryptoManager,
    message_db: MessageDB,
}

impl App {
    /// Create a new application instance
    pub fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto_manager = CryptoManager::new()?;
        let message_db = MessageDB::new("messages.db")?;
        let state = AppState::new(config.port, config.security_level);

        Ok(Self {
            config,
            state,
            crypto_manager,
            message_db,
        })
    }

    /// Handle UI events from the terminal interface
    pub fn handle_ui_event(&mut self, event: UiEvent) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        match event {
            UiEvent::Tab => {
                self.handle_tab();
                Ok(None)
            }
            UiEvent::CharInput(c) => {
                self.handle_char_input(c);
                Ok(None)
            }
            UiEvent::Backspace => {
                self.handle_backspace();
                Ok(None)
            }
            UiEvent::Enter => {
                self.handle_enter()
            }
            UiEvent::AcceptConnection => {
                self.accept_connection()
            }
            UiEvent::DeclineConnection => {
                self.decline_connection()
            }
            UiEvent::Disconnect => {
                self.send_disconnect_notification()
            }
            UiEvent::Quit => {
                self.state.should_quit = true;
                self.send_disconnect_notification()
            }
            _ => Ok(None),
        }
    }

    /// Handle network events from the network layer
    pub fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::MessageReceived(message) => {
                self.handle_network_message(message);
            }
            NetworkEvent::ConnectionEstablished(addr) => {
                // Handle connection established
            }
            NetworkEvent::ConnectionLost(addr) => {
                // Handle connection lost
                self.reset_connection_state();
            }
            NetworkEvent::ConnectionFailed(addr, error) => {
                // Handle connection failure
                self.add_message(format!("Connection failed: {}", error), false);
            }
            _ => {}
        }
    }

    /// Get current UI state for rendering
    pub fn get_ui_state(&self) -> UiState {
        UiState {
            input_mode: self.state.input_mode.clone(),
            connect_input: self.state.connect_input.clone(),
            message_input: self.state.message_input.clone(),
            connection_status: self.state.connection_status.clone(),
            security_level: self.config.security_level,
            peer_ip: self.state.peer_ip.clone(),
            connected_at: self.state.connected_at,
            last_activity: self.state.last_activity,
            last_ping_sent: self.state.last_ping_sent,
            pending_ping: self.state.pending_ping.is_some(),
            messages: self.state.messages.clone().into(),
            incoming_connection: self.state.incoming_connection.clone(),
            port: self.config.port,
        }
    }

    /// Check if the application should quit
    pub fn should_quit(&self) -> bool {
        self.state.should_quit
    }

    /// Check for timeouts and other periodic tasks
    pub fn update(&mut self) -> Result<Vec<NetworkMessage>, Box<dyn std::error::Error>> {
        let mut messages = Vec::new();
        
        // Check connection timeout
        self.check_timeout();
        
        // Check session timeout and send pings if needed
        if let Some(ping_msg) = self.check_session_timeout()? {
            messages.push(ping_msg);
        }
        
        Ok(messages)
    }

    // Private helper methods
    fn handle_tab(&mut self) {
        self.state.input_mode = match self.state.input_mode {
            InputMode::ConnectField => InputMode::MessageField,
            InputMode::MessageField => InputMode::ConnectField,
            InputMode::IncomingResponse => InputMode::IncomingResponse,
        };
    }

    fn handle_char_input(&mut self, c: char) {
        match self.state.input_mode {
            InputMode::ConnectField => self.state.connect_input.push(c),
            InputMode::MessageField => self.state.message_input.push(c),
            InputMode::IncomingResponse => {}
        }
    }

    fn handle_backspace(&mut self) {
        match self.state.input_mode {
            InputMode::ConnectField => { self.state.connect_input.pop(); }
            InputMode::MessageField => { self.state.message_input.pop(); }
            InputMode::IncomingResponse => {}
        }
    }

    fn handle_enter(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        match self.state.input_mode {
            InputMode::ConnectField => self.send_connection_request(),
            InputMode::MessageField => self.send_message(),
            InputMode::IncomingResponse => Ok(None),
        }
    }

    fn send_connection_request(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        let target_address = if self.state.connect_input.contains(':') {
            self.state.connect_input.clone()
        } else {
            format!("{}:{}", self.state.connect_input, 8080)
        };

        if target_address.parse::<std::net::SocketAddr>().is_ok() {
            let msg = NetworkMessage::connection_request(
                format!("127.0.0.1:{}", self.config.port),
                self.get_public_key_base64()?,
            );

            self.state.peer_ip = Some(target_address);
            self.state.connection_status = ConnectionStatus::Establishing;
            self.state.connect_input.clear();
            
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    fn send_message(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if !self.state.message_input.is_empty() && matches!(self.state.connection_status, ConnectionStatus::Connected) {
            if let Some(peer_public_key) = &self.state.peer_public_key {
                let encrypted_content = self.crypto_manager.encrypt_message(&self.state.message_input, peer_public_key)?;
                
                // Store message encrypted with local storage key
                if let Some(peer_id) = &self.state.current_peer_id {
                    if let Ok(storage_encrypted) = self.crypto_manager.encrypt_for_storage(&self.state.message_input) {
                        let _ = self.message_db.store_message(peer_id, &storage_encrypted, true);
                    }
                }
                
                let msg = NetworkMessage::text_message(
                    format!("127.0.0.1:{}", self.config.port),
                    encrypted_content,
                );
                
                self.add_message(self.state.message_input.clone(), true);
                self.state.message_input.clear();
                self.state.last_activity = Instant::now();
                
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    fn accept_connection(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if let Some(incoming) = self.state.incoming_connection.clone() {
            let msg = NetworkMessage::connection_accept(
                format!("127.0.0.1:{}", self.config.port),
                self.get_public_key_base64()?,
            );

            // Store/update peer in database
            if let Ok(peer_id) = self.message_db.get_or_create_peer(&incoming.public_key, &incoming.from_ip) {
                self.state.current_peer_id = Some(peer_id.clone());
            }
            
            self.state.peer_ip = Some(incoming.from_ip.clone());
            self.state.peer_public_key = Some(incoming.public_key.clone());
            self.state.connection_status = ConnectionStatus::Connected;
            self.state.connected_at = Some(Instant::now());
            self.state.last_activity = Instant::now();
            self.state.incoming_connection = None;
            self.state.input_mode = InputMode::MessageField;
            
            self.reload_current_peer_history();
            self.add_message("Connection established!".to_string(), false);
            
            return Ok(Some(msg));
        }
        Ok(None)
    }

    fn decline_connection(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if let Some(_) = &self.state.incoming_connection {
            let msg = NetworkMessage::connection_decline(
                format!("127.0.0.1:{}", self.config.port)
            );

            self.state.incoming_connection = None;
            self.state.input_mode = InputMode::ConnectField;
            
            return Ok(Some(msg));
        }
        Ok(None)
    }

    fn send_disconnect_notification(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if matches!(self.state.connection_status, ConnectionStatus::Connected) {
            let msg = NetworkMessage::disconnect(
                format!("127.0.0.1:{}", self.config.port)
            );
            return Ok(Some(msg));
        }
        Ok(None)
    }

    fn handle_network_message(&mut self, msg: NetworkMessage) {
        match msg.msg_type {
            MessageType::ConnectionRequest => {
                if let Some(public_key) = msg.public_key {
                    self.state.incoming_connection = Some(IncomingConnection {
                        from_ip: msg.from_ip,
                        public_key,
                        expires_at: Instant::now() + std::time::Duration::from_secs(180),
                    });
                    self.state.input_mode = InputMode::IncomingResponse;
                }
            }
            MessageType::ConnectionAccept => {
                if let Some(public_key) = msg.public_key {
                    if let Ok(peer_id) = self.message_db.get_or_create_peer(&public_key, &msg.from_ip) {
                        self.state.current_peer_id = Some(peer_id.clone());
                    }
                    
                    self.state.peer_public_key = Some(public_key);
                    self.state.connection_status = ConnectionStatus::Connected;
                    self.state.connected_at = Some(Instant::now());
                    self.state.last_activity = Instant::now();
                    
                    self.reload_current_peer_history();
                    self.add_message("Connection established!".to_string(), false);
                }
            }
            MessageType::ConnectionDecline => {
                self.state.connection_status = ConnectionStatus::Online;
                self.state.peer_ip = None;
                self.add_message("Connection declined by peer".to_string(), false);
            }
            MessageType::Disconnect => {
                self.add_message("Peer disconnected".to_string(), false);
                self.reset_connection_state();
            }
            MessageType::TextMessage => {
                match self.crypto_manager.decrypt_message(&msg.content) {
                    Ok(decrypted_content) => {
                        if let Some(peer_id) = &self.state.current_peer_id {
                            if let Ok(storage_encrypted) = self.crypto_manager.encrypt_for_storage(&decrypted_content) {
                                let _ = self.message_db.store_message(peer_id, &storage_encrypted, false);
                            }
                        }
                        
                        self.add_message(decrypted_content, false);
                        self.state.last_activity = Instant::now();
                    }
                    Err(e) => {
                        self.add_message(format!("[Decryption error: {}]", e), false);
                    }
                }
            }
            MessageType::Ping => {
                // Handle ping - this should generate a ping response
                self.state.last_activity = Instant::now();
            }
            MessageType::PingResponse => {
                if let Some(pending_ping_id) = self.state.pending_ping {
                    if pending_ping_id == msg.id {
                        self.state.pending_ping = None;
                        self.state.last_activity = Instant::now();
                    }
                }
            }
            _ => {}
        }
    }

    fn get_public_key_base64(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.crypto_manager.get_public_key_base64()
    }

    fn add_message(&mut self, content: String, from_self: bool) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.state.messages.push_back(ChatMessage {
            content,
            from_self,
            timestamp,
        });

        // Keep only last 100 messages
        while self.state.messages.len() > 100 {
            self.state.messages.pop_front();
        }
    }

    fn reload_current_peer_history(&mut self) {
        if let Some(peer_id) = &self.state.current_peer_id {
            if let Ok(history) = self.message_db.load_history(peer_id) {
                self.load_history_into_ui(history);
            }
        }
    }

    fn load_history_into_ui(&mut self, history: Vec<StoredMessage>) {
        self.state.messages.clear();
        
        for stored_msg in history {
            match self.crypto_manager.decrypt_from_storage(&stored_msg.content) {
                Ok(decrypted_content) => {
                    self.state.messages.push_back(ChatMessage {
                        content: decrypted_content,
                        from_self: stored_msg.is_outgoing,
                        timestamp: stored_msg.timestamp.clone(),
                    });
                }
                Err(_) => {
                    self.state.messages.push_back(ChatMessage {
                        content: "[Encrypted message - storage decryption failed]".to_string(),
                        from_self: stored_msg.is_outgoing,
                        timestamp: stored_msg.timestamp.clone(),
                    });
                }
            }
        }
        
        while self.state.messages.len() > 100 {
            self.state.messages.pop_front();
        }
    }

    fn check_timeout(&mut self) {
        if let Some(incoming) = &self.state.incoming_connection {
            if Instant::now() > incoming.expires_at {
                self.state.incoming_connection = None;
                self.state.input_mode = InputMode::ConnectField;
            }
        }
    }

    fn check_session_timeout(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if !matches!(self.state.connection_status, ConnectionStatus::Connected) {
            return Ok(None);
        }

        let now = Instant::now();
        let time_since_activity = now.duration_since(self.state.last_activity).as_secs();

        // Check if session should timeout (5 minutes)
        if time_since_activity >= 300 {
            self.disconnect_with_timeout();
            return Ok(None);
        }

        // Check if we should send a ping (every minute)
        if self.state.last_ping_sent.is_none() || 
           now.duration_since(self.state.last_ping_sent.unwrap()).as_secs() >= 60 {
            return Ok(Some(self.send_ping()?));
        }

        Ok(None)
    }

    fn send_ping(&mut self) -> Result<NetworkMessage, Box<dyn std::error::Error>> {
        let ping_id = Uuid::new_v4();
        let ping_msg = NetworkMessage::ping(format!("127.0.0.1:{}", self.config.port));
        
        self.state.pending_ping = Some(ping_id);
        self.state.last_ping_sent = Some(Instant::now());
        
        Ok(ping_msg)
    }

    fn disconnect_with_timeout(&mut self) {
        self.state.previous_peer_ip = self.state.peer_ip.clone();
        self.reset_connection_state();
        self.add_message("Session timed out due to inactivity".to_string(), false);
        
        if let Some(prev_ip) = &self.state.previous_peer_ip {
            self.state.connect_input = prev_ip.clone();
        }
    }

    fn reset_connection_state(&mut self) {
        self.state.connection_status = ConnectionStatus::Online;
        self.state.peer_ip = None;
        self.state.peer_public_key = None;
        self.state.current_peer_id = None;
        self.state.connected_at = None;
        self.state.last_activity = Instant::now();
        self.state.last_ping_sent = None;
        self.state.pending_ping = None;
        self.state.input_mode = InputMode::ConnectField;
        self.state.messages.clear();
    }
}