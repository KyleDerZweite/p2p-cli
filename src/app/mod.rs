use std::time::Instant;
use uuid::Uuid;

pub mod state;
pub mod config;

pub use state::AppState;
pub use config::{AppConfig, SecurityLevel};

use crate::crypto::{CryptoManager, IdentityManager};
use crate::messagedb::{MessageDB, StoredMessage, TrustLevel};
use crate::network::{NetworkMessage, MessageType, NetworkEvent};
use crate::ui::{UiEvent, UiState, InputMode, ConnectionStatus, ChatMessage, IncomingConnection, IdentityStatus};

/// Main application logic coordinator
pub struct App {
    config: AppConfig,
    state: AppState,
    crypto_manager: CryptoManager,
    identity_manager: IdentityManager,
    message_db: MessageDB,
}

impl App {
    /// Create a new application instance
    pub fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto_manager = CryptoManager::new()?;
        let identity_manager = IdentityManager::new(".p2p_identity")?;
        let message_db = MessageDB::new("messages.db")?;
        let mut state = AppState::new(config.port, config.security_level);
        
        // Set our fingerprint in state
        state.our_fingerprint = Some(identity_manager.get_fingerprint());

        Ok(Self {
            config,
            state,
            crypto_manager,
            identity_manager,
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
                self.accept_connection(TrustLevel::Trusted)
            }
            UiEvent::AcceptConnectionOnce => {
                self.accept_connection(TrustLevel::TrustedOnce)
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
            UiEvent::ShowSecuritySelection => {
                self.state.show_security_selection = true;
                Ok(None)
            }
            UiEvent::SecurityLevelSelect(level) => {
                self.config.security_level = level;
                self.state.show_security_selection = false;
                Ok(None)
            }
            UiEvent::KeyPress(crossterm::event::KeyCode::Esc, _) => {
                if self.state.show_security_selection {
                    self.state.show_security_selection = false;
                }
                Ok(None)
            }
            UiEvent::ScrollUp => {
                self.state.scroll_up(5);
                Ok(None)
            }
            UiEvent::ScrollDown => {
                self.state.scroll_down(5);
                Ok(None)
            }
            UiEvent::ScrollTop => {
                self.state.scroll_top();
                Ok(None)
            }
            UiEvent::ScrollBottom => {
                self.state.scroll_bottom();
                Ok(None)
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
            peer_security_level: self.state.peer_security_level,
            negotiated_security_level: self.state.negotiated_security_level,
            peer_ip: self.state.peer_ip.clone(),
            connected_at: self.state.connected_at,
            last_activity: self.state.last_activity,
            last_ping_sent: self.state.last_ping_sent,
            pending_ping: self.state.pending_ping.is_some(),
            messages: self.state.messages.clone().into(),
            incoming_connection: self.state.incoming_connection.clone(),
            port: self.config.port,
            show_security_selection: self.state.show_security_selection,
            our_fingerprint: self.state.our_fingerprint.clone(),
            peer_fingerprint: self.state.peer_fingerprint.clone(),
            peer_alias: self.state.peer_alias.clone(),
            identity_status: self.state.identity_status,
            message_scroll: self.state.message_scroll,
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
            InputMode::SecuritySelection => InputMode::SecuritySelection,
        };
    }

    fn handle_char_input(&mut self, c: char) {
        match self.state.input_mode {
            InputMode::ConnectField => self.state.connect_input.push(c),
            InputMode::MessageField => self.state.message_input.push(c),
            InputMode::IncomingResponse => {}
            InputMode::SecuritySelection => {}
        }
    }

    fn handle_backspace(&mut self) {
        match self.state.input_mode {
            InputMode::ConnectField => { self.state.connect_input.pop(); }
            InputMode::MessageField => { self.state.message_input.pop(); }
            InputMode::IncomingResponse => {}
            InputMode::SecuritySelection => {}
        }
    }

    fn handle_enter(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        match self.state.input_mode {
            InputMode::ConnectField => self.send_connection_request(),
            InputMode::MessageField => self.send_message(),
            InputMode::IncomingResponse => Ok(None),
            InputMode::SecuritySelection => Ok(None),
        }
    }

    fn send_connection_request(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        let target_address = if self.state.connect_input.contains(':') {
            self.state.connect_input.clone()
        } else {
            format!("{}:{}", self.state.connect_input, 8080)
        };

        if target_address.parse::<std::net::SocketAddr>().is_ok() {
            let msg = if self.config.security_level.requires_identity() {
                // TOFU mode: Include identity information
                let session_key = self.get_public_key_base64()?;
                let identity_key = self.identity_manager.get_public_key_base64();
                let fingerprint = self.identity_manager.get_fingerprint();
                let signature = self.identity_manager.sign_string(&session_key);
                
                NetworkMessage::connection_request_with_identity(
                    format!("127.0.0.1:{}", self.config.port),
                    session_key,
                    self.config.security_level,
                    identity_key,
                    fingerprint,
                    signature,
                )
            } else {
                // Quick mode: No identity
                NetworkMessage::connection_request(
                    format!("127.0.0.1:{}", self.config.port),
                    self.get_public_key_base64()?,
                    self.config.security_level,
                )
            };

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
            // Check for commands
            if self.state.message_input.starts_with('/') {
                return self.handle_command();
            }
            
            if let Some(peer_public_key) = &self.state.peer_public_key {
                let encrypted_content = self.crypto_manager.encrypt_message(&self.state.message_input, peer_public_key)?;
                
                // Store message encrypted with local storage key (unless Maximum security)
                if !self.config.security_level.disable_persistent_history() {
                    if let Some(peer_id) = &self.state.current_peer_id {
                        if let Ok(storage_encrypted) = self.crypto_manager.encrypt_for_storage(&self.state.message_input) {
                            let _ = self.message_db.store_message(peer_id, &storage_encrypted, true);
                        }
                    }
                }
                
                let msg = NetworkMessage::text_message(
                    format!("127.0.0.1:{}", self.config.port),
                    encrypted_content,
                );
                
                self.add_message(self.state.message_input.clone(), true);
                self.state.message_input.clear();
                self.state.last_activity = Instant::now();
                // Reset scroll to bottom when sending
                self.state.message_scroll = 0;
                
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    /// Handle slash commands
    fn handle_command(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        let input = self.state.message_input.trim().to_lowercase();
        let parts: Vec<&str> = input.split_whitespace().collect();
        
        match parts.first().map(|s| *s) {
            Some("/help") | Some("/h") | Some("/?") => {
                self.show_help();
            }
            Some("/fingerprint") | Some("/fp") => {
                self.show_fingerprint();
            }
            Some("/alias") => {
                if parts.len() > 1 {
                    let alias = parts[1..].join(" ");
                    self.set_peer_alias(&alias);
                } else {
                    self.add_message("Usage: /alias <name>".to_string(), false);
                }
            }
            Some("/trust") => {
                self.trust_current_peer();
            }
            Some("/clear") => {
                self.state.messages.clear();
                self.state.message_scroll = 0;
                self.add_message("Messages cleared".to_string(), false);
            }
            Some("/disconnect") | Some("/dc") => {
                self.state.message_input.clear();
                return self.send_disconnect_notification();
            }
            Some("/status") => {
                self.show_status();
            }
            Some(cmd) => {
                self.add_message(format!("Unknown command: {}. Type /help for available commands.", cmd), false);
            }
            None => {}
        }
        
        self.state.message_input.clear();
        Ok(None)
    }

    fn show_help(&mut self) {
        self.add_message("═══ Available Commands ═══".to_string(), false);
        self.add_message("/help, /h        - Show this help message".to_string(), false);
        self.add_message("/fingerprint, /fp - Show identity fingerprints".to_string(), false);
        self.add_message("/alias <name>    - Set alias for current peer".to_string(), false);
        self.add_message("/trust           - Permanently trust current peer".to_string(), false);
        self.add_message("/clear           - Clear message history".to_string(), false);
        self.add_message("/disconnect, /dc - Disconnect from peer".to_string(), false);
        self.add_message("/status          - Show connection status".to_string(), false);
        self.add_message("═══ Keyboard Shortcuts ═══".to_string(), false);
        self.add_message("Ctrl+C           - Quit application".to_string(), false);
        self.add_message("Ctrl+D           - Disconnect from peer".to_string(), false);
        self.add_message("Ctrl+S           - Open security level selection".to_string(), false);
        self.add_message("Tab              - Switch between input fields".to_string(), false);
        self.add_message("PageUp/Down      - Scroll messages".to_string(), false);
        self.add_message("Ctrl+Home/End    - Scroll to top/bottom".to_string(), false);
    }

    fn show_fingerprint(&mut self) {
        if let Some(our_fp) = &self.state.our_fingerprint {
            self.add_message(format!("Your fingerprint: {}", our_fp), false);
        }
        if let Some(peer_fp) = &self.state.peer_fingerprint {
            let status = match self.state.identity_status {
                IdentityStatus::Verified => " ✓ VERIFIED",
                IdentityStatus::Unknown => " (unknown)",
                IdentityStatus::Mismatch => " ⚠ MISMATCH!",
                IdentityStatus::None => "",
            };
            self.add_message(format!("Peer fingerprint: {}{}", peer_fp, status), false);
        } else {
            self.add_message("No peer connected or peer has no identity".to_string(), false);
        }
    }

    fn set_peer_alias(&mut self, alias: &str) {
        if let Some(fingerprint) = &self.state.peer_fingerprint {
            if let Err(e) = self.message_db.set_identity_alias(fingerprint, alias) {
                self.add_message(format!("Failed to set alias: {}", e), false);
            } else {
                self.state.peer_alias = Some(alias.to_string());
                self.add_message(format!("Alias set to: {}", alias), false);
            }
        } else {
            self.add_message("Cannot set alias: peer has no identity".to_string(), false);
        }
    }

    fn trust_current_peer(&mut self) {
        if let (Some(fingerprint), Some(identity_key)) = (&self.state.peer_fingerprint, &self.state.peer_identity_key) {
            if let Err(e) = self.message_db.trust_identity(fingerprint, identity_key, TrustLevel::Trusted, self.state.peer_alias.as_deref()) {
                self.add_message(format!("Failed to trust peer: {}", e), false);
            } else {
                self.state.identity_status = IdentityStatus::Verified;
                self.add_message(format!("Peer {} is now permanently trusted", fingerprint), false);
            }
        } else {
            self.add_message("Cannot trust: peer has no identity".to_string(), false);
        }
    }

    fn show_status(&mut self) {
        self.add_message(format!("Security level: {}", self.config.security_level.display_name()), false);
        if let Some(negotiated) = self.state.negotiated_security_level {
            self.add_message(format!("Negotiated level: {}", negotiated.display_name()), false);
        }
        self.add_message(format!("Identity status: {:?}", self.state.identity_status), false);
        if let Some(peer_ip) = &self.state.peer_ip {
            self.add_message(format!("Connected to: {}", peer_ip), false);
        }
    }

    fn accept_connection(&mut self, trust_level: TrustLevel) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if let Some(incoming) = self.state.incoming_connection.clone() {
            // Negotiate security level (use the higher level)
            let negotiated_level = self.config.security_level.negotiate_with(incoming.security_level);
            
            let msg = if negotiated_level.requires_identity() {
                // TOFU mode: Include identity information
                let session_key = self.get_public_key_base64()?;
                let identity_key = self.identity_manager.get_public_key_base64();
                let fingerprint = self.identity_manager.get_fingerprint();
                let signature = self.identity_manager.sign_string(&session_key);
                
                NetworkMessage::connection_accept_with_identity(
                    format!("127.0.0.1:{}", self.config.port),
                    session_key,
                    self.config.security_level,
                    identity_key,
                    fingerprint,
                    signature,
                )
            } else {
                NetworkMessage::connection_accept(
                    format!("127.0.0.1:{}", self.config.port),
                    self.get_public_key_base64()?,
                    self.config.security_level,
                )
            };

            // Store/update peer in database
            if let Ok(peer_id) = self.message_db.get_or_create_peer(&incoming.public_key, &incoming.from_ip) {
                self.state.current_peer_id = Some(peer_id.clone());
            }
            
            // Handle TOFU identity trust
            if let (Some(identity_key), Some(fingerprint)) = (&incoming.identity_key, &incoming.identity_fingerprint) {
                self.state.peer_identity_key = Some(identity_key.clone());
                self.state.peer_fingerprint = Some(fingerprint.clone());
                self.state.identity_status = incoming.identity_status;
                self.state.peer_alias = incoming.identity_alias.clone();
                
                // Trust the identity if requested
                if trust_level == TrustLevel::Trusted && incoming.identity_status == IdentityStatus::Unknown {
                    let _ = self.message_db.trust_identity(fingerprint, identity_key, trust_level, None);
                    self.state.identity_status = IdentityStatus::Verified;
                }
            }
            
            self.state.peer_ip = Some(incoming.from_ip.clone());
            self.state.peer_public_key = Some(incoming.public_key.clone());
            self.state.peer_security_level = Some(incoming.security_level);
            self.state.negotiated_security_level = Some(negotiated_level);
            self.state.connection_status = ConnectionStatus::Connected;
            self.state.connected_at = Some(Instant::now());
            self.state.last_activity = Instant::now();
            self.state.incoming_connection = None;
            self.state.input_mode = InputMode::MessageField;
            
            self.reload_current_peer_history();
            
            let identity_info = match self.state.identity_status {
                IdentityStatus::Verified => " [✓ VERIFIED]",
                IdentityStatus::Unknown => " [unknown identity]",
                IdentityStatus::Mismatch => " [⚠ IDENTITY MISMATCH!]",
                IdentityStatus::None => "",
            };
            self.add_message(format!("Connection established! Security: {}{}", negotiated_level.display_name(), identity_info), false);
            
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

    /// Verify peer identity for TOFU mode
    fn verify_peer_identity(&mut self, identity_key: &str, fingerprint: &str, session_key: &str, signature: &str) -> IdentityStatus {
        // First verify the signature (proves peer owns the identity key)
        if let Ok(valid) = IdentityManager::verify_signature(identity_key, session_key.as_bytes(), signature) {
            if !valid {
                return IdentityStatus::Mismatch; // Invalid signature
            }
        } else {
            return IdentityStatus::Unknown; // Signature verification failed
        }
        
        // Check if we have this identity in our trust database
        match self.message_db.verify_identity(fingerprint, identity_key) {
            Ok((matches, Some(trusted))) => {
                if matches {
                    // Known and verified
                    self.state.peer_alias = trusted.alias.clone();
                    IdentityStatus::Verified
                } else {
                    // KEY MISMATCH - potential impersonation!
                    IdentityStatus::Mismatch
                }
            }
            Ok((_, None)) => {
                // New identity - not trusted yet
                IdentityStatus::Unknown
            }
            Err(_) => IdentityStatus::Unknown,
        }
    }

    fn handle_network_message(&mut self, msg: NetworkMessage) {
        match msg.msg_type {
            MessageType::ConnectionRequest => {
                if let Some(public_key) = msg.public_key {
                    let peer_security_level = msg.security_level.unwrap_or(SecurityLevel::Quick);
                    
                    // Check identity if TOFU mode
                    let (identity_status, identity_alias) = if let (Some(id_key), Some(fp), Some(sig)) = 
                        (&msg.identity_key, &msg.identity_fingerprint, &msg.identity_signature) 
                    {
                        let status = self.verify_peer_identity(id_key, fp, &public_key, sig);
                        let alias = if status == IdentityStatus::Verified {
                            self.message_db.get_trusted_identity(fp)
                                .ok()
                                .flatten()
                                .and_then(|t| t.alias)
                        } else {
                            None
                        };
                        (status, alias)
                    } else {
                        (IdentityStatus::None, None)
                    };
                    
                    self.state.incoming_connection = Some(IncomingConnection {
                        from_ip: msg.from_ip,
                        public_key,
                        security_level: peer_security_level,
                        expires_at: Instant::now() + std::time::Duration::from_secs(180),
                        identity_key: msg.identity_key,
                        identity_fingerprint: msg.identity_fingerprint,
                        identity_status,
                        identity_alias,
                    });
                    self.state.input_mode = InputMode::IncomingResponse;
                }
            }
            MessageType::ConnectionAccept => {
                if let Some(public_key) = msg.public_key {
                    let peer_security_level = msg.security_level.unwrap_or(SecurityLevel::Quick);
                    let negotiated_level = self.config.security_level.negotiate_with(peer_security_level);
                    
                    if let Ok(peer_id) = self.message_db.get_or_create_peer(&public_key, &msg.from_ip) {
                        self.state.current_peer_id = Some(peer_id.clone());
                    }
                    
                    // Handle identity verification
                    let identity_status = if let (Some(id_key), Some(fp), Some(sig)) = 
                        (&msg.identity_key, &msg.identity_fingerprint, &msg.identity_signature) 
                    {
                        let status = self.verify_peer_identity(id_key, fp, &public_key, sig);
                        self.state.peer_identity_key = Some(id_key.clone());
                        self.state.peer_fingerprint = Some(fp.clone());
                        status
                    } else {
                        IdentityStatus::None
                    };
                    self.state.identity_status = identity_status;
                    
                    self.state.peer_public_key = Some(public_key);
                    self.state.peer_security_level = Some(peer_security_level);
                    self.state.negotiated_security_level = Some(negotiated_level);
                    self.state.connection_status = ConnectionStatus::Connected;
                    self.state.connected_at = Some(Instant::now());
                    self.state.last_activity = Instant::now();
                    
                    self.reload_current_peer_history();
                    
                    let identity_info = match identity_status {
                        IdentityStatus::Verified => " [✓ VERIFIED]",
                        IdentityStatus::Unknown => " [unknown identity]",
                        IdentityStatus::Mismatch => " [⚠ IDENTITY MISMATCH!]",
                        IdentityStatus::None => "",
                    };
                    self.add_message(format!("Connection established! Security: {}{}", negotiated_level.display_name(), identity_info), false);
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
                        // Don't store if Maximum security
                        if !self.config.security_level.disable_persistent_history() {
                            if let Some(peer_id) = &self.state.current_peer_id {
                                if let Ok(storage_encrypted) = self.crypto_manager.encrypt_for_storage(&decrypted_content) {
                                    let _ = self.message_db.store_message(peer_id, &storage_encrypted, false);
                                }
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
        self.state.peer_security_level = None;
        self.state.negotiated_security_level = None;
        self.state.current_peer_id = None;
        self.state.connected_at = None;
        self.state.last_activity = Instant::now();
        self.state.last_ping_sent = None;
        self.state.pending_ping = None;
        self.state.input_mode = InputMode::ConnectField;
        self.state.messages.clear();
    }
}