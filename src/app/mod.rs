use std::{sync::Arc, time::Instant};
use uuid::Uuid;

pub mod config;
pub mod state;

pub use config::{AppConfig, SecurityLevel};
pub use state::AppState;

use crate::crypto::{CryptoManager, IdentityManager};
use crate::messagedb::{MessageDB, StoredMessage, TrustLevel};
use crate::network::{MessageType, NetworkEvent, NetworkMessage};
use crate::ui::{
    ChatMessage, ConnectionStatus, IdentityStatus, IncomingConnection, InputMode, MessageSource,
    UiEvent, UiState,
};
use directories::ProjectDirs;
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

/// Main application logic coordinator
pub struct App {
    config: AppConfig,
    state: AppState,
    crypto_manager: CryptoManager,
    identity_manager: Arc<IdentityManager>,
    message_db: MessageDB,
    seen_message_ids: HashSet<Uuid>,
    seen_message_order: VecDeque<Uuid>,
    persistent_history: bool,
    pending_network_messages: VecDeque<NetworkMessage>,
    pending_candidates: VecDeque<std::net::SocketAddr>,
    expected_identity: Option<String>,
    invitation_addresses: Vec<std::net::SocketAddr>,
}

impl App {
    /// Create a new application instance
    pub fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let persistent_history = !config.security_level.disable_persistent_history();
        let crypto_manager = CryptoManager::new(persistent_history)?;

        // Resolve platform-specific directories for config and data
        let proj_dirs = ProjectDirs::from("com", "kylederzweite", "p2p-cli")
            .ok_or("Could not determine platform-specific project directories")?;
        let config_dir = proj_dirs.config_dir();
        let data_dir = proj_dirs.data_dir();
        std::fs::create_dir_all(config_dir)?;
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [config_dir, data_dir] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        let identity_path: PathBuf = config_dir.join("p2p_identity");
        let db_path: PathBuf = data_dir.join("messages.db");

        let identity_manager = Arc::new(IdentityManager::new(identity_path)?);
        let message_db = if persistent_history {
            MessageDB::new(db_path)?
        } else {
            MessageDB::new_in_memory()?
        };
        let mut state = AppState::new(config.port, config.security_level);

        // Set our fingerprint in state
        state.our_fingerprint = Some(identity_manager.get_fingerprint());

        // Discover a local address without a remote lookup.
        state.local_ip = crate::network::addr::local_ip().map(|ip| ip.to_string());

        Ok(Self {
            config,
            state,
            crypto_manager,
            identity_manager,
            message_db,
            seen_message_ids: HashSet::new(),
            seen_message_order: VecDeque::new(),
            persistent_history,
            pending_network_messages: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            expected_identity: None,
            invitation_addresses: Vec::new(),
        })
    }

    pub fn transport_identity(&self) -> Arc<IdentityManager> {
        Arc::clone(&self.identity_manager)
    }

    /// Handle UI events from the terminal interface
    pub fn handle_ui_event(
        &mut self,
        event: UiEvent,
    ) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        match event {
            UiEvent::Tab => {
                self.handle_tab();
                Ok(None)
            }
            UiEvent::CharInput(c) => {
                self.handle_char_input(c);
                Ok(None)
            }
            UiEvent::Paste(text) => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    self.handle_char_input(c);
                }
                Ok(None)
            }
            UiEvent::Backspace => {
                self.handle_backspace();
                Ok(None)
            }
            UiEvent::Enter => self.handle_enter(),
            UiEvent::AcceptConnection => {
                // Only handle as connection accept if there's a pending incoming connection
                if self.state.incoming_connection.is_some() {
                    self.accept_connection(TrustLevel::Trusted)
                } else {
                    self.handle_char_input('a');
                    Ok(None)
                }
            }
            UiEvent::AcceptConnectionOnce => {
                // Only handle as connection accept if there's a pending incoming connection
                if self.state.incoming_connection.is_some() {
                    self.accept_connection(TrustLevel::TrustedOnce)
                } else {
                    self.handle_char_input('o');
                    Ok(None)
                }
            }
            UiEvent::DeclineConnection => {
                // Only handle as connection decline if there's a pending incoming connection
                if self.state.incoming_connection.is_some() {
                    self.decline_connection()
                } else {
                    self.handle_char_input('d');
                    Ok(None)
                }
            }
            UiEvent::CopyAddress => {
                self.copy_shareable_address();
                Ok(None)
            }
            UiEvent::Disconnect => self.send_disconnect_notification(),
            UiEvent::Quit => {
                self.state.should_quit = true;
                self.send_disconnect_notification()
            }
            UiEvent::ShowSecuritySelection => {
                self.state.show_security_selection = true;
                Ok(None)
            }
            UiEvent::SecurityLevelSelect(level) => {
                self.select_security_level(level);
                Ok(None)
            }
            UiEvent::Escape => {
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
    pub fn handle_network_event(&mut self, event: NetworkEvent) -> Result<(), String> {
        match event {
            NetworkEvent::MessageReceived(mut message, addr) => {
                if let Err(reason) = self.validate_incoming(&message, addr) {
                    self.add_system_message(format!(
                        "Rejected unauthenticated protocol message: {}",
                        reason
                    ));
                    return Err(reason);
                } else {
                    // Preserve the signed envelope until validation completes. Replies
                    // use the live socket, including inbound ephemeral ports.
                    message.from_ip = addr.to_string();
                    self.handle_network_message(message);
                }
            }
            NetworkEvent::ConnectionEstablished(_addr) => {
                // Handle connection established
            }
            NetworkEvent::ConnectionLost(addr) => {
                if self.state.peer_ip.as_deref() == Some(addr.to_string().as_str()) {
                    self.reset_connection_state();
                    self.add_system_message("Transport closed. Reconnect to start a new authenticated session.".into());
                }
                if self.state.incoming_connection.as_ref().is_some_and(|incoming| incoming.from_ip == addr.to_string()) {
                    self.state.incoming_connection = None;
                    self.state.input_mode = InputMode::ConnectField;
                }
            }
            NetworkEvent::ConnectionFailed(addr, error) => {
                self.add_system_message(format!("Connection to {addr} failed: {error}"));
                if self.state.peer_ip.as_deref() == Some(addr.to_string().as_str())
                    && self.state.connection_status == ConnectionStatus::Establishing {
                    if self.pending_candidates.is_empty() {
                        self.reset_connection_state();
                        self.add_system_message("No candidate succeeded. See --diagnose and docs/linux.md; try reversing who connects.".into());
                    } else {
                        self.queue_next_candidate();
                    }
                }
            }
            NetworkEvent::IncomingFailed(_, _) => {
                // Unsolicited handshakes belong in diagnostics, not the conversation.
            }
            NetworkEvent::ListenerStarted(port) => self.add_system_message(format!("Listening on TCP port {port}. Ctrl+Y copies your invitation; /myip shows candidates.")),
            NetworkEvent::ListenerWarning(error) => self.add_system_message(error),
            NetworkEvent::ListenerFailed(error) => self.add_system_message(format!("Listener failed: {error}. Choose another port or check bind permissions. Outgoing connections can still work.")),
        }
        Ok(())
    }

    pub fn set_message_scroll_limit(&mut self, limit: usize) {
        self.state.max_message_scroll = limit;
        self.state.message_scroll = self.state.message_scroll.min(limit);
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
            previous_peer_ip: self.state.previous_peer_ip.clone(),
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
            is_localhost: self.state.is_localhost,
            local_ip: self.state.local_ip.clone(),
            message_scroll: self.state.message_scroll,
        }
    }

    pub fn set_invitation_addresses(&mut self, addresses: Vec<std::net::SocketAddr>) {
        self.invitation_addresses = addresses;
    }

    pub fn expected_peer_identity(&self) -> Option<String> {
        self.expected_identity
            .clone()
            .or_else(|| self.state.peer_identity_key.clone())
    }

    pub fn start_connection(&mut self, input: &str) -> Result<(), String> {
        if !matches!(
            self.state.connection_status,
            ConnectionStatus::Online | ConnectionStatus::PeerDisconnected
        ) {
            return Err("Disconnect the current peer before connecting again".into());
        }
        let (expected, candidates) = if input.trim().starts_with("p2p-cli:") {
            let invitation = crate::network::invitation::Invitation::parse(input)?;
            (Some(invitation.identity_key), invitation.candidates)
        } else {
            let addr = Self::parse_socket_addr(input.trim(), self.config.port)
                .ok_or("Enter a p2p-cli invitation or a literal IP:PORT")?;
            if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
                return Err("The target must be a unicast address with a nonzero port".into());
            }
            (None, vec![addr])
        };
        self.reset_connection_state();
        self.expected_identity = expected;
        self.pending_candidates = candidates.into();
        if self.expected_identity.is_none() {
            self.add_system_message("Address-only connection: compare fingerprints with your peer before sending private text. An invitation pins the expected identity.".into());
        }
        self.queue_next_candidate();
        Ok(())
    }

    fn queue_next_candidate(&mut self) {
        if let Some(target) = self.pending_candidates.pop_front() {
            self.state.peer_ip = Some(target.to_string());
            self.state.connection_status = ConnectionStatus::Establishing;
            self.state.last_activity = Instant::now();
            let message = NetworkMessage::connection_request(
                format!("127.0.0.1:{}", self.config.port),
                self.identity_manager.get_public_key_base64(),
                self.config.security_level,
            );
            self.pending_network_messages.push_back(message);
            self.add_system_message(format!("Connecting to {target}..."));
        }
    }

    fn our_invitation(&self) -> Result<String, String> {
        let mut candidates = self.invitation_addresses.clone();
        if candidates.is_empty() {
            candidates = crate::network::addr::local_addresses()
                .into_iter()
                .filter(|ip| !ip.is_loopback())
                .map(|ip| std::net::SocketAddr::new(ip, self.config.port))
                .collect();
            if candidates.is_empty() {
                candidates.push(([127, 0, 0, 1], self.config.port).into());
            }
            candidates.truncate(16);
        }
        crate::network::invitation::Invitation::new(
            self.identity_manager.get_public_key_base64(),
            candidates,
        )?
        .encode()
    }

    /// Check if the application should quit
    pub fn should_quit(&self) -> bool {
        self.state.should_quit
    }

    /// Bind every application message to our long-term identity. Noise protects
    /// the hop; this signature authenticates the application transcript and is
    /// what TOFU pins across fresh forward-secret connections.
    pub fn authenticate_outgoing(
        &self,
        mut message: NetworkMessage,
    ) -> Result<NetworkMessage, Box<dyn std::error::Error>> {
        message.identity_key = Some(self.identity_manager.get_public_key_base64());
        message.identity_fingerprint = Some(self.identity_manager.get_fingerprint());
        message.identity_signature = None;
        message.identity_signature = Some(self.identity_manager.sign(&message.signing_bytes()?));
        Ok(message)
    }

    fn validate_incoming(
        &mut self,
        message: &NetworkMessage,
        source: std::net::SocketAddr,
    ) -> Result<(), String> {
        let age = chrono::Utc::now()
            .signed_duration_since(message.timestamp)
            .num_seconds()
            .abs();
        if age > 300 {
            return Err("timestamp outside five-minute replay window".into());
        }
        if self.seen_message_ids.contains(&message.id) {
            return Err("replayed message id".into());
        }
        let key = message
            .identity_key
            .as_deref()
            .ok_or("missing identity key")?;
        let fingerprint = message
            .identity_fingerprint
            .as_deref()
            .ok_or("missing fingerprint")?;
        let signature = message
            .identity_signature
            .as_deref()
            .ok_or("missing signature")?;
        let computed =
            IdentityManager::fingerprint_from_base64(key).map_err(|_| "invalid identity key")?;
        if computed != fingerprint {
            return Err("fingerprint does not match identity key".into());
        }
        let valid = IdentityManager::verify_signature(
            key,
            &message.signing_bytes().map_err(|_| "invalid message")?,
            signature,
        )
        .map_err(|_| "invalid signature encoding")?;
        if !valid {
            return Err("signature verification failed".into());
        }
        if let Ok((matches, Some(_))) = self.message_db.verify_identity(fingerprint, key) {
            if !matches {
                return Err("trusted identity key changed".into());
            }
        }

        use MessageType::*;
        match message.msg_type {
            ConnectionRequest
                if self.state.incoming_connection.is_some()
                    || matches!(
                        self.state.connection_status,
                        ConnectionStatus::Connected | ConnectionStatus::Establishing
                    ) =>
            {
                return Err("already connected to a peer".into())
            }
            ConnectionAccept | ConnectionDecline
                if !matches!(self.state.connection_status, ConnectionStatus::Establishing) =>
            {
                return Err("unexpected handshake response".into())
            }
            TextMessage | Disconnect | Ping | PingResponse
                if !matches!(
                    self.state.connection_status,
                    ConnectionStatus::Connected | ConnectionStatus::PeerDisconnected
                ) =>
            {
                return Err("message outside an established session".into())
            }
            _ => {}
        }
        if matches!(message.msg_type, ConnectionAccept | ConnectionDecline) {
            let expected = self
                .state
                .peer_ip
                .as_deref()
                .and_then(|v| v.parse::<std::net::SocketAddr>().ok());
            let actual = Some(source);
            if expected.zip(actual).is_some_and(|(a, b)| a.ip() != b.ip()) {
                return Err("handshake response came from a different host".into());
            }
        }
        if matches!(message.msg_type, ConnectionAccept | ConnectionDecline)
            && self
                .expected_identity
                .as_deref()
                .is_some_and(|expected| expected != key)
        {
            return Err("peer identity does not match invitation".into());
        }
        if matches!(
            message.msg_type,
            TextMessage | Disconnect | Ping | PingResponse
        ) && self.state.peer_ip.as_deref() != Some(source.to_string().as_str())
        {
            return Err("message came from a different session".into());
        }
        if let Some(expected) = &self.state.peer_identity_key {
            if !matches!(message.msg_type, ConnectionRequest) && expected != key {
                return Err("message identity differs from active peer".into());
            }
        }
        self.seen_message_ids.insert(message.id);
        self.seen_message_order.push_back(message.id);
        while self.seen_message_order.len() > 4096 {
            if let Some(old) = self.seen_message_order.pop_front() {
                self.seen_message_ids.remove(&old);
            }
        }
        Ok(())
    }

    /// Check for timeouts and other periodic tasks
    pub fn update(&mut self) -> Result<Vec<NetworkMessage>, Box<dyn std::error::Error>> {
        let mut messages = Vec::new();
        messages.extend(self.pending_network_messages.drain(..));

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

    fn select_security_level(&mut self, level: SecurityLevel) {
        if level.disable_persistent_history() == self.persistent_history {
            self.add_system_message("Switching to/from Maximum requires a restart so storage guarantees cannot be bypassed.".to_string());
        } else {
            self.config.security_level = level;
        }
        self.state.show_security_selection = false;
    }

    fn handle_char_input(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        let limit = match self.state.input_mode {
            InputMode::ConnectField => (self.state.connect_input.len(), 8192),
            _ => (self.state.message_input.len(), 16 * 1024),
        };
        if limit.0 + c.len_utf8() > limit.1 {
            return;
        }
        // While the security popup is open, digits select a level and all
        // other characters are swallowed instead of landing in an input field
        if self.state.show_security_selection {
            let level = match c {
                '0' => Some(SecurityLevel::Quick),
                '1' => Some(SecurityLevel::Tofu),
                '2' => Some(SecurityLevel::Secure),
                '3' => Some(SecurityLevel::Maximum),
                _ => None,
            };
            if let Some(level) = level {
                self.select_security_level(level);
            }
            return;
        }
        match self.state.input_mode {
            InputMode::ConnectField => self.state.connect_input.push(c),
            InputMode::MessageField => self.state.message_input.push(c),
            InputMode::IncomingResponse => {}
        }
    }

    fn handle_backspace(&mut self) {
        if self.state.show_security_selection {
            return;
        }
        match self.state.input_mode {
            InputMode::ConnectField => {
                self.state.connect_input.pop();
            }
            InputMode::MessageField => {
                self.state.message_input.pop();
            }
            InputMode::IncomingResponse => {}
        }
    }

    fn handle_enter(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if self.state.show_security_selection {
            return Ok(None);
        }
        match self.state.input_mode {
            InputMode::ConnectField => self.send_connection_request(),
            InputMode::MessageField => self.send_message(),
            InputMode::IncomingResponse => Ok(None),
        }
    }

    fn send_connection_request(
        &mut self,
    ) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        let input = self.state.connect_input.clone();
        match self.start_connection(&input) {
            Ok(()) => self.state.connect_input.clear(),
            Err(error) => self.add_system_message(error),
        }
        Ok(None)
    }

    fn send_message(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if !self.state.message_input.is_empty() {
            // Check for commands first - these can work even when not connected
            if self.state.message_input.starts_with('/') {
                return self.handle_command();
            }

            // For regular messages, require connection
            if !matches!(self.state.connection_status, ConnectionStatus::Connected) {
                self.add_system_message(
                    "Not connected to a peer. Use /help for available commands.".to_string(),
                );
                self.state.message_input.clear();
                return Ok(None);
            }

            if self.state.peer_identity_key.is_some() {
                let content = self.state.message_input.clone();

                // Store message encrypted with local storage key (unless Maximum security)
                if !self.config.security_level.disable_persistent_history() {
                    if let Some(peer_id) = &self.state.current_peer_id {
                        let result = self.crypto_manager.encrypt_for_storage(&content).and_then(
                            |encrypted| {
                                self.message_db
                                    .store_message(peer_id, &encrypted, true)
                                    .map(|_| ())
                            },
                        );
                        if let Err(error) = result {
                            self.add_system_message(format!(
                                "Could not save outgoing message: {error}"
                            ));
                        }
                    }
                }

                let msg = NetworkMessage::text_message(
                    format!("127.0.0.1:{}", self.config.port),
                    content,
                );

                self.add_message(self.state.message_input.clone(), MessageSource::Me);
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
        let original_input = self.state.message_input.trim().to_string();
        let parts: Vec<&str> = input.split_whitespace().collect();

        // Show the command the user entered
        self.add_message(original_input, MessageSource::Me);

        match parts.first().copied() {
            Some("/help") | Some("/h") | Some("/?") => {
                self.show_help();
            }
            Some("/fingerprint") | Some("/fp") => {
                self.show_fingerprint();
            }
            Some("/whoami") => {
                self.show_whoami();
            }
            Some("/alias") => {
                if parts.len() > 1 {
                    let alias = parts[1..].join(" ");
                    self.set_peer_alias(&alias);
                } else {
                    self.add_system_message("Usage: /alias <name>".to_string());
                }
            }
            Some("/untrust") => {
                if let Some(fingerprint) = &self.state.peer_fingerprint {
                    if let Err(error) = self.message_db.untrust_identity(fingerprint) {
                        self.add_system_message(format!("Could not remove trust: {error}"));
                    } else {
                        self.state.identity_status = IdentityStatus::Unknown;
                        self.add_system_message("Remembered trust removed. The current authenticated session remains open.".into());
                    }
                }
            }
            Some("/trust") => {
                self.trust_current_peer();
            }
            Some("/clear") => {
                self.state.messages.clear();
                self.state.message_scroll = 0;
                self.add_system_message("Messages cleared".to_string());
            }
            Some("/disconnect") | Some("/dc") => {
                self.state.message_input.clear();
                return self.send_disconnect_notification();
            }
            Some("/status") => {
                self.show_status();
            }
            Some("/invite") => match self.our_invitation() {
                Ok(invitation) => self.add_system_message(invitation),
                Err(error) => self.add_system_message(error),
            },
            Some("/connect") => {
                if parts.len() == 2 {
                    let target = parts[1].to_string();
                    if let Err(error) = self.start_connection(&target) {
                        self.add_system_message(error);
                    }
                } else {
                    self.add_system_message("Usage: /connect <invitation-or-IP:PORT>".into());
                }
            }
            Some("/myip") | Some("/ip") => {
                self.show_my_addresses();
            }
            Some(cmd) => {
                self.add_system_message(format!(
                    "Unknown command: {}. Type /help for available commands.",
                    cmd
                ));
            }
            None => {}
        }

        self.state.message_input.clear();
        Ok(None)
    }

    fn show_help(&mut self) {
        self.add_system_message("═══ Available Commands ═══".to_string());
        self.add_system_message("/help, /h        - Show this help message".to_string());
        self.add_system_message("/fingerprint, /fp - Show identity fingerprints".to_string());
        self.add_system_message(
            "/whoami          - Show your identity info + security warning".to_string(),
        );
        self.add_system_message("/alias <name>    - Set alias for current peer".to_string());
        self.add_system_message("/trust           - Remember current identity".to_string());
        self.add_system_message("/untrust         - Forget current identity trust".to_string());
        self.add_system_message(
            "/clear           - Clear visible messages; stored history remains".to_string(),
        );
        self.add_system_message("/disconnect, /dc - Disconnect from peer".to_string());
        self.add_system_message("/status          - Show connection status".to_string());
        self.add_system_message("/myip, /ip       - Show shareable addresses".to_string());
        self.add_system_message("/invite          - Show your invitation".into());
        self.add_system_message("/connect <peer>  - Connect using an invitation or address".into());
        self.add_system_message("═══ Keyboard Shortcuts ═══".to_string());
        self.add_system_message("Ctrl+C           - Quit application".to_string());
        self.add_system_message("Ctrl+D           - Disconnect from peer".to_string());
        self.add_system_message("Ctrl+S           - Open security level selection".to_string());
        self.add_system_message(
            "Ctrl+Y           - Copy shareable address to clipboard".to_string(),
        );
        self.add_system_message("Tab              - Switch between input fields".to_string());
        self.add_system_message("PageUp/Down      - Scroll messages".to_string());
        self.add_system_message("Ctrl+Home/End    - Scroll to top/bottom".to_string());
        self.add_system_message("═══ Security Levels (F1-F4) ═══".to_string());
        self.add_system_message(format!(
            "Current: {}",
            self.config.security_level.display_name()
        ));
        self.add_system_message(
            "F1/0: Quick    - Signed + encrypted, session approval".to_string(),
        );
        self.add_system_message("F2/1: TOFU     - Persistent identity pinning".to_string());
        self.add_system_message(
            "F3/2: Secure   - Authenticated forward-secret sessions".to_string(),
        );
        self.add_system_message("F4/3: Maximum  - Memory-only history/trust".to_string());
    }

    fn show_whoami(&mut self) {
        self.add_system_message("═══ Your Identity ═══".to_string());
        if let Some(our_fp) = &self.state.our_fingerprint {
            self.add_system_message(format!("Fingerprint: {}", our_fp));
        }
        self.add_system_message(format!(
            "Identity file: {}",
            self.identity_manager.get_identity_path()
        ));
        self.add_system_message("Your identity file contains your private key. Share the invitation or fingerprint; keep the file private.".into());
    }

    fn copy_shareable_address(&mut self) {
        match self.our_invitation() {
            Ok(invitation) => {
                match crate::ui::terminal::copy_to_clipboard(&invitation) {
                    Ok(()) => self.add_system_message("Invitation sent to clipboard. If your terminal blocks OSC 52, use /invite or p2p-cli --invite.".into()),
                    Err(error) => self.add_system_message(format!("Clipboard failed: {error}. Use /invite.")),
                }
            }
            Err(error) => self.add_system_message(error),
        }
    }

    pub fn show_my_addresses(&mut self) {
        let (addresses, notes) = crate::network::addr::local_addresses_with_diagnostics();
        for address in addresses {
            self.add_system_message(format!(
                "Local candidate: {}",
                std::net::SocketAddr::new(address, self.config.port)
            ));
        }
        for note in notes {
            self.add_system_message(note);
        }
        for address in self.invitation_addresses.clone() {
            self.add_system_message(format!("Advertised candidate: {address}"));
        }
    }

    fn show_fingerprint(&mut self) {
        if let Some(our_fp) = &self.state.our_fingerprint {
            self.add_system_message(format!("Your fingerprint: {}", our_fp));
        }
        if let Some(peer_fp) = &self.state.peer_fingerprint {
            let status = match self.state.identity_status {
                IdentityStatus::Verified => " ✓ VERIFIED",
                IdentityStatus::Unknown => " (unknown)",
                IdentityStatus::Mismatch => " ⚠ MISMATCH!",
                IdentityStatus::LocalSelf => " 🏠 LOCAL/SELF",
                IdentityStatus::ClonedIdentity => " ⚠ CLONED IDENTITY!",
                IdentityStatus::None => "",
            };
            self.add_system_message(format!("Peer fingerprint: {}{}", peer_fp, status));
        } else {
            self.add_system_message("No peer connected or peer has no identity".to_string());
        }
    }

    fn set_peer_alias(&mut self, alias: &str) {
        if alias.chars().count() > 64 {
            self.add_system_message("Alias must be at most 64 characters".into());
            return;
        }
        if let Some(fingerprint) = &self.state.peer_fingerprint {
            if let Err(e) = self.message_db.set_identity_alias(fingerprint, alias) {
                self.add_system_message(format!("Failed to set alias: {}", e));
            } else {
                self.state.peer_alias = Some(alias.to_string());
                self.add_system_message(format!("Alias set to: {}", alias));
            }
        } else {
            self.add_system_message("Cannot set alias: peer has no identity".to_string());
        }
    }

    fn trust_current_peer(&mut self) {
        if let (Some(fingerprint), Some(identity_key)) =
            (&self.state.peer_fingerprint, &self.state.peer_identity_key)
        {
            if let Err(e) = self.message_db.trust_identity(
                fingerprint,
                identity_key,
                TrustLevel::Trusted,
                self.state.peer_alias.as_deref(),
            ) {
                self.add_system_message(format!("Failed to trust peer: {}", e));
            } else {
                self.state.identity_status = IdentityStatus::Verified;
                self.add_system_message(format!(
                    "Peer {} is trusted{}",
                    fingerprint,
                    if self.persistent_history {
                        " persistently"
                    } else {
                        " for this run"
                    }
                ));
            }
        } else {
            self.add_system_message("Cannot trust: peer has no identity".to_string());
        }
    }

    fn show_status(&mut self) {
        self.add_system_message(format!(
            "Security level: {}",
            self.config.security_level.display_name()
        ));
        if let Some(negotiated) = self.state.negotiated_security_level {
            self.add_system_message(format!("Negotiated level: {}", negotiated.display_name()));
        }
        self.add_system_message(format!("Identity status: {:?}", self.state.identity_status));
        if let Some(peer_ip) = &self.state.peer_ip {
            self.add_system_message(format!("Connected to: {}", peer_ip));
        }
    }

    fn accept_connection(
        &mut self,
        trust_level: TrustLevel,
    ) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if let Some(incoming) = self.state.incoming_connection.clone() {
            // Report the weaker endpoint policy as the effective shared level.
            let negotiated_level = self
                .config
                .security_level
                .negotiate_with(incoming.security_level);

            let msg = NetworkMessage::connection_accept(
                format!("127.0.0.1:{}", self.config.port),
                self.identity_manager.get_public_key_base64(),
                self.config.security_level,
            );

            // Store/update peer in database
            if let Ok(peer_id) = self.message_db.get_or_create_peer(
                incoming
                    .identity_key
                    .as_deref()
                    .ok_or("missing authenticated peer identity")?,
                &incoming.from_ip,
            ) {
                self.state.current_peer_id = Some(peer_id.clone());
            }

            // Handle TOFU identity trust
            if let (Some(identity_key), Some(fingerprint)) =
                (&incoming.identity_key, &incoming.identity_fingerprint)
            {
                self.state.peer_identity_key = Some(identity_key.clone());
                self.state.peer_fingerprint = Some(fingerprint.clone());
                self.state.identity_status = incoming.identity_status;
                self.state.peer_alias = incoming.identity_alias.clone();

                // Trust the identity if requested (but not for LocalSelf - that's auto-trusted)
                if trust_level == TrustLevel::Trusted
                    && incoming.identity_status == IdentityStatus::Unknown
                    && self.config.security_level != SecurityLevel::Quick
                {
                    let _ = self.message_db.trust_identity(
                        fingerprint,
                        identity_key,
                        trust_level,
                        None,
                    );
                    self.state.identity_status = IdentityStatus::Verified;
                }
            }

            // Set localhost flag
            self.state.is_localhost = incoming.is_localhost;

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
                IdentityStatus::LocalSelf => " [🏠 LOCAL/SELF]",
                IdentityStatus::ClonedIdentity => " [⚠ CLONED IDENTITY - DANGER!]",
                IdentityStatus::None => "",
            };
            self.add_system_message(format!(
                "Connection established! Security: {}{}",
                negotiated_level.display_name(),
                identity_info
            ));

            return Ok(Some(msg));
        }
        Ok(None)
    }

    fn decline_connection(&mut self) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if let Some(incoming) = &self.state.incoming_connection {
            self.state.previous_peer_ip = Some(incoming.from_ip.clone());
            let msg = NetworkMessage::connection_decline(format!("127.0.0.1:{}", self.config.port));

            self.state.incoming_connection = None;
            self.state.input_mode = InputMode::ConnectField;

            return Ok(Some(msg));
        }
        Ok(None)
    }

    fn send_disconnect_notification(
        &mut self,
    ) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        if matches!(self.state.connection_status, ConnectionStatus::Connected) {
            let msg = NetworkMessage::disconnect(format!("127.0.0.1:{}", self.config.port));
            // Save peer IP before resetting so the message can be sent
            self.state.previous_peer_ip = self.state.peer_ip.clone();
            // Reset local connection state after disconnecting
            self.add_system_message("Disconnected from peer.".to_string());
            self.reset_connection_state();
            return Ok(Some(msg));
        } else if matches!(
            self.state.connection_status,
            ConnectionStatus::PeerDisconnected
        ) {
            // Peer already disconnected, just reset our state locally
            self.add_system_message("Session closed.".to_string());
            self.reset_connection_state();
        }
        Ok(None)
    }

    /// Check if an IP address is localhost
    fn is_localhost_ip(ip: &str) -> bool {
        // Try parsing as socket addr first
        if let Ok(sock) = ip.parse::<std::net::SocketAddr>() {
            return sock.ip().is_loopback();
        }
        // Try parsing as ip-only
        if let Ok(ipaddr) = ip.parse::<std::net::IpAddr>() {
            return ipaddr.is_loopback();
        }
        // fallback to hostname check
        ip.eq_ignore_ascii_case("localhost")
    }

    /// Parse user input into a SocketAddr, handling IPv6 bracketed notation and hostname without port
    fn parse_socket_addr(input: &str, default_port: u16) -> Option<std::net::SocketAddr> {
        // Try as-is
        if let Ok(addr) = input.parse::<std::net::SocketAddr>() {
            return Some(addr);
        }

        // If it contains colon(s), it might be a bare IPv6 address
        if input.contains(':') {
            // Attempt to bracket and append port
            let bracketed = format!(
                "[{}]:{}",
                input.trim_matches(|c| c == '[' || c == ']'),
                default_port
            );
            if let Ok(addr) = bracketed.parse::<std::net::SocketAddr>() {
                return Some(addr);
            }
        } else {
            // Hostname or IPv4 without port
            let appended = format!("{}:{}", input, default_port);
            if let Ok(addr) = appended.parse::<std::net::SocketAddr>() {
                return Some(addr);
            }
        }

        None
    }

    /// Verify peer identity for TOFU mode
    /// Returns (IdentityStatus, is_localhost)
    fn verify_peer_identity(
        &mut self,
        identity_key: &str,
        fingerprint: &str,
        peer_ip: &str,
    ) -> (IdentityStatus, bool) {
        let is_localhost = Self::is_localhost_ip(peer_ip);

        // The full application message signature was verified before dispatch.
        // Recompute the fingerprint locally; never trust the advertised value.
        if IdentityManager::fingerprint_from_base64(identity_key)
            .ok()
            .as_deref()
            != Some(fingerprint)
        {
            return (IdentityStatus::Mismatch, is_localhost);
        }

        // Check if this is our own fingerprint
        if let Some(our_fp) = &self.state.our_fingerprint {
            if fingerprint == our_fp {
                if is_localhost {
                    // Same fingerprint via localhost = local/self connection
                    return (IdentityStatus::LocalSelf, true);
                } else {
                    // Same fingerprint from remote IP = someone cloned our identity!
                    return (IdentityStatus::ClonedIdentity, false);
                }
            }
        }

        // Check if we have this identity in our trust database
        match self.message_db.verify_identity(fingerprint, identity_key) {
            Ok((matches, Some(trusted))) => {
                if matches
                    && matches!(
                        trusted.trust_level,
                        TrustLevel::Trusted | TrustLevel::Verified
                    )
                {
                    // Known and verified
                    self.state.peer_alias = trusted.alias.clone();
                    (IdentityStatus::Verified, is_localhost)
                } else if matches {
                    (IdentityStatus::Unknown, is_localhost)
                } else {
                    (IdentityStatus::Mismatch, is_localhost)
                }
            }
            Ok((_, None)) => {
                // New identity - not trusted yet
                (IdentityStatus::Unknown, is_localhost)
            }
            Err(_) => (IdentityStatus::Unknown, is_localhost),
        }
    }

    fn handle_network_message(&mut self, msg: NetworkMessage) {
        match msg.msg_type {
            MessageType::ConnectionRequest => {
                if let Some(public_key) = msg.public_key {
                    let peer_security_level = msg.security_level.unwrap_or(SecurityLevel::Quick);

                    // Check identity if TOFU mode
                    let (identity_status, identity_alias, is_localhost) =
                        if let (Some(id_key), Some(fp)) =
                            (&msg.identity_key, &msg.identity_fingerprint)
                        {
                            let (status, is_local) =
                                self.verify_peer_identity(id_key, fp, &msg.from_ip);
                            let alias = if status == IdentityStatus::Verified
                                || status == IdentityStatus::LocalSelf
                            {
                                if status == IdentityStatus::LocalSelf {
                                    Some("You (local)".to_string())
                                } else {
                                    self.message_db
                                        .get_trusted_identity(fp)
                                        .ok()
                                        .flatten()
                                        .and_then(|t| t.alias)
                                }
                            } else {
                                None
                            };
                            (status, alias, is_local)
                        } else {
                            (
                                IdentityStatus::None,
                                None,
                                Self::is_localhost_ip(&msg.from_ip),
                            )
                        };

                    self.state.incoming_connection = Some(IncomingConnection {
                        from_ip: msg.from_ip,
                        public_key,
                        security_level: peer_security_level,
                        expires_at: Instant::now() + std::time::Duration::from_secs(90),
                        identity_key: msg.identity_key,
                        identity_fingerprint: msg.identity_fingerprint,
                        identity_status,
                        identity_alias,
                        is_localhost,
                    });
                    self.state.input_mode = InputMode::IncomingResponse;
                }
            }
            MessageType::ConnectionAccept => {
                if let Some(public_key) = msg.public_key {
                    let peer_security_level = msg.security_level.unwrap_or(SecurityLevel::Quick);
                    let negotiated_level = self
                        .config
                        .security_level
                        .negotiate_with(peer_security_level);

                    if let Ok(peer_id) = self.message_db.get_or_create_peer(
                        msg.identity_key.as_deref().expect("validated identity"),
                        &msg.from_ip,
                    ) {
                        self.state.current_peer_id = Some(peer_id.clone());
                    }

                    // Handle identity verification
                    let (identity_status, is_localhost) = if let (Some(id_key), Some(fp)) =
                        (&msg.identity_key, &msg.identity_fingerprint)
                    {
                        let (status, is_local) =
                            self.verify_peer_identity(id_key, fp, &msg.from_ip);
                        self.state.peer_identity_key = Some(id_key.clone());
                        self.state.peer_fingerprint = Some(fp.clone());
                        if status == IdentityStatus::LocalSelf {
                            self.state.peer_alias = Some("You (local)".to_string());
                        }
                        (status, is_local)
                    } else {
                        (IdentityStatus::None, Self::is_localhost_ip(&msg.from_ip))
                    };
                    self.state.identity_status = identity_status;
                    self.state.is_localhost = is_localhost;

                    self.state.peer_public_key = Some(public_key);
                    self.state.peer_security_level = Some(peer_security_level);
                    self.state.negotiated_security_level = Some(negotiated_level);
                    self.state.connection_status = ConnectionStatus::Connected;
                    self.state.input_mode = InputMode::MessageField;
                    self.pending_candidates.clear();
                    if self.expected_identity.is_some() {
                        self.state.identity_status = IdentityStatus::Verified;
                        if self.config.security_level != SecurityLevel::Quick {
                            self.trust_current_peer();
                        }
                    }
                    self.state.connected_at = Some(Instant::now());
                    self.state.last_activity = Instant::now();

                    self.reload_current_peer_history();

                    let identity_info = match identity_status {
                        IdentityStatus::Verified => " [✓ VERIFIED]",
                        IdentityStatus::Unknown => " [unknown identity]",
                        IdentityStatus::Mismatch => " [⚠ IDENTITY MISMATCH!]",
                        IdentityStatus::LocalSelf => " [🏠 LOCAL/SELF]",
                        IdentityStatus::ClonedIdentity => " [⚠ CLONED IDENTITY - DANGER!]",
                        IdentityStatus::None => "",
                    };
                    self.add_system_message(format!(
                        "Connection established! Security: {}{}",
                        negotiated_level.display_name(),
                        identity_info
                    ));
                }
            }
            MessageType::ConnectionDecline => {
                self.state.connection_status = ConnectionStatus::Online;
                self.state.peer_ip = None;
                self.add_system_message("Connection declined by peer".to_string());
            }
            MessageType::Disconnect => {
                self.add_system_message(
                    "Peer disconnected. Press Ctrl+D to close this session.".to_string(),
                );
                // Don't fully reset - just mark as peer disconnected so user can still see messages
                self.state.connection_status = ConnectionStatus::PeerDisconnected;
                // Clear crypto state since peer is gone
                self.state.pending_ping = None;
                self.state.last_ping_sent = None;
            }
            MessageType::TextMessage => {
                if self.persistent_history {
                    if let Some(peer_id) = &self.state.current_peer_id {
                        let result = self
                            .crypto_manager
                            .encrypt_for_storage(&msg.content)
                            .and_then(|encrypted| {
                                self.message_db
                                    .store_message(peer_id, &encrypted, false)
                                    .map(|_| ())
                            });
                        if let Err(error) = result {
                            self.add_system_message(format!(
                                "Could not save received message: {error}"
                            ));
                        }
                    }
                }
                self.add_message(msg.content, MessageSource::Peer);
                self.state.last_activity = Instant::now();
            }
            MessageType::Ping => {
                self.state.last_activity = Instant::now();
                self.pending_network_messages
                    .push_back(NetworkMessage::ping_response(
                        format!("127.0.0.1:{}", self.config.port),
                        msg.id,
                    ));
            }
            MessageType::PingResponse => {
                if let Some(pending_ping_id) = self.state.pending_ping {
                    if pending_ping_id == msg.id {
                        self.state.pending_ping = None;
                        self.state.last_activity = Instant::now();
                    }
                }
            }
        }
    }

    fn add_message(&mut self, content: String, source: MessageSource) {
        let content = terminal_text(&content);
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.state.messages.push_back(ChatMessage {
            content,
            source,
            timestamp,
        });

        // Keep only last 100 messages
        while self.state.messages.len() > 100 {
            self.state.messages.pop_front();
        }
    }

    fn add_system_message(&mut self, content: String) {
        self.add_message(content, MessageSource::System);
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
            match self
                .crypto_manager
                .decrypt_from_storage(&stored_msg.content)
            {
                Ok(decrypted_content) => {
                    self.state.messages.push_back(ChatMessage {
                        content: terminal_text(&decrypted_content),
                        source: if stored_msg.is_outgoing {
                            MessageSource::Me
                        } else {
                            MessageSource::Peer
                        },
                        timestamp: stored_msg.timestamp.clone(),
                    });
                }
                Err(_) => {
                    self.state.messages.push_back(ChatMessage {
                        content: "[Encrypted message - storage decryption failed]".to_string(),
                        source: if stored_msg.is_outgoing {
                            MessageSource::Me
                        } else {
                            MessageSource::Peer
                        },
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

    fn check_session_timeout(
        &mut self,
    ) -> Result<Option<NetworkMessage>, Box<dyn std::error::Error>> {
        let now = Instant::now();
        let time_since_activity = now.duration_since(self.state.last_activity).as_secs();

        // Handle PeerDisconnected state - auto-reset after 5 minutes of inactivity
        if matches!(
            self.state.connection_status,
            ConnectionStatus::PeerDisconnected
        ) {
            if time_since_activity >= 300 {
                self.add_system_message(
                    "Session auto-closed after peer disconnect timeout.".to_string(),
                );
                self.reset_connection_state();
            }
            return Ok(None);
        }

        if !matches!(self.state.connection_status, ConnectionStatus::Connected) {
            return Ok(None);
        }

        // Check if session should timeout (5 minutes)
        if time_since_activity >= 300 {
            self.disconnect_with_timeout();
            return Ok(None);
        }

        // Check if we should send a ping (every minute)
        if self.state.last_ping_sent.is_none()
            || now
                .duration_since(self.state.last_ping_sent.unwrap())
                .as_secs()
                >= 60
        {
            return Ok(Some(self.send_ping()?));
        }

        Ok(None)
    }

    fn send_ping(&mut self) -> Result<NetworkMessage, Box<dyn std::error::Error>> {
        let ping_id = Uuid::new_v4();
        let mut ping_msg = NetworkMessage::ping(format!("127.0.0.1:{}", self.config.port));
        ping_msg.id = ping_id;

        self.state.pending_ping = Some(ping_id);
        self.state.last_ping_sent = Some(Instant::now());

        Ok(ping_msg)
    }

    fn disconnect_with_timeout(&mut self) {
        self.state.previous_peer_ip = self.state.peer_ip.clone();
        self.reset_connection_state();
        self.add_system_message("Session timed out due to inactivity".to_string());

        if let Some(prev_ip) = &self.state.previous_peer_ip {
            self.state.connect_input = prev_ip.clone();
        }
    }

    fn reset_connection_state(&mut self) {
        self.state.connection_status = ConnectionStatus::Online;
        self.state.peer_ip = None;
        self.state.peer_public_key = None;
        self.state.peer_identity_key = None;
        self.state.peer_fingerprint = None;
        self.state.peer_alias = None;
        self.state.identity_status = IdentityStatus::None;
        self.state.incoming_connection = None;
        self.expected_identity = None;
        self.pending_candidates.clear();
        self.pending_network_messages.clear();
        self.state.peer_security_level = None;
        self.state.negotiated_security_level = None;
        self.state.current_peer_id = None;
        self.state.connected_at = None;
        self.state.last_activity = Instant::now();
        self.state.last_ping_sent = None;
        self.state.pending_ping = None;
        self.state.input_mode = InputMode::ConnectField;
        // Keep diagnostics and the visible transcript after a transport failure.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_request_uses_observed_address_after_verification() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Arc::new(IdentityManager::new(dir.path().join("identity")).unwrap());
        let config = AppConfig::default();
        let mut app = App {
            state: AppState::new(config.port, config.security_level),
            config,
            crypto_manager: CryptoManager::new(false).unwrap(),
            identity_manager: identity.clone(),
            message_db: MessageDB::new_in_memory().unwrap(),
            seen_message_ids: HashSet::new(),
            seen_message_order: VecDeque::new(),
            persistent_history: false,
            pending_network_messages: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            expected_identity: None,
            invitation_addresses: Vec::new(),
        };
        let mut message = NetworkMessage::connection_request(
            "127.0.0.1:8080".into(),
            "session".into(),
            SecurityLevel::Tofu,
        );
        message.identity_key = Some(identity.get_public_key_base64());
        message.identity_fingerprint = Some(identity.get_fingerprint());
        message.identity_signature = Some(identity.sign(&message.signing_bytes().unwrap()));
        let observed = "192.0.2.1:49152".parse().unwrap();
        let _ = app.handle_network_event(NetworkEvent::MessageReceived(message.clone(), observed));
        assert_eq!(
            app.state.incoming_connection.as_ref().unwrap().from_ip,
            observed.to_string()
        );
        assert!(app
            .validate_incoming(&message, observed)
            .unwrap_err()
            .contains("replayed"));
    }

    #[test]
    fn parse_ipv4_without_port() {
        let addr = App::parse_socket_addr("127.0.0.1", 8080).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn parse_ipv4_with_port() {
        let addr = App::parse_socket_addr("127.0.0.1:9000", 8080).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:9000");
    }

    #[test]
    fn parse_ipv6_without_port() {
        let addr = App::parse_socket_addr("::1", 8080).unwrap();
        assert_eq!(addr.to_string(), "[::1]:8080");
    }

    #[test]
    fn parse_ipv6_with_port_bracketed() {
        let addr = App::parse_socket_addr("[::1]:9000", 8080).unwrap();
        assert_eq!(addr.to_string(), "[::1]:9000");
    }

    #[test]
    fn is_localhost_checks() {
        assert!(App::is_localhost_ip("127.0.0.1"));
        assert!(App::is_localhost_ip("127.0.0.1:8080"));
        assert!(App::is_localhost_ip("::1"));
        assert!(App::is_localhost_ip("[::1]:8080"));
        assert!(App::is_localhost_ip("localhost"));
    }
}

#[cfg(test)]
mod security_tests;

/// Peer content must never reach the terminal as control sequences.
fn terminal_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            (!c.is_control() || *c == '\n')
                && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}
