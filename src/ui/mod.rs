use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use std::io::Stdout;
use std::time::Instant;

pub mod terminal;
pub mod renderer;
pub mod input;

pub use terminal::TerminalManager;
pub use renderer::Renderer;
pub use input::InputHandler;

// Re-export commonly used types
pub use crossterm::event::{Event, KeyEvent};
pub use ratatui::Frame;

/// Events that the UI can generate
#[derive(Debug, Clone)]
pub enum UiEvent {
    KeyPress(KeyCode, KeyModifiers),
    Tab,
    Enter,
    Backspace,
    Quit,
    Disconnect,
    AcceptConnection,
    DeclineConnection,
    /// Accept connection but only for this session (don't permanently trust)
    AcceptConnectionOnce,
    CharInput(char),
    Resize(u16, u16),
    SecurityLevelSelect(SecurityLevel),
    ShowSecuritySelection,
    /// Scroll messages up
    ScrollUp,
    /// Scroll messages down
    ScrollDown,
    /// Scroll messages to top
    ScrollTop,
    /// Scroll messages to bottom
    ScrollBottom,
}

/// Verification status for TOFU identity
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IdentityStatus {
    /// No identity verification (Level 0)
    None,
    /// Unknown identity - never seen before
    Unknown,
    /// Identity matches trusted record
    Verified,
    /// Identity mismatch - potential impersonation!
    Mismatch,
}

/// Current state of the UI inputs and display
#[derive(Debug, Clone)]
pub struct UiState {
    pub input_mode: InputMode,
    pub connect_input: String,
    pub message_input: String,
    pub connection_status: ConnectionStatus,
    pub security_level: SecurityLevel,
    pub peer_security_level: Option<SecurityLevel>,
    pub negotiated_security_level: Option<SecurityLevel>,
    pub peer_ip: Option<String>,
    pub connected_at: Option<Instant>,
    pub last_activity: Instant,
    pub last_ping_sent: Option<Instant>,
    pub pending_ping: bool,
    pub messages: Vec<ChatMessage>,
    pub incoming_connection: Option<IncomingConnection>,
    pub port: u16,
    pub show_security_selection: bool,
    /// Our identity fingerprint
    pub our_fingerprint: Option<String>,
    /// Peer's identity fingerprint (for TOFU)
    pub peer_fingerprint: Option<String>,
    /// Peer's identity alias (if set)
    pub peer_alias: Option<String>,
    /// Identity verification status
    pub identity_status: IdentityStatus,
    /// Current scroll position in messages (0 = bottom/latest)
    pub message_scroll: usize,
}

/// Input modes for the terminal interface
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    ConnectField,
    MessageField,
    IncomingResponse,
    SecuritySelection,
}

/// Connection status for UI display
#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Online,
    Establishing,
    Connected,
    Disconnected,
}

// Re-export SecurityLevel from app module
pub use crate::app::SecurityLevel;

/// Source of a chat message
#[derive(Debug, Clone, PartialEq)]
pub enum MessageSource {
    Me,
    Peer,
    System,
}

/// Chat message for display
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub content: String,
    pub source: MessageSource,
    pub timestamp: String,
}

/// Incoming connection information
#[derive(Debug, Clone)]
pub struct IncomingConnection {
    pub from_ip: String,
    pub public_key: String,
    pub security_level: SecurityLevel,
    pub expires_at: Instant,
    /// Identity public key (for TOFU verification)
    pub identity_key: Option<String>,
    /// Identity fingerprint
    pub identity_fingerprint: Option<String>,
    /// Whether the identity is known/trusted
    pub identity_status: IdentityStatus,
    /// Alias if known
    pub identity_alias: Option<String>,
}

/// Main UI manager that coordinates terminal, rendering, and input
pub struct UiManager {
    terminal_manager: TerminalManager,
    renderer: Renderer,
    input_handler: InputHandler,
}

impl UiManager {
    /// Create a new UI manager and initialize the terminal
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let terminal_manager = TerminalManager::new()?;
        let renderer = Renderer::new();
        let input_handler = InputHandler::new();

        Ok(Self {
            terminal_manager,
            renderer,
            input_handler,
        })
    }

    /// Get the next UI event (blocks until event available)
    pub fn next_event(&mut self) -> Result<Option<UiEvent>, Box<dyn std::error::Error>> {
        self.input_handler.next_event()
    }

    /// Poll for UI events with timeout (non-blocking)
    pub fn poll_event(&mut self, timeout_ms: u64) -> Result<Option<UiEvent>, Box<dyn std::error::Error>> {
        self.input_handler.poll_event(timeout_ms)
    }

    /// Render the current UI state
    pub fn render(&mut self, state: &UiState) -> Result<(), Box<dyn std::error::Error>> {
        self.terminal_manager.draw(|frame| {
            self.renderer.render(frame, state);
        })?;
        Ok(())
    }

    /// Clean up terminal on exit
    pub fn cleanup(self) -> Result<(), Box<dyn std::error::Error>> {
        self.terminal_manager.cleanup()
    }

    /// Get terminal size
    pub fn size(&self) -> Result<(u16, u16), Box<dyn std::error::Error>> {
        self.terminal_manager.size()
    }
}