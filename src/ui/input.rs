use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use std::time::Duration;

use super::UiEvent;

/// Handles input events and converts them to UI events
pub struct InputHandler;

impl InputHandler {
    pub fn new() -> Self {
        Self
    }

    /// Get the next input event (blocking)
    pub fn next_event(&mut self) -> Result<Option<UiEvent>, Box<dyn std::error::Error>> {
        loop {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if let Some(ui_event) = self.convert_key_event(key.code, key.modifiers) {
                        return Ok(Some(ui_event));
                    }
                }
            }
        }
    }

    /// Poll for input events with timeout (non-blocking)
    pub fn poll_event(&mut self, timeout_ms: u64) -> Result<Option<UiEvent>, Box<dyn std::error::Error>> {
        if event::poll(Duration::from_millis(timeout_ms))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if let Some(ui_event) = self.convert_key_event(key.code, key.modifiers) {
                        return Ok(Some(ui_event));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Convert crossterm key events to UI events
    fn convert_key_event(&self, key_code: KeyCode, modifiers: KeyModifiers) -> Option<UiEvent> {
        use crate::app::SecurityLevel;
        
        match key_code {
            // Ctrl+C: Quit
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UiEvent::Quit)
            }
            // Ctrl+D: Disconnect
            KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UiEvent::Disconnect)
            }
            // Ctrl+S: Show security selection
            KeyCode::Char('s') if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UiEvent::ShowSecuritySelection)
            }
            // Navigation and basic input
            KeyCode::Tab => Some(UiEvent::Tab),
            KeyCode::Enter => Some(UiEvent::Enter),
            KeyCode::Backspace => Some(UiEvent::Backspace),
            // Connection response keys
            KeyCode::Char('a') => Some(UiEvent::AcceptConnection),
            KeyCode::Char('d') => Some(UiEvent::DeclineConnection),
            KeyCode::Char('o') => Some(UiEvent::AcceptConnectionOnce),
            // Security level selection with F-keys
            KeyCode::F(1) => Some(UiEvent::SecurityLevelSelect(SecurityLevel::Quick)),
            KeyCode::F(2) => Some(UiEvent::SecurityLevelSelect(SecurityLevel::Tofu)),
            KeyCode::F(3) => Some(UiEvent::SecurityLevelSelect(SecurityLevel::Secure)),
            KeyCode::F(4) => Some(UiEvent::SecurityLevelSelect(SecurityLevel::Maximum)),
            // Scrolling controls
            KeyCode::PageUp => Some(UiEvent::ScrollUp),
            KeyCode::PageDown => Some(UiEvent::ScrollDown),
            KeyCode::Home if modifiers.contains(KeyModifiers::CONTROL) => Some(UiEvent::ScrollTop),
            KeyCode::End if modifiers.contains(KeyModifiers::CONTROL) => Some(UiEvent::ScrollBottom),
            KeyCode::Up if modifiers.contains(KeyModifiers::CONTROL) => Some(UiEvent::ScrollUp),
            KeyCode::Down if modifiers.contains(KeyModifiers::CONTROL) => Some(UiEvent::ScrollDown),
            // Escape and other keys
            KeyCode::Esc => Some(UiEvent::KeyPress(key_code, modifiers)),
            // Regular character input
            KeyCode::Char(c) => Some(UiEvent::CharInput(c)),
            // Pass through other key presses
            _ => Some(UiEvent::KeyPress(key_code, modifiers)),
        }
    }
}