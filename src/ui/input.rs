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
        match key_code {
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UiEvent::Quit)
            }
            KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UiEvent::Disconnect)
            }
            KeyCode::Tab => Some(UiEvent::Tab),
            KeyCode::Enter => Some(UiEvent::Enter),
            KeyCode::Backspace => Some(UiEvent::Backspace),
            KeyCode::Char('a') => Some(UiEvent::AcceptConnection),
            KeyCode::Char('d') => Some(UiEvent::DeclineConnection),
            KeyCode::Char(c) => Some(UiEvent::CharInput(c)),
            _ => Some(UiEvent::KeyPress(key_code, modifiers)),
        }
    }
}