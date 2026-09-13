use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};

/// Manages terminal setup, cleanup, and drawing
pub struct TerminalManager {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalManager {
    /// Initialize the terminal for TUI mode
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        // Mouse capture is intentionally NOT enabled: the app has no mouse
        // interactions, and capture would break the terminal's native
        // select-to-copy for addresses and fingerprints
        if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableBracketedPaste) {
            let _ = execute!(stdout, DisableBracketedPaste, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return Err(error.into());
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                return Err(error.into());
            }
        };

        Ok(Self { terminal })
    }

    /// Draw using the provided closure
    pub fn draw<F>(&mut self, f: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut ratatui::Frame),
    {
        self.terminal.draw(f)?;
        Ok(())
    }

    /// Get terminal size
    pub fn size(&self) -> Result<(u16, u16), Box<dyn std::error::Error>> {
        let size = self.terminal.size()?;
        Ok((size.width, size.height))
    }

    /// Clean up terminal and restore normal mode
    pub fn cleanup(mut self) -> Result<(), Box<dyn std::error::Error>> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            DisableBracketedPaste,
            LeaveAlternateScreen
        )?;
        self.terminal.show_cursor()?;
        Ok(())
    }
}

/// Copy text to the system clipboard via the OSC 52 escape sequence.
/// Supported by most modern terminals (incl. over SSH); harmlessly
/// ignored by terminals that don't support it.
pub fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    use std::io::Write;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut stdout = io::stdout();
    write!(stdout, "\x1b]52;c;{}\x07", encoded)?;
    stdout.flush()?;
    Ok(())
}

impl Drop for TerminalManager {
    fn drop(&mut self) {
        // Ensure cleanup happens even if cleanup() wasn't called
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableBracketedPaste,
            LeaveAlternateScreen
        );
        let _ = self.terminal.show_cursor();
    }
}
