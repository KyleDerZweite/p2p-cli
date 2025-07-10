use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::time::Instant;

use super::{UiState, InputMode, ConnectionStatus, SecurityLevel, ChatMessage, IncomingConnection};

/// Handles all UI rendering logic
pub struct Renderer;

impl Renderer {
    pub fn new() -> Self {
        Self
    }

    /// Main render function - renders the entire UI
    pub fn render(&self, frame: &mut Frame, state: &UiState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Connect field
                Constraint::Length(5),  // Connection status / incoming connection
                Constraint::Min(5),     // Messages
                Constraint::Length(5),  // Message input
            ])
            .split(frame.size());

        self.render_connect_field(frame, chunks[0], state);
        self.render_connection_info(frame, chunks[1], state);
        self.render_messages(frame, chunks[2], state);
        self.render_message_input(frame, chunks[3], state);
        
        // Render security selection overlay if needed
        if state.show_security_selection {
            self.render_security_selection(frame, state);
        }
    }

    /// Render the connection input field with security level indicator
    fn render_connect_field(&self, frame: &mut Frame, area: ratatui::layout::Rect, state: &UiState) {
        let connect_style = if state.input_mode == InputMode::ConnectField {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let security_indicator = if let Some(negotiated_level) = state.negotiated_security_level {
            if negotiated_level != SecurityLevel::Quick {
                format!(" [{}]", negotiated_level.display_name())
            } else {
                String::new()
            }
        } else if state.security_level != SecurityLevel::Quick {
            format!(" [{}]", state.security_level.display_name())
        } else {
            String::new()
        };

        let title = format!(
            "Connect to IP:PORT (Listening on: {}){} (Ctrl+C=quit, Ctrl+D=disconnect, Ctrl+S=security)",
            state.port,
            security_indicator
        );

        let widget = Paragraph::new(state.connect_input.as_str())
            .style(connect_style)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: true });
        
        frame.render_widget(widget, area);
    }

    /// Render connection status and incoming connection info
    fn render_connection_info(&self, frame: &mut Frame, area: ratatui::layout::Rect, state: &UiState) {
        let mut text_lines = Vec::new();
        let mut title = String::new();
        let mut style = Style::default();

        // Show current connection if connected
        if let Some(peer_ip) = &state.peer_ip {
            if let Some(connected_at) = state.connected_at {
                let connection_duration = Instant::now().duration_since(connected_at);
                let mins = connection_duration.as_secs() / 60;
                let secs = connection_duration.as_secs() % 60;
                
                title = format!("Connected to {} ({}m {}s)", peer_ip, mins, secs);
                style = Style::default().fg(Color::Blue);
                
                // Show session timeout countdown (assuming 300 second timeout)
                let time_since_activity = Instant::now().duration_since(state.last_activity).as_secs();
                let time_remaining = 300u64.saturating_sub(time_since_activity);
                let timeout_mins = time_remaining / 60;
                let timeout_secs = time_remaining % 60;
                
                if time_remaining > 0 {
                    text_lines.push(format!("Session expires in {}m {}s", timeout_mins, timeout_secs));
                } else {
                    text_lines.push("Session expiring...".to_string());
                }
                
                // Show security level info
                if let Some(negotiated_level) = state.negotiated_security_level {
                    if let Some(peer_level) = state.peer_security_level {
                        text_lines.push(format!("Security: {} (You: {}, Peer: {})", 
                            negotiated_level.display_name(), 
                            state.security_level.display_name(),
                            peer_level.display_name()));
                    } else {
                        text_lines.push(format!("Security: {}", negotiated_level.display_name()));
                    }
                }
                
                // Show ping status
                if let Some(last_ping) = state.last_ping_sent {
                    let ping_age = Instant::now().duration_since(last_ping).as_secs();
                    if state.pending_ping {
                        text_lines.push(format!("Ping sent {}s ago (waiting for response)", ping_age));
                    } else {
                        text_lines.push(format!("Last ping: {}s ago", ping_age));
                    }
                }
            }
        }

        // Show incoming connection if there is one
        if let Some(incoming) = &state.incoming_connection {
            let remaining = (incoming.expires_at - Instant::now()).as_secs();
            if !text_lines.is_empty() {
                text_lines.push("".to_string()); // Empty line separator
            }
            text_lines.push(format!("Incoming from {} ({}s remaining)", incoming.from_ip, remaining));
            text_lines.push(format!("Peer Security: {} → Negotiated: {}", 
                incoming.security_level.display_name(),
                state.security_level.negotiate_with(incoming.security_level).display_name()));
            text_lines.push("Press 'a' to accept, 'd' to decline".to_string());
            
            if title.is_empty() {
                title = "Incoming Connection".to_string();
                style = Style::default().fg(Color::Green);
            }
        }

        // Default state
        if title.is_empty() {
            title = "Connection Status".to_string();
            text_lines.push("No active connection".to_string());
        }

        let text = text_lines.join("\n");
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_style(style);

        let widget = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
        frame.render_widget(widget, area);
    }

    /// Render the chat messages
    fn render_messages(&self, frame: &mut Frame, area: ratatui::layout::Rect, state: &UiState) {
        let messages: Vec<ListItem> = state.messages
            .iter()
            .map(|msg| {
                let (prefix, style) = if msg.from_self {
                    ("You: ", Style::default().fg(Color::Cyan))
                } else {
                    ("Peer: ", Style::default().fg(Color::White))
                };

                // Extract just the time part (HH:MM:SS) from the timestamp
                let time_part = if msg.timestamp.len() >= 19 {
                    &msg.timestamp[11..19] // Extract "HH:MM:SS" from "YYYY-MM-DD HH:MM:SS"
                } else {
                    &msg.timestamp
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{}] ", time_part), Style::default().fg(Color::DarkGray)),
                    Span::styled(prefix, style.add_modifier(Modifier::BOLD)),
                    Span::raw(&msg.content),
                ]))
            })
            .collect();

        let widget = List::new(messages)
            .block(Block::default().borders(Borders::ALL).title("Messages"));
        frame.render_widget(widget, area);
    }

    /// Render the message input field
    fn render_message_input(&self, frame: &mut Frame, area: ratatui::layout::Rect, state: &UiState) {
        let (status_text, status_color) = match state.connection_status {
            ConnectionStatus::Online => ("Online", Color::Green),
            ConnectionStatus::Establishing => ("Establishing...", Color::Yellow),
            ConnectionStatus::Connected => {
                if let Some(negotiated_level) = state.negotiated_security_level {
                    match negotiated_level {
                        SecurityLevel::Quick => ("Connected [Encrypted]", Color::Blue),
                        _ => ("Connected [Encrypted + Verified]", Color::Blue),
                    }
                } else {
                    ("Connected [Encrypted]", Color::Blue)
                }
            },
            ConnectionStatus::Disconnected => ("Disconnected", Color::Red),
        };

        let message_style = if state.input_mode == InputMode::MessageField {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let widget = Paragraph::new(state.message_input.as_str())
            .style(message_style)
            .block(Block::default()
                .borders(Borders::ALL)
                .title(format!("Message [{}]", status_text))
                .title_style(Style::default().fg(status_color)))
            .wrap(Wrap { trim: true });
        
        frame.render_widget(widget, area);
    }

    /// Render the security level selection overlay
    fn render_security_selection(&self, frame: &mut Frame, state: &UiState) {
        use ratatui::widgets::Clear;
        
        let area = frame.size();
        let popup_area = ratatui::layout::Rect {
            x: area.width / 4,
            y: area.height / 4,
            width: area.width / 2,
            height: area.height / 2,
        };

        // Clear the area behind the popup
        frame.render_widget(Clear, popup_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title("Security Level Selection")
            .style(Style::default().bg(Color::Blue));

        let lines = vec![
            Line::from(vec![
                Span::styled("Current: ", Style::default().fg(Color::White)),
                Span::styled(state.security_level.display_name(), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("F1/0: ", Style::default().fg(Color::Green)),
                Span::styled("Quick Mode", Style::default().fg(Color::White)),
                Span::styled(" - No verification", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("F2/1: ", Style::default().fg(Color::Green)),
                Span::styled("TOFU Mode", Style::default().fg(Color::White)),
                Span::styled(" - Trust on first use", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("F3/2: ", Style::default().fg(Color::Green)),
                Span::styled("Secure Mode", Style::default().fg(Color::White)),
                Span::styled(" - Signatures + rotation", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("F4/3: ", Style::default().fg(Color::Green)),
                Span::styled("Maximum Security", Style::default().fg(Color::White)),
                Span::styled(" - No persistent history", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ESC to close", Style::default().fg(Color::DarkGray)),
            ]),
        ];

        let widget = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: true });

        frame.render_widget(widget, popup_area);
    }
}