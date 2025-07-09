use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
    time::timeout,
};
use uuid::Uuid;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey}};
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose};

const DEFAULT_PORT: u16 = 8080;
const CONNECTION_TIMEOUT_SECS: u64 = 180;
const MAX_MESSAGES: usize = 100;
const BUFFER_SIZE: usize = 4096;

// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkMessage {
    id: Uuid,
    msg_type: MessageType,
    from_ip: String,
    content: String,
    public_key: Option<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MessageType {
    ConnectionRequest,
    ConnectionAccept,
    ConnectionDecline,
    TextMessage,
    Ping,
}

// UI-related structures
#[derive(Debug, Clone, PartialEq)]
enum InputMode {
    ConnectField,
    MessageField,
    IncomingResponse,
}

#[derive(Debug, Clone)]
enum ConnectionStatus {
    Online,
    Establishing,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone)]
struct ChatMessage {
    content: String,
    from_self: bool,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
struct IncomingConnection {
    from_ip: String,
    public_key: String,
    expires_at: Instant,
}

// Main application state
struct App {
    // UI state
    input_mode: InputMode,
    connect_input: String,
    message_input: String,

    // Connection state
    connection_status: ConnectionStatus,
    peer_ip: Option<String>,
    peer_public_key: Option<String>,

    // Crypto
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,

    // Messages
    messages: VecDeque<ChatMessage>,
    incoming_connection: Option<IncomingConnection>,

    // Network
    network_tx: mpsc::UnboundedSender<NetworkMessage>,
    port: u16,
}

impl App {
    fn new(network_tx: mpsc::UnboundedSender<NetworkMessage>, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            input_mode: InputMode::ConnectField,
            connect_input: String::new(),
            message_input: String::new(),
            connection_status: ConnectionStatus::Online,
            peer_ip: None,
            peer_public_key: None,
            private_key,
            public_key,
            messages: VecDeque::new(),
            incoming_connection: None,
            network_tx,
            port,
        })
    }

    fn get_public_key_base64(&self) -> Result<String, Box<dyn std::error::Error>> {
        let pem = self.public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
        Ok(general_purpose::STANDARD.encode(pem.as_bytes()))
    }

    fn add_message(&mut self, content: String, from_self: bool) {
        self.messages.push_back(ChatMessage {
            content,
            from_self,
            timestamp: chrono::Utc::now(),
        });

        // Keep only last MAX_MESSAGES
        while self.messages.len() > MAX_MESSAGES {
            self.messages.pop_front();
        }
    }

    fn handle_tab(&mut self) {
        self.input_mode = match self.input_mode {
            InputMode::ConnectField => InputMode::MessageField,
            InputMode::MessageField => InputMode::ConnectField,
            InputMode::IncomingResponse => InputMode::IncomingResponse,
        };
    }

    fn handle_char_input(&mut self, c: char) {
        match self.input_mode {
            InputMode::ConnectField => self.connect_input.push(c),
            InputMode::MessageField => self.message_input.push(c),
            InputMode::IncomingResponse => {}
        }
    }

    fn handle_backspace(&mut self) {
        match self.input_mode {
            InputMode::ConnectField => { self.connect_input.pop(); }
            InputMode::MessageField => { self.message_input.pop(); }
            InputMode::IncomingResponse => {}
        }
    }

    fn handle_enter(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.input_mode {
            InputMode::ConnectField => self.send_connection_request()?,
            InputMode::MessageField => self.send_message()?,
            InputMode::IncomingResponse => {} // Handled by 'a' and 'd' keys
        }
        Ok(())
    }

    fn send_connection_request(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let target_address = if self.connect_input.contains(':') {
            // User entered IP:port format
            self.connect_input.clone()
        } else {
            // User entered just IP, use default port
            format!("{}:{}", self.connect_input, DEFAULT_PORT)
        };

        // Validate the address format
        if target_address.parse::<SocketAddr>().is_ok() {
            let msg = NetworkMessage {
                id: Uuid::new_v4(),
                msg_type: MessageType::ConnectionRequest,
                from_ip: format!("127.0.0.1:{}", self.port),
                content: "Connection request".to_string(),
                public_key: Some(self.get_public_key_base64()?),
                timestamp: chrono::Utc::now(),
            };

            self.peer_ip = Some(target_address);
            self.connection_status = ConnectionStatus::Establishing;
            self.network_tx.send(msg)?;
            self.connect_input.clear();
        }
        Ok(())
    }

    fn send_message(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.message_input.is_empty() && matches!(self.connection_status, ConnectionStatus::Connected) {
            let msg = NetworkMessage {
                id: Uuid::new_v4(),
                msg_type: MessageType::TextMessage,
                from_ip: format!("127.0.0.1:{}", self.port),
                content: self.message_input.clone(),
                public_key: None,
                timestamp: chrono::Utc::now(),
            };

            self.add_message(self.message_input.clone(), true);
            self.message_input.clear();
            self.network_tx.send(msg)?;
        }
        Ok(())
    }

    fn accept_connection(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(incoming) = &self.incoming_connection {
            let msg = NetworkMessage {
                id: Uuid::new_v4(),
                msg_type: MessageType::ConnectionAccept,
                from_ip: format!("127.0.0.1:{}", self.port),
                content: "Connection accepted".to_string(),
                public_key: Some(self.get_public_key_base64()?),
                timestamp: chrono::Utc::now(),
            };

            self.peer_ip = Some(incoming.from_ip.clone());
            self.peer_public_key = Some(incoming.public_key.clone());
            self.connection_status = ConnectionStatus::Connected;
            self.incoming_connection = None;
            self.input_mode = InputMode::MessageField;

            self.network_tx.send(msg)?;
            self.add_message("Connection established!".to_string(), false);
        }
        Ok(())
    }

    fn decline_connection(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(_) = &self.incoming_connection {
            let msg = NetworkMessage {
                id: Uuid::new_v4(),
                msg_type: MessageType::ConnectionDecline,
                from_ip: format!("127.0.0.1:{}", self.port),
                content: "Connection declined".to_string(),
                public_key: None,
                timestamp: chrono::Utc::now(),
            };

            self.incoming_connection = None;
            self.input_mode = InputMode::ConnectField;
            self.network_tx.send(msg)?;
        }
        Ok(())
    }

    fn handle_network_message(&mut self, msg: NetworkMessage) {
        match msg.msg_type {
            MessageType::ConnectionRequest => {
                if let Some(public_key) = msg.public_key {
                    self.incoming_connection = Some(IncomingConnection {
                        from_ip: msg.from_ip,
                        public_key,
                        expires_at: Instant::now() + Duration::from_secs(CONNECTION_TIMEOUT_SECS),
                    });
                    self.input_mode = InputMode::IncomingResponse;
                }
            }
            MessageType::ConnectionAccept => {
                if let Some(public_key) = msg.public_key {
                    self.peer_public_key = Some(public_key);
                    self.connection_status = ConnectionStatus::Connected;
                    self.add_message("Connection established!".to_string(), false);
                }
            }
            MessageType::ConnectionDecline => {
                self.connection_status = ConnectionStatus::Online;
                self.peer_ip = None;
                self.add_message("Connection declined by peer".to_string(), false);
            }
            MessageType::TextMessage => {
                self.add_message(msg.content, false);
            }
            MessageType::Ping => {
                // Handle ping/keepalive if needed
            }
        }
    }

    fn check_timeout(&mut self) {
        if let Some(incoming) = &self.incoming_connection {
            if Instant::now() > incoming.expires_at {
                self.incoming_connection = None;
                self.input_mode = InputMode::ConnectField;
            }
        }
    }
}

// Network handling functions
async fn start_network_listener(
    app_state: Arc<Mutex<App>>,
    mut message_rx: mpsc::UnboundedReceiver<NetworkMessage>,
    port: u16,
) {
    // Handle incoming connections
    let listener_state = Arc::clone(&app_state);
    tokio::spawn(async move {
        if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            loop {
                if let Ok((stream, addr)) = listener.accept().await {
                    let state = Arc::clone(&listener_state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_incoming_connection(stream, addr, state).await {
                            eprintln!("Error handling incoming connection: {}", e);
                        }
                    });
                }
            }
        }
    });

    // Handle outgoing messages
    while let Some(msg) = message_rx.recv().await {
        let app = app_state.lock().await;
        if let Some(peer_ip) = &app.peer_ip {
            let peer_ip = peer_ip.clone();
            drop(app); // Release lock before network operation
            tokio::spawn(async move {
                if let Err(e) = send_message_to_peer(msg, peer_ip).await {
                    eprintln!("Error sending message: {}", e);
                }
            });
        }
    }
}

async fn handle_incoming_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    state: Arc<Mutex<App>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = vec![0; BUFFER_SIZE];
    let n = stream.read(&mut buffer).await?;

    if let Ok(msg_str) = String::from_utf8(buffer[..n].to_vec()) {
        if let Ok(msg) = serde_json::from_str::<NetworkMessage>(&msg_str) {
            let mut app = state.lock().await;
            app.handle_network_message(msg);
        }
    }

    Ok(())
}

async fn send_message_to_peer(
    msg: NetworkMessage,
    peer_ip: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(&peer_ip).await?;
    let data = serde_json::to_string(&msg)?;
    stream.write_all(data.as_bytes()).await?;
    Ok(())
}

// UI rendering
fn render_ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Connect field
            Constraint::Length(5),  // Incoming connection
            Constraint::Min(5),     // Messages
            Constraint::Length(5),  // Message input
        ])
        .split(f.size());

    // Connect field with quit instructions
    let connect_style = if app.input_mode == InputMode::ConnectField {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let connect_widget = Paragraph::new(app.connect_input.as_str())
        .style(connect_style)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(format!("Connect to IP:PORT (Listening on: {}) (Press Ctrl+C to quit)", app.port)))
        .wrap(Wrap { trim: true });
    f.render_widget(connect_widget, chunks[0]);

    // Incoming connection
    render_incoming_connection(f, chunks[1], app);

    // Messages
    render_messages(f, chunks[2], app);

    // Message input
    render_message_input(f, chunks[3], app);
}

fn render_incoming_connection(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let (block, text) = if let Some(incoming) = &app.incoming_connection {
        let remaining = (incoming.expires_at - Instant::now()).as_secs();
        (
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Incoming from {} ({}s)", incoming.from_ip, remaining))
                .style(Style::default().fg(Color::Green)),
            "Press 'a' to accept, 'd' to decline"
        )
    } else {
        (
            Block::default()
                .borders(Borders::ALL)
                .title("Incoming connections"),
            "No incoming connections"
        )
    };

    let widget = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(widget, area);
}

fn render_messages(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let messages: Vec<ListItem> = app.messages
        .iter()
        .map(|msg| {
            let (prefix, style) = if msg.from_self {
                ("You: ", Style::default().fg(Color::Cyan))
            } else {
                ("Peer: ", Style::default().fg(Color::White))
            };

            ListItem::new(Line::from(vec![
                Span::styled(prefix, style.add_modifier(Modifier::BOLD)),
                Span::raw(&msg.content),
            ]))
        })
        .collect();

    let widget = List::new(messages)
        .block(Block::default().borders(Borders::ALL).title("Messages"));
    f.render_widget(widget, area);
}

fn render_message_input(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let (status_text, status_color) = match app.connection_status {
        ConnectionStatus::Online => ("Online", Color::Green),
        ConnectionStatus::Establishing => ("Establishing...", Color::Yellow),
        ConnectionStatus::Connected => ("Connected", Color::Blue),
        ConnectionStatus::Disconnected => ("Disconnected", Color::Red),
    };

    let message_style = if app.input_mode == InputMode::MessageField {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let widget = Paragraph::new(app.message_input.as_str())
        .style(message_style)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(format!("Message [{}]", status_text))
            .title_style(Style::default().fg(status_color)))
        .wrap(Wrap { trim: true });
    f.render_widget(widget, area);
}

// Main function
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("P2P Terminal Messenger");
        println!("Usage: {} [PORT]", args[0]);
        println!("  PORT: Port number to listen on (default: {})", DEFAULT_PORT);
        println!("  --help, -h: Show this help message");
        return Ok(());
    }
    
    let port = if args.len() > 1 {
        args[1].parse::<u16>().unwrap_or(DEFAULT_PORT)
    } else {
        DEFAULT_PORT
    };

    println!("Starting P2P messenger on port {}", port);

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create channels
    let (network_tx, network_rx) = mpsc::unbounded_channel();

    // Create app state
    let app = Arc::new(Mutex::new(App::new(network_tx, port)?));

    // Start network task
    let network_app = Arc::clone(&app);
    let network_task = tokio::spawn(async move {
        start_network_listener(network_app, network_rx, port).await;
    });

    // Run UI loop
    let result = run_ui_loop(&mut terminal, app).await;

    // Cleanup
    network_task.abort();
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        eprintln!("Error: {:?}", err);
    }

    Ok(())
}

async fn run_ui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app_state: Arc<Mutex<App>>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Draw UI
        {
            let app = app_state.lock().await;
            terminal.draw(|f| render_ui(f, &app))?;
        }

        // Handle input with timeout
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let mut app = app_state.lock().await;

                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Tab => app.handle_tab(),
                        KeyCode::Enter => app.handle_enter()?,
                        KeyCode::Backspace => app.handle_backspace(),
                        KeyCode::Char('a') if app.input_mode == InputMode::IncomingResponse => {
                            app.accept_connection()?;
                        }
                        KeyCode::Char('d') if app.input_mode == InputMode::IncomingResponse => {
                            app.decline_connection()?;
                        }
                        KeyCode::Char(c) => app.handle_char_input(c),
                        _ => {}
                    }
                }
            }
        }

        // Check for timeouts
        {
            let mut app = app_state.lock().await;
            app.check_timeout();
        }
    }
}