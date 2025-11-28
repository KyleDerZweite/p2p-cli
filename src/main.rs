use clap::Parser;

// Module declarations
mod crypto;
mod error;
mod messagedb;
mod ui;
mod network;
mod app;

// Imports from our modules
use app::{App, AppConfig, SecurityLevel};
use error::{P2PError, P2PResult};
use ui::UiManager;
use network::NetworkManager;

const DEFAULT_PORT: u16 = 8080;

/// A modern, secure, terminal-based peer-to-peer messenger
#[derive(Parser, Debug)]
#[command(name = "p2p-cli")]
#[command(author = "KyleDerZweite")]
#[command(version = "0.2.0")]
#[command(about = "A modern, secure, terminal-based peer-to-peer messenger", long_about = None)]
#[command(after_help = "SECURITY LEVELS:
  0, quick    Quick & dirty - no identity verification
  1, tofu     Trust on First Use - verify peer identity
  2, secure   Secure communications - signatures + key rotation  
  3, max      Maximum security - no persistent history

EXAMPLES:
  p2p-cli                       Start with default settings (port 8080, quick mode)
  p2p-cli -p 9000               Listen on port 9000
  p2p-cli -s tofu               Start with TOFU security
  p2p-cli -p 9000 -s secure     Listen on port 9000 with secure mode

COMMANDS (in chat):
  /help                         Show available commands
  /alias <name>                 Set alias for current peer
  /fingerprint                  Show peer's identity fingerprint
  /trust                        Trust current peer's identity
  /clear                        Clear message history
  /disconnect                   Disconnect from current peer")]
struct Cli {
    /// Port to listen on for incoming connections
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Security level (0=quick, 1=tofu, 2=secure, 3=max)
    #[arg(short, long, default_value = "0", value_parser = parse_security_level)]
    security: SecurityLevel,

    /// Enable verbose output for debugging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

/// Parse security level from string (supports both numbers and names)
fn parse_security_level(s: &str) -> Result<SecurityLevel, String> {
    SecurityLevel::from_str(s)
}

// Main function
#[tokio::main]
async fn main() -> P2PResult<()> {
    let cli = Cli::parse();

    if cli.verbose {
        println!("Starting P2P messenger...");
        println!("  Port: {}", cli.port);
        println!("  Security Level: {} ({})", cli.security as u8, cli.security.display_name());
    }

    run_app(cli.port, cli.security, cli.verbose).await
}

async fn run_app(port: u16, security_level: SecurityLevel, verbose: bool) -> P2PResult<()> {
    if verbose {
        println!("Initializing components...");
    }

    // Create application configuration
    let config = AppConfig::new(port, security_level);
    
    // Initialize components
    let mut app = App::new(config).map_err(|e| P2PError::ConfigError(e.to_string()))?;
    let mut ui_manager = UiManager::new().map_err(|e| P2PError::TerminalError(e.to_string()))?;
    let mut network_manager = NetworkManager::new(port).await.map_err(|e| P2PError::NetworkError(e.to_string()))?;
    
    // Start network listener
    network_manager.start_listener(port).await.map_err(|e| P2PError::NetworkError(e.to_string()))?;

    // Main event loop
    loop {
        // Handle UI events (with timeout)
        if let Some(ui_event) = ui_manager.poll_event(100).map_err(|e| P2PError::TerminalError(e.to_string()))? {
            if let Some(network_msg) = app.handle_ui_event(ui_event).map_err(|e| P2PError::ConfigError(e.to_string()))? {
                // Send network message if generated
                // Use peer_ip if available, otherwise fall back to previous_peer_ip (for disconnect messages)
                let ui_state = app.get_ui_state();
                let target_ip = ui_state.peer_ip.as_ref().or(ui_state.previous_peer_ip.as_ref());
                if let Some(peer_ip) = target_ip {
                    if let Ok(addr) = peer_ip.parse() {
                        let _ = network_manager.send_message(network_msg, addr).await;
                    }
                }
            }
            
            if app.should_quit() {
                break;
            }
        }

        // Handle network events
        if let Some(network_event) = network_manager.try_next_event() {
            app.handle_network_event(network_event);
        }

        // Update app (timeouts, pings, etc.)
        let update_messages = app.update().map_err(|e| P2PError::ConfigError(e.to_string()))?;
        for msg in update_messages {
            if let Some(peer_ip) = &app.get_ui_state().peer_ip {
                if let Ok(addr) = peer_ip.parse() {
                    let _ = network_manager.send_message(msg, addr).await;
                }
            }
        }

        // Render UI
        ui_manager.render(&app.get_ui_state()).map_err(|e| P2PError::RenderError(e.to_string()))?;
    }

    // Cleanup
    ui_manager.cleanup().map_err(|e| P2PError::TerminalError(e.to_string()))?;
    network_manager.shutdown().await.map_err(|e| P2PError::NetworkError(e.to_string()))?;

    Ok(())
}

