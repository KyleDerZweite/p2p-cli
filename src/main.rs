use std::time::Duration;

// Module declarations
mod crypto;
mod messagedb;
mod ui;
mod network;
mod app;

// Imports from our modules
use app::{App, AppConfig, SecurityLevel};
use ui::UiManager;
use network::NetworkManager;

const DEFAULT_PORT: u16 = 8080;

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

    // Create application configuration
    let config = AppConfig::new(port, SecurityLevel::Quick);
    
    // Initialize components
    let mut app = App::new(config)?;
    let mut ui_manager = UiManager::new()?;
    let mut network_manager = NetworkManager::new(port).await?;
    
    // Start network listener
    network_manager.start_listener(port).await?;

    // Main event loop
    loop {
        // Handle UI events (with timeout)
        if let Some(ui_event) = ui_manager.poll_event(100)? {
            if let Some(network_msg) = app.handle_ui_event(ui_event)? {
                // Send network message if generated
                if let Some(peer_ip) = &app.get_ui_state().peer_ip {
                    if let Ok(addr) = peer_ip.parse() {
                        network_manager.send_message(network_msg, addr).await?;
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
        let update_messages = app.update()?;
        for msg in update_messages {
            if let Some(peer_ip) = &app.get_ui_state().peer_ip {
                if let Ok(addr) = peer_ip.parse() {
                    network_manager.send_message(msg, addr).await?;
                }
            }
        }

        // Render UI
        ui_manager.render(&app.get_ui_state())?;
    }

    // Cleanup
    ui_manager.cleanup()?;
    network_manager.shutdown().await?;

    Ok(())
}

