use clap::Parser;

// Module declarations
mod app;
mod crypto;
mod diagnostics;
mod error;
mod messagedb;
mod network;
mod ui;

// Imports from our modules
use app::{App, AppConfig, SecurityLevel};
use error::{P2PError, P2PResult};
use network::NetworkManager;
use ui::UiManager;

const DEFAULT_PORT: u16 = 8080;

/// A direct, authenticated two-party terminal messenger
#[derive(Parser, Debug)]
#[command(name = "p2p-cli")]
#[command(author = "KyleDerZweite")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "A direct, authenticated two-party terminal messenger", long_about = None)]
#[command(after_help = "SECURITY LEVELS:
  0, quick    Encrypted + signed; approve peers per session
  1, tofu     Persistently pin peer identities
  2, secure   Authenticated Noise session with persistent identity pinning
  3, max      Secure transport with memory-only history/trust

EXAMPLES:
  p2p-cli                       Start with default settings (port 8080, TOFU mode)
  p2p-cli -p 9000               Listen on port 9000
  p2p-cli -s tofu               Start with TOFU security
  p2p-cli -p 9000 -s secure     Listen on port 9000 with secure mode

COMMANDS (in chat):
  /help                         Show available commands
  /alias <name>                 Set alias for current peer
  /fingerprint                  Show peer's identity fingerprint
  /trust                        Trust current peer's identity
  /clear                        Clear visible messages; stored history remains
  /disconnect                   Disconnect from current peer")]
struct Cli {
    /// Port to listen on for incoming connections
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Security level (0=quick, 1=tofu, 2=secure, 3=max)
    #[arg(short, long, default_value = "tofu", value_parser = parse_security_level)]
    security: SecurityLevel,

    /// Print a shareable identity invitation and exit
    #[arg(long, conflicts_with_all = ["connect", "diagnose"])]
    invite: bool,

    /// Address to include in your invitation, e.g. router public IP:forwarded-port
    #[arg(long, value_name = "IP:PORT")]
    address: Vec<std::net::SocketAddr>,

    /// Connect to a peer invitation or literal IP:PORT on startup
    #[arg(short, long, conflicts_with = "diagnose")]
    connect: Option<String>,

    /// Print local addresses, optionally test TCP reachability, then exit
    #[arg(long, value_name = "IP:PORT", num_args = 0..=1, default_missing_value = "")]
    diagnose: Option<String>,

    /// Write bounded diagnostics to a NEW private file; excludes chat text and keys
    #[arg(long, value_name = "FILE")]
    log: Option<std::path::PathBuf>,

    /// Show local address diagnostics on startup
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

    if cli.security == SecurityLevel::Maximum && cli.log.is_some() {
        return Err(P2PError::ConfigError(
            "Maximum mode does not write diagnostic files; omit --log".into(),
        ));
    }
    let mut log = cli
        .log
        .as_deref()
        .map(diagnostics::DiagnosticLog::open)
        .transpose()?;
    if let Some(target) = &cli.diagnose {
        return diagnose(target, cli.port, &mut log).await;
    }
    if cli.port == 0 {
        return Err(P2PError::ConfigError(
            "Listening port must be between 1 and 65535".into(),
        ));
    }
    if cli.invite {
        let dirs = directories::ProjectDirs::from("com", "kylederzweite", "p2p-cli")
            .ok_or_else(|| P2PError::ConfigError("Cannot find config directory".into()))?;
        std::fs::create_dir_all(dirs.config_dir())?;
        let identity = crypto::IdentityManager::new(dirs.config_dir().join("p2p_identity"))?;
        let mut candidates = cli.address;
        if candidates.is_empty() {
            let (addresses, notes) = network::addr::local_addresses_with_diagnostics();
            for note in notes {
                eprintln!("{note}");
            }
            candidates = addresses
                .into_iter()
                .filter(|ip| !ip.is_loopback())
                .map(|ip| std::net::SocketAddr::new(ip, cli.port))
                .collect();
            if candidates.is_empty() {
                candidates.push(([127, 0, 0, 1], cli.port).into());
            }
            candidates.truncate(16);
        }
        let invitation =
            network::invitation::Invitation::new(identity.get_public_key_base64(), candidates)
                .map_err(P2PError::ConfigError)?;
        println!("{}", invitation.encode().map_err(P2PError::ConfigError)?);
        return Ok(());
    }
    run_app(cli, &mut log).await
}

async fn diagnose(
    target: &str,
    port: u16,
    log: &mut Option<diagnostics::DiagnosticLog>,
) -> P2PResult<()> {
    let (addresses, notes) = network::addr::local_addresses_with_diagnostics();
    for ip in addresses {
        println!("Local candidate: {}", network::addr::display_addr(ip, port));
    }
    for note in notes {
        println!("{note}");
        if let Some(log) = log.as_mut() {
            log.record(&note)?;
        }
    }
    if target.is_empty() {
        return Ok(());
    }
    let addr = target.parse::<std::net::SocketAddr>().map_err(|_| {
        P2PError::ConfigError(
            "--diagnose requires a literal IP:PORT; use [IPv6]:PORT for IPv6".into(),
        )
    })?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await;
    let detail = match result {
        Ok(Ok(_)) => format!("TCP connection to {addr} succeeded. This proves TCP reachability only; use --connect to verify the peer's Noise protocol and identity."),
        other => {
            let error = match other { Ok(Err(e)) => e, _ => std::io::ErrorKind::TimedOut.into() };
            let detail = network::addr::connection_diagnostic(addr, &error);
            if let Some(log) = log.as_mut() { log.record(&detail)?; }
            return Err(P2PError::NetworkError(detail));
        }
    };
    println!("{detail}");
    if let Some(log) = log.as_mut() {
        log.record(&detail)?;
    }
    Ok(())
}

async fn run_app(cli: Cli, log: &mut Option<diagnostics::DiagnosticLog>) -> P2PResult<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(P2PError::TerminalError("Interactive chat needs a terminal. Use --invite or --diagnose for non-interactive commands.".into()));
    }
    let port = cli.port;
    let config = AppConfig::new(port, cli.security);
    let mut app = App::new(config).map_err(|e| P2PError::ConfigError(e.to_string()))?;
    let mut network_manager = NetworkManager::new(port, app.transport_identity())
        .await
        .map_err(|e| P2PError::NetworkError(e.to_string()))?;
    network_manager
        .start_listener(port)
        .await
        .map_err(|e| P2PError::NetworkError(e.to_string()))?;
    let mut ui_manager = UiManager::new().map_err(|e| P2PError::TerminalError(e.to_string()))?;
    if let Some(log) = log.as_mut() {
        log.record(&format!(
            "Startup: requested TCP port {port}, policy {}",
            cli.security
        ))?;
    }
    app.set_invitation_addresses(cli.address);
    if cli.verbose {
        app.show_my_addresses();
    }
    if let Some(target) = cli.connect {
        app.start_connection(&target)
            .map_err(P2PError::ConfigError)?;
    }

    // Main event loop
    loop {
        // Handle UI events (with timeout)
        if let Some(ui_event) = ui_manager
            .poll_event(100)
            .map_err(|e| P2PError::TerminalError(e.to_string()))?
        {
            if let Some(network_msg) = app
                .handle_ui_event(ui_event)
                .map_err(|e| P2PError::ConfigError(e.to_string()))?
            {
                // Send network message if generated
                // Use peer_ip if available, otherwise fall back to previous_peer_ip (for disconnect messages)
                let network_msg = app
                    .authenticate_outgoing(network_msg)
                    .map_err(|e| P2PError::CryptoError(e.to_string()))?;
                let ui_state = app.get_ui_state();
                let target_ip = ui_state
                    .peer_ip
                    .as_ref()
                    .or(ui_state.previous_peer_ip.as_ref());
                if let Some(peer_ip) = target_ip {
                    if let Ok(addr) = peer_ip.parse() {
                        network_manager
                            .send_message(network_msg, addr, app.expected_peer_identity())
                            .await
                            .map_err(|e| P2PError::NetworkError(e.to_string()))?;
                    }
                }
            }

            if app.should_quit() {
                break;
            }
        }

        // Handle network events
        for _ in 0..128 {
            let Some(network_event) = network_manager.try_next_event() else {
                break;
            };
            if let Some(detail) = event_diagnostic(&network_event) {
                if let Some(log) = log.as_mut() {
                    log.record(&detail)?;
                }
            }
            let source = match &network_event {
                network::NetworkEvent::MessageReceived(_, addr) => Some(*addr),
                _ => None,
            };
            if let Err(reason) = app.handle_network_event(network_event) {
                if let Some(log) = log.as_mut() {
                    log.record(&format!(
                        "Application authentication/state rejection: {reason}"
                    ))?;
                }
                if let Some(addr) = source {
                    network_manager
                        .disconnect(addr)
                        .await
                        .map_err(|e| P2PError::NetworkError(e.to_string()))?;
                }
            }
        }

        // Update app (timeouts, pings, etc.)
        let update_messages = app
            .update()
            .map_err(|e| P2PError::ConfigError(e.to_string()))?;
        for msg in update_messages {
            let msg = app
                .authenticate_outgoing(msg)
                .map_err(|e| P2PError::CryptoError(e.to_string()))?;
            if let Some(peer_ip) = &app.get_ui_state().peer_ip {
                if let Ok(addr) = peer_ip.parse() {
                    network_manager
                        .send_message(msg, addr, app.expected_peer_identity())
                        .await
                        .map_err(|e| P2PError::NetworkError(e.to_string()))?;
                }
            }
        }

        // Render UI
        ui_manager
            .render(&app.get_ui_state())
            .map_err(|e| P2PError::RenderError(e.to_string()))?;
    }

    // Cleanup
    ui_manager
        .cleanup()
        .map_err(|e| P2PError::TerminalError(e.to_string()))?;
    network_manager
        .shutdown()
        .await
        .map_err(|e| P2PError::NetworkError(e.to_string()))?;

    Ok(())
}

fn event_diagnostic(event: &network::NetworkEvent) -> Option<String> {
    use network::NetworkEvent::*;
    match event {
        ConnectionFailed(addr, error) => Some(format!("Connection {addr} failed: {error}")),
        IncomingFailed(addr, error) => {
            Some(format!("Unsolicited connection {addr} rejected: {error}"))
        }
        ListenerWarning(error) => Some(format!("Listener warning: {error}")),
        ListenerFailed(error) => Some(format!("Listener failed: {error}")),
        ListenerStarted(port) => Some(format!("Listening on TCP port {port}")),
        ConnectionEstablished(addr) => Some(format!("Authenticated transport to {addr}")),
        ConnectionLost(addr) => Some(format!("Transport to {addr} closed")),
        _ => None,
    }
}
