use tokio::sync::mpsc;
use std::net::SocketAddr;
use uuid::Uuid;

pub mod messages;
pub mod connection;

pub use messages::{NetworkMessage, MessageType};
pub use connection::ConnectionManager;

/// Events that the network layer can generate
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    MessageReceived(NetworkMessage),
    ConnectionEstablished(SocketAddr),
    ConnectionLost(SocketAddr),
    ConnectionFailed(SocketAddr, String),
    ListenerStarted(u16),
    ListenerFailed(String),
}

/// Commands that can be sent to the network layer
#[derive(Debug, Clone)]
pub enum NetworkCommand {
    SendMessage(NetworkMessage, SocketAddr),
    StartListener(u16),
    StopListener,
    Disconnect(SocketAddr),
}

/// Main network manager that handles all networking operations
pub struct NetworkManager {
    command_sender: mpsc::UnboundedSender<NetworkCommand>,
    event_receiver: mpsc::UnboundedReceiver<NetworkEvent>,
    _connection_task: tokio::task::JoinHandle<()>,
}

impl NetworkManager {
    /// Create a new network manager
    pub async fn new(_port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let connection_manager = ConnectionManager::new(event_sender, command_receiver).await?;
        
        // Start the connection manager task
        let connection_task = tokio::spawn(async move {
            connection_manager.run().await;
        });
        
        Ok(Self {
            command_sender,
            event_receiver,
            _connection_task: connection_task,
        })
    }

    /// Start the network listener on the specified port
    pub async fn start_listener(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        self.command_sender.send(NetworkCommand::StartListener(port))
            .map_err(|e| format!("Failed to send start listener command: {}", e))?;
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(&self, message: NetworkMessage, target: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        self.command_sender.send(NetworkCommand::SendMessage(message, target))
            .map_err(|e| format!("Failed to send message command: {}", e))?;
        Ok(())
    }

    /// Get the next network event (blocking)
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_receiver.recv().await
    }

    /// Try to get a network event without blocking
    pub fn try_next_event(&mut self) -> Option<NetworkEvent> {
        self.event_receiver.try_recv().ok()
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        self.command_sender.send(NetworkCommand::Disconnect(peer))
            .map_err(|e| format!("Failed to send disconnect command: {}", e))?;
        Ok(())
    }

    /// Shutdown the network manager
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.command_sender.send(NetworkCommand::StopListener)
            .map_err(|e| format!("Failed to send stop listener command: {}", e))?;
        Ok(())
    }
}