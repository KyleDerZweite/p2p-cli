use std::net::SocketAddr;
use tokio::sync::mpsc;

pub mod addr;
pub mod connection;
mod handshake;
pub mod invitation;
pub mod messages;

pub use connection::ConnectionManager;
pub use messages::{MessageType, NetworkMessage};

/// Events that the network layer can generate
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    MessageReceived(NetworkMessage, SocketAddr),
    ConnectionEstablished(SocketAddr),
    ConnectionLost(SocketAddr),
    ConnectionFailed(SocketAddr, String),
    /// An inbound connection reached us but failed before yielding a message
    IncomingFailed(SocketAddr, String),
    ListenerStarted(u16),
    ListenerFailed(String),
    ListenerWarning(String),
}

/// Commands that can be sent to the network layer
#[derive(Debug, Clone)]
pub enum NetworkCommand {
    SendMessage(NetworkMessage, SocketAddr, Option<String>),
    StartListener(u16),
    StopListener,
    Disconnect(SocketAddr),
}

/// Main network manager that handles all networking operations
pub struct NetworkManager {
    command_sender: mpsc::Sender<NetworkCommand>,
    event_receiver: mpsc::Receiver<NetworkEvent>,
    _connection_task: tokio::task::JoinHandle<()>,
}

impl NetworkManager {
    /// Create a new network manager
    pub async fn new(
        _port: u16,
        identity: std::sync::Arc<crate::crypto::IdentityManager>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (command_sender, command_receiver) = mpsc::channel(128);
        let (event_sender, event_receiver) = mpsc::channel(128);

        let connection_manager =
            ConnectionManager::new(event_sender, command_receiver, identity).await?;

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
        self.command_sender
            .send(NetworkCommand::StartListener(port))
            .await
            .map_err(|e| format!("Failed to send start listener command: {}", e))?;
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(
        &self,
        message: NetworkMessage,
        target: SocketAddr,
        expected_identity: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.command_sender
            .send(NetworkCommand::SendMessage(
                message,
                target,
                expected_identity,
            ))
            .await
            .map_err(|e| format!("Failed to send message command: {}", e))?;
        Ok(())
    }

    /// Get the next network event (blocking)
    #[cfg(test)]
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_receiver.recv().await
    }

    /// Try to get a network event without blocking
    pub fn try_next_event(&mut self) -> Option<NetworkEvent> {
        self.event_receiver.try_recv().ok()
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        self.command_sender
            .send(NetworkCommand::Disconnect(peer))
            .await
            .map_err(|e| format!("Failed to send disconnect command: {}", e))?;
        Ok(())
    }

    /// Shutdown the network manager
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        // Stop local event backpressure before joining the network actor.
        drop(self.event_receiver);
        self.command_sender
            .send(NetworkCommand::StopListener)
            .await
            .map_err(|e| format!("Failed to send stop listener command: {}", e))?;
        self._connection_task
            .await
            .map_err(|e| format!("Network shutdown failed: {e}"))?;
        Ok(())
    }
}
