use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use std::net::SocketAddr;

use super::{NetworkEvent, NetworkCommand, NetworkMessage};

const BUFFER_SIZE: usize = 4096;

/// Manages TCP connections and message sending/receiving
pub struct ConnectionManager {
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    command_receiver: mpsc::UnboundedReceiver<NetworkCommand>,
    listener_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub async fn new(
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
        command_receiver: mpsc::UnboundedReceiver<NetworkCommand>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            event_sender,
            command_receiver,
            listener_handle: None,
        })
    }

    /// Start the connection manager's main loop
    pub async fn run(mut self) {
        while let Some(command) = self.command_receiver.recv().await {
            match command {
                NetworkCommand::StartListener(port) => {
                    self.start_listener(port).await;
                }
                NetworkCommand::SendMessage(message, target) => {
                    self.send_message(message, target).await;
                }
                NetworkCommand::Disconnect(addr) => {
                    // Handle disconnect logic
                    let _ = self.event_sender.send(NetworkEvent::ConnectionLost(addr));
                }
                NetworkCommand::StopListener => {
                    self.stop_listener().await;
                    break;
                }
            }
        }
    }

    /// Start listening for incoming connections
    async fn start_listener(&mut self, port: u16) {
        let event_sender = self.event_sender.clone();
        
        let handle = tokio::spawn(async move {
            match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                Ok(listener) => {
                    let _ = event_sender.send(NetworkEvent::ListenerStarted(port));
                    
                    loop {
                        match listener.accept().await {
                            Ok((stream, addr)) => {
                                let event_sender_clone = event_sender.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_incoming_connection(stream, addr, event_sender_clone).await {
                                        eprintln!("Error handling incoming connection: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("Error accepting connection: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = event_sender.send(NetworkEvent::ListenerFailed(e.to_string()));
                }
            }
        });

        self.listener_handle = Some(handle);
    }

    /// Stop the listener
    async fn stop_listener(&mut self) {
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
        }
    }

    /// Send a message to a target address
    async fn send_message(&self, message: NetworkMessage, target: SocketAddr) {
        let event_sender = self.event_sender.clone();
        
        tokio::spawn(async move {
            match Self::send_message_to_peer(message, target).await {
                Ok(_) => {
                    // Message sent successfully
                }
                Err(e) => {
                    let _ = event_sender.send(NetworkEvent::ConnectionFailed(
                        target,
                        e.to_string(),
                    ));
                }
            }
        });
    }

    /// Handle an incoming TCP connection
    async fn handle_incoming_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = vec![0; BUFFER_SIZE];
        let n = stream.read(&mut buffer).await?;

        if let Ok(msg_str) = String::from_utf8(buffer[..n].to_vec()) {
            if let Ok(message) = NetworkMessage::from_json(&msg_str) {
                let _ = event_sender.send(NetworkEvent::MessageReceived(message));
                let _ = event_sender.send(NetworkEvent::ConnectionEstablished(addr));
            }
        }

        Ok(())
    }

    /// Send a message to a specific peer
    async fn send_message_to_peer(
        message: NetworkMessage,
        target: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect(target).await?;
        let data = message.to_json()?;
        stream.write_all(data.as_bytes()).await?;
        Ok(())
    }
}