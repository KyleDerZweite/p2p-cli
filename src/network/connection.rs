use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    time::timeout,
};

use super::{NetworkCommand, NetworkEvent, NetworkMessage};

const MAX_PLAINTEXT: usize = 48 * 1024;
const MAX_NOISE_FRAME: usize = MAX_PLAINTEXT + 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 64;
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub struct ConnectionManager {
    event_sender: mpsc::Sender<NetworkEvent>,
    command_receiver: mpsc::Receiver<NetworkCommand>,
    listener_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionManager {
    pub async fn new(
        event_sender: mpsc::Sender<NetworkEvent>,
        command_receiver: mpsc::Receiver<NetworkCommand>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            event_sender,
            command_receiver,
            listener_handle: None,
        })
    }

    pub async fn run(mut self) {
        while let Some(command) = self.command_receiver.recv().await {
            match command {
                NetworkCommand::StartListener(port) => self.start_listener(port).await,
                NetworkCommand::SendMessage(message, target) => {
                    self.send_message(message, target).await
                }
                NetworkCommand::Disconnect(addr) => {
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::ConnectionLost(addr))
                        .await;
                }
                NetworkCommand::StopListener => {
                    self.stop_listener().await;
                    break;
                }
            }
        }
    }

    async fn start_listener(&mut self, port: u16) {
        let events = self.event_sender.clone();
        self.listener_handle = Some(tokio::spawn(async move {
            let listener = match TcpListener::bind(("::", port)).await {
                Ok(listener) => Ok(listener),
                Err(_) => TcpListener::bind(("0.0.0.0", port)).await,
            };
            let listener = match listener {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = events
                        .send(NetworkEvent::ListenerFailed(error.to_string()))
                        .await;
                    return;
                }
            };
            let _ = events.send(NetworkEvent::ListenerStarted(port)).await;
            let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
            loop {
                let (stream, addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let events = events.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match timeout(IO_TIMEOUT, receive_noise_message(stream))
                        .await
                        .unwrap_or(Err("timed out during encryption handshake — the peer reached us over TCP but never completed the handshake".into()))
                    {
                        Ok(message) => {
                            let _ = events
                                .send(NetworkEvent::MessageReceived(message, addr))
                                .await;
                        }
                        Err(error) => {
                            let _ = events
                                .send(NetworkEvent::IncomingFailed(addr, error.to_string()))
                                .await;
                        }
                    }
                });
            }
        }));
    }

    async fn stop_listener(&mut self) {
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
        }
    }

    async fn send_message(&self, message: NetworkMessage, target: SocketAddr) {
        let events = self.event_sender.clone();
        tokio::spawn(async move {
            if let Err(reason) = send_noise_message(message, target).await {
                let _ = events
                    .send(NetworkEvent::ConnectionFailed(target, reason.to_string()))
                    .await;
            }
        });
    }
}

async fn send_noise_message(
    message: NetworkMessage,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let plaintext = message.to_json()?.into_bytes();
    if plaintext.len() > MAX_PLAINTEXT {
        return Err("message exceeds protocol limit".into());
    }

    // Stage 1: TCP reachability. A failure here means the peer's port is
    // closed, not forwarded, or firewalled — nothing p2p-cli-specific ran yet.
    let mut stream = match timeout(IO_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(format!(
                "[stage 1/3: TCP connect] could not reach {}: {}. The port is closed or refused — check that the peer app is running and the port is forwarded on their router",
                target, e
            )
            .into())
        }
        Err(_) => {
            return Err(format!(
                "[stage 1/3: TCP connect] no response from {} after {}s. Packets are being dropped — the port is likely not forwarded, or a firewall is silently blocking it",
                target,
                IO_TIMEOUT.as_secs()
            )
            .into())
        }
    };

    // Stage 2: Noise handshake. Reaching this stage proves TCP connectivity,
    // so failures point at the peer application, not the network path.
    let handshake = async {
        let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let mut noise = builder
            .local_private_key(&keypair.private)?
            .build_initiator()?;
        let mut buf = vec![0u8; MAX_NOISE_FRAME];
        let n = noise.write_message(&[], &mut buf)?;
        write_frame(&mut stream, &buf[..n]).await?;
        let reply = read_frame(&mut stream).await?;
        noise.read_message(&reply, &mut buf)?;
        let n = noise.write_message(&[], &mut buf)?;
        write_frame(&mut stream, &buf[..n]).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(noise.into_transport_mode()?)
    };
    let mut transport = match timeout(IO_TIMEOUT, handshake).await {
        Ok(Ok(transport)) => transport,
        Ok(Err(e)) => {
            return Err(format!(
                "[stage 2/3: encryption handshake] TCP connected to {} but the handshake failed: {}. Something is listening on that port, but it may not be p2p-cli or is an incompatible version",
                target, e
            )
            .into())
        }
        Err(_) => {
            return Err(format!(
                "[stage 2/3: encryption handshake] TCP connected to {} but the handshake timed out. Something accepted the connection but never completed the handshake — possibly a different service on that port",
                target
            )
            .into())
        }
    };

    // Stage 3: encrypted delivery.
    let deliver = async {
        let mut buf = vec![0u8; MAX_NOISE_FRAME];
        let n = transport.write_message(&plaintext, &mut buf)?;
        write_frame(&mut stream, &buf[..n]).await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    match timeout(IO_TIMEOUT, deliver).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!(
            "[stage 3/3: message delivery] handshake with {} succeeded but sending the message failed: {}",
            target, e
        )
        .into()),
        Err(_) => Err(format!(
            "[stage 3/3: message delivery] handshake with {} succeeded but sending the message timed out",
            target
        )
        .into()),
    }
}

async fn receive_noise_message(
    mut stream: TcpStream,
) -> Result<NetworkMessage, Box<dyn std::error::Error + Send + Sync>> {
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    let mut noise = builder
        .local_private_key(&keypair.private)?
        .build_responder()?;
    let mut buf = vec![0u8; MAX_NOISE_FRAME];
    let first = read_frame(&mut stream).await?;
    noise.read_message(&first, &mut buf)?;
    let n = noise.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;
    let third = read_frame(&mut stream).await?;
    noise.read_message(&third, &mut buf)?;
    let mut transport = noise.into_transport_mode()?;
    let ciphertext = read_frame(&mut stream).await?;
    let n = transport.read_message(&ciphertext, &mut buf)?;
    Ok(serde_json::from_slice(&buf[..n])?)
}

async fn read_frame(
    stream: &mut TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > MAX_NOISE_FRAME {
        return Err("invalid frame length".into());
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

async fn write_frame(
    stream: &mut TcpStream,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if data.is_empty() || data.len() > MAX_NOISE_FRAME {
        return Err("invalid frame length".into());
    }
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(data).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MessageType;

    #[tokio::test]
    async fn noise_round_trip_preserves_large_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = NetworkMessage::new(
            MessageType::TextMessage,
            "127.0.0.1:8080".into(),
            "x".repeat(16 * 1024),
            None,
            None,
        );
        let expected_id = expected.id;
        let receiver = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            receive_noise_message(stream).await.unwrap()
        });
        send_noise_message(expected, addr).await.unwrap();
        let received = receiver.await.unwrap();
        assert_eq!(received.id, expected_id);
        assert_eq!(received.content.len(), 16 * 1024);
    }

    #[tokio::test]
    async fn reports_tcp_stage_when_port_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let message = NetworkMessage::new(
            MessageType::TextMessage,
            "127.0.0.1:8080".into(),
            "hi".into(),
            None,
            None,
        );
        let error = send_noise_message(message, addr).await.unwrap_err();
        assert!(error.to_string().contains("stage 1/3"), "{}", error);
    }

    #[tokio::test]
    async fn reports_handshake_stage_when_peer_speaks_garbage() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&[0, 0, 0, 4, 1, 2, 3, 4]).await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
        });
        let message = NetworkMessage::new(
            MessageType::TextMessage,
            "127.0.0.1:8080".into(),
            "hi".into(),
            None,
            None,
        );
        let error = send_noise_message(message, addr).await.unwrap_err();
        assert!(error.to_string().contains("stage 2/3"), "{}", error);
    }

    #[tokio::test]
    async fn rejects_oversized_plaintext() {
        let message = NetworkMessage::new(
            MessageType::TextMessage,
            "127.0.0.1:8080".into(),
            "x".repeat(MAX_PLAINTEXT + 1),
            None,
            None,
        );
        assert!(send_noise_message(message, "127.0.0.1:9".parse().unwrap())
            .await
            .is_err());
    }
}
