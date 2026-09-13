use super::{MessageType, NetworkCommand, NetworkEvent, NetworkMessage};
use crate::crypto::IdentityManager;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    time::timeout,
};

const MAX_PLAINTEXT: usize = 48 * 1024;
const MAX_NOISE_FRAME: usize = MAX_PLAINTEXT + 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 16;
const SESSION_QUEUE: usize = 32;
type Error = Box<dyn std::error::Error + Send + Sync>;

struct Session {
    sender: mpsc::Sender<NetworkMessage>,
    task: tokio::task::JoinHandle<()>,
}
pub struct ConnectionManager {
    event_sender: mpsc::Sender<NetworkEvent>,
    command_receiver: mpsc::Receiver<NetworkCommand>,
    listener_handle: Option<tokio::task::JoinHandle<()>>,
    identity: Arc<IdentityManager>,
    sessions: HashMap<SocketAddr, Session>,
    permits: Arc<Semaphore>,
}
impl ConnectionManager {
    pub async fn new(
        event_sender: mpsc::Sender<NetworkEvent>,
        command_receiver: mpsc::Receiver<NetworkCommand>,
        identity: Arc<IdentityManager>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            event_sender,
            command_receiver,
            listener_handle: None,
            identity,
            sessions: HashMap::new(),
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }
    pub async fn run(mut self) {
        let (accepted, mut incoming) = mpsc::channel(16);
        loop {
            tokio::select! {
                command=self.command_receiver.recv()=>match command {
                    Some(NetworkCommand::StartListener(port))=>self.start_listener(port,accepted.clone()).await,
                    Some(NetworkCommand::SendMessage(message,target,expected))=>self.send_message(message,target,expected).await,
                    Some(NetworkCommand::Disconnect(addr))=>{if let Some(s)=self.sessions.remove(&addr){s.task.abort();}},
                    Some(NetworkCommand::StopListener)|None=>break,
                },
                Some((stream,addr))=incoming.recv()=>{self.spawn_session(stream,addr,false,None).await;}
            }
            self.sessions.retain(|_, s| !s.task.is_finished());
        }
        if let Some(task) = self.listener_handle.take() {
            task.abort();
        }
        let mut tasks: Vec<_> = self
            .sessions
            .drain()
            .map(|(_, s)| {
                drop(s.sender);
                s.task
            })
            .collect();
        let drained = timeout(Duration::from_secs(2), async {
            for task in &mut tasks {
                let _ = task.await;
            }
        })
        .await
        .is_ok();
        if !drained {
            for task in &tasks {
                task.abort();
            }
        }
    }
    async fn start_listener(&mut self, port: u16, accepted: mpsc::Sender<(TcpStream, SocketAddr)>) {
        if let Some(task) = self.listener_handle.take() {
            task.abort();
        }
        let events = self.event_sender.clone();
        self.listener_handle = Some(tokio::spawn(async move {
            let ipv4 = match bind_listener(SocketAddr::from(([0, 0, 0, 0], port))) {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = events
                        .send(NetworkEvent::ListenerFailed(format!(
                            "IPv4 TCP bind on port {port}: {error}"
                        )))
                        .await;
                    return;
                }
            };
            let actual_port = ipv4.local_addr().map(|a| a.port()).unwrap_or(port);
            let ipv6 = match bind_listener(SocketAddr::from(([0u16; 8], actual_port))) {
                Ok(listener) => Some(listener),
                Err(error) => {
                    let _ = events
                        .send(NetworkEvent::ListenerWarning(format!(
                            "IPv6 TCP bind on port {actual_port}: {error}. IPv4 remains available"
                        )))
                        .await;
                    None
                }
            };
            let _ = events
                .send(NetworkEvent::ListenerStarted(actual_port))
                .await;
            let mut admission_window = std::time::Instant::now();
            let mut admitted = 0;
            let mut reported = false;
            loop {
                let accepted_socket = tokio::select! {
                    pair=ipv4.accept()=>pair,
                    pair=async {match &ipv6 {Some(listener)=>listener.accept().await,None=>std::future::pending().await}}=>pair,
                };
                match accepted_socket {
                    Ok(pair) => {
                        if admission_window.elapsed() >= Duration::from_secs(1) {
                            admission_window = std::time::Instant::now();
                            admitted = 0;
                            reported = false;
                        }
                        let addr = pair.1;
                        let rejected = if admitted >= 4 {
                            true
                        } else {
                            admitted += 1;
                            accepted.try_send(pair).is_err()
                        };
                        if rejected && !reported {
                            reported = true;
                            let _=events.try_send(NetworkEvent::IncomingFailed(addr,"Inbound admission limit reached; excess connections rejected for this second".into()));
                        }
                    }
                    Err(e) => {
                        let _ = events
                            .send(NetworkEvent::ListenerFailed(format!(
                                "TCP accept failed: {e}"
                            )))
                            .await;
                        break;
                    }
                }
            }
        }));
    }
    async fn send_message(
        &mut self,
        message: NetworkMessage,
        target: SocketAddr,
        expected: Option<String>,
    ) {
        if message
            .to_json()
            .map(|s| s.len() > MAX_PLAINTEXT)
            .unwrap_or(true)
        {
            let _ = self
                .event_sender
                .send(NetworkEvent::ConnectionFailed(
                    target,
                    "Message exceeds the 48 KiB protocol limit; shorten it and send again".into(),
                ))
                .await;
            return;
        }
        if matches!(message.msg_type, MessageType::ConnectionRequest) {
            if let Some(old) = self.sessions.remove(&target) {
                old.task.abort();
            }
        }
        if let Some(s) = self.sessions.get(&target) {
            if !s.task.is_finished() {
                if let Err(e) = s.sender.try_send(message) {
                    let _=self.event_sender.send(NetworkEvent::ConnectionFailed(target,format!("Session send queue unavailable: {e}. Message was not queued; reconnect if the peer disconnected"))).await;
                }
                return;
            }
        }
        // Only a new conversation may dial. Never silently replay application messages.
        if !matches!(message.msg_type, MessageType::ConnectionRequest) {
            let _ = self
                .event_sender
                .send(NetworkEvent::ConnectionFailed(
                    target,
                    "No active transport. Reconnect to the peer; this message was not sent".into(),
                ))
                .await;
            return;
        }
        self.spawn_outbound(target, message, expected).await;
    }
    async fn spawn_outbound(
        &mut self,
        target: SocketAddr,
        message: NetworkMessage,
        expected: Option<String>,
    ) {
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let _ = self
                    .event_sender
                    .send(NetworkEvent::ConnectionFailed(
                        target,
                        "Connection limit reached; close another session and retry".into(),
                    ))
                    .await;
                return;
            }
        };
        let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
        let events = self.event_sender.clone();
        let identity = self.identity.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let stream = match timeout(IO_TIMEOUT, TcpStream::connect(target)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => return Err(super::addr::connection_diagnostic(target, &e).into()),
                    Err(_) => {
                        return Err(super::addr::connection_diagnostic(
                            target,
                            &std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "10-second connect deadline expired",
                            ),
                        )
                        .into())
                    }
                };
                conversation(
                    stream,
                    target,
                    true,
                    identity,
                    receiver,
                    events.clone(),
                    Some(message),
                    expected,
                )
                .await
            }
            .await;
            if let Err(e) = result {
                let _ = events
                    .send(NetworkEvent::ConnectionFailed(target, e.to_string()))
                    .await;
            }
            let _ = events.send(NetworkEvent::ConnectionLost(target)).await;
        });
        self.sessions.insert(target, Session { sender, task });
    }
    async fn spawn_session(
        &mut self,
        stream: TcpStream,
        addr: SocketAddr,
        initiator: bool,
        first: Option<NetworkMessage>,
    ) {
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let _ = self
                    .event_sender
                    .send(NetworkEvent::IncomingFailed(
                        addr,
                        "Connection limit reached; retry after another session closes".into(),
                    ))
                    .await;
                return;
            }
        };
        let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
        let events = self.event_sender.clone();
        let identity = self.identity.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = conversation(
                stream,
                addr,
                initiator,
                identity,
                receiver,
                events.clone(),
                first,
                None,
            )
            .await
            {
                let _ = events
                    .send(NetworkEvent::IncomingFailed(addr, e.to_string()))
                    .await;
            }
            let _ = events.send(NetworkEvent::ConnectionLost(addr)).await;
        });
        self.sessions.insert(addr, Session { sender, task });
    }
}

fn bind_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

async fn conversation(
    mut stream: TcpStream,
    addr: SocketAddr,
    initiator: bool,
    identity: Arc<IdentityManager>,
    mut outgoing: mpsc::Receiver<NetworkMessage>,
    events: mpsc::Sender<NetworkEvent>,
    first: Option<NetworkMessage>,
    expected: Option<String>,
) -> Result<(), Error> {
    stream.set_nodelay(true)?;
    let (transport, peer_key) = timeout(
        IO_TIMEOUT,
        super::handshake::handshake(&mut stream, initiator, &identity),
    )
    .await
    .map_err(|_| "[encryption handshake] TCP connected but identity handshake timed out after 10s")?
    .map_err(|e| format!("[encryption handshake] TCP connected but authentication failed: {e}"))?;
    if expected.as_ref().is_some_and(|key| key != &peer_key) {
        return Err("[session identity] peer key does not match invitation; no application message was sent".into());
    }
    let (mut reader, mut writer) = stream.into_split();
    // A single owner advances both Noise nonce counters. A dedicated frame reader
    // prevents cancellation of a partial read when an outgoing message arrives.
    let (frames, mut received) = mpsc::channel(8);
    let read_task = tokio::spawn(async move {
        loop {
            let result = timeout(Duration::from_secs(90), read_frame(&mut reader)).await.unwrap_or_else(|_| Err("[session read] no peer frame for 90s; peer offline or path lost. Reconnect to retry".into()));
            let failed = result.is_err();
            if frames.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _reader = AbortOnDrop(read_task);
    let mut transport = transport;
    let mut buffer = vec![0u8; MAX_NOISE_FRAME];
    let _ = events.send(NetworkEvent::ConnectionEstablished(addr)).await;
    let mut lifecycle = Lifecycle::new(initiator);
    let approval_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    if let Some(message) = first {
        lifecycle.check(&message.msg_type, false)?;
        send_encrypted(&mut writer, &mut transport, &message, &mut buffer).await?;
    }
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(approval_deadline), if !lifecycle.approved=>return Err("[session approval] conversation was not accepted within 90s; reconnect to retry".into()),
            incoming=received.recv()=>{
                let ciphertext=incoming.ok_or("[session read] frame reader stopped")??;
                let n=transport.read_message(&ciphertext,&mut buffer)?;
                if n>MAX_PLAINTEXT {return Err("[session read] plaintext exceeds protocol limit".into());}
                let message:NetworkMessage=serde_json::from_slice(&buffer[..n])?;
                if message.identity_key.as_deref()!=Some(peer_key.as_str()){return Err("[session identity] message identity differs from authenticated channel".into());}
                lifecycle.check(&message.msg_type, true)?;
                let closes=matches!(message.msg_type,MessageType::Disconnect|MessageType::ConnectionDecline);
                events.send(NetworkEvent::MessageReceived(message,addr)).await?;
                if closes {return Ok(());}
            }
            outgoing=outgoing.recv()=>{
                let message=match outgoing{Some(m)=>m,None=>return Ok(())};
                lifecycle.check(&message.msg_type, false)?;
                send_encrypted(&mut writer,&mut transport,&message,&mut buffer).await?;
                if matches!(message.msg_type,MessageType::Disconnect|MessageType::ConnectionDecline){writer.shutdown().await?;return Ok(());}
            }
        }
    }
}
/// Transport lifecycle follows the conversation decisions made by App. An
/// inbound session becomes approved only when App queues ConnectionAccept.
struct Lifecycle {
    initiator: bool,
    requested: bool,
    approved: bool,
}
impl Lifecycle {
    fn new(initiator: bool) -> Self {
        Self {
            initiator,
            requested: false,
            approved: false,
        }
    }
    fn check(&mut self, kind: &MessageType, incoming: bool) -> Result<(), Error> {
        use MessageType::*;
        let from_initiator = incoming != self.initiator;
        match kind {
            ConnectionRequest if from_initiator && !self.requested && !self.approved=>{self.requested=true;Ok(())},
            ConnectionAccept if !from_initiator && self.requested && !self.approved=>{self.approved=true;Ok(())},
            ConnectionDecline if !from_initiator && self.requested && !self.approved=>Ok(()),
            Disconnect if self.requested=>Ok(()),
            TextMessage|Ping|PingResponse if self.approved=>Ok(()),
            _=>Err(format!("[session protocol] unexpected {kind:?}; application data requires an accepted conversation").into()),
        }
    }
}

async fn send_encrypted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    transport: &mut snow::TransportState,
    message: &NetworkMessage,
    buffer: &mut [u8],
) -> Result<(), Error> {
    let plaintext = message.to_json()?;
    if plaintext.len() > MAX_PLAINTEXT {
        return Err("[session write] message exceeds 48 KiB protocol limit".into());
    }
    let n = transport.write_message(plaintext.as_bytes(), buffer)?;
    timeout(IO_TIMEOUT,write_frame(writer,&buffer[..n])).await.map_err(|_|"[session write] peer stopped reading; send timed out after 10s. Delivery is uncertain; reconnect before retrying")??;
    Ok(())
}
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, Error> {
    // Idle sessions remain open. Once a frame starts, the remainder must arrive promptly.
    let first = reader
        .read_u8()
        .await
        .map_err(|e| format!("[session read] peer closed or connection failed: {e}"))?;
    timeout(IO_TIMEOUT, async {
        let mut prefix = [first, 0, 0, 0];
        reader.read_exact(&mut prefix[1..]).await?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len == 0 || len > MAX_NOISE_FRAME {
            return Err(format!("invalid frame length {len}; maximum {MAX_NOISE_FRAME}").into());
        }
        let mut data = vec![0; len];
        reader.read_exact(&mut data).await?;
        Ok(data)
    })
    .await
    .map_err(|_| "[session read] partial frame timed out after 10s")?
}
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<(), Error> {
    if data.is_empty() || data.len() > MAX_NOISE_FRAME {
        return Err("invalid frame length".into());
    }
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_gate_rejects_preapproval_data_and_repeated_requests() {
        let mut server = Lifecycle::new(false);
        assert!(server.check(&MessageType::Ping, true).is_err());
        server.check(&MessageType::ConnectionRequest, true).unwrap();
        assert!(server.check(&MessageType::ConnectionRequest, true).is_err());
        assert!(server.check(&MessageType::TextMessage, true).is_err());
        assert!(server.check(&MessageType::ConnectionAccept, true).is_err());
        server.check(&MessageType::ConnectionAccept, false).unwrap();
        server.check(&MessageType::TextMessage, true).unwrap();
        server.check(&MessageType::Ping, false).unwrap();
        assert!(server.check(&MessageType::ConnectionAccept, false).is_err());
    }
    #[tokio::test]
    async fn frame_roundtrip_and_limit() {
        let (mut a, mut b) = tokio::io::duplex(65536);
        let data = vec![42; MAX_PLAINTEXT];
        write_frame(&mut a, &data).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), data);
        a.write_u32((MAX_NOISE_FRAME + 1) as u32).await.unwrap();
        assert!(read_frame(&mut b)
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid frame length"));
    }
    #[tokio::test]
    async fn rejects_truncated_frame() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&[0, 0, 0, 4, 1]).await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }
}

#[cfg(test)]
mod conversation_tests {
    use super::*;
    use crate::network::NetworkManager;
    async fn event(net: &mut NetworkManager) -> NetworkEvent {
        timeout(Duration::from_secs(3), net.next_event())
            .await
            .expect("event timed out")
            .expect("manager stopped")
    }
    async fn message(net: &mut NetworkManager) -> (NetworkMessage, SocketAddr) {
        loop {
            match event(net).await {
                NetworkEvent::MessageReceived(m, a) => return (m, a),
                NetworkEvent::ConnectionEstablished(_) => {}
                e => panic!("unexpected {e:?}"),
            }
        }
    }
    fn msg(kind: MessageType, key: &IdentityManager, content: &str) -> NetworkMessage {
        let mut m = NetworkMessage::new(kind, "127.0.0.1:1".into(), content.into(), None, None);
        m.identity_key = Some(key.get_public_key_base64());
        m
    }
    #[tokio::test]
    async fn conversation_replies_without_dialer_listener_and_preserves_order() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
        let bob = Arc::new(IdentityManager::new(dir.path().join("bob")).unwrap());
        let mut a = NetworkManager::new(0, alice.clone()).await.unwrap();
        let mut b = NetworkManager::new(0, bob.clone()).await.unwrap();
        b.start_listener(0).await.unwrap();
        let port = match event(&mut b).await {
            NetworkEvent::ListenerStarted(p) => p,
            e => panic!("{e:?}"),
        };
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        a.send_message(
            msg(MessageType::ConnectionRequest, &alice, "hello"),
            target,
            None,
        )
        .await
        .unwrap();
        let (_, dialer) = message(&mut b).await;
        b.send_message(
            msg(MessageType::ConnectionAccept, &bob, "accepted"),
            dialer,
            None,
        )
        .await
        .unwrap();
        assert_eq!(message(&mut a).await.0.content, "accepted");
        for i in 0..12 {
            a.send_message(
                msg(MessageType::TextMessage, &alice, &i.to_string()),
                target,
                None,
            )
            .await
            .unwrap();
        }
        for i in 0..12 {
            let (m, source) = message(&mut b).await;
            assert_eq!(m.content, i.to_string());
            assert_eq!(source, dialer);
        }
        b.send_message(
            msg(MessageType::TextMessage, &bob, &"x".repeat(16 * 1024)),
            dialer,
            None,
        )
        .await
        .unwrap();
        assert_eq!(message(&mut a).await.0.content.len(), 16 * 1024);
        a.send_message(msg(MessageType::Disconnect, &alice, "bye"), target, None)
            .await
            .unwrap();
        a.shutdown().await.unwrap();
        assert!(matches!(
            message(&mut b).await.0.msg_type,
            MessageType::Disconnect
        ));
        b.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn rejects_identity_different_from_channel() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
        let bob = Arc::new(IdentityManager::new(dir.path().join("bob")).unwrap());
        let a = NetworkManager::new(0, alice.clone()).await.unwrap();
        let mut b = NetworkManager::new(0, bob.clone()).await.unwrap();
        b.start_listener(0).await.unwrap();
        let port = match event(&mut b).await {
            NetworkEvent::ListenerStarted(p) => p,
            e => panic!("{e:?}"),
        };
        a.send_message(
            msg(MessageType::ConnectionRequest, &bob, "forged"),
            SocketAddr::from(([127, 0, 0, 1], port)),
            None,
        )
        .await
        .unwrap();
        loop {
            match event(&mut b).await {
                NetworkEvent::ConnectionEstablished(_) => {}
                NetworkEvent::IncomingFailed(_, e) => {
                    assert!(e.contains("differs from authenticated channel"));
                    break;
                }
                e => panic!("{e:?}"),
            }
        }
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn invitation_key_mismatch_sends_no_application_message() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
        let bob = Arc::new(IdentityManager::new(dir.path().join("bob")).unwrap());
        let mut a = NetworkManager::new(0, alice.clone()).await.unwrap();
        let mut b = NetworkManager::new(0, bob.clone()).await.unwrap();
        b.start_listener(0).await.unwrap();
        let port = match event(&mut b).await {
            NetworkEvent::ListenerStarted(p) => p,
            e => panic!("{e:?}"),
        };
        a.send_message(
            msg(MessageType::ConnectionRequest, &alice, "private"),
            SocketAddr::from(([127, 0, 0, 1], port)),
            Some(alice.get_public_key_base64()),
        )
        .await
        .unwrap();
        match event(&mut a).await {
            NetworkEvent::ConnectionFailed(_, e) => {
                assert!(e.contains("does not match invitation"))
            }
            e => panic!("{e:?}"),
        }
        loop {
            match event(&mut b).await {
                NetworkEvent::ConnectionEstablished(_) => {}
                NetworkEvent::IncomingFailed(_, _) | NetworkEvent::ConnectionLost(_) => break,
                e => panic!("application data leaked: {e:?}"),
            }
        }
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn queued_ping_before_acceptance_closes_transport() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
        let bob = Arc::new(IdentityManager::new(dir.path().join("bob")).unwrap());
        let mut a = NetworkManager::new(0, alice.clone()).await.unwrap();
        let mut b = NetworkManager::new(0, bob.clone()).await.unwrap();
        b.start_listener(0).await.unwrap();
        let port = match event(&mut b).await {
            NetworkEvent::ListenerStarted(p) => p,
            e => panic!("{e:?}"),
        };
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        a.send_message(
            msg(MessageType::ConnectionRequest, &alice, "hello"),
            target,
            None,
        )
        .await
        .unwrap();
        message(&mut b).await;
        a.send_message(msg(MessageType::Ping, &alice, "keep alive"), target, None)
            .await
            .unwrap();
        loop {
            match event(&mut a).await {
                NetworkEvent::ConnectionEstablished(_) => {}
                NetworkEvent::ConnectionFailed(_, e) => {
                    assert!(e.contains("accepted conversation"));
                    break;
                }
                e => panic!("unexpected {e:?}"),
            }
        }
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }
}
