use super::*;

fn app(identity: Arc<IdentityManager>) -> App {
    let config = AppConfig::default();
    App {
        state: AppState::new(config.port, config.security_level), config,
        crypto_manager: CryptoManager::new(false).unwrap(), identity_manager: identity,
        message_db: MessageDB::new_in_memory().unwrap(), seen_message_ids: HashSet::new(),
        seen_message_order: VecDeque::new(), persistent_history: false,
        pending_network_messages: VecDeque::new(), pending_candidates: VecDeque::new(),
        expected_identity: None, invitation_addresses: Vec::new(),
    }
}
fn signed(identity: &IdentityManager, kind: MessageType) -> NetworkMessage {
    let mut msg = NetworkMessage::new(kind, "127.0.0.1:8080".into(), "hello".into(), Some("session".into()), Some(SecurityLevel::Tofu));
    msg.identity_key = Some(identity.get_public_key_base64());
    msg.identity_fingerprint = Some(identity.get_fingerprint());
    msg.identity_signature = Some(identity.sign(&msg.signing_bytes().unwrap()));
    msg
}

#[test]
fn authenticated_identity_still_requires_valid_message_state_signature_and_route() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
    let mut app = app(alice.clone());
    let source = "192.0.2.1:49152".parse().unwrap();
    let valid = signed(&bob, MessageType::TextMessage);
    assert!(app.validate_incoming(&valid, source).unwrap_err().contains("outside an established"));
    app.state.connection_status = ConnectionStatus::Connected;
    app.state.peer_identity_key = Some(bob.get_public_key_base64());
    app.state.peer_ip = Some(source.to_string());
    let mut tampered = valid.clone();
    tampered.content = "attacker changed the text".into();
    assert!(app.validate_incoming(&tampered, source).unwrap_err().contains("signature verification failed"));
    let other_route = "192.0.2.1:49153".parse().unwrap();
    assert!(app.validate_incoming(&valid, other_route).unwrap_err().contains("different session"));
    assert!(app.validate_incoming(&signed(&alice, MessageType::TextMessage), source).unwrap_err().contains("identity differs"));
    app.validate_incoming(&valid, source).unwrap();
    assert!(app.validate_incoming(&valid, source).unwrap_err().contains("replayed"));
}

#[test]
fn raw_outgoing_address_never_automatically_trusts_a_new_identity() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
    let mallory = IdentityManager::new(dir.path().join("mallory")).unwrap();
    let mut app = app(alice);
    for peer in [&bob, &mallory] {
        app.reset_connection_state();
        app.start_connection("192.0.2.1:8080").unwrap();
        app.handle_network_event(NetworkEvent::MessageReceived(signed(peer, MessageType::ConnectionAccept), "192.0.2.1:8080".parse().unwrap()));
        assert!(matches!(app.state.identity_status, IdentityStatus::Unknown));
        assert!(app.message_db.get_trusted_identity(&peer.get_fingerprint()).unwrap().is_none());
    }
}

#[test]
fn invitation_rejects_validly_signed_accept_from_wrong_identity() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
    let mallory = IdentityManager::new(dir.path().join("mallory")).unwrap();
    let mut app = app(alice);
    let source = "192.0.2.1:8080".parse().unwrap();
    let invite = crate::network::invitation::Invitation::new(bob.get_public_key_base64(), vec![source]).unwrap().encode().unwrap();
    app.start_connection(&invite).unwrap();
    assert!(app.validate_incoming(&signed(&mallory, MessageType::ConnectionAccept), source).unwrap_err().contains("does not match invitation"));
    app.validate_incoming(&signed(&bob, MessageType::ConnectionAccept), source).unwrap();
}

#[test]
fn invitation_fallback_preserves_identity_and_discards_stale_failures() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
    let mut app = app(alice);
    let first = "192.0.2.1:8080".parse().unwrap();
    let second = "192.0.2.2:8080".parse().unwrap();
    let invite = crate::network::invitation::Invitation::new(bob.get_public_key_base64(), vec![first, second]).unwrap().encode().unwrap();
    app.start_connection(&invite).unwrap();
    assert_eq!(app.update().unwrap().len(), 1);
    app.handle_network_event(NetworkEvent::ConnectionFailed(first, "refused".into()));
    assert_eq!(app.state.peer_ip, Some(second.to_string()));
    assert_eq!(app.expected_peer_identity(), Some(bob.get_public_key_base64()));
    assert_eq!(app.update().unwrap().len(), 1);
    app.handle_network_event(NetworkEvent::ConnectionLost(first));
    app.handle_network_event(NetworkEvent::ConnectionFailed(first, "late failure".into()));
    assert_eq!(app.state.peer_ip, Some(second.to_string()));
    assert_eq!(app.expected_peer_identity(), Some(bob.get_public_key_base64()));
}

#[test]
fn unrelated_connection_loss_preserves_active_chat() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let mut app = app(alice.clone());
    let peer: std::net::SocketAddr = "192.0.2.1:49152".parse().unwrap();
    app.state.connection_status = ConnectionStatus::Connected;
    app.state.peer_ip = Some(peer.to_string());
    app.state.peer_identity_key = Some(alice.get_public_key_base64());
    app.handle_network_event(NetworkEvent::ConnectionLost("192.0.2.1:49153".parse().unwrap()));
    assert_eq!(app.state.connection_status, ConnectionStatus::Connected);
    assert_eq!(app.state.peer_ip, Some(peer.to_string()));
    assert_eq!(app.state.peer_identity_key, Some(alice.get_public_key_base64()));
}

#[test]
fn declined_incoming_request_retains_observed_socket_for_reply() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
    let mut app = app(alice);
    let peer: std::net::SocketAddr = "192.0.2.1:49152".parse().unwrap();
    app.handle_network_event(NetworkEvent::MessageReceived(signed(&bob, MessageType::ConnectionRequest), peer));
    let reply = app.decline_connection().unwrap().unwrap();
    assert!(matches!(reply.msg_type, MessageType::ConnectionDecline));
    assert_eq!(app.get_ui_state().previous_peer_ip, Some(peer.to_string()));
    assert!(app.state.incoming_connection.is_none());
}

#[test]
fn peer_content_cannot_inject_terminal_controls_or_bidi_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let mut app = app(alice);
    app.add_message("hello\x1b]52;c;secret\x07\r\u{009b}world\u{202e}abc\u{2066}\nnext".into(), MessageSource::Peer);
    let content = &app.state.messages.back().unwrap().content;
    assert!(!content.chars().any(|c| c.is_control() && c != '\n'));
    assert!(!content.contains('\u{202e}'));
    assert!(!content.contains('\u{2066}'));
    assert!(content.contains("\nnext"));
}

#[test]
fn paste_bounds_utf8_input_and_filters_controls() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let mut app = app(alice);
    app.state.show_security_selection = false;
    for (mode, limit) in [(InputMode::ConnectField, 8192), (InputMode::MessageField, 16384)] {
        app.state.input_mode = mode;
        app.handle_ui_event(UiEvent::Paste(format!("\x1b\n\r{}", "😀".repeat(20000)))).unwrap();
        let input = if matches!(app.state.input_mode, InputMode::ConnectField) { &app.state.connect_input } else { &app.state.message_input };
        assert!(input.len() <= limit, "input has {} bytes, expected at most {limit}", input.len());
        assert!(!input.chars().any(char::is_control));
        assert!(!input.is_empty());
    }
}

#[test]
fn quick_invitation_authenticates_without_implicit_persistent_trust() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(IdentityManager::new(dir.path().join("alice")).unwrap());
    let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
    let mut app = app(alice);
    app.config.security_level = SecurityLevel::Quick;
    let peer = "192.0.2.1:8080".parse().unwrap();
    let invite = crate::network::invitation::Invitation::new(bob.get_public_key_base64(), vec![peer]).unwrap().encode().unwrap();
    app.start_connection(&invite).unwrap();
    app.handle_network_event(NetworkEvent::MessageReceived(signed(&bob, MessageType::ConnectionAccept), peer));
    assert_eq!(app.state.connection_status, ConnectionStatus::Connected);
    assert_eq!(app.expected_peer_identity(), Some(bob.get_public_key_base64()));
    assert!(app.message_db.get_trusted_identity(&bob.get_fingerprint()).unwrap().is_none());
}
