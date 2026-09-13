# Linux completion record

A working Linux terminal messenger for pairwise text chat, with authenticated direct connections, copyable invitations, persistent or memory-only history, and useful failure diagnostics. Only the two clients are required at runtime; restrictive network pairs may remain unreachable.

The decisions below are implemented. Future features need a new plan. See [design](design.md) for module ownership and [Linux troubleshooting](linux.md) for network limits.

## Completed decisions

- [No-service addresses](planning/issues/001-no-service-addresses.md): local interface enumeration with explicit diagnostics and manually supplied public addresses.
- [Signed transport binding](planning/issues/002-signed-transport.md): both peers sign the completed Noise transcript with protocol and role separation.
- [Persistent conversation session](planning/issues/003-persistent-session.md): one bidirectional TCP session, bounded queues and deadlines, explicit reconnect with no automatic text retransmission.
- [Self-contained invitations](planning/issues/004-invitations.md): versioned identity plus literal candidate addresses, pinned before sending application data, with ordered fallback.
- [Local discovery](planning/issues/005-local-discovery.md): explicit invitation exchange and local interface enumeration; defer identity broadcasts and automatic router mutation.

## Out of scope

Relays, central rendezvous, STUN/TURN, accounts, and hosted discovery conflict with the two-party runtime constraint. Automatic router mapping and mDNS add router mutation or identity broadcasting that manual invitations avoid. File transfer and groups require new product/protocol work. Automatic reconnect and retransmission require delivery semantics beyond the current explicit retry model.

Internet reachability across arbitrary routers is not an acceptance claim. Local tests prove the application behaviour; global IPv6 routing, ISP CGNAT, and each user's router policy require verification on those networks.

## Verification

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/linux_smoke.py
cargo build --release --locked
```

The Linux smoke test uses two real terminals with separate profiles to check invitations, acceptance, messages in both directions, paste, restart, and encrypted history recovery. Network tests cover a dialer with no listening socket, wrong identity pins, protocol state, framing limits, and shutdown.
