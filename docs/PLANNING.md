# Direct transport implementation plan

This plan delivers a two-client runtime with authenticated direct chat, one persistent bidirectional TCP stream, and no relay, rendezvous service, STUN/TURN server, or third-party address lookup. Existing seams remain the contract: `App` owns state and approval, `NetworkManager` owns sockets, `handshake` owns channel authentication, `Invitation` owns peer configuration, and `MessageDB` owns encrypted history.

## Phase 1: authenticate the channel and freeze the envelope

1. In `src/network/handshake.rs`, bind both Ed25519 proofs to the completed Noise transcript hash, protocol domain, and sender role. Verify before accepting chat payloads.
2. In `src/network/messages.rs`, separate immutable signed fields from transport metadata. Validate signed bytes before attaching socket address, receive time, or routing state.
3. In `src/network/connection.rs`, enforce bounded frames and queues plus handshake, read, write, and approval deadlines.
4. Remove the unauthenticated `api.ipify.org` request. Use local interface enumeration and explicit candidates.
5. Classify scanner and protocol probes as diagnostics; they must not create chat alerts or approval prompts.

Add adversarial loopback tests for transcript tampering, identity and role confusion, envelope mutation, limits, timeouts, and scanner noise. Exit when authenticated and validated packets are the only events reaching `App` and `cargo fmt --check`, clippy, and tests pass.

## Phase 2: build the persistent stream

Refactor `NetworkManager` to create one `ConversationSession` per conversation, with split read and write halves, bounded outbound queues, ordered length-delimited frames, ping/pong, deadlines, and orderly close. `App` uses a session handle and never opens sockets. Disconnects end the session; reconnect is explicit, reauthenticates, and never silently retransmits accepted text. Preserve one active pairwise conversation and identity pin.

Test ordering, concurrent sends, queue limits, half-close, peer loss, ping timeout, shutdown, and explicit reconnect over real loopback TCP. Extend `tests/linux_smoke.py` to prove multiple messages use one connection, restart, and recover history.

## Phase 3: invitations, LAN discovery, and IPv6

Make invitations versioned, size-bounded, self-contained values containing the listener's Ed25519 public key and ordered literal address candidates. Parse and encode without network calls; reject invalid keys, unsupported versions, unusable addresses, and duplicates. Enumerate addresses in `src/network/addr.rs`, preferring direct global IPv6, then LAN addresses, then explicitly supplied or manually forwarded IPv4, while preserving the expected identity across fallback.

Add opt-in link-local mDNS for LAN convenience. It advertises reachability metadata only after user action and never broadcasts messages or silently accepts identities. Update CLI and docs with candidate ordering, IPv6 scope and firewall requirements, and clean failure diagnostics. Test invitation limits, fallback, IPv6 scope, duplicate suppression, and mDNS isolation.

## Phase 4: optional PCP and UPnP mapping

After explicit terminal consent, request a bounded PCP or UPnP lease for the listener port, renew only while active, and clean it up on exit. Prefer direct IPv6 and existing/manual mappings first. Mapping remains optional and disabled when declined or unsupported. Never add relays, hosted signaling, public STUN/TURN, IP lookup APIs, accounts, or self-hosted relay modes.

Mock router responses to test consent, lease bounds, renewal, cleanup, malformed replies, and unavailable routers. Verify operation with mapping declined.

## Release gates

Every phase preserves authenticated encryption, encrypted local history, bounded I/O, and actionable diagnostics. Arbitrary router pairs may remain unreachable. Run:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/linux_smoke.py
cargo build --release --locked
```

Compatibility ends at the old per-message transport because its routing and channel-authentication defects cannot be safely negotiated. Existing keys and encrypted history remain readable; random-session history is retained without automatic identity reassignment.
