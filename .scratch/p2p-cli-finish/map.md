## Destination

A working Linux terminal messenger for pairwise text chat, with authenticated direct connections, copyable invitations, persistent or memory-only history, and useful failure diagnostics. Only the two clients are required at runtime; restrictive network pairs may remain unreachable.

## Notes

Implementation is on `main`. The three implementation agents worked on security, persistent transport, and Linux reachability/storage/terminal verification. The integration uses the existing Rust crypto libraries and one added direct socket2 dependency, already present transitively, for explicit IPv4/IPv6 binding.

Verification: Rust tests, strict Clippy, formatting, and real Linux terminal acceptance. The terminal test covers separate profiles, acceptance, both message directions, pasted invitations, restart/history, address fallback, identity mismatch, private logs, and Maximum storage policy. `docs/design.md` records the implemented module interfaces; `docs/linux.md` records network limits.

## Decisions so far

- [No-service addresses](issues/001-no-service-addresses.md): local interface enumeration with explicit diagnostics and manually supplied public addresses.
- [Signed transport binding](issues/002-signed-transport.md): both peers sign the completed Noise transcript with protocol and role separation.
- [Persistent conversation session](issues/003-persistent-session.md): one bidirectional TCP session, bounded queues and deadlines, explicit reconnect with no automatic text retransmission.
- [Self-contained invitations](issues/004-invitations.md): versioned identity plus literal candidate addresses, pinned before sending application data, with ordered fallback.
- [Local discovery](issues/005-local-discovery.md): explicit invitation exchange and local interface enumeration; defer identity broadcasts and automatic router mutation.

## Not yet specified

No unresolved decision blocks the Linux pairwise text-chat scope. Future feature work starts a new map rather than expanding this completion record.

## Out of scope

Relays, central rendezvous, STUN/TURN, accounts, and hosted discovery conflict with the two-party runtime constraint. Automatic router mapping and mDNS add router mutation or identity broadcasting that manual invitations avoid. File transfer and groups require new product/protocol work. Automatic reconnect and retransmission require delivery semantics beyond the current explicit retry model.

Internet reachability across arbitrary routers is not an acceptance claim. Local tests prove the application behaviour; global IPv6 routing, ISP CGNAT, and each user's router policy require verification on those networks.
