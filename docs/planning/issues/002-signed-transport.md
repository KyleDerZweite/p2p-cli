# Signed transport binding

Question: How should identity signatures authenticate the Noise transport session?

Type: security design. Blockers: none. Status: resolved and implemented.

Both peers sign the completed Noise handshake hash, protocol domain, and sender role with their persistent Ed25519 identity. Encrypted proof exchange completes before application data. The dialer compares the authenticated identity with the invitation pin before sending the connection request. Each received envelope must use that channel's identity. App verifies the immutable signed envelope before substituting the observed socket address for routing.

Evidence: `src/network/handshake.rs` tests reject wrong channel, role, key and forwarded proofs between real Noise sessions. `src/app/security_tests.rs` rejects signature tampering, wrong session, identity changes, replay, and wrong invitation keys. This is implementation evidence, not an independent cryptographic audit.
