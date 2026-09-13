# Signed transport binding

Question: How should identity signatures authenticate the Noise transport session?

Type: security design. Blockers: none. Status: resolved.

Both peers exchange encrypted Ed25519 proofs immediately after Noise XX completes. Each proof signs the completed Noise transcript hash, a protocol-specific prefix, and the sender's initiator or responder role. Strict signature verification rejects proof reuse on another channel or in the opposite role. The transport checks that every application message's identity matches its authenticated peer before dispatch.

The versioned Noise prologue intentionally rejects old unauthenticated transports. There is no fallback. First contact still requires an independently checked invitation identity or explicit user approval. Authentication proves possession of a key; it cannot identify an unknown human by itself.

The application verifies the original signed envelope before replacing its advertised address with the observed socket for replies. Conversation history uses the authenticated persistent identity instead of the random process session identifier.

Evidence lives in `src/network/handshake.rs` tests for channel, role and identity substitution, and a real TCP handshake authenticating both peers. The application regression test covers a signed request whose observed remote socket differs from its advertised address and replay rejection.
