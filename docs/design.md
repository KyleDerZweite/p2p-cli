# Linux messenger design

The external seam for networking is `NetworkManager`: start listening, send a signed envelope to a session address with an optional expected identity, consume events, and shut down. Its implementation owns dialing, dual-stack listeners, authentication, framing, nonce order, queue bounds, approval state, deadlines, and connection cleanup. Callers never construct Noise state or open return connections.

`App` owns the conversation and user decisions. It validates signed envelopes before using the observed socket for routing, checks expected identity and state, and applies approval, history, and UI changes. An invitation supplies candidate addresses plus one expected identity. Fallback changes the address but preserves that identity. A failed or unrelated socket cannot reset a different conversation.

`handshake` is an internal module of networking. Its interface returns an authenticated transport and peer identity, or an error. Both Ed25519 proofs sign the Noise handshake hash, protocol domain, and sender role. This concentrates channel authentication in one place and permits real TCP adversarial tests at that interface.

`Invitation` validates the copyable value. Versioning, size limits, Ed25519 validation, and unusable address rejection live behind parse and encode. Invitations contain public information. They pin the listener's identity and still require the listener to approve the connecting identity.

`CryptoManager` encrypts local history. Network confidentiality belongs entirely to networking. The earlier pass-through message encryption and unused per-process public identifier were removed. `MessageDB` uses persistent identity for peer history, so reconnecting with a new transport does not create a new contact.

The terminal is an adapter for user input and display. Bracketed paste enters text without sending it. Input is bounded, and peer control sequences are filtered before rendering. The diagnostic file is opt-in, private, bounded, and receives network metadata rather than chat envelopes.

Concrete Rust structs are sufficient at these seams. There are no alternative transport adapters or speculative repository traits. Tests cross the real module interfaces with loopback TCP, temporary SQLite profiles, and Linux pseudo-terminals.

The protocol permits one active pairwise conversation per App. Network admission and queues are bounded; pending approval expires independently of traffic. Established peers exchange pings. A closed connection ends the session; reconnecting performs fresh authentication and never silently retries chat messages.

Compatibility stops at the old transport. Its envelope-routing and channel-authentication defects make a fallback inappropriate. Existing local keys and encrypted history remain readable; older history indexed by random session identifiers is retained but is not automatically assigned to an identity without trustworthy migration evidence.
