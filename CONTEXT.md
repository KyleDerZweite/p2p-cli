# P2P CLI context

## Terms

- **Peer**: the person or device at the other end of a conversation.
- **Identity**: the persistent Ed25519 public key that names a peer across sessions.
- **Fingerprint**: the short human-readable representation of an identity public key.
- **Conversation**: one pairwise exchange of messages between two identities.
- **Invitation**: a copyable value containing an identity and candidate direct addresses.
- **Candidate address**: an address a peer may try for a direct connection.
- **Trust**: the local decision to accept an identity permanently or for one session.
- **Transport session**: the encrypted Noise channel carrying conversation messages.
- **Direct-only**: messages travel between the two peer clients without a relay or central service.
