# Security

Every policy uses the same Noise XX transport with X25519, ChaCha20-Poly1305, and BLAKE2s. Both peers sign the completed handshake transcript with Ed25519 before sending application messages. Signatures separate the two roles and protocol version. Each conversation has a fresh transport. Application envelopes remain signed, with identity, session-state, timestamp, and replay checks.

The default is `--security tofu`. Invitations pin the expected identity in every policy:

| Policy | Local behaviour |
| --- | --- |
| `quick` | Session approval, encrypted history; no implicit persistent trust |
| `tofu` | Explicit approval can remember identities |
| `secure` | Same behaviour as TOFU; retained for existing commands |
| `max` | Memory-only history and trust; persistent identity remains |

Persistent history encrypts message bodies with AES-256-GCM. Linux uses XDG config/data directories, normally `~/.config/p2p-cli` and `~/.local/share/p2p-cli`. Identity and storage-key files are owner-only and created atomically. Chat and trust metadata remain in SQLite. Keep both the identity and storage key private; losing the storage key loses access to existing history. Corrupt keys cause a startup error instead of silently replacing them.

TOFU identifies previously accepted keys, not people. An address-only connection to a new key remains unverified; compare fingerprints before sending private text. A trusted invitation detects an unexpected endpoint key. The app cannot protect a compromised endpoint, terminal recording, IP/timing metadata, or an attacker exhausting network capacity. Local encryption does not protect history from someone who can read the storage key. Maximum mode does not erase earlier files. Local policy cannot control what the other person stores.

The cryptographic implementation has not received an independent audit.
