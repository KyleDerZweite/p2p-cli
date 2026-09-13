# P2P CLI

![Rust](https://github.com/KyleDerZweite/p2p-cli/workflows/CI/badge.svg)

A terminal-based peer-to-peer messenger written in Rust. Every application message uses a fresh Noise XX channel (X25519, ChaCha20-Poly1305, BLAKE2s), is signed with a persistent Ed25519 identity, and is checked for replay and protocol-state violations. No relay server is involved; peers must be directly reachable.

> IMPORTANT: This project is under development and is not a stable, released product. It is provided "as-is", without warranty or guarantee. It works to some extent, but may be incomplete, unstable, or contain bugs. Mentions of a version such as "v2" do not imply an official release.

![P2P TUI](public/p2p-tui.png)

![Security Selection](public/p2p-tui-security-select.png)

## Features

- **Authenticated Noise Transport** - Fresh forward-secret X25519 + ChaCha20-Poly1305 channel per application message
- **Signed Protocol Transcript** - Ed25519 signatures bind message type, content, timestamp, ID, and metadata
- **TOFU Identity Verification** - Trust on First Use with Ed25519 identity keys
- **Four Security Levels** - From quick messaging to maximum security
- **Persistent Encrypted History** - SQLite storage with AES-256 encryption
- **Modern TUI** - Ratatui-based terminal interface with scrolling and contextual shortcut hints
- **Address Sharing** - Shows your localhost/LAN `IP:PORT` so peers can reach you (`/myip`)
- **Chat Commands** - `/help`, `/fingerprint`, `/alias`, and more

## Installation

```bash
# Clone the repository
git clone https://github.com/KyleDerZweite/p2p-cli.git
cd p2p-cli

# Build and run
cargo build --release
./target/release/p2p-cli --help
```

## Usage

```bash
# Start with default settings (port 8080, quick mode)
p2p-cli

# Listen on a specific port
p2p-cli -p 9000

# Start with TOFU security (identity verification)
p2p-cli -s tofu

# Start with maximum security (no persistent history)
p2p-cli -s max

# Combine options
p2p-cli -p 9000 -s secure -v
```

## Connecting Across Networks

The application design follows a direct-only model: two clients communicating directly with no accounts, servers, or relays.

- **Same machine:** connect to `127.0.0.1:<port>`.
- **Same LAN:** connect to the other person's LAN address, such as `192.168.1.x:8080`, or find them via local mDNS discovery.
- **Across the internet:** connect to the listener's reachable address. In the current implementation, every message opens a fresh TCP connection, requiring both sides to forward their listening port. The planned transport replaces this with a single persistent, bidirectional TCP connection per conversation, meaning only one side needs to be reachable.
- **Reaching peers without manual port forwarding:** direct connections work across networks when one side has a reachable global IPv6 address or when the local router supports automatic port mapping via PCP or UPnP. When network firewalls prevent direct connections on both sides, direct communication is not possible without changing network settings or using a mesh VPN like Tailscale or WireGuard. The app intentionally includes no relay fallback, preserving a strict two-node architecture.

Candidate addresses are shared out-of-band by exchanging a self-contained invitation containing the peer's expected public key and address options.

## Security Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | **Quick** | Encrypted and signed; approve peers for the current session |
| 1 | **TOFU** | Quick plus persistent identity pinning and change rejection |
| 2 | **Secure** | TOFU policy with a fresh forward-secret Noise channel for every protocol message |
| 3 | **Maximum** | Secure transport with in-memory message/trust database and no storage key creation |

All levels have encrypted, integrity-protected transport and signed identities. Levels are policy choices, not choices between plaintext and encryption. Switching to or from Maximum requires restarting because its storage backend is selected before the TUI starts.

## Chat Commands

| Command | Description |
|---------|-------------|
| `/help`, `/h` | Show available commands |
| `/myip`, `/ip` | Show your shareable addresses |
| `/fingerprint`, `/fp` | Show identity fingerprints |
| `/whoami` | Show your identity info |
| `/alias <name>` | Set alias for current peer |
| `/trust` | Permanently trust current peer |
| `/clear` | Clear message history |
| `/disconnect`, `/dc` | Disconnect from peer |
| `/status` | Show connection status |

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Switch between Connect/Message fields |
| `Enter` | Connect to peer / Send message |
| `Ctrl+C` | Quit application |
| `Ctrl+D` | Disconnect from peer |
| `Ctrl+S` | Open security level selection |
| `Ctrl+Y` | Copy your shareable address to the clipboard |
| `F1-F4` or `0-3` | Select security level (in the selection popup) |
| `PageUp/Down` | Scroll messages |
| `Ctrl+Home/End` | Scroll to top/bottom |
| `a` | Accept incoming connection |
| `d` | Decline incoming connection |
| `o` | Accept once (don't permanently trust) |

The footer line at the bottom of the TUI always shows the shortcuts relevant to the current context.

## Security Architecture

### Cryptographic layers

1. **Transport**: Noise XX using X25519, ChaCha20-Poly1305, and BLAKE2s. A new ephemeral handshake is performed for every application message.
2. **Application authentication**: Every complete protocol envelope is signed by a persistent Ed25519 identity.
3. **Replay resistance**: UUIDs are cached and timestamps must fall within a five-minute window.
4. **Storage**: Persistent tiers encrypt message bodies with AES-256-GCM and random nonces. Maximum uses SQLite only in memory.
5. **TOFU**: Fingerprints are computed locally from identity keys and pinned keys are rejected if they change.

### TOFU (Trust on First Use)

When running in TOFU mode (`-s tofu`), the app:
1. Generates a permanent Ed25519 identity key pair (stored in the platform-specific config directory, e.g., `~/.config/p2p-cli/p2p_identity` on Linux or `%APPDATA%\\p2p-cli\\p2p_identity` on Windows)
2. Signs the complete application protocol envelope with the identity key
3. Displays peer fingerprints (e.g., `A1B2-C3D4-E5F6-G7H8`)
4. Rejects a known fingerprint whose identity key changes

## Threat model and limitations

The design aims to protect message content and integrity against passive network observers, active network modification, replay, and later compromise of long-term identity keys after ephemeral channel secrets have been erased. TOFU cannot identify an attacker who successfully intercepts the very first contact. Compare fingerprints through an independent channel before assigning trust.

It does not protect an unlocked or compromised endpoint, terminal capture, malicious dependencies, traffic analysis metadata like IP addresses, timing, and packet sizes, denial of service by a network attacker, or plaintext copied outside the application. Persistent tiers keep peer and trust metadata in SQLite; only message bodies are encrypted. Maximum prevents new persistent chat and trust records, but does not erase files created by earlier runs. Secure deletion on SSDs and journaled filesystems cannot be guaranteed by an application.

### Known transport concerns under review

- **Channel binding:** Ephemeral Noise keypairs are generated per message, but the handshake hash is not yet cryptographically bound to the persistent Ed25519 identity signature. The application signature does not authenticate the specific ephemeral transport session, which is an open gap under review.
- **Signed envelope mutation:** `App::handle_network_event` replaces `from_ip` with the observed source address before signature verification. Because `signing_bytes()` includes `from_ip`, this can break verification on WAN connections. Transport routing metadata must be separated from the signed application payload.
- **Port scanner noise:** The TCP listener reports inbound handshake failures to the user interface. When exposed to the open internet, automated internet scanners touching the port trigger false connection alerts.
- **External IP lookup:** The startup lookup to `api.ipify.org` currently runs over unencrypted HTTP. This call will be removed entirely, replacing external web lookups with local interface enumeration, global IPv6 detection, and router responses.

This project has not received an independent cryptographic audit. Concrete algorithms, state transitions, and documented limitations are more useful and testable than marketing claims.

## Project Structure

Key crates: **tokio** (async runtime), **ratatui** (TUI), **snow** (Noise), **ed25519-dalek** (signatures), **aes-gcm** (storage encryption), **rusqlite** (history). Source lives in `src/` split into `app/` (logic & config), `crypto/`, `network/`, `ui/`, and `messagedb.rs`.

## Roadmap

- [x] Basic P2P messaging
- [x] Noise XX authenticated transport
- [x] Persistent message history
- [x] Security level framework
- [x] TOFU identity verification
- [x] Chat commands
- [x] Message scrolling
- [x] Fresh ephemeral transport keys for each application message
- [ ] Fix signature verification by separating transport metadata from signed envelopes
- [ ] Bind Noise transport handshake hash to persistent Ed25519 identity signatures
- [ ] Single persistent bidirectional TCP connection per conversation
- [x] Remove external HTTP IP lookup API; derive addresses locally
- [ ] Direct global IPv6 connectivity
- [ ] Optional local router port mapping via PCP and UPnP with explicit user prompt
- [ ] Self-contained copyable connection invitations containing public key and candidate addresses
- [ ] Link-local LAN discovery via mDNS
- [ ] File transfer
- [ ] Multi-peer connections

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
