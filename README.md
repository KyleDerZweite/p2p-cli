# P2P CLI

A Linux terminal messenger for two people who can reach each other directly. Both clients run locally. Chat requires no account, relay, public IP lookup, rendezvous server, STUN/TURN server, or hosted VPN.

One peer must have a reachable TCP listening port. That can be a LAN address, global IPv6 with firewall permission, or a manually forwarded IPv4 port. The other peer connects once; both directions use that same encrypted connection. Some network pairs cannot connect under these constraints.

## Build and chat

Install Rust, a C compiler, and iproute2 on Linux. SQLite is bundled. Build and install:

```sh
cargo install --path . --locked
```

The listener generates an invitation, shares it with the other person, then starts chat using the same profile and port:

```sh
p2p-cli --invite -p 8080
p2p-cli -p 8080
```

The connecting person runs:

```sh
p2p-cli --connect 'p2p-cli:v1:...'
```

The listener presses `a` to accept and remember the identity, `o` to accept once, or `d` to decline. Type a message and press Enter. `Ctrl+C` quits, `Ctrl+D` disconnects, and `Tab` switches fields. An invitation can also be pasted into the connection field. `Ctrl+Y` copies your invitation in terminals that permit OSC 52 clipboard access; `/invite` prints it in chat.

For internet IPv4, supply the router's public address and forwarded TCP port when generating the invitation:

```sh
p2p-cli --invite --address 203.0.113.10:8080
```

The example IP above is a documentation address. Replace it with your own. The command does not configure the router. For IPv6 use `[address]:port`. Exchange invitations through a channel where you can verify who sent them. The invitation pins the expected public identity key; addresses alone do not.

See [Linux networking and troubleshooting](docs/linux.md) for CGNAT, firewalls, IPv6, and WireGuard.

## Diagnostics

```sh
p2p-cli --diagnose
p2p-cli --diagnose 192.168.1.20:8080
p2p-cli --connect 'p2p-cli:v1:...' --log connection.log
```

`--diagnose` prints assigned addresses and discovery limitations. With a target, it tests TCP reachability. A successful probe does not verify the remote identity. Interactive connection failures include the phase, destination, observed error, and suggested checks. Invitation addresses are tried in order with the same expected identity.

`--log` creates a new owner-only file, capped near 4 MiB. It records network metadata and failures, excludes chat text and keys, and refuses existing paths. Maximum mode rejects persistent logs. Unsolicited scanner failures go to diagnostics rather than the chat display.

A timeout cannot identify which router or firewall dropped a packet. The app reports that uncertainty. Exact router policy requires the router's response or its logs.

## Security and storage

Every policy uses the same Noise XX transport with X25519, ChaCha20-Poly1305, and BLAKE2s. Both peers sign the completed handshake transcript with Ed25519 before sending application messages. Signatures separate the two roles and protocol version. Each conversation has a fresh transport. Application envelopes remain signed, with identity, session-state, timestamp, and replay checks.

The default is `--security tofu`. Existing flags remain available:

| Policy | Local behaviour |
| --- | --- |
| `quick` | Session approval, encrypted history; no implicit persistent trust |
| `tofu` | Explicit approval can remember identities; invitations pin the expected key |
| `secure` | Alias policy for TOFU, retained for existing commands |
| `max` | Memory-only history and trust; persistent identity remains |

`/trust` explicitly remembers a peer, `/untrust` removes remembered trust, `/fingerprint` displays both fingerprints, `/alias name` assigns a local name, `/status` reports the connection, `/myip` lists candidates, and `/clear` clears only the visible transcript. `/help` lists shortcuts. Local policy cannot control what the other person stores.

Persistent history encrypts message bodies with AES-256-GCM. Linux uses XDG config/data directories, normally `~/.config/p2p-cli` and `~/.local/share/p2p-cli`. Identity and storage-key files are owner-only and created atomically. Chat and trust metadata remain in SQLite. Keep both the identity and storage key private; losing the storage key loses access to existing history. Corrupt keys cause a startup error instead of silently replacing them.

TOFU identifies previously accepted keys, not people. An address-only connection to a new key remains unverified; compare fingerprints before sending private text. A trusted invitation detects an unexpected endpoint key. The app cannot protect a compromised endpoint, terminal recording, IP/timing metadata, or an attacker exhausting network capacity. Local encryption does not protect history from someone who can read the storage key. Maximum mode does not erase earlier files.

Messages appear locally when queued. There are no delivery receipts or automatic retransmission; if a connection fails during a send, delivery can be uncertain. Reconnect explicitly. The protocol intentionally rejects older per-message-connection versions. Use the same current version on both sides.

## Verification and scope

```sh
cargo fmt --check
cargo test --locked
cargo build --locked
python3 tests/linux_smoke.py
cargo build --release --locked
```

The Linux smoke test uses two real terminals with separate profiles to check invitations, acceptance, messages in both directions, paste, restart, and encrypted history recovery. Network tests cover a dialer with no listening socket, wrong identity pins, protocol state, framing limits, and shutdown.

This release scope is pairwise text chat. Automatic router mapping, LAN broadcasts, file transfer, group chat, and automatic reconnect are deferred. [The implementation design](docs/design.md) and [completion map](.scratch/p2p-cli-finish/map.md) record the choices. The cryptographic implementation has not received an independent audit.

MIT license. See [LICENSE.md](LICENSE.md).
