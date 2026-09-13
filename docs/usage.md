# Using p2p-cli

## Installation

Download the x86-64 Linux binary and `SHA256SUMS` from [v0.3](https://github.com/KyleDerZweite/p2p-cli/releases/tag/v0.3). The binary is built on Ubuntu 22.04 with glibc. Verify it and make it executable:

```sh
sha256sum --check SHA256SUMS
chmod +x p2p-cli-linux-x86_64
./p2p-cli-linux-x86_64 --help
```

The commands below use `p2p-cli`. Substitute `./p2p-cli-linux-x86_64` when running the downloaded binary directly. Install iproute2 for local address discovery.

To build from source, install Rust and a C compiler, then run this in the repository. SQLite is bundled:

```sh
cargo install --path . --locked
```

If you only run `cargo build --release`, the command is `./target/release/p2p-cli`. Building alone does not install `p2p-cli` on your PATH.

## Chat controls

The listener presses `a` to accept and remember the identity, `o` to accept once, or `d` to decline. Type a message and press Enter. `Ctrl+C` quits, `Ctrl+D` disconnects, and `Tab` switches fields. An invitation can also be pasted into the connection field. `Ctrl+Y` copies your invitation in terminals that permit OSC 52 clipboard access; `/invite` prints it in chat.

`/trust` explicitly remembers a peer, `/untrust` removes remembered trust without closing the active conversation, `/fingerprint` displays both fingerprints, `/alias name` assigns a local name, `/status` reports the connection, `/myip` lists candidates, and `/clear` clears only the visible transcript. `/help` lists shortcuts.

Messages appear locally when queued. There are no delivery receipts or automatic retransmission; if a connection fails during a send, delivery can be uncertain. Reconnect explicitly. The protocol intentionally rejects older per-message-connection versions. Use the same current version on both sides.

See the [quick start](../README.md) for connecting two peers and [Linux troubleshooting](linux.md) for address selection and diagnostics. [Security and storage](../SECURITY.md) explains the local policies.
