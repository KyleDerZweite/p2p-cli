# P2P CLI

Linux terminal chat between two people, with authenticated encryption and no third-party runtime service. A conversation uses one persistent, bidirectional TCP connection between the two clients. Only one peer needs a reachable port. Connections work on a LAN, over direct IPv6, or through router-mapped IPv4; incompatible firewalls fail cleanly with diagnostics. There is no relay fallback.

## Install and chat

Download the Linux binary from [v0.3](https://github.com/KyleDerZweite/p2p-cli/releases/tag/v0.3), or install from this repository with Rust and a C compiler:

```sh
cargo install --path . --locked
```

Install iproute2 for address discovery. See [installation details](docs/usage.md) for binary verification and running without installing.

The listener generates an invitation, shares it through a channel where the other person can verify the sender, then starts chat with the same profile and port:

```sh
p2p-cli --invite -p 8080
p2p-cli -p 8080
```

The other person connects using that invitation:

```sh
p2p-cli --connect 'p2p-cli:v1:...'
```

The listener presses `a` to accept and remember the identity, `o` to accept once, or `d` to decline. Type a message and press Enter. `Ctrl+C` quits; `/help` lists controls.

For internet connections, follow the [address and firewall guide](docs/linux.md). Generating an invitation does not configure your router or prove reachability.

## Documentation

- [Usage](docs/usage.md): installation, controls, and delivery limits.
- [Linux troubleshooting](docs/linux.md): diagnostics, logs, NAT, IPv6, and WireGuard.
- [Security](SECURITY.md): authentication, trust policies, storage, and threat model.
- [Design](docs/design.md), [domain glossary](docs/CONTEXT.md), and [planning](docs/PLANNING.md): implementation, decisions, and verification.
- [v0.3 release notes](docs/releases/v0.3.md): compatibility and known issues. The published binary clips long diagnostics; `main` includes the display fix.

[MIT license](LICENSE.md).
