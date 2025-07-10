# P2P CLI - TUI Messenger

![Rust](https://github.com/KyleDerZweite/p2p-cli/workflows/Rust/badge.svg)

![P2P TUI](public/p2p-tui.png)

A terminal-based peer-to-peer messenger with proper connection flow and basic cryptography.

## Features

- **Clean TUI interface** with three main sections
- **Connection establishment** with public key exchange
- **180-second timeout** for incoming connection requests
- **Real-time messaging** with connection status
- **Basic RSA encryption** ready for E2EE
- **Message history** with sender identification

## Usage

1. Start the application: `cargo run`
2. Use Tab to switch between fields
3. Enter peer IP and press Enter to connect
4. Accept/decline incoming connections with 'a'/'d'
5. Send messages when connected
6. Press 'ctrl+c' to quit

## Connection Flow

1. **Connect to**: Enter IP → sends connection request with public key
2. **Incoming**: Shows request with accept/decline options (180s timeout)
3. **Handshake**: Keys exchanged, connection established
4. **Messaging**: Real-time encrypted communication

## Status Indicators

- **Online**: Ready to connect
- **Establishing**: Waiting for response
- **Connected**: Ready to message
- **Disconnected**: Connection lost
