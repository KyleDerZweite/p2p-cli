# Persistent conversation session

Question: What owns one bidirectional TCP connection, and how does reconnect work?

Type: module and lifecycle design. Blockers: [signed transport binding](002-signed-transport.md). Status: resolved and implemented.

NetworkManager owns the connection lifecycle behind command/event queues. Both message directions use the established socket, including the dialer's ephemeral source port. App owns user approval. Text and pings require acceptance. Pending approval expires after 90 seconds independently of traffic; idle sessions and partial frames have deadlines. Admission and queues are bounded. Shutdown drains queued messages within a two-second aggregate deadline.

Reconnect is explicit and authenticates a new transport. Chat is never silently replayed. Failed sends can have uncertain delivery; the local transcript is not a delivery receipt. Failure diagnostics preserve the observed phase and error.

Evidence: real TCP tests cover a dialer with no listener, IPv4 and IPv6, ordered bidirectional text, large frames, invalid framing, preapproval traffic, identity pin mismatch and shutdown. App tests reject unrelated close events and preserve the invitation pin during fallback. Linux terminal tests exercise actual user approval and restart.
