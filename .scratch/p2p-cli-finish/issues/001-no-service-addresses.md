# No-service address discovery

Question: How does the client discover addresses without third-party services?

Type: resolved design decision. Blockers: none. Status: resolved.

Answer: Use local interface and route discovery. Never call a public IP lookup service. Users may share router-observed public IPv4 addresses manually.

Evidence: `src/network/addr.rs` uses a local UDP route probe; `src/main.rs` no longer starts an HTTP lookup. Commit `e81a7cf` is pushed to `origin/main`.
