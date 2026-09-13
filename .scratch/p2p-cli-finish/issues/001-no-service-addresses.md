# No-service address discovery

Question: How does the client discover addresses without third-party services?

Type: design. Blockers: none. Status: resolved and implemented.

Use local Linux interface enumeration through iproute2, with a packet-free local IPv4 route fallback. Report missing iproute2, unusable interfaces, and the difference between assigned and reachable addresses. Obtain public IPv4 behind NAT from the router and supply it explicitly with `--address`.

Evidence: `src/network/addr.rs`, its address/error tests, and `p2p-cli --diagnose`. The external HTTP lookup was removed in `e81a7cf`.
