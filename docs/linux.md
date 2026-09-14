# Linux direct connections

p2p-cli connects directly over TCP. Neither peer needs an account, public address lookup, rendezvous server, relay, or hosted VPN. Both applications must be running to chat. At least one peer must have an address and listening TCP port that the other can reach.

## Getting connected

Follow the [quick start](../README.md) to install the client, generate an invitation, and start the listener. `--invite` prints the invitation and exits; start chat separately with the same profile and port. Both applications must stay running.

Linux interface enumeration uses `ip` from iproute2. If it is missing, discovery falls back to the default IPv4 route and reports the limitation.

On the same machine, use different listening ports and loopback addresses. On the same LAN, use the listener's LAN address. Across the internet, use a reachable global IPv6 address or configure TCP forwarding on the listener's router to its LAN address and listening port. Share a router-observed public address with `--address IP:PORT` when generating the invitation. Bracket IPv6 literals, for example `[2001:db8::1]:8080`. That example is a documentation address, not a working destination.

Assigned interface addresses are only candidates. A global IPv6 address still needs host and router firewall permission. A private IPv4 address works only where the other peer has a route to that private network. Router port forwarding can stop working when DHCP changes the listener's LAN address; reserve that address in the router when needed.

The current release uses copyable invitations and does not broadcast identities through mDNS or change router configuration automatically. Direct IPv6 and existing or manual IPv4 forwarding are supported. Optional mDNS and consent-based PCP/UPnP mapping are planned separately and must not be treated as relay services.

## Diagnosing failures

```sh
p2p-cli --diagnose
p2p-cli --diagnose 192.168.1.20:8080
p2p-cli --connect 'p2p-cli:v1:...' --log connection.log
```

`--diagnose` prints assigned addresses and discovery limitations. With a target, it tests TCP reachability. A successful probe does not verify the remote identity. Interactive connection failures include the phase, destination, observed error, and suggested checks. Invitation addresses are tried in order with the same expected identity.

`--log` creates a new owner-only file, capped near 4 MiB. It records network metadata and failures, excludes chat text and keys, and refuses existing paths. Maximum mode rejects persistent logs. Unsolicited scanner failures go to diagnostics rather than the chat display.

A timeout cannot identify which router or firewall dropped a packet. The app reports that uncertainty. Exact router policy requires the router's response or its logs.

Keep the full connection error, including destination, phase, and operating system code. A TCP failure happens before encrypted session authentication; an authentication failure means TCP reached a process, but that process did not complete the expected secure protocol.

| Evidence | Meaning and next step |
| --- | --- |
| Connection refused | Something rejected TCP. Check the listening application and port, host firewall, and router forwarding destination. A firewall may actively reject too. |
| TCP timeout | No response arrived in time. An offline peer, wrong address, filtering, or NAT can all cause this. Check each side's configuration and try reversing the connection direction. |
| No route or address unavailable | Check local connectivity and IPv6 support. Try another candidate that is reachable from this network. |
| Permission denied | Check local firewall, process sandbox, or security policy. |
| Address already in use | Another process owns the listening port. Stop it or choose another port. |
| Identity mismatch | The endpoint does not have the key in the invitation or stored trust. Verify the invitation and identity with the person before accepting a replacement. |
| Handshake failure | TCP worked, but the remote endpoint may be a different program, incompatible version, scanner, or an attacker. Compare versions and destination ports. |

When SSH works but the chat port times out, test a different listening port on the same server. For example, start the listener with `-p 44443`, generate a new invitation with `--invite -p 44443`, and use that new invitation on the connecting client. A reachable alternate port can avoid a port-specific filter without changing the protocol. Keep the listener running during the test. A server-side packet capture can distinguish packets that reached the host from packets dropped earlier, but it cannot name an upstream rule.

For local inspection, use `ip address`, `ip route`, `ip -6 route`, and `ss -ltnp`. Firewall inspection depends on the distribution, commonly `sudo nft list ruleset` or `sudo ufw status verbose`. These inspect your own machine. Router policy requires inspecting your router's own interface or logs.

A timeout does not prove that a specific router rejected traffic. The application cannot truthfully name that router or rule without its response or logs. Behind carrier-grade NAT, the router's WAN address may itself be private or in `100.64.0.0/10`. Home-router forwarding alone does not make that WAN reachable. Try reachable IPv6, let the other person listen, or ask the ISP about public addressing. Some network pairs cannot connect within the project's direct-only requirement.

## WireGuard

WireGuard encrypts IP traffic over UDP. A tunnel run by the two peers fits the ownership constraint, but it does not solve reachability by itself. At least one reachable UDP endpoint is normally needed for a simple two-peer setup. Routers can block UDP, drop unsolicited packets, or place both peers behind NAT that prevents them from reaching each other. `PersistentKeepalive` maintains an existing NAT mapping; it does not create port forwarding through an upstream router or guarantee traversal of carrier-grade NAT.

A working two-peer WireGuard tunnel can carry p2p-cli traffic using its tunnel addresses. Configuring the tunnel requires separate keys, routes, firewall rules, and usually administrator privileges. p2p-cli already encrypts and authenticates its direct connection, so WireGuard remains an optional network choice rather than a prerequisite.
