# Local discovery

Question: Should LAN discovery use mDNS, and what information may it announce?

Type: reachability design. Blockers: [invitations](004-invitations.md). Status: resolved; mDNS excluded from the Linux completion scope.

Use explicit invitations generated from local interface addresses. This provides LAN use without broadcasting identities, adding multicast discovery state, or relying on another process. Public addresses may be supplied manually. No router changes occur automatically. This is the simplest sufficient approach within the user's allowance that some networks cannot connect.

Evidence: invitation-based two-client terminal acceptance and local interface parser tests. `docs/linux.md` explains how to inspect routes, listeners, local firewalls, CGNAT and router forwarding. It also explains why a two-peer WireGuard tunnel can be blocked and is optional.

Revisit opt-in mDNS or finite-lease PCP/UPnP only with a separate requirement and explicit exposure policy. Neither is needed to make the current pairwise messenger work on reachable networks.
