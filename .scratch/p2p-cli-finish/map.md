## Destination

A usable p2p-cli that communicates directly between two clients, keeps identity and message contents private, and needs no third-party service.

## Notes

The baseline no-service change is committed and pushed on `main`. Keep implementation small, use local platform networking, and preserve the existing Rust crypto libraries.

## Decisions so far

- [Baseline no-service transport](issues/001-no-service-addresses.md): remove external IP lookup and report local addresses.

## Not yet specified

- Persistent transport ownership and reconnect behaviour depend on the session model decision.
- Invitation fields and address discovery depend on the reachability decision.

## Out of scope

- Relays, central rendezvous, STUN/TURN, accounts, and hosted discovery.
