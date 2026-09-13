# Self-contained invitations

Question: What canonical fields and encoding let a user copy an identity plus direct candidate addresses?

Type: protocol design. Blockers: [signed transport binding](002-signed-transport.md), [persistent session](003-persistent-session.md). Status: resolved and implemented.

Use `p2p-cli:v1:` followed by URL-safe unpadded base64 of JSON containing `identity_key` and `candidates`. Parsing accepts 1 through 16 literal socket addresses, caps the input at 8192 bytes, validates the Ed25519 key, rejects unknown fields, and rejects unspecified, multicast, broadcast, and scoped/link-local IPv6 candidates. Scoped addresses require receiver-local interface information and are excluded from this portable format.

Expose `--invite`, repeated `--address`, `--connect`, `/invite`, and Ctrl+Y. Clipboard failure has a printable alternative. Candidates are tried in order with an unchanged identity pin. Exchanging the invitation through an authenticated channel remains the user's responsibility. The listener still approves the incoming conversation.

Evidence: `src/network/invitation.rs` validation tests; app fallback/pin tests; real terminal paste, failed-candidate fallback and wrong-key rejection in `tests/linux_smoke.py`.
