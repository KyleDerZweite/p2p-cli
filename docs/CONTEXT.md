# Direct messenger

A conversation between two peers who run their own clients and approve whom they talk to.

## Language

**Peer**: The other participant in a conversation. An address may locate a peer, but it does not identify that peer.

**Identity**: A persistent public identity key that distinguishes a peer across conversations. A new key is a new identity until a person verifies the change.
_Avoid_: Account, address

**Fingerprint**: A human-readable representation of an identity for comparison with the other person.

**Conversation**: A pairwise exchange of messages that both peers have accepted.
_Avoid_: Group, room

**Invitation**: A shareable value naming the expected identity and candidate addresses of a peer. Possessing an invitation permits an attempt to connect, not permission to start a conversation.

**Candidate address**: A possible route to a peer. Availability of an address does not establish that another peer can reach it.

**Trust**: A local decision to remember an accepted identity. Approval for one conversation does not imply remembered trust.

**Direct-only**: Communication between the two participating clients without an intermediary relay or externally operated discovery system.
