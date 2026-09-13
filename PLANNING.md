# P2P CLI Security Enhancement Planning

> **Document note:** Sections 1 through 6 describe the retired RSA transport and are retained for design history. Section 7 outlines the direct-only, zero-infrastructure architecture for network connectivity and transport security.

## Table of Contents
1. [Project Analysis](#project-analysis)
2. [Security Assessment](#security-assessment)
3. [Tiered Security Approach](#tiered-security-approach)
4. [Technical Deep Dive](#technical-deep-dive)
5. [Implementation Strategy](#implementation-strategy)
6. [Design Decisions](#design-decisions)
7. [Direct Transport and Zero-Infrastructure Connectivity Plan](#direct-transport-and-zero-infrastructure-connectivity-plan)

---

## Project Analysis

### Current State (As of Analysis)

**Architecture Overview:**
- **Main Application**: `main.rs` (906 lines) - Core logic, UI, networking
- **Cryptography**: `crypto.rs` (142 lines) - Hybrid RSA/AES encryption
- **Database**: `messagedb.rs` (270 lines) - SQLite persistence

**Existing Security Features:**
- ✅ **Forward Secrecy**: Ephemeral RSA keys generated per session
- ✅ **Hybrid Encryption**: RSA for key exchange, AES for storage
- ✅ **Session Management**: Timeout handling, ping/pong heartbeats
- ✅ **Persistent History**: Encrypted message storage with separate DB_KEY

**Current Crypto Implementation:**
```rust
// Generate ephemeral RSA keys for this session
let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
```

**Key Insight**: The current system already provides forward secrecy through ephemeral session keys, which is more secure than initially assessed.

---

## Security Assessment

### Current Vulnerabilities

#### 1. **No Identity Verification** (Critical)
**Problem**: Anyone can generate RSA keys and impersonate any user.

**Attack Scenario:**
```
Alice connects to 192.168.1.100 (thinking it's Bob)
↓
Attacker on 192.168.1.100 accepts connection
↓
Attacker generates fresh RSA keys
↓
Alice believes she's talking to Bob
↓
Alice shares sensitive information with attacker
```

**Impact**: Complete compromise of confidentiality and authenticity.

#### 2. **No Replay Protection** (Medium)
**Problem**: Messages could potentially be replayed by attackers.

#### 3. **No Message Authentication** (Medium)
**Problem**: No way to verify message integrity or authenticity.

### Current Strengths

#### 1. **Forward Secrecy** ✅
- Ephemeral RSA keys per session
- Past sessions remain secure even if current keys are compromised
- Keys are discarded when application closes

#### 2. **Encrypted Storage** ✅
- Separate DB_KEY for persistent message history
- Messages encrypted at rest using AES-256-GCM

#### 3. **Session Security** ✅
- Connection timeouts and heartbeat monitoring
- Graceful disconnection handling

---

## Tiered Security Approach

### Design Philosophy

**Why Tiered Security?**
1. **Backward Compatibility**: Existing usage patterns continue working
2. **Progressive Learning**: Users can gradually adopt security features
3. **Practical Flexibility**: Different conversations require different security levels
4. **Development Sanity**: Incremental implementation without breaking changes

**Real-World Parallels:**
- **SSH**: `-o StrictHostKeyChecking=no` vs default behavior
- **Signal**: Verified vs unverified contact indicators
- **Browsers**: HTTP vs HTTPS vs Extended Validation certificates

### Security Levels

#### Level 0: "Quick & Dirty" (Default)
**Current Behavior - No Changes**

**Features:**
- Ephemeral RSA keys (forward secrecy maintained)
- No identity verification
- Message history stored in SQLite
- Fast connection with minimal prompts

**Security Properties:**
- ✅ Forward secrecy
- ✅ Encrypted communications
- ✅ Encrypted storage
- ❌ No authentication
- ❌ No replay protection

**Use Case**: "I know Bob's IP and just want to send a quick message"

**CLI Usage:**
```bash
cargo run                    # Default behavior
cargo run -- --security 0   # Explicit
cargo run -- --security quick
```

#### Level 1: "Trusted Contacts"
**Add TOFU (Trust on First Use) Identity Verification**

**Features:**
- Keep current ephemeral RSA for session encryption
- Add permanent identity keys for verification
- Trust database for known contacts
- UI shows "Trusted" vs "Unknown" peer status

**Security Properties:**
- ✅ All Level 0 properties
- ✅ Identity verification after first connection
- ✅ Protection against future impersonation
- ❌ Vulnerable to first-connection attacks

**Use Case**: "I chat with Alice regularly and want to know it's really her"

**CLI Usage:**
```bash
cargo run -- --security 1
cargo run -- --security tofu
```

#### Level 2: "Secure Communications"
**Production-Level Security**

**Features:**
- TOFU + digital signatures
- Session key rotation (every 5-10 minutes)
- Replay attack protection with timestamps
- Enhanced connection verification

**Security Properties:**
- ✅ All Level 1 properties
- ✅ Digital signature verification
- ✅ Replay protection
- ✅ Regular key rotation
- ✅ Cryptographic message authentication

**Use Case**: "I'm discussing sensitive business information"

**CLI Usage:**
```bash
cargo run -- --security 2
cargo run -- --security secure
```

#### Level 3: "Maximum Security"
**No Persistent History + Enhanced Features**

**Features:**
- All Level 2 security features
- No message history saved to disk
- Messages cleared from memory after display
- Optional: Self-destructing messages

**Security Properties:**
- ✅ All Level 2 properties
- ✅ No persistent traces
- ✅ Memory clearing
- ✅ Perfect forward secrecy + perfect deletion

**Use Case**: "Highly sensitive discussion that should leave no trace"

**CLI Usage:**
```bash
cargo run -- --security 3
cargo run -- --security max
```

---

## Technical Deep Dive

### Forward Secrecy (Already Implemented)

**What is Forward Secrecy?**
Forward secrecy ensures that compromise of long-term keys cannot decrypt past communications.

**Current Implementation:**
```rust
// CryptoManager::new() generates fresh keys each session
let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
let public_key = RsaPublicKey::from(&private_key);
```

**Security Timeline:**
```
Session 1: RSA_Key_A → messages encrypted → app closes → Key_A deleted
Session 2: RSA_Key_B → messages encrypted → app closes → Key_B deleted
Storage:   DB_KEY (persistent) → history encryption in SQLite
```

**Result**: Past sessions remain secure even if current keys are compromised.

### Trust on First Use (TOFU)

**Concept:**
1. First connection: Store peer's identity key
2. Subsequent connections: Verify against stored key
3. Warn if key changes unexpectedly

**Implementation Flow:**
```
First Connection:
Alice → Bob: "Hi, my identity key is X"
Bob's App: "Unknown identity X from Alice. Trust? (y/n)"
Bob: "y"
[Identity X stored as "Alice"]

Subsequent Connections:
Alice → Bob: "Hi, my identity key is X"
Bob's App: "Verified: This is Alice" (automatic)

Attack Scenario:
Attacker → Bob: "Hi, my identity key is Y"
Bob's App: "WARNING: Alice's key changed from X to Y!"
```

**Database Schema:**
```sql
CREATE TABLE trusted_identities (
    peer_id TEXT PRIMARY KEY,
    identity_public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    alias TEXT,
    first_seen DATETIME,
    last_seen DATETIME
);
```

### Digital Signatures

**Purpose:**
Cryptographically prove that a message came from a specific identity.

**Two-Key System:**
1. **Identity Key**: Permanent, proves "I am Alice"
2. **Session Key**: Ephemeral, encrypts this conversation

**Message Flow:**
```
Alice's Side:
1. Generate ephemeral session key
2. Sign session public key with identity private key
3. Send: session_public_key + signature + identity_fingerprint

Bob's Side:
1. Look up Alice's trusted identity key
2. Verify signature using Alice's identity public key
3. If valid: "This session key is really from Alice"
4. If invalid: "This is an imposter!"
```

**Message Protocol:**
```rust
#[derive(Serialize, Deserialize)]
struct AuthenticatedMessage {
    session_public_key: String,
    identity_fingerprint: String,
    signature: String,      // session_key signed with identity_key
    timestamp: u64,         // Prevent replay attacks
    content: String,        // Actual message content
}
```

### Key Rotation

**Purpose:**
Periodically generate new encryption keys during an active session.

**Benefits:**
1. **Limits Damage**: Compromise affects only recent messages
2. **Reduces Cryptanalysis**: Less ciphertext per key
3. **Prevents Key Wear**: Fresh keys regularly

**Rotation Triggers:**
- **Time-based**: Every 5-10 minutes
- **Message-based**: Every 50-100 messages
- **Volume-based**: Every 1MB of data

**Rotation Protocol:**
```
Current State: Using Session Key K1

Alice                           Bob
[Rotation timer expires]
KEY_ROTATION_REQUEST ─────────→ [Acknowledge]
Generate new ephemeral keys     Generate new ephemeral keys
NEW_SESSION_KEY_A ─────────────→ 
                 ←───────────── NEW_SESSION_KEY_B
Compute shared secret K2        Compute shared secret K2
Delete old keys                 Delete old keys
[Now using Session Key K2]
```

---

## Implementation Strategy

### Phase 1: Infrastructure (Foundation)
**Goal**: Set up framework for multiple security levels

**Duration**: 1-2 days

**Changes Required:**
1. Add SecurityLevel enum
2. Parse CLI arguments for security level
3. Update UI to show security level indicators
4. Add security level to App struct

**Files Modified:**
- `main.rs`: SecurityLevel enum, CLI parsing, UI updates
- `Cargo.toml`: Add clap crate for argument parsing

**Code Structure:**
```rust
#[derive(Debug, Clone, Copy)]
pub enum SecurityLevel {
    Quick = 0,     // Current behavior
    Tofu = 1,      // Trust on first use
    Secure = 2,    // Signatures + rotation
    Maximum = 3,   // No persistent history
}

impl App {
    fn handle_connection(&mut self, msg: NetworkMessage) {
        match self.security_level {
            SecurityLevel::Quick => self.handle_quick_connection(msg),
            SecurityLevel::Tofu => self.handle_tofu_connection(msg),
            SecurityLevel::Secure => self.handle_secure_connection(msg),
            SecurityLevel::Maximum => self.handle_maximum_connection(msg),
        }
    }
}
```

### Phase 2: Level 1 Implementation (TOFU)
**Goal**: Add identity verification with trust-on-first-use

**Duration**: 1 week

**Changes Required:**
1. Add IdentityManager to crypto.rs
2. Extend MessageDB with identity/trust tables
3. Update connection protocol to include identity keys
4. Add trust prompts to UI

**Files Modified:**
- `crypto.rs`: IdentityManager struct and methods
- `messagedb.rs`: Identity and trust tables
- `main.rs`: Connection handling, trust UI

**New Components:**
```rust
pub struct IdentityManager {
    identity_private_key: RsaPrivateKey,  // Permanent
    identity_public_key: RsaPublicKey,    // Permanent
    trusted_peers: HashMap<String, RsaPublicKey>,
}
```

**Trust Prompt UI:**
```
╭─ Incoming Connection ─────────────────╮
│ From: 192.168.1.100                  │
│ Identity: UNKNOWN                     │
│ Fingerprint: A1B2-C3D4-E5F6-G7H8     │
│                                       │
│ This peer is not in your trust list. │
│ Press 'a' to accept and trust         │
│ Press 'd' to decline                  │
│ Press 'o' to accept once (no trust)   │
╰───────────────────────────────────────╯
```

### Phase 3: Level 2 Implementation (Secure)
**Goal**: Add digital signatures and key rotation

**Duration**: 1-2 weeks

**Changes Required:**
1. Add signature verification to IdentityManager
2. Implement key rotation logic
3. Add replay protection with timestamps
4. Update message protocol for signatures

**Files Modified:**
- `crypto.rs`: Signature methods, key rotation
- `main.rs`: Rotation timers, signature verification

**Key Rotation Implementation:**
```rust
impl App {
    fn check_key_rotation(&mut self) -> Result<(), CryptoError> {
        if self.security_level >= SecurityLevel::Secure {
            let should_rotate = self.last_rotation.elapsed() > Duration::from_secs(300) || // 5 minutes
                               self.messages_with_current_key > 50;
            
            if should_rotate {
                self.initiate_key_rotation()?;
            }
        }
        Ok(())
    }
}
```

### Phase 4: Level 3 Implementation (Maximum)
**Goal**: Add no-persistent-history mode

**Duration**: 3-5 days

**Changes Required:**
1. Add ephemeral-only mode to MessageDB
2. Implement memory clearing for messages
3. Add session-only message storage

**Files Modified:**
- `messagedb.rs`: Ephemeral mode
- `main.rs`: Conditional message storage

**Ephemeral Storage:**
```rust
impl MessageDB {
    pub fn new_ephemeral() -> Result<Self, Box<dyn std::error::Error>> {
        // In-memory SQLite database
        let conn = Connection::open(":memory:")?;
        // ... rest of initialization
    }
}
```

---

## Design Decisions

### Why RSA + AES Hybrid?
**Decision**: Keep current RSA for key exchange, AES for bulk encryption
**Reasoning**: 
- RSA provides good key exchange security
- AES provides efficient bulk encryption
- Hybrid approach is well-established
- No need to change working system

### Why TOFU Over Other Authentication Methods?
**Decision**: Implement Trust on First Use for Level 1
**Reasoning**:
- **Simplicity**: Easy to understand and implement
- **User Experience**: Minimal friction after first connection
- **Real-world proven**: Used by SSH, many other systems
- **Incremental**: Can be enhanced with signatures later

### Why Time-Based Key Rotation?
**Decision**: Rotate keys every 5-10 minutes in Level 2
**Reasoning**:
- **Predictable**: Users can understand the timing
- **Balanced**: Not too frequent (annoying) or infrequent (insecure)
- **Simple**: Easier to implement than message-count or volume-based

### Why Four Security Levels?
**Decision**: Levels 0-3 with specific feature sets
**Reasoning**:
- **Level 0**: Maintains backward compatibility
- **Level 1**: Addresses primary vulnerability (authentication)
- **Level 2**: Provides production-grade security
- **Level 3**: Addresses compliance/high-security needs

### Why No Persistent History in Level 3?
**Decision**: Level 3 disables message history storage
**Reasoning**:
- **Compliance**: Some security policies require no persistent traces
- **Forward Secrecy**: Complements cryptographic forward secrecy
- **Use Case**: Sensitive discussions that should leave no trace

---

## CLI Interface Design

### Command Line Arguments
```bash
# Level 0 (default)
cargo run
cargo run -- --port 8080
cargo run -- --security 0

# Level 1 (TOFU)
cargo run -- --security 1
cargo run -- --security tofu

# Level 2 (Secure)
cargo run -- --security 2
cargo run -- --security secure

# Level 3 (Maximum)
cargo run -- --security 3
cargo run -- --security max
```

### Help Output
```
P2P Terminal Messenger

Usage: p2p-cli [OPTIONS]

Options:
  -p, --port <PORT>           Port to listen on [default: 8080]
  -s, --security <LEVEL>      Security level [default: 0]
  -h, --help                  Print help information

Security Levels:
  0, quick    Quick & dirty - no identity verification (current behavior)
  1, tofu     Trust on first use - verify peer identity
  2, secure   Secure communications - signatures + key rotation
  3, max      Maximum security - no persistent history

Examples:
  p2p-cli                     # Quick mode (Level 0)
  p2p-cli --security 1        # TOFU mode
  p2p-cli --security secure   # Secure mode
  p2p-cli --security max      # Maximum security
```

### UI Security Indicators

**Title Bar:**
```
Level 0: "Connect to IP:PORT (Listening on: 8080)"
Level 1: "Connect to IP:PORT (Listening on: 8080) [TOFU MODE]"
Level 2: "Connect to IP:PORT (Listening on: 8080) [SECURE MODE]"
Level 3: "Connect to IP:PORT (Listening on: 8080) [MAX SECURITY]"
```

**Connection Status:**
```
Level 0: "Connected [Encrypted]"
Level 1+: "Connected [Encrypted + Verified]"    // Trusted peer
Level 1+: "Connected [Encrypted + UNVERIFIED]"  // Unknown peer
```

---

## Success Metrics

### Phase 1 Success Criteria
- [ ] All four security levels selectable via CLI
- [ ] UI shows current security level
- [ ] Level 0 maintains exact current behavior
- [ ] Help system documents security levels

### Phase 2 Success Criteria
- [ ] Identity keys generated and stored
- [ ] Trust database operational
- [ ] TOFU prompts work correctly
- [ ] Trusted vs untrusted peer indicators

### Phase 3 Success Criteria
- [ ] Digital signatures verify correctly
- [ ] Key rotation works without disconnection
- [ ] Replay protection prevents old messages
- [ ] Performance remains acceptable

### Phase 4 Success Criteria
- [ ] No messages stored in Level 3
- [ ] Memory clearing works correctly
- [ ] Session-only storage functional
- [ ] All security levels work together

---

## Risk Analysis

### Implementation Risks
1. **Complexity Creep**: Each phase adds significant complexity
2. **Backward Compatibility**: Changes might break existing behavior
3. **Performance Impact**: Security features may slow down communications
4. **User Experience**: Security prompts may confuse users

### Mitigation Strategies
1. **Incremental Implementation**: Build one phase at a time
2. **Extensive Testing**: Test each security level thoroughly
3. **Performance Monitoring**: Benchmark each phase
4. **User Testing**: Get feedback on UI/UX changes

### Security Risks
1. **Implementation Bugs**: Crypto code is easy to get wrong
2. **Side-Channel Attacks**: Timing attacks on signature verification
3. **Key Management**: Identity key compromise
4. **Protocol Attacks**: Message replay, downgrade attacks

### Security Mitigations
1. **Use Established Libraries**: Leverage well-tested crypto crates
2. **Constant-Time Operations**: Use constant-time comparison functions
3. **Key Backup/Recovery**: Document identity key management
4. **Protocol Analysis**: Review message protocols for vulnerabilities

---

## Future Enhancements

### Potential Phase 5+ Features
1. **Key Escrow**: Backup and recovery of identity keys
2. **Multi-Device Support**: Sync identity across devices
3. **Group Messaging**: Extend security to group conversations
4. **File Transfer**: Secure file sharing with same security levels
5. **Audit Logging**: Security event logging (who, when, what)

### Advanced Security Features
1. **Post-Quantum Cryptography**: Prepare for quantum computing threats
2. **Zero-Knowledge Proofs**: Prove identity without revealing keys
3. **Homomorphic Encryption**: Compute on encrypted data
4. **Steganography**: Hide messages in innocent-looking data

---

## Conclusion

This tiered security approach provides a practical path to enhance the P2P CLI's security while maintaining usability and backward compatibility. The four-level system addresses different use cases from quick messaging to high-security communications.

The implementation strategy allows for incremental development, with each phase building on the previous one. This approach reduces risk and allows for learning and adjustment throughout the development process.

The current system's forward secrecy foundation provides a strong starting point, and the planned enhancements will address the primary vulnerability of identity verification while adding additional security layers for users who need them.

---

## Direct transport and zero-infrastructure connectivity plan

### Core design principle

The application architecture commits strictly to a direct-only model: two clients, with no accounts, servers, or relays.

Public relays compromise security and leak conversation metadata. Self-hosted relays introduce operational complexity and defeat the goal of running only two client programs. Therefore, intermediate relay servers are explicitly excluded.

### The unavoidable network boundary

Direct peer-to-peer communication operates under physical network constraints:

1. On the same LAN, connections succeed directly unless local firewalls or Wi-Fi client isolation block traffic.
2. Across networks with a reachable global IPv6 address on one side, connections succeed directly when firewalls permit incoming packets.
3. Across networks with an IPv4 port mapped to one client, connections succeed directly. This mapping can be automatic when the router supports PCP or UPnP, or manually configured.
4. When neither side has a reachable address and both networks forbid inbound traffic, no direct connection is possible without altering network conditions or using a mesh VPN like WireGuard.

The application accepts this boundary honestly. When networks prevent direct communication, the app produces a clear diagnostic rather than silently falling back to intermediate relay servers.

### Immediate correctness and security blockers

Before expanding listener exposure or changing transport lifecycles, these four codebase issues must be resolved:

1. **Transport channel binding.** In `src/network/connection.rs`, each session generates fresh Noise keypairs, and the handshake completes with empty payloads. Message envelopes carry Ed25519 signatures, but those signatures do not bind to the Noise handshake transcript hash. Without channel binding, an active adversary could establish separate encrypted transport sessions to each peer and forward signed envelopes. The application signature must authenticate the specific session handshake hash before any chat text is transmitted.
2. **Envelope immutability vs transport metadata.** In `src/app/mod.rs`, incoming messages have `from_ip` overwritten with the observed socket address before `validate_incoming` verifies the signature. Because `NetworkMessage::signing_bytes` includes `from_ip`, this invalidates signatures whenever the observed source address differs from the sender address. Transport-level address tracking must be stored outside the immutable signed envelope.
3. **Removing external web dependencies.** The public IP lookup in `src/network/addr.rs` queries `api.ipify.org` over plain HTTP on port 80. External IP lookups create an unwanted third-party dependency. This call will be removed entirely, deriving candidate addresses from local network interfaces, global IPv6 addresses, and router responses.
4. **Scanner isolation and connection limits.** The TCP listener reports all failed handshakes directly to the interface. On the public internet, port scanners flood the terminal with false alerts. Inbound failures from unprompted connections must be filtered, rate-limited, and isolated from user chat notifications.

### Planned transport architecture

#### 1. Persistent bidirectional TCP connections

Replace the current ephemeral model of opening a new TCP connection per message with a single persistent, bidirectional TCP connection per conversation.

Once either side connects, both participants send and receive through that single duplex stream. Either client can take the listening role, meaning only the listening side needs to be reachable. This halves the reachability requirement compared to the current two-way listener model.

#### 2. Self-contained invitations and local discovery

- **Local link discovery.** On the same LAN, link-local mDNS provides zero-configuration discovery without external DNS servers. Discovery identifies connection addresses, while cryptographic identity verification remains an independent gate.
- **Copyable connection invitations.** Across networks, the listening client generates a compact invitation string containing its expected Ed25519 public key and candidate connection addresses. Users exchange this invitation over an existing trusted channel.
- **Pre-connection verification.** The connecting client verifies the listener public key against the invitation before establishing the conversation.

#### 3. IPv6 and optional router port mapping

- **Direct IPv6.** The client attempts direct connections over available global IPv6 addresses first, avoiding IPv4 NAT entirely when both networks support it.
- **Optional PCP and UPnP mapping.** For IPv4, the client can request a temporary port mapping from the local router using PCP or UPnP.
- **Explicit user consent.** Router port requests require explicit user permission in the terminal interface. Mappings use finite leases, renew periodically while active, and perform best-effort cleanup on shutdown.
- **No DMZ or firewall disabling.** The app will never request broad DMZ settings or disable local firewalls.

### What is explicitly excluded

To honor the zero-infrastructure requirement, the following are permanently excluded from the core messenger:

- No public or self-hosted relays.
- No central rendezvous or signaling servers.
- No public STUN or TURN dependencies.
- No third-party IP lookup APIs.

### Implementation phases

1. **Phase 1: Security and correctness fixes.** Implement Noise handshake hash channel binding, decouple transport metadata from signed envelopes, remove the HTTP IP lookup, and suppress scanner noise.
2. **Phase 2: Persistent TCP engine.** Refactor the connection manager to maintain a single bidirectional TCP stream per session with length-delimited framing and bounded queues.
3. **Phase 3: Invitations and IPv6 support.** Implement self-contained invitation generation and parsing, add dual-stack IPv6 socket binding, and add link-local mDNS for LAN discovery.
4. **Phase 4: Router port mapping.** Integrate optional PCP and UPnP mapping with explicit terminal permission prompts and lease renewal.
