# Threat Model

## Overview

This document outlines the security threat model for the network-protocol library, identifying potential threats, attack vectors, and implemented mitigations.

## Trust Boundaries

### In Scope (We Protect Against)
- **Network Adversaries**: Attackers who can intercept, modify, or inject network traffic
- **Malicious Peers**: Untrusted clients or servers attempting to exploit the protocol
- **Denial of Service**: Resource exhaustion attacks (memory, CPU, connections)
- **Cryptographic Attacks**: Attempts to break encryption, replay messages, or forge handshakes
- **Implementation Bugs**: Memory safety issues, logic errors in protocol handling

### Out of Scope (Caller Responsibility)
- **Physical Security**: Physical access to machines running the protocol
- **Side-Channel Attacks**: Timing attacks, power analysis (rely on constant-time crypto primitives)
- **Application Logic**: Business logic vulnerabilities in code using this library
- **Denial of Service via Valid Traffic**: Application-layer rate limiting
- **Social Engineering**: Attacks targeting human operators
- **Supply Chain**: Compromised build tools or dependencies (mitigated via cargo-deny/audit)

## Threat Categories

### 1. Network-Level Threats

#### 1.1 Man-in-the-Middle (MitM) Attacks
**Threat**: Attacker intercepts and modifies traffic between client and server.

**Mitigations**:
- TLS 1.2/1.3 encryption with strong cipher suites
- Certificate validation (system root CAs or pinning)
- Mutual TLS (mTLS) support for client authentication
- ChaCha20-Poly1305 AEAD encryption for non-TLS transports
- X25519 key exchange for forward secrecy

**Residual Risk**: Certificate pinning bypass if attacker controls DNS and has valid CA cert (out of scope).

#### 1.2 Replay Attacks
**Threat**: Attacker captures valid messages and replays them later.

**Mitigations**:
- Per-session nonce tracking (10,000 nonces per session)
- Timestamp validation (5-second window)
- Session-specific encryption keys
- Unique nonces per message

**Residual Risk**: Clock skew >5s could allow stale messages (mitigated by NTP).

#### 1.3 Traffic Analysis
**Threat**: Attacker infers information from packet sizes, timing, or patterns.

**Mitigations**:
- TLS encryption hides payload content
- No protocol-level padding (application responsibility)

**Residual Risk**: Packet size correlation possible (application can add padding).

### 2. Cryptographic Threats

#### 2.1 Weak Cryptography
**Threat**: Use of broken or weak algorithms.

**Mitigations**:
- ChaCha20-Poly1305 AEAD (modern, secure)
- X25519 elliptic curve Diffie-Hellman
- TLS 1.2+ only (no SSLv3, TLS 1.0/1.1)
- Vetted RustCrypto implementations
- No custom crypto primitives

**Residual Risk**: Quantum computers break X25519 (post-quantum not yet standardized).

#### 2.2 Key Management
**Threat**: Insecure key generation, storage, or lifecycle.

**Mitigations**:
- Cryptographically secure RNG (getrandom)
- Keys are ephemeral per-session
- Memory zeroing via `zeroize` crate
- No key persistence (application responsibility)

**Residual Risk**: Keys in memory vulnerable to memory dumps (OS-level protection needed).

#### 2.3 Nonce Reuse
**Threat**: Reusing nonces breaks AEAD security.

**Mitigations**:
- 192-bit nonces (collision probability negligible)
- Cryptographic RNG for nonce generation
- Per-session nonce tracking

**Residual Risk**: RNG failure would be catastrophic (hardware/OS level).

### 3. Protocol-Level Threats

#### 3.1 Handshake Tampering
**Threat**: Attacker manipulates handshake to downgrade security.

**Mitigations**:
- Secure handshake with key exchange
- Nonce verification prevents replay
- Timestamp validation prevents stale handshakes
- All handshake messages are encrypted after initial exchange

**Residual Risk**: Initial handshake negotiation observable (fixed parameters).

#### 3.2 Message Injection
**Threat**: Attacker injects forged protocol messages.

**Mitigations**:
- AEAD authentication prevents forgery
- Session keys prevent cross-session injection
- Packet magic bytes validate format

**Residual Risk**: None if cryptography holds.

#### 3.3 Session Hijacking
**Threat**: Attacker takes over an established session.

**Mitigations**:
- Per-session encryption keys
- No session tokens (connection-based)
- TLS prevents session hijacking at transport layer

**Residual Risk**: Connection hijacking at TCP level (mitigated by TCP sequence numbers).

### 4. Denial of Service (DoS)

#### 4.1 Resource Exhaustion - Memory
**Threat**: Attacker exhausts server memory.

**Mitigations**:
- Maximum packet size: 16MB
- Decompression bomb protection (16MB output limit)
- Backpressure mechanisms limit buffering
- Connection limits (application configured)
- Pre-decompression size validation

**Residual Risk**: Many simultaneous connections could exhaust memory (application rate limiting).

#### 4.2 Resource Exhaustion - CPU
**Threat**: Attacker triggers expensive operations.

**Mitigations**:
- Compression threshold avoids unnecessary work
- Fast packet validation (reject invalid early)
- Efficient binary serialization (bincode)
- Connection timeouts prevent slowloris

**Residual Risk**: Cryptographic operations are inherently expensive (application rate limiting).

#### 4.3 Connection Exhaustion
**Threat**: Attacker opens many connections.

**Mitigations**:
- Connection timeouts (configurable)
- Graceful shutdown mechanisms
- Backpressure prevents cascading overload

**Residual Risk**: No built-in rate limiting (application responsibility).

#### 4.4 Amplification Attacks
**Threat**: Small request triggers large response.

**Mitigations**:
- No reflection mechanisms in protocol
- Request-response pattern is balanced
- No broadcast or multicast support

**Residual Risk**: Application logic could create amplification (out of scope).

### 5. Implementation Threats

#### 5.1 Memory Safety
**Threat**: Buffer overflows, use-after-free, data races.

**Mitigations**:
- Rust memory safety guarantees
- No unsafe code in core protocol logic
- Fuzzing infrastructure (3 targets)
- Comprehensive test coverage (77+ tests)

**Residual Risk**: Logic bugs in safe code, unsafe in dependencies.

#### 5.2 Integer Overflow
**Threat**: Arithmetic overflows causing unexpected behavior.

**Mitigations**:
- Rust checked arithmetic in debug builds
- Explicit bounds checking on sizes
- Maximum size limits enforced

**Residual Risk**: Overflow in release builds not checked (performance trade-off).

#### 5.3 Panic/Crash Vulnerabilities
**Threat**: Malicious input causes panics.

**Mitigations**:
- No `unwrap()` on untrusted input
- Clippy lints warn on `unwrap`/`expect`/`panic`
- Fuzz testing catches panics
- Comprehensive edge case tests

**Residual Risk**: Unfuzzed code paths could panic.

### 6. Dependency Threats

#### 6.1 Supply Chain Attacks
**Threat**: Compromised dependencies inject malicious code.

**Mitigations**:
- `cargo-deny` enforces allowed dependencies
- `cargo-audit` checks for known vulnerabilities
- Minimal dependency tree
- Vetted cryptographic crates (RustCrypto, Rustls)
- CI runs security checks on every build

**Residual Risk**: Zero-day in dependencies (monitor advisories).

#### 6.2 Transitive Dependencies
**Threat**: Vulnerabilities in indirect dependencies.

**Mitigations**:
- `cargo-audit` scans entire dependency tree
- Automatic Dependabot updates (if enabled)

**Residual Risk**: Delay between disclosure and fix.

## Attack Scenarios

### Scenario 1: Decompression Bomb
**Attack**: Send compressed payload that expands to gigabytes.

**Defense**: 
- Pre-decompression size validation
- 16MB decompression limit
- Rejects payloads claiming >16MB output
- **Result**: Attack fails, connection terminated

### Scenario 2: Replay Attack
**Attack**: Capture and replay handshake messages.

**Defense**:
- Nonce tracking (10k per session)
- Timestamp validation (5-second window)
- Session-specific keys
- **Result**: Replayed messages rejected

### Scenario 3: Slowloris
**Attack**: Hold connections open without sending data.

**Defense**:
- Send/receive timeouts (configurable)
- Keepalive heartbeat (30s default)
- Graceful shutdown on timeout
- **Result**: Stalled connections closed

### Scenario 4: Message Forgery
**Attack**: Craft fake messages to impersonate peer.

**Defense**:
- AEAD authentication
- Session encryption keys unknown to attacker
- TLS prevents network-level forgery
- **Result**: Forged messages fail authentication

### Scenario 5: Connection Flood
**Attack**: Open thousands of connections simultaneously.

**Defense**:
- Connection timeout enforcement
- Backpressure mechanisms
- Application-level rate limiting (recommended)
- **Result**: Partial mitigation, requires application logic

## Security Assumptions

1. **Cryptographic Primitives**: ChaCha20-Poly1305, X25519, and TLS implementations are secure
2. **Operating System**: OS provides secure random number generation
3. **Time Source**: System clock is reasonably accurate (±5 seconds)
4. **Network**: TCP provides reliable, ordered delivery (no out-of-order handling)
5. **Dependencies**: RustCrypto and Rustls maintainers are trustworthy
6. **Application**: Caller properly handles sensitive data and implements rate limiting

## Recommended Deployment Practices

1. **Use TLS**: Always use TLS in production unless performance is critical and you control the network
2. **Enable mTLS**: Use mutual TLS for service-to-service communication
3. **Rate Limiting**: Implement connection and request rate limiting at application layer
4. **Monitoring**: Log and monitor failed handshakes, timeouts, and errors
5. **Updates**: Stay current with security patches via `cargo audit`
6. **Certificate Pinning**: Consider pinning for high-security deployments
7. **Timeouts**: Configure appropriate timeouts for your use case
8. **Graceful Degradation**: Handle errors gracefully, don't expose internals
9. **Audit Logs**: Log security-relevant events for forensics
10. **Testing**: Run fuzzing and stress tests in staging environments

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for vulnerability disclosure process.

## References

- [RustCrypto Security Policy](https://github.com/RustCrypto)
- [Rustls Security](https://github.com/rustls/rustls/blob/main/SECURITY.md)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)
