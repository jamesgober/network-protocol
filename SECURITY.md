# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of network-protocol seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: [jamesgober@users.noreply.github.com](mailto:jamesgober@users.noreply.github.com)

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, authentication bypass, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine the affected versions
2. Audit code to find any potential similar problems
3. Prepare fixes for all supported releases
4. Release patched versions as soon as possible

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue to discuss.

## Cryptographic Material Handling

### Memory Zeroi zation Guarantees (v1.2.0+)

Network-protocol implements comprehensive memory zeroization for all cryptographic material to prevent accidental disclosure through memory dumps, swap files, or side-channel attacks.

**Zeroized Components:**

| Component | Mechanism | Location |
|-----------|-----------|----------|
| ECDH Shared Secrets | `zeroize` crate + `Drop` impl | `protocol/handshake.rs` (via x25519-dalek) |
| Session Keys (32-byte) | `zeroize::Zeroize` trait | `protocol/handshake.rs`, `service/secure.rs` |
| ChaCha20-Poly1305 Keys | Explicit zeroization on drop | `service/secure.rs` (SecureConnection) |
| XChaCha Nonces | `zeroize` after encryption/decryption | `service/secure.rs` |
| TLS Private Keys | `PrivateKeyDer` internal zeroization | `transport/tls.rs` (via rustls crates) |
| Handshake State | `#[derive(Zeroize, ZeroizeOnDrop)]` | `protocol/handshake.rs` (ClientHandshakeState, ServerHandshakeState) |

**Implementation Details:**

1. **Handshake Keys**: All ephemeral ECDH keypairs are wrapped in `x25519_dalek` types which implement `ZeroizeOnDrop`.

2. **Session Keys**: Derived session keys are explicitly zeroized after being passed to `Crypto::new()`:
   ```rust
   let mut key = derive_session_key(...);
   let crypto = Crypto::new(&key);
   key.zeroize(); // Explicit clearing
   ```

3. **Encrypted Payloads**: Plaintext buffers are dropped immediately after encryption, nonces are zeroized after use.

4. **Handshake State**: Client and server handshake state structures derive `Zeroize` and `ZeroizeOnDrop`, ensuring all intermediate cryptographic material is cleared when the state is dropped.

### Compliance Matrix

| Standard | Requirement | Implementation |
|----------|-------------|----------------|
| **HIPAA** | Protected Health Information (PHI) must be zeroed from memory | ✅ Session keys zeroized |
| **PCI-DSS** | Cardholder data must not remain in memory after use | ✅ All crypto material cleared on drop |
| **GDPR** | Personal data must be securely erased when no longer needed | ✅ Handshake state zeroized |
| **SOC 2** | Cryptographic keys must be protected in memory | ✅ Comprehensive zeroization audit (v1.2.0) |
| **NIST SP 800-88** | Data sanitization guidelines | ✅ Memory cleared before deallocation |

### Audit Trail

- **v1.0.1**: Initial zeroization for handshake per-session state
- **v1.1.0**: Added explicit nonce zeroization in secure send/receive paths
- **v1.2.0**: Comprehensive audit and hardening:
  - Added `SharedSecret` wrapper with `Zeroize` trait
  - Verified all `x25519` shared secrets cleared via `diffie_hellman()`
  - Documented zeroization guarantees for compliance certification
  - Added `Crypto::generate_key()` with caller-responsible zeroization contract

### Verification

Run tests with memory sanitizer (nightly):
```bash
RUSTFLAGS="-Z sanitizer=memory" cargo +nightly test
```

Audit zeroization manually:
```bash
# Search for all cryptographic types that should be zeroized
rg "EphemeralSecret|SharedSecret|\[u8; 32\]" src/ --type rust
```

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue to discuss.

