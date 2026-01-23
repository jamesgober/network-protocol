# Architecture

## Overview

The network-protocol library is a Rust-based secure networking protocol designed for high-performance, low-latency communication. It provides layered security, configurable transport options, and comprehensive error handling.

## Design Principles

1. **Security First**: All communications encrypted by default, defense in depth
2. **Zero-Copy Where Possible**: Minimize allocations and copies in hot paths
3. **Async by Default**: Built on Tokio for scalable concurrent connections
4. **Type Safety**: Leverage Rust's type system to prevent bugs at compile time
5. **Fail-Fast**: Validate early, reject invalid input before expensive operations
6. **Observable**: Structured logging for debugging and monitoring

## Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Application Layer                     │
│              (User Code / Business Logic)               │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │
┌─────────────────────────────────────────────────────────┐
│                    Protocol Layer                       │
│  ┌──────────┐  ┌───────────┐  ┌────────────────────┐  │
│  │ Handshake│  │ Dispatcher│  │ Message Routing    │  │
│  └──────────┘  └───────────┘  └────────────────────┘  │
│  ┌──────────┐  ┌───────────┐  ┌────────────────────┐  │
│  │Heartbeat │  │ Keepalive │  │ Session Management │  │
│  └──────────┘  └───────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │
┌─────────────────────────────────────────────────────────┐
│                     Core Layer                          │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │Packet Codec  │  │   Framing   │  │ Serialization│  │
│  └──────────────┘  └─────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │
┌─────────────────────────────────────────────────────────┐
│                   Transport Layer                       │
│  ┌───────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │    TLS    │  │   TCP    │  │  Unix Sockets     │   │
│  └───────────┘  └──────────┘  └───────────────────┘   │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │
┌─────────────────────────────────────────────────────────┐
│                   Utilities Layer                       │
│  ┌──────────┐  ┌────────────┐  ┌─────────────────┐    │
│  │  Crypto  │  │Compression │  │   Logging       │    │
│  └──────────┘  └────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### Transport Layer

#### TLS Transport (`src/transport/tls.rs`)
- **Purpose**: Secure communication over untrusted networks
- **Features**:
  - TLS 1.2/1.3 support via rustls
  - Mutual TLS (mTLS) for client authentication
  - Certificate pinning for high-security deployments
  - Self-signed certificate generation for testing
- **Security**: System root CAs, modern cipher suites only
- **Use Case**: Internet-facing services, untrusted networks

#### Local Transport (`src/transport/local.rs`)
- **Purpose**: High-performance IPC on same machine
- **Features**:
  - Unix domain sockets (UDS)
  - Lower overhead than TCP
  - OS-level security via filesystem permissions
- **Use Case**: Microservices, local daemons, same-machine communication

#### Remote Transport (`src/transport/remote.rs`)
- **Purpose**: TCP without TLS (trusted networks only)
- **Features**:
  - Direct TCP connections
  - Lower latency than TLS
  - Must be combined with application-level encryption
- **Use Case**: Internal data centers, VPNs, localhost

#### Cluster Transport (`src/transport/cluster.rs`)
- **Purpose**: Manage multi-peer topologies
- **Features**:
  - Peer discovery and management
  - Gossip protocol support
  - Fault tolerance
- **Use Case**: Distributed systems, service meshes

### Core Layer

#### Packet (`src/core/packet.rs`)
- **Purpose**: Binary wire format with framing
- **Format**:
  ```
  [Magic: 0xDEADBEEF (4 bytes)]
  [Version: 1 (1 byte)]
  [Flags: compression/encryption (1 byte)]
  [Length: payload size (4 bytes BE)]
  [Payload: N bytes]
  ```
- **Limits**: 
  - Min: 10 bytes (header only)
  - Max: 16 MB (prevents DoS)
- **Validation**: Magic bytes, version check, length bounds

#### Codec (`src/core/codec.rs`)
- **Purpose**: Tokio codec for async framing
- **Features**:
  - Incremental parsing (no buffering entire packets)
  - Zero-copy where possible
  - Backpressure support
- **Implementation**: `tokio_util::codec::{Encoder, Decoder}`

### Protocol Layer

#### Handshake (`src/protocol/handshake.rs`)
- **Purpose**: Establish secure session with key exchange
- **Flow**:
  1. Client → Server: `SecureHandshakeInit` (pubkey, timestamp, nonce)
  2. Server validates timestamp, generates shared secret
  3. Server → Client: `SecureHandshakeResponse` (encrypted challenge)
  4. Client → Server: `SecureHandshakeConfirm` (encrypted nonce verification)
- **Security**:
  - X25519 ECDH key exchange
  - Per-session keys
  - Timestamp validation (±5 seconds)
  - Nonce tracking (10,000 per session)

#### Message (`src/protocol/message.rs`)
- **Purpose**: Application-level message types
- **Types**:
  - `Data`: Arbitrary payload
  - `Echo`: Request-response test
  - `Ping`/`Pong`: Keepalive
  - `SecureHandshake*`: Session establishment
- **Serialization**: Bincode (efficient binary)

#### Dispatcher (`src/protocol/dispatcher.rs`)
- **Purpose**: Route messages to registered handlers
- **Features**:
  - Handler registration by message type
  - Thread-safe via `Arc<RwLock<>>`
  - Extensible for custom message types
- **Use Case**: Server-side message routing

#### Heartbeat (`src/protocol/heartbeat.rs`)
- **Purpose**: Detect idle connections
- **Mechanism**:
  - Track last send/receive time
  - Configurable interval (default 30s)
  - Triggers keepalive ping if idle
- **Use Case**: Prevent silent connection failures

#### Keepalive (`src/protocol/keepalive.rs`)
- **Purpose**: Prevent connection timeouts
- **Mechanism**:
  - Send `Ping` if idle
  - Expect `Pong` response
  - Configurable interval
- **Use Case**: Long-lived connections through NAT/firewalls

### Service Layer

#### Client (`src/service/client.rs`)
- **Purpose**: Client-side connection management
- **Features**:
  - Automatic keepalive
  - Request-response patterns
  - Timeout handling
  - Graceful shutdown

#### Daemon (`src/service/daemon.rs`)
- **Purpose**: Server-side connection handling
- **Features**:
  - Accept incoming connections
  - Per-connection processing
  - Backpressure (channel limits)
  - Graceful shutdown with signal handling

#### Secure Client/Daemon (`src/service/secure.rs`, `tls_*.rs`)
- **Purpose**: TLS-wrapped versions of client/daemon
- **Features**: All base features + TLS encryption

### Utilities Layer

#### Crypto (`src/utils/crypto.rs`)
- **Algorithm**: ChaCha20-Poly1305 AEAD
- **Key Size**: 256-bit
- **Nonce Size**: 192-bit (unique per message)
- **Features**:
  - Authenticated encryption
  - Key derivation
  - Secure RNG (getrandom)

#### Compression (`src/utils/compression.rs`)
- **Algorithms**: LZ4 (fast), Zstd (high ratio)
- **Threshold**: 512 bytes (configurable)
- **Limits**: 16 MB output (DoS protection)
- **Features**:
  - Conditional compression based on size
  - Pre-decompression size validation
  - OOM attack prevention

#### Logging (`src/utils/logging.rs`)
- **Framework**: Tracing
- **Formats**: JSON, pretty-print
- **Outputs**: Stdout, file rotation
- **Levels**: Trace, Debug, Info, Warn, Error

#### Time/Timeout (`src/utils/time.rs`, `timeout.rs`)
- **Time**: Timestamp utilities (seconds, milliseconds)
- **Timeout**: Async wrappers for operations
- **Use Case**: Connection timeouts, handshake deadlines

## Data Flow

### Sending a Message

```
Application
    │
    ├─ Serialize message (bincode)
    │
    ├─ Optionally compress (if > threshold)
    │
    ├─ Optionally encrypt (if session keys present)
    │
    ├─ Create Packet (magic, version, flags, length, payload)
    │
    ├─ Encode to bytes (PacketCodec)
    │
    └─ Write to transport (TLS/TCP/UDS)
```

### Receiving a Message

```
Transport (TLS/TCP/UDS)
    │
    ├─ Read bytes from socket
    │
    ├─ Decode Packet (PacketCodec validates magic/length)
    │
    ├─ Extract payload from Packet
    │
    ├─ Optionally decrypt (check flags)
    │
    ├─ Optionally decompress (check flags)
    │
    ├─ Deserialize message (bincode)
    │
    └─ Deliver to application
```

## Security Model

### Threat Boundaries

- **Network**: All network traffic is assumed hostile
- **Peer**: Peers may be malicious (validate all input)
- **Resources**: Assume DoS attempts (enforce limits)

### Defense Mechanisms

1. **Encryption**: ChaCha20-Poly1305 or TLS 1.2+
2. **Authentication**: mTLS or session handshake
3. **Replay Protection**: Nonce tracking + timestamps
4. **DoS Protection**: Size limits, timeouts, backpressure
5. **Memory Safety**: Rust ownership, no unsafe in core

### Trust Model

- **System Libraries**: Trust OS RNG, TLS stack
- **Dependencies**: Audit via cargo-deny/audit
- **Crypto Primitives**: RustCrypto (community vetted)

See [THREAT_MODEL.md](THREAT_MODEL.md) for comprehensive threat analysis.

## Configuration

### Key Configuration Points

- **Timeouts**: Connection, send, receive (prevent slowloris)
- **Compression**: Threshold, algorithm selection
- **Backpressure**: Channel capacity (prevent memory exhaustion)
- **TLS**: Certificate paths, cipher suites, client auth

### Configuration Sources

1. TOML files (`config.toml`)
2. Environment variables (application-specific)
3. Programmatic defaults

## Performance Considerations

### Hot Paths

1. **Packet Encoding/Decoding**: Minimize allocations
2. **Crypto Operations**: Use hardware acceleration (AES-NI, etc.)
3. **Compression**: Only for large payloads (threshold)
4. **Serialization**: Bincode (zero-copy where possible)

### Optimization Strategies

- **LTO**: Link-time optimization in release builds
- **Codegen Units**: Single unit for better optimization
- **Zero-Copy**: Direct buffer access where safe
- **Async**: Non-blocking I/O for concurrency

### Benchmarking

- **Criterion**: Microbenchmarks for packet, compression, messages
- **Integration Tests**: End-to-end latency and throughput
- **Stress Tests**: Large payload series, concurrent operations

See [PERFORMANCE.md](docs/PERFORMANCE.md) for detailed metrics.

## Testing Strategy

### Test Categories

1. **Unit Tests**: Individual functions and modules
2. **Integration Tests**: Cross-module interactions
3. **Edge Cases**: Invalid inputs, boundary conditions
4. **Stress Tests**: High load, large payloads
5. **Fuzz Tests**: Random input generation (cargo-fuzz)
6. **Property Tests**: Invariants (encode/decode roundtrip)

### Coverage Goals

- **Core Protocol**: 100% (critical path)
- **Transport**: >90% (platform-dependent)
- **Utilities**: >95% (heavily reused)

## Error Handling

### Error Types

- **Recoverable**: Timeouts, temporary network failures
- **Protocol Errors**: Invalid packets, handshake failures
- **Fatal**: Crypto failures, out of memory

### Error Propagation

- **Result<T>**: All fallible operations
- **thiserror**: Structured error types with context
- **Logging**: Error details for debugging

### Retry Strategy

- Application-specific (library doesn't retry)
- Caller decides retry policy

## Deployment

### Recommended Patterns

1. **Edge Services**: TLS with system root CAs
2. **Internal Services**: mTLS or Unix sockets
3. **High-Throughput**: TCP in VPC, compression disabled
4. **High-Security**: mTLS + certificate pinning

### Monitoring

- Log structured events (JSON)
- Metrics: connection count, latency, throughput
- Alerts: Handshake failures, crypto errors, timeouts

## Future Enhancements

### Planned

- [ ] Post-quantum cryptography (when standardized)
- [ ] HTTP/3 transport (QUIC)
- [ ] Multi-stream connections
- [ ] Connection pooling

### Under Consideration

- [ ] Protocol versioning and negotiation
- [ ] Compression algorithm negotiation
- [ ] Message priority/QoS
- [ ] Rate limiting primitives

## References

- [API Documentation](docs/API.md)
- [Performance Guide](docs/PERFORMANCE.md)
- [Threat Model](THREAT_MODEL.md)
- [Security Policy](SECURITY.md)
