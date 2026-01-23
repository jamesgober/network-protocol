<div align="center">
        <img width="120px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <h1>network-protocol</h1>
    <br>
    <div>
        <a href="https://crates.io/crates/network-protocol" alt="Network-Protocol on Crates.io"><img alt="Crates.io" src="https://img.shields.io/crates/v/network-protocol"></a>
        <span>&nbsp;</span>
        <a href="https://crates.io/crates/network-protocol" alt="Download Network-Protocol"><img alt="Crates.io Downloads" src="https://img.shields.io/crates/d/network-protocol?color=%230099ff"></a>
        <span>&nbsp;</span>
        <a href="https://docs.rs/network-protocol" title="Network-Protocol Documentation"><img alt="docs.rs" src="https://img.shields.io/docsrs/network-protocol"></a>
        <span>&nbsp;</span>
        <a href="https://github.com/jamesgober/network-protocol/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/network-protocol/actions/workflows/ci.yml/badge.svg"></a>
    </div>
</div>
<br>
<p>
    A <strong>battle-hardened, security-first</strong> network protocol implementation for Rust. Built for production systems requiring both high performance and strong security guarantees. Features include comprehensive DoS protection, memory safety guarantees, and extensive testing infrastructure (77+ tests, fuzzing, stress tests).
</p>
<p>
    Designed for <strong>zero-compromise reliability</strong> in high-load environments with built-in backpressure control, automatic connection health monitoring, and graceful degradation. Supports multiple transport modes with consistent APIs and TLS 1.2+/1.3 encryption by default.
</p>

## Security Guarantees

### 🔒 Cryptographic Protections
- **Modern Encryption**: ChaCha20-Poly1305 AEAD or TLS 1.2+/1.3 (no legacy ciphers)
- **Key Exchange**: X25519 ECDH with per-session ephemeral keys
- **Forward Secrecy**: Session keys never persist, automatic key rotation
- **Replay Protection**: Nonce tracking (10,000 per session) + timestamp validation (±5s window)
- **Authentication**: Mutual TLS support, certificate pinning available

### 🛡️ DoS/Memory Protections
- **Decompression Bombs**: Pre-validation prevents LZ4/Zstd expansion attacks (16MB hard limit)
- **Memory Exhaustion**: Maximum packet size 16MB, backpressure prevents unbounded buffering
- **Slowloris**: Connection timeouts (configurable), automatic dead connection cleanup
- **Resource Limits**: Bounded channels, connection limits, compression thresholds
- **Fuzzing**: 3 fuzz targets continuously tested, OOM attacks caught pre-release

### 🔍 Implementation Safety
- **Memory Safe**: 100% safe Rust (zero `unsafe` in protocol core), fuzz-tested
- **No Panics**: All `unwrap()`/`expect()` confined to test code only
- **Validated Input**: All network data validated before processing, fail-fast on invalid packets
- **Audit Trail**: Structured logging, comprehensive error context for forensics
- **Supply Chain**: `cargo-deny` + `cargo-audit` in CI, vetted crypto dependencies (RustCrypto/Rustls)

### 📋 Standards Compliance
- **TLS**: Enforces TLS 1.2+ minimum (no SSLv3/TLS 1.0/1.1), strong cipher suites only
- **Crypto**: NIST-approved algorithms (ChaCha20-Poly1305, X25519, SHA-256)
- **Best Practices**: Certificate validation, no homebrew crypto, constant-time operations

> **Threat Model**: See [THREAT_MODEL.md](THREAT_MODEL.md) for comprehensive security analysis and attack scenarios.

<br>

## Features

### Security
- Secure handshake + post-handshake encryption using *Elliptic Curve Diffie-Hellman* (`ECDH`) key exchange
- TLS transport with client/server implementations and mutual authentication (`mTLS`)
- Certificate pinning for enhanced security in TLS connections
- Self-signed certificate generation capability for development environments
- Protection against replay attacks using timestamps and nonce verification

### Performance & Reliability
- Advanced backpressure mechanism to prevent server overload from slow clients
- Bounded channels with dynamic read pausing to maintain stable memory usage
- Configurable connection timeouts for all network operations with proper error handling
- Heartbeat mechanism with keep-alive ping/pong messages for connection health monitoring
- Automatic detection and cleanup of dead connections
- Client-side timeout handling with reconnection capabilities
- **Optimized Release Builds**: LTO + single codegen unit for maximum performance

### Testing & Quality
- **77+ Test Suite**: Unit, integration, edge cases, stress tests, doc tests
- **Fuzzing Infrastructure**: 3 targets (packet, handshake, compression) with CI smoke tests
- **Benchmarking**: Criterion-based micro-benchmarks for packet encode/decode, compression, messages
- **CI Pipeline**: Format, clippy, cross-platform builds (Linux/macOS/Windows), security audits

### Core Architecture
- Custom binary packet format with optional compression (`LZ4`, `Zstd`)
- Plugin-friendly dispatcher for message routing with zero-copy serialization
- Graceful shutdown support for all server implementations with configurable timeouts
- Modular transport: `TCP`, `Unix socket`, `TLS`, `cluster sync`
- Comprehensive configuration system with `TOML` files and environment variable overrides
- Structured logging with flexible log level control via configuration

### Compatibility
- Cross-platform support for local transport (**Windows**, **Linux**, **macOS**)
- Windows-compatible alternative for Unix Domain Sockets
- Ready for *microservices*, *databases*, *daemons*, and *system protocols*

<hr>

<p>
    <b>REPS</b> (<i>Rust Efficiency &amp; Performance Standards</i>)
    <br>⚡ <a href="https://github.com/jamesgober/rust-performance-collection"><strong>Rust Performance Collection</strong></a>
</p>

<br>


## Installation
Add the library to your `Cargo.toml`:
```toml
[dependencies]
network-protocol = "1.0.0"
```

<br>

## Quick Start

### TCP Server with Backpressure and Structured Logging
```rust
use network_protocol::utils::logging;
use network_protocol::service::daemon::{self, ServerConfig};
use network_protocol::config::NetworkConfig;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::error::Result;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging
    logging::init_logging(Some("info"), None).expect("Failed to initialize logging");
    
    // Create a dispatcher
    let dispatcher = Arc::new(Dispatcher::default());
    
    // Register message handlers
    dispatcher.register("ECHO", |msg| {
        info!(message_type = "ECHO", "Processing echo request");
        Ok(msg.clone())
    });
    
    // Option 1: Load configuration from file
    // let config = NetworkConfig::from_file("config.toml")?.server;
    
    // Option 2: Load configuration from environment variables
    // let config = NetworkConfig::from_env()?.server;
    
    // Option 3: Configure server with custom settings
    let config = ServerConfig {
        address: "127.0.0.1:9000".to_string(),
        backpressure_limit: 100, // Limit pending messages
        connection_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_secs(15),
        shutdown_timeout: Duration::from_secs(10),
        max_connections: 1000,
    };
    
    // Start server with configuration
    let server = daemon::new_with_config(config, dispatcher);
    
    // Handle Ctrl+C for graceful shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        info!("Initiating graceful shutdown...");
        server.shutdown(Some(Duration::from_secs(10))).await;
    });
    
    // Run server until stopped
    info!("Server starting on 127.0.0.1:9000");
    server.run().await
}
```

### TLS Server
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Generate or load certificates
    let cert_config = TlsConfig {
        cert_path: "server_cert.pem",
        key_path: "server_key.pem",
        ca_path: Some("ca_cert.pem"), // For mTLS
        verify_client: true, // Enable mTLS
    };
    
    // Start TLS server
    network_protocol::service::tls_daemon::start("127.0.0.1:9443", cert_config).await?;
    Ok(())
}
```

### Client with Timeout Handling
```rust
use network_protocol::utils::logging;
use network_protocol::service::client::{self, ClientConfig};
use network_protocol::config::NetworkConfig;
use network_protocol::protocol::message::Message;
use network_protocol::error::ProtocolError;
use std::time::Duration;
use tracing::{info, error};
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), ProtocolError> {
    // Initialize structured logging
    logging::init_logging(Some("info"), None)?;
    
    // Option 1: Load configuration from file
    // let config = NetworkConfig::from_file("config.toml")?.client;
    
    // Option 2: Load from environment variables
    // let config = NetworkConfig::from_env()?.client;
    
    // Option 3: Configure client with custom settings
    let config = ClientConfig {
        address: "127.0.0.1:9000".to_string(),
        connection_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(3),
        response_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_secs(15),
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay: Duration::from_secs(1),
    };
    
    // Connect with timeout handling
    info!("Connecting to server...");
    let mut conn = match timeout(Duration::from_secs(5), client::connect_with_config(config)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            error!(error = ?e, "Failed to connect to server");
            return Err(e);
        }
        Err(_) => {
            error!("Connection timeout");
            return Err(ProtocolError::Timeout);
        }
    };
    
    info!("Connected successfully");
    
    // Send message with timeout
    match timeout(Duration::from_secs(3), conn.secure_send(Message::Echo("hello".into()))).await {
        Ok(Ok(_)) => info!("Message sent successfully"),
        Ok(Err(e)) => {
            error!(error = ?e, "Failed to send message");
            return Err(e);
        }
        Err(_) => {
            error!("Send timeout");
            return Err(ProtocolError::Timeout);
        }
    }
    
    // Receive reply with timeout
    let reply = match timeout(Duration::from_secs(3), conn.secure_recv()).await {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => {
            error!(error = ?e, "Failed to receive reply");
            return Err(e);
        }
        Err(_) => {
            error!("Receive timeout");
            return Err(ProtocolError::Timeout);
        }
    };
    
    info!(reply = ?reply, "Received reply");
    
    // Close connection gracefully
    conn.close().await?
    
    Ok(())
}
```

### TLS Client
```rust
use network_protocol::service::client::{self, TlsClientConfig};
use network_protocol::protocol::message::Message;
use network_protocol::error::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure TLS client
    let tls_config = TlsClientConfig {
        cert_path: Some("client_cert.pem"), // For mTLS
        key_path: Some("client_key.pem"),  // For mTLS
        ca_path: Some("ca_cert.pem"),      // Server verification
        server_name: "example.com",         // SNI
    };
    
    // Connect with TLS
    let mut conn = client::connect_tls(
        "127.0.0.1:9443", 
        tls_config
    ).await?;
    
    info!("Connected securely to TLS server");
    
    // Communicate securely
    conn.send(Message::Echo("secure message".into())).await?;
    let reply = conn.receive().await?;
    
    info!(response = ?reply, "Received secure response");
    
    // Close connection properly
    conn.close().await?
}
```

<br>

### Message Types
Built-in messages include:
- `HandshakeInit` / `HandshakeAck`
- `Ping` / `Pong`
- `Echo(String)`
- `Unknown`

You can extend this list with your own enums or handlers.

<br>

## Benchmarks

Run microbenchmarks (Criterion):

```bash
cargo bench
```

Highlights:
- Packet encode: up to ~1.9 GiB/s, decode up to ~24.5 GiB/s
- LZ4: compress ~1.0 GiB/s, decompress ~18–19 GiB/s @ 1 MiB
- Zstd (level 1): compress ~1.0 GiB/s, decompress ~0.4 GiB/s @ 1 MiB
- Compression threshold: default 512 bytes (configurable) to skip compression on tiny payloads

See detailed results and recommendations in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Testing

Full test suite:
```bash
cargo test --all --all-features
```

Fuzz smoke tests (nightly):
```bash
rustup install nightly
cargo install cargo-fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=30
cargo +nightly fuzz run fuzz_handshake -- -max_total_time=30
cargo +nightly fuzz run fuzz_compression -- -max_total_time=30
```

Stress tests:
```bash
cargo test --test stress -- --nocapture
cargo test --test concurrency -- --nocapture
```

Production build profile (already configured): LTO, codegen-units=1, opt-level=3, stripped symbols. Run with `cargo build --release`.


### Custom Message Handlers
Register your own handlers with the dispatcher to process different message types:

```rust
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::error::Result;
use std::sync::Arc;
use tracing::info;

// Create a dispatcher (typically shared between connections)
let dispatcher = Arc::new(Dispatcher::default());

// Basic handlers for built-in message types
dispatcher.register("PING", |_| {
    info!("Ping received, sending pong");
    Ok(Message::Pong)
});

dispatcher.register("ECHO", |msg| {
    info!(content = ?msg, "Echo request received");
    Ok(msg.clone())
});

// Custom message type handler with complex processing
dispatcher.register("DATA_PROCESS", |msg| {
    if let Message::Custom(data) = msg {
        // Process custom data
        info!(bytes = data.len(), "Processing custom data");
        
        // Return a response based on processing outcome
        if data.len() > 100 {
            Ok(Message::Custom(vec![1, 0, 1])) // Success code
        } else {
            Ok(Message::Custom(vec![0, 0, 1])) // Error code
        }
    } else {
        // Handle unexpected message type
        info!("Received incorrect message type for DATA_PROCESS");
        Ok(Message::Unknown)
    }
});
```

The dispatcher automatically routes incoming messages based on their `message_type()`. You can register handlers for both built-in message types and your own custom message types.

<br>

### Running Tests
```bash
cargo test
```

Runs full unit + integration tests.

### Benchmarking

```bash
# Run all benchmarks with output
cargo test --test perf -- --nocapture

# Run specific benchmark
cargo test --test perf benchmark_roundtrip_latency -- --nocapture
cargo test --test perf benchmark_throughput -- --nocapture
```

#### Performance Metrics

| Metric | Result | Environment |
|--------|--------|-------------|
| Roundtrip Latency | <1ms avg | Local transport |
| Throughput | ~5,000 msg/sec | Standard payload |
| TLS Overhead | +2-5ms | With certificate validation |

The library includes comprehensive benchmarking tools that measure:
- Message roundtrip latency (client → server → client)
- Maximum throughput under various conditions
- Backpressure effectiveness during high load
- Connection recovery after network failures

For detailed benchmarking documentation, see the [API Reference](./docs/API.md#benchmarking).

<br>

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design, data flow, component details
- **[THREAT_MODEL.md](THREAT_MODEL.md)** - Security analysis, attack scenarios, mitigations
- **[SECURITY.md](SECURITY.md)** - Vulnerability disclosure policy
- **[API Reference](./docs/API.md)** - Detailed API documentation
- **[Performance Guide](./docs/PERFORMANCE.md)** - Optimization strategies and benchmarks

<br>

### Project Structure
```
src/
├── config.rs    # Configuration structures and loading
├── core/        # Codec, packet structure  
├── protocol/    # Handshake, heartbeat, message types
├── transport/   # TCP, Unix socket, TLS, Cluster
├── service/     # Daemon + client APIs
├── utils/       # Compression, crypto, timers
benches/         # Criterion benchmarks
fuzz/            # Fuzzing targets (cargo-fuzz)
tests/           # Integration and stress tests
```

<br>

## Contributing

Contributions welcome! Please:
1. Run `cargo fmt && cargo clippy --workspace -- -D warnings` before committing
2. Add tests for new features
3. Update documentation as needed
4. Follow existing code style and patterns

For security issues, see [SECURITY.md](SECURITY.md).

<br>

[Documentation](./docs/README.md) | 
[API Reference](./docs/API.md) | 
[Performance](./docs/PERFORMANCE.md) | 
[Principles](./docs/PRINCIPLES.md)


<hr><br>

<!--
:: CONTRIBUTORS
=========================== -->
<div id="contributors">
    <h2>❤️ Contributors</h2>
    <h3><sup>Pending</sup></h3>
    <br>
</div>



<!--
:: LICENSE
=========================== -->
<div id="license">
    <hr><br>
    <h2>⚖️ License</h2>
    <p>Licensed under the <b>Apache License</b>, version 2.0 (the <b>"License"</b>); you may not use this software, including, but not limited to the source code, media files, ideas, techniques, or any other associated property or concept belonging to, associated with, or otherwise packaged with this software except in compliance with the <b>License</b>.</p>
    <p>You may obtain a copy of the <b>License</b> at: <a href="http://www.apache.org/licenses/LICENSE-2.0" title="Apache-2.0 License" target="_blank">http://www.apache.org/licenses/LICENSE-2.0</a>.</p>
    <p>Unless required by applicable law or agreed to in writing, software distributed under the <b>License</b> is distributed on an "<b>AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND</b>, either express or implied.</p>
    <p>See the <a href="./LICENSE" title="Software License file">LICENSE</a> file included with this project for the specific language governing permissions and limitations under the <b>License</b>.</p>
    <br>
</div>


<!--
:: COPYRIGHT
=========================== -->
<div align="center">

  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2025 <strong>JAMES GOBER.</strong></sup>
</div>