<div align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
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
    A <strong>battle-hardened, security-first</strong> network protocol implementation for Rust. Built for production systems requiring both high performance and strong security guarantees. Features comprehensive DoS protection, memory safety guarantees, and extensive testing infrastructure (214+ tests, fuzzing, stress tests).
</p>
<p>
    Designed for <strong>zero-compromise reliability</strong> in high-load environments with built-in backpressure control, automatic connection health monitoring, and graceful degradation. The fastest, most efficient version yet with v1.2.1 delivering measurable performance gains through connection pooling, request multiplexing, adaptive compression, and zero-allocation optimizations.
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
 - **Zeroize Audit**: Explicit memory clearing for session keys and shared secrets

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
- Client-side timeouts for connecting, sending and waiting for a response
- Connection pooling with health checks, LRU reuse, and circuit breaker
- Request multiplexing with ID-tagged routing and timeout cleanup
- **Optimized Release Builds**: LTO + single codegen unit for maximum performance

### Testing & Quality
- **214+ Test Suite**: Unit, integration, edge cases, stress tests, doc tests
- **Fuzzing Infrastructure**: 3 targets (packet, handshake, compression) with CI smoke tests
- **Benchmarking**: Criterion-based micro-benchmarks for packet encode/decode, compression, messages
- **CI Pipeline**: Format, clippy, cross-platform builds (Linux/macOS/Windows), security audits

### Core Architecture
- Custom binary packet format with optional compression (`LZ4`, `Zstd`)
- Plugin-friendly dispatcher for message routing with zero-copy serialization
- Graceful shutdown support for all server implementations with configurable timeouts
- Modular transport: `TCP`, `Unix socket`, `TLS`, `cluster sync`
- Comprehensive configuration system with `TOML` files and environment variable overrides
- Configuration validation with detailed error reporting
- Structured logging with flexible log level control via configuration

### Compatibility
- Cross-platform support for local transport (**Windows**, **Linux**, **macOS**)
- Windows-compatible alternative for Unix Domain Sockets
- Ready for *microservices*, *databases*, *daemons*, and *system protocols*

<hr>

<p>
    <b>REPS</b> (<i>Rust Efficiency &amp; Performance Standards</i>)
    <br>⚡ <a href="https://github.com/jamesgober/rust-collection"><strong>Rust Collection</strong></a>
</p>

<br>


## Installation
Add the library to your `Cargo.toml`:
```toml
[dependencies]
network-protocol = "1.3"
```

<br>

## Quick Start

### TCP Server with Backpressure and Structured Logging
```rust
use network_protocol::config::ServerConfig;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::service::daemon;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    network_protocol::init();

    // Create a dispatcher. The server uses only the handlers registered here.
    let dispatcher = Arc::new(Dispatcher::new());

    // Register message handlers
    dispatcher.register("PING", |_| Ok(Message::Pong))?;
    dispatcher.register("ECHO", |msg| {
        info!(message_type = "ECHO", "Processing echo request");
        Ok(msg.clone())
    })?;

    // Option 1: Load configuration from file
    // let config = network_protocol::config::NetworkConfig::from_file("config.toml")?.server;

    // Option 2: Load configuration from environment variables
    // let config = network_protocol::config::NetworkConfig::from_env()?.server;

    // Option 3: Configure server with custom settings
    let config = ServerConfig {
        address: "127.0.0.1:9000".to_string(),
        backpressure_limit: 100,                     // Messages queued per connection before reads pause
        connection_timeout: Duration::from_secs(10), // Limit for each handshake step
        heartbeat_interval: Duration::from_secs(15),
        shutdown_timeout: Duration::from_secs(10),   // How long shutdown waits for open connections
        max_connections: 1000,                       // Connections over this are closed on accept
    };

    // Start the server in a background task and keep a handle to it
    let mut server = daemon::start_daemon_no_signals(config, dispatcher).await?;
    info!(address = %server.address, "Server started");

    // Stop on Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Initiating graceful shutdown...");
    // Signals the server task. It waits up to shutdown_timeout for open
    // connections, but only while the runtime is still running.
    server.shutdown().await?;

    Ok(())
}
```

`start_daemon_no_signals()` does not install a Ctrl+C handler, so the example waits for Ctrl+C itself. If the built-in `PING` and `ECHO` handlers are all you need, `daemon::start_with_config(config).await?` runs the server in the current task until Ctrl+C.

`daemon::new_with_config()`, `Daemon::run()` and `Daemon::shutdown_with_timeout()` are deprecated in 1.3.0: the first never started a server, `run()` returns at once, and the timeout argument was ignored. Use `start_daemon_no_signals()` and `Daemon::shutdown()`, and set the wait with `ServerConfig::shutdown_timeout`.

### TLS Server
```rust
use network_protocol::service::tls_daemon;
use network_protocol::transport::tls::TlsServerConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    network_protocol::init();

    // PEM certificate chain and PKCS#8 private key
    let config = TlsServerConfig::new("server_cert.pem", "server_key.pem")
        // mTLS: require a client certificate signed by this CA
        .with_client_auth("client_ca.pem");

    // Serves PING and ECHO until Ctrl+C
    tls_daemon::start("127.0.0.1:9443", config).await?;
    Ok(())
}
```

To accept clients with or without a certificate, add `.require_client_auth(false)` after `with_client_auth(..)`. A certificate that is presented must still be signed by the client CA. Calling `require_client_auth(true)` without `with_client_auth(..)` is a configuration error from 1.3.0, because there is no CA to check certificates against. Clients have 10 seconds to finish the TLS handshake.

Use `tls_daemon::start_with_shutdown(addr, config, shutdown_rx)` with a `tokio::sync::mpsc::Receiver<()>` to stop the server from your own code: it shuts down when `()` is sent.

### Client with Timeout Handling
```rust
use network_protocol::config::ClientConfig;
use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    network_protocol::init();

    // Option 1: Load configuration from file
    // let config = network_protocol::config::NetworkConfig::from_file("config.toml")?.client;

    // Option 2: Load from environment variables
    // let config = network_protocol::config::NetworkConfig::from_env()?.client;

    // Option 3: Configure client with custom settings
    let config = ClientConfig {
        address: "127.0.0.1:9000".to_string(),
        connection_timeout: Duration::from_secs(5), // Connect and each handshake step
        operation_timeout: Duration::from_secs(3),  // Each Client::send
        response_timeout: Duration::from_secs(30),  // Client::send_and_wait
        heartbeat_interval: Duration::from_secs(15),
        ..Default::default()
    };

    // Fails with ProtocolError::Timeout if the connection or handshake takes too long
    info!("Connecting to server...");
    let mut client = Client::connect_with_config(config).await?;
    info!("Connected successfully");

    // Send a message, then wait for the reply
    client.send(Message::Echo("hello".into())).await?;
    let reply = client.recv().await?;
    info!(reply = ?reply, "Received reply");

    // Or do both in one call, bounded by response_timeout
    let reply = client.send_and_wait(Message::Echo("hello again".into())).await?;
    info!(reply = ?reply, "Received reply");

    // Tell the server we are done; dropping the client closes the connection
    client.send(Message::Disconnect).await?;

    Ok(())
}
```

`Client` does not reconnect on its own. `ClientConfig::auto_reconnect`, `max_reconnect_attempts` and `reconnect_delay` are deprecated in 1.3.0 because they never had any effect; to reconnect, call `Client::connect_with_config()` again.

### TLS Client
```rust
use network_protocol::protocol::message::Message;
use network_protocol::service::tls_client::TlsClient;
use network_protocol::transport::tls::TlsClientConfig;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The server name is sent as SNI and checked against the server certificate
    let config = TlsClientConfig::new("example.com")
        // Trust this CA instead of the system roots (for a private CA)
        .with_root_ca("ca_cert.pem")
        // mTLS: present a client certificate
        .with_client_certificate("client_cert.pem", "client_key.pem");

    // Connect with TLS
    let mut client = TlsClient::connect("127.0.0.1:9443", config).await?;

    info!("Connected securely to TLS server");

    // Communicate securely
    let reply = client.request(Message::Echo("secure message".into())).await?;

    info!(response = ?reply, "Received secure response");

    // Dropping the client closes the connection
    Ok(())
}
```

Without `with_root_ca(..)` the client trusts the system root store. `TlsClient` also has `send()` and `receive()` for one-way messages, and `TlsClient::connect_with_session(addr, config, Some(cache))` resumes TLS sessions across connections that share the same `Arc<SessionCache>`.

### Certificate Pinning
A pin is the SHA-256 fingerprint of the server's DER certificate, as 32 raw bytes (not hex). This example reads the certificate with `rustls::pki_types`, so it needs `rustls = "0.23"` in your own `Cargo.toml`:

```rust
use network_protocol::service::tls_client::TlsClient;
use network_protocol::transport::tls::{TlsClientConfig, TlsServerConfig};
use rustls::pki_types::{pem::PemObject, CertificateDer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_cert = CertificateDer::from_pem_file("server_cert.pem")?;
    let pin = TlsServerConfig::calculate_cert_hash(&server_cert);

    let config = TlsClientConfig::new("example.com")
        .with_root_ca("ca_cert.pem")
        .with_pinned_cert_hash(pin);

    let _client = TlsClient::connect("127.0.0.1:9443", config).await?;
    Ok(())
}
```

From 1.3.0 the pin is checked on top of normal validation: the server certificate must chain to a trusted CA, match the server name, and have the pinned fingerprint. With `insecure()` the pin replaces CA validation instead, which is meant for development servers with a self-signed certificate. A pin that is not 32 bytes long makes `load_client_config()` (and so `connect`) return a `TlsError`.

<br>

### Message Types
Built-in messages include:
- `SecureHandshakeInit` / `SecureHandshakeResponse` / `SecureHandshakeConfirm`
- `Ping` / `Pong`
- `Echo(String)`
- `Custom { command, payload }`
- `Disconnect`
- `Unknown`

Use `Message::Custom` with your own `command` names for application messages, and register a handler for each name.

<br>

## Benchmarks

Run microbenchmarks (Criterion):

```bash
cargo bench
```

**Performance Highlights (v1.2.1 baseline):**
- **Packet encode:** 1.64 GiB/s @ 1MB
- **Packet decode:** 4.90 GiB/s @ 1MB
- **LZ4 compress:** 8.33 GiB/s @ 1MB
- **LZ4 decompress:** 4.67 GiB/s @ 1MB
- **Zstd compress:** 3.05 GiB/s @ 1MB
- **Zstd decompress:** 4.44 GiB/s @ 1MB
- **Adaptive compression:** 10-15% CPU savings on mixed workloads
- **Buffer pooling:** 3-5% latency reduction under high load
- **Pooling + multiplexing:** lower connection churn and improved throughput under concurrency

Benchmarks collected on Windows (MSVC) with `cargo bench`.

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

fn build_dispatcher() -> Result<Arc<Dispatcher>> {
    // Create a dispatcher (typically shared between connections)
    let dispatcher = Arc::new(Dispatcher::default());

    // Basic handlers for built-in message types
    dispatcher.register("PING", |_| {
        info!("Ping received, sending pong");
        Ok(Message::Pong)
    })?;

    dispatcher.register("ECHO", |msg| {
        info!(content = ?msg, "Echo request received");
        Ok(msg.clone())
    })?;

    // Handler for Message::Custom { command: "DATA_PROCESS", .. }
    dispatcher.register("DATA_PROCESS", |msg| {
        if let Message::Custom { payload, .. } = msg {
            // Process custom data
            info!(bytes = payload.len(), "Processing custom data");

            // Return a response based on processing outcome
            let code = if payload.len() > 100 { vec![1, 0, 1] } else { vec![0, 0, 1] };
            Ok(Message::Custom {
                command: "DATA_PROCESS_RESULT".to_string(),
                payload: code,
            })
        } else {
            // Handle unexpected message type
            info!("Received incorrect message type for DATA_PROCESS");
            Ok(Message::Unknown)
        }
    })?;

    Ok(dispatcher)
}
```

The dispatcher routes each message by its opcode: `PING`, `PONG`, `ECHO` and `DISCONNECT` for the built-in variants, and the `command` string for `Message::Custom`. A message with no registered handler fails with `ProtocolError::UnexpectedMessage`. Pass the dispatcher to `daemon::start_daemon_no_signals()`; the TLS daemon uses its own fixed `PING` and `ECHO` handlers.

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