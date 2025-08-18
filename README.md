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
    A secure, high-performance network protocol core for Rust applications and services with advanced features including backpressure control, structured logging, timeout handling, and TLS support. The library provides a comprehensive benchmarking framework for performance analysis and optimization, making it suitable for critical infrastructure and high-throughput systems.
</p>
<p>
    This protocol is designed for reliability in high-load environments with built-in protection against slow clients and network failures. It supports multiple transport modes (local, remote, TLS, cluster) with consistent APIs and graceful shutdown capabilities across all implementations. The architecture emphasizes both security and performance, with zero-copy optimizations where beneficial and efficient memory usage patterns throughout.
</p>
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
<p align="center">
    &mdash; Part of the <a href="https://github.com/jamesgober/rust-performance-library"><strong>Rust Performance Library</strong></a> collection. &mdash;
</p>
<hr>
<br>



## Installation
Add the library to your `Cargo.toml`:
```toml
[dependencies]
network-protocol = "0.9.9"
```

<br>

## Example Usage

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

### Project Structure
```
src/
├── config.rs    # Configuration structures and loading
├── core/        # Codec, packet structure
├── protocol/    # Handshake, heartbeat, message types
├── transport/   # TCP, Unix socket, Cluster (WIP)
├── service/     # Daemon + client APIs
├── utils/       # Compression, crypto, timers
```


[Docs](./docs/README.md) | 
[Benchmarks](./docs/BENCHMARKS.md) | 
[API Reference](./docs/API.md)

