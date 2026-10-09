<div align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <h1>
        <strong>network-protocol</strong>
        <sup>
            <br>
            <sub>API REFERENCE</sub>
            <br>
        </sup>
    </h1>
</div>


[Home](../README.md) | 
[Documentation](./README.md)

<br>

## Table of Contents

- [Getting Started](#getting-started)
  - [Configuration](#configuration-guide)
  - [Server Setup](#server-setup)
  - [Client Setup](#client-setup)
  - [Transport Options](#transport-options)
  - [TLS Security](#tls-security)
  - [Using Dispatchers](#using-dispatchers)
- [Installation](#installation)
- [Core Modules](#core-modules)
  - [Packet](#packet)
  - [PacketCodec](#packetcodec)
- [Transport](#transport)
- [Benchmarking](#benchmarking)
  - [Running Benchmarks](#running-benchmarks)
  - [Performance Metrics](#performance-metrics)
  - [Interpreting Results](#interpreting-results)
  - [Custom Benchmark Configuration](#custom-benchmark-configuration)
  - [Remote Transport](#remote-transport)
  - [Local Transport](#local-transport)
  - [TLS Transport](#tls-transport)
  - [Cluster Transport](#cluster-transport)
- [Protocol](#protocol)
  - [Message](#message)
  - [Handshake](#handshake)
  - [Dispatcher](#dispatcher)
  - [Heartbeat](#heartbeat)
- [Service](#service)
  - [Client](#client)
  - [Daemon](#daemon)
  - [TLS Daemon](#tls-daemon)
  - [TLS Client](#tls-client)
  - [Secure Connection](#secure-connection)
    - [Connection Pooling](#connection-pooling)
    - [Multiplexing](#multiplexing)
  - [Configuration](#service-configuration)
- [Utilities](#utilities)
  - [Cryptography](#cryptography)
  - [Compression](#compression)
  - [Time](#time)
- [Error Handling](#error-handling)
- [Configuration](#configuration)
- [Logging](#logging)

## Getting Started

This guide will help you quickly get started with the `network-protocol` library, focusing on configuration, setup, and common usage patterns.

### Configuration Guide

The library uses a comprehensive configuration system that supports both TOML files and environment variables. Configuration options are organized into sections for server, client, transport, and logging.

#### Using TOML Configuration

Create a `config.toml` file in your project with your desired settings:

```toml
# Server-specific configuration
[server]
address = "127.0.0.1:9000"
backpressure_limit = 32      # messages queued per connection
connection_timeout = 5000    # milliseconds, per handshake step
heartbeat_interval = 15000   # milliseconds
shutdown_timeout = 10000     # milliseconds
max_connections = 1000

# Client-specific configuration
[client]
address = "127.0.0.1:9000"
connection_timeout = 5000    # milliseconds
operation_timeout = 3000     # milliseconds, per send
response_timeout = 30000     # milliseconds
heartbeat_interval = 15000   # milliseconds

# Logging configuration
[logging]
app_name = "my-application"
log_level = "info"           # options: trace, debug, info, warn, error
log_to_console = true
log_to_file = false
json_format = false
```

Each table is optional and falls back to its defaults when left out, but a table that is present must list all of its fields, except the deprecated ones. The deprecated `[client]` reconnect settings and every `[transport]` field have no effect from 1.3.0 and can be left out; they are still accepted if present, so older files keep loading.

Load the configuration in your code:

```rust
use network_protocol::config::NetworkConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load from a specific file path
    let config = NetworkConfig::from_file("path/to/config.toml")?;

    // Or start from the defaults and apply environment variables
    // let config = NetworkConfig::from_env()?;

    // Check the values before using them
    config.validate_strict()?;

    // Access configuration values
    let server_addr = config.server.address.clone();
    println!("Server will bind to: {}", server_addr);
    Ok(())
}
```

#### Using Environment Variables

`NetworkConfig::from_env()` starts from the defaults (it does not read a TOML file) and applies these variables when they are set:

```bash
# Server listen address
export NETWORK_PROTOCOL_SERVER_ADDRESS="0.0.0.0:8080"

# Server backpressure_limit
export NETWORK_PROTOCOL_BACKPRESSURE_LIMIT="64"

# connection_timeout for both server and client, in milliseconds
export NETWORK_PROTOCOL_CONNECTION_TIMEOUT_MS="10000"

# Server heartbeat_interval, in milliseconds
export NETWORK_PROTOCOL_HEARTBEAT_INTERVAL_MS="15000"
```

No other variables are read. Values that do not parse as numbers are ignored.

### Server Setup

Start a server with the default configuration. It answers `PING` and `ECHO` and runs until Ctrl+C:

```rust
use network_protocol::service::daemon;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    daemon::start("127.0.0.1:9000").await?;
    Ok(())
}
```

With custom configuration and your own message handlers:

```rust
use network_protocol::config::NetworkConfig;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::service::daemon;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = NetworkConfig::from_env()?;

    // Create a dispatcher for handling messages. The server uses only these handlers.
    let dispatcher = Arc::new(Dispatcher::new());
    dispatcher.register("PING", |_| Ok(Message::Pong))?;
    dispatcher.register("ECHO", |msg| match msg {
        Message::Echo(s) => Ok(Message::Echo(s.clone())),
        _ => Ok(Message::Unknown),
    })?;

    // Start the server in a background task
    let mut server = daemon::start_daemon_no_signals(config.server, dispatcher).await?;

    // Stop it on Ctrl+C
    tokio::signal::ctrl_c().await?;
    server.shutdown().await?;
    Ok(())
}
```

### Client Setup

Create a client and communicate with a server:

```rust
use network_protocol::service::client::Client;
use network_protocol::protocol::message::Message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to server with default configuration
    let mut client = Client::connect("127.0.0.1:9000").await?;

    // Send a ping message and read the reply
    client.send(Message::Ping).await?;
    let response = client.recv().await?;

    // Check the response
    match response {
        Message::Pong => println!("Server responded with pong"),
        _ => println!("Unexpected response: {:?}", response),
    }

    // Send an echo message and wait for the reply (up to response_timeout)
    let response = client
        .send_and_wait(Message::Echo("Hello, server!".to_string()))
        .await?;
    println!("Echo response: {:?}", response);

    // Disconnect gracefully
    client.send(Message::Disconnect).await?;
    Ok(())
}
```

### Transport Options

The library supports multiple transport methods:

#### TCP Transport

```rust
use network_protocol::transport::remote;

// Server
async fn start_tcp_server() -> Result<()> {
    remote::start_server("127.0.0.1:8080").await
}

// Client
async fn connect_to_tcp_server() -> Result<()> {
    let framed = remote::connect("127.0.0.1:8080").await?;
    // Use framed for sending/receiving packets
}
```

#### Unix Domain Socket Transport

```rust
use network_protocol::transport::local;

// Server
async fn start_uds_server() -> Result<()> {
    local::start_server("/tmp/network_protocol.sock").await
}

// Client
async fn connect_to_uds_server() -> Result<()> {
    let framed = local::connect("/tmp/network_protocol.sock").await?;
    // Use framed for sending/receiving packets
}
```

### TLS Security

Secure your connections with TLS. Both sides are configured with builders in `transport::tls`:

```rust
use network_protocol::protocol::message::Message;
use network_protocol::service::{tls_client::TlsClient, tls_daemon};
use network_protocol::transport::tls::{TlsClientConfig, TlsServerConfig};

// TLS Server
async fn start_tls_server() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsServerConfig::new("certs/server.crt", "certs/server.key")
        .with_client_auth("certs/client-ca.crt"); // Require client certificates (mTLS)

    // Serves PING and ECHO until Ctrl+C
    tls_daemon::start("127.0.0.1:8443", config).await?;
    Ok(())
}

// TLS Client
async fn connect_to_tls_server() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsClientConfig::new("example.com") // SNI and hostname check
        .with_root_ca("certs/ca.crt") // Validate the server against this CA, not the system roots
        .with_client_certificate("certs/client.crt", "certs/client.key"); // For mTLS

    let mut client = TlsClient::connect("127.0.0.1:8443", config).await?;
    let reply = client.request(Message::Ping).await?;
    println!("Reply: {:?}", reply);
    Ok(())
}
```

See [TLS Transport](#tls-transport) for every option, including certificate pinning, optional client authentication and protocol version limits.

### Using Dispatchers

Dispatchers provide a flexible way to handle different message types:

```rust
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use std::sync::Arc;

// Create a shared dispatcher
let dispatcher = Arc::new(Dispatcher::new());

// Register a simple ping handler
dispatcher.register("PING", |_| Ok(Message::Pong))?;

// Register a more complex handler for custom messages
dispatcher.register("CUSTOM", |msg| {
    match msg {
        Message::Custom { command, payload } => {
            // Process the payload
            let result = process_payload(payload)?;
            
            // Return a response with the result
            Ok(Message::Custom { 
                command: "RESULT".to_string(),
                payload: result,
            })
        },
        _ => Err(ProtocolError::UnexpectedMessage),
    }
})?;

// Dispatch a message
let response = dispatcher.dispatch(&Message::Ping)?;
```

## Installation

### Install Manually
```toml
[dependencies]
network-protocol = "1.3"
```

### Install Using Cargo
```bash
cargo install network-protocol
```

## Core Modules

The core modules provide the fundamental structures and functionality for packet handling and serialization/deserialization.

### Packet

The `Packet` struct represents a fully decoded protocol packet, including the protocol version and binary payload.

#### Constants

```rust
pub const HEADER_SIZE: usize = 9; // 4 magic + 1 version + 4 length
```

#### Struct Definition

```rust
pub struct Packet {
    pub version: u8,
    pub payload: Vec<u8>,
}
```

#### Methods

##### `from_bytes`

Parses a packet from a raw buffer containing a header and body.

```rust
pub fn from_bytes(buf: &[u8]) -> Result<Self>
```

**Parameters:**
- `buf`: A byte slice containing the raw packet data

**Returns:**
- `Result<Packet>`: A result containing either the parsed packet or an error

**Errors:**
- `ProtocolError::InvalidHeader`: If the buffer is too short or has invalid magic bytes
- `ProtocolError::UnsupportedVersion`: If the protocol version is not supported
- `ProtocolError::OversizedPacket`: If the packet exceeds the maximum allowed size

**Example:**
```rust
use network_protocol::core::packet::Packet;

let raw_data = vec![0x4E, 0x50, 0x52, 0x4F, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
match Packet::from_bytes(&raw_data) {
    Ok(packet) => println!("Parsed packet with version {} and payload of {} bytes", packet.version, packet.payload.len()),
    Err(e) => eprintln!("Failed to parse packet: {}", e),
}
```

##### `to_bytes`

Serializes a packet to a byte vector containing a header and body.

```rust
pub fn to_bytes(&self) -> Vec<u8>
```

**Returns:**
- `Vec<u8>`: The serialized packet as bytes

**Example:**
```rust
use network_protocol::core::packet::Packet;

let packet = Packet {
    version: 1,
    payload: vec![1, 2, 3, 4, 5],
};

let bytes = packet.to_bytes();
println!("Serialized packet: {:?}", bytes);
```

### PacketCodec

The `PacketCodec` struct implements the Tokio `Decoder` and `Encoder` traits for packet-based communication, enabling integration with Tokio's asynchronous I/O framework.

#### Struct Definition

```rust
pub struct PacketCodec;
```

This struct is a stateless codec that handles framing, encoding, and decoding of protocol packets.

#### Implementations

##### Decoder Implementation

```rust
impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Packet>> {
        // Wait until we have at least a full header
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Extract payload length from header
        let len = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) as usize;
        let total_len = HEADER_SIZE + len;

        // Wait until we have the full packet
        if src.len() < total_len {
            return Ok(None);
        }

        // Split off the complete packet and parse it
        let buf = src.split_to(total_len).freeze();
        Packet::from_bytes(&buf).map(Some)
    }
}
```

**Parameters:**
- `src`: A mutable reference to a `BytesMut` buffer containing incoming data

**Returns:**
- `Result<Option<Packet>>`: A result containing either:
  - `Some(Packet)` if a complete packet was successfully decoded
  - `None` if more data is needed to decode a complete packet
  - `Err(ProtocolError)` if an error occurred during decoding

**Process:**
1. First checks if enough data exists for the header (9 bytes)
2. Extracts the payload length from the header
3. Ensures the buffer contains a complete packet
4. Splits off the complete frame and calls `Packet::from_bytes` to parse it

##### Encoder Implementation

```rust
impl Encoder<Packet> for PacketCodec {
    type Error = ProtocolError;

    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> Result<()> {
        // Calculate total size and reserve space in the buffer
        let total_size = HEADER_SIZE + packet.payload.len();
        dst.reserve(total_size);
        
        // Write header directly to buffer: magic bytes + version + length
        dst.put_slice(&MAGIC_BYTES);
        dst.put_u8(PROTOCOL_VERSION);
        dst.put_u32(packet.payload.len() as u32);
        
        // Write payload directly to buffer
        dst.put_slice(&packet.payload);
        
        Ok(())
    }
}
```

**Parameters:**
- `packet`: The `Packet` to encode
- `dst`: A mutable reference to a `BytesMut` buffer to write the encoded packet to

**Returns:**
- `Result<()>`: A result indicating success or an encoding error

**Process:**
1. Reserves buffer space for the entire packet
2. Writes the magic bytes (4 bytes) directly to the buffer
3. Writes the protocol version (1 byte)
4. Writes the payload length as a 4-byte big-endian integer
5. Writes the payload bytes

**Example:**
```rust
use network_protocol::core::codec::PacketCodec;
use network_protocol::core::packet::Packet;
use tokio_util::codec::{Decoder, Encoder};
use bytes::{BytesMut, BufMut};

// Create a stateless codec
let mut codec = PacketCodec;

// Prepare a buffer for encoding
let mut buffer = BytesMut::new();

// Create a packet to encode
let packet = Packet {
    version: 1,
    payload: vec![1, 2, 3, 4, 5],
};

// Encode the packet into the buffer
codec.encode(packet, &mut buffer).unwrap();
println!("Encoded {} bytes", buffer.len());

// Decode the packet from the buffer
match codec.decode(&mut buffer) {
    Ok(Some(decoded)) => println!(
        "Successfully decoded packet: version={}, payload={:?}", 
        decoded.version, 
        decoded.payload
    ),
    Ok(None) => println!("Need more data to decode a packet"),
    Err(e) => println!("Error decoding packet: {}", e),
}
```

**Integration with Tokio Streams:**

```rust
use network_protocol::core::codec::PacketCodec;
use network_protocol::core::packet::Packet;
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, FramedRead, FramedWrite};
use futures::{SinkExt, StreamExt};

// Connect to a server
let socket = TcpStream::connect("127.0.0.1:8080").await?;

// Create a framed connection using our codec
let mut framed = Framed::new(socket, PacketCodec);

// Send a packet
let packet = Packet {
    version: 1,
    payload: vec![1, 2, 3, 4, 5],
};
framed.send(packet).await?;

// Receive a packet
if let Some(result) = framed.next().await {
    match result {
        Ok(received) => println!("Received packet with payload: {:?}", received.payload),
        Err(e) => println!("Error receiving packet: {}", e),
    }
}
```

## Transport

### Remote Transport

The remote transport module provides functions for TCP-based network communication.

#### Functions

##### `start_server`

Starts a TCP server at the given address.

```rust
pub async fn start_server(addr: &str) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8080")

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::transport::remote;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    remote::start_server("127.0.0.1:8080").await
}
```

##### `connect`

Connects to a remote server and returns a framed transport.

```rust
pub async fn connect(addr: &str) -> Result<Framed<TcpStream, PacketCodec>>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8080")

**Returns:**
- `Result<Framed<TcpStream, PacketCodec>>`: A result containing either the framed connection or an error

**Example:**
```rust
use network_protocol::transport::remote;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let framed = remote::connect("127.0.0.1:8080").await?;
    println!("Connected to server!");
    Ok(())
}
```

### Local Transport

The local transport module provides functions for Unix Domain Socket (UDS) communication.

#### Functions

##### `start_server`

Starts a UDS server at the given socket path.

```rust
pub async fn start_server<P: AsRef<Path>>(path: P) -> Result<()>
```

**Parameters:**
- `path`: The path to the Unix domain socket

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::transport::local;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    local::start_server("/tmp/my_socket").await
}
```

##### `connect`

Connects to a local UDS socket.

```rust
pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Framed<UnixStream, PacketCodec>>
```

**Parameters:**
- `path`: The path to the Unix domain socket

**Returns:**
- `Result<Framed<UnixStream, PacketCodec>>`: A result containing either the framed connection or an error

**Example:**
```rust
use network_protocol::transport::local;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let framed = local::connect("/tmp/my_socket").await?;
    println!("Connected to local socket!");
    Ok(())
}
```

### TLS Transport

The TLS transport module provides functions for secure TLS-based network communication with certificate validation and mutual TLS support. It uses rustls with the `ring` provider. TLS 1.2 and 1.3 are enabled by default.

#### Structs

##### `TlsServerConfig`

A builder for the server side. The fields are private; configure it with these methods:

```rust
impl TlsServerConfig {
    pub fn new<P: AsRef<Path>>(cert_path: P, key_path: P) -> Self
    pub fn with_client_auth<S: Into<String>>(self, client_ca_path: S) -> Self
    pub fn require_client_auth(self, required: bool) -> Self
    pub fn with_tls_versions(self, versions: Vec<TlsVersion>) -> Self
    pub fn with_cipher_suites(self, cipher_suites: Vec<rustls::SupportedCipherSuite>) -> Self
    pub fn with_alpn_protocols(self, protocols: Vec<Vec<u8>>) -> Self
    pub fn generate_self_signed<P: AsRef<Path>>(cert_path: P, key_path: P) -> io::Result<Self>
    pub fn load_server_config(&self) -> Result<rustls::ServerConfig>
    pub fn calculate_cert_hash(cert: &CertificateDer<'_>) -> Vec<u8>
}
```

- `new`: PEM certificate chain and private key. The key must be a PEM `PRIVATE KEY` (PKCS#8) block.
- `with_client_auth`: enables mTLS. Clients must present a certificate signed by a CA in this PEM file.
- `require_client_auth(false)`: call it after `with_client_auth(..)` to make client certificates optional. Clients without a certificate are accepted; a certificate that is presented must still be signed by the client CA. `require_client_auth(true)` without `with_client_auth(..)` has no CA to check against, so `load_server_config()` returns a `TlsError` (since 1.3.0; before that, every client was accepted).
- `with_tls_versions`: only the listed versions are enabled. An empty list is a config error.
- `with_cipher_suites`: only the listed suites are enabled, in the provider's preference order. Suites the `ring` provider does not support are ignored with a warning. If nothing usable is left for the enabled versions, loading fails.
- `with_alpn_protocols`: ALPN protocols to advertise. The default is `h2` and `http/1.1`.
- `generate_self_signed`: writes a self-signed certificate for `localhost` and its key, and returns a config that uses them. For development only. On Unix the key file is created with mode 0600.
- `load_server_config`: builds the rustls config. Returns `ProtocolError::TlsError` if a file cannot be read or parsed, if the version or cipher suite settings leave nothing usable, or if client authentication is required without a client CA.
- `calculate_cert_hash`: the SHA-256 fingerprint of a DER certificate, as 32 raw bytes. Use it with `TlsClientConfig::with_pinned_cert_hash`.

##### `TlsClientConfig`

A builder for the client side:

```rust
impl TlsClientConfig {
    pub fn new<S: Into<String>>(server_name: S) -> Self
    pub fn with_root_ca<S: Into<String>>(self, ca_path: S) -> Self
    pub fn with_client_certificate<S: Into<String>>(self, cert_path: S, key_path: S) -> Self
    pub fn with_pinned_cert_hash(self, hash: Vec<u8>) -> Self
    pub fn insecure(self) -> Self
    pub fn with_tls_versions(self, versions: Vec<TlsVersion>) -> Self
    pub fn with_cipher_suites(self, cipher_suites: Vec<rustls::SupportedCipherSuite>) -> Self
    pub fn load_client_config(&self) -> Result<rustls::ClientConfig>
    pub fn server_name(&self) -> Result<ServerName<'_>>
    pub fn server_name_string(&self) -> String
}
```

- `new`: the server name is sent as SNI and the server certificate must match it. By default the certificate is validated against the system root store.
- `with_root_ca` (new in 1.3.0): trust only the CA certificates in this PEM file instead of the system roots. Use it for servers with a private CA. Chain and hostname validation still apply. Combining it with `insecure()` is a config error.
- `with_client_certificate`: client certificate and PKCS#8 key for mTLS.
- `with_pinned_cert_hash`: only accept a server whose certificate has this SHA-256 fingerprint (32 raw bytes from `TlsServerConfig::calculate_cert_hash`, not hex). Without `insecure()` the pin is checked on top of CA and hostname validation (since 1.3.0; before that, the pin was ignored unless `insecure()` was set). With `insecure()` it replaces CA validation. In both cases the server must prove it holds the certificate's private key. A pin that is not 32 bytes long makes `load_client_config()` return a `TlsError`.
- `insecure`: skips CA and hostname validation. Any certificate is accepted unless one is pinned. Only for development and testing; for a private CA, use `with_root_ca` instead.
- `with_tls_versions` / `with_cipher_suites`: same rules as on the server.
- `load_client_config`: builds the rustls config. Returns `ProtocolError::TlsError` for a pin that is not 32 bytes, for `with_root_ca` combined with `insecure()`, for files that cannot be read or parsed, for version or cipher suite settings that leave nothing usable, and when the system root store is empty (the error suggests `with_root_ca`).

##### `TlsVersion`

```rust
pub enum TlsVersion {
    TLS12,
    TLS13,
    All, // TLS 1.2 and 1.3
}
```

Cipher suites are rustls values, for example `rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384`. To name them, add `rustls = "0.23"` to your own `Cargo.toml`.

#### Functions

##### `start_server`

Starts a TLS server at the given address. It echoes every packet back to the sender, which makes it useful for testing; for a server that dispatches `Message`s, use [`service::tls_daemon`](#tls-daemon). Each client must finish the TLS handshake within 10 seconds.

```rust
pub async fn start_server(addr: &str, config: TlsServerConfig) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8443")
- `config`: The TLS configuration for the server

**Returns:**
- `Result<()>`: Runs until binding or accepting fails. Configuration errors from `load_server_config()` are returned before binding.

**Example:**
```rust
use network_protocol::transport::tls::{self, TlsServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsServerConfig::new("server.crt", "server.key")
        .with_client_auth("client-ca.crt") // Require client certificates (mTLS)
        .require_client_auth(false);       // ...or make them optional

    tls::start_server("127.0.0.1:8443", config).await?;
    Ok(())
}
```

##### `connect`

Connects to a TLS server and returns a framed transport. The handshake must finish within 10 seconds, otherwise it fails with `ProtocolError::Timeout`.

```rust
pub async fn connect(
    addr: &str,
    config: TlsClientConfig,
) -> Result<Framed<tokio_rustls::client::TlsStream<TcpStream>, PacketCodec>>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8443")
- `config`: The TLS client configuration

**Returns:**
- A result containing either the framed connection or an error

**Example:**
```rust
use network_protocol::transport::tls::{self, TlsClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsClientConfig::new("example.com") // Server Name Indication
        .with_root_ca("ca.crt")                      // For server cert validation
        .with_client_certificate("client.crt", "client.key"); // For mTLS

    let _framed = tls::connect("127.0.0.1:8443", config).await?;
    println!("Connected to TLS server!");
    Ok(())
}
```

**Certificate pinning example:**

Reading the certificate uses `rustls::pki_types`, so this needs `rustls = "0.23"` in your own `Cargo.toml`.

```rust
use network_protocol::transport::tls::{self, TlsClientConfig, TlsServerConfig};
use rustls::pki_types::{pem::PemObject, CertificateDer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_cert = CertificateDer::from_pem_file("server.crt")?;
    let pin = TlsServerConfig::calculate_cert_hash(&server_cert); // 32 raw bytes

    let config = TlsClientConfig::new("example.com")
        .with_root_ca("ca.crt")      // The chain and hostname are still validated
        .with_pinned_cert_hash(pin); // ...and the fingerprint must match too

    let _framed = tls::connect("127.0.0.1:8443", config).await?;
    Ok(())
}
```

##### `TlsServerConfig::generate_self_signed`

Generates a self-signed certificate and private key for `localhost`, for development purposes.

```rust
pub fn generate_self_signed<P: AsRef<Path>>(cert_path: P, key_path: P) -> io::Result<TlsServerConfig>
```

**Parameters:**
- `cert_path`: The path to save the certificate to
- `key_path`: The path to save the private key to (mode 0600 on Unix)

**Returns:**
- `io::Result<TlsServerConfig>`: A server config that uses the new files

**Example:**
```rust
use network_protocol::transport::tls::{self, TlsClientConfig, TlsServerConfig};
use rustls::pki_types::{pem::PemObject, CertificateDer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a self-signed certificate for development
    let server_config = TlsServerConfig::generate_self_signed("dev_cert.pem", "dev_key.pem")?;
    tokio::spawn(tls::start_server("127.0.0.1:8443", server_config));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await; // Let the server bind

    // No CA signed this certificate, so pin it and skip CA validation
    let pin = TlsServerConfig::calculate_cert_hash(&CertificateDer::from_pem_file("dev_cert.pem")?);
    let client_config = TlsClientConfig::new("localhost")
        .insecure()
        .with_pinned_cert_hash(pin);
    let _framed = tls::connect("127.0.0.1:8443", client_config).await?;
    Ok(())
}
```

### Cluster Transport

The cluster module provides functionality for managing a cluster of network nodes.

#### Structs

##### `ClusterNode`

```rust
pub struct ClusterNode {
    pub id: String,
    pub addr: String,
    pub last_seen: Option<Instant>,
}
```

##### `Cluster`

```rust
pub struct Cluster {
    peers: HashMap<String, ClusterNode>,
}
```

#### Methods

##### `Cluster::new`

Creates a new cluster with the given peers.

```rust
pub fn new(peers: Vec<(String, String)>) -> Self
```

**Parameters:**
- `peers`: A vector of (id, address) tuples representing the cluster peers

**Returns:**
- `Cluster`: A new cluster instance

##### `Cluster::start_heartbeat`

Starts the heartbeat process to monitor cluster nodes.

```rust
pub async fn start_heartbeat(&mut self, interval: Duration)
```

**Parameters:**
- `interval`: The interval between heartbeats

##### `Cluster::get_peers`

Gets a list of all peers in the cluster.

```rust
pub fn get_peers(&self) -> Vec<&ClusterNode>
```

**Returns:**
- `Vec<&ClusterNode>`: A vector of references to cluster nodes

**Example:**
```rust
use network_protocol::transport::cluster::Cluster;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let peers = vec![
        ("node1".to_string(), "127.0.0.1:8081".to_string()),
        ("node2".to_string(), "127.0.0.1:8082".to_string()),
    ];
    
    let mut cluster = Cluster::new(peers);
    
    // Print all peers
    for node in cluster.get_peers() {
        println!("Cluster node: {} at {}", node.id, node.addr);
    }
    
    // Start heartbeat in a separate task
    tokio::spawn(async move {
        cluster.start_heartbeat(Duration::from_secs(5)).await;
    });
}
```

## Protocol

### Message

The `Message` enum defines the types of messages that can be exchanged in the protocol, including standard operations, secure handshake messages, and custom commands.

#### Enum Definition

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
#[repr(u8)]
pub enum Message {
    // Standard control messages
    Ping,
    Pong,

    // Secure handshake using ECDH key exchange
    // Client initiates with its public key and a timestamp to prevent replay attacks
    SecureHandshakeInit {
        /// Client's public key for ECDH exchange
        pub_key: [u8; 32],
        /// Timestamp to prevent replay attacks
        timestamp: u64,
        /// Random nonce for additional security
        nonce: [u8; 16],
    },
    
    // Server responds with its public key and a signature
    SecureHandshakeResponse {
        /// Server's public key for ECDH exchange
        pub_key: [u8; 32],
        /// Server's nonce (different from client nonce)
        nonce: [u8; 16],
        /// Hash of the client's nonce to prove receipt
        nonce_verification: [u8; 32],
    },
    
    // Final handshake confirmation from client
    SecureHandshakeConfirm {
        /// Hash of server's nonce to prove receipt
        nonce_verification: [u8; 32],
    },

    // Echo message for testing
    Echo(String),
    
    // Connection management
    Disconnect,
    
    // Custom command with payload for extensibility
    Custom {
        command: String,
        payload: Vec<u8>,
    },

    // Default case for unrecognized messages
    #[serde(other)]
    Unknown,
}
```

### Handshake

The handshake module provides functions for performing secure handshakes between client and server using Elliptic Curve Diffie-Hellman (ECDH) key exchange over x25519. `Client` and `service::daemon` run it for you; call these functions directly only when you build your own transport.

State is kept per connection: each side gets a state value from the first step and passes it into the next one. Nothing is stored globally, so concurrent handshakes do not interfere.

#### Types

```rust
pub struct ClientHandshakeState { /* private fields */ }
pub struct ServerHandshakeState { /* private fields */ }
```

Both hold the ephemeral secret, public keys and nonces for one handshake. They are zeroized when dropped.

#### Secure ECDH Handshake

##### `client_secure_handshake_init`

Starts a handshake on the client side by generating an ephemeral key pair, a timestamp and a nonce.

```rust
pub fn client_secure_handshake_init() -> Result<(ClientHandshakeState, Message)>
```

**Returns:**
- The client state to pass to `client_secure_handshake_verify`, and a `SecureHandshakeInit` message containing:
  - The client's public key as a 32-byte array
  - The current time in milliseconds since the Unix epoch
  - A random 16-byte nonce

**Errors:**
- Returns `ProtocolError::Custom` if the system clock is before the Unix epoch

##### `server_secure_handshake_response`

Processes a client's `SecureHandshakeInit` and generates a response.

```rust
pub fn server_secure_handshake_response(
    client_pub_key: [u8; 32],
    client_nonce: [u8; 16],
    client_timestamp: u64,
    peer_id: &str,
    replay_cache: &mut ReplayCache,
) -> Result<(ServerHandshakeState, Message)>
```

**Parameters:**
- `client_pub_key`: The client's public key
- `client_nonce`: The client's random nonce
- `client_timestamp`: The client's timestamp (milliseconds since epoch)
- `peer_id`: An identifier for the peer, used as the replay cache key (the daemon uses the peer's socket address)
- `replay_cache`: Records nonces already seen from this peer

**Returns:**
- The server state to pass to `server_secure_handshake_finalize`, and a `SecureHandshakeResponse` message containing:
  - The server's public key
  - A new 16-byte server nonce
  - A SHA-256 hash of the client's nonce

**Errors:**
- `ProtocolError::HandshakeError` if the timestamp is more than 30 seconds old or more than 2 seconds in the future
- `ProtocolError::HandshakeError` if the replay cache has already seen this nonce and timestamp from this peer

##### `client_secure_handshake_verify`

Checks the server's response and creates the confirmation message.

```rust
pub fn client_secure_handshake_verify(
    state: ClientHandshakeState,
    server_pub_key: [u8; 32],
    server_nonce: [u8; 16],
    nonce_verification: [u8; 32],
    peer_id: &str,
    replay_cache: &mut ReplayCache,
) -> Result<(ClientHandshakeState, Message)>
```

**Parameters:**
- `state`: The state returned by `client_secure_handshake_init`
- `server_pub_key`, `server_nonce`, `nonce_verification`: The fields of the server's `SecureHandshakeResponse`
- `peer_id`, `replay_cache`: As on the server side (the client uses the server address)

**Returns:**
- The updated client state for `client_derive_session_key`, and a `SecureHandshakeConfirm` message containing a SHA-256 hash of the server's nonce

**Errors:**
- `ProtocolError::HandshakeError` if `nonce_verification` is not the hash of the client's nonce, or if the server nonce was already seen

##### `server_secure_handshake_finalize`

Checks the client's confirmation and derives the session key on the server side.

```rust
pub fn server_secure_handshake_finalize(
    state: ServerHandshakeState,
    nonce_verification: [u8; 32],
) -> Result<[u8; 32]>
```

**Returns:**
- A 32-byte session key derived with SHA-256 from the ECDH shared secret and both nonces

**Errors:**
- `ProtocolError::HandshakeError` if `nonce_verification` is not the hash of the server's nonce, or if the state is incomplete

##### `client_derive_session_key`

Derives the same session key on the client side. Call it after `client_secure_handshake_verify`.

```rust
pub fn client_derive_session_key(state: ClientHandshakeState) -> Result<[u8; 32]>
```

**Errors:**
- `ProtocolError::HandshakeError` if the state is incomplete

##### `verify_timestamp`

```rust
pub fn verify_timestamp(timestamp: u64, max_age_seconds: u64) -> bool
```

Returns `true` if `timestamp` (milliseconds since epoch) is no older than `max_age_seconds` and no more than 2 seconds in the future.

#### Security Features

- **Forward Secrecy**: Uses ephemeral x25519 keys that are discarded after session establishment
- **Anti-Replay Protection**: Rejects timestamps older than 30 seconds and nonces already in the `ReplayCache`
- **Cryptographic Nonces**: Uses random nonces from the OS generator for every handshake
- **Session Key Derivation**: Combines the shared secret with the client and server nonces using SHA-256
- **Zeroize**: Handshake state is cleared from memory when dropped

The handshake does not authenticate either side: there are no certificates or long-term keys, so it does not stop an active man-in-the-middle who runs a handshake with each side. When you need to know which server you are talking to, use the TLS transport with CA validation or certificate pinning.

**Example:**
```rust
use network_protocol::error::{ProtocolError, Result};
use network_protocol::protocol::handshake;
use network_protocol::protocol::message::Message;
use network_protocol::utils::replay_cache::ReplayCache;

fn main() -> Result<()> {
    let mut client_cache = ReplayCache::new();
    let mut server_cache = ReplayCache::new();

    // Client initiates handshake
    let (client_state, init_msg) = handshake::client_secure_handshake_init()?;

    // In a real application, each message is sent over the network
    let Message::SecureHandshakeInit { pub_key, timestamp, nonce } = init_msg else {
        return Err(ProtocolError::UnexpectedMessage);
    };

    // Server processes handshake initiation
    let (server_state, response_msg) = handshake::server_secure_handshake_response(
        pub_key,
        nonce,
        timestamp,
        "client-1",
        &mut server_cache,
    )?;

    let Message::SecureHandshakeResponse { pub_key, nonce, nonce_verification } = response_msg else {
        return Err(ProtocolError::UnexpectedMessage);
    };

    // Client verifies server response
    let (client_state, confirm_msg) = handshake::client_secure_handshake_verify(
        client_state,
        pub_key,
        nonce,
        nonce_verification,
        "server-1",
        &mut client_cache,
    )?;

    let Message::SecureHandshakeConfirm { nonce_verification } = confirm_msg else {
        return Err(ProtocolError::UnexpectedMessage);
    };

    // Server finalizes handshake and gets session key
    let server_key = handshake::server_secure_handshake_finalize(server_state, nonce_verification)?;

    // Client derives the same session key
    let client_key = handshake::client_derive_session_key(client_state)?;
    assert_eq!(client_key, server_key);

    Ok(())
}
```

#### Legacy Handshake Support

> **Note**: Legacy handshake support has been removed from the codebase in favor of the more secure ECDH handshake implementation.

### Dispatcher

The dispatcher module provides a thread-safe mechanism for routing and handling messages, implementing a command pattern with dynamic handler registration.

#### Struct Definition

```rust
pub struct Dispatcher {
    handlers: Arc<RwLock<HashMap<String, Box<HandlerFn>>>>,
}
```

#### Type Definitions

```rust
type HandlerFn = dyn Fn(&Message) -> Result<Message> + Send + Sync + 'static;
```

#### Methods

##### `new`

Creates a new dispatcher with an empty handler registry.

```rust
pub fn new() -> Self
```

**Returns:**
- `Dispatcher`: A new dispatcher instance

##### `default`

Provides a default implementation that calls `new()`.

```rust
impl Default for Dispatcher {
    fn default() -> Self
}
```

**Returns:**
- `Dispatcher`: A new dispatcher instance via the `new()` method

##### `register`

Registers a handler function for a specific operation code.

```rust
pub fn register<F>(&self, opcode: &str, handler: F) -> Result<()>
where
    F: Fn(&Message) -> Result<Message> + Send + Sync + 'static,
```

**Parameters:**
- `opcode`: The operation code to register the handler for (e.g., "PING", "ECHO")
- `handler`: The function to handle messages with the given opcode

**Returns:**
- `Result<()>`: Success or an error if the lock couldn't be acquired

**Errors:**
- `ProtocolError::Custom`: If the dispatcher's write lock cannot be acquired

##### `dispatch`

Dispatches a message to the appropriate handler based on its operation code.

```rust
pub fn dispatch(&self, msg: &Message) -> Result<Message>
```

**Parameters:**
- `msg`: The message to dispatch

**Returns:**
- `Result<Message>`: A result containing either the handler's response or an error

**Errors:**
- `ProtocolError::Custom`: If the dispatcher's read lock cannot be acquired
- `ProtocolError::UnexpectedMessage`: If no handler is registered for the message type

**Internal Operation:**
The dispatcher determines the message type using the `get_opcode` function, which extracts a string identifier from the message. It then looks up the appropriate handler in its registry and invokes it with the message.

**Example: Basic Handler Registration**
```rust
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::error::Result;
use std::sync::Arc;

let dispatcher = Arc::new(Dispatcher::new());

// Register handlers with error handling
if let Err(e) = dispatcher.register("PING", |_| Ok(Message::Pong)) {
    eprintln!("Failed to register PING handler: {:?}", e);
}

if let Err(e) = dispatcher.register("ECHO", |msg| {
    match msg {
        Message::Echo(s) => Ok(Message::Echo(s.clone())),
        _ => Ok(Message::Unknown),
    }
}) {
    eprintln!("Failed to register ECHO handler: {:?}", e);
}

// Dispatch a ping message with error handling
match dispatcher.dispatch(&Message::Ping) {
    Ok(Message::Pong) => println!("Received expected pong response"),
    Ok(other) => println!("Received unexpected response: {:?}", other),
    Err(e) => println!("Error dispatching message: {:?}", e),
}
```

**Example: Advanced Handler with Custom Messages**
```rust
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::error::{Result, ProtocolError};
use std::sync::Arc;
use tracing::info;

// Create a dispatcher for a data processing service
let dispatcher = Arc::new(Dispatcher::default());

// Register a handler that processes binary data
if let Err(e) = dispatcher.register("PROCESS_DATA", |msg| {
    match msg {
        Message::Custom { command, data } => {
            info!(command = command, data_len = data.len(), "Processing custom data");
            
            if data.len() > 0 {
                // Process the data (example: check if it starts with a magic byte)
                if data[0] == 0x42 {
                    // Success response with processed result
                    Ok(Message::Custom { 
                        command: "RESULT".to_string(),
                        data: vec![0x01, 0x00] // Success code
                    })
                } else {
                    // Error response for invalid data
                    Ok(Message::Custom { 
                        command: "ERROR".to_string(),
                        data: vec![0xFF] // Error code
                    })
                }
            } else {
                // Empty data error
                Err(ProtocolError::InvalidMessage)
            }
        },
        // Return error for any other message type
        _ => Err(ProtocolError::UnexpectedMessage),
    }
}) {
    eprintln!("Failed to register data processor: {:?}", e);
}

// Example usage: process some data
let data_msg = Message::Custom {
    command: "PROCESS_DATA".to_string(),
    data: vec![0x42, 0x01, 0x02, 0x03],
};

let result = dispatcher.dispatch(&data_msg);
info!(result = ?result, "Got processing result");
```

**Thread Safety Notes:**
The `Dispatcher` uses an `Arc<RwLock<...>>` for thread-safe access to handlers, allowing:
- Multiple readers (dispatch calls) to operate concurrently
- Exclusive access during handler registration
- Safe sharing between threads using `Arc`

This makes it suitable for high-concurrency servers where multiple worker threads handle incoming requests.

### Heartbeat

The heartbeat module provides functions for implementing heartbeat mechanisms to detect and clean up dead connections.

#### Functions

##### `build_ping`

Builds a heartbeat ping message.

```rust
pub fn build_ping() -> Message
```

**Returns:**
- `Message`: A `Ping` message

##### `is_pong`

Returns true if a received message is a valid pong.

```rust
pub fn is_pong(msg: &Message) -> bool
```

**Parameters:**
- `msg`: The message to check

**Returns:**
- `bool`: `true` if the message is a `Pong`, `false` otherwise

**Example:**
```rust
use network_protocol::protocol::heartbeat;
use network_protocol::protocol::message::Message;
use tokio::time::timeout;
use std::time::Duration;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Send a ping with timeout
    let ping_msg = heartbeat::build_ping();
    let mut conn = // ...get connection
    
    // Send ping with timeout
    match timeout(Duration::from_secs(5), conn.send(ping_msg)).await {
        Ok(Ok(_)) => info!("Ping sent successfully"),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            warn!("Ping send timeout - connection may be dead");
            return Err(ProtocolError::Timeout);
        }
    }
    
    // Receive pong with timeout
    let response = match timeout(Duration::from_secs(5), conn.receive()).await {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            warn!("Pong receive timeout - connection may be dead");
            return Err(ProtocolError::Timeout);
        }
    };
    
    // Check if the response is a valid pong
    if heartbeat::is_pong(&response) {
        info!("Received valid pong response - connection is alive");
        Ok(())
    } else {
        warn!("Response is not a pong - unexpected message type");
        Err(ProtocolError::UnexpectedMessageType)
    }
}
```

##### `start_heartbeat_task`

Starts a background task that sends periodic heartbeats on a connection.

```rust
pub async fn start_heartbeat_task(
    conn: Arc<Mutex<Connection>>,
    interval: Duration,
    on_failure: impl Fn() + Send + 'static
) -> JoinHandle<()>
```

**Parameters:**
- `conn`: A thread-safe reference to a connection
- `interval`: How frequently to send heartbeats
- `on_failure`: Callback function to execute if heartbeat fails

**Returns:**
- `JoinHandle<()>`: A handle to the spawned heartbeat task

**Example:**
```rust
use std::sync::{Arc, Mutex};
use std::time::Duration;
use network_protocol::protocol::heartbeat;
use tracing::warn;

#[tokio::main]
async fn main() {
    let conn = Arc::new(Mutex::new(/* connection */));
    
    // Start heartbeat task that will run every 15 seconds
    let heartbeat_handle = heartbeat::start_heartbeat_task(
        Arc::clone(&conn),
        Duration::from_secs(15),
        || {
            warn!("Heartbeat failed, connection may be dead");
            // Trigger connection cleanup or reconnection logic
        }
    ).await;
    
    // Later, when shutting down:
    heartbeat_handle.abort();
}
```

## Service

### Client

The client module provides a TCP client that runs the secure ECDH handshake and encrypts every message after it, with timeouts for connecting, sending and waiting for responses.

#### Struct Definition

```rust
pub struct Client {
    // private fields
}
```

#### Methods

##### `connect` and `connect_with_config`

Connects to a remote TCP server and performs the secure handshake.

```rust
pub async fn connect(addr: &str) -> Result<Self>
pub async fn connect_with_config(config: ClientConfig) -> Result<Self>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8080"). `connect` uses the default `ClientConfig` with this address.
- `config`: Client configuration. `connection_timeout` bounds the TCP connect and the wait for the server's handshake response; `operation_timeout` bounds each `send`.

**Returns:**
- `Result<Client>`: A result containing either a connected client or an error. A timeout is reported as `ProtocolError::Timeout`.

`Client` does not reconnect. The `auto_reconnect`, `max_reconnect_attempts` and `reconnect_delay` fields of `ClientConfig` are deprecated in 1.3.0 and have no effect. To reconnect, call `connect_with_config` again.

##### `send`

Encrypts and sends a message to the server.

```rust
pub async fn send(&mut self, msg: Message) -> Result<()>
```

**Parameters:**
- `msg`: The message to send

**Returns:**
- `Result<()>`: A result indicating success or an error. Fails with `ProtocolError::Timeout` if the send takes longer than `ClientConfig::operation_timeout` (since 1.3.0).

##### `recv`

Receives and decrypts a message from the server. It uses the default 5 second receive timeout.

```rust
pub async fn recv(&mut self) -> Result<Message>
```

**Returns:**
- `Result<Message>`: A result containing either the received message or an error

##### `send_and_wait`

Sends a message and waits up to `ClientConfig::response_timeout` for the reply, sending keep-alive pings while it waits. `Pong` messages are skipped, so do not use it to wait for a reply to `Message::Ping`.

```rust
pub async fn send_and_wait(&mut self, msg: Message) -> Result<Message>
```

##### `recv_with_keepalive` and `send_keepalive`

```rust
pub async fn recv_with_keepalive(&mut self, timeout_duration: Duration) -> Result<Message>
pub async fn send_keepalive(&mut self) -> Result<()>
```

`recv_with_keepalive` waits up to `timeout_duration` for a message other than `Pong`, sending pings at the configured `heartbeat_interval`. It returns `ProtocolError::ConnectionTimeout` if the server stops answering. `send_keepalive` sends a single ping.

There is no `close` method. Send `Message::Disconnect` to end the session cleanly, or drop the client to close the connection.

**Example with Timeout Handling:**
```rust
use network_protocol::config::ClientConfig;
use network_protocol::error::ProtocolError;
use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use std::time::Duration;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    network_protocol::init();

    // Configure client timeouts
    let config = ClientConfig {
        address: "127.0.0.1:9000".to_string(),
        connection_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(3),
        ..Default::default()
    };

    // Connect; connection_timeout applies to the connect and to the handshake
    info!("Connecting to server...");
    let mut client = match Client::connect_with_config(config).await {
        Ok(client) => client,
        Err(ProtocolError::Timeout) => {
            error!("Connection timeout");
            return Err(ProtocolError::Timeout.into());
        }
        Err(e) => {
            error!(error = ?e, "Failed to connect to server");
            return Err(e.into());
        }
    };

    info!("Connected successfully");

    // Send message; operation_timeout applies
    match client.send(Message::Echo("hello".into())).await {
        Ok(()) => info!("Message sent successfully"),
        Err(ProtocolError::Timeout) => {
            error!("Send timeout");
            return Err(ProtocolError::Timeout.into());
        }
        Err(e) => {
            error!(error = ?e, "Failed to send message");
            return Err(e.into());
        }
    }

    let reply = client.recv().await?;
    info!(reply = ?reply, "Received reply");

    // Close connection gracefully
    client.send(Message::Disconnect).await?;
    Ok(())
}
```

### Daemon

The daemon module runs a TCP server that performs the secure handshake with each client, then dispatches the decrypted messages, with backpressure, timeouts, heartbeats and graceful shutdown.

#### Functions

##### `start`, `start_with_config`, `start_with_shutdown` and `start_with_config_and_shutdown`

Run a server in the current task with the built-in `PING` and `ECHO` handlers.

```rust
pub async fn start(addr: &str) -> Result<()>
pub async fn start_with_config(config: ServerConfig) -> Result<()>
pub async fn start_with_shutdown(addr: &str, shutdown_rx: tokio::sync::oneshot::Receiver<()>) -> Result<()>
pub async fn start_with_config_and_shutdown(
    config: ServerConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8080"). The other settings are the `ServerConfig` defaults.
- `config`: Server configuration (see [ServerConfig](#serverconfig))
- `shutdown_rx`: The server shuts down gracefully when `()` is sent on the matching sender

**Returns:**
- `Result<()>`: Returns after a graceful shutdown, or with an error if the address cannot be bound

The server also shuts down on Ctrl+C. On shutdown it waits up to `shutdown_timeout` for open connections to close.

##### `start_daemon_no_signals`

Starts a server in a background task with your own dispatcher and returns a handle to stop it.

```rust
pub async fn start_daemon_no_signals(config: ServerConfig, dispatcher: Arc<Dispatcher>) -> Result<Daemon>
```

**Parameters:**
- `config`: Server configuration
- `dispatcher`: The dispatcher that handles every message. Register all the handlers you need (including `PING` and `ECHO` if clients use them) before calling. Before 1.3.0 this argument was ignored and the default handlers were used.

**Returns:**
- `Result<Daemon>`: A handle to the running server

This server does not install a Ctrl+C handler: it stops only when `Daemon::shutdown()` is called (before 1.3.0 it also stopped on Ctrl+C). Handle signals yourself, as in the example below.

##### Deprecated

- `new_with_config(config, dispatcher) -> Daemon`: deprecated in 1.3.0. It never started a server and ignored the dispatcher. Use `start_daemon_no_signals`.

#### Structs

##### `Daemon`

```rust
pub struct Daemon {
    pub address: String,
    // private fields
}
```

#### Methods

##### `Daemon::shutdown`

Signals the server to shut down gracefully. It stops accepting connections and waits up to `ServerConfig::shutdown_timeout` for open connections to close.

```rust
pub async fn shutdown(&mut self) -> Result<()>
```

**Returns:**
- `Result<()>`: An error if `shutdown` was already called

`Daemon::run()` and `Daemon::shutdown_with_timeout()` are deprecated in 1.3.0: `run()` returns immediately (the server is already running), and `shutdown_with_timeout()` ignores its timeout. Use `shutdown()` and set `ServerConfig::shutdown_timeout`.

**Example with Backpressure and Timeouts:**
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

    let dispatcher = Arc::new(Dispatcher::default());
    dispatcher.register("PING", |_| Ok(Message::Pong))?;
    dispatcher.register("ECHO", |msg| Ok(msg.clone()))?;

    // Configure server with backpressure settings
    let config = ServerConfig {
        address: "127.0.0.1:9000".to_string(),
        backpressure_limit: 100, // Messages queued per connection before reads pause
        connection_timeout: Duration::from_secs(10), // Each handshake step
        heartbeat_interval: Duration::from_secs(15),
        shutdown_timeout: Duration::from_secs(10),
        max_connections: 1000, // Extra connections are closed on accept
    };

    // Start server with configuration
    let mut server = daemon::start_daemon_no_signals(config, dispatcher).await?;
    info!(address = %server.address, "Server started");

    // Shut down on Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Initiating graceful shutdown...");
    server.shutdown().await?;
    Ok(())
}
```

**Example with an external shutdown signal:**
```rust
use network_protocol::service::daemon;
use std::time::Duration;
use tokio::sync::oneshot;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Stop the server after 60 seconds
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let _ = shutdown_tx.send(());
    });

    // Run server until shutdown is signalled
    daemon::start_with_shutdown("127.0.0.1:8080", shutdown_rx).await?;
    println!("Server has shut down successfully");
    Ok(())
}
```

### TLS Daemon

The TLS daemon module runs a TLS server that dispatches `Message`s. TLS provides the encryption, so there is no separate ECDH handshake. The server registers its own `PING` and `ECHO` handlers; a custom dispatcher cannot be passed in.

#### Functions

##### `start`

Starts a TLS server and runs it until Ctrl+C.

```rust
pub async fn start(addr: &str, tls_config: TlsServerConfig) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8443")
- `tls_config`: The TLS configuration for the server (see [TLS Transport](#tls-transport))

**Returns:**
- `Result<()>`: Returns after a graceful shutdown, or with an error if the TLS configuration is invalid or the address cannot be bound

Before 1.3.0 this function returned about half a second after starting.

##### `start_with_shutdown`

Starts a TLS server that shuts down when `()` is sent on the channel.

```rust
pub async fn start_with_shutdown(
    addr: &str,
    tls_config: TlsServerConfig,
    shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()>
```

Dropping every sender without sending does not stop the server. On shutdown it waits up to 10 seconds for open connections to close. Each client must finish the TLS handshake within 10 seconds.

**Example:**
```rust
use network_protocol::service::tls_daemon;
use network_protocol::transport::tls::TlsServerConfig;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls_config = TlsServerConfig::new("server.crt", "server.key")
        .with_client_auth("ca.crt"); // Require client certificates (mTLS)

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Set up graceful shutdown on Ctrl+C
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("Shutting down TLS server gracefully...");
            let _ = shutdown_tx.send(()).await;
        }
    });

    // Run server until shutdown is signalled
    tls_daemon::start_with_shutdown("127.0.0.1:8443", tls_config, shutdown_rx).await?;
    println!("TLS Server has shut down successfully");
    Ok(())
}
```

### TLS Client

`service::tls_client::TlsClient` connects to a TLS server such as the TLS daemon and exchanges `Message`s.

```rust
impl TlsClient {
    pub async fn connect(addr: &str, config: TlsClientConfig) -> Result<Self>
    pub async fn connect_with_session(
        addr: &str,
        config: TlsClientConfig,
        session_cache: Option<Arc<SessionCache>>,
    ) -> Result<Self>
    pub async fn send(&mut self, message: Message) -> Result<()>
    pub async fn receive(&mut self) -> Result<Message>
    pub async fn request(&mut self, message: Message) -> Result<Message>
    pub fn session_cache(&self) -> Option<&SessionCache>
    pub fn session_id(&self) -> Option<&str>
}
```

- `connect`: connects without session resumption. The handshake must finish within 10 seconds, otherwise it fails with `ProtocolError::Timeout`.
- `connect_with_session`: with `Some(cache)`, the server's session tickets are stored in the cache, and a later connection that uses the same cache and server name resumes the TLS session instead of running a full handshake (fixed in 1.3.0; before that nothing was resumed).
- `send` / `receive`: one message each way. `request` sends a message and waits for the next reply.

**Example:**
```rust
use network_protocol::protocol::message::Message;
use network_protocol::service::tls_client::TlsClient;
use network_protocol::transport::session_cache::SessionCache;
use network_protocol::transport::tls::TlsClientConfig;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One cache shared by every connection to this server
    let cache = Arc::new(SessionCache::new(100, Duration::from_secs(3600)));

    for _ in 0..2 {
        let config = TlsClientConfig::new("example.com")
            .with_root_ca("ca.crt")
            .with_client_certificate("client.crt", "client.key");

        // The second connection resumes the session from the first
        let mut client =
            TlsClient::connect_with_session("127.0.0.1:8443", config, Some(cache.clone())).await?;
        let reply = client.request(Message::Ping).await?;
        println!("Reply: {:?}", reply);
    }
    Ok(())
}
```

### Secure Connection

`service::secure::SecureConnection` wraps a framed TCP stream and encrypts every message with XChaCha20-Poly1305 under the session key from the handshake. `Client` and `service::daemon` use it internally; use it directly only when you run the handshake yourself.

#### Struct Definition

```rust
pub struct SecureConnection {
    // private fields
}
```

#### Methods

##### `new`

Creates a secure connection over a framed TCP stream with the given session key. The send and receive timeouts both start at 5 seconds. The local copy of the key is zeroized after use.

```rust
pub fn new(framed: Framed<TcpStream, PacketCodec>, key: [u8; 32]) -> Self
```

**Parameters:**
- `framed`: A connected stream (from `transport::remote::connect`) on which the handshake has completed
- `key`: The 32-byte session key from the handshake

##### `with_timeouts`

Sets the send and receive timeouts.

```rust
pub fn with_timeouts(self, send_timeout: Duration, recv_timeout: Duration) -> Self
```

##### `secure_send`

Serializes a value with bincode, encrypts it with a fresh random 24-byte nonce and sends it as one packet. The payload is the nonce followed by the ciphertext.

```rust
pub async fn secure_send(&mut self, msg: impl serde::Serialize) -> Result<()>
```

**Errors:**
- `ProtocolError::Timeout` if the send takes longer than the send timeout
- Serialization, encryption or transport errors

##### `secure_recv`

Receives one packet, decrypts it and deserializes it.

```rust
pub async fn secure_recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T>
```

**Errors:**
- `ProtocolError::Timeout` if nothing arrives within the receive timeout
- `ProtocolError::ConnectionClosed` if the peer closed the connection
- `ProtocolError::DecryptionFailure` if the payload is shorter than a nonce or fails authentication

##### `time_since_last_activity`

```rust
pub fn time_since_last_activity(&self) -> Duration
```

Time since the last successful send or receive.

**Example:**
```rust
use network_protocol::protocol::message::Message;
use network_protocol::service::secure::SecureConnection;
use network_protocol::PacketCodec;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

// `framed` is the stream the handshake ran on, and `key` is the session key it produced
// (see the Handshake section). Both sides must use the same key.
async fn send_secret(
    framed: Framed<TcpStream, PacketCodec>,
    key: [u8; 32],
) -> network_protocol::error::Result<Message> {
    let mut conn = SecureConnection::new(framed, key)
        .with_timeouts(Duration::from_secs(3), Duration::from_secs(10));

    conn.secure_send(Message::Echo("Secret message".to_string())).await?;
    let reply: Message = conn.secure_recv().await?;
    Ok(reply)
}
```

### Connection Pooling

The pooling module provides reusable connections with health checks, circuit breaking, and backpressure.

**Example:**
```rust
use network_protocol::service::pool::{ConnectionPool, PoolConfig};
use std::time::Duration;

let config = PoolConfig {
    min_size: 5,
    max_size: 50,
    idle_timeout: Duration::from_secs(300),
    max_lifetime: Duration::from_secs(3600),
    ..Default::default()
};

let pool = ConnectionPool::new(factory, config)?;
let conn = pool.acquire().await?;
```

- `max_size` is the number of idle connections the pool keeps. A connection released while the pool already holds `max_size` is closed (since 1.3.0; before that up to 100 were kept whatever the setting).
- `max_lifetime` counts from when the connection was created. Returning a connection to the pool does not reset it (since 1.3.0).

### Multiplexing

The multiplexing module provides ID-tagged request routing over shared connections.

**Example:**
```rust
use network_protocol::service::multiplex::{MultiplexConfig, Multiplexer};
use tokio::io::{AsyncRead, AsyncWrite};

let config = MultiplexConfig::default();
let (writer, reader) = tokio::io::split(stream);
let multiplex = Multiplexer::new(reader, writer, config);
let response = multiplex.request(payload).await?;
```

## Utilities

### Cryptography

The crypto module provides cryptographic functions for secure communication.

#### Functions

##### `generate_random_bytes`

Generates a vector of random bytes of the specified length.

```rust
pub fn generate_random_bytes(len: usize) -> Vec<u8>
```

**Parameters:**
- `len`: The length of the random byte vector to generate

**Returns:**
- `Vec<u8>`: A vector containing the random bytes

##### `encrypt`

Encrypts data using XChaCha20Poly1305.

```rust
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>
```

**Parameters:**
- `key`: The 32-byte encryption key
- `plaintext`: The data to encrypt

**Returns:**
- `Result<(Vec<u8>, Vec<u8>)>`: A result containing either a tuple of (ciphertext, nonce) or an error

##### `decrypt`

Decrypts data using XChaCha20Poly1305.

```rust
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>>
```

**Parameters:**
- `key`: The 32-byte encryption key
- `ciphertext`: The encrypted data
- `nonce`: The nonce used during encryption

**Returns:**
- `Result<Vec<u8>>`: A result containing either the decrypted data or an error

**Example:**
```rust
use network_protocol::utils::crypto;

// Generate a random encryption key
let key: [u8; 32] = crypto::generate_random_bytes(32).try_into().unwrap();

// Data to encrypt
let data = b"This is a secret message";

// Encrypt the data
let (ciphertext, nonce) = crypto::encrypt(&key, data).unwrap();
println!("Encrypted data length: {}", ciphertext.len());

// Decrypt the data
let plaintext = crypto::decrypt(&key, &ciphertext, &nonce).unwrap();
let decrypted_text = String::from_utf8(plaintext).unwrap();
println!("Decrypted text: {}", decrypted_text);
```

### Compression

The compression module provides functions for compressing and decompressing data.

#### Functions

##### `compress_lz4`

Compresses data using the LZ4 algorithm.

```rust
pub fn compress_lz4(data: &[u8]) -> Vec<u8>
```

**Parameters:**
- `data`: The data to compress

**Returns:**
- `Vec<u8>`: The compressed data

##### `decompress_lz4`

Decompresses data compressed with the LZ4 algorithm.

```rust
pub fn decompress_lz4(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>>
```

**Parameters:**
- `compressed`: The compressed data
- `expected_size`: The expected size of the decompressed data

**Returns:**
- `Result<Vec<u8>>`: A result containing either the decompressed data or an error

##### `compress_zstd`

Compresses data using the Zstd algorithm.

```rust
pub fn compress_zstd(data: &[u8]) -> Result<Vec<u8>>
```

**Parameters:**
- `data`: The data to compress

**Returns:**
- `Result<Vec<u8>>`: A result containing either the compressed data or an error

##### `decompress_zstd`

Decompresses data compressed with the Zstd algorithm.

```rust
pub fn decompress_zstd(compressed: &[u8]) -> Result<Vec<u8>>
```

**Parameters:**
- `compressed`: The compressed data

**Returns:**
- `Result<Vec<u8>>`: A result containing either the decompressed data or an error

**Example:**
```rust
use network_protocol::utils::compression;

// Original data
let data = b"This is some test data that will be compressed and then decompressed";

// Compress with LZ4
let compressed = compression::compress_lz4(data);
println!("Original size: {}, Compressed size: {}", data.len(), compressed.len());

// Decompress with LZ4
let decompressed = compression::decompress_lz4(&compressed, data.len()).unwrap();
let decompressed_text = String::from_utf8(decompressed).unwrap();
println!("Decompressed text: {}", decompressed_text);

// Compress with Zstd
let zstd_compressed = compression::compress_zstd(data).unwrap();
println!("Zstd compressed size: {}", zstd_compressed.len());

// Decompress with Zstd
let zstd_decompressed = compression::decompress_zstd(&zstd_compressed).unwrap();
let zstd_text = String::from_utf8(zstd_decompressed).unwrap();
println!("Zstd decompressed text: {}", zstd_text);
```

### Time

The time module provides time-related utilities.

#### Functions

##### `get_current_time_ms`

Returns the current system time in milliseconds.

```rust
pub fn get_current_time_ms() -> u64
```

**Returns:**
- `u64`: The current system time in milliseconds since the Unix epoch

##### `duration_since`

Calculates the duration in milliseconds between the current time and a past timestamp.

```rust
pub fn duration_since(past_time_ms: u64) -> u64
```

**Parameters:**
- `past_time_ms`: A timestamp in milliseconds since the Unix epoch

**Returns:**
- `u64`: The duration in milliseconds between the current time and the past timestamp

**Example:**
```rust
use network_protocol::utils::time;
use std::thread::sleep;
use std::time::Duration;

// Get current time
let now = time::get_current_time_ms();
println!("Current time (ms): {}", now);

// Sleep for a short time
sleep(Duration::from_millis(500));

// Calculate duration since the recorded time
let elapsed = time::duration_since(now);
println!("Elapsed time (ms): {}", elapsed);
```

## Benchmarking

The network-protocol library provides built-in benchmarking tools to measure performance characteristics such as latency and throughput. These benchmarks are essential for ensuring high performance in production environments.

### Running Benchmarks

To run the benchmarks, use the following command:

```bash
cargo test --test perf -- --nocapture
```

For more detailed performance metrics, use the `--nocapture` flag to see console output:

```bash
cargo test --test perf -- --nocapture
```

To run a specific benchmark test:

```bash
cargo test --test perf benchmark_roundtrip_latency -- --nocapture
cargo test --test perf benchmark_throughput -- --nocapture
```

### Understanding Benchmark Output

When running benchmarks, you may see connection errors like `Broken pipe` or `ConnectionClosed`. These are normal and expected during benchmark shutdown sequence. The most important information to look for is:

- **Latency Benchmark**: Look for "Average roundtrip latency over X successful packets: Xµs per message"
- **Throughput Benchmark**: Look for "Throughput: X messages/sec (X successful of X attempts)"

#### Common Error Messages

```
Error sending ping message: Io(Os { code: 32, kind: BrokenPipe, message: "Broken pipe" })
Error receiving response: ConnectionClosed
```

These errors typically appear when the server shuts down while there are still pending client requests. They do not indicate a problem with the benchmark itself, as long as you see successful metrics reported above the errors.

#### Troubleshooting

If you see "No successful exchanges completed" in the throughput benchmark:

1. Increase the delay between messages (currently set to 20ms)
2. Check if another process is using the same port
3. Ensure the server has enough time to start before client connects

### Performance Metrics

The library measures two primary performance metrics:

#### Roundtrip Latency

Measures the time taken for a complete message roundtrip (client → server → client).

```rust
#[tokio::test]
async fn benchmark_roundtrip_latency() {
    // Test setup
    let addr = "127.0.0.1:7799";
    
    // Start server
    let _server_handle = tokio::spawn(async move {
        daemon::start(addr).await.unwrap();
    });
    
    // Connect client and send/receive multiple ping-pong messages
    // ...
    
    // Calculate average latency
    if successful > 0 {
        let avg = total / successful;
        println!("Average roundtrip latency over {successful} successful packets: {avg:?} per message");
    }
}
```

#### Message Throughput

Measures the number of messages that can be processed per second.

```rust
#[tokio::test]
async fn benchmark_throughput() {
    // Test setup
    let addr = "127.0.0.1:7798";
    
    // Start server and connect client
    // ...
    
    // Send multiple messages and count successful exchanges
    // ...
    
    // Calculate throughput
    let elapsed = start.elapsed();
    if successful > 0 {
        let per_sec = successful as f64 / elapsed.as_secs_f64();
        println!("Throughput: {per_sec:.0} messages/sec ({successful} successful of {rounds} attempts) over {elapsed:?} total");
    }
}
```

### Interpreting Results

When running benchmarks, the output will show:

- **Roundtrip Latency**: Average time in microseconds for a complete ping-pong cycle
- **Throughput**: Messages processed per second

Typical results on modern hardware should show:

| Metric | Expected Range | Interpretation |
|--------|---------------|----------------|
| Latency | <1ms | Excellent |
| Latency | 1-5ms | Good |
| Latency | >10ms | Investigate bottlenecks |
| Throughput | >5,000 msg/sec | Excellent |
| Throughput | 1,000-5,000 msg/sec | Good |
| Throughput | <1,000 msg/sec | Investigate bottlenecks |

Factors affecting performance:

1. **Network conditions**: Local vs. remote testing
2. **Hardware resources**: CPU, memory, network interface
3. **Message size**: Larger payloads reduce throughput
4. **Encryption overhead**: TLS adds processing time
5. **Backpressure settings**: May limit throughput but improve stability

### Custom Benchmark Configuration

You can create custom benchmarks using the `BenchmarkClient` implementation from the test utilities:

```rust
use network_protocol::protocol::message::Message;
use std::time::{Duration, Instant};

// Import our test-specific client implementation
use test_utils::BenchmarkClient;

// Connect to server with our BenchmarkClient that doesn't use global state
let mut client = BenchmarkClient::connect(addr).await?;

// Start timing
let start = Instant::now();

// Send message
await client.send(Message::Ping).await?;

// Receive response
let response = client.recv().await?;

// Calculate elapsed time
let elapsed = start.elapsed();
println!("Elapsed time: {:?}", elapsed);
```

To customize benchmark parameters:

1. **Rounds**: Adjust the number of test iterations
2. **Payload size**: Use custom messages with varying payload sizes
3. **Delay**: Modify the delay between messages
4. **Transport**: Test different transport types (TCP, UDS, TLS)

```rust
// Example custom benchmark with larger payload
let large_payload = vec![0u8; 1024 * 1024]; // 1MB payload
let msg = Message::Custom {
    command: "BENCHMARK".to_string(),
    data: large_payload,
};

let start = Instant::now();
await client.send(msg).await?;
let response = client.recv().await?;
let elapsed = start.elapsed();
println!("Elapsed time (ms): {}", elapsed);
```

## Error Handling

The error module defines a unified error handling mechanism for the network protocol, encapsulating various error scenarios such as I/O errors, serialization issues, and protocol-specific logic failures. It uses the `thiserror` crate for ergonomic error definition and provides a custom `Result<T>` alias to simplify function signatures across the protocol stack.

### Type Aliases

```rust
pub type Result<T> = std::result::Result<T, ProtocolError>;
```

### ProtocolError Enum Definition

```rust
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    #[serde(skip_serializing, skip_deserializing)]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    #[serde(skip_serializing, skip_deserializing)]
    Serialization(#[from] bincode::Error),
    
    #[error("Serialize error: {0}")]
    SerializeError(String),
    
    #[error("Deserialize error: {0}")]
    DeserializeError(String),
    
    #[error("Transport error: {0}")]
    TransportError(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Security error: {0}")]
    SecurityError(String),

    #[error("Invalid protocol header")]
    InvalidHeader,

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Packet too large: {0} bytes")]
    OversizedPacket(usize),

    #[error("Decryption failed")]
    DecryptionFailure,

    #[error("Encryption failed")]
    EncryptionFailure,

    #[error("Compression failed")]
    CompressionFailure,

    #[error("Decompression failed")]
    DecompressionFailure,

    #[error("Handshake failed: {0}")]
    HandshakeError(String),

    #[error("Unexpected message type")]
    UnexpectedMessage,

    #[error("Timeout occurred")]
    Timeout,
    
    #[error("Connection timed out (no activity)")]
    ConnectionTimeout,

    #[error("Custom error: {0}")]
    Custom(String),

    #[error("TLS error: {0}")]
    TlsError(String),
}
```

### Error Variants

- **`Io`**: Wraps standard I/O errors from operations like reading/writing to sockets
- **`Serialization`**: Wraps bincode serialization/deserialization errors
- **`SerializeError`/`DeserializeError`**: Custom serialization error messages
- **`TransportError`**: Errors in the transport layer (TCP, UDS, etc.)
- **`ConnectionClosed`**: Indicates a connection was cleanly closed
- **`SecurityError`**: General security-related errors
- **`InvalidHeader`**: Invalid protocol header in packet
- **`UnsupportedVersion`**: Protocol version not supported
- **`OversizedPacket`**: Packet size exceeds allowed maximum
- **`DecryptionFailure`/`EncryptionFailure`**: Cryptographic operation failures
- **`CompressionFailure`/`DecompressionFailure`**: Data compression operation failures
- **`HandshakeError`**: Failure during connection handshake process
- **`UnexpectedMessage`**: Received message type doesn't match expected type
- **`Timeout`**: Operation timed out
- **`ConnectionTimeout`**: Connection timed out due to inactivity
- **`Custom`**: Custom error messages for specific situations
- **`TlsError`**: Errors related to TLS operations

### Example Usage

```rust
use network_protocol::error::{ProtocolError, Result};
use std::fs::File;
use std::io::Read;
use tracing::{info, error};

// Function that returns our custom Result type
fn read_file(path: &str) -> Result<String> {
    // Convert io::Error to ProtocolError::Io automatically with the ? operator
    let mut file = File::open(path).map_err(ProtocolError::Io)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(ProtocolError::Io)?;
    Ok(contents)
}

// Example of handling specific error types
fn handle_network_error(result: Result<()>) {
    match result {
        Ok(()) => info!("Operation completed successfully"),
        Err(ProtocolError::Timeout) => error!("Operation timed out, retrying..."),
        Err(ProtocolError::ConnectionClosed) => info!("Connection closed gracefully"),
        Err(ProtocolError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::ConnectionRefused => {
            error!("Connection refused, server might be down")
        },
        Err(e) => error!(error = %e, "Unexpected error occurred"),
    }
}
```

### Error Propagation

The library makes extensive use of the `?` operator for concise error handling and propagation. Combined with the `#[from]` attribute provided by `thiserror`, this allows for automatic conversion of standard error types into `ProtocolError` variants.

```rust
// Example showing error propagation in the protocol
async fn send_with_timeout<T: Serialize>(
    connection: &mut Connection, 
    message: &T,
    timeout: Duration
) -> Result<()> {
    // TimeoutError automatically converts to ProtocolError::Timeout
    tokio::time::timeout(timeout, async {
        // BincodeError automatically converts to ProtocolError::Serialization
        let bytes = bincode::serialize(message)?;
        
        // IoError automatically converts to ProtocolError::Io
        connection.write_all(&bytes).await?;
        
        Ok(())
    }).await.map_err(|_| ProtocolError::Timeout)??
}
```

## Logging

The logging module provides structured logging capabilities using the `tracing` crate.

### Types

##### `LogConfig`

```rust
pub struct LogConfig {
    pub app_name: String,
    pub log_level: tracing::Level,
    pub json_format: bool,
    pub log_dir: Option<String>,
    pub log_to_stdout: bool,
}
```

**Fields:**
- `app_name`: Application name, used in the log filter and as the log file name (default: "network-protocol")
- `log_level`: Level applied to `app_name` (default: INFO)
- `json_format`: Write JSON lines instead of plain text (default: false)
- `log_dir`: Directory for a daily rolling file named `<app_name>.log`; `None` for no file (default: None)
- `log_to_stdout`: Also write to stdout (default: true). If there is no `log_dir` and this is `false`, logs still go to stdout and a warning is logged.

This is a different struct from `config::LoggingConfig`. The `[logging]` table of `NetworkConfig` is not read by any of these functions; build a `LogConfig` from it yourself if you want to use it.

### Functions

##### `init_logging`

Installs a global `tracing` subscriber. Only the first call has any effect; later calls do nothing.

```rust
pub fn init_logging(config: &LogConfig)
```

If the `RUST_LOG` environment variable is set, it is used as the filter and `log_level` is not applied.

##### `setup_default_logging`

```rust
pub fn setup_default_logging()
```

Calls `init_logging(&LogConfig::default())`.

##### `network_protocol::init` and `network_protocol::init_with_config`

```rust
pub fn init()
pub fn init_with_config(log_config: &utils::logging::LogConfig)
```

Shortcuts at the crate root: `init()` calls `setup_default_logging()`, and `init_with_config(..)` calls `init_logging(..)`.

**Example:**
```rust
use network_protocol::utils::logging::{init_logging, LogConfig};
use tracing::{debug, error, info, Level};

fn main() {
    // DEBUG level for this app, stdout only
    init_logging(&LogConfig {
        app_name: "my-service".to_string(),
        log_level: Level::DEBUG,
        ..Default::default()
    });

    // Log various events with different levels
    debug!("This is a debug message with a value: {}", 42);
    info!(user = "admin", action = "login", "User logged in successfully");
    error!(error_code = 500, message = "Database connection failed");
}
```

## Configuration

The configuration system provides a comprehensive way to customize the network protocol's behavior through TOML files, environment variables, or programmatic overrides.

### NetworkConfig

The main configuration structure that contains all configurable settings.

```rust
pub struct NetworkConfig {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub transport: TransportConfig,
    pub logging: LoggingConfig,
}
```

#### Methods

##### `from_file`

Loads configuration from a TOML file.

```rust
pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self>
```

**Parameters:**
- `path`: Path to the TOML configuration file

**Returns:**
- `Result<NetworkConfig>`: Parsed configuration or an error

**Errors:**
- `ProtocolError::ConfigError`: If the file cannot be read or parsed

**Example:**
```rust
use network_protocol::config::NetworkConfig;

let config = NetworkConfig::from_file("config.toml")?;
println!("Server address: {}", config.server.address);
```

##### `from_toml`

Loads configuration from a TOML string.

```rust
pub fn from_toml(content: &str) -> Result<Self>
```

**Parameters:**
- `content`: TOML content as a string

**Returns:**
- `Result<NetworkConfig>`: Parsed configuration or an error

**Errors:**
- `ProtocolError::ConfigError`: If the content cannot be parsed

##### `from_env`

Loads configuration from environment variables, falling back to defaults.

```rust
pub fn from_env() -> Result<Self>
```

**Returns:**
- `Result<NetworkConfig>`: Configuration with environment variable overrides

**Supported Environment Variables:**
- `NETWORK_PROTOCOL_SERVER_ADDRESS`: Server listen address
- `NETWORK_PROTOCOL_BACKPRESSURE_LIMIT`: Maximum backpressure queue size
- `NETWORK_PROTOCOL_CONNECTION_TIMEOUT_MS`: Connection timeout in milliseconds
- `NETWORK_PROTOCOL_HEARTBEAT_INTERVAL_MS`: Heartbeat interval in milliseconds

##### `default_with_overrides`

Creates a configuration with default values and applies overrides.

```rust
pub fn default_with_overrides<F>(mutator: F) -> Self
where F: FnOnce(&mut Self)
```

**Parameters:**
- `mutator`: Closure that modifies the default configuration

**Returns:**
- `NetworkConfig`: Modified configuration

**Example:**
```rust
use network_protocol::config::NetworkConfig;
use std::time::Duration;

let config = NetworkConfig::default_with_overrides(|cfg| {
    cfg.server.address = "0.0.0.0:8080".to_string();
    cfg.server.connection_timeout = Duration::from_secs(60);
    cfg.client.operation_timeout = Duration::from_secs(5);
});
```

##### `validate`

Validates the configuration and returns a list of validation errors.

```rust
pub fn validate(&self) -> Vec<String>
```

**Returns:**
- `Vec<String>`: Validation errors (empty when valid)

##### `validate_strict`

Validates the configuration and returns a `Result` with a consolidated error message.

```rust
pub fn validate_strict(&self) -> Result<()>
```

**Example:**
```rust
use network_protocol::config::NetworkConfig;

let config = NetworkConfig::from_env()?;
config.validate_strict()?;
```

##### `example_config`

Generates an example configuration in TOML format.

```rust
pub fn example_config() -> String
```

**Returns:**
- `String`: Example configuration in TOML format

##### `save_to_file`

Saves the configuration to a TOML file.

```rust
pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()>
```

**Parameters:**
- `path`: Path to save the configuration file

**Returns:**
- `Result<()>`: Success or an error

**Errors:**
- `ProtocolError::ConfigError`: If the file cannot be written

### ServerConfig

Server-specific configuration settings, used by `service::daemon`. The TLS daemon does not take a `ServerConfig`.

```rust
pub struct ServerConfig {
    pub address: String,
    pub backpressure_limit: usize,
    pub connection_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub shutdown_timeout: Duration,
    pub max_connections: usize,
}
```

**Fields:**
- `address`: Server listen address (default: "127.0.0.1:9000")
- `backpressure_limit`: Depth of each connection's message queue. When it is full, the server stops reading from that client until the queue drains (default: 32). Before 1.3.0 the queues were fixed at 32 whatever this was set to.
- `connection_timeout`: How long the server waits for each step of a client's handshake (default: 5s). An established session is not limited by it; it lasts until the client disconnects or the keep-alive finds it dead. In 1.2.x it closed every connection once it was older than this.
- `heartbeat_interval`: Interval for sending keep-alive pings (default: 15s). A client that sends nothing for 4 times this interval is treated as dead and disconnected.
- `shutdown_timeout`: How long a graceful shutdown waits for open connections to close (default: 30s)
- `max_connections`: Maximum number of concurrent connections (default: 1000). Connections accepted over the limit are closed immediately. Before 1.3.0 this was validated but not enforced.

### ClientConfig

Client-specific configuration settings, used by `service::client::Client`.

```rust
pub struct ClientConfig {
    pub address: String,
    pub connection_timeout: Duration,
    pub operation_timeout: Duration,
    pub response_timeout: Duration,
    pub heartbeat_interval: Duration,
    #[deprecated] pub auto_reconnect: bool,
    #[deprecated] pub max_reconnect_attempts: u32,
    #[deprecated] pub reconnect_delay: Duration,
}
```

**Fields:**
- `address`: Target server address (default: "127.0.0.1:9000")
- `connection_timeout`: Timeout for the TCP connect and for the server's handshake response (default: 5s)
- `operation_timeout`: Timeout for each `Client::send` (default: 3s). Before 1.3.0 it was not used. Receives keep their 5 second default.
- `response_timeout`: How long `Client::send_and_wait` waits for a reply (default: 30s)
- `heartbeat_interval`: Interval for keep-alive pings while waiting in `recv_with_keepalive` (default: 15s)
- `auto_reconnect`, `max_reconnect_attempts`, `reconnect_delay`: deprecated in 1.3.0. `Client` has never reconnected, whatever they are set to. Build the struct with `..Default::default()` to avoid deprecation warnings. They can be left out of a `[client]` TOML table.

### TransportConfig

Transport-specific configuration settings. Every field is deprecated in 1.3.0 because nothing reads them.

```rust
pub struct TransportConfig {
    #[deprecated] pub compression_enabled: bool,
    #[deprecated] pub encryption_enabled: bool,
    #[deprecated] pub max_payload_size: usize,
    #[deprecated] pub compression_level: i32,
    #[deprecated] pub compression_threshold_bytes: usize,
}
```

**Fields:**
- `compression_enabled`, `compression_level`, `compression_threshold_bytes`: not applied by any transport. Call `utils::compression` directly if you want compression.
- `encryption_enabled`: not applied. The built-in services always encrypt.
- `max_payload_size`: not applied. The packet codec always enforces `MAX_PAYLOAD_SIZE` (16 MiB).

All of them can be left out of a `[transport]` TOML table, or the table can be left out entirely.

### LoggingConfig

Logging-specific configuration settings. They are loaded and validated with the rest of `NetworkConfig`, but the library does not read them: `init_logging` takes a `utils::logging::LogConfig` (see [Logging](#logging)).

```rust
pub struct LoggingConfig {
    pub app_name: String,
    pub log_level: tracing::Level,
    pub log_to_console: bool,
    pub log_to_file: bool,
    pub log_file_path: Option<String>,
    pub json_format: bool,
}
```

**Fields:**
- `app_name`: Application name for logs (default: "network-protocol")
- `log_level`: Log level (default: INFO)
- `log_to_console`: Whether to log to console (default: true)
- `log_to_file`: Whether to log to file (default: false)
- `log_file_path`: Path to log file (if log_to_file is true)
- `json_format`: Whether to use JSON formatting for logs (default: false)

### Helper Modules

#### Duration Serialization

Helpers for serializing and deserializing `std::time::Duration` in milliseconds.

```rust
mod duration_serde {
    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
}
```

#### Log Level Serialization

Helpers for serializing and deserializing `tracing::Level` as strings.

```rust
mod log_level_serde {
    pub fn serialize<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
}
```

### Usage Example

```rust
use network_protocol::config::NetworkConfig;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::service::daemon;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from file
    let config = NetworkConfig::from_file("config.toml")?;

    // Or from environment variables
    // let config = NetworkConfig::from_env()?;

    config.validate_strict()?;

    let dispatcher = Arc::new(Dispatcher::new());
    dispatcher.register("PING", |_| Ok(Message::Pong))?;

    // Start server with configuration
    let mut server = daemon::start_daemon_no_signals(config.server.clone(), dispatcher).await?;

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    // Shut down gracefully
    server.shutdown().await?;

    Ok(())
}
```

### Example Configuration File

A complete example configuration file (`example_config.toml`) is available in the docs directory, demonstrating all available settings with their default values and comments. Its `[transport]` table and the reconnect settings in `[client]` are deprecated in 1.3.0 and have no effect.

#### Constants

```rust
// Protocol version - bump this when making breaking changes
pub const PROTOCOL_VERSION: u8 = 1;

// Magic bytes for identifying protocol packets ("NPRO")
pub const MAGIC_BYTES: [u8; 4] = [0x4E, 0x50, 0x52, 0x4F];

// Maximum size of a packet payload in bytes, enforced by the packet codec
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16MB

// Default values for the deprecated TransportConfig fields
pub const ENABLE_COMPRESSION: bool = false;
pub const ENABLE_ENCRYPTION: bool = true;
```

The codec checks a frame's header as soon as its 9 bytes arrive and rejects a declared payload over `MAX_PAYLOAD_SIZE` with `ProtocolError::OversizedPacket` before buffering it.




<!--
:: COPYRIGHT
============================================================================ -->
<div align="center">
  <br>
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2025 <strong>JAMES GOBER.</strong></sup>
</div>