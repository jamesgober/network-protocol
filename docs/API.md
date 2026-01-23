<div align="center">
    <img width="120px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
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
  - [Secure Connection](#secure-connection)
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
backpressure_limit = 32
connection_timeout = 5000    # milliseconds
heartbeat_interval = 15000   # milliseconds

# Client-specific configuration
[client]
address = "127.0.0.1:9000"
connection_timeout = 5000    # milliseconds
response_timeout = 30000     # milliseconds

# Transport configuration
[transport]
compression_enabled = false
encryption_enabled = true

# Logging configuration
[logging]
app_name = "my-application"
log_level = "info"           # options: trace, debug, info, warn, error
log_to_console = true
```

Load the configuration in your code:

```rust
use network_protocol::config::Config;

async fn main() -> Result<()> {
    // Load from a specific file path
    let config = Config::from_file("path/to/config.toml").await?;
    
    // Or load from the default location
    let config = Config::load().await?;
    
    // Access configuration values
    let server_addr = config.server.address.clone();
    println!("Server will bind to: {}", server_addr);
}
```

#### Using Environment Variables

Environment variables override corresponding TOML settings, following this naming pattern:

```
NP_SECTION_KEY=value
```

For example:

```bash
# Override server address
export NP_SERVER_ADDRESS="0.0.0.0:8080"

# Override logging level
export NP_LOGGING_LOG_LEVEL="debug"

# Override client timeout
export NP_CLIENT_CONNECTION_TIMEOUT="10000"
```

### Server Setup

Create a basic server with default configuration:

```rust
use network_protocol::service::daemon::Daemon;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a dispatcher for handling messages
    let dispatcher = Arc::new(Dispatcher::new());
    
    // Register message handlers
    dispatcher.register("PING", |_| Ok(Message::Pong))?;
    dispatcher.register("ECHO", |msg| {
        match msg {
            Message::Echo(s) => Ok(Message::Echo(s.clone())),
            _ => Ok(Message::Unknown),
        }
    })?;
    
    // Start the server with default config
    let daemon = Daemon::new(dispatcher);
    daemon.start().await?
}
```

With custom configuration:

```rust
use network_protocol::config::Config;
use network_protocol::service::daemon::Daemon;

async fn main() -> Result<()> {
    // Load configuration
    let config = Config::load().await?;
    
    // Create and start daemon with custom config
    let daemon = Daemon::with_config(dispatcher, config);
    daemon.start().await?
}
```

### Client Setup

Create a client and communicate with a server:

```rust
use network_protocol::service::client::Client;
use network_protocol::protocol::message::Message;

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to server with default configuration
    let mut client = Client::connect("127.0.0.1:9000").await?;
    
    // Send a ping message
    let response = client.send(Message::Ping).await?;
    
    // Check the response
    match response {
        Message::Pong => println!("Server responded with pong"),
        _ => println!("Unexpected response: {:?}", response),
    }
    
    // Send an echo message
    let response = client.send(Message::Echo("Hello, server!".to_string())).await?;
    println!("Echo response: {:?}", response);
    
    // Disconnect gracefully
    client.disconnect().await?
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

Secure your connections with TLS:

```rust
use network_protocol::transport::tls;
use network_protocol::transport::tls::{TlsConfig, TlsClientConfig};

// TLS Server
async fn start_tls_server() -> Result<()> {
    let config = TlsConfig {
        cert_path: "certs/server.crt",
        key_path: "certs/server.key",
        ca_path: Some("certs/ca.crt"),  // For client cert validation
        verify_client: true,             // Enable mTLS
    };
    
    tls::start_server("127.0.0.1:8443", config).await
}

// TLS Client
async fn connect_to_tls_server() -> Result<()> {
    let config = TlsClientConfig {
        cert_path: Some("certs/client.crt"),  // For mTLS
        key_path: Some("certs/client.key"),   // For mTLS
        ca_path: Some("certs/ca.crt"),        // To validate server cert
        server_name: "example.com",           // SNI
    };
    
    let framed = tls::connect("127.0.0.1:8443", config).await?;
    // Use framed for sending/receiving packets
}
```

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
network-protocol = "1.0.1"
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

The TLS transport module provides functions for secure TLS-based network communication with certificate validation and mutual TLS support.

#### Structs

##### `TlsConfig`

```rust
pub struct TlsConfig {
    pub cert_path: &'static str,
    pub key_path: &'static str,
    pub ca_path: Option<&'static str>,
    pub verify_client: bool,
}
```

##### `TlsClientConfig`

```rust
pub struct TlsClientConfig {
    pub cert_path: Option<&'static str>,
    pub key_path: Option<&'static str>,
    pub ca_path: Option<&'static str>,
    pub server_name: &'static str,
}
```

#### Functions

##### `start_server`

Starts a TLS server at the given address with the specified TLS configuration.

```rust
pub async fn start_server(addr: &str, config: TlsConfig) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8443")
- `config`: The TLS configuration for the server

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::transport::tls;
use network_protocol::transport::tls::TlsConfig;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let config = TlsConfig {
        cert_path: "server.crt",
        key_path: "server.key",
        ca_path: Some("ca.crt"),   // For client cert validation (mTLS)
        verify_client: true,        // Enable mTLS
    };
    
    tls::start_server("127.0.0.1:8443", config).await
}
```

##### `connect`

Connects to a TLS server and returns a framed transport.

```rust
pub async fn connect(addr: &str, config: TlsClientConfig) -> Result<Framed<TlsStream<TcpStream>, PacketCodec>>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8443")
- `config`: The TLS client configuration

**Returns:**
- `Result<Framed<TlsStream<TcpStream>, PacketCodec>>`: A result containing either the framed connection or an error

**Example:**
```rust
use network_protocol::transport::tls;
use network_protocol::transport::tls::TlsClientConfig;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let config = TlsClientConfig {
        cert_path: Some("client.crt"),  // For mTLS
        key_path: Some("client.key"),   // For mTLS
        ca_path: Some("ca.crt"),        // For server cert validation
        server_name: "example.com",     // Server Name Indication
    };
    
    let framed = tls::connect("127.0.0.1:8443", config).await?;
    println!("Connected to TLS server!");
    Ok(())
}
```

##### `generate_self_signed_cert`

Generates a self-signed certificate and private key for development purposes.

```rust
pub fn generate_self_signed_cert(
    common_name: &str,
    cert_path: &Path,
    key_path: &Path
) -> Result<()>
```

**Parameters:**
- `common_name`: The common name for the certificate (e.g., "localhost")
- `cert_path`: The path to save the certificate to
- `key_path`: The path to save the private key to

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::transport::tls;
use std::path::Path;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    // Generate a self-signed certificate for development
    tls::generate_self_signed_cert(
        "localhost",
        Path::new("dev_cert.pem"),
        Path::new("dev_key.pem")
    )?;
    
    println!("Generated self-signed certificate");
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

The handshake module provides functions for performing secure handshakes between client and server using Elliptic Curve Diffie-Hellman (ECDH) key exchange. It offers strong security guarantees including forward secrecy, protection against replay attacks, and man-in-the-middle attack prevention.

#### Secure ECDH Handshake

##### `client_secure_handshake_init`

Initiates a secure handshake from the client side by generating an ephemeral key pair, timestamp, and nonce.

```rust
pub fn client_secure_handshake_init() -> Result<Message>
```

**Returns:**
- `Result<Message>`: A `SecureHandshakeInit` message containing:
  - The client's public key as a 32-byte array
  - Current timestamp to prevent replay attacks
  - A cryptographically secure random 16-byte nonce

**Notes:**
- Internally stores the client's ephemeral secret and nonce in thread-safe storage
- Returns an error if the thread-safe storage can't be accessed

##### `server_secure_handshake_response`

Processes a client's handshake initialization and generates a response.

```rust
pub fn server_secure_handshake_response(
    client_pub_key: [u8; 32], 
    client_nonce: [u8; 16], 
    client_timestamp: u64
) -> Result<Message>
```

**Parameters:**
- `client_pub_key`: The client's public key as a 32-byte array
- `client_nonce`: The client's random nonce as a 16-byte array
- `client_timestamp`: The client's timestamp (milliseconds since epoch)

**Returns:**
- `Result<Message>`: A `SecureHandshakeResponse` message containing:
  - The server's public key as a 32-byte array
  - A new server-generated 16-byte nonce
  - A SHA-256 hash of the client's nonce for verification

**Errors:**
- Returns `ProtocolError::HandshakeError` if the timestamp is invalid (too old or from the future)
- Returns `ProtocolError::HandshakeError` if the thread-safe storage can't be accessed

##### `client_secure_handshake_verify`

Verifies the server's handshake response and creates a confirmation message.

```rust
pub fn client_secure_handshake_verify(
    server_pub_key: [u8; 32], 
    server_nonce: [u8; 16], 
    nonce_verification: [u8; 32]
) -> Result<Message>
```

**Parameters:**
- `server_pub_key`: The server's public key as a 32-byte array
- `server_nonce`: The server's random nonce as a 16-byte array
- `nonce_verification`: SHA-256 hash of the client's nonce

**Returns:**
- `Result<Message>`: A `SecureHandshakeConfirm` message containing a SHA-256 hash of the server's nonce

**Errors:**
- Returns `ProtocolError::HandshakeError` if the server's verification of the client nonce fails
- Returns `ProtocolError::HandshakeError` if the thread-safe storage can't be accessed
- Returns `ProtocolError::HandshakeError` if the client nonce isn't found in storage

##### `server_secure_handshake_finalize`

Finalizes the handshake process on the server side and derives the session key.

```rust
pub fn server_secure_handshake_finalize(nonce_verification: [u8; 32]) -> Result<[u8; 32]>
```

**Parameters:**
- `nonce_verification`: SHA-256 hash of the server's nonce received from client

**Returns:**
- `Result<[u8; 32]>`: A 32-byte session key derived from the shared secret and both nonces

**Errors:**
- Returns `ProtocolError::HandshakeError` if client's verification of the server nonce fails
- Returns `ProtocolError::HandshakeError` if any required data is missing from storage

##### `client_derive_session_key`

Derives the session key on the client side after a successful handshake.

```rust
pub fn client_derive_session_key() -> Result<[u8; 32]>
```

**Returns:**
- `Result<[u8; 32]>`: A 32-byte session key derived from the shared secret and both nonces

**Errors:**
- Returns `ProtocolError::HandshakeError` if any required data is missing from storage

##### `clear_handshake_data`

Clears all sensitive handshake data from memory, including ephemeral keys and nonces.

```rust
pub fn clear_handshake_data() -> Result<()>
```

**Returns:**
- `Result<()>`: Success or an error if clearing fails

**Errors:**
- Returns `ProtocolError::HandshakeError` if the thread-safe storage can't be accessed

#### Security Features

- **Forward Secrecy**: Uses ephemeral x25519 keys that are discarded after session establishment
- **Anti-Replay Protection**: Validates timestamps to prevent replay attacks (30-second threshold)
- **Cryptographic Nonces**: Uses secure random nonces to prevent replay and ensure unique sessions
- **Man-in-the-Middle Protection**: Full key verification through double-sided nonce verification
- **Session Key Derivation**: Combines shared secret with client and server nonces using SHA-256
- **Thread-Safety**: All handshake state is stored in thread-safe containers using `Mutex`

**Example:**
```rust
use network_protocol::protocol::handshake;
use network_protocol::protocol::message::Message;
use network_protocol::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Client initiates handshake
    let init_msg = handshake::client_secure_handshake_init()?;
    
    // In a real application, this message would be sent over the network
    // Here we extract the values directly for demonstration
    let (client_pub_key, client_nonce, client_timestamp) = match &init_msg {
        Message::SecureHandshakeInit { pub_key, timestamp, nonce } => {
            (*pub_key, *nonce, *timestamp)
        },
        _ => panic!("Unexpected message type"),
    };
    
    // Server processes handshake initiation
    let response_msg = handshake::server_secure_handshake_response(
        client_pub_key,
        client_nonce,
        client_timestamp
    )?;
    
    // Extract server's response data
    let (server_pub_key, server_nonce, nonce_verification) = match &response_msg {
        Message::SecureHandshakeResponse { pub_key, nonce, nonce_verification } => {
            (*pub_key, *nonce, *nonce_verification)
        },
        _ => panic!("Unexpected message type"),
    };
    
    // Client verifies server response
    let confirm_msg = handshake::client_secure_handshake_verify(
        server_pub_key,
        server_nonce,
        nonce_verification
    )?;
    
    // Extract confirmation data
    let client_verification = match &confirm_msg {
        Message::SecureHandshakeConfirm { nonce_verification } => {
            *nonce_verification
        },
        _ => panic!("Unexpected message type"),
    };
    
    // Server finalizes handshake and gets session key
    let server_session_key = handshake::server_secure_handshake_finalize(client_verification)?;
    
    // Client derives the same session key
    let client_session_key = handshake::client_derive_session_key()?;
    
    // At this point, both sides have the same session key
    // In a real application, you would verify this with assert_eq!(client_session_key, server_session_key);
    
    // Clean up sensitive data
    handshake::clear_handshake_data()?;
    
    Ok(())
}

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

The client module provides functionality for establishing secure connections to servers with support for timeouts, auto-reconnection, and graceful shutdown.

#### Struct Definition

```rust
pub struct Client {
    framed: FramedConnection,
    secure: SecureConnection,
}
```

#### Methods

##### `connect_tcp` and `connect_with_config`

Connects to a remote TCP server with secure communication.

```rust
pub async fn connect_tcp(addr: &str) -> Result<Self>
pub async fn connect_with_config(config: ClientConfig) -> Result<Self>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8080")
- `config`: Client configuration including timeouts and reconnection settings

**Returns:**
- `Result<Client>`: A result containing either a connected client or an error

##### `connect_uds`

Connects to a Unix domain socket server with secure communication.

```rust
pub async fn connect_uds<P: AsRef<Path>>(path: P) -> Result<Self>
```

**Parameters:**
- `path`: The path to the Unix domain socket

**Returns:**
- `Result<Client>`: A result containing either a connected client or an error

##### `send`

Sends a message to the server.

```rust
pub async fn send(&mut self, msg: Message) -> Result<()>
```

**Parameters:**
- `msg`: The message to send

**Returns:**
- `Result<()>`: A result indicating success or an error

##### `receive`

Receives a message from the server.

```rust
pub async fn receive(&mut self) -> Result<Message>
```

**Returns:**
- `Result<Message>`: A result containing either the received message or an error

##### `close`

Closes the connection to the server.

```rust
pub async fn close(&mut self) -> Result<()>
```

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example with Timeout Handling:**
```rust
use network_protocol::utils::logging;
use network_protocol::service::client::{self, ClientConfig};
use network_protocol::protocol::message::Message;
use network_protocol::error::ProtocolError;
use std::time::Duration;
use tracing::{info, error};
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), ProtocolError> {
    // Initialize structured logging
    logging::init_logging(Some("info"), None)?;
    
    // Configure client with timeouts and reconnection settings
    let config = ClientConfig {
        address: "127.0.0.1:9000".to_string(),
        connection_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(3),
        auto_reconnect: true,
        max_reconnect_attempts: 3,
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
    let msg = Message::Echo("hello".into());
    match timeout(Duration::from_secs(3), conn.send(msg)).await {
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
    
    // Close connection gracefully
    conn.close().await
}
```

### Daemon

The daemon module provides functionality for running a server that accepts client connections with support for backpressure control, timeouts, heartbeats, and graceful shutdown.

#### Functions

##### `new` and `new_with_config`

Creates a new server daemon with graceful shutdown support.

```rust
pub fn new(addr: &str, dispatcher: Arc<dyn MessageDispatcher>) -> ServerHandle
pub fn new_with_config(config: ServerConfig, dispatcher: Arc<dyn MessageDispatcher>) -> ServerHandle
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8080")
- `config`: Server configuration including backpressure and timeout settings
- `dispatcher`: The message dispatcher to use for handling messages

**Returns:**
- `ServerHandle`: A handle to control the server, including shutdown

##### `run`

Runs the server until it is shut down.

```rust
pub async fn run(&self) -> Result<()>
```

**Returns:**
- `Result<()>`: A result indicating success or an error when calling `run()`

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8080")
- `dispatcher`: The message dispatcher to use for handling messages

**Returns:**
- `ServerHandle`: A handle to control the server, including shutdown
- `Result<()>`: A result indicating success or an error when calling `run()`

#### Structs

##### `ServerHandle`

```rust
pub struct ServerHandle {
    // internal fields omitted
}
```

#### Methods

##### `ServerHandle::clone`

Clones the server handle for use in another thread.

```rust
pub fn clone(&self) -> Self
```

**Returns:**
- `ServerHandle`: A new handle to the same server

##### `ServerHandle::shutdown`

Initiates a graceful shutdown of the server.

```rust
pub async fn shutdown(&self, timeout: Option<Duration>)
```

**Parameters:**
- `timeout`: Optional maximum duration to wait for connections to close before forcing shutdown

**Example with Backpressure and Timeouts:**
```rust
use network_protocol::service::daemon::{self, ServerConfig};
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::utils::logging;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging
    logging::init_logging(Some("info"), None).expect("Failed to initialize logging");
    
    let dispatcher = Arc::new(Dispatcher::default());
    
    // Configure server with backpressure settings
    let config = ServerConfig {
        address: "127.0.0.1:9000".to_string(),
        backpressure_limit: 100, // Limit pending messages
        connection_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_secs(15),
        shutdown_timeout: Duration::from_secs(10),
    };
    
    // Start server with configuration
    let server = daemon::new_with_config(config, dispatcher);
    
    // Handle Ctrl+C for graceful shutdown
    let server_clone = server.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        info!("Initiating graceful shutdown...");
        server_clone.shutdown(Some(Duration::from_secs(10))).await;
    });
    
    // Run server until stopped
    info!("Server starting on 127.0.0.1:9000");
    server.run().await
}
```

**Example:**
```rust
use network_protocol::service::daemon;
use network_protocol::protocol::dispatcher::EchoDispatcher;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let dispatcher = Arc::new(EchoDispatcher::new());
    
    // Create server with handle for shutdown
    let server = daemon::new("127.0.0.1:8080", dispatcher);
    
    // Set up graceful shutdown on Ctrl+C
    let server_clone = server.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        println!("Shutting down gracefully...");
        // Wait up to 10 seconds for connections to close
        server_clone.shutdown(Some(Duration::from_secs(10))).await;
    });
    
    // Run server until shutdown is called
    server.run().await?;
    println!("Server has shut down successfully");
    Ok(())
}
```

##### `run_uds_server`

Runs a Unix domain socket server with the provided dispatcher.

```rust
pub async fn run_uds_server<P: AsRef<Path>>(path: P, dispatcher: Arc<Dispatcher>) -> Result<()>
```

**Parameters:**
- `path`: The path to the Unix domain socket
- `dispatcher`: An Arc-wrapped dispatcher for handling incoming messages

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::service::daemon;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use std::sync::Arc;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    // Create a dispatcher
    let dispatcher = Arc::new(Dispatcher::new());
    
    // Register handlers
    let dispatcher_clone = Arc::clone(&dispatcher);
    dispatcher_clone.register("PING", |_| Ok(Message::Pong));
    dispatcher_clone.register("ECHO", |msg| {
        match msg {
            Message::Echo(s) => Ok(Message::Echo(s.clone())),
            _ => Ok(Message::Unknown),
        }
    });
    
    // Run the server
    println!("Starting server on 127.0.0.1:8080");
    daemon::run_tcp_server("127.0.0.1:8080", dispatcher).await
}
```

### TLS Daemon

The TLS daemon module provides functionality for running a TLS-secured server that accepts client connections with certificate validation.

#### Functions

##### `start`

Starts a TLS server with the provided configuration and message dispatcher.

```rust
pub async fn start(addr: &str, tls_config: TlsConfig) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8443")
- `tls_config`: The TLS configuration for the server

**Returns:**
- `Result<()>`: A result indicating success or an error

##### `new` and `run`

Creates and runs a new TLS server daemon with graceful shutdown support.

```rust
pub fn new(addr: &str, tls_config: TlsConfig, dispatcher: Arc<dyn MessageDispatcher>) -> ServerHandle
pub async fn run(&self) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8443")
- `tls_config`: The TLS configuration for the server
- `dispatcher`: The message dispatcher to use for handling messages

**Returns:**
- `ServerHandle`: A handle to control the server, including shutdown
- `Result<()>`: A result indicating success or an error when calling `run()`

**Example:**
```rust
use network_protocol::service::tls_daemon;
use network_protocol::transport::tls::TlsConfig;
use network_protocol::protocol::dispatcher::EchoDispatcher;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let dispatcher = Arc::new(EchoDispatcher::new());
    
    let tls_config = TlsConfig {
        cert_path: "server.crt",
        key_path: "server.key",
        ca_path: Some("ca.crt"),   // For client cert validation
        verify_client: true,        // Enable mTLS
    };
    
    // Create TLS server with handle for shutdown
    let server = tls_daemon::new("127.0.0.1:8443", tls_config, dispatcher);
    
    // Set up graceful shutdown on Ctrl+C
    let server_clone = server.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        println!("Shutting down TLS server gracefully...");
        server_clone.shutdown(Some(Duration::from_secs(10))).await;
    });
    
    // Run server until shutdown is called
    server.run().await?;
    println!("TLS Server has shut down successfully");
    Ok(())
}
```

### Secure Connection

The secure connection module provides encryption and decryption capabilities for network communications.

#### Struct Definition

```rust
pub struct SecureConnection {
    key: [u8; 32],
    cipher: XChaCha20Poly1305,
    compress: bool,
}
```

#### Methods

##### `new`

Creates a new secure connection with the given key.

```rust
pub fn new(key: [u8; 32], compress: bool) -> Result<Self>
```

**Parameters:**
- `key`: The 32-byte encryption key
- `compress`: Whether to enable compression

**Returns:**
- `Result<SecureConnection>`: A result containing either the secure connection or an error

##### `encrypt`

Encrypts a message using the established key.

```rust
pub fn encrypt(&self, msg: &Message) -> Result<Vec<u8>>
```

**Parameters:**
- `msg`: The message to encrypt

**Returns:**
- `Result<Vec<u8>>`: A result containing either the encrypted message as bytes or an error

##### `decrypt`

Decrypts a message using the established key.

```rust
pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Message>
```

**Parameters:**
- `ciphertext`: The encrypted message bytes to decrypt

**Returns:**
- `Result<Message>`: A result containing either the decrypted message or an error

**Example:**
```rust
use network_protocol::service::secure::SecureConnection;
use network_protocol::protocol::message::Message;
use network_protocol::protocol::handshake;

// Establish a shared key (in a real scenario, this would be via handshake)
let client_nonce = 12345678;
let key = handshake::derive_shared_key(client_nonce);

// Create a secure connection
let secure_conn = SecureConnection::new(key, true).unwrap();

// Encrypt a message
let message = Message::Echo("Secret message".to_string());
let encrypted = secure_conn.encrypt(&message).unwrap();

// Decrypt the message
let decrypted = secure_conn.decrypt(&encrypted).unwrap();
if let Message::Echo(text) = decrypted {
    println!("Decrypted message: {}", text);
}
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

### Functions

##### `init_logging`

Initializes structured logging with configurable log level.

```rust
pub fn init_logging(log_level: Option<&str>, log_file: Option<&str>) -> Result<()>
```

**Parameters:**
- `log_level`: Optional string representation of the log level ("trace", "debug", "info", "warn", "error")
- `log_file`: Optional file path to write logs to

**Returns:**
- `Result<()>`: Success or error if logging initialization fails

**Example:**
```rust
use network_protocol::utils::logging;
use tracing::{info, debug, error};

fn main() -> Result<()> {
    // Initialize with INFO level and no log file (stdout only)
    logging::init_logging(Some("info"), None)?;
    
    // Log various events with different levels
    debug!("This is a debug message with a value: {}", 42);
    info!(user = "admin", action = "login", "User logged in successfully");
    error!(error_code = 500, message = "Database connection failed");
    
    Ok(())
}
```

##### `get_subscriber`

Creates a tracing subscriber with the specified configuration.

```rust
pub fn get_subscriber(log_level: String, sink: impl Sink<String> + Send + Sync + 'static) -> impl Subscriber + Send + Sync
```

**Parameters:**
- `log_level`: String representation of the log level
- `sink`: Where to send the log output

**Returns:**
- A tracing subscriber configured with the specified settings

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
    cfg.transport.compression_enabled = true;
});
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

Server-specific configuration settings.

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
- `address`: Server listen address (e.g., "127.0.0.1:9000")
- `backpressure_limit`: Maximum number of messages in the queue (default: 32)
- `connection_timeout`: Timeout for client connections
- `heartbeat_interval`: Interval for sending heartbeat messages
- `shutdown_timeout`: Timeout for graceful server shutdown
- `max_connections`: Maximum number of concurrent connections (default: 1000)

### ClientConfig

Client-specific configuration settings.

```rust
pub struct ClientConfig {
    pub address: String,
    pub connection_timeout: Duration,
    pub operation_timeout: Duration,
    pub response_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
    pub reconnect_delay: Duration,
}
```

**Fields:**
- `address`: Target server address (e.g., "127.0.0.1:9000")
- `connection_timeout`: Timeout for connection attempts
- `operation_timeout`: Timeout for individual operations (default: 3s)
- `response_timeout`: Timeout for waiting for response messages (default: 30s)
- `heartbeat_interval`: Interval for sending heartbeat messages
- `auto_reconnect`: Whether to automatically reconnect (default: true)
- `max_reconnect_attempts`: Maximum reconnect attempts (default: 3)
- `reconnect_delay`: Delay between reconnect attempts (default: 1s)

### TransportConfig

Transport-specific configuration settings.

```rust
pub struct TransportConfig {
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub max_payload_size: usize,
    pub compression_level: i32,
}
```

**Fields:**
- `compression_enabled`: Whether to enable compression (default: false)
- `encryption_enabled`: Whether to enable encryption (default: true)
- `max_payload_size`: Maximum allowed payload size (default: 16MB)
- `compression_level`: Compression level when enabled (default: 6)

### LoggingConfig

Logging-specific configuration settings.

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
use network_protocol::service::daemon::Daemon;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    // Load configuration from file
    let config = NetworkConfig::from_file("config.toml")?;
    
    // Or from environment variables
    // let config = NetworkConfig::from_env()?;
    
    // Start server with configuration
    let daemon = Daemon::start_with_config(config.server.clone()).await?;
    
    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    
    // Shut down gracefully
    daemon.shutdown().await?;
    
    Ok(())
}
```

### Example Configuration File

A complete example configuration file (`example_config.toml`) is available in the docs directory, demonstrating all available settings with their default values and comments.

#### Constants

```rust
// Protocol version - bump this when making breaking changes
pub const PROTOCOL_VERSION: u8 = 1;

// Magic bytes for identifying protocol packets ("NPRO")
pub const MAGIC_BYTES: [u8; 4] = [0x4E, 0x50, 0x52, 0x4F];

// Maximum size of a packet payload in bytes
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16MB

// Default settings
pub const DEFAULT_COMPRESSION_ENABLED: bool = true;
pub const DEFAULT_ENCRYPTION_ENABLED: bool = true;
```




<!--
:: COPYRIGHT
============================================================================ -->
<div align="center">
  <br>
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2025 <strong>JAMES GOBER.</strong></sup>
</div>