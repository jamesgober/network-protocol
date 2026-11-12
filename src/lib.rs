//! # Network Protocol
//! This file is part of the Network Protocol project.
//!
//! It provides the main entry point for the protocol layer,
//! including the core components, transport mechanisms,
//! and utility functions.
//!
//! The protocol is designed to be modular, high-performance,
//! and suitable for local, remote, and cluster communication.
//!
//! The main components include:
//! - Core: packet handling, codec, error management
//! - Transport: network communication, remote operations
//! - Protocol: message routing, handshake logic
//! - Service: client and daemon abstractions
//! - Utils: cryptography, compression, time management
//!
//! The protocol layer is built with a focus on performance,
//! scalability, and ease of integration with other systems.
//!
//! # Security
//!
//! **Use the built-in encrypted transport only inside TLS.** The built-in
//! handshake ([`protocol::handshake`]: an X25519 key exchange, then
//! ChaCha20-Poly1305) authenticates neither side, and it has no replay
//! protection. It does not protect traffic from anyone who can intercept,
//! change, or replay it on the network path. Use it only inside an
//! authenticated TLS channel ([`transport::tls`] with certificate verification
//! on), and never on its own across a network you do not trust. The default
//! [`service::client::Client`] and [`service::daemon`] paths use that
//! handshake. An authenticated key exchange with replay protection is planned
//! for 2.0.
pub mod config;
pub mod core;
pub mod error;

pub mod protocol; // message + handshake routing
pub mod service; // client/daemon abstraction
pub mod transport; // will add files shortly
pub mod utils; // crypto/compression/time/etc

pub use config::*;
pub use core::codec::PacketCodec;
pub use core::packet::Packet;
pub use core::serialization::{MultiFormat, SerializationFormat};
pub use error::*;
pub use transport::session_cache::SessionCache;
pub use utils::ReplayCache;

/// Initialize the library with default logging configuration.
/// This should be called early in your application setup.
pub fn init() {
    utils::logging::setup_default_logging();
}

/// Initialize the library with custom logging configuration.
///
/// # Example
/// ```
/// use network_protocol::{init_with_config, utils::logging::LogConfig};
/// use tracing::Level;
///
/// let config = LogConfig {
///    app_name: "my-application".to_string(),
///    log_level: Level::DEBUG,
///    ..Default::default()
/// };
///
/// init_with_config(&config);
/// ```
pub fn init_with_config(log_config: &utils::logging::LogConfig) {
    utils::logging::init_logging(log_config);
}
