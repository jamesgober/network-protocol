//! # Error Types
//!
//! Comprehensive error handling for the network protocol.
//!
//! This module defines all error variants that can occur during protocol operations,
//! from low-level I/O errors to high-level protocol violations.
//!
//! ## Error Categories
//! - **I/O Errors**: Network and file system failures
//! - **Protocol Errors**: Invalid packets, handshake failures, timeouts
//! - **Cryptographic Errors**: Encryption/decryption failures
//! - **TLS Errors**: Certificate and connection issues
//! - **Compression Errors**: Decompression failures, size limit violations
//!
//! All errors implement `std::error::Error` for interoperability.
//!
//! ## Example Usage
//! ```rust
//! use network_protocol::error::{ProtocolError, Result};
//! use std::fs::File;
//! use std::io::Read;
//! use tracing::{info, error};
//!
//! fn read_file(path: &str) -> Result<String> {
//!     let mut file = File::open(path).map_err(ProtocolError::Io)?;
//!     let mut contents = String::new();
//!     file.read_to_string(&mut contents).map_err(ProtocolError::Io)?;
//!     Ok(contents)
//! }
//!
//! fn main() {
//!     match read_file("example.txt") {
//!         Ok(contents) => info!(contents, "Successfully read file"),
//!         Err(e) => error!(error=%e, "Error reading file"),
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;

/// Error message constants to reduce allocations in error paths.
/// Static strings are borrowed, avoiding heap allocations for common error cases.
pub mod constants {
    /// Dispatcher-related error messages
    pub const ERR_DISPATCHER_WRITE_LOCK: &str = "Failed to acquire write lock on dispatcher";
    pub const ERR_DISPATCHER_READ_LOCK: &str = "Failed to acquire read lock on dispatcher";

    /// Protocol validation errors
    pub const ERR_INVALID_HEADER: &str = "Invalid protocol header";
    pub const ERR_INVALID_PACKET: &str = "Invalid packet structure";
    pub const ERR_OVERSIZED_PACKET: &str = "Packet exceeds maximum size";

    /// Connection errors
    pub const ERR_CONNECTION_CLOSED: &str = "Connection closed";
    pub const ERR_CONNECTION_TIMEOUT: &str = "Connection timed out (no activity)";
    pub const ERR_TIMEOUT: &str = "Operation timed out";

    /// Cryptographic errors
    pub const ERR_ENCRYPTION_FAILED: &str = "Encryption failed";
    pub const ERR_DECRYPTION_FAILED: &str = "Decryption failed";

    /// Compression errors
    pub const ERR_COMPRESSION_FAILED: &str = "Compression failed";
    pub const ERR_DECOMPRESSION_FAILED: &str = "Decompression failed";

    /// Protocol negotiation errors
    pub const ERR_UNSUPPORTED_VERSION: &str = "Unsupported protocol version";
    pub const ERR_HANDSHAKE_FAILED: &str = "Handshake failed";
    pub const ERR_UNEXPECTED_MESSAGE: &str = "Unexpected message type";

    /// Security errors
    pub const ERR_SECURITY_ERROR: &str = "Security violation detected";
    pub const ERR_LOCK_POISONED: &str = "Synchronization primitive poisoned";

    /// Handshake-specific errors
    pub const ERR_SYSTEM_TIME: &str = "System time error: time went backwards";
    pub const ERR_INVALID_TIMESTAMP: &str = "Invalid or stale timestamp";
    pub const ERR_REPLAY_ATTACK: &str = "Replay attack detected - nonce/timestamp already seen";
    pub const ERR_CLIENT_NONCE_NOT_FOUND: &str = "Client nonce not found";
    pub const ERR_SERVER_NONCE_NOT_FOUND: &str = "Server nonce not found";
    pub const ERR_CLIENT_SECRET_NOT_FOUND: &str = "Client secret not found";
    pub const ERR_SERVER_SECRET_NOT_FOUND: &str = "Server secret not found";
    pub const ERR_CLIENT_PUBLIC_NOT_FOUND: &str = "Client public key not found";
    pub const ERR_SERVER_PUBLIC_NOT_FOUND: &str = "Server public key not found";
    pub const ERR_NONCE_VERIFICATION_FAILED: &str = "Server failed to verify client nonce";
    pub const ERR_SERVER_VERIFICATION_FAILED: &str = "Client failed to verify server nonce";
}

// ProtocolError is the primary error type for all protocol operations
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

    #[error("Serialization error: {0}")]
    SerializationError(String),

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

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Custom error: {0}")]
    Custom(String),

    #[error("TLS error: {0}")]
    TlsError(String),
}

/// Type alias for Results using ProtocolError
pub type Result<T> = std::result::Result<T, ProtocolError>;
