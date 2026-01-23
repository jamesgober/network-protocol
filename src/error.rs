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