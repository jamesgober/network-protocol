//! # Error
//!
//! This file is part of the Network Protocol project.
//!
//! It defines the error types used throughout the protocol layer.
//!
//! This module provides a unified error handling mechanism for the network protocol,
//! encapsulating various error scenarios such as I/O errors, serialization issues,
//! and protocol-specific logic failures.
//!
//! It uses the `thiserror` crate for ergonomic error definition.
//!
//! A custom `Result<T>` alias is provided to simplify signatures across the protocol stack.
//!
//! The `ProtocolError` enum includes variants for:
//! - Invalid headers
//! - Unsupported protocol versions
//! - Oversized packets
//! - Encryption/decryption failures
//! - I/O and serialization errors
//!
//! # Example Usage
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

pub type Result<T> = std::result::Result<T, ProtocolError>;

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
