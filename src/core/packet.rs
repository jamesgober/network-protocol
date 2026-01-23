//! # Packet
//!
//! This file is part of the Network Protocol project.
//!
//! It defines the `Packet` structure and handles all related serialization
//! and deserialization logic.
//!
//! The `Packet` struct represents a fully decoded protocol packet,
//! including the protocol version, magic header, and binary payload.
//!
//! This module uses the `bincode` crate for efficient binary encoding.
//! Protocol constants like `MAGIC_BYTES` and `PROTOCOL_VERSION` are defined
//! in the `config` module.
//!
//! ## Responsibilities
//! - Decode packets from raw byte buffers
//! - Encode `Packet` structs into raw bytes
//! - Validate protocol headers and versions
//!
//! The design is optimized for performance and integration with the rest
//! of the protocol layer.
use crate::config::{MAGIC_BYTES, MAX_PAYLOAD_SIZE, PROTOCOL_VERSION};
use crate::error::{ProtocolError, Result};

/// Total size of the fixed-length header
pub const HEADER_SIZE: usize = 9; // 4 magic + 1 version + 4 length

/// Represents a fully decoded protocol packet
#[derive(Debug)]
pub struct Packet {
    pub version: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Parse a packet from a raw buffer (header + body)
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::InvalidHeader);
        }

        if buf[0..4] != MAGIC_BYTES {
            return Err(ProtocolError::InvalidHeader);
        }

        let version = buf[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let length = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
        if length > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::OversizedPacket(length));
        }

        let payload = buf[HEADER_SIZE..].to_vec();
        Ok(Packet { version, payload })
    }

    /// Serialize a packet to a byte vector (header + body)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&MAGIC_BYTES);
        // Write the actual packet version from the struct, not the protocol constant
        out.push(self.version);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}
