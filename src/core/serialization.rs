//! # Serialization Formats
//!
//! This module provides abstraction over multiple serialization formats for protocol messages.
//! Supports bincode (default), JSON (debugging/interop), and MessagePack (compact encoding).
//!
//! ## Features
//! - **Multiple formats**: Bincode, JSON, MessagePack with automatic format detection
//! - **Zero-copy where possible**: Direct byte manipulation for performance-critical paths
//! - **Format metadata**: Optional format byte prefix for automatic detection
//! - **Human-readable options**: JSON with pretty-printing for debugging
//! - **Compact encoding**: MessagePack for bandwidth-constrained scenarios
//!
//! ## Performance Characteristics
//! - **Bincode**: ~100-200ns (fastest, binary)
//! - **MessagePack**: ~150-300ns (compact, binary)
//! - **JSON**: ~500-1000ns (human-readable, text)
//!
//! ## Usage
//! ```ignore
//! use network_protocol::codec::SerializationFormat;
//!
//! // Default bincode
//! let bytes = bincode::serialize(&message)?;
//!
//! // JSON for debugging
//! let json_bytes = serde_json::to_vec(&message)?;
//!
//! // MessagePack for compact encoding
//! let msgpack_bytes = rmp_serde::to_vec(&message)?;
//! ```

use serde::{Deserialize, Serialize};

/// Supported serialization formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SerializationFormat {
    /// Binary compact format (default, fastest)
    #[default]
    Bincode,
    /// Human-readable JSON format (debugging, interop)
    Json,
    /// Compact binary format (MessagePack, efficient)
    MessagePack,
}

impl SerializationFormat {
    /// Get the format identifier byte for wire protocol
    pub fn format_byte(self) -> u8 {
        match self {
            SerializationFormat::Bincode => 0x01,
            SerializationFormat::Json => 0x02,
            SerializationFormat::MessagePack => 0x03,
        }
    }

    /// Detect format from identifier byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(SerializationFormat::Bincode),
            0x02 => Some(SerializationFormat::Json),
            0x03 => Some(SerializationFormat::MessagePack),
            _ => None,
        }
    }

    /// Get human-readable name
    pub fn name(self) -> &'static str {
        match self {
            SerializationFormat::Bincode => "Bincode",
            SerializationFormat::Json => "JSON",
            SerializationFormat::MessagePack => "MessagePack",
        }
    }
}

/// Trait for types that support multiple serialization formats
pub trait MultiFormat: Serialize + for<'de> Deserialize<'de> + Sized {
    /// Serialize to bytes using the specified format
    fn serialize_format(&self, format: SerializationFormat) -> crate::error::Result<Vec<u8>> {
        match format {
            SerializationFormat::Bincode => bincode::serialize(self)
                .map_err(|e| crate::error::ProtocolError::SerializeError(e.to_string())),
            SerializationFormat::Json => serde_json::to_vec(self)
                .map_err(|e| crate::error::ProtocolError::SerializeError(e.to_string())),
            SerializationFormat::MessagePack => rmp_serde::to_vec(self)
                .map_err(|e| crate::error::ProtocolError::SerializeError(e.to_string())),
        }
    }

    /// Serialize to bytes with format header
    fn serialize_with_header(&self, format: SerializationFormat) -> crate::error::Result<Vec<u8>> {
        let mut data = vec![format.format_byte()];
        let mut payload = self.serialize_format(format)?;
        data.append(&mut payload);
        Ok(data)
    }

    /// Deserialize from bytes using the specified format
    fn deserialize_format(data: &[u8], format: SerializationFormat) -> crate::error::Result<Self> {
        match format {
            SerializationFormat::Bincode => bincode::deserialize(data)
                .map_err(|e| crate::error::ProtocolError::DeserializeError(e.to_string())),
            SerializationFormat::Json => serde_json::from_slice(data)
                .map_err(|e| crate::error::ProtocolError::DeserializeError(e.to_string())),
            SerializationFormat::MessagePack => rmp_serde::from_slice(data)
                .map_err(|e| crate::error::ProtocolError::DeserializeError(e.to_string())),
        }
    }

    /// Deserialize from bytes with format header
    fn deserialize_with_header(data: &[u8]) -> crate::error::Result<(Self, SerializationFormat)> {
        if data.is_empty() {
            return Err(crate::error::ProtocolError::DeserializeError(
                "Empty data".to_string(),
            ));
        }

        let format = SerializationFormat::from_byte(data[0]).ok_or_else(|| {
            crate::error::ProtocolError::DeserializeError(format!(
                "Unknown format byte: {}",
                data[0]
            ))
        })?;

        let value = Self::deserialize_format(&data[1..], format)?;
        Ok((value, format))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::Message;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_format_byte_roundtrip() {
        for format in &[
            SerializationFormat::Bincode,
            SerializationFormat::Json,
            SerializationFormat::MessagePack,
        ] {
            let byte = format.format_byte();
            let recovered = SerializationFormat::from_byte(byte).expect("valid format byte");
            assert_eq!(*format, recovered);
        }
    }

    #[test]
    fn test_format_names() {
        assert_eq!(SerializationFormat::Bincode.name(), "Bincode");
        assert_eq!(SerializationFormat::Json.name(), "JSON");
        assert_eq!(SerializationFormat::MessagePack.name(), "MessagePack");
    }

    #[test]
    fn test_default_format() {
        assert_eq!(SerializationFormat::default(), SerializationFormat::Bincode);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_bincode_serialization() {
        let msg = Message::Ping;
        let bytes = bincode::serialize(&msg).expect("serialize");
        let recovered: Message = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(msg, recovered);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_json_serialization() {
        let msg = Message::Ping;
        let bytes = serde_json::to_vec(&msg).expect("serialize");
        let recovered: Message = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(msg, recovered);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_messagepack_serialization() {
        let msg = Message::Ping;
        let bytes = rmp_serde::to_vec(&msg).expect("serialize");
        let recovered: Message = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(msg, recovered);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_format_sizes() {
        let msg = Message::Ping;

        let bincode_size = bincode::serialize(&msg).expect("bincode").len();
        let json_size = serde_json::to_vec(&msg).expect("json").len();
        let msgpack_size = rmp_serde::to_vec(&msg).expect("msgpack").len();

        println!("Bincode: {bincode_size} bytes");
        println!("JSON: {json_size} bytes");
        println!("MessagePack: {msgpack_size} bytes");

        // MessagePack should be more compact than JSON
        assert!(msgpack_size < json_size);
    }
}
