//! # Codec
//!
//! This file is part of the Network Protocol project.
//!
//! It defines the codec for encoding and decoding protocol packets using the [`Packet`] struct.
//!
//! The codec is designed to work with the [`tokio`] framework for asynchronous I/O.
//! Specifically, the `PacketCodec` struct implements the [`Decoder`] and [`Encoder`] traits
//! from [`tokio_util::codec`].
//!
//! ## Responsibilities
//! - Decode packets from a byte stream
//! - Encode packets into a byte stream
//! - Handle fixed-length headers and variable-length payloads
//!
//! This module is essential for processing protocol packets in a networked environment,
//! ensuring correct parsing and serialization.
//!
//! It is designed to be efficient, minimal, and easy to integrate into the protocol layer.
//!

use crate::config::{MAGIC_BYTES, MAX_PAYLOAD_SIZE, PROTOCOL_VERSION};
use crate::core::packet::{Packet, HEADER_SIZE};
use crate::error::{ProtocolError, Result};
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
//use futures::StreamExt;

pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = ProtocolError;

    /// Decodes a packet from the byte stream
    ///
    /// Returns `None` if there aren't enough bytes to form a complete packet.
    ///
    /// The header is validated as soon as its 9 bytes have arrived, before any of
    /// the payload is buffered, so a peer cannot make the connection hold a frame
    /// larger than `MAX_PAYLOAD_SIZE` or one with a bad magic or version.
    ///
    /// # Errors
    /// Returns `ProtocolError::InvalidHeader` for a wrong magic,
    /// `ProtocolError::UnsupportedVersion` for an unknown version, and
    /// `ProtocolError::OversizedPacket` for a declared length over
    /// `MAX_PAYLOAD_SIZE`.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Packet>> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        if src[0..4] != MAGIC_BYTES {
            return Err(ProtocolError::InvalidHeader);
        }
        if src[4] != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(src[4]));
        }
        let len = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) as usize;
        if len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::OversizedPacket(len));
        }
        let total_len = HEADER_SIZE + len;

        if src.len() < total_len {
            return Ok(None); // Wait for full frame
        }

        let buf = src.split_to(total_len).freeze();
        Packet::from_bytes(&buf).map(Some)
    }
}

impl Encoder<Packet> for PacketCodec {
    type Error = ProtocolError;

    /// Encodes a packet into the byte stream
    ///
    /// # Errors
    /// Returns `ProtocolError::OversizedPacket` if the payload is larger than
    /// `MAX_PAYLOAD_SIZE`, which the receiving side would reject.
    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> Result<()> {
        if packet.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::OversizedPacket(packet.payload.len()));
        }

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn header(magic: [u8; 4], version: u8, len: u32) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_slice(&magic);
        buf.put_u8(version);
        buf.put_u32(len);
        buf
    }

    #[test]
    fn oversized_length_is_rejected_from_the_header_alone() {
        let mut buf = header(MAGIC_BYTES, PROTOCOL_VERSION, (MAX_PAYLOAD_SIZE + 1) as u32);
        assert!(matches!(
            PacketCodec.decode(&mut buf),
            Err(ProtocolError::OversizedPacket(_))
        ));
        let mut buf = header(MAGIC_BYTES, PROTOCOL_VERSION, u32::MAX);
        assert!(matches!(
            PacketCodec.decode(&mut buf),
            Err(ProtocolError::OversizedPacket(_))
        ));
    }

    #[test]
    fn bad_magic_or_version_is_rejected_from_the_header_alone() {
        let mut buf = header(*b"HTTP", PROTOCOL_VERSION, 4);
        assert!(matches!(
            PacketCodec.decode(&mut buf),
            Err(ProtocolError::InvalidHeader)
        ));
        let mut buf = header(MAGIC_BYTES, PROTOCOL_VERSION.wrapping_add(1), 4);
        assert!(matches!(
            PacketCodec.decode(&mut buf),
            Err(ProtocolError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn valid_header_waits_for_the_payload() {
        let mut buf = header(MAGIC_BYTES, PROTOCOL_VERSION, 4);
        assert!(PacketCodec.decode(&mut buf).unwrap().is_none());
        buf.put_slice(b"ping");
        let packet = PacketCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(packet.payload, b"ping");
        assert!(buf.is_empty());
    }

    #[test]
    fn largest_allowed_payload_round_trips_and_larger_is_not_sent() {
        let mut buf = BytesMut::new();
        let packet = Packet {
            version: PROTOCOL_VERSION,
            payload: vec![7u8; MAX_PAYLOAD_SIZE],
        };
        PacketCodec.encode(packet, &mut buf).unwrap();
        let decoded = PacketCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), MAX_PAYLOAD_SIZE);

        let mut buf = BytesMut::new();
        let too_big = Packet {
            version: PROTOCOL_VERSION,
            payload: vec![0u8; MAX_PAYLOAD_SIZE + 1],
        };
        assert!(matches!(
            PacketCodec.encode(too_big, &mut buf),
            Err(ProtocolError::OversizedPacket(_))
        ));
        assert!(buf.is_empty(), "nothing is written for a rejected packet");
    }
}
