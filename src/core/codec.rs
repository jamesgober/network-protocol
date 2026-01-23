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
    /// # Errors
    /// Returns `ProtocolError::InvalidPacket` if the packet data is malformed
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Packet>> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        let len = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) as usize;
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
    /// This method should never fail under normal conditions, but may return protocol errors
    /// if there are internal serialization issues
    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> Result<()> {
        // Calculate total size and reserve space in the buffer
        let total_size = HEADER_SIZE + packet.payload.len();
        dst.reserve(total_size);

        // Write header directly to buffer: magic bytes + version + length
        dst.put_slice(&crate::config::MAGIC_BYTES);
        dst.put_u8(crate::config::PROTOCOL_VERSION);
        dst.put_u32(packet.payload.len() as u32);

        // Write payload directly to buffer
        dst.put_slice(&packet.payload);

        Ok(())
    }
}
