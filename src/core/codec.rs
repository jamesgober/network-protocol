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

use tokio_util::codec::{Decoder, Encoder};
use bytes::{BytesMut, BufMut};
use crate::core::packet::{Packet, HEADER_SIZE};
use crate::error::{Result, ProtocolError};
//use futures::StreamExt;

pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = ProtocolError;

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

    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> Result<()> {
        let encoded = packet.to_bytes();
        dst.reserve(encoded.len());
        dst.put_slice(&encoded);
        Ok(())
    }
}