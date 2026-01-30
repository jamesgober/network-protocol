//! Integration tests for zero-copy codec operations
//!
//! These tests validate the zero-copy characteristics of the packet codec,
//! ensuring efficient memory usage and minimal allocations.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use bytes::{Bytes, BytesMut};
use network_protocol::config::PROTOCOL_VERSION;
use network_protocol::core::codec::PacketCodec;
use network_protocol::core::packet::Packet;
use tokio_util::codec::{Decoder, Encoder};

#[test]
fn test_codec_decode_zero_copy_split() {
    let mut codec = PacketCodec;

    // Create a buffer with a complete packet
    let payload = vec![1, 2, 3, 4, 5];
    let packet = Packet {
        version: PROTOCOL_VERSION,
        payload,
    };
    let bytes = packet.to_bytes();

    // Wrap in BytesMut to test zero-copy split behavior
    let mut buffer = BytesMut::from(&bytes[..]);
    let original_capacity = buffer.capacity();

    // Decode should split the buffer (zero-copy operation)
    let decoded = codec.decode(&mut buffer).expect("Failed to decode");

    assert!(decoded.is_some());
    let decoded_packet = decoded.unwrap();
    assert_eq!(decoded_packet.payload, vec![1, 2, 3, 4, 5]);

    // Buffer should now be empty after split
    assert_eq!(buffer.len(), 0);

    // Capacity should be preserved (no reallocation)
    assert!(buffer.capacity() <= original_capacity);
}

#[test]
fn test_codec_partial_decode_preserves_buffer() {
    let mut codec = PacketCodec;

    // Create incomplete packet data (only 5 bytes of header)
    let mut buffer = BytesMut::from(&[0x4E, 0x50, 0x52, 0x4F, 0x01][..]);

    // Decode should return None without consuming buffer
    let result = codec.decode(&mut buffer).expect("Decode should not error");

    assert!(result.is_none());
    assert_eq!(buffer.len(), 5); // Buffer unchanged
}

#[test]
fn test_codec_encode_reserves_space_efficiently() {
    let mut codec = PacketCodec;

    let payload = vec![0u8; 100];
    let packet = Packet {
        version: PROTOCOL_VERSION,
        payload: payload.clone(),
    };

    let mut buffer = BytesMut::new();

    // Encode should reserve space efficiently
    codec.encode(packet, &mut buffer).expect("Failed to encode");

    // Buffer should contain exactly the packet data
    assert_eq!(buffer.len(), 9 + 100); // 9 byte header + 100 byte payload

    // Verify the packet is valid
    let bytes = buffer.freeze();
    let decoded = Packet::from_bytes(&bytes).expect("Failed to decode");
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_codec_multiple_packets_in_buffer() {
    let mut codec = PacketCodec;

    // Create two packets
    let packet1 = Packet {
        version: PROTOCOL_VERSION,
        payload: vec![1, 2, 3],
    };
    let packet2 = Packet {
        version: PROTOCOL_VERSION,
        payload: vec![4, 5, 6],
    };

    let bytes1 = packet1.to_bytes();
    let bytes2 = packet2.to_bytes();

    // Concatenate into single buffer
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice(&bytes1);
    buffer.extend_from_slice(&bytes2);

    // Decode first packet
    let decoded1 = codec
        .decode(&mut buffer)
        .expect("Failed to decode")
        .expect("Should have packet");
    assert_eq!(decoded1.payload, vec![1, 2, 3]);

    // Decode second packet
    let decoded2 = codec
        .decode(&mut buffer)
        .expect("Failed to decode")
        .expect("Should have packet");
    assert_eq!(decoded2.payload, vec![4, 5, 6]);

    // Buffer should be empty
    assert_eq!(buffer.len(), 0);
}

#[test]
fn test_bytes_freeze_is_zero_copy() {
    // Test that bytes::Bytes freeze operation is zero-copy
    let mut buffer = BytesMut::with_capacity(100);
    buffer.extend_from_slice(&[1, 2, 3, 4, 5]);

    // Get pointer to data
    let ptr_before = buffer.as_ptr();

    // Freeze should be zero-copy
    let frozen: Bytes = buffer.freeze();

    // Pointer should be the same (zero-copy)
    assert_eq!(ptr_before, frozen.as_ptr());
    assert_eq!(frozen.len(), 5);
}

#[test]
fn test_codec_decode_with_exact_data() {
    let mut codec = PacketCodec;

    // Create packet with exact header + payload
    let payload = vec![10, 20, 30];
    let packet = Packet {
        version: PROTOCOL_VERSION,
        payload,
    };
    let bytes = packet.to_bytes();

    let mut buffer = BytesMut::from(&bytes[..]);

    // Decode should work with exact data
    let decoded = codec
        .decode(&mut buffer)
        .expect("Failed to decode")
        .expect("Should have packet");

    assert_eq!(decoded.payload, vec![10, 20, 30]);
    assert_eq!(buffer.len(), 0);
}

#[test]
fn test_codec_encode_large_payload() {
    let mut codec = PacketCodec;

    // Create large payload (1MB)
    let payload = vec![0xAB; 1024 * 1024];
    let packet = Packet {
        version: PROTOCOL_VERSION,
        payload: payload.clone(),
    };

    let mut buffer = BytesMut::new();

    // Should handle large payloads efficiently
    codec.encode(packet, &mut buffer).expect("Failed to encode");

    assert_eq!(buffer.len(), 9 + 1024 * 1024);

    // Verify decoding works
    let bytes = buffer.freeze();
    let decoded = Packet::from_bytes(&bytes).expect("Failed to decode");
    assert_eq!(decoded.payload.len(), 1024 * 1024);
    assert_eq!(decoded.payload[0], 0xAB);
}

#[test]
fn test_codec_buffer_reuse() {
    let mut codec = PacketCodec;

    let mut buffer = BytesMut::with_capacity(1000);

    // Encode multiple packets using same buffer
    for i in 0..10 {
        let packet = Packet {
            version: PROTOCOL_VERSION,
            payload: vec![i as u8; 10],
        };

        codec.encode(packet, &mut buffer).expect("Failed to encode");
    }

    // Buffer should contain all packets
    assert_eq!(buffer.len(), 10 * (9 + 10)); // 10 packets * (header + payload)

    // Decode all packets
    let mut count = 0;
    while let Some(packet) = codec.decode(&mut buffer).expect("Failed to decode") {
        assert_eq!(packet.payload.len(), 10);
        assert_eq!(packet.payload[0], count as u8);
        count += 1;
    }

    assert_eq!(count, 10);
}

#[test]
fn test_codec_incremental_buffer_fill() {
    let mut codec = PacketCodec;

    // Simulate incremental network reads
    let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let packet = Packet {
        version: PROTOCOL_VERSION,
        payload,
    };
    let full_bytes = packet.to_bytes();

    let mut buffer = BytesMut::new();

    // Add data byte by byte (simulating slow network)
    for (i, byte) in full_bytes.iter().enumerate() {
        buffer.extend_from_slice(&[*byte]);

        let result = codec.decode(&mut buffer).expect("Should not error");

        if i < full_bytes.len() - 1 {
            // Should return None until complete
            assert!(result.is_none());
            assert!(!buffer.is_empty());
        } else {
            // Should decode when complete
            assert!(result.is_some());
            let decoded = result.unwrap();
            assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
            assert_eq!(buffer.len(), 0);
        }
    }
}

#[test]
fn test_codec_split_to_is_zero_copy() {
    // Verify that BytesMut::split_to is zero-copy
    let mut buffer = BytesMut::with_capacity(100);
    buffer.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    let original_ptr = buffer.as_ptr();

    // Split off first 5 bytes
    let split = buffer.split_to(5);

    // Split should have original pointer (zero-copy)
    assert_eq!(split.as_ptr(), original_ptr);
    assert_eq!(split.len(), 5);

    // Remaining buffer has advanced pointer
    assert_eq!(buffer.len(), 5);
    assert_eq!(buffer[0], 6);
}

#[test]
fn test_codec_memory_efficiency() {
    let mut codec = PacketCodec;

    // Create a large packet
    let large_payload = vec![0xFF; 10 * 1024]; // 10KB
    let packet = Packet {
        version: PROTOCOL_VERSION,
        payload: large_payload.clone(),
    };

    let bytes = packet.to_bytes();
    let mut buffer = BytesMut::from(&bytes[..]);

    // Initial buffer size
    let initial_capacity = buffer.capacity();

    // Decode should not cause excessive reallocation
    let decoded = codec
        .decode(&mut buffer)
        .expect("Failed to decode")
        .expect("Should have packet");

    assert_eq!(decoded.payload, large_payload);

    // Capacity should not have increased significantly
    assert!(buffer.capacity() <= initial_capacity * 2);
}

#[test]
fn test_bytes_reference_counting() {
    // Test that Bytes uses reference counting for efficient sharing
    let data = vec![1, 2, 3, 4, 5];
    let bytes1 = Bytes::from(data);

    // Clone should share data (reference counting)
    let bytes2 = bytes1.clone();

    // Both should point to same data
    assert_eq!(bytes1.as_ptr(), bytes2.as_ptr());
    assert_eq!(bytes1.len(), bytes2.len());

    // Both should have same content
    assert_eq!(bytes1, bytes2);
}
