//! Property-based tests using proptest
//!
//! These tests validate protocol invariants across a wide range of randomly
//! generated inputs, ensuring robust behavior under all conditions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use network_protocol::config::PROTOCOL_VERSION;
use network_protocol::core::packet::Packet;
use network_protocol::core::serialization::{MultiFormat, SerializationFormat};
use network_protocol::protocol::message::Message;
use network_protocol::utils::compression::{compress, decompress, CompressionKind};
use proptest::prelude::*;

// Property: Any packet can be serialized and deserialized correctly
proptest! {
    #[test]
    fn prop_packet_roundtrip(payload in prop::collection::vec(any::<u8>(), 0..10000)) {
        let packet = Packet { version: PROTOCOL_VERSION, payload: payload.clone() };

        let serialized = packet.to_bytes();
        let deserialized = Packet::from_bytes(&serialized).expect("Deserialization should not fail");

        prop_assert_eq!(deserialized.payload, payload);
    }
}

// Property: Packet serialization is deterministic
proptest! {
    #[test]
    fn prop_packet_serialization_deterministic(payload in prop::collection::vec(any::<u8>(), 0..1000)) {
        let packet = Packet { version: PROTOCOL_VERSION, payload };

        let bytes1 = packet.to_bytes();
        let bytes2 = packet.to_bytes();

        prop_assert_eq!(bytes1, bytes2);
    }
}

// Property: LZ4 compression roundtrip preserves data
proptest! {
    #[test]
    fn prop_lz4_compression_roundtrip(data in prop::collection::vec(any::<u8>(), 0..50000)) {
        let compressed = compress(&data, &CompressionKind::Lz4).expect("Compression should not fail");
        let decompressed = decompress(&compressed, &CompressionKind::Lz4).expect("Decompression should not fail");

        prop_assert_eq!(decompressed, data);
    }
}

// Property: Zstd compression roundtrip preserves data
proptest! {
    #[test]
    fn prop_zstd_compression_roundtrip(data in prop::collection::vec(any::<u8>(), 0..50000)) {
        let compressed = compress(&data, &CompressionKind::Zstd).expect("Compression should not fail");
        let decompressed = decompress(&compressed, &CompressionKind::Zstd).expect("Decompression should not fail");

        prop_assert_eq!(decompressed, data);
    }
}

// Property: Compression always produces valid output (never panics)
proptest! {
    #[test]
    fn prop_compression_never_panics(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        // LZ4 should never panic
        let lz4_result = compress(&data, &CompressionKind::Lz4);
        prop_assert!(lz4_result.is_ok());

        // Zstd should never panic
        let zstd_result = compress(&data, &CompressionKind::Zstd);
        prop_assert!(zstd_result.is_ok());
    }
}

// Property: Decompression of invalid data returns error (doesn't panic)
proptest! {
    #[test]
    fn prop_decompression_invalid_data_returns_error(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        // Attempting to decompress random data should either succeed or return error (not panic)
        let _ = decompress(&data, &CompressionKind::Lz4);
        let _ = decompress(&data, &CompressionKind::Zstd);

        // If we got here, no panic occurred
        prop_assert!(true);
    }
}

// Property: Packet size calculation is accurate
proptest! {
    #[test]
    fn prop_packet_size_accurate(payload in prop::collection::vec(any::<u8>(), 0..10000)) {
        let packet = Packet { version: PROTOCOL_VERSION, payload: payload.clone() };
        let serialized = packet.to_bytes();

        // Size should be: 4 (magic) + 1 (version) + 4 (length) + payload_len
        let expected_size = 9 + payload.len();
        prop_assert_eq!(serialized.len(), expected_size);
    }
}

// Property: Empty payloads are handled correctly
proptest! {
    #[test]
    fn prop_empty_payload_handled(_seed in any::<u8>()) {
        let packet = Packet { version: PROTOCOL_VERSION, payload: vec![] };

        let serialized = packet.to_bytes();
        let deserialized = Packet::from_bytes(&serialized).expect("Deserialization should not fail");

        prop_assert!(deserialized.payload.is_empty());
    }
}

// Property: Large payloads (up to max size) are handled correctly
proptest! {
    #[test]
    fn prop_large_payload_handled(size in 0usize..100_000) {
        let payload = vec![0xAB; size];
        let packet = Packet { version: PROTOCOL_VERSION, payload: payload.clone() };

        let serialized = packet.to_bytes();
        let deserialized = Packet::from_bytes(&serialized).expect("Deserialization should not fail");

        prop_assert_eq!(deserialized.payload.len(), size);
        if !payload.is_empty() {
            prop_assert_eq!(deserialized.payload[0], 0xAB);
        }
    }
}

// Property: Message serialization with different formats is consistent
proptest! {
    #[test]
    fn prop_message_format_consistency(msg_type in 0u8..5) {
        let message = match msg_type {
            0 => Message::Ping,
            1 => Message::Pong,
            2 => Message::Disconnect,
            3 => Message::Echo("test".to_string()),
            _ => Message::Custom {
                command: "cmd".to_string(),
                payload: vec![1, 2, 3],
            },
        };

        // Each format should be able to roundtrip
        for format in [SerializationFormat::Bincode, SerializationFormat::Json, SerializationFormat::MessagePack] {
            let serialized = message.serialize_format(format).expect("Serialization should not fail");
            let deserialized = Message::deserialize_format(&serialized, format).expect("Deserialization should not fail");

            prop_assert_eq!(&message, &deserialized);
        }
    }
}

// Property: Packet header magic bytes are always correct
proptest! {
    #[test]
    fn prop_packet_magic_bytes_correct(payload in prop::collection::vec(any::<u8>(), 0..1000)) {
        let packet = Packet { version: PROTOCOL_VERSION, payload };
        let serialized = packet.to_bytes();

        // First 4 bytes should be magic bytes: 0x4E, 0x50, 0x52, 0x4F ("NPRO")
        prop_assert_eq!(serialized[0], 0x4E);
        prop_assert_eq!(serialized[1], 0x50);
        prop_assert_eq!(serialized[2], 0x52);
        prop_assert_eq!(serialized[3], 0x4F);
    }
}

// Property: Packet version byte is always correct
proptest! {
    #[test]
    fn prop_packet_version_correct(payload in prop::collection::vec(any::<u8>(), 0..1000)) {
        let packet = Packet { version: PROTOCOL_VERSION, payload };
        let serialized = packet.to_bytes();

        // 5th byte should be protocol version (currently 1)
        prop_assert_eq!(serialized[4], PROTOCOL_VERSION);
    }
}

// Property: Packet length field matches payload length
proptest! {
    #[test]
    fn prop_packet_length_field_correct(payload in prop::collection::vec(any::<u8>(), 0..10000)) {
        let packet = Packet { version: PROTOCOL_VERSION, payload: payload.clone() };
        let serialized = packet.to_bytes();

        // Bytes 5-8 contain the length as big-endian u32
        let length_bytes = [serialized[5], serialized[6], serialized[7], serialized[8]];
        let length = u32::from_be_bytes(length_bytes) as usize;

        prop_assert_eq!(length, payload.len());
    }
}

// Property: Compression reduces size for repetitive data
proptest! {
    #[test]
    fn prop_compression_reduces_repetitive_data(byte in any::<u8>(), size in 1000usize..10000) {
        // Create highly repetitive data (should compress well)
        let data = vec![byte; size];

        let compressed = compress(&data, &CompressionKind::Lz4).expect("Compression should not fail");

        // Compressed should be significantly smaller for repetitive data
        prop_assert!(compressed.len() < data.len() / 2);
    }
}

// Property: Compression doesn't break on random data
proptest! {
    #[test]
    fn prop_compression_handles_random_data(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        // Random data may not compress well, but should not fail
        let lz4_compressed = compress(&data, &CompressionKind::Lz4).expect("LZ4 compression should not fail");
        let lz4_decompressed = decompress(&lz4_compressed, &CompressionKind::Lz4).expect("LZ4 decompression should not fail");
        prop_assert_eq!(&lz4_decompressed, &data);

        let zstd_compressed = compress(&data, &CompressionKind::Zstd).expect("Zstd compression should not fail");
        let zstd_decompressed = decompress(&zstd_compressed, &CompressionKind::Zstd).expect("Zstd decompression should not fail");
        prop_assert_eq!(&zstd_decompressed, &data);
    }
}

// Property: Packet deserialization rejects invalid magic bytes
proptest! {
    #[test]
    fn prop_packet_rejects_invalid_magic(
        b0 in any::<u8>(),
        b1 in any::<u8>(),
        b2 in any::<u8>(),
        b3 in any::<u8>()
    ) {
        // Skip valid magic bytes
        prop_assume!([b0, b1, b2, b3] != [0x4E, 0x50, 0x52, 0x4F]);

        // Create packet with invalid magic bytes
        let data = vec![b0, b1, b2, b3, 1, 0, 0, 0, 0]; // version + length 0

        let result = Packet::from_bytes(&data);

        // Should return an error for invalid magic bytes
        prop_assert!(result.is_err());
    }
}

// Property: Multiple consecutive compressions are stable
proptest! {
    #[test]
    fn prop_multiple_compressions_stable(data in prop::collection::vec(any::<u8>(), 100..1000)) {
        let compressed1 = compress(&data, &CompressionKind::Lz4).expect("First compression failed");
        let decompressed1 = decompress(&compressed1, &CompressionKind::Lz4).expect("First decompression failed");

        let compressed2 = compress(&decompressed1, &CompressionKind::Lz4).expect("Second compression failed");
        let decompressed2 = decompress(&compressed2, &CompressionKind::Lz4).expect("Second decompression failed");

        // Data should remain identical after multiple cycles
        prop_assert_eq!(data, decompressed2);
    }
}

// Property: Packet encoding/decoding is independent of payload content
proptest! {
    #[test]
    fn prop_packet_content_independent(
        payload1 in prop::collection::vec(any::<u8>(), 0..1000),
        payload2 in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let packet1 = Packet { version: PROTOCOL_VERSION, payload: payload1.clone() };
        let packet2 = Packet { version: PROTOCOL_VERSION, payload: payload2.clone() };

        let bytes1 = packet1.to_bytes();
        let bytes2 = packet2.to_bytes();

        let recovered1 = Packet::from_bytes(&bytes1).expect("Deserialization should not fail");
        let recovered2 = Packet::from_bytes(&bytes2).expect("Deserialization should not fail");

        prop_assert_eq!(recovered1.payload, payload1);
        prop_assert_eq!(recovered2.payload, payload2);
    }
}
