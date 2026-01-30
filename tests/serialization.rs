//! Integration tests for alternative serialization formats
//!
//! Tests the MultiFormat trait implementation and various serialization formats
//! including Bincode (default), JSON (human-readable), and MessagePack (compact).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::expect_fun_call
)]

use network_protocol::core::serialization::{MultiFormat, SerializationFormat};
use network_protocol::protocol::message::Message;

#[test]
fn test_bincode_serialization() {
    let message = Message::Ping;

    // Serialize with bincode
    let bytes = message
        .serialize_format(SerializationFormat::Bincode)
        .expect("Failed to serialize");

    // Deserialize
    let recovered = Message::deserialize_format(&bytes, SerializationFormat::Bincode)
        .expect("Failed to deserialize");

    assert_eq!(message, recovered);
}

#[test]
fn test_json_serialization() {
    let message = Message::Echo("Hello, JSON!".to_string());

    // Serialize with JSON
    let bytes = message
        .serialize_format(SerializationFormat::Json)
        .expect("Failed to serialize");

    // Verify it's valid JSON
    let json_str = std::str::from_utf8(&bytes).expect("Invalid UTF-8");
    println!("JSON representation: {}", json_str);
    assert!(json_str.contains("Hello, JSON!"));

    // Deserialize
    let recovered = Message::deserialize_format(&bytes, SerializationFormat::Json)
        .expect("Failed to deserialize");

    assert_eq!(message, recovered);
}

#[test]
fn test_messagepack_serialization() {
    let message = Message::Custom {
        command: "test_command".to_string(),
        payload: vec![1, 2, 3, 4, 5],
    };

    // Serialize with MessagePack
    let bytes = message
        .serialize_format(SerializationFormat::MessagePack)
        .expect("Failed to serialize");

    // Deserialize
    let recovered = Message::deserialize_format(&bytes, SerializationFormat::MessagePack)
        .expect("Failed to deserialize");

    assert_eq!(message, recovered);
}

#[test]
fn test_format_with_header() {
    let message = Message::Pong;

    // Serialize with header
    let bytes = message
        .serialize_with_header(SerializationFormat::Json)
        .expect("Failed to serialize");

    // First byte should be the format identifier
    assert_eq!(bytes[0], SerializationFormat::Json.format_byte());

    // Deserialize with header
    let (recovered, format) =
        Message::deserialize_with_header(&bytes).expect("Failed to deserialize");

    assert_eq!(message, recovered);
    assert_eq!(format, SerializationFormat::Json);
}

#[test]
fn test_all_formats_roundtrip() {
    let messages = vec![
        Message::Ping,
        Message::Pong,
        Message::Echo("Test message".to_string()),
        Message::Disconnect,
        Message::Custom {
            command: "custom".to_string(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        },
        Message::SecureHandshakeInit {
            pub_key: [0u8; 32],
            timestamp: 1234567890,
            nonce: [1u8; 16],
        },
    ];

    let formats = vec![
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::MessagePack,
    ];

    for message in &messages {
        for format in &formats {
            let bytes = message
                .serialize_format(*format)
                .expect(&format!("Failed to serialize with {:?}", format));

            let recovered = Message::deserialize_format(&bytes, *format)
                .expect(&format!("Failed to deserialize with {:?}", format));

            assert_eq!(
                *message, recovered,
                "Roundtrip failed for format {:?}",
                format
            );
        }
    }
}

#[test]
fn test_format_size_comparison() {
    let message = Message::Custom {
        command: "benchmark".to_string(),
        payload: vec![0xAB; 1024], // 1KB payload
    };

    let bincode_bytes = message
        .serialize_format(SerializationFormat::Bincode)
        .expect("Bincode failed");
    let json_bytes = message
        .serialize_format(SerializationFormat::Json)
        .expect("JSON failed");
    let msgpack_bytes = message
        .serialize_format(SerializationFormat::MessagePack)
        .expect("MessagePack failed");

    println!("Size comparison for 1KB payload:");
    println!("  Bincode:     {} bytes", bincode_bytes.len());
    println!("  JSON:        {} bytes", json_bytes.len());
    println!("  MessagePack: {} bytes", msgpack_bytes.len());

    // Verify bincode is most compact (or close to MessagePack)
    assert!(bincode_bytes.len() <= msgpack_bytes.len());

    // JSON should be larger due to text encoding
    assert!(json_bytes.len() > bincode_bytes.len());
    assert!(json_bytes.len() > msgpack_bytes.len());
}

#[test]
fn test_handshake_messages_all_formats() {
    let init_msg = Message::SecureHandshakeInit {
        pub_key: [0x42; 32],
        timestamp: 9876543210,
        nonce: [0xAB; 16],
    };

    let response_msg = Message::SecureHandshakeResponse {
        pub_key: [0x24; 32],
        nonce: [0xCD; 16],
        nonce_verification: [0xEF; 32],
    };

    let confirm_msg = Message::SecureHandshakeConfirm {
        nonce_verification: [0x12; 32],
    };

    for format in &[
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::MessagePack,
    ] {
        // Test init
        let init_bytes = init_msg.serialize_format(*format).unwrap();
        let init_recovered = Message::deserialize_format(&init_bytes, *format).unwrap();
        assert_eq!(init_msg, init_recovered);

        // Test response
        let response_bytes = response_msg.serialize_format(*format).unwrap();
        let response_recovered = Message::deserialize_format(&response_bytes, *format).unwrap();
        assert_eq!(response_msg, response_recovered);

        // Test confirm
        let confirm_bytes = confirm_msg.serialize_format(*format).unwrap();
        let confirm_recovered = Message::deserialize_format(&confirm_bytes, *format).unwrap();
        assert_eq!(confirm_msg, confirm_recovered);
    }
}

#[test]
fn test_auto_format_detection() {
    let message = Message::Echo("Auto-detect format!".to_string());

    // Test each format with header
    for format in &[
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::MessagePack,
    ] {
        let bytes = message.serialize_with_header(*format).unwrap();

        // Deserialize should auto-detect format
        let (recovered, detected_format) = Message::deserialize_with_header(&bytes).unwrap();

        assert_eq!(message, recovered);
        assert_eq!(*format, detected_format);
    }
}

#[test]
fn test_invalid_format_byte() {
    let message = Message::Ping;
    let mut bytes = message
        .serialize_with_header(SerializationFormat::Bincode)
        .unwrap();

    // Corrupt the format byte
    bytes[0] = 0xFF;

    // Should fail with unknown format
    let result = Message::deserialize_with_header(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_empty_data_deserialization() {
    let result = Message::deserialize_with_header(&[]);
    assert!(result.is_err());
}

#[test]
fn test_json_human_readable() {
    let message = Message::Custom {
        command: "debug_command".to_string(),
        payload: vec![1, 2, 3],
    };

    let json_bytes = message.serialize_format(SerializationFormat::Json).unwrap();

    let json_str = std::str::from_utf8(&json_bytes).unwrap();

    // Verify JSON is human-readable
    assert!(json_str.contains("Custom"));
    assert!(json_str.contains("debug_command"));

    println!("Human-readable JSON:\n{}", json_str);
}

#[test]
fn test_large_payload_all_formats() {
    // Test with a large payload (10KB)
    let large_payload = vec![0x42; 10 * 1024];
    let message = Message::Custom {
        command: "large_test".to_string(),
        payload: large_payload.clone(),
    };

    for format in &[
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::MessagePack,
    ] {
        let bytes = message.serialize_format(*format).unwrap();
        let recovered = Message::deserialize_format(&bytes, *format).unwrap();

        if let Message::Custom { payload, .. } = recovered {
            assert_eq!(payload.len(), large_payload.len());
            assert_eq!(payload, large_payload);
        } else {
            panic!("Wrong message type recovered");
        }
    }
}
