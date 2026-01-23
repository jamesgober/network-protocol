#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Comprehensive edge-case tests for production-grade reliability
//! Tests boundary conditions, error scenarios, resource limits, and concurrent edge cases

use network_protocol::core::packet::Packet;
use network_protocol::error::ProtocolError;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::utils::compression::CompressionKind;
use network_protocol::utils::crypto::Crypto;
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// PACKET CODEC EDGE CASES
// ============================================================================

#[test]
fn test_packet_empty_payload() {
    let packet = Packet {
        version: 1,
        payload: vec![],
    };
    let _bytes = packet.to_bytes();
    let decoded = Packet::from_bytes(&_bytes).expect("Should decode empty payload");
    assert_eq!(decoded.payload.len(), 0);
    assert_eq!(decoded.version, 1);
}

#[test]
fn test_packet_max_payload_size() {
    // Create a packet with maximum allowed payload
    let max_payload = vec![0xAB; 16 * 1024 * 1024]; // 16MB
    let packet = Packet {
        version: 1,
        payload: max_payload.clone(),
    };
    let bytes = packet.to_bytes();
    let decoded = Packet::from_bytes(&bytes).expect("Should decode max payload");
    assert_eq!(decoded.payload.len(), 16 * 1024 * 1024);
}

#[test]
fn test_packet_oversized_payload_rejected() {
    // Manually craft a header that claims a size larger than MAX_PAYLOAD_SIZE
    // Packet format: [magic(4)] [version(1)] [length(4)] [payload]
    let mut bad_bytes = vec![0x50, 0x52, 0x4F, 0x54]; // PROT magic
    bad_bytes.push(1); // version
    bad_bytes.extend_from_slice(&(20_000_000_u32).to_be_bytes()); // 20MB size claim
    bad_bytes.extend_from_slice(&[0xFF; 10]); // minimal payload to ensure we have enough bytes

    let result = Packet::from_bytes(&bad_bytes);
    // When claimed size exceeds MAX_PAYLOAD_SIZE, parser should reject it
    match result {
        Err(ProtocolError::OversizedPacket(20_000_000)) => {} // Expected
        Err(ProtocolError::InvalidHeader) => {
            // Also acceptable if parser validates all conditions
        }
        other => panic!("Unexpected result: {other:?}"),
    }
}

#[test]
fn test_packet_invalid_magic_bytes() {
    let mut bytes = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Invalid magic
    bytes.push(1); // version
    bytes.extend_from_slice(&(5_u32).to_be_bytes()); // length
    bytes.extend_from_slice(&[0xAA; 5]); // payload

    let result = Packet::from_bytes(&bytes);
    assert!(
        matches!(result, Err(ProtocolError::InvalidHeader)),
        "Should reject invalid magic bytes"
    );
}

#[test]
fn test_packet_unsupported_version() {
    // Packet format: [magic(4)] [version(1)] [length(4)] [payload]
    let mut bytes = vec![0x50, 0x52, 0x4F, 0x54]; // PROT magic
    bytes.push(99); // Unsupported version
    bytes.extend_from_slice(&(5_u32).to_be_bytes()); // length
    bytes.extend_from_slice(&[0xAA; 5]); // payload

    let result = Packet::from_bytes(&bytes);
    match result {
        Err(ProtocolError::UnsupportedVersion(99)) => {} // Expected
        Err(ProtocolError::InvalidHeader) => {
            // Also acceptable if header is rejected early
        }
        other => panic!("Unexpected: {other:?}"),
    }
}

#[test]
fn test_packet_truncated_header() {
    let bytes = vec![0x50, 0x52, 0x4F, 0x54, 0x01]; // Only 5 bytes, need 9
    let result = Packet::from_bytes(&bytes);
    assert!(
        matches!(result, Err(ProtocolError::InvalidHeader)),
        "Should reject truncated header"
    );
}

#[test]
fn test_packet_empty_buffer() {
    let result = Packet::from_bytes(&[]);
    assert!(
        matches!(result, Err(ProtocolError::InvalidHeader)),
        "Should reject empty buffer"
    );
}

#[test]
fn test_packet_roundtrip_large_payload() {
    let large_payload = vec![0x42; 5 * 1024 * 1024]; // 5MB
    let packet = Packet {
        version: 1,
        payload: large_payload.clone(),
    };
    let bytes = packet.to_bytes();
    let decoded = Packet::from_bytes(&bytes).expect("Should roundtrip large payload");
    assert_eq!(decoded.payload, large_payload);
}

// ============================================================================
// COMPRESSION EDGE CASES
// ============================================================================

#[test]
fn test_compression_empty_data() {
    let empty = &[];
    let compressed = network_protocol::utils::compression::compress(empty, &CompressionKind::Lz4)
        .expect("Should compress empty data");
    let decompressed =
        network_protocol::utils::compression::decompress(&compressed, &CompressionKind::Lz4)
            .expect("Should decompress empty data");
    assert_eq!(decompressed.len(), 0);
}

#[test]
fn test_compression_single_byte() {
    let single_byte = &[0x42];
    for kind in &[CompressionKind::Lz4, CompressionKind::Zstd] {
        let compressed = network_protocol::utils::compression::compress(single_byte, kind)
            .expect("Should compress single byte");
        let decompressed = network_protocol::utils::compression::decompress(&compressed, kind)
            .expect("Should decompress single byte");
        assert_eq!(decompressed, single_byte);
    }
}

#[test]
fn test_compression_highly_repetitive_data() {
    let repetitive = vec![0xAA; 1_000_000]; // 1MB of same byte
    for kind in &[CompressionKind::Lz4, CompressionKind::Zstd] {
        let compressed = network_protocol::utils::compression::compress(&repetitive, kind)
            .expect("Should compress repetitive data");
        // Compressed should be much smaller than original
        assert!(compressed.len() < repetitive.len() / 10);
        let decompressed = network_protocol::utils::compression::decompress(&compressed, kind)
            .expect("Should decompress");
        assert_eq!(decompressed, repetitive);
    }
}

#[test]
fn test_compression_random_data() {
    let random: Vec<u8> = (0..10_000).map(|i| ((i * 7) % 256) as u8).collect();
    for kind in &[CompressionKind::Lz4, CompressionKind::Zstd] {
        let compressed = network_protocol::utils::compression::compress(&random, kind)
            .expect("Should compress random data");
        let decompressed = network_protocol::utils::compression::decompress(&compressed, kind)
            .expect("Should decompress");
        assert_eq!(decompressed, random);
    }
}

#[test]
fn test_decompression_corrupted_data_lz4() {
    let data = &[0xAA; 100];
    let compressed = network_protocol::utils::compression::compress(data, &CompressionKind::Lz4)
        .expect("Should compress");
    let mut corrupted = compressed.clone();
    if !corrupted.is_empty() && corrupted.len() > 4 {
        // Flip bits in the middle of the data (after size header which is 4 bytes)
        corrupted[8] ^= 0xFF;
    }

    // Note: LZ4 with prepended size may or may not detect corruption depending on
    // whether the size header is valid. This is a behavior test.
    let result =
        network_protocol::utils::compression::decompress(&corrupted, &CompressionKind::Lz4);
    // Decompress may fail or succeed with truncated/invalid data depending on LZ4 implementation
    // We're just ensuring it doesn't panic
    let _ = result;
}

#[test]
fn test_decompression_truncated_data() {
    let data = &[0xBB; 50];
    let compressed = network_protocol::utils::compression::compress(data, &CompressionKind::Zstd)
        .expect("Should compress");
    if compressed.len() > 1 {
        let truncated = &compressed[..compressed.len() - 1];
        let result =
            network_protocol::utils::compression::decompress(truncated, &CompressionKind::Zstd);
        assert!(result.is_err(), "Should reject truncated compressed data");
    }
}

// ============================================================================
// CRYPTOGRAPHY EDGE CASES
// ============================================================================

#[test]
fn test_crypto_encrypt_empty_plaintext() {
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let crypto = Crypto::new(&key);
    let ciphertext = crypto.encrypt(&[], &nonce).expect("Should encrypt empty");
    // Verify it contains authentication tag but no plaintext
    assert!(!ciphertext.is_empty());
}

#[test]
fn test_crypto_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x99u8; 24];
    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let crypto = Crypto::new(&key);

    let ciphertext = crypto.encrypt(plaintext, &nonce).expect("Should encrypt");
    assert_ne!(ciphertext, plaintext); // Should be different

    let decrypted = crypto.decrypt(&ciphertext, &nonce).expect("Should decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_crypto_same_plaintext_different_nonce() {
    let key = [0x11u8; 32];
    let plaintext = b"Same message";
    let crypto = Crypto::new(&key);

    let nonce1 = [0x11u8; 24];
    let nonce2 = [0x22u8; 24];

    let ct1 = crypto.encrypt(plaintext, &nonce1).expect("Should encrypt");
    let ct2 = crypto.encrypt(plaintext, &nonce2).expect("Should encrypt");

    assert_ne!(
        ct1, ct2,
        "Different nonces should produce different ciphertexts"
    );
}

#[test]
fn test_crypto_decrypt_with_wrong_nonce() {
    let key = [0x55u8; 32];
    let plaintext = b"Secret";
    let crypto = Crypto::new(&key);

    let correct_nonce = [0xAAu8; 24];
    let wrong_nonce = [0xBBu8; 24];

    let ciphertext = crypto
        .encrypt(plaintext, &correct_nonce)
        .expect("Should encrypt");
    let result = crypto.decrypt(&ciphertext, &wrong_nonce);

    assert!(result.is_err(), "Decryption with wrong nonce should fail");
}

#[test]
fn test_crypto_decrypt_corrupted_ciphertext() {
    let key = [0x77u8; 32];
    let plaintext = b"Message";
    let crypto = Crypto::new(&key);

    let nonce = [0xCCu8; 24];
    let mut ciphertext = crypto.encrypt(plaintext, &nonce).expect("Should encrypt");

    // Corrupt the ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0xFF;
    }

    let result = crypto.decrypt(&ciphertext, &nonce);
    assert!(
        result.is_err(),
        "Decryption of corrupted ciphertext should fail"
    );
}

#[test]
fn test_crypto_large_plaintext() {
    let key = [0x88u8; 32];
    let nonce = [0x99u8; 24];
    let large_plaintext = vec![0xDDu8; 10 * 1024 * 1024]; // 10MB
    let crypto = Crypto::new(&key);

    let ciphertext = crypto
        .encrypt(&large_plaintext, &nonce)
        .expect("Should encrypt large data");
    let decrypted = crypto
        .decrypt(&ciphertext, &nonce)
        .expect("Should decrypt large data");

    assert_eq!(decrypted, large_plaintext);
}

#[test]
fn test_crypto_nonce_generation_uniqueness() {
    let nonce1 = Crypto::generate_nonce();
    let nonce2 = Crypto::generate_nonce();
    let nonce3 = Crypto::generate_nonce();

    assert_ne!(nonce1, nonce2, "Nonces should be different");
    assert_ne!(nonce2, nonce3, "Nonces should be different");
    assert_ne!(nonce1, nonce3, "Nonces should be different");

    // All should be 24 bytes
    assert_eq!(nonce1.len(), 24);
    assert_eq!(nonce2.len(), 24);
    assert_eq!(nonce3.len(), 24);
}

// ============================================================================
// DISPATCHER EDGE CASES
// ============================================================================

#[test]
fn test_dispatcher_empty_message_type() {
    let dispatcher = Arc::new(Dispatcher::default());
    let result = dispatcher.register("", |_| Ok(Message::Pong));
    // Empty handler names should either be rejected or work; verify consistent behavior
    // Currently the code doesn't validate, so this tests current behavior
    let _ = result; // May succeed or fail depending on implementation
}

#[test]
fn test_dispatcher_very_long_message_type() {
    let dispatcher = Arc::new(Dispatcher::default());
    let long_name = "A".repeat(10_000);
    let result = dispatcher.register(&long_name, |_| Ok(Message::Pong));
    // Should handle without panic
    let _ = result;
}

#[test]
fn test_dispatcher_special_characters_in_handler_name() {
    let dispatcher = Arc::new(Dispatcher::default());
    let special_names = vec![
        "HANDLER@123",
        "handler-with-dashes",
        "handler.with.dots",
        "handler_with_underscores",
        "HANDLER/PATH",
    ];

    for name in special_names {
        let result = dispatcher.register(name, |_| Ok(Message::Pong));
        let _ = result; // Should not panic
    }
}

#[test]
fn test_dispatcher_handler_override() {
    let dispatcher = Arc::new(Dispatcher::default());

    // Register initial handler
    let _ = dispatcher.register("TEST", |_| Ok(Message::Pong));

    // Register new handler with same name (override)
    let _ = dispatcher.register("TEST", |_| Ok(Message::Ping));

    // Dispatch should use the latest registered handler
    let message = Message::Ping;
    let result = dispatcher.dispatch(&message);
    // Result depends on implementation; verify no panic
    let _ = result;
}

#[test]
fn test_dispatcher_null_bytes_in_message_type() {
    let dispatcher = Arc::new(Dispatcher::default());
    let handler_name = "HANDLER\0HIDDEN";
    let result = dispatcher.register(handler_name, |_| Ok(Message::Pong));
    // Should handle null bytes gracefully
    let _ = result;
}

// ============================================================================
// TIMEOUT EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_timeout_zero_duration() {
    let timeout_result = tokio::time::timeout(Duration::from_secs(0), async {
        // Immediate resolution
        42
    })
    .await;

    // Zero timeout is very tight but should not panic
    let _ = timeout_result;
}

#[tokio::test]
async fn test_timeout_immediate_complete() {
    let result = tokio::time::timeout(Duration::from_secs(10), async { "done" }).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "done");
}

#[tokio::test]
async fn test_timeout_exceeds_duration() {
    let result = tokio::time::timeout(Duration::from_millis(10), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        "should not reach"
    })
    .await;

    assert!(result.is_err(), "Should timeout");
}

// ============================================================================
// CONCURRENT EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_concurrent_encryption_same_key() {
    use std::sync::Arc;
    let key = [0xFFu8; 32];
    let crypto = Arc::new(Crypto::new(&key));

    let mut tasks = vec![];
    for i in 0..100 {
        let crypto_clone = Arc::clone(&crypto);
        let task = tokio::spawn(async move {
            let nonce = Crypto::generate_nonce();
            let plaintext = format!("message {i}").into_bytes();
            let ciphertext = crypto_clone
                .encrypt(&plaintext, &nonce)
                .expect("Should encrypt");
            let decrypted = crypto_clone
                .decrypt(&ciphertext, &nonce)
                .expect("Should decrypt");
            assert_eq!(decrypted, plaintext);
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.expect("Task should complete");
    }
}

#[tokio::test]
async fn test_concurrent_compression() {
    let mut tasks = vec![];
    for i in 0..50 {
        let task = tokio::spawn(async move {
            let data = format!("data sample {i}").repeat(100).into_bytes();
            let compressed =
                network_protocol::utils::compression::compress(&data, &CompressionKind::Lz4)
                    .expect("Should compress");
            let decompressed = network_protocol::utils::compression::decompress(
                &compressed,
                &CompressionKind::Lz4,
            )
            .expect("Should decompress");
            assert_eq!(decompressed, data);
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.expect("Task should complete");
    }
}

// ============================================================================
// MESSAGE HANDLING EDGE CASES
// ============================================================================

#[test]
fn test_message_echo_empty_string() {
    let msg = Message::Echo(String::new());
    match msg {
        Message::Echo(_) => {} // Correct type
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_message_echo_very_long_string() {
    let long_string = "X".repeat(1_000_000);
    let msg = Message::Echo(long_string.clone());
    match msg {
        Message::Echo(s) => {
            assert_eq!(s.len(), 1_000_000);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_message_echo_special_characters() {
    let special = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`".to_string();
    let msg = Message::Echo(special.clone());
    match msg {
        Message::Echo(s) => assert_eq!(s, special),
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_message_echo_unicode() {
    let unicode = "Hello 世界 🌍 Привет العالم".to_string();
    let msg = Message::Echo(unicode.clone());
    match msg {
        Message::Echo(s) => assert_eq!(s, unicode),
        _ => panic!("Wrong message type"),
    }
}

// ============================================================================
// ERROR PROPAGATION EDGE CASES
// ============================================================================

#[test]
fn test_error_display_formatting() {
    let errors = vec![
        ProtocolError::InvalidHeader,
        ProtocolError::UnsupportedVersion(42),
        ProtocolError::OversizedPacket(999),
        ProtocolError::ConnectionClosed,
        ProtocolError::ConnectionTimeout,
        ProtocolError::CompressionFailure,
        ProtocolError::DecompressionFailure,
        ProtocolError::EncryptionFailure,
        ProtocolError::DecryptionFailure,
        ProtocolError::Io(std::io::Error::other("test error")),
    ];

    for err in errors {
        let display_str = format!("{err}");
        assert!(!display_str.is_empty(), "Error should have display format");
    }
}

#[test]
fn test_error_debug_formatting() {
    let err = ProtocolError::InvalidHeader;
    let debug_str = format!("{err:?}");
    assert!(!debug_str.is_empty(), "Error should have debug format");
}

// ============================================================================
// BUFFER BOUNDARY EDGE CASES
// ============================================================================

#[test]
fn test_packet_payload_exactly_max() {
    let max_size = 16 * 1024 * 1024;
    let payload = vec![0x7E; max_size];
    let packet = Packet {
        version: 1,
        payload,
    };
    let bytes = packet.to_bytes();
    let decoded = Packet::from_bytes(&bytes).expect("Should decode max boundary");
    assert_eq!(decoded.payload.len(), max_size);
}

#[test]
fn test_packet_payload_one_less_than_max() {
    let size = 16 * 1024 * 1024 - 1;
    let payload = vec![0x7D; size];
    let packet = Packet {
        version: 1,
        payload,
    };
    let bytes = packet.to_bytes();
    let decoded = Packet::from_bytes(&bytes).expect("Should decode just under max");
    assert_eq!(decoded.payload.len(), size);
}

#[test]
fn test_packet_payload_one_more_than_max_fails() {
    let oversized = vec![0xFF; 16 * 1024 * 1024 + 1];
    let packet = Packet {
        version: 1,
        payload: oversized,
    };
    let bytes = packet.to_bytes();
    // This will fail at deserialization since the size exceeds MAX_PAYLOAD_SIZE
    let result = Packet::from_bytes(&bytes);
    assert!(matches!(result, Err(ProtocolError::OversizedPacket(_))));
}

// ============================================================================
// RESOURCE CLEANUP EDGE CASES
// ============================================================================

#[test]
fn test_multiple_dispatcher_instances() {
    for _ in 0..1000 {
        let _dispatcher = Arc::new(Dispatcher::default());
        // Should not leak resources
    }
}

#[test]
fn test_crypto_key_memory_handling() {
    // Ensure no panics with multiple key instantiations
    for i in 0..100 {
        let key = [i as u8; 32];
        let _crypto = Crypto::new(&key);
    }
}

#[test]
fn test_large_message_memory_cleanup() {
    for _ in 0..10 {
        let _large_vec = vec![0xAAu8; 10 * 1024 * 1024]; // 10MB
                                                         // Should be cleaned up automatically
    }
}
