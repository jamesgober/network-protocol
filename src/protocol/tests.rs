// test-only module included via protocol/mod.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::protocol::handshake::*;
use crate::protocol::message::Message;

#[test]
fn test_secure_handshake_flow() {
    // =================== Step 1: Client init ===================
    let (client_state, init_msg) =
        client_secure_handshake_init().expect("Client init should succeed");

    // Extract client message data
    let (client_pub_key, timestamp, client_nonce) = match &init_msg {
        Message::SecureHandshakeInit {
            pub_key,
            nonce,
            timestamp,
        } => (*pub_key, *timestamp, *nonce),
        _ => panic!("Expected SecureHandshakeInit message"),
    };

    // =================== Step 2: Server responds ===================
    let (server_state, server_response) =
        server_secure_handshake_response(client_pub_key, client_nonce, timestamp)
            .expect("Server response should succeed");

    // Extract server response data
    let (server_pub_key, server_nonce, nonce_verification) = match server_response {
        Message::SecureHandshakeResponse {
            pub_key,
            nonce,
            nonce_verification,
        } => (pub_key, nonce, nonce_verification),
        _ => panic!("Expected SecureHandshakeResponse message"),
    };

    // =================== Step 3: Client verifies and confirms ===================
    let (client_state_verified, client_confirm) = client_secure_handshake_verify(
        client_state,
        server_pub_key,
        server_nonce,
        nonce_verification,
    )
    .expect("Client verification should succeed");

    // Extract client confirmation data
    let confirmation_hash = match client_confirm {
        Message::SecureHandshakeConfirm { nonce_verification } => nonce_verification,
        _ => panic!("Expected SecureHandshakeConfirm message"),
    };

    // =================== Step 4: Session key derivation ===================
    let server_key = server_secure_handshake_finalize(server_state, confirmation_hash)
        .expect("Server finalization should succeed");

    let client_key = client_derive_session_key(client_state_verified)
        .expect("Client should be able to derive session key");

    // Keys should match (validates the Diffie-Hellman exchange worked)
    assert_eq!(
        server_key, client_key,
        "Client and server session keys must match"
    );
}

#[test]
fn test_replay_attack_prevention() {
    // Current timestamp should be valid
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    assert!(verify_timestamp(now_ms, 30));

    // Timestamp too old should be rejected
    let old_ts = now_ms - 31000; // 31 seconds ago
    assert!(!verify_timestamp(old_ts, 30));

    // Timestamp too far in future should be rejected
    let future_ts = now_ms + 3000; // 3 seconds in future (beyond 2s tolerance)
    assert!(!verify_timestamp(future_ts, 30));

    // Timestamp within tolerance should be accepted
    let recent_ts = now_ms - 5000; // 5 seconds ago
    assert!(verify_timestamp(recent_ts, 30));
}

#[test]
fn test_tampering_detection() {
    // Step 1: Client initiates handshake
    let (_client_state, init_message) =
        client_secure_handshake_init().expect("Client init should succeed");

    // Extract client data
    let (client_pub_key, timestamp, client_nonce) = match init_message {
        Message::SecureHandshakeInit {
            pub_key,
            timestamp,
            nonce,
        } => (pub_key, timestamp, nonce),
        _ => panic!("Expected SecureHandshakeInit message"),
    };

    // Step 2: Server processes handshake and responds
    let (_server_state, server_response) =
        server_secure_handshake_response(client_pub_key, client_nonce, timestamp)
            .expect("Server response should succeed");

    // Extract server data
    let (server_pub_key, server_nonce, _nonce_verification) = match server_response {
        Message::SecureHandshakeResponse {
            pub_key,
            nonce,
            nonce_verification,
        } => (pub_key, nonce, nonce_verification),
        _ => panic!("Expected SecureHandshakeResponse message"),
    };

    // Simulate tampering with incorrect verification
    let tampered_nonce_verification = [0u8; 32];

    // Attempt verification with tampered data (using fresh state)
    let (client_state_fresh, _) =
        client_secure_handshake_init().expect("Client init should succeed");

    // This should fail verification
    let result = client_secure_handshake_verify(
        client_state_fresh,
        server_pub_key,
        server_nonce,
        tampered_nonce_verification,
    );

    assert!(
        result.is_err(),
        "Verification should fail with tampered nonce hash"
    );
}

#[test]
fn test_per_session_state_isolation() {
    // Simulate two concurrent handshakes - they should not interfere
    let (client1, msg1) = client_secure_handshake_init().unwrap();
    let (client2, msg2) = client_secure_handshake_init().unwrap();

    // Extract from messages
    let (pub_key1, ts1, nonce1) = match msg1 {
        Message::SecureHandshakeInit {
            pub_key,
            timestamp,
            nonce,
        } => (pub_key, timestamp, nonce),
        _ => panic!("Wrong message type"),
    };

    let (pub_key2, ts2, nonce2) = match msg2 {
        Message::SecureHandshakeInit {
            pub_key,
            timestamp,
            nonce,
        } => (pub_key, timestamp, nonce),
        _ => panic!("Wrong message type"),
    };

    // Verify they are different (different ephemeral secrets)
    assert_ne!(pub_key1, pub_key2);
    assert_ne!(nonce1, nonce2);

    // Server responses should be independent
    let (server1, resp1) = server_secure_handshake_response(pub_key1, nonce1, ts1).unwrap();
    let (server2, resp2) = server_secure_handshake_response(pub_key2, nonce2, ts2).unwrap();

    let (server_pub1, server_nonce1, verify1) = match resp1 {
        Message::SecureHandshakeResponse {
            pub_key,
            nonce,
            nonce_verification,
        } => (pub_key, nonce, nonce_verification),
        _ => panic!("Wrong message type"),
    };

    let (server_pub2, server_nonce2, verify2) = match resp2 {
        Message::SecureHandshakeResponse {
            pub_key,
            nonce,
            nonce_verification,
        } => (pub_key, nonce, nonce_verification),
        _ => panic!("Wrong message type"),
    };

    assert_ne!(server_pub1, server_pub2);
    assert_ne!(server_nonce1, server_nonce2);

    // Complete both handshakes independently
    let (client1_verified, confirm1) =
        client_secure_handshake_verify(client1, server_pub1, server_nonce1, verify1).unwrap();
    let (client2_verified, confirm2) =
        client_secure_handshake_verify(client2, server_pub2, server_nonce2, verify2).unwrap();

    let confirm_hash1 = match confirm1 {
        Message::SecureHandshakeConfirm { nonce_verification } => nonce_verification,
        _ => panic!("Wrong message type"),
    };

    let confirm_hash2 = match confirm2 {
        Message::SecureHandshakeConfirm { nonce_verification } => nonce_verification,
        _ => panic!("Wrong message type"),
    };

    assert_ne!(confirm_hash1, confirm_hash2);

    // Finalize both sides
    let key1_server = server_secure_handshake_finalize(server1, confirm_hash1).unwrap();
    let key1_client = client_derive_session_key(client1_verified).unwrap();

    let key2_server = server_secure_handshake_finalize(server2, confirm_hash2).unwrap();
    let key2_client = client_derive_session_key(client2_verified).unwrap();

    // Keys should match on both sides of each handshake
    assert_eq!(key1_server, key1_client);
    assert_eq!(key2_server, key2_client);

    // But different handshakes must have different keys
    assert_ne!(key1_server, key2_server);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_nonce_uniqueness() {
    // Verify that nonces are unique across multiple calls
    let (_s1, msg1) = client_secure_handshake_init().unwrap();
    let (_s2, msg2) = client_secure_handshake_init().unwrap();
    let (_s3, msg3) = client_secure_handshake_init().unwrap();

    let nonce1 = match msg1 {
        Message::SecureHandshakeInit { nonce, .. } => nonce,
        _ => unreachable!("Expected SecureHandshakeInit"),
    };

    let nonce2 = match msg2 {
        Message::SecureHandshakeInit { nonce, .. } => nonce,
        _ => unreachable!("Expected SecureHandshakeInit"),
    };

    let nonce3 = match msg3 {
        Message::SecureHandshakeInit { nonce, .. } => nonce,
        _ => unreachable!("Expected SecureHandshakeInit"),
    };

    // All nonces should be unique
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce1, nonce3);
}
