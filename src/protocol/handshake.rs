//! Secure handshake protocol implementation using Elliptic Curve Diffie-Hellman (ECDH)
//!
//! This module implements a secure cryptographic handshake based on x25519-dalek
//! with protection against replay attacks using timestamped nonces.
//!
//! **Key Change: Per-Session State**
//! Instead of global singletons, handshake state is now managed through session-scoped
//! structures (`ClientHandshakeState`, `ServerHandshakeState`) that are passed through
//! the handshake flow. This prevents concurrent handshake state trampling and ensures
//! clean state per connection.

use crate::error::{constants, ProtocolError, Result};
use crate::protocol::message::Message;
use crate::utils::replay_cache::ReplayCache;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

#[allow(unused_imports)]
use tracing::{debug, instrument, warn};

/// Client-side handshake state - passed through the handshake flow
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ClientHandshakeState {
    secret: Option<EphemeralSecret>,
    public: Option<[u8; 32]>,
    server_public: Option<[u8; 32]>,
    client_nonce: Option<[u8; 16]>,
    server_nonce: Option<[u8; 16]>,
}

impl ClientHandshakeState {
    /// Create a new empty client handshake state
    pub fn new() -> Self {
        Self {
            secret: None,
            public: None,
            server_public: None,
            client_nonce: None,
            server_nonce: None,
        }
    }

    /// Get reference to client nonce (for testing)
    #[cfg(test)]
    pub fn client_nonce(&self) -> Option<&[u8; 16]> {
        self.client_nonce.as_ref()
    }

    /// Get reference to server nonce (for testing)
    #[cfg(test)]
    pub fn server_nonce(&self) -> Option<&[u8; 16]> {
        self.server_nonce.as_ref()
    }
}

impl Default for ClientHandshakeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Server-side handshake state - passed through the handshake flow
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ServerHandshakeState {
    secret: Option<EphemeralSecret>,
    public: Option<[u8; 32]>,
    client_public: Option<[u8; 32]>,
    client_nonce: Option<[u8; 16]>,
    server_nonce: Option<[u8; 16]>,
}

impl ServerHandshakeState {
    /// Create a new empty server handshake state
    pub fn new() -> Self {
        Self {
            secret: None,
            public: None,
            client_public: None,
            client_nonce: None,
            server_nonce: None,
        }
    }

    /// Get reference to server nonce (for testing)
    #[cfg(test)]
    pub fn server_nonce(&self) -> Option<&[u8; 16]> {
        self.server_nonce.as_ref()
    }

    /// Get reference to client public key (for testing)
    #[cfg(test)]
    pub fn client_public(&self) -> Option<&[u8; 32]> {
        self.client_public.as_ref()
    }
}

impl Default for ServerHandshakeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the current timestamp in milliseconds
///
/// # Errors
/// Returns a `ProtocolError::Custom` if the system time is earlier than UNIX_EPOCH
fn current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| ProtocolError::Custom(constants::ERR_SYSTEM_TIME.into()))
}

/// Generate a cryptographically secure random nonce
fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Verify that a timestamp is recent enough
/// Default threshold is 30 seconds with a strict 2-second future tolerance for clock skew
pub fn verify_timestamp(timestamp: u64, max_age_seconds: u64) -> bool {
    let current = match current_timestamp() {
        Ok(time) => time,
        Err(_) => return false,
    };

    let max_age_ms = max_age_seconds * 1000;
    const FUTURE_TOLERANCE_MS: u64 = 2000; // 2 seconds max clock skew

    // Check if timestamp is from the future (strict tolerance for clock skew)
    if timestamp > current + FUTURE_TOLERANCE_MS {
        return false;
    }

    // Check if timestamp is too old
    if current > timestamp && current - timestamp > max_age_ms {
        return false;
    }

    true
}

/// Compute hash of a nonce for verification
fn hash_nonce(nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Derive a session key from a shared secret and nonces
fn derive_key_from_shared_secret(
    shared_secret: &SharedSecret,
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Include shared secret
    hasher.update(shared_secret.as_bytes());

    // Include both nonces for additional security (order matters for domain separation)
    hasher.update(b"client_nonce");
    hasher.update(client_nonce);
    hasher.update(b"server_nonce");
    hasher.update(server_nonce);

    hasher.finalize().into()
}

/// Initiates secure handshake from the client side.
/// Generates a new key pair and nonce for the client.
///
/// # Returns
/// A tuple of (new `ClientHandshakeState`, `Message::SecureHandshakeInit`)
///
/// # Errors
/// Returns timestamp errors if system time is invalid
#[instrument]
pub fn client_secure_handshake_init() -> Result<(ClientHandshakeState, Message)> {
    // Generate a new client key pair using OsRng
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);

    // Generate nonce and timestamp
    let nonce = generate_nonce();
    let timestamp = current_timestamp()?;

    let mut state = ClientHandshakeState::new();
    state.secret = Some(client_secret);
    state.public = Some(client_public.to_bytes());
    state.client_nonce = Some(nonce);

    debug!("Client initiating secure handshake");

    Ok((
        state,
        Message::SecureHandshakeInit {
            pub_key: client_public.to_bytes(),
            timestamp,
            nonce,
        },
    ))
}

/// Generates server response to client handshake initialization.
/// Validates client timestamp, generates server key pair and nonce.
///
/// # Returns
/// A tuple of (new `ServerHandshakeState`, `Message::SecureHandshakeResponse`)
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if client timestamp is invalid or too old
#[instrument(skip(client_pub_key, client_nonce, replay_cache))]
pub fn server_secure_handshake_response(
    client_pub_key: [u8; 32],
    client_nonce: [u8; 16],
    client_timestamp: u64,
    peer_id: &str,
    replay_cache: &mut ReplayCache,
) -> Result<(ServerHandshakeState, Message)> {
    // Validate the client timestamp (must be within last 30 seconds)
    if !verify_timestamp(client_timestamp, 30) {
        return Err(ProtocolError::HandshakeError(
            constants::ERR_INVALID_TIMESTAMP.into(),
        ));
    }

    // Check for replay attacks using the cache
    if replay_cache.is_replay(peer_id, &client_nonce, client_timestamp) {
        return Err(ProtocolError::HandshakeError(
            constants::ERR_REPLAY_ATTACK.into(),
        ));
    }

    // Generate server key pair and nonce
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);
    let server_nonce = generate_nonce();

    // Compute verification hash of client nonce
    let nonce_verification = hash_nonce(&client_nonce);

    let mut state = ServerHandshakeState::new();
    state.secret = Some(server_secret);
    state.public = Some(server_public.to_bytes());
    state.client_public = Some(client_pub_key);
    state.client_nonce = Some(client_nonce);
    state.server_nonce = Some(server_nonce);

    debug!("Server responding to handshake initiation");

    Ok((
        state,
        Message::SecureHandshakeResponse {
            pub_key: server_public.to_bytes(),
            nonce: server_nonce,
            nonce_verification,
        },
    ))
}

/// Client verifies server response and sends verification message.
/// Updates client state and returns confirmation message.
///
/// # Returns
/// Updated `ClientHandshakeState` and `Message::SecureHandshakeConfirm`
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if verification fails
#[instrument(skip(state, server_pub_key, server_nonce, nonce_verification, replay_cache))]
pub fn client_secure_handshake_verify(
    mut state: ClientHandshakeState,
    server_pub_key: [u8; 32],
    server_nonce: [u8; 16],
    nonce_verification: [u8; 32],
    peer_id: &str,
    replay_cache: &mut ReplayCache,
) -> Result<(ClientHandshakeState, Message)> {
    // Check for replay attacks using the cache
    if replay_cache.is_replay(peer_id, &server_nonce, 0) {
        // Use 0 for server nonce timestamp check
        return Err(ProtocolError::HandshakeError(
            constants::ERR_REPLAY_ATTACK.into(),
        ));
    }

    // Verify that server correctly verified our nonce
    let client_nonce = state.client_nonce.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_CLIENT_NONCE_NOT_FOUND.into())
    })?;

    let expected_verification = hash_nonce(&client_nonce);

    if expected_verification != nonce_verification {
        return Err(ProtocolError::HandshakeError(
            constants::ERR_NONCE_VERIFICATION_FAILED.into(),
        ));
    }

    // Store server info
    state.server_public = Some(server_pub_key);
    state.server_nonce = Some(server_nonce);
    // Verify that server correctly verified our nonce
    let client_nonce = state.client_nonce.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_CLIENT_NONCE_NOT_FOUND.into())
    })?;

    let expected_verification = hash_nonce(&client_nonce);

    if expected_verification != nonce_verification {
        return Err(ProtocolError::HandshakeError(
            constants::ERR_NONCE_VERIFICATION_FAILED.into(),
        ));
    }

    // Store server info
    state.server_public = Some(server_pub_key);
    state.server_nonce = Some(server_nonce);

    // Hash the server nonce for verification
    let hash = hash_nonce(&server_nonce);

    debug!("Client verified server response");

    Ok((
        state,
        Message::SecureHandshakeConfirm {
            nonce_verification: hash,
        },
    ))
}

/// Server verifies client's confirmation and derives session key.
/// Returns the session key if verification succeeds.
///
/// # Returns
/// The derived session key (32 bytes)
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if verification fails or state is incomplete
#[instrument(skip(state, nonce_verification))]
pub fn server_secure_handshake_finalize(
    mut state: ServerHandshakeState,
    nonce_verification: [u8; 32],
) -> Result<[u8; 32]> {
    // Verify that client correctly verified our nonce
    let server_nonce = state.server_nonce.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_SERVER_NONCE_NOT_FOUND.into())
    })?;

    let expected_verification = hash_nonce(&server_nonce);

    if expected_verification != nonce_verification {
        return Err(ProtocolError::HandshakeError(
            constants::ERR_SERVER_VERIFICATION_FAILED.into(),
        ));
    }

    // Extract and take ownership of secret data for key derivation
    let server_secret = state.secret.take().ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_SERVER_SECRET_NOT_FOUND.into())
    })?;
    let client_public_bytes = state.client_public.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_CLIENT_PUBLIC_NOT_FOUND.into())
    })?;
    let client_nonce = state.client_nonce.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_CLIENT_NONCE_NOT_FOUND.into())
    })?;

    // Perform ECDH to derive shared secret
    let client_public = PublicKey::from(client_public_bytes);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    // Derive final key using shared secret and both nonces
    let key = derive_key_from_shared_secret(&shared_secret, &client_nonce, &server_nonce);

    // State will be zeroized on drop due to Zeroize derive
    debug!("Server finalized handshake and derived session key");

    Ok(key)
}

/// Client derives the session key.
/// Must be called after `client_secure_handshake_verify`.
///
/// # Returns
/// The derived session key (32 bytes)
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if state is incomplete
#[instrument(skip(state))]
pub fn client_derive_session_key(mut state: ClientHandshakeState) -> Result<[u8; 32]> {
    // Extract required data
    let client_secret = state.secret.take().ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_CLIENT_SECRET_NOT_FOUND.into())
    })?;
    let server_public_bytes = state.server_public.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_SERVER_PUBLIC_NOT_FOUND.into())
    })?;
    let client_nonce = state.client_nonce.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_CLIENT_NONCE_NOT_FOUND.into())
    })?;
    let server_nonce = state.server_nonce.ok_or_else(|| {
        ProtocolError::HandshakeError(constants::ERR_SERVER_NONCE_NOT_FOUND.into())
    })?;

    // Perform ECDH to derive shared secret
    let server_public = PublicKey::from(server_public_bytes);
    let shared_secret = client_secret.diffie_hellman(&server_public);

    // Derive session key
    let key = derive_key_from_shared_secret(&shared_secret, &client_nonce, &server_nonce);

    // State will be zeroized on drop
    debug!("Client derived session key");

    Ok(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_per_session_state_isolation() {
        let mut replay_cache = crate::utils::replay_cache::ReplayCache::new();
        let peer_id = "test-peer";

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

        // Verify they are different
        assert_ne!(pub_key1, pub_key2);
        assert_ne!(nonce1, nonce2);

        // Server responses should be independent
        let (server1, resp1) =
            server_secure_handshake_response(pub_key1, nonce1, ts1, peer_id, &mut replay_cache)
                .unwrap();
        let (server2, resp2) =
            server_secure_handshake_response(pub_key2, nonce2, ts2, peer_id, &mut replay_cache)
                .unwrap();

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

        // Client verifications
        let (client1_verified, confirm1) = client_secure_handshake_verify(
            client1,
            server_pub1,
            server_nonce1,
            verify1,
            peer_id,
            &mut replay_cache,
        )
        .unwrap();
        let (client2_verified, confirm2) = client_secure_handshake_verify(
            client2,
            server_pub2,
            server_nonce2,
            verify2,
            peer_id,
            &mut replay_cache,
        )
        .unwrap();

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

        // Keys should match on both sides
        assert_eq!(key1_server, key1_client);
        assert_eq!(key2_server, key2_client);

        // But different pairs should have different keys
        assert_ne!(key1_server, key2_server);
    }

    #[test]
    fn test_timestamp_validation() {
        let now = current_timestamp().unwrap();
        assert!(verify_timestamp(now, 30));
        assert!(verify_timestamp(now - 10000, 30)); // 10 seconds ago
        assert!(!verify_timestamp(now - 31000, 30)); // 31 seconds ago
        assert!(verify_timestamp(now + 1000, 30)); // 1 second in future (within tolerance)
        assert!(!verify_timestamp(now + 3000, 30)); // 3 seconds in future (beyond tolerance)
    }

    #[test]
    fn test_nonce_verification() {
        let nonce = generate_nonce();
        let hash = hash_nonce(&nonce);
        assert_eq!(hash.len(), 32);
        // Same nonce should produce same hash
        assert_eq!(hash, hash_nonce(&nonce));
        // Different nonce should produce different hash
        let mut different_nonce = nonce;
        different_nonce[0] ^= 0xFF;
        assert_ne!(hash, hash_nonce(&different_nonce));
    }
}
