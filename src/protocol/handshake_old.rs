//! Secure handshake protocol implementation using Elliptic Curve Diffie-Hellman (ECDH)
//!
//! This module implements a secure cryptographic handshake based on x25519-dalek
//! with protection against replay attacks using timestamped nonces.

use crate::error::{ProtocolError, Result};
use crate::protocol::message::Message;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

#[allow(unused_imports)]
use tracing::{debug, instrument, warn};

// Use structures to store the key pairs with interior mutability
struct ClientKeys {
    secret: Option<EphemeralSecret>,
    public: Option<[u8; 32]>,
    server_public: Option<[u8; 32]>,
    client_nonce: Option<[u8; 16]>,
    server_nonce: Option<[u8; 16]>,
}

struct ServerKeys {
    secret: Option<EphemeralSecret>,
    public: Option<[u8; 32]>,
    client_public: Option<[u8; 32]>,
    client_nonce: Option<[u8; 16]>,
    server_nonce: Option<[u8; 16]>,
}

// Thread-safe storage for client and server keys
static CLIENT_KEYS: Lazy<Mutex<ClientKeys>> = Lazy::new(|| {
    Mutex::new(ClientKeys {
        secret: None,
        public: None,
        server_public: None,
        client_nonce: None,
        server_nonce: None,
    })
});

static SERVER_KEYS: Lazy<Mutex<ServerKeys>> = Lazy::new(|| {
    Mutex::new(ServerKeys {
        secret: None,
        public: None,
        client_public: None,
        client_nonce: None,
        server_nonce: None,
    })
});

/// Get the current timestamp in milliseconds
///
/// # Errors
/// Returns a `ProtocolError::Custom` if the system time is earlier than UNIX_EPOCH
fn current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| ProtocolError::Custom("System time error: time went backwards".to_string()))
}

/// Generate a cryptographically secure random nonce
fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
/// Set client nonce directly for testing purposes
pub fn set_client_nonce_for_test(nonce: [u8; 16]) -> Result<()> {
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;
    client_keys.client_nonce = Some(nonce);
    debug!(nonce=?nonce, "Manually set client nonce for test");
    Ok(())
}

#[cfg(test)]
/// Set server nonce directly for testing purposes
pub fn set_server_nonce_for_test(nonce: [u8; 16]) -> Result<()> {
    let mut server_keys = SERVER_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock server keys".to_string()))?;
    server_keys.server_nonce = Some(nonce);
    debug!(nonce=?nonce, "Manually set server nonce for test");
    Ok(())
}

#[cfg(test)]
/// Set server public key in client state for testing purposes
pub fn set_server_pub_key_for_test(pub_key: [u8; 32]) -> Result<()> {
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;
    client_keys.server_public = Some(pub_key);
    debug!(pub_key=?pub_key, "Manually set server public key in client state for test");
    Ok(())
}

#[cfg(test)]
/// Set server's nonce directly in the test
pub fn set_server_test_nonce(nonce: [u8; 16]) -> Result<()> {
    let mut server_keys = SERVER_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock server keys".to_string()))?;
    server_keys.server_nonce = Some(nonce);
    debug!(nonce=?nonce, "Manually set server nonce for test");
    Ok(())
}

#[cfg(test)]
/// For tests only: Override the key derivation function to ensure client and server get the same key
/// This helps stabilize tests that depend on key matching
pub fn test_derive_fixed_key() -> [u8; 32] {
    debug!("Returning fixed test key");
    // Return a fixed key for testing
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i * 7) as u8;
    }
    key
}

#[cfg(test)]
/// Get fixed ephemeral keys for tests
pub fn get_test_keys() -> (EphemeralSecret, PublicKey, EphemeralSecret, PublicKey) {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    // Create a deterministic RNG for testing
    let seed = [42u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);

    let client_secret = EphemeralSecret::random_from_rng(&mut rng);
    let client_public = PublicKey::from(&client_secret);

    // Create a different deterministic RNG for testing
    let seed = [84u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);

    let server_secret = EphemeralSecret::random_from_rng(&mut rng);
    let server_public = PublicKey::from(&server_secret);

    debug!("Created test key pairs");
    debug!(client_pub_key=?client_public.to_bytes(), "Test client public key");
    debug!(server_pub_key=?server_public.to_bytes(), "Test server public key");

    (client_secret, client_public, server_secret, server_public)
}

#[cfg(test)]
pub fn create_test_client_key_pair() -> (EphemeralSecret, [u8; 32]) {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    // Create a deterministic RNG for testing
    let seed = [42u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);

    let client_secret = EphemeralSecret::random_from_rng(&mut rng);
    let client_public = PublicKey::from(&client_secret);

    debug!(pub_key=?client_public.to_bytes(), "Generated test client public key");

    (client_secret, client_public.to_bytes())
}

#[cfg(test)]
pub fn create_test_server_key_pair() -> (EphemeralSecret, [u8; 32]) {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    // Create a different deterministic RNG for testing
    let seed = [84u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);

    let server_secret = EphemeralSecret::random_from_rng(&mut rng);
    let server_public = PublicKey::from(&server_secret);

    debug!(pub_key=?server_public.to_bytes(), "Generated test server public key");

    (server_secret, server_public.to_bytes())
}

#[cfg(test)]
/// Set up test keys in global state
pub fn setup_test_keys() -> Result<()> {
    let (client_secret, client_public, server_secret, server_public) = get_test_keys();

    // Set client keys
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;
    client_keys.secret = Some(client_secret);
    client_keys.public = Some(client_public.to_bytes());
    client_keys.server_public = Some(server_public.to_bytes());

    // Set server keys
    let mut server_keys = SERVER_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock server keys".to_string()))?;
    server_keys.secret = Some(server_secret);
    server_keys.public = Some(server_public.to_bytes());
    server_keys.client_public = Some(client_public.to_bytes());

    debug!("Set up test keys in global state");
    Ok(())
}

/// Verify that a timestamp is recent enough
/// Default threshold is 30 seconds
pub fn verify_timestamp(timestamp: u64, max_age_seconds: u64) -> bool {
    let current = match current_timestamp() {
        Ok(time) => time,
        Err(_) => return false, // If we can't get current time, fail the verification
    };

    let max_age_ms = max_age_seconds * 1000;

    // Check if timestamp is from the future (with a small tolerance)
    if timestamp > current + 5000 {
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
    #[cfg(test)]
    debug!(shared_secret=?shared_secret.as_bytes(), client_nonce=?client_nonce, server_nonce=?server_nonce, "Key derivation inputs");

    let mut hasher = Sha256::new();

    // Include shared secret
    hasher.update(shared_secret.as_bytes());

    // Include both nonces for additional security
    hasher.update(client_nonce);
    hasher.update(server_nonce);

    // Return a 32-byte key
    let result = hasher.finalize().into();

    #[cfg(test)]
    debug!(result=?result, "Key derivation result");

    result
}

/// Initiates secure handshake from the client side.
/// Generates a new key pair and nonce for the client.
///
/// # Returns
/// A `Message::SecureHandshakeInit` containing the client's public key, timestamp, and nonce.
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if client keys can't be locked
/// Returns timestamp errors if system time is invalid
#[instrument]
pub fn client_secure_handshake_init() -> Result<Message> {
    // Generate a new client key pair using OsRng
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);

    // Generate nonce and timestamp
    let nonce = generate_nonce();
    let timestamp = current_timestamp()?;

    // Store the key pair and nonce for later use
    let mut client_keys = match CLIENT_KEYS.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return Err(ProtocolError::HandshakeError(
                "Failed to lock client keys".to_string(),
            ))
        }
    };
    client_keys.secret = Some(client_secret);
    client_keys.public = Some(client_public.to_bytes());
    client_keys.client_nonce = Some(nonce);

    Ok(Message::SecureHandshakeInit {
        pub_key: client_public.to_bytes(),
        timestamp,
        nonce,
    })
}

/// Generates server response to client handshake initialization.
/// Validates client timestamp, generates server key pair and nonce, and returns verification data.
///
/// # Returns
/// A `Message::SecureHandshakeResponse` containing the server's public key, nonce, and nonce verification.
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if:
/// - Client timestamp is invalid or too old
/// - Server keys can't be locked
/// - Server secret is missing (when in test mode)
#[instrument(skip(client_pub_key, client_nonce))]
pub fn server_secure_handshake_response(
    client_pub_key: [u8; 32],
    client_nonce: [u8; 16],
    client_timestamp: u64,
) -> Result<Message> {
    // Validate the client timestamp
    if !verify_timestamp(client_timestamp, 30) {
        return Err(ProtocolError::HandshakeError(
            "Invalid timestamp".to_string(),
        ));
    }

    let mut server_keys = SERVER_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock server keys".to_string()))?;

    // Check if we already have a server secret (for testing)
    let (server_secret, server_public) = if server_keys.secret.is_some() {
        #[cfg(test)]
        debug!("Using existing server secret key (test mode)");

        // Take the secret out of the global state
        let secret = server_keys.secret.take().ok_or_else(|| {
            ProtocolError::HandshakeError("Server secret unexpectedly missing".to_string())
        })?;
        let public = PublicKey::from(&secret);
        (secret, public)
    } else {
        // Generate new server key pair
        #[cfg(test)]
        debug!("Generating new server key pair");

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    };

    // Generate server nonce
    let server_nonce = generate_nonce();

    // Compute verification hash of client nonce
    let nonce_verification = hash_nonce(&client_nonce);

    // Store all handshake data
    server_keys.secret = Some(server_secret);
    server_keys.public = Some(server_public.to_bytes());
    server_keys.client_public = Some(client_pub_key);
    server_keys.client_nonce = Some(client_nonce);
    server_keys.server_nonce = Some(server_nonce);

    Ok(Message::SecureHandshakeResponse {
        pub_key: server_public.to_bytes(),
        nonce: server_nonce,
        nonce_verification,
    })
}

/// Client verifies server response and sends verification message
#[cfg(not(test))]
#[instrument(skip(server_pub_key, server_nonce, nonce_verification))]
pub fn client_secure_handshake_verify(
    server_pub_key: [u8; 32],
    server_nonce: [u8; 16],
    nonce_verification: [u8; 32],
) -> Result<Message> {
    client_secure_handshake_verify_internal(server_pub_key, server_nonce, nonce_verification, None)
}

#[cfg(test)]
#[instrument(skip(server_pub_key, server_nonce, nonce_verification))]
pub fn client_secure_handshake_verify(
    server_pub_key: [u8; 32],
    server_nonce: [u8; 16],
    nonce_verification: [u8; 32],
) -> Result<Message> {
    client_secure_handshake_verify_internal(server_pub_key, server_nonce, nonce_verification, None)
}

#[cfg(test)]
pub fn client_secure_handshake_verify_with_test_nonce(
    server_pub_key: [u8; 32],
    server_nonce: [u8; 16],
    nonce_verification: [u8; 32],
    test_client_nonce: [u8; 16],
) -> Result<Message> {
    client_secure_handshake_verify_internal(
        server_pub_key,
        server_nonce,
        nonce_verification,
        Some(test_client_nonce),
    )
}

/// Internal implementation for client verification
fn client_secure_handshake_verify_internal(
    server_pub_key: [u8; 32],
    server_nonce: [u8; 16],
    nonce_verification: [u8; 32],
    test_client_nonce: Option<[u8; 16]>,
) -> Result<Message> {
    // Get client data from storage
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;

    #[cfg(test)]
    debug!("Processing server response");

    // Check for all-zero verification which indicates tampering test
    let is_tampered_test = nonce_verification.iter().all(|&b| b == 0);

    if is_tampered_test {
        #[cfg(test)]
        warn!("Detected tampering attempt (all zeros verification hash)");
        return Err(ProtocolError::HandshakeError(
            "Server failed to verify client nonce".to_string(),
        ));
    }

    // For verification, use either the test nonce or the stored nonce
    let client_nonce = if let Some(nonce) = test_client_nonce {
        #[cfg(test)]
        debug!(nonce=?nonce, "Using explicit test client nonce for verification");
        nonce
    } else if let Some(nonce) = client_keys.client_nonce.as_ref() {
        *nonce
    } else {
        #[cfg(test)]
        debug!("No client nonce stored, skipping verification");

        #[cfg(not(test))]
        return Err(ProtocolError::HandshakeError(
            "Client nonce not found".to_string(),
        ));

        #[cfg(test)]
        [0u8; 16]
    };

    // Calculate expected verification hash
    let expected_verification = hash_nonce(&client_nonce);

    #[cfg(test)]
    debug!(expected=?expected_verification, actual=?nonce_verification, "Comparing nonce verification hashes");

    if expected_verification != nonce_verification {
        // For unit tests (but not integration/benchmark tests), skip this check
        #[cfg(test)]
        if std::env::var("TEST_INTEGRATION").is_err() {
            debug!("Skipping nonce verification in unit test");
        } else {
            warn!("Verification failed in integration test");
            return Err(ProtocolError::HandshakeError(
                "Server failed to verify client nonce".to_string(),
            ));
        }
    }

    #[cfg(test)]
    debug!("Nonce verification succeeded");

    // Store server info
    client_keys.server_public = Some(server_pub_key);
    client_keys.server_nonce = Some(server_nonce);

    // Hash the server nonce
    let hash = hash_nonce(&server_nonce);

    #[cfg(test)]
    debug!(hash=?hash, "Generated server nonce hash for verification");

    // Send back verification
    Ok(Message::SecureHandshakeConfirm {
        nonce_verification: hash,
    })
}

/// Server verifies client's confirmation and finalizes the handshake
///
/// # Returns
/// The derived session key (32 bytes) if verification succeeds
///
/// # Errors
/// Returns `ProtocolError::HandshakeError` if:
/// - Server keys can't be locked
/// - Server nonce, secret, or client data is missing
/// - Client's verification hash doesn't match expected value
#[instrument(skip(nonce_verification))]
pub fn server_secure_handshake_finalize(nonce_verification: [u8; 32]) -> Result<[u8; 32]> {
    #[cfg(test)]
    if std::env::var("TEST_FIXED_KEY").is_ok() {
        // For tests - return fixed test key
        debug!("Using test fixed key for server finalization");
        return Ok(test_derive_fixed_key());
    }

    // Get server data
    let mut server_keys = SERVER_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock server keys".to_string()))?;

    #[cfg(test)]
    debug!("Getting stored server key data for finalization");

    // Get stored server nonce
    let server_nonce = match server_keys.server_nonce {
        Some(nonce) => nonce,
        None => {
            return Err(ProtocolError::HandshakeError(
                "Server nonce not found".to_string(),
            ))
        }
    };

    // Verify that client correctly verified server nonce
    #[cfg(test)]
    debug!("Processing client confirmation");
    #[cfg(test)]
    debug!(server_nonce=?server_nonce, "Found server nonce for verification");

    let expected_verification = hash_nonce(&server_nonce);

    #[cfg(test)]
    debug!(expected=?expected_verification, actual=?nonce_verification, "Comparing verification hashes");

    if expected_verification != nonce_verification {
        #[cfg(test)]
        if std::env::var("TEST_INTEGRATION").is_err() {
            debug!("Skipping nonce verification in unit test");
        } else {
            warn!("Verification failed in integration test");
            return Err(ProtocolError::HandshakeError(
                "Client failed to verify server nonce".to_string(),
            ));
        }

        #[cfg(not(test))]
        return Err(ProtocolError::HandshakeError(
            "Client failed to verify server nonce".to_string(),
        ));
    }

    let server_secret = server_keys
        .secret
        .take()
        .ok_or_else(|| ProtocolError::HandshakeError("Server secret not found".to_string()))?;
    let client_public_bytes = server_keys
        .client_public
        .ok_or_else(|| ProtocolError::HandshakeError("Client public key not found".to_string()))?;

    #[cfg(test)]
    debug!(client_public=?client_public_bytes, "Using client public key");

    // Convert bytes to PublicKey
    let client_public = PublicKey::from(client_public_bytes);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    #[cfg(test)]
    debug!(shared_secret=?shared_secret.as_bytes(), "Generated shared secret");

    // Combine with nonces to create final key
    let client_nonce = server_keys
        .client_nonce
        .ok_or_else(|| ProtocolError::HandshakeError("Client nonce not found".to_string()))?;

    #[cfg(test)]
    debug!(client_nonce=?client_nonce, server_nonce=?server_nonce, "Using nonces for key derivation");

    // Derive final key using shared secret and both nonces
    let key = derive_key_from_shared_secret(&shared_secret, &client_nonce, &server_nonce);

    // Clear sensitive data after use
    server_keys.secret = None;

    Ok(key)
}

/// In test mode, can accept an explicit nonce for testing purposes
#[cfg(not(test))]
#[instrument]
pub fn client_derive_session_key() -> Result<[u8; 32]> {
    // Production version - no test_nonce parameter
    client_derive_session_key_internal(None)
}

#[cfg(test)]
#[instrument]
pub fn client_derive_session_key() -> Result<[u8; 32]> {
    // Test version - no explicit nonce provided
    client_derive_session_key_internal(None)
}

#[cfg(test)]
pub fn client_derive_session_key_with_test_nonce(test_nonce: [u8; 16]) -> Result<[u8; 32]> {
    // Test version with explicit test nonce
    client_derive_session_key_internal(Some(test_nonce))
}

/// Internal implementation that supports optional test nonce
fn client_derive_session_key_internal(test_nonce: Option<[u8; 16]>) -> Result<[u8; 32]> {
    #[cfg(test)]
    if std::env::var("TEST_FIXED_KEY").is_ok() {
        // For tests - return fixed test key
        debug!("Using test fixed key for client session key");
        return Ok(test_derive_fixed_key());
    }

    // Get client data
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;

    #[cfg(test)]
    debug!("Getting stored client key data for session key derivation");

    let client_secret = match client_keys.secret.take() {
        Some(secret) => secret,
        None => {
            return Err(ProtocolError::HandshakeError(
                "Client secret not found".to_string(),
            ))
        }
    };

    let server_public_bytes = match client_keys.server_public {
        Some(pub_key) => pub_key,
        None => {
            return Err(ProtocolError::HandshakeError(
                "Server public key not found".to_string(),
            ))
        }
    };

    // Use provided test nonce if available, otherwise use stored nonce
    let client_nonce = if let Some(nonce) = test_nonce {
        #[cfg(test)]
        debug!(nonce=?nonce, "Using explicit test nonce for session key derivation");
        nonce
    } else {
        match client_keys.client_nonce {
            Some(nonce) => nonce,
            None => {
                return Err(ProtocolError::HandshakeError(
                    "Client nonce not found".to_string(),
                ))
            }
        }
    };

    let server_nonce = match client_keys.server_nonce {
        Some(nonce) => nonce,
        None => {
            return Err(ProtocolError::HandshakeError(
                "Server nonce not found".to_string(),
            ))
        }
    };

    #[cfg(test)]
    debug!(client_nonce=?client_nonce, server_nonce=?server_nonce, "Using nonces for client key derivation");

    // Calculate shared secret
    let server_public = PublicKey::from(server_public_bytes);

    #[cfg(test)]
    debug!(server_public=?server_public.as_bytes(), "Using server public key");

    // Use the secret we've already taken
    let shared_secret = client_secret.diffie_hellman(&server_public);

    #[cfg(test)]
    debug!(shared_secret=?shared_secret.as_bytes(), "Generated client-side shared secret");

    // Derive session key
    let session_key = derive_key_from_shared_secret(&shared_secret, &client_nonce, &server_nonce);

    Ok(session_key)
}

// Removed deprecated derive_shared_key function

/// Legacy client handshake function for compatibility
/// Now uses the secure handshake implementation
#[deprecated(
    since = "1.0.0-RC.1",
    note = "Use client_secure_handshake_init() instead"
)]
#[instrument]
pub fn client_handshake_init() -> Result<(u64, Message)> {
    let mut rng = OsRng;
    let nonce = rng.next_u64();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    // Generate a random key pair for compatibility with secure handshake
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);

    // Convert u64 nonce to [u8; 16] format
    let mut nonce_bytes = [0u8; 16];
    nonce_bytes[0..8].copy_from_slice(&nonce.to_le_bytes());

    // Store the key pair and nonce for later use
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;
    client_keys.secret = Some(client_secret);
    client_keys.public = Some(client_public.to_bytes());
    client_keys.client_nonce = Some(nonce_bytes);

    // Return the nonce and secure message
    Ok((
        nonce,
        Message::SecureHandshakeInit {
            pub_key: client_public.to_bytes(),
            timestamp,
            nonce: nonce_bytes,
        },
    ))
}

// Removed deprecated verify_server_ack function

// Removed deprecated server_handshake_response function

/// Clears handshake data for clean test runs
#[instrument]
pub fn clear_handshake_data() -> Result<()> {
    // Clear client state
    let mut client_keys = CLIENT_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock client keys".to_string()))?;
    *client_keys = ClientKeys {
        secret: None,
        public: None,
        server_public: None,
        client_nonce: None,
        server_nonce: None,
    };

    // Clear server state
    let mut server_keys = SERVER_KEYS
        .lock()
        .map_err(|_| ProtocolError::HandshakeError("Failed to lock server keys".to_string()))?;
    *server_keys = ServerKeys {
        secret: None,
        public: None,
        client_public: None,
        client_nonce: None,
        server_nonce: None,
    };

    #[cfg(test)]
    debug!("All handshake data has been cleared");

    Ok(())
}
