use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use getrandom::fill;
use zeroize::Zeroize;

use crate::error::{ProtocolError, Result};

pub struct Crypto {
    cipher: XChaCha20Poly1305,
}

impl Crypto {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        let cipher = XChaCha20Poly1305::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>> {
        let nonce = XNonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| ProtocolError::EncryptionFailure)
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>> {
        let nonce = XNonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| ProtocolError::DecryptionFailure)
    }

    /// Generates a secure random 24-byte nonce
    /// Note: Returned nonce should be zeroized after use if it contains sensitive material
    #[allow(clippy::expect_used)] // cryptographic RNG failure is unrecoverable
    pub fn generate_nonce() -> [u8; 24] {
        let mut nonce = [0u8; 24];
        fill(&mut nonce).expect("Failed to fill nonce");
        nonce
    }

    /// Generate a random 32-byte key material
    /// Caller is responsible for zeroizing the returned bytes
    #[allow(clippy::expect_used)] // cryptographic RNG failure is unrecoverable
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        fill(&mut key).expect("Failed to fill key");
        key
    }
}

impl Drop for Crypto {
    fn drop(&mut self) {
        // Note: XChaCha20Poly1305 doesn't expose its internal key for zeroization
        // The underlying key material should be zeroized by the chacha20poly1305 crate
        // This is acceptable as the crate uses secure containers
    }
}

/// Shared secret wrapper that zeroizes on drop
#[derive(Clone)]
pub struct SharedSecret {
    secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_nonce_generation() {
        let nonce = Crypto::generate_nonce();
        assert_eq!(nonce.len(), 24);
        // Nonces should not be all zeros (extremely unlikely with secure RNG)
        assert!(nonce.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_crypto_key_generation() {
        let key = Crypto::generate_key();
        assert_eq!(key.len(), 32);
        // Keys should not be all zeros
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_shared_secret_zeroize() {
        let mut secret = SharedSecret::new([0xAB; 32]);
        secret.zeroize();
        assert!(secret.as_bytes().iter().all(|&b| b == 0));
    }
}
