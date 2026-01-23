use chacha20poly1305::{
    // OsRng and generic_array::GenericArray are unused
    aead::{Aead, KeyInit},
    Key,
    XChaCha20Poly1305,
    XNonce,
};
use getrandom::fill;

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
    #[allow(clippy::expect_used)] // cryptographic RNG failure is unrecoverable
    pub fn generate_nonce() -> [u8; 24] {
        let mut nonce = [0u8; 24];
        fill(&mut nonce).expect("Failed to fill nonce");
        nonce
    }
}
