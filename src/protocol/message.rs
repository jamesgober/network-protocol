use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[repr(u8)]
pub enum Message {
    Ping,
    Pong,

    /// Secure handshake using ECDH key exchange
    /// Client initiates with its public key and a timestamp to prevent replay attacks
    SecureHandshakeInit {
        /// Client's public key for ECDH exchange
        pub_key: [u8; 32],
        /// Timestamp to prevent replay attacks
        timestamp: u64,
        /// Random nonce for additional security
        nonce: [u8; 16],
    },

    /// Server responds with its public key and a signature
    SecureHandshakeResponse {
        /// Server's public key for ECDH exchange
        pub_key: [u8; 32],
        /// Server's nonce (different from client nonce)
        nonce: [u8; 16],
        /// Hash of the client's nonce to prove receipt
        nonce_verification: [u8; 32],
    },

    /// Final handshake confirmation from client
    SecureHandshakeConfirm {
        /// Hash of server's nonce to prove receipt
        nonce_verification: [u8; 32],
    },

    // Placeholder for custom commands:
    Echo(String),
    Disconnect,

    // Custom command with payload for testing and extensibility
    Custom {
        command: String,
        payload: Vec<u8>,
    },

    #[serde(other)]
    Unknown,
}
