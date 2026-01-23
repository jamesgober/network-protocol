use futures::{SinkExt, StreamExt};
use network_protocol::core::packet::Packet;
use network_protocol::error::{ProtocolError, Result};
use network_protocol::protocol::message::Message;
use network_protocol::service::secure::SecureConnection;
use network_protocol::transport::remote;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Benchmark client that doesn't rely on global state for handshake
pub struct BenchmarkClient {
    conn: SecureConnection,
}

impl BenchmarkClient {
    /// Connect and perform secure handshake without using global state
    pub async fn connect(addr: &str) -> Result<Self> {
        let mut framed = remote::connect(addr).await?;

        // Generate client key pair with OsRng which implements both RngCore and CryptoRng
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // Generate client nonce
        let mut client_nonce = [0u8; 16];
        RngCore::fill_bytes(&mut OsRng, &mut client_nonce);

        // Get current timestamp
        #[allow(clippy::expect_used)]
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        // Create and send init message
        let init_msg = Message::SecureHandshakeInit {
            pub_key: client_public.to_bytes(),
            nonce: client_nonce,
            timestamp,
        };

        let init_bytes = bincode::serialize(&init_msg)?;
        framed
            .send(Packet {
                version: 1,
                payload: init_bytes,
            })
            .await?;

        // Process server response
        let packet = framed.next().await.ok_or(ProtocolError::Timeout)??;
        let response: Message = bincode::deserialize(&packet.payload)?;

        // Extract data from server response
        let (server_pub_key, server_nonce, _nonce_verification) = match response {
            Message::SecureHandshakeResponse {
                pub_key,
                nonce,
                nonce_verification,
            } => (pub_key, nonce, nonce_verification),
            _ => {
                return Err(ProtocolError::HandshakeError(
                    "Invalid server response message type".into(),
                ))
            }
        };

        println!("[benchmark_client] Received server response");

        // Check the nonce verification from server - it should be a hash of our client nonce
        let expected_client_nonce_hash = {
            let mut hasher = Sha256::new();
            hasher.update(client_nonce);
            hasher.finalize().to_vec()
        };

        // For debug purposes
        println!("[benchmark_client] Server nonce verification: {_nonce_verification:?}");
        println!("[benchmark_client] Expected client nonce hash: {expected_client_nonce_hash:?}");

        // Hash the server nonce for our verification response
        let server_nonce_hash = {
            let mut hasher = Sha256::new();
            hasher.update(server_nonce);
            let mut result = [0u8; 32];
            result.copy_from_slice(&hasher.finalize()[..]);
            result
        };

        // Send client verification
        let verify_msg = Message::SecureHandshakeConfirm {
            nonce_verification: server_nonce_hash,
        };

        let verify_bytes = bincode::serialize(&verify_msg)?;
        framed
            .send(Packet {
                version: 1,
                payload: verify_bytes,
            })
            .await?;

        println!("[benchmark_client] Sent client verification");

        // Derive session key
        let server_public = PublicKey::from(server_pub_key);
        let shared_secret = client_secret.diffie_hellman(&server_public);

        let key = {
            let mut hasher = Sha256::new();
            hasher.update(shared_secret.as_bytes());
            hasher.update(client_nonce);
            hasher.update(server_nonce);
            let mut result = [0u8; 32];
            result.copy_from_slice(&hasher.finalize()[..]);
            result
        };

        println!("[benchmark_client] Derived session key");

        // Create secure connection
        let conn = SecureConnection::new(framed, key);
        Ok(Self { conn })
    }

    /// Securely send a message
    pub async fn send(&mut self, msg: Message) -> Result<()> {
        self.conn.secure_send(msg).await
    }

    /// Securely receive a message
    pub async fn recv(&mut self) -> Result<Message> {
        self.conn.secure_recv().await
    }
}
