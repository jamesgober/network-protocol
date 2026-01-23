use futures::{SinkExt, StreamExt};
use tokio::time;
use tracing::{debug, info, instrument, warn};

use crate::config::ClientConfig;

use crate::core::packet::Packet;
use crate::protocol::message::Message;
// Import secure handshake functions
use crate::error::{ProtocolError, Result};
use crate::protocol::handshake::{
    client_derive_session_key, client_secure_handshake_init, client_secure_handshake_verify,
};
use crate::protocol::heartbeat::{build_ping, is_pong};
use crate::protocol::keepalive::KeepAliveManager;
use crate::service::secure::SecureConnection;
use crate::transport::remote;
use crate::utils::timeout::with_timeout_error;

/// High-level protocol client with post-handshake encryption
pub struct Client {
    conn: SecureConnection,
    keep_alive: KeepAliveManager,
    config: ClientConfig,
}

impl Client {
    /// Connect and perform secure handshake with timeout using default configuration
    #[instrument(skip(addr), fields(address = %addr))]
    pub async fn connect(addr: &str) -> Result<Self> {
        let config = ClientConfig {
            address: addr.to_string(),
            ..Default::default()
        };
        Self::connect_with_config(config).await
    }

    /// Connect and perform secure handshake with custom configuration
    #[instrument(skip(config), fields(address = %config.address))]
    pub async fn connect_with_config(config: ClientConfig) -> Result<Self> {
        // Connect with timeout
        let mut framed = with_timeout_error(
            async { remote::connect(&config.address).await },
            config.connection_timeout,
        )
        .await?;

        // --- Legacy Handshake Support ---
        // Commented out legacy code for reference
        // #[allow(deprecated)]
        // async fn legacy_handshake(framed: &mut remote::RemoteFramed) -> Result<[u8; 32]> {
        //     // Legacy handshake process
        //     let (client_nonce, handshake) = client_handshake_init();
        //
        // --- Secure Handshake Process ---
        // Step 1: Send client init with public key, nonce, and timestamp
        let (client_state, init_msg) = client_secure_handshake_init()?;
        let init_bytes = bincode::serialize(&init_msg)?;
        framed
            .send(Packet {
                version: 1,
                payload: init_bytes,
            })
            .await?;

        // Step 2: Receive server response with timeout
        let response = with_timeout_error(
            async {
                let packet = framed
                    .next()
                    .await
                    .ok_or(ProtocolError::ConnectionClosed)?
                    .map_err(|e| ProtocolError::TransportError(e.to_string()))?;
                bincode::deserialize::<Message>(&packet.payload)
                    .map_err(|e| ProtocolError::DeserializeError(e.to_string()))
            },
            config.connection_timeout,
        )
        .await?;

        // Step 3: Verify server response and send confirmation
        // Extract data from server response
        let (server_pub_key, server_nonce, nonce_verification) = match response {
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

        // Verify the server's response and prepare confirmation message
        let (client_state_verified, verify_msg) = client_secure_handshake_verify(
            client_state,
            server_pub_key,
            server_nonce,
            nonce_verification,
        )?;

        let verify_bytes = bincode::serialize(&verify_msg)?;
        framed
            .send(Packet {
                version: 1,
                payload: verify_bytes,
            })
            .await?;

        // Step 4: Derive shared session key
        let key = client_derive_session_key(client_state_verified)?;
        let conn = SecureConnection::new(framed, key);

        // Create keep-alive manager with configured interval
        let dead_timeout = config.heartbeat_interval.mul_f32(4.0); // 4x the heartbeat interval
        let keep_alive = KeepAliveManager::with_settings(config.heartbeat_interval, dead_timeout);

        info!("Connection established successfully");
        Ok(Self {
            conn,
            keep_alive,
            config,
        })
    }

    /// Securely send a message
    #[instrument(skip(self, msg))]
    pub async fn send(&mut self, msg: Message) -> Result<()> {
        let result = self.conn.secure_send(msg).await;
        if result.is_ok() {
            self.keep_alive.update_send();
        }
        result
    }

    /// Securely receive a message
    #[instrument(skip(self))]
    pub async fn recv(&mut self) -> Result<Message> {
        let result = self.conn.secure_recv().await;
        if result.is_ok() {
            self.keep_alive.update_recv();
        }
        result
    }

    /// Send a keep-alive ping to the server
    #[instrument(skip(self))]
    pub async fn send_keepalive(&mut self) -> Result<()> {
        debug!("Sending keep-alive ping");
        let ping = build_ping();
        self.send(ping).await
    }

    /// Wait for messages with keep-alive handling using custom timeout
    #[instrument(skip(self))]
    pub async fn recv_with_keepalive(
        &mut self,
        timeout_duration: std::time::Duration,
    ) -> Result<Message> {
        let mut ping_interval = time::interval(self.keep_alive.ping_interval());

        let timeout = time::sleep(timeout_duration);
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                // Check if we need to send a ping
                _ = ping_interval.tick() => {
                    if self.keep_alive.should_ping() {
                        self.send_keepalive().await?;
                    }

                    // Check if connection is dead
                    if self.keep_alive.is_connection_dead() {
                        warn!(dead_seconds = ?self.keep_alive.time_since_last_recv().as_secs(),
                              "Connection appears dead");
                        return Err(ProtocolError::ConnectionTimeout);
                    }
                }

                // Try to receive a message
                recv_result = self.conn.secure_recv::<Message>() => {
                    match recv_result {
                        Ok(msg) => {
                            self.keep_alive.update_recv();

                            // Filter out pong messages, return everything else
                            if !is_pong(&msg) {
                                return Ok(msg);
                            } else {
                                debug!("Received pong response");
                                // Continue waiting for non-pong messages
                            }
                        }
                        Err(ProtocolError::Timeout) => {
                            // Timeout is expected, just continue the loop
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }

                // User-provided timeout
                _ = &mut timeout => {
                    return Err(ProtocolError::Timeout);
                }
            }
        }
    }

    /// Send a message and wait for a response with keep-alive handling
    #[instrument(skip(self, msg))]
    pub async fn send_and_wait(&mut self, msg: Message) -> Result<Message> {
        self.send(msg).await?;
        // Use configured response timeout
        self.recv_with_keepalive(self.config.response_timeout).await
    }
}
