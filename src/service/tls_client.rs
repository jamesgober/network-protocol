use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::Framed;
use tracing::{debug, instrument};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::{ProtocolError, Result};
use crate::protocol::message::Message;
use crate::transport::session_cache::SessionCache;
use crate::transport::tls::TlsClientConfig;
use crate::utils::timeout::HANDSHAKE_TIMEOUT;

/// TLS secure client for connecting to TLS-enabled servers
///
/// Supports optional session resumption for improved reconnection performance.
/// With session resumption, reconnections can skip the full TLS handshake,
/// reducing latency by ~50-70%.
pub struct TlsClient {
    framed: Framed<TlsStream<TcpStream>, PacketCodec>,
    /// Optional session cache for resumption support
    session_cache: Option<Arc<SessionCache>>,
    /// Session identifier (used with session cache)
    session_id: Option<String>,
}

impl TlsClient {
    /// Connect to a TLS server
    #[instrument(skip(config))]
    pub async fn connect(addr: &str, config: TlsClientConfig) -> Result<Self> {
        Self::connect_with_session(addr, config, None).await
    }

    /// Connect to a TLS server with session resumption support
    ///
    /// With a session cache, the server's session tickets are stored in it and offered
    /// on later connections that use the same cache, so a reconnect to the same server
    /// name resumes the session instead of running a full handshake. Without one, every
    /// connection does a full handshake.
    ///
    /// # Arguments
    /// * `addr` - Server address to connect to
    /// * `config` - TLS configuration
    /// * `session_cache` - Optional session cache for resumption
    ///
    /// # Example
    /// ```ignore
    /// let cache = SessionCache::new(100, Duration::from_secs(3600));
    /// let client = TlsClient::connect_with_session(
    ///     "127.0.0.1:8443",
    ///     config,
    ///     Some(Arc::new(cache))
    /// ).await?;
    /// ```
    pub async fn connect_with_session(
        addr: &str,
        config: TlsClientConfig,
        session_cache: Option<Arc<SessionCache>>,
    ) -> Result<Self> {
        let tls_config = match &session_cache {
            // The cache supplies one shared config per TLS configuration, so later
            // connections see the same verifier and session store and can resume.
            Some(cache) => {
                debug!("Session resumption enabled");
                cache.tls_client_config(&config)?
            }
            None => {
                let mut tls_config = config.load_client_config()?;
                tls_config.resumption = rustls::client::Resumption::disabled();
                Arc::new(tls_config)
            }
        };
        let connector = tokio_rustls::TlsConnector::from(tls_config);

        let domain = config.owned_server_name()?;

        let stream = TcpStream::connect(addr).await?;

        let tls_stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, stream))
            .await
            .map_err(|_| ProtocolError::Timeout)??;
        let framed = Framed::new(tls_stream, PacketCodec);

        let session_id = format!(
            "{}_{}",
            addr,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        Ok(Self {
            framed,
            session_cache,
            session_id: Some(session_id),
        })
    }

    /// Send a message to the TLS server
    pub async fn send(&mut self, message: Message) -> Result<()> {
        let bytes = bincode::serialize(&message)?;
        let packet = Packet {
            version: 1,
            payload: bytes,
        };

        self.framed.send(packet).await?;
        Ok(())
    }

    /// Receive a message from the TLS server
    pub async fn receive(&mut self) -> Result<Message> {
        let packet = match self.framed.next().await {
            Some(Ok(pkt)) => pkt,
            Some(Err(e)) => return Err(e),
            None => {
                return Err(crate::error::ProtocolError::Custom(
                    "Connection closed".to_string(),
                ))
            }
        };

        let message = bincode::deserialize(&packet.payload)?;
        Ok(message)
    }

    /// Send a message and wait for a response
    pub async fn request(&mut self, message: Message) -> Result<Message> {
        self.send(message).await?;
        self.receive().await
    }

    /// Get the session cache if configured
    pub fn session_cache(&self) -> Option<&SessionCache> {
        self.session_cache.as_deref()
    }

    /// Get the session identifier
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}
