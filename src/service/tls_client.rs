use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::Framed;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::Result;
use crate::protocol::message::Message;
use crate::transport::tls::TlsClientConfig;

/// TLS secure client for connecting to TLS-enabled servers
pub struct TlsClient {
    framed: Framed<TlsStream<TcpStream>, PacketCodec>,
}

impl TlsClient {
    /// Connect to a TLS server
    pub async fn connect(addr: &str, config: TlsClientConfig) -> Result<Self> {
        let tls_config = config.load_client_config()?;
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));

        let stream = TcpStream::connect(addr).await?;
        let domain = config.server_name()?;

        let tls_stream = connector.connect(domain, stream).await?;
        let framed = Framed::new(tls_stream, PacketCodec);

        Ok(Self { framed })
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
}
