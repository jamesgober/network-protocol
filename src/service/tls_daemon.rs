use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, warn};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::dispatcher::Dispatcher;
use crate::protocol::message::Message;
// Secure connection not needed since TLS handles encryption
use crate::error::Result;
use crate::transport::tls::TlsServerConfig;

/// Start a secure TLS server and listen for connections
#[instrument(skip(tls_config))]
pub async fn start(addr: &str, tls_config: TlsServerConfig) -> Result<()> {
    // Create shutdown channel
    let (_, shutdown_rx) = mpsc::channel::<()>(1);

    // Start with internal shutdown channel
    start_with_shutdown(addr, tls_config, shutdown_rx).await
}

/// Start a secure TLS server with an external shutdown channel
#[instrument(skip(tls_config, shutdown_rx))]
pub async fn start_with_shutdown(
    addr: &str,
    tls_config: TlsServerConfig,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    let config = tls_config.load_server_config()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(addr).await?;
    info!(address=%addr, "TLS daemon listening");

    // 🔁 Shared dispatcher
    let dispatcher = Arc::new({
        let d = Dispatcher::new();
        let _ = d.register("PING", |_| Ok(Message::Pong));
        let _ = d.register("ECHO", |msg| Ok(msg.clone()));
        d
    });

    // Track active connections
    let active_connections = Arc::new(Mutex::new(0u32));

    // Spawn ctrl-c handler to forward to the provided shutdown channel
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received shutdown signal, initiating graceful shutdown");
        }
    });

    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = shutdown_rx.recv() => {
                info!("Shutting down server. Waiting for connections to close...");

                // Wait for active connections to close (with timeout)
                let timeout = tokio::time::sleep(Duration::from_secs(10));
                tokio::pin!(timeout);

                loop {
                    tokio::select! {
                        _ = &mut timeout => {
                            warn!("Shutdown timeout reached, forcing exit");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let connections = *active_connections.lock().await;
                            debug!(connections, "Waiting for connections to close");
                            if connections == 0 {
                                info!("All connections closed, shutting down");
                                break;
                            }
                        }
                    }
                }

                return Ok(());
            }

            // Accept new connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer)) => {
                        info!(%peer, "New connection accepted");
                        let dispatcher = dispatcher.clone();
                        let acceptor = acceptor.clone();
                        let active_connections = active_connections.clone();

                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                        }

                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    if let Err(e) = handle_tls_connection(tls_stream, dispatcher, peer, active_connections).await {
                                        error!(%peer, error=%e, "Connection error");
                                    }
                                },
                                Err(e) => {
                                    error!(%peer, error=%e, "TLS handshake failed");
                                    // Decrement connections on handshake failure
                                    let mut count = active_connections.lock().await;
                                    *count -= 1;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(error=%e, "Error accepting connection");
                    }
                }
            }
        }
    }
}

/// Handle a TLS connection
#[instrument(skip(tls_stream, dispatcher, active_connections), fields(peer=%peer))]
async fn handle_tls_connection(
    tls_stream: TlsStream<TcpStream>,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr,
    active_connections: Arc<Mutex<u32>>,
) -> Result<()> {
    let mut framed = Framed::new(tls_stream, PacketCodec);

    info!("TLS connection established");

    // Unlike regular daemon, we don't need a separate handshake
    // TLS already provides the encryption layer

    // Message loop
    loop {
        let packet = match framed.next().await {
            Some(Ok(pkt)) => pkt,
            Some(Err(e)) => {
                error!(error=%e, "Protocol error");
                break;
            }
            None => break,
        };

        // Deserialize the message
        let msg = match bincode::deserialize::<Message>(&packet.payload) {
            Ok(m) => m,
            Err(e) => {
                error!(error=%e, "Deserialization error");
                continue;
            }
        };

        debug!(message=?msg, "Received message");

        // Process with dispatcher
        match dispatcher.dispatch(&msg) {
            Ok(reply) => {
                let reply_bytes = match bincode::serialize(&reply) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!(error=%e, "Serialization error");
                        continue;
                    }
                };

                let reply_packet = Packet {
                    version: packet.version,
                    payload: reply_bytes,
                };

                if let Err(e) = framed.send(reply_packet).await {
                    error!(error=%e, "Send error");
                    break;
                }
            }
            Err(e) => {
                error!(error=%e, "Dispatch error");
                break;
            }
        }
    }

    info!("Connection closed");

    // Decrement connection counter on disconnect
    {
        let mut count = active_connections.lock().await;
        *count -= 1;
    }

    Ok(())
}
