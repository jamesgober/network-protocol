use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, warn};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::dispatcher::Dispatcher;
use crate::protocol::message::Message;
// Secure connection not needed since TLS handles encryption
use crate::error::Result;
use crate::service::daemon::close_connections;
use crate::transport::tls::TlsServerConfig;
use crate::utils::timeout::HANDSHAKE_TIMEOUT;

/// How long shutdown waits for open connections before closing them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Start a secure TLS server and listen for connections
///
/// Runs until the process receives Ctrl-C, then shuts down gracefully.
#[instrument(skip(tls_config))]
pub async fn start(addr: &str, tls_config: TlsServerConfig) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Forward Ctrl-C to the shutdown channel. The task owns the only sender, so the
    // channel stays open (and the server keeps running) until the signal arrives.
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received shutdown signal, initiating graceful shutdown");
            let _ = shutdown_tx.send(()).await;
        }
    });

    start_with_shutdown(addr, tls_config, shutdown_rx).await
}

/// Start a secure TLS server with an external shutdown channel
///
/// The server shuts down gracefully when a `()` is sent on the channel. Dropping every
/// sender without sending does not stop the server.
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

    // Once every sender is gone, `recv()` returns `None` immediately; stop polling it
    // then instead of treating the closed channel as a shutdown request.
    let mut shutdown_open = true;

    // Connection tasks, so shutdown can wait for them and then close the rest
    let mut connections = JoinSet::new();

    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal
            signal = shutdown_rx.recv(), if shutdown_open => {
                if signal.is_none() {
                    shutdown_open = false;
                    continue;
                }
                info!(connections = connections.len(), "Shutting down server. Waiting for connections to close...");
                close_connections(&mut connections, SHUTDOWN_GRACE).await;
                return Ok(());
            }

            // Reap finished connection tasks
            Some(_) = connections.join_next(), if !connections.is_empty() => {}

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

                        connections.spawn(async move {
                            // Bound the handshake so a client that stalls cannot hold a
                            // connection slot open indefinitely.
                            let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
                            match handshake {
                                Ok(Ok(tls_stream)) => {
                                    if let Err(e) = handle_tls_connection(tls_stream, dispatcher, peer, active_connections).await {
                                        error!(%peer, error=%e, "Connection error");
                                    }
                                },
                                Ok(Err(e)) => {
                                    error!(%peer, error=%e, "TLS handshake failed");
                                    // Decrement connections on handshake failure
                                    let mut count = active_connections.lock().await;
                                    *count -= 1;
                                }
                                Err(_) => {
                                    warn!(%peer, "TLS handshake timed out");
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
