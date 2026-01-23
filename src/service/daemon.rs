use bincode;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, warn};

use crate::config::ServerConfig;

use crate::utils::timeout::with_timeout_error;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
// Import secure handshake functions
use crate::error::{ProtocolError, Result};
use crate::protocol::dispatcher::Dispatcher;
use crate::protocol::handshake::{
    server_secure_handshake_finalize, server_secure_handshake_response,
};
use crate::protocol::heartbeat::{build_ping, is_pong};
use crate::protocol::keepalive::KeepAliveManager;
use crate::service::secure::SecureConnection;

/// Start a secure server and listen for connections using default configuration
#[instrument(skip(addr), fields(address = %addr))]
pub async fn start(addr: &str) -> Result<()> {
    // Create a never-resolving shutdown receiver for standard operation
    let (_, shutdown_rx) = oneshot::channel::<()>();
    start_with_shutdown(addr, shutdown_rx).await
}

/// Start a secure server with custom configuration
#[instrument(skip(config), fields(address = %config.address))]
pub async fn start_with_config(config: ServerConfig) -> Result<()> {
    // Create a never-resolving shutdown receiver for standard operation
    let (_, shutdown_rx) = oneshot::channel::<()>();
    start_with_config_and_shutdown(config, shutdown_rx).await
}

/// Start a secure server with shutdown control for testing
#[instrument(skip(addr, shutdown_rx), fields(address = %addr))]
pub async fn start_with_shutdown(addr: &str, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    // Use default configuration with overridden address
    let config = ServerConfig {
        address: addr.to_string(),
        ..Default::default()
    };
    start_with_config_and_shutdown(config, shutdown_rx).await
}

/// Start a secure server with custom configuration and shutdown control
#[instrument(skip(config, shutdown_rx), fields(address = %config.address))]
pub async fn start_with_config_and_shutdown(
    config: ServerConfig,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let listener = TcpListener::bind(&config.address).await?;
    info!(address = %config.address, "Server listening");

    // Shared dispatcher
    let dispatcher = Arc::new(Dispatcher::new());

    // Register default handlers
    register_default_handlers(&dispatcher)?;

    // Track active connections for graceful shutdown
    let active_connections = Arc::new(Mutex::new(0u32));

    // Create a shutdown channel for internal use
    let (internal_shutdown_tx, mut internal_shutdown_rx) = mpsc::channel::<()>(1);

    // Extract configuration values we need before moving config
    let shutdown_timeout = config.shutdown_timeout;
    let heartbeat_interval = config.heartbeat_interval;

    // Clone a sender for the task
    let shutdown_tx_clone = internal_shutdown_tx.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutdown signal received");
                let _ = shutdown_tx_clone.send(()).await;
            }
            Err(err) => {
                error!(error = %err, "Failed to listen for shutdown signal");
            }
        }
    });

    // Also set up the oneshot receiver to trigger shutdown
    let internal_shutdown_tx_clone = internal_shutdown_tx.clone();
    tokio::spawn(async move {
        if shutdown_rx.await.is_ok() {
            info!("External shutdown signal received");
            let _ = internal_shutdown_tx_clone.send(()).await;
        }
    });

    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = internal_shutdown_rx.recv() => {
                info!("Shutting down server. Waiting for connections to close...");

                // Wait for active connections to close (with configured timeout)
                let timeout = tokio::time::sleep(shutdown_timeout);
                tokio::pin!(timeout);

                loop {
                    tokio::select! {
                        _ = &mut timeout => {
                            warn!("Shutdown timeout reached, forcing exit");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let connections = *active_connections.lock().await;
                            info!(connections = %connections, "Waiting for connections to close");
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
                        info!(peer = %peer, "New connection established");
                        let dispatcher = dispatcher.clone();
                        let active_connections = active_connections.clone();
                        // We don't need this clone if we're not using it in this scope
                        // let _shutdown_tx = shutdown_tx.clone();

                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                        }

                        // Clone the things we need to move into the task
                        let active_connections_clone = active_connections.clone();
                        let config_clone = config.clone();

                        tokio::spawn(async move {
                            handle_connection(stream, peer, dispatcher, active_connections_clone, config_clone, heartbeat_interval).await;
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "Error accepting connection");
                    }
                }
            }
        }
    }
}

/// Handle a client connection with proper cleanup on exit
#[instrument(skip(stream, dispatcher, active_connections, config, heartbeat_interval), fields(peer = %peer))]
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    dispatcher: Arc<Dispatcher>,
    active_connections: Arc<Mutex<u32>>,
    config: ServerConfig,
    heartbeat_interval: Duration,
) {
    // Setup the connection with cleanup
    let result = with_timeout_error(
        async {
            process_connection(stream, dispatcher, peer, config.clone(), heartbeat_interval).await
        },
        config.connection_timeout,
    )
    .await;

    // If there was an error, log it
    match result {
        Ok(_) => info!("Connection closed gracefully"),
        Err(ProtocolError::Timeout) => warn!("Connection timed out"),
        Err(e) => error!(error = %e, "Connection error"),
    }

    // Always decrement active connections on exit
    {
        let mut count = active_connections.lock().await;
        *count -= 1;
    }

    info!("Client disconnected");
}

/// Process a client connection with handshake and secure messages
#[instrument(skip(stream, dispatcher, peer, config, heartbeat_interval), fields(peer = %peer))]
async fn process_connection(
    stream: TcpStream,
    dispatcher: Arc<Dispatcher>,
    peer: SocketAddr,
    config: ServerConfig,
    heartbeat_interval: Duration,
) -> Result<()> {
    // Create the framed stream for packet codec
    let mut framed = Framed::new(stream, PacketCodec);

    // --- Expect Secure Handshake Init (with timeout) ---
    let init = with_timeout_error(
        async {
            match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload)
                    .map_err(|e| ProtocolError::DeserializeError(e.to_string())),
                Some(Err(e)) => Err(ProtocolError::TransportError(e.to_string())),
                None => Err(ProtocolError::ConnectionClosed),
            }
        },
        config.connection_timeout,
    )
    .await?;

    // Extract the client's handshake init data
    let (client_pub_key, client_timestamp, client_nonce) = match init {
        Message::SecureHandshakeInit {
            pub_key,
            timestamp,
            nonce,
        } => (pub_key, timestamp, nonce),
        _ => {
            return Err(ProtocolError::HandshakeError(
                "Unexpected message type".to_string(),
            ))
        }
    };

    // --- Send Secure Handshake Response ---
    let (server_state, response) =
        server_secure_handshake_response(client_pub_key, client_nonce, client_timestamp)?;

    let response_bytes =
        bincode::serialize(&response).map_err(|e| ProtocolError::SerializeError(e.to_string()))?;

    framed
        .send(Packet {
            version: 1,
            payload: response_bytes,
        })
        .await
        .map_err(|e| ProtocolError::TransportError(e.to_string()))?;

    // --- Expect Handshake Confirmation (with timeout) ---
    let confirm = with_timeout_error(
        async {
            match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload)
                    .map_err(|e| ProtocolError::DeserializeError(e.to_string())),
                Some(Err(e)) => Err(ProtocolError::TransportError(e.to_string())),
                None => Err(ProtocolError::ConnectionClosed),
            }
        },
        config.connection_timeout,
    )
    .await?;

    let nonce_verification = match confirm {
        Message::SecureHandshakeConfirm { nonce_verification } => nonce_verification,
        _ => {
            return Err(ProtocolError::HandshakeError(
                "Expected handshake confirmation".to_string(),
            ))
        }
    };

    // --- Finalize Handshake and Derive Session Key ---
    let session_key = server_secure_handshake_finalize(server_state, nonce_verification)?;

    // Session state is zeroized automatically on drop

    // Create secure connection with derived key
    let conn = SecureConnection::new(framed, session_key);

    // Handle the secure message loop
    handle_secure_connection(conn, dispatcher, peer, heartbeat_interval).await?;

    Ok(())
}

/// Register default message handlers
#[instrument(skip(dispatcher))]
fn register_default_handlers(dispatcher: &Arc<Dispatcher>) -> Result<()> {
    // Handle Ping messages
    dispatcher.register("PING", |_| {
        debug!("Responding to ping with pong");
        Ok(Message::Pong)
    })?;

    // Handle Echo messages
    dispatcher.register("ECHO", |msg| {
        if let Message::Echo(text) = msg {
            debug!(text = %text, "Echoing message");
            Ok(Message::Echo(text.clone()))
        } else {
            Err(ProtocolError::Custom(
                "Invalid Echo message format".to_string(),
            ))
        }
    })?;

    Ok(())
}

/// Message type for the internal processing channel
#[derive(Debug)]
enum ProcessingMessage {
    /// Regular message to be processed
    Message(Message),
    /// Signal to terminate the processing task
    Terminate,
}

/// Response from the processing task
#[derive(Debug)]
struct ProcessingResult {
    /// The original message ID or correlation ID
    original_id: usize,
    /// The response message to send back
    response: Option<Message>,
}

/// Handle a secure connection after handshake with backpressure
#[instrument(skip(conn, dispatcher, heartbeat_interval), fields(peer = %peer))]
async fn handle_secure_connection(
    mut conn: SecureConnection,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr,
    heartbeat_interval: Duration,
) -> Result<()> {
    // --- Initialize Keep-Alive Manager with configured interval ---
    let dead_timeout = heartbeat_interval.mul_f32(4.0); // 4x the heartbeat interval for dead connection detection
    let mut keep_alive = KeepAliveManager::with_settings(heartbeat_interval, dead_timeout);
    let mut ping_interval = time::interval(keep_alive.ping_interval());

    // --- Create bounded channels for backpressure with capacity from config ---
    // We're using an internal messaging channel, so we can use a reasonable default here
    let (msg_tx, msg_rx) = mpsc::channel::<ProcessingMessage>(32);
    let (resp_tx, mut resp_rx) = mpsc::channel::<ProcessingResult>(32);

    // --- Spawn message processing task ---
    let dispatcher_clone = dispatcher.clone();
    let processor_handle =
        tokio::spawn(async move { process_messages(msg_rx, resp_tx, dispatcher_clone).await });

    // --- Set up result for final status ---
    let mut final_result = Ok(());
    let mut next_msg_id: usize = 0;

    // --- Secure Message Loop with Backpressure ---
    'main: loop {
        tokio::select! {
            // Check if we need to send a ping
            _ = ping_interval.tick() => {
                if keep_alive.should_ping() {
                    debug!("Sending keep-alive ping");
                    let ping = build_ping();
                    if let Err(e) = conn.secure_send(ping).await {
                        warn!(error = %e, "Failed to send ping");
                        final_result = Err(e);
                        break 'main;
                    }
                    keep_alive.update_send();
                }

                // Check if connection is dead
                if keep_alive.is_connection_dead() {
                    warn!(dead_seconds = ?keep_alive.time_since_last_recv().as_secs(),
                          "Connection appears dead, closing");
                    final_result = Err(ProtocolError::ConnectionTimeout);
                    break 'main;
                }
            }

            // Process any responses from the processing task
            Some(result) = resp_rx.recv() => {
                if let Some(response) = result.response {
                    debug!("Sending response for message {}", result.original_id);
                    if let Err(e) = conn.secure_send(response).await {
                        warn!(error = %e, "Failed to send response");
                        final_result = Err(e);
                        break 'main;
                    }
                    keep_alive.update_send();
                }
            }

            // Try to receive a message with backpressure awareness
            recv_result = conn.secure_recv::<Message>() => {
                match recv_result {
                    Ok(msg) => {
                        debug!(message = ?msg, "Received message");
                        keep_alive.update_recv();

                        // Check for disconnect message - handle directly without channel
                        if matches!(msg, Message::Disconnect) {
                            info!("Received disconnect request");
                            break 'main;
                        }

                        // Special handling for pong messages - handle directly
                        if is_pong(&msg) {
                            debug!("Received pong response");
                            continue;
                        }

                        // Just increment the ID counter for the next message
                        next_msg_id = next_msg_id.wrapping_add(1);

                        // Apply backpressure if needed
                        if msg_tx.capacity() == 0 {
                            debug!("Channel full - applying backpressure");

                            // Wait until the channel has capacity before receiving more messages
                            match msg_tx.reserve().await {
                                Ok(permit) => {
                                    // Channel has capacity again, send the message
                                    permit.send(ProcessingMessage::Message(msg));
                                },
                                Err(_) => {
                                    // Channel was closed, exit the loop
                                    warn!("Processing channel closed unexpectedly");
                                    break 'main;
                                }
                            }
                        } else {
                            // Channel has capacity, send the message
                            if (msg_tx.send(ProcessingMessage::Message(msg)).await).is_err() {
                                // Channel was closed, exit the loop
                                warn!("Failed to send message to processing channel");
                                break 'main;
                            }
                        }
                    }
                    Err(ProtocolError::Timeout) => {
                        // Timeout is expected, just continue the loop
                        continue;
                    }
                    Err(e) => {
                        final_result = Err(e);
                        break 'main;
                    }
                }
            }
        }
    }

    // Signal the processor to terminate
    debug!("Signaling processor to terminate");
    let _ = msg_tx.send(ProcessingMessage::Terminate).await;

    // Wait for processor to finish
    debug!("Waiting for processor to terminate");
    let _ = processor_handle.await;

    final_result
}

/// Process messages from the channel
#[instrument(skip(rx, resp_tx, dispatcher), level = "debug")]
async fn process_messages(
    mut rx: mpsc::Receiver<ProcessingMessage>,
    resp_tx: mpsc::Sender<ProcessingResult>,
    dispatcher: Arc<Dispatcher>,
) {
    let mut msg_counter: usize = 0;

    while let Some(proc_msg) = rx.recv().await {
        match proc_msg {
            ProcessingMessage::Message(msg) => {
                let msg_id = msg_counter;
                msg_counter += 1;

                debug!(msg_id = msg_id, message = ?msg, "Processing message from channel");

                let response = match dispatcher.dispatch(&msg) {
                    Ok(reply) => {
                        // Successfully dispatched, prepare response
                        Some(reply)
                    }
                    Err(e) => {
                        // Log dispatch error but continue processing messages
                        warn!(error = %e, "Error dispatching message");
                        None
                    }
                };

                // Send response back through the response channel
                let result = ProcessingResult {
                    original_id: msg_id,
                    response,
                };

                if (resp_tx.send(result).await).is_err() {
                    warn!("Failed to send processing result - reader likely disconnected");
                    break;
                }
            }
            ProcessingMessage::Terminate => {
                debug!("Processor received terminate signal");
                break;
            }
        }
    }

    debug!("Message processor terminated");
}

/// A server daemon handle that can be controlled externally
#[derive(Debug)]
pub struct Daemon {
    /// Address the server is listening on
    pub address: String,
    /// Shutdown signal sender
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Daemon {
    /// Create a new daemon handle
    pub fn new(address: String, shutdown_tx: oneshot::Sender<()>) -> Self {
        Self {
            address,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Run the daemon until completion or shutdown signal
    pub async fn run(self) -> Result<()> {
        // This function doesn't actually do anything - the server is started in the start_* functions
        // This is just a placeholder for API compatibility
        Ok(())
    }

    /// Shutdown the daemon gracefully
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
            Ok(())
        } else {
            Err(ProtocolError::Custom("Shutdown already called".to_string()))
        }
    }

    /// Shutdown the daemon with a custom timeout
    pub async fn shutdown_with_timeout(&mut self, _timeout: Duration) -> Result<()> {
        // The timeout is handled internally in the server loop
        self.shutdown().await
    }
}

/// Start a server daemon with provided configuration and return a handle to it
#[instrument(skip(config, _dispatcher), fields(address = %config.address))]
pub async fn start_daemon_no_signals(
    config: ServerConfig,
    _dispatcher: Arc<Dispatcher>,
) -> Result<Daemon> {
    // Create a shutdown channel
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let address = config.address.clone();

    // Start the server in a background task
    tokio::spawn(async move {
        if let Err(e) = start_with_config_and_shutdown(config, shutdown_rx).await {
            error!(error = ?e, "Server error");
        }
    });

    // Return a daemon handle
    Ok(Daemon::new(address, shutdown_tx))
}

/// Create a new server daemon with configuration and dispatcher
pub fn new_with_config(config: ServerConfig, _dispatcher: Arc<Dispatcher>) -> Daemon {
    let (shutdown_tx, _) = oneshot::channel::<()>();
    Daemon::new(config.address.clone(), shutdown_tx)
}
