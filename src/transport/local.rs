use futures::{SinkExt, StreamExt};
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, warn};

use crate::core::codec::PacketCodec;
use crate::error::Result;
#[cfg(windows)]
use std::net::SocketAddr;
#[cfg(windows)]
use tokio::net::{TcpListener, TcpStream};

/// Start a local server for IPC
///
/// On Unix systems, this uses Unix Domain Sockets
/// On Windows, this falls back to TCP localhost connections
#[cfg(unix)]
#[instrument(skip(path), fields(socket_path = %path.as_ref().display()))]
pub async fn start_server<P: AsRef<Path>>(path: P) -> Result<()> {
    // Create internal shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Set up ctrl-c handler that sends to our internal shutdown channel
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received CTRL+C signal, shutting down");
            let _ = shutdown_tx_clone.send(()).await;
        }
    });

    // Start with our internal shutdown channel
    start_server_with_shutdown(path, shutdown_rx).await
}

/// Start a Unix domain socket server with an external shutdown channel
#[cfg(unix)]
#[instrument(skip(path, shutdown_rx), fields(socket_path = %path.as_ref().display()))]
pub async fn start_server_with_shutdown<P: AsRef<Path>>(
    path: P,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    if path.as_ref().exists() {
        tokio::fs::remove_file(&path).await.ok();
    }

    // Store path for cleanup on shutdown
    let path_string = path.as_ref().to_string_lossy().to_string();

    let listener = UnixListener::bind(&path)?;
    info!(path = %path_string, "Listening on unix socket");

    // Track active connections
    let active_connections = Arc::new(Mutex::new(0u32));

    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal from the provided shutdown_rx channel
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
                            info!(connections = %connections, "Waiting for connections to close");
                            if connections == 0 {
                                info!("All connections closed, shutting down");
                                break;
                            }
                        }
                    }
                }

                // Clean up socket file
                if Path::new(&path_string).exists() {
                    if let Err(e) = tokio::fs::remove_file(&path_string).await {
                        error!(error = %e, path = %path_string, "Failed to remove socket file");
                    } else {
                        info!(path = %path_string, "Removed socket file");
                    }
                }

                return Ok(());
            }

            // Accept new connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let active_connections = active_connections.clone();

                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                        }

                        tokio::spawn(async move {
                            let mut framed = Framed::new(stream, PacketCodec);

                            while let Some(Ok(packet)) = framed.next().await {
                                debug!("Received packet of {} bytes", packet.payload.len());

                                // Echo it back
                                let _ = framed.send(packet).await;
                            }

                            // Decrement connection counter when connection closes
                            let mut count = active_connections.lock().await;
                            *count -= 1;
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

/// Windows implementation using TCP on localhost instead of Unix sockets
#[cfg(windows)]
#[instrument(skip(path))]
pub async fn start_server<S: AsRef<str>>(path: S) -> Result<()> {
    // On Windows, interpret the path as a port number on localhost
    // Extract just the port number or use a default
    let addr = format!("127.0.0.1:{}", extract_port_or_default(path.as_ref()));

    let listener = TcpListener::bind(&addr).await?;
    info!(address = %addr, "Listening (Windows compatibility mode)");

    // Track active connections
    let active_connections = Arc::new(Mutex::new(0u32));

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Spawn ctrl-c handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received shutdown signal, initiating graceful shutdown");
            let _ = shutdown_tx_clone.send(()).await;
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
                    Ok((stream, addr)) => {
                        info!(peer = %addr, "New connection established");
                        let active_connections = active_connections.clone();

                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                        }

                        tokio::spawn(async move {
                            let mut framed = Framed::new(stream, PacketCodec);

                            while let Some(Ok(packet)) = framed.next().await {
                                debug!(bytes = packet.payload.len(), "Packet received");

                                // Echo it back
                                let _ = framed.send(packet).await;
                            }

                            // Decrement connection counter when connection closes
                            let mut count = active_connections.lock().await;
                            *count -= 1;
                            info!(peer = %addr, "Connection closed");
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

/// Connect to a local IPC socket
///
/// On Unix systems, this uses Unix Domain Sockets
/// On Windows, this falls back to TCP localhost connections
#[cfg(unix)]
#[instrument(skip(path), fields(socket_path = %path.as_ref().display()))]
pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Framed<UnixStream, PacketCodec>> {
    let stream = UnixStream::connect(path).await?;
    Ok(Framed::new(stream, PacketCodec))
}

#[cfg(windows)]
#[instrument(skip(path))]
pub async fn connect<S: AsRef<str>>(path: S) -> Result<Framed<TcpStream, PacketCodec>> {
    // On Windows, interpret the path as a port number on localhost
    let addr = format!("127.0.0.1:{}", extract_port_or_default(path.as_ref()));

    let stream = TcpStream::connect(&addr).await?;
    Ok(Framed::new(stream, PacketCodec))
}

#[cfg(windows)]
fn extract_port_or_default(path: &str) -> u16 {
    // Try to extract a port number from the path string
    // Default to 8080 if we can't parse anything
    path.split('/')
        .last()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8080)
}
