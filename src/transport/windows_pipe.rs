//! # Windows Named Pipes Transport
//!
//! This module provides native Windows Named Pipes support for high-performance
//! local IPC on Windows systems. Named pipes offer significantly better performance
//! than TCP localhost connections for local communication.
//!
//! ## Performance
//!
//! Named pipes typically provide 30-40% better throughput compared to TCP localhost
//! for local IPC operations, with lower latency and reduced CPU overhead.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use network_protocol::transport::windows_pipe;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Start a named pipe server
//!     windows_pipe::start_server("\\\\.\\pipe\\my_app").await?;
//!     Ok(())
//! }
//! ```

#[cfg(windows)]
use futures::{SinkExt, StreamExt};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
#[cfg(windows)]
use tokio::sync::{mpsc, Mutex};
#[cfg(windows)]
use tokio_util::codec::Framed;
#[cfg(windows)]
use tracing::{debug, error, info, instrument, warn};

#[cfg(windows)]
use crate::core::codec::PacketCodec;
#[cfg(windows)]
use crate::error::Result;

/// Start a Windows Named Pipe server for IPC
///
/// # Arguments
///
/// * `pipe_name` - The name of the pipe (e.g., "\\\\.\\pipe\\my_app")
///
/// # Example
///
/// ```rust,no_run
/// use network_protocol::transport::windows_pipe;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     windows_pipe::start_server("\\\\.\\pipe\\my_app").await?;
///     Ok(())
/// }
/// ```
#[cfg(windows)]
#[instrument(skip(pipe_name), fields(pipe = %pipe_name))]
pub async fn start_server(pipe_name: &str) -> Result<()> {
    // Create internal shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Set up ctrl-c handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received CTRL+C signal, shutting down");
            let _ = shutdown_tx_clone.send(()).await;
        }
    });

    start_server_with_shutdown(pipe_name, shutdown_rx).await
}

/// Start a Windows Named Pipe server with an external shutdown channel
///
/// This variant allows external shutdown control, useful for testing and
/// integration with other shutdown mechanisms.
///
/// # Arguments
///
/// * `pipe_name` - The name of the pipe (e.g., "\\\\.\\pipe\\my_app")
/// * `shutdown_rx` - Channel to receive shutdown signal
#[cfg(windows)]
#[instrument(skip(pipe_name, shutdown_rx), fields(pipe = %pipe_name))]
pub async fn start_server_with_shutdown(
    pipe_name: &str,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    info!(pipe = %pipe_name, "Starting named pipe server");

    // Track active connections
    let active_connections = Arc::new(Mutex::new(0u32));

    // Create the first pipe instance
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name)?;

    info!(pipe = %pipe_name, "Named pipe server listening");

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

            // Wait for a client to connect
            result = server.connect() => {
                match result {
                    Ok(()) => {
                        let active_connections = active_connections.clone();

                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                            info!(connections = *count, "New pipe connection established");
                        }

                        // Take ownership of this pipe instance
                        let client_pipe = server;

                        // Create a new pipe instance for the next client
                        server = ServerOptions::new().create(pipe_name)?;

                        // Spawn a task to handle this connection
                        tokio::spawn(async move {
                            handle_pipe_connection(client_pipe, active_connections).await;
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "Error accepting pipe connection");
                        // Try to recreate the server pipe on error
                        match ServerOptions::new().create(pipe_name) {
                            Ok(new_server) => {
                                server = new_server;
                                debug!("Recreated server pipe after error");
                            }
                            Err(recreate_err) => {
                                error!(error = %recreate_err, "Failed to recreate server pipe");
                                return Err(recreate_err.into());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single named pipe connection
#[cfg(windows)]
async fn handle_pipe_connection(pipe: NamedPipeServer, active_connections: Arc<Mutex<u32>>) {
    let mut framed = Framed::new(pipe, PacketCodec);

    while let Some(result) = framed.next().await {
        match result {
            Ok(packet) => {
                debug!("Received packet of {} bytes", packet.payload.len());

                // Echo it back
                if let Err(e) = framed.send(packet).await {
                    error!(error = %e, "Failed to send packet");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "Error reading from pipe");
                break;
            }
        }
    }

    // Decrement connection counter when connection closes
    let mut count = active_connections.lock().await;
    *count -= 1;
    info!(connections = *count, "Pipe connection closed");
}

/// Connect to a Windows Named Pipe
///
/// # Arguments
///
/// * `pipe_name` - The name of the pipe to connect to (e.g., "\\\\.\\pipe\\my_app")
///
/// # Example
///
/// ```rust,no_run
/// use network_protocol::transport::windows_pipe;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut client = windows_pipe::connect("\\\\.\\pipe\\my_app").await?;
///     Ok(())
/// }
/// ```
#[cfg(windows)]
#[instrument(skip(pipe_name), fields(pipe = %pipe_name))]
pub async fn connect(
    pipe_name: &str,
) -> Result<Framed<tokio::net::windows::named_pipe::NamedPipeClient, PacketCodec>> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let client = ClientOptions::new().open(pipe_name)?;
    info!(pipe = %pipe_name, "Connected to named pipe");
    Ok(Framed::new(client, PacketCodec))
}

#[cfg(not(windows))]
compile_error!("This module is only available on Windows");
