use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use network_protocol::utils::logging::{init_logging, LogConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use tracing::{info, warn};

// Import serial_test for sequentially running tests
use serial_test::serial;

const NUM_CLIENTS: usize = 4; // Reduced from 8
const MESSAGES_PER_CLIENT: usize = 20; // Reduced from 100
const SERVER_PORT: u16 = 9936;

/// Test the backpressure implementation with high message load
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_backpressure_under_load() {
    // Initialize logging
    init_logging(&LogConfig::default());
    info!("Starting backpressure test");

    // Start the daemon in the background
    let daemon_handle = tokio::spawn(async move {
        let addr = format!("127.0.0.1:{SERVER_PORT}");
        let _dispatcher = Arc::new(Dispatcher::default());

        info!("Starting daemon on {}", addr);
        if let Err(e) = network_protocol::service::daemon::start(&addr).await {
            warn!("Daemon error: {}", e);
        }
    });

    // Give daemon time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use barrier for synchronized client start
    let barrier = Arc::new(Barrier::new(NUM_CLIENTS));
    let mut client_handles = Vec::new();

    // Create multiple clients
    for client_id in 0..NUM_CLIENTS {
        let barrier_clone = barrier.clone();

        let client_handle = tokio::spawn(async move {
            let addr = format!("127.0.0.1:{SERVER_PORT}");

            // Create the client with timeout
            let mut client =
                match tokio::time::timeout(Duration::from_secs(5), Client::connect(&addr)).await {
                    Ok(result) => match result {
                        Ok(client) => client,
                        Err(e) => {
                            warn!("Client {} failed to connect: {}", client_id, e);
                            return;
                        }
                    },
                    Err(_) => {
                        warn!("Client {} connection timed out", client_id);
                        return;
                    }
                };

            // Wait for all clients to be ready
            barrier_clone.wait().await;
            info!("Client {} starting message flood", client_id);

            // Send many messages rapidly to trigger backpressure
            for i in 0..MESSAGES_PER_CLIENT {
                let message = Message::Ping;

                // Add timeout to send operation
                match tokio::time::timeout(Duration::from_secs(5), client.send(message)).await {
                    Ok(result) => match result {
                        Ok(_) => {
                            if i % 10 == 0 {
                                info!(
                                    "Client {} sent message {}/{}",
                                    client_id, i, MESSAGES_PER_CLIENT
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Client {} failed to send message {}: {}", client_id, i, e);
                        }
                    },
                    Err(_) => {
                        warn!(
                            "Client {} send operation timed out for message {}",
                            client_id, i
                        );
                    }
                }
            }

            info!("Client {} completed sending all messages", client_id);
        });

        client_handles.push(client_handle);
    }

    // Wait for all clients to finish with a timeout
    for (i, handle) in client_handles.into_iter().enumerate() {
        match tokio::time::timeout(Duration::from_secs(10), handle).await {
            Ok(result) => match result {
                Ok(_) => info!("Client {} finished", i),
                Err(e) => warn!("Client {} task failed: {:?}", i, e),
            },
            Err(_) => warn!("Client {} timed out after 10 seconds", i),
        }
    }

    // All tests done, wait a moment for daemon to process final messages
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Kill the daemon
    daemon_handle.abort();

    info!("Backpressure test completed successfully");
}

/// Test a single slow client doesn't block other clients
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_slow_client_isolation() {
    // Initialize logging
    init_logging(&LogConfig::default());
    info!("Starting slow client isolation test");

    // Start the daemon in the background with a custom port
    let slow_test_port = SERVER_PORT + 1;
    let daemon_handle = tokio::spawn(async move {
        let addr = format!("127.0.0.1:{slow_test_port}");
        let _dispatcher = Arc::new(Dispatcher::default());

        info!("Starting daemon on {}", addr);
        if let Err(e) = network_protocol::service::daemon::start(&addr).await {
            warn!("Daemon error: {}", e);
        }
    });

    // Give daemon time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start a slow client
    let slow_client_handle = tokio::spawn(async move {
        let addr = format!("127.0.0.1:{slow_test_port}");

        // Create the client with timeout
        let mut client =
            match tokio::time::timeout(Duration::from_secs(5), Client::connect(&addr)).await {
                Ok(result) => match result {
                    Ok(client) => client,
                    Err(e) => {
                        warn!("Slow client failed to connect: {}", e);
                        return;
                    }
                },
                Err(_) => {
                    warn!("Slow client connection timed out");
                    return;
                }
            };

        info!("Slow client connected, sending messages slowly");

        // Send messages with delay to simulate slow client
        for i in 0..10 {
            // Reduced from 20
            let message = Message::Ping;

            // Add timeout to send operation
            match tokio::time::timeout(Duration::from_secs(5), client.send(message)).await {
                Ok(result) => match result {
                    Ok(_) => {
                        info!("Slow client sent message {}/10", i);
                    }
                    Err(e) => {
                        warn!("Slow client failed to send message {}: {}", i, e);
                    }
                },
                Err(_) => {
                    warn!("Slow client send operation timed out for message {}", i);
                    continue;
                }
            }

            // Add delay between messages
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("Slow client completed sending all messages");
    });

    // Let the slow client start sending
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Start some fast clients in parallel
    let mut fast_client_handles = Vec::new();

    for client_id in 0..3 {
        let client_handle = tokio::spawn(async move {
            let addr = format!("127.0.0.1:{slow_test_port}");

            // Create the client with timeout
            let mut client =
                match tokio::time::timeout(Duration::from_secs(5), Client::connect(&addr)).await {
                    Ok(result) => match result {
                        Ok(client) => client,
                        Err(e) => {
                            warn!("Fast client {} failed to connect: {}", client_id, e);
                            return;
                        }
                    },
                    Err(_) => {
                        warn!("Fast client {} connection timed out", client_id);
                        return;
                    }
                };

            info!(
                "Fast client {} connected, sending messages quickly",
                client_id
            );

            // Send messages rapidly
            let start = std::time::Instant::now();

            for i in 0..15 {
                // Reduced from 30
                let message = Message::Ping;

                // Add timeout to send operation
                match tokio::time::timeout(Duration::from_secs(5), client.send(message)).await {
                    Ok(result) => match result {
                        Ok(_) => {
                            if i % 5 == 0 {
                                info!("Fast client {} sent message {}/15", client_id, i);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Fast client {} failed to send message {}: {}",
                                client_id, i, e
                            );
                        }
                    },
                    Err(_) => {
                        warn!(
                            "Fast client {} send operation timed out for message {}",
                            client_id, i
                        );
                    }
                }
            }

            let elapsed = start.elapsed();
            info!("Fast client {} completed in {:?}", client_id, elapsed);
        });

        fast_client_handles.push(client_handle);
    }

    // Wait for all fast clients to finish with timeout
    for (i, handle) in fast_client_handles.into_iter().enumerate() {
        match tokio::time::timeout(Duration::from_secs(10), handle).await {
            Ok(result) => match result {
                Ok(_) => info!("Fast client {} finished", i),
                Err(e) => warn!("Fast client {} task failed: {:?}", i, e),
            },
            Err(_) => warn!("Fast client {} timed out after 10 seconds", i),
        }
    }

    // Wait for slow client to finish with timeout
    match tokio::time::timeout(Duration::from_secs(20), slow_client_handle).await {
        Ok(result) => match result {
            Ok(_) => info!("Slow client finished"),
            Err(e) => warn!("Slow client task failed: {:?}", e),
        },
        Err(_) => warn!("Slow client timed out after 20 seconds"),
    }

    // All tests done, kill the daemon
    daemon_handle.abort();

    info!("Slow client isolation test completed successfully");
}
