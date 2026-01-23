use network_protocol::protocol::message::Message;
use network_protocol::service::daemon;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::sleep;

// Import our test-specific client implementation
mod test_utils;
use test_utils::BenchmarkClient;

async fn setup_server(addr: &str) -> (JoinHandle<()>, oneshot::Sender<()>) {
    let addr = addr.to_string();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Start the server with proper shutdown handling
    let server_handle = tokio::spawn(async move {
        let server_task = tokio::spawn(async move {
            #[allow(clippy::unwrap_used)]
            daemon::start(&addr).await.unwrap();
        });

        // Wait for shutdown signal
        let _ = shutdown_rx.await;
        // Server will be dropped when task is aborted
        server_task.abort();
    });

    // Give server time to start up
    sleep(Duration::from_millis(500)).await;

    (server_handle, shutdown_tx)
}

#[tokio::test]
async fn benchmark_roundtrip_latency() {
    // Using benchmark client implementation that doesn't rely on global state
    // so we don't need to set environment variables or clear handshake data

    let addr = "127.0.0.1:7799";
    let (server_handle, shutdown_tx) = setup_server(addr).await;

    // Connect to server with our BenchmarkClient that doesn't use global state
    let mut client = match BenchmarkClient::connect(addr).await {
        Ok(client) => {
            println!("[benchmark] Client connected successfully");
            client
        }
        Err(e) => {
            #[allow(clippy::panic)]
            {
                panic!("Failed to connect: {e:?}");
            }
        }
    };

    let rounds = 50; // Reduced number of rounds for stability
    let mut total = Duration::ZERO;
    let mut successful = 0;

    for i in 0..rounds {
        // Add a small delay between messages to avoid overwhelming the server
        if i % 10 == 0 {
            sleep(Duration::from_millis(10)).await;
        }

        let start = Instant::now();

        // Send ping with error handling
        if let Err(e) = client.send(Message::Ping).await {
            println!("Error sending ping message: {e:?}");
            continue;
        }

        // Receive with timeout
        match tokio::time::timeout(Duration::from_millis(500), client.recv()).await {
            Ok(Ok(response)) => {
                match response {
                    Message::Pong => {
                        // Valid response
                        total += start.elapsed();
                        successful += 1;
                    }
                    _ => {
                        println!("Unexpected response type: {response:?}");
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Error receiving response: {e:?}");
            }
            Err(_) => {
                println!("Timeout waiting for response");
            }
        }
    }

    if successful > 0 {
        let avg = total / successful;
        println!(
            "Average roundtrip latency over {successful} successful packets: {avg:?} per message"
        );
    } else {
        println!("No successful ping-pong exchanges completed");
    }

    // Graceful shutdown sequence
    println!("[benchmark] Shutting down server...");
    let _ = shutdown_tx.send(()); // Ignore errors if receiver is already dropped

    // Give server time to shut down before client is dropped
    sleep(Duration::from_millis(100)).await;

    // Wait for server to terminate
    let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;
}

#[tokio::test]
async fn benchmark_throughput() {
    // Using benchmark client implementation that doesn't rely on global state

    let addr = "127.0.0.1:7798";
    let (server_handle, shutdown_tx) = setup_server(addr).await;

    // Connect to server with our BenchmarkClient that doesn't use global state
    let mut client = match BenchmarkClient::connect(addr).await {
        Ok(client) => {
            println!("[benchmark] Client connected successfully");
            client
        }
        Err(e) => {
            #[allow(clippy::panic)]
            {
                panic!("Failed to connect: {e:?}");
            }
        }
    };

    // Use ping/pong for throughput test since it's more reliable
    let rounds = 50;
    let mut successful = 0;
    let start = Instant::now();

    for i in 0..rounds {
        // Add a small delay between messages to avoid overwhelming the server
        if i % 10 == 0 {
            sleep(Duration::from_millis(20)).await;
        }

        // Send ping with error handling
        if let Err(e) = client.send(Message::Ping).await {
            println!("Error sending ping message: {e:?}");
            continue;
        }

        // Receive with timeout
        match tokio::time::timeout(Duration::from_millis(500), client.recv()).await {
            Ok(Ok(response)) => {
                match response {
                    Message::Pong => {
                        // Valid response
                        successful += 1;
                    }
                    _ => {
                        println!("Unexpected response type: {response:?}");
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Error receiving response: {e:?}");
            }
            Err(_) => {
                println!("Timeout waiting for response");
            }
        }
    }

    let elapsed = start.elapsed();
    if successful > 0 {
        let per_sec = successful as f64 / elapsed.as_secs_f64();
        println!("Throughput: {per_sec:.0} messages/sec ({successful} successful of {rounds} attempts) over {elapsed:?} total");
    } else {
        println!("No successful exchanges completed");
    }

    // Graceful shutdown sequence
    println!("[benchmark] Shutting down server...");
    let _ = shutdown_tx.send(());

    // Give server time to shut down before client is dropped
    sleep(Duration::from_millis(100)).await;

    // Wait for server to terminate
    let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;
}
