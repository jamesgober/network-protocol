#![allow(clippy::unwrap_used, clippy::panic)]

use network_protocol::error::ProtocolError;
use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use network_protocol::service::daemon;

use std::net::TcpStream as StdTcpStream;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

#[tokio::test]
#[serial_test::serial] // Run tests sequentially to avoid port conflicts
async fn test_server_connection_timeout() {
    // No need to clear handshake state anymore (per-session design)

    // Bind to random port to avoid conflicts
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener); // Release the port so daemon can use it

    // Start server in background
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_addr = addr.clone(); // Clone for server task
    let server_handle = tokio::spawn(async move {
        daemon::start_with_shutdown(&server_addr, shutdown_rx)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a raw TCP connection that doesn't send anything
    let result = StdTcpStream::connect(&addr);
    assert!(result.is_ok(), "Should be able to establish raw connection");

    // The server should timeout this connection after the handshake timeout
    tokio::time::sleep(Duration::from_secs(7)).await;

    // Try a normal connection after the dead connection is cleaned up
    let client_result = timeout(Duration::from_secs(5), Client::connect(&addr)).await;
    assert!(client_result.is_ok(), "Client connection timed out");

    // Get connected client
    let mut client = client_result.unwrap().unwrap();

    // Send a test message
    let test_msg = Message::Custom {
        command: "test".to_string(),
        payload: Vec::new(),
    };
    let result = client.send(test_msg).await;
    assert!(result.is_ok(), "Should get successful response");

    // Cleanup
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
}

#[tokio::test]
#[serial_test::serial] // Run tests sequentially to avoid port conflicts
async fn test_client_timeout_detection() {
    // No need to clear handshake state anymore (per-session design)

    // Bind to random port to avoid conflicts
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener); // Release the port so daemon can use it

    // Start server
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_addr = addr.clone(); // Clone for server task
    let server_handle = tokio::spawn(async move {
        daemon::start_with_shutdown(&server_addr, shutdown_rx)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect with client
    let mut client = Client::connect(&addr).await.unwrap();

    // Send a test message
    let test_msg = Message::Custom {
        command: "test".to_string(),
        payload: Vec::new(),
    };
    let result = client.send(test_msg).await;
    assert!(result.is_ok(), "Should get successful response");

    // Wait a moment to ensure message is processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shutdown server without proper client disconnect to simulate a dead server
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    // Client should detect the dead connection during keep-alive
    let result = timeout(
        Duration::from_secs(20),
        client.recv_with_keepalive(Duration::from_secs(15)),
    )
    .await;

    // The result should be an error, either ConnectionTimeout or ConnectionClosed
    match result {
        Ok(Err(ProtocolError::ConnectionTimeout)) => {
            // This is expected - dead connection detected
        }
        Ok(Err(ProtocolError::ConnectionClosed)) => {
            // This is also acceptable - server closed connection
        }
        Ok(Err(e)) => {
            panic!("Got unexpected error: {e:?}");
        }
        Err(_) => {
            panic!("Test timed out without detecting dead connection");
        }
        Ok(Ok(_)) => {
            panic!("Should not have received a valid message");
        }
    }
}

#[tokio::test]
#[serial_test::serial] // Run tests sequentially to avoid port conflicts
async fn test_keepalive_ping_pong() {
    // No need to clear handshake state anymore (per-session design)

    // Bind to random port to avoid conflicts
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener); // Release the port so daemon can use it

    // Start server
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_addr = addr.clone(); // Clone for server task
    let server_handle = tokio::spawn(async move {
        daemon::start_with_shutdown(&server_addr, shutdown_rx)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect with client
    let mut client = Client::connect(&addr).await.unwrap();

    // Force a keepalive ping
    client.send_keepalive().await.unwrap();

    // Wait a bit and check that the connection is still alive
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Send a real message after the ping/pong exchange
    let test_msg = Message::Custom {
        command: "after_ping_pong".to_string(),
        payload: Vec::new(),
    };
    client.send(test_msg).await.unwrap();

    // Receive response with timeout
    let response = timeout(Duration::from_secs(5), client.recv()).await;
    assert!(
        response.is_ok(),
        "Should get successful response after ping/pong"
    );

    // Cleanup
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
}
