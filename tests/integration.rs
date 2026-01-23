use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use network_protocol::service::daemon;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration};

use std::error::Error;

#[tokio::test]
async fn test_secure_handshake_and_messages() -> Result<(), Box<dyn Error>> {
    // No need to clear handshake state anymore (per-session design)

    // Bind to port 0 to get a random available port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    drop(listener); // Release the port so daemon can use it

    // Clone the address for the server task
    let server_addr = addr.clone();

    // Create shutdown channel for test cleanup
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Spawn the daemon server in background
    let server_handle = tokio::spawn(async move {
        if let Err(e) = daemon::start_with_shutdown(&server_addr, shutdown_rx).await {
            eprintln!("Server error in test: {e}");
        }
    });

    // Give the server a moment to start
    sleep(Duration::from_millis(100)).await;

    // Connect the client (includes secure handshake)
    let mut client = match Client::connect(&addr).await {
        Ok(client) => client,
        Err(e) => {
            panic!("Failed to connect: {e}");
        }
    };

    // --- Test Ping → Pong ---
    if let Err(e) = client.send(Message::Ping).await {
        panic!("Failed to send ping: {e}");
    }

    let response = match client.recv().await {
        Ok(resp) => resp,
        Err(e) => panic!("No pong received: {e}"),
    };
    assert!(
        matches!(response, Message::Pong),
        "Expected Pong, got {response:?}"
    );

    // --- Test Echo ---
    let echo_msg = "Secure echo test!".to_string();
    if let Err(e) = client.send(Message::Echo(echo_msg.clone())).await {
        panic!("Failed to send echo: {e}");
    }

    let response = match client.recv().await {
        Ok(resp) => resp,
        Err(e) => panic!("No echo received: {e}"),
    };
    match response {
        Message::Echo(reply) => assert_eq!(reply, echo_msg),
        _ => panic!("Expected Echo, got {response:?}"),
    }

    // --- Disconnect (optional) ---
    if let Err(e) = client.send(Message::Disconnect).await {
        panic!("Failed to disconnect: {e}");
    }

    // Clean shutdown of the server
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    Ok(())
}
