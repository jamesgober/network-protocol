//! Windows Named Pipes transport tests
//!
//! These tests verify the Windows Named Pipes implementation for local IPC.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(all(windows, not(feature = "use-tcp-on-windows")))]
mod windows_pipe_tests {
    use futures::{SinkExt, StreamExt};
    use network_protocol::config::PROTOCOL_VERSION;
    use network_protocol::core::packet::Packet;
    use network_protocol::transport::windows_pipe;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_named_pipe_connection() {
        let pipe_name = "\\\\.\\pipe\\test_connection";

        // Create shutdown channel for server
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        // Start server in background
        let server_pipe = pipe_name.to_string();
        let server_handle = tokio::spawn(async move {
            windows_pipe::start_server_with_shutdown(&server_pipe, shutdown_rx)
                .await
                .expect("Server failed");
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client = timeout(Duration::from_secs(5), windows_pipe::connect(pipe_name))
            .await
            .expect("Connection timeout")
            .expect("Failed to connect");

        // Send a test packet
        let test_packet = Packet {
            version: PROTOCOL_VERSION,
            payload: b"Hello, Windows Pipes!".to_vec(),
        };

        client
            .send(test_packet.clone())
            .await
            .expect("Failed to send packet");

        // Receive echo response
        let response = timeout(Duration::from_secs(5), client.next())
            .await
            .expect("Response timeout")
            .expect("Stream ended")
            .expect("Failed to receive packet");

        assert_eq!(response.payload, test_packet.payload);

        // Close client connection
        drop(client);
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Shutdown server
        shutdown_tx.send(()).await.expect("Failed to send shutdown");
        timeout(Duration::from_secs(5), server_handle)
            .await
            .expect("Server shutdown timeout")
            .expect("Server task panicked");
    }

    #[tokio::test]
    async fn test_multiple_connections() {
        let pipe_name = "\\\\.\\pipe\\test_multiple";

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        // Start server
        let server_pipe = pipe_name.to_string();
        let server_handle = tokio::spawn(async move {
            windows_pipe::start_server_with_shutdown(&server_pipe, shutdown_rx)
                .await
                .expect("Server failed");
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect multiple clients
        let mut clients = Vec::new();
        for _ in 0..3 {
            let client = windows_pipe::connect(pipe_name)
                .await
                .expect("Failed to connect");
            clients.push(client);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Each client sends a packet
        for (i, client) in clients.iter_mut().enumerate() {
            let test_packet = Packet {
                version: PROTOCOL_VERSION,
                payload: format!("Client {}", i).into_bytes(),
            };

            client
                .send(test_packet.clone())
                .await
                .expect("Failed to send");

            let response = timeout(Duration::from_secs(5), client.next())
                .await
                .expect("Timeout")
                .expect("Stream ended")
                .expect("Failed to receive");

            assert_eq!(response.payload, test_packet.payload);
        }

        // Close all client connections
        drop(clients);
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Cleanup
        shutdown_tx.send(()).await.expect("Failed to shutdown");
        timeout(Duration::from_secs(5), server_handle)
            .await
            .expect("Server shutdown timeout")
            .expect("Server task panicked");
    }

    #[tokio::test]
    async fn test_large_packet() {
        let pipe_name = "\\\\.\\pipe\\test_large";

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        let server_pipe = pipe_name.to_string();
        let server_handle = tokio::spawn(async move {
            windows_pipe::start_server_with_shutdown(&server_pipe, shutdown_rx)
                .await
                .expect("Server failed");
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = windows_pipe::connect(pipe_name)
            .await
            .expect("Failed to connect");

        // Send a large packet (1MB)
        let large_payload = vec![0xAB; 1024 * 1024];
        let test_packet = Packet {
            version: PROTOCOL_VERSION,
            payload: large_payload.clone(),
        };

        client
            .send(test_packet.clone())
            .await
            .expect("Failed to send large packet");

        let response = timeout(Duration::from_secs(10), client.next())
            .await
            .expect("Timeout")
            .expect("Stream ended")
            .expect("Failed to receive");

        assert_eq!(response.payload.len(), large_payload.len());
        assert_eq!(response.payload, large_payload);

        // Close client connection
        drop(client);
        tokio::time::sleep(Duration::from_millis(200)).await;

        shutdown_tx.send(()).await.expect("Failed to shutdown");
        timeout(Duration::from_secs(5), server_handle)
            .await
            .expect("Server shutdown timeout")
            .expect("Server task panicked");
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let pipe_name = "\\\\.\\pipe\\test_shutdown";

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        let server_pipe = pipe_name.to_string();
        let server_handle = tokio::spawn(async move {
            windows_pipe::start_server_with_shutdown(&server_pipe, shutdown_rx)
                .await
                .expect("Server failed");
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect a client
        let mut client = windows_pipe::connect(pipe_name)
            .await
            .expect("Failed to connect");

        // Send a packet
        let test_packet = Packet {
            version: PROTOCOL_VERSION,
            payload: b"test".to_vec(),
        };
        client.send(test_packet).await.expect("Failed to send");

        // Trigger shutdown
        shutdown_tx.send(()).await.expect("Failed to shutdown");

        // Server should shutdown gracefully
        timeout(Duration::from_secs(15), server_handle)
            .await
            .expect("Server shutdown timeout")
            .expect("Server task panicked");
    }
}

#[cfg(not(windows))]
#[test]
fn windows_tests_skipped() {
    println!("Windows Named Pipes tests are only available on Windows");
}
