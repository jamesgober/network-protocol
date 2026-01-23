#![allow(clippy::panic)]

use futures::SinkExt;
#[cfg(test)]
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

use network_protocol::protocol::message::Message;

const TEST_PORT: u16 = 49155; // Use a high port number for tests
const CERT_PATH: &str = "tests/test_cert.pem";
const KEY_PATH: &str = "tests/test_key.pem";

#[tokio::test]
async fn test_tls_daemon_graceful_shutdown() -> network_protocol::error::Result<()> {
    use network_protocol::service::tls_client::TlsClient;
    use network_protocol::transport::tls::TlsServerConfig;
    use std::path::PathBuf;

    // Setup server configuration
    let cert_path = PathBuf::from(CERT_PATH);
    let key_path = PathBuf::from(KEY_PATH);
    let server_addr_str = format!("127.0.0.1:{TEST_PORT}");

    // Create shutdown channels
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    println!("[test] Starting TLS daemon for shutdown test");
    // Start TLS daemon server with our shutdown channel
    let config = TlsServerConfig::new(cert_path, key_path);
    let server_addr_clone = server_addr_str.clone();
    let server_handle = tokio::spawn(async move {
        let _ = network_protocol::service::tls_daemon::start_with_shutdown(
            &server_addr_clone,
            config,
            shutdown_rx,
        )
        .await;
        println!("[test] TLS daemon server stopped");
    });

    // Wait for server to start - increased delay to ensure server is fully initialized
    sleep(Duration::from_millis(800)).await;

    // Connect with a client
    let config = network_protocol::transport::tls::TlsClientConfig::new("localhost").insecure();
    let mut client = TlsClient::connect(&server_addr_str, config).await?;

    // Verify connection works
    let response = client.request(Message::Ping).await?;
    assert!(matches!(response, Message::Pong), "Expected Pong response");

    // Drop the client before shutdown
    println!("[test] Dropping client connection");
    drop(client);

    // Trigger shutdown directly rather than through Ctrl-C
    println!("[test] Sending shutdown signal");
    let _ = shutdown_tx.send(()).await;

    // Give time for the shutdown sequence to start
    sleep(Duration::from_millis(300)).await;

    // Try to connect again - should fail as server is shutting down
    println!("[test] Attempting connection during shutdown");
    let new_config = network_protocol::transport::tls::TlsClientConfig::new("localhost").insecure();
    match TlsClient::connect(&server_addr_str, new_config).await {
        Ok(_) => panic!("Server accepted connection during shutdown"),
        Err(e) => println!("[test] Connection failed during shutdown as expected: {e}"),
    }

    // Wait for server to fully shut down
    println!("[test] Waiting for server to shut down");
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    println!("[test] TLS shutdown test complete");

    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn test_local_transport_graceful_shutdown() -> network_protocol::error::Result<()> {
    use network_protocol::transport::local;
    use std::path::PathBuf;
    use tokio::fs::remove_file;

    // Use a test socket path
    let socket_path = PathBuf::from("/tmp/network_protocol_test_socket");
    let socket_path_str = socket_path.to_string_lossy().to_string();

    // Clean up any existing socket
    if socket_path.exists() {
        remove_file(&socket_path).await.ok();
    }

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    let socket_path_clone = socket_path.clone();

    println!("[test] Starting local transport server for shutdown test");
    // Start local transport server with our shutdown channel
    let server_handle = tokio::spawn(async move {
        let _ = local::start_server_with_shutdown(&socket_path_clone, shutdown_rx).await;
        println!("[test] Local transport server stopped");
    });

    // Wait for server to start - increased delay to ensure server is fully initialized
    sleep(Duration::from_millis(800)).await;

    // Connect client and verify it works
    let mut conn = local::connect(&socket_path_str).await?;

    // Send a test packet
    use network_protocol::core::packet::Packet;
    let test_packet = Packet {
        version: 1,
        payload: vec![1, 2, 3, 4],
    };
    conn.send(test_packet).await?;

    // Drop client connection
    println!("[test] Dropping client connection");
    drop(conn);

    // Trigger shutdown directly rather than through Ctrl-C
    println!("[test] Sending shutdown signal to local transport");
    let _ = shutdown_tx.send(()).await;

    // Wait for server to fully shut down
    println!("[test] Waiting for local transport server to shut down");
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

    // Give filesystem time to clean up the socket
    println!("[test] Checking socket file cleanup");
    sleep(Duration::from_millis(500)).await;

    // Verify socket file was cleaned up
    assert!(
        !socket_path.exists(),
        "Socket file should be removed during graceful shutdown"
    );
    println!("[test] Local transport shutdown test complete");

    Ok(())
}

#[tokio::test]
async fn test_cluster_graceful_shutdown() -> network_protocol::error::Result<()> {
    use network_protocol::transport::cluster::Cluster;

    // Create a test cluster with some peers (we don't need actual connections for this test)
    let test_peers = vec![
        ("node1".to_string(), "127.0.0.1:8001".to_string()),
        ("node2".to_string(), "127.0.0.1:8002".to_string()),
    ];

    // Create and start the cluster
    let mut cluster = Cluster::new(test_peers);
    let _shutdown_tx = cluster.start_heartbeat(Duration::from_secs(1)).await;

    // Let it run for a bit
    sleep(Duration::from_millis(200)).await;

    // Now shutdown the cluster heartbeat
    cluster.shutdown().await;

    // Short pause to ensure shutdown completes
    sleep(Duration::from_millis(200)).await;

    // Successful test is one that completes without hanging
    Ok(())
}
