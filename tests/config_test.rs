use network_protocol::config::{ClientConfig, NetworkConfig, ServerConfig}; //LoggingConfig
use network_protocol::error::Result;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tracing::Level;

#[tokio::test]
async fn test_config_loading() -> Result<()> {
    // Create a temporary config file for testing
    let test_config = r#"
    [server]
    address = "127.0.0.1:9999"
    backpressure_limit = 64
    connection_timeout = 15000
    heartbeat_interval = 5000
    shutdown_timeout = 5000
    max_connections = 500

    [client]
    address = "127.0.0.1:9999"
    connection_timeout = 5000
    operation_timeout = 5000
    response_timeout = 15000
    heartbeat_interval = 5000
    auto_reconnect = true
    max_reconnect_attempts = 5
    reconnect_delay = 500

    [transport]
    compression_enabled = true
    encryption_enabled = true
    max_payload_size = 8388608
    compression_level = 8

    [logging]
    app_name = "config-test"
    log_level = "debug"
    log_to_console = true
    log_to_file = false
    json_format = false
    "#;

    let test_config_path = Path::new("test_config.toml");
    fs::write(test_config_path, test_config)?;

    // Test loading from file
    println!("Testing config loading from file...");
    let file_config = NetworkConfig::from_file(test_config_path)?;

    // Verify server config
    assert_eq!(file_config.server.address, "127.0.0.1:9999");
    assert_eq!(file_config.server.backpressure_limit, 64);
    assert_eq!(
        file_config.server.connection_timeout,
        Duration::from_millis(15000)
    );
    assert_eq!(
        file_config.server.heartbeat_interval,
        Duration::from_millis(5000)
    );
    assert_eq!(file_config.server.max_connections, 500);

    // Verify client config
    assert_eq!(file_config.client.address, "127.0.0.1:9999");
    assert_eq!(
        file_config.client.connection_timeout,
        Duration::from_millis(5000)
    );
    assert_eq!(
        file_config.client.operation_timeout,
        Duration::from_millis(5000)
    );
    assert_eq!(
        file_config.client.response_timeout,
        Duration::from_millis(15000)
    );
    assert_eq!(file_config.client.max_reconnect_attempts, 5);
    assert_eq!(
        file_config.client.reconnect_delay,
        Duration::from_millis(500)
    );

    // Verify transport config
    assert!(file_config.transport.compression_enabled);
    assert!(file_config.transport.encryption_enabled);
    assert_eq!(file_config.transport.max_payload_size, 8388608);
    assert_eq!(file_config.transport.compression_level, 8);

    // Verify logging config
    assert_eq!(file_config.logging.app_name, "config-test");
    assert_eq!(file_config.logging.log_level, Level::DEBUG);
    assert!(file_config.logging.log_to_console);
    assert!(!file_config.logging.log_to_file);
    assert!(!file_config.logging.json_format);

    // Test env var overrides
    println!("Testing config loading from environment variables...");

    // Set environment variables
    env::set_var("NETWORK_PROTOCOL_SERVER_ADDRESS", "127.0.0.1:8888");
    env::set_var("NETWORK_PROTOCOL_BACKPRESSURE_LIMIT", "128");
    env::set_var("NETWORK_PROTOCOL_CONNECTION_TIMEOUT_MS", "10000");
    env::set_var("NETWORK_PROTOCOL_HEARTBEAT_INTERVAL_MS", "7500");

    // Load config with environment variables
    let env_config = NetworkConfig::from_env()?;

    // Verify environment variable overrides
    assert_eq!(env_config.server.address, "127.0.0.1:8888");
    assert_eq!(env_config.server.backpressure_limit, 128);
    assert_eq!(
        env_config.server.connection_timeout,
        Duration::from_millis(10000)
    );
    assert_eq!(
        env_config.server.heartbeat_interval,
        Duration::from_millis(7500)
    );

    // Also check that client connection timeout is updated (as specified in implementation)
    assert_eq!(
        env_config.client.connection_timeout,
        Duration::from_millis(10000)
    );

    // Test programmatic overrides
    println!("Testing programmatic config overrides...");

    let custom_config = NetworkConfig::default_with_overrides(|cfg| {
        cfg.server.address = "0.0.0.0:7000".to_string();
        cfg.server.backpressure_limit = 256;
        cfg.client.auto_reconnect = false;
        cfg.transport.compression_enabled = true;
        cfg.logging.log_level = Level::TRACE;
    });

    assert_eq!(custom_config.server.address, "0.0.0.0:7000");
    assert_eq!(custom_config.server.backpressure_limit, 256);
    assert!(!custom_config.client.auto_reconnect);
    assert!(custom_config.transport.compression_enabled);
    assert_eq!(custom_config.logging.log_level, Level::TRACE);

    // Test save to file and reload
    println!("Testing config save and reload...");

    let save_path = Path::new("test_config_save.toml");
    custom_config.save_to_file(save_path)?;

    let reloaded_config = NetworkConfig::from_file(save_path)?;
    assert_eq!(reloaded_config.server.address, "0.0.0.0:7000");
    assert_eq!(reloaded_config.server.backpressure_limit, 256);
    assert!(!reloaded_config.client.auto_reconnect);
    assert!(reloaded_config.transport.compression_enabled);
    assert_eq!(reloaded_config.logging.log_level, Level::TRACE);

    // Clean up test files
    println!("Cleaning up test files...");
    fs::remove_file(test_config_path)?;
    fs::remove_file(save_path)?;

    // Clean up environment variables
    env::remove_var("NETWORK_PROTOCOL_SERVER_ADDRESS");
    env::remove_var("NETWORK_PROTOCOL_BACKPRESSURE_LIMIT");
    env::remove_var("NETWORK_PROTOCOL_CONNECTION_TIMEOUT_MS");
    env::remove_var("NETWORK_PROTOCOL_HEARTBEAT_INTERVAL_MS");

    println!("All configuration tests passed!");
    Ok(())
}

#[tokio::test]
async fn test_config_integration() -> Result<()> {
    use network_protocol::protocol::dispatcher::Dispatcher;
    use network_protocol::protocol::message::Message;
    use network_protocol::service::client;
    use network_protocol::service::daemon::start_daemon_no_signals as new_daemon;
    use std::sync::Arc;

    println!("Testing config integration with server and client...");

    // Create a custom server config
    let server_config = ServerConfig {
        address: "127.0.0.1:9876".to_string(),
        backpressure_limit: 50,
        connection_timeout: Duration::from_secs(5),
        heartbeat_interval: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        max_connections: 100,
    };

    // Create a dispatcher with an echo handler
    let dispatcher = Arc::new(Dispatcher::default());
    dispatcher.register("ECHO", |msg| {
        println!("Echo handler received message");
        Ok(msg.clone())
    })?;

    // Start server with custom config
    let mut daemon = new_daemon(server_config.clone(), dispatcher).await?;

    // Give server time to fully initialize
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Create a custom client config
    let client_config = ClientConfig {
        address: "127.0.0.1:9876".to_string(),
        connection_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(3),
        response_timeout: Duration::from_secs(10),
        heartbeat_interval: Duration::from_secs(2),
        auto_reconnect: true,
        max_reconnect_attempts: 2,
        reconnect_delay: Duration::from_millis(500),
    };

    // Connect client with custom config
    println!("Connecting client with custom config...");
    let mut conn = client::Client::connect_with_config(client_config).await?;

    // Send and receive a test message
    println!("Testing message exchange...");
    conn.send(Message::Echo("test message".to_string())).await?;
    let response = conn.recv().await?;

    // Verify response
    if let Message::Echo(msg) = response {
        assert_eq!(msg, "test message");
        println!("Successfully received echo response");
    } else {
        #[allow(clippy::panic)]
        {
            panic!("Received unexpected message type: {response:?}");
        }
    }

    // The connection will be dropped automatically when conn goes out of scope
    // No explicit close method needed

    // Shutdown server
    println!("Shutting down server...");
    daemon.shutdown().await?;

    println!("All integration tests passed!");
    Ok(())
}
