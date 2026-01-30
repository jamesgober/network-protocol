//! Integration tests for QUIC transport interface
//!
//! These tests validate the QUIC transport placeholder implementation
//! and ensure the interface is correctly defined for future implementation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use network_protocol::transport::quic::{
    connect, start_server, QuicClientConfig, QuicServerConfig,
};

#[tokio::test]
async fn test_quic_server_config_defaults() {
    let config = QuicServerConfig::default();

    assert_eq!(config.address, "0.0.0.0:4433");
    assert_eq!(config.cert_path, "cert.pem");
    assert_eq!(config.key_path, "key.pem");
    assert_eq!(config.max_connections, 1000);
}

#[tokio::test]
async fn test_quic_client_config_creation() {
    let config = QuicClientConfig::new("example.com:4433".to_string(), "example.com".to_string());

    assert_eq!(config.server_addr, "example.com:4433");
    assert_eq!(config.server_name, "example.com");
    assert!(config.cert_path.is_none());
    assert!(config.key_path.is_none());
}

#[tokio::test]
async fn test_quic_client_config_with_mtls() {
    let config = QuicClientConfig::new("example.com:4433".to_string(), "example.com".to_string())
        .with_client_cert("client.crt".to_string(), "client.key".to_string());

    assert_eq!(config.cert_path, Some("client.crt".to_string()));
    assert_eq!(config.key_path, Some("client.key".to_string()));
}

#[tokio::test]
async fn test_quic_server_placeholder_returns_error() {
    let config = QuicServerConfig::default();

    let result = start_server(config).await;

    // Placeholder should return not implemented error
    assert!(result.is_err());
    let error_message = format!("{:?}", result.unwrap_err());
    assert!(error_message.contains("not yet implemented"));
}

#[tokio::test]
async fn test_quic_client_placeholder_returns_error() {
    let config = QuicClientConfig::new("localhost:4433".to_string(), "localhost".to_string());

    let result = connect(config).await;

    // Placeholder should return not implemented error
    assert!(result.is_err());
    let error_message = format!("{:?}", result.unwrap_err());
    assert!(error_message.contains("not yet implemented"));
}

#[test]
fn test_quic_server_config_can_be_cloned() {
    let config = QuicServerConfig::default();
    let cloned = config.clone();

    assert_eq!(config.address, cloned.address);
    assert_eq!(config.max_connections, cloned.max_connections);
}

#[test]
fn test_quic_client_config_can_be_cloned() {
    let config = QuicClientConfig::new("localhost:4433".to_string(), "localhost".to_string());
    let cloned = config.clone();

    assert_eq!(config.server_addr, cloned.server_addr);
    assert_eq!(config.server_name, cloned.server_name);
}

#[test]
fn test_quic_configs_can_be_debug_formatted() {
    let server_config = QuicServerConfig::default();
    let client_config =
        QuicClientConfig::new("localhost:4433".to_string(), "localhost".to_string());

    // Should not panic when debug formatting
    let _ = format!("{:?}", server_config);
    let _ = format!("{:?}", client_config);
}

/// Test that QUIC configuration supports custom settings
#[test]
fn test_quic_server_custom_config() {
    let config = QuicServerConfig {
        address: "127.0.0.1:5000".to_string(),
        cert_path: "/custom/path/cert.pem".to_string(),
        key_path: "/custom/path/key.pem".to_string(),
        max_connections: 5000,
    };

    assert_eq!(config.address, "127.0.0.1:5000");
    assert_eq!(config.cert_path, "/custom/path/cert.pem");
    assert_eq!(config.key_path, "/custom/path/key.pem");
    assert_eq!(config.max_connections, 5000);
}

/// Test that QUIC client configuration builder pattern works
#[test]
fn test_quic_client_builder_pattern() {
    let config = QuicClientConfig::new("server:4433".to_string(), "server".to_string())
        .with_client_cert("client.crt".to_string(), "client.key".to_string());

    assert!(config.cert_path.is_some());
    assert!(config.key_path.is_some());
}

/// Validate that the QUIC interface is properly defined for future implementation
#[test]
fn test_quic_interface_readiness() {
    // This test validates that all necessary types and functions are exported
    // and can be used when QUIC is eventually implemented

    // Server config type exists and is usable
    let _server_config: QuicServerConfig = QuicServerConfig::default();

    // Client config type exists and is usable
    let _client_config: QuicClientConfig =
        QuicClientConfig::new("test:4433".to_string(), "test".to_string());

    // Functions are properly typed (compile-time check)
    let _start_fn: fn(QuicServerConfig) -> _ = start_server;
    let _connect_fn: fn(QuicClientConfig) -> _ = connect;
}
