//! Integration tests for configuration validation

#![allow(clippy::expect_used)]

use network_protocol::config::{
    ClientConfig, LoggingConfig, NetworkConfig, ServerConfig, TransportConfig,
};
use std::time::Duration;
use tracing::Level;

#[test]
fn test_default_config_validates() {
    let config = NetworkConfig::default();
    let errors = config.validate();
    assert!(
        errors.is_empty(),
        "Default config should be valid, but got errors: {:?}",
        errors
    );
}

#[test]
fn test_invalid_server_address() {
    let mut config = NetworkConfig::default();
    config.server.address = "invalid_address".to_string();

    let errors = config.validate();
    assert!(!errors.is_empty(), "Should have validation errors");
    assert!(errors.iter().any(|e| e.contains("Invalid server address")));
}

#[test]
fn test_empty_server_address() {
    let mut config = NetworkConfig::default();
    config.server.address = String::new();

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("cannot be empty")));
}

#[test]
fn test_zero_backpressure_limit() {
    let mut config = NetworkConfig::default();
    config.server.backpressure_limit = 0;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Backpressure limit must be greater than 0")));
}

#[test]
fn test_excessive_backpressure_limit() {
    let mut config = NetworkConfig::default();
    config.server.backpressure_limit = 2_000_000;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Backpressure limit too large")));
}

#[test]
fn test_short_connection_timeout() {
    let mut config = NetworkConfig::default();
    config.server.connection_timeout = Duration::from_millis(50);

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Connection timeout too short")));
}

#[test]
fn test_long_connection_timeout() {
    let mut config = NetworkConfig::default();
    config.server.connection_timeout = Duration::from_secs(400);

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Connection timeout too long")));
}

#[test]
fn test_zero_max_connections() {
    let mut config = NetworkConfig::default();
    config.server.max_connections = 0;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Max connections must be greater than 0")));
}

#[test]
fn test_high_max_connections_warning() {
    let mut config = NetworkConfig::default();
    config.server.max_connections = 150_000;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Max connections very high")));
}

#[test]
fn test_invalid_client_address() {
    let mut config = NetworkConfig::default();
    config.client.address = "not:a:valid:address".to_string();

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("Invalid client address")));
}

#[test]
fn test_zero_reconnect_attempts_with_auto_reconnect() {
    let mut config = NetworkConfig::default();
    config.client.auto_reconnect = true;
    config.client.max_reconnect_attempts = 0;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Max reconnect attempts must be greater than 0")));
}

#[test]
fn test_zero_max_payload_size() {
    let mut config = NetworkConfig::default();
    config.transport.max_payload_size = 0;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Max payload size cannot be 0")));
}

#[test]
fn test_tiny_max_payload_size() {
    let mut config = NetworkConfig::default();
    config.transport.max_payload_size = 512; // Less than 1 KB

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Max payload size too small")));
}

#[test]
fn test_excessive_max_payload_size() {
    let mut config = NetworkConfig::default();
    config.transport.max_payload_size = 200 * 1024 * 1024; // 200 MB

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Max payload size too large")));
}

#[test]
fn test_invalid_compression_level() {
    let mut config = NetworkConfig::default();
    config.transport.compression_enabled = true;
    config.transport.compression_level = 25; // Out of range

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Invalid compression level")));
}

#[test]
fn test_compression_threshold_larger_than_max_payload() {
    let mut config = NetworkConfig::default();
    config.transport.compression_enabled = true;
    config.transport.max_payload_size = 1000;
    config.transport.compression_threshold_bytes = 2000;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Compression threshold cannot be larger")));
}

#[test]
fn test_encryption_disabled_warning() {
    let mut config = NetworkConfig::default();
    config.transport.encryption_enabled = false;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("Encryption is disabled")));
}

#[test]
fn test_empty_app_name() {
    let mut config = NetworkConfig::default();
    config.logging.app_name = String::new();

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Application name cannot be empty")));
}

#[test]
fn test_long_app_name() {
    let mut config = NetworkConfig::default();
    config.logging.app_name = "a".repeat(100);

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("Application name too long")));
}

#[test]
fn test_log_to_file_without_path() {
    let mut config = NetworkConfig::default();
    config.logging.log_to_file = true;
    config.logging.log_file_path = None;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("log_file_path must be specified")));
}

#[test]
fn test_no_logging_outputs() {
    let mut config = NetworkConfig::default();
    config.logging.log_to_console = false;
    config.logging.log_to_file = false;

    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors
        .iter()
        .any(|e| e.contains("At least one logging output")));
}

#[test]
fn test_validate_strict_with_valid_config() {
    let config = NetworkConfig::default();
    assert!(config.validate_strict().is_ok());
}

#[test]
fn test_validate_strict_with_invalid_config() {
    let mut config = NetworkConfig::default();
    config.server.address = String::new();

    let result = config.validate_strict();
    assert!(result.is_err());

    if let Err(e) = result {
        let error_str = e.to_string();
        assert!(error_str.contains("Configuration validation failed"));
    }
}

#[test]
fn test_multiple_validation_errors() {
    let mut config = NetworkConfig::default();

    // Introduce multiple errors
    config.server.address = String::new();
    config.server.backpressure_limit = 0;
    config.client.address = String::new();
    config.transport.max_payload_size = 0;
    config.logging.app_name = String::new();

    let errors = config.validate();

    // Should have at least 5 errors
    assert!(
        errors.len() >= 5,
        "Expected at least 5 errors, got {}: {:?}",
        errors.len(),
        errors
    );
}

#[test]
fn test_valid_production_config() {
    let config = NetworkConfig {
        server: ServerConfig {
            address: "0.0.0.0:8443".to_string(),
            backpressure_limit: 1000,
            connection_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(10),
            max_connections: 10000,
        },
        client: ClientConfig {
            address: "example.com:8443".to_string(),
            connection_timeout: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(30),
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            reconnect_delay: Duration::from_secs(2),
        },
        transport: TransportConfig {
            compression_enabled: true,
            encryption_enabled: true,
            max_payload_size: 16 * 1024 * 1024, // 16 MB
            compression_level: 6,
            compression_threshold_bytes: 1024,
        },
        logging: LoggingConfig {
            app_name: "production-server".to_string(),
            log_level: Level::INFO,
            log_to_console: true,
            log_to_file: true,
            log_file_path: Some("/var/log/myapp/server.log".to_string()),
            json_format: true,
        },
    };

    let errors = config.validate();

    // Should only have the encryption warning if any
    assert!(
        errors.is_empty() || errors.iter().all(|e| !e.contains("ERROR")),
        "Production config should be valid, got: {:?}",
        errors
    );
}
