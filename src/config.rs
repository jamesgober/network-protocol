//! # Configuration Management
//!
//! Centralized configuration for the network protocol library.
//!
//! This module provides structured configuration for servers and clients,
//! including connection parameters, timeouts, compression settings, and security options.
//!
//! ## Configuration Sources
//! - TOML files via `from_toml_file()`
//! - Direct instantiation with defaults
//! - Environment-specific overrides
//!
//! ## Security Considerations
//! - Default compression threshold (512 bytes) balances performance and CPU
//! - Recommended timeout values prevent slowloris attacks
//! - TLS settings enforce modern cryptography (TLS 1.2+)

use crate::error::{ProtocolError, Result};
use crate::utils::timeout;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tracing::Level;

/// Current supported protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes to identify protocol packets (e.g., 0x4E50524F → "NPRO")
pub const MAGIC_BYTES: [u8; 4] = [0x4E, 0x50, 0x52, 0x4F];

/// Max allowed payload size (e.g. 16 MB)
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Whether to enable compression by default
pub const ENABLE_COMPRESSION: bool = false;

/// Whether to enable encryption by default
pub const ENABLE_ENCRYPTION: bool = true;

/// Main network configuration structure that contains all configurable settings
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NetworkConfig {
    /// Server-specific configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Client-specific configuration
    #[serde(default)]
    pub client: ClientConfig,

    /// Transport configuration
    #[serde(default)]
    pub transport: TransportConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

// Default implementation is now derived

impl NetworkConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to open config file: {e}")))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to read config file: {e}")))?;

        Self::from_toml(&contents)
    }

    /// Load configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str::<Self>(content)
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to parse TOML: {e}")))
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        // Start with defaults
        let mut config = Self::default();

        // Override with environment variables
        if let Ok(addr) = std::env::var("NETWORK_PROTOCOL_SERVER_ADDRESS") {
            config.server.address = addr;
        }

        if let Ok(capacity) = std::env::var("NETWORK_PROTOCOL_BACKPRESSURE_LIMIT") {
            if let Ok(val) = capacity.parse::<usize>() {
                config.server.backpressure_limit = val;
            }
        }

        if let Ok(timeout) = std::env::var("NETWORK_PROTOCOL_CONNECTION_TIMEOUT_MS") {
            if let Ok(val) = timeout.parse::<u64>() {
                config.server.connection_timeout = Duration::from_millis(val);
                config.client.connection_timeout = Duration::from_millis(val);
            }
        }

        if let Ok(heartbeat) = std::env::var("NETWORK_PROTOCOL_HEARTBEAT_INTERVAL_MS") {
            if let Ok(val) = heartbeat.parse::<u64>() {
                config.server.heartbeat_interval = Duration::from_millis(val);
            }
        }

        // Add more environment variables as needed

        Ok(config)
    }

    /// Apply overrides to the default configuration
    pub fn default_with_overrides<F>(mutator: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        let mut config = Self::default();
        mutator(&mut config);
        config
    }

    /// Generate example configuration file content
    pub fn example_config() -> String {
        toml::to_string_pretty(&Self::default())
            .unwrap_or_else(|_| String::from("# Failed to generate example config"))
    }

    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to serialize config: {e}")))?;

        std::fs::write(path, content)
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to write config file: {e}")))?;

        Ok(())
    }

    /// Validate the configuration for common issues and misconfigurations
    ///
    /// Returns a list of validation errors. Empty list means configuration is valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate server configuration
        errors.extend(self.server.validate());

        // Validate client configuration
        errors.extend(self.client.validate());

        // Validate transport configuration
        errors.extend(self.transport.validate());

        // Validate logging configuration
        errors.extend(self.logging.validate());

        errors
    }

    /// Validate and return Result - convenience method
    pub fn validate_strict(&self) -> Result<()> {
        let errors = self.validate();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::ConfigError(format!(
                "Configuration validation failed:\n  - {}",
                errors.join("\n  - ")
            )))
        }
    }
}

/// Server-specific configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Server listen address (e.g., "127.0.0.1:9000")
    pub address: String,

    /// Maximum number of messages in the backpressure queue
    pub backpressure_limit: usize,

    /// Timeout for client connections
    #[serde(with = "duration_serde")]
    pub connection_timeout: Duration,

    /// Interval for sending heartbeat messages
    #[serde(with = "duration_serde")]
    pub heartbeat_interval: Duration,

    /// Timeout for graceful server shutdown
    #[serde(with = "duration_serde")]
    pub shutdown_timeout: Duration,

    /// Maximum number of concurrent connections
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: String::from("127.0.0.1:9000"),
            backpressure_limit: 32,
            connection_timeout: timeout::DEFAULT_TIMEOUT,
            heartbeat_interval: timeout::KEEPALIVE_INTERVAL,
            shutdown_timeout: timeout::SHUTDOWN_TIMEOUT,
            max_connections: 1000,
        }
    }
}

impl ServerConfig {
    /// Validate server configuration
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate address format
        if self.address.is_empty() {
            errors.push("Server address cannot be empty".to_string());
        } else if self.address.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "Invalid server address format: '{}' (expected format: '0.0.0.0:8080')",
                self.address
            ));
        }

        // Validate backpressure limit
        if self.backpressure_limit == 0 {
            errors.push("Backpressure limit must be greater than 0".to_string());
        } else if self.backpressure_limit > 1_000_000 {
            errors.push(format!(
                "Backpressure limit too large: {} (max recommended: 1,000,000)",
                self.backpressure_limit
            ));
        }

        // Validate connection timeout
        if self.connection_timeout.as_millis() < 100 {
            errors.push("Connection timeout too short (minimum: 100ms)".to_string());
        } else if self.connection_timeout.as_secs() > 300 {
            errors.push("Connection timeout too long (maximum: 300s)".to_string());
        }

        // Validate heartbeat interval
        if self.heartbeat_interval.as_millis() < 100 {
            errors.push("Heartbeat interval too short (minimum: 100ms)".to_string());
        } else if self.heartbeat_interval.as_secs() > 3600 {
            errors.push("Heartbeat interval too long (maximum: 1 hour)".to_string());
        }

        // Validate shutdown timeout
        if self.shutdown_timeout.as_secs() < 1 {
            errors.push("Shutdown timeout too short (minimum: 1s)".to_string());
        } else if self.shutdown_timeout.as_secs() > 60 {
            errors.push("Shutdown timeout too long (maximum: 60s)".to_string());
        }

        // Validate max connections
        if self.max_connections == 0 {
            errors.push("Max connections must be greater than 0".to_string());
        } else if self.max_connections > 100_000 {
            errors.push(format!(
                "Max connections very high: {} (ensure system resources can support this)",
                self.max_connections
            ));
        }

        errors
    }
}

/// Client-specific configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    /// Target server address
    pub address: String,

    /// Timeout for connection attempts
    #[serde(with = "duration_serde")]
    pub connection_timeout: Duration,

    /// Timeout for individual operations
    #[serde(with = "duration_serde")]
    pub operation_timeout: Duration,

    /// Timeout for waiting for response messages
    #[serde(with = "duration_serde")]
    pub response_timeout: Duration,

    /// Interval for sending heartbeat messages
    #[serde(with = "duration_serde")]
    pub heartbeat_interval: Duration,

    /// Whether to automatically reconnect on connection loss
    pub auto_reconnect: bool,

    /// Maximum number of reconnect attempts before giving up
    pub max_reconnect_attempts: u32,

    /// Delay between reconnect attempts
    #[serde(with = "duration_serde")]
    pub reconnect_delay: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            address: String::from("127.0.0.1:9000"),
            connection_timeout: timeout::DEFAULT_TIMEOUT,
            operation_timeout: Duration::from_secs(3),
            response_timeout: Duration::from_secs(30),
            heartbeat_interval: timeout::KEEPALIVE_INTERVAL,
            auto_reconnect: true,
            max_reconnect_attempts: 3,
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

impl ClientConfig {
    /// Validate client configuration
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate address format
        if self.address.is_empty() {
            errors.push("Client address cannot be empty".to_string());
        } else if self.address.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "Invalid client address format: '{}' (expected format: 'example.com:8080')",
                self.address
            ));
        }

        // Validate timeouts
        if self.connection_timeout.as_millis() < 100 {
            errors.push("Connection timeout too short (minimum: 100ms)".to_string());
        }

        if self.operation_timeout.as_millis() < 10 {
            errors.push("Operation timeout too short (minimum: 10ms)".to_string());
        }

        if self.response_timeout.as_millis() < 100 {
            errors.push("Response timeout too short (minimum: 100ms)".to_string());
        }

        // Validate reconnect settings
        if self.auto_reconnect && self.max_reconnect_attempts == 0 {
            errors.push(
                "Max reconnect attempts must be greater than 0 when auto_reconnect is enabled"
                    .to_string(),
            );
        }

        if self.reconnect_delay.as_millis() < 10 {
            errors.push("Reconnect delay too short (minimum: 10ms)".to_string());
        } else if self.reconnect_delay.as_secs() > 60 {
            errors.push("Reconnect delay too long (maximum: 60s)".to_string());
        }

        errors
    }
}

/// Transport configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportConfig {
    /// Whether to enable compression
    pub compression_enabled: bool,

    /// Whether to enable encryption
    pub encryption_enabled: bool,

    /// Maximum allowed payload size in bytes
    pub max_payload_size: usize,

    /// Compression level (when compression is enabled)
    pub compression_level: i32,

    /// Minimum payload size (bytes) before compression is applied
    /// Payloads smaller than this threshold should bypass compression to reduce overhead
    #[serde(default)]
    pub compression_threshold_bytes: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            compression_enabled: ENABLE_COMPRESSION,
            encryption_enabled: ENABLE_ENCRYPTION,
            max_payload_size: MAX_PAYLOAD_SIZE,
            compression_level: 6, // Default compression level (medium)
            compression_threshold_bytes: 512,
        }
    }
}

impl TransportConfig {
    /// Validate transport configuration
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate max payload size
        if self.max_payload_size == 0 {
            errors.push("Max payload size cannot be 0".to_string());
        } else if self.max_payload_size < 1024 {
            errors.push("Max payload size too small (minimum: 1 KB)".to_string());
        } else if self.max_payload_size > 100 * 1024 * 1024 {
            errors.push(format!(
                "Max payload size too large: {} bytes (maximum recommended: 100 MB)",
                self.max_payload_size
            ));
        }

        // Validate compression settings
        if self.compression_enabled {
            if self.compression_level < 1 || self.compression_level > 22 {
                errors.push(format!(
                    "Invalid compression level: {} (valid range: 1-22)",
                    self.compression_level
                ));
            }

            if self.compression_threshold_bytes > self.max_payload_size {
                errors.push(
                    "Compression threshold cannot be larger than max payload size".to_string(),
                );
            }
        }

        // Warn if encryption is disabled
        if !self.encryption_enabled {
            errors.push(
                "WARNING: Encryption is disabled - not recommended for production".to_string(),
            );
        }

        errors
    }
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Application name for logs
    pub app_name: String,

    /// Log level
    #[serde(with = "log_level_serde")]
    pub log_level: Level,

    /// Whether to log to console
    pub log_to_console: bool,

    /// Whether to log to file
    pub log_to_file: bool,

    /// Path to log file (if log_to_file is true)
    pub log_file_path: Option<String>,

    /// Whether to use JSON formatting for logs
    pub json_format: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            app_name: String::from("network-protocol"),
            log_level: Level::INFO,
            log_to_console: true,
            log_to_file: false,
            log_file_path: None,
            json_format: false,
        }
    }
}

impl LoggingConfig {
    /// Validate logging configuration
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate app name
        if self.app_name.is_empty() {
            errors.push("Application name cannot be empty".to_string());
        } else if self.app_name.len() > 64 {
            errors.push(format!(
                "Application name too long: {} characters (maximum: 64)",
                self.app_name.len()
            ));
        }

        // Validate file logging configuration
        if self.log_to_file {
            if let Some(ref path) = self.log_file_path {
                // Check if parent directory exists (if path is absolute)
                if let Some(parent) = std::path::Path::new(path).parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        errors.push(format!(
                            "Log file directory does not exist: {}",
                            parent.display()
                        ));
                    }
                }
            } else {
                errors.push("log_file_path must be specified when log_to_file is true".to_string());
            }
        }

        // Validate at least one output is enabled
        if !self.log_to_console && !self.log_to_file {
            errors
                .push("At least one logging output (console or file) must be enabled".to_string());
        }

        errors
    }
}

/// Helper module for Duration serialization/deserialization
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let millis = duration.as_millis() as u64;
        millis.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

/// Helper module for tracing::Level serialization/deserialization
mod log_level_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::str::FromStr;
    use tracing::Level;

    pub fn serialize<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let level_str = match *level {
            Level::TRACE => "trace",
            Level::DEBUG => "debug",
            Level::INFO => "info",
            Level::WARN => "warn",
            Level::ERROR => "error",
        };
        level_str.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: Deserializer<'de>,
    {
        let level_str = String::deserialize(deserializer)?;
        Level::from_str(&level_str)
            .map_err(|_| serde::de::Error::custom(format!("Invalid log level: {level_str}")))
    }
}
