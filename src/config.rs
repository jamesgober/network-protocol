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
