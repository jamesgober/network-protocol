use crate::error::{ProtocolError, Result};
use std::time::Duration;
use tokio::time;

/// Default timeout duration for network operations (5 seconds)
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default timeout duration for handshake operations (10 seconds)
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout duration for graceful shutdown (30 seconds)
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Default keep-alive interval (15 seconds)
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Default time to wait before considering a connection dead (60 seconds)
pub const DEAD_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Wrap an async operation with a timeout
///
/// # Errors
/// Returns `tokio::time::error::Elapsed` if the operation does not complete within the specified duration
pub async fn with_timeout<T>(
    operation: impl std::future::Future<Output = T>,
    duration: Duration,
) -> std::result::Result<T, time::error::Elapsed> {
    time::timeout(duration, operation).await
}

/// Wrap an async operation with a timeout, converting Elapsed errors to ProtocolError::Timeout
///
/// # Errors
/// Returns `ProtocolError::Timeout` if the operation times out, otherwise propagates any error from the operation
pub async fn with_timeout_error<T>(
    operation: impl std::future::Future<Output = Result<T>>,
    duration: Duration,
) -> Result<T> {
    match time::timeout(duration, operation).await {
        Ok(result) => result,
        Err(_) => Err(ProtocolError::Timeout),
    }
}
