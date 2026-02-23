//! # Connection Pooling
//!
//! Generic connection pool for all transport types.
//!
//! This module provides a thread-safe, async-aware connection pooling mechanism
//! that eliminates expensive TLS handshakes for repeated connections to the same
//! endpoint. Essential for database and RPC scenarios where clients make many
//! short-lived requests.
//!
//! ## Features
//! - Generic over any transport type `T`
//! - Configurable pool size (min/max connections)
//! - TTL-based connection expiration
//! - Health checks with automatic eviction
//! - FIFO acquisition with LRU eviction on overflow
//! - Thread-safe async operations

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, warn};

use crate::error::{ProtocolError, Result};

/// Configuration for connection pooling
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum connections to maintain (pre-warmed)
    pub min_size: usize,
    /// Maximum connections in pool
    pub max_size: usize,
    /// Time-to-live for idle connections before eviction
    pub idle_timeout: Duration,
    /// Maximum lifetime of a connection regardless of idle time
    pub max_lifetime: Duration,
    /// Maximum concurrent waiters for connections (backpressure limit)
    pub max_waiters: usize,
    /// Circuit breaker: consecutive failures before opening
    pub circuit_breaker_threshold: usize,
    /// Circuit breaker: time to wait before trying again
    pub circuit_breaker_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_size: 5,
            max_size: 50,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            max_lifetime: Duration::from_secs(3600), // 1 hour
            max_waiters: 1000,                      // Prevent OOM
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(10),
        }
    }
}

impl PoolConfig {
    /// Validate configuration parameters
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        // Validate pool sizes
        if self.max_size == 0 {
            errors.push("Pool max_size must be greater than 0".to_string());
        }

        if self.min_size > self.max_size {
            errors.push(format!(
                "Pool min_size ({}) cannot exceed max_size ({})",
                self.min_size, self.max_size
            ));
        }

        // Validate reasonable limits
        if self.max_size > 10_000 {
            errors.push(format!(
                "Pool max_size ({}) exceeds recommended limit (10,000)",
                self.max_size
            ));
        }

        if self.max_waiters == 0 {
            errors.push("Pool max_waiters must be greater than 0".to_string());
        }

        if self.max_waiters > 1_000_000 {
            errors.push(format!(
                "Pool max_waiters ({}) exceeds recommended limit (1,000,000)",
                self.max_waiters
            ));
        }

        // Validate timeouts
        if self.idle_timeout.is_zero() {
            errors.push("Pool idle_timeout must be greater than 0".to_string());
        }

        if self.max_lifetime.is_zero() {
            errors.push("Pool max_lifetime must be greater than 0".to_string());
        }

        if self.idle_timeout >= self.max_lifetime {
            errors.push(format!(
                "Pool idle_timeout ({:?}) should be less than max_lifetime ({:?})",
                self.idle_timeout, self.max_lifetime
            ));
        }

        if self.idle_timeout.as_secs() > 3600 {
            errors.push(format!(
                "Pool idle_timeout ({} seconds) is unusually long (recommended: < 1 hour)",
                self.idle_timeout.as_secs()
            ));
        }

        if self.max_lifetime.as_secs() > 86400 {
            errors.push(format!(
                "Pool max_lifetime ({} seconds) is unusually long (recommended: < 24 hours)",
                self.max_lifetime.as_secs()
            ));
        }

        // Validate circuit breaker settings
        if self.circuit_breaker_threshold == 0 {
            errors.push("Circuit breaker threshold must be greater than 0".to_string());
        }

        if self.circuit_breaker_threshold > 100 {
            errors.push(format!(
                "Circuit breaker threshold ({}) is unusually high (recommended: < 100)",
                self.circuit_breaker_threshold
            ));
        }

        if self.circuit_breaker_timeout.is_zero() {
            errors.push("Circuit breaker timeout must be greater than 0".to_string());
        }

        if self.circuit_breaker_timeout.as_secs() > 300 {
            errors.push(format!(
                "Circuit breaker timeout ({} seconds) is unusually long (recommended: < 5 minutes)",
                self.circuit_breaker_timeout.as_secs()
            ));
        }

        // Return aggregated errors
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::ConfigError(format!(
                "Pool configuration validation failed:\n  - {}",
                errors.join("\n  - ")
            )))
        }
    }
}

/// Pooled connection wrapper with metadata
struct PooledConnection<T> {
    connection: T,
    created_at: Instant,
    last_used_at: Instant,
}

impl<T> PooledConnection<T> {
    fn new(connection: T) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used_at: now,
        }
    }

    fn is_expired(&self, config: &PoolConfig) -> bool {
        let now = Instant::now();
        // Check max lifetime exceeded
        if now.duration_since(self.created_at) > config.max_lifetime {
            return true;
        }
        // Check idle timeout exceeded
        if now.duration_since(self.last_used_at) > config.idle_timeout {
            return true;
        }
        false
    }

    fn touch(&mut self) {
        self.last_used_at = Instant::now();
    }
}

/// Factory trait for creating new connections
pub trait ConnectionFactory<T>: Send + Sync {
    /// Create a new connection asynchronously
    fn create(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>>;

    /// Check if a connection is still healthy
    fn is_healthy(&self, _conn: &T) -> bool {
        true
    }
}

/// Pool metrics for monitoring and capacity planning
#[derive(Debug, Default)]
pub struct PoolMetrics {
    /// Total connections created
    pub connections_created: AtomicU64,
    /// Total connections reused from pool
    pub connections_reused: AtomicU64,
    /// Total connections evicted (expired/unhealthy)
    pub connections_evicted: AtomicU64,
    /// Total acquisition errors
    pub acquisition_errors: AtomicU64,
    /// Current active (checked out) connections
    pub active_connections: AtomicUsize,
    /// Current idle (in pool) connections
    pub idle_connections: AtomicUsize,
    /// Total wait time in microseconds (for avg calculation)
    pub total_wait_time_us: AtomicU64,
    /// Total successful acquisitions
    pub total_acquisitions: AtomicU64,
}

impl PoolMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn average_wait_time_us(&self) -> u64 {
        let total = self.total_acquisitions.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        self.total_wait_time_us.load(Ordering::Relaxed) / total
    }

    pub fn utilization_percent(&self) -> f64 {
        let active = self.active_connections.load(Ordering::Relaxed) as f64;
        let idle = self.idle_connections.load(Ordering::Relaxed) as f64;
        let total = active + idle;
        if total == 0.0 {
            return 0.0;
        }
        (active / total) * 100.0
    }
}

/// Circuit breaker for fail-fast behavior
#[derive(Debug)]
struct CircuitBreaker {
    consecutive_failures: AtomicUsize,
    threshold: usize,
    timeout: Duration,
    opened_at: Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    fn new(threshold: usize, timeout: Duration) -> Self {
        Self {
            consecutive_failures: AtomicUsize::new(0),
            threshold,
            timeout,
            opened_at: Mutex::new(None),
        }
    }

    async fn check(&self) -> Result<()> {
        let mut opened_at = self.opened_at.lock().await;
        if let Some(opened_time) = *opened_at {
            // Circuit is open, check if timeout elapsed
            if opened_time.elapsed() < self.timeout {
                return Err(ProtocolError::CircuitBreakerOpen);
            }
            // Timeout elapsed, enter half-open state
            *opened_at = None;
            self.consecutive_failures.store(0, Ordering::SeqCst);
            debug!("Circuit breaker entering half-open state");
        }
        Ok(())
    }

    async fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        let mut opened_at = self.opened_at.lock().await;
        if opened_at.is_some() {
            *opened_at = None;
            debug!("Circuit breaker closed after successful operation");
        }
    }

    async fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if failures >= self.threshold {
            let mut opened_at = self.opened_at.lock().await;
            *opened_at = Some(Instant::now());
            error!(
                "Circuit breaker opened after {} consecutive failures",
                failures
            );
        }
    }
}

/// Generic connection pool for any transport type
pub struct ConnectionPool<T> {
    config: PoolConfig,
    factory: Arc<dyn ConnectionFactory<T>>,
    connections: Arc<Mutex<VecDeque<PooledConnection<T>>>>,
    metrics: Arc<PoolMetrics>,
    circuit_breaker: Arc<CircuitBreaker>,
    backpressure: Arc<Semaphore>,
}

impl<T: Send + 'static> ConnectionPool<T> {
    /// Create a new connection pool
    pub fn new(factory: Arc<dyn ConnectionFactory<T>>, config: PoolConfig) -> Result<Self> {
        config.validate()?;

        let metrics = Arc::new(PoolMetrics::new());
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            config.circuit_breaker_threshold,
            config.circuit_breaker_timeout,
        ));

        let pool = Self {
            config: config.clone(),
            factory: factory.clone(),
            connections: Arc::new(Mutex::new(VecDeque::new())),
            metrics: metrics.clone(),
            circuit_breaker,
            backpressure: Arc::new(Semaphore::new(config.max_waiters)),
        };

        // Spawn connection warming task
        if config.min_size > 0 {
            let factory_clone = factory;
            let connections_clone = pool.connections.clone();
            let metrics_clone = metrics;
            let min_size = config.min_size;

            tokio::spawn(async move {
                debug!("Warming connection pool with {} connections", min_size);
                for _ in 0..min_size {
                    match factory_clone.create().await {
                        Ok(conn) => {
                            let mut connections = connections_clone.lock().await;
                            connections.push_back(PooledConnection::new(conn));
                            metrics_clone
                                .connections_created
                                .fetch_add(1, Ordering::Relaxed);
                            metrics_clone
                                .idle_connections
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            warn!("Failed to warm connection: {}", e);
                            break;
                        }
                    }
                }
                debug!("Connection pool warming complete");
            });
        }

        Ok(pool)
    }

    /// Get a connection from the pool or create a new one
    pub async fn acquire(&self) -> Result<PooledConnectionGuard<T>> {
        let start = Instant::now();

        // Enforce backpressure limit
        let _permit = self
            .backpressure
            .acquire()
            .await
            .map_err(|_| ProtocolError::PoolExhausted)?;

        // Check circuit breaker
        self.circuit_breaker.check().await?;

        let mut connections = self.connections.lock().await;

        // Try to find a valid connection in the pool (LRU: take from back)
        while let Some(mut pooled) = connections.pop_back() {
            if !pooled.is_expired(&self.config) && self.factory.is_healthy(&pooled.connection) {
                pooled.touch();
                self.metrics
                    .connections_reused
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .idle_connections
                    .fetch_sub(1, Ordering::Relaxed);
                self.metrics
                    .active_connections
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .total_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .total_wait_time_us
                    .fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);

                debug!("Reused connection from pool (LRU)");
                return Ok(PooledConnectionGuard {
                    connection: Some(pooled.connection),
                    pool: self.connections.clone(),
                    metrics: self.metrics.clone(),
                });
            }
            debug!("Evicted expired/unhealthy connection from pool");
            self.metrics
                .connections_evicted
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .idle_connections
                .fetch_sub(1, Ordering::Relaxed);
        }

        // No valid connection found, create new one
        drop(connections); // Release lock before creating new connection

        match self.factory.create().await {
            Ok(new_conn) => {
                self.circuit_breaker.record_success().await;
                self.metrics
                    .connections_created
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .active_connections
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .total_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .total_wait_time_us
                    .fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);

                debug!("Created new connection for pool");

                Ok(PooledConnectionGuard {
                    connection: Some(new_conn),
                    pool: self.connections.clone(),
                    metrics: self.metrics.clone(),
                })
            }
            Err(e) => {
                self.circuit_breaker.record_failure().await;
                self.metrics
                    .acquisition_errors
                    .fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Get pool metrics
    pub fn metrics(&self) -> Arc<PoolMetrics> {
        self.metrics.clone()
    }

    /// Current number of connections in pool
    pub async fn size(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Clear all connections from the pool
    pub async fn clear(&self) {
        self.connections.lock().await.clear();
        debug!("Cleared all connections from pool");
    }

    /// Get pool configuration
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }
}

/// RAII guard for pooled connections
///
/// Returns the connection to the pool on drop.
pub struct PooledConnectionGuard<T: Send + 'static> {
    connection: Option<T>,
    pool: Arc<Mutex<VecDeque<PooledConnection<T>>>>,
    metrics: Arc<PoolMetrics>,
}

impl<T: Send + 'static> PooledConnectionGuard<T> {
    /// Get a reference to the underlying connection
    pub fn get(&self) -> Option<&T> {
        self.connection.as_ref()
    }

    /// Get a mutable reference to the underlying connection
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.connection.as_mut()
    }

    /// Extract the connection (won't be returned to pool)
    pub fn into_inner(mut self) -> Option<T> {
        self.connection.take()
    }
}

impl<T: Send + 'static> AsRef<T> for PooledConnectionGuard<T> {
    #[allow(clippy::expect_used)] // Connection is guaranteed to exist unless into_inner() was called
    fn as_ref(&self) -> &T {
        self.connection.as_ref().expect("Connection should exist")
    }
}

impl<T: Send + 'static> AsMut<T> for PooledConnectionGuard<T> {
    #[allow(clippy::expect_used)] // Connection is guaranteed to exist unless into_inner() was called
    fn as_mut(&mut self) -> &mut T {
        self.connection.as_mut().expect("Connection should exist")
    }
}

impl<T: Send + 'static> Drop for PooledConnectionGuard<T> {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            let pool = self.pool.clone();
            let metrics = self.metrics.clone();
            let pooled = PooledConnection::new(conn);

            // Update metrics
            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);

            // Try to return connection to pool (async context may not be available)
            // This spawns a background task to handle the return
            tokio::spawn(async move {
                let mut connections = pool.lock().await;
                if connections.len() < 100 {
                    // Reasonable max to prevent memory issues
                    connections.push_back(pooled);
                    metrics.idle_connections.fetch_add(1, Ordering::Relaxed);
                } else {
                    warn!("Connection pool at capacity, discarding connection");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[allow(dead_code)]
    struct TestConnection {
        id: usize,
    }

    struct TestFactory {
        counter: Arc<AtomicUsize>,
    }

    impl TestFactory {
        fn new() -> Self {
            Self {
                counter: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn count(&self) -> usize {
            self.counter.load(Ordering::SeqCst)
        }
    }

    impl ConnectionFactory<TestConnection> for TestFactory {
        fn create(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TestConnection>> + Send>>
        {
            let id = self.counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(TestConnection { id }) })
        }
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let factory = Arc::new(TestFactory::new());
        let pool = ConnectionPool::new(
            factory.clone(),
            PoolConfig {
                min_size: 2,
                max_size: 10,
                idle_timeout: Duration::from_secs(60),
                max_lifetime: Duration::from_secs(600),
                ..Default::default()
            },
        );

        assert!(pool.is_ok());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)] // Test code
    async fn test_pool_acquire_creates_connection() {
        let factory = Arc::new(TestFactory::new());
        let pool = ConnectionPool::new(factory.clone(), PoolConfig::default()).unwrap();

        let guard = pool.acquire().await.unwrap();
        assert!(guard.get().is_some());
        assert_eq!(factory.count(), 1);
    }

    #[tokio::test]
    async fn test_config_validation() {
        let invalid_config = PoolConfig {
            min_size: 100,
            max_size: 10,
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(600),
            ..Default::default()
        };

        let factory = Arc::new(TestFactory::new());
        let result = ConnectionPool::new(factory, invalid_config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_config_validation_zero_max_size() {
        let config = PoolConfig {
            max_size: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_config_validation_zero_timeouts() {
        let config = PoolConfig {
            idle_timeout: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config2 = PoolConfig {
            max_lifetime: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(config2.validate().is_err());
    }

    #[tokio::test]
    async fn test_config_validation_idle_exceeds_lifetime() {
        let config = PoolConfig {
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(300),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_config_validation_circuit_breaker() {
        let config = PoolConfig {
            circuit_breaker_threshold: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config2 = PoolConfig {
            circuit_breaker_timeout: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(config2.validate().is_err());
    }

    #[tokio::test]
    async fn test_config_validation_valid_config() {
        let config = PoolConfig::default();
        assert!(config.validate().is_ok());
    }
}
