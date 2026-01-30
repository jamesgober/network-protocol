//! Observability and Metrics
//!
//! This module provides metrics collection and observability features
//! for monitoring protocol performance and health.
//!
//! Uses atomic counters for thread-safe metrics collection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::{debug, info};

/// Global metrics collector for protocol operations
#[derive(Debug)]
pub struct Metrics {
    /// Total connections established
    pub connections_total: AtomicU64,
    /// Currently active connections
    pub connections_active: AtomicU64,
    /// Total handshake attempts
    pub handshakes_total: AtomicU64,
    /// Successful handshakes
    pub handshakes_success: AtomicU64,
    /// Failed handshakes
    pub handshakes_failed: AtomicU64,
    /// Total messages sent
    pub messages_sent: AtomicU64,
    /// Total messages received
    pub messages_received: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Total compression operations
    pub compression_total: AtomicU64,
    /// Successful compression operations
    pub compression_success: AtomicU64,
    /// Total encryption operations
    pub encryption_total: AtomicU64,
    /// Successful encryption operations
    pub encryption_success: AtomicU64,
    /// Total replay cache hits
    pub replay_cache_hits: AtomicU64,
    /// Total replay cache misses
    pub replay_cache_misses: AtomicU64,
    /// Connection errors
    pub connection_errors: AtomicU64,
    /// Protocol errors
    pub protocol_errors: AtomicU64,
    /// Start time for uptime calculation
    start_time: Instant,
}

impl Metrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            handshakes_total: AtomicU64::new(0),
            handshakes_success: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            compression_total: AtomicU64::new(0),
            compression_success: AtomicU64::new(0),
            encryption_total: AtomicU64::new(0),
            encryption_success: AtomicU64::new(0),
            replay_cache_hits: AtomicU64::new(0),
            replay_cache_misses: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            protocol_errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record a new connection
    pub fn connection_established(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closed
    pub fn connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a handshake attempt
    pub fn handshake_attempt(&self) {
        self.handshakes_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful handshake
    pub fn handshake_success(&self) {
        self.handshakes_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed handshake
    pub fn handshake_failed(&self) {
        self.handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a message sent
    pub fn message_sent(&self, byte_count: u64) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(byte_count, Ordering::Relaxed);
    }

    /// Record a message received
    pub fn message_received(&self, byte_count: u64) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(byte_count, Ordering::Relaxed);
    }

    /// Record a compression attempt
    pub fn compression_attempt(&self) {
        self.compression_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful compression
    pub fn compression_success(&self) {
        self.compression_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an encryption attempt
    pub fn encryption_attempt(&self) {
        self.encryption_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful encryption
    pub fn encryption_success(&self) {
        self.encryption_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a replay cache hit
    pub fn replay_cache_hit(&self) {
        self.replay_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a replay cache miss
    pub fn replay_cache_miss(&self) {
        self.replay_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection error
    pub fn connection_error(&self) {
        self.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a protocol error
    pub fn protocol_error(&self) {
        self.protocol_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            handshakes_total: self.handshakes_total.load(Ordering::Relaxed),
            handshakes_success: self.handshakes_success.load(Ordering::Relaxed),
            handshakes_failed: self.handshakes_failed.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            compression_total: self.compression_total.load(Ordering::Relaxed),
            compression_success: self.compression_success.load(Ordering::Relaxed),
            encryption_total: self.encryption_total.load(Ordering::Relaxed),
            encryption_success: self.encryption_success.load(Ordering::Relaxed),
            replay_cache_hits: self.replay_cache_hits.load(Ordering::Relaxed),
            replay_cache_misses: self.replay_cache_misses.load(Ordering::Relaxed),
            connection_errors: self.connection_errors.load(Ordering::Relaxed),
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    /// Log current metrics
    pub fn log_metrics(&self) {
        let snapshot = self.snapshot();
        info!(
            connections_total = snapshot.connections_total,
            connections_active = snapshot.connections_active,
            handshakes_total = snapshot.handshakes_total,
            handshakes_success = snapshot.handshakes_success,
            handshakes_failed = snapshot.handshakes_failed,
            messages_sent = snapshot.messages_sent,
            messages_received = snapshot.messages_received,
            bytes_sent = snapshot.bytes_sent,
            bytes_received = snapshot.bytes_received,
            compression_total = snapshot.compression_total,
            compression_success = snapshot.compression_success,
            encryption_total = snapshot.encryption_total,
            encryption_success = snapshot.encryption_success,
            replay_cache_hits = snapshot.replay_cache_hits,
            replay_cache_misses = snapshot.replay_cache_misses,
            connection_errors = snapshot.connection_errors,
            protocol_errors = snapshot.protocol_errors,
            uptime_seconds = snapshot.uptime_seconds,
            "Protocol metrics snapshot"
        );
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub handshakes_total: u64,
    pub handshakes_success: u64,
    pub handshakes_failed: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub compression_total: u64,
    pub compression_success: u64,
    pub encryption_total: u64,
    pub encryption_success: u64,
    pub replay_cache_hits: u64,
    pub replay_cache_misses: u64,
    pub connection_errors: u64,
    pub protocol_errors: u64,
    pub uptime_seconds: u64,
}

/// Global metrics instance (lazy static for simplicity)
static METRICS: once_cell::sync::Lazy<Metrics> = once_cell::sync::Lazy::new(Metrics::new);

/// Get the global metrics instance
pub fn global_metrics() -> &'static Metrics {
    &METRICS
}

/// Initialize metrics collection (call once at startup)
pub fn init_metrics() {
    // Force initialization
    let _ = global_metrics();
    info!("Metrics collection initialized");
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
    operation: &'static str,
}

impl Timer {
    /// Start timing an operation
    pub fn start(operation: &'static str) -> Self {
        Self {
            start: Instant::now(),
            operation,
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        debug!(
            operation = self.operation,
            duration_ms = duration.as_millis(),
            "Operation completed"
        );
    }
}
