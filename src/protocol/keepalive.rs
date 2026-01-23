use crate::protocol::heartbeat::{build_ping, is_pong};
use crate::protocol::message::Message;
use crate::utils::timeout::KEEPALIVE_INTERVAL;
use std::time::{Duration, Instant};
use tracing::{debug, instrument, warn};

/// Keep-alive manager to maintain active connections and detect dead peers
#[derive(Debug)]
pub struct KeepAliveManager {
    /// Last time a message was sent
    last_send: Instant,
    /// Last time a message was received
    last_recv: Instant,
    /// Interval for sending ping messages
    pub ping_interval: Duration,
    /// Max time without receiving any message before considering connection dead
    dead_timeout: Duration,
}

impl KeepAliveManager {
    /// Create a new keep-alive manager with default settings
    pub fn new() -> Self {
        Self {
            last_send: Instant::now(),
            last_recv: Instant::now(),
            ping_interval: KEEPALIVE_INTERVAL,
            dead_timeout: KEEPALIVE_INTERVAL.mul_f32(4.0), // 4x the ping interval
        }
    }

    /// Create a new keep-alive manager with custom settings
    pub fn with_settings(ping_interval: Duration, dead_timeout: Duration) -> Self {
        Self {
            last_send: Instant::now(),
            last_recv: Instant::now(),
            ping_interval,
            dead_timeout,
        }
    }

    /// Update last send time
    pub fn update_send(&mut self) {
        self.last_send = Instant::now();
    }

    /// Update last receive time
    pub fn update_recv(&mut self) {
        self.last_recv = Instant::now();
    }

    /// Check if we need to send a ping to keep the connection alive
    pub fn should_ping(&self) -> bool {
        self.last_send.elapsed() >= self.ping_interval
    }

    /// Get the ping interval duration
    pub fn ping_interval(&self) -> Duration {
        self.ping_interval
    }

    /// Check if the connection is considered dead (no messages received)
    pub fn is_connection_dead(&self) -> bool {
        self.last_recv.elapsed() >= self.dead_timeout
    }

    /// Get time since last received message
    pub fn time_since_last_recv(&self) -> Duration {
        self.last_recv.elapsed()
    }

    /// Build a ping message for keep-alive
    #[instrument]
    pub fn build_ping_message() -> Message {
        debug!("Building ping message for keep-alive");
        build_ping()
    }

    /// Process an incoming message, update received timestamp if it's not a pong
    /// Returns true if the message was a pong response to our ping
    #[instrument(skip(msg))]
    pub fn process_message(&mut self, msg: &Message) -> bool {
        let is_pong_msg = is_pong(msg);

        // Update last received time for any message (including pong)
        self.update_recv();

        if is_pong_msg {
            debug!("Received pong message");
        }

        is_pong_msg
    }
}

impl Default for KeepAliveManager {
    fn default() -> Self {
        Self::new()
    }
}
