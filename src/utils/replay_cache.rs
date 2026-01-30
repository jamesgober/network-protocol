//! Replay Cache for Enhanced Replay Attack Protection
//!
//! This module implements a TTL-based cache to track seen nonces and timestamps
//! per peer, providing stronger protection against replay attacks beyond the
//! basic timestamp window validation.
//!
//! The cache automatically expires entries to prevent unbounded growth while
//! maintaining security guarantees.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};
use tracing::{debug, instrument, warn};

/// Cache entry for a seen nonce/timestamp combination
#[derive(Debug, Clone)]
struct CacheEntry {
    /// When this entry was added to the cache
    added_at: Instant,
    /// The timestamp from the original message
    timestamp: u64,
    /// The nonce from the original message
    #[allow(dead_code)]
    nonce: [u8; 16],
}

/// Key for cache entries - combines peer identifier with nonce
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Peer identifier (could be IP, connection ID, etc.)
    peer_id: String,
    /// The nonce being tracked
    nonce: [u8; 16],
}

/// TTL-based replay cache with automatic expiration and O(1) eviction
///
/// Uses VecDeque to track insertion order for constant-time removal of oldest
/// entries when the cache reaches capacity, avoiding O(n log n) sorting overhead.
#[derive(Debug)]
pub struct ReplayCache {
    /// Internal storage mapping keys to entries
    entries: HashMap<CacheKey, CacheEntry>,
    /// Insertion order for FIFO eviction (O(1) instead of O(n log n))
    insertion_order: VecDeque<CacheKey>,
    /// Time-to-live for cache entries
    ttl: Duration,
    /// Maximum number of entries to prevent unbounded growth
    max_entries: usize,
}

impl ReplayCache {
    /// Create a new replay cache with default settings
    ///
    /// Default TTL: 5 minutes (longer than handshake timeout)
    /// Default max entries: 10,000
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            ttl: Duration::from_secs(300),
            max_entries: 10_000,
        }
    }

    /// Create a replay cache with custom settings
    pub fn with_settings(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            ttl,
            max_entries,
        }
    }

    /// Check if a nonce/timestamp combination has been seen recently
    ///
    /// Returns true if the combination is a replay (already seen), false if new.
    /// Automatically cleans up expired entries during the check.
    #[instrument(skip(self, peer_id, nonce))]
    pub fn is_replay(&mut self, peer_id: &str, nonce: &[u8; 16], timestamp: u64) -> bool {
        let key = CacheKey {
            peer_id: peer_id.to_string(),
            nonce: *nonce,
        };

        // Clean expired entries first
        self.cleanup_expired();

        // Check if we have this exact nonce for this peer
        if let Some(entry) = self.entries.get(&key) {
            // If timestamps match, it's definitely a replay
            if entry.timestamp == timestamp {
                warn!(
                    peer_id,
                    ?nonce,
                    timestamp,
                    "Replay attack detected - identical nonce and timestamp"
                );
                return true;
            }
            // If timestamps differ but nonce is same, still suspicious but allow
            // (could be legitimate nonce reuse with different timestamp)
            debug!(
                peer_id,
                ?nonce,
                "Nonce seen before with different timestamp - allowing"
            );
        }

        // Add to cache
        let entry = CacheEntry {
            added_at: Instant::now(),
            timestamp,
            nonce: *nonce,
        };

        // Enforce max entries limit by removing oldest entries if needed
        if self.entries.len() >= self.max_entries {
            let to_remove = self.entries.len() - self.max_entries + 1;
            self.remove_oldest_entries(to_remove);
        }

        self.entries.insert(key.clone(), entry);
        self.insertion_order.push_back(key);
        debug!(peer_id, ?nonce, timestamp, "New nonce/timestamp cached");

        false
    }

    /// Remove expired entries from the cache
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let initial_count = self.entries.len();

        self.entries
            .retain(|_, entry| now.duration_since(entry.added_at) < self.ttl);

        // Clean up insertion_order queue to match HashMap
        while let Some(key) = self.insertion_order.front() {
            if !self.entries.contains_key(key) {
                self.insertion_order.pop_front();
            } else {
                break;
            }
        }

        let removed = initial_count - self.entries.len();
        if removed > 0 {
            debug!("Cleaned up {} expired replay cache entries", removed);
        }
    }

    /// Remove oldest entries when cache is full using O(1) FIFO eviction.
    /// Previous O(n log n) sorting approach replaced with VecDeque pop_front.
    #[inline]
    fn remove_oldest_entries(&mut self, count: usize) {
        if count == 0 {
            return;
        }

        for _ in 0..count {
            if let Some(key) = self.insertion_order.pop_front() {
                self.entries.remove(&key);
            }
        }

        debug!(
            "Removed {} oldest replay cache entries due to size limit",
            count
        );
    }

    /// Get current cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.entries.len(),
            max_entries: self.max_entries,
            ttl_seconds: self.ttl.as_secs(),
        }
    }

    /// Clear all entries (useful for testing or manual cache reset)
    pub fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
        debug!("Replay cache cleared");
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the replay cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries
    pub entries: usize,
    /// Maximum allowed entries
    pub max_entries: usize,
    /// TTL in seconds
    pub ttl_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_replay_detection() {
        let mut cache = ReplayCache::with_settings(Duration::from_secs(60), 100);

        let peer_id = "test_peer";
        let nonce = [1u8; 16];
        let timestamp = 1234567890;

        // First time should not be replay
        assert!(!cache.is_replay(peer_id, &nonce, timestamp));

        // Same nonce/timestamp should be detected as replay
        assert!(cache.is_replay(peer_id, &nonce, timestamp));
    }

    #[test]
    fn test_different_nonce_allowed() {
        let mut cache = ReplayCache::with_settings(Duration::from_secs(60), 100);

        let peer_id = "test_peer";
        let nonce1 = [1u8; 16];
        let nonce2 = [2u8; 16];
        let timestamp = 1234567890;

        // Both should be allowed
        assert!(!cache.is_replay(peer_id, &nonce1, timestamp));
        assert!(!cache.is_replay(peer_id, &nonce2, timestamp));
    }

    #[test]
    fn test_same_nonce_different_timestamp_allowed() {
        let mut cache = ReplayCache::with_settings(Duration::from_secs(60), 100);

        let peer_id = "test_peer";
        let nonce = [1u8; 16];
        let timestamp1 = 1234567890;
        let timestamp2 = 1234567891;

        // Both should be allowed (different timestamps)
        assert!(!cache.is_replay(peer_id, &nonce, timestamp1));
        assert!(!cache.is_replay(peer_id, &nonce, timestamp2));
    }

    #[test]
    fn test_expiration() {
        let mut cache = ReplayCache::with_settings(Duration::from_millis(10), 100);

        let peer_id = "test_peer";
        let nonce = [1u8; 16];
        let timestamp = 1234567890;

        // Add entry
        assert!(!cache.is_replay(peer_id, &nonce, timestamp));

        // Wait for expiration
        thread::sleep(Duration::from_millis(20));

        // Should not be detected as replay anymore
        assert!(!cache.is_replay(peer_id, &nonce, timestamp));
    }

    #[test]
    fn test_max_entries_limit() {
        let mut cache = ReplayCache::with_settings(Duration::from_secs(60), 5);

        // Fill cache
        for i in 0..10 {
            let nonce = [i as u8; 16];
            assert!(!cache.is_replay("peer", &nonce, 1000 + i as u64));
        }

        // Cache should have removed some old entries
        assert!(cache.entries.len() <= 5);
    }
}
