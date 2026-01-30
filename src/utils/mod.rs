//! # Utility Modules
//!
//! Supporting utilities for cryptography, compression, logging, and timing.
//!
//! This module provides reusable utilities used throughout the protocol implementation.
//!
//! ## Components
//! - **Crypto**: ChaCha20-Poly1305 AEAD encryption
//! - **Compression**: LZ4 and Zstd with size limits and thresholds
//! - **Logging**: Structured logging configuration
//! - **Time**: Timestamp utilities for timeout and expiry checks
//! - **Timeout**: Async timeout wrappers
//! - **Replay Cache**: TTL-based nonce deduplication for replay attack prevention
//! - **Metrics**: Thread-safe observability counters
//!
//! ## Security
//! - Cryptographically secure RNG (getrandom)
//! - Decompression bomb protection (16MB limit)
//! - Memory zeroing for sensitive data (zeroize crate)

pub mod compression;
pub mod crypto;
pub mod logging;
pub mod metrics;
pub mod replay_cache;
pub mod time;
pub mod timeout;

// Re-export public types for advanced users
pub use replay_cache::{CacheKey, ReplayCache};
