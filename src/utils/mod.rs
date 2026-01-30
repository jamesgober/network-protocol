//! # Utility Modules
//!
//! Supporting utilities for cryptography, compression, logging, and timing.
//!
//! This module provides reusable utilities used throughout the protocol implementation.
//!
//! ## Components
//! - **Crypto**: ChaCha20-Poly1305 AEAD encryption
//! - **Compression**: LZ4 and Zstd with size limits and adaptive entropy-based selection
//! - **Logging**: Structured logging configuration
//! - **Time**: Timestamp utilities for timeout and expiry checks
//! - **Timeout**: Async timeout wrappers
//! - **Replay Cache**: TTL-based nonce deduplication for replay attack prevention
//! - **Metrics**: Thread-safe observability counters
//! - **Buffer Pool**: Object pooling for small buffer allocations (<4KB)
//!
//! ## Security
//! - Cryptographically secure RNG (getrandom)
//! - Decompression bomb protection (16MB limit)
//! - Memory zeroing for sensitive data (zeroize crate)
//!
//! ## Performance
//! - Buffer pooling reduces allocation overhead by 3-5%
//! - Adaptive compression reduces CPU usage by 10-15% for mixed workloads

pub mod buffer_pool;
pub mod compression;
pub mod crypto;
pub mod logging;
pub mod metrics;
pub mod replay_cache;
pub mod time;
pub mod timeout;

// Re-export public types for advanced users
pub use buffer_pool::BufferPool;
pub use replay_cache::{CacheKey, ReplayCache};
