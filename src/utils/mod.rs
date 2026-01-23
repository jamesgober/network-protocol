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
//!
//! ## Security
//! - Cryptographically secure RNG (getrandom)
//! - Decompression bomb protection (16MB limit)
//! - Memory zeroing for sensitive data (zeroize crate)

pub mod compression;
pub mod crypto;
pub mod logging;
pub mod time;
pub mod timeout;

/// Optional runtime configuration (may be expanded to struct later)
pub struct RuntimeConfig;
