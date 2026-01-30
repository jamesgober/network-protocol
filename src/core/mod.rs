//! # Core Protocol Components
//!
//! Low-level packet handling, codecs, and binary serialization.
//!
//! This module provides the foundation for the protocol, handling packet framing,
//! encoding/decoding, and wire format.
//!
//! ## Components
//! - **Packet**: Binary packet format with magic bytes and checksums
//! - **Codec**: Tokio codec for framing over byte streams
//!
//! ## Wire Format
//! ```text
//! [Magic(4)] [Version(1)] [Flags(1)] [Length(4)] [Payload(N)]
//! ```
//!
//! ## Security
//! - Maximum packet size: 16MB (prevents memory exhaustion)
//! - Magic bytes prevent accidental misinterpretation
//! - Length validation before allocation

pub mod codec;
pub mod packet;
pub mod serialization;
