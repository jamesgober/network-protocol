//! # Network Protocol Module
//!
//! This file is part of the Network Protocol project.
//!
//! It provides the main entry point for the protocol layer,
//! including the core components, transport mechanisms,
//! and utility functions.
//!
//! The protocol is designed to be modular, high-performance,
//! and suitable for local, remote, and cluster communication.
//!
//! The main components include:
//! - Core: packet handling, codec, error management
//! - Transport: network communication, remote operations
//! - Protocol: message routing, handshake logic
//! - Service: client and daemon abstractions
//! - Utils: cryptography, compression, time management
//!
//! The protocol layer is built with a focus on performance,
//! scalability, and ease of integration with other systems.
//!
//! ## Components
//! - `core`: Contains the core packet structure and codec for serialization/deserialization.
//! - `transport`: Implements the transport layer for network communication, including remote and local operations.
//! - `protocol`: Handles message routing and protocol-specific logic.
//! - `service`: Provides abstractions for client and daemon operations.
//! - `utils`: Contains utility functions for cryptography, compression, and time management.
//!
//! This module is essential for processing protocol packets in a networked environment,
//! ensuring correct parsing and serialization.
//!
//! It is designed to be efficient, minimal, and easy to integrate into the protocol layer.
//! # Protocol Layer
//!
//! Core protocol implementation including message handling, handshakes, and keepalive.
//!
//! This module implements the application-level protocol on top of the transport layer.
//! It handles secure session establishment, message routing, and connection lifecycle.
//!
//! ## Components
//! - **Handshake**: Secure session establishment with nonce and timestamp validation
//! - **Message**: Application-level message types and serialization
//! - **Dispatcher**: Message routing and handler registration
//! - **Heartbeat**: Connection liveness and idle detection
//! - **Keepalive**: Ping/pong mechanism for timeout prevention
//!
//! ## Security Features
//! - Per-session nonce tracking (prevents replay attacks)
//! - Timestamp validation (5-second window)
//! - AEAD encryption for all messages
//! - Session-specific encryption keys

pub mod dispatcher;
pub mod handshake;
pub mod heartbeat;
pub mod keepalive;
pub mod message;

#[cfg(test)]
mod tests;
