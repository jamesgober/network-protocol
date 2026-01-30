//! # Transport Layer
//!
//! This file is part of the Network Protocol project.
//!
//! It defines the transport layer for network communication,
//! including remote and local operations.
//!
//! The transport layer is responsible for handling the actual data transmission
//! between nodes in a network,
//! ensuring that packets are sent and received correctly.
//!
//! It abstracts the underlying network details,
//! allowing higher-level protocol logic to focus on message routing and processing.
//!
//! The transport layer is designed to be modular and extensible,
//! supporting various transport mechanisms such as TCP, UDP, and custom protocols.
//!
//! ## Responsibilities
//! - Send and receive packets over the network
//! - Handle connection management
//! - Provide a unified interface for different transport protocols
pub mod cluster;
pub mod local;
pub mod quic;
pub mod remote;
pub mod session_cache;
pub mod tls;

#[cfg(windows)]
pub mod windows_pipe;
