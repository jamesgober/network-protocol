# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **CRITICAL**: Added pre-decompression size validation for LZ4 to prevent OOM DoS attacks from malicious size claims (discovered via fuzzing)
- Refactored the handshake to per-session state with `#[derive(Zeroize)]`, eliminating global mutexed state and ensuring secrets are cleared on drop.
- Added explicit nonce/key zeroization in secure send/receive paths to prevent secret retention in memory.
- Bounded decompression output to `MAX_PAYLOAD_SIZE` (4MB) for LZ4 and Zstd to mitigate compression-bomb DoS vectors.
- Tightened replay protection: 30s maximum age with 2s future skew tolerance for handshake timestamps.
- Authenticated packet headers (magic/version/length) via AEAD associated data to detect header tampering.
- Hardened TLS configuration: validate requested versions/cipher suites, validate pinned cert hash length, and emit warnings when insecure mode disables certificate verification.
- Resolved `cargo-audit` findings by upgrading `rcgen` to 0.14.5 (now 0.14.7 via patch) and pinning `tracing-subscriber` to 0.3.20.
- Updated TLS self-signed certificate generation to use `rcgen` 0.14 `CertifiedKey` API.

### Added
- Comprehensive fuzzing infrastructure using cargo-fuzz and libFuzzer
- Three fuzz targets: packet deserialization, protocol messages, and compression boundaries
- Fuzzing documentation in fuzz/README.md with usage guidelines and CI integration
- Pre-decompression validation of LZ4 claimed size to prevent memory exhaustion
- Configurable `compression_threshold_bytes` to bypass compression for tiny payloads (default 512B)
- Helper APIs `maybe_compress`/`maybe_decompress` for threshold-aware compression
- GitHub Actions fuzz smoke job (nightly, 30s per target)
- Criterion microbenchmarks for packet, compression, message paths
- Stress tests for encode/decode bursts and concurrent async load
- Optimized release/bench profiles (LTO, codegen-units=1, strip symbols)

### Added
- Comprehensive fuzzing infrastructure using cargo-fuzz and libFuzzer
- Three fuzz targets: packet deserialization, protocol messages, and compression boundaries
- Fuzzing documentation in fuzz/README.md with usage guidelines and CI integration
- Pre-decompression validation of LZ4 claimed size to prevent memory exhaustion

### Changed
- Handshake APIs now return per-connection state and messages instead of relying on global singletons; client and daemon call sites updated accordingly.
- TLS builder logs and validates configuration intent so operators can confirm enforced TLS settings.
- Enabled `rcgen` `pem` feature and adapted certificate/key serialization in `src/transport/tls.rs`.
- Cleaned up clippy warnings across tests and protocol modules.
- LZ4 decompression now validates claimed size before allocation to prevent DoS

### Fixed
- Packet serialization now respects the packet's `version` field instead of always writing the protocol constant.
- LZ4 decompression OOM vulnerability (CVE-class: remote DoS via crafted 4-byte payload)



## [1.0.0] - 2025-08-18

### Added
- Comprehensive configuration management system with extensive customization options
- Support for TOML configuration files with serde serialization/deserialization
- Environment variable overrides for all configuration settings
- Configuration structures for server, client, transport, and logging settings
- Default configuration values aligned with existing protocol constants
- Example configuration file in docs/example_config.toml
- Helper modules for serializing Duration and tracing::Level types
- API for loading configuration from files, environment variables, and TOML strings
- ConfigError variant added to ProtocolError enum for proper error handling
- Custom configuration serialization utilities for duration and log level

### Changed
- Updated service APIs to accept custom configuration parameters
- Enhanced daemon server to use configuration for timeouts, backpressure, and connection limits
- Modified client connection code to support configuration-driven behavior
- Refactored protocol constants into structured configuration objects
- Improved error handling for configuration-related operations
- Added Copy and Clone derives to CompressionKind enum for better ergonomics
- Modified compression utilities to take references instead of values for better performance

### Fixed
- Fixed clippy warnings throughout the codebase for better code quality
- Improved TLS shutdown test stability by increasing startup delay

### Documentation
- Enhanced error documentation across core modules:
  - Added comprehensive error case documentation to compress/decompress functions
  - Added detailed error documentation to timeout utility functions
  - Improved codec documentation with better error case descriptions
  - Enhanced handshake protocol documentation with security considerations
- Updated API documentation with more usage examples
- Clarified error handling patterns in public API functions


## [0.9.9] - 2025-08-17

### Added
- Comprehensive benchmarking documentation in API.md
- Performance metrics reference in README.md
- Benchmark result interpretation guidelines
- Research and evaluation of zero-copy deserialization approaches
- Detailed zero-copy deserialization analysis in docs/zero-copy.md

### Changed
- Improved benchmark tests with proper graceful shutdown
- Enhanced error handling in performance tests
- Added explicit server termination in benchmark tests
- Updated project description and keywords to reflect benchmarking focus

### Fixed
- Fixed "broken pipe" errors in benchmark tests with proper connection handling
- Corrected throughput calculation in benchmarking
- Added proper error documentation for expected benchmark behavior


## [0.9.6] - 2025-08-17

### Added
- Integrated structured logging with `tracing` crate throughout the codebase
- Added `#[tracing::instrument]` attributes to key async functions for enhanced contextual logging
- Created logging configuration module with flexible log level control via environment variables
- Implemented concurrent-safe logging infrastructure for better debugging and observability
- Added configurable connection timeouts for all network operations
- Implemented heartbeat mechanism with keep-alive ping/pong messages
- Added automatic detection and cleanup of dead connections
- Implemented client-side timeout handling with automatic reconnection capability
- Implemented backpressure mechanism in connection handling with bounded channels to prevent server overload
- Added ability to pause reading from connections when processing queues are full

### Changed
- Optimized packet encoding to avoid intermediate Vec<u8> allocations, reducing memory pressure and improving performance
- Replaced all `println!` and `eprintln!` calls with appropriate structured logging macros (`debug!`, `info!`, `warn!`, `error!`)
- Enhanced logging detail with structured fields for better filtering and analysis
- Improved error logging with contextual information across all modules
- Updated documentation examples to use structured logging
- Modified connection handling to use timeout wrappers for all I/O operations
- Enhanced client and server implementations to support configurable timeouts
- Updated network transport layer to detect and report connection timeouts
- Refactored message processing loops to handle keep-alive messages transparently

### Fixed
- Removed deprecated legacy handshake functions (`derive_shared_key`, `verify_server_ack`, `server_handshake_response`)
- Removed deprecated message types (`HandshakeInit`, `HandshakeAck`)
- Removed references to deprecated code from dispatcher, client, and daemon
- Updated API documentation to reflect removal of legacy handshake functionality
- Fixed double error unwrapping in timeout handlers for client and server code
- Corrected handshake state management in parallel test executions
- Fixed client send_and_wait functionality to properly handle timeout errors
- Added proper cleanup of connection resources when timeout or keep-alive failures occur
- Fixed backpressure test freezing by adding proper timeout handling for all async operations
- Added appropriate mutability declarations for client variables in tests

### Security
- Enhanced security by removing insecure legacy handshake implementation


## [0.9.3] - 2025-08-17

### Added
- Cross-platform support for local transport (Windows compatibility)
- Windows-compatible alternative for Unix Domain Sockets using TCP
- Updated client and server binaries to work across platforms
- Secure handshake protocol using ECDH key exchange
- Protection against replay attacks using timestamps and nonce verification
- TLS support for secure external connections
- Self-signed certificate generation capability for development
- Dedicated TLS transport layer with client and server implementations
- Certificate pinning functionality for enhanced security in TLS connections
- Mutual TLS authentication (mTLS) support for bidirectional certificate verification
- Configuration options for TLS protocol versions (TLS 1.2, TLS 1.3)
- Customizable cipher suite selection for TLS connections
- Graceful shutdown support for all server implementations:
  - Signal handling (CTRL+C) for clean termination
  - Active connection tracking and draining
  - Configurable shutdown timeouts
  - Resource cleanup during shutdown (sockets, files, etc.)
  - Heartbeat task termination for cluster transport

### Changed
- Improved error handling in client/server binaries
- Updated format strings to use modern Rust syntax
- Fixed Clippy warnings throughout the codebase
- Added Default implementation for Dispatcher
- Replaced manual slice copying with more efficient `copy_from_slice` operations
- Added proper deprecated attribute handling for legacy message variants
- Fixed key derivation to ensure consistent shared secrets in secure handshake
- Replaced all `unwrap()` and `expect()` calls with proper error handling using Result propagation
- Added serialization support for ProtocolError with serde's Serialize/Deserialize traits
- Updated return types for handshake functions to use Result consistently
- Modified client handshake code to properly handle Result types
- Implemented graceful shutdown mechanism for the daemon server with proper signal handling
- Added comprehensive error propagation throughout the service layer
- Standardized graceful shutdown mechanism across all transport implementations
- Implemented proper shutdown test suite for verifying graceful termination

### Fixed
- Fixed intermittent test failures in secure handshake tests
- Added deterministic test keys for stable test behavior
- Implemented explicit nonce setting for reproducible tests
- Fixed integration tests to use random available ports to avoid port conflicts
- Corrected type mismatches in client connection code
- Resolved unused variable warnings
- Fixed unused Result warnings in daemon and server code

### Security
- Implemented Elliptic Curve Diffie-Hellman (ECDH) key exchange using x25519-dalek
- Added timestamp verification to prevent replay attacks
- Enhanced key derivation using SHA-256 and multiple entropy sources
- Ensured forward secrecy with ephemeral key pairs
- Deprecated the previous insecure handshake implementation



## [0.9.0] - 2025-07-29

### Added
- Initial release of Network Protocol
- Core packet structure with serialization and deserialization
- Protocol message types and dispatcher
- Transport layer with remote and cluster support
- Service layer with client and daemon implementations
- Secure connection handling with handshake protocol
- Cross-platform CI testing workflow

### Security
- Implemented secure handshake mechanism
- Added encryption for protocol messages

[Unreleased]: https://github.com/jamesgober/network-protocol/compare/1.0.0...HEAD
[1.0.0]: https://github.com/jamesgober/network-protocol/compare/v0.9.9...v1.0.0
[0.9.9]: https://github.com/jamesgober/network-protocol/compare/v0.9.6...v0.9.9
[0.9.6]: https://github.com/jamesgober/network-protocol/compare/v0.9.3...v0.9.6
[0.9.3]: https://github.com/jamesgober/network-protocol/compare/0.9.0...v0.9.3
[0.9.0]: https://github.com/jamesgober/network-protocol/releases/tag/0.9.0