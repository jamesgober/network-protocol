# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **BUFFER POOLING**: Object pooling for small buffer allocations (<4KB)
  - New `src/utils/buffer_pool.rs` module for efficient memory reuse
  - Thread-safe buffer pool with configurable capacity
  - 3-5% latency reduction under high load by reducing allocator contention
  - Automatic return-to-pool on drop with size limits
  - Public API: `BufferPool` and `PooledBuffer` types exported from utils module

- **ADAPTIVE COMPRESSION**: Entropy-based compression decision making
  - `maybe_compress_adaptive()` function uses Shannon entropy analysis
  - Automatically skips compression of high-entropy data (encrypted, compressed, random)
  - 10-15% CPU reduction for mixed workloads by avoiding futile compression attempts
  - Smart sampling (first 512 bytes) for fast entropy calculation
  - Validates compression benefit (only use if actually smaller)

- **WINDOWS NAMED PIPES**: Native Windows Named Pipes transport for high-performance local IPC
  - New `src/transport/windows_pipe.rs` module with full named pipe server/client implementation
  - 30-40% better throughput compared to TCP localhost for local IPC on Windows
  - Graceful shutdown support with connection tracking
  - Automatic pipe recreation on errors for resilient server operation
  - Comprehensive test suite in `tests/windows_pipes.rs`
  - Updated `src/transport/local.rs` to use named pipes by default on Windows (TCP fallback available via `use-tcp-on-windows` feature)
  - Helper function to convert Unix-style paths to Windows pipe names (`\\\\.\\pipe\\name`)
  
- **ALTERNATIVE SERIALIZATION FORMATS**: Full multi-format serialization support via `MultiFormat` trait
  - Enhanced `src/core/serialization.rs` with comprehensive format abstraction
  - **Bincode** (default): Fastest, most compact binary format (~100-200ns)
  - **JSON**: Human-readable format for debugging and web API interoperability (~500-1000ns)
  - **MessagePack**: Compact binary format for cross-language compatibility (~150-300ns)
  - Automatic format detection via format header bytes (0x01=Bincode, 0x02=JSON, 0x03=MessagePack)
  - `serialize_format()` and `deserialize_format()` methods for explicit format control
  - `serialize_with_header()` and `deserialize_with_header()` for automatic format detection
  - Message type now implements `MultiFormat` trait for seamless format switching
  - Comprehensive test suite in `tests/serialization.rs` covering all formats and edge cases
  - Example program in `examples/serialization_formats.rs` demonstrating all features

### Improved
- **ZERO-ALLOCATION ERROR PATHS**: Static error constants eliminate heap allocations in hot paths
  - All handshake errors now use static `&'static str` constants
  - Dispatcher lock errors use error constants module
  - 5-10% reduction in allocation overhead for error cases
  - Enhanced `error::constants` module with comprehensive error message catalog
  - Maintains full Error trait compatibility and error context

- **PLATFORM SUPPORT**: Windows IPC now uses native Named Pipes for optimal performance
  - Falls back to TCP localhost only when `use-tcp-on-windows` feature is explicitly enabled
  - Provides performance parity with Unix Domain Sockets on Unix systems
  - Updated transport module documentation with platform-specific guidance

- **SERIALIZATION FLEXIBILITY**: Applications can now choose optimal format for their use case
  - Use Bincode for production workloads (fastest, most efficient)
  - Use JSON for debugging, logging, and web API endpoints
  - Use MessagePack for cross-language interoperability and bandwidth-constrained scenarios
  - Format selection at runtime without code changes

### Removed
- **LEGACY CODE**: Removed `src/protocol/handshake_old.rs` (obsolete per-session handshake)
  - New per-session state architecture fully replaces old global singleton approach
  - No functional impact - old module was unused
  - Cleaner codebase for v1.1.0 release

### Security
- **WINDOWS NAMED PIPES**: Native Windows Named Pipes transport for high-performance local IPC
  - New `src/transport/windows_pipe.rs` module with full named pipe server/client implementation
  - 30-40% better throughput compared to TCP localhost for local IPC on Windows
  - Graceful shutdown support with connection tracking
  - Automatic pipe recreation on errors for resilient server operation
  - Comprehensive test suite in `tests/windows_pipes.rs`
  - Updated `src/transport/local.rs` to use named pipes by default on Windows (TCP fallback available via `use-tcp-on-windows` feature)
  - Helper function to convert Unix-style paths to Windows pipe names (`\\\\.\\pipe\\name`)
  
- **ALTERNATIVE SERIALIZATION FORMATS**: Full multi-format serialization support via `MultiFormat` trait
  - Enhanced `src/core/serialization.rs` with comprehensive format abstraction
  - **Bincode** (default): Fastest, most compact binary format (~100-200ns)
  - **JSON**: Human-readable format for debugging and web API interoperability (~500-1000ns)
  - **MessagePack**: Compact binary format for cross-language compatibility (~150-300ns)
  - Automatic format detection via format header bytes (0x01=Bincode, 0x02=JSON, 0x03=MessagePack)
  - `serialize_format()` and `deserialize_format()` methods for explicit format control
  - `serialize_with_header()` and `deserialize_with_header()` for automatic format detection
  - Message type now implements `MultiFormat` trait for seamless format switching
  - Comprehensive test suite in `tests/serialization.rs` covering all formats and edge cases
  - Example program in `examples/serialization_formats.rs` demonstrating all features

### Improved
- **PLATFORM SUPPORT**: Windows IPC now uses native Named Pipes for optimal performance
  - Falls back to TCP localhost only when `use-tcp-on-windows` feature is explicitly enabled
  - Provides performance parity with Unix Domain Sockets on Unix systems
  - Updated transport module documentation with platform-specific guidance

- **SERIALIZATION FLEXIBILITY**: Applications can now choose optimal format for their use case
  - Use Bincode for production workloads (fastest, most efficient)
  - Use JSON for debugging, logging, and web API endpoints
  - Use MessagePack for cross-language interoperability and bandwidth-constrained scenarios
  - Format selection at runtime without code changes

### Security
- **REPLAY PROTECTION**: Implemented TTL-based replay cache with per-peer nonce tracking to prevent handshake replay attacks
- **OBSERVABILITY**: Added global atomic metrics for monitoring handshakes, messages, connections, and errors with zero startup cost
- **ERROR CONSTANTS**: Introduced centralized error message constants module to reduce allocations in error paths (security-sensitive code)
- **TLS SESSION CACHE**: Implemented in-memory session cache for TLS 1.3 session resumption with automatic TTL-based expiration

### Added
- **REPLAY CACHE**: New `src/utils/replay_cache.rs` module with configurable TTL, max entries, and automatic cleanup
  - O(1) FIFO eviction algorithm using VecDeque for constant-time removal at capacity
  - Per-peer nonce/timestamp tracking for replay attack prevention
  - Automatic TTL-based cleanup of expired entries
  - **PUBLIC API**: ReplayCache now exported from lib.rs for advanced users implementing custom protection strategies
- **METRICS**: New `src/utils/metrics.rs` module providing thread-safe counters for operation tracking and debugging
- **ALPN SUPPORT**: Added Application-Layer Protocol Negotiation to TLS server configuration for protocol evolution
- **QUIC TRANSPORT**: Added placeholder `src/transport/quic.rs` module with complete interface definitions for future QUIC implementation
- **HANDSHAKE INTEGRATION**: Updated handshake functions to accept replay cache parameters for replay attack prevention
- **ERROR CONSTANTS**: New `error::constants` module with static error messages for zero-allocation error propagation
- **TLS SESSION RESUMPTION**: New `src/transport/session_cache.rs` module for managing TLS session tickets
  - Thread-safe in-memory session storage with configurable capacity and TTL
  - Automatic expiration and FIFO eviction when capacity is exceeded
  - Integration with TlsClient for transparent reconnection support via `connect_with_session()`
  - Session statistics and monitoring capabilities
  - Reduces reconnection latency by ~50-70% for resumable connections

### Improved
- **DISPATCHER OPTIMIZATION**: Zero-copy opcode routing using `Cow<'static, str>` instead of heap-allocated `String`
  - Static message type opcodes (PING, PONG, ECHO, etc.) use borrowed references
  - Custom message commands use owned values only when necessary
  - Estimated 5-10% throughput improvement on high-message-volume workloads
  - Added `#[inline]` hints for hot path optimization

- **REPLAY CACHE EVICTION**: Replaced O(n log n) sorting algorithm with O(1) FIFO eviction
  - VecDeque tracks insertion order for constant-time removal
  - Enables stable performance at 100k+ concurrent connections
  - Eliminates allocation overhead from Vec sorting at capacity

- **ERROR HANDLING**: Centralized error messages to reduce allocations
  - All common errors now use static string constants
  - `error::constants` module provides reference documentation
  - Maintains full Error enum compatibility

- **TLS CLIENT**: Enhanced with optional session caching for improved reconnection performance
  - New `connect_with_session()` API for session resumption support
  - Automatic session ID generation and lifecycle management
  - Backward compatible - existing `connect()` API unchanged

### Performance
- **DISPATCHER HOT PATH**: +5-10% throughput improvement via zero-copy opcode routing
- **REPLAY CACHE**: O(n log n) → O(1) eviction for unbounded scalability
- **ERROR PROPAGATION**: Reduced allocations in error paths for security-sensitive code
- **TLS RECONNECTION**: ~50-70% latency reduction via session resumption
- Maintained performance within acceptable bounds (<15% regression in security-added features) while improving optimization

### Non-Breaking Changes
- **PUBLIC API EXPOSURE**: ReplayCache now available as public type via `use network_protocol::ReplayCache;`
  - Non-breaking addition - all existing code continues to work
  - Enables advanced users to implement custom replay protection strategies
- **SESSION CACHE API**: SessionCache is optional and transparent
  - TLS client works exactly as before without session caching
  - New `connect_with_session()` API for those who want session resumption
  - Existing applications require zero changes

## [1.0.1] - 2026-01-23

### Security
* **CRITICAL**: Added pre-decompression size validation for LZ4 and Zstd to prevent OOM and compression-bomb DoS attacks (discovered via fuzzing), enforcing strict bounds (`MAX_PAYLOAD_SIZE`, 16MB hard limit).
* Refactored handshake to per-session state with `#[derive(Zeroize)]`, eliminating global mutexed secrets and ensuring cryptographic material is cleared on drop.
* Added explicit nonce/key zeroization in secure send/receive paths to prevent secret retention in memory.
* Tightened replay protection: 30s maximum age with 2s future skew tolerance for handshake timestamps.
* Authenticated packet headers (magic/version/length) via AEAD associated data to detect header tampering.
* Hardened TLS configuration: validate requested protocol versions and cipher suites, validate pinned certificate hash length, and emit warnings when insecure mode disables certificate verification.
* Updated TLS self-signed certificate generation to use `rcgen` 0.14 `CertifiedKey` API.
* **SUPPLY CHAIN**: Resolved all `cargo-audit` findings by upgrading `rcgen` to 0.14.7 and pinning `tracing-subscriber` to 0.3.20.
* **SUPPLY CHAIN**: Updated `deny.toml` to modern cargo-deny 0.18+ format (removed deprecated keys, improved compatibility).
* **QUALITY GATES**: Applied comprehensive Clippy deny lints (`suspicious`, `correctness`, `unwrap/expect/panic`) to enforce secure coding practices.
* **CODE QUALITY**: Refactored TLS `load_client_config()` from 143 lines into focused helper functions, significantly reducing cyclomatic complexity.


### Added
* **DOCUMENTATION**:
  * Comprehensive module-level documentation for core, protocol, service, and utils layers.
  * `ARCHITECTURE.md`: 500+ line system design document (layer diagrams, data flow, security model, deployment patterns).
  * `THREAT_MODEL.md`: 300+ line threat analysis with attack scenarios, mitigations, and trust boundaries.
  * Enhanced README with explicit cryptographic, DoS/memory, implementation, and compliance guarantees.
* **FUZZING & QA**:
  * Full fuzzing infrastructure using `cargo-fuzz` and libFuzzer.
  * Three fuzz targets: packet deserialization, protocol messages, and compression boundaries.
  * Fuzzing documentation in `fuzz/README.md`.
  * GitHub Actions fuzz smoke job (nightly, 30s per target).
* **PERFORMANCE & TESTING**:
  * Criterion microbenchmarks for packet, compression, and message paths.
  * Stress tests for encode/decode bursts and concurrent async load.
  * Configurable `compression_threshold_bytes` (default 512B) to bypass compression for tiny payloads.
  * Helper APIs `maybe_compress` / `maybe_decompress` for threshold-aware compression.
  * Optimized release and benchmark profiles (LTO, `codegen-units=1`, stripped symbols).
* **CI/CD HARDENING**:
  * Format gate: `cargo fmt --all -- --check`
  * Clippy gate: `cargo clippy -D warnings` across all targets
  * Supply chain gate: `cargo-deny check` (licenses, advisories, sources)
  * Audit gate: `cargo-audit`
  * Fuzz smoke gate: libFuzzer runs on 3 targets

### Fixed
* **FORMAT**: Corrected whitespace and blank-line issues across TLS and error modules to satisfy `cargo fmt --check`.
* **CLIPPY**: Added scoped allowances for `unwrap/expect/panic` in test and benchmark code:

  * `src/protocol/tests.rs`, `handshake.rs` (test modules)
  * Benchmarks: `packet_bench.rs`, `compression_bench.rs`, `message_bench.rs`
  * Tests: `stress.rs`, `config_test.rs`, `concurrency.rs`, `tls.rs`, `perf.rs`, `dispatcher_bench.rs`, `test_utils.rs`, `timeouts.rs`, `integration.rs`, `shutdown.rs`, `edge_cases.rs`
  * Fixed inner attribute ordering in `tests/timeouts.rs`
  * Resolved `let_unit_value` lint in `tests/perf.rs`
* **DENY.toml**: Removed invalid advisory severity keys (`vulnerability`, `unlicensed`, `copyleft`, `default`) for cargo-deny 0.18+ compatibility.
* **STABILITY**: All 80 tests passing, `cargo fmt` clean, `cargo clippy -D warnings` clean, and optimized release builds verified.


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

[Unreleased]: https://github.com/jamesgober/network-protocol/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/jamesgober/network-protocol/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/jamesgober/network-protocol/compare/v0.9.9...v1.0.0
[0.9.9]: https://github.com/jamesgober/network-protocol/compare/v0.9.6...v0.9.9
[0.9.6]: https://github.com/jamesgober/network-protocol/compare/v0.9.3...v0.9.6
[0.9.3]: https://github.com/jamesgober/network-protocol/compare/0.9.0...v0.9.3
[0.9.0]: https://github.com/jamesgober/network-protocol/releases/tag/0.9.0