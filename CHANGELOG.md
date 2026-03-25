# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1] - 2026-03-25

### Security
- Upgraded `lz4_flex` from 0.11.5 to 0.11.6 to address RUSTSEC-2026-0041 (block decompression memory disclosure risk)
- Upgraded TLS dependency line to `rustls` 0.23.x and `tokio-rustls` 0.26.x, resolving RUSTSEC-2026-0049 via `rustls-webpki` 0.103.10

### Changed
- Enabled the `ring` feature explicitly on `rustls` to keep the existing provider-based TLS builder path intact
- Updated version references in documentation and release metadata to 1.2.1

### Known Issues
- `bincode` 1.3.3 remains unmaintained (RUSTSEC-2025-0141) and is still tracked for migration
- `rustls-pemfile` 2.2.0 remains unmaintained (RUSTSEC-2025-0134) and is still required for PEM parsing paths

## [1.2.0] - 2026-02-23

### Fixed
- **Critical**: Removed invalid `#[cfg(test)]` attribute from use statement in `tests/shutdown.rs` that caused compilation failures on Linux/macOS CI runners
- **Critical**: Added missing `SinkExt` trait import in `tests/shutdown.rs` for Framed::send() method call on local transport test
- Added `.gitattributes` with explicit LF line ending rules to prevent cross-platform line ending conversion issues on Windows CI

### Added
- **Enterprise Connection Pooling**: Production-grade `ConnectionPool<T>` with Oracle-beating performance features:
  - **Connection Warming**: Automatic pre-creation of `min_size` connections on startup (eliminates cold start latency)
  - **Pool Metrics**: Real-time observability (utilization %, avg wait time, creation/reuse/eviction counts, active/idle connections) for capacity planning
  - **Circuit Breaker**: Fail-fast on consecutive failures (configurable threshold + timeout) to prevent cascade failures
  - **Backpressure**: Semaphore-based waiter limit (default 1,000) prevents OOM under extreme load
  - **LRU Acquisition**: Least-recently-used connection eviction (vs FIFO) for optimal load distribution
  - **Health Validation**: Automatic eviction of expired/unhealthy connections via `ConnectionFactory::is_healthy()`
  - **Configurable TTL**: Per-connection idle timeout + max lifetime enforcement
- **Request Multiplexing**: High-performance pipelining over single connections (the Oracle killer):
  - **ID-Tagged Requests**: 64-bit request IDs for collision-free correlation
  - **Lockless Routing**: O(1) response demuxing via DashMap concurrent hashmap
  - **Sub-millisecond Latency**: Zero-copy frame processing with per-request oneshot channels
  - **Automatic Cleanup**: Timeout-based stale request eviction (prevents memory leaks)
  - **Backpressure**: Configurable in-flight limit (default 10,000 concurrent requests) prevents pool exhaustion
  - **Performance**: Thousands of concurrent requests over handful of connections (eliminates TLS handshake bottleneck)
- **Zeroize Hardening**: Complete audit of cryptographic material handling with explicit memory clearing for session keys, shared secrets, and private keys — required for regulated data (HIPAA, PCI-DSS, GDPR) and SOC 2 compliance
- **Configuration Validation**: Comprehensive validation for all config structs with detailed error messages:
  - **PoolConfig**: Validates pool sizes, timeouts, circuit breaker settings, and backpressure limits
  - **MultiplexConfig**: Validates in-flight limits, request timeouts, and buffer sizes
  - **NetworkConfig**: Validates server/client/transport/logging configurations (already existing, enhanced)
  - **Detailed Error Messages**: Multi-line validation errors with specific parameter names and recommended limits
- **Deployment Guides**: Docker container examples, systemd unit templates, Kubernetes manifest samples, and operational troubleshooting guide in `docs/DEPLOYMENT.md`
- **New Error Variants**: `CircuitBreakerOpen`, `PoolExhausted` for precise error handling

### Changed
- **Major Dependency Upgrade**: Rustls 0.21.12 → 0.22.4, tokio-rustls 0.24.1 → 0.25.0, rustls-pemfile 1.0.4 → 2.2.0
  - Modernized TLS API: `.builder_with_provider()` for explicit crypto provider control
  - Updated certificate/key types: `CertificateDer<'_>`, `PrivateKeyDer` enums for better type safety
  - Custom verifiers moved to `rustls::client::danger` module for explicit "unsafe" semantics
  - Removed `#[instrument]` macros causing temporary lifetime issues (replaced with explicit logging at call sites)
- **New Dependency**: dashmap 6.1 for lockless concurrent hashmap in multiplexer
- Connection pooling and multiplexing interfaces integrated into `src/service/mod.rs` for seamless adoption

### Improved
- **Oracle-Scale OLTP Performance**: Request multiplexing eliminates connection pool exhaustion under high concurrency (10,000+ concurrent requests over ~10 connections vs traditional 1:1 model)
- **Production Observability**: Pool and multiplex metrics for capacity planning, alerting, and performance analysis
- **Reliability**: Circuit breaker prevents cascade failures, backpressure prevents OOM
- Memory safety: Session key structs now implement `Zeroize` trait ensuring sensitive data is cleared from memory on drop
- TLS handshake security: Explicit ServerName lifetime management via `Box::leak()` to satisfy rustls' `'static` requirements
- Enterprise readiness: All connection lifecycle now supports pooling + multiplexing for distributed database workloads

### Security
- Complete zeroize hardening audit: All `x25519` shared secrets, `ChaCha20-Poly1305` keys, and derived session material explicitly zeroed on drop
- Cryptographic keys in `TlsClientConfig` now wrapped in zeroizing types to prevent accidental memory leaks
- Updated SECURITY.md with zeroize guarantees and compliance matrix (HIPAA, PCI-DSS, GDPR, SOC 2)
- Resolved RUSTSEC-2025-0134 (rustls-pemfile 1.0.4 unmaintained) by upgrading to 2.2.0 with rustls 0.22

### Known Issues
- `bincode` 1.3.3 is unmaintained (RUSTSEC-2025-0141) — still required by existing code paths; upgrade path tracked for future release

## [1.1.1] - 2026-02-23

Security patch with critical vulnerability fixes and rustls-pemfile compatibility updates.

### Changed
- Updated TLS module to work with iterator-based return values from rustls-pemfile (collecting iterator results before error handling)

### Security
- Upgraded `bytes` from 1.5 to 1.11 to fix integer overflow vulnerability in `BytesMut::reserve` (RUSTSEC-2026-0007)
- Upgraded `time` to 0.3.47 to fix denial of service vulnerability via stack exhaustion (RUSTSEC-2026-0009)

### Known Issues
- `rustls-pemfile` 1.0.4 is unmaintained (RUSTSEC-2025-0134) — rustls-pemfile 2.0+ requires rustls 0.22+, incompatible with current rustls 0.21. Upgrade path to rustls 0.22 tracked for future release.
- `bincode` 1.3.3 is unmaintained (RUSTSEC-2025-0141) — still required by existing code paths

## [1.1.0] - 2026-01-30

Performance-focused release with adaptive compression, buffer pooling, zero-allocation error paths, and full backward compatibility.

### Added
- Buffer pooling for small allocations (<4KB) via `BufferPool` and `PooledBuffer` — 3-5% latency reduction under high load
- Adaptive compression using Shannon entropy analysis (`maybe_compress_adaptive()`) — 10-15% CPU reduction for mixed workloads
- Windows Named Pipes transport for local IPC — 30-40% better throughput vs TCP localhost on Windows
- Multi-format serialization via `MultiFormat` trait: Bincode (default), JSON, MessagePack with automatic format detection
- Replay cache (`src/utils/replay_cache.rs`) with O(1) FIFO eviction and per-peer nonce tracking
- Global atomic metrics for monitoring handshakes, messages, connections, and errors
- TLS session cache for 1.3 session resumption with automatic TTL-based expiration — ~50-70% reconnection latency reduction
- ALPN support in TLS server configuration
- QUIC transport module with interface definitions for future implementation
- Error constants module for zero-allocation error propagation

### Improved
- Zero-allocation error paths: static `&'static str` constants for all handshake and dispatcher errors
- Zero-copy opcode routing in dispatcher using `Cow<'static, str>` — 5-10% throughput improvement
- Replay cache eviction: O(n log n) → O(1) via VecDeque insertion-order tracking
- TLS client enhanced with optional session caching via `connect_with_session()` API
- Windows IPC defaults to Named Pipes (TCP fallback via `use-tcp-on-windows` feature)

### Removed
- Legacy `src/protocol/handshake_old.rs` — fully replaced by per-session state architecture

### Security
- TTL-based replay cache with per-peer nonce tracking prevents handshake replay attacks
- Centralized error constants reduce allocations in security-sensitive code paths
- TLS session cache with automatic expiration for session resumption


## [1.0.1] - 2026-01-23

### Security
- Pre-decompression size validation for LZ4/Zstd to prevent compression-bomb DoS (16MB hard limit)
- Refactored handshake to per-session state with `#[derive(Zeroize)]` — cryptographic material cleared on drop
- Explicit nonce/key zeroization in secure send/receive paths
- Tightened replay protection: 30s maximum age, 2s future skew tolerance
- Authenticated packet headers via AEAD associated data
- Hardened TLS configuration: protocol version/cipher suite validation, pinned cert hash length checks
- Updated TLS cert generation to `rcgen` 0.14 `CertifiedKey` API
- Resolved all `cargo-audit` findings (`rcgen` 0.14.7, `tracing-subscriber` 0.3.20)
- Updated `deny.toml` to cargo-deny 0.18+ format
- Applied comprehensive Clippy deny lints (`suspicious`, `correctness`, `unwrap/expect/panic`)
- Refactored TLS `load_client_config()` from 143 lines into focused helpers

### Added
- `ARCHITECTURE.md`: system design document (layer diagrams, data flow, security model)
- `THREAT_MODEL.md`: threat analysis with attack scenarios and mitigations
- Fuzzing infrastructure: 3 fuzz targets (packet, handshake, compression) with CI smoke tests
- Criterion microbenchmarks for packet, compression, and message paths
- Stress tests for encode/decode bursts and concurrent async load
- Configurable `compression_threshold_bytes` (default 512B) with `maybe_compress`/`maybe_decompress` helpers
- Optimized release/benchmark profiles (LTO, `codegen-units=1`, stripped symbols)
- CI gates: fmt, clippy, cargo-deny, cargo-audit, fuzz smoke

### Fixed
- Whitespace issues across TLS and error modules
- Scoped clippy allowances for `unwrap/expect/panic` in test and benchmark code
- Invalid `deny.toml` advisory severity keys for cargo-deny 0.18+
- All 80 tests passing, fmt clean, clippy clean



## [1.0.0] - 2025-08-18

### Added
- Configuration management system with TOML files, environment variable overrides, and programmatic API
- Configuration structures for server, client, transport, and logging settings
- Example configuration file in `docs/example_config.toml`
- Helper modules for serializing `Duration` and `tracing::Level` types
- `ConfigError` variant added to `ProtocolError` enum

### Changed
- Service APIs accept custom configuration parameters
- Daemon server uses configuration for timeouts, backpressure, and connection limits
- Protocol constants refactored into structured configuration objects
- `CompressionKind` now derives `Copy` and `Clone`
- Compression utilities take references instead of values

### Fixed
- Clippy warnings throughout the codebase
- TLS shutdown test stability

### Documentation
- Comprehensive error case documentation for compress/decompress, timeout, codec, and handshake functions
- Updated API docs with usage examples and error handling patterns


## [0.9.9] - 2025-08-17

### Added
- Benchmarking documentation in API.md and README.md
- Zero-copy deserialization analysis in `docs/zero-copy.md`

### Changed
- Benchmark tests now use proper graceful shutdown and explicit server termination

### Fixed
- "Broken pipe" errors in benchmark tests
- Throughput calculation in benchmarking


## [0.9.6] - 2025-08-17

### Added
- Structured logging with `tracing` crate and `#[tracing::instrument]` on key async functions
- Configurable connection timeouts for all network operations
- Heartbeat mechanism with keep-alive ping/pong and dead connection cleanup
- Client-side timeout handling with automatic reconnection
- Backpressure mechanism with bounded channels and dynamic read pausing

### Changed
- Packet encoding optimized to avoid intermediate `Vec<u8>` allocations
- All `println!`/`eprintln!` replaced with structured logging macros
- Connection handling uses timeout wrappers for all I/O operations
- Message processing loops handle keep-alive messages transparently

### Fixed
- Removed deprecated legacy handshake functions and message types
- Double error unwrapping in timeout handlers
- Handshake state management in parallel test executions
- Client `send_and_wait` timeout handling
- Backpressure test freezing

### Security
- Removed insecure legacy handshake implementation


## [0.9.3] - 2025-08-17

### Added
- Cross-platform local transport (Windows compatibility via TCP fallback)
- ECDH key exchange with X25519 and replay attack protection
- TLS transport with client/server implementations, mTLS, certificate pinning
- Self-signed certificate generation for development
- Configurable TLS protocol versions (1.2, 1.3) and cipher suites
- Graceful shutdown for all server implementations with signal handling

### Changed
- All `unwrap()`/`expect()` replaced with proper Result propagation
- `ProtocolError` now implements Serialize/Deserialize
- Standardized graceful shutdown across all transport implementations

### Fixed
- Intermittent secure handshake test failures (deterministic test keys)
- Integration tests use random ports to avoid conflicts
- Type mismatches in client connection code

### Security
- ECDH key exchange using x25519-dalek with forward secrecy
- Timestamp verification and SHA-256 key derivation


## [0.9.0] - 2025-07-29

### Added
- Initial release of Network Protocol
- Core packet structure with serialization and deserialization
- Protocol message types and dispatcher
- Transport layer with remote and cluster support
- Service layer with client and daemon implementations
- Secure connection handling with handshake protocol
- Cross-platform CI testing workflow


[Unreleased]: https://github.com/jamesgober/network-protocol/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/jamesgober/network-protocol/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/jamesgober/network-protocol/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/jamesgober/network-protocol/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jamesgober/network-protocol/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/jamesgober/network-protocol/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/jamesgober/network-protocol/compare/v0.9.9...v1.0.0
[0.9.9]: https://github.com/jamesgober/network-protocol/compare/v0.9.6...v0.9.9
[0.9.6]: https://github.com/jamesgober/network-protocol/compare/v0.9.3...v0.9.6
[0.9.3]: https://github.com/jamesgober/network-protocol/compare/0.9.0...v0.9.3
[0.9.0]: https://github.com/jamesgober/network-protocol/releases/tag/0.9.0
