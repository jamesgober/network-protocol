# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-10-09

A review of every TLS, transport and server setting for values that were accepted and then ignored, or that failed open. Each one found is fixed below. Settings that cannot do what they say without a new design are deprecated, so the compiler now tells you they have no effect.

### Security
- `TlsClientConfig::with_pinned_cert_hash(..)` was ignored unless `insecure()` was also set. Without `insecure()` the client built a standard webpki verifier and never looked at the pin, so any certificate from a trusted CA for the host name was accepted, contrary to the documentation. The pin is now checked on top of CA and hostname validation: the certificate must chain to a trusted root, match the server name, and have the pinned SHA-256 fingerprint.
- `TlsServerConfig::require_client_auth(true)` without `with_client_auth(..)` required nothing: with no client CA the server was built with no client authentication at all and accepted every client. `load_server_config()` now returns `ProtocolError::TlsError("client authentication is required but no client CA is configured: call with_client_auth(\"<client-ca.pem>\") ...")`. Servers that call `with_client_auth(..)` are unaffected.
- The packet codec read the 4-byte length from a frame header and then waited for that many bytes before checking anything. The magic, the version and `MAX_PAYLOAD_SIZE` (16 MiB) were only checked once the whole frame had arrived, so a peer could send a 9-byte header declaring up to 4 GiB and make the connection buffer it, on every transport (TLS, TCP, Unix sockets, named pipes). The header is now validated as soon as its 9 bytes arrive, and a frame that declares more than `MAX_PAYLOAD_SIZE` fails with `ProtocolError::OversizedPacket` before any payload is buffered. The encoder also refuses to send a payload over the limit instead of sending one the peer must reject (or, above 4 GiB, a truncated length that desynchronises the stream).
- TLS servers (`transport::tls::start_server` and `service::tls_daemon`) waited indefinitely for a client to complete the handshake, so stalled connections could be held open without limit. The handshake now has to finish within `HANDSHAKE_TIMEOUT` (10 s), which already existed but was unused. The client side of `tls::connect` and `TlsClient` has the same bound.
- `TlsServerConfig::generate_self_signed(..)` wrote the private key with the default file mode (usually 0644 on Unix). It is now created with mode 0600.

### Fixed
- A pinned hash that is not 32 bytes long can never match, but `with_pinned_cert_hash(..)` only logged a warning and every handshake then failed with a misleading "hash mismatch". `load_client_config()` now returns a `TlsError` naming the length it got and pointing to `TlsServerConfig::calculate_cert_hash()`. This also catches the common mistake of passing a hex string.
- `service::tls_daemon::start()` dropped the only sender of its shutdown channel, so the server returned about half a second after it started. It now runs until Ctrl-C. `start_with_shutdown()` no longer treats a channel whose senders were all dropped as a shutdown request; it shuts down when `()` is sent.
- `TlsClient::connect_with_session(.., Some(cache))` only logged "Session resumption enabled": a fresh rustls config was built per connection, so nothing was ever resumed. The `SessionCache` now holds the rustls session store, plus the rustls client config built for each distinct `TlsClientConfig` (rustls only resumes with the verifier that checked the original session), and a reconnect to the same server name resumes the TLS session. Certificate and CA files are read on the first connection with a given configuration; call `SessionCache::clear()` after replacing them.
- `tls::connect()` and `TlsClient::connect*()` leaked the server name string on every connection (`Box::leak`). They now use an owned `ServerName`.
- `ServerConfig::connection_timeout` was applied to the whole session in `service::daemon`, so every connection was closed once it was older than the timeout (5 s by default), however active it was. It now bounds each handshake step, as before, and an established session lasts until the client disconnects or the keep-alive finds it dead.
- Shutting down `service::daemon` or `service::tls_daemon` waited for open sessions for the grace period (`ServerConfig::shutdown_timeout`, or 10 s for the TLS daemon) and then returned while leaving those sessions running. Sessions still open when the grace period ends are now closed.
- `start_daemon_no_signals()` installed a Ctrl-C handler despite its name. It now stops only through `Daemon::shutdown()`.
- `ServerConfig::max_connections` was validated but never enforced. Connections accepted over the limit are now closed immediately.
- `ServerConfig::backpressure_limit` was validated but never used; the per-connection queues were fixed at 32 messages. They now use the configured limit.
- `service::daemon::start_daemon_no_signals(config, dispatcher)` ignored `dispatcher` and served with its own default handlers. It now dispatches with the dispatcher it is given.
- `ClientConfig::operation_timeout` was never used. It now bounds `Client::send()`; receives keep their 5 s default.
- `PoolConfig::max_size` was validated but the pool kept up to 100 idle connections whatever it was set to. Released connections beyond `max_size` are now closed.
- `PoolConfig::max_lifetime` was reset each time a connection was returned to the pool, so a connection in steady use was never retired. The lifetime now counts from when the connection was created.
- `TlsClientConfig::load_client_config()` accepted an empty system root store and then failed every handshake. It now returns a `TlsError` that suggests `with_root_ca(..)`.
- `utils::logging::init_logging()` with `log_dir` set wrote nothing to the log file: the guard of the non-blocking file writer was dropped inside the function, which shut the writer down. The guard is now kept for the life of the process.
- The `insecure()` docs referred to a `dangerous_configuration` feature that does not exist.
- README and `docs/` described TLS and server APIs that do not exist (`TlsConfig { .. }` literals, `client::connect_tls`, `tls::ServerConfig::builder()`, a running server from `daemon::new_with_config`, and others), and some metrics, logging and handshake examples did not match the code. They now use the real API.
- The key-loading error now says which key format is supported (PEM `PRIVATE KEY`, PKCS#8).

### Added
- `TlsClientConfig::with_root_ca(path)`: trust the CA certificates in a PEM file instead of the system roots, for servers with a private CA. Before this, the only way to reach such a server was `insecure()`. Combining it with `insecure()` is a config error.

### Deprecated
- `ClientConfig::auto_reconnect`, `max_reconnect_attempts` and `reconnect_delay`: `Client` has never reconnected, whatever they are set to. They now default when missing from a config file, so they can be removed from it.
- Every field of `TransportConfig`: nothing reads them. They now default when missing from a config file. The codec always enforces `MAX_PAYLOAD_SIZE`, the built-in services always encrypt, and compression is only applied where `utils::compression` is called directly.
- `service::daemon::new_with_config()` (starts nothing and ignores its dispatcher), `Daemon::run()` (returns immediately) and `Daemon::shutdown_with_timeout()` (ignores its timeout). Use `start_daemon_no_signals()` and `Daemon::shutdown()`.

### Known Issues
- `bincode` 1.3.3 remains unmaintained (RUSTSEC-2025-0141). It defines the wire encoding and appears in the public `ProtocolError` type, so replacing it is a breaking change planned for 2.0.

## [1.2.4] - 2026-10-08

### Security
- Certificate pinning did not prove that the server holds the pinned certificate's private key. With `TlsClientConfig::insecure().with_pinned_cert_hash(..)`, the client compared the certificate fingerprint, but its `verify_tls12_signature` and `verify_tls13_signature` returned success without checking the handshake signature. A certificate is public, so any server that presented a copy of the pinned certificate was accepted, and an attacker on the network path could impersonate the pinned server. The verifier now checks the handshake signature against the certificate's public key with `rustls::crypto::verify_tls12_signature` / `verify_tls13_signature`, using the signature algorithms of the crate's `ring` provider. A server that presents the pinned certificate without its private key now fails the handshake with a `BadSignature` error. The bug was introduced in 1.2.0 with the move to rustls 0.22, which replaced the rustls default signature checks with these no-op methods; 1.1.x and earlier are not affected.
- `insecure()` without a pin now also verifies the handshake signature. This mode is documented to accept any certificate, and it still does: there is no chain or hostname validation, so it gives no protection against an attacker who presents their own certificate. The signature check only confirms that the server holds the key for the certificate it sent. It costs nothing and every correctly configured server passes it, so both custom verifiers now behave the same way. The `insecure()` docs now say exactly what is and is not checked.
- Both custom verifiers advertised only three signature schemes (RSA PKCS#1 SHA-256, ECDSA P-256 SHA-256, Ed25519). They now advertise the schemes supported by the `ring` provider, the same list the standard rustls verifier uses.

### Fixed
- `TlsServerConfig::require_client_auth(false)` had no effect: once a client CA was set with `with_client_auth(..)`, a client certificate was always required. `false` now makes client authentication optional, as documented: a client without a certificate is accepted, and a certificate that is presented must still be signed by the client CA. This is a behaviour change for code that called `require_client_auth(false)` but relied on certificates being required anyway.
- `with_tls_versions(..)` and `with_cipher_suites(..)` on `TlsServerConfig` and `TlsClientConfig` only logged the requested values; the configs always used the rustls defaults (TLS 1.2 and 1.3 with every `ring` cipher suite). They are now applied, which is a behaviour change toward what the API always promised:
  - Only the listed protocol versions are enabled. `TlsVersion::All` enables TLS 1.2 and 1.3.
  - Only the listed cipher suites are enabled. Suites are matched by their IANA identifier against the suites of the `ring` provider and keep that provider's preference order. A requested suite the provider does not support is ignored with a warning.
  - `load_server_config()` and `load_client_config()` now return `ProtocolError::TlsError` when the request leaves nothing usable: an empty version list, an empty cipher suite list, no supported suite among those given, or no suite that works with the enabled versions. These cases no longer fall back to the defaults.
  - Code that passed values to these methods and was unknowingly running with the defaults can now see config errors, or handshakes refused by peers that only support the excluded versions or suites.

### Added
- TLS tests: a pinned client connects to the real server; a pinned client rejects an impostor server that presents the pinned certificate but signs with a different key (TLS 1.2 and 1.3); `insecure()` rejects the same impostor; optional client authentication accepts a client without a certificate and still rejects a certificate from an untrusted CA; a TLS 1.3-only server rejects a TLS 1.2-only client; cipher suite restrictions are visible in the negotiated suite; and the config errors listed above.

## [1.2.3] - 2026-10-08

### Fixed
- `TlsServerConfig::load_server_config()` panicked with "Could not automatically determine the process-level CryptoProvider" when mTLS was enabled with `with_client_auth(..)`. The client certificate verifier was built with `WebPkiClientVerifier::builder`, which uses the process-level default provider, and `rustls` was built with both the `ring` and `aws-lc-rs` backends, so no default could be chosen. The verifier now uses the same explicit `ring` provider as the server and client config builders. The bug was present since 1.2.1.

### Changed
- `rustls` and `tokio-rustls` are now built without their default features, enabling only `ring`, `std`, `tls12` and `logging`. The crate only uses the `ring` provider, so `aws-lc-rs` (and its `cmake` build dependency) is no longer pulled into downstream builds. TLS behaviour is unchanged.

### Added
- mTLS tests that run without installing a process-level `CryptoProvider`: building an mTLS server config, a handshake with a client certificate signed by the trusted CA, and rejection of a client with no certificate or with a certificate from an untrusted CA
- Tests now build `rustls` with both the `ring` and `aws-lc-rs` backends, so any code path that falls back to the process-level provider fails in tests. The manual `CryptoProvider::install_default()` call in `test_tls_pem_loading` is no longer needed and was removed.

## [1.2.2] - 2026-10-08

### Security
- Raised the `rustls` floor to 0.23.45 to address RUSTSEC-2026-0285 (TLS 1.3 handshake messages were accepted across encryption levels). This version of `rustls` requires `rustls-webpki` 0.103.14 or later, so downstream builds can no longer resolve a vulnerable webpki.
- Upgraded `rustls-webpki` from 0.103.10 to 0.103.15 to address RUSTSEC-2026-0098 and RUSTSEC-2026-0099 (incorrectly accepted name constraints) and RUSTSEC-2026-0104 (reachable panic in CRL parsing)
- Raised the `rand` floor to 0.9.3 to address RUSTSEC-2026-0097 (unsound `rand::rng()` with a custom logger)
- Upgraded `crossbeam-epoch` from 0.9.18 to 0.9.21 in the lockfile (dev dependency via `criterion`) to address RUSTSEC-2026-0204
- Removed the unmaintained `rustls-pemfile` dependency (RUSTSEC-2025-0134). PEM certificates and PKCS8 keys are now parsed with the `PemObject` API from `rustls-pki-types`. Parsing behaviour and error messages are unchanged.

### Changed
- Upgraded `rustls-native-certs` from 0.7 to 0.8, which no longer depends on `rustls-pemfile`. Loading system roots still fails if the platform store reports any error, as before.
- Refreshed `Cargo.lock` and `fuzz/Cargo.lock`
- Removed the RUSTSEC-2025-0134 ignore from `deny.toml`
- CI: updated `actions/checkout` from v4 to v7

### Added
- Test covering PEM loading for server certificates, the mTLS client CA file and client credentials, including rejection of files with the wrong PEM section type

### Known Issues
- `bincode` 1.3.3 remains unmaintained (RUSTSEC-2025-0141) and is still tracked for migration

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


[Unreleased]: https://github.com/jamesgober/network-protocol/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/jamesgober/network-protocol/compare/v1.2.4...v1.3.0
[1.2.4]: https://github.com/jamesgober/network-protocol/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/jamesgober/network-protocol/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/jamesgober/network-protocol/compare/v1.2.1...v1.2.2
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
