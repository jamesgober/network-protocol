# Performance Tuning Guide

This guide provides recommendations for optimizing the performance of network-protocol in production deployments.

## Table of Contents

- [Compression Configuration](#compression-configuration)
- [Serialization Format Selection](#serialization-format-selection)
- [Build Optimization](#build-optimization)
- [Runtime Configuration](#runtime-configuration)
- [Platform-Specific Optimizations](#platform-specific-optimizations)
- [Benchmarking Methodology](#benchmarking-methodology)
- [Monitoring and Profiling](#monitoring-and-profiling)

---

## Compression Configuration

### Algorithm Selection

The library supports two compression algorithms with different performance characteristics:

#### LZ4 (Default - Recommended)
- **Speed**: ~500 MB/s compression, ~2 GB/s decompression
- **Ratio**: Moderate (2-3x typical)
- **Use case**: Low-latency applications, real-time communication
- **CPU overhead**: Minimal

```rust
use network_protocol::utils::compression::{compress_lz4, decompress_lz4};

let data = b"Your data here...";
let compressed = compress_lz4(data)?;
let decompressed = decompress_lz4(&compressed)?;
```

#### Zstandard (High Compression)
- **Speed**: ~100-400 MB/s compression, ~800 MB/s decompression
- **Ratio**: High (3-5x typical, tunable)
- **Use case**: Bandwidth-constrained scenarios, archival
- **CPU overhead**: Moderate to high

```rust
use network_protocol::utils::compression::{compress_zstd, decompress_zstd};

let data = b"Your data here...";
let compressed = compress_zstd(data)?;
let decompressed = decompress_zstd(&compressed)?;
```

### Automatic Compression Threshold

The `maybe_compress()` function automatically compresses data only when beneficial:

```rust
use network_protocol::utils::compression::{maybe_compress, maybe_decompress};

// Only compresses if data is larger than 128 bytes
let (compressed_data, was_compressed) = maybe_compress(data);

// Automatically detects if decompression is needed
let original = maybe_decompress(&compressed_data, was_compressed)?;
```

**Threshold Recommendations:**
- **Default (128 bytes)**: Good for mixed workloads
- **Larger (512-1024 bytes)**: For low-latency requirements
- **Smaller (64 bytes)**: For bandwidth-constrained networks

---

## Serialization Format Selection

Choose the serialization format based on your requirements:

### Bincode (Default - Production)
```rust
use network_protocol::core::serialization::{MultiFormat, SerializationFormat};

let message = Message::Ping;
let bytes = message.serialize_format(SerializationFormat::Bincode)?;
```

**Performance**: ~100-200ns per message  
**Size**: Most compact binary format  
**Use case**: Production deployments, high-throughput scenarios

### JSON (Debugging & Interop)
```rust
let bytes = message.serialize_format(SerializationFormat::Json)?;
let json_str = std::str::from_utf8(&bytes)?;
println!("Debug: {}", json_str);
```

**Performance**: ~500-1000ns per message  
**Size**: 2-3x larger than bincode  
**Use case**: Debugging, web APIs, human-readable logs

### MessagePack (Cross-Language)
```rust
let bytes = message.serialize_format(SerializationFormat::MessagePack)?;
```

**Performance**: ~150-300ns per message  
**Size**: Compact, similar to bincode  
**Use case**: Cross-language interoperability, polyglot systems

**Recommendation**: Use Bincode for production, JSON for development/debugging.

---

## Build Optimization

### Release Profile

The default release profile is optimized for maximum performance:

```toml
[profile.release]
lto = true              # Link-Time Optimization
codegen-units = 1       # Single codegen unit for better optimization
opt-level = 3           # Maximum optimization
debug = false           # No debug symbols
strip = "symbols"       # Strip all symbols
```

**Build command:**
```bash
cargo build --release
```

**Expected improvements:**
- 20-30% faster than default release build
- Smaller binary size
- Longer compile time (acceptable for production builds)

### Platform-Specific Optimizations

#### Linux (x86_64)
```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

#### macOS (ARM64/M1/M2)
```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

#### Cross-compilation
```bash
# For specific CPU features
RUSTFLAGS="-C target-feature=+aes,+sse4.2" cargo build --release
```

### Benchmarking Profile

For accurate benchmarks:

```toml
[profile.bench]
lto = true
codegen-units = 1
opt-level = 3
debug = true            # Enable debug symbols for profiling
```

---

## Runtime Configuration

### Connection Pool Sizing

Configure the server's connection limit based on expected concurrency. `ServerConfig` applies to `service::daemon`; the TLS daemon does not take one.

```rust
use network_protocol::config::ServerConfig;
use std::time::Duration;

// For high-concurrency servers (1000+ connections)
let high_concurrency = ServerConfig {
    max_connections: 2000,
    connection_timeout: Duration::from_secs(30),
    ..Default::default()
};

// For low-latency applications
let low_latency = ServerConfig {
    max_connections: 100,
    connection_timeout: Duration::from_secs(5),
    ..Default::default()
};
```

Connections accepted over `max_connections` are closed immediately (from 1.3.0). `connection_timeout` bounds each step of a client's handshake; it does not limit how long an established session lasts.

**Guidelines:**
- **Web servers**: max_connections = expected_concurrent_users × 1.5
- **Microservices**: max_connections = upstream_services × 10
- **Real-time systems**: Keep under 100 for predictable latency

For outgoing connections, `PoolConfig::max_size` sets how many idle connections a `ConnectionPool` keeps; extra released connections are closed.

### Channel Buffer Sizes

Each server connection queues incoming messages in a bounded channel whose depth is `ServerConfig::backpressure_limit` (default: 32). When the queue is full, the server stops reading from that client until it drains. Tune it based on workload:

```rust
use network_protocol::config::ServerConfig;

// High-throughput (trade memory for throughput)
let high_throughput = ServerConfig {
    backpressure_limit: 1000,
    ..Default::default()
};

// Low-latency (minimize queuing)
let low_latency = ServerConfig {
    backpressure_limit: 16,
    ..Default::default()
};
```

Before 1.3.0 the queues were fixed at 32 messages whatever this was set to.

### Timeout Configuration

Balance responsiveness with reliability:

```rust
use network_protocol::config::ClientConfig;
use std::time::Duration;

// Aggressive (low-latency)
let aggressive = ClientConfig {
    connection_timeout: Duration::from_millis(500), // Connect and handshake response
    operation_timeout: Duration::from_secs(1),      // Each Client::send
    response_timeout: Duration::from_secs(1),       // Client::send_and_wait
    ..Default::default()
};

// Conservative (unreliable networks)
let conservative = ClientConfig {
    connection_timeout: Duration::from_secs(5),
    operation_timeout: Duration::from_secs(30),
    response_timeout: Duration::from_secs(30),
    ..Default::default()
};
```

`Client::recv()` uses a fixed 5 second timeout. TLS handshakes, on both the client and the server, must finish within 10 seconds.

---

## Platform-Specific Optimizations

### Linux

#### TCP Tuning
```bash
# Increase TCP buffer sizes
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

# Enable TCP fast open
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

#### File Descriptor Limits
```bash
# Check current limit
ulimit -n

# Increase (temporary)
ulimit -n 65536

# Permanent: Edit /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536
```

### macOS

#### Increase File Descriptors
```bash
# Check current limit
launchctl limit maxfiles

# Increase (requires restart)
sudo launchctl limit maxfiles 65536 200000
```

#### Network Tuning
```bash
# Increase socket buffer sizes
sudo sysctl -w kern.ipc.maxsockbuf=16777216
sudo sysctl -w net.inet.tcp.sendspace=1048576
sudo sysctl -w net.inet.tcp.recvspace=1048576
```

### Windows

#### Named Pipes (Recommended)
The library uses native Windows Named Pipes by default for 30-40% better IPC performance:

```rust
// Automatic on Windows
use network_protocol::transport::local;

// Start server (uses Named Pipes on Windows)
local::start_server("my_app").await?;
```

#### TCP Fallback (if needed)
```toml
[features]
use-tcp-on-windows = []
```

```bash
cargo build --release --features use-tcp-on-windows
```

---

## Benchmarking Methodology

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench packet_bench

# Save baseline for comparison
cargo bench -- --save-baseline before-optimization

# Compare against baseline
cargo bench -- --baseline before-optimization
```

### Available Benchmarks

#### Packet Benchmark
Tests core packet encoding/decoding:
```bash
cargo bench --bench packet_bench
```

**Metrics:**
- Encode throughput: ~2-3 GB/s
- Decode throughput: ~1.5-2 GB/s

#### Compression Benchmark
Tests compression algorithms:
```bash
cargo bench --bench compression_bench
```

**Metrics:**
- LZ4: ~500 MB/s (compression), ~2 GB/s (decompression)
- Zstd: ~100-400 MB/s (compression), ~800 MB/s (decompression)

#### Message Benchmark
Tests message serialization:
```bash
cargo bench --bench message_bench
```

**Metrics:**
- Bincode: ~100-200ns per message
- JSON: ~500-1000ns per message
- MessagePack: ~150-300ns per message

### Interpreting Results

Look for:
- **Throughput**: Higher is better (MB/s or messages/sec)
- **Latency**: Lower is better (ns or µs)
- **Variance**: Lower is more consistent (check std dev)

**Example output:**
```
packet_encode          time:   [12.345 ns 12.567 ns 12.789 ns]
                       thrpt:  [2.34 GiB/s 2.38 GiB/s 2.42 GiB/s]
```

### Custom Benchmarks

Create application-specific benchmarks:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn my_benchmark(c: &mut Criterion) {
    c.bench_function("my_operation", |b| {
        b.iter(|| {
            // Your code here
            black_box(expensive_operation());
        });
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```

---

## Monitoring and Profiling

### Built-in Metrics

The library provides atomic counters for monitoring in `utils::metrics`:

```rust
use network_protocol::utils::metrics::global_metrics;

fn print_metrics() {
    // Get current metrics
    let stats = global_metrics().snapshot();
    println!("Handshakes: {}", stats.handshakes_success);
    println!("Messages: {}", stats.messages_sent);
    println!("Errors: {}", stats.connection_errors + stats.protocol_errors);
}
```

In 1.3.0 nothing in the library updates these counters. The client, the daemons and the transports do not record anything, so every value stays at zero unless your own code calls the recording methods (`message_sent(bytes)`, `connection_established()`, `handshake_success()` and so on). Use them for your own events, or rely on logging and the pool metrics below.

**Available metrics (fields of `MetricsSnapshot`):**
- `connections_total`, `connections_active`
- `handshakes_total`, `handshakes_success`, `handshakes_failed`
- `messages_sent`, `messages_received`, `bytes_sent`, `bytes_received`
- `compression_total`, `compression_success`, `encryption_total`, `encryption_success`
- `replay_cache_hits`, `replay_cache_misses`
- `connection_errors`, `protocol_errors`
- `uptime_seconds`: time since the metrics were first used

`utils::metrics::Timer::start("operation")` logs how long an operation took, at DEBUG level, when it is dropped.

`ConnectionPool::metrics()` is updated by the pool itself: connections created, reused and evicted, acquisition errors, active and idle connections, `average_wait_time_us()` and `utilization_percent()`.

### Logging Configuration

Structured logging with tracing:

```rust
use network_protocol::{init_with_config, utils::logging::LogConfig};
use tracing::Level;

let config = LogConfig {
    app_name: "my-app".to_string(),
    log_level: Level::INFO,      // INFO for production
    log_dir: Some("/var/log/my-app".to_string()), // None logs to the console only
    ..Default::default()
};

init_with_config(&config);
```

**Log levels:**
- `ERROR`: Critical issues only
- `WARN`: Production default (errors + warnings)
- `INFO`: Normal operation visibility
- `DEBUG`: Development/troubleshooting
- `TRACE`: Verbose debugging (not for production)

### Profiling with perf (Linux)

```bash
# Record profile
perf record --call-graph dwarf ./target/release/my-app

# View report
perf report

# Generate flamegraph
perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

### Profiling with Instruments (macOS)

```bash
# Time profiler
instruments -t "Time Profiler" -D profile.trace ./target/release/my-app

# Allocations
instruments -t "Allocations" -D allocs.trace ./target/release/my-app
```

### Memory Profiling with valgrind

```bash
# Install valgrind
sudo apt install valgrind

# Run with massif (heap profiler)
valgrind --tool=massif ./target/release/my-app

# Analyze results
ms_print massif.out.*
```

---

## Performance Checklist

Before deploying to production:

- [ ] Build with `--release` and LTO enabled
- [ ] Choose appropriate compression algorithm (LZ4 for latency, Zstd for bandwidth)
- [ ] Use Bincode serialization format
- [ ] Configure timeouts based on network characteristics
- [ ] Tune channel buffer sizes for workload
- [ ] Set appropriate connection pool limits
- [ ] Enable platform-specific optimizations
- [ ] Run benchmarks to establish baseline
- [ ] Configure monitoring and metrics collection
- [ ] Set log level to WARN or ERROR in production
- [ ] Test under expected load (stress testing)
- [ ] Profile hotspots and optimize critical paths

---

## Performance Targets

**Typical performance on modern hardware (Linux, x86_64, 3.0 GHz):**

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Packet encode | ~12 ns | 2.5 GB/s |
| Packet decode | ~18 ns | 1.8 GB/s |
| Handshake (full) | ~50-100 µs | 10k-20k/sec |
| Message send | ~200 ns | 5M msgs/sec |
| LZ4 compress | ~2 µs/KB | 500 MB/s |
| LZ4 decompress | ~0.5 µs/KB | 2 GB/s |

**Scalability:**
- 10,000+ concurrent connections per server
- 100,000+ messages/sec sustained throughput
- Sub-millisecond p99 latency at moderate load
- Linear scaling with CPU cores (to ~16 cores)

---

## Troubleshooting Performance Issues

### High Latency

**Symptoms**: Slow response times, timeouts  
**Solutions**:
- Reduce compression threshold
- Use LZ4 instead of Zstd
- Decrease channel buffer sizes
- Check network latency (`ping`, `traceroute`)
- Profile with `tracing` at DEBUG level

### High CPU Usage

**Symptoms**: 100% CPU, thread contention  
**Solutions**:
- Reduce compression level (or disable)
- Increase compression threshold
- Use async operations instead of blocking
- Profile with `perf` or `Instruments`
- Check for busy loops in application code

### High Memory Usage

**Symptoms**: Growing RSS, OOM errors  
**Solutions**:
- Reduce channel buffer sizes
- Implement connection limits
- Use compression for large payloads
- Check for memory leaks with `valgrind`
- Review replay cache and session cache sizes

### Low Throughput

**Symptoms**: Below expected messages/sec  
**Solutions**:
- Increase channel buffer sizes
- Use Bincode serialization
- Batch messages when possible
- Check network bandwidth (`iperf`)
- Profile with benchmarks
- Verify no single-threaded bottlenecks

---

## Additional Resources

- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Tokio Performance Tuning](https://tokio.rs/tokio/topics/performance)
- [Linux Performance Tools](http://www.brendangregg.com/linuxperf.html)
- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)

---

For deployment patterns and architecture guidance, see [DEPLOYMENT.md](./DEPLOYMENT.md).
