<div align="center">
    <img width="120px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <h1>
        <strong>network-protocol</strong>
        <sup>
            <br>
            <sub>PERFORMANCE</sub>
            <br>
        </sup>
    </h1>
</div>

[Home](../README.md) | 
[Documentation](./README.md)

<!-- PERFORMANCE DATA -->
## Core Performance Metrics

| Metric | Result | Comparison | Improvement |
|--------|--------|------------|-------------|
| Round-trip Latency | 0.7ms | 40% faster than Tokio raw TCP | 15% vs v0.9.8 |
| Max Throughput | 12,500 msg/sec | 2x ZeroMQ | 30% vs v0.9.8 |
| Memory Per Connection | 4.2KB | 30% less than gRPC | 18% vs v0.9.8 |
| CPU Usage (single core) | 2.1% at 1000 msg/sec | 25% less than raw TCP | 5% vs v0.9.8 |

## Microbenchmarks (Criterion)

The following microbenchmarks were collected on macOS with `cargo bench` (v1.1.0).

### Packet Encode/Decode

| Size | Encode | Decode |
|------|--------|--------|
| 64B | 427 MiB/s | 1.02 GiB/s |
| 512B | 1.25 GiB/s | 4.29 GiB/s |
| 4KB | 5.59 GiB/s | 43.6 GiB/s |
| 64KB | 2.94 GiB/s | 44.4 GiB/s |
| 1MB | **2.48 GiB/s** (+26% vs v1.0.1) | **27.4 GiB/s** |

**Key Improvements (v1.1.0):**
- Large payload encoding improved by 26% (buffer pooling impact)
- Consistent high-speed decoding across all payload sizes

### Compression Performance

#### LZ4 (Optimized for Latency)
| Size | Compress | Decompress |
|------|----------|------------|
| 64B | 110 MiB/s | 785 MiB/s |
| 512B | 768 MiB/s | 3.56 GiB/s |
| 4KB | 3.34 GiB/s | 25.9 GiB/s |
| 64KB | 1.01 GiB/s | 21.1 GiB/s |
| 1MB | **1.61 GiB/s** (+24% vs v1.0.1) | **21.1 GiB/s** |

#### Zstd (Optimized for Ratio)
| Size | Compress | Decompress |
|------|----------|------------|
| 64B | 19.9 MiB/s | 739 KiB/s |
| 512B | 160 MiB/s | 5.33 MiB/s |
| 4KB | 1.09 GiB/s | 43.1 MiB/s |
| 64KB | 731 MiB/s | 77.1 MiB/s |
| 1MB | **1.43 GiB/s** (+56% vs v1.0.1) | **1.06 GiB/s** (+135% vs v1.0.1) |

**Key Improvements (v1.1.0):**
- Zstd compression 56% faster on large payloads (entropy-based bypass)
- Zstd decompression 135% faster (buffer pooling + adaptive selection)
- LZ4 compression 24% faster on large payloads

### Message Serialization (Bincode)
- Serialize: 670 ns/msg (1.49 M msgs/sec)
- Deserialize: 91 ns/msg (11.0 M msgs/sec)

Interpretation:
- **LZ4** is preferred for low-latency and high-throughput paths, especially for small/medium payloads.
- **Zstd** yields better compression ratios but with slower decompression; use for archival or bandwidth-constrained links.
- **Adaptive compression** (v1.1.0) automatically skips incompressible data (encrypted, pre-compressed) based on Shannon entropy, saving 10-15% CPU in mixed workloads.

## Stress & Concurrency Results

- Encode/decode stress (10k iterations across sizes up to 1 MiB) passes in ~1.2s without panics.
- Concurrent async stress (8 threads, 50k iterations per size) passes reliably, demonstrating thread-safety in codec and packet paths.

## Operational Recommendations

- Prefer `LZ4` for message compression under 256 KiB for best tail latency.
- Consider `Zstd` for large, highly compressible payloads when bandwidth dominates cost.
- Set a compression threshold (e.g., 256–512 bytes) to bypass compression for tiny payloads to avoid overhead.
- Enable release flags with `codegen-units=1` and `lto=true` for maximum efficiency in production.

<br>

### Light Load (100 concurrent connections)
- Avg latency: 0.8ms
- Memory usage: 420KB total
- Zero message loss

### Medium Load (1,000 concurrent connections)
- Avg latency: 1.2ms
- Memory usage: 4.1MB total
- Zero message loss

### Heavy Load (10,000 concurrent connections)
- Avg latency: 2.5ms
- Memory usage: 41MB total
- 99.998% message delivery rate

## Optimization Decisions

### Zero-Copy Implementation
While zero-copy deserialization can offer significant performance benefits for large payloads, [our benchmarks](./notes/zero-copy.md) show that our current implementation is not bottlenecked by deserialization for the typical message sizes (<64KB) used by most applications.

Current serialization overhead is only ~5% of total processing time. We've deferred implementation until:
1. Customer workloads demonstrate a need
2. Message sizes regularly exceed 1MB
3. Performance profiling identifies deserialization as a critical path

See [zero-copy research](./notes/zero-copy.md) for detailed analysis.


## Version Performance History

### v1.1.0 (Current)
**Measured Performance Gains:**
- **+26%** large payload encoding throughput (buffer pooling)
- **+56%** Zstd compression speed (adaptive entropy-based bypass)
- **+135%** Zstd decompression speed (optimized buffer management)
- **+24%** LZ4 compression speed on 1MB payloads
- **5-10%** lower error handling overhead (zero-allocation error paths)
- **10-15%** CPU reduction in mixed workloads (adaptive compression)
- **3-5%** latency improvement under high load (buffer pooling)

**Optimizations:**
- Buffer pooling for <4KB allocations reduces allocator contention
- Adaptive compression with Shannon entropy analysis (4.0 bits/byte threshold)
- Zero-allocation error constants in hot paths
- Removed legacy handshake code (782 lines)

### v1.0.1
- Baseline performance established
- Comprehensive test coverage (196+ tests)

### v0.9.9
- 30% higher throughput than v0.9.8
- 18% lower memory usage per connection
- Added cluster transport with minimal overhead

### v0.9.8
- Reduced latency by 25% through buffer optimization
- Improved TLS handshake speed by 40%

<br><br><br>

### Research
- [Zero Copy](./notes/zero-copy.md)





<!--
:: COPYRIGHT
============================================================================ -->
<div align="center">
  <br>
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2025 <strong>JAMES GOBER.</strong></sup>
</div>