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

The following microbenchmarks were collected on macOS with `cargo bench`.

### Packet Encode/Decode
- Encode throughput: up to 1.89 GiB/s at 1 MiB payloads
- Decode throughput: up to 24.5 GiB/s at 1 MiB payloads

### Compression
- LZ4 compress: ~0.9–1.0 GiB/s at 1 MiB
- LZ4 decompress: ~18–19 GiB/s at 1 MiB
- Zstd compress (level 1): ~0.9–1.0 GiB/s at 1 MiB
- Zstd decompress: ~0.37–0.42 GiB/s at 1 MiB

Interpretation:
- LZ4 is preferred for low-latency and high-throughput paths, especially for small/medium payloads.
- Zstd yields better compression ratios but with much slower decompression; use for archival or bandwidth-constrained links.

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

### v0.9.9 (Current)
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