# Fuzzing Harnesses

This directory contains fuzzing harnesses for the network protocol library using cargo-fuzz and libFuzzer.

## Prerequisites

```bash
# Install nightly toolchain
rustup install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Fuzz Targets

### fuzz_target_1 - Packet Deserialization
Tests packet parsing for:
- Magic byte validation
- Protocol version checks
- Length field parsing
- Payload bounds checking
- Malformed input handling

### fuzz_handshake - Protocol Message Fuzzing
Tests protocol message serialization/deserialization for:
- Bincode deserialization safety
- Message type discrimination
- Serialization roundtrip consistency
- Data corruption resilience

### fuzz_compression - Compression Boundary Testing
Tests compression/decompression for:
- Decompression bomb DoS prevention
- Size limit enforcement (4MB cap)
- Malformed compressed data handling
- Both LZ4 and Zstd algorithms

## Running Fuzz Tests

### Quick Smoke Test (10 seconds each)
```bash
cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=10
cargo +nightly fuzz run fuzz_handshake -- -max_total_time=10
cargo +nightly fuzz run fuzz_compression -- -max_total_time=10
```

### Extended Fuzzing (1 hour)
```bash
cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=3600
cargo +nightly fuzz run fuzz_handshake -- -max_total_time=3600
cargo +nightly fuzz run fuzz_compression -- -max_total_time=3600
```

### Continuous Fuzzing (unlimited)
```bash
# Run until manually stopped (Ctrl+C)
cargo +nightly fuzz run fuzz_target_1
```

## Advanced Usage

### Minimize Crashing Input
```bash
cargo +nightly fuzz tmin <target_name> <artifact_path>
```

### Run with Specific Corpus
```bash
cargo +nightly fuzz run <target_name> <corpus_dir>
```

### Generate Coverage Report
```bash
cargo +nightly fuzz coverage <target_name>
```

## Interpreting Results

### Success Indicators
- `DONE` message at end
- No crashes or timeouts
- High code coverage (`cov:` metric)
- Large corpus size (`corp:` metric)

### Failure Indicators
- Crashes saved to `fuzz/artifacts/<target_name>/`
- OOM (out-of-memory) errors
- Timeout errors
- ASan/UBSan violations

## Security Findings

The fuzzing harnesses have already identified and helped fix critical issues:

1. **LZ4 Decompression Bomb** - Input `[43, 96, 187, 187]` claimed to decompress to 3+ GB
   - **Fix**: Validate claimed size before attempting decompression
   - **Impact**: Prevented remote OOM DoS attacks

## Integration with CI

To add fuzzing to CI (smoke test mode):

```yaml
- name: Fuzz smoke tests
  run: |
    rustup install nightly
    cargo install cargo-fuzz
    cargo +nightly fuzz build
    cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=30
    cargo +nightly fuzz run fuzz_handshake -- -max_total_time=30
    cargo +nightly fuzz run fuzz_compression -- -max_total_time=30
```

## Best Practices

1. **Run regularly** - Fuzzing should be part of development workflow
2. **Long runs** - Run overnight or longer for deeper coverage
3. **Minimize inputs** - Always minimize crashing inputs before investigating
4. **Update corpus** - Keep successful corpus in version control
5. **CI smoke tests** - Run brief fuzz tests in CI to catch regressions

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Fuzzing strategies](https://rust-fuzz.github.io/book/introduction.html)
