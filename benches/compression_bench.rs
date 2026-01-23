#![allow(clippy::unwrap_used, clippy::uninlined_format_args)]

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use network_protocol::utils::compression::{compress, decompress, CompressionKind};

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");
    let sizes = [64usize, 512, 4096, 65536, 1024 * 1024];

    for &size in &sizes {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("lz4_compress_{}b", size), |b| {
            b.iter_batched(
                || data.clone(),
                |d| {
                    let _ = compress(&d, &CompressionKind::Lz4).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("lz4_decompress_{}b", size), |b| {
            let compressed = compress(&data, &CompressionKind::Lz4).unwrap();
            b.iter(|| {
                let out = decompress(&compressed, &CompressionKind::Lz4).unwrap();
                assert_eq!(out.len(), data.len());
            })
        });

        group.bench_function(format!("zstd_compress_{}b", size), |b| {
            b.iter_batched(
                || data.clone(),
                |d| {
                    let _ = compress(&d, &CompressionKind::Zstd).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("zstd_decompress_{}b", size), |b| {
            let compressed = compress(&data, &CompressionKind::Zstd).unwrap();
            b.iter(|| {
                let out = decompress(&compressed, &CompressionKind::Zstd).unwrap();
                assert_eq!(out.len(), data.len());
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_compression);
criterion_main!(benches);
