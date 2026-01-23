use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use network_protocol::{config::PROTOCOL_VERSION, core::codec::PacketCodec, core::packet::Packet};
use tokio_util::codec::Encoder;

#[allow(clippy::unwrap_used)]
fn bench_packet_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_encode_decode");
    let payload_sizes = [64usize, 512, 4096, 65536, 1024 * 1024];

    for &size in &payload_sizes {
        let payload = vec![0u8; size];
        let _pkt = Packet {
            version: PROTOCOL_VERSION,
            payload: payload.clone(),
        };
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encode_{size}b"), |b| {
            b.iter_batched(
                || vec![0u8; size],
                |payload| {
                    let p = Packet {
                        version: PROTOCOL_VERSION,
                        payload,
                    };
                    let mut buf = BytesMut::with_capacity(size + 32);
                    let mut codec = PacketCodec;
                    codec.encode(p, &mut buf).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("decode_{size}b"), |b| {
            let mut buf = BytesMut::new();
            let mut codec = PacketCodec;
            codec
                .encode(
                    Packet {
                        version: PROTOCOL_VERSION,
                        payload: payload.clone(),
                    },
                    &mut buf,
                )
                .unwrap();
            b.iter(|| {
                let decoded = Packet::from_bytes(&buf);
                assert!(decoded.is_ok());
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_packet_encode_decode);
criterion_main!(benches);
