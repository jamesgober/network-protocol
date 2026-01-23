use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use network_protocol::protocol::message::Message;

fn bench_message_bincode(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_bincode");
    let messages = vec![
        Message::Ping,
        Message::Pong,
        Message::Echo("hello world".into()),
        Message::Echo("a".repeat(1024)),
    ];

    group.bench_function("serialize", |b| {
        b.iter_batched(
            || messages.clone(),
            |msgs| {
                for m in msgs {
                    let _ = bincode::serialize(&m).unwrap();
                }
            },
            BatchSize::SmallInput,
        )
    });

    let blob = bincode::serialize(&Message::Echo("a".repeat(1024))).unwrap();
    group.bench_function("deserialize", |b| {
        b.iter(|| {
            let _: Message = bincode::deserialize(&blob).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_message_bincode);
criterion_main!(benches);
