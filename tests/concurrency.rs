use bytes::BytesMut;
use network_protocol::{config::PROTOCOL_VERSION, core::codec::PacketCodec, core::packet::Packet};
use tokio_util::codec::Encoder;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_encode_decode_heavy() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let iterations = 50_000usize;
    let payload_sizes = [0usize, 64, 512, 4096, 65536];
    let codec = Arc::new(());

    let mut tasks = JoinSet::new();
    for &size in &payload_sizes {
        let _codec = codec.clone();
        tasks.spawn(async move {
            let mut buf = BytesMut::new();
            for i in 0..iterations {
                let payload = vec![((i + size) & 0xFF) as u8; size];
                let p = Packet {
                    version: PROTOCOL_VERSION,
                    payload,
                };
                let mut c = PacketCodec;
                c.encode(p, &mut buf).unwrap();
                let decoded = Packet::from_bytes(&buf);
                assert!(decoded.is_ok());
                buf.clear();
            }
        });
    }

    while let Some(res) = tasks.join_next().await {
        res.unwrap();
    }
}
