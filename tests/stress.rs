use bytes::BytesMut;
use network_protocol::{config::PROTOCOL_VERSION, core::codec::PacketCodec, core::packet::Packet};
use tokio_util::codec::Encoder;

#[test]
fn stress_packet_encode_decode_large_series() {
    // Simulate heavy burst of packets, ensure no panics and minimal overhead
    let mut codec = PacketCodec;
    let mut buf = BytesMut::new();

    for size in [0usize, 1, 64, 512, 4096, 65536, 1_048_576] {
        for _ in 0..10_000 {
            let p = Packet {
                version: PROTOCOL_VERSION,
                payload: vec![0u8; size],
            };
            codec.encode(p, &mut buf).unwrap();
            let decoded = Packet::from_bytes(&buf);
            assert!(decoded.is_ok());
            buf.clear();
        }
    }
}
