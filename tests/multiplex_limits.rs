//! The multiplexer's frame size limit: a peer-declared length is checked
//! before any memory is reserved for it.
//!
//! This binary's allocator refuses any single allocation over 1 GiB, so a
//! regression (allocating the declared length up front) aborts the test
//! process instead of depending on how much memory the host can commit.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use network_protocol::service::multiplex::{MultiplexConfig, Multiplexer};
use network_protocol::{ProtocolError, MAX_PAYLOAD_SIZE};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Capped;

const CAP: usize = 1 << 30;

// SAFETY: forwards to the system allocator, refusing (null) any request over
// `CAP`, which `GlobalAlloc` permits.
unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > CAP {
            return std::ptr::null_mut();
        }
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.size() > CAP {
            return std::ptr::null_mut();
        }
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Capped = Capped;

fn config() -> MultiplexConfig {
    MultiplexConfig {
        request_timeout: Duration::from_millis(500),
        ..MultiplexConfig::default()
    }
}

#[tokio::test]
async fn test_declared_4_gib_frame_is_refused_without_allocating() {
    let (ours, mut peer) = tokio::io::duplex(1024);
    let (reader, writer) = tokio::io::split(ours);
    let mux = Multiplexer::new(reader, writer, config());
    assert_eq!(mux.max_frame_size(), MAX_PAYLOAD_SIZE);

    // Request id 1, declared payload length 0xFFFF_FFFF, no payload: 12 bytes.
    peer.write_all(&[0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF])
        .await
        .unwrap();

    // The receive loop refuses the frame and stops reading.
    let metrics = mux.metrics();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while metrics.errors.load(Ordering::Relaxed) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the frame was not refused"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_frame_over_a_configured_limit_is_refused() {
    let (ours, mut peer) = tokio::io::duplex(1024);
    let (reader, writer) = tokio::io::split(ours);
    let mux = Multiplexer::new_with_max_frame_size(reader, writer, config(), 16);
    assert_eq!(mux.max_frame_size(), 16);

    // A frame of exactly the limit is delivered.
    let request = tokio::spawn(async move {
        let reply = mux.request(b"ping".to_vec()).await;
        (mux, reply)
    });
    let mut header = [0u8; 12];
    peer.read_exact(&mut header).await.unwrap();
    let id = u64::from_be_bytes(header[..8].try_into().unwrap());
    let mut body = [0u8; 4];
    peer.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ping");
    let mut frame = id.to_be_bytes().to_vec();
    frame.extend_from_slice(&16u32.to_be_bytes());
    frame.extend_from_slice(&[7u8; 16]);
    peer.write_all(&frame).await.unwrap();
    let (mux, reply) = request.await.unwrap();
    assert_eq!(reply.unwrap(), vec![7u8; 16]);

    // One byte over is refused, and the loop stops.
    let mut frame = 2u64.to_be_bytes().to_vec();
    frame.extend_from_slice(&17u32.to_be_bytes());
    peer.write_all(&frame).await.unwrap();
    let metrics = mux.metrics();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while metrics.errors.load(Ordering::Relaxed) == 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_outgoing_payload_over_the_limit_is_not_sent() {
    let (ours, _peer) = tokio::io::duplex(1024);
    let (reader, writer) = tokio::io::split(ours);
    let mux = Multiplexer::new_with_max_frame_size(reader, writer, config(), 8);
    let result = mux.request(vec![0u8; 9]).await;
    assert!(
        matches!(result, Err(ProtocolError::OversizedPacket(9))),
        "expected OversizedPacket(9), got {result:?}"
    );
    assert_eq!(mux.metrics().requests_sent.load(Ordering::Relaxed), 0);
}
