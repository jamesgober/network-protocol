#![no_main]

use libfuzzer_sys::fuzz_target;
use network_protocol::utils::compression::{compress, decompress, CompressionKind};

fuzz_target!(|data: &[u8]| {
    // Fuzz LZ4 compression/decompression with various input sizes
    if let Ok(compressed) = compress(data, &CompressionKind::Lz4) {
        // Test decompression doesn't panic and respects size limits
        let _ = decompress(&compressed, &CompressionKind::Lz4);
    }
    
    // Fuzz Zstd compression/decompression
    if let Ok(compressed) = compress(data, &CompressionKind::Zstd) {
        let _ = decompress(&compressed, &CompressionKind::Zstd);
    }
    
    // Fuzz raw decompression (test size limits with malformed data)
    let _ = decompress(data, &CompressionKind::Lz4);
    let _ = decompress(data, &CompressionKind::Zstd);
});
