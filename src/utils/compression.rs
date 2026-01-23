use crate::config::MAX_PAYLOAD_SIZE;
use crate::error::{ProtocolError, Result};

#[derive(Copy, Clone)]
pub enum CompressionKind {
    Lz4,
    Zstd,
}

/// Maximum output size for decompression (align with MAX_PAYLOAD_SIZE to prevent DoS)
const MAX_DECOMPRESSION_SIZE: usize = MAX_PAYLOAD_SIZE;

/// Compresses data using the specified compression algorithm
///
/// # Errors
/// Returns `ProtocolError::CompressionFailure` if compression fails
pub fn compress(data: &[u8], kind: &CompressionKind) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
        CompressionKind::Zstd => {
            let mut out = Vec::new();
            zstd::stream::copy_encode(data, &mut out, 1)
                .map_err(|_| ProtocolError::CompressionFailure)?;
            Ok(out)
        }
    }
}

/// Decompresses data that was compressed with the specified algorithm
///
/// Enforces a maximum output size limit to prevent decompression bombs (DoS attacks).
/// The limit is set to MAX_PAYLOAD_SIZE to align with protocol packet limits.
///
/// # Errors
/// Returns `ProtocolError::DecompressionFailure` if:
/// - Decompression fails
/// - Output size exceeds MAX_DECOMPRESSION_SIZE
pub fn decompress(data: &[u8], kind: &CompressionKind) -> Result<Vec<u8>> {
    match *kind {
        CompressionKind::Lz4 => {
            // CRITICAL SECURITY: Validate claimed size before attempting decompression
            // LZ4 prepends the size as a variable-length integer (varint)
            // We need to check this before lz4_flex attempts allocation
            if data.len() < 4 {
                return Err(ProtocolError::DecompressionFailure);
            }

            // Read the prepended uncompressed size (lz4_flex uses 4-byte little-endian)
            let claimed_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

            // Reject if claimed size exceeds our limit BEFORE attempting decompression
            if claimed_size > MAX_DECOMPRESSION_SIZE {
                return Err(ProtocolError::DecompressionFailure);
            }

            let decompressed = lz4_flex::decompress_size_prepended(data)
                .map_err(|_| ProtocolError::DecompressionFailure)?;

            // Double-check the actual output size (defense in depth)
            if decompressed.len() > MAX_DECOMPRESSION_SIZE {
                return Err(ProtocolError::DecompressionFailure);
            }
            Ok(decompressed)
        }
        CompressionKind::Zstd => {
            let mut out = Vec::new();
            // Use Zstd with size limit
            let mut reader = zstd::stream::Decoder::new(data)
                .map_err(|_| ProtocolError::DecompressionFailure)?;

            // Read in chunks to enforce size limit
            use std::io::Read;
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        out.extend_from_slice(&buffer[..n]);
                        // Check size limit on each chunk
                        if out.len() > MAX_DECOMPRESSION_SIZE {
                            return Err(ProtocolError::DecompressionFailure);
                        }
                    }
                    Err(_) => return Err(ProtocolError::DecompressionFailure),
                }
            }
            Ok(out)
        }
    }
}

/// Compress data if it meets the configured threshold, otherwise return it unchanged.
/// Returns the output bytes and a flag indicating whether compression was applied.
pub fn maybe_compress(
    data: &[u8],
    kind: &CompressionKind,
    threshold_bytes: usize,
) -> Result<(Vec<u8>, bool)> {
    if data.len() < threshold_bytes {
        Ok((data.to_vec(), false))
    } else {
        Ok((compress(data, kind)?, true))
    }
}

/// Decompress data only if it was previously compressed; otherwise return as-is.
pub fn maybe_decompress(
    data: &[u8],
    kind: &CompressionKind,
    was_compressed: bool,
) -> Result<Vec<u8>> {
    if was_compressed {
        decompress(data, kind)
    } else {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_lz4_compression_roundtrip() {
        let original = b"Hello, World! This is a test of LZ4 compression.";
        let compressed = compress(original, &CompressionKind::Lz4).unwrap();
        let decompressed = decompress(&compressed, &CompressionKind::Lz4).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_zstd_compression_roundtrip() {
        let original = b"Hello, World! This is a test of Zstd compression.";
        let compressed = compress(original, &CompressionKind::Zstd).unwrap();
        let decompressed = decompress(&compressed, &CompressionKind::Zstd).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_lz4_oom_attack_prevention() {
        // This is the actual payload that caused OOM before the fix
        // It claims to decompress to 3+ GB (0xbbbb60ab = 3149676715 bytes)
        let malicious_payload = vec![0x2b, 0x60, 0xbb, 0xbb];

        // Should reject due to claimed size exceeding MAX_DECOMPRESSION_SIZE
        let result = decompress(&malicious_payload, &CompressionKind::Lz4);
        assert!(
            result.is_err(),
            "Should reject malicious payload claiming huge output size"
        );
    }

    #[test]
    fn test_lz4_size_limit_enforcement() {
        // Create a payload that claims to be larger than MAX_DECOMPRESSION_SIZE
        let claimed_size = (MAX_DECOMPRESSION_SIZE + 1) as u32;
        let mut malicious = claimed_size.to_le_bytes().to_vec();
        malicious.extend_from_slice(&[0u8; 16]); // Add some compressed data

        let result = decompress(&malicious, &CompressionKind::Lz4);
        assert!(
            result.is_err(),
            "Should reject payload claiming size > MAX_DECOMPRESSION_SIZE"
        );
    }

    #[test]
    fn test_lz4_short_input_rejection() {
        // Input too short to contain valid size header
        let short_input = vec![0x2b, 0x60];
        let result = decompress(&short_input, &CompressionKind::Lz4);
        assert!(result.is_err(), "Should reject input shorter than 4 bytes");
    }

    #[test]
    fn test_malformed_compressed_data() {
        // Valid size claim but malformed compressed data
        let malformed = vec![0x10, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff];
        let result = decompress(&malformed, &CompressionKind::Lz4);
        assert!(result.is_err(), "Should reject malformed compressed data");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_maybe_compress_below_threshold() {
        let data = b"tiny";
        let (out, compressed) = maybe_compress(data, &CompressionKind::Lz4, 512).unwrap();
        assert!(!compressed);
        assert_eq!(out, data);
        let roundtrip = maybe_decompress(&out, &CompressionKind::Lz4, compressed).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_maybe_compress_above_threshold() {
        let data = vec![1u8; 1024];
        let (out, compressed) = maybe_compress(&data, &CompressionKind::Lz4, 512).unwrap();
        assert!(compressed);
        let roundtrip = maybe_decompress(&out, &CompressionKind::Lz4, compressed).unwrap();
        assert_eq!(roundtrip, data);
    }
}
