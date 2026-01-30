//! Example: Using Alternative Serialization Formats
//!
//! This example demonstrates how to use different serialization formats
//! (Bincode, JSON, MessagePack) with the network protocol library.
//!
//! Run with: `cargo run --example serialization_formats`

#![allow(clippy::uninlined_format_args)]

use network_protocol::core::serialization::{MultiFormat, SerializationFormat};
use network_protocol::protocol::message::Message;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Alternative Serialization Formats Demo ===\n");

    // Create a sample message
    let message = Message::Custom {
        command: "example_command".to_string(),
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
    };

    println!("Original message: {:?}\n", message);

    // 1. Bincode (Default - Fast and Compact)
    println!("1. BINCODE (Default)");
    println!("   - Best for: High-performance scenarios");
    println!("   - Characteristics: Fastest, most compact binary format");

    let bincode_bytes = message.serialize_format(SerializationFormat::Bincode)?;
    println!("   - Serialized size: {} bytes", bincode_bytes.len());
    println!(
        "   - Hex: {:02X?}",
        &bincode_bytes[..bincode_bytes.len().min(20)]
    );

    let recovered = Message::deserialize_format(&bincode_bytes, SerializationFormat::Bincode)?;
    println!(
        "   - Roundtrip: {}",
        if message == recovered {
            "✓ Success"
        } else {
            "✗ Failed"
        }
    );
    println!();

    // 2. JSON (Human-Readable)
    println!("2. JSON (Human-Readable)");
    println!("   - Best for: Debugging, interoperability, web APIs");
    println!("   - Characteristics: Text-based, human-readable, larger size");

    let json_bytes = message.serialize_format(SerializationFormat::Json)?;
    println!("   - Serialized size: {} bytes", json_bytes.len());

    let json_str = std::str::from_utf8(&json_bytes)?;
    println!("   - JSON: {}", json_str);

    let recovered = Message::deserialize_format(&json_bytes, SerializationFormat::Json)?;
    println!(
        "   - Roundtrip: {}",
        if message == recovered {
            "✓ Success"
        } else {
            "✗ Failed"
        }
    );
    println!();

    // 3. MessagePack (Compact Binary)
    println!("3. MESSAGEPACK (Compact Binary)");
    println!("   - Best for: Bandwidth-constrained scenarios, cross-language interop");
    println!("   - Characteristics: Compact binary, good compression, widely supported");

    let msgpack_bytes = message.serialize_format(SerializationFormat::MessagePack)?;
    println!("   - Serialized size: {} bytes", msgpack_bytes.len());
    println!(
        "   - Hex: {:02X?}",
        &msgpack_bytes[..msgpack_bytes.len().min(20)]
    );

    let recovered = Message::deserialize_format(&msgpack_bytes, SerializationFormat::MessagePack)?;
    println!(
        "   - Roundtrip: {}",
        if message == recovered {
            "✓ Success"
        } else {
            "✗ Failed"
        }
    );
    println!();

    // 4. Using Format Headers (Auto-Detection)
    println!("4. AUTO-DETECTION with Format Headers");
    println!("   - Automatic format detection from header byte");

    for format in &[
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::MessagePack,
    ] {
        let with_header = message.serialize_with_header(*format)?;
        let (recovered, detected_format) = Message::deserialize_with_header(&with_header)?;

        println!(
            "   - Format: {:10} | Header byte: 0x{:02X} | Detected: {} | Size: {} bytes",
            format.name(),
            format.format_byte(),
            detected_format.name(),
            with_header.len()
        );

        assert_eq!(message, recovered);
        assert_eq!(*format, detected_format);
    }
    println!();

    // 5. Size Comparison
    println!("5. SIZE COMPARISON");
    println!("   Serializing the same message with different formats:");
    println!("   - Bincode:     {} bytes (baseline)", bincode_bytes.len());
    println!(
        "   - MessagePack: {} bytes ({:+.1}%)",
        msgpack_bytes.len(),
        ((msgpack_bytes.len() as f64 / bincode_bytes.len() as f64) - 1.0) * 100.0
    );
    println!(
        "   - JSON:        {} bytes ({:+.1}%)",
        json_bytes.len(),
        ((json_bytes.len() as f64 / bincode_bytes.len() as f64) - 1.0) * 100.0
    );
    println!();

    // 6. Handshake Messages Example
    println!("6. HANDSHAKE MESSAGES (All Formats)");
    let handshake = Message::SecureHandshakeInit {
        pub_key: [0x42; 32],
        timestamp: 1234567890,
        nonce: [0xAB; 16],
    };

    for format in &[
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::MessagePack,
    ] {
        let bytes = handshake.serialize_format(*format)?;
        let recovered = Message::deserialize_format(&bytes, *format)?;

        println!(
            "   - {:10}: {} bytes | Roundtrip: {}",
            format.name(),
            bytes.len(),
            if handshake == recovered { "✓" } else { "✗" }
        );
    }
    println!();

    // 7. Recommendations
    println!("7. RECOMMENDATIONS");
    println!("   - Use BINCODE for production (fastest, most efficient)");
    println!("   - Use JSON for debugging and development");
    println!("   - Use MessagePack for cross-language interoperability");
    println!("   - Use format headers when format may vary at runtime");

    Ok(())
}
