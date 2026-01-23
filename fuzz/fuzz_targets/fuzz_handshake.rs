#![no_main]

use libfuzzer_sys::fuzz_target;
use network_protocol::protocol::message::Message;

fuzz_target!(|data: &[u8]| {
    // Fuzz message deserialization
    if data.len() < 4 {
        return;
    }
    
    if let Ok(msg) = bincode::deserialize::<Message>(data) {
        // If deserialization succeeds, test serialization roundtrip
        if let Ok(serialized) = bincode::serialize(&msg) {
            let _ = bincode::deserialize::<Message>(&serialized);
        }
    }
});
