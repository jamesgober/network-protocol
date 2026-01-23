#![no_main]

use libfuzzer_sys::fuzz_target;
use network_protocol::Packet;

fuzz_target!(|data: &[u8]| {
    // Fuzz packet deserialization - test for panics, crashes, infinite loops
    let _ = Packet::from_bytes(data);
});
