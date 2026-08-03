#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::vless::{UserId, VisionDecoder};

fuzz_target!(|input: &[u8]| {
    let mut decoder = VisionDecoder::new(UserId::new([0x11; 16]));
    let mut output = Vec::new();
    let _ = decoder.decode(input, &mut output);
});
