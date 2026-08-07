#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::handoff::fuzz_decode_blob;

fuzz_target!(|input: &[u8]| {
    let _ = fuzz_decode_blob(input);
});
