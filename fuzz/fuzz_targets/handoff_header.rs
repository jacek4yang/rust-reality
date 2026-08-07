#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::handoff::message_len_from_header;

fuzz_target!(|input: &[u8]| {
    let _ = message_len_from_header(input);
});
