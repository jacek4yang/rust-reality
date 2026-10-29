#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    let _ = rr_fingerprint::decode(input);
    let _ = rr_fingerprint::compare::compare(input, input, true);
    let _ = rr_fingerprint::compare::compare(input, input, false);
    let _ = rr_fingerprint::first_client_hello(input);
});
