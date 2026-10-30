#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    rust_reality::crypto::fuzz_p256_agreement(input);
});
