#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::reality::tls13::{fuzz_cover_flight, fuzz_cover_profile_extensions};

fuzz_target!(|input: &[u8]| {
    fuzz_cover_flight(input);
    fuzz_cover_profile_extensions(input);
});
