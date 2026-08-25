#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::{
    nxr::{NxrKey, decode_authenticated_request, request_len_from_header},
    reality::ClientHello,
    vless::{decode_request, fuzz_decode_request_ref},
};

fuzz_target!(|input: &[u8]| {
    let _ = decode_request(input);
    fuzz_decode_request_ref(input);
    if let Ok(hello) = ClientHello::parse_message(input) {
        let _ = hello.normalized_profile_class();
    }
    let _ = ClientHello::parse_record(input);
    let _ = request_len_from_header(input);
    let key = NxrKey::new([0x33; 32]);
    let _ = decode_authenticated_request(input, &key, 1_785_761_600, 30);
});
