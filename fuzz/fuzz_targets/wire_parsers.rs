#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::{
    nxr::{NxrKey, decode_authenticated_request, request_len_from_header},
    reality::ClientHello,
    vless::{
        Command, decode_request, decode_response, encode_vision_tcp_request,
        fuzz_decode_request_ref,
    },
};

fuzz_target!(|input: &[u8]| {
    if let Ok(decoded) = decode_request(input) {
        if decoded.header().command() == Command::Tcp {
            if let Some(destination) = decoded.header().destination() {
                let mut output = [0_u8; 533];
                if let Ok(n) =
                    encode_vision_tcp_request(decoded.header().user_id(), destination, &mut output)
                {
                    let round_trip = decode_request(&output[..n]).expect("encoded request");
                    assert_eq!(round_trip.header().destination(), Some(destination));
                    assert_eq!(round_trip.header().user_id(), decoded.header().user_id());
                    assert!(round_trip.payload().is_empty());
                }
            }
        }
    }
    if let Ok(decoded) = decode_response(input) {
        let header_len = 2 + usize::from(input[1]);
        assert_eq!(decoded.payload(), &input[header_len..]);
    }
    fuzz_decode_request_ref(input);
    if let Ok(hello) = ClientHello::parse_message(input) {
        let _ = hello.normalized_profile_class();
    }
    let _ = ClientHello::parse_record(input);
    let _ = request_len_from_header(input);
    let key = NxrKey::new([0x33; 32]);
    let _ = decode_authenticated_request(input, &key, 1_785_761_600, 30);
});
