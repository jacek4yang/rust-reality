#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::{
    nxr::NxrKey,
    nxr_udp::{
        DIR_LINE_TO_LANDING, FRAME_TYPE_DATAGRAM, NXR_UDP_MAX_PAYLOAD, NxrUdpSessionKey,
        decode_frame, encode_frame, fuzz_decode_frame,
    },
    vless::{Address, Destination},
};

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_frame(data);
    let mode = data.first().copied().unwrap_or(0);
    let address = match mode % 4 {
        0 => Address::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, mode)),
        1 => Address::Ipv6(std::net::Ipv6Addr::from([mode; 16])),
        _ => Address::Domain(String::from_utf8_lossy(&data[..data.len().min(254)]).into_owned()),
    };
    let destination = Destination::new(address, u16::from(mode));
    let destination = (mode & 4 != 0).then_some(&destination);
    let payload = &data[..data.len().min(NXR_UDP_MAX_PAYLOAD + 1)];
    let session = NxrUdpSessionKey::derive(&NxrKey::new([0x33; 32]), b"fuzz-frame-writer");
    let mut output = vec![0xa5; 16];
    if encode_frame(
        &session,
        DIR_LINE_TO_LANDING,
        FRAME_TYPE_DATAGRAM,
        42,
        destination,
        payload,
        &mut output,
    )
    .is_ok()
    {
        let (frame, consumed) = decode_frame(&output, &session, DIR_LINE_TO_LANDING).unwrap();
        assert_eq!(consumed, output.len());
        assert_eq!(frame.destination.as_ref(), destination);
        assert_eq!(frame.payload, payload);
        assert_eq!(frame.seq, 42);
        *output.last_mut().unwrap() ^= 1;
        assert!(decode_frame(&output, &session, DIR_LINE_TO_LANDING).is_err());
    } else {
        assert_eq!(output, [0xa5; 16]);
    }
});
