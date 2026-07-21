use rust_reality::protocol::vless::{Address, Command, DecodeError, VERSION, decode_request};

// VLESS request packet, 38 bytes.
#[rustfmt::skip]
const REQUEST_PACKET: &[u8; 38] = &[
    // [0] Version
    0x00,

    // [1..17] User ID: 00010203-0405-0607-0809-0a0b0c0d0e0f
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,

    // [17] Addons length
    0x00,

    // [18] Command: TCP
    0x01,

    // [19..21] Port: 443, big endian
    0x01, 0xbb,

    // [21] Address type: domain
    0x02,

    // [22] Domain length: 11
    0x0b,

    // [23..34] Domain: example.com
    0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d,

    // [34..38] First payload bytes
    0x16, 0x03, 0x01, 0x00,
];

#[test]
fn decodes_fixed_domain_request_vector() {
    let decoded = decode_request(REQUEST_PACKET).expect("fixed request vector should decode");

    let header = decoded.header();

    assert_eq!(header.version(), VERSION);
    assert_eq!(
        header.user_id().as_bytes(),
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]
    );
    assert!(header.addons().is_empty());
    assert_eq!(header.command(), Command::Tcp);

    let destination = header
        .destination()
        .expect("TCP request should have a destination");

    assert_eq!(destination.port(), 443);
    assert_eq!(
        destination.address(),
        &Address::Domain("example.com".to_owned())
    );
    assert_eq!(decoded.payload(), &[0x16, 0x03, 0x01, 0x00]);
}

#[test]
fn reports_incomplete_fixed_vector() {
    let incomplete = &REQUEST_PACKET[..20];

    assert_eq!(
        decode_request(incomplete),
        Err(DecodeError::UnexpectedEnd {
            field: "destination port",
            needed: 2,
            remaining: 1
        })
    );
}
