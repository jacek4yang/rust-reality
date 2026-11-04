use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    ConnectRequest, DecodeError, EncodeError, MAX_CONNECT_REQUEST_LEN, MethodResponse, VERSION,
    decode_connect_request, decode_method_request, decode_udp_associate_request,
    decode_udp_datagram, encode_command_reply, encode_connect_request, encode_method_response,
    encode_udp_associate_request, encode_udp_datagram,
};
use crate::protocol::vless::{Address, Destination};

#[test]
fn decodes_no_auth_method_offer_with_coalesced_bytes() {
    let input = [VERSION, 3, 2, 0, 1, 0xaa, 0xbb];
    let decoded = decode_method_request(&input).expect("no-auth offer should parse");

    assert_eq!(decoded.methods(), &[2, 0, 1]);
    assert_eq!(decoded.consumed(), 5);
    assert_eq!(decoded.trailing(), &[0xaa, 0xbb]);
    assert_eq!(&input[..decoded.consumed()], &[VERSION, 3, 2, 0, 1]);
}

#[test]
fn distinguishes_every_truncated_method_prefix_from_invalid_input() {
    let complete = [VERSION, 2, 2, 0];
    for end in 0..complete.len() {
        assert!(
            matches!(
                decode_method_request(&complete[..end]),
                Err(DecodeError::IncompleteInput { .. })
            ),
            "prefix length {end} must be incomplete"
        );
    }
    assert!(decode_method_request(&complete).is_ok());
    assert_eq!(
        decode_method_request(&[4, 1, 0]),
        Err(DecodeError::InvalidVersion(4))
    );
    assert_eq!(
        decode_method_request(&[VERSION, 0]),
        Err(DecodeError::InvalidMethodCount)
    );
    assert_eq!(
        decode_method_request(&[VERSION, 1, 2]),
        Err(DecodeError::UnsupportedMethod)
    );
}

#[test]
fn accepts_the_rfc_maximum_method_count() {
    let mut input = vec![VERSION, u8::MAX];
    input.resize(2 + usize::from(u8::MAX), 0x02);
    input[2 + usize::from(u8::MAX) - 1] = 0;

    let decoded = decode_method_request(&input).expect("255 offered methods are valid");
    assert_eq!(decoded.methods().len(), usize::from(u8::MAX));
    assert_eq!(decoded.consumed(), input.len());
    assert!(decoded.trailing().is_empty());
}

#[test]
fn encodes_both_method_selection_values() {
    let mut output = [0xa5; 4];
    assert_eq!(
        encode_method_response(MethodResponse::NoAuthentication, &mut output),
        Ok(2)
    );
    assert_eq!(&output[..2], &[VERSION, 0]);
    assert_eq!(&output[2..], &[0xa5; 2]);
    assert_eq!(
        encode_method_response(MethodResponse::NoAcceptableMethods, &mut output),
        Ok(2)
    );
    assert_eq!(&output[..2], &[VERSION, 0xff]);
    assert_eq!(&output[2..], &[0xa5; 2]);
}

#[test]
fn method_response_bounds_fail_at_every_short_length_without_mutation() {
    for available in 0..2 {
        let mut output = [0xa5; 2];
        assert_eq!(
            encode_method_response(MethodResponse::NoAuthentication, &mut output[..available]),
            Err(EncodeError::OutputTooSmall {
                required: 2,
                available,
            })
        );
        assert_eq!(output, [0xa5; 2]);
    }
}

#[test]
fn round_trips_ipv4_ipv6_and_domain_connect_requests() {
    let destinations = [
        Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 19)), 443),
        Destination::new(
            Address::Ipv6("2001:db8::19".parse().expect("IPv6 literal")),
            65535,
        ),
        Destination::new(Address::Domain("example.com".to_owned()), 1),
    ];

    for destination in destinations {
        let mut output = [0xa5; MAX_CONNECT_REQUEST_LEN];
        let written = encode_connect_request(&destination, &mut output)
            .expect("canonical destination should encode");
        assert!(output[written..].iter().all(|&byte| byte == 0xa5));
        let decoded = decode_connect_request(&output[..written])
            .expect("encoded CONNECT request should decode");
        assert_eq!(decoded.destination(), &destination);
        assert_eq!(decoded.consumed(), written);
        assert!(decoded.payload().is_empty());
    }
}

#[test]
fn connect_parser_preserves_coalesced_payload_and_consumed_length() {
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 8443);
    let mut input = [0_u8; MAX_CONNECT_REQUEST_LEN];
    let written = encode_connect_request(&destination, &mut input).expect("encode request");
    let mut coalesced = input[..written].to_vec();
    coalesced.extend_from_slice(b"first application payload");

    let decoded = decode_connect_request(&coalesced).expect("coalesced request should parse");
    assert_eq!(decoded.destination(), &destination);
    assert_eq!(decoded.consumed(), written);
    assert_eq!(decoded.payload(), b"first application payload");
    assert_eq!(&coalesced[..decoded.consumed()], &input[..written]);
}

#[test]
fn every_truncated_prefix_of_each_address_form_is_incomplete() {
    let requests = [
        encode(&Destination::new(
            Address::Ipv4(Ipv4Addr::new(203, 0, 113, 5)),
            1080,
        )),
        encode(&Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 1080)),
        encode(&Destination::new(
            Address::Domain("edge.example".to_owned()),
            1080,
        )),
    ];

    for request in requests {
        for end in 0..request.len() {
            assert!(
                matches!(
                    decode_connect_request(&request[..end]),
                    Err(DecodeError::IncompleteInput { .. })
                ),
                "prefix length {end} of {} must be incomplete",
                request.len()
            );
        }
        assert!(decode_connect_request(&request).is_ok());
    }
}

#[test]
fn fragmented_connect_bytes_become_complete_only_after_the_last_fragment() {
    let complete = encode(&Destination::new(
        Address::Domain("fragments.example".to_owned()),
        8443,
    ));
    let mut accumulated = Vec::new();

    for (index, byte) in complete.iter().copied().enumerate() {
        accumulated.push(byte);
        if index + 1 < complete.len() {
            assert!(matches!(
                decode_connect_request(&accumulated),
                Err(DecodeError::IncompleteInput { .. })
            ));
        }
    }
    assert!(decode_connect_request(&accumulated).is_ok());
}

#[test]
fn rejects_invalid_version_reserved_command_and_address_type() {
    assert_eq!(
        decode_connect_request(&[4, 1, 0, 1]),
        Err(DecodeError::InvalidVersion(4))
    );
    assert_eq!(
        decode_connect_request(&[VERSION, 1, 1, 1]),
        Err(DecodeError::InvalidReservedField(1))
    );
    assert_eq!(
        decode_connect_request(&[VERSION, 2, 0, 1]),
        Err(DecodeError::UnsupportedCommand(2))
    );
    assert_eq!(
        decode_connect_request(&[VERSION, 3, 0, 1]),
        Err(DecodeError::UnsupportedCommand(3))
    );
    assert_eq!(
        decode_connect_request(&[VERSION, 1, 0, 1, 127, 0, 0, 1, 0, 0]),
        Err(DecodeError::ZeroPort)
    );
    assert_eq!(
        decode_connect_request(&[VERSION, 1, 0, 2]),
        Err(DecodeError::UnsupportedAddressType(2))
    );
}

#[test]
fn validates_domain_length_and_canonical_domain_grammar() {
    assert_eq!(
        decode_connect_request(&[VERSION, 1, 0, 3, 0]),
        Err(DecodeError::EmptyDomain)
    );
    assert_eq!(
        decode_connect_request(&[VERSION, 1, 0, 3, 1, b'/', 0, 80]),
        Err(DecodeError::InvalidDomainName)
    );

    let max_domain = "x".repeat(usize::from(u8::MAX));
    let destination = Destination::new(Address::Domain(max_domain), u16::MAX);
    let bytes = encode(&destination);
    assert_eq!(bytes.len(), MAX_CONNECT_REQUEST_LEN);
    assert_eq!(bytes[4], u8::MAX);
    assert_eq!(
        decode_connect_request(&bytes)
            .expect("255-byte domain is valid")
            .destination(),
        &destination
    );
}

#[test]
fn connect_request_output_bounds_and_invalid_domain_do_not_mutate_output() {
    let destination = Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
    let mut too_short = [0xa5; 21];
    assert_eq!(
        encode_connect_request(&destination, &mut too_short),
        Err(EncodeError::OutputTooSmall {
            required: 22,
            available: 21,
        })
    );
    assert_eq!(too_short, [0xa5; 21]);

    let invalid_domain = Destination::new(Address::Domain(String::new()), 80);
    let mut output = [0xa5; MAX_CONNECT_REQUEST_LEN];
    assert_eq!(
        encode_connect_request(&invalid_domain, &mut output),
        Err(EncodeError::InvalidDomainName)
    );
    assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);

    for invalid_domain in [
        Destination::new(Address::Domain("bad/name".to_owned()), 80),
        Destination::new(Address::Domain("x".repeat(usize::from(u8::MAX) + 1)), 80),
    ] {
        assert_eq!(
            encode_connect_request(&invalid_domain, &mut output),
            Err(EncodeError::InvalidDomainName)
        );
        assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);
    }

    let zero_port = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 0);
    assert_eq!(
        encode_connect_request(&zero_port, &mut output),
        Err(EncodeError::ZeroPort)
    );
    assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);
}

#[test]
fn connect_output_bounds_cover_every_destination_encoding() {
    let destinations = [
        Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80),
        Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 80),
        Destination::new(Address::Domain("x".to_owned()), 80),
        Destination::new(Address::Domain("x".repeat(usize::from(u8::MAX))), 80),
    ];

    for destination in destinations {
        let required = encode(&destination).len();
        for available in 0..required {
            let mut output = [0xa5; MAX_CONNECT_REQUEST_LEN];
            assert_eq!(
                encode_connect_request(&destination, &mut output[..available]),
                Err(EncodeError::OutputTooSmall {
                    required,
                    available,
                })
            );
            assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);
        }
        let mut exact = [0xa5; MAX_CONNECT_REQUEST_LEN];
        assert_eq!(
            encode_connect_request(&destination, &mut exact[..required]),
            Ok(required)
        );
    }
}

#[test]
fn decoder_result_retains_only_borrowed_payload_after_owned_destination() {
    let input = [VERSION, 1, 0, 1, 127, 0, 0, 1, 0, 80, 0xde, 0xad];
    let decoded: ConnectRequest<'_> = decode_connect_request(&input).expect("request");
    let (destination, payload) = decoded.into_parts();
    assert_eq!(
        destination,
        Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80)
    );
    assert_eq!(payload, &[0xde, 0xad]);
}

#[test]
fn udp_associate_round_trips_unspecified_ipv4() {
    let dest = Destination::new(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 0);
    let mut buf = [0_u8; MAX_CONNECT_REQUEST_LEN];
    let n = encode_udp_associate_request(&dest, &mut buf).expect("encode");
    let decoded = decode_udp_associate_request(&buf[..n]).expect("decode");
    assert_eq!(decoded.destination(), &dest);
    assert_eq!(decoded.consumed(), n);
}

#[test]
fn udp_datagram_round_trips_payload() {
    let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
    let mut out = Vec::new();
    encode_udp_datagram(&dest, b"hello", &mut out).expect("encode");
    let decoded = decode_udp_datagram(&out).expect("decode");
    assert_eq!(decoded.destination(), &dest);
    assert_eq!(decoded.payload(), b"hello");
}

#[test]
fn udp_datagram_rejects_fragment() {
    let mut wire = vec![0, 0, 1, 1, 127, 0, 0, 1, 0, 53, b'x'];
    assert_eq!(
        decode_udp_datagram(&wire),
        Err(DecodeError::FragmentedUdp(1))
    );
    wire[2] = 0;
    assert!(decode_udp_datagram(&wire).is_ok());
}

#[test]
fn encode_command_reply_ipv4_shape() {
    let bound: std::net::SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut out = [0_u8; 22];
    let n = encode_command_reply(0, &bound, &mut out).unwrap();
    assert_eq!(n, 10);
    assert_eq!(&out[..10], &[5, 0, 0, 1, 127, 0, 0, 1, 4, 56]);
}

fn encode(destination: &Destination) -> Vec<u8> {
    let mut output = [0_u8; MAX_CONNECT_REQUEST_LEN];
    let written = encode_connect_request(destination, &mut output).expect("encode destination");
    output[..written].to_vec()
}
