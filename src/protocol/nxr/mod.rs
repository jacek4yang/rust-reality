//! Native eXpress Relay (NXR) request framing and authentication.
//!
//! This module owns the on-wire open request: header layout, AEAD seal/open,
//! and the authenticated destination decode used by LANDING. TCP and UDP
//! sessions reuse the same request shape; higher layers in `server::nxr`
//! decide how the resulting association is served.

mod error;
mod keys;
mod layout;
mod wire;

pub use error::NxrProtocolError;
pub use keys::NxrKey;
pub use layout::{
    FLAG_TCP, FLAG_UDP, FLAGS_OFFSET, MAX_REQUEST_LEN, REQUEST_HEADER_LEN, peek_open_flags,
};
pub use wire::{
    AuthenticatedRequest, decode_authenticated_request, encode_request, request_len_from_header,
};

#[cfg(test)]
mod tests {
    use std::{hint::black_box, net::Ipv4Addr, net::Ipv6Addr};

    use super::{
        MAX_REQUEST_LEN, NxrKey, NxrProtocolError, REQUEST_HEADER_LEN,
        decode_authenticated_request, encode_request, request_len_from_header,
    };
    use crate::protocol::vless::{Address, Destination};

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn repeated_encode_reuses_reserved_output_without_allocating() {
        let key = NxrKey::new([0x0b; 32]);
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let mut encoded = Vec::with_capacity(MAX_REQUEST_LEN);

        let measured = allocation_counter::measure(|| {
            for _ in 0..1_024 {
                encode_request(
                    black_box(&destination),
                    black_box(NOW),
                    black_box([0x44; 16]),
                    black_box(&key),
                    black_box(&mut encoded),
                )
                .expect("request must encode");
            }
        });

        assert_eq!(
            measured.count_total, 0,
            "reserved NXR encoding must not allocate: {measured:?}"
        );
    }

    #[test]
    fn fixed_ipv4_hmac_vector_round_trips() {
        let key = NxrKey::new([0x0b; 32]);
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let mut encoded = Vec::new();
        encode_request(
            &destination,
            NOW,
            core::array::from_fn(|index| u8::try_from(index).expect("index must fit")),
            &key,
            &mut encoded,
        )
        .expect("request must encode");

        assert_eq!(
            hex(&encoded),
            "4e5852010001000401bb000000006553f100000102030405060708090a0b0c0d0e0f01020304a5cf813fbe96f09cfedd30ce904f3664887f57a5f1fd026ae7a855ff15767d74"
        );
        let decoded = decode_authenticated_request(&encoded, &key, NOW + 5, 10)
            .expect("authenticated vector must decode");
        assert_eq!(decoded.destination(), &destination);
        assert_eq!(decoded.timestamp(), NOW);
    }

    #[test]
    fn domain_and_ipv6_requests_round_trip_at_exact_boundaries() {
        let key = NxrKey::new([0x42; 32]);
        let destinations = [
            Destination::new(Address::Domain("a".repeat(253)), 53),
            Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8443),
        ];
        for destination in destinations {
            let mut encoded = Vec::new();
            encode_request(&destination, NOW, [0x55; 16], &key, &mut encoded)
                .expect("bounded destination must encode");
            assert_eq!(
                request_len_from_header(&encoded[..REQUEST_HEADER_LEN])
                    .expect("header must declare exact size"),
                encoded.len()
            );
            assert!(encoded.len() <= MAX_REQUEST_LEN);
            assert_eq!(
                decode_authenticated_request(&encoded, &key, NOW, 0)
                    .expect("request must authenticate")
                    .destination(),
                &destination
            );
        }
    }

    #[test]
    fn rejects_tamper_wrong_key_time_and_trailing_data() {
        let key = NxrKey::new([0x31; 32]);
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let mut encoded = Vec::new();
        encode_request(&destination, NOW, [0x77; 16], &key, &mut encoded)
            .expect("request must encode");

        let mut tampered = encoded.clone();
        tampered[REQUEST_HEADER_LEN] ^= 1;
        assert_eq!(
            decode_authenticated_request(&tampered, &key, NOW, 1),
            Err(NxrProtocolError::Authentication)
        );
        assert_eq!(
            decode_authenticated_request(&encoded, &NxrKey::new([0x32; 32]), NOW, 1),
            Err(NxrProtocolError::Authentication)
        );
        assert_eq!(
            decode_authenticated_request(&encoded, &key, NOW + 2, 1),
            Err(NxrProtocolError::TimeWindow)
        );
        // Future-dated requests must be rejected as well: a one-sided window
        // would let a captured request be replayed until its timestamp passes.
        assert_eq!(
            decode_authenticated_request(&encoded, &key, NOW - 2, 1),
            Err(NxrProtocolError::TimeWindow)
        );
        assert!(decode_authenticated_request(&encoded, &key, NOW - 1, 1).is_ok());
        assert!(decode_authenticated_request(&encoded, &key, NOW + 1, 1).is_ok());
        encoded.push(0);
        assert_eq!(
            decode_authenticated_request(&encoded, &key, NOW, 1),
            Err(NxrProtocolError::Length)
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic_or_exceed_declared_bound() {
        let key = NxrKey::new([0x99; 32]);
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for length in 0..=MAX_REQUEST_LEN + 8 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state.to_le_bytes()[0];
            }
            let _ignored = decode_authenticated_request(&input, &key, NOW, 30);
            if length >= REQUEST_HEADER_LEN
                && let Ok(declared) = request_len_from_header(&input[..REQUEST_HEADER_LEN])
            {
                assert!(declared <= MAX_REQUEST_LEN);
            }
        }
    }

    #[test]
    fn header_sizing_rejects_bad_magic_flags_and_address_shapes() {
        use super::layout::{
            ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_LENGTH_OFFSET, MAX_DOMAIN_LEN,
        };
        let key = NxrKey::new([0x21; 32]);
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let mut encoded = Vec::new();
        encode_request(&destination, NOW, [0x66; 16], &key, &mut encoded).expect("encode");
        let header = &encoded[..REQUEST_HEADER_LEN];
        assert_eq!(request_len_from_header(header), Ok(encoded.len()));

        let mut bad_magic = header.to_vec();
        bad_magic[0] ^= 0xff;
        assert_eq!(
            request_len_from_header(&bad_magic),
            Err(NxrProtocolError::Version)
        );
        for flags in [super::FLAG_UDP, 2, 0xff] {
            let mut bad_flags = header.to_vec();
            bad_flags[super::FLAGS_OFFSET] = flags;
            assert_eq!(
                request_len_from_header(&bad_flags),
                Err(NxrProtocolError::Flags),
                "flags {flags}"
            );
        }

        let with_address = |kind: u8, length: u16| {
            let mut header = header.to_vec();
            header[5] = kind;
            header[ADDRESS_LENGTH_OFFSET..ADDRESS_LENGTH_OFFSET + 2]
                .copy_from_slice(&length.to_be_bytes());
            request_len_from_header(&header)
        };
        let max = u16::try_from(MAX_DOMAIN_LEN).expect("domain cap fits u16");
        assert!(with_address(ADDRESS_DOMAIN, max).is_ok());
        for (kind, length) in [
            (ADDRESS_DOMAIN, 0),
            (ADDRESS_DOMAIN, max + 1),
            (ADDRESS_IPV4, 5),
            (ADDRESS_IPV6, 17),
            (0, 4),
            (4, 4),
        ] {
            assert_eq!(
                with_address(kind, length),
                Err(NxrProtocolError::Address),
                "kind {kind} length {length}"
            );
        }
    }

    #[test]
    fn port_zero_and_out_of_range_domains_fail_on_both_sides() {
        use super::layout::{PORT_OFFSET, TAG_LEN};
        let key = NxrKey::new([0x22; 32]);
        let mut out = Vec::new();
        for destination in [
            Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 0),
            Destination::new(Address::Domain(String::new()), 443),
            Destination::new(Address::Domain("a".repeat(254)), 443),
        ] {
            assert!(
                encode_request(&destination, NOW, [0x66; 16], &key, &mut out).is_err(),
                "{destination:?} must not encode"
            );
        }

        // An authenticated request whose port is zero is still rejected.
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        encode_request(&destination, NOW, [0x66; 16], &key, &mut out).expect("encode");
        out[PORT_OFFSET..PORT_OFFSET + 2].copy_from_slice(&[0, 0]);
        let authenticated_len = out.len() - TAG_LEN;
        let tag = key.tag(&out[..authenticated_len]);
        out[authenticated_len..].copy_from_slice(&tag);
        assert_eq!(
            decode_authenticated_request(&out, &key, NOW, 1),
            Err(NxrProtocolError::Port)
        );
    }

    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
