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

    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
