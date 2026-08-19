#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::{
    nxr::{NxrKey, decode_authenticated_request, encode_request},
    vless::{Address, Destination},
};

// NXR authenticated-decode target: encodes a structured request, decodes it
// under the same key, and asserts field-for-field equality. A single-bit
// corruption anywhere in the request must fail authentication.

#[derive(Debug)]
struct RequestSpec {
    key: [u8; 32],
    destination: Destination,
    timestamp: u64,
    nonce: [u8; 16],
}

impl<'a> Arbitrary<'a> for RequestSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let address = match u.arbitrary::<u8>()? % 3 {
            0 => Address::Ipv4(Ipv4Addr::from(u.arbitrary::<u32>()?)),
            1 => {
                let length = u.int_in_range(1..=32_usize)?;
                let mut domain = String::with_capacity(length);
                for _ in 0..length {
                    domain.push(char::from(
                        *u.choose(b"abcdefghijklmnopqrstuvwxyz0123456789.-")?,
                    ));
                }
                Address::Domain(domain)
            }
            _ => Address::Ipv6(Ipv6Addr::from(u.arbitrary::<u128>()?)),
        };
        // Port zero is an encode-side reject; keep the round trip in range.
        let port = u.arbitrary::<u16>()?.max(1);
        Ok(Self {
            key: u.arbitrary()?,
            destination: Destination::new(address, port),
            timestamp: u.arbitrary()?,
            nonce: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: &[u8]| {
    let mut unstructured = Unstructured::new(input);
    let Ok(spec) = RequestSpec::arbitrary(&mut unstructured) else {
        return;
    };
    let mutation_offset = unstructured.arbitrary::<u16>().unwrap_or(0);

    let key = NxrKey::new(spec.key);
    let mut request = Vec::new();
    if encode_request(
        &spec.destination,
        spec.timestamp,
        spec.nonce,
        &key,
        &mut request,
    )
    .is_err()
    {
        return;
    }

    let decoded = decode_authenticated_request(&request, &key, spec.timestamp, 30)
        .unwrap_or_else(|error| panic!("encoded request must decode: {error:?}"));
    let (nonce, destination) = decoded.into_parts();
    assert_eq!(nonce, spec.nonce, "nonce diverged");
    assert_eq!(destination, spec.destination, "destination diverged");

    // Any single-bit corruption of the authenticated request must fail.
    let offset = usize::from(mutation_offset) % (request.len() + 1);
    if offset < request.len() {
        let mut corrupted = request.clone();
        corrupted[offset] ^= 0x01;
        assert!(
            decode_authenticated_request(&corrupted, &key, spec.timestamp, 30).is_err(),
            "corrupted request must not authenticate"
        );
    }
});
