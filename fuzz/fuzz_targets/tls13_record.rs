#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::reality::tls13::{
    CipherSuite, ContentType, Tls13RecordLayer, TrafficKeys,
};

// TLS 1.3 record open/seal target. Phase 1 seals a structured record batch
// with one layer and opens it with a fresh layer holding identical traffic
// keys: the seal→open round trip must reproduce every record per cipher
// suite. Phase 2 applies truncation, coalescing, and ciphertext-bitflip
// mutations to sealed records and asserts the opener rejects every one of
// them without panicking.

const MAX_RECORDS: usize = 8;
const MAX_PLAINTEXT: usize = 1 << 14;
const MAX_PADDING: usize = 256;

#[derive(Arbitrary, Debug)]
struct RecordSpec {
    content_type: u8,
    plaintext: Vec<u8>,
    padding: u8,
}

#[derive(Arbitrary, Debug)]
struct RecordInput {
    suite: u8,
    key: [u8; 32],
    iv: [u8; 12],
    records: Vec<RecordSpec>,
    mutation_offset: u16,
}

fn suite_of(byte: u8) -> CipherSuite {
    match byte % 3 {
        0 => CipherSuite::Aes128GcmSha256,
        1 => CipherSuite::Aes256GcmSha384,
        _ => CipherSuite::ChaCha20Poly1305Sha256,
    }
}

fn content_type_of(byte: u8) -> ContentType {
    match byte % 4 {
        0 => ContentType::ChangeCipherSpec,
        1 => ContentType::Alert,
        2 => ContentType::Handshake,
        _ => ContentType::ApplicationData,
    }
}

fn layer(suite: CipherSuite, key: &[u8; 32], iv: [u8; 12]) -> Option<Tls13RecordLayer> {
    let key_len = match suite {
        CipherSuite::Aes128GcmSha256 => 16,
        CipherSuite::Aes256GcmSha384 | CipherSuite::ChaCha20Poly1305Sha256 => 32,
    };
    let keys = TrafficKeys::from_raw_parts(&key[..key_len], iv).ok()?;
    Tls13RecordLayer::new(suite, keys).ok()
}

fuzz_target!(|input: RecordInput| {
    let suite = suite_of(input.suite);
    let Some(mut sealer) = layer(suite, &input.key, input.iv) else {
        return;
    };
    let Some(mut opener) = layer(suite, &input.key, input.iv) else {
        return;
    };

    // Phase 1: seal→open round trip per record.
    let mut sealed_records = Vec::new();
    for spec in input.records.iter().take(MAX_RECORDS) {
        let content_type = content_type_of(spec.content_type);
        let plaintext = &spec.plaintext[..spec.plaintext.len().min(MAX_PLAINTEXT)];
        let padding = usize::from(spec.padding) % MAX_PADDING;
        let mut record = Vec::new();
        if sealer
            .seal_into(content_type, plaintext, padding, &mut record)
            .is_err()
        {
            return;
        }
        let mut opened_buffer = record.clone();
        let opened = opener.open_in_place(&mut opened_buffer);
        let opened = opened.unwrap_or_else(|error| {
            panic!("sealed record must open: {error:?}");
        });
        assert_eq!(opened.content_type(), content_type, "content type diverged");
        assert_eq!(opened.plaintext(), plaintext, "plaintext diverged");
        sealed_records.push(record);
    }

    // Phase 2: mutated records must be rejected, never panic.
    let Some(mut verifier) = layer(suite, &input.key, input.iv) else {
        return;
    };
    for record in &sealed_records {
        let offset = usize::from(input.mutation_offset) % (record.len() + 1);

        // Truncation at every fuzz-driven boundary.
        if offset < record.len() {
            let mut truncated = record[..offset].to_vec();
            assert!(
                verifier.open_in_place(&mut truncated).is_err(),
                "truncated record must not open"
            );
        }

        // Single-byte corruption anywhere in header, ciphertext, or tag.
        if offset < record.len() {
            let mut corrupted = record.clone();
            corrupted[offset] ^= 0x01;
            assert!(
                verifier.open_in_place(&mut corrupted).is_err(),
                "corrupted record must not open"
            );
        }
    }

    // Coalescing: two concatenated records are not one record.
    if sealed_records.len() >= 2 {
        let mut coalesced = sealed_records[0].clone();
        coalesced.extend_from_slice(&sealed_records[1]);
        let Some(mut verifier) = layer(suite, &input.key, input.iv) else {
            return;
        };
        assert!(
            verifier.open_in_place(&mut coalesced).is_err(),
            "coalesced records must not open as one"
        );
    }
});
