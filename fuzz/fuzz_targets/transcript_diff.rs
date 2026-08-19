#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::reality::tls13::{HashAlgorithm, fuzz_transcript_snapshot_matches};

// Differential target: the incremental handshake-transcript hash must equal
// the one-shot digest over the concatenated messages for every chunking.

const MAX_CHUNKS: usize = 32;
const MAX_CHUNK_LEN: usize = 1024;

#[derive(Arbitrary, Debug)]
struct TranscriptInput {
    sha384: bool,
    chunks: Vec<Vec<u8>>,
}

fuzz_target!(|input: TranscriptInput| {
    let algorithm = if input.sha384 {
        HashAlgorithm::Sha384
    } else {
        HashAlgorithm::Sha256
    };
    let chunks: Vec<&[u8]> = input
        .chunks
        .iter()
        .take(MAX_CHUNKS)
        .map(|chunk| &chunk[..chunk.len().min(MAX_CHUNK_LEN)])
        .collect();
    assert!(
        fuzz_transcript_snapshot_matches(algorithm, &chunks),
        "incremental transcript hash diverged from one-shot digest"
    );
});
