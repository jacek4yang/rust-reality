//! Differential tests between the retained reference Vision encoder and the
//! plan/assemble encoder used by the hot path.
//!
//! The hot path no longer builds a complete intermediate Vision frame: it plans
//! the frame, then assembles UUID, header, content and padding directly inside
//! the final TLS AEAD plaintext region. These tests prove the two producers are
//! byte-identical across payload sizes, commands, padding modes and random
//! fragmentation, and that the decoder accepts both.

use rust_reality::protocol::vless::{
    UserId, VISION_FRAME_SIZE, VisionCommand, VisionDecoder, VisionEncoder, VisionMode,
};

const USER: UserId = UserId::new([0x3c; 16]);
const HEADER_SIZE: usize = 5;
const UUID_SIZE: usize = 16;

/// Deterministic non-cryptographic sequence used to build test payloads.
///
/// Test inputs must be reproducible; padding randomness is supplied separately
/// by the encoder's seeded generator.
struct Lcg(u64);

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }

    fn below(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next() >> 16) as usize % upper
    }
}

fn payload(length: usize, seed: u64) -> Vec<u8> {
    let mut random = Lcg::new(seed);
    (0..length).map(|_| random.byte()).collect()
}

/// Runs both encoders over the same command sequence with the same padding seed.
fn assert_encoders_agree(sequence: &[(usize, VisionCommand, bool)], seed: [u8; 44]) {
    let mut reference = VisionEncoder::with_padding_seed(USER, &seed);
    let mut assembled = VisionEncoder::with_padding_seed(USER, &seed);
    let mut expected = Vec::new();
    let mut actual = Vec::new();

    for (index, (length, command, long_padding)) in sequence.iter().enumerate() {
        let content = payload(*length, 0x9e37_79b9 ^ index as u64);

        let mut frame = Vec::new();
        reference
            .encode(&content, *command, *long_padding, &mut frame)
            .expect("reference frame must encode");

        let plan = assembled
            .plan(content.len(), *command, *long_padding)
            .expect("frame must plan");
        let mut region = vec![0_u8; plan.wire_len()];
        assembled.assemble(&plan, &content, &mut region);
        assembled.commit(&plan);

        assert_eq!(
            region, frame,
            "frame {index} with length {length}, command {command:?}, long padding \
             {long_padding} must be byte-identical"
        );
        assert_eq!(plan.wire_len(), frame.len());
        assert_eq!(plan.command(), *command);

        expected.extend_from_slice(&content);
        actual.extend_from_slice(&region);
    }

    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut received = Vec::new();
    for byte in &actual {
        decoder
            .decode(std::slice::from_ref(byte), &mut decoded)
            .expect("byte-fragmented frame must decode");
        received.extend_from_slice(&decoded);
    }
    assert_eq!(received, expected, "decoded content must round-trip");
}

#[test]
fn agrees_on_all_boundary_content_lengths() {
    let first_frame_maximum = VISION_FRAME_SIZE - HEADER_SIZE - UUID_SIZE;
    for length in [
        0,
        1,
        2,
        899,
        900,
        901,
        1024,
        first_frame_maximum - 1,
        first_frame_maximum,
    ] {
        assert_encoders_agree(&[(length, VisionCommand::Continue, true)], [0x11; 44]);
        assert_encoders_agree(&[(length, VisionCommand::Continue, false)], [0x22; 44]);
    }
}

#[test]
fn agrees_on_every_terminal_command() {
    for command in [
        VisionCommand::Continue,
        VisionCommand::End,
        VisionCommand::Direct,
    ] {
        assert_encoders_agree(&[(64, command, true)], [0x33; 44]);
        assert_encoders_agree(&[(0, command, false)], [0x44; 44]);
    }
}

#[test]
fn agrees_across_multi_frame_sequences() {
    assert_encoders_agree(
        &[
            (32, VisionCommand::Continue, true),
            (0, VisionCommand::Continue, true),
            (4096, VisionCommand::Continue, false),
            (1, VisionCommand::Continue, true),
            (900, VisionCommand::End, false),
        ],
        [0x55; 44],
    );
}

#[test]
fn agrees_on_randomized_sequences() {
    let mut random = Lcg::new(0x5eed);
    for round in 0..64_u64 {
        let frames = 1 + random.below(6);
        let mut sequence = Vec::with_capacity(frames);
        for index in 0..frames {
            let length = random.below(VISION_FRAME_SIZE - HEADER_SIZE - UUID_SIZE);
            let command = if index + 1 == frames {
                match random.below(3) {
                    0 => VisionCommand::Continue,
                    1 => VisionCommand::End,
                    _ => VisionCommand::Direct,
                }
            } else {
                VisionCommand::Continue
            };
            sequence.push((length, command, random.below(2) == 0));
        }
        let mut seed = [0_u8; 44];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = (round as u8).wrapping_add(index as u8);
        }
        assert_encoders_agree(&sequence, seed);
    }
}

#[test]
fn assembly_emits_the_user_id_exactly_once() {
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x66; 44]);
    let first = encoder
        .plan(8, VisionCommand::Continue, false)
        .expect("first frame must plan");
    let mut first_region = vec![0_u8; first.wire_len()];
    encoder.assemble(&first, b"12345678", &mut first_region);
    encoder.commit(&first);

    let second = encoder
        .plan(8, VisionCommand::Continue, false)
        .expect("second frame must plan");
    let mut second_region = vec![0_u8; second.wire_len()];
    encoder.assemble(&second, b"abcdefgh", &mut second_region);
    encoder.commit(&second);

    assert!(first_region.starts_with(USER.as_bytes()));
    assert!(!second_region.starts_with(USER.as_bytes()));
    assert_eq!(
        first.wire_len() as isize - second.wire_len() as isize,
        UUID_SIZE as isize + first.padding_len() as isize - second.padding_len() as isize,
        "only the UUID prefix and the chosen padding may differ between frames"
    );
}

#[test]
fn assembly_rejects_mismatched_regions_without_panicking() {
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x77; 44]);
    let plan = encoder
        .plan(4, VisionCommand::Continue, false)
        .expect("frame must plan");

    let mut short = vec![0xff_u8; plan.wire_len() - 1];
    encoder.assemble(&plan, b"abcd", &mut short);
    assert!(
        short.iter().all(|byte| *byte == 0xff),
        "a mismatched region must be left untouched"
    );

    let mut region = vec![0xff_u8; plan.wire_len()];
    encoder.assemble(&plan, b"abc", &mut region);
    assert!(
        region.iter().all(|byte| *byte == 0xff),
        "mismatched content length must be left untouched"
    );
}

#[test]
fn direct_command_stops_framing_at_the_exact_boundary() {
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x88; 44]);
    let plan = encoder
        .plan(6, VisionCommand::Direct, false)
        .expect("direct frame must plan");
    let mut wire = vec![0_u8; plan.wire_len()];
    encoder.assemble(&plan, b"tlsraw", &mut wire);
    encoder.commit(&plan);
    wire.extend_from_slice(b"RAWTAIL");

    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mode = decoder
        .decode(&wire, &mut decoded)
        .expect("direct frame must decode");

    assert_eq!(mode, VisionMode::Direct);
    assert_eq!(decoded, b"tlsrawRAWTAIL");
    assert_eq!(decoder.mode(), VisionMode::Direct);
}
