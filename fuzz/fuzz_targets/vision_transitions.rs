#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::vless::{
    UserId, VisionCommand, VisionDecoder, VisionEncoder, VisionMode,
};

// Vision decoder transitions target: builds a valid framed stream with the
// deterministic-seed encoder, then replays it through the decoder under a
// fuzz-driven fragmentation. The decoded payload must equal the encoded
// content byte-for-byte and the terminal mode must match the final committed
// command. A second phase feeds raw fuzz chunks straight into a decoder to
// reach malformed-transition paths.

const MAX_FRAMES: usize = 8;
const MAX_CONTENT: usize = 1024;
const MAX_FRAGMENTS: usize = 16;

#[derive(Arbitrary, Debug)]
struct FrameSpec {
    content: Vec<u8>,
    command: u8,
    long_padding: bool,
}

#[derive(Arbitrary, Debug)]
struct StructuredInput {
    seed: [u8; 44],
    frames: Vec<FrameSpec>,
    fragments: Vec<u16>,
}

fn command_of(byte: u8) -> VisionCommand {
    match byte % 3 {
        0 => VisionCommand::Continue,
        1 => VisionCommand::End,
        _ => VisionCommand::Direct,
    }
}

fn expected_mode(command: VisionCommand) -> VisionMode {
    match command {
        VisionCommand::Continue => VisionMode::Framed,
        VisionCommand::End => VisionMode::Raw,
        VisionCommand::Direct => VisionMode::Direct,
    }
}

fuzz_target!(|input: &[u8]| {
    let mut unstructured = Unstructured::new(input);

    // Phase 1: structured round trip under fuzz-driven fragmentation.
    if let Ok(structured) = StructuredInput::arbitrary(&mut unstructured) {
        let user_id = UserId::new([0x11; 16]);
        let mut encoder = VisionEncoder::with_padding_seed(user_id, &structured.seed);
        let mut wire = Vec::new();
        let mut expected_payload = Vec::new();
        let mut terminal = VisionMode::Framed;
        let mut encoded_any = false;
        for frame in structured.frames.iter().take(MAX_FRAMES) {
            let content = &frame.content[..frame.content.len().min(MAX_CONTENT)];
            let command = command_of(frame.command);
            let mut frame_wire = Vec::new();
            if encoder
                .encode(content, command, frame.long_padding, &mut frame_wire)
                .is_err()
            {
                break;
            }
            wire.extend_from_slice(&frame_wire);
            expected_payload.extend_from_slice(content);
            terminal = expected_mode(command);
            encoded_any = true;
        }

        if encoded_any {
            let mut decoder = VisionDecoder::new(user_id);
            let mut decoded = Vec::new();
            let mut output = Vec::new();
            let mut cursor = 0;
            let mut mode = VisionMode::Framed;
            for fragment in structured.fragments.iter().take(MAX_FRAGMENTS) {
                if cursor >= wire.len() {
                    break;
                }
                let take = usize::from(*fragment % 64) + 1;
                let end = (cursor + take).min(wire.len());
                let result = decoder.decode(&wire[cursor..end], &mut output);
                assert!(
                    result.is_ok(),
                    "valid encoded stream must decode: {result:?}"
                );
                mode = result.unwrap_or(mode);
                decoded.extend_from_slice(&output);
                cursor = end;
            }
            if cursor < wire.len() {
                let result = decoder.decode(&wire[cursor..], &mut output);
                assert!(
                    result.is_ok(),
                    "valid encoded stream must decode: {result:?}"
                );
                mode = result.unwrap_or(mode);
                decoded.extend_from_slice(&output);
            }
            assert_eq!(decoded, expected_payload, "fragmented decode diverged");
            assert_eq!(mode, terminal, "terminal mode diverged");
        }
    }

    // Phase 2: raw chunked decode of whatever bytes remain. The loop must
    // stop on empty input: `arbitrary::<Vec<u8>>` returns `Ok(vec![])` at
    // end-of-input instead of an error, which would spin forever.
    let mut decoder = VisionDecoder::new(UserId::new([0x11; 16]));
    let mut output = Vec::new();
    while !unstructured.is_empty() {
        let Ok(chunk) = unstructured.arbitrary::<Vec<u8>>() else {
            break;
        };
        if chunk.is_empty() || chunk.len() > 4096 {
            break;
        }
        let _ = decoder.decode(&chunk, &mut output);
    }
});
