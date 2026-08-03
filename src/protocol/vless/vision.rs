use std::{error::Error, fmt};

use super::UserId;

/// Maximum wire size of one Xray Vision padding block.
pub const VISION_FRAME_SIZE: usize = 8 * 1024;

const UUID_SIZE: usize = 16;
const HEADER_SIZE: usize = 5;
const DEFAULT_LONG_PADDING_THRESHOLD: usize = 900;
const DEFAULT_LONG_PADDING_RANGE: u32 = 500;
const DEFAULT_LONG_PADDING_TARGET: usize = 900;
const DEFAULT_SHORT_PADDING_RANGE: u32 = 256;

/// A command carried in a Vision padding block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VisionCommand {
    /// More framed blocks follow.
    Continue = 0,

    /// Padding ends and subsequent bytes are unframed.
    End = 1,

    /// Padding ends at an authenticated direct-copy boundary.
    Direct = 2,
}

impl TryFrom<u8> for VisionCommand {
    type Error = VisionDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            _ => Err(VisionDecodeError::UnknownCommand(value)),
        }
    }
}

/// The receiver mode after processing a Vision input fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisionMode {
    /// Vision padding blocks are still being decoded.
    Framed,

    /// An End command was authenticated; following bytes are unframed.
    Raw,

    /// A Direct command was authenticated at a frame boundary.
    Direct,
}

/// Stateful, allocation-free decoding of Xray-compatible Vision blocks.
#[derive(Debug)]
pub struct VisionDecoder {
    user_id: UserId,
    first_frame: bool,
    uuid_read: usize,
    header: [u8; HEADER_SIZE],
    header_read: usize,
    content_remaining: usize,
    padding_remaining: usize,
    command: Option<VisionCommand>,
    mode: VisionMode,
    failed: bool,
}

impl VisionDecoder {
    /// Creates a decoder for the VLESS user that negotiated Vision.
    pub const fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            first_frame: true,
            uuid_read: 0,
            header: [0; HEADER_SIZE],
            header_read: 0,
            content_remaining: 0,
            padding_remaining: 0,
            command: None,
            mode: VisionMode::Framed,
            failed: false,
        }
    }

    /// Decodes one arbitrary input fragment into caller-owned output storage.
    ///
    /// The output is cleared first and never grows beyond the input fragment.
    /// Header, UUID, and padding may be fragmented at any byte boundary.
    pub fn decode(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<VisionMode, VisionDecodeError> {
        output.clear();
        if self.failed {
            return Err(VisionDecodeError::DecoderFailed);
        }
        output
            .try_reserve(input.len())
            .map_err(|_| self.fail(VisionDecodeError::AllocationFailed))?;

        let result = self.decode_inner(input, output);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Returns the decoder's current framing mode.
    pub const fn mode(&self) -> VisionMode {
        self.mode
    }

    fn decode_inner(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<VisionMode, VisionDecodeError> {
        if self.mode != VisionMode::Framed {
            output.extend_from_slice(input);
            return Ok(self.mode);
        }

        let mut cursor = 0;
        while cursor < input.len() {
            if self.first_frame && self.uuid_read < UUID_SIZE {
                let available = input.len() - cursor;
                let count = available.min(UUID_SIZE - self.uuid_read);
                let expected = &self.user_id.as_bytes()[self.uuid_read..self.uuid_read + count];
                let received = &input[cursor..cursor + count];
                if received != expected {
                    return Err(VisionDecodeError::UserIdMismatch);
                }
                self.uuid_read += count;
                cursor += count;
                continue;
            }

            if self.header_read < HEADER_SIZE {
                let available = input.len() - cursor;
                let count = available.min(HEADER_SIZE - self.header_read);
                self.header[self.header_read..self.header_read + count]
                    .copy_from_slice(&input[cursor..cursor + count]);
                self.header_read += count;
                cursor += count;

                if self.header_read == HEADER_SIZE {
                    self.start_frame()?;
                }
                continue;
            }

            if self.content_remaining > 0 {
                let count = (input.len() - cursor).min(self.content_remaining);
                output.extend_from_slice(&input[cursor..cursor + count]);
                self.content_remaining -= count;
                cursor += count;
                continue;
            }

            if self.padding_remaining > 0 {
                let count = (input.len() - cursor).min(self.padding_remaining);
                self.padding_remaining -= count;
                cursor += count;
                continue;
            }

            self.finish_frame();
            if self.mode != VisionMode::Framed {
                output.extend_from_slice(&input[cursor..]);
                break;
            }
        }

        if self.frame_complete() {
            self.finish_frame();
        }

        Ok(self.mode)
    }

    fn start_frame(&mut self) -> Result<(), VisionDecodeError> {
        let command = VisionCommand::try_from(self.header[0])?;
        let content_length = usize::from(u16::from_be_bytes([self.header[1], self.header[2]]));
        let padding_length = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
        let prefix_length = HEADER_SIZE + usize::from(self.first_frame) * UUID_SIZE;
        let wire_length = prefix_length
            .checked_add(content_length)
            .and_then(|length| length.checked_add(padding_length))
            .ok_or(VisionDecodeError::FrameTooLarge {
                content_length,
                padding_length,
            })?;
        if wire_length > VISION_FRAME_SIZE {
            return Err(VisionDecodeError::FrameTooLarge {
                content_length,
                padding_length,
            });
        }

        self.command = Some(command);
        self.content_remaining = content_length;
        self.padding_remaining = padding_length;
        Ok(())
    }

    fn frame_complete(&self) -> bool {
        self.header_read == HEADER_SIZE
            && self.content_remaining == 0
            && self.padding_remaining == 0
            && self.command.is_some()
    }

    fn finish_frame(&mut self) {
        let Some(command) = self.command.take() else {
            return;
        };

        self.mode = match command {
            VisionCommand::Continue => VisionMode::Framed,
            VisionCommand::End => VisionMode::Raw,
            VisionCommand::Direct => VisionMode::Direct,
        };
        self.first_frame = false;
        self.header_read = 0;
        self.header.fill(0);
    }

    fn fail(&mut self, error: VisionDecodeError) -> VisionDecodeError {
        self.failed = true;
        error
    }
}

/// Stateful Xray-compatible Vision padding encoder.
#[derive(Debug)]
pub struct VisionEncoder {
    user_id: UserId,
    first_frame: bool,
}

impl VisionEncoder {
    /// Creates an encoder for one authenticated VLESS user.
    pub const fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            first_frame: true,
        }
    }

    /// Encodes one bounded Vision frame into reusable caller-owned storage.
    pub fn encode(
        &mut self,
        content: &[u8],
        command: VisionCommand,
        long_padding: bool,
        output: &mut Vec<u8>,
    ) -> Result<(), VisionEncodeError> {
        let prefix_length = HEADER_SIZE + usize::from(self.first_frame) * UUID_SIZE;
        let maximum_content = VISION_FRAME_SIZE - prefix_length;
        if content.len() > maximum_content || content.len() > usize::from(u16::MAX) {
            return Err(VisionEncodeError::ContentTooLarge {
                length: content.len(),
                maximum: maximum_content,
            });
        }

        let maximum_padding = VISION_FRAME_SIZE - prefix_length - content.len();
        let padding_length = choose_padding_length(content.len(), long_padding, maximum_padding)?;
        let frame_length = prefix_length + content.len() + padding_length;

        output.clear();
        output
            .try_reserve(frame_length)
            .map_err(|_| VisionEncodeError::AllocationFailed)?;
        if self.first_frame {
            output.extend_from_slice(self.user_id.as_bytes());
        }
        output.push(command as u8);
        output.extend_from_slice(
            &u16::try_from(content.len())
                .map_err(|_| VisionEncodeError::ContentTooLarge {
                    length: content.len(),
                    maximum: maximum_content,
                })?
                .to_be_bytes(),
        );
        output.extend_from_slice(
            &u16::try_from(padding_length)
                .map_err(|_| VisionEncodeError::PaddingTooLarge(padding_length))?
                .to_be_bytes(),
        );
        output.extend_from_slice(content);
        output.resize(frame_length, 0);
        self.first_frame = false;
        Ok(())
    }
}

/// An error produced while decoding Vision framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisionDecodeError {
    /// The first padding block did not carry the authenticated VLESS user ID.
    UserIdMismatch,

    /// A padding block carried an unknown command.
    UnknownCommand(u8),

    /// The declared content and padding exceed Xray's 8 KiB frame size.
    FrameTooLarge {
        content_length: usize,
        padding_length: usize,
    },

    /// The output buffer could not reserve its bounded capacity.
    AllocationFailed,

    /// A caller attempted to reuse a decoder after a protocol error.
    DecoderFailed,
}

impl fmt::Display for VisionDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserIdMismatch => formatter.write_str("Vision user ID does not match VLESS user"),
            Self::UnknownCommand(command) => {
                write!(formatter, "Vision command {command} is unknown")
            }
            Self::FrameTooLarge {
                content_length,
                padding_length,
            } => write!(
                formatter,
                "Vision frame content {content_length} plus padding {padding_length} exceeds 8 KiB"
            ),
            Self::AllocationFailed => {
                formatter.write_str("failed to reserve bounded Vision decode buffer")
            }
            Self::DecoderFailed => formatter.write_str("Vision decoder already failed"),
        }
    }
}

impl Error for VisionDecodeError {}

/// An error produced while encoding Vision framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisionEncodeError {
    /// A content fragment cannot fit in one Vision frame.
    ContentTooLarge { length: usize, maximum: usize },

    /// A generated padding length cannot be represented on the wire.
    PaddingTooLarge(usize),

    /// Operating-system entropy was unavailable.
    EntropyUnavailable,

    /// The output buffer could not reserve its bounded capacity.
    AllocationFailed,
}

impl fmt::Display for VisionEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentTooLarge { length, maximum } => write!(
                formatter,
                "Vision content length {length} exceeds frame maximum {maximum}"
            ),
            Self::PaddingTooLarge(length) => {
                write!(
                    formatter,
                    "Vision padding length {length} exceeds wire limit"
                )
            }
            Self::EntropyUnavailable => {
                formatter.write_str("operating-system entropy unavailable for Vision padding")
            }
            Self::AllocationFailed => {
                formatter.write_str("failed to reserve bounded Vision encode buffer")
            }
        }
    }
}

impl Error for VisionEncodeError {}

fn choose_padding_length(
    content_length: usize,
    long_padding: bool,
    maximum: usize,
) -> Result<usize, VisionEncodeError> {
    let candidate = if content_length < DEFAULT_LONG_PADDING_THRESHOLD && long_padding {
        usize::try_from(random_below(DEFAULT_LONG_PADDING_RANGE)?)
            .map_err(|_| VisionEncodeError::EntropyUnavailable)?
            + DEFAULT_LONG_PADDING_TARGET
            - content_length
    } else {
        usize::try_from(random_below(DEFAULT_SHORT_PADDING_RANGE)?)
            .map_err(|_| VisionEncodeError::EntropyUnavailable)?
    };

    Ok(candidate.min(maximum))
}

fn random_below(upper: u32) -> Result<u32, VisionEncodeError> {
    let acceptance_limit = u32::MAX - (u32::MAX % upper);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| VisionEncodeError::EntropyUnavailable)?;
        let value = u32::from_ne_bytes(bytes);
        if value < acceptance_limit {
            return Ok(value % upper);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        VISION_FRAME_SIZE, VisionCommand, VisionDecodeError, VisionDecoder, VisionEncoder,
        VisionMode,
    };
    use crate::protocol::vless::UserId;

    const USER: UserId = UserId::new([0x11; 16]);

    #[test]
    fn decodes_xray_wire_vector_fragmented_at_every_byte() {
        let mut wire = USER.as_bytes().to_vec();
        wire.extend_from_slice(&[0, 0, 3, 0, 2, b'a', b'b', b'c', 0, 0]);
        wire.extend_from_slice(&[1, 0, 2, 0, 1, b'd', b'e', 0]);
        wire.extend_from_slice(b"raw");
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut all = Vec::new();

        for byte in wire {
            let mode = decoder
                .decode(&[byte], &mut decoded)
                .expect("fragmented Xray frame should decode");
            all.extend_from_slice(&decoded);
            if mode == VisionMode::Raw {
                assert_eq!(decoder.mode(), VisionMode::Raw);
            }
        }

        assert_eq!(all, b"abcderaw");
        assert_eq!(decoder.mode(), VisionMode::Raw);
    }

    #[test]
    fn reports_authenticated_direct_boundary_and_preserves_remainder() {
        let mut wire = USER.as_bytes().to_vec();
        wire.extend_from_slice(&[2, 0, 3, 0, 0]);
        wire.extend_from_slice(b"tlsraw");
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();

        let mode = decoder
            .decode(&wire, &mut decoded)
            .expect("direct frame should decode");

        assert_eq!(mode, VisionMode::Direct);
        assert_eq!(decoded, b"tlsraw");
    }

    #[test]
    fn rejects_wrong_user_id_and_poison_decoder() {
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();

        assert_eq!(
            decoder.decode(&[0x22], &mut decoded),
            Err(VisionDecodeError::UserIdMismatch)
        );
        assert_eq!(
            decoder.decode(USER.as_bytes(), &mut decoded),
            Err(VisionDecodeError::DecoderFailed)
        );
    }

    #[test]
    fn rejects_frame_larger_than_xray_buffer() {
        let mut wire = USER.as_bytes().to_vec();
        wire.extend_from_slice(&[0, 0x20, 0, 0, 0]);
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();

        assert_eq!(
            decoder.decode(&wire, &mut decoded),
            Err(VisionDecodeError::FrameTooLarge {
                content_length: VISION_FRAME_SIZE,
                padding_length: 0,
            })
        );
    }

    #[test]
    fn encoder_roundtrips_and_emits_uuid_only_once() {
        let mut encoder = VisionEncoder::new(USER);
        let mut first = Vec::new();
        let mut second = Vec::new();
        encoder
            .encode(b"hello", VisionCommand::Continue, true, &mut first)
            .expect("first frame should encode");
        encoder
            .encode(b"world", VisionCommand::End, false, &mut second)
            .expect("second frame should encode");
        assert!(first.starts_with(USER.as_bytes()));
        assert!(!second.starts_with(USER.as_bytes()));
        assert!(first.len() <= VISION_FRAME_SIZE);
        assert!(second.len() <= VISION_FRAME_SIZE);

        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        decoder
            .decode(&first, &mut decoded)
            .expect("first frame should decode");
        assert_eq!(decoded, b"hello");
        decoder
            .decode(&second, &mut decoded)
            .expect("second frame should decode");
        assert_eq!(decoded, b"world");
        assert_eq!(decoder.mode(), VisionMode::Raw);
    }
}
