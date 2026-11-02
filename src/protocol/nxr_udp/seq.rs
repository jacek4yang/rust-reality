//! Per-direction NXR UDP frame sequence state.

use super::error::NxrUdpError;

/// Exact next-sequence tracker (rejects replay and reordering).
#[derive(Clone, Debug, Default)]
pub struct NxrUdpSeq {
    // One extra state represents exhaustion without reusing a wire sequence.
    next: u64,
}

impl NxrUdpSeq {
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Allocates a wire sequence once; exhaustion requires a new association.
    ///
    /// # Errors
    ///
    /// [`NxrUdpError::Sequence`] after every 32-bit sequence has been used.
    pub fn next_out(&mut self) -> Result<u32, NxrUdpError> {
        let seq = u32::try_from(self.next).map_err(|_| NxrUdpError::Sequence)?;
        self.next += 1;
        Ok(seq)
    }

    /// # Errors
    ///
    /// [`NxrUdpError::Sequence`] when `seq` is not expected or the
    /// association has exhausted its wire sequence space.
    pub fn accept_in(&mut self, seq: u32) -> Result<(), NxrUdpError> {
        if u64::from(seq) != self.next {
            return Err(NxrUdpError::Sequence);
        }
        self.next += 1;
        Ok(())
    }
}

#[cfg(test)]
mod sequence_exhaustion_tests {
    use super::NxrUdpSeq;
    use crate::protocol::{
        nxr::NxrKey,
        nxr_udp::{
            DIR_LINE_TO_LANDING, FRAME_TYPE_DATAGRAM, NxrUdpError, NxrUdpSessionKey, decode_frame,
            encode_frame,
        },
    };

    #[test]
    fn exhausted_inbound_sequence_rejects_replay() {
        let mut sequence = NxrUdpSeq {
            next: u64::from(u32::MAX),
        };
        // An old frame remains MAC-valid under this association's key. The
        // sequence guard must still reject it after the final wire value.
        let key = NxrKey::new([0x37; 32]);
        let session = NxrUdpSessionKey::derive(&key, b"sequence-exhaustion-test");
        let mut replay = Vec::new();
        encode_frame(
            &session,
            DIR_LINE_TO_LANDING,
            FRAME_TYPE_DATAGRAM,
            0,
            None,
            b"old-datagram",
            &mut replay,
        )
        .unwrap();
        sequence.accept_in(u32::MAX).unwrap();
        let (frame, consumed) = decode_frame(&replay, &session, DIR_LINE_TO_LANDING).unwrap();
        assert_eq!(consumed, replay.len());
        assert_eq!(sequence.accept_in(frame.seq), Err(NxrUdpError::Sequence));
        assert_eq!(sequence.accept_in(u32::MAX), Err(NxrUdpError::Sequence));
    }

    #[test]
    fn exhausted_outbound_sequence_never_reuses_a_wire_value() {
        let mut sequence = NxrUdpSeq {
            next: u64::from(u32::MAX) - 1,
        };
        assert_eq!(sequence.next_out(), Ok(u32::MAX - 1));
        assert_eq!(sequence.next_out(), Ok(u32::MAX));
        for _ in 0..3 {
            assert_eq!(sequence.next_out(), Err(NxrUdpError::Sequence));
        }
    }
}
