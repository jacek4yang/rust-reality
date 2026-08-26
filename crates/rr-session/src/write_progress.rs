//! Byte-exact ownership progress for a single authenticated message.

/// Observable progress at a transport's irreversible write boundary.
///
/// `CompleteWrite` means the peer may already authenticate the message and
/// perform external side effects. The logical session must therefore never be
/// retried on another transport after reaching that state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteProgress {
    /// The peer received none of this attempt's authenticated message.
    NoBytesWritten,
    /// The peer received an incomplete prefix of this attempt's message.
    PartialWrite {
        /// Number of bytes accepted by the transport.
        bytes_written: usize,
    },
    /// The transport accepted the complete authenticated message.
    CompleteWrite,
}

impl WriteProgress {
    /// Classifies a cumulative write count against one bounded message.
    #[must_use]
    pub const fn from_written(bytes_written: usize, message_len: usize) -> Self {
        if bytes_written == 0 {
            Self::NoBytesWritten
        } else if bytes_written < message_len {
            Self::PartialWrite { bytes_written }
        } else {
            Self::CompleteWrite
        }
    }

    /// Whether a new transport may receive newly constructed authentication.
    ///
    /// This says nothing about retry budgets. The runtime adapter still owns
    /// the fixed attempt count and must construct fresh protocol state.
    #[must_use]
    pub const fn permits_fresh_attempt(self) -> bool {
        !matches!(self, Self::CompleteWrite)
    }
}

#[cfg(test)]
mod tests {
    use super::WriteProgress;

    #[test]
    fn classifies_the_irreversible_boundary() {
        assert_eq!(
            WriteProgress::from_written(0, 16),
            WriteProgress::NoBytesWritten
        );
        assert_eq!(
            WriteProgress::from_written(7, 16),
            WriteProgress::PartialWrite { bytes_written: 7 }
        );
        assert_eq!(
            WriteProgress::from_written(16, 16),
            WriteProgress::CompleteWrite
        );
        assert_eq!(
            WriteProgress::from_written(17, 16),
            WriteProgress::CompleteWrite
        );
    }

    #[test]
    fn complete_write_is_never_retryable() {
        assert!(WriteProgress::NoBytesWritten.permits_fresh_attempt());
        assert!(WriteProgress::PartialWrite { bytes_written: 1 }.permits_fresh_attempt());
        assert!(!WriteProgress::CompleteWrite.permits_fresh_attempt());
    }
}
