//! Runtime-independent semantics for one authenticated single-message transfer.
//!
//! A "transfer" here is one bounded authenticated message that a session must
//! place on a transport before that transport carries the session: the sealed
//! Handoff transfer message and the sealed NXR request are both instances.
//!
//! The rules this module owns are ownership rules, not I/O rules:
//!
//! - a complete write is irreversible, because the peer may already
//!   authenticate the message and perform a destination side effect;
//! - an attempt that committed no byte may be replaced, but only by an attempt
//!   that constructs entirely fresh authenticated bytes;
//! - a prepaid warm transport is protocol-unprivileged until its own fresh
//!   authenticated message is fully accepted, so it never inherits authority
//!   from the pool that produced it.

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
    ///
    /// Completion is tested first so the classification agrees with a writer
    /// that submits nothing for an empty message: delivering every byte of a
    /// zero-length message is completion, not an absence of progress. Production
    /// authenticated messages always carry a mandatory header and are never
    /// empty, so this only removes a latent disagreement rather than changing a
    /// reachable outcome.
    #[must_use]
    pub const fn from_written(bytes_written: usize, message_len: usize) -> Self {
        if bytes_written >= message_len {
            Self::CompleteWrite
        } else if bytes_written == 0 {
            Self::NoBytesWritten
        } else {
            Self::PartialWrite { bytes_written }
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

    /// Splits the total classification into its two ownership consequences.
    ///
    /// `Ok` yields the one-shot irreversible-commit witness, `Err` yields the
    /// statically retryable remainder. Callers that already hold a
    /// [`RetryableProgress`] cannot accidentally reason about a committed write,
    /// and callers holding a [`CommittedWrite`] cannot reason about a retry, so
    /// neither case needs a runtime `unreachable!` guard.
    #[expect(
        clippy::missing_errors_doc,
        reason = "the Err case is the documented retryable remainder, not a failure"
    )]
    pub const fn split(self) -> Result<CommittedWrite, RetryableProgress> {
        match self {
            Self::NoBytesWritten => Err(RetryableProgress::NoBytesWritten),
            Self::PartialWrite { bytes_written } => {
                Err(RetryableProgress::PartialWrite { bytes_written })
            }
            Self::CompleteWrite => Ok(CommittedWrite { _private: () }),
        }
    }
}

/// Proof that one transport accepted a complete authenticated message.
///
/// This value is deliberately neither `Copy` nor `Clone`. It is the irreversible
/// boundary: it exists exactly once per committed message, and the runtime
/// adapter consumes it when it binds the session to that transport. A session
/// that holds no witness has committed nothing and may still be moved; a session
/// whose witness has been consumed can never be retried elsewhere.
#[derive(Debug, Eq, PartialEq)]
pub struct CommittedWrite {
    // Keeps construction inside this module so a `CommittedWrite` can only come
    // from a real complete write classification.
    _private: (),
}

impl CommittedWrite {
    /// Consumes the witness while binding the session to its transport.
    ///
    /// The name records the ownership meaning at the call site: after this
    /// returns, no other transport may carry this session.
    pub const fn commit_transport_ownership(self) {}
}

/// Write progress that is statically known to permit a fresh attempt.
///
/// Producing this type requires having ruled out `CompleteWrite`, so a value of
/// this type is itself the proof that no destination side effect can have been
/// triggered by the failed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryableProgress {
    /// The peer received none of the failed attempt's authenticated message.
    NoBytesWritten,
    /// The peer received an incomplete prefix of the failed attempt's message.
    PartialWrite {
        /// Number of bytes accepted by the transport before it failed.
        bytes_written: usize,
    },
}

impl RetryableProgress {
    /// Widens back to the total classification.
    #[must_use]
    pub const fn progress(self) -> WriteProgress {
        match self {
            Self::NoBytesWritten => WriteProgress::NoBytesWritten,
            Self::PartialWrite { bytes_written } => WriteProgress::PartialWrite { bytes_written },
        }
    }

    /// Bytes the failed attempt placed on the transport, always discarded.
    ///
    /// The count exists for accounting and diagnostics only. A permitted retry
    /// never resumes from this offset: it builds an entirely new message.
    #[must_use]
    pub const fn bytes_discarded(self) -> usize {
        match self {
            Self::NoBytesWritten => 0,
            Self::PartialWrite { bytes_written } => bytes_written,
        }
    }
}

/// Which transport an authenticated single-message attempt is using.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttemptTransport {
    /// A prepaid warm socket taken from a pool.
    ///
    /// Warm sockets are transport state, never authentication authority. The
    /// attempt still constructs and sends fresh authenticated bytes, and the
    /// socket carries no session privilege until that write commits.
    Warm,
    /// The mandatory cold dial.
    Cold,
}

impl AttemptTransport {
    /// Whether failing on this transport leaves an alternate attempt available.
    ///
    /// A warm attempt is speculative: losing it falls back to the required cold
    /// dial. The cold dial is the last attempt in the sequence, so failing it
    /// exhausts the transfer.
    #[must_use]
    pub const fn permits_alternate_attempt(self) -> bool {
        matches!(self, Self::Warm)
    }

    /// The transport an alternate attempt would use, if one is permitted.
    #[must_use]
    pub const fn alternate_attempt(self) -> Option<Self> {
        match self {
            Self::Warm => Some(Self::Cold),
            Self::Cold => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AttemptTransport, RetryableProgress, WriteProgress};

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

    #[test]
    fn split_agrees_with_the_retry_predicate_for_every_classification() {
        for (written, length) in [(0, 16), (1, 16), (15, 16), (16, 16), (17, 16), (0, 0)] {
            let progress = WriteProgress::from_written(written, length);
            match progress.split() {
                Ok(_) => assert!(
                    !progress.permits_fresh_attempt(),
                    "{progress:?} produced a commit witness but claims to be retryable"
                ),
                Err(retryable) => {
                    assert!(
                        progress.permits_fresh_attempt(),
                        "{progress:?} produced retryable progress but forbids a fresh attempt"
                    );
                    assert_eq!(retryable.progress(), progress);
                    assert_eq!(retryable.bytes_discarded(), written);
                }
            }
        }
    }

    #[test]
    fn a_zero_length_message_is_committed_immediately() {
        // A bounded authenticated message is never empty in production, but the
        // classification must still not invent a retryable state for it.
        assert_eq!(
            WriteProgress::from_written(0, 0),
            WriteProgress::CompleteWrite
        );
        assert!(WriteProgress::from_written(0, 0).split().is_ok());
    }

    #[test]
    fn retryable_progress_never_resumes_from_an_offset() {
        assert_eq!(RetryableProgress::NoBytesWritten.bytes_discarded(), 0);
        assert_eq!(
            RetryableProgress::PartialWrite { bytes_written: 9 }.bytes_discarded(),
            9
        );
    }

    #[test]
    fn only_the_warm_attempt_has_an_alternate() {
        assert!(AttemptTransport::Warm.permits_alternate_attempt());
        assert!(!AttemptTransport::Cold.permits_alternate_attempt());
        assert_eq!(
            AttemptTransport::Warm.alternate_attempt(),
            Some(AttemptTransport::Cold)
        );
        assert_eq!(AttemptTransport::Cold.alternate_attempt(), None);
    }

    #[test]
    fn the_alternate_chain_terminates() {
        // The attempt sequence must be bounded by construction: following
        // alternates from any transport reaches None in a fixed number of steps.
        let mut transport = Some(AttemptTransport::Warm);
        let mut steps = 0_u8;
        while let Some(current) = transport {
            transport = current.alternate_attempt();
            steps += 1;
            assert!(steps <= 2, "attempt chain did not terminate");
        }
        assert_eq!(steps, 2);
    }

    #[test]
    fn transfer_values_remain_compact() {
        assert_eq!(core::mem::size_of::<AttemptTransport>(), 1);
        assert_eq!(core::mem::size_of::<super::CommittedWrite>(), 0);
        assert_eq!(
            core::mem::size_of::<RetryableProgress>(),
            core::mem::size_of::<usize>() * 2
        );
    }
}
