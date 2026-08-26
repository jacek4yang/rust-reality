//! Byte-precise bounded writes for single-use authenticated transports.

use std::{fmt, io};

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    time::{self, Instant},
};

use rr_session::{CommittedWrite, RetryableProgress, WriteProgress};

/// A write failed before the complete authenticated message was submitted.
///
/// The carried progress is a [`RetryableProgress`], so holding this error is
/// itself the proof that the peer cannot have authenticated the message. No
/// caller needs to re-examine whether the failure might have been a complete
/// write.
#[derive(Debug)]
pub(crate) struct CountedWriteError {
    source: io::Error,
    progress: RetryableProgress,
}

impl CountedWriteError {
    pub(crate) const fn progress(&self) -> RetryableProgress {
        self.progress
    }

    pub(crate) fn into_source(self) -> io::Error {
        self.source
    }
}

impl fmt::Display for CountedWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for CountedWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Writes exactly one bounded authenticated message under an absolute deadline.
///
/// Success yields the one-shot [`CommittedWrite`] witness: the peer may already
/// have authenticated the message, so the session is bound to this transport.
/// Failure yields statically retryable progress. The two outcomes are disjoint
/// by type, so callers express the retry rule without a runtime guard.
pub(crate) async fn write_all_counted_before<W: AsyncWrite + Unpin>(
    stream: &mut W,
    bytes: &[u8],
    deadline: Instant,
) -> Result<CommittedWrite, CountedWriteError> {
    let mut written = 0_usize;
    while written < bytes.len() {
        let result = time::timeout_at(deadline, stream.write(&bytes[written..])).await;
        let count = match result {
            Ok(Ok(0)) => {
                return Err(failure(
                    io::Error::new(
                        io::ErrorKind::WriteZero,
                        "authenticated write returned zero",
                    ),
                    written,
                    bytes.len(),
                ));
            }
            Ok(Ok(count)) => count,
            Ok(Err(error)) => return Err(failure(error, written, bytes.len())),
            Err(_) => {
                return Err(failure(
                    io::Error::new(io::ErrorKind::TimedOut, "authenticated write timed out"),
                    written,
                    bytes.len(),
                ));
            }
        };
        written = written.saturating_add(count);
    }
    // Every byte of the message was submitted, including the vacuous case of an
    // empty message, which the classifier agrees is a completed write.
    match WriteProgress::from_written(written, bytes.len()).split() {
        Ok(committed) => Ok(committed),
        Err(retryable) => Err(CountedWriteError {
            source: io::Error::new(
                io::ErrorKind::WriteZero,
                "authenticated write loop exited before completion",
            ),
            progress: retryable,
        }),
    }
}

/// Builds the retryable failure for a write that stopped before completion.
///
/// The loop only reaches this function with `written < message_len`, so the
/// classification is retryable. Should that ever stop holding, the committed
/// witness is dropped and the error is reported as a zero-progress failure
/// rather than silently authorizing a retry of a committed message.
fn failure(source: io::Error, written: usize, message_len: usize) -> CountedWriteError {
    let progress = match WriteProgress::from_written(written, message_len).split() {
        Err(retryable) => retryable,
        Ok(_committed) => RetryableProgress::NoBytesWritten,
    };
    debug_assert!(
        written < message_len,
        "counted write failure path reached with a completed message"
    );
    CountedWriteError { source, progress }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::io::AsyncWrite;

    use rr_session::RetryableProgress;

    use super::write_all_counted_before;

    struct ScriptedWriter {
        first_limit: usize,
        writes: usize,
        fail_after_first: bool,
    }

    impl AsyncWrite for ScriptedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            if self.fail_after_first && self.writes > 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "scripted failure",
                )));
            }
            self.writes += 1;
            Poll::Ready(Ok(bytes.len().min(self.first_limit)))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reports_complete_and_partial_boundaries_exactly() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut complete = ScriptedWriter {
            first_limit: 16,
            writes: 0,
            fail_after_first: false,
        };
        // Success can only be the commit witness; the type admits no other value.
        write_all_counted_before(&mut complete, b"authenticated", deadline)
            .await
            .expect("complete write must succeed")
            .commit_transport_ownership();

        let mut partial = ScriptedWriter {
            first_limit: 3,
            writes: 0,
            fail_after_first: true,
        };
        let error = write_all_counted_before(&mut partial, b"authenticated", deadline)
            .await
            .expect_err("the second write must fail");
        assert_eq!(
            error.progress(),
            RetryableProgress::PartialWrite { bytes_written: 3 }
        );
        assert_eq!(error.progress().bytes_discarded(), 3);

        let mut zero = ScriptedWriter {
            first_limit: 0,
            writes: 0,
            fail_after_first: false,
        };
        let error = write_all_counted_before(&mut zero, b"authenticated", deadline)
            .await
            .expect_err("a zero-byte write must fail");
        assert_eq!(error.progress(), RetryableProgress::NoBytesWritten);
        assert_eq!(error.progress().bytes_discarded(), 0);
    }

    #[tokio::test]
    async fn an_empty_message_commits_without_writing() {
        // No production authenticated message is empty, but the writer and the
        // pure classifier must not disagree about this boundary.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut writer = ScriptedWriter {
            first_limit: 0,
            writes: 0,
            fail_after_first: true,
        };
        write_all_counted_before(&mut writer, b"", deadline)
            .await
            .expect("an empty message is vacuously complete")
            .commit_transport_ownership();
        assert_eq!(writer.writes, 0, "an empty message must issue no write");
    }
}
