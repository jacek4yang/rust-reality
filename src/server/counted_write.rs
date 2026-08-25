//! Byte-precise bounded writes for single-use authenticated transports.

use std::{fmt, io};

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    time::{self, Instant},
};

/// Observable ownership progress at the retry boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteProgress {
    NoBytesWritten,
    PartialWrite { bytes_written: usize },
    CompleteWrite,
}

/// A write failed before the complete authenticated message was submitted.
#[derive(Debug)]
pub(crate) struct CountedWriteError {
    source: io::Error,
    progress: WriteProgress,
}

impl CountedWriteError {
    pub(crate) const fn progress(&self) -> WriteProgress {
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
pub(crate) async fn write_all_counted_before<W: AsyncWrite + Unpin>(
    stream: &mut W,
    bytes: &[u8],
    deadline: Instant,
) -> Result<WriteProgress, CountedWriteError> {
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
                ));
            }
            Ok(Ok(count)) => count,
            Ok(Err(error)) => return Err(failure(error, written)),
            Err(_) => {
                return Err(failure(
                    io::Error::new(io::ErrorKind::TimedOut, "authenticated write timed out"),
                    written,
                ));
            }
        };
        written = written.saturating_add(count);
    }
    Ok(WriteProgress::CompleteWrite)
}

fn failure(source: io::Error, written: usize) -> CountedWriteError {
    let progress = if written == 0 {
        WriteProgress::NoBytesWritten
    } else {
        WriteProgress::PartialWrite {
            bytes_written: written,
        }
    };
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

    use super::{WriteProgress, write_all_counted_before};

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
        assert_eq!(
            write_all_counted_before(&mut complete, b"authenticated", deadline)
                .await
                .expect("complete write must succeed"),
            WriteProgress::CompleteWrite
        );

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
            WriteProgress::PartialWrite { bytes_written: 3 }
        );

        let mut zero = ScriptedWriter {
            first_limit: 0,
            writes: 0,
            fail_after_first: false,
        };
        let error = write_all_counted_before(&mut zero, b"authenticated", deadline)
            .await
            .expect_err("a zero-byte write must fail");
        assert_eq!(error.progress(), WriteProgress::NoBytesWritten);
    }
}
