//! One reusable idle deadline per connection direction.
//!
//! `tokio::time::timeout` builds and registers a fresh timer at every call, so
//! a relay chunk paid that cost once for its read and again for its write.
//! [`IdleDeadline`] keeps a single pinned `Sleep`: each progress step restarts
//! the same timer, giving one timer registration per progress step and no
//! per-operation timer construction at all.
//!
//! The semantics are an idle deadline, never a session-total cap: callers
//! reset the window at each progress step, so a transfer making steady
//! progress never times out while a stalled peer is bounded by the timeout.

use std::{fmt, io, pin::Pin, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, Sleep},
};

/// A reusable idle timeout shared by every operation of one direction.
///
/// The timer is created lazily on the first [`IdleDeadline::reset`], so the
/// value can be constructed outside a runtime and stays allocation-free until
/// it is actually armed. Operations polled through this value must follow a
/// `reset`; an operation polled after the window elapsed fails immediately.
#[derive(Debug, Default)]
pub struct IdleDeadline {
    sleep: Option<Pin<Box<Sleep>>>,
}

/// An operation guarded by an [`IdleDeadline`] failed.
#[derive(Debug)]
pub enum IdleError {
    /// No progress was made within the configured idle window.
    Timeout,
    /// The guarded socket operation failed.
    Io(io::Error),
}

impl fmt::Display for IdleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("idle operation timed out"),
            Self::Io(_) => formatter.write_str("idle-guarded socket I/O failed"),
        }
    }
}

impl std::error::Error for IdleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Timeout => None,
            Self::Io(source) => Some(source),
        }
    }
}

impl IdleDeadline {
    /// Creates an unarmed idle deadline without touching the timer.
    #[must_use]
    pub const fn new() -> Self {
        Self { sleep: None }
    }

    /// Restarts the idle window at the beginning of one progress step.
    ///
    /// The first reset allocates the pinned timer; every later reset reuses
    /// it, so a steady-state loop performs exactly one timer registration per
    /// progress step.
    ///
    /// # Errors
    ///
    /// Returns [`IdleError::Timeout`] when the deadline is not representable,
    /// matching the previous `Instant::now().checked_add(timeout)` behavior.
    pub fn reset(&mut self, timeout: Duration) -> Result<(), IdleError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(IdleError::Timeout)?;
        match &mut self.sleep {
            Some(sleep) => sleep.as_mut().reset(deadline),
            None => self.sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
        Ok(())
    }

    /// Reads once into `output` within the current idle window.
    ///
    /// # Errors
    ///
    /// Returns [`IdleError::Timeout`] when the window elapsed first, or the
    /// socket error of the read.
    pub async fn read<R>(&mut self, reader: &mut R, output: &mut [u8]) -> Result<usize, IdleError>
    where
        R: AsyncRead + Unpin,
    {
        self.guard(reader.read(output)).await
    }

    /// Writes `input` completely within the current idle window.
    ///
    /// # Errors
    ///
    /// Returns [`IdleError::Timeout`] when the window elapsed first, or the
    /// socket error of the write.
    pub async fn write_all<W>(&mut self, writer: &mut W, input: &[u8]) -> Result<(), IdleError>
    where
        W: AsyncWrite + Unpin,
    {
        self.guard(writer.write_all(input)).await
    }

    /// Shuts the writer down within the current idle window.
    ///
    /// # Errors
    ///
    /// Returns [`IdleError::Timeout`] when the window elapsed first, or the
    /// socket error of the shutdown.
    pub async fn shutdown<W>(&mut self, writer: &mut W) -> Result<(), IdleError>
    where
        W: AsyncWrite + Unpin,
    {
        self.guard(writer.shutdown()).await
    }

    /// Polls one socket operation against the current idle window.
    ///
    /// The operation is polled first, mirroring `tokio::time::timeout`: an
    /// operation that is immediately ready wins over an already elapsed
    /// window. `pub(crate)` so the raw relay backends can guard operations
    /// that are not plain `AsyncRead`/`AsyncWrite` calls (readiness-driven
    /// splice steps) through the same semantics.
    pub(crate) async fn guard<T, F>(&mut self, operation: F) -> Result<T, IdleError>
    where
        F: std::future::Future<Output = io::Result<T>>,
    {
        let Some(sleep) = self.sleep.as_mut() else {
            return Err(IdleError::Timeout);
        };
        tokio::select! {
            biased;
            result = operation => result.map_err(IdleError::Io),
            () = sleep => Err(IdleError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, duplex};

    use super::{IdleDeadline, IdleError};

    #[tokio::test(flavor = "current_thread")]
    async fn unarmed_deadline_fails_without_polling() {
        let (mut local, _remote) = duplex(64);
        let mut idle = IdleDeadline::new();

        let mut output = [0_u8; 8];
        assert!(matches!(
            idle.read(&mut local, &mut output).await,
            Err(IdleError::Timeout)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_operation_wins_over_an_elapsed_window() {
        let (mut local, mut remote) = duplex(64);
        remote
            .write_all(b"ping")
            .await
            .expect("peer write must succeed");
        let mut idle = IdleDeadline::new();
        idle.reset(Duration::ZERO)
            .expect("zero idle window must be representable");

        let mut output = [0_u8; 8];
        let read = idle
            .read(&mut local, &mut output)
            .await
            .expect("ready read must win over the elapsed window");
        assert_eq!(read, 4);
        assert_eq!(&output[..read], b"ping");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_operation_times_out_and_the_timer_is_reusable() {
        let (mut local, _remote) = duplex(64);
        let mut idle = IdleDeadline::new();
        let mut output = [0_u8; 8];

        for _ in 0..4 {
            idle.reset(Duration::from_millis(20))
                .expect("idle window must be representable");
            assert!(matches!(
                idle.read(&mut local, &mut output).await,
                Err(IdleError::Timeout)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn steady_progress_never_times_out_across_many_steps() {
        let (mut local, mut remote) = duplex(64);
        let mut idle = IdleDeadline::new();
        let mut output = [0_u8; 4];

        for step in 0..64_u8 {
            remote
                .write_all(&[step; 4])
                .await
                .expect("peer write must succeed");
            idle.reset(Duration::from_millis(50))
                .expect("idle window must be representable");
            let read = idle
                .read(&mut local, &mut output)
                .await
                .expect("progress within the window must succeed");
            assert_eq!(read, 4);
            assert_eq!(output, [step; 4]);
        }
    }
}
