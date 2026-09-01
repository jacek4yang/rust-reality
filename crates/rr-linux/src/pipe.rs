//! Owned nonblocking pipe and splice operations for the Linux relay backend.

use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    io::Errno,
    pipe::{PipeFlags, SpliceFlags},
};

/// A CLOEXEC, nonblocking pipe with its effective kernel capacity.
///
/// The pipe owns both descriptors and closes them on drop; callers only ever
/// receive lifetime-bound borrows of them.
pub struct NonblockingPipe {
    read: OwnedFd,
    write: OwnedFd,
    capacity: usize,
}

impl NonblockingPipe {
    /// Opens a pipe and best-effort raises its capacity.
    ///
    /// # Errors
    ///
    /// Returns the kernel error from `pipe2(2)`. A capacity request that the
    /// kernel refuses is not an error: the effective capacity is read back, and
    /// `conservative_fallback` is used only when even that fails.
    pub fn open(requested_capacity: usize, conservative_fallback: usize) -> Result<Self, Errno> {
        let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
        let capacity = rustix::pipe::fcntl_setpipe_size(&write, requested_capacity)
            .or_else(|_| rustix::pipe::fcntl_getpipe_size(&write))
            .unwrap_or(conservative_fallback);
        Ok(Self {
            read,
            write,
            capacity,
        })
    }

    #[must_use]
    pub fn read_fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }

    #[must_use]
    pub fn write_fd(&self) -> BorrowedFd<'_> {
        self.write.as_fd()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Splices bytes without blocking, retrying interruption in the syscall layer.
///
/// # Errors
///
/// Returns the kernel error from `splice(2)`. `EAGAIN` is returned to the
/// caller, which is what drives the readiness loop; only `EINTR` is retried
/// here.
#[inline]
pub fn splice_nonblocking(
    input: impl AsFd,
    output: impl AsFd,
    length: usize,
) -> Result<usize, Errno> {
    let flags = SpliceFlags::MOVE | SpliceFlags::NONBLOCK;
    loop {
        match rustix::pipe::splice(input.as_fd(), None, output.as_fd(), None, length, flags) {
            Ok(transferred) => return Ok(transferred),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error),
        }
    }
}

/// Writes directly to a pipe; retained for boundary tests that poison pooled pipes.
///
/// # Errors
///
/// Returns the kernel error from `write(2)`.
#[inline]
pub fn write_nonblocking(output: impl AsFd, input: &[u8]) -> Result<usize, Errno> {
    rustix::io::write(output.as_fd(), input)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{NonblockingPipe, splice_nonblocking, write_nonblocking};
    use crate::socket::pending_input;

    #[test]
    fn a_pipe_is_close_on_exec_nonblocking_and_reports_its_capacity() {
        let pipe = NonblockingPipe::open(512 * 1024, 16 * 1024).expect("open a relay pipe");
        for fd in [pipe.read_fd(), pipe.write_fd()] {
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .expect("read descriptor flags")
                    .contains(rustix::io::FdFlags::CLOEXEC),
                "relay pipes must not leak across exec"
            );
            assert!(
                rustix::fs::fcntl_getfl(fd)
                    .expect("read file status flags")
                    .contains(rustix::fs::OFlags::NONBLOCK),
                "relay pipes must never block the reactor"
            );
        }
        assert!(
            pipe.capacity() >= 16 * 1024,
            "the effective capacity must be the kernel's answer, never zero"
        );
        assert_eq!(
            pipe.capacity(),
            rustix::pipe::fcntl_getpipe_size(pipe.write_fd()).expect("read the pipe size"),
            "the reported capacity must be the one the kernel actually applied"
        );
    }

    #[test]
    fn an_empty_pipe_reports_would_block_rather_than_zero() {
        let pipe = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open a relay pipe");
        let mut sink = [0_u8; 8];
        assert_eq!(
            rustix::io::read(pipe.read_fd(), &mut sink[..]).err(),
            Some(rustix::io::Errno::AGAIN),
            "a drained nonblocking pipe must not be mistaken for end of stream"
        );
    }

    #[test]
    fn splice_moves_bytes_between_two_pipes_and_leaves_the_source_drained() {
        let source = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open the source pipe");
        let sink = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open the sink pipe");

        assert_eq!(
            write_nonblocking(source.write_fd(), b"spliced").expect("stage bytes"),
            7
        );
        assert_eq!(
            splice_nonblocking(source.read_fd(), sink.write_fd(), 64 * 1024)
                .expect("splice between pipes"),
            7,
            "splice must move every staged byte"
        );
        assert_eq!(
            pending_input(source.read_fd()).expect("query the source"),
            0,
            "the source must be drained so the pool may recycle it"
        );
        assert_eq!(
            pending_input(sink.read_fd()).expect("query the sink"),
            7,
            "the bytes must be visible on the sink"
        );
    }

    #[test]
    fn splice_from_an_empty_source_reports_would_block() {
        let source = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open the source pipe");
        let sink = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open the sink pipe");
        assert_eq!(
            splice_nonblocking(source.read_fd(), sink.write_fd(), 64 * 1024).err(),
            Some(rustix::io::Errno::AGAIN),
            "an empty source must ask for readiness, never report end of stream"
        );
    }

    #[test]
    fn an_invalid_descriptor_propagates_the_kernel_error() {
        let pipe = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open a relay pipe");
        let closed = crate::socket::tests::always_invalid_fd();
        assert_eq!(
            splice_nonblocking(closed, pipe.write_fd(), 4_096).err(),
            Some(rustix::io::Errno::BADF)
        );
        assert_eq!(
            splice_nonblocking(pipe.read_fd(), closed, 4_096).err(),
            Some(rustix::io::Errno::BADF)
        );
        assert_eq!(
            write_nonblocking(closed, b"x").err(),
            Some(rustix::io::Errno::BADF)
        );
    }

    #[test]
    fn dropping_a_pipe_closes_both_descriptors_exactly_once() {
        use rustix::fd::AsRawFd as _;
        let pipe = NonblockingPipe::open(64 * 1024, 16 * 1024).expect("open a relay pipe");
        let numbers = [pipe.read_fd().as_raw_fd(), pipe.write_fd().as_raw_fd()];
        let before = numbers.map(crate::socket::tests::descriptor_identity);
        assert!(
            before.iter().all(Option::is_some),
            "a live pipe has both ends in /proc/self/fd"
        );
        drop(pipe);
        for (number, identity) in numbers.into_iter().zip(before) {
            assert_ne!(
                crate::socket::tests::descriptor_identity(number),
                identity,
                "a dropped pipe must leave no open descriptor behind"
            );
        }
    }
}
