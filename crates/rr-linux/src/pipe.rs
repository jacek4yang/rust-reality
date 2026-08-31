//! Owned nonblocking pipe and splice operations for the Linux relay backend.

use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

/// A CLOEXEC, nonblocking pipe with its effective kernel capacity.
pub struct NonblockingPipe {
    read: OwnedFd,
    write: OwnedFd,
    capacity: usize,
}

impl NonblockingPipe {
    /// Opens a pipe and best-effort raises its capacity.
    pub fn open(requested_capacity: usize, conservative_fallback: usize) -> io::Result<Self> {
        let (read, write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .map_err(io::Error::from)?;
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
#[inline]
pub fn splice_nonblocking(input: impl AsFd, output: impl AsFd, length: usize) -> io::Result<usize> {
    let flags = rustix::pipe::SpliceFlags::MOVE | rustix::pipe::SpliceFlags::NONBLOCK;
    loop {
        match rustix::pipe::splice(input.as_fd(), None, output.as_fd(), None, length, flags) {
            Ok(transferred) => return Ok(transferred),
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

/// Writes directly to a pipe; retained for boundary tests that poison pooled pipes.
#[inline]
pub fn write_nonblocking(output: impl AsFd, input: &[u8]) -> io::Result<usize> {
    rustix::io::write(output.as_fd(), input).map_err(io::Error::from)
}
