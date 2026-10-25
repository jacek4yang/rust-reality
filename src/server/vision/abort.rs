//! Abortive close guards for Vision relay sockets.
//!
//! Internal to [`crate::server::vision`]: `SO_LINGER {on,0}` arming and the
//! borrow-scoped guards that make an aborted transfer observably distinct from
//! a graceful FIN (#195).

use std::os::fd::{AsFd as _, BorrowedFd};

use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::protocol::reality::tls13::{TlsApplicationReader, TlsApplicationWriter};

use super::nested::NestedRecordReader;

/// A session socket an abort guard can reset while it still borrows it.
pub(super) trait AbortableSocket {
    /// Borrows the descriptor for the duration of the borrow of `self`.
    fn abort_fd(&self) -> BorrowedFd<'_>;

    /// Releases the socket without the graceful shutdown a normal drop performs.
    ///
    /// Tokio's `OwnedWriteHalf` shuts its direction down when dropped, which
    /// puts a FIN on the wire *ahead* of the abortive close. The peer reads
    /// that FIN as a clean end of stream and never observes the reset behind
    /// it, so arming `SO_LINGER {on,0}` alone does not deliver the contract.
    /// Every abort path therefore releases through this instead of dropping.
    ///
    /// Read halves and whole streams have nothing to suppress, so for them
    /// this is an ordinary drop.
    fn release_aborted(self);
}

impl AbortableSocket for TlsApplicationReader<OwnedReadHalf> {
    fn abort_fd(&self) -> BorrowedFd<'_> {
        self.fd()
    }

    fn release_aborted(self) {}
}

impl AbortableSocket for TlsApplicationWriter<OwnedWriteHalf> {
    fn abort_fd(&self) -> BorrowedFd<'_> {
        self.fd()
    }

    fn release_aborted(self) {
        let (half, _records, _key_update_response_pending) = self.into_handoff_parts();
        half.forget();
    }
}

impl AbortableSocket for OwnedReadHalf {
    fn abort_fd(&self) -> BorrowedFd<'_> {
        self.as_ref().as_fd()
    }

    fn release_aborted(self) {}
}

impl AbortableSocket for OwnedWriteHalf {
    fn abort_fd(&self) -> BorrowedFd<'_> {
        self.as_ref().as_fd()
    }

    fn release_aborted(self) {
        self.forget();
    }
}

impl AbortableSocket for NestedRecordReader {
    fn abort_fd(&self) -> BorrowedFd<'_> {
        self.fd()
    }

    fn release_aborted(self) {}
}

impl AbortableSocket for TcpStream {
    fn abort_fd(&self) -> BorrowedFd<'_> {
        self.as_fd()
    }

    fn release_aborted(self) {}
}

/// Marks `socket` so its close delivers a reset instead of a FIN.
///
/// The caller holds a borrow, which is what proves the descriptor is still
/// open and still the intended socket.
fn arm_abort(socket: &impl AbortableSocket) {
    let _ignored = rr_linux::socket::abort_linger(socket.abort_fd());
}

/// Resets one socket with `SO_LINGER {on,0}` unless it is disarmed.
///
/// Used where abort authority covers a single socket, or two sockets whose
/// lifetimes differ — one guard each, both dropping before either closes.
pub(super) struct SocketAbortGuard<'socket, S: AbortableSocket> {
    socket: &'socket S,
    disarmed: bool,
}

impl<'socket, S: AbortableSocket> SocketAbortGuard<'socket, S> {
    pub(super) const fn new(socket: &'socket S) -> Self {
        Self {
            socket,
            disarmed: false,
        }
    }

    pub(super) const fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<S: AbortableSocket> Drop for SocketAbortGuard<'_, S> {
    fn drop(&mut self) {
        if !self.disarmed {
            arm_abort(self.socket);
        }
    }
}

/// Resets both sockets of one relay direction unless it is disarmed —
/// cancellation via `try_join`, shutdown abort, or any error path. An aborted
/// transfer must be distinguishable from graceful completion: the peer
/// observes a reset, never a clean short EOF that could make a truncated
/// stream look complete. Graceful exits disarm the guard, preserving FIN and
/// independent half-close.
///
/// # Why this holds the borrows rather than descriptor numbers
///
/// The guard used to hold captured descriptor *numbers*, so it could outlive
/// the sockets it was meant to reset. When one direction finished before the
/// other failed, it did exactly that: both marks returned `EBADF` and the peer
/// received a clean FIN for a truncated transfer — the one outcome this type
/// exists to prevent (#195).
///
/// Holding the borrows makes the invariant structural instead of a matter of
/// drop-order discipline. A value cannot be moved, closed, or dropped while it
/// is mutably borrowed, so an armed guard is *provably* resetting a live
/// socket, and the borrow checker rejects any future edit that would hand a
/// socket onward without disarming first. The direction's I/O runs through
/// [`Self::parts_mut`], so the guard is the only owner of the borrows and
/// nothing aliases them.
pub(super) struct DirectionAbortGuard<'sockets, C: AbortableSocket, D: AbortableSocket> {
    client: &'sockets mut C,
    destination: &'sockets mut D,
    disarmed: bool,
}

impl<'sockets, C: AbortableSocket, D: AbortableSocket> DirectionAbortGuard<'sockets, C, D> {
    pub(super) const fn new(client: &'sockets mut C, destination: &'sockets mut D) -> Self {
        Self {
            client,
            destination,
            disarmed: false,
        }
    }

    /// Lends both sockets to the direction's framed phase.
    pub(super) const fn parts_mut(&mut self) -> (&mut C, &mut D) {
        (self.client, self.destination)
    }

    pub(super) const fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<C: AbortableSocket, D: AbortableSocket> Drop for DirectionAbortGuard<'_, C, D> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        arm_abort(self.client);
        arm_abort(self.destination);
    }
}
