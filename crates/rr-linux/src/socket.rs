//! Safe wrappers for the socket operations the relay path uses.
//!
//! * `SO_KEEPALIVE` is the kernel backstop against a peer that dies without
//!   a FIN.
//! * `SO_LINGER { on, 0 }` marks an aborted transfer so the peer observes a
//!   reset rather than a clean short EOF.
//! * `FIONREAD` reports userspace-visible queued input; the pipe pool uses it
//!   to refuse recycling a pipe that still holds unread bytes.

use std::{io, mem, os::fd::RawFd};

/// Returns whether `SO_KEEPALIVE` is enabled on `fd` (test/diagnostic use).
///
/// # Errors
///
/// Returns the kernel error from `getsockopt(SO_KEEPALIVE)`.
pub fn keepalive_enabled(fd: RawFd) -> io::Result<bool> {
    let mut value: libc::c_int = 0;
    let mut length = u32::try_from(mem::size_of::<libc::c_int>()).unwrap_or(4);
    // SAFETY: `getsockopt` writes at most `sizeof(c_int)` bytes through the
    // third argument; `value` is a live `c_int` of exactly that size, and
    // `length` starts at the writable capacity.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &raw mut value as *mut libc::c_void,
            &raw mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value != 0)
}

/// Enables the kernel keepalive backstop on `fd`.
///
/// The kernel probes a silent peer after `idle`, repeats every `interval`,
/// and declares it dead after `count` unanswered probes. The proxy's
/// application idle liveness bounds no-progress transfers; keepalive bounds
/// the failure the application cannot see — a peer that dies without a FIN
/// (lost NAT state, dead middlebox, lost link). Healthy connections pay three
/// probe packets per detection window and are otherwise unaffected; healthy
/// active transfers have no maximum duration from this mechanism.
///
/// # Errors
///
/// Returns the kernel error from any of the four `setsockopt` calls.
pub fn set_keepalive(
    fd: RawFd,
    idle: std::time::Duration,
    interval: std::time::Duration,
    count: u32,
) -> io::Result<()> {
    fn seconds(duration: std::time::Duration) -> libc::c_int {
        libc::c_int::try_from(duration.as_secs().max(1)).unwrap_or(libc::c_int::MAX)
    }
    set_int_option(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    set_int_option(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, seconds(idle))?;
    set_int_option(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        seconds(interval),
    )?;
    set_int_option(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPCNT,
        count as libc::c_int,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_int_option(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `setsockopt` reads exactly `sizeof(c_int)` bytes from the third
    // argument, which points at the live `value` of exactly that size for the
    // duration of the call. An invalid `fd` is reported by the kernel as
    // `EBADF`.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &raw const value as *const libc::c_void,
            u32::try_from(mem::size_of::<libc::c_int>()).unwrap_or(4),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Arms `SO_LINGER { on, 0 }` so closing `fd` sends a reset instead of a FIN.
///
/// An aborted transfer must be distinguishable from graceful completion: the
/// abort path marks the socket before close, and the peer observes `ECONNRESET`
/// rather than a clean short EOF. A descriptor that is already closed or reset
/// simply reports the kernel error, which callers are expected to ignore.
///
/// # Errors
///
/// Returns the kernel error from `setsockopt(SO_LINGER)`.
pub fn abort_linger(fd: RawFd) -> io::Result<()> {
    let value = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `setsockopt(SO_LINGER)` reads exactly `sizeof(linger)` bytes from
    // the third argument; `value` is a live `linger` of exactly that size, so
    // the pointer is valid for that read. An invalid `fd` is reported by the
    // kernel as `EBADF`.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &raw const value as *const libc::c_void,
            u32::try_from(mem::size_of::<libc::linger>()).unwrap_or(8),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Returns the number of userspace-visible queued input bytes on `fd`.
///
/// # Errors
///
/// Returns the kernel error from `ioctl(FIONREAD)`, including `EBADF` for an
/// invalid descriptor and `ENOTCONN`-family errors for a reset connection.
pub fn pending_input(fd: RawFd) -> io::Result<u32> {
    let mut value: libc::c_int = 0;
    // SAFETY: `FIONREAD` writes exactly one `c_int` through its third argument;
    // `value` is a live, exclusively owned `c_int`, so the pointer is valid for
    // that write. An invalid `fd` is reported by the kernel as `EBADF`.
    let result = unsafe { libc::ioctl(fd, libc::FIONREAD, &raw mut value) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(value).map_err(|_| io::Error::other("FIONREAD reported a negative queue length"))
}
