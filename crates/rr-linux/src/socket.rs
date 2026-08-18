//! Safe wrappers for the socket operations the relay path uses.
//!
//! * `SO_KEEPALIVE` is the kernel backstop against a peer that dies without
//!   a FIN.
//! * `SO_LINGER { on, 0 }` marks an aborted transfer so the peer observes a
//!   reset rather than a clean short EOF.
//! * `FIONREAD` reports userspace-visible queued input; the pipe pool uses it
//!   to refuse recycling a pipe that still holds unread bytes.

use std::{
    io, mem,
    net::{SocketAddr, SocketAddrV6, TcpListener},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

/// Creates, configures, and binds a nonblocking IPv6 TCP listener with
/// `IPV6_V6ONLY=1` set before `bind(2)`.
///
/// Setting the option before bind is essential: it makes a separate IPv4 and
/// IPv6 wildcard socket deterministic regardless of the host's
/// `net.ipv6.bindv6only` value.
///
/// # Errors
///
/// Returns the kernel error from `socket`, `setsockopt`, `bind`, or `listen`,
/// or `InvalidInput` when `address` is not IPv6.
pub fn bind_tcp_listener_v6only(address: SocketAddr) -> io::Result<TcpListener> {
    let SocketAddr::V6(address) = address else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 listener requires an IPv6 address",
        ));
    };
    // SAFETY: `socket` has no pointer arguments. On success the returned raw
    // descriptor is uniquely owned and is immediately wrapped in `OwnedFd`.
    let raw = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh successful `socket` result and ownership is
    // transferred exactly once to `OwnedFd`.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_int_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    set_int_option(fd.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    bind_ipv6(fd.as_raw_fd(), &address)?;
    // SAFETY: the descriptor is a bound `SOCK_STREAM`; `listen` takes no
    // pointers and leaves ownership with `fd` on both success and failure.
    if unsafe { libc::listen(fd.as_raw_fd(), libc::SOMAXCONN) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

fn bind_ipv6(fd: RawFd, address: &SocketAddrV6) -> io::Result<()> {
    let raw = libc::sockaddr_in6 {
        sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).unwrap_or_default(),
        sin6_port: address.port().to_be(),
        sin6_flowinfo: address.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: address.ip().octets(),
        },
        sin6_scope_id: address.scope_id(),
    };
    // SAFETY: `raw` is a live initialized `sockaddr_in6`; the pointer and
    // exact structure size remain valid for the duration of `bind`.
    let result = unsafe {
        libc::bind(
            fd,
            (&raw as *const libc::sockaddr_in6).cast::<libc::sockaddr>(),
            u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap_or(u32::MAX),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reports `IPV6_V6ONLY` for a socket (test and diagnostic use).
///
/// # Errors
///
/// Returns the kernel error from `getsockopt(IPV6_V6ONLY)`.
pub fn ipv6_only(fd: RawFd) -> io::Result<bool> {
    let mut value: libc::c_int = 0;
    let mut length = u32::try_from(mem::size_of::<libc::c_int>()).unwrap_or(4);
    // SAFETY: `getsockopt` writes at most `sizeof(c_int)` bytes into the live
    // `value`; `length` advertises exactly that capacity.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &raw mut value as *mut libc::c_void,
            &raw mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value != 0)
}

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
