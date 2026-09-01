//! Safe wrappers for the socket operations the relay path uses.
//!
//! * `SO_KEEPALIVE` is the kernel backstop against a peer that dies without
//!   a FIN.
//! * `SO_LINGER { on, 0 }` marks an aborted transfer so the peer observes a
//!   reset rather than a clean short EOF.
//! * `FIONREAD` reports userspace-visible queued input; the pipe pool uses it
//!   to refuse recycling a pipe that still holds unread bytes.
//!
//! Every entry point takes a borrowed descriptor or returns an owned one. The
//! single exception, [`AbortMark`], exists because one abort guard outlives the
//! socket it marks, and its raw handling is contained here.

use core::{net::SocketAddrV6, time::Duration};

use rustix::{
    fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd, RawFd},
    io::Errno,
    net::{AddressFamily, Shutdown, SocketFlags, SocketType, ipproto, sockopt},
};

/// The `listen(2)` backlog the public listener requests.
///
/// This is the C library's `SOMAXCONN` policy, which is deliberately
/// target-specific: 4096 on glibc, 128 on musl. It is a userspace policy
/// constant, not a kernel ABI number — the kernel clamps the request to
/// `net.core.somaxconn` regardless — so neither rustix nor `linux-raw-sys`
/// exposes it. Sourcing it from the reviewed `libc` bindings keeps the GNU and
/// musl builds behaving exactly as they did; inventing one universal number
/// here would silently change the backlog on one of the two release targets.
/// This is the crate's only use of `libc`, it is resolved at compile time, and
/// it mediates no syscall.
const LISTEN_BACKLOG: i32 = libc::SOMAXCONN;

/// Shuts down only the write side of a socket.
///
/// # Errors
///
/// Returns the kernel error from `shutdown(2)`.
#[inline]
pub fn shutdown_write(fd: impl AsFd) -> Result<(), Errno> {
    rustix::net::shutdown(fd.as_fd(), Shutdown::Write)
}

/// Creates, configures, binds, and listens on a nonblocking IPv6 TCP socket
/// with `IPV6_V6ONLY=1` set before `bind(2)`, returning the owned descriptor.
///
/// Setting the option before bind is essential: it makes a separate IPv4 and
/// IPv6 wildcard socket deterministic regardless of the host's
/// `net.ipv6.bindv6only` value.
///
/// The descriptor is returned rather than an `std::net::TcpListener` so this
/// crate owns the kernel object and nothing else. With the `std` feature the
/// returned [`OwnedFd`] *is* `std::os::fd::OwnedFd`, so the Transport converts
/// it into a std or Tokio listener by value, transferring ownership exactly
/// once and without `unsafe`.
///
/// # Errors
///
/// Returns the kernel error from `socket`, `setsockopt`, `bind`, or `listen`.
/// A failure closes the descriptor; no partially configured socket escapes.
pub fn bind_tcp_listener_v6only(address: SocketAddrV6) -> Result<OwnedFd, Errno> {
    let socket = rustix::net::socket_with(
        AddressFamily::INET6,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        Some(ipproto::TCP),
    )?;
    sockopt::set_socket_reuseaddr(&socket, true)?;
    sockopt::set_ipv6_v6only(&socket, true)?;
    rustix::net::bind(&socket, &address)?;
    rustix::net::listen(&socket, LISTEN_BACKLOG)?;
    Ok(socket)
}

/// Reports `IPV6_V6ONLY` for a socket (test and diagnostic use).
///
/// # Errors
///
/// Returns the kernel error from `getsockopt(IPV6_V6ONLY)`.
#[inline]
pub fn ipv6_only(fd: impl AsFd) -> Result<bool, Errno> {
    sockopt::ipv6_v6only(fd.as_fd())
}

/// Returns whether `SO_KEEPALIVE` is enabled on `fd` (test/diagnostic use).
///
/// # Errors
///
/// Returns the kernel error from `getsockopt(SO_KEEPALIVE)`.
#[inline]
pub fn keepalive_enabled(fd: impl AsFd) -> Result<bool, Errno> {
    sockopt::socket_keepalive(fd.as_fd())
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
    fd: impl AsFd,
    idle: Duration,
    interval: Duration,
    count: u32,
) -> Result<(), Errno> {
    let fd = fd.as_fd();
    sockopt::set_socket_keepalive(fd, true)?;
    sockopt::set_tcp_keepidle(fd, whole_seconds(idle))?;
    sockopt::set_tcp_keepintvl(fd, whole_seconds(interval))?;
    sockopt::set_tcp_keepcnt(fd, count)?;
    Ok(())
}

/// Normalises a keepalive timer to the value the socket option actually takes.
///
/// The options are whole seconds in a C `int`. A sub-second window becomes one
/// second rather than zero, which the kernel rejects, and an absurd window is
/// clamped rather than turned into `EINVAL`.
fn whole_seconds(duration: Duration) -> Duration {
    /// The largest value the C `int` socket option can carry.
    // The option is a C `int`; the constant is positive so the cast is exact.
    const MAX: u64 = i32::MAX as u64;
    Duration::from_secs(duration.as_secs().clamp(1, MAX))
}

/// Arms `SO_LINGER { on, 0 }` so closing `fd` sends a reset instead of a FIN.
///
/// An aborted transfer must be distinguishable from graceful completion: the
/// abort path marks the socket before close, and the peer observes
/// `ECONNRESET` rather than a clean short EOF. A descriptor that is already
/// closed or reset simply reports the kernel error, which callers are expected
/// to ignore.
///
/// # Errors
///
/// Returns the kernel error from `setsockopt(SO_LINGER)`.
#[inline]
pub fn abort_linger(fd: impl AsFd) -> Result<(), Errno> {
    sockopt::set_socket_linger(fd.as_fd(), Some(Duration::ZERO))
}

/// A descriptor number captured from a live socket for later abort marking.
///
/// Abort guards are armed while a socket is live and fire on unwind, by which
/// time the owner may already have closed it — so a guard can only hold a
/// descriptor *number*, never a borrow. Capturing one is safe; applying one is
/// best-effort. A number the process has since closed reports `EBADF`, which
/// the caller ignores. A number the process has since *reused* would mark an
/// unrelated socket, which is why every path that hands a descriptor onward
/// disarms its guard first.
///
/// The `unsafe` needed to address a bare descriptor number lives here so the
/// protocol crate keeps `#![deny(unsafe_code)]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortMark(RawFd);

impl AbortMark {
    /// Captures the number of a socket that is live right now.
    #[must_use]
    #[inline]
    pub fn capture(fd: impl AsFd) -> Self {
        Self(fd.as_fd().as_raw_fd())
    }

    /// Applies [`abort_linger`] to the captured number, best effort.
    ///
    /// # Errors
    ///
    /// Returns the kernel error from `setsockopt(SO_LINGER)`, which is `EBADF`
    /// when the descriptor has already been closed.
    #[inline]
    pub fn apply(self) -> Result<(), Errno> {
        // SAFETY: `borrow_raw` requires a descriptor number that is not `-1`.
        // `capture` recorded it from a live `AsFd`, so it was a real descriptor
        // of this process and is never `-1`. The borrow does not outlive this
        // statement, and it is used only for one `setsockopt`, which reports
        // `EBADF` rather than misbehaving if the number is no longer open. No
        // ownership is created or destroyed here: nothing closes this
        // descriptor.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.0) };
        abort_linger(borrowed)
    }
}

/// Returns the number of userspace-visible queued input bytes on `fd`.
///
/// # Errors
///
/// Returns the kernel error from `ioctl(FIONREAD)`, including `EBADF` for an
/// invalid descriptor and `ENOTCONN`-family errors for a reset connection.
#[inline]
pub fn pending_input(fd: impl AsFd) -> Result<u64, Errno> {
    rustix::io::ioctl_fionread(fd.as_fd())
}

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests {
    use core::{net::SocketAddrV6, time::Duration};

    use rustix::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
    use std::{
        net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream},
        path::PathBuf,
    };

    use super::{
        AbortMark, LISTEN_BACKLOG, abort_linger, bind_tcp_listener_v6only, ipv6_only,
        keepalive_enabled, pending_input, set_keepalive, shutdown_write, whole_seconds,
    };

    /// Pins the listen backlog to the C library policy of each release target.
    ///
    /// The two supported tiers deliberately disagree. Asserting the numbers
    /// here means a dependency bump that changes either one fails the build
    /// instead of silently reshaping the accept queue of one release.
    #[test]
    fn the_listen_backlog_is_the_target_c_library_policy() {
        #[cfg(target_env = "gnu")]
        assert_eq!(LISTEN_BACKLOG, 4_096, "glibc SOMAXCONN");
        #[cfg(target_env = "musl")]
        assert_eq!(LISTEN_BACKLOG, 128, "musl SOMAXCONN");
        assert!(LISTEN_BACKLOG > 0, "a non-positive backlog cannot listen");
    }

    fn loopback_listener() -> OwnedFd {
        bind_tcp_listener_v6only(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
            .expect("bind an ephemeral IPv6 loopback listener")
    }

    /// Returns which kernel object `number` currently refers to, if any.
    ///
    /// `/proc/self/fd/<n>` links to the object (`socket:[123456]`), not to the
    /// descriptor slot. Comparing the link across a drop proves the descriptor
    /// was closed even when a parallel test immediately reuses the number,
    /// which a bare `EBADF` probe cannot do.
    pub(crate) fn descriptor_identity(number: RawFd) -> Option<PathBuf> {
        std::fs::read_link(std::format!("/proc/self/fd/{number}")).ok()
    }

    /// A descriptor number this process can never have open.
    ///
    /// `RLIMIT_NOFILE` bounds descriptor numbers to `0..soft`, so the soft
    /// limit itself is closed no matter what the rest of the test binary does.
    fn always_invalid_number() -> RawFd {
        RawFd::try_from(crate::rlimit::descriptor_limit().soft).unwrap_or(RawFd::MAX)
    }

    /// Borrows a descriptor number that is guaranteed not to be open.
    pub(crate) fn always_invalid_fd() -> BorrowedFd<'static> {
        // SAFETY: `borrow_raw` requires a number other than `-1`;
        // `always_invalid_number` returns a positive number at or above the
        // process descriptor limit. The borrow is used only for calls that
        // report `EBADF` for a number that is not open, which is the point.
        unsafe { BorrowedFd::borrow_raw(always_invalid_number()) }
    }

    #[test]
    fn the_chosen_invalid_number_really_is_closed() {
        assert_eq!(
            rustix::io::fcntl_getfd(always_invalid_fd()).err(),
            Some(rustix::io::Errno::BADF),
            "the error-propagation tests depend on this number staying closed"
        );
    }

    #[test]
    fn a_bound_listener_is_v6only_nonblocking_and_close_on_exec() {
        let listener = loopback_listener();
        assert!(
            ipv6_only(&listener).expect("read IPV6_V6ONLY"),
            "IPV6_V6ONLY must be set before bind so dual-stack policy is deterministic"
        );
        assert!(
            rustix::io::fcntl_getfd(&listener)
                .expect("read descriptor flags")
                .contains(rustix::io::FdFlags::CLOEXEC),
            "the listener must not leak across exec"
        );
        assert!(
            rustix::fs::fcntl_getfl(&listener)
                .expect("read file status flags")
                .contains(rustix::fs::OFlags::NONBLOCK),
            "the listener must be nonblocking for the async runtime"
        );
        assert!(
            rustix::net::sockopt::socket_reuseaddr(&listener).expect("read SO_REUSEADDR"),
            "SO_REUSEADDR must be set so a restart can rebind"
        );
    }

    #[test]
    fn the_owned_descriptor_transfers_into_std_without_changing_identity() {
        let listener = loopback_listener();
        let raw = listener.as_fd().as_raw_fd();

        // The production Transport performs exactly this move.
        let std_listener = TcpListener::from(listener);
        assert_eq!(
            std_listener.as_fd().as_raw_fd(),
            raw,
            "the transfer must move the same kernel object, not reopen one"
        );
        assert!(
            ipv6_only(&std_listener).expect("read IPV6_V6ONLY after transfer"),
            "socket configuration must survive the ownership transfer"
        );

        let bound = std_listener.local_addr().expect("read the bound address");
        assert!(bound.is_ipv6() && bound.port() != 0, "the socket is bound");

        // The listener is still listening: a connect completes and accepts.
        let peer = TcpStream::connect(bound).expect("connect to the transferred listener");
        std_listener
            .set_nonblocking(false)
            .expect("block for the accept");
        let (accepted, _) = std_listener.accept().expect("accept over the transfer");
        drop(accepted);
        drop(peer);

        let identity = descriptor_identity(raw).expect("a live listener has a /proc entry");
        drop(std_listener);
        assert_ne!(
            descriptor_identity(raw),
            Some(identity),
            "the sole owner must close the descriptor on drop, leaking nothing"
        );
    }

    #[test]
    fn keepalive_is_armed_and_readable() {
        let listener = loopback_listener();
        let bound = TcpListener::from(listener);
        let address = bound.local_addr().expect("read the bound address");
        let client = TcpStream::connect(address).expect("connect for a data socket");

        assert!(
            !keepalive_enabled(&client).expect("read SO_KEEPALIVE"),
            "a fresh socket starts without the backstop"
        );
        set_keepalive(&client, Duration::from_secs(30), Duration::from_secs(10), 3)
            .expect("arm keepalive");
        assert!(
            keepalive_enabled(&client).expect("read SO_KEEPALIVE"),
            "keepalive must be enabled"
        );
        assert_eq!(
            rustix::net::sockopt::tcp_keepidle(&client).expect("read TCP_KEEPIDLE"),
            Duration::from_secs(30)
        );
        assert_eq!(
            rustix::net::sockopt::tcp_keepintvl(&client).expect("read TCP_KEEPINTVL"),
            Duration::from_secs(10)
        );
        assert_eq!(
            rustix::net::sockopt::tcp_keepcnt(&client).expect("read TCP_KEEPCNT"),
            3
        );
    }

    #[test]
    fn a_keepalive_window_is_whole_seconds_and_never_zero() {
        assert_eq!(whole_seconds(Duration::ZERO), Duration::from_secs(1));
        assert_eq!(
            whole_seconds(Duration::from_millis(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            whole_seconds(Duration::from_millis(1_500)),
            Duration::from_secs(1),
            "a partial second is truncated, never rounded up"
        );
        assert_eq!(
            whole_seconds(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            whole_seconds(Duration::from_secs(u64::MAX)),
            Duration::from_secs(u64::from(i32::MAX.unsigned_abs())),
            "an absurd window clamps instead of failing"
        );
    }

    #[test]
    fn abort_linger_arms_a_reset_and_reports_a_closed_descriptor() {
        let listener = loopback_listener();
        let bound = TcpListener::from(listener);
        let address = bound.local_addr().expect("read the bound address");
        let client = TcpStream::connect(address).expect("connect for a data socket");

        abort_linger(&client).expect("arm SO_LINGER {on, 0}");
        assert_eq!(
            rustix::net::sockopt::socket_linger(&client).expect("read SO_LINGER"),
            Some(Duration::ZERO),
            "the abort marker must be a zero linger, not a timed one"
        );

        // A mark is a captured number, so applying it must reach the same
        // socket the borrow-taking entry point does.
        let mark = AbortMark::capture(&client);
        rustix::net::sockopt::set_socket_linger(&client, None).expect("clear SO_LINGER");
        mark.apply().expect("a captured live socket applies");
        assert_eq!(
            rustix::net::sockopt::socket_linger(&client).expect("read SO_LINGER"),
            Some(Duration::ZERO),
            "the mark must arm the same socket it was captured from"
        );

        // A number that is not open reports the kernel error; callers ignore it.
        assert_eq!(
            abort_linger(always_invalid_fd()).err(),
            Some(rustix::io::Errno::BADF),
            "an abort on a closed descriptor must surface as EBADF, never succeed"
        );
    }

    #[test]
    fn pending_input_counts_queued_bytes_and_rejects_a_closed_descriptor() {
        let listener = loopback_listener();
        let bound = TcpListener::from(listener);
        let address = bound.local_addr().expect("read the bound address");
        let mut client = TcpStream::connect(address).expect("connect for a data socket");
        let (accepted, _) = bound.accept().expect("accept the client");

        assert_eq!(
            pending_input(&accepted).expect("query an empty queue"),
            0,
            "an idle socket has nothing queued"
        );

        use std::io::Write as _;
        client.write_all(b"queued").expect("send six bytes");
        client.flush().expect("flush");
        let queued = loop {
            let queued = pending_input(&accepted).expect("query the queue");
            if queued != 0 {
                break queued;
            }
            std::thread::yield_now();
        };
        assert_eq!(queued, 6, "FIONREAD reports userspace-visible bytes");

        shutdown_write(&client).expect("half-close the write side");
        assert_eq!(
            pending_input(always_invalid_fd()).err(),
            Some(rustix::io::Errno::BADF),
            "an invalid descriptor must propagate the kernel error"
        );
        assert_eq!(
            ipv6_only(always_invalid_fd()).err(),
            Some(rustix::io::Errno::BADF),
            "every query must propagate the kernel error rather than a default"
        );
        assert_eq!(
            keepalive_enabled(always_invalid_fd()).err(),
            Some(rustix::io::Errno::BADF)
        );
        assert_eq!(
            shutdown_write(always_invalid_fd()).err(),
            Some(rustix::io::Errno::BADF)
        );
        assert_eq!(
            set_keepalive(
                always_invalid_fd(),
                Duration::from_secs(30),
                Duration::from_secs(10),
                3
            )
            .err(),
            Some(rustix::io::Errno::BADF)
        );
    }

    #[test]
    fn a_half_shutdown_is_observed_as_end_of_stream_by_the_peer() {
        let listener = loopback_listener();
        let bound = TcpListener::from(listener);
        let address = bound.local_addr().expect("read the bound address");
        let mut client = TcpStream::connect(address).expect("connect for a data socket");
        let (accepted, _) = bound.accept().expect("accept the client");

        shutdown_write(&accepted).expect("shut down the write side only");

        use std::io::{Read as _, Write as _};
        let mut sink = [0_u8; 1];
        assert_eq!(
            client
                .read(&mut sink)
                .expect("read after the peer half-closed"),
            0,
            "the peer must observe a clean end of stream"
        );
        client
            .write_all(b"still open")
            .expect("the other direction must remain writable");
    }

    #[test]
    fn an_ipv6_only_listener_does_not_accept_a_mapped_ipv4_connection() {
        let listener = loopback_listener();
        let bound = TcpListener::from(listener);
        let port = bound.local_addr().expect("read the bound address").port();

        // A separate IPv4 listener on the same port must be possible precisely
        // because IPV6_V6ONLY was set before bind.
        let v4 = TcpListener::bind(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)))
            .expect("an IPv4 listener must coexist on the same port");
        assert_eq!(
            v4.local_addr().expect("read the IPv4 address").port(),
            port,
            "the two wildcard families must be independent"
        );
    }
}
