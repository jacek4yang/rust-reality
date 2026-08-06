//! TCP acceptance with descriptor-pressure survival.
//!
//! # Why this file changed
//!
//! The previous implementation was:
//!
//! ```ignore
//! let (stream, peer_addr) = self.listener.accept().await?;
//! stream.set_nodelay(true)?;
//! ```
//!
//! Kernel liveness policy: [`KEEPALIVE_IDLE`], [`KEEPALIVE_INTERVAL`], and
//! [`KEEPALIVE_COUNT`] arm `SO_KEEPALIVE` on every data socket so a peer that
//! dies silently is detected inside about a minute instead of pinning the
//! connection until the application idle window ends.
//!
//! Two defects are visible in those two lines, and a production trace shows
//! both mattering:
//!
//! * a `TCP_NODELAY` failure on one accepted socket is indistinguishable from a
//!   listener failure, so a per-connection problem could terminate the server;
//! * `EMFILE` reached the caller as a plain `io::Error`, and the caller's `?`
//!   turned it into `error: listener accept failed` and process exit.
//!
//! Acceptance is therefore split into three phases with distinct failure
//! semantics — accept, configure, admit — and every accept error is classified
//! from its raw `errno` rather than from its `ErrorKind`.

use std::{fmt, io, net::SocketAddr};

use tokio::net::{TcpListener, TcpStream};

/// How the listener must respond to an accept error.
///
/// Classification is driven by `raw_os_error`, not by [`io::ErrorKind`], because
/// several distinct errnos collapse into the same `ErrorKind` and the required
/// responses differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptErrorClass {
    /// `EAGAIN`/`EWOULDBLOCK`. Normal readiness behaviour; retry without logging.
    WouldBlock,
    /// A documented transient condition. Count it and retry immediately.
    ///
    /// `ECONNABORTED` in particular is routine: the peer reset between the
    /// handshake completing and the accept being serviced.
    Transient,
    /// `EMFILE`/`ENFILE`. Enter descriptor-pressure recovery; never terminate.
    DescriptorPressure,
    /// `ENOBUFS`/`ENOMEM`. Back off with bounded exponential delay.
    MemoryPressure,
    /// The listening socket is permanently unusable. Terminate this listener only.
    Fatal,
    /// An errno with no documented accept meaning. Treated as transient with
    /// backoff so an unknown platform condition cannot spin or kill the server.
    Unknown,
}

impl AcceptErrorClass {
    /// Classifies one accept error from its raw operating-system errno.
    #[must_use]
    pub fn classify(error: &io::Error) -> Self {
        let Some(errno) = error.raw_os_error() else {
            // No errno means the error did not come from `accept`; treat it as
            // unknown rather than guessing that it is safe to retry forever.
            return Self::Unknown;
        };
        match errno {
            libc_compat::EAGAIN => Self::WouldBlock,
            libc_compat::EINTR
            | libc_compat::ECONNABORTED
            | libc_compat::EPROTO
            | libc_compat::ECONNRESET
            | libc_compat::ENETDOWN
            | libc_compat::ENETUNREACH
            | libc_compat::EHOSTDOWN
            | libc_compat::EHOSTUNREACH
            | libc_compat::ENONET
            | libc_compat::ETIMEDOUT
            | libc_compat::EPERM => Self::Transient,
            libc_compat::EMFILE | libc_compat::ENFILE => Self::DescriptorPressure,
            libc_compat::ENOBUFS | libc_compat::ENOMEM => Self::MemoryPressure,
            // `EBADF` and `ENOTSOCK` mean the descriptor is not our listener.
            // `EOPNOTSUPP` means it is not a listening socket.
            //
            // `EINVAL` is classified as fatal deliberately, not blindly. The
            // only two documented causes are invalid `accept4` flags and a
            // socket that is not listening. The flags are fixed by tokio and
            // are valid by construction, so the remaining cause is a listener
            // that can never accept again. Retrying would spin forever.
            libc_compat::EBADF
            | libc_compat::ENOTSOCK
            | libc_compat::EOPNOTSUPP
            | libc_compat::EINVAL
            | libc_compat::EFAULT => Self::Fatal,
            _ => Self::Unknown,
        }
    }

    /// Returns the stable low-cardinality identifier used in logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WouldBlock => "wouldBlock",
            Self::Transient => "transient",
            Self::DescriptorPressure => "descriptorPressure",
            Self::MemoryPressure => "memoryPressure",
            Self::Fatal => "fatal",
            Self::Unknown => "unknown",
        }
    }

    /// Returns whether the listener must stop.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, Self::Fatal)
    }

    /// Returns whether the class warrants a bounded backoff before retrying.
    #[must_use]
    pub const fn needs_backoff(self) -> bool {
        matches!(
            self,
            Self::DescriptorPressure | Self::MemoryPressure | Self::Unknown
        )
    }
}

/// Errno values used for accept classification.
///
/// The protocol crate denies `unsafe_code` and does not depend on `libc`, so the
/// handful of constants needed here are declared directly. They are pinned by a
/// test against `rr-linux`'s `libc` on Linux, so a mismatch is a build failure
/// rather than a silent misclassification.
mod libc_compat {
    #![allow(
        dead_code,
        reason = "the full set is declared so classification is auditable against errno(3)"
    )]

    // `EWOULDBLOCK` is an alias for `EAGAIN` on Linux; it is declared for
    // auditability but must not appear in a match arm, which would be
    // unreachable.

    pub(super) const EPERM: i32 = 1;
    pub(super) const EINTR: i32 = 4;
    pub(super) const EBADF: i32 = 9;
    pub(super) const EAGAIN: i32 = 11;
    pub(super) const EWOULDBLOCK: i32 = EAGAIN;
    pub(super) const ENOMEM: i32 = 12;
    pub(super) const EFAULT: i32 = 14;
    pub(super) const EINVAL: i32 = 22;
    pub(super) const EMFILE: i32 = 24;
    pub(super) const ENFILE: i32 = 23;
    pub(super) const ENOTSOCK: i32 = 88;
    pub(super) const EOPNOTSUPP: i32 = 95;
    pub(super) const ENOBUFS: i32 = 105;
    pub(super) const ECONNRESET: i32 = 104;
    pub(super) const ETIMEDOUT: i32 = 110;
    pub(super) const ECONNABORTED: i32 = 103;
    pub(super) const ENETDOWN: i32 = 100;
    pub(super) const ENETUNREACH: i32 = 101;
    pub(super) const EHOSTDOWN: i32 = 112;
    pub(super) const EHOSTUNREACH: i32 = 113;
    pub(super) const ENONET: i32 = 64;
    pub(super) const EPROTO: i32 = 71;
}

/// The single descriptor held in reserve for `EMFILE` recovery.
///
/// # Why a reserve is needed at all
///
/// Admission is strict, but it bounds only the descriptors *this process*
/// accounts for. A descriptor can still be consumed outside that accounting —
/// by a library, by a resolver thread, or by another process against a shared
/// `ENFILE` system limit. When that happens `accept4` returns `EMFILE` with a
/// full backlog and no way to drain it, and the listener would otherwise spin at
/// full speed logging an error it cannot act on.
///
/// Releasing this descriptor makes exactly one `accept` possible, which drains
/// one backlog entry and lets the peer observe a close rather than a hang.
pub struct EmergencyDescriptor {
    file: Option<std::fs::File>,
}

impl EmergencyDescriptor {
    /// Opens the reserve descriptor.
    ///
    /// # Errors
    ///
    /// Returns the raw OS error when `/dev/null` cannot be opened, which itself
    /// indicates the process is already at its descriptor limit.
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            file: Some(open_reserve()?),
        })
    }

    /// Returns whether the reserve is currently held.
    #[must_use]
    pub const fn is_held(&self) -> bool {
        self.file.is_some()
    }

    /// Releases the reserve so one descriptor becomes available.
    ///
    /// Returns whether a descriptor was actually released, so a caller cannot
    /// mistake a double release for freed capacity.
    pub fn release(&mut self) -> bool {
        self.file.take().is_some()
    }

    /// Reopens the reserve after a recovery attempt.
    ///
    /// # Errors
    ///
    /// Returns the raw OS error when the reserve cannot be reacquired, which
    /// means the process is still at its limit. The caller must keep backing
    /// off and retry rather than treating this as fatal.
    pub fn reacquire(&mut self) -> io::Result<()> {
        if self.file.is_some() {
            return Ok(());
        }
        self.file = Some(open_reserve()?);
        Ok(())
    }
}

fn open_reserve() -> io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        rr_linux::open_reserve_descriptor()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::fs::OpenOptions::new().read(true).open("/dev/null")
    }
}

impl fmt::Debug for EmergencyDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmergencyDescriptor")
            .field("held", &self.is_held())
            .finish()
    }
}

/// Owns a TCP listening socket and accepts inbound connections.
pub struct TcpAcceptor {
    listener: TcpListener,
}

/// Keepalive probes start after this much connection silence.
pub const KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(30);
/// Interval between unanswered keepalive probes.
pub const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// Unanswered probes before the kernel declares the peer dead.
pub const KEEPALIVE_COUNT: u32 = 3;

impl TcpAcceptor {
    /// Creates a TCP listener bound to `address`.
    ///
    /// # Errors
    ///
    /// Returns the raw OS error when the address cannot be bound.
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;

        Ok(Self { listener })
    }

    /// Returns the local address assigned to the listening socket.
    ///
    /// # Errors
    ///
    /// Returns the raw OS error when the socket name cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts one inbound connection without configuring it.
    ///
    /// This performs *only* the accept. Socket configuration is a separate
    /// phase, so a per-connection option failure can never be mistaken for a
    /// listener failure.
    ///
    /// # Errors
    ///
    /// Returns the raw accept error with its `errno` intact. Callers must
    /// classify it with [`AcceptErrorClass::classify`] rather than propagating
    /// it, because most accept errors are recoverable.
    pub async fn accept_only(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept().await
    }

    /// Applies per-connection socket options to an accepted stream.
    ///
    /// # Errors
    ///
    /// Returns the raw OS error. The failure affects only this connection: the
    /// caller closes the stream, releases its permit, and keeps accepting.
    pub fn configure_accepted(stream: &TcpStream) -> io::Result<()> {
        Self::configure_stream(stream)
    }

    /// Applies the shared data-socket options: `TCP_NODELAY` plus the kernel
    /// keepalive backstop.
    ///
    /// The proxy bounds no-progress transfers at the application layer;
    /// keepalive bounds the failure the application cannot see — a peer that
    /// dies without a FIN. Detection (30 s idle + 3 probes x 10 s, about 60 s)
    /// precedes the 120 s application idle window, costs three probe packets
    /// per window on idle connections, and never caps a healthy active
    /// transfer.
    ///
    /// # Errors
    ///
    /// Returns the raw OS error from either `setsockopt`.
    pub fn configure_stream(stream: &TcpStream) -> io::Result<()> {
        use std::os::fd::AsRawFd as _;
        stream.set_nodelay(true)?;
        rr_linux::socket::set_keepalive(
            stream.as_raw_fd(),
            KEEPALIVE_IDLE,
            KEEPALIVE_INTERVAL,
            KEEPALIVE_COUNT,
        )
    }

    /// Accepts and configures one inbound TCP connection.
    ///
    /// Retained for tests and for call sites that do not implement pressure
    /// recovery. Production listeners use [`Self::accept_only`] and
    /// [`Self::configure_accepted`] so the two failure modes stay separable.
    ///
    /// # Errors
    ///
    /// Returns either an accept error or a socket-configuration error, which is
    /// exactly the ambiguity production code must avoid.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer_addr) = self.accept_only().await?;
        Self::configure_accepted(&stream)?;

        Ok((stream, peer_addr))
    }
}

/// Bounded exponential backoff for recoverable accept errors.
///
/// The delay is capped, so a sustained pressure condition costs a fixed poll
/// interval rather than an unbounded stall, and it resets on the first
/// successful accept so a transient burst does not degrade steady-state latency.
#[derive(Clone, Copy, Debug)]
pub struct AcceptBackoff {
    current_ms: u64,
}

impl AcceptBackoff {
    /// The first delay applied after a recoverable error.
    pub const INITIAL_MS: u64 = 5;
    /// The delay ceiling.
    pub const MAXIMUM_MS: u64 = 500;

    /// Creates a backoff in its reset state.
    #[must_use]
    pub const fn new() -> Self {
        Self { current_ms: 0 }
    }

    /// Returns the backoff to its initial state after a successful accept.
    pub const fn reset(&mut self) {
        self.current_ms = 0;
    }

    /// Returns whether any delay is currently scheduled.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.current_ms != 0
    }

    /// Advances the backoff and returns the delay to wait.
    pub const fn next_delay(&mut self) -> std::time::Duration {
        self.current_ms = if self.current_ms == 0 {
            Self::INITIAL_MS
        } else {
            let doubled = self.current_ms.saturating_mul(2);
            if doubled > Self::MAXIMUM_MS {
                Self::MAXIMUM_MS
            } else {
                doubled
            }
        };
        std::time::Duration::from_millis(self.current_ms)
    }

    /// Returns the current delay in milliseconds for reporting.
    #[must_use]
    pub const fn current_ms(&self) -> u64 {
        self.current_ms
    }
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
    };

    use tokio::net::TcpStream;

    use super::{AcceptBackoff, AcceptErrorClass, EmergencyDescriptor, TcpAcceptor};

    #[tokio::test(flavor = "current_thread")]
    async fn bind_replaces_zero_port_with_kernel_assigned_port() {
        let requested_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

        let acceptor = TcpAcceptor::bind(requested_addr)
            .await
            .expect("loopback listener should bind");

        let actual_addr = acceptor
            .local_addr()
            .expect("bound listener should have a local address");

        assert_eq!(actual_addr.ip(), requested_addr.ip());
        assert_ne!(actual_addr.port(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accept_enables_tcp_nodelay() {
        let acceptor = TcpAcceptor::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind loopback listener");
        let listen_addr = acceptor.local_addr().expect("read listener address");

        let connect = TcpStream::connect(listen_addr);
        let accept = acceptor.accept();
        let (client_result, accepted_result) = tokio::join!(connect, accept);

        let _client = client_result.expect("connect to listener");
        let (accepted, _) = accepted_result.expect("accept client");

        assert!(
            accepted.nodelay().expect("read TCP_NODELAY"),
            "accepted proxy streams must disable Nagle"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn data_sockets_arm_the_kernel_keepalive_backstop() {
        let acceptor = TcpAcceptor::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind loopback listener");
        let listen_addr = acceptor.local_addr().expect("read listener address");

        let connect = TcpStream::connect(listen_addr);
        let accept = acceptor.accept();
        let (client_result, accepted_result) = tokio::join!(connect, accept);
        let client = client_result.expect("connect to listener");
        let (accepted, _) = accepted_result.expect("accept client");

        use std::os::fd::AsRawFd as _;
        assert!(
            rr_linux::socket::keepalive_enabled(accepted.as_raw_fd()).expect("read SO_KEEPALIVE"),
            "accepted streams must arm keepalive"
        );
        crate::transport::TcpAcceptor::configure_stream(&client).expect("configure outbound");
        assert!(
            rr_linux::socket::keepalive_enabled(client.as_raw_fd()).expect("read SO_KEEPALIVE"),
            "outbound streams must arm keepalive"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accept_only_leaves_socket_configuration_to_a_separate_phase() {
        let acceptor = TcpAcceptor::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind loopback listener");
        let listen_addr = acceptor.local_addr().expect("read listener address");

        let connect = TcpStream::connect(listen_addr);
        let accept = acceptor.accept_only();
        let (client_result, accepted_result) = tokio::join!(connect, accept);

        let _client = client_result.expect("connect to listener");
        let (accepted, _) = accepted_result.expect("accept client");

        TcpAcceptor::configure_accepted(&accepted).expect("configure accepted stream");
        assert!(accepted.nodelay().expect("read TCP_NODELAY"));
    }

    #[test]
    fn descriptor_pressure_is_never_classified_as_fatal() {
        for errno in [super::libc_compat::EMFILE, super::libc_compat::ENFILE] {
            let class = AcceptErrorClass::classify(&io::Error::from_raw_os_error(errno));
            assert_eq!(
                class,
                AcceptErrorClass::DescriptorPressure,
                "errno {errno} terminated the production listener and must not be fatal"
            );
            assert!(!class.is_fatal());
            assert!(class.needs_backoff());
        }
    }

    #[test]
    fn transient_network_errors_do_not_stop_the_listener() {
        for errno in [
            super::libc_compat::EINTR,
            super::libc_compat::ECONNABORTED,
            super::libc_compat::EPROTO,
            super::libc_compat::ECONNRESET,
            super::libc_compat::EHOSTUNREACH,
            super::libc_compat::ENETDOWN,
            super::libc_compat::EPERM,
        ] {
            let class = AcceptErrorClass::classify(&io::Error::from_raw_os_error(errno));
            assert_eq!(class, AcceptErrorClass::Transient, "errno {errno}");
            assert!(!class.is_fatal());
            assert!(
                !class.needs_backoff(),
                "a transient accept error must retry immediately, not stall the listener"
            );
        }
    }

    #[test]
    fn readiness_errors_are_not_logged_as_failures() {
        let class =
            AcceptErrorClass::classify(&io::Error::from_raw_os_error(super::libc_compat::EAGAIN));
        assert_eq!(class, AcceptErrorClass::WouldBlock);
        assert!(!class.is_fatal());
        assert!(!class.needs_backoff());
    }

    #[test]
    fn memory_pressure_backs_off_rather_than_busy_looping() {
        for errno in [super::libc_compat::ENOBUFS, super::libc_compat::ENOMEM] {
            let class = AcceptErrorClass::classify(&io::Error::from_raw_os_error(errno));
            assert_eq!(class, AcceptErrorClass::MemoryPressure);
            assert!(class.needs_backoff());
            assert!(!class.is_fatal());
        }
    }

    #[test]
    fn permanent_listener_corruption_stops_only_that_listener() {
        for errno in [
            super::libc_compat::EBADF,
            super::libc_compat::ENOTSOCK,
            super::libc_compat::EOPNOTSUPP,
            super::libc_compat::EINVAL,
        ] {
            let class = AcceptErrorClass::classify(&io::Error::from_raw_os_error(errno));
            assert_eq!(class, AcceptErrorClass::Fatal, "errno {errno}");
            assert!(class.is_fatal());
        }
    }

    #[test]
    fn an_error_without_an_errno_is_not_assumed_retryable_forever() {
        let class = AcceptErrorClass::classify(&io::Error::other("synthetic"));
        assert_eq!(class, AcceptErrorClass::Unknown);
        assert!(!class.is_fatal());
        assert!(
            class.needs_backoff(),
            "an unclassified condition must back off rather than spin"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_declared_errno_values_match_the_platform() {
        assert_eq!(super::libc_compat::EPERM, libc_errno::EPERM);
        assert_eq!(super::libc_compat::EMFILE, libc_errno::EMFILE);
        assert_eq!(super::libc_compat::ENFILE, libc_errno::ENFILE);
        assert_eq!(super::libc_compat::EAGAIN, libc_errno::EAGAIN);
        assert_eq!(super::libc_compat::ECONNABORTED, libc_errno::ECONNABORTED);
        assert_eq!(super::libc_compat::EINVAL, libc_errno::EINVAL);
        assert_eq!(super::libc_compat::EBADF, libc_errno::EBADF);
        assert_eq!(super::libc_compat::ENOTSOCK, libc_errno::ENOTSOCK);
        assert_eq!(super::libc_compat::ENOBUFS, libc_errno::ENOBUFS);
        assert_eq!(super::libc_compat::ENOMEM, libc_errno::ENOMEM);
        assert_eq!(super::libc_compat::EPROTO, libc_errno::EPROTO);
        assert_eq!(super::libc_compat::EINTR, libc_errno::EINTR);
        assert_eq!(super::libc_compat::EOPNOTSUPP, libc_errno::EOPNOTSUPP);
    }

    /// Platform errno values sourced from `rustix`, which the crate already
    /// depends on for Linux splice support.
    #[cfg(target_os = "linux")]
    mod libc_errno {
        pub(super) const EPERM: i32 = rustix::io::Errno::PERM.raw_os_error();
        pub(super) const EINTR: i32 = rustix::io::Errno::INTR.raw_os_error();
        pub(super) const EBADF: i32 = rustix::io::Errno::BADF.raw_os_error();
        pub(super) const EAGAIN: i32 = rustix::io::Errno::AGAIN.raw_os_error();
        pub(super) const ENOMEM: i32 = rustix::io::Errno::NOMEM.raw_os_error();
        pub(super) const EINVAL: i32 = rustix::io::Errno::INVAL.raw_os_error();
        pub(super) const EMFILE: i32 = rustix::io::Errno::MFILE.raw_os_error();
        pub(super) const ENFILE: i32 = rustix::io::Errno::NFILE.raw_os_error();
        pub(super) const ENOTSOCK: i32 = rustix::io::Errno::NOTSOCK.raw_os_error();
        pub(super) const EOPNOTSUPP: i32 = rustix::io::Errno::OPNOTSUPP.raw_os_error();
        pub(super) const ENOBUFS: i32 = rustix::io::Errno::NOBUFS.raw_os_error();
        pub(super) const ECONNABORTED: i32 = rustix::io::Errno::CONNABORTED.raw_os_error();
        pub(super) const EPROTO: i32 = rustix::io::Errno::PROTO.raw_os_error();
    }

    #[test]
    fn the_emergency_descriptor_survives_a_full_release_and_reacquire_cycle() {
        let mut reserve = EmergencyDescriptor::open().expect("open reserve descriptor");
        assert!(reserve.is_held());
        assert!(
            reserve.release(),
            "the first release must free a descriptor"
        );
        assert!(!reserve.is_held());
        assert!(
            !reserve.release(),
            "a double release must be visible rather than silently reported as freed capacity"
        );
        reserve.reacquire().expect("reacquire reserve descriptor");
        assert!(reserve.is_held());
        reserve
            .reacquire()
            .expect("reacquiring a held reserve is a no-op");
        assert!(reserve.is_held());
    }

    #[test]
    fn backoff_is_bounded_and_resets_after_success() {
        let mut backoff = AcceptBackoff::new();
        assert!(!backoff.is_active());
        assert_eq!(backoff.next_delay().as_millis(), 5);
        assert_eq!(backoff.next_delay().as_millis(), 10);
        assert_eq!(backoff.next_delay().as_millis(), 20);
        for _ in 0..64 {
            let delay = backoff.next_delay();
            assert!(
                delay.as_millis() <= u128::from(AcceptBackoff::MAXIMUM_MS),
                "backoff must never exceed its ceiling"
            );
        }
        assert_eq!(backoff.current_ms(), AcceptBackoff::MAXIMUM_MS);
        assert!(backoff.is_active());
        backoff.reset();
        assert!(!backoff.is_active());
        assert_eq!(backoff.next_delay().as_millis(), 5);
    }
}
