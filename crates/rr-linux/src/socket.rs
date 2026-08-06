//! Safe wrappers for the socket queries the `SOCKHASH` backend arms and
//! accounts against.
//!
//! An armed socket is redirected entirely inside the kernel, so userspace
//! never observes its data path with a `read(2)`. The two queries here are
//! the honest substitutes:
//!
//! * `FIONREAD` reports userspace-visible queued input. A socket that is about
//!   to be armed must report zero, because queued bytes would bypass the
//!   kernel redirect and reorder the stream. After arming, a nonzero report
//!   means the socket left the redirected path.
//! * `TCP_INFO` reports the connection state and the cumulative
//!   `tcpi_bytes_received` / `tcpi_bytes_acked` counters. Byte accounting for
//!   an armed session is the delta of these counters between the arm-time
//!   baseline and teardown: userspace never sees the bytes, but the kernel
//!   still counts them.

use std::{io, mem, os::fd::RawFd};

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

/// TCP connection states as the kernel reports them in `tcpi_state`.
pub mod tcp_state {
    /// `TCP_ESTABLISHED`.
    pub const ESTABLISHED: u8 = 1;
    /// `TCP_SYN_SENT`.
    pub const SYN_SENT: u8 = 2;
    /// `TCP_SYN_RECV`.
    pub const SYN_RECV: u8 = 3;
    /// `TCP_FIN_WAIT1`: the local side sent a FIN; the peer may still send.
    pub const FIN_WAIT1: u8 = 4;
    /// `TCP_FIN_WAIT2`: the local FIN was acknowledged; the peer may still send.
    pub const FIN_WAIT2: u8 = 5;
    /// `TCP_TIME_WAIT`.
    pub const TIME_WAIT: u8 = 6;
    /// `TCP_CLOSE`.
    pub const CLOSE: u8 = 7;
    /// `TCP_CLOSE_WAIT`: the peer sent a FIN; the local side has not.
    pub const CLOSE_WAIT: u8 = 8;
    /// `TCP_LAST_ACK`.
    pub const LAST_ACK: u8 = 9;
    /// `TCP_CLOSING`: both sides sent a FIN.
    pub const CLOSING: u8 = 11;
}

/// The kernel-reported counters an armed session is accounted with.
///
/// All values are cumulative since the connection was established; a session
/// computes deltas against the baseline captured at arm time. Wrapping is
/// handled by the caller with wrapping subtraction, matching the kernel's own
/// counter semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpCounters {
    /// The connection state, one of [`tcp_state`].
    pub state: u8,
    /// `tcpi_bytes_received`: payload bytes this socket's TCP stack accepted.
    pub bytes_received: u64,
    /// `tcpi_bytes_acked`: payload bytes this socket sent that the peer
    /// acknowledged.
    pub bytes_acked: u64,
}

impl TcpCounters {
    /// Returns whether the *peer* closed or aborted its side of the
    /// connection.
    ///
    /// This deliberately excludes `FIN_WAIT1` and `FIN_WAIT2`: those states
    /// mean the *local* side sent a FIN — exactly what a relay does when it
    /// propagates a half-close with `shutdown(2)` — and the peer may still be
    /// sending. Treating them as peer-close would truncate a live direction,
    /// which the relay's privileged gates reproduce and pin. The states that
    /// do imply the peer finished are `CLOSE_WAIT` (peer FIN, local side still
    /// open), `LAST_ACK`, `CLOSING` and `TIME_WAIT` (both closed), and `CLOSE`
    /// (the connection is gone, e.g. after a reset).
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        matches!(
            self.state,
            tcp_state::TIME_WAIT
                | tcp_state::CLOSE
                | tcp_state::CLOSE_WAIT
                | tcp_state::LAST_ACK
                | tcp_state::CLOSING
        )
    }
}

/// Reads the `TCP_INFO` counters for `fd`.
///
/// # Errors
///
/// Returns the kernel error from `getsockopt(TCP_INFO)`, including `EBADF`
/// for an invalid descriptor and `ENOTCONN` for a socket without a connection.
pub fn tcp_counters(fd: RawFd) -> io::Result<TcpCounters> {
    let mut info: kernel_tcp_info = unsafe_zeroed();
    let mut length = socklen(mem::size_of::<kernel_tcp_info>())?;
    // SAFETY: `getsockopt(TCP_INFO)` writes at most `length` bytes of the
    // plain-old-data `kernel_tcp_info` struct through the pointer, and the
    // pointer describes exactly that many bytes of the exclusively owned
    // `info`. `length` is updated to the number of bytes actually written; a
    // kernel older than this layout writes fewer bytes and leaves the tail
    // zeroed, which the caller reads as "no bytes counted".
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpCounters {
        state: info.state,
        bytes_received: info.bytes_received,
        bytes_acked: info.bytes_acked,
    })
}

/// The kernel UAPI `tcp_info` prefix through `tcpi_bytes_received`.
///
/// The `libc` crate's `tcp_info` ends at `tcpi_total_retrans`, mirroring the
/// glibc header; the byte counters this crate accounts with live in the UAPI
/// tail that glibc does not expose. The layout is stable ABI: the kernel only
/// ever appends fields, and `getsockopt` copies the minimum of the caller's
/// and the kernel's struct size.
#[repr(C)]
#[derive(Clone, Copy)]
struct kernel_tcp_info {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    wscale: u8,
    delivery_rate_app_limited: u8,
    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,
    last_data_sent: u32,
    last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,
    pmtu: u32,
    rcv_ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    advmss: u32,
    reordering: u32,
    rcv_rtt: u32,
    rcv_space: u32,
    total_retrans: u32,
    pacing_rate: u64,
    max_pacing_rate: u64,
    bytes_acked: u64,
    bytes_received: u64,
}

fn socklen(bytes: usize) -> io::Result<libc::socklen_t> {
    libc::socklen_t::try_from(bytes).map_err(|_| io::Error::other("TCP_INFO length overflows"))
}

fn unsafe_zeroed<T>() -> T {
    // SAFETY: `kernel_tcp_info` is a plain-old-data `#[repr(C)]` struct of
    // integers, for which an all-zero bit pattern is a valid value; fields the
    // kernel does not write stay zero, which reads as "no bytes counted".
    unsafe { mem::zeroed() }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        os::fd::AsRawFd as _,
    };

    use super::{kernel_tcp_info, pending_input, tcp_counters, tcp_state};

    #[test]
    fn the_tcp_info_layout_matches_the_kernel_uapi() {
        // The kernel reads each field at a fixed byte position; a layout
        // mistake silently reads the wrong counter.
        assert_eq!(core::mem::size_of::<kernel_tcp_info>(), 136);
        assert_eq!(core::mem::offset_of!(kernel_tcp_info, state), 0);
        assert_eq!(core::mem::offset_of!(kernel_tcp_info, total_retrans), 100);
        assert_eq!(core::mem::offset_of!(kernel_tcp_info, bytes_acked), 120);
        assert_eq!(core::mem::offset_of!(kernel_tcp_info, bytes_received), 128);
    }

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        (client, accepted)
    }

    #[test]
    fn pending_input_reports_queued_bytes_and_drains_to_zero() {
        let (mut client, mut accepted) = loopback_pair();
        assert_eq!(pending_input(accepted.as_raw_fd()).expect("query"), 0);

        client.write_all(b"queued").expect("write");
        for _ in 0..1_000 {
            if pending_input(accepted.as_raw_fd()).expect("query") == 6 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(pending_input(accepted.as_raw_fd()).expect("query"), 6);

        let mut buffer = [0_u8; 6];
        accepted.read_exact(&mut buffer).expect("read");
        assert_eq!(pending_input(accepted.as_raw_fd()).expect("query"), 0);
    }

    #[test]
    fn tcp_counters_report_an_established_connection_and_its_bytes() {
        let (mut client, accepted) = loopback_pair();
        let before = tcp_counters(accepted.as_raw_fd()).expect("TCP_INFO must succeed");
        assert_eq!(before.state, tcp_state::ESTABLISHED);
        assert!(!before.peer_closed());

        client.write_all(&[0xAB; 1_000]).expect("write");
        for _ in 0..1_000 {
            let now = tcp_counters(accepted.as_raw_fd()).expect("TCP_INFO must succeed");
            if now.bytes_received >= before.bytes_received + 1_000 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("tcpi_bytes_received must observe userspace traffic");
    }

    #[test]
    fn local_fin_wait_states_are_not_peer_close() {
        let counters = |state| super::TcpCounters {
            state,
            bytes_received: 0,
            bytes_acked: 0,
        };
        for state in [
            tcp_state::ESTABLISHED,
            tcp_state::SYN_SENT,
            tcp_state::FIN_WAIT1,
            tcp_state::FIN_WAIT2,
        ] {
            assert!(
                !counters(state).peer_closed(),
                "state {state} means the peer may still be sending"
            );
        }
        for state in [
            tcp_state::CLOSE_WAIT,
            tcp_state::LAST_ACK,
            tcp_state::CLOSING,
            tcp_state::TIME_WAIT,
            tcp_state::CLOSE,
        ] {
            assert!(
                counters(state).peer_closed(),
                "state {state} means the peer finished"
            );
        }
    }

    #[test]
    fn a_peer_close_moves_the_state_out_of_established() {
        let (client, accepted) = loopback_pair();
        drop(client);
        for _ in 0..1_000 {
            let now = tcp_counters(accepted.as_raw_fd()).expect("TCP_INFO must succeed");
            if now.peer_closed() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("a peer FIN must move the socket out of ESTABLISHED");
    }
}
