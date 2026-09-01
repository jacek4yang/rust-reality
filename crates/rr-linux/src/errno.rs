//! Linux errno values used by root-level error classification.
//!
//! The protocol crate classifies accept failures from `raw_os_error`, so it
//! needs the numbers rather than a typed error. They are taken from
//! [`rustix::io::Errno`], whose constants come from the kernel headers through
//! `linux-raw-sys`, and are pinned by a test in the protocol crate.

use rustix::io::Errno;

pub const EPERM: i32 = Errno::PERM.raw_os_error();
pub const EINTR: i32 = Errno::INTR.raw_os_error();
pub const EBADF: i32 = Errno::BADF.raw_os_error();
pub const EAGAIN: i32 = Errno::AGAIN.raw_os_error();
pub const ENOMEM: i32 = Errno::NOMEM.raw_os_error();
pub const EFAULT: i32 = Errno::FAULT.raw_os_error();
pub const EINVAL: i32 = Errno::INVAL.raw_os_error();
pub const EMFILE: i32 = Errno::MFILE.raw_os_error();
pub const ENFILE: i32 = Errno::NFILE.raw_os_error();
pub const ENOTSOCK: i32 = Errno::NOTSOCK.raw_os_error();
pub const EOPNOTSUPP: i32 = Errno::OPNOTSUPP.raw_os_error();
pub const ENOBUFS: i32 = Errno::NOBUFS.raw_os_error();
pub const ECONNRESET: i32 = Errno::CONNRESET.raw_os_error();
pub const ETIMEDOUT: i32 = Errno::TIMEDOUT.raw_os_error();
pub const ECONNABORTED: i32 = Errno::CONNABORTED.raw_os_error();
pub const ENETDOWN: i32 = Errno::NETDOWN.raw_os_error();
pub const ENETUNREACH: i32 = Errno::NETUNREACH.raw_os_error();
pub const EHOSTDOWN: i32 = Errno::HOSTDOWN.raw_os_error();
pub const EHOSTUNREACH: i32 = Errno::HOSTUNREACH.raw_os_error();
pub const ENONET: i32 = Errno::NONET.raw_os_error();
pub const EPROTO: i32 = Errno::PROTO.raw_os_error();
