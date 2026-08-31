//! Linux errno values used by root-level error classification.

pub const EPERM: i32 = libc::EPERM;
pub const EINTR: i32 = libc::EINTR;
pub const EBADF: i32 = libc::EBADF;
pub const EAGAIN: i32 = libc::EAGAIN;
pub const ENOMEM: i32 = libc::ENOMEM;
pub const EFAULT: i32 = libc::EFAULT;
pub const EINVAL: i32 = libc::EINVAL;
pub const EMFILE: i32 = libc::EMFILE;
pub const ENFILE: i32 = libc::ENFILE;
pub const ENOTSOCK: i32 = libc::ENOTSOCK;
pub const EOPNOTSUPP: i32 = libc::EOPNOTSUPP;
pub const ENOBUFS: i32 = libc::ENOBUFS;
pub const ECONNRESET: i32 = libc::ECONNRESET;
pub const ETIMEDOUT: i32 = libc::ETIMEDOUT;
pub const ECONNABORTED: i32 = libc::ECONNABORTED;
pub const ENETDOWN: i32 = libc::ENETDOWN;
pub const ENETUNREACH: i32 = libc::ENETUNREACH;
pub const EHOSTDOWN: i32 = libc::EHOSTDOWN;
pub const EHOSTUNREACH: i32 = libc::EHOSTUNREACH;
pub const ENONET: i32 = libc::ENONET;
pub const EPROTO: i32 = libc::EPROTO;
