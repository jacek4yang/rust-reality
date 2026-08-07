//! Process descriptor limit discovery.
//!
//! Admission cannot be derived from a guess. The effective file-descriptor
//! budget is a function of `RLIMIT_NOFILE`, which is inherited from whatever
//! started the process; the incident this module exists to prevent happened
//! because a configuration sized for a systemd unit (`LimitNOFILE=1048576`) was
//! run from an interactive shell whose soft limit was `1024`.
//!
//! Reading the limit is the only thing this module does. Deciding what to do
//! about it belongs to the protocol crate, which owns the configuration.

use std::io;

/// A process descriptor limit pair as reported by the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorLimit {
    /// The limit currently enforced on the process.
    pub soft: u64,
    /// The ceiling the process may raise the soft limit to without privilege.
    pub hard: u64,
}

impl DescriptorLimit {
    /// The value the kernel reports for an unlimited resource.
    ///
    /// `RLIM_INFINITY` is `u64::MAX` on every Linux ABI this crate supports; it
    /// is re-exported so callers can clamp rather than overflow.
    pub const INFINITY: u64 = u64::MAX;

    /// Returns the soft limit clamped to a value that arithmetic can use.
    ///
    /// An unlimited soft limit is not an invitation to admit unlimited work, so
    /// it is reported as `ceiling` rather than as `u64::MAX`.
    #[must_use]
    pub const fn usable_soft(self, ceiling: u64) -> u64 {
        if self.soft == Self::INFINITY || self.soft > ceiling {
            ceiling
        } else {
            self.soft
        }
    }
}

/// Reads the process `RLIMIT_NOFILE` soft and hard limits.
///
/// # Errors
///
/// Returns the raw OS error when `getrlimit(2)` fails, which on Linux happens
/// only for an invalid resource identifier and is therefore not expected here.
#[cfg(target_os = "linux")]
pub fn descriptor_limit() -> io::Result<DescriptorLimit> {
    // SAFETY: `libc::rlimit` is a `#[repr(C)]` plain-old-data struct of two
    // integers, for which an all-zero bit pattern is valid. It is fully
    // overwritten by `getrlimit` before it is read on the success path.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: `RLIMIT_NOFILE` is a valid resource identifier and `limit` is a
    // live, correctly sized, correctly aligned `struct rlimit` that the kernel
    // writes at most `size_of::<rlimit>()` bytes into and never retains.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(DescriptorLimit {
        soft: limit.rlim_cur,
        hard: limit.rlim_max,
    })
}

/// Reads the process descriptor limit on a platform that does not report one.
///
/// # Errors
///
/// Always returns [`io::ErrorKind::Unsupported`] so a caller cannot mistake an
/// absent limit for an unlimited one.
#[cfg(not(target_os = "linux"))]
pub fn descriptor_limit() -> io::Result<DescriptorLimit> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor limits are only discoverable on Linux",
    ))
}

/// Raises the process `RLIMIT_NOFILE` soft limit to `target`, clamped to the
/// hard limit, and returns the re-read limit pair.
///
/// This touches only the calling process. Raising the soft limit up to the
/// hard limit requires no privilege; nothing here can raise the hard limit or
/// touch any other process or any system-wide setting.
///
/// # Errors
///
/// Returns the raw OS error when `getrlimit(2)` or `setrlimit(2)` fails. A
/// failure leaves the previous soft limit in place.
#[cfg(target_os = "linux")]
pub fn raise_descriptor_soft_limit(target: u64) -> io::Result<DescriptorLimit> {
    let current = descriptor_limit()?;
    let new_soft = target.min(current.hard);
    if new_soft <= current.soft {
        return Ok(current);
    }
    let limit = libc::rlimit {
        rlim_cur: new_soft,
        rlim_max: current.hard,
    };
    // SAFETY: `RLIMIT_NOFILE` is a valid resource identifier and `limit` is a
    // live, correctly sized, correctly aligned `struct rlimit` whose fields
    // are fully initialised from the values just read back from the kernel.
    // The call affects only the calling process and never retains the pointer.
    let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    descriptor_limit()
}

/// Raises the process descriptor soft limit on a platform that does not report one.
///
/// # Errors
///
/// Always returns [`io::ErrorKind::Unsupported`] so a caller cannot mistake an
/// absent limit for a successful raise.
#[cfg(not(target_os = "linux"))]
pub fn raise_descriptor_soft_limit(_target: u64) -> io::Result<DescriptorLimit> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor limits are only adjustable on Linux",
    ))
}

/// Reads the process `RLIMIT_MEMLOCK` soft and hard limits.
///
/// The startup machine report includes the limit for operator visibility even
/// though no budget is derived from it.
///
/// # Errors
///
/// Returns the raw OS error when `getrlimit(2)` fails, or
/// [`io::ErrorKind::Unsupported`] off Linux.
#[cfg(target_os = "linux")]
pub fn memlock_limit() -> io::Result<DescriptorLimit> {
    // SAFETY: same contract as `descriptor_limit`: a zeroed `struct rlimit`
    // is valid and is fully overwritten by `getrlimit` on the success path.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: `RLIMIT_MEMLOCK` is a valid resource identifier and `limit` is
    // a live, correctly sized, correctly aligned `struct rlimit` that the
    // kernel writes at most `size_of::<rlimit>()` bytes into and never retains.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(DescriptorLimit {
        soft: limit.rlim_cur,
        hard: limit.rlim_max,
    })
}

/// Reads the process memory-lock limit on a platform that does not report one.
///
/// # Errors
///
/// Always returns [`io::ErrorKind::Unsupported`] so a caller cannot mistake an
/// absent limit for an unlimited one.
#[cfg(not(target_os = "linux"))]
pub fn memlock_limit() -> io::Result<DescriptorLimit> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "memory-lock limits are only discoverable on Linux",
    ))
}

/// Opens the emergency reserve descriptor on `/dev/null`.
///
/// The reserve exists so the listener can still perform one `accept` and one
/// `close` after an unexpected `EMFILE`, which is what turns a permanent wedge
/// into a bounded backoff. It deliberately opens a file rather than a socket:
/// `/dev/null` cannot fail for a reason that also blocks recovery.
///
/// # Errors
///
/// Returns the raw OS error when `/dev/null` cannot be opened.
pub fn open_reserve_descriptor() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open("/dev/null")
}

#[cfg(test)]
mod tests {
    use super::{DescriptorLimit, descriptor_limit, open_reserve_descriptor};

    #[test]
    fn the_reported_soft_limit_never_exceeds_the_hard_limit() {
        let Ok(limit) = descriptor_limit() else {
            return;
        };
        assert!(
            limit.soft <= limit.hard,
            "a soft limit above the hard limit would make every derived budget unsound"
        );
        assert!(limit.soft > 0, "a zero soft limit cannot open a listener");
    }

    #[test]
    fn an_unlimited_soft_limit_is_clamped_rather_than_overflowing() {
        let limit = DescriptorLimit {
            soft: DescriptorLimit::INFINITY,
            hard: DescriptorLimit::INFINITY,
        };
        assert_eq!(limit.usable_soft(65_536), 65_536);
    }

    #[test]
    fn a_finite_soft_limit_below_the_ceiling_is_returned_unchanged() {
        let limit = DescriptorLimit {
            soft: 1_024,
            hard: 1_048_576,
        };
        assert_eq!(limit.usable_soft(65_536), 1_024);
    }

    #[test]
    fn the_emergency_reserve_descriptor_opens_and_closes() {
        let reserve = open_reserve_descriptor().expect("/dev/null must be openable");
        drop(reserve);
        let again = open_reserve_descriptor().expect("/dev/null must reopen after release");
        drop(again);
    }
}
