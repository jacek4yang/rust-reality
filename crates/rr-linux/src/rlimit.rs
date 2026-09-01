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

use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags},
    io::Errno,
    process::{Resource, Rlimit},
};

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

    /// Converts the kernel representation, where absent means unlimited.
    const fn from_rlimit(limit: Rlimit) -> Self {
        Self {
            soft: match limit.current {
                Some(soft) => soft,
                None => Self::INFINITY,
            },
            hard: match limit.maximum {
                Some(hard) => hard,
                None => Self::INFINITY,
            },
        }
    }

    /// Converts back, mapping the sentinel to the kernel's absent value.
    const fn into_rlimit(self) -> Rlimit {
        Rlimit {
            current: if self.soft == Self::INFINITY {
                None
            } else {
                Some(self.soft)
            },
            maximum: if self.hard == Self::INFINITY {
                None
            } else {
                Some(self.hard)
            },
        }
    }
}

/// Reads the process `RLIMIT_NOFILE` soft and hard limits.
///
/// `prlimit64` on the calling process with a valid resource cannot fail, so
/// there is no error to report and no fallback for a caller to invent.
#[must_use]
pub fn descriptor_limit() -> DescriptorLimit {
    DescriptorLimit::from_rlimit(rustix::process::getrlimit(Resource::Nofile))
}

/// Reads the process `RLIMIT_MEMLOCK` soft and hard limits.
///
/// The startup machine report includes the limit for operator visibility even
/// though no budget is derived from it.
#[must_use]
pub fn memlock_limit() -> DescriptorLimit {
    DescriptorLimit::from_rlimit(rustix::process::getrlimit(Resource::Memlock))
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
/// Returns the kernel error from `setrlimit(2)`. A failure leaves the previous
/// soft limit in place.
pub fn raise_descriptor_soft_limit(target: u64) -> Result<DescriptorLimit, Errno> {
    let current = descriptor_limit();
    let new_soft = target.min(current.hard);
    if new_soft <= current.soft {
        return Ok(current);
    }
    let raised = DescriptorLimit {
        soft: new_soft,
        hard: current.hard,
    };
    rustix::process::setrlimit(Resource::Nofile, raised.into_rlimit())?;
    Ok(descriptor_limit())
}

/// Opens the emergency reserve descriptor on `/dev/null`.
///
/// The reserve exists so the listener can still perform one `accept` and one
/// `close` after an unexpected `EMFILE`, which is what turns a permanent wedge
/// into a bounded backoff. It deliberately opens a file rather than a socket:
/// `/dev/null` cannot fail for a reason that also blocks recovery. The owned
/// descriptor is the whole reserve — no file abstraction is needed to hold one
/// descriptor open and release it on demand.
///
/// # Errors
///
/// Returns the kernel error when `/dev/null` cannot be opened.
pub fn open_reserve_descriptor() -> Result<OwnedFd, Errno> {
    rustix::fs::open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{
        DescriptorLimit, descriptor_limit, memlock_limit, open_reserve_descriptor,
        raise_descriptor_soft_limit,
    };

    #[test]
    fn the_reported_soft_limit_never_exceeds_the_hard_limit() {
        let limit = descriptor_limit();
        assert!(
            limit.soft <= limit.hard,
            "a soft limit above the hard limit would make every derived budget unsound"
        );
        assert!(limit.soft > 0, "a zero soft limit cannot open a listener");
    }

    #[test]
    fn the_memory_lock_limit_is_readable() {
        let limit = memlock_limit();
        assert!(
            limit.soft <= limit.hard,
            "the reported pair must be internally consistent"
        );
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
    fn an_unlimited_pair_round_trips_through_the_kernel_representation() {
        let unlimited = DescriptorLimit {
            soft: DescriptorLimit::INFINITY,
            hard: DescriptorLimit::INFINITY,
        };
        assert_eq!(
            DescriptorLimit::from_rlimit(unlimited.into_rlimit()),
            unlimited,
            "the unlimited sentinel must survive both directions"
        );
        let finite = DescriptorLimit {
            soft: 1_024,
            hard: 1_048_576,
        };
        assert_eq!(DescriptorLimit::from_rlimit(finite.into_rlimit()), finite);
    }

    #[test]
    fn a_raise_at_or_below_the_current_soft_limit_is_a_no_op() {
        let current = descriptor_limit();
        let unchanged = raise_descriptor_soft_limit(current.soft)
            .expect("a request that changes nothing must succeed");
        assert_eq!(unchanged, current, "the process limit must not move");
        assert_eq!(descriptor_limit(), current);
    }

    #[test]
    fn the_emergency_reserve_descriptor_opens_closes_and_is_close_on_exec() {
        let reserve = open_reserve_descriptor().expect("/dev/null must be openable");
        assert!(
            rustix::io::fcntl_getfd(&reserve)
                .expect("read descriptor flags")
                .contains(rustix::io::FdFlags::CLOEXEC),
            "the reserve must not leak into a child process"
        );
        drop(reserve);
        let again = open_reserve_descriptor().expect("/dev/null must reopen after release");
        drop(again);
    }
}
