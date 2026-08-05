//! Probed, never assumed, kernel capability reporting.
//!
//! The specification is explicit that privilege requirements must be measured
//! on the running host rather than stated as universal facts. Nothing in this
//! module claims that a particular capability set is sufficient; each probe
//! performs the operation the backend actually needs and reports what happened.

use std::{fmt, io};

/// The closed vocabulary of reasons a Linux backend is unusable.
///
/// The categories mirror the protocol crate's reasons exactly so the mapping is
/// total and no free-form string ever reaches an operator log.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeclineReason {
    /// Configuration did not enable this backend.
    Disabled,
    /// The build target is not Linux.
    UnsupportedOperatingSystem,
    /// The running kernel lacks a required interface.
    UnsupportedKernel,
    /// A required kernel operation is not available.
    MissingOperation,
    /// A required process capability is missing.
    MissingCapability,
    /// A seccomp policy rejected a required system call.
    BlockedBySeccomp,
    /// A Linux security module rejected a required operation.
    BlockedByLsm,
    /// The eBPF verifier refused to accept the program.
    ///
    /// `BPF_PROG_LOAD` reports a verifier rejection as `EACCES`, which the
    /// generic errno mapping reads as an LSM denial. Keeping this category
    /// separate is what turns "something denied us" into "the program is
    /// wrong", and the incident this crate was audited against was misdiagnosed
    /// for exactly that reason.
    VerifierRejected,
    /// A configured bound is currently exhausted.
    ResourceLimit,
    /// A submission queue or driver shard was unavailable.
    QueueUnavailable,
    /// A required eBPF map was unavailable.
    MapUnavailable,
    /// Arming would not have been safe for this socket pair.
    UnsafeToArm,
    /// Bytes were already queued on a socket that must be armed empty.
    ExistingQueuedBytes,
    /// One-time backend initialization failed.
    InitializationFailure,
}

impl DeclineReason {
    /// Returns the stable identifier used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::UnsupportedOperatingSystem => "unsupportedOperatingSystem",
            Self::UnsupportedKernel => "unsupportedKernel",
            Self::MissingOperation => "missingOperation",
            Self::MissingCapability => "missingCapability",
            Self::BlockedBySeccomp => "blockedBySeccomp",
            Self::BlockedByLsm => "blockedByLsm",
            Self::VerifierRejected => "verifierRejected",
            Self::ResourceLimit => "resourceLimit",
            Self::QueueUnavailable => "queueUnavailable",
            Self::MapUnavailable => "mapUnavailable",
            Self::UnsafeToArm => "unsafeToArm",
            Self::ExistingQueuedBytes => "existingQueuedBytes",
            Self::InitializationFailure => "initializationFailure",
        }
    }

    /// Classifies an `errno` from a probed system call into a fixed category.
    ///
    /// The mapping is deliberately conservative. `EPERM` from a kernel interface
    /// that is otherwise present means the process lacks a capability or an LSM
    /// refused; the two are distinguished only where the kernel actually
    /// separates them, and never guessed.
    #[must_use]
    pub fn from_errno(error: &io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::ENOSYS) => Self::UnsupportedKernel,
            Some(libc::EOPNOTSUPP | libc::EINVAL) => Self::MissingOperation,
            Some(libc::EPERM) => Self::MissingCapability,
            Some(libc::EACCES) => Self::BlockedByLsm,
            Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOSPC) => Self::ResourceLimit,
            // A seccomp filter configured with SECCOMP_RET_ERRNO commonly
            // returns EAFNOSUPPORT or EPERM; only the former is unambiguous.
            Some(libc::EAFNOSUPPORT) => Self::BlockedBySeccomp,
            _ => Self::InitializationFailure,
        }
    }
}

impl fmt::Display for DeclineReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The result of probing one kernel operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    /// The operation is available on this host.
    Available,
    /// The operation is unavailable for a fixed reason.
    Declined(DeclineReason),
}

impl Probe {
    /// Returns whether the probe succeeded.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Returns the decline reason, if any.
    #[must_use]
    pub const fn reason(self) -> Option<DeclineReason> {
        match self {
            Self::Available => None,
            Self::Declined(reason) => Some(reason),
        }
    }

    /// Converts a probed system-call result into a probe outcome.
    #[must_use]
    pub fn from_result<T>(result: &io::Result<T>) -> Self {
        match result {
            Ok(_) => Self::Available,
            Err(error) => Self::Declined(DeclineReason::from_errno(error)),
        }
    }
}

impl fmt::Display for Probe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available => formatter.write_str("available"),
            Self::Declined(reason) => write!(formatter, "declined({reason})"),
        }
    }
}

/// One backend's probe result, including which individual operations passed.
///
/// The per-operation detail is bounded and non-secret: it names kernel
/// operations, never a target, an address, or any payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReport {
    backend: &'static str,
    overall: Probe,
    operations: Vec<(&'static str, Probe)>,
}

impl ProbeReport {
    /// Starts a report for one backend.
    #[must_use]
    pub const fn new(backend: &'static str) -> Self {
        Self {
            backend,
            overall: Probe::Available,
            operations: Vec::new(),
        }
    }

    /// Records one probed operation, downgrading the overall result if needed.
    #[must_use]
    pub fn with(mut self, operation: &'static str, probe: Probe) -> Self {
        if let (Probe::Available, Probe::Declined(reason)) = (self.overall, probe) {
            self.overall = Probe::Declined(reason);
        }
        self.operations.push((operation, probe));
        self
    }

    /// Marks the whole backend declined without probing further operations.
    #[must_use]
    pub const fn declined(backend: &'static str, reason: DeclineReason) -> Self {
        Self {
            backend,
            overall: Probe::Declined(reason),
            operations: Vec::new(),
        }
    }

    /// Returns the backend name.
    #[must_use]
    pub const fn backend(&self) -> &'static str {
        self.backend
    }

    /// Returns the overall probe outcome.
    #[must_use]
    pub const fn overall(&self) -> Probe {
        self.overall
    }

    /// Returns each probed operation in probe order.
    #[must_use]
    pub fn operations(&self) -> &[(&'static str, Probe)] {
        &self.operations
    }

    /// Returns whether every probed operation succeeded.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.overall.is_available()
    }
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.backend, self.overall)?;
        for (operation, probe) in &self.operations {
            if let Probe::Declined(reason) = probe {
                write!(formatter, " [{operation}={reason}]")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{DeclineReason, Probe, ProbeReport};

    #[test]
    fn errno_classification_never_guesses_a_capability() {
        assert_eq!(
            DeclineReason::from_errno(&io::Error::from_raw_os_error(libc::ENOSYS)),
            DeclineReason::UnsupportedKernel
        );
        assert_eq!(
            DeclineReason::from_errno(&io::Error::from_raw_os_error(libc::EPERM)),
            DeclineReason::MissingCapability
        );
        assert_eq!(
            DeclineReason::from_errno(&io::Error::from_raw_os_error(libc::EACCES)),
            DeclineReason::BlockedByLsm
        );
        assert_eq!(
            DeclineReason::from_errno(&io::Error::from_raw_os_error(libc::ENOMEM)),
            DeclineReason::ResourceLimit
        );
        assert_eq!(
            DeclineReason::from_errno(&io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
            DeclineReason::MissingOperation
        );
        assert_eq!(
            DeclineReason::from_errno(&io::Error::from_raw_os_error(libc::EIO)),
            DeclineReason::InitializationFailure
        );
    }

    #[test]
    fn a_single_declined_operation_downgrades_the_backend() {
        let report = ProbeReport::new("io_uring")
            .with("ring", Probe::Available)
            .with("recv", Probe::Declined(DeclineReason::MissingOperation))
            .with("send", Probe::Available);

        assert!(!report.is_available());
        assert_eq!(
            report.overall(),
            Probe::Declined(DeclineReason::MissingOperation)
        );
        assert_eq!(report.operations().len(), 3);
    }

    #[test]
    fn the_first_decline_is_the_reported_reason() {
        let report = ProbeReport::new("sockhash")
            .with("map", Probe::Declined(DeclineReason::MissingCapability))
            .with("program", Probe::Declined(DeclineReason::MissingOperation));

        assert_eq!(
            report.overall(),
            Probe::Declined(DeclineReason::MissingCapability)
        );
    }

    #[test]
    fn rendering_never_includes_anything_connection_specific() {
        let rendered = ProbeReport::new("io_uring")
            .with("ring", Probe::Available)
            .with("cancel", Probe::Declined(DeclineReason::MissingOperation))
            .to_string();

        assert_eq!(
            rendered,
            "io_uring: declined(missingOperation) [cancel=missingOperation]"
        );
    }

    #[test]
    fn probe_from_result_maps_success_and_failure() {
        assert!(Probe::from_result::<()>(&Ok(())).is_available());
        assert_eq!(
            Probe::from_result::<()>(&Err(io::Error::from_raw_os_error(libc::ENOSYS))),
            Probe::Declined(DeclineReason::UnsupportedKernel)
        );
    }
}
