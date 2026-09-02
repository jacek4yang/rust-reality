//! The bounded relay backend model shared by every raw TCP-to-TCP path.
//!
//! Three properties are structural rather than conventional here:
//!
//! * a backend can only decline *before* it has transferred a byte, because the
//!   only constructor for a decline consults the shared transfer ledger;
//! * decline reasons are a closed vocabulary, so no operator-visible string can
//!   ever carry a target, an SNI value, or a payload;
//! * every counter is checked, so a byte count can never silently wrap.

use std::{
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

/// One raw relay implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RelayBackend {
    /// Portable bounded pooled userspace copy.
    Buffered,
    /// Linux nonblocking `splice` through bounded pipe pairs.
    Splice,
}

impl RelayBackend {
    /// Returns the stable lowercase identifier used in configuration and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buffered => "buffered",
            Self::Splice => "splice",
        }
    }

    /// Returns every backend in the order the automatic policy considers them.
    #[must_use]
    pub const fn automatic_preference() -> &'static [Self] {
        &[Self::Splice, Self::Buffered]
    }

    /// Returns every backend, including those excluded from automatic selection.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Buffered, Self::Splice]
    }
}

impl fmt::Display for RelayBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The closed vocabulary of reasons a backend can refuse a relay.
///
/// Fixed categories keep operator output low-cardinality and guarantee that no
/// connection-specific detail leaks into a log line.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BackendDeclineReason {
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
    /// A configured bound is currently exhausted.
    ResourceLimit,
    /// A submission queue or driver shard was unavailable.
    QueueUnavailable,
    /// Arming would not have been safe for this socket pair.
    UnsafeToArm,
    /// Bytes were already queued on a socket that must be armed empty.
    ExistingQueuedBytes,
    /// One-time backend initialization failed.
    InitializationFailure,
}

impl BackendDeclineReason {
    /// Returns the stable identifier used in logs and reports.
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
            Self::ResourceLimit => "resourceLimit",
            Self::QueueUnavailable => "queueUnavailable",
            Self::UnsafeToArm => "unsafeToArm",
            Self::ExistingQueuedBytes => "existingQueuedBytes",
            Self::InitializationFailure => "initializationFailure",
        }
    }
}

impl fmt::Display for BackendDeclineReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Byte counts and timing produced by one completed relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayOutcome {
    backend: RelayBackend,
    inbound_to_outbound: u64,
    outbound_to_inbound: u64,
    duration: Duration,
    pipe_downgrade: Option<(usize, usize)>,
}

impl RelayOutcome {
    pub(crate) const fn new(
        backend: RelayBackend,
        inbound_to_outbound: u64,
        outbound_to_inbound: u64,
        duration: Duration,
        pipe_downgrade: Option<(usize, usize)>,
    ) -> Self {
        Self {
            backend,
            inbound_to_outbound,
            outbound_to_inbound,
            duration,
            pipe_downgrade,
        }
    }

    /// Returns the `(requested, granted)` pipe capacity when the backend was
    /// downgraded below the requested size by kernel pipe-page limits.
    #[must_use]
    pub const fn pipe_downgrade(self) -> Option<(usize, usize)> {
        self.pipe_downgrade
    }

    /// Returns the backend that actually transferred the bytes.
    #[must_use]
    pub const fn backend(self) -> RelayBackend {
        self.backend
    }

    /// Returns bytes copied from the inbound socket to the outbound socket.
    #[must_use]
    pub const fn inbound_to_outbound(self) -> u64 {
        self.inbound_to_outbound
    }

    /// Returns bytes copied from the outbound socket to the inbound socket.
    #[must_use]
    pub const fn outbound_to_inbound(self) -> u64 {
        self.outbound_to_inbound
    }

    /// Returns the wall-clock duration of the relay.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.duration
    }
}

/// One direction of a raw TCP relay.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RelayDirection {
    /// Inbound socket to outbound socket.
    Uplink,
    /// Outbound socket to inbound socket.
    Downlink,
}

impl RelayDirection {
    /// Returns whether this direction records into the inbound-to-outbound
    /// ledger counter.
    #[must_use]
    pub const fn is_inbound_to_outbound(self) -> bool {
        matches!(self, Self::Uplink)
    }
}

impl fmt::Display for RelayDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
        })
    }
}

/// Byte count and backend produced by one completed single-direction relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionalRelayOutcome {
    bytes: u64,
    backend: RelayBackend,
    duration: Duration,
    pipe_downgrade: Option<(usize, usize)>,
}

impl DirectionalRelayOutcome {
    pub(crate) const fn new(
        bytes: u64,
        backend: RelayBackend,
        duration: Duration,
        pipe_downgrade: Option<(usize, usize)>,
    ) -> Self {
        Self {
            bytes,
            backend,
            duration,
            pipe_downgrade,
        }
    }

    /// Returns the bytes transferred in the relayed direction.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns the backend that actually transferred the bytes.
    #[must_use]
    pub const fn backend(self) -> RelayBackend {
        self.backend
    }

    /// Returns the wall-clock duration of the relay.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.duration
    }

    /// Returns the `(requested, granted)` pipe capacity when the backend was
    /// downgraded below the requested size by kernel pipe-page limits.
    #[must_use]
    pub const fn pipe_downgrade(self) -> Option<(usize, usize)> {
        self.pipe_downgrade
    }
}

/// Whether a backend is usable, and if not, exactly why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendCapability {
    /// Configuration enabled this backend.
    pub enabled_by_config: bool,
    /// The runtime probe accepted this backend.
    pub available: bool,
    /// The fixed reason the backend is unusable, when it is unusable.
    pub decline_reason: Option<BackendDeclineReason>,
}

impl BackendCapability {
    /// Returns an available capability.
    #[must_use]
    pub const fn available() -> Self {
        Self {
            enabled_by_config: true,
            available: true,
            decline_reason: None,
        }
    }

    /// Returns an unavailable capability with a fixed reason.
    #[must_use]
    pub const fn declined(enabled_by_config: bool, reason: BackendDeclineReason) -> Self {
        Self {
            enabled_by_config,
            available: false,
            decline_reason: Some(reason),
        }
    }
}

/// One stable capability line per backend, emitted once at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendReport {
    /// The buffered userspace backend.
    pub buffered: BackendCapability,
    /// The Linux `splice` backend.
    pub splice: BackendCapability,
}

impl BackendReport {
    /// Returns the capability of one backend.
    #[must_use]
    pub const fn capability(&self, backend: RelayBackend) -> BackendCapability {
        match backend {
            RelayBackend::Buffered => self.buffered,
            RelayBackend::Splice => self.splice,
        }
    }

    /// Returns each backend paired with its capability, in reporting order.
    #[must_use]
    pub fn entries(&self) -> [(RelayBackend, BackendCapability); 2] {
        [
            (RelayBackend::Buffered, self.buffered),
            (RelayBackend::Splice, self.splice),
        ]
    }
}

/// Which backend a caller asked for.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackendRequest {
    /// Follow the configured automatic preference order.
    #[default]
    Automatic,
    /// Use exactly this backend, or fall back if it declines before transfer.
    Explicit(RelayBackend),
}

/// Immutable per-relay context.
#[derive(Clone, Copy, Debug, Default)]
pub struct RelayContext {
    /// The backend the caller requested.
    pub request: BackendRequest,
    /// Idle liveness bound for the raw relay.
    ///
    /// When set, a direction that moves no byte for this long terminates the
    /// relay instead of parking on a stalled peer forever, pinning its
    /// descriptors, pipes, map entries and permits. `None` means unbounded,
    /// which is what [`RelayContext::owned`] and its directional twin give a
    /// caller that owns both halves and is therefore accountable for the
    /// stall itself.
    pub liveness: Option<std::time::Duration>,
    /// Whether a source reset ends its direction like an EOF.
    ///
    /// Default `false`: a reset mid-transfer is a true abort, so the peer
    /// observes a reset rather than a clean short EOF that could pass a
    /// truncated stream off as complete. Callers whose endpoints enforce
    /// their own record-layer close semantics — the Handoff LINE relay, where
    /// both sockets carry the session's TLS 1.3 records — opt in: a real
    /// client commonly closes with the server's final close_notify still
    /// unread, which the kernel turns into a RST that reaches the raw relay
    /// only because no TLS layer terminates the session there first. The
    /// byte counts stay exact either way: only destination-accepted bytes are
    /// ever recorded.
    pub source_reset_is_eof: bool,
}

impl RelayContext {
    /// Returns a context for a caller that owns both complete sockets.
    #[must_use]
    pub const fn owned() -> Self {
        Self {
            request: BackendRequest::Automatic,
            liveness: None,
            source_reset_is_eof: false,
        }
    }

    /// Returns the same context with an explicit backend request.
    #[must_use]
    pub const fn with_request(mut self, request: BackendRequest) -> Self {
        self.request = request;
        self
    }

    /// Returns the same context with an idle liveness bound for the raw relay.
    #[must_use]
    pub const fn with_liveness(mut self, liveness: std::time::Duration) -> Self {
        self.liveness = Some(liveness);
        self
    }

    /// Returns the same context treating a source reset as direction EOF.
    #[must_use]
    pub const fn with_source_reset_as_eof(mut self) -> Self {
        self.source_reset_is_eof = true;
        self
    }
}

/// Immutable per-relay policy for the raw **directional** capability.
///
/// The two raw capabilities this transport offers are described by two policy
/// types, not one, because they honour different options:
///
/// * the bidirectional capability owns both complete sockets and can therefore
///   treat a source reset as a direction EOF ([`RelayContext::source_reset_is_eof`]);
/// * the directional capability owns one direction's halves, leaves the peer
///   direction untouched, and its backends do **not** implement reset-as-EOF.
///
/// Giving the directional capability its own policy type makes that difference
/// unrepresentable rather than silently ignored: a caller cannot ask a
/// directional relay for an option it would drop on the floor. This mirrors how
/// the Session Engine makes a retry after an irreversible write unrepresentable
/// instead of guarding it at runtime.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectionalRelayContext {
    /// The backend the caller requested.
    pub request: BackendRequest,
    /// Idle liveness bound for this direction.
    ///
    /// When set, a direction that moves no byte for this long terminates instead
    /// of parking on a stalled peer forever, pinning its descriptors, pipes, map
    /// entries and permits.
    pub liveness: Option<Duration>,
}

impl DirectionalRelayContext {
    /// Returns a context for a caller that owns exactly one direction's halves.
    #[must_use]
    pub const fn owned_direction() -> Self {
        Self {
            request: BackendRequest::Automatic,
            liveness: None,
        }
    }

    /// Returns the same context with an explicit backend request.
    #[must_use]
    pub const fn with_request(mut self, request: BackendRequest) -> Self {
        self.request = request;
        self
    }

    /// Returns the same context with an idle liveness bound.
    #[must_use]
    pub const fn with_liveness(mut self, liveness: Duration) -> Self {
        self.liveness = Some(liveness);
        self
    }
}

/// Monotonic, checked byte counters shared by a relay and its backend.
///
/// The ledger is the single source of truth for "has this relay transferred a
/// byte". A backend cannot report a decline without presenting the ledger, and
/// the ledger refuses to produce a decline once either counter is nonzero.
#[derive(Debug, Default)]
pub struct TransferLedger {
    inbound_to_outbound: AtomicU64,
    outbound_to_inbound: AtomicU64,
    pipe_downgrade: std::sync::atomic::AtomicU64,
}

impl TransferLedger {
    /// Creates an untouched ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inbound_to_outbound: AtomicU64::new(0),
            outbound_to_inbound: AtomicU64::new(0),
            pipe_downgrade: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Adds inbound-to-outbound bytes with checked arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an error instead of wrapping when the counter would overflow.
    pub fn add_inbound_to_outbound(&self, bytes: u64) -> io::Result<()> {
        Self::add(&self.inbound_to_outbound, bytes)
    }

    /// Adds outbound-to-inbound bytes with checked arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an error instead of wrapping when the counter would overflow.
    pub fn add_outbound_to_inbound(&self, bytes: u64) -> io::Result<()> {
        Self::add(&self.outbound_to_inbound, bytes)
    }

    fn add(counter: &AtomicU64, bytes: u64) -> io::Result<()> {
        let mut current = counter.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(bytes)
                .ok_or_else(|| io::Error::other("relay byte count overflow"))?;
            match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns the inbound-to-outbound count.
    #[must_use]
    pub fn inbound_to_outbound(&self) -> u64 {
        self.inbound_to_outbound.load(Ordering::Acquire)
    }

    /// Returns the outbound-to-inbound count.
    #[must_use]
    pub fn outbound_to_inbound(&self) -> u64 {
        self.outbound_to_inbound.load(Ordering::Acquire)
    }

    /// Returns whether the relay has transferred no byte in either direction.
    #[must_use]
    pub fn is_untouched(&self) -> bool {
        self.inbound_to_outbound() == 0 && self.outbound_to_inbound() == 0
    }

    /// Produces a decline, which is only possible before any transfer.
    ///
    /// This is the sole constructor of [`Decline`]. A backend that has already
    /// moved a byte therefore cannot hand the relay back to the selection loop,
    /// and the "no fallback after transfer" rule cannot be violated by writing
    /// the wrong control-flow branch.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger is not untouched.
    pub fn decline(&self, reason: BackendDeclineReason) -> io::Result<BackendRun> {
        if self.is_untouched() {
            Ok(BackendRun::Declined(Decline { reason }))
        } else {
            Err(io::Error::other(
                "a relay backend cannot decline after transferring bytes",
            ))
        }
    }

    /// Records that a splice relay was granted less pipe capacity than
    /// requested, packed as `(requested << 32) | granted` — zero means none.
    pub fn note_pipe_downgrade(&self, requested: usize, granted: usize) {
        let packed = (u64::try_from(requested).unwrap_or(u64::MAX) << 32)
            | u64::try_from(granted).unwrap_or(u64::MAX);
        let _ = self.pipe_downgrade.compare_exchange(
            0,
            packed,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    /// Returns the recorded `(requested, granted)` downgrade, when any.
    #[must_use]
    pub fn pipe_downgrade(&self) -> Option<(usize, usize)> {
        let packed = self
            .pipe_downgrade
            .load(std::sync::atomic::Ordering::Acquire);
        if packed == 0 {
            return None;
        }
        Some((
            usize::try_from(packed >> 32).unwrap_or(usize::MAX),
            usize::try_from(packed & 0xffff_ffff).unwrap_or(usize::MAX),
        ))
    }

    /// Builds the completed outcome for a backend that ran to the end.
    #[must_use]
    pub fn complete(&self, backend: RelayBackend, duration: Duration) -> BackendRun {
        BackendRun::Completed(RelayOutcome::new(
            backend,
            self.inbound_to_outbound(),
            self.outbound_to_inbound(),
            duration,
            self.pipe_downgrade(),
        ))
    }
}

/// A refusal that is provably free of transferred bytes.
///
/// The private field prevents construction outside this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decline {
    reason: BackendDeclineReason,
}

impl Decline {
    /// Returns the fixed reason category.
    #[must_use]
    pub const fn reason(self) -> BackendDeclineReason {
        self.reason
    }
}

/// The result of running one backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendRun {
    /// The backend refused before transferring anything; the next backend may run.
    Declined(Decline),
    /// The backend ran the relay to completion.
    Completed(RelayOutcome),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BackendDeclineReason, BackendRun, RelayBackend, TransferLedger};

    #[test]
    fn an_untouched_ledger_may_decline() {
        let ledger = TransferLedger::new();

        let run = ledger
            .decline(BackendDeclineReason::ResourceLimit)
            .expect("an untouched ledger may decline");

        match run {
            BackendRun::Declined(decline) => {
                assert_eq!(decline.reason(), BackendDeclineReason::ResourceLimit);
            }
            BackendRun::Completed(_) => panic!("expected a decline"),
        }
    }

    #[test]
    fn a_pipe_downgrade_is_recorded_once_and_carried_into_the_outcome() {
        let ledger = TransferLedger::new();
        assert_eq!(ledger.pipe_downgrade(), None);

        ledger.note_pipe_downgrade(256 * 1024, 8 * 1024);
        assert_eq!(
            ledger.pipe_downgrade(),
            Some((256 * 1024, 8 * 1024)),
            "the first downgrade must be recorded"
        );
        ledger.note_pipe_downgrade(256 * 1024, 64 * 1024);
        assert_eq!(
            ledger.pipe_downgrade(),
            Some((256 * 1024, 8 * 1024)),
            "the worst (first) downgrade must win"
        );

        let BackendRun::Completed(outcome) = ledger.complete(RelayBackend::Splice, Duration::ZERO)
        else {
            panic!("completion must produce an outcome");
        };
        assert_eq!(outcome.pipe_downgrade(), Some((256 * 1024, 8 * 1024)));
    }

    #[test]
    fn a_ledger_that_moved_bytes_can_never_decline() {
        let ledger = TransferLedger::new();
        ledger
            .add_inbound_to_outbound(1)
            .expect("one byte must be recorded");

        assert!(
            ledger.decline(BackendDeclineReason::ResourceLimit).is_err(),
            "a backend must not be able to hand back a relay after transferring"
        );

        let reverse = TransferLedger::new();
        reverse
            .add_outbound_to_inbound(1)
            .expect("one byte must be recorded");
        assert!(reverse.decline(BackendDeclineReason::UnsafeToArm).is_err());
    }

    #[test]
    fn byte_counters_are_checked_rather_than_wrapping() {
        let ledger = TransferLedger::new();
        ledger
            .add_inbound_to_outbound(u64::MAX)
            .expect("the maximum count must be representable");

        assert!(ledger.add_inbound_to_outbound(1).is_err());
        assert_eq!(ledger.inbound_to_outbound(), u64::MAX);
    }

    #[test]
    fn completion_reports_both_directions_and_the_backend() {
        let ledger = TransferLedger::new();
        ledger
            .add_inbound_to_outbound(7)
            .expect("uplink count must record");
        ledger
            .add_outbound_to_inbound(9)
            .expect("downlink count must record");

        let BackendRun::Completed(outcome) =
            ledger.complete(RelayBackend::Buffered, Duration::from_millis(3))
        else {
            panic!("expected completion");
        };
        assert_eq!(outcome.backend(), RelayBackend::Buffered);
        assert_eq!(outcome.inbound_to_outbound(), 7);
        assert_eq!(outcome.outbound_to_inbound(), 9);
        assert_eq!(outcome.duration(), Duration::from_millis(3));
    }

    #[test]
    fn automatic_preference_lists_every_backend() {
        assert_eq!(
            RelayBackend::automatic_preference(),
            [RelayBackend::Splice, RelayBackend::Buffered]
        );
        assert_eq!(RelayBackend::all().len(), 2);
        for backend in RelayBackend::automatic_preference() {
            assert!(RelayBackend::all().contains(backend));
        }
    }

    #[test]
    fn decline_reasons_are_stable_low_cardinality_identifiers() {
        for reason in [
            BackendDeclineReason::Disabled,
            BackendDeclineReason::UnsupportedOperatingSystem,
            BackendDeclineReason::UnsupportedKernel,
            BackendDeclineReason::MissingOperation,
            BackendDeclineReason::MissingCapability,
            BackendDeclineReason::BlockedBySeccomp,
            BackendDeclineReason::BlockedByLsm,
            BackendDeclineReason::ResourceLimit,
            BackendDeclineReason::QueueUnavailable,
            BackendDeclineReason::UnsafeToArm,
            BackendDeclineReason::ExistingQueuedBytes,
            BackendDeclineReason::InitializationFailure,
        ] {
            assert!(!reason.as_str().is_empty());
            assert!(!reason.as_str().contains(' '));
        }
    }
}
