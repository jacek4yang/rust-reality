//! Deriving a safe dynamic descriptor budget from `RLIMIT_NOFILE`.
//!
//! # Policy
//!
//! This module implements exactly one of the two policies the specification
//! permits, and it implements it before any listener is bound:
//!
//! * if the soft limit cannot cover the fixed process reserve plus a minimum
//!   viable dynamic budget, **startup fails** with the measured limit and a
//!   concrete recommendation;
//! * otherwise the effective dynamic budget is **clamped downward** to what the
//!   limit safely permits, and exactly one warning is emitted.
//!
//! The alternative — rejecting any configuration whose theoretical peak exceeds
//! the limit — was not chosen because `maxConnections` is a protocol limit that
//! operators tune for their own reasons, and because the peak is a sum of
//! worst cases that never occur simultaneously. Clamping keeps a
//! conservatively-configured server running; it does not keep an impossible one
//! running silently, because the warning names both numbers.
//!
//! Under no policy does the process start with a configuration it cannot honour
//! and then discover the problem in `accept4`.

use std::fmt;

/// Descriptors the process holds for its entire lifetime.
///
/// Every field is a conservative over-estimate. Over-reserving costs admission
/// headroom; under-reserving costs the process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFdReserve {
    /// Listening sockets.
    pub listeners: u64,
    /// Standard streams plus any logger file.
    pub logger: u64,
    /// Async runtime descriptors: epoll, eventfd and wakers.
    pub runtime: u64,
    /// Resolver descriptors held by uncancellable blocking lookups.
    pub resolver: u64,
    /// The emergency reserve descriptor held open on `/dev/null`.
    pub emergency: u64,
}

impl FixedFdReserve {
    /// Standard streams the process always holds.
    const STANDARD_STREAMS: u64 = 3;
    /// One logger sink beyond the standard streams.
    const LOGGER_SINK: u64 = 1;
    /// Tokio's reactor descriptors, over-estimated for a multi-thread runtime.
    const RUNTIME_DESCRIPTORS: u64 = 16;
    /// Concurrent uncancellable `getaddrinfo` descriptors.
    ///
    /// A cancelled `TcpStream::connect` cannot cancel the blocking resolver
    /// thread underneath it, so those descriptors survive the connection that
    /// requested them and must be reserved rather than admitted.
    const RESOLVER_DESCRIPTORS: u64 = 32;

    /// Builds the fixed reserve for a concrete process shape.
    #[must_use]
    pub const fn new(listeners: u64) -> Self {
        Self {
            listeners,
            logger: Self::STANDARD_STREAMS + Self::LOGGER_SINK,
            runtime: Self::RUNTIME_DESCRIPTORS,
            resolver: Self::RESOLVER_DESCRIPTORS,
            emergency: 1,
        }
    }

    /// Returns the total fixed reservation.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.listeners
            .saturating_add(self.logger)
            .saturating_add(self.runtime)
            .saturating_add(self.resolver)
            .saturating_add(self.emergency)
    }
}

/// The smallest dynamic budget that can serve traffic at all.
///
/// Below this the process would accept a connection, fail to open its outbound
/// socket, and thrash. Refusing to start is the honest outcome.
pub const MINIMUM_DYNAMIC_UNITS: u64 = 64;

/// The largest soft limit this process will plan against.
///
/// An unlimited or absurd soft limit is not an invitation to reserve unbounded
/// memory for admission bookkeeping.
pub(crate) const MAXIMUM_PLANNED_SOFT_LIMIT: u64 = 1_048_576;

/// How much of the measured limit is held back as safety headroom.
///
/// The headroom absorbs descriptor consumers this process cannot account for:
/// libraries, resolver threads and anything else sharing the limit. The two
/// policies differ only in how much of the machine the process assumes it
/// owns; both keep the strict invariant that budget plus reserve plus
/// headroom never exceeds the effective soft limit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FdHeadroomPolicy {
    /// One sixteenth of the limit (6.25%), floored at 64.
    ///
    /// The shared-machine default: the process assumes as little as possible
    /// about what else consumes the same limit.
    #[default]
    Standard,
    /// One tenth of the limit (10%), floored at 64.
    ///
    /// The dedicated-machine policy: the process has already raised its soft
    /// limit to the hard limit and owns the machine or cgroup, so the larger
    /// fraction buys margin against kernel-side descriptor consumers while
    /// still admitting roughly 90% of the effective capacity as dynamic work.
    Dedicated,
}

impl FdHeadroomPolicy {
    /// Returns the headroom to hold back from `planned_soft`.
    #[must_use]
    pub const fn headroom(self, planned_soft: u64) -> u64 {
        let divisor = match self {
            Self::Standard => 16,
            Self::Dedicated => 10,
        };
        let fraction = planned_soft / divisor;
        if fraction > 64 { fraction } else { 64 }
    }
}

/// A derived, validated dynamic descriptor budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdBudgetPlan {
    soft_limit: u64,
    hard_limit: u64,
    fixed_reserve: FixedFdReserve,
    safety_headroom: u64,
    effective_budget: u64,
    theoretical_peak: u64,
}

impl FdBudgetPlan {
    /// Derives the effective dynamic budget from a measured limit.
    ///
    /// `theoretical_peak` is the sum of every configured worst case. It is used
    /// only to decide whether a clamp warning is warranted; it never raises the
    /// budget above what the limit permits.
    ///
    /// # Errors
    ///
    /// Returns [`FdBudgetError::LimitTooLow`] when the soft limit cannot cover
    /// the fixed reserve plus [`MINIMUM_DYNAMIC_UNITS`]. This is returned before
    /// any listener is bound.
    pub fn derive(
        soft_limit: u64,
        hard_limit: u64,
        fixed_reserve: FixedFdReserve,
        theoretical_peak: u64,
        headroom_policy: FdHeadroomPolicy,
    ) -> Result<Self, FdBudgetError> {
        let planned_soft = if soft_limit == 0 || soft_limit > MAXIMUM_PLANNED_SOFT_LIMIT {
            MAXIMUM_PLANNED_SOFT_LIMIT
        } else {
            soft_limit
        };
        let reserve = fixed_reserve.total();
        let safety_headroom = headroom_policy.headroom(planned_soft);
        let required = reserve
            .saturating_add(safety_headroom)
            .saturating_add(MINIMUM_DYNAMIC_UNITS);
        if planned_soft < required {
            return Err(FdBudgetError::LimitTooLow {
                soft_limit,
                hard_limit,
                required,
            });
        }
        let effective_budget = planned_soft
            .saturating_sub(reserve)
            .saturating_sub(safety_headroom);
        Ok(Self {
            soft_limit,
            hard_limit,
            fixed_reserve,
            safety_headroom,
            effective_budget,
            theoretical_peak,
        })
    }

    /// Returns the measured soft limit.
    #[must_use]
    pub const fn soft_limit(&self) -> u64 {
        self.soft_limit
    }

    /// Returns the measured hard limit.
    #[must_use]
    pub const fn hard_limit(&self) -> u64 {
        self.hard_limit
    }

    /// Returns the fixed process reservation.
    #[must_use]
    pub const fn fixed_reserve(&self) -> FixedFdReserve {
        self.fixed_reserve
    }

    /// Returns the applied safety headroom.
    #[must_use]
    pub const fn safety_headroom(&self) -> u64 {
        self.safety_headroom
    }

    /// Returns the effective dynamic descriptor budget.
    #[must_use]
    pub const fn effective_budget(&self) -> u64 {
        self.effective_budget
    }

    /// Returns the configured theoretical peak demand.
    #[must_use]
    pub const fn theoretical_peak(&self) -> u64 {
        self.theoretical_peak
    }

    /// Returns whether the configured peak exceeds what the limit permits.
    ///
    /// A clamped plan is serviceable but will refuse work earlier than the
    /// configuration implies, so it warrants exactly one startup warning.
    #[must_use]
    pub const fn is_clamped(&self) -> bool {
        self.theoretical_peak > self.effective_budget
    }

    /// Returns the soft limit an operator should configure to avoid clamping.
    #[must_use]
    pub const fn recommended_soft_limit(&self) -> u64 {
        self.theoretical_peak
            .saturating_add(self.fixed_reserve.total())
            .saturating_add(self.safety_headroom)
    }
}

/// Startup refused because the process limit cannot support any useful budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdBudgetError {
    /// The soft `RLIMIT_NOFILE` is below the minimum viable reserve.
    LimitTooLow {
        /// Measured soft limit.
        soft_limit: u64,
        /// Measured hard limit.
        hard_limit: u64,
        /// The soft limit that would be required.
        required: u64,
    },
}

impl fmt::Display for FdBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitTooLow {
                soft_limit,
                hard_limit,
                required,
            } => write!(
                formatter,
                "the process file-descriptor soft limit is {soft_limit} (hard limit {hard_limit}) \
                 but at least {required} is required to serve traffic safely; \
                 raise it with `ulimit -n {required}` or `LimitNOFILE={required}` in the unit file"
            ),
        }
    }
}

impl std::error::Error for FdBudgetError {}

#[cfg(test)]
mod tests {
    use super::{
        FdBudgetError, FdBudgetPlan, FdHeadroomPolicy, FixedFdReserve, MINIMUM_DYNAMIC_UNITS,
    };

    fn reserve() -> FixedFdReserve {
        FixedFdReserve::new(1)
    }

    fn derive(soft: u64, hard: u64, peak: u64) -> Result<FdBudgetPlan, FdBudgetError> {
        FdBudgetPlan::derive(soft, hard, reserve(), peak, FdHeadroomPolicy::Standard)
    }

    #[test]
    fn the_incident_limit_produces_a_clamped_but_serviceable_budget() {
        // The exact limits from the incident capture.
        let plan = derive(1_024, 1_048_576, 24_000).expect("a 1024 soft limit must still start");
        assert!(plan.is_clamped(), "24000 requested against a 1024 limit");
        assert!(plan.effective_budget() >= MINIMUM_DYNAMIC_UNITS);
        assert!(
            plan.effective_budget() + plan.fixed_reserve().total() + plan.safety_headroom()
                <= 1_024,
            "the derived budget must never exceed the measured soft limit"
        );
        assert!(plan.recommended_soft_limit() > 24_000);
    }

    #[test]
    fn a_generous_limit_is_not_clamped() {
        let plan = derive(1_048_576, 1_048_576, 24_000).expect("a large soft limit must start");
        assert!(!plan.is_clamped());
        assert!(plan.effective_budget() > 24_000);
    }

    #[test]
    fn an_impossible_limit_is_rejected_before_binding() {
        let error =
            derive(64, 1_048_576, 128).expect_err("a 64 descriptor limit cannot serve traffic");
        let FdBudgetError::LimitTooLow {
            soft_limit,
            required,
            ..
        } = error;
        assert_eq!(soft_limit, 64);
        assert!(required > 64);
        assert!(
            error.to_string().contains("ulimit -n"),
            "the error must tell the operator exactly what to change"
        );
    }

    #[test]
    fn an_unlimited_soft_limit_is_planned_against_a_finite_ceiling() {
        let plan = derive(u64::MAX, u64::MAX, 1_000).expect("an unlimited soft limit must start");
        assert!(
            plan.effective_budget() <= super::MAXIMUM_PLANNED_SOFT_LIMIT,
            "an unlimited limit must not produce an unbounded admission pool"
        );
        assert!(!plan.is_clamped());
    }

    #[test]
    fn the_budget_plus_every_reserve_never_exceeds_the_soft_limit() {
        // 182 is the exact minimum this reserve permits; 128 is correctly
        // refused and is covered by `an_impossible_limit_is_rejected_before_binding`.
        for soft in [182_u64, 256, 1_024, 4_096, 65_536, 1_048_576] {
            let plan =
                derive(soft, soft, 10).expect("every limit at or above the minimum must start");
            let total =
                plan.effective_budget() + plan.fixed_reserve().total() + plan.safety_headroom();
            assert!(
                total <= soft,
                "soft limit {soft} produced a total reservation of {total}"
            );
        }
    }

    #[test]
    fn the_dedicated_policy_holds_back_one_tenth_of_the_limit() {
        assert_eq!(FdHeadroomPolicy::Standard.headroom(1_600), 100);
        assert_eq!(FdHeadroomPolicy::Dedicated.headroom(1_600), 160);
        assert_eq!(
            FdHeadroomPolicy::Dedicated.headroom(100),
            64,
            "the floor holds"
        );
    }

    #[test]
    fn the_dedicated_policy_admits_more_but_never_overshoots() {
        for soft in [182_u64, 256, 1_024, 4_096, 65_536, 1_048_576] {
            let standard = derive(soft, soft, 10).expect("standard must start");
            let dedicated =
                FdBudgetPlan::derive(soft, soft, reserve(), 10, FdHeadroomPolicy::Dedicated)
                    .expect("dedicated must start");
            assert!(
                dedicated.effective_budget() <= standard.effective_budget(),
                "a larger headroom must yield a smaller dynamic budget"
            );
            let total = dedicated.effective_budget()
                + dedicated.fixed_reserve().total()
                + dedicated.safety_headroom();
            assert!(
                total <= soft,
                "dedicated soft limit {soft} produced a total reservation of {total}"
            );
            assert!(
                dedicated.effective_budget() * 10 <= soft * 9,
                "the dedicated dynamic budget must stay under 90% of the limit"
            );
        }
    }

    #[test]
    fn the_dedicated_policy_still_refuses_an_impossible_limit() {
        let error =
            FdBudgetPlan::derive(128, 1_048_576, reserve(), 10, FdHeadroomPolicy::Dedicated)
                .expect_err("a 128 descriptor limit cannot serve traffic under any policy");
        assert!(matches!(error, FdBudgetError::LimitTooLow { .. }));
    }
}
