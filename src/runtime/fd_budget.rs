//! Strict upper-bound file-descriptor admission.
//!
//! # Why this module exists
//!
//! A production server was terminated by `accept4(...) = -1 EMFILE`. The soft
//! `RLIMIT_NOFILE` was `1024`; the configuration, sized for a systemd unit with
//! `LimitNOFILE=1048576`, permitted roughly twenty-four thousand descriptors
//! across inbound sockets, cover mirrors, outbound sockets and splice pipes.
//! Nothing in the process read the limit, so the mismatch was discovered by the
//! kernel rather than by the configuration validator.
//!
//! # Design
//!
//! Three properties are structural rather than conventional:
//!
//! * **No overshoot.** [`FdBudget::try_acquire`] is a checked compare-exchange
//!   loop. The in-use count can never exceed capacity, even transiently, even
//!   under arbitrary concurrency. Accounting may over-reserve; it may never
//!   under-reserve.
//! * **No heavyweight hot-path lock.** The fast path is one relaxed load and
//!   one `compare_exchange_weak`. There is no `Mutex` anywhere in this module.
//! * **Release is RAII.** [`FdPermit`] releases in `Drop`, so cancellation,
//!   timeout, early return, `?` propagation and panic containment all release
//!   through the same path. A permit is held by the same object that owns the
//!   descriptor, never by a detached task.
//!
//! Release uses a *checked* subtraction rather than a saturating one. A
//! saturating release would silently absorb a double-release bug and slowly
//! leak capacity; the checked form records the underflow so a test can fail on
//! it.
//!
//! # Units, not descriptors
//!
//! A permit is denominated in conservative *units*. One unit is one descriptor
//! the process expects to hold. A bidirectional splice relay costs four units
//! because it creates two pipe pairs. The count does not model kernel-internal
//! objects, and it is not a measurement: it is a reservation.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use tokio::sync::Notify;

/// Conservative descriptor cost of one accepted inbound socket.
pub const UNITS_INBOUND_SOCKET: u32 = 1;
/// Conservative descriptor cost of one connected outbound socket.
pub const UNITS_OUTBOUND_SOCKET: u32 = 1;
/// Conservative descriptor cost of one live connector candidate socket.
/// Conservative descriptor cost of one bidirectional splice relay.
///
/// A bidirectional splice relay creates two pipe pairs, and a pipe pair is two
/// descriptors. The incident trace reached `pipe2(...) = -1 EMFILE` precisely
/// because this cost was never reserved.
pub const UNITS_SPLICE_RELAY: u32 = 4;
/// Conservative descriptor cost of one single-direction splice relay.
///
/// A directional splice relay creates one pipe pair, and a pipe pair is two
/// descriptors — exactly half of a bilateral splice relay.
pub const UNITS_SPLICE_DIRECTION: u32 = 2;

/// Whether the process is currently operating under descriptor pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdPressure {
    /// Capacity is available; the listener accepts normally.
    Normal,
    /// The high watermark was crossed; the listener pauses until capacity returns.
    High,
}

impl FdPressure {
    /// Returns the stable identifier used in logs and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

/// A strict, lock-free, RAII descriptor budget.
#[derive(Clone)]
pub struct FdBudget {
    inner: Arc<FdBudgetInner>,
}

struct FdBudgetInner {
    used: AtomicU64,
    capacity: u64,
    high_watermark: u64,
    low_watermark: u64,
    under_pressure: AtomicBool,
    released: Notify,
    waiters: AtomicU64,
    peak_used: AtomicU64,
    denials: AtomicU64,
    underflows: AtomicU64,
    pressure_transitions: AtomicU64,
}

impl FdBudget {
    /// Creates a budget with hysteresis watermarks derived from `capacity`.
    ///
    /// The high watermark is 15/16 of capacity and the low watermark is 13/16,
    /// which gives a resume gap wide enough that a burst of releases does not
    /// re-enter pressure on the next accept. Both are clamped so that a tiny
    /// capacity — which the low-RLIMIT tests deliberately construct — still has
    /// a strictly ordered `low <= high <= capacity`.
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        let capacity = capacity.max(1);
        let high_watermark = capacity.saturating_mul(15) / 16;
        let high_watermark = high_watermark.clamp(1, capacity);
        let low_watermark = capacity.saturating_mul(13) / 16;
        let low_watermark = low_watermark.min(high_watermark);
        Self {
            inner: Arc::new(FdBudgetInner {
                used: AtomicU64::new(0),
                capacity,
                high_watermark,
                low_watermark,
                under_pressure: AtomicBool::new(false),
                released: Notify::new(),
                waiters: AtomicU64::new(0),
                peak_used: AtomicU64::new(0),
                denials: AtomicU64::new(0),
                underflows: AtomicU64::new(0),
                pressure_transitions: AtomicU64::new(0),
            }),
        }
    }

    /// Returns the total admissible unit count.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.inner.capacity
    }

    /// Returns the units currently reserved.
    ///
    /// The value is a snapshot. Admission is strict; this observation is not.
    #[must_use]
    pub fn in_use(&self) -> u64 {
        self.inner.used.load(Ordering::Acquire)
    }

    /// Returns the largest simultaneous reservation observed.
    #[must_use]
    pub fn peak_in_use(&self) -> u64 {
        self.inner.peak_used.load(Ordering::Relaxed)
    }

    /// Returns how many acquisitions were refused for lack of capacity.
    #[must_use]
    pub fn denials(&self) -> u64 {
        self.inner.denials.load(Ordering::Relaxed)
    }

    /// Returns how many releases attempted to drop below zero.
    ///
    /// A non-zero value is a double-release bug. Tests assert it stays zero.
    #[must_use]
    pub fn underflows(&self) -> u64 {
        self.inner.underflows.load(Ordering::Relaxed)
    }

    /// Returns how many times the pressure state changed.
    ///
    /// Pressure logging is transition-based, so this doubles as the bound on
    /// how many pressure lines an operator can ever see.
    #[must_use]
    pub fn pressure_transitions(&self) -> u64 {
        self.inner.pressure_transitions.load(Ordering::Relaxed)
    }

    /// Returns the current pressure state.
    #[must_use]
    pub fn pressure(&self) -> FdPressure {
        if self.inner.under_pressure.load(Ordering::Acquire) {
            FdPressure::High
        } else {
            FdPressure::Normal
        }
    }

    /// Reserves `units` without waiting, or returns `None`.
    ///
    /// The reservation is strict: on return the in-use count is at most
    /// [`Self::capacity`], and no interleaving of concurrent callers can push it
    /// past that bound.
    #[must_use]
    pub fn try_acquire(&self, units: u32) -> Option<FdPermit> {
        if units == 0 {
            return Some(FdPermit {
                budget: self.clone(),
                units: 0,
            });
        }
        let requested = u64::from(units);
        let mut current = self.inner.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(requested) else {
                self.inner.denials.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if next > self.inner.capacity {
                self.inner.denials.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            match self.inner.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.observe_acquired(next);
                    return Some(FdPermit {
                        budget: self.clone(),
                        units,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Reserves `units`, waiting for capacity when the budget is exhausted.
    ///
    /// The wait is a bounded `Notify` wakeup, never a poll loop. `Notify`
    /// registers a `Notified` lazily at its first poll and `notify_waiters`
    /// stores no permit, so the waiter is registered eagerly with `enable`
    /// *before* the final capacity re-check: a release landing between the
    /// failed attempt and the wait then still wakes it.
    pub async fn acquire(&self, units: u32) -> FdPermit {
        loop {
            if let Some(permit) = self.try_acquire(units) {
                return permit;
            }
            // Counted as a waiter only after a failed attempt, and registered
            // with the Notify before the recheck, so a release between them
            // either lands on the recheck or on the registered waiter. The
            // release path pays the Notify cost only when someone listens.
            self.inner.waiters.fetch_add(1, Ordering::Relaxed);
            let notified = self.inner.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(permit) = self.try_acquire(units) {
                self.inner.waiters.fetch_sub(1, Ordering::Relaxed);
                return permit;
            }
            notified.await;
            self.inner.waiters.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn observe_acquired(&self, next: u64) {
        self.inner.peak_used.fetch_max(next, Ordering::Relaxed);
        if next >= self.inner.high_watermark
            && !self.inner.under_pressure.swap(true, Ordering::AcqRel)
        {
            self.inner
                .pressure_transitions
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn release(&self, units: u32) {
        if units == 0 {
            return;
        }
        let requested = u64::from(units);
        let outcome = self
            .inner
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(requested)
            });
        let Ok(previous) = outcome else {
            // A saturating subtraction here would hide the bug. Record it so a
            // test can fail on it, and do not corrupt the counter further.
            self.inner.underflows.fetch_add(1, Ordering::Relaxed);
            debug_assert!(
                false,
                "descriptor budget released more units than were reserved"
            );
            return;
        };
        let remaining = previous.saturating_sub(requested);
        if remaining <= self.inner.low_watermark
            && self.inner.under_pressure.swap(false, Ordering::AcqRel)
        {
            self.inner
                .pressure_transitions
                .fetch_add(1, Ordering::Relaxed);
        }
        // Every release reaches here, but almost none of them have a listener:
        // skip the Notify (and its global wait-list lock) unless a waiter is
        // registered. A waiter that registered after this check is still inside
        // its capacity recheck and sees the freed units without a wake.
        if self.inner.waiters.load(Ordering::Relaxed) > 0 {
            self.inner.released.notify_waiters();
        }
    }
}

impl fmt::Debug for FdBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FdBudget")
            .field("capacity", &self.inner.capacity)
            .field("in_use", &self.in_use())
            .field("high_watermark", &self.inner.high_watermark)
            .field("low_watermark", &self.inner.low_watermark)
            .field("pressure", &self.pressure())
            .finish_non_exhaustive()
    }
}

/// A reservation that releases exactly once, in `Drop`.
///
/// The permit must live in the same object as the descriptor it accounts for.
/// Storing it anywhere that can outlive the descriptor reintroduces the leak
/// this type exists to prevent.
pub struct FdPermit {
    budget: FdBudget,
    units: u32,
}

impl FdPermit {
    /// Returns the reserved unit count.
    #[must_use]
    pub const fn units(&self) -> u32 {
        self.units
    }

    /// Releases the reservation before the permit is dropped.
    ///
    /// Used where a descriptor is closed well before its owner goes out of
    /// scope, so capacity returns at close time rather than at scope end.
    pub fn release_now(mut self) {
        let units = std::mem::take(&mut self.units);
        self.budget.release(units);
    }

    /// Merges another permit for the same budget into this one.
    ///
    /// # Errors
    ///
    /// Returns both permits unchanged when they belong to different budgets or
    /// when the combined unit count would overflow.
    pub fn merge(mut self, other: Self) -> Result<Self, (Self, Self)> {
        if !Arc::ptr_eq(&self.budget.inner, &other.budget.inner) {
            return Err((self, other));
        }
        let Some(total) = self.units.checked_add(other.units) else {
            return Err((self, other));
        };
        let mut other = other;
        other.units = 0;
        drop(other);
        self.units = total;
        Ok(self)
    }
}

impl fmt::Debug for FdPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FdPermit")
            .field("units", &self.units)
            .finish_non_exhaustive()
    }
}

impl Drop for FdPermit {
    fn drop(&mut self) {
        self.budget.release(self.units);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, atomic::AtomicU64};

    use super::{FdBudget, FdPressure};

    #[test]
    fn a_strict_budget_never_admits_more_than_its_capacity() {
        let budget = FdBudget::new(4);
        let permits: Vec<_> = (0..4)
            .map(|_| budget.try_acquire(1).expect("capacity must admit"))
            .collect();
        assert_eq!(budget.in_use(), 4);
        assert!(
            budget.try_acquire(1).is_none(),
            "admission past capacity is the exact defect this type prevents"
        );
        assert_eq!(budget.denials(), 1);
        drop(permits);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.underflows(), 0);
    }

    #[test]
    fn a_multi_unit_permit_is_all_or_nothing() {
        let budget = FdBudget::new(4);
        let held = budget.try_acquire(3).expect("three units must fit");
        assert!(
            budget.try_acquire(4).is_none(),
            "a partial reservation would let the process exceed its limit"
        );
        assert_eq!(budget.in_use(), 3);
        let last = budget.try_acquire(1).expect("the remaining unit must fit");
        assert_eq!(budget.in_use(), 4);
        drop(held);
        drop(last);
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn concurrent_acquisition_never_overshoots() {
        const THREADS: usize = 16;
        const CAPACITY: u64 = 64;

        let budget = FdBudget::new(CAPACITY);
        let barrier = Arc::new(Barrier::new(THREADS));
        let observed_peak = Arc::new(AtomicU64::new(0));
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let budget = budget.clone();
                let barrier = Arc::clone(&barrier);
                let observed_peak = Arc::clone(&observed_peak);
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..2_000 {
                        if let Some(permit) = budget.try_acquire(2) {
                            let in_use = budget.in_use();
                            observed_peak.fetch_max(in_use, std::sync::atomic::Ordering::Relaxed);
                            assert!(
                                in_use <= CAPACITY,
                                "observed {in_use} units against a capacity of {CAPACITY}"
                            );
                            drop(permit);
                        }
                    }
                });
            }
        });
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.underflows(), 0);
        assert!(budget.peak_in_use() <= CAPACITY);
    }

    #[test]
    fn repeated_cycles_return_the_counter_to_baseline() {
        let budget = FdBudget::new(8);
        for _ in 0..10_000 {
            let first = budget.try_acquire(4).expect("capacity must admit");
            let second = budget.try_acquire(4).expect("capacity must admit");
            assert_eq!(budget.in_use(), 8);
            drop(first);
            drop(second);
            assert_eq!(budget.in_use(), 0);
        }
        assert_eq!(budget.underflows(), 0);
        assert_eq!(budget.peak_in_use(), 8);
    }

    #[test]
    fn releasing_early_returns_capacity_before_the_permit_scope_ends() {
        let budget = FdBudget::new(2);
        let permit = budget.try_acquire(2).expect("capacity must admit");
        assert!(budget.try_acquire(1).is_none());
        permit.release_now();
        assert_eq!(budget.in_use(), 0);
        assert!(budget.try_acquire(1).is_some());
    }

    #[test]
    fn merging_permits_preserves_the_total_reservation() {
        let budget = FdBudget::new(8);
        let first = budget.try_acquire(2).expect("capacity must admit");
        let second = budget.try_acquire(3).expect("capacity must admit");
        let merged = first.merge(second).expect("same budget must merge");
        assert_eq!(merged.units(), 5);
        assert_eq!(budget.in_use(), 5);
        drop(merged);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.underflows(), 0);
    }

    #[test]
    fn merging_across_budgets_is_refused_without_losing_either_reservation() {
        let first_budget = FdBudget::new(4);
        let second_budget = FdBudget::new(4);
        let first = first_budget.try_acquire(1).expect("capacity must admit");
        let second = second_budget.try_acquire(1).expect("capacity must admit");
        let (first, second) = first
            .merge(second)
            .expect_err("permits from different budgets must not merge");
        assert_eq!(first_budget.in_use(), 1);
        assert_eq!(second_budget.in_use(), 1);
        drop(first);
        drop(second);
        assert_eq!(first_budget.in_use(), 0);
        assert_eq!(second_budget.in_use(), 0);
    }

    #[test]
    fn pressure_uses_hysteresis_rather_than_a_single_threshold() {
        let budget = FdBudget::new(16);
        let mut held = Vec::new();
        for _ in 0..14 {
            held.push(budget.try_acquire(1).expect("capacity must admit"));
        }
        assert_eq!(budget.pressure(), FdPressure::Normal);
        held.push(budget.try_acquire(1).expect("capacity must admit"));
        assert_eq!(
            budget.pressure(),
            FdPressure::High,
            "the high watermark is 15/16 of capacity"
        );
        held.pop();
        assert_eq!(
            budget.pressure(),
            FdPressure::High,
            "leaving pressure at the same point it was entered causes oscillation"
        );
        held.pop();
        assert_eq!(
            budget.pressure(),
            FdPressure::Normal,
            "the low watermark is 13/16 of capacity"
        );
        assert_eq!(budget.pressure_transitions(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_acquirer_is_woken_by_a_release() {
        let budget = FdBudget::new(1);
        let held = budget.try_acquire(1).expect("capacity must admit");
        let waiter = {
            let budget = budget.clone();
            tokio::spawn(async move { budget.acquire(1).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "the waiter must not be admitted yet");
        drop(held);
        let permit = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("a released permit must wake a waiter")
            .expect("the waiting task must not panic");
        assert_eq!(budget.in_use(), 1);
        drop(permit);
        assert_eq!(budget.in_use(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_cancelled_acquirer_reserves_nothing() {
        let budget = FdBudget::new(1);
        let held = budget.try_acquire(1).expect("capacity must admit");
        let acquire = budget.acquire(1);
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(20), acquire).await;
        assert!(cancelled.is_err(), "the acquire must still be waiting");
        assert_eq!(
            budget.in_use(),
            1,
            "a cancelled acquire must not have reserved anything"
        );
        drop(held);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.underflows(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rapid_acquire_release_cycles_never_strand_a_waiter() {
        // Regression test for the lost-wakeup race: `Notify` registers a
        // `Notified` lazily at first poll and `notify_waiters` stores no
        // permit, so without eager registration a release landing between the
        // capacity re-check and the first poll could be missed. Thousands of
        // rapid cycles with an active waiter must always terminate.
        for _ in 0..4_000 {
            let budget = FdBudget::new(1);
            let held = budget.try_acquire(1).expect("capacity must admit");
            let waiter = {
                let budget = budget.clone();
                tokio::spawn(async move { budget.acquire(1).await })
            };
            tokio::task::yield_now().await;
            drop(held);
            let permit = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
                .await
                .expect("a waiter must never be stranded by a missed release")
                .expect("the waiting task must not panic");
            assert_eq!(budget.in_use(), 1);
            drop(permit);
            assert_eq!(budget.in_use(), 0);
        }
    }

    #[test]
    fn a_zero_unit_permit_is_inert() {
        let budget = FdBudget::new(1);
        let permit = budget.try_acquire(0).expect("zero units always admit");
        assert_eq!(budget.in_use(), 0);
        assert!(budget.try_acquire(1).is_some());
        drop(permit);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.underflows(), 0);
    }
}
