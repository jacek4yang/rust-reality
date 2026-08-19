//! Soft-ceiling semaphore: a tokio semaphore sized to a hard bound, gated by an
//! atomically adjustable ceiling (design v1.6.0 §3.3).
//!
//! Tokio's [`Semaphore`] supports `add_permits` but no shrink, so pool sizes
//! used to be fixed at construction. [`CeilingSemaphore`] keeps the hard bound
//! in the semaphore and enforces a controller-adjustable soft ceiling with a
//! CAS-guarded in-flight counter: two extra atomic operations on the acquire
//! hot path, no locks, and no wait queue, preserving the fail-fast admission
//! contract. Lowering the ceiling takes effect on subsequent acquires only;
//! permits already held are never revoked.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A fail-fast bounded pool whose soft ceiling can be raised or lowered at
/// runtime without revoking permits that are already held.
#[derive(Clone)]
pub(crate) struct CeilingSemaphore {
    /// Hard-bound permit pool, sized at construction and never resized.
    permits: Arc<Semaphore>,
    /// Currently held permits, CAS-guarded against the soft ceiling. All
    /// orderings are `Relaxed`: the counter is pure accounting and the
    /// semaphore itself synchronizes the permits it hands out.
    in_flight: Arc<AtomicU64>,
    /// Soft ceiling written by the adaptive controller; never above the hard bound.
    ceiling: Arc<AtomicU64>,
    /// Maximum value the ceiling can take; equals the configured pool size.
    hard_bound: u64,
}

/// An RAII permit that returns capacity to the soft-ceiling accounting on drop.
pub(crate) struct CeilingPermit {
    _permit: OwnedSemaphorePermit,
    in_flight: Arc<AtomicU64>,
}

impl Drop for CeilingPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl CeilingSemaphore {
    /// Creates a pool of `hard_bound` permits with the soft ceiling initially
    /// at the hard bound, matching the former fixed-size semaphore behavior.
    pub(crate) fn new(hard_bound: u32) -> Self {
        let hard_bound = u64::from(hard_bound);
        Self {
            permits: Arc::new(Semaphore::new(
                usize::try_from(hard_bound).unwrap_or(usize::MAX),
            )),
            in_flight: Arc::new(AtomicU64::new(0)),
            ceiling: Arc::new(AtomicU64::new(hard_bound)),
            hard_bound,
        }
    }

    /// Returns the current soft ceiling.
    pub(crate) fn ceiling(&self) -> u64 {
        self.ceiling.load(Ordering::Relaxed)
    }

    /// Returns the number of permits currently held.
    pub(crate) fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Moves the soft ceiling, clamped to the hard bound. Lowering takes
    /// effect on subsequent acquires only; held permits are never revoked, so
    /// the in-flight count may transiently exceed a freshly lowered ceiling.
    pub(crate) fn set_ceiling(&self, ceiling: u64) {
        self.ceiling
            .store(ceiling.min(self.hard_bound), Ordering::Relaxed);
    }

    /// Attempts immediate admission against the soft ceiling without waiting.
    ///
    /// The ceiling is read once per call: a concurrent lowering can admit one
    /// extra racing acquirer, but never above the hard bound, and the new
    /// ceiling reliably applies to subsequent calls.
    pub(crate) fn try_acquire(&self) -> Option<CeilingPermit> {
        let ceiling = self.ceiling();
        let mut observed = self.in_flight.load(Ordering::Relaxed);
        loop {
            if observed >= ceiling {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
        }
        match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => Some(CeilingPermit {
                _permit: permit,
                in_flight: Arc::clone(&self.in_flight),
            }),
            Err(_) => {
                // Unreachable while the ceiling stays clamped to the hard
                // bound (in_flight <= ceiling <= hard bound implies a permit
                // is available); roll the accounting back defensively.
                self.in_flight.fetch_sub(1, Ordering::Relaxed);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    };

    use super::CeilingSemaphore;

    #[test]
    fn acquire_fails_fast_at_the_ceiling_with_exact_denial_accounting() {
        let pool = CeilingSemaphore::new(3);
        let held: Vec<_> = (0..3)
            .map(|_| pool.try_acquire().expect("below the ceiling"))
            .collect();

        assert_eq!(pool.in_flight(), 3);
        assert!(pool.try_acquire().is_none());
        assert!(pool.try_acquire().is_none());
        assert_eq!(
            pool.in_flight(),
            3,
            "denied attempts must not consume capacity"
        );

        drop(held);
        assert_eq!(pool.in_flight(), 0, "dropped permits must be returned");
        assert!(pool.try_acquire().is_some());
    }

    #[test]
    fn raising_the_ceiling_admits_more_without_disturbing_held_permits() {
        let pool = CeilingSemaphore::new(4);
        pool.set_ceiling(2);
        let held: Vec<_> = (0..2)
            .map(|_| pool.try_acquire().expect("below the ceiling"))
            .collect();
        assert!(pool.try_acquire().is_none());

        pool.set_ceiling(4);
        let extra: Vec<_> = (0..2)
            .map(|_| pool.try_acquire().expect("raised ceiling must admit"))
            .collect();
        assert!(pool.try_acquire().is_none());
        drop((held, extra));
        assert_eq!(pool.in_flight(), 0);
    }

    #[test]
    fn lowering_never_revokes_and_applies_to_subsequent_acquires() {
        let pool = CeilingSemaphore::new(4);
        let mut held: Vec<_> = (0..4)
            .map(|_| pool.try_acquire().expect("below the ceiling"))
            .collect();

        pool.set_ceiling(1);
        assert!(
            pool.try_acquire().is_none(),
            "in-flight permits above the new ceiling are kept, not revoked"
        );
        drop(held.drain(..3));
        assert!(
            pool.try_acquire().is_none(),
            "one held permit still reaches the lowered ceiling"
        );
        drop(held);
        assert!(pool.try_acquire().is_some());
    }

    #[test]
    fn the_ceiling_is_clamped_to_the_hard_bound() {
        let pool = CeilingSemaphore::new(2);
        pool.set_ceiling(u64::MAX);
        assert_eq!(pool.ceiling(), 2);

        let held: Vec<_> = (0..2)
            .map(|_| pool.try_acquire().expect("at the hard bound"))
            .collect();
        assert!(
            pool.try_acquire().is_none(),
            "clamping must keep the pool from oversubscribing"
        );
        drop(held);
    }

    #[test]
    fn a_zero_ceiling_denies_everything_until_raised() {
        let pool = CeilingSemaphore::new(2);
        pool.set_ceiling(0);
        assert!(pool.try_acquire().is_none());
        pool.set_ceiling(1);
        assert!(pool.try_acquire().is_some());
    }

    #[test]
    fn racing_acquirers_split_exactly_into_ceiling_successes_and_denials() {
        const CEILING: u64 = 5;
        const RACERS: usize = 16;
        let pool = CeilingSemaphore::new(8);
        pool.set_ceiling(CEILING);
        let start = Arc::new(Barrier::new(RACERS + 1));

        let results = std::thread::scope(|scope| {
            let racers: Vec<_> = (0..RACERS)
                .map(|_| {
                    let start = Arc::clone(&start);
                    let pool = pool.clone();
                    scope.spawn(move || {
                        start.wait();
                        pool.try_acquire()
                    })
                })
                .collect();
            start.wait();
            racers
                .into_iter()
                .map(|racer| racer.join().expect("racer must not panic"))
                .collect::<Vec<_>>()
        });

        let admitted = results.iter().filter(|result| result.is_some()).count();
        assert_eq!(admitted, CEILING as usize);
        assert_eq!(RACERS - admitted, RACERS - CEILING as usize);
        assert_eq!(pool.in_flight(), CEILING);
        drop(results);
        assert_eq!(pool.in_flight(), 0);
    }

    #[test]
    fn shrinking_under_load_never_revokes_never_strands_and_drains_to_zero() {
        const HARD_BOUND: u32 = 64;
        const WORKERS: usize = 8;
        const ROUNDS: usize = 2_000;
        let pool = CeilingSemaphore::new(HARD_BOUND);
        let max_observed = Arc::new(AtomicU64::new(0));
        let start = Arc::new(Barrier::new(WORKERS + 2));

        std::thread::scope(|scope| {
            for _ in 0..WORKERS {
                let pool = pool.clone();
                let max_observed = Arc::clone(&max_observed);
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..ROUNDS {
                        if let Some(permit) = pool.try_acquire() {
                            max_observed.fetch_max(pool.in_flight(), Ordering::Relaxed);
                            drop(permit);
                        }
                    }
                });
            }
            let shrinker = {
                let pool = pool.clone();
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    for ceiling in [48, 16, 0, HARD_BOUND as u64] {
                        pool.set_ceiling(ceiling);
                    }
                })
            };
            start.wait();
            shrinker.join().expect("shrinker must not panic");
        });

        let observed = max_observed.load(Ordering::Relaxed);
        assert!(
            observed <= u64::from(HARD_BOUND),
            "held permits must never exceed the ceiling in effect at acquire time: {observed}"
        );
        assert_eq!(pool.in_flight(), 0, "no acquirer is stranded by a shrink");
        assert!(
            pool.try_acquire().is_some(),
            "the pool stays usable after concurrent shrink/grow"
        );
    }
}
