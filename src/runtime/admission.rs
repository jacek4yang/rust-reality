use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use crate::config::{DirectBarrierConfig, ResourceGovernorConfig};
use crate::runtime::ceiling::{CeilingPermit, CeilingSemaphore};
use crate::runtime::pressure::{PressureGauge, ResourcePressure};

/// Independently bounded work categories in the unauthenticated and setup paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionKind {
    /// Accepted client sockets.
    Connection,
    /// Incomplete authenticated handshakes.
    Handshake,
    /// Cover-target fallback sessions.
    Fallback,
    /// Expensive asymmetric or post-quantum operations.
    CryptoOperation,
    /// Pending and committed replay entries.
    ReplayEntry,
    /// In-flight DNS resolutions, held until the underlying lookup ends.
    DnsLookup,
}

/// A bounded resource or rate rejected additional work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDenied {
    /// No permit is currently available for this category.
    Limit(AdmissionKind),
    /// The resource-pressure state pauses this category.
    Pressure(AdmissionKind),
    /// The direct outbound concurrency barrier is full.
    DirectConcurrency,
    /// The direct outbound new-connection rate was exceeded.
    DirectRate,
    /// The resource-pressure state pauses new direct outbound connects.
    DirectPressure,
    /// Internal synchronization is unavailable after a poisoned lock or closed semaphore.
    Unavailable,
}

impl fmt::Display for AdmissionDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(kind) => write!(formatter, "admission limit reached for {kind:?}"),
            Self::Pressure(kind) => {
                write!(formatter, "resource pressure pauses admission for {kind:?}")
            }
            Self::DirectConcurrency => {
                formatter.write_str("direct outbound concurrency limit reached")
            }
            Self::DirectRate => formatter.write_str("direct outbound rate limit reached"),
            Self::DirectPressure => {
                formatter.write_str("resource pressure pauses direct outbound connects")
            }
            Self::Unavailable => formatter.write_str("admission control is unavailable"),
        }
    }
}

impl Error for AdmissionDenied {}

/// An RAII permit that releases capacity even on timeout, cancellation, or early return.
pub struct AdmissionPermit {
    kind: AdmissionKind,
    _permit: CeilingPermit,
}

impl AdmissionPermit {
    /// Returns the bounded category held by this permit.
    #[must_use]
    pub const fn kind(&self) -> AdmissionKind {
        self.kind
    }
}

struct GovernorInner {
    connections: CeilingSemaphore,
    handshakes: CeilingSemaphore,
    fallbacks: CeilingSemaphore,
    dns_lookups: CeilingSemaphore,
    crypto_operations: CeilingSemaphore,
    replay_entries: CeilingSemaphore,
    pressure: Option<PressureGauge>,
}

/// Non-waiting admission control for resources exposed before authentication.
#[derive(Clone)]
pub struct ResourceGovernor {
    inner: Arc<GovernorInner>,
}

impl ResourceGovernor {
    /// Creates independent bounded resource pools from validated configuration.
    #[must_use]
    pub fn new(config: &ResourceGovernorConfig) -> Self {
        Self::pools(config, None)
    }

    /// Creates bounded resource pools that also honor the pressure gauge.
    ///
    /// The gauge is process-lifetime; in standard resource mode it never
    /// leaves `Normal`, so gating is one extra atomic load that always
    /// admits. Under `Pressure`, new fallback and handshake work is refused;
    /// under `Critical`, every new category is refused. Held permits are
    /// never affected.
    #[must_use]
    pub fn with_pressure(config: &ResourceGovernorConfig, pressure: PressureGauge) -> Self {
        Self::pools(config, Some(pressure))
    }

    fn pools(config: &ResourceGovernorConfig, pressure: Option<PressureGauge>) -> Self {
        Self {
            inner: Arc::new(GovernorInner {
                connections: CeilingSemaphore::new(config.max_connections),
                handshakes: CeilingSemaphore::new(config.max_handshakes),
                fallbacks: CeilingSemaphore::new(config.max_fallbacks),
                dns_lookups: CeilingSemaphore::new(config.max_dns_lookups),
                crypto_operations: CeilingSemaphore::new(config.max_crypto_operations),
                replay_entries: CeilingSemaphore::new(config.max_replay_entries),
                pressure,
            }),
        }
    }

    /// Attempts immediate admission without building an attacker-controlled wait queue.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionDenied`] when the selected limit is full, the
    /// pressure state pauses the category, or synchronization is unavailable.
    pub fn try_acquire(&self, kind: AdmissionKind) -> Result<AdmissionPermit, AdmissionDenied> {
        if let Some(gauge) = &self.inner.pressure
            && !gauge.state().admits(kind)
        {
            return Err(AdmissionDenied::Pressure(kind));
        }
        let permit = self
            .pool(kind)
            .try_acquire()
            .ok_or(AdmissionDenied::Limit(kind))?;
        Ok(AdmissionPermit {
            kind,
            _permit: permit,
        })
    }

    /// Returns the soft ceiling currently in effect for `kind`.
    ///
    /// Ceilings start at the configured limit and only move when a controller
    /// adjusts them, so behavior is identical to a fixed pool until then.
    #[must_use]
    pub fn ceiling(&self, kind: AdmissionKind) -> u64 {
        self.pool(kind).ceiling()
    }

    /// Adjusts the soft ceiling for `kind`, clamped to the configured limit.
    ///
    /// Lowering takes effect on subsequent acquires only; permits already
    /// held are never revoked. This is the adaptive-controller knob from the
    /// v1.6 design (§3.3); until a controller exists, nothing calls it and
    /// admission behaves exactly as a fixed-size pool.
    pub fn set_ceiling(&self, kind: AdmissionKind, ceiling: u64) {
        self.pool(kind).set_ceiling(ceiling);
    }

    /// Returns the number of permits currently held for `kind`, for the
    /// controller's published snapshot and pressure signals.
    #[must_use]
    pub fn in_flight(&self, kind: AdmissionKind) -> u64 {
        self.pool(kind).in_flight()
    }

    fn pool(&self, kind: AdmissionKind) -> &CeilingSemaphore {
        match kind {
            AdmissionKind::Connection => &self.inner.connections,
            AdmissionKind::Handshake => &self.inner.handshakes,
            AdmissionKind::Fallback => &self.inner.fallbacks,
            AdmissionKind::CryptoOperation => &self.inner.crypto_operations,
            AdmissionKind::ReplayEntry => &self.inner.replay_entries,
            AdmissionKind::DnsLookup => &self.inner.dns_lookups,
        }
    }
}

/// RAII direct-dial concurrency permit.
pub struct DirectPermit {
    _permit: CeilingPermit,
}

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// GCRA timing parameters for a dials-per-second rate: the conservative
/// integral-nanosecond emission interval and the one-second burst allowance.
fn rate_timing(rate: u64) -> (u64, u64) {
    let interval_nanos = if rate == 0 {
        0
    } else {
        NANOS_PER_SECOND.div_ceil(rate)
    };
    (interval_nanos, interval_nanos.saturating_mul(rate))
}

/// Lock-free GCRA gate with the same one-second burst allowance as the former
/// token bucket. A conservative integral-nanosecond interval prevents the gate
/// from ever exceeding the configured rate. The interval and burst are atomic
/// so the adaptive controller can retarget the rate at runtime (design §3.3).
struct DialRateGate {
    origin: Instant,
    rate_per_second: AtomicU64,
    interval_nanos: AtomicU64,
    burst_nanos: AtomicU64,
    next_nanos: AtomicU64,
}

impl DialRateGate {
    fn new(max_per_second: u32) -> Self {
        let (interval_nanos, burst_nanos) = rate_timing(u64::from(max_per_second));
        Self {
            origin: Instant::now(),
            rate_per_second: AtomicU64::new(u64::from(max_per_second)),
            interval_nanos: AtomicU64::new(interval_nanos),
            burst_nanos: AtomicU64::new(burst_nanos),
            next_nanos: AtomicU64::new(0),
        }
    }

    /// Recomputes the GCRA timing for a new rate. The burst allowance is
    /// stored before the interval so a racing `try_take` that sees the new
    /// interval already sees the new burst; an attempt mid-change may still
    /// pair the old interval with the new burst once, which is bounded by
    /// both rates and harmless. The accumulated `next_nanos` history is kept,
    /// so a rate change never grants a retroactive burst.
    fn set_rate(&self, max_per_second: u32) {
        let (interval_nanos, burst_nanos) = rate_timing(u64::from(max_per_second));
        self.burst_nanos.store(burst_nanos, Ordering::Relaxed);
        self.interval_nanos.store(interval_nanos, Ordering::Relaxed);
        self.rate_per_second
            .store(u64::from(max_per_second), Ordering::Relaxed);
    }

    fn rate(&self) -> u32 {
        u32::try_from(self.rate_per_second.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    fn try_take(&self) -> bool {
        let now_nanos = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.try_take_at(now_nanos)
    }

    fn try_take_at(&self, now_nanos: u64) -> bool {
        let interval_nanos = self.interval_nanos.load(Ordering::Relaxed);
        if interval_nanos == 0 {
            return false;
        }
        let latest = now_nanos.saturating_add(self.burst_nanos.load(Ordering::Relaxed));
        let mut observed = self.next_nanos.load(Ordering::Relaxed);
        loop {
            let Some(next) = observed.max(now_nanos).checked_add(interval_nanos) else {
                // Do not let saturation turn MAX -> MAX into an endlessly
                // successful compare-exchange after the time domain is spent.
                return false;
            };
            if next > latest {
                return false;
            }
            match self.next_nanos.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => observed = actual,
            }
        }
    }
}

struct DirectBarrierInner {
    concurrency: CeilingSemaphore,
    rate: DialRateGate,
    pressure: Option<PressureGauge>,
}

/// Direct outbound isolation with independent concurrency and lock-free GCRA limits.
#[derive(Clone)]
pub struct DirectBarrier {
    inner: Arc<DirectBarrierInner>,
}

impl DirectBarrier {
    /// Creates a direct-dial barrier from validated configuration.
    #[must_use]
    pub fn new(config: &DirectBarrierConfig) -> Self {
        Self::barrier(config, None)
    }

    /// Creates a direct-dial barrier that pauses new dials at `Critical`
    /// pressure. Established relays hold no barrier permit, so pausing new
    /// dials never interrupts traffic already flowing.
    #[must_use]
    pub fn with_pressure(config: &DirectBarrierConfig, pressure: PressureGauge) -> Self {
        Self::barrier(config, Some(pressure))
    }

    fn barrier(config: &DirectBarrierConfig, pressure: Option<PressureGauge>) -> Self {
        Self {
            inner: Arc::new(DirectBarrierInner {
                concurrency: CeilingSemaphore::new(config.max_concurrent),
                rate: DialRateGate::new(config.max_per_second),
                pressure,
            }),
        }
    }

    /// Attempts a direct dial without queuing. Capacity is released on every drop path.
    ///
    /// Callers hold the returned permit only for the dial itself and drop it as
    /// soon as the connect resolves, so an established relay consumes no
    /// barrier capacity.
    ///
    /// # Errors
    ///
    /// Returns a category-specific denial when concurrency, rate, pressure, or
    /// synchronization prevents immediate admission.
    pub fn try_acquire(&self) -> Result<DirectPermit, AdmissionDenied> {
        if let Some(gauge) = &self.inner.pressure
            && gauge.state() == ResourcePressure::Critical
        {
            return Err(AdmissionDenied::DirectPressure);
        }
        let permit = self
            .inner
            .concurrency
            .try_acquire()
            .ok_or(AdmissionDenied::DirectConcurrency)?;
        if !self.inner.rate.try_take() {
            return Err(AdmissionDenied::DirectRate);
        }
        Ok(DirectPermit { _permit: permit })
    }

    /// Returns the soft ceiling on concurrent direct dials.
    #[must_use]
    pub fn concurrency_ceiling(&self) -> u64 {
        self.inner.concurrency.ceiling()
    }

    /// Adjusts the soft ceiling on concurrent direct dials, clamped to the
    /// configured limit. Lowering takes effect on subsequent dials only;
    /// held dial permits are never revoked (design §3.3).
    pub fn set_concurrency_ceiling(&self, ceiling: u64) {
        self.inner.concurrency.set_ceiling(ceiling);
    }

    /// Returns the new-connection rate currently in effect, in dials per second.
    #[must_use]
    pub fn rate_per_second(&self) -> u32 {
        self.inner.rate.rate()
    }

    /// Retargets the GCRA new-connection rate. The new rate governs
    /// subsequent dials only; the gate's history is preserved, so no
    /// retroactive burst is granted (design §3.3).
    pub fn set_rate_per_second(&self, max_per_second: u32) {
        self.inner.rate.set_rate(max_per_second);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    };

    use crate::config::{DirectBarrierConfig, ResourceGovernorConfig};

    use super::{
        AdmissionDenied, AdmissionKind, DialRateGate, DirectBarrier, NANOS_PER_SECOND,
        ResourceGovernor,
    };

    #[test]
    fn governor_releases_permit_on_drop() {
        let config = ResourceGovernorConfig {
            max_connections: 1,
            ..ResourceGovernorConfig::default()
        };
        let governor = ResourceGovernor::new(&config);
        let permit = governor
            .try_acquire(AdmissionKind::Connection)
            .expect("first connection must be admitted");

        assert!(matches!(
            governor.try_acquire(AdmissionKind::Connection),
            Err(AdmissionDenied::Limit(AdmissionKind::Connection))
        ));
        drop(permit);
        assert!(governor.try_acquire(AdmissionKind::Connection).is_ok());
    }

    #[test]
    fn governor_keeps_resource_pools_independent() {
        let config = ResourceGovernorConfig {
            max_handshakes: 1,
            ..ResourceGovernorConfig::default()
        };
        let governor = ResourceGovernor::new(&config);
        let handshake = governor
            .try_acquire(AdmissionKind::Handshake)
            .expect("handshake must be admitted");

        assert!(governor.try_acquire(AdmissionKind::CryptoOperation).is_ok());
        assert_eq!(handshake.kind(), AdmissionKind::Handshake);
    }

    #[test]
    fn governor_ceilings_default_to_the_configured_limits() {
        let config = ResourceGovernorConfig {
            max_connections: 7,
            max_handshakes: 3,
            ..ResourceGovernorConfig::default()
        };
        let governor = ResourceGovernor::new(&config);

        assert_eq!(governor.ceiling(AdmissionKind::Connection), 7);
        assert_eq!(governor.ceiling(AdmissionKind::Handshake), 3);
    }

    #[test]
    fn governor_denial_accounting_stays_exact_around_shrink_and_grow() {
        let config = ResourceGovernorConfig {
            max_connections: 4,
            max_handshakes: 4,
            ..ResourceGovernorConfig::default()
        };
        let governor = ResourceGovernor::new(&config);

        let held: Vec<_> = (0..4)
            .map(|_| {
                governor
                    .try_acquire(AdmissionKind::Connection)
                    .expect("at the configured limit")
            })
            .collect();
        for _ in 0..3 {
            assert!(matches!(
                governor.try_acquire(AdmissionKind::Connection),
                Err(AdmissionDenied::Limit(AdmissionKind::Connection))
            ));
        }

        governor.set_ceiling(AdmissionKind::Connection, 1);
        assert_eq!(governor.ceiling(AdmissionKind::Connection), 1);
        drop(held);
        let one = governor
            .try_acquire(AdmissionKind::Connection)
            .expect("the lowered ceiling still admits up to itself");
        assert!(matches!(
            governor.try_acquire(AdmissionKind::Connection),
            Err(AdmissionDenied::Limit(AdmissionKind::Connection))
        ));
        assert!(
            governor.try_acquire(AdmissionKind::Handshake).is_ok(),
            "shrinking one category leaves the others untouched"
        );

        governor.set_ceiling(AdmissionKind::Connection, u64::MAX);
        assert_eq!(
            governor.ceiling(AdmissionKind::Connection),
            4,
            "raising clamps to the configured limit"
        );
        drop(one);
        let refilled: Vec<_> = (0..4)
            .map(|_| {
                governor
                    .try_acquire(AdmissionKind::Connection)
                    .expect("grown ceiling readmits up to the configured limit")
            })
            .collect();
        assert!(matches!(
            governor.try_acquire(AdmissionKind::Connection),
            Err(AdmissionDenied::Limit(AdmissionKind::Connection))
        ));
        drop(refilled);
    }

    #[test]
    fn governor_shrink_under_load_never_revokes_and_never_exceeds_the_bound() {
        const MAX: u32 = 64;
        const WORKERS: usize = 8;
        const ROUNDS: usize = 2_000;
        let config = ResourceGovernorConfig {
            max_connections: MAX,
            ..ResourceGovernorConfig::default()
        };
        let governor = ResourceGovernor::new(&config);
        let held = Arc::new(AtomicU64::new(0));
        let max_held = Arc::new(AtomicU64::new(0));
        let start = Arc::new(Barrier::new(WORKERS + 2));

        std::thread::scope(|scope| {
            for _ in 0..WORKERS {
                let governor = governor.clone();
                let held = Arc::clone(&held);
                let max_held = Arc::clone(&max_held);
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..ROUNDS {
                        if let Ok(permit) = governor.try_acquire(AdmissionKind::Connection) {
                            let now = held.fetch_add(1, Ordering::Relaxed) + 1;
                            max_held.fetch_max(now, Ordering::Relaxed);
                            held.fetch_sub(1, Ordering::Relaxed);
                            drop(permit);
                        }
                    }
                });
            }
            let shrinker = {
                let governor = governor.clone();
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    for ceiling in [48, 16, 0, u64::from(MAX)] {
                        governor.set_ceiling(AdmissionKind::Connection, ceiling);
                    }
                })
            };
            start.wait();
            shrinker.join().expect("shrinker must not panic");
        });

        let observed = max_held.load(Ordering::Relaxed);
        assert!(
            observed <= u64::from(MAX),
            "held permits never exceed the configured limit: {observed}"
        );
        assert!(
            governor.try_acquire(AdmissionKind::Connection).is_ok(),
            "no waiter is stranded and the pool stays usable after shrink/grow"
        );
    }

    #[test]
    fn direct_barrier_enforces_concurrency_then_rate() {
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1,
        });
        let permit = barrier.try_acquire().expect("first dial must be admitted");

        assert!(matches!(
            barrier.try_acquire(),
            Err(AdmissionDenied::DirectConcurrency)
        ));
        drop(permit);
        assert!(matches!(
            barrier.try_acquire(),
            Err(AdmissionDenied::DirectRate)
        ));
    }

    #[test]
    fn direct_barrier_adjusts_concurrency_ceiling_without_revoking_dials() {
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 2,
            max_per_second: 1_000_000,
        });
        assert_eq!(barrier.concurrency_ceiling(), 2);
        let first = barrier.try_acquire().expect("first dial admitted");
        let second = barrier.try_acquire().expect("second dial admitted");

        barrier.set_concurrency_ceiling(1);
        assert_eq!(barrier.concurrency_ceiling(), 1);
        assert!(matches!(
            barrier.try_acquire(),
            Err(AdmissionDenied::DirectConcurrency)
        ));
        drop(first);
        assert!(
            matches!(
                barrier.try_acquire(),
                Err(AdmissionDenied::DirectConcurrency)
            ),
            "one held dial still reaches the lowered ceiling"
        );
        drop(second);
        let only = barrier.try_acquire().expect("drained dials readmit");
        assert!(matches!(
            barrier.try_acquire(),
            Err(AdmissionDenied::DirectConcurrency)
        ));
        drop(only);

        barrier.set_concurrency_ceiling(u64::MAX);
        assert_eq!(
            barrier.concurrency_ceiling(),
            2,
            "raising clamps to the configured limit"
        );
    }

    #[test]
    fn direct_barrier_retargets_the_rate_at_runtime() {
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1_000_000,
        });
        assert_eq!(barrier.rate_per_second(), 1_000_000);

        barrier.set_rate_per_second(0);
        assert_eq!(barrier.rate_per_second(), 0);
        assert!(matches!(
            barrier.try_acquire(),
            Err(AdmissionDenied::DirectRate)
        ));

        barrier.set_rate_per_second(1_000_000);
        assert!(
            barrier.try_acquire().is_ok(),
            "restoring the rate readmits dials"
        );
    }

    #[test]
    fn rate_gate_enforces_burst_and_refill_without_a_lock() {
        let gate = DialRateGate::new(4);
        let interval_nanos = gate.interval_nanos.load(Ordering::Relaxed);

        assert!((0..4).all(|_| gate.try_take_at(0)));
        assert!(!gate.try_take_at(0));
        assert!(gate.try_take_at(interval_nanos));
        assert!(!gate.try_take_at(interval_nanos));
    }

    #[test]
    fn rate_gate_never_oversubscribes_under_contention() {
        const RATE: u32 = 1_024;
        let gate = DialRateGate::new(RATE);
        let accepted = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| (0..512).filter(|_| gate.try_take_at(0)).count()))
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("rate worker must not panic"))
                .sum::<usize>()
        });

        assert_eq!(accepted, RATE as usize);
    }

    #[test]
    fn lowering_the_rate_denies_until_the_new_interval_allows() {
        let gate = DialRateGate::new(1_000);
        assert!(gate.try_take_at(0));
        assert!(gate.try_take_at(0), "the burst allowance still admits");

        gate.set_rate(1);
        assert_eq!(gate.rate(), 1);
        assert!(
            !gate.try_take_at(0),
            "the wider interval applies immediately"
        );
        assert!(
            gate.try_take_at(2 * 1_000_000),
            "admission resumes once the GCRA history plus the new interval elapses"
        );
    }

    #[test]
    fn raising_the_rate_applies_forward_without_a_retroactive_burst() {
        let gate = DialRateGate::new(1);
        assert!(gate.try_take_at(0));
        assert!(!gate.try_take_at(0));

        gate.set_rate(1_000);
        assert_eq!(gate.rate(), 1_000);
        assert!(
            !gate.try_take_at(0),
            "the accumulated GCRA history is kept across a rate change"
        );
        assert!(
            gate.try_take_at(NANOS_PER_SECOND),
            "the narrower interval governs subsequent slots"
        );
    }

    #[test]
    fn a_rate_of_zero_set_at_runtime_denies_everything() {
        let gate = DialRateGate::new(100);
        assert!(gate.try_take_at(0));

        gate.set_rate(0);
        assert_eq!(gate.rate(), 0);
        assert!(!gate.try_take_at(u64::MAX / 2));
    }

    #[test]
    fn zero_rate_rejects_without_panicking() {
        let gate = DialRateGate::new(0);
        assert!(!gate.try_take_at(0));
        assert!(!gate.try_take_at(u64::MAX));
    }

    #[test]
    fn exhausted_monotonic_time_fails_closed_instead_of_admitting_forever() {
        let gate = DialRateGate::new(1);
        assert!(!gate.try_take_at(u64::MAX));

        gate.next_nanos.store(u64::MAX, Ordering::Relaxed);
        assert!(!gate.try_take_at(0));
        assert_eq!(gate.next_nanos.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn pressure_refuses_fallback_first_then_handshake_then_everything() {
        let config = ResourceGovernorConfig::default();
        let gauge = crate::runtime::PressureGauge::new();
        let governor = ResourceGovernor::with_pressure(&config, gauge.clone());

        gauge.set(crate::runtime::ResourcePressure::Pressure);
        assert!(matches!(
            governor.try_acquire(AdmissionKind::Fallback),
            Err(AdmissionDenied::Pressure(AdmissionKind::Fallback))
        ));
        assert!(matches!(
            governor.try_acquire(AdmissionKind::Handshake),
            Err(AdmissionDenied::Pressure(AdmissionKind::Handshake))
        ));
        assert!(
            governor.try_acquire(AdmissionKind::Connection).is_ok(),
            "new connections are still admitted under pressure"
        );

        gauge.set(crate::runtime::ResourcePressure::Critical);
        assert!(matches!(
            governor.try_acquire(AdmissionKind::Connection),
            Err(AdmissionDenied::Pressure(AdmissionKind::Connection))
        ));

        gauge.set(crate::runtime::ResourcePressure::Normal);
        assert!(
            governor.try_acquire(AdmissionKind::Handshake).is_ok(),
            "admission resumes when the pressure state exits"
        );
    }

    #[test]
    fn a_governor_without_a_gauge_never_sees_pressure() {
        let config = ResourceGovernorConfig {
            max_fallbacks: 1,
            ..ResourceGovernorConfig::default()
        };
        let governor = ResourceGovernor::new(&config);
        assert!(
            governor.try_acquire(AdmissionKind::Fallback).is_ok(),
            "standard mode behavior is unchanged"
        );
    }

    #[test]
    fn the_direct_barrier_pauses_only_at_critical_pressure() {
        let config = DirectBarrierConfig {
            max_concurrent: 4,
            max_per_second: 1_000,
        };
        let gauge = crate::runtime::PressureGauge::new();
        let barrier = DirectBarrier::with_pressure(&config, gauge.clone());

        gauge.set(crate::runtime::ResourcePressure::Pressure);
        assert!(
            barrier.try_acquire().is_ok(),
            "pressure does not pause outbound dials for admitted sessions"
        );

        gauge.set(crate::runtime::ResourcePressure::Critical);
        assert!(matches!(
            barrier.try_acquire(),
            Err(AdmissionDenied::DirectPressure)
        ));

        gauge.set(crate::runtime::ResourcePressure::Normal);
        assert!(barrier.try_acquire().is_ok());
    }
}
