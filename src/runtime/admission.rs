//! Bounded admission for unauthenticated and setup-path work.
//!
//! [`ResourceGovernor`] hands out [`AdmissionPermit`]s per [`AdmissionKind`]
//! (connection, pre-auth idle, handshake, fallback, crypto, replay, DNS) and a
//! separate direct-outbound barrier. Denials are immediate [`AdmissionDenied`]
//! values (never waits), so callers can fail closed under pressure without
//! stalling the accept loop. Dropping a permit returns capacity.

use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use crate::runtime::ceiling::{CeilingPermit, CeilingSemaphore};
use crate::runtime::policy::{DirectBarrierPolicy, ResourceGovernorPolicy};
use crate::runtime::pressure::{PressureGauge, ResourcePressure};

/// Independently bounded work categories in the unauthenticated and setup paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionKind {
    /// Accepted client sockets.
    Connection,
    /// Accepted Handoff/NXR sockets that have not sent a protocol byte.
    PreAuthIdle,
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
    pre_auth_idle: CeilingSemaphore,
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
    pub fn new(config: &ResourceGovernorPolicy) -> Self {
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
    pub fn with_pressure(config: &ResourceGovernorPolicy, pressure: PressureGauge) -> Self {
        Self::pools(config, Some(pressure))
    }

    fn pools(config: &ResourceGovernorPolicy, pressure: Option<PressureGauge>) -> Self {
        Self {
            inner: Arc::new(GovernorInner {
                connections: CeilingSemaphore::new(config.max_connections),
                pre_auth_idle: CeilingSemaphore::new(config.max_pre_auth_idle_connections),
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
            AdmissionKind::PreAuthIdle => &self.inner.pre_auth_idle,
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
    pub fn new(config: &DirectBarrierPolicy) -> Self {
        Self::barrier(config, None)
    }

    /// Creates a direct-dial barrier that pauses new dials at `Critical`
    /// pressure. Established relays hold no barrier permit, so pausing new
    /// dials never interrupts traffic already flowing.
    #[must_use]
    pub fn with_pressure(config: &DirectBarrierPolicy, pressure: PressureGauge) -> Self {
        Self::barrier(config, Some(pressure))
    }

    fn barrier(config: &DirectBarrierPolicy, pressure: Option<PressureGauge>) -> Self {
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

    /// Returns the number of dial permits currently held, the adaptive
    /// controller's utilization signal for both direct-dial knobs.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.inner.concurrency.in_flight()
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
mod tests;
