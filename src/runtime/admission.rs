use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::config::{DirectBarrierConfig, ResourceGovernorConfig};
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
    _permit: OwnedSemaphorePermit,
}

impl AdmissionPermit {
    /// Returns the bounded category held by this permit.
    #[must_use]
    pub const fn kind(&self) -> AdmissionKind {
        self.kind
    }
}

struct GovernorInner {
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    fallbacks: Arc<Semaphore>,
    crypto_operations: Arc<Semaphore>,
    replay_entries: Arc<Semaphore>,
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
                connections: semaphore(config.max_connections),
                handshakes: semaphore(config.max_handshakes),
                fallbacks: semaphore(config.max_fallbacks),
                crypto_operations: semaphore(config.max_crypto_operations),
                replay_entries: semaphore(config.max_replay_entries),
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
        let semaphore = match kind {
            AdmissionKind::Connection => &self.inner.connections,
            AdmissionKind::Handshake => &self.inner.handshakes,
            AdmissionKind::Fallback => &self.inner.fallbacks,
            AdmissionKind::CryptoOperation => &self.inner.crypto_operations,
            AdmissionKind::ReplayEntry => &self.inner.replay_entries,
        };
        let permit = Arc::clone(semaphore)
            .try_acquire_owned()
            .map_err(|error| map_semaphore_error(error, kind))?;
        Ok(AdmissionPermit {
            kind,
            _permit: permit,
        })
    }
}

fn semaphore(permits: u32) -> Arc<Semaphore> {
    let permits = usize::try_from(permits).map_or(usize::MAX, |value| value);
    Arc::new(Semaphore::new(permits))
}

const fn map_semaphore_error(error: TryAcquireError, kind: AdmissionKind) -> AdmissionDenied {
    match error {
        TryAcquireError::NoPermits => AdmissionDenied::Limit(kind),
        TryAcquireError::Closed => AdmissionDenied::Unavailable,
    }
}

/// RAII direct-dial concurrency permit.
pub struct DirectPermit {
    _permit: OwnedSemaphorePermit,
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(max_per_second: u32) -> Self {
        let capacity = f64::from(max_per_second);
        Self {
            tokens: capacity,
            capacity,
            refill_per_second: capacity,
            updated: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct DirectBarrierInner {
    concurrency: Arc<Semaphore>,
    rate: Mutex<TokenBucket>,
    pressure: Option<PressureGauge>,
}

/// Direct outbound isolation with independent concurrency and token-bucket limits.
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
                concurrency: semaphore(config.max_concurrent),
                rate: Mutex::new(TokenBucket::new(config.max_per_second)),
                pressure,
            }),
        }
    }

    /// Attempts a direct dial without queuing. Capacity is released on every drop path.
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
        let permit = Arc::clone(&self.inner.concurrency)
            .try_acquire_owned()
            .map_err(|error| match error {
                TryAcquireError::NoPermits => AdmissionDenied::DirectConcurrency,
                TryAcquireError::Closed => AdmissionDenied::Unavailable,
            })?;
        let mut bucket = self
            .inner
            .rate
            .lock()
            .map_err(|_| AdmissionDenied::Unavailable)?;
        if !bucket.try_take() {
            return Err(AdmissionDenied::DirectRate);
        }
        Ok(DirectPermit { _permit: permit })
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{DirectBarrierConfig, ResourceGovernorConfig};

    use super::{AdmissionDenied, AdmissionKind, DirectBarrier, ResourceGovernor};

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
