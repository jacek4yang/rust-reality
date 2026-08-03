use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::config::{DirectBarrierConfig, ResourceGovernorConfig};

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
    /// The direct outbound concurrency barrier is full.
    DirectConcurrency,
    /// The direct outbound new-connection rate was exceeded.
    DirectRate,
    /// Internal synchronization is unavailable after a poisoned lock or closed semaphore.
    Unavailable,
}

impl fmt::Display for AdmissionDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(kind) => write!(formatter, "admission limit reached for {kind:?}"),
            Self::DirectConcurrency => {
                formatter.write_str("direct outbound concurrency limit reached")
            }
            Self::DirectRate => formatter.write_str("direct outbound rate limit reached"),
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
        Self {
            inner: Arc::new(GovernorInner {
                connections: semaphore(config.max_connections),
                handshakes: semaphore(config.max_handshakes),
                fallbacks: semaphore(config.max_fallbacks),
                crypto_operations: semaphore(config.max_crypto_operations),
                replay_entries: semaphore(config.max_replay_entries),
            }),
        }
    }

    /// Attempts immediate admission without building an attacker-controlled wait queue.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionDenied`] when the selected limit is full or unavailable.
    pub fn try_acquire(&self, kind: AdmissionKind) -> Result<AdmissionPermit, AdmissionDenied> {
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
        Self {
            inner: Arc::new(DirectBarrierInner {
                concurrency: semaphore(config.max_concurrent),
                rate: Mutex::new(TokenBucket::new(config.max_per_second)),
            }),
        }
    }

    /// Attempts a direct dial without queuing. Capacity is released on every drop path.
    ///
    /// # Errors
    ///
    /// Returns a category-specific denial when concurrency, rate, or synchronization
    /// prevents immediate admission.
    pub fn try_acquire(&self) -> Result<DirectPermit, AdmissionDenied> {
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
}
