//! Bounded adaptive pools of TCP-established, protocol-unprivileged sockets.
//!
//! The pool owns only the TCP setup phase. It never authenticates a protocol,
//! sends preparation bytes, or returns a checked-out socket. Handoff, NXR,
//! SOCKS5, and REALITY cover code retain explicit protocol transitions after
//! checkout.

use std::{
    collections::hash_map::DefaultHasher,
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{
    sync::Notify,
    time::{self, Instant},
};

use crate::{
    runtime::{PressureGauge, ResourcePressure},
    transport::{FdBudget, FdPressure},
};

use super::connector::{AccountedTcpStream, DestinationConnectError, DestinationConnector};
use crate::runtime::policy::WarmConnectionPolicy;

const LIFECYCLE_CREATED: u8 = 0;
const LIFECYCLE_ACTIVE: u8 = 1;
const LIFECYCLE_STOPPED: u8 = 2;
const ADAPT_INTERVAL: Duration = Duration::from_millis(100);
const QUIET_RECHECK: Duration = Duration::from_secs(30);
const BASE_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const ARRIVAL_EWMA_WEIGHT: f64 = 0.25;
const CONNECT_EWMA_WEIGHT: f64 = 0.25;
const CONNECT_SAFETY_FACTOR: f64 = 1.0;
const BURST_HEADROOM_FACTOR: f64 = 0.25;
const MAX_STALE_CHECKS_PER_CHECKOUT: usize = 4;

/// Process-lifetime bounds shared by every pool and immutable generation.
#[derive(Clone)]
pub(crate) struct WarmPoolAuthority {
    connecting: StrictCounter,
    ready: StrictCounter,
    pressure: PressureGauge,
}

impl WarmPoolAuthority {
    pub(crate) fn new(
        policy: &WarmConnectionPolicy,
        maximum_pool_count: usize,
        pressure: PressureGauge,
    ) -> Self {
        let pools = u64::try_from(maximum_pool_count).unwrap_or(u64::MAX);
        Self {
            connecting: StrictCounter::new(u64::from(policy.max_connecting).saturating_mul(pools)),
            ready: StrictCounter::new(u64::from(policy.max_ready).saturating_mul(pools)),
            pressure,
        }
    }

    fn try_connecting(&self) -> Option<CounterPermit> {
        self.speculative_allowed()
            .then(|| self.connecting.try_acquire())
            .flatten()
    }

    fn try_ready(&self) -> Option<CounterPermit> {
        self.speculative_allowed()
            .then(|| self.ready.try_acquire())
            .flatten()
    }

    fn ready_capacity_available(&self) -> bool {
        self.ready.in_use() < self.ready.inner.capacity
    }

    fn speculative_allowed(&self) -> bool {
        self.pressure.state() == ResourcePressure::Normal
    }

    pub(crate) fn capacity(&self) -> u64 {
        self.ready
            .inner
            .capacity
            .saturating_add(self.connecting.inner.capacity)
    }

    pub(crate) fn counts(&self) -> (u64, u64) {
        (self.ready.in_use(), self.connecting.in_use())
    }
}

#[derive(Clone)]
struct StrictCounter {
    inner: Arc<StrictCounterInner>,
}

struct StrictCounterInner {
    used: AtomicU64,
    capacity: u64,
    underflows: AtomicU64,
}

impl StrictCounter {
    fn new(capacity: u64) -> Self {
        Self {
            inner: Arc::new(StrictCounterInner {
                used: AtomicU64::new(0),
                capacity,
                underflows: AtomicU64::new(0),
            }),
        }
    }

    fn try_acquire(&self) -> Option<CounterPermit> {
        let mut current = self.inner.used.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(1)?;
            if next > self.inner.capacity {
                return None;
            }
            match self.inner.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(CounterPermit {
                        counter: self.clone(),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn in_use(&self) -> u64 {
        self.inner.used.load(Ordering::Acquire)
    }

    fn release(&self) {
        if self
            .inner
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(1)
            })
            .is_err()
        {
            self.inner.underflows.fetch_add(1, Ordering::Relaxed);
            debug_assert!(false, "warm-pool authority permit released twice");
        }
    }
}

struct CounterPermit {
    counter: StrictCounter,
}

impl Drop for CounterPermit {
    fn drop(&mut self) {
        self.counter.release();
    }
}

/// One endpoint- and generation-bound adaptive TCP pool.
#[derive(Clone)]
pub(crate) struct AdaptiveTcpPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    target: Arc<str>,
    target_hash: u64,
    generation: u64,
    connector: DestinationConnector,
    fd_budget: FdBudget,
    authority: WarmPoolAuthority,
    policy: PoolPolicy,
    lifecycle: AtomicU8,
    state: Mutex<PoolState>,
    notify: Notify,
    metrics: PoolMetrics,
    #[cfg(test)]
    before_wait: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[derive(Clone, Copy)]
struct PoolPolicy {
    min_ready: u32,
    max_ready: u32,
    max_connecting: u32,
    refill_batch: u32,
    idle_timeout: Duration,
    max_lifetime: Duration,
    shrink_delay: Duration,
}

impl From<&WarmConnectionPolicy> for PoolPolicy {
    fn from(policy: &WarmConnectionPolicy) -> Self {
        Self {
            min_ready: policy.min_ready,
            max_ready: policy.max_ready,
            max_connecting: policy.max_connecting,
            refill_batch: policy.refill_batch,
            idle_timeout: Duration::from_millis(policy.idle_timeout_ms),
            max_lifetime: Duration::from_millis(policy.max_lifetime_ms),
            shrink_delay: Duration::from_millis(policy.shrink_delay_ms),
        }
    }
}

struct PoolState {
    ready: Vec<ReadySocket>,
    connecting: u32,
    target_ready: u32,
    arrivals_window: u64,
    misses_window: u64,
    arrival_rate_ewma: f64,
    connect_latency_ewma_ms: f64,
    recent_burst: f64,
    last_tick: Instant,
    last_demand: Instant,
    failure_streak: u32,
    failures: DialFailureCounts,
    backoff_until: Option<Instant>,
    pressure_resume_at: Option<Instant>,
}

struct ReadySocket {
    connection: AccountedTcpStream,
    _ready_permit: CounterPermit,
    connected_at: Instant,
    idle_since: Instant,
}

/// Fixed-cardinality dial outcomes, updated under the existing pool lock.
/// No peer identity, error text, allocation, or additional lock is retained.
#[derive(Clone, Copy, Default)]
struct DialFailureCounts {
    timeout: u64,
    resource: u64,
    policy: u64,
    io: u64,
}

impl DialFailureCounts {
    fn record(&mut self, error: &DestinationConnectError) {
        let count = match error {
            DestinationConnectError::TimedOut { .. } => &mut self.timeout,
            DestinationConnectError::DescriptorBudget | DestinationConnectError::Allocation => {
                &mut self.resource
            }
            DestinationConnectError::NoAddressesForPolicy
            | DestinationConnectError::TooManyResolvedAddresses => &mut self.policy,
            DestinationConnectError::Io(error) => match error.kind() {
                std::io::ErrorKind::TimedOut => &mut self.timeout,
                std::io::ErrorKind::OutOfMemory => &mut self.resource,
                _ => &mut self.io,
            },
        };
        *count = count.saturating_add(1);
    }
}

#[derive(Default)]
struct PoolMetrics {
    ready: AtomicU32,
    connecting: AtomicU32,
    in_use: AtomicU64,
    checkout_total: AtomicU64,
    checkout_hit: AtomicU64,
    checkout_miss: AtomicU64,
    cold_fallback: AtomicU64,
    connect_failure: AtomicU64,
    stale_discard: AtomicU64,
    refill: AtomicU64,
    target_ready: AtomicU32,
    growth: AtomicU64,
    shrink: AtomicU64,
}

/// Secret-free, fixed-cardinality observation of one pool.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct WarmPoolSnapshot {
    pub(crate) generation: u64,
    pub(crate) ready: u32,
    pub(crate) connecting: u32,
    pub(crate) in_use: u64,
    pub(crate) checkout_total: u64,
    pub(crate) checkout_hit: u64,
    pub(crate) checkout_miss: u64,
    pub(crate) cold_fallback: u64,
    pub(crate) connect_failure: u64,
    pub(crate) connect_timeout: u64,
    pub(crate) connect_resource: u64,
    pub(crate) connect_policy: u64,
    pub(crate) connect_io: u64,
    pub(crate) failure_streak: u32,
    pub(crate) backoff_remaining_ms: u64,
    pub(crate) stale_discard: u64,
    pub(crate) refill: u64,
    pub(crate) target_ready: u32,
    pub(crate) growth: u64,
    pub(crate) shrink: u64,
    pub(crate) arrival_rate_per_second: f64,
    pub(crate) connect_latency_ms: f64,
    pub(crate) recent_burst: f64,
}

/// A single-use checked-out socket plus its pool-use observation permit.
pub(crate) struct WarmCheckout {
    connection: AccountedTcpStream,
    use_permit: WarmUsePermit,
}

impl WarmCheckout {
    pub(crate) fn into_parts(self) -> (AccountedTcpStream, WarmUsePermit) {
        (self.connection, self.use_permit)
    }
}

/// Decrements the checked-out gauge when the cover transaction finishes.
pub(crate) struct WarmUsePermit {
    inner: Arc<PoolInner>,
}

impl Drop for WarmUsePermit {
    fn drop(&mut self) {
        let outcome =
            self.inner
                .metrics
                .in_use
                .try_update(Ordering::AcqRel, Ordering::Acquire, |in_use| {
                    in_use.checked_sub(1)
                });
        debug_assert!(outcome.is_ok(), "warm checkout gauge underflowed");
    }
}

impl AdaptiveTcpPool {
    pub(crate) fn new(
        target: Arc<str>,
        generation: u64,
        connector: DestinationConnector,
        fd_budget: FdBudget,
        authority: WarmPoolAuthority,
        policy: &WarmConnectionPolicy,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        target.hash(&mut hasher);
        generation.hash(&mut hasher);
        let target_hash = hasher.finish();
        let policy = PoolPolicy::from(policy);
        let now = Instant::now();
        Self {
            inner: Arc::new(PoolInner {
                target,
                target_hash,
                generation,
                connector,
                fd_budget,
                authority,
                policy,
                lifecycle: AtomicU8::new(LIFECYCLE_CREATED),
                state: Mutex::new(PoolState {
                    ready: Vec::new(),
                    connecting: 0,
                    target_ready: policy.min_ready,
                    arrivals_window: 0,
                    misses_window: 0,
                    arrival_rate_ewma: 0.0,
                    connect_latency_ewma_ms: 0.0,
                    recent_burst: 0.0,
                    last_tick: now,
                    last_demand: now,
                    failure_streak: 0,
                    failures: DialFailureCounts::default(),
                    backoff_until: None,
                    pressure_resume_at: None,
                }),
                notify: Notify::new(),
                metrics: PoolMetrics {
                    target_ready: AtomicU32::new(policy.min_ready),
                    ..PoolMetrics::default()
                },
                #[cfg(test)]
                before_wait: Mutex::new(None),
            }),
        }
    }

    /// Starts one controller task. Calling this more than once is a no-op.
    pub(crate) fn activate(&self) -> bool {
        if self
            .inner
            .lifecycle
            .compare_exchange(
                LIFECYCLE_CREATED,
                LIFECYCLE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.inner
                .lifecycle
                .store(LIFECYCLE_CREATED, Ordering::Release);
            return false;
        };
        runtime.spawn(run_controller(Arc::clone(&self.inner)));
        self.inner.notify.notify_one();
        true
    }

    /// Stops refill and synchronously drops every unused socket.
    pub(crate) fn deactivate(&self) -> bool {
        if self
            .inner
            .lifecycle
            .swap(LIFECYCLE_STOPPED, Ordering::AcqRel)
            == LIFECYCLE_STOPPED
        {
            return false;
        }
        let mut state = lock(&self.inner.state);
        state.ready.clear();
        self.inner.metrics.ready.store(0, Ordering::Release);
        drop(state);
        self.inner.notify.notify_waiters();
        true
    }

    /// Transfers one healthy socket without waiting or performing network I/O.
    pub(crate) fn checkout(&self) -> Option<WarmCheckout> {
        self.inner
            .metrics
            .checkout_total
            .fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        if self.inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            let mut state = lock(&self.inner.state);
            state.arrivals_window = state.arrivals_window.saturating_add(1);
            state.last_demand = now;
            drop(state);
            self.record_miss();
            return None;
        }

        for attempt in 0..MAX_STALE_CHECKS_PER_CHECKOUT {
            let (candidate, ready_after, target_ready) = {
                let mut state = lock(&self.inner.state);
                if attempt == 0 {
                    state.arrivals_window = state.arrivals_window.saturating_add(1);
                    state.last_demand = now;
                }
                let candidate = state.ready.pop();
                let ready_after = saturating_u32(state.ready.len());
                self.inner
                    .metrics
                    .ready
                    .store(ready_after, Ordering::Release);
                (candidate, ready_after, state.target_ready)
            };
            let Some(candidate) = candidate else {
                break;
            };
            if now.duration_since(candidate.idle_since) > self.inner.policy.idle_timeout
                || now.duration_since(candidate.connected_at) > self.inner.policy.max_lifetime
                || !candidate.connection.idle_healthy()
            {
                self.inner
                    .metrics
                    .stale_discard
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.inner
                .metrics
                .checkout_hit
                .fetch_add(1, Ordering::Relaxed);
            self.inner.metrics.in_use.fetch_add(1, Ordering::AcqRel);
            if ready_after <= low_watermark(target_ready) {
                self.inner.notify.notify_one();
            }
            return Some(WarmCheckout {
                connection: candidate.connection,
                use_permit: WarmUsePermit::new(Arc::clone(&self.inner)),
            });
        }
        self.record_miss();
        None
    }

    pub(crate) fn record_cold_fallback(&self) {
        self.inner
            .metrics
            .cold_fallback
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a socket that passed the passive idle check but failed on first use.
    pub(crate) fn record_stale_checkout(&self) {
        self.inner
            .metrics
            .stale_discard
            .fetch_add(1, Ordering::Relaxed);
        self.inner.notify.notify_one();
    }

    pub(crate) fn snapshot(&self) -> WarmPoolSnapshot {
        let state = lock(&self.inner.state);
        WarmPoolSnapshot {
            generation: self.inner.generation,
            ready: self.inner.metrics.ready.load(Ordering::Acquire),
            connecting: self.inner.metrics.connecting.load(Ordering::Acquire),
            in_use: self.inner.metrics.in_use.load(Ordering::Acquire),
            checkout_total: self.inner.metrics.checkout_total.load(Ordering::Relaxed),
            checkout_hit: self.inner.metrics.checkout_hit.load(Ordering::Relaxed),
            checkout_miss: self.inner.metrics.checkout_miss.load(Ordering::Relaxed),
            cold_fallback: self.inner.metrics.cold_fallback.load(Ordering::Relaxed),
            connect_failure: self.inner.metrics.connect_failure.load(Ordering::Relaxed),
            connect_timeout: state.failures.timeout,
            connect_resource: state.failures.resource,
            connect_policy: state.failures.policy,
            connect_io: state.failures.io,
            failure_streak: state.failure_streak,
            backoff_remaining_ms: state.backoff_until.map_or(0, |deadline| {
                u64::try_from(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .unwrap_or(u64::MAX)
            }),
            stale_discard: self.inner.metrics.stale_discard.load(Ordering::Relaxed),
            refill: self.inner.metrics.refill.load(Ordering::Relaxed),
            target_ready: self.inner.metrics.target_ready.load(Ordering::Acquire),
            growth: self.inner.metrics.growth.load(Ordering::Relaxed),
            shrink: self.inner.metrics.shrink.load(Ordering::Relaxed),
            arrival_rate_per_second: state.arrival_rate_ewma,
            connect_latency_ms: state.connect_latency_ewma_ms,
            recent_burst: state.recent_burst,
        }
    }

    fn record_miss(&self) {
        self.inner
            .metrics
            .checkout_miss
            .fetch_add(1, Ordering::Relaxed);
        let mut state = lock(&self.inner.state);
        state.misses_window = state.misses_window.saturating_add(1);
        drop(state);
        self.inner.notify.notify_one();
    }
}

impl WarmUsePermit {
    fn new(inner: Arc<PoolInner>) -> Self {
        Self { inner }
    }
}

struct DialOutcome {
    result: Result<AccountedTcpStream, DestinationConnectError>,
    elapsed: Duration,
}

type DialFuture = Pin<Box<dyn Future<Output = DialOutcome> + Send>>;

async fn run_controller(inner: Arc<PoolInner>) {
    let mut dials = FuturesUnordered::<DialFuture>::new();
    let maintenance = time::sleep_until(next_maintenance_deadline(&inner, Instant::now()));
    tokio::pin!(maintenance);
    let mut resource_pressure = inner.authority.pressure.state();
    let mut fd_pressure = inner.fd_budget.pressure();
    prune_and_adjust(&inner, Instant::now());
    loop {
        if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            break;
        }
        reconcile(&inner, &mut dials);
        #[cfg(test)]
        if let Some(before_wait) = lock(&inner.before_wait).take() {
            before_wait();
        }
        let notified = inner.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // A retirement broadcast stores no permit. Recheck after registering
        // so shutdown never depends on a later dial or maintenance deadline.
        if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            break;
        }
        tokio::select! {
            biased;
            _ = &mut notified => {
                let now = Instant::now();
                adjust_if_due(&inner, now);
                maintenance.as_mut().reset(next_maintenance_deadline(&inner, now));
            }
            completed = dials.next(), if !dials.is_empty() => {
                if let Some(outcome) = completed {
                    handle_dial_completion(&inner, outcome);
                    let now = Instant::now();
                    adjust_if_due(&inner, now);
                    maintenance.as_mut().reset(next_maintenance_deadline(&inner, now));
                }
            }
            changed = inner.authority.pressure.wait_for_change(resource_pressure) => {
                resource_pressure = changed;
                if resource_pressure != ResourcePressure::Normal {
                    cancel_speculative_dials(&inner, &mut dials);
                }
                let now = Instant::now();
                prune_and_adjust(&inner, now);
                maintenance.as_mut().reset(next_maintenance_deadline(&inner, now));
            }
            changed = inner.fd_budget.wait_for_pressure_change(fd_pressure) => {
                fd_pressure = changed;
                if fd_pressure != FdPressure::Normal {
                    cancel_speculative_dials(&inner, &mut dials);
                }
                let now = Instant::now();
                prune_and_adjust(&inner, now);
                maintenance.as_mut().reset(next_maintenance_deadline(&inner, now));
            }
            () = &mut maintenance => {
                let now = Instant::now();
                prune_and_adjust(&inner, now);
                maintenance.as_mut().reset(next_maintenance_deadline(&inner, now));
            }
        }
    }
    drop(dials);
    let mut state = lock(&inner.state);
    state.connecting = 0;
    state.ready.clear();
    inner.metrics.connecting.store(0, Ordering::Release);
    inner.metrics.ready.store(0, Ordering::Release);
}

fn cancel_speculative_dials(inner: &PoolInner, dials: &mut FuturesUnordered<DialFuture>) {
    dials.clear();
    let mut state = lock(&inner.state);
    state.connecting = 0;
    defer_pressure_refill(&mut state, Instant::now());
    inner.metrics.connecting.store(0, Ordering::Release);
}

// Shedding speculative resources can itself clear FD hysteresis. Do not let
// that self-induced transition immediately start the same speculative work.
// This runs only on the pool controller, under its existing state lock.
fn defer_pressure_refill(state: &mut PoolState, now: Instant) {
    let until = now + BASE_BACKOFF;
    // A successful concurrent dial may clear failure backoff, but must not
    // erase a pressure cooldown caused by another dial's released permit.
    state.pressure_resume_at = Some(
        state
            .pressure_resume_at
            .map_or(until, |current| current.max(until)),
    );
}

/// Schedules only work that can change state. A stable minimum pool wakes for
/// its earliest socket expiry (normally 30 seconds), not every socket and not
/// on a fixed subsecond polling tick.
fn next_maintenance_deadline(inner: &PoolInner, now: Instant) -> Instant {
    let state = lock(&inner.state);
    let mut next = now + QUIET_RECHECK;
    if state.arrivals_window != 0 || state.misses_window != 0 {
        next = next.min(state.last_tick + ADAPT_INTERVAL);
    }
    if state.target_ready > inner.policy.min_ready {
        let shrink_at = state.last_demand + inner.policy.shrink_delay;
        next = next.min(if shrink_at <= now {
            now + ADAPT_INTERVAL
        } else {
            shrink_at
        });
    }
    if let Some(backoff_until) = state.backoff_until.max(state.pressure_resume_at) {
        next = next.min(backoff_until.max(now + Duration::from_millis(1)));
    }
    for ready in &state.ready {
        next = next.min(ready.idle_since + inner.policy.idle_timeout + Duration::from_millis(1));
        next = next.min(ready.connected_at + inner.policy.max_lifetime + Duration::from_millis(1));
    }
    next.max(now)
}

fn adjust_if_due(inner: &Arc<PoolInner>, now: Instant) {
    let due = now.duration_since(lock(&inner.state).last_tick) >= ADAPT_INTERVAL;
    if due {
        prune_and_adjust(inner, now);
    }
}

fn prune_and_adjust(inner: &Arc<PoolInner>, now: Instant) {
    let mut state = lock(&inner.state);
    let pressure =
        inner.fd_budget.pressure() != FdPressure::Normal || !inner.authority.speculative_allowed();
    let before = state.ready.len();
    let mut expired = 0_usize;
    if pressure {
        defer_pressure_refill(&mut state, now);
        state.ready.clear();
    } else {
        state.ready.retain(|ready| {
            // FIN, RST, and unsolicited data are checked exactly once before
            // checkout. Repeating a recv syscall for every ready socket on
            // every controller tick costs CPU while providing no additional
            // authorization boundary.
            let healthy = now.duration_since(ready.idle_since) <= inner.policy.idle_timeout
                && now.duration_since(ready.connected_at) <= inner.policy.max_lifetime;
            expired += usize::from(!healthy);
            healthy
        });
    }
    if expired > 0 {
        inner.metrics.stale_discard.fetch_add(
            u64::try_from(expired).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    if !pressure {
        debug_assert_eq!(before - state.ready.len(), expired);
    }

    let elapsed = now.duration_since(state.last_tick).as_secs_f64().max(0.001);
    let arrivals = state.arrivals_window;
    let misses = state.misses_window;
    state.arrivals_window = 0;
    state.misses_window = 0;
    state.last_tick = now;
    let observed_rate = arrivals as f64 / elapsed;
    state.arrival_rate_ewma = ewma(state.arrival_rate_ewma, observed_rate, ARRIVAL_EWMA_WEIGHT);
    state.recent_burst = (state.recent_burst * 0.75).max(arrivals as f64);
    let latency_seconds = (state.connect_latency_ewma_ms / 1_000.0).max(0.001);
    let estimated = (state.arrival_rate_ewma * latency_seconds * CONNECT_SAFETY_FACTOR
        + state.recent_burst * BURST_HEADROOM_FACTOR)
        .ceil();
    let estimated = if estimated.is_finite() && estimated > 0.0 {
        estimated.min(f64::from(u32::MAX)) as u32
    } else {
        0
    };
    let mut desired = estimated.max(inner.policy.min_ready);
    if misses > 0 {
        // A miss is an acceleration signal, not evidence that a complete
        // refill batch must remain idle forever. Growing by refill_batch made
        // four cold-start misses retain twenty cover sockets under the
        // default policy. Scale the step to observed misses (with a small
        // multiplicative floor) and let the rate/latency estimator account
        // for sustained load on the following ticks.
        let miss_step = u32::try_from(misses)
            .unwrap_or(u32::MAX)
            .min(inner.policy.refill_batch)
            .max((state.target_ready / 2).max(1));
        let accelerated = state.target_ready.saturating_add(miss_step);
        desired = desired.max(accelerated);
    }
    desired = desired.min(inner.policy.max_ready);
    if desired > state.target_ready {
        state.target_ready = desired;
        inner.metrics.growth.fetch_add(1, Ordering::Relaxed);
    } else if desired < state.target_ready
        && now.duration_since(state.last_demand) >= inner.policy.shrink_delay
    {
        state.target_ready = state
            .target_ready
            .saturating_sub(inner.policy.refill_batch)
            .max(desired)
            .max(inner.policy.min_ready);
        inner.metrics.shrink.fetch_add(1, Ordering::Relaxed);
    }
    while state.ready.len() > usize::try_from(state.target_ready).unwrap_or(usize::MAX) {
        state.ready.pop();
    }
    inner
        .metrics
        .ready
        .store(saturating_u32(state.ready.len()), Ordering::Release);
    inner
        .metrics
        .target_ready
        .store(state.target_ready, Ordering::Release);
}

fn reconcile(inner: &Arc<PoolInner>, dials: &mut FuturesUnordered<DialFuture>) {
    if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE
        || inner.fd_budget.pressure() != FdPressure::Normal
        || !inner.authority.speculative_allowed()
        // Hot reload can add pools without increasing process-lifetime limits.
        // Do not establish sockets that cannot enter any ready slot. Capacity
        // may race with an in-flight dial; completion still owns admission.
        || !inner.authority.ready_capacity_available()
    {
        return;
    }
    let now = Instant::now();
    let mut state = lock(&inner.state);
    if state
        .backoff_until
        .max(state.pressure_resume_at)
        .is_some_and(|deadline| deadline > now)
    {
        return;
    }
    state.backoff_until = None;
    state.pressure_resume_at = None;
    let occupied = saturating_u32(state.ready.len()).saturating_add(state.connecting);
    let deficit = state.target_ready.saturating_sub(occupied);
    let local_slots = inner.policy.max_connecting.saturating_sub(state.connecting);
    let to_spawn = deficit.min(local_slots).min(inner.policy.refill_batch);
    for _ in 0..to_spawn {
        let Some(global_permit) = inner.authority.try_connecting() else {
            break;
        };
        state.connecting = state.connecting.saturating_add(1);
        inner
            .metrics
            .connecting
            .store(state.connecting, Ordering::Release);
        inner.metrics.refill.fetch_add(1, Ordering::Relaxed);
        let connector = inner.connector.clone();
        let target = Arc::clone(&inner.target);
        let fd_budget = inner.fd_budget.clone();
        dials.push(Box::pin(async move {
            let _global_permit = global_permit;
            let started = Instant::now();
            let result = connector
                .connect_target_accounted(target.as_ref(), &fd_budget)
                .await;
            DialOutcome {
                result,
                elapsed: started.elapsed(),
            }
        }));
    }
}

fn handle_dial_completion(inner: &Arc<PoolInner>, outcome: DialOutcome) {
    let now = Instant::now();
    let mut state = lock(&inner.state);
    state.connecting = state.connecting.saturating_sub(1);
    inner
        .metrics
        .connecting
        .store(state.connecting, Ordering::Release);
    let elapsed_ms = outcome.elapsed.as_secs_f64() * 1_000.0;
    state.connect_latency_ewma_ms = ewma(
        state.connect_latency_ewma_ms,
        elapsed_ms,
        CONNECT_EWMA_WEIGHT,
    );
    match outcome.result {
        Ok(connection)
            if inner.lifecycle.load(Ordering::Acquire) == LIFECYCLE_ACTIVE
                && inner.fd_budget.pressure() == FdPressure::Normal
                && saturating_u32(state.ready.len()) < state.target_ready
                && saturating_u32(state.ready.len()) < inner.policy.max_ready =>
        {
            let Some(ready_permit) = inner.authority.try_ready() else {
                return;
            };
            state.failure_streak = 0;
            state.backoff_until = None;
            state.ready.push(ReadySocket {
                connection,
                _ready_permit: ready_permit,
                connected_at: now,
                idle_since: now,
            });
            inner
                .metrics
                .ready
                .store(saturating_u32(state.ready.len()), Ordering::Release);
        }
        Ok(connection) => {
            // Observe pressure before dropping the connection releases its FD
            // permit; otherwise this controller can erase its own signal.
            if inner.fd_budget.pressure() != FdPressure::Normal {
                defer_pressure_refill(&mut state, now);
            }
            drop(connection);
        }
        Err(error) => {
            state.failures.record(&error);
            record_dial_failure(inner, &mut state, now);
        }
    }
}

fn record_dial_failure(inner: &PoolInner, state: &mut PoolState, now: Instant) {
    inner
        .metrics
        .connect_failure
        .fetch_add(1, Ordering::Relaxed);
    state.failure_streak = state.failure_streak.saturating_add(1);
    let exponent = state.failure_streak.saturating_sub(1).min(8);
    let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    let base = BASE_BACKOFF.saturating_mul(multiplier).min(MAX_BACKOFF);
    let quarter_ms = u64::try_from(base.as_millis() / 4).unwrap_or(u64::MAX);
    let mixed = inner
        .target_hash
        .wrapping_add(u64::from(state.failure_streak).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let jitter_ms = if quarter_ms == 0 {
        0
    } else {
        mixed % quarter_ms.saturating_add(1)
    };
    state.backoff_until = now.checked_add(base.saturating_add(Duration::from_millis(jitter_ms)));
}

fn ewma(previous: f64, observed: f64, weight: f64) -> f64 {
    if previous == 0.0 {
        observed
    } else {
        previous * (1.0 - weight) + observed * weight
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn low_watermark(target_ready: u32) -> u32 {
    target_ready.saturating_sub((target_ready / 4).max(1))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl std::fmt::Debug for AdaptiveTcpPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdaptiveTcpPool")
            .field("generation", &self.inner.generation)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for WarmPoolAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WarmPoolAuthority")
            .field("ready_in_use", &self.ready.in_use())
            .field("connecting_in_use", &self.connecting.in_use())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
