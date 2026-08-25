//! Bounded adaptive pools of TCP-established, protocol-unprivileged sockets.
//!
//! The pool owns only the TCP setup phase. It never authenticates a protocol,
//! sends preparation bytes, or returns a checked-out socket. Handoff, NXR,
//! SOCKS5, and REALITY cover code retain explicit protocol transitions after
//! checkout.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::Notify,
    task::JoinSet,
    time::{self, Instant, MissedTickBehavior},
};

use crate::{
    config::WarmConnectionPolicy,
    runtime::{FdBudget, FdPressure, PressureGauge, ResourcePressure},
};

use super::connector::{AccountedTcpStream, DestinationConnectError, DestinationConnector};

const LIFECYCLE_CREATED: u8 = 0;
const LIFECYCLE_ACTIVE: u8 = 1;
const LIFECYCLE_STOPPED: u8 = 2;
const CONTROLLER_TICK: Duration = Duration::from_millis(100);
const BASE_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const ARRIVAL_EWMA_WEIGHT: f64 = 0.25;
const CONNECT_EWMA_WEIGHT: f64 = 0.25;
const CONNECT_SAFETY_FACTOR: f64 = 1.5;
const BURST_HEADROOM_FACTOR: f64 = 0.5;
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

    fn speculative_allowed(&self) -> bool {
        self.pressure.state() == ResourcePressure::Normal
    }

    #[cfg(test)]
    fn counts(&self) -> (u64, u64) {
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
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
    backoff_until: Option<Instant>,
}

struct ReadySocket {
    connection: AccountedTcpStream,
    _ready_permit: CounterPermit,
    connected_at: Instant,
    idle_since: Instant,
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
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_use| {
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
                    backoff_until: None,
                }),
                notify: Notify::new(),
                metrics: PoolMetrics {
                    target_ready: AtomicU32::new(policy.min_ready),
                    ..PoolMetrics::default()
                },
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

async fn run_controller(inner: Arc<PoolInner>) {
    let mut dials = JoinSet::new();
    let mut ticker = time::interval(CONTROLLER_TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    prune_and_adjust(&inner, Instant::now());
    loop {
        if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            break;
        }
        reconcile(&inner, &mut dials);
        tokio::select! {
            biased;
            _ = inner.notify.notified() => {}
            completed = dials.join_next(), if !dials.is_empty() => {
                handle_dial_completion(&inner, completed);
            }
            _ = ticker.tick() => {
                prune_and_adjust(&inner, Instant::now());
            }
        }
    }
    dials.abort_all();
    while dials.join_next().await.is_some() {}
    let mut state = lock(&inner.state);
    state.connecting = 0;
    state.ready.clear();
    inner.metrics.connecting.store(0, Ordering::Release);
    inner.metrics.ready.store(0, Ordering::Release);
}

fn prune_and_adjust(inner: &Arc<PoolInner>, now: Instant) {
    let mut state = lock(&inner.state);
    let pressure =
        inner.fd_budget.pressure() != FdPressure::Normal || !inner.authority.speculative_allowed();
    let before = state.ready.len();
    let mut expired = 0_usize;
    if pressure {
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
        let accelerated = state
            .target_ready
            .saturating_add(inner.policy.refill_batch.max(state.target_ready / 2));
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

fn reconcile(inner: &Arc<PoolInner>, dials: &mut JoinSet<DialOutcome>) {
    if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE
        || inner.fd_budget.pressure() != FdPressure::Normal
        || !inner.authority.speculative_allowed()
    {
        return;
    }
    let now = Instant::now();
    let mut state = lock(&inner.state);
    if state.backoff_until.is_some_and(|deadline| deadline > now) {
        return;
    }
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
        dials.spawn(async move {
            let _global_permit = global_permit;
            let started = Instant::now();
            let result = connector
                .connect_target_accounted(target.as_ref(), &fd_budget)
                .await;
            DialOutcome {
                result,
                elapsed: started.elapsed(),
            }
        });
    }
}

fn handle_dial_completion(
    inner: &Arc<PoolInner>,
    completed: Option<Result<DialOutcome, tokio::task::JoinError>>,
) {
    let now = Instant::now();
    let mut state = lock(&inner.state);
    state.connecting = state.connecting.saturating_sub(1);
    inner
        .metrics
        .connecting
        .store(state.connecting, Ordering::Release);
    let Some(Ok(outcome)) = completed else {
        record_dial_failure(inner, &mut state, now);
        return;
    };
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
        Ok(_) => {}
        Err(_) => record_dial_failure(inner, &mut state, now),
    }
    drop(state);
    inner.notify.notify_one();
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
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time};

    use super::{AdaptiveTcpPool, WarmPoolAuthority};
    use crate::{
        config::{NetworkConfig, WarmConnectionPolicy},
        network::NetworkEnvironment,
        runtime::{FdBudget, PressureGauge},
        server::connector::DestinationConnector,
    };

    struct CoverFixture {
        target: Arc<str>,
        accepted: Arc<Mutex<Vec<tokio::net::TcpStream>>>,
        task: JoinHandle<()>,
    }

    impl CoverFixture {
        async fn start() -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("cover fixture must bind");
            let target: Arc<str> = Arc::from(
                listener
                    .local_addr()
                    .expect("cover address must exist")
                    .to_string(),
            );
            let accepted = Arc::new(Mutex::new(Vec::new()));
            let accepted_for_task = Arc::clone(&accepted);
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    accepted_for_task
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(stream);
                }
            });
            Self {
                target,
                accepted,
                task,
            }
        }

        fn accepted_count(&self) -> usize {
            self.accepted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }
    }

    impl Drop for CoverFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn policy() -> WarmConnectionPolicy {
        WarmConnectionPolicy {
            min_ready: 2,
            max_ready: 8,
            max_connecting: 4,
            refill_batch: 4,
            idle_timeout_ms: 500,
            max_lifetime_ms: 1_000,
            shrink_delay_ms: 200,
        }
    }

    fn pool(
        fixture: &CoverFixture,
        generation: u64,
        policy: &WarmConnectionPolicy,
        authority: WarmPoolAuthority,
        fd_budget: FdBudget,
    ) -> AdaptiveTcpPool {
        AdaptiveTcpPool::new(
            Arc::clone(&fixture.target),
            generation,
            DestinationConnector::with_environment(
                Duration::from_millis(500),
                NetworkConfig::default(),
                NetworkEnvironment::detect(),
            ),
            fd_budget,
            authority,
            policy,
        )
    }

    async fn wait_for(mut predicate: impl FnMut() -> bool) {
        time::timeout(Duration::from_secs(2), async {
            while !predicate() {
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("bounded condition must become true");
    }

    #[test]
    fn process_authority_is_strict_and_raii() {
        let mut policy = policy();
        policy.max_ready = 2;
        policy.max_connecting = 1;
        let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
        let ready_a = authority.try_ready().expect("first ready permit");
        let ready_b = authority.try_ready().expect("second ready permit");
        assert!(authority.try_ready().is_none());
        let connecting = authority.try_connecting().expect("connecting permit");
        assert!(authority.try_connecting().is_none());
        assert_eq!(authority.counts(), (2, 1));
        drop((ready_a, ready_b, connecting));
        assert_eq!(authority.counts(), (0, 0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn warms_checks_out_and_proactively_refills_without_protocol_bytes() {
        let fixture = CoverFixture::start().await;
        let policy = policy();
        let fd_budget = FdBudget::new(64);
        let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
        let pool = pool(&fixture, 7, &policy, authority.clone(), fd_budget.clone());
        assert!(pool.activate());
        assert!(!pool.activate());
        wait_for(|| pool.snapshot().ready == policy.min_ready).await;
        wait_for(|| fixture.accepted_count() == policy.min_ready as usize).await;

        {
            let accepted = fixture
                .accepted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for stream in accepted.iter() {
                let mut byte = [0_u8; 1];
                let error = stream
                    .try_read(&mut byte)
                    .expect_err("warming must not send TLS or protocol bytes");
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            }
        }

        let checkout = pool.checkout().expect("warm checkout must hit");
        assert_eq!(pool.snapshot().in_use, 1);
        drop(checkout);
        wait_for(|| pool.snapshot().ready == policy.min_ready).await;
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.generation, 7);
        assert_eq!(snapshot.checkout_hit, 1);
        assert_eq!(snapshot.checkout_miss, 0);
        assert_eq!(snapshot.in_use, 0);
        assert!(snapshot.refill >= u64::from(policy.min_ready + 1));

        pool.deactivate();
        wait_for(|| {
            pool.snapshot().ready == 0 && pool.snapshot().connecting == 0 && fd_budget.in_use() == 0
        })
        .await;
        assert_eq!(authority.counts(), (0, 0));
        assert_eq!(fd_budget.underflows(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn burst_growth_and_idle_shrink_are_bounded() {
        let fixture = CoverFixture::start().await;
        let mut policy = policy();
        policy.min_ready = 1;
        policy.shrink_delay_ms = 100;
        let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
        let pool = pool(&fixture, 11, &policy, authority, FdBudget::new(64));
        assert!(pool.activate());
        wait_for(|| pool.snapshot().ready == 1).await;

        for _ in 0..8 {
            drop(pool.checkout());
        }
        wait_for(|| pool.snapshot().target_ready > policy.min_ready).await;
        let grown = pool.snapshot();
        assert!(grown.target_ready <= policy.max_ready);
        assert!(grown.connecting <= policy.max_connecting);
        assert!(grown.checkout_miss > 0);
        wait_for(|| pool.snapshot().ready == pool.snapshot().target_ready).await;
        wait_for(|| pool.snapshot().target_ready == policy.min_ready).await;
        assert!(pool.snapshot().shrink > 0);

        pool.deactivate();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn low_watermark_coalesces_refill_without_waiting_for_exhaustion() {
        let fixture = CoverFixture::start().await;
        let mut policy = policy();
        policy.min_ready = 8;
        policy.max_ready = 8;
        policy.max_connecting = 8;
        policy.refill_batch = 8;
        let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
        let pool = pool(&fixture, 12, &policy, authority, FdBudget::new(64));
        assert!(pool.activate());
        wait_for(|| pool.snapshot().ready == 8).await;
        let initial_refills = pool.snapshot().refill;

        drop(pool.checkout());
        time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.snapshot().ready, 7);
        assert_eq!(pool.snapshot().refill, initial_refills);

        drop(pool.checkout());
        wait_for(|| pool.snapshot().ready == 8).await;
        assert_eq!(pool.snapshot().refill, initial_refills + 2);
        pool.deactivate();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn checkout_discards_a_peer_closed_idle_socket_and_recovers() {
        let fixture = CoverFixture::start().await;
        let mut policy = policy();
        policy.min_ready = 1;
        policy.max_ready = 1;
        policy.max_connecting = 1;
        policy.refill_batch = 1;
        let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
        let pool = pool(&fixture, 13, &policy, authority, FdBudget::new(64));
        assert!(pool.activate());
        wait_for(|| pool.snapshot().ready == 1 && fixture.accepted_count() == 1).await;

        let mut peer = fixture
            .accepted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .expect("fixture must own the peer half");
        peer.shutdown().await.expect("peer FIN must succeed");
        drop(peer);
        time::sleep(Duration::from_millis(10)).await;

        assert!(pool.checkout().is_none());
        assert_eq!(pool.snapshot().stale_discard, 1);
        wait_for(|| pool.snapshot().ready == 1 && fixture.accepted_count() == 1).await;
        pool.deactivate();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expiry_and_generation_shutdown_release_speculative_resources() {
        let fixture = CoverFixture::start().await;
        let mut policy = policy();
        policy.min_ready = 1;
        policy.idle_timeout_ms = 100;
        policy.max_lifetime_ms = 150;
        let authority = WarmPoolAuthority::new(&policy, 2, PressureGauge::new());
        let fd_budget = FdBudget::new(64);
        let old = pool(&fixture, 21, &policy, authority.clone(), fd_budget.clone());
        let new = pool(&fixture, 22, &policy, authority.clone(), fd_budget.clone());
        assert!(old.activate());
        assert!(new.activate());
        wait_for(|| old.snapshot().ready == 1 && new.snapshot().ready == 1).await;
        wait_for(|| old.snapshot().stale_discard > 0).await;

        old.deactivate();
        wait_for(|| old.snapshot().ready == 0 && old.snapshot().connecting == 0).await;
        assert_eq!(old.snapshot().generation, 21);
        assert_eq!(new.snapshot().generation, 22);
        assert_eq!(new.snapshot().ready, 1);
        assert_eq!(authority.counts().0, 1);

        new.deactivate();
        wait_for(|| fd_budget.in_use() == 0).await;
        assert_eq!(authority.counts(), (0, 0));
        assert_eq!(fd_budget.underflows(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_refill_backs_off_and_recovers_when_cover_returns() {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("port probe must bind");
        let address = probe.local_addr().expect("probe address must exist");
        drop(probe);
        let mut policy = policy();
        policy.min_ready = 1;
        policy.max_connecting = 1;
        policy.refill_batch = 1;
        let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
        let pool = AdaptiveTcpPool::new(
            Arc::from(address.to_string()),
            41,
            DestinationConnector::new(Duration::from_millis(100)),
            FdBudget::new(64),
            authority,
            &policy,
        );
        assert!(pool.activate());
        time::sleep(Duration::from_millis(350)).await;
        let failed = pool.snapshot();
        assert!(failed.connect_failure >= 1);
        assert!(
            failed.refill <= 3,
            "exponential backoff must prevent a tight speculative dial loop"
        );

        let listener = TcpListener::bind(address)
            .await
            .expect("cover must be able to return on the same endpoint");
        let accept = tokio::spawn(async move { listener.accept().await });
        wait_for(|| pool.snapshot().ready == 1).await;
        let accepted = accept
            .await
            .expect("cover accept task must not panic")
            .expect("recovered cover must accept");
        assert_eq!(pool.snapshot().ready, 1);
        pool.deactivate();
        drop(accepted);
    }
}
