//! Bounded NXR nonce replay cache.
//!
//! Same construction as the Handoff replay cache: reserve-before-use, sharded
//! maps, and monotonic retention. Authenticator and landing stay in the parent
//! module.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant as MonotonicInstant},
};

use crate::config::node::landing::NxrLandingConfig;

use super::error::{NxrLandingConfigError, NxrReplayError};

const REPLAY_SHARDS: usize = 16;

#[derive(Default)]
struct NonceShard {
    entries: HashMap<[u8; 16], MonotonicInstant>,
    expirations: BinaryHeap<Reverse<(MonotonicInstant, [u8; 16])>>,
}

type NonceShards = Box<[Mutex<NonceShard>]>;

/// Bounded nonce cache shared by all generations of one NXR landing listener.
#[derive(Clone)]
pub struct NxrReplayCache {
    inner: Arc<NxrReplayCacheInner>,
}

struct NxrReplayCacheInner {
    shards: NonceShards,
    capacity: usize,
    used: AtomicUsize,
    retention: Duration,
}

/// Retained verified nonces per landing listener.
///
/// Derived rather than configured: the bound exists to cap memory, and a
/// landing has no information an operator could add to it.
pub(crate) const REPLAY_NONCE_CAPACITY: u32 = 65_536;

/// How long a verified nonce is retained, from the accepted clock skew.
///
/// A nonce must outlive the window in which a replayed request could still be
/// accepted, which is the skew in both directions plus a second of margin.
pub(crate) const fn replay_retention_seconds(max_time_difference_seconds: u64) -> u64 {
    max_time_difference_seconds
        .saturating_mul(2)
        .saturating_add(1)
}

impl NxrReplayCache {
    /// Compiles the bounded replay policy for one validated NXR listener.
    ///
    /// # Errors
    ///
    /// Rejects an unrepresentable capacity or unavailable replay policy.
    pub fn from_landing(inbound: &NxrLandingConfig) -> Result<Self, NxrLandingConfigError> {
        let capacity =
            usize::try_from(REPLAY_NONCE_CAPACITY).map_err(|_| NxrLandingConfigError::Capacity)?;
        Self::new(
            capacity,
            Duration::from_secs(replay_retention_seconds(
                inbound.timing().max_time_difference_seconds,
            )),
        )
        .map_err(NxrLandingConfigError::Replay)
    }

    /// Creates an independently bounded nonce cache.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or retention before allocating shards.
    pub fn new(capacity: usize, retention: Duration) -> Result<Self, NxrReplayError> {
        if capacity == 0 || retention.is_zero() {
            return Err(NxrReplayError::Unavailable);
        }
        let shards = (0..REPLAY_SHARDS)
            .map(|_| Mutex::new(NonceShard::default()))
            .collect();
        Ok(Self {
            inner: Arc::new(NxrReplayCacheInner {
                shards,
                capacity,
                used: AtomicUsize::new(0),
                retention,
            }),
        })
    }

    /// Atomically records a verified nonce until its monotonic retention deadline.
    ///
    /// # Errors
    ///
    /// Rejects duplicate nonces, exhausted bounded capacity, allocation failure,
    /// and unrepresentable monotonic deadlines.
    pub fn reserve(&self, nonce: [u8; 16]) -> Result<(), NxrReplayError> {
        self.reserve_at(nonce, MonotonicInstant::now())
    }

    /// Removes every expired nonce and returns the number of released entries.
    pub fn purge_expired(&self) -> usize {
        self.purge_expired_at(MonotonicInstant::now())
    }

    pub(super) fn reserve_at(
        &self,
        nonce: [u8; 16],
        now: MonotonicInstant,
    ) -> Result<(), NxrReplayError> {
        let expires_at = now
            .checked_add(self.inner.retention)
            .ok_or(NxrReplayError::Unavailable)?;
        let shard_index = nonce_shard(nonce);
        let mut swept_all = false;
        loop {
            let mut shard = lock_recover(&self.inner.shards[shard_index]);
            let removed = purge_nonce_shard(&mut shard, now);
            if removed != 0 {
                self.inner.used.fetch_sub(removed, Ordering::AcqRel);
            }
            if shard.entries.contains_key(&nonce) {
                return Err(NxrReplayError::Duplicate);
            }

            // The normal path touches only the nonce's shard. A full sweep is
            // reserved for actual global pressure, amortizing sixteen locks
            // over a capacity event rather than every accepted connection.
            if self.inner.used.load(Ordering::Acquire) >= self.inner.capacity {
                drop(shard);
                if swept_all {
                    return Err(NxrReplayError::Capacity);
                }
                self.purge_expired_at(now);
                swept_all = true;
                continue;
            }

            shard
                .entries
                .try_reserve(1)
                .map_err(|_| NxrReplayError::Capacity)?;
            shard
                .expirations
                .try_reserve(1)
                .map_err(|_| NxrReplayError::Capacity)?;
            match reserve_slot(&self.inner) {
                Ok(()) => {
                    shard.entries.insert(nonce, expires_at);
                    shard.expirations.push(Reverse((expires_at, nonce)));
                    return Ok(());
                }
                Err(_) if !swept_all => {
                    drop(shard);
                    self.purge_expired_at(now);
                    swept_all = true;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) fn purge_expired_at(&self, now: MonotonicInstant) -> usize {
        let removed: usize = self
            .inner
            .shards
            .iter()
            .map(|shard| {
                let mut shard = lock_recover(shard);
                purge_nonce_shard(&mut shard, now)
            })
            .sum();
        if removed != 0 {
            self.inner.used.fetch_sub(removed, Ordering::AcqRel);
        }
        removed
    }

    pub(crate) fn retention_policy(&self) -> (usize, Duration) {
        (self.inner.capacity, self.inner.retention)
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.inner.used.load(Ordering::Acquire)
    }
}

fn purge_nonce_shard(shard: &mut NonceShard, now: MonotonicInstant) -> usize {
    let mut removed = 0;
    while shard
        .expirations
        .peek()
        .is_some_and(|Reverse((expires_at, _))| *expires_at <= now)
    {
        let Some(Reverse((expires_at, nonce))) = shard.expirations.pop() else {
            break;
        };
        if shard
            .entries
            .get(&nonce)
            .is_some_and(|current| *current == expires_at)
        {
            shard.entries.remove(&nonce);
            removed += 1;
        }
    }
    removed
}

fn reserve_slot(inner: &NxrReplayCacheInner) -> Result<(), NxrReplayError> {
    let mut observed = inner.used.load(Ordering::Acquire);
    loop {
        if observed >= inner.capacity {
            return Err(NxrReplayError::Capacity);
        }
        match inner.used.compare_exchange_weak(
            observed,
            observed + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(current) => observed = current,
        }
    }
}

fn nonce_shard(nonce: [u8; 16]) -> usize {
    usize::from(nonce[0]) % REPLAY_SHARDS
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
