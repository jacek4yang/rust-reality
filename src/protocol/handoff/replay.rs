//! Bounded Handoff transfer-nonce replay cache.
//!
//! Same construction as the NXR replay cache: reserve-before-use, sharded
//! maps, and monotonic retention. Wire seal/open stays in the parent module.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant as MonotonicInstant},
};

use super::{HandoffError, NONCE_LEN};

const REPLAY_SHARDS: usize = 16;

/// Bounded nonce cache shared by all transfers of one LANDING listener.
///
/// Same construction as the NXR replay cache: sixteen mutex-sharded nonce
/// maps, one atomic capacity counter, monotonic retention deadlines, and
/// reserve-before-use so a nonce is burned even when the transfer it arrived
/// on later fails authentication. Reserve-before-use is deliberate — it keeps
/// the replay check ahead of all DH work — but it also means an
/// unauthenticated peer burns one slot per structurally valid, in-window
/// message, so cache capacity alone does not bound that burn. This is the
/// exact exposure the NXR listener already accepts on the same
/// firewall-restricted internal-port posture; per-source rate limiting
/// belongs to that outer layer, not to this process.
#[derive(Clone)]
pub struct HandoffReplayCache {
    inner: Arc<HandoffReplayCacheInner>,
}

#[derive(Default)]
struct NonceShard {
    entries: HashMap<[u8; NONCE_LEN], MonotonicInstant>,
    expirations: BinaryHeap<Reverse<(MonotonicInstant, [u8; NONCE_LEN])>>,
}

type NonceShards = Box<[Mutex<NonceShard>]>;

struct HandoffReplayCacheInner {
    shards: NonceShards,
    capacity: usize,
    used: AtomicUsize,
    retention: Duration,
}

impl HandoffReplayCache {
    /// Creates an independently bounded nonce cache.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or retention before allocating shards.
    pub fn new(capacity: usize, retention: Duration) -> Result<Self, HandoffError> {
        if capacity == 0 || retention.is_zero() {
            return Err(HandoffError::Replay);
        }
        let shards = (0..REPLAY_SHARDS)
            .map(|_| Mutex::new(NonceShard::default()))
            .collect();
        Ok(Self {
            inner: Arc::new(HandoffReplayCacheInner {
                shards,
                capacity,
                used: AtomicUsize::new(0),
                retention,
            }),
        })
    }

    /// Atomically records a structurally valid, fresh nonce until its
    /// monotonic retention deadline.
    ///
    /// # Errors
    ///
    /// Rejects duplicate nonces, exhausted bounded capacity, and allocation
    /// failure.
    pub fn reserve(&self, nonce: [u8; NONCE_LEN]) -> Result<(), HandoffError> {
        self.reserve_at(nonce, MonotonicInstant::now())
    }

    pub(super) fn reserve_at(
        &self,
        nonce: [u8; NONCE_LEN],
        now: MonotonicInstant,
    ) -> Result<(), HandoffError> {
        let expires_at = now
            .checked_add(self.inner.retention)
            .ok_or(HandoffError::Replay)?;
        let shard_index = usize::from(nonce[0]) % REPLAY_SHARDS;
        let mut swept_all = false;
        loop {
            let mut shard = lock_recover(&self.inner.shards[shard_index]);
            let removed = purge_nonce_shard(&mut shard, now);
            if removed != 0 {
                self.inner.used.fetch_sub(removed, Ordering::AcqRel);
            }
            if shard.entries.contains_key(&nonce) {
                return Err(HandoffError::Replay);
            }

            if self.inner.used.load(Ordering::Acquire) >= self.inner.capacity {
                drop(shard);
                if swept_all {
                    return Err(HandoffError::Replay);
                }
                self.purge_expired_at(now);
                swept_all = true;
                continue;
            }

            shard
                .entries
                .try_reserve(1)
                .map_err(|_| HandoffError::Allocation)?;
            shard
                .expirations
                .try_reserve(1)
                .map_err(|_| HandoffError::Allocation)?;
            match self.reserve_slot() {
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

    /// Removes every expired nonce and returns the number of released entries.
    pub fn purge_expired(&self) -> usize {
        self.purge_expired_at(MonotonicInstant::now())
    }

    fn purge_expired_at(&self, now: MonotonicInstant) -> usize {
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

    fn reserve_slot(&self) -> Result<(), HandoffError> {
        let mut observed = self.inner.used.load(Ordering::Acquire);
        loop {
            if observed >= self.inner.capacity {
                return Err(HandoffError::Replay);
            }
            match self.inner.used.compare_exchange_weak(
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

impl fmt::Debug for HandoffReplayCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffReplayCache")
            .field("capacity", &self.inner.capacity)
            .finish_non_exhaustive()
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
