use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::ClientHello;
use crate::{
    config::ResourceGovernorConfig,
    runtime::{AdmissionKind, AdmissionPermit, ResourceGovernor},
};

const REPLAY_SHARDS: usize = 16;

/// A replay reservation or committed entry could not be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    /// The exact authenticated ClientHello is already pending or committed.
    Duplicate,
    /// The global replay-entry bound or allocator rejected another entry.
    Capacity,
    /// The reservation expired or was replaced before ClientFinished.
    ReservationLost,
    /// A monotonic deadline could not be represented.
    Unavailable,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("REALITY replay admission failed")
    }
}

impl Error for ReplayError {}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct ReplayKey([u8; 32]);

impl ReplayKey {
    fn from_client_hello(hello: &ClientHello) -> Self {
        let digest = Sha256::digest(hello.raw_message());
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self(key)
    }
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayKey([REDACTED])")
    }
}

struct ReplayEntry {
    generation: u64,
    committed: bool,
    expires_at: Instant,
    _permit: AdmissionPermit,
}

struct ReplayCacheInner {
    shards: Box<[Mutex<HashMap<ReplayKey, ReplayEntry>>]>,
    governor: ResourceGovernor,
    pending_ttl: Duration,
    committed_ttl: Duration,
    next_generation: AtomicU64,
}

/// Bounded, sharded two-phase replay cache for authenticated REALITY handshakes.
///
/// [`ReplayReservation`] removes its pending entry on every drop path. A replay
/// becomes persistent only through [`ReplayReservation::commit_after_client_finished`].
#[derive(Clone)]
pub struct ReplayCache {
    inner: Arc<ReplayCacheInner>,
}

impl ReplayCache {
    /// Creates a cache sharing the process-wide resource governor.
    #[must_use]
    pub fn new(governor: ResourceGovernor, config: &ResourceGovernorConfig) -> Self {
        let shards = (0..REPLAY_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Self {
            inner: Arc::new(ReplayCacheInner {
                shards,
                governor,
                pending_ttl: Duration::from_millis(config.handshake_timeout_ms),
                committed_ttl: Duration::from_millis(config.replay_retention_ms),
                next_generation: AtomicU64::new(1),
            }),
        }
    }

    /// Reserves the exact authenticated ClientHello until TLS ClientFinished.
    ///
    /// The reservation is automatically rolled back on authentication failure,
    /// fallback, timeout, task cancellation, or any other early return.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, exhausted global capacity, allocation failure, and
    /// unrepresentable monotonic deadlines.
    pub fn reserve(&self, hello: &ClientHello) -> Result<ReplayReservation, ReplayError> {
        self.reserve_at(hello, Instant::now())
    }

    /// Reserves with the TTL anchored at `now`.
    ///
    /// The acceptor passes the instant its handshake deadline is computed
    /// from, so the pending reservation cannot expire before that deadline:
    /// both are the same duration measured from one instant.
    pub(crate) fn reserve_at(
        &self,
        hello: &ClientHello,
        now: Instant,
    ) -> Result<ReplayReservation, ReplayError> {
        self.reserve_key_at(ReplayKey::from_client_hello(hello), now)
    }

    /// Removes expired pending and committed entries and returns the removal count.
    pub fn purge_expired(&self) -> usize {
        self.purge_expired_at(Instant::now())
    }

    fn reserve_key_at(
        &self,
        key: ReplayKey,
        now: Instant,
    ) -> Result<ReplayReservation, ReplayError> {
        let expires_at = now
            .checked_add(self.inner.pending_ttl)
            .ok_or(ReplayError::Unavailable)?;
        let shard_index = shard_index(key);
        {
            let mut entries = lock_recover(&self.inner.shards[shard_index]);
            entries.retain(|_, entry| entry.expires_at > now);
            if entries.contains_key(&key) {
                return Err(ReplayError::Duplicate);
            }
        }
        let permit = match self.inner.governor.try_acquire(AdmissionKind::ReplayEntry) {
            Ok(permit) => permit,
            Err(_) => {
                // Expired entries own their global permits. Reclaim all shards once
                // before reporting capacity, without ever adding a waiter queue.
                self.purge_expired_at(now);
                self.inner
                    .governor
                    .try_acquire(AdmissionKind::ReplayEntry)
                    .map_err(|_| ReplayError::Capacity)?
            }
        };
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut entries = lock_recover(&self.inner.shards[shard_index]);
        entries.retain(|_, entry| entry.expires_at > now);
        if entries.contains_key(&key) {
            return Err(ReplayError::Duplicate);
        }
        entries.try_reserve(1).map_err(|_| ReplayError::Capacity)?;
        entries.insert(
            key,
            ReplayEntry {
                generation,
                committed: false,
                expires_at,
                _permit: permit,
            },
        );
        Ok(ReplayReservation {
            cache: self.clone(),
            key,
            generation,
            active: true,
        })
    }

    fn purge_expired_at(&self, now: Instant) -> usize {
        self.inner
            .shards
            .iter()
            .map(|shard| {
                let mut entries = lock_recover(shard);
                let previous = entries.len();
                entries.retain(|_, entry| entry.expires_at > now);
                previous.saturating_sub(entries.len())
            })
            .sum()
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner
            .shards
            .iter()
            .map(|shard| lock_recover(shard).len())
            .sum()
    }
}

/// A pending replay entry that rolls back unless ClientFinished explicitly commits it.
pub struct ReplayReservation {
    cache: ReplayCache,
    key: ReplayKey,
    generation: u64,
    active: bool,
}

impl ReplayReservation {
    /// Commits the replay entry after the TLS 1.3 ClientFinished was verified.
    ///
    /// This method deliberately consumes the reservation so it cannot be committed
    /// twice or reused by a later handshake state.
    ///
    /// # Errors
    ///
    /// Returns an error if the pending entry expired, was replaced, or its new
    /// monotonic retention deadline cannot be represented.
    pub fn commit_after_client_finished(mut self) -> Result<(), ReplayError> {
        self.commit_at(Instant::now())
    }

    fn commit_at(&mut self, now: Instant) -> Result<(), ReplayError> {
        let expires_at = now
            .checked_add(self.cache.inner.committed_ttl)
            .ok_or(ReplayError::Unavailable)?;
        let shard_index = shard_index(self.key);
        let mut entries = lock_recover(&self.cache.inner.shards[shard_index]);
        let Some(entry) = entries.get_mut(&self.key) else {
            return Err(ReplayError::ReservationLost);
        };
        if entry.generation != self.generation || entry.committed || entry.expires_at <= now {
            if entry.generation == self.generation && !entry.committed {
                entries.remove(&self.key);
            }
            return Err(ReplayError::ReservationLost);
        }
        entry.committed = true;
        entry.expires_at = expires_at;
        self.active = false;
        Ok(())
    }
}

impl fmt::Debug for ReplayReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayReservation")
            .field("key", &self.key)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl Drop for ReplayReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let shard_index = shard_index(self.key);
        let mut entries = lock_recover(&self.cache.inner.shards[shard_index]);
        if entries
            .get(&self.key)
            .is_some_and(|entry| entry.generation == self.generation && !entry.committed)
        {
            entries.remove(&self.key);
        }
    }
}

fn shard_index(key: ReplayKey) -> usize {
    usize::from(key.0[0]) % REPLAY_SHARDS
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::{Duration, Instant},
    };

    use super::{ReplayCache, ReplayError, ReplayKey};
    use crate::{config::ResourceGovernorConfig, runtime::ResourceGovernor};

    #[test]
    fn pending_duplicate_is_rejected_and_drop_rolls_back() {
        let cache = test_cache(1);
        let now = Instant::now();
        let key = replay_key(1);
        let reservation = cache
            .reserve_key_at(key, now)
            .expect("first handshake must reserve");

        assert!(matches!(
            cache.reserve_key_at(key, now),
            Err(ReplayError::Duplicate)
        ));
        drop(reservation);
        assert_eq!(cache.entry_count(), 0);
        assert!(cache.reserve_key_at(key, now).is_ok());
    }

    #[test]
    fn only_explicit_client_finished_commit_persists() {
        let cache = test_cache(2);
        let now = Instant::now();
        let key = replay_key(2);
        let mut reservation = cache
            .reserve_key_at(key, now)
            .expect("first handshake must reserve");
        reservation
            .commit_at(now + Duration::from_millis(1))
            .expect("verified ClientFinished must commit");
        drop(reservation);

        assert_eq!(cache.entry_count(), 1);
        assert!(matches!(
            cache.reserve_key_at(key, now + Duration::from_millis(2)),
            Err(ReplayError::Duplicate)
        ));
    }

    #[test]
    fn expired_entries_release_global_capacity() {
        let cache = test_cache(1);
        let now = Instant::now();
        let mut committed = cache
            .reserve_key_at(replay_key(3), now)
            .expect("first entry must reserve");
        committed
            .commit_at(now)
            .expect("verified ClientFinished must commit");
        assert!(matches!(
            cache.reserve_key_at(replay_key(4), now),
            Err(ReplayError::Capacity)
        ));

        let replacement = cache
            .reserve_key_at(replay_key(4), now + Duration::from_millis(101))
            .expect("expired committed entry must release its permit");
        assert_eq!(cache.entry_count(), 1);
        drop(replacement);
    }

    #[test]
    fn expired_pending_reservation_cannot_remove_replacement() {
        let cache = test_cache(2);
        let now = Instant::now();
        let key = replay_key(5);
        let old = cache
            .reserve_key_at(key, now)
            .expect("first handshake must reserve");
        let replacement = cache
            .reserve_key_at(key, now + Duration::from_millis(101))
            .expect("expired pending entry must be replaceable");
        drop(old);

        assert_eq!(cache.entry_count(), 1);
        assert!(matches!(
            cache.reserve_key_at(key, now + Duration::from_millis(102)),
            Err(ReplayError::Duplicate)
        ));
        drop(replacement);
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn expired_pending_reservation_cannot_commit() {
        let cache = test_cache(1);
        let now = Instant::now();
        let mut reservation = cache
            .reserve_key_at(replay_key(6), now)
            .expect("first handshake must reserve");

        assert!(matches!(
            reservation.commit_at(now + Duration::from_millis(101)),
            Err(ReplayError::ReservationLost)
        ));
        assert_eq!(cache.entry_count(), 0);
        assert!(cache.reserve_key_at(replay_key(7), now).is_ok());
    }

    #[test]
    fn a_client_finished_just_before_the_deadline_commits() {
        // The acceptor anchors the pending reservation TTL and the handshake
        // deadline at one shared instant with the same duration, so any
        // ClientFinished the deadline admits must still find its reservation
        // alive. A reservation expiring earlier than the deadline killed
        // authenticated sessions with ReservationLost.
        let cache = test_cache(1);
        let started = Instant::now();
        let mut reservation = cache
            .reserve_key_at(replay_key(9), started)
            .expect("first handshake must reserve");
        let handshake_deadline = started + Duration::from_millis(100);
        reservation
            .commit_at(handshake_deadline - Duration::from_millis(1))
            .expect("a ClientFinished accepted before the handshake deadline must commit");
        drop(reservation);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn concurrent_duplicate_race_has_one_winner() {
        const TASKS: usize = 8;
        let cache = test_cache(TASKS as u32);
        let start = Arc::new(Barrier::new(TASKS + 1));
        let attempted = Arc::new(Barrier::new(TASKS));
        let now = Instant::now();
        let mut tasks = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let cache = cache.clone();
            let start = Arc::clone(&start);
            let attempted = Arc::clone(&attempted);
            tasks.push(thread::spawn(move || {
                start.wait();
                let result = cache.reserve_key_at(replay_key(8), now);
                attempted.wait();
                result.is_ok()
            }));
        }
        start.wait();

        let winners = tasks
            .into_iter()
            .map(|task| task.join().expect("test worker must not panic"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }

    fn test_cache(max_entries: u32) -> ReplayCache {
        let config = ResourceGovernorConfig {
            max_replay_entries: max_entries,
            handshake_timeout_ms: 100,
            replay_retention_ms: 100,
            ..ResourceGovernorConfig::default()
        };
        ReplayCache::new(ResourceGovernor::new(&config), &config)
    }

    const fn replay_key(value: u8) -> ReplayKey {
        ReplayKey([value; 32])
    }
}
