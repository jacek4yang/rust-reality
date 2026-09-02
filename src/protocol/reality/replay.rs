use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    error::Error,
    fmt,
    hash::{BuildHasherDefault, Hash, Hasher},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::ClientHello;
use crate::runtime::policy::ResourceGovernorPolicy;
use crate::runtime::{AdmissionKind, AdmissionPermit, ResourceGovernor};

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

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct ReplayKey([u8; 32]);

impl ReplayKey {
    fn from_client_hello(hello: &ClientHello) -> Self {
        let digest = Sha256::digest(hello.raw_message());
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self(key)
    }
}

impl Hash for ReplayKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // The first digest byte selects the mutex shard. Use a disjoint digest
        // word for the table hash so every shard still sees all 64 hash bits.
        let digest_word = u64::from_ne_bytes([
            self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14],
            self.0[15],
        ]);
        state.write_u64(digest_word);
    }
}

/// Identity finalizer for a key that is already a uniformly distributed
/// SHA-256 digest. Re-running keyed SipHash over all 32 bytes adds work but no
/// useful collision resistance: targeting this 64-bit digest word still
/// requires a SHA-256 preimage search.
#[derive(Default)]
struct ReplayKeyHasher(u64);

impl Hasher for ReplayKeyHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // ReplayKey always calls write_u64. Keep the required generic entry
        // point deterministic and well-defined for defensive future use.
        self.0 = bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

type ReplayEntries = HashMap<ReplayKey, ReplayEntry, BuildHasherDefault<ReplayKeyHasher>>;

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

#[derive(Default)]
struct ReplayShard {
    entries: ReplayEntries,
    expirations: BinaryHeap<Reverse<(Instant, u64, ReplayKey)>>,
}

struct ReplayCacheInner {
    shards: Box<[Mutex<ReplayShard>]>,
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
    pub fn new(governor: ResourceGovernor, config: &ResourceGovernorPolicy) -> Self {
        let shards = (0..REPLAY_SHARDS)
            .map(|_| Mutex::new(ReplayShard::default()))
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
            let mut shard = lock_recover(&self.inner.shards[shard_index]);
            purge_replay_shard(&mut shard, now);
            if shard.entries.contains_key(&key) {
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
        let generation = self
            .inner
            .next_generation
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ReplayError::Unavailable)?;
        let mut shard = lock_recover(&self.inner.shards[shard_index]);
        purge_replay_shard(&mut shard, now);
        if shard.entries.contains_key(&key) {
            return Err(ReplayError::Duplicate);
        }
        shard
            .entries
            .try_reserve(1)
            .map_err(|_| ReplayError::Capacity)?;
        shard
            .expirations
            .try_reserve(1)
            .map_err(|_| ReplayError::Capacity)?;
        shard.entries.insert(
            key,
            ReplayEntry {
                generation,
                committed: false,
                expires_at,
                _permit: permit,
            },
        );
        shard
            .expirations
            .push(Reverse((expires_at, generation, key)));
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
                let mut shard = lock_recover(shard);
                purge_replay_shard(&mut shard, now)
            })
            .sum()
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner
            .shards
            .iter()
            .map(|shard| lock_recover(shard).entries.len())
            .sum()
    }

    /// Returns the entry count for structured replay fuzzing.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    #[must_use]
    pub fn fuzz_entry_count(&self) -> usize {
        self.inner
            .shards
            .iter()
            .map(|shard| lock_recover(shard).entries.len())
            .sum()
    }

    /// Reserves at an explicit monotonic instant for deterministic expiry fuzzing.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_reserve_at(
        &self,
        hello: &ClientHello,
        now: Instant,
    ) -> Result<ReplayReservation, ReplayError> {
        self.reserve_at(hello, now)
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
        let mut shard = lock_recover(&self.cache.inner.shards[shard_index]);
        let Some(entry) = shard.entries.get(&self.key) else {
            return Err(ReplayError::ReservationLost);
        };
        if entry.generation != self.generation || entry.committed || entry.expires_at <= now {
            if entry.generation == self.generation && !entry.committed {
                shard.entries.remove(&self.key);
                compact_stale_expirations(&mut shard);
            }
            return Err(ReplayError::ReservationLost);
        }
        shard
            .expirations
            .try_reserve(1)
            .map_err(|_| ReplayError::Capacity)?;
        let Some(entry) = shard.entries.get_mut(&self.key) else {
            return Err(ReplayError::ReservationLost);
        };
        entry.committed = true;
        entry.expires_at = expires_at;
        shard
            .expirations
            .push(Reverse((expires_at, self.generation, self.key)));
        self.active = false;
        Ok(())
    }

    /// Commits at an explicit instant for deterministic structured fuzzing.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_commit_at(&mut self, now: Instant) -> Result<(), ReplayError> {
        self.commit_at(now)
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
        let mut shard = lock_recover(&self.cache.inner.shards[shard_index]);
        if shard
            .entries
            .get(&self.key)
            .is_some_and(|entry| entry.generation == self.generation && !entry.committed)
        {
            shard.entries.remove(&self.key);
            compact_stale_expirations(&mut shard);
        }
    }
}

fn purge_replay_shard(shard: &mut ReplayShard, now: Instant) -> usize {
    let mut removed = 0;
    while shard
        .expirations
        .peek()
        .is_some_and(|Reverse((expires_at, _, _))| *expires_at <= now)
    {
        let Some(Reverse((expires_at, generation, key))) = shard.expirations.pop() else {
            break;
        };
        if shard
            .entries
            .get(&key)
            .is_some_and(|entry| entry.generation == generation && entry.expires_at == expires_at)
        {
            shard.entries.remove(&key);
            removed += 1;
        }
    }
    removed
}

/// Dropped pending reservations leave one unreachable heap record. Compact
/// only after a generous slack threshold, bounding memory while amortizing
/// the scan over at least 1,024 failed handshakes.
fn compact_stale_expirations(shard: &mut ReplayShard) {
    let maximum = shard.entries.len().saturating_mul(2).saturating_add(1_024);
    if shard.expirations.len() <= maximum {
        return;
    }
    let entries = &shard.entries;
    shard
        .expirations
        .retain(|Reverse((expires_at, generation, key))| {
            entries.get(key).is_some_and(|entry| {
                entry.generation == *generation && entry.expires_at == *expires_at
            })
        });
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
        sync::{Arc, Barrier, atomic::Ordering},
        thread,
        time::{Duration, Instant},
    };

    use super::{ReplayCache, ReplayError, ReplayKey};
    use crate::runtime::{ResourceGovernor, policy::ResourceGovernorPolicy};

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
    fn exhausted_generation_fails_closed_without_leaking_capacity() {
        let cache = test_cache(1);
        let now = Instant::now();
        cache
            .inner
            .next_generation
            .store(u64::MAX, Ordering::Relaxed);

        assert!(matches!(
            cache.reserve_key_at(replay_key(10), now),
            Err(ReplayError::Unavailable)
        ));
        assert_eq!(cache.entry_count(), 0);

        // Resetting the synthetic test state proves the failed reservation
        // released its global admission permit instead of stranding capacity.
        cache.inner.next_generation.store(1, Ordering::Relaxed);
        assert!(cache.reserve_key_at(replay_key(10), now).is_ok());
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
        let config = ResourceGovernorPolicy {
            max_replay_entries: max_entries,
            handshake_timeout_ms: 100,
            replay_retention_ms: 100,
            ..ResourceGovernorPolicy::default()
        };
        ReplayCache::new(ResourceGovernor::new(&config), &config)
    }

    const fn replay_key(value: u8) -> ReplayKey {
        ReplayKey([value; 32])
    }
}
