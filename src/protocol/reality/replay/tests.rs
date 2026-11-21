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
fn committed_entries_expire_and_refill_across_shards() {
    let cache = test_cache(300);
    let now = Instant::now();
    let ttl = Duration::from_millis(100);
    let key = |id: u64| {
        let mut bytes = [0; 32];
        bytes[0] = (id % 16) as u8;
        bytes[8..16].copy_from_slice(&id.to_ne_bytes());
        ReplayKey(bytes)
    };

    for cycle in 0..2 {
        let started = now + ttl * cycle;
        let first = u64::from(cycle) * 300;
        for id in first..first + 300 {
            let mut reservation = cache
                .reserve_key_at(key(id), started)
                .expect("every shard must admit fresh entries");
            reservation
                .commit_at(started)
                .expect("verified ClientFinished must commit");
        }
        assert_eq!(cache.entry_count(), 300);
        assert_eq!(
            cache
                .inner
                .governor
                .in_flight(crate::runtime::AdmissionKind::ReplayEntry),
            300
        );
        assert!(matches!(
            cache.reserve_key_at(key(first + 300), started),
            Err(ReplayError::Capacity)
        ));
        let expires = started + ttl;
        assert!(matches!(
            cache.reserve_key_at(key(first), expires - Duration::from_nanos(1)),
            Err(ReplayError::Duplicate)
        ));
        assert_eq!(cache.purge_expired_at(expires), 300);
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(
            cache
                .inner
                .governor
                .in_flight(crate::runtime::AdmissionKind::ReplayEntry),
            0
        );
        for shard in &cache.inner.shards {
            let shard = super::lock_recover(shard);
            assert!(shard.entries.is_empty());
            assert!(shard.expirations.is_empty());
        }
    }
}

#[test]
fn saturated_replay_storage_reuses_allocation_after_expiry() {
    let cache = test_cache(300);
    let start = Instant::now();
    let ttl = Duration::from_millis(100);
    let cycle = |index: u32| {
        let now = start + ttl * index;
        for id in 0_u64..300 {
            let mut bytes = [0; 32];
            bytes[0] = u8::try_from(id % 16).unwrap();
            bytes[8..16].copy_from_slice(&id.to_ne_bytes());
            let mut reservation = cache.reserve_key_at(ReplayKey(bytes), now).unwrap();
            reservation.commit_at(now).unwrap();
        }
        assert_eq!(cache.entry_count(), 300);
        assert_eq!(cache.purge_expired_at(now + ttl), 300);
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(
            cache
                .inner
                .governor
                .in_flight(crate::runtime::AdmissionKind::ReplayEntry),
            0
        );
    };
    cycle(0);
    let retained: [_; 16] = std::array::from_fn(|index| {
        let shard = super::lock_recover(&cache.inner.shards[index]);
        (shard.entries.capacity(), shard.expirations.capacity())
    });
    let allocation = allocation_counter::measure(|| {
        for index in 1..129 {
            cycle(index);
        }
    });
    assert_eq!(
        allocation.count_total, 0,
        "identical saturated cycles reuse storage"
    );
    assert_eq!(allocation.bytes_current, 0);
    for (index, capacities) in retained.iter().enumerate() {
        let shard = super::lock_recover(&cache.inner.shards[index]);
        assert_eq!(
            (shard.entries.capacity(), shard.expirations.capacity()),
            *capacities
        );
    }
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

/// Production retains committed entries far longer than a pending handshake
/// may last (120 s vs 10 s by default). With distinct TTLs, a committed
/// ClientHello must keep rejecting replays after the pending deadline passes
/// and its stale pending expiry record is purged, and only release once the
/// committed retention elapses.
#[test]
fn committed_entry_outlives_its_pending_deadline() {
    let config = ResourceGovernorPolicy {
        max_replay_entries: 4,
        handshake_timeout_ms: 10,
        replay_retention_ms: 100,
        ..ResourceGovernorPolicy::default()
    };
    let cache = ReplayCache::new(ResourceGovernor::new(&config), &config);
    let key = replay_key(9);
    let started = Instant::now();
    let committed_at = started + Duration::from_millis(5);
    cache
        .reserve_key_at(key, started)
        .expect("first reservation")
        .commit_at(committed_at)
        .expect("in-window commit");

    // Past the pending deadline: purging the stale pending record must keep
    // the committed entry, and an exact replay stays rejected.
    let after_pending = started + Duration::from_millis(50);
    assert_eq!(cache.purge_expired_at(after_pending), 0);
    assert_eq!(cache.entry_count(), 1);
    assert!(matches!(
        cache.reserve_key_at(key, after_pending),
        Err(ReplayError::Duplicate)
    ));
    let just_before_release = committed_at + Duration::from_millis(99);
    assert!(matches!(
        cache.reserve_key_at(key, just_before_release),
        Err(ReplayError::Duplicate)
    ));

    // Once committed retention elapses the entry and its permit are released.
    let released = committed_at + Duration::from_millis(100);
    assert_eq!(cache.purge_expired_at(released), 1);
    assert_eq!(cache.entry_count(), 0);
    cache
        .reserve_key_at(key, released)
        .expect("retention elapsed; key admissible again");
}

/// The pending entry expires at its deadline instant, exactly as the purge
/// treats it, so a commit that arrives at that instant is too late.
#[test]
fn a_commit_at_the_exact_pending_deadline_is_lost() {
    let cache = test_cache(1);
    let started = Instant::now();
    let mut reservation = cache
        .reserve_key_at(replay_key(11), started)
        .expect("first handshake must reserve");
    assert!(matches!(
        reservation.commit_at(started + Duration::from_millis(100)),
        Err(ReplayError::ReservationLost)
    ));
    assert_eq!(cache.entry_count(), 0);
}

/// A stale reservation whose pending entry expired and was replaced for the
/// same ClientHello must neither commit nor remove the replacement.
#[test]
fn a_stale_reservation_cannot_commit_or_evict_its_replacement() {
    let cache = test_cache(2);
    let started = Instant::now();
    let key = replay_key(12);
    let mut stale = cache
        .reserve_key_at(key, started)
        .expect("first handshake must reserve");
    let replaced_at = started + Duration::from_millis(100);
    let mut replacement = cache
        .reserve_key_at(key, replaced_at)
        .expect("an expired pending entry must be replaceable");

    assert!(matches!(
        stale.commit_at(replaced_at + Duration::from_millis(1)),
        Err(ReplayError::ReservationLost)
    ));
    assert_eq!(cache.entry_count(), 1);
    assert!(matches!(
        cache.reserve_key_at(key, replaced_at + Duration::from_millis(1)),
        Err(ReplayError::Duplicate)
    ));
    replacement
        .commit_at(replaced_at + Duration::from_millis(2))
        .expect("the live replacement must still commit");
    drop(stale);
    drop(replacement);
    assert_eq!(cache.entry_count(), 1);
}

/// Abandoned reservations leave stale expiry records behind; the heap must
/// be compacted so churn cannot grow it without bound.
#[test]
fn abandoned_reservations_do_not_grow_the_expiry_heap_without_bound() {
    let cache = test_cache(1);
    let now = Instant::now();
    let key = replay_key(13);
    for _ in 0..4_096 {
        drop(cache.reserve_key_at(key, now).expect("churn must reserve"));
    }
    let shard = super::lock_recover(&cache.inner.shards[super::shard_index(key)]);
    assert!(shard.entries.is_empty());
    assert!(
        shard.expirations.len() <= 1_025,
        "stale expiry records: {}",
        shard.expirations.len()
    );
}
