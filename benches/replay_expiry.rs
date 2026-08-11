use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hash, Hasher},
    time::{Duration, Instant},
};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::server::nxr::NxrReplayCache;
use sha2::{Digest, Sha256};

const REPLAY_SHARDS: usize = 16;
const CARDINALITIES: &[usize] = &[256, 4_096];
const RESERVATIONS_PER_BATCH: usize = 64;

fn replay_expiry(criterion: &mut Criterion) {
    reality_digest_lookup(criterion);

    let mut group = criterion.benchmark_group("replay/purge_live");
    group.sample_size(100);

    for &count in CARDINALITIES {
        let cache = NxrReplayCache::new(count + 1, Duration::from_secs(3_600))
            .expect("benchmark replay cache must compile");
        let mut retain = RetainCache::default();
        for ordinal in 0..count {
            let nonce = nonce(ordinal);
            cache.reserve(nonce).expect("benchmark nonce must fit");
            retain.insert(nonce);
        }

        group.bench_with_input(
            BenchmarkId::new("deadline_heap", count),
            &count,
            |bencher, _| bencher.iter(|| cache.purge_expired()),
        );
        group.bench_with_input(
            BenchmarkId::new("full_retain", count),
            &count,
            |bencher, _| bencher.iter(|| retain.purge_expired()),
        );
    }
    group.finish();

    let mut group = criterion.benchmark_group("replay/reserve_live");
    group.sample_size(100);
    group.throughput(Throughput::Elements(RESERVATIONS_PER_BATCH as u64));
    for &count in CARDINALITIES {
        group.bench_with_input(
            BenchmarkId::new("selected_shard_heap", count),
            &count,
            |bencher, &count| {
                bencher.iter_batched(
                    || {
                        let cache = NxrReplayCache::new(
                            count + RESERVATIONS_PER_BATCH,
                            Duration::from_secs(3_600),
                        )
                        .expect("benchmark replay cache must compile");
                        for ordinal in 0..count {
                            cache.reserve(nonce(ordinal)).expect("setup nonce must fit");
                        }
                        cache
                    },
                    |cache| {
                        for ordinal in count..count + RESERVATIONS_PER_BATCH {
                            cache
                                .reserve(nonce(ordinal))
                                .expect("measured nonce must fit");
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("legacy_full_retain", count),
            &count,
            |bencher, &count| {
                bencher.iter_batched(
                    || {
                        let mut cache = RetainCache::default();
                        for ordinal in 0..count {
                            cache.insert(nonce(ordinal));
                        }
                        cache
                    },
                    |mut cache| {
                        for ordinal in count..count + RESERVATIONS_PER_BATCH {
                            cache.reserve(nonce(ordinal));
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn reality_digest_lookup(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("replay/reality_digest_lookup");
    group.throughput(Throughput::Elements(1));
    for &count in CARDINALITIES {
        let keys = (0..count).map(digest_key).collect::<Vec<_>>();
        let siphash = keys
            .iter()
            .copied()
            .map(|key| (key.0, ()))
            .collect::<HashMap<_, _>>();
        let digest_word = keys
            .iter()
            .copied()
            .map(|key| (key, ()))
            .collect::<DigestMap>();
        let hit = keys[count / 2];
        let miss = digest_key(usize::MAX);

        group.bench_with_input(
            BenchmarkId::new("siphash_hit", count),
            &hit,
            |bencher, key| {
                bencher.iter(|| siphash.contains_key(&key.0));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("digest_word_hit", count),
            &hit,
            |bencher, key| {
                bencher.iter(|| digest_word.contains_key(key));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_miss", count),
            &miss,
            |bencher, key| {
                bencher.iter(|| siphash.contains_key(&key.0));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("digest_word_miss", count),
            &miss,
            |bencher, key| {
                bencher.iter(|| digest_word.contains_key(key));
            },
        );
    }
    group.finish();
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DigestKey([u8; 32]);

impl Hash for DigestKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(u64::from_ne_bytes(
            self.0[8..16]
                .try_into()
                .expect("SHA-256 benchmark key contains a second word"),
        ));
    }
}

#[derive(Default)]
struct DigestWordHasher(u64);

impl Hasher for DigestWordHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

type DigestMap = HashMap<DigestKey, (), BuildHasherDefault<DigestWordHasher>>;

fn digest_key(ordinal: usize) -> DigestKey {
    DigestKey(Sha256::digest(ordinal.to_be_bytes()).into())
}

struct RetainCache {
    shards: [HashMap<[u8; 16], Instant>; REPLAY_SHARDS],
    deadline: Instant,
}

impl Default for RetainCache {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| HashMap::new()),
            deadline: Instant::now() + Duration::from_secs(3_600),
        }
    }
}

impl RetainCache {
    fn insert(&mut self, nonce: [u8; 16]) {
        self.shards[usize::from(nonce[0]) % REPLAY_SHARDS].insert(nonce, self.deadline);
    }

    fn reserve(&mut self, nonce: [u8; 16]) {
        self.purge_expired();
        self.insert(nonce);
    }

    fn purge_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut removed = 0;
        for shard in &mut self.shards {
            let previous = shard.len();
            shard.retain(|_, expires_at| *expires_at > now);
            removed += previous - shard.len();
        }
        removed
    }
}

fn nonce(ordinal: usize) -> [u8; 16] {
    let mut nonce = u128::try_from(ordinal)
        .expect("benchmark cardinality fits u128")
        .to_be_bytes();
    nonce[0] = u8::try_from(ordinal % REPLAY_SHARDS).expect("shard index fits u8");
    nonce
}

criterion_group!(benches, replay_expiry);
criterion_main!(benches);
