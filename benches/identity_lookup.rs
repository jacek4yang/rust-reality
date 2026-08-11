use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::protocol::vless::{UserId, UserRegistry};

const CARDINALITIES: &[usize] = &[1, 16, 32, 64, 128, 256, 4_096];

fn identity_lookup(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("identity/lookup");
    group.sample_size(200);
    group.noise_threshold(0.02);

    for &count in CARDINALITIES {
        let users = (0..count).map(user_id).collect::<Vec<_>>();
        let registry = UserRegistry::new(users.iter().copied());
        // Match the production binding's 16-byte value footprint rather than
        // comparing against a key-only set with artificially smaller buckets.
        let hash = users
            .iter()
            .copied()
            .map(|user| (user, [0_u8; 16]))
            .collect::<HashMap<_, _>>();
        let hit = users[count / 2];
        let miss = UserId::new(u128::MAX.to_be_bytes());

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("adaptive_hit", count),
            &hit,
            |bencher, user| bencher.iter(|| registry.contains(*user)),
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_hit", count),
            &hit,
            |bencher, user| bencher.iter(|| hash.contains_key(user)),
        );
        group.bench_with_input(
            BenchmarkId::new("adaptive_miss", count),
            &miss,
            |bencher, user| bencher.iter(|| registry.contains(*user)),
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_miss", count),
            &miss,
            |bencher, user| bencher.iter(|| hash.contains_key(user)),
        );
    }
    group.finish();
}

fn user_id(index: usize) -> UserId {
    let ordinal = u128::try_from(index).expect("benchmark cardinality fits u128") + 1;
    UserId::new(ordinal.to_be_bytes())
}

criterion_group!(benches, identity_lookup);
criterion_main!(benches);
