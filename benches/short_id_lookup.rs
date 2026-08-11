use std::{collections::HashMap, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _};

const CARDINALITIES: &[usize] = &[2, 4, 8, 16, 64, 256, 512, 4_096];

fn short_id_lookup(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("short_id/owner_lookup");
    group.sample_size(100);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.noise_threshold(0.02);

    for &count in CARDINALITIES {
        let bindings = (0..count)
            .map(|index| (short_id(index), user_id(index)))
            .collect::<Vec<_>>();
        let hashed = bindings.iter().copied().collect::<HashMap<_, _>>();
        let hit = short_id(count / 2);
        let miss = u64::MAX.to_be_bytes();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("constant_time_hit", count),
            &hit,
            |bencher, short_id| bencher.iter(|| constant_time_owner(&bindings, short_id)),
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_hit", count),
            &hit,
            |bencher, short_id| bencher.iter(|| hashed.get(short_id).copied()),
        );
        group.bench_with_input(
            BenchmarkId::new("sorted_hit", count),
            &hit,
            |bencher, short_id| bencher.iter(|| sorted_owner(&bindings, short_id)),
        );
        group.bench_with_input(
            BenchmarkId::new("constant_time_miss", count),
            &miss,
            |bencher, short_id| bencher.iter(|| constant_time_owner(&bindings, short_id)),
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_miss", count),
            &miss,
            |bencher, short_id| bencher.iter(|| hashed.get(short_id).copied()),
        );
        group.bench_with_input(
            BenchmarkId::new("sorted_miss", count),
            &miss,
            |bencher, short_id| bencher.iter(|| sorted_owner(&bindings, short_id)),
        );
    }
    group.finish();
}

fn sorted_owner(bindings: &[([u8; 8], [u8; 16])], candidate: &[u8; 8]) -> Option<[u8; 16]> {
    bindings
        .binary_search_by_key(candidate, |(short_id, _)| *short_id)
        .ok()
        .map(|index| bindings[index].1)
}

fn constant_time_owner(bindings: &[([u8; 8], [u8; 16])], candidate: &[u8; 8]) -> Option<[u8; 16]> {
    let mut matched = Choice::from(0);
    let mut owner = [0_u8; 16];
    for (short_id, user_id) in bindings {
        let current = short_id.ct_eq(candidate);
        for (selected, byte) in owner.iter_mut().zip(user_id) {
            *selected = u8::conditional_select(selected, byte, current);
        }
        matched |= current;
    }
    bool::from(matched).then_some(owner)
}

fn short_id(index: usize) -> [u8; 8] {
    (u64::try_from(index).expect("benchmark cardinality fits u64") + 1).to_be_bytes()
}

fn user_id(index: usize) -> [u8; 16] {
    (u128::try_from(index).expect("benchmark cardinality fits u128") + 1).to_be_bytes()
}

criterion_group!(benches, short_id_lookup);
criterion_main!(benches);
