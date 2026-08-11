use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const CARDINALITIES: &[usize] = &[1, 4, 16, 64, 256];

fn tag_lookup(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("tag/lookup");
    group.sample_size(200);
    group.noise_threshold(0.02);

    for &count in CARDINALITIES {
        let entries = (0..count)
            .map(|index| (format!("outbound-{index:04}"), index))
            .collect::<Vec<_>>();
        let sorted: Box<[(String, usize)]> = entries.clone().into_boxed_slice();
        let hashed: HashMap<_, _> = entries.into_iter().collect();
        let hit = format!("outbound-{:04}", count / 2);
        let miss = "outbound-missing";

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("sorted_hit", count),
            &hit,
            |bencher, tag| {
                bencher.iter(|| {
                    sorted
                        .binary_search_by(|(candidate, _)| candidate.as_str().cmp(tag))
                        .ok()
                        .map(|index| &sorted[index].1)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_hit", count),
            &hit,
            |bencher, tag| bencher.iter(|| hashed.get(tag)),
        );
        group.bench_with_input(
            BenchmarkId::new("sorted_miss", count),
            &miss,
            |bencher, tag| {
                bencher.iter(|| {
                    sorted
                        .binary_search_by(|(candidate, _)| candidate.as_str().cmp(tag))
                        .ok()
                        .map(|index| &sorted[index].1)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("siphash_miss", count),
            &miss,
            |bencher, tag| bencher.iter(|| hashed.get(*tag)),
        );
    }
    group.finish();
}

criterion_group!(benches, tag_lookup);
criterion_main!(benches);
