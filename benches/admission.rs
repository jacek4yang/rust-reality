use std::{
    sync::{Arc, Barrier, Mutex},
    time::Instant,
};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::{config::DirectBarrierConfig, runtime::DirectBarrier};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CONTENDED_WORKERS: usize = 4;

fn admission_benchmarks(criterion: &mut Criterion) {
    let direct = barrier();
    let legacy = LegacyBarrier::new();
    let mut group = criterion.benchmark_group("admission/direct_barrier");
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_thread", |bencher| {
        bencher.iter(|| {
            let permit = direct
                .try_acquire()
                .expect("unbounded benchmark barrier must admit");
            std::hint::black_box(permit);
        });
    });
    group.bench_function("legacy_mutex_single_thread", |bencher| {
        bencher.iter(|| {
            let permit = legacy.acquire();
            std::hint::black_box(permit);
        });
    });
    group.bench_function("contended_4_threads", |bencher| {
        bencher.iter_custom(|iterations| contended_batch(iterations, CONTENDED_WORKERS, barrier()));
    });
    group.bench_function("legacy_mutex_contended_4_threads", |bencher| {
        bencher.iter_custom(|iterations| {
            contended_batch(iterations, CONTENDED_WORKERS, LegacyBarrier::new())
        });
    });
    group.finish();
}

trait BenchBarrier: Clone + Send + Sync + 'static {
    type Permit;

    fn acquire(&self) -> Self::Permit;
}

impl BenchBarrier for DirectBarrier {
    type Permit = rust_reality::runtime::DirectPermit;

    fn acquire(&self) -> Self::Permit {
        self.try_acquire()
            .expect("unbounded benchmark barrier must admit")
    }
}

fn contended_batch<B: BenchBarrier>(
    iterations: u64,
    workers: usize,
    barrier: B,
) -> std::time::Duration {
    let start_gate = Arc::new(Barrier::new(workers + 1));
    let handles: Vec<_> = (0..workers)
        .map(|worker| {
            let barrier = barrier.clone();
            let start_gate = Arc::clone(&start_gate);
            let iterations = iterations / workers as u64
                + u64::from((worker as u64) < iterations % workers as u64);
            std::thread::spawn(move || {
                start_gate.wait();
                for _ in 0..iterations {
                    let permit = barrier.acquire();
                    std::hint::black_box(permit);
                }
            })
        })
        .collect();
    start_gate.wait();
    let started = Instant::now();
    for handle in handles {
        handle.join().expect("admission benchmark worker must join");
    }
    started.elapsed()
}

fn barrier() -> DirectBarrier {
    DirectBarrier::new(&DirectBarrierConfig {
        max_concurrent: u32::MAX,
        max_per_second: u32::MAX,
    })
}

#[derive(Clone)]
struct LegacyBarrier {
    inner: Arc<LegacyBarrierInner>,
}

struct LegacyBarrierInner {
    concurrency: Arc<Semaphore>,
    rate: Mutex<LegacyTokenBucket>,
}

struct LegacyPermit {
    _permit: OwnedSemaphorePermit,
}

impl LegacyBarrier {
    fn new() -> Self {
        Self {
            inner: Arc::new(LegacyBarrierInner {
                concurrency: Arc::new(Semaphore::new(u32::MAX as usize)),
                rate: Mutex::new(LegacyTokenBucket::new(u32::MAX)),
            }),
        }
    }
}

impl BenchBarrier for LegacyBarrier {
    type Permit = LegacyPermit;

    fn acquire(&self) -> Self::Permit {
        let permit = Arc::clone(&self.inner.concurrency)
            .try_acquire_owned()
            .expect("unbounded legacy benchmark semaphore must admit");
        assert!(
            self.inner
                .rate
                .lock()
                .expect("legacy benchmark mutex must remain available")
                .try_take(),
            "unbounded legacy benchmark bucket must admit"
        );
        LegacyPermit { _permit: permit }
    }
}

struct LegacyTokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    updated: Instant,
}

impl LegacyTokenBucket {
    fn new(max_per_second: u32) -> Self {
        let capacity = f64::from(max_per_second);
        Self {
            tokens: capacity,
            capacity,
            refill_per_second: capacity,
            updated: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

criterion_group!(benches, admission_benchmarks);
criterion_main!(benches);
