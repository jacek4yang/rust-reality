//! The NXR authenticated request encode: what a line node builds once per
//! flow before it reaches a landing node.
//!
//! This case moved out of the production binary's own `benchmark` command,
//! which is gone: performance measurement is an engineering task, and the
//! deployed daemon is not the project's engineering toolbox. Everything the
//! command measured is covered here or in `vless_decode`/`vision`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::protocol::{
    nxr::{MAX_REQUEST_LEN, NxrKey, encode_request},
    vless::{Address, Destination},
};

/// A fixed instant, so the measurement never varies with the wall clock.
const FIXED_UNIX_SECONDS: u64 = 1_785_761_600;

fn nxr_request_benchmarks(criterion: &mut Criterion) {
    let key = NxrKey::new([0x33; 32]);
    let mut output = Vec::with_capacity(MAX_REQUEST_LEN);

    let mut group = criterion.benchmark_group("nxr/encode_request");

    for (name, destination) in [
        (
            "domain",
            Destination::new(Address::Domain("example.com".to_owned()), 443),
        ),
        (
            // The longest domain the wire format accepts, which is also the
            // longest authenticated payload this encode ever has to cover.
            "maximum_domain",
            Destination::new(Address::Domain("a".repeat(253)), 443),
        ),
        (
            "ipv4",
            Destination::new(Address::Ipv4(std::net::Ipv4Addr::new(203, 0, 113, 10)), 443),
        ),
    ] {
        // The throughput is the destination the request authenticates, which
        // is what varies between the cases.
        group.throughput(Throughput::Bytes(match destination.address() {
            Address::Domain(domain) => domain.len() as u64,
            Address::Ipv4(_) => 4,
            Address::Ipv6(_) => 16,
        }));
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                encode_request(
                    black_box(&destination),
                    black_box(FIXED_UNIX_SECONDS),
                    black_box([0x44; 16]),
                    &key,
                    &mut output,
                )
                .expect("benchmark request must encode");

                black_box(output.as_slice());
            })
        });
    }

    group.finish();
}

criterion_group!(benches, nxr_request_benchmarks);
criterion_main!(benches);
