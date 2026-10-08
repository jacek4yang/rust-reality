//! An in-process cost report for the control plane.
//!
//! Ignored by default: it is a measurement, not a correctness test, and its
//! numbers depend on the host. Run it on one host and one build profile:
//!
//! ```text
//! cargo test --release --lib -- --ignored --nocapture control_plane_cost_report
//! ```
//!
//! It prints one JSON object. It compares, on the same process and
//! configuration, the publication paths a control change can take (no-op,
//! identity-only, full compile), the paged read path, and — as a proxy for the
//! accept path, which is the only data-plane code that touches what the
//! control plane publishes — the latency of the per-connection generation
//! lookup with the control plane idle, under sustained reads, and under
//! mutation churn. It does not drive proxy traffic; the benchmark harness
//! (`cargo dev bench`) owns throughput and connection-latency evidence.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::execute_blocking;
use crate::{
    config::{MAX_CONFIG_BYTES, NodeConfig, node::UserConfig},
    control::{Operation, protocol::PageArgs},
    server::production::{
        ProductionServer,
        fixture::{entry_config, unused_loopback_port},
        snapshot::GenerationOrigin,
        store::RuntimeStore,
    },
};

const USERS: usize = 5_000;
const MAX_CONFIG_USERS: usize = 40_000;
const MAX_PAGE_ENTRIES: usize = 1_000;
const PUBLICATIONS: usize = 20;
const READS: usize = 200;
const PROBE: Duration = Duration::from_millis(1_500);

fn many_users(port: u16, users: usize) -> NodeConfig {
    let mut node = entry_config(port).into_node();
    if let NodeConfig::Entry(entry) = &mut node {
        let template = entry.users[0].clone();
        for index in 1..users {
            entry.users.push(UserConfig {
                id: format!("{index:08x}-0000-4000-8000-{index:012x}"),
                short_ids: vec![format!("{:016x}", index + 0x1000)],
                label: Some(format!("user-{index}")),
                enabled: None,
                ..template.clone()
            });
        }
    }
    node
}

fn summary(mut samples: Vec<Duration>) -> Value {
    samples.sort_unstable();
    let at = |quantile: f64| {
        let index = ((samples.len() as f64 - 1.0) * quantile).round() as usize;
        samples[index].as_secs_f64() * 1e6
    };
    json!({
        "samples": samples.len(),
        "p50Us": at(0.5),
        "p99Us": at(0.99),
        "maxUs": at(1.0),
    })
}

fn time(mut operation: impl FnMut()) -> Duration {
    let started = Instant::now();
    operation();
    started.elapsed()
}

fn allocations(operation: impl FnOnce()) -> Value {
    let measured = allocation_counter::measure(operation);
    json!({
        "count": measured.count_total,
        "bytes": measured.bytes_total,
        "peakBytes": measured.bytes_max,
    })
}

fn toggle(store: &RuntimeStore, user: usize, enabled: bool) {
    store
        .publish_derived(GenerationOrigin::Control, None, |current| {
            let mut node = current.node.clone();
            if let NodeConfig::Entry(entry) = &mut node {
                entry.users[user].enabled = (!enabled).then_some(false);
            }
            Ok::<_, crate::server::production::RuntimeUpdateError>((node, ()))
        })
        .expect("an identity change publishes");
}

fn read_page(store: &RuntimeStore) {
    std::hint::black_box(read_page_with_limit(store, 100));
}

fn read_page_with_limit(store: &RuntimeStore, limit: usize) -> Value {
    let (_, result) = execute_blocking(
        store,
        None,
        Operation::UsersList(PageArgs {
            cursor: None,
            limit: Some(limit),
        }),
        None,
    )
    .expect("a page reads");
    result
}

/// Per-lookup latency of what an accept does with a generation: load the
/// current snapshot and find the listener's runtime.
fn probe_accept_path(store: &RuntimeStore, address: SocketAddr) -> Value {
    let mut samples = Vec::with_capacity(1 << 20);
    let started = Instant::now();
    while started.elapsed() < PROBE {
        let begin = Instant::now();
        let snapshot = store.load();
        std::hint::black_box(snapshot.connections.get(&address));
        drop(snapshot);
        samples.push(begin.elapsed());
    }
    let lookups = samples.len();
    let mut value = summary(samples);
    value["lookupsPerSecond"] = json!(lookups as f64 / PROBE.as_secs_f64());
    value
}

#[test]
#[ignore = "measurement; run explicitly with --release --ignored --nocapture"]
fn control_plane_cost_report() {
    let port = unused_loopback_port();
    let server = ProductionServer::from_config(entry_config(port)).expect("server");
    let store = Arc::clone(&server.runtime);
    store
        .publish(many_users(port, USERS))
        .expect("many users publish");
    let address = *store.load().connections.keys().next().expect("a listener");

    let full = (0..PUBLICATIONS)
        .map(|_| {
            time(|| {
                store.refresh().expect("full compile");
            })
        })
        .collect();
    let identity = (0..PUBLICATIONS)
        .map(|round| time(|| toggle(&store, 1 + round, round % 2 == 1)))
        .collect();
    let no_op = (0..PUBLICATIONS)
        .map(|_| {
            time(|| {
                store
                    .publish_derived(GenerationOrigin::Control, None, |current| {
                        Ok::<_, crate::server::production::RuntimeUpdateError>((
                            current.node.clone(),
                            (),
                        ))
                    })
                    .expect("no-op");
            })
        })
        .collect();

    // A fresh generation: the first read derives every handle.
    toggle(&store, 1, false);
    let first_read = time(|| read_page(&store));
    let reads = (0..READS).map(|_| time(|| read_page(&store))).collect();

    let allocation = json!({
        "fullCompile": allocations(|| { store.refresh().expect("full"); }),
        "identityOnly": allocations(|| toggle(&store, 2, false)),
        "pageReadSteady": allocations(|| read_page(&store)),
    });

    let large_port = unused_loopback_port();
    let large_server =
        ProductionServer::from_config(entry_config(large_port)).expect("large server");
    let large_store = Arc::clone(&large_server.runtime);
    large_store
        .publish(many_users(large_port, MAX_CONFIG_USERS))
        .expect("near-maximum user config publishes");
    let config_bytes = serde_json::to_vec(&large_store.load().node)
        .expect("large config serializes")
        .len();
    assert!(config_bytes <= MAX_CONFIG_BYTES);
    assert!(config_bytes >= MAX_CONFIG_BYTES * 9 / 10);
    let large_first_page = time(|| {
        std::hint::black_box(read_page_with_limit(&large_store, MAX_PAGE_ENTRIES));
    });
    let large_reads = (0..READS)
        .map(|_| {
            time(|| {
                std::hint::black_box(read_page_with_limit(&large_store, MAX_PAGE_ENTRIES));
            })
        })
        .collect();
    let large_page = read_page_with_limit(&large_store, MAX_PAGE_ENTRIES);
    let large_page_bytes = serde_json::to_vec(&large_page)
        .expect("page serializes")
        .len();
    let large_page_allocation = allocations(|| {
        std::hint::black_box(read_page_with_limit(&large_store, MAX_PAGE_ENTRIES));
    });

    let idle = probe_accept_path(&store, address);
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut done = 0_u64;
                while !stop.load(Ordering::Relaxed) {
                    read_page(&store);
                    done += 1;
                }
                done
            })
        })
        .collect();
    let under_reads = probe_accept_path(&store, address);
    stop.store(true, Ordering::Relaxed);
    let page_reads: u64 = readers
        .into_iter()
        .map(|reader| reader.join().expect("reader"))
        .sum();

    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut done = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                toggle(&store, 3, done % 2 == 1);
                done += 1;
            }
            done
        })
    };
    let under_churn = probe_accept_path(&store, address);
    stop.store(true, Ordering::Relaxed);
    let publications = churn.join().expect("churn");

    let report = json!({
        "users": USERS,
        "publication": {
            "fullCompile": summary(full),
            "identityOnly": summary(identity),
            "noOp": summary(no_op),
        },
        "read": {
            "firstPageUs": first_read.as_secs_f64() * 1e6,
            "steadyPage": summary(reads),
            "nearMaximumConfig": {
                "users": MAX_CONFIG_USERS,
                "configBytes": config_bytes,
                "pageEntries": MAX_PAGE_ENTRIES,
                "pageResponseBytes": large_page_bytes,
                "firstPageUs": large_first_page.as_secs_f64() * 1e6,
                "steadyPage": summary(large_reads),
                "steadyPageAllocations": large_page_allocation,
            },
        },
        "allocations": allocation,
        "acceptPathLookup": {
            "idle": idle,
            "sustainedReads": { "probe": under_reads, "pagesRead": page_reads },
            "mutationChurn": { "probe": under_churn, "publications": publications },
        },
    });
    println!("{report}");
}
