//! Prints exactly what this host permits, so a captured test log records the
//! measured capability rather than an assumption.
//!
//! The test never asserts availability: an environment without eBPF privileges
//! is a valid environment, and reporting a skipped gate as a pass is explicitly
//! forbidden.

use rr_linux::{Budget, sockhash};

const BUDGET: Budget = Budget {
    max_relays: 64,
    buffer_bytes: 32 * 1024,
    max_shards: 2,
    queue_depth: 64,
};

#[test]
fn reports_measured_kernel_capability() {
    let sockhash = sockhash::probe(BUDGET);

    println!("kernel: {}", kernel_release());
    println!("{sockhash}");
    for (operation, probe) in sockhash.operations() {
        println!("  sockhash.{operation}: {probe}");
    }

    // The only assertion is that an unavailable backend always names a fixed,
    // low-cardinality reason instead of failing silently.
    if !sockhash.is_available() {
        assert!(sockhash.overall().reason().is_some());
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|release| release.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}
