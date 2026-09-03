//! Server CPU attribution read from `/proc/<pid>/task/*/schedstat`.
//!
//! The `perf` attribution mode is the harness's authority for CPU per
//! connection, and it needs a `perf` binary and — because
//! `perf_event_paranoid` is 3 on the measurement host — `sudo`. Both are
//! host properties rather than properties of the thing being measured, and one
//! of them is not satisfiable everywhere: a host can be entirely representative
//! of production hardware and still have no `linux-tools` package at all, which
//! is exactly the situation issue #219 records.
//!
//! The first field of `/proc/<pid>/task/<tid>/schedstat` is the scheduler's
//! `se.sum_exec_runtime` for that thread, in nanoseconds. It is maintained by
//! ordinary CFS accounting rather than by the `CONFIG_SCHEDSTATS` statistics
//! (which govern the second and third fields), needs no privilege, no `perf`,
//! and no kernel policy change, and it is the same quantity `perf stat`'s
//! `task-clock` reports.
//!
//! This mode is deliberately **not** a replacement for `perf`. `perf` also
//! carries `instructions` and `context-switches`, which this cannot, and it
//! remains the mode a cross-host claim should be made in. What this adds is the
//! ability to produce the primary acceptance metric on a host where `perf` is
//! unavailable, so that the profiling tier and the representative-hardware tier
//! do not have to be the same machine.
//!
//! ## Why the reading is per-thread
//!
//! `/proc/<pid>/schedstat` reports the group leader's runtime alone, not the
//! process's. A Tokio multi-threaded runtime would have most of its work
//! silently omitted. Every thread under `/proc/<pid>/task` is therefore read
//! and summed.
//!
//! ## What can go wrong, and what is done about it
//!
//! A thread that exits inside the measurement window takes its remaining
//! runtime with it, which would understate CPU. That is not detectable after
//! the fact, so it is *bounded* instead: a thread that vanished ran for at most
//! the wall duration of the window, so the total unattributed time is at most
//! the wall window times the number of vanished threads. The measurement is
//! refused when that bound is a material fraction of what was measured, and the
//! bound is recorded either way so a reader never has to assume it was zero.

use std::{collections::BTreeMap, fs, path::PathBuf};

use crate::perf::json_out::Json;

/// The widest unattributed fraction a sample may carry and still be accepted.
///
/// A measurement whose own error bound approaches the effect sizes this
/// repository accepts is not evidence. One percent sits an order of magnitude
/// below the smallest A/B result the setup-rate suite has ever accepted.
const MAX_UNATTRIBUTED_FRACTION: f64 = 0.01;

/// Every thread's accumulated CPU time at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSnapshot {
    /// Thread id to `se.sum_exec_runtime` in nanoseconds.
    threads: BTreeMap<u32, u128>,
}

impl CpuSnapshot {
    /// Reads every thread of `pid`.
    ///
    /// # Errors
    ///
    /// Returns an error when the process has no readable task directory, when a
    /// `schedstat` file cannot be parsed, or when the process has no threads —
    /// each of which would otherwise produce a zero that reads like a result.
    pub fn capture(pid: u32) -> Result<Self, String> {
        let root = PathBuf::from(format!("/proc/{pid}/task"));
        let entries = fs::read_dir(&root)
            .map_err(|error| format!("could not list {}: {error}", root.display()))?;
        let mut threads = BTreeMap::new();
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("could not read {}: {error}", root.display()))?;
            let name = entry.file_name();
            let Some(tid) = name.to_str().and_then(|raw| raw.parse::<u32>().ok()) else {
                continue;
            };
            let path = entry.path().join("schedstat");
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                // The thread exited between listing the directory and reading
                // it. It is absent from this snapshot, which the delta below
                // then accounts for explicitly.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("could not read {}: {error}", path.display())),
            };
            threads.insert(tid, parse_runtime(&raw, &path)?);
        }
        if threads.is_empty() {
            return Err(format!("process {pid} reported no readable threads"));
        }
        Ok(Self { threads })
    }

    /// Total CPU nanoseconds accumulated by every thread in this snapshot.
    #[must_use]
    pub fn total_nanoseconds(&self) -> u128 {
        self.threads.values().sum()
    }

    /// How many threads this snapshot covers.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }
}

/// Parses `sum_exec_runtime` — the first whitespace-separated field.
fn parse_runtime(raw: &str, path: &std::path::Path) -> Result<u128, String> {
    raw.split_whitespace()
        .next()
        .ok_or_else(|| format!("{} was empty", path.display()))?
        .parse::<u128>()
        .map_err(|error| format!("{} did not start with a runtime: {error}", path.display()))
}

/// The CPU a process consumed between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuDelta {
    nanoseconds: u128,
    wall_nanoseconds: u128,
    threads_before: usize,
    threads_after: usize,
    threads_started: usize,
    threads_exited: usize,
    unattributed_bound_nanoseconds: u128,
}

impl CpuDelta {
    /// CPU consumed, in milliseconds, matching `perf stat`'s `task-clock` unit.
    #[must_use]
    pub fn milliseconds(&self) -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a benchmark window is far below the 2^53 nanoseconds f64 represents exactly"
        )]
        {
            self.nanoseconds as f64 / 1_000_000.0
        }
    }

    /// The durable record, in the shape the slot evidence stores.
    ///
    /// Counts and nanosecond totals are integers, so they are written as
    /// integers; only the millisecond figure is derived and floating.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("source", Json::string("/proc/<pid>/task/*/schedstat")),
            ("cpuMilliseconds", Json::Float(self.milliseconds())),
            ("cpuNanoseconds", nanoseconds(self.nanoseconds)),
            ("wallNanoseconds", nanoseconds(self.wall_nanoseconds)),
            ("threadsBefore", count(self.threads_before)),
            ("threadsAfter", count(self.threads_after)),
            ("threadsStartedDuringWindow", count(self.threads_started)),
            ("threadsExitedDuringWindow", count(self.threads_exited)),
            (
                "unattributedBoundNanoseconds",
                nanoseconds(self.unattributed_bound_nanoseconds),
            ),
        ])
    }
}

/// Renders a nanosecond total, saturating rather than wrapping.
///
/// A benchmark window is nine orders of magnitude below `i64::MAX` nanoseconds,
/// so the saturation is unreachable; it exists so the conversion has no
/// undefined edge rather than because the edge is expected.
fn nanoseconds(value: u128) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Renders a thread count.
fn count(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Computes the CPU consumed between two snapshots of the same process.
///
/// `wall_nanoseconds` is the wall duration of the measurement window, which
/// bounds how much runtime a thread that exited inside it could have hidden.
///
/// # Errors
///
/// Fails closed rather than returning a number that quietly understates CPU:
/// on a thread whose runtime moved backwards (which would mean the pid was
/// reused), on a non-positive total, and on an unattributed bound wide enough
/// to matter against the measured total.
pub fn delta(
    before: &CpuSnapshot,
    after: &CpuSnapshot,
    wall_nanoseconds: u128,
) -> Result<CpuDelta, String> {
    let mut total: u128 = 0;
    let mut exited = 0_usize;
    for (tid, start) in &before.threads {
        match after.threads.get(tid) {
            Some(end) if end >= start => total += end - start,
            Some(_) => {
                return Err(format!(
                    "thread {tid} reported less CPU than before the window; \
                     the pid was reused and this sample cannot be trusted"
                ));
            }
            None => exited += 1,
        }
    }
    // A thread the window started contributes everything it ran, because all of
    // that happened inside the window.
    let mut started = 0_usize;
    for (tid, end) in &after.threads {
        if !before.threads.contains_key(tid) {
            started += 1;
            total += end;
        }
    }

    let bound = wall_nanoseconds.saturating_mul(exited as u128);
    if total == 0 {
        return Err("the measured window consumed no CPU at all".to_owned());
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a benchmark window is far below the 2^53 nanoseconds f64 represents exactly"
    )]
    let fraction = bound as f64 / total as f64;
    if fraction > MAX_UNATTRIBUTED_FRACTION {
        return Err(format!(
            "{exited} thread(s) exited during the window, leaving up to {bound} ns \
             ({:.2}%) of CPU unattributed against {total} ns measured; \
             the limit is {:.2}%",
            fraction * 100.0,
            MAX_UNATTRIBUTED_FRACTION * 100.0
        ));
    }

    Ok(CpuDelta {
        nanoseconds: total,
        wall_nanoseconds,
        threads_before: before.threads.len(),
        threads_after: after.threads.len(),
        threads_started: started,
        threads_exited: exited,
        unattributed_bound_nanoseconds: bound,
    })
}

#[cfg(test)]
mod tests {
    use super::{CpuSnapshot, delta};
    use std::collections::BTreeMap;

    fn snapshot(threads: &[(u32, u128)]) -> CpuSnapshot {
        let mut map = BTreeMap::new();
        for (tid, ns) in threads {
            map.insert(*tid, *ns);
        }
        CpuSnapshot { threads: map }
    }

    #[test]
    fn a_busy_child_process_reports_the_cpu_it_actually_burned() {
        if !crate::process::Tool::exists("sh") {
            return;
        }
        // Measured on a *separate* process, which is how the mode is used and
        // which this test binary is not: `cargo test` runs hundreds of tests on
        // a churning thread pool, and a sibling thread exiting inside the
        // window is exactly what `delta` refuses.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "while :; do :; done"])
            .spawn()
            .expect("start a busy child");
        let pid = child.id();
        // Let the shell finish exec'ing before the first sample.
        std::thread::sleep(std::time::Duration::from_millis(150));

        let before = CpuSnapshot::capture(pid).expect("a live child is readable");
        assert!(
            before.thread_count() >= 1,
            "a running process has at least one thread"
        );
        let started = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let after = CpuSnapshot::capture(pid).expect("the child is still readable");
        let elapsed = started.elapsed();

        let _ = child.kill();
        let _ = child.wait();

        let measured = delta(&before, &after, elapsed.as_nanos()).expect("a live child yields CPU");
        assert_eq!(measured.threads_exited, 0, "a busy shell keeps its thread");
        assert_eq!(measured.unattributed_bound_nanoseconds, 0);

        // What this test uniquely proves is that `/proc` parsing works against
        // a real process and that its runtime advances. It must not assert a
        // share of a CPU: on an oversubscribed machine — which is what CI is —
        // a spinning child gets whatever the scheduler spares, and an earlier
        // version of this assertion failed at 100.8ms against a 101.6ms floor
        // for exactly that reason. The exact arithmetic of summing, units and
        // bounds is pinned by the table-driven tests above, which do not
        // depend on the scheduler at all.
        let window_ms = elapsed.as_secs_f64() * 1000.0;
        assert!(
            measured.milliseconds() > 5.0,
            "a spinning child must register real CPU, got {:.1}ms over {window_ms:.1}ms",
            measured.milliseconds()
        );
        // A single-threaded child cannot consume more CPU than the window it
        // ran in, so anything far above it would mean the sum double-counts.
        assert!(
            measured.milliseconds() < window_ms * 1.5,
            "a single-threaded child cannot burn {:.1}ms of CPU in {window_ms:.1}ms",
            measured.milliseconds()
        );
    }

    #[test]
    fn the_current_process_is_readable_and_reports_its_threads() {
        let snapshot = CpuSnapshot::capture(std::process::id()).expect("self is readable");
        assert!(
            snapshot.thread_count() >= 1,
            "a running process has at least one thread"
        );
        assert!(
            snapshot.total_nanoseconds() > 0,
            "a process that reached this line has consumed CPU"
        );
    }

    #[test]
    fn a_missing_process_is_an_error_rather_than_a_zero() {
        // The kernel's maximum pid is far below this, so it cannot exist.
        let error = CpuSnapshot::capture(u32::MAX).expect_err("no such process");
        assert!(error.contains("could not list"), "{error}");
    }

    #[test]
    fn every_thread_is_summed_not_only_the_leader() {
        let before = snapshot(&[(1, 100), (2, 200), (3, 300)]);
        let after = snapshot(&[(1, 150), (2, 260), (3, 370)]);
        let measured = delta(&before, &after, 1_000_000).expect("all threads present");
        assert_eq!(measured.nanoseconds, 50 + 60 + 70);
        assert_eq!(measured.threads_before, 3);
        assert_eq!(measured.threads_after, 3);
    }

    #[test]
    fn a_thread_started_inside_the_window_contributes_all_of_its_runtime() {
        let before = snapshot(&[(1, 100)]);
        let after = snapshot(&[(1, 150), (9, 400)]);
        let measured = delta(&before, &after, 1_000_000).expect("a started thread is attributable");
        assert_eq!(measured.nanoseconds, 50 + 400);
        assert_eq!(measured.threads_started, 1);
        assert_eq!(measured.unattributed_bound_nanoseconds, 0);
    }

    #[test]
    fn a_thread_that_exits_is_bounded_and_tolerated_when_the_bound_is_small() {
        let before = snapshot(&[(1, 0), (2, 0)]);
        let after = snapshot(&[(1, 1_000_000_000)]);
        let measured = delta(&before, &after, 5_000_000).expect("a 0.5% bound is acceptable");
        assert_eq!(measured.threads_exited, 1);
        assert_eq!(measured.unattributed_bound_nanoseconds, 5_000_000);
    }

    #[test]
    fn a_thread_that_exits_is_refused_when_the_bound_could_matter() {
        let before = snapshot(&[(1, 0), (2, 0)]);
        let after = snapshot(&[(1, 1_000_000)]);
        let error = delta(&before, &after, 5_000_000).expect_err("a 500% bound is not evidence");
        assert!(error.contains("unattributed"), "{error}");
        assert!(error.contains("1 thread(s) exited"), "{error}");
    }

    #[test]
    fn a_backwards_runtime_is_refused_rather_than_wrapped() {
        let before = snapshot(&[(1, 500)]);
        let after = snapshot(&[(1, 100)]);
        let error = delta(&before, &after, 1_000_000).expect_err("pid reuse must fail closed");
        assert!(error.contains("pid was reused"), "{error}");
    }

    #[test]
    fn an_idle_window_is_refused_rather_than_reported_as_zero_cpu() {
        let before = snapshot(&[(1, 100)]);
        let after = snapshot(&[(1, 100)]);
        let error = delta(&before, &after, 1_000_000).expect_err("zero CPU is not a measurement");
        assert!(error.contains("no CPU at all"), "{error}");
    }

    #[test]
    fn the_record_states_the_unattributed_bound_it_accepted() {
        let before = snapshot(&[(1, 0), (2, 0)]);
        let after = snapshot(&[(1, 1_000_000_000)]);
        let json = delta(&before, &after, 5_000_000)
            .expect("acceptable")
            .to_json()
            .to_python_json();
        assert!(
            json.contains("\"unattributedBoundNanoseconds\": 5000000"),
            "{json}"
        );
        assert!(json.contains("\"threadsExitedDuringWindow\": 1"), "{json}");
        assert!(json.contains("\"cpuMilliseconds\": 1000.0"), "{json}");
    }
}
