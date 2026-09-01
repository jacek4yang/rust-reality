//! Machine and cgroup detection for the dedicated resource mode.
//!
//! # Why this module exists
//!
//! `standard` resource mode derives every budget from the inherited process
//! limits and assumes nothing about the host. `dedicated` mode declares that
//! this process owns the machine — or, under a container runtime, its
//! cgroup — so the budgets must be derived from what the machine actually
//! has: the descriptor limits, the cgroup v2 CPU and memory boundaries, and
//! the kernel's view of total memory. Everything here is detected once at
//! startup, reported in one structured log event, and never re-polled on any
//! request path.
//!
//! Nothing in this module changes anything outside the calling process. The
//! only mutation anywhere in the dedicated startup path is raising the
//! process's own soft `RLIMIT_NOFILE` up to its hard limit, which requires
//! no privilege and touches no sysctl, no cgroup file and no other process.

use std::path::{Path, PathBuf};

use super::pressure::ResourcePressure;

/// One detected view of the machine this process runs on.
///
/// Every field is a machine- or process-wide quantity. None can carry a
/// target, a peer or a configuration value, which is what makes the report
/// safe to log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineReport {
    /// Measured soft `RLIMIT_NOFILE`, before any dedicated-mode raise.
    pub fd_soft_limit: u64,
    /// Measured hard `RLIMIT_NOFILE`.
    pub fd_hard_limit: u64,
    /// Measured soft `RLIMIT_MEMLOCK`.
    pub memlock_soft_limit: u64,
    /// Measured hard `RLIMIT_MEMLOCK`.
    pub memlock_hard_limit: u64,
    /// Logical CPUs visible to the process.
    pub available_cpus: usize,
    /// The cgroup v2 `cpu.max` quota in microseconds, when set.
    pub cpu_quota_us: Option<u64>,
    /// The cgroup v2 `cpu.max` period in microseconds, when detected.
    pub cpu_period_us: Option<u64>,
    /// The cgroup v2 `cpuset.cpus.effective` list, when detected.
    pub cpuset_effective: Option<String>,
    /// Where the memory quantities come from: `cgroup_v2`, `proc_meminfo`
    /// or `unavailable`.
    pub memory_source: &'static str,
    /// Cgroup v2 `memory.current`, when detected.
    pub memory_current: Option<u64>,
    /// Cgroup v2 `memory.high`, when set to a finite value.
    pub memory_high: Option<u64>,
    /// Cgroup v2 `memory.max`, when set to a finite value.
    pub memory_max: Option<u64>,
    /// The effective memory total used for budget derivation: the cgroup
    /// limit when one is set, otherwise the kernel `MemTotal`.
    pub memory_total: u64,
}

/// The cgroup v2 files of the current process, already parsed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CgroupReading {
    cpu_quota_us: Option<u64>,
    cpu_period_us: Option<u64>,
    cpuset_effective: Option<String>,
    memory_current: Option<u64>,
    memory_high: Option<u64>,
    memory_max: Option<u64>,
}

impl MachineReport {
    /// Detects the machine view of the current process.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::conservative()
        }
    }

    /// The conservative view for a platform that cannot report limits.
    ///
    /// Matches the descriptor-limit fallback: an unobservable machine is
    /// treated as small, never as abundant. `memory_total` of zero disables
    /// the memory dimension rather than inventing a number.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            fd_soft_limit: 1_024,
            fd_hard_limit: 1_024,
            memlock_soft_limit: 0,
            memlock_hard_limit: 0,
            available_cpus: 1,
            cpu_quota_us: None,
            cpu_period_us: None,
            cpuset_effective: None,
            memory_source: "unavailable",
            memory_current: None,
            memory_high: None,
            memory_max: None,
            memory_total: 0,
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux() -> Self {
        let fd = rr_linux::descriptor_limit();
        let fd = Some((fd.soft, fd.hard));
        let memlock = rr_linux::memlock_limit();
        let memlock = Some((memlock.soft, memlock.hard));
        let meminfo_total = read_meminfo_total(Path::new("/proc/meminfo"));
        let cgroup = read_cgroup_v2(Path::new("/proc/self/cgroup"), Path::new("/sys/fs/cgroup"));
        Self::assemble(
            fd,
            memlock,
            meminfo_total,
            cgroup,
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
        )
    }

    /// Combines the raw readings into one report. Pure, so tests can feed
    /// synthetic values without touching the host.
    fn assemble(
        fd: Option<(u64, u64)>,
        memlock: Option<(u64, u64)>,
        meminfo_total: Option<u64>,
        cgroup: Option<CgroupReading>,
        available_cpus: usize,
    ) -> Self {
        let conservative = Self::conservative();
        let (memory_source, memory_total) = match (&cgroup, meminfo_total) {
            (Some(reading), _) => (
                "cgroup_v2",
                effective_memory_total(reading.memory_max, meminfo_total),
            ),
            (None, Some(total)) => ("proc_meminfo", total),
            (None, None) => ("unavailable", 0),
        };
        Self {
            fd_soft_limit: fd.map_or(conservative.fd_soft_limit, |limit| limit.0),
            fd_hard_limit: fd.map_or(conservative.fd_hard_limit, |limit| limit.1),
            memlock_soft_limit: memlock.map_or(0, |limit| limit.0),
            memlock_hard_limit: memlock.map_or(0, |limit| limit.1),
            available_cpus,
            cpu_quota_us: cgroup.as_ref().and_then(|reading| reading.cpu_quota_us),
            cpu_period_us: cgroup.as_ref().and_then(|reading| reading.cpu_period_us),
            cpuset_effective: cgroup
                .as_ref()
                .and_then(|reading| reading.cpuset_effective.clone()),
            memory_source,
            memory_current: cgroup.as_ref().and_then(|reading| reading.memory_current),
            memory_high: cgroup.as_ref().and_then(|reading| reading.memory_high),
            memory_max: cgroup.as_ref().and_then(|reading| reading.memory_max),
            memory_total,
        }
    }

    /// Returns the CPU count after applying a finite cgroup CPU quota.
    ///
    /// A quota of `q` microseconds per `p`-microsecond period allows
    /// `ceil(q / p)` CPUs, never fewer than one and never more than the
    /// affinity-visible count. An absent quota or a zero period leaves the
    /// visible count untouched, so an unobservable boundary never shrinks
    /// the plan.
    #[must_use]
    pub fn effective_cpus(&self) -> usize {
        let quota = self
            .cpu_quota_us
            .zip(self.cpu_period_us)
            .filter(|(_, period)| *period > 0)
            .map(|(quota, period)| quota.saturating_add(period - 1) / period)
            .and_then(|count| usize::try_from(count).ok());
        quota.map_or(self.available_cpus, |count| {
            self.available_cpus.min(count.max(1))
        })
    }

    /// Returns whether the single-tenancy boundary is fully observable.
    ///
    /// "Tenancy" here means the process is dedicated to its *cgroup* — the
    /// boundary the dedicated-mode derivation budgets against — not that it
    /// is the only tenant of the host; sibling cgroups may share the
    /// machine. True only when the process sits in a cgroup v2 with both a
    /// finite `cpu.max` quota and a finite `memory.max` — the two boundaries
    /// a dedicated-mode derivation budgets against. Bare metal, an unbounded
    /// quota (`max`), and unreadable files all count as unobservable, so
    /// `auto` profile resolution never guesses dedicated without evidence.
    #[must_use]
    pub const fn tenancy_boundary_observable(&self) -> bool {
        self.cpu_quota_us.is_some() && self.memory_max.is_some()
    }

    /// Returns the memory sampler the pressure monitor should run.
    ///
    /// The cgroup file is preferred because it measures exactly what the
    /// cgroup OOM killer measures; the resident set size is the fallback for
    /// hosts where the cgroup files are absent or unreadable.
    #[must_use]
    pub fn memory_sampler(&self) -> MemorySampler {
        #[cfg(target_os = "linux")]
        if self.memory_source == "cgroup_v2"
            && let Some(path) =
                cgroup_directory(Path::new("/proc/self/cgroup"), Path::new("/sys/fs/cgroup"))
        {
            return MemorySampler::CgroupV2(path.join("memory.current"));
        }
        MemorySampler::ResidentSet
    }
}

/// Returns the descriptor soft limit a dedicated process should raise to, or
/// `None` when the soft limit already equals the hard limit.
///
/// The target is the hard limit; the raise itself clamps to it. This is the
/// only process-limit decision the dedicated mode makes, and it is a pure
/// function so the policy is testable without touching a real limit.
#[must_use]
pub const fn soft_limit_raise_target(soft: u64, hard: u64) -> Option<u64> {
    if hard > soft { Some(hard) } else { None }
}

/// The memory total to plan against: the finite cgroup limit when one is
/// set, capped by the machine total when that is known.
fn effective_memory_total(cgroup_max: Option<u64>, meminfo_total: Option<u64>) -> u64 {
    match (cgroup_max, meminfo_total) {
        (Some(max), Some(total)) => max.min(total),
        (Some(max), None) => max,
        (None, Some(total)) => total,
        (None, None) => 0,
    }
}

/// Locates the cgroup v2 directory of the current process.
fn cgroup_directory(proc_cgroup: &Path, cgroup_root: &Path) -> Option<PathBuf> {
    let contents = std::fs::read_to_string(proc_cgroup).ok()?;
    let relative = contents.lines().find_map(|line| line.strip_prefix("0::"))?;
    let directory = cgroup_root.join(relative.trim_start_matches('/'));
    directory.is_dir().then_some(directory)
}

/// Reads the cgroup v2 resource files of the current process.
///
/// Any file that is absent or unreadable degrades to `None` rather than to a
/// fabricated value; the whole cgroup degrades to `None` when the process is
/// not in a cgroup v2 hierarchy at all.
fn read_cgroup_v2(proc_cgroup: &Path, cgroup_root: &Path) -> Option<CgroupReading> {
    let directory = cgroup_directory(proc_cgroup, cgroup_root)?;
    let read = |name: &str| std::fs::read_to_string(directory.join(name)).ok();
    let cpu_max = read("cpu.max");
    let (cpu_quota_us, cpu_period_us) = cpu_max
        .as_deref()
        .map(parse_cpu_max)
        .unwrap_or((None, None));
    Some(CgroupReading {
        cpu_quota_us,
        cpu_period_us,
        cpuset_effective: read("cpuset.cpus.effective")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        memory_current: read("memory.current").and_then(|value| value.trim().parse().ok()),
        memory_high: read("memory.high").and_then(|value| parse_cgroup_limit(&value)),
        memory_max: read("memory.max").and_then(|value| parse_cgroup_limit(&value)),
    })
}

/// Parses `cpu.max`: `"<quota> <period>"`, where quota may be `max`.
fn parse_cpu_max(contents: &str) -> (Option<u64>, Option<u64>) {
    let mut fields = contents.split_whitespace();
    let quota = match fields.next() {
        Some("max") => None,
        Some(value) => value.parse().ok(),
        None => None,
    };
    let period = fields.next().and_then(|value| value.parse().ok());
    (quota, period)
}

/// Parses a cgroup limit file whose value may be the literal `max`.
fn parse_cgroup_limit(contents: &str) -> Option<u64> {
    let trimmed = contents.trim();
    if trimmed == "max" {
        None
    } else {
        trimmed.parse().ok()
    }
}

/// Reads `MemTotal` in bytes from a meminfo file, or `None` when unreadable.
fn read_meminfo_total(meminfo: &Path) -> Option<u64> {
    let contents = std::fs::read_to_string(meminfo).ok()?;
    parse_meminfo_total(&contents)
}

/// Parses `MemTotal` (reported in kibibytes) from meminfo contents.
fn parse_meminfo_total(contents: &str) -> Option<u64> {
    let kibibytes = contents.lines().find_map(|line| {
        line.strip_prefix("MemTotal:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })?;
    Some(kibibytes.saturating_mul(1_024))
}

/// A bounded memory-usage signal for the pressure monitor.
///
/// Sampling happens in the monitor task on a fixed interval, never in a
/// read, write or record path.
#[derive(Clone, Debug)]
pub enum MemorySampler {
    /// Reads one cgroup v2 `memory.current` file.
    CgroupV2(PathBuf),
    /// Reads the process resident set size from `/proc/self/statm`.
    ResidentSet,
}

/// The measurement source a sample actually came from.
///
/// Reported alongside every reading so a fallback can never masquerade as the
/// configured source: a process RSS reading is never labelled `cgroup_v2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemorySampleSource {
    /// Read from cgroup v2 `memory.current`.
    CgroupV2,
    /// Read from `/proc/self/statm` resident set size.
    ResidentSet,
}

impl MemorySampleSource {
    /// Returns the stable identifier for structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupV2 => "cgroup_v2",
            Self::ResidentSet => "resident_set",
        }
    }
}

/// One memory reading and the source it actually came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemorySample {
    /// Usage in bytes.
    pub bytes: u64,
    /// The source that produced the reading.
    pub source: MemorySampleSource,
}

impl MemorySampler {
    /// Returns the current usage and its actual source, or `None` when
    /// unreadable.
    ///
    /// A cgroup sampler that cannot read its file falls back to the resident
    /// set size rather than freezing the pressure state at a stale value:
    /// process RSS measures a different quantity than cgroup `memory.current`
    /// (no page cache or kernel memory), but a live degraded signal beats a
    /// silently frozen one. Only when both reads fail does `None` keep the
    /// previous pressure state — a monitoring gap must never itself trigger
    /// or clear an alarm.
    #[must_use]
    pub fn sample(&self) -> Option<MemorySample> {
        match self {
            Self::CgroupV2(path) => std::fs::read_to_string(path)
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .map(|bytes| MemorySample {
                    bytes,
                    source: MemorySampleSource::CgroupV2,
                })
                .or_else(|| {
                    resident_set_size().map(|bytes| MemorySample {
                        bytes,
                        source: MemorySampleSource::ResidentSet,
                    })
                }),
            Self::ResidentSet => resident_set_size().map(|bytes| MemorySample {
                bytes,
                source: MemorySampleSource::ResidentSet,
            }),
        }
    }

    /// Returns the configured (pre-fallback) source of this sampler.
    #[must_use]
    pub const fn configured_source(&self) -> MemorySampleSource {
        match self {
            Self::CgroupV2(_) => MemorySampleSource::CgroupV2,
            Self::ResidentSet => MemorySampleSource::ResidentSet,
        }
    }
}

#[cfg(target_os = "linux")]
fn resident_set_size() -> Option<u64> {
    rr_linux::resident_set_bytes().ok()
}

#[cfg(not(target_os = "linux"))]
const fn resident_set_size() -> Option<u64> {
    None
}

/// A derived memory budget with hysteresis watermarks.
///
/// # Exact fractions
///
/// All watermarks are fractions of the effective memory total (the cgroup
/// `memory.max` when set, else the kernel `MemTotal`):
///
/// * **usable = 80%** — one fifth is held back for the kernel, socket
///   buffers and the runtime itself, none of which the process can account
///   per allocation;
/// * **pressure enter = 60%** — three quarters of the usable budget;
/// * **pressure exit = 50%** — a ten-point gap, so releases do not
///   re-enter pressure on the next sample;
/// * **critical enter = 90%** — below the hard cgroup/machine limit, early
///   enough that refusing new work can still move the number;
/// * **critical exit = 80%** — exactly the usable budget: the process
///   resumes new work only once it is back inside its own allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPlan {
    total: u64,
    usable: u64,
    pressure_enter: u64,
    pressure_exit: u64,
    critical_enter: u64,
    critical_exit: u64,
}

impl MemoryPlan {
    /// Derives the memory budget from an effective memory total.
    ///
    /// Returns `None` when the total is unknown (zero), which disables the
    /// memory dimension rather than inventing watermarks from nothing.
    #[must_use]
    pub fn derive(total: u64) -> Option<Self> {
        if total == 0 {
            return None;
        }
        // Divide before multiplying so a huge total cannot overflow.
        let usable = total / 5 * 4;
        Some(Self {
            total,
            usable,
            pressure_enter: usable / 4 * 3,
            pressure_exit: total / 2,
            critical_enter: total / 10 * 9,
            critical_exit: usable,
        })
    }

    /// Returns the effective memory total the plan was derived from.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns the process's own memory allowance (80% of the total).
    #[must_use]
    pub const fn usable(&self) -> u64 {
        self.usable
    }

    /// Returns the usage at which memory pressure is entered (60% of total).
    #[must_use]
    pub const fn pressure_enter(&self) -> u64 {
        self.pressure_enter
    }

    /// Returns the usage at which memory pressure is left (50% of total).
    #[must_use]
    pub const fn pressure_exit(&self) -> u64 {
        self.pressure_exit
    }

    /// Returns the usage at which the critical state is entered (90% of total).
    #[must_use]
    pub const fn critical_enter(&self) -> u64 {
        self.critical_enter
    }

    /// Returns the usage at which the critical state is left (80% of total).
    #[must_use]
    pub const fn critical_exit(&self) -> u64 {
        self.critical_exit
    }

    /// Advances the memory pressure state for one new sample.
    ///
    /// Each tier has a separate enter and exit watermark, so a usage value
    /// oscillating around any single threshold produces no transitions.
    #[must_use]
    pub fn classify(&self, current: ResourcePressure, usage: u64) -> ResourcePressure {
        match current {
            ResourcePressure::Normal if usage >= self.pressure_enter => ResourcePressure::Pressure,
            ResourcePressure::Normal => ResourcePressure::Normal,
            ResourcePressure::Pressure if usage >= self.critical_enter => {
                ResourcePressure::Critical
            }
            ResourcePressure::Pressure if usage <= self.pressure_exit => ResourcePressure::Normal,
            ResourcePressure::Pressure => ResourcePressure::Pressure,
            ResourcePressure::Critical if usage <= self.critical_exit => ResourcePressure::Pressure,
            ResourcePressure::Critical => ResourcePressure::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MachineReport, MemoryPlan, ResourcePressure, effective_memory_total, parse_cgroup_limit,
        parse_cpu_max, parse_meminfo_total, soft_limit_raise_target,
    };

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreadable_cgroup_sample_falls_back_to_resident_set_size() {
        let sampler = super::MemorySampler::CgroupV2(std::path::PathBuf::from(
            "/nonexistent/rust-reality/memory.current",
        ));
        let sample = sampler.sample();
        assert!(
            sample.is_some_and(|reading| {
                reading.bytes > 0 && reading.source == super::MemorySampleSource::ResidentSet
            }),
            "a missing cgroup file must fall back to a live RSS sample, got {sample:?}"
        );
    }

    #[test]
    fn effective_cpus_apply_a_finite_cgroup_quota() {
        let mut report = MachineReport::conservative();
        report.available_cpus = 16;
        report.cpu_quota_us = Some(250_000);
        report.cpu_period_us = Some(100_000);
        assert_eq!(report.effective_cpus(), 3, "the quota rounds up");

        report.cpu_quota_us = Some(50_000);
        assert_eq!(
            report.effective_cpus(),
            1,
            "a sub-CPU quota still leaves one CPU"
        );

        report.cpu_quota_us = Some(1_600_000);
        assert_eq!(
            report.effective_cpus(),
            16,
            "a quota above the visible count never inflates it"
        );
    }

    #[test]
    fn effective_cpus_ignore_an_unusable_quota() {
        let mut report = MachineReport::conservative();
        report.available_cpus = 8;
        assert_eq!(report.effective_cpus(), 8, "no quota detected");

        report.cpu_quota_us = Some(200_000);
        assert_eq!(
            report.effective_cpus(),
            8,
            "a quota without a period is unusable"
        );

        report.cpu_period_us = Some(0);
        assert_eq!(
            report.effective_cpus(),
            8,
            "a zero period cannot divide and is ignored"
        );
    }

    #[test]
    fn the_raise_target_is_the_hard_limit_only_when_it_is_higher() {
        assert_eq!(soft_limit_raise_target(1_024, 1_048_576), Some(1_048_576));
        assert_eq!(soft_limit_raise_target(1_048_576, 1_048_576), None);
        assert_eq!(
            soft_limit_raise_target(65_536, u64::MAX),
            Some(u64::MAX),
            "an unlimited hard limit is still a valid raise target"
        );
        assert_eq!(soft_limit_raise_target(2_048, 1_024), None);
    }

    #[test]
    fn cgroup_limits_treat_max_as_unbounded() {
        assert_eq!(parse_cgroup_limit("max\n"), None);
        assert_eq!(parse_cgroup_limit("2147483648\n"), Some(2_147_483_648));
        assert_eq!(parse_cgroup_limit("garbage"), None);
    }

    #[test]
    fn cpu_max_parses_quota_and_period() {
        assert_eq!(
            parse_cpu_max("200000 100000"),
            (Some(200_000), Some(100_000))
        );
        assert_eq!(parse_cpu_max("max 100000"), (None, Some(100_000)));
        assert_eq!(parse_cpu_max("garbage"), (None, None));
    }

    #[test]
    fn meminfo_total_is_reported_in_bytes() {
        let contents = "MemTotal:       16384000 kB\nMemFree:         1024000 kB\n";
        assert_eq!(parse_meminfo_total(contents), Some(16_384_000 * 1_024));
        assert_eq!(parse_meminfo_total("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn the_effective_total_prefers_the_tighter_boundary() {
        assert_eq!(effective_memory_total(Some(1_000), Some(4_000)), 1_000);
        assert_eq!(effective_memory_total(Some(8_000), Some(4_000)), 4_000);
        assert_eq!(effective_memory_total(None, Some(4_000)), 4_000);
        assert_eq!(effective_memory_total(Some(8_000), None), 8_000);
        assert_eq!(effective_memory_total(None, None), 0);
    }

    #[test]
    fn the_memory_plan_uses_the_documented_fractions() {
        let plan = MemoryPlan::derive(1_000_000).expect("a known total must produce a plan");
        assert_eq!(plan.usable(), 800_000);
        assert_eq!(plan.pressure_enter(), 600_000);
        assert_eq!(plan.pressure_exit(), 500_000);
        assert_eq!(plan.critical_enter(), 900_000);
        assert_eq!(plan.critical_exit(), 800_000);
        assert!(MemoryPlan::derive(0).is_none());
    }

    #[test]
    fn the_memory_plan_watermarks_are_strictly_ordered() {
        for total in [1_u64, 64, 1_000, 1 << 20, 1 << 30, u64::MAX / 2] {
            let Some(plan) = MemoryPlan::derive(total) else {
                continue;
            };
            assert!(plan.pressure_exit() <= plan.pressure_enter());
            assert!(plan.pressure_enter() <= plan.critical_exit());
            assert!(plan.critical_exit() <= plan.critical_enter());
            assert!(plan.critical_enter() <= plan.total());
        }
    }

    #[test]
    fn memory_hysteresis_does_not_flap_around_any_threshold() {
        let plan = MemoryPlan::derive(1_000_000).expect("a known total must produce a plan");

        let mut state = ResourcePressure::Normal;
        state = plan.classify(state, 599_999);
        assert_eq!(state, ResourcePressure::Normal);
        state = plan.classify(state, 600_000);
        assert_eq!(state, ResourcePressure::Pressure);

        // Hovering exactly on the enter threshold must not oscillate.
        state = plan.classify(state, 600_000);
        assert_eq!(state, ResourcePressure::Pressure);
        state = plan.classify(state, 550_000);
        assert_eq!(
            state,
            ResourcePressure::Pressure,
            "the exit watermark is 50%, not the 60% enter point"
        );
        state = plan.classify(state, 500_000);
        assert_eq!(state, ResourcePressure::Normal);

        state = plan.classify(state, 900_000);
        assert_eq!(
            state,
            ResourcePressure::Pressure,
            "escalation also advances one tier per sample"
        );
        state = plan.classify(state, 900_000);
        assert_eq!(state, ResourcePressure::Critical);
        state = plan.classify(state, 850_000);
        assert_eq!(
            state,
            ResourcePressure::Critical,
            "critical holds until usage returns inside the usable budget"
        );
        state = plan.classify(state, 800_000);
        assert_eq!(state, ResourcePressure::Pressure);
    }

    #[test]
    fn memory_transitions_never_skip_a_tier_downward() {
        let plan = MemoryPlan::derive(1_000_000).expect("a known total must produce a plan");
        let state = plan.classify(ResourcePressure::Critical, 0);
        assert_eq!(
            state,
            ResourcePressure::Pressure,
            "recovery de-escalates one tier per sample, never straight to normal"
        );
    }

    #[test]
    fn a_conservative_report_disables_the_memory_dimension() {
        let report = MachineReport::conservative();
        assert_eq!(report.memory_total, 0);
        assert!(MemoryPlan::derive(report.memory_total).is_none());
    }

    #[test]
    fn cgroup_detection_reads_synthetic_files() {
        let root = test_directory("cgroup");
        let cgroup_dir = root.join("sys/fs/cgroup/machine.slice/rust-reality.service");
        std::fs::create_dir_all(&cgroup_dir).expect("cgroup directory must be created");
        std::fs::write(cgroup_dir.join("cpu.max"), "200000 100000\n").expect("cpu.max");
        std::fs::write(cgroup_dir.join("cpuset.cpus.effective"), "0-3\n").expect("cpuset");
        std::fs::write(cgroup_dir.join("memory.current"), "1048576\n").expect("memory.current");
        std::fs::write(cgroup_dir.join("memory.high"), "max\n").expect("memory.high");
        std::fs::write(cgroup_dir.join("memory.max"), "2147483648\n").expect("memory.max");
        let proc_cgroup = root.join("proc/self/cgroup");
        std::fs::create_dir_all(proc_cgroup.parent().expect("parent exists"))
            .expect("proc directory must be created");
        std::fs::write(&proc_cgroup, "0::/machine.slice/rust-reality.service\n")
            .expect("proc cgroup");

        let reading = super::read_cgroup_v2(&proc_cgroup, &root.join("sys/fs/cgroup"))
            .expect("a v2 cgroup must be detected");
        assert_eq!(reading.cpu_quota_us, Some(200_000));
        assert_eq!(reading.cpu_period_us, Some(100_000));
        assert_eq!(reading.cpuset_effective.as_deref(), Some("0-3"));
        assert_eq!(reading.memory_current, Some(1_048_576));
        assert_eq!(reading.memory_high, None, "max is unbounded");
        assert_eq!(reading.memory_max, Some(2_147_483_648));
        cleanup(&root);
    }

    #[test]
    fn cgroup_detection_degrades_when_the_hierarchy_is_absent() {
        let root = test_directory("no-cgroup");
        let proc_cgroup = root.join("proc/self/cgroup");
        std::fs::create_dir_all(proc_cgroup.parent().expect("parent exists"))
            .expect("proc directory must be created");
        std::fs::write(&proc_cgroup, "1:name=systemd:/\n0::/\n").expect("proc cgroup");

        assert!(
            super::read_cgroup_v2(&proc_cgroup, &root.join("sys/fs/cgroup")).is_none(),
            "a missing cgroup directory must not fabricate readings"
        );
        cleanup(&root);
    }

    #[test]
    fn assembly_combines_readings_without_touching_the_host() {
        let cgroup = super::CgroupReading {
            cpu_quota_us: Some(400_000),
            cpu_period_us: Some(100_000),
            cpuset_effective: Some("0-7".to_owned()),
            memory_current: Some(65_536),
            memory_high: None,
            memory_max: Some(8_000_000),
        };
        let report = MachineReport::assemble(
            Some((1_024, 1_048_576)),
            Some((8_388_608, 8_388_608)),
            Some(16_000_000),
            Some(cgroup),
            8,
        );
        assert_eq!(report.fd_soft_limit, 1_024);
        assert_eq!(report.fd_hard_limit, 1_048_576);
        assert_eq!(report.memlock_soft_limit, 8_388_608);
        assert_eq!(report.available_cpus, 8);
        assert_eq!(report.cpu_quota_us, Some(400_000));
        assert_eq!(report.cpuset_effective.as_deref(), Some("0-7"));
        assert_eq!(report.memory_source, "cgroup_v2");
        assert_eq!(report.memory_total, 8_000_000, "the cgroup cap is tighter");
        assert_eq!(report.memory_current, Some(65_536));

        let fallback = MachineReport::assemble(None, None, Some(16_000_000), None, 2);
        assert_eq!(
            fallback.fd_soft_limit, 1_024,
            "unreadable limits stay conservative"
        );
        assert_eq!(fallback.memory_source, "proc_meminfo");
        assert_eq!(fallback.memory_total, 16_000_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_detection_produces_a_coherent_report() {
        let report = MachineReport::detect();
        assert!(report.fd_soft_limit > 0);
        assert!(
            report.fd_soft_limit <= report.fd_hard_limit,
            "a soft limit above the hard limit would make every derived budget unsound"
        );
        assert!(report.available_cpus > 0);
        match report.memory_source {
            "cgroup_v2" | "proc_meminfo" => assert!(report.memory_total > 0),
            "unavailable" => assert_eq!(report.memory_total, 0),
            other => panic!("unexpected memory source {other}"),
        }
    }

    fn test_directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rust-reality-machine-test-{name}-{}",
            std::process::id()
        ));
        let _ignored = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("unique test directory must be created");
        path
    }

    fn cleanup(directory: &std::path::Path) {
        std::fs::remove_dir_all(directory).expect("test directory must be removed");
    }
}
