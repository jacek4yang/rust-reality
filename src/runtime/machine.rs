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
        // `getrlimit` on the calling process cannot fail, so on Linux these are
        // always present; `assemble` keeps taking an option because the
        // platforms that cannot report a limit, and its tests, still need one.
        let fd = rr_linux::descriptor_limit();
        let memlock = rr_linux::memlock_limit();
        let meminfo_total = read_meminfo_total(Path::new("/proc/meminfo"));
        let cgroup = read_cgroup_v2(Path::new("/proc/self/cgroup"), Path::new("/sys/fs/cgroup"));
        Self::assemble(
            Some((fd.soft, fd.hard)),
            Some((memlock.soft, memlock.hard)),
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
mod tests;
