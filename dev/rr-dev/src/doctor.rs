//! Non-mutating diagnosis of the development and measurement environment.
//!
//! `doctor` answers one question: *what can this host actually do?* It never
//! changes a system setting, installs anything, or asks for elevated privileges.
//!
//! The distinction that motivates this module is between a tool being **absent**
//! and a tool being **present but restricted**. The repository has already been
//! bitten by that difference: `perf` is installed on the benchmark host, yet
//! `perf_event_paranoid = 3` means unprivileged PMU counters are unavailable.
//! Reporting that as "perf missing" would send a future developer to install a
//! package they already have, and reporting it as "perf available" would invite
//! fabricated hardware-counter numbers. Neither is acceptable, so
//! [`Availability::Restricted`] exists as a first-class outcome.

use std::{fmt, fs, path::Path};

use crate::process::{Tool, which};

/// How usable one capability is on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Present and usable.
    Available,
    /// Absent, and something the repository requires.
    MissingRequired,
    /// Absent, but only optional workflows need it.
    MissingOptional,
    /// Present but blocked by policy, permissions or kernel settings.
    Restricted,
    /// Present but the wrong version or wrong platform for this repository.
    Incompatible,
}

impl Availability {
    /// The stable label used in reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "ok",
            Self::MissingRequired => "MISSING",
            Self::MissingOptional => "absent",
            Self::Restricted => "RESTRICTED",
            Self::Incompatible => "INCOMPATIBLE",
        }
    }

    /// Whether this outcome should make `doctor` exit non-zero.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::MissingRequired | Self::Incompatible)
    }
}

/// Whether a capability is needed for ordinary work or only for specialised work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Required to build, test or check the repository.
    Required,
    /// Needed only for benchmarking, profiling, release or deployment work.
    Optional,
}

/// One diagnosed capability.
#[derive(Debug)]
pub struct Finding {
    /// Capability name as a developer would search for it.
    pub name: &'static str,
    /// Whether ordinary work needs it.
    pub need: Need,
    /// What was determined.
    pub availability: Availability,
    /// Version, path or the precise reason for a restriction.
    pub detail: String,
}

impl Need {
    /// The stable label used in reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:<14} {:<9} {:<12} {}",
            self.name,
            self.need.label(),
            self.availability.label(),
            self.detail
        )
    }
}

/// Collects every finding for this host.
#[must_use]
pub fn diagnose() -> Vec<Finding> {
    let mut findings = vec![
        rustc(),
        version_of("cargo", Need::Required, &["--version"]),
        version_of("git", Need::Required, &["--version"]),
        subcommand("cargo-nextest", Need::Required, &["nextest", "--version"]),
        subcommand("cargo-deny", Need::Optional, &["deny", "--version"]),
        subcommand("cargo-audit", Need::Optional, &["audit", "--version"]),
        version_of("gh", Need::Optional, &["--version"]),
        version_of("ssh", Need::Optional, &["-V"]),
        version_of("tc", Need::Optional, &["-Version"]),
        version_of("ip", Need::Optional, &["-Version"]),
        presence("nstat", Need::Optional),
        presence("llvm-objdump", Need::Optional),
        presence("objdump", Need::Optional),
        presence("readelf", Need::Optional),
        presence("musl-gcc", Need::Optional),
        presence("mdbook", Need::Optional),
    ];
    findings.push(perf());
    findings.push(platform());
    findings.push(kernel());
    findings.push(cgroup());
    findings
}

/// The minimum toolchain the repository declares in `Cargo.toml`.
const MINIMUM_RUSTC: (u32, u32) = (1, 96);

/// Diagnoses `rustc`, treating a toolchain older than the declared MSRV as
/// incompatible rather than merely present.
///
/// Reporting "ok" for a toolchain that cannot compile the repository would send a
/// developer into a wall of unrelated compile errors.
fn rustc() -> Finding {
    let base = version_of("rustc", Need::Required, &["--version"]);
    if base.availability != Availability::Available {
        return base;
    }
    let Some(version) = parse_semver(&base.detail) else {
        return base;
    };
    if version < MINIMUM_RUSTC {
        return Finding {
            name: "rustc",
            need: Need::Required,
            availability: Availability::Incompatible,
            detail: format!(
                "{}.{} is older than the required {}.{}",
                version.0, version.1, MINIMUM_RUSTC.0, MINIMUM_RUSTC.1
            ),
        };
    }
    base
}

/// Extracts a leading `major.minor` pair from a version string.
fn parse_semver(text: &str) -> Option<(u32, u32)> {
    let token = text.split_whitespace().find(|word| {
        word.split('.').count() >= 2 && word.starts_with(|c: char| c.is_ascii_digit())
    })?;
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Diagnoses `perf` and, separately, whether unprivileged PMU access is permitted.
///
/// This is the finding that motivated the whole `Availability::Restricted`
/// variant. `perf` being on `PATH` says nothing about whether counters can be
/// read, and the repository's measurement policy forbids estimating hardware
/// counters, so the reason must be reported precisely.
fn perf() -> Finding {
    if which("perf").is_none() {
        return Finding {
            name: "perf",
            need: Need::Optional,
            availability: Availability::MissingOptional,
            detail: "not installed; hardware-counter work is unavailable".to_owned(),
        };
    }
    let paranoid_path = Path::new("/proc/sys/kernel/perf_event_paranoid");
    let paranoid = fs::read_to_string(paranoid_path)
        .ok()
        .and_then(|raw| raw.trim().parse::<i32>().ok());
    match paranoid {
        Some(level) if level <= 2 => Finding {
            name: "perf",
            need: Need::Optional,
            availability: Availability::Available,
            detail: format!("installed, perf_event_paranoid={level} permits unprivileged counters"),
        },
        Some(level) => Finding {
            name: "perf",
            need: Need::Optional,
            availability: Availability::Restricted,
            detail: format!(
                "installed, but perf_event_paranoid={level} blocks unprivileged PMU counters; \
                 record PMU questions as pending rather than estimating them, and do not \
                 lower this setting on a host that also serves production"
            ),
        },
        None => Finding {
            name: "perf",
            need: Need::Optional,
            availability: Availability::Restricted,
            detail: "installed, but perf_event_paranoid is unreadable".to_owned(),
        },
    }
}

/// Reports the host architecture and operating system.
fn platform() -> Finding {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let availability = if os == "linux" {
        Availability::Available
    } else {
        // Production targets Linux. A non-Linux host can still build, check and
        // work on documentation, so this is not fatal on its own; the commands
        // that genuinely need Linux refuse individually.
        Availability::Restricted
    };
    Finding {
        name: "platform",
        need: Need::Required,
        availability,
        detail: if os == "linux" {
            format!("{os}/{arch}")
        } else {
            format!("{os}/{arch}; benchmark, profiling and deployment commands require Linux")
        },
    }
}

/// Reports the running kernel release, which bounds relay-backend availability.
fn kernel() -> Finding {
    let detail = Tool::new("uname")
        .arg("-r")
        .probe()
        .ok()
        .filter(crate::process::Outcome::success)
        .map_or_else(
            || "unknown".to_owned(),
            |outcome| outcome.trimmed_stdout().to_owned(),
        );

    Finding {
        name: "kernel",
        need: Need::Optional,
        availability: Availability::Available,
        detail,
    }
}

/// Reports which cgroup hierarchy is mounted, which affects resource detection.
fn cgroup() -> Finding {
    let unified = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let legacy = Path::new("/sys/fs/cgroup/memory").exists();
    let detail = match (unified, legacy) {
        (true, _) => "v2 (unified)".to_owned(),
        (false, true) => "v1 (legacy)".to_owned(),
        (false, false) => "not mounted".to_owned(),
    };
    Finding {
        name: "cgroup",
        need: Need::Optional,
        availability: if unified || legacy {
            Availability::Available
        } else {
            Availability::MissingOptional
        },
        detail,
    }
}

/// Diagnoses a plain executable by asking it for a version string.
fn version_of(program: &'static str, need: Need, args: &[&str]) -> Finding {
    if which(program).is_none() {
        return Finding {
            name: program,
            need,
            availability: missing(need),
            detail: "not found on PATH".to_owned(),
        };
    }
    let outcome = Tool::new(program).args(args.iter().copied()).probe();
    let detail = match outcome {
        // Some tools, notably `ssh -V` and `tc -Version`, report on stderr.
        Ok(result) => first_line(if result.stdout.trim().is_empty() {
            &result.stderr
        } else {
            &result.stdout
        }),
        Err(error) => format!("present but not runnable: {error}"),
    };
    Finding {
        name: program,
        need,
        availability: Availability::Available,
        detail,
    }
}

/// Diagnoses a cargo subcommand, which cannot be found by `PATH` lookup alone.
fn subcommand(name: &'static str, need: Need, args: &[&str]) -> Finding {
    let outcome = Tool::new("cargo").args(args.iter().copied()).probe();
    match outcome {
        Ok(result) if result.success() => Finding {
            name,
            need,
            availability: Availability::Available,
            detail: first_line(result.trimmed_stdout()),
        },
        Ok(_) | Err(_) => Finding {
            name,
            need,
            availability: missing(need),
            detail: format!("not installed; add it with `cargo install {name}`"),
        },
    }
}

/// Diagnoses a tool for which a version probe adds nothing.
fn presence(program: &'static str, need: Need) -> Finding {
    match which(program) {
        Some(path) => Finding {
            name: program,
            need,
            availability: Availability::Available,
            detail: path.display().to_string(),
        },
        None => Finding {
            name: program,
            need,
            availability: missing(need),
            detail: "not found on PATH".to_owned(),
        },
    }
}

const fn missing(need: Need) -> Availability {
    match need {
        Need::Required => Availability::MissingRequired,
        Need::Optional => Availability::MissingOptional,
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_tools_present_in_this_environment_are_reported_available() {
        let findings = diagnose();
        let rustc = findings
            .iter()
            .find(|finding| finding.name == "rustc")
            .expect("rustc must be diagnosed");
        // These tests only run under cargo, so rustc and cargo must be present.
        assert_eq!(rustc.availability, Availability::Available);
        assert!(
            rustc.detail.contains("rustc"),
            "the detail should carry the version string: {}",
            rustc.detail
        );
    }

    #[test]
    fn every_capability_is_diagnosed_exactly_once() {
        let findings = diagnose();
        let mut names: Vec<&str> = findings.iter().map(|finding| finding.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate finding: {names:?}");
        assert!(
            before >= 15,
            "the diagnosis is unexpectedly small: {before}"
        );
    }

    #[test]
    fn a_restricted_capability_does_not_block_but_a_missing_requirement_does() {
        assert!(!Availability::Restricted.is_blocking());
        assert!(!Availability::MissingOptional.is_blocking());
        assert!(Availability::MissingRequired.is_blocking());
        assert!(Availability::Incompatible.is_blocking());
    }

    #[test]
    fn perf_is_never_reported_as_missing_when_it_is_installed() {
        let finding = perf();
        if which("perf").is_some() {
            assert_ne!(
                finding.availability,
                Availability::MissingOptional,
                "an installed perf must never be reported as absent; \
                 a restricted PMU is a different fact: {}",
                finding.detail
            );
        }
    }

    #[test]
    fn a_version_string_yields_its_major_and_minor() {
        assert_eq!(
            parse_semver("rustc 1.96.0 (ac68faa20 2026-05-25)"),
            Some((1, 96))
        );
        assert_eq!(parse_semver("cargo-deny 0.19.4"), Some((0, 19)));
        assert_eq!(parse_semver("no version here"), None);
    }

    #[test]
    fn the_running_toolchain_satisfies_the_declared_minimum() {
        // These tests are compiled by the toolchain under test, so anything that
        // can run them must already be new enough.
        assert_eq!(rustc().availability, Availability::Available);
    }

    #[test]
    fn a_paranoid_host_reports_the_exact_reason() {
        // Only meaningful where perf exists and the kernel restricts counters.
        let finding = perf();
        if finding.availability == Availability::Restricted
            && finding.detail.contains("perf_event_paranoid=")
        {
            assert!(
                finding.detail.contains("pending"),
                "a restricted PMU must tell the reader what to do instead: {}",
                finding.detail
            );
        }
    }
}
