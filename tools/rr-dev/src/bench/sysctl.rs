//! Global kernel limits a benchmark has to raise, and put back.
//!
//! The matrix runs nine proxy processes at once, and both implementations relay
//! through pipes. At concurrency 32 the peak pipe-page demand is far above the
//! default `fs.pipe-user-pages-soft`, and a run that hits the limit does not fail
//! cleanly — it degrades into a slower relay path and reports the degradation as a
//! measurement. So the limit is raised for the run.
//!
//! This is host-global state owned by the user, not by the process, so it is
//! handled the way §9 of the plan requires:
//!
//! * the original value is read and retained **before** anything is changed;
//! * it is raised only when the computed budget actually exceeds it;
//! * it is restored on every path, including panics, by [`Drop`];
//! * [`PipePagesGuard::verify_restored`] re-reads the sysctl afterwards and
//!   asserts equality with the original, so a write that silently failed is
//!   caught here rather than left for the next user of the machine.
//!
//! The budget itself is [`crate::checks::pipe_budget`], which already owns the
//! formula and is pinned against the numbers the shell computed.

use std::path::Path;

use crate::process::Tool;

/// The sysctl this guard owns.
pub const PIPE_PAGES_SOFT: &str = "fs.pipe-user-pages-soft";

/// The `procfs` path behind it.
const PIPE_PAGES_PATH: &str = "/proc/sys/fs/pipe-user-pages-soft";

/// A raised `fs.pipe-user-pages-soft`, restored on drop.
#[derive(Debug)]
pub struct PipePagesGuard {
    original: u64,
    raised: bool,
}

/// Reads the current value of the pipe-page soft limit.
///
/// # Errors
///
/// Returns a message when the sysctl cannot be read or parsed.
pub fn read_pipe_pages_soft() -> Result<u64, String> {
    let raw = std::fs::read_to_string(PIPE_PAGES_PATH)
        .map_err(|error| format!("could not read {PIPE_PAGES_PATH}: {error}"))?;
    raw.trim()
        .parse::<u64>()
        .map_err(|error| format!("{PIPE_PAGES_PATH} is not an integer: {error}"))
}

/// Writes the pipe-page soft limit through `sudo sysctl`.
fn write_pipe_pages_soft(value: u64) -> Result<(), String> {
    let outcome = Tool::new("sudo")
        .args(["-n", "sysctl", "-q", &format!("{PIPE_PAGES_SOFT}={value}")])
        .probe()
        .map_err(|error| format!("could not set {PIPE_PAGES_SOFT}: {error}"))?;
    if outcome.success() {
        return Ok(());
    }
    Err(format!(
        "setting {PIPE_PAGES_SOFT}={value} exited {:?}: {}",
        outcome.code,
        outcome.stderr.trim_end()
    ))
}

impl PipePagesGuard {
    /// Raises the limit to `required` if the current value is lower.
    ///
    /// Returns a guard even when no change was needed, so the caller's restore and
    /// verify path is the same either way.
    ///
    /// # Errors
    ///
    /// Returns a message when the sysctl cannot be read, or when it needs raising
    /// and the write fails.
    pub fn raise_to(required: u64) -> Result<Self, String> {
        let original = read_pipe_pages_soft()?;
        if original >= required {
            return Ok(Self {
                original,
                raised: false,
            });
        }
        if !Path::new("/usr/sbin/sysctl").is_file() && !Tool::exists("sysctl") {
            return Err("raising the pipe-page budget requires sysctl".to_owned());
        }
        write_pipe_pages_soft(required)?;
        Ok(Self {
            original,
            raised: true,
        })
    }

    /// The value found before the run.
    #[must_use]
    pub const fn original(&self) -> u64 {
        self.original
    }

    /// Whether this guard actually changed the limit.
    #[must_use]
    pub const fn raised(&self) -> bool {
        self.raised
    }

    /// Puts the original value back, best effort.
    fn restore(&mut self) {
        if self.raised {
            let _ = write_pipe_pages_soft(self.original);
            self.raised = false;
        }
    }

    /// Re-reads the sysctl and asserts it matches `original`.
    ///
    /// Restoration is verified rather than assumed: a `sysctl` that reported
    /// success but did not take effect would otherwise leave the machine altered
    /// for whoever uses it next.
    ///
    /// # Errors
    ///
    /// Returns a message naming both values when they differ.
    pub fn verify_restored(original: u64) -> Result<(), String> {
        let observed = read_pipe_pages_soft()?;
        if observed == original {
            return Ok(());
        }
        Err(format!(
            "{PIPE_PAGES_SOFT} was not restored: found {observed}, expected {original}"
        ))
    }
}

impl Drop for PipePagesGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_limit_is_readable() {
        let value = read_pipe_pages_soft().expect("Linux exposes the pipe-page soft limit");
        assert!(value > 0, "a zero soft limit would block every pipe");
    }

    /// Asking for a limit the host already meets must not touch the sysctl at all.
    /// This is the arm that runs without privilege, so it is the one that proves
    /// the guard does not raise gratuitously.
    #[test]
    fn a_sufficient_limit_is_left_alone() {
        let original = read_pipe_pages_soft().unwrap();
        let guard = PipePagesGuard::raise_to(original).expect("no change is needed");
        assert!(!guard.raised(), "the limit already met the requirement");
        assert_eq!(guard.original(), original);
        drop(guard);
        PipePagesGuard::verify_restored(original).expect("nothing was changed");
    }

    #[test]
    fn restoration_verification_reports_a_mismatch() {
        let original = read_pipe_pages_soft().unwrap();
        let error = PipePagesGuard::verify_restored(original + 1).unwrap_err();
        assert!(error.contains("was not restored"), "{error}");
    }

    /// The budget the matrix needs comes from the shared formula, so the guard and
    /// the check cannot drift apart.
    #[test]
    fn the_required_budget_comes_from_the_shared_formula() {
        let budget = crate::checks::pipe_budget::compute(4096, 32);
        assert_eq!(budget.required, 344_064);
        // The default Debian limit is far below what concurrency 32 needs, which
        // is why the guard exists.
        assert!(budget.required > 16_384);
    }
}
