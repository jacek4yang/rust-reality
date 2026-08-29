//! The shared benchmark run lifecycle.
//!
//! This is the single owner of the plan → run → evidence flow that the legacy
//! `benchmark-*.sh` scripts each re-implemented. The concrete measurement suites
//! (matrix, tls-shape, dns, routing, …) land on top of this core as suite
//! definitions rather than separate orchestration engines.
//!
//! At this stage the core provides the lifecycle primitives and an environment
//! preflight that every suite depends on; the suite catalogue is declared so the
//! surface and migration order are visible and testable.

use crate::{
    bench::{host_lock::HostLock, process::Child, workspace::Workspace},
    process::Tool,
};

/// A benchmark suite the runner knows how to describe.
///
/// A suite is a configuration/domain variation over the one shared lifecycle, not
/// a separate engine. Each entry names the legacy script it supersedes so the
/// migration is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    /// Stable suite id used on the command line.
    pub id: &'static str,
    /// One-line description of what the suite measures.
    pub summary: &'static str,
    /// The legacy script this suite supersedes.
    pub supersedes: &'static str,
}

/// The catalogue of benchmark suites, in migration order.
pub const SUITES: [Suite; 16] = [
    Suite {
        id: "real-path",
        summary: "real-network A/B download through rust-reality and Xray tunnels",
        supersedes: "benchmark-real-path.sh",
    },
    Suite {
        id: "matrix",
        summary: "the protected-metric performance matrix across concurrency and policy",
        supersedes: "benchmark-matrix.sh",
    },
    Suite {
        id: "setup-rate",
        summary: "connection setup rate and CPU per connection",
        supersedes: "benchmark-setup-rate.sh",
    },
    Suite {
        id: "setup-rate-xray",
        summary: "setup rate with Xray serving one leg",
        supersedes: "benchmark-setup-rate-xray.sh",
    },
    Suite {
        id: "tls-shape",
        summary: "TLS record and closure shape versus a pinned Xray ClientHello",
        supersedes: "benchmark-tls-shape.sh",
    },
    Suite {
        id: "dns",
        summary: "DNS cold/warm/burst resolution versus Xray",
        supersedes: "benchmark-dns-comparison.sh",
    },
    Suite {
        id: "routing",
        summary: "routing-rule scaling versus Xray",
        supersedes: "benchmark-routing-comparison.sh",
    },
    Suite {
        id: "fallback",
        summary: "fallback A/B behaviour under cover",
        supersedes: "benchmark-fallback-ab.sh",
    },
    Suite {
        id: "vision-direct",
        summary: "Vision direct-copy datapath",
        supersedes: "benchmark-vision-direct.sh",
    },
    Suite {
        id: "vless-encryption",
        summary: "VLESS encryption datapath",
        supersedes: "benchmark-vless-encryption.sh",
    },
    Suite {
        id: "xray",
        summary: "Xray comparator baseline",
        supersedes: "benchmark-xray.sh",
    },
    Suite {
        id: "soak",
        summary: "long-duration soak with resource sampling",
        supersedes: "soak-test.sh",
    },
    Suite {
        id: "xray-interop",
        summary: "unmodified-Xray interoperability and the ML-DSA differential",
        supersedes: "test-xray-interop.sh",
    },
    Suite {
        id: "no-ccs-interop",
        summary: "interoperability with a TLS 1.3 cover that omits the server CCS",
        supersedes: "test-openssl-no-ccs-interop.sh",
    },
    Suite {
        id: "ipv6",
        summary: "IPv4/IPv6 listener, session, transfer and resilience validation",
        supersedes: "validate-ipv6-e2e.sh",
    },
    Suite {
        id: "descriptor-pressure",
        summary: "file-descriptor pressure behaviour",
        supersedes: "test-descriptor-pressure.sh",
    },
];

/// Resolves a suite by id.
///
/// # Errors
///
/// Returns a message naming the unknown suite and the known ids.
pub fn resolve(id: &str) -> Result<&'static Suite, String> {
    SUITES.iter().find(|suite| suite.id == id).ok_or_else(|| {
        let known: Vec<&str> = SUITES.iter().map(|suite| suite.id).collect();
        format!(
            "unknown benchmark suite: {id} (known: {})",
            known.join(", ")
        )
    })
}

/// The default host-exclusive lock path under the runtime root.
#[must_use]
pub fn default_lock_path() -> std::path::PathBuf {
    crate::bench::workspace::runtime_root().join("host-exclusive.lock")
}

/// The outcome of an environment preflight.
#[derive(Debug)]
pub struct Preflight {
    /// Tools found on `PATH`.
    pub present_tools: Vec<String>,
    /// Required tools that were missing.
    pub missing_tools: Vec<String>,
    /// Whether the host-exclusive lock could be acquired and released.
    pub lock_ok: bool,
    /// The lock device:inode attestation, when acquired.
    pub lock_identity: Option<String>,
    /// Whether an ephemeral workspace could be created and removed.
    pub workspace_ok: bool,
    /// Loopback ports reserved during the check.
    pub reserved_ports: usize,
}

impl Preflight {
    /// Whether the environment can run a benchmark.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.missing_tools.is_empty() && self.lock_ok && self.workspace_ok
    }
}

/// Validates the benchmark environment without running a measurement.
///
/// Exercises every lifecycle primitive: tool availability, host-lock
/// acquire/release, an ephemeral workspace, and loopback port reservation. This
/// is the typed preflight the legacy contract performed inline in every script.
#[must_use]
pub fn preflight(required_tools: &[&str]) -> Preflight {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for tool in required_tools {
        if Tool::exists(tool) {
            present.push((*tool).to_owned());
        } else {
            missing.push((*tool).to_owned());
        }
    }

    let lock_path = default_lock_path();
    let (lock_ok, lock_identity) = match HostLock::acquire(&lock_path) {
        Ok(lock) => {
            let identity = lock.device_inode().to_owned();
            drop(lock);
            (true, Some(identity))
        }
        Err(_) => (false, None),
    };

    let (workspace_ok, reserved_ports) = match Workspace::create("preflight") {
        Ok(workspace) => {
            let ports = crate::bench::workspace::reserve_ports(2).map_or(0, |ports| ports.len());
            // Prove the process guard launches and cleans up a child on this host.
            let process_ok = self_check_process(&workspace).is_ok();
            drop(workspace);
            (process_ok, ports)
        }
        Err(_) => (false, 0),
    };

    Preflight {
        present_tools: present,
        missing_tools: missing,
        lock_ok,
        lock_identity,
        workspace_ok,
        reserved_ports,
    }
}

/// The tools every current benchmark suite needs on `PATH`.
pub const COMMON_TOOLS: [&str; 4] = ["curl", "jq", "python3", "sha256sum"];

/// A demonstration that the process guard cleans up: launches a short-lived
/// helper and lets its guard drop. Used by the environment check to prove the
/// process lifecycle works end to end on this host.
///
/// # Errors
///
/// Returns a message if the helper cannot be started.
pub fn self_check_process(workspace: &Workspace) -> Result<(), String> {
    let Some(sleep) = which("sleep") else {
        return Ok(());
    };
    let mut child = Child::spawn(
        "preflight-sleep",
        &sleep,
        &["1".to_owned()],
        workspace.path(),
        &[],
        &workspace.join("preflight-sleep.log"),
    )
    .map_err(|error| error.to_string())?;
    let alive = child.is_alive();
    child.terminate();
    if alive {
        Ok(())
    } else {
        Err("preflight helper did not start".to_owned())
    }
}

fn which(program: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_suite_names_the_script_it_supersedes() {
        for suite in &SUITES {
            assert!(!suite.id.is_empty());
            assert!(suite.supersedes.contains(".sh"), "{}", suite.id);
        }
        let ids: std::collections::BTreeSet<&str> = SUITES.iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), SUITES.len(), "suite ids must be unique");
    }

    #[test]
    fn an_unknown_suite_is_rejected() {
        assert!(resolve("does-not-exist").is_err());
        assert!(resolve("real-path").is_ok());
    }

    #[test]
    fn preflight_reports_missing_tools() {
        let report = preflight(&["definitely-not-a-real-tool-xyz"]);
        assert!(
            report
                .missing_tools
                .iter()
                .any(|t| t.contains("real-tool-xyz"))
        );
        assert!(!report.is_ready(), "a missing tool must block readiness");
    }

    #[test]
    fn preflight_acquires_and_releases_the_host_lock() {
        // With no required tools, readiness depends only on lock + workspace.
        let report = preflight(&[]);
        assert!(report.lock_ok, "the host lock must acquire in preflight");
        assert!(
            report.workspace_ok,
            "the workspace must create in preflight"
        );
        // The lock was released, so a second preflight also succeeds.
        let again = preflight(&[]);
        assert!(
            again.lock_ok,
            "the host lock must be released after preflight"
        );
    }
}
