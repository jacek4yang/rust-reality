//! Native soak integration: fixed startup ownership and scheduled recovery.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    bench::{
        evidence::RunDirectory,
        identity::{self, Binary},
    },
    hash,
};

use super::{
    collect,
    evaluate::{self, Verdict},
    observation,
    schema::{self, Artifact, Policy, Sample},
};

struct Process {
    pid: u32,
    start_ticks: String,
    log: PathBuf,
    baseline: Option<(Policy, Sample)>,
}

/// Owns the native run's immutable startup census, not any product process.
pub struct Qualification<'a> {
    run: &'a RunDirectory,
    processes: BTreeMap<String, Process>,
    receipt: schema::NativeEvidence,
}

impl<'a> Qualification<'a> {
    /// Register already owned processes before any workload is submitted.
    ///
    /// # Errors
    /// Every process must have its own debug log.
    pub fn new(
        run: &'a RunDirectory,
        identities: &[(String, u32, String)],
        logs: &[(&str, &std::path::Path)],
        candidate: &Binary,
        evaluator_sha256: &str,
        duration: Duration,
    ) -> Result<Self, String> {
        let mut processes = BTreeMap::new();
        for (name, pid, start_ticks) in identities {
            let log = logs
                .iter()
                .find(|(label, _)| *label == name)
                .ok_or("missing native process log")?
                .1
                .to_path_buf();
            processes.insert(
                name.clone(),
                Process {
                    pid: *pid,
                    start_ticks: start_ticks.clone(),
                    log,
                    baseline: None,
                },
            );
        }
        Ok(Self {
            run,
            processes,
            receipt: schema::NativeEvidence {
                source_commit: identity::embedded_commit(&candidate.identity)?,
                candidate_sha256: candidate.sha256.clone(),
                evaluator_sha256: evaluator_sha256.to_owned(),
                contract_sha256: hash::sha256_hex(schema::CONTRACT.as_bytes()),
                duration_ms: u64::try_from(duration.as_millis())
                    .map_err(|_| "native duration overflow")?,
                workload_started_unix_ms: None,
                recovery_started_unix_ms: None,
                policies: Vec::new(),
                checkpoints: Vec::new(),
                primary_error: None,
                finalization_errors: Vec::new(),
            },
        })
    }

    /// Fix startup inventory before workload. Allow the one-second diagnostics
    /// cadence and readiness connections to settle on a predetermined delay.
    ///
    /// # Errors
    /// Incomplete observations never establish a passing baseline.
    pub fn begin(&mut self) -> Result<(), String> {
        std::thread::sleep(Duration::from_secs(3));
        self.capture("baseline", false, None)?;
        self.receipt.workload_started_unix_ms = Some(collect::unix_ms()?);
        Ok(())
    }

    /// Observe ownership at the native workload's existing round boundary.
    ///
    /// # Errors
    /// Returns incomplete observations or resource-accounting violations.
    pub fn round(&mut self, round: usize) -> Result<(), String> {
        self.capture(&format!("round-{round}"), false, None)
    }

    /// Collect every recovery checkpoint at its contract-defined offset.
    /// A failed checkpoint does not suppress later raw evidence.
    ///
    /// # Errors
    /// Returns all collection, accounting, envelope or scheduling failures.
    pub fn recover(&mut self) -> Result<(), String> {
        let contract: schema::Contract =
            serde_json::from_str(schema::CONTRACT).expect("compiled contract");
        let started = Instant::now();
        let epoch = collect::unix_ms()?;
        self.receipt.recovery_started_unix_ms = Some(epoch);
        let mut errors = Vec::new();
        for offset in &contract.native_recovery_offsets_ms {
            let deadline = Duration::from_millis(*offset);
            if let Some(delay) = deadline.checked_sub(started.elapsed()) {
                std::thread::sleep(delay);
            }
            let recovered = Some(offset) == contract.native_recovery_offsets_ms.last();
            let window = RecoveryWindow {
                started,
                epoch,
                offset: *offset,
                tolerance: contract.checkpoint_tolerance_ms,
            };
            if let Err(error) = self.capture(&format!("recovery-{offset}"), recovered, Some(window))
            {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Retain one raw observation per registered process even after failure.
    /// This is evidence finalization; it does not replace scheduled checkpoints.
    ///
    /// # Errors
    /// Returns errors only after every registered process has been attempted.
    pub fn finalize(
        &mut self,
        primary_error: Option<&String>,
        finalization: &[(String, Result<(), String>)],
    ) -> Result<(), String> {
        self.receipt.primary_error = primary_error.cloned();
        self.receipt.finalization_errors = finalization
            .iter()
            .filter_map(|(name, result)| {
                result
                    .as_ref()
                    .err()
                    .map(|error| format!("{name}: {error}"))
            })
            .collect();
        let capture = self.capture(
            "terminal",
            primary_error.is_none() && self.receipt.finalization_errors.is_empty(),
            None,
        );
        if let Err(error) = &capture {
            self.receipt.finalization_errors.push(error.clone());
        }
        self.receipt.policies = self
            .processes
            .iter()
            .filter_map(|(role, process)| {
                process
                    .baseline
                    .as_ref()
                    .map(|(policy, _)| schema::NativePolicy {
                        role: role.clone(),
                        policy: policy.clone(),
                    })
            })
            .collect();
        let written = serde_json::to_string(&self.receipt)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                self.run
                    .write_new("native-resources.json", &bytes)
                    .map(|_| ())
            });
        match (capture, written) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(primary), Err(secondary)) => {
                Err(format!("{primary}; native receipt: {secondary}"))
            }
        }
    }

    fn capture(
        &mut self,
        label: &str,
        recovered: bool,
        window: Option<RecoveryWindow>,
    ) -> Result<(), String> {
        let mut errors = Vec::new();
        let mut checkpoint = schema::NativeCheckpoint {
            phase: label.to_owned(),
            started_unix_ms: collect::unix_ms()?,
            observations: Vec::new(),
            samples: Vec::new(),
            errors: Vec::new(),
        };
        // Finish raw collection before serialization, digesting and evaluation.
        // Those operations must not delay another role's observation or count
        // as time spent observing the candidate.
        let collected: Vec<_> = self
            .processes
            .iter()
            .map(|(name, process)| (name.clone(), collect::observe(process.pid, &process.log)))
            .collect();
        if let Some(window) = window {
            match collect::unix_ms() {
                Ok(completed)
                    if window.contains(
                        checkpoint.started_unix_ms,
                        completed,
                        window.started.elapsed(),
                    ) => {}
                Ok(_) => errors.push(format!(
                    "native recovery checkpoint {} exceeded its fixed collection window",
                    window.offset
                )),
                Err(error) => errors.push(error),
            }
        }
        for (name, raw) in collected {
            let process = self.processes.get_mut(&name).expect("registered process");
            let result = (|| {
                let raw = raw?;
                let file = format!("ownership-{label}-{name}.json");
                let bytes = serde_json::to_string(&raw).map_err(|error| error.to_string())?;
                self.run.write_new(&file, &bytes)?;
                let artifact = Artifact {
                    sha256: collect::file_digest(&self.run.join(&file))?,
                    path: file,
                };
                checkpoint.observations.push(artifact.clone());
                if raw.initial_start_ticks.as_ref() != Some(&process.start_ticks) {
                    return Err("native process was replaced or exited".to_owned());
                }
                let policy = if let Some((policy, _)) = &process.baseline {
                    policy.clone()
                } else if label == "baseline" {
                    observation::startup_policy(&raw, 1)?
                } else {
                    return Err("missing native ownership baseline".to_owned());
                };
                let sample = observation::normalize(&raw, &policy, &name, artifact)?;
                checkpoint.samples.push(sample.clone());
                let baseline = process
                    .baseline
                    .as_ref()
                    .map_or(&sample, |(_, sample)| sample);
                let report =
                    evaluate::evaluate_native_resources(&policy, baseline, &sample, recovered);
                self.run.write_new(
                    &format!("ownership-{label}-{name}-verdict.json"),
                    &serde_json::to_string(
                        &serde_json::json!({"policy":policy,"sample":sample,"report":report}),
                    )
                    .map_err(|error| error.to_string())?,
                )?;
                if report.verdict != Verdict::Pass {
                    return Err(format!(
                        "native ownership {label}/{name}: {}",
                        serde_json::to_string(&report).map_err(|error| error.to_string())?
                    ));
                }
                if label == "baseline" {
                    let contract: schema::Contract =
                        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
                    let recovery = *contract
                        .native_recovery_offsets_ms
                        .last()
                        .expect("native recovery");
                    if policy.replay_expiry_ms > recovery
                        || policy.retirement_deadline_ms > recovery
                    {
                        return Err("startup lifetime exceeds native recovery schedule".to_owned());
                    }
                    process.baseline = Some((policy, sample));
                }
                Ok(())
            })();
            if let Err(error) = result {
                errors.push(format!("{name}: {error}"));
            }
        }
        checkpoint.errors.clone_from(&errors);
        self.receipt.checkpoints.push(checkpoint);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

/// Deadline applies to collecting evidence, not to processing retained bytes.
#[derive(Clone, Copy)]
struct RecoveryWindow {
    started: Instant,
    epoch: u64,
    offset: u64,
    tolerance: u64,
}

impl RecoveryWindow {
    fn contains(self, began: u64, completed: u64, elapsed: Duration) -> bool {
        let Some(start) = self.epoch.checked_add(self.offset) else {
            return false;
        };
        let Some(end) = start.checked_add(self.tolerance) else {
            return false;
        };
        let Some(monotonic_end) = self.offset.checked_add(self.tolerance) else {
            return false;
        };
        began >= start
            && completed >= began
            && completed <= end
            && elapsed >= Duration::from_millis(self.offset)
            && elapsed <= Duration::from_millis(monotonic_end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_window_checks_raw_collection_not_later_processing() {
        let window = RecoveryWindow {
            started: Instant::now(),
            epoch: 1000,
            offset: 180_000,
            tolerance: 2000,
        };
        // Reproduce the historical last raw completion at offset + 1629ms.
        assert!(window.contains(181_000, 182_629, Duration::from_millis(181_629)));
        // Later serialization/evaluation has no input to this decision.
        assert!(!window.contains(181_000, 183_001, Duration::from_millis(182_001)));
        assert!(!window.contains(180_999, 182_000, Duration::from_secs(181)));
        assert!(!window.contains(181_000, 182_000, Duration::from_millis(182_001)));
        assert!(!window.contains(181_000, 180_999, Duration::from_secs(181)));
    }

    #[test]
    fn recovery_window_rejects_timestamp_overflow() {
        let window = RecoveryWindow {
            started: Instant::now(),
            epoch: u64::MAX,
            offset: 1,
            tolerance: 2000,
        };
        assert!(!window.contains(u64::MAX, u64::MAX, Duration::from_millis(1)));
    }
}
