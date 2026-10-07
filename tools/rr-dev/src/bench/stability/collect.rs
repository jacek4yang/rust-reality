//! Raw Linux observations. Collection never assigns an acceptance verdict.
//!
//! Every read is retained independently, including failures. Identity is read
//! before and after inspection; a failed intermediate read cannot skip the
//! terminal identity attempt. This collector runs locally on each owned guest.

use std::{collections::BTreeMap, fs, io::Read as _, path::Path, time::SystemTime};

use crate::{bench::process::proc_starttime, process::Tool};

use super::schema::Observation;

pub(super) fn unix_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| format!("observation clock: {error}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "observation clock overflow".to_owned())
}

fn retain<T>(result: Result<T, String>, label: &str, errors: &mut Vec<String>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{label}: {error}"));
            None
        }
    }
}

fn read(path: &Path, errors: &mut Vec<String>) -> Option<String> {
    retain(
        (|| {
            let file = fs::File::open(path).map_err(|error| error.to_string())?;
            let mut text = String::new();
            file.take((super::schema::MAX_EVIDENCE_BYTES + 1) as u64)
                .read_to_string(&mut text)
                .map_err(|error| error.to_string())?;
            if text.len() > super::schema::MAX_EVIDENCE_BYTES {
                return Err("observation exceeds 64 MiB".to_owned());
            }
            Ok(text)
        })(),
        &path.display().to_string(),
        errors,
    )
}

/// Retain kernel-wide counters and the actual guest profile before and after work.
///
/// # Errors
/// Only a timestamp failure prevents a receipt; individual read failures are retained.
pub fn guest_environment() -> Result<super::execution::Environment, String> {
    let observed_unix_ms = unix_ms()?;
    let mut errors = Vec::new();
    let mut field = |path| read(Path::new(path), &mut errors);
    Ok(super::execution::Environment {
        observed_unix_ms,
        boot_id: field("/proc/sys/kernel/random/boot_id"),
        online_cpus: field("/sys/devices/system/cpu/online"),
        meminfo: field("/proc/meminfo"),
        swaps: field("/proc/swaps"),
        vmstat: field("/proc/vmstat"),
        kernel: field("/proc/sys/kernel/osrelease"),
        errors,
    })
}

/// Hash a retained file or running executable with the same coreutils primitive
/// used by release tooling. Sampling must not depend on rr-dev's debug/release
/// code-generation speed; the entire observation still has its fixed deadline.
///
/// # Errors
/// Fails on missing files, tool failures, timeouts or malformed digest receipts.
pub fn file_digest(path: &Path) -> Result<String, String> {
    let path = path.to_str().ok_or("non-UTF-8 digest path")?;
    let outcome = Tool::new("sha256sum")
        .args(["--", path])
        .timeout(std::time::Duration::from_secs(2))
        .run()
        .map_err(|error| error.to_string())?;
    super::observation::digest_receipt(&outcome.stdout, path)
}

/// Hash the running controller image, including when its pathname was replaced.
///
/// # Errors
/// Returns an error if the kernel image or digest command cannot be read.
pub fn running_image_digest() -> Result<String, String> {
    // `self` inside sha256sum would name that child, not this controller.
    file_digest(Path::new(&format!("/proc/{}/exe", std::process::id())))
}

/// Collect raw observations for one explicitly selected local process.
///
/// # Errors
/// Returns an error only when the system clock cannot timestamp the attempt.
/// Process/read errors are returned inside the observation, preserving all other
/// fields and the final identity attempt. This function never signals a process.
pub fn observe(pid: u32, log: &Path) -> Result<Observation, String> {
    let started_unix_ms = unix_ms()?;
    let mut errors = Vec::new();
    let root = std::path::PathBuf::from(format!("/proc/{pid}"));
    let initial_start_ticks = retain(
        proc_starttime(pid).ok_or_else(|| "process unavailable".to_owned()),
        "initial process identity",
        &mut errors,
    );
    let initial_executable_sha256 = retain(
        file_digest(&root.join("exe")),
        "initial executable identity",
        &mut errors,
    );
    let boot_id = read(Path::new("/proc/sys/kernel/random/boot_id"), &mut errors);
    let status = read(&root.join("status"), &mut errors);
    let smaps_rollup = read(&root.join("smaps_rollup"), &mut errors);
    let limits = read(&root.join("limits"), &mut errors);
    let mut descriptors = BTreeMap::new();
    let mut closed_during_read = Vec::new();
    let entries = retain(
        fs::read_dir(root.join("fd")).map_err(|error| error.to_string()),
        "descriptor directory",
        &mut errors,
    );
    if let Some(entries) = entries {
        for entry in entries {
            let Some(entry) = retain(
                entry.map_err(|error| error.to_string()),
                "descriptor directory entry",
                &mut errors,
            ) else {
                continue;
            };
            let Some(number) = entry
                .file_name()
                .to_str()
                .and_then(|text| text.parse().ok())
            else {
                errors.push("invalid descriptor number".to_owned());
                continue;
            };
            match fs::read_link(entry.path()) {
                Ok(target) => match target.into_os_string().into_string() {
                    Ok(target) => {
                        descriptors.insert(number, target);
                    }
                    Err(_) => errors.push(format!("descriptor {number}: non-UTF-8 target")),
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    closed_during_read.push(number);
                }
                Err(error) => errors.push(format!("descriptor {number}: {error}")),
            }
        }
    }
    let ownership_log = read(log, &mut errors);
    let unix_sockets = read(&root.join("net/unix"), &mut errors).and_then(|table| {
        retain(
            super::observation::owned_unix_rows(&table, &descriptors),
            "owned Unix socket rows",
            &mut errors,
        )
    });
    // Do not use `?` before both terminal identity reads have been attempted.
    let final_start_ticks = retain(
        proc_starttime(pid).ok_or_else(|| "process unavailable".to_owned()),
        "final process identity",
        &mut errors,
    );
    let final_executable_sha256 = retain(
        file_digest(&root.join("exe")),
        "final executable identity",
        &mut errors,
    );
    Ok(Observation {
        pid,
        started_unix_ms,
        completed_unix_ms: unix_ms()?,
        initial_start_ticks,
        final_start_ticks,
        boot_id,
        initial_executable_sha256,
        final_executable_sha256,
        status,
        smaps_rollup,
        limits,
        descriptors,
        unix_sockets,
        closed_during_read,
        ownership_log,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_process_preserves_each_failed_read_and_final_identity_attempt() {
        let observation = observe(u32::MAX, Path::new("/proc/missing-stability-log")).unwrap();
        assert!(observation.initial_start_ticks.is_none());
        assert!(observation.final_start_ticks.is_none());
        assert!(observation.initial_executable_sha256.is_none());
        assert!(observation.final_executable_sha256.is_none());
        for label in [
            "initial process identity",
            "initial executable identity",
            "descriptor directory",
            "final process identity",
            "final executable identity",
        ] {
            assert!(
                observation
                    .errors
                    .iter()
                    .any(|error| error.starts_with(label)),
                "{label}"
            );
        }
        assert!(observation.boot_id.is_some());
        assert!(observation.completed_unix_ms >= observation.started_unix_ms);
    }
}
