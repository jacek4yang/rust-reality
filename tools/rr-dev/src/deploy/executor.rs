//! Execution of typed deployment plans.
//!
//! Planning and execution are deliberately separate. A plan is pure recorded
//! evidence; this module consumes an already validated plan, repeats the relevant
//! identity checks immediately before mutation, and performs one argv-only remote
//! operation at a time. Cutover failure constructs and executes rollback from the
//! pre-cutover snapshot rather than relying on a remote shell trap.

use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    deploy::{
        host::Host,
        plan::{ArtifactIdentity, DeploymentPlan, Paths, PlanKind, validate_release_id},
        remote::{Transport, checked},
        snapshot::{HostSnapshot, inspect},
    },
    hash,
    perf::json_out::Json,
    process::Tool,
};

/// Validates candidate bytes on the controller before they are copied.
pub trait CandidateValidator {
    /// Checks the local binary/config identity and their built-in validators.
    fn validate(&mut self, artifact: &ArtifactIdentity) -> Result<(), String>;
}

/// The production local candidate validator.
#[derive(Debug, Default)]
pub struct SystemCandidateValidator;

impl CandidateValidator for SystemCandidateValidator {
    fn validate(&mut self, artifact: &ArtifactIdentity) -> Result<(), String> {
        artifact.validate()?;
        let binary = Path::new(&artifact.binary_path);
        let config = Path::new(&artifact.config_path);
        let metadata = binary
            .metadata()
            .map_err(|error| format!("candidate binary {}: {error}", binary.display()))?;
        if !metadata.is_file() {
            return Err(format!(
                "candidate binary is not a regular file: {}",
                binary.display()
            ));
        }
        if !config.is_file() {
            return Err(format!(
                "candidate config is not a readable file: {}",
                config.display()
            ));
        }
        let observed = hash::sha256_file(binary)?;
        if observed != artifact.binary_sha256 {
            return Err(format!(
                "candidate binary SHA-256 mismatch: expected {}, observed {observed}",
                artifact.binary_sha256
            ));
        }
        let version = Tool::new(&artifact.binary_path)
            .arg("--version")
            .run()
            .map_err(|error| format!("candidate version: {error}"))?;
        let observed_version = version
            .trimmed_stdout()
            .split_whitespace()
            .nth(1)
            .unwrap_or_default();
        if observed_version != artifact.version {
            return Err(format!(
                "candidate version mismatch: expected {}, observed {observed_version:?}",
                artifact.version
            ));
        }
        for subcommand in ["check", "self-test"] {
            Tool::new(&artifact.binary_path)
                .args([
                    subcommand.to_owned(),
                    "--config".to_owned(),
                    artifact.config_path.clone(),
                ])
                .run()
                .map_err(|error| format!("candidate {subcommand}: {error}"))?;
        }
        Ok(())
    }
}

/// Secret-free evidence from an executed transaction.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    /// Plan that was executed.
    pub plan: DeploymentPlan,
    /// Snapshot immediately before the transaction.
    pub before: HostSnapshot,
    /// Snapshot after success.
    pub after: HostSnapshot,
    /// Ordered, non-sensitive executor milestones.
    pub milestones: Vec<String>,
}

impl ExecutionReport {
    /// Renders the execution evidence as JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("plan", self.plan.to_json()),
            ("before", self.before.to_json()),
            ("after", self.after.to_json()),
            (
                "milestones",
                Json::Array(
                    self.milestones
                        .iter()
                        .map(|line| Json::string(line.clone()))
                        .collect(),
                ),
            ),
            ("verdict", Json::string("PASS")),
        ])
    }
}

/// Executes one plan against its named host.
///
/// The caller owns authorization. The CLI enforces an explicit mutation flag;
/// this lower layer assumes that boundary has been crossed so fake transports can
/// exercise the exact same implementation without special modes.
///
/// # Errors
///
/// Returns an identity, transport, postcondition, or rollback failure. A cutover
/// error always attempts rollback before it is returned.
pub fn execute(
    transport: &mut impl Transport,
    validator: &mut impl CandidateValidator,
    host: &Host,
    plan: &DeploymentPlan,
    before: &HostSnapshot,
    artifact: Option<&ArtifactIdentity>,
    unit_file: Option<&Path>,
) -> Result<ExecutionReport, String> {
    if plan.target != host.alias() || before.alias != host.alias() {
        return Err("deployment plan/snapshot target does not match the host".to_owned());
    }
    let mut milestones = Vec::new();
    match plan.kind {
        PlanKind::Bootstrap => {
            let unit_file = unit_file
                .ok_or_else(|| "bootstrap requires the repository systemd unit".to_owned())?;
            bootstrap(transport, host, plan, unit_file)?;
            milestones.extend([
                "baseline-generation-adopted".to_owned(),
                "current-and-previous-initialized".to_owned(),
                "systemd-unit-installed-without-restart".to_owned(),
            ]);
        }
        PlanKind::Stage => {
            let artifact = artifact.ok_or_else(|| "stage requires candidate identity".to_owned())?;
            validator.validate(artifact)?;
            milestones.push("local-candidate-validated".to_owned());
            stage_remote(transport, host, artifact)?;
            milestones.push("remote-candidate-staged-and-verified".to_owned());
        }
        PlanKind::Cutover => {
            let artifact = artifact.ok_or_else(|| "cutover requires candidate identity".to_owned())?;
            artifact.validate()?;
            if let Err(error) = cutover(transport, host, before, artifact) {
                let rollback = restore_before(transport, host, before);
                return Err(match rollback {
                    Ok(()) => format!("cutover failed and CURRENT was rolled back: {error}"),
                    Err(rollback_error) => format!(
                        "cutover failed ({error}); automatic rollback also failed: {rollback_error}"
                    ),
                });
            }
            milestones.extend([
                "current-and-previous-switched".to_owned(),
                "service-identity-and-listeners-verified".to_owned(),
                "pending-release-recorded".to_owned(),
            ]);
        }
        PlanKind::Rollback => {
            rollback_to_previous(transport, host, before)?;
            milestones.extend([
                "previous-restored".to_owned(),
                "service-identity-and-listeners-verified".to_owned(),
                "pending-release-cleared".to_owned(),
            ]);
        }
        PlanKind::Promote => {
            promote(transport, host, plan, before)?;
            milestones.extend([
                "current-generation-recorded".to_owned(),
                "pending-release-cleared".to_owned(),
            ]);
            if plan
                .actions
                .iter()
                .any(|action| matches!(action, crate::deploy::plan::DeploymentAction::PruneOldReleases))
            {
                milestones.push("old-generations-pruned".to_owned());
            }
        }
    }
    let after = inspect(transport, host)?;
    let expected = expected_binary(plan, before, artifact)?;
    verify_snapshot(before, &after, &expected)?;
    Ok(ExecutionReport {
        plan: plan.clone(),
        before: before.clone(),
        after,
        milestones,
    })
}

fn expected_binary(
    plan: &DeploymentPlan,
    before: &HostSnapshot,
    artifact: Option<&ArtifactIdentity>,
) -> Result<String, String> {
    match plan.kind {
        PlanKind::Bootstrap | PlanKind::Stage | PlanKind::Promote => before
            .executable
            .as_deref()
            .map(str::to_owned)
            .ok_or_else(|| "pre-transaction executable identity is absent".to_owned()),
        PlanKind::Cutover => {
            let artifact = artifact.ok_or_else(|| "cutover identity is absent".to_owned())?;
            // The returned value cannot borrow the formatted path, so plans carry
            // the exact expected executable as their VerifyService action.
            plan.actions
                .iter()
                .find_map(|action| match action {
                    crate::deploy::plan::DeploymentAction::VerifyService {
                        expected_binary,
                    } => Some(expected_binary.clone()),
                    _ => None,
                })
                .ok_or_else(|| format!("cutover {} lacks verification", artifact.release_id))
        }
        PlanKind::Rollback => plan
            .actions
            .iter()
            .find_map(|action| match action {
                crate::deploy::plan::DeploymentAction::VerifyService { expected_binary } => {
                    Some(expected_binary.clone())
                }
                _ => None,
            })
            .ok_or_else(|| "rollback plan lacks verification".to_owned()),
    }
}

#[allow(clippy::too_many_lines)]
fn bootstrap(
    transport: &mut impl Transport,
    host: &Host,
    plan: &DeploymentPlan,
    unit_file: &Path,
) -> Result<(), String> {
    if !unit_file.is_file() {
        return Err(format!(
            "repository systemd unit is absent: {}",
            unit_file.display()
        ));
    }
    let (release_id, baseline_binary, baseline_config) = plan
        .actions
        .iter()
        .find_map(|action| match action {
            crate::deploy::plan::DeploymentAction::Bootstrap {
                release_id,
                baseline_binary,
                baseline_config,
            } => Some((release_id.as_str(), baseline_binary.as_str(), baseline_config.as_str())),
            _ => None,
        })
        .ok_or_else(|| "bootstrap plan has no baseline action".to_owned())?;
    validate_release_id(release_id)?;
    run(
        transport,
        host,
        true,
        &["test", "-x", baseline_binary],
        "verify baseline binary",
    )?;
    run(
        transport,
        host,
        true,
        &["test", "-r", baseline_config],
        "verify baseline config",
    )?;
    let binary_digest = checked(
        transport,
        host,
        true,
        &["sha256sum".to_owned(), baseline_binary.to_owned()],
        "digest baseline binary",
    )?
    .split_whitespace()
    .next()
    .ok_or_else(|| "baseline binary digest output is empty".to_owned())?
    .to_owned();
    let config_digest = checked(
        transport,
        host,
        true,
        &["sha256sum".to_owned(), baseline_config.to_owned()],
        "digest baseline config",
    )?
    .split_whitespace()
    .next()
    .ok_or_else(|| "baseline config digest output is empty".to_owned())?
    .to_owned();
    for (label, digest) in [
        ("baseline binary", binary_digest.as_str()),
        ("baseline config", config_digest.as_str()),
    ] {
        if digest.len() != 64
            || digest
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(format!("{label} digest is not lowercase SHA-256"));
        }
    }
    let paths = Paths::canonical();
    let binary_dir = format!("{}/{release_id}", paths.releases);
    let config_dir = format!("{}/{release_id}", paths.config_releases);
    run(
        transport,
        host,
        true,
        &["install", "-d", "-m", "0755", &binary_dir],
        "create bootstrap binary generation",
    )?;
    run(
        transport,
        host,
        true,
        &[
            "install",
            "-d",
            "-m",
            "0750",
            "-o",
            "root",
            "-g",
            "rust-reality",
            &config_dir,
        ],
        "create bootstrap config generation",
    )?;
    run(
        transport,
        host,
        true,
        &[
            "install",
            "-m",
            "0755",
            baseline_binary,
            &format!("{binary_dir}/rust-reality"),
        ],
        "install bootstrap binary",
    )?;
    run(
        transport,
        host,
        true,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            "rust-reality",
            baseline_config,
            &format!("{config_dir}/config.json"),
        ],
        "install bootstrap config",
    )?;
    for (target, link) in [
        (binary_dir.as_str(), paths.current_binary.as_str()),
        (binary_dir.as_str(), paths.previous_binary.as_str()),
        (config_dir.as_str(), paths.current_config.as_str()),
        (config_dir.as_str(), paths.previous_config.as_str()),
    ] {
        switch_link(transport, host, target, link, "next")?;
    }
    install_record(
        transport,
        host,
        "bootstrap",
        &format!(
            "legacyBinary={baseline_binary}\nlegacyBinarySha256={binary_digest}\nlegacyConfig={baseline_config}\nlegacyConfigSha256={config_digest}\n"
        ),
    )?;
    install_unit(transport, host, unit_file)
}

fn install_unit(
    transport: &mut impl Transport,
    host: &Host,
    unit_file: &Path,
) -> Result<(), String> {
    let staging = checked(
        transport,
        host,
        false,
        &strings(&["mktemp", "-d", "/tmp/rust-reality-deploy.XXXXXXXX"]),
        "create unit staging directory",
    )?;
    if !safe_staging(&staging) {
        return Err(format!("remote mktemp returned unsafe path {staging:?}"));
    }
    let remote = format!("{staging}/rust-reality.service");
    let result = (|| {
        transport.copy_to(host, unit_file, &remote)?;
        run(
            transport,
            host,
            true,
            &[
                "install",
                "-m",
                "0644",
                &remote,
                &format!("/etc/systemd/system/{}", host.service()),
            ],
            "install systemd unit",
        )?;
        run(
            transport,
            host,
            true,
            &["systemctl", "daemon-reload"],
            "reload systemd units",
        )
    })();
    let cleanup = run(
        transport,
        host,
        false,
        &["rm", "-rf", "--", &staging],
        "remove unit staging directory",
    );
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(format!("{error}; unit staging cleanup failed: {cleanup}"))
        }
    }
}

fn stage_remote(
    transport: &mut impl Transport,
    host: &Host,
    artifact: &ArtifactIdentity,
) -> Result<(), String> {
    let staging = checked(
        transport,
        host,
        false,
        &strings(&["mktemp", "-d", "/tmp/rust-reality-deploy.XXXXXXXX"]),
        "create remote staging directory",
    )?;
    if !safe_staging(&staging) {
        return Err(format!("remote mktemp returned unsafe path {staging:?}"));
    }
    let binary_remote = format!("{staging}/rust-reality");
    let config_remote = format!("{staging}/config.json");
    let result = (|| {
        transport.copy_to(host, Path::new(&artifact.binary_path), &binary_remote)?;
        transport.copy_to(host, Path::new(&artifact.config_path), &config_remote)?;
        run(transport, host, true, &["chmod", "0755", &binary_remote], "chmod staged binary")?;
        let digest = checked(
            transport,
            host,
            true,
            &["sha256sum".to_owned(), binary_remote.clone()],
            "digest staged binary",
        )?;
        if digest.split_whitespace().next() != Some(artifact.binary_sha256.as_str()) {
            return Err("remote staged binary SHA-256 mismatch".to_owned());
        }
        let version = checked(
            transport,
            host,
            true,
            &[binary_remote.clone(), "--version".to_owned()],
            "version staged binary",
        )?;
        if version.split_whitespace().nth(1) != Some(artifact.version.as_str()) {
            return Err("remote staged binary version mismatch".to_owned());
        }
        for subcommand in ["check", "self-test"] {
            run(
                transport,
                host,
                true,
                &[&binary_remote, subcommand, "--config", &config_remote],
                &format!("remote candidate {subcommand}"),
            )?;
        }
        let paths = Paths::canonical();
        let binary_dir = format!("{}/{}", paths.releases, artifact.release_id);
        let config_dir = format!("{}/{}", paths.config_releases, artifact.release_id);
        run(transport, host, true, &["install", "-d", "-m", "0755", &binary_dir], "create binary generation")?;
        run(transport, host, true, &["install", "-d", "-m", "0750", "-o", "root", "-g", "rust-reality", &config_dir], "create config generation")?;
        let installed_binary = format!("{binary_dir}/rust-reality");
        let installed_config = format!("{config_dir}/config.json");
        run(transport, host, true, &["install", "-m", "0755", &binary_remote, &installed_binary], "install candidate binary")?;
        run(transport, host, true, &["install", "-m", "0640", "-o", "root", "-g", "rust-reality", &config_remote, &installed_config], "install candidate config")?;
        let installed_digest = checked(
            transport,
            host,
            true,
            &["sha256sum".to_owned(), installed_binary],
            "digest installed binary",
        )?;
        if installed_digest.split_whitespace().next() != Some(artifact.binary_sha256.as_str()) {
            return Err("installed binary SHA-256 mismatch".to_owned());
        }
        Ok(())
    })();
    let cleanup = run(
        transport,
        host,
        false,
        &["rm", "-rf", "--", &staging],
        "remove remote staging directory",
    );
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; staging cleanup failed: {cleanup}")),
    }
}

fn cutover(
    transport: &mut impl Transport,
    host: &Host,
    before: &HostSnapshot,
    artifact: &ArtifactIdentity,
) -> Result<(), String> {
    let paths = Paths::canonical();
    let new_binary = format!("{}/{}", paths.releases, artifact.release_id);
    let new_config = format!("{}/{}", paths.config_releases, artifact.release_id);
    run(transport, host, true, &["test", "-x", &format!("{new_binary}/rust-reality")], "verify staged binary")?;
    run(transport, host, true, &["test", "-r", &format!("{new_config}/config.json")], "verify staged config")?;
    let generations = before
        .generations
        .as_ref()
        .ok_or_else(|| "cutover snapshot has no generation pointers".to_owned())?;
    let old_binary = generations
        .current_binary
        .as_deref()
        .ok_or_else(|| "cutover snapshot has no CURRENT binary".to_owned())?;
    let old_config = generations
        .current_config
        .as_deref()
        .ok_or_else(|| "cutover snapshot has no CURRENT config".to_owned())?;
    switch_link(transport, host, old_binary, &paths.previous_binary, "previous")?;
    switch_link(transport, host, old_config, &paths.previous_config, "previous")?;
    run(transport, host, true, &["systemctl", "stop", host.service()], "stop service for cutover")?;
    switch_link(transport, host, &new_binary, &paths.current_binary, "next")?;
    switch_link(transport, host, &new_config, &paths.current_config, "next")?;
    run(transport, host, true, &["systemctl", "start", host.service()], "start cutover service")?;
    let after = wait_healthy(transport, host, &format!("{new_binary}/rust-reality"), before)?;
    verify_snapshot(before, &after, &format!("{new_binary}/rust-reality"))?;
    install_record(
        transport,
        host,
        "pending",
        &format!(
            "pendingRelease={}\npreviousBinary={}\npreviousConfig={}\n",
            artifact.release_id, old_binary, old_config
        ),
    )
}

fn rollback_to_previous(
    transport: &mut impl Transport,
    host: &Host,
    before: &HostSnapshot,
) -> Result<(), String> {
    let generations = before
        .generations
        .as_ref()
        .ok_or_else(|| "rollback snapshot has no generation pointers".to_owned())?;
    let binary = generations
        .previous_binary
        .as_deref()
        .ok_or_else(|| "rollback snapshot has no PREVIOUS binary".to_owned())?;
    let config = generations
        .previous_config
        .as_deref()
        .ok_or_else(|| "rollback snapshot has no PREVIOUS config".to_owned())?;
    switch_current(transport, host, binary, config)?;
    let after = wait_healthy(transport, host, &format!("{binary}/rust-reality"), before)?;
    verify_snapshot(before, &after, &format!("{binary}/rust-reality"))?;
    clear_pending(transport, host)
}

fn restore_before(
    transport: &mut impl Transport,
    host: &Host,
    before: &HostSnapshot,
) -> Result<(), String> {
    let generations = before
        .generations
        .as_ref()
        .ok_or_else(|| "automatic rollback has no original generation pointers".to_owned())?;
    let binary = generations
        .current_binary
        .as_deref()
        .ok_or_else(|| "automatic rollback has no original CURRENT binary".to_owned())?;
    let config = generations
        .current_config
        .as_deref()
        .ok_or_else(|| "automatic rollback has no original CURRENT config".to_owned())?;
    switch_current(transport, host, binary, config)?;
    let restored = wait_healthy(transport, host, &format!("{binary}/rust-reality"), before)?;
    verify_snapshot(before, &restored, &format!("{binary}/rust-reality"))
}

fn switch_current(
    transport: &mut impl Transport,
    host: &Host,
    binary: &str,
    config: &str,
) -> Result<(), String> {
    let paths = Paths::canonical();
    let _ = run(
        transport,
        host,
        true,
        &["systemctl", "stop", host.service()],
        "stop service for generation switch",
    );
    switch_link(transport, host, binary, &paths.current_binary, "next")?;
    switch_link(transport, host, config, &paths.current_config, "next")?;
    run(
        transport,
        host,
        true,
        &["systemctl", "start", host.service()],
        "start service after generation switch",
    )
}

fn switch_link(
    transport: &mut impl Transport,
    host: &Host,
    target: &str,
    link: &str,
    suffix: &str,
) -> Result<(), String> {
    let temporary = format!("{link}.{suffix}");
    run(transport, host, true, &["ln", "-sfn", target, &temporary], "prepare generation symlink")?;
    run(transport, host, true, &["mv", "-Tf", &temporary, link], "commit generation symlink")
}

fn wait_healthy(
    transport: &mut impl Transport,
    host: &Host,
    expected_binary: &str,
    before: &HostSnapshot,
) -> Result<HostSnapshot, String> {
    let mut last = String::new();
    for _ in 0..100 {
        match inspect(transport, host) {
            Ok(snapshot) => match verify_snapshot(before, &snapshot, expected_binary) {
                Ok(()) => return Ok(snapshot),
                Err(error) => last = error,
            },
            Err(error) => last = error,
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!("service did not become healthy within 10 seconds: {last}"))
}

fn verify_snapshot(
    before: &HostSnapshot,
    after: &HostSnapshot,
    expected_binary: &str,
) -> Result<(), String> {
    if !after.service_healthy() || !after.ssh_22_present {
        return Err(format!("post-deployment service is unhealthy: {}", after.summary_line()));
    }
    if after.executable.as_deref() != Some(expected_binary) {
        return Err(format!(
            "post-deployment executable mismatch: expected {expected_binary}, observed {:?}",
            after.executable
        ));
    }
    let existing = listener_set(before);
    let introduced: Vec<_> = listener_set(after).difference(&existing).cloned().collect();
    let unexpected: Vec<_> = introduced
        .into_iter()
        .filter(|(_, port)| !HostSnapshot::EXPECTED_PUBLIC_PORTS.contains(port))
        .collect();
    if !unexpected.is_empty() {
        return Err(format!(
            "deployment introduced public listeners {unexpected:?}"
        ));
    }
    Ok(())
}

fn listener_set(snapshot: &HostSnapshot) -> BTreeSet<(String, u16)> {
    snapshot
        .listeners
        .iter()
        .filter(|listener| listener.is_wildcard())
        .map(|listener| (listener.address.clone(), listener.port))
        .collect()
}

fn promote(
    transport: &mut impl Transport,
    host: &Host,
    plan: &DeploymentPlan,
    before: &HostSnapshot,
) -> Result<(), String> {
    let release_id = plan
        .actions
        .iter()
        .find_map(|action| match action {
            crate::deploy::plan::DeploymentAction::RecordPromoted { release_id } => {
                Some(release_id.as_str())
            }
            _ => None,
        })
        .ok_or_else(|| "promote plan has no release record".to_owned())?;
    let generations = before
        .generations
        .as_ref()
        .ok_or_else(|| "promote snapshot has no generation pointers".to_owned())?;
    let current = generations
        .current_binary
        .as_deref()
        .ok_or_else(|| "promote snapshot has no CURRENT binary".to_owned())?;
    let previous = generations
        .previous_binary
        .as_deref()
        .ok_or_else(|| "promote snapshot has no PREVIOUS binary".to_owned())?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before Unix epoch: {error}"))?
        .as_secs();
    install_record(
        transport,
        host,
        "current",
        &format!(
            "releaseId={release_id}\ncurrent={current}\nprevious={previous}\npromotedAtUnixSeconds={timestamp}\n"
        ),
    )?;
    clear_pending(transport, host)?;
    if plan
        .actions
        .iter()
        .any(|action| matches!(action, crate::deploy::plan::DeploymentAction::PruneOldReleases))
    {
        prune(transport, host, generations)?;
    }
    Ok(())
}

fn install_record(
    transport: &mut impl Transport,
    host: &Host,
    name: &str,
    contents: &str,
) -> Result<(), String> {
    if !matches!(name, "pending" | "current" | "bootstrap") {
        return Err(format!("unsafe deployment record name {name:?}"));
    }
    let staging = checked(
        transport,
        host,
        false,
        &strings(&["mktemp", "-d", "/tmp/rust-reality-deploy.XXXXXXXX"]),
        "create record staging directory",
    )?;
    if !safe_staging(&staging) {
        return Err(format!("remote mktemp returned unsafe path {staging:?}"));
    }
    let local = temporary_record(name, contents)?;
    let remote = format!("{staging}/{name}");
    let result = (|| {
        transport.copy_to(host, &local, &remote)?;
        let state = Paths::canonical().state;
        run(transport, host, true, &["install", "-d", "-m", "0750", "-o", "root", "-g", "rust-reality", &state], "create deployment state directory")?;
        run(transport, host, true, &["install", "-m", "0600", &remote, &format!("{state}/{name}")], "install deployment state record")
    })();
    let _ = std::fs::remove_file(&local);
    let cleanup = run(transport, host, false, &["rm", "-rf", "--", &staging], "remove record staging directory");
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; record cleanup failed: {cleanup}")),
    }
}

fn temporary_record(name: &str, contents: &str) -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "rust-reality-deploy-record-{}-{nonce}-{name}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create deployment record {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("write deployment record {}: {error}", path.display()))?;
    Ok(path)
}

fn clear_pending(transport: &mut impl Transport, host: &Host) -> Result<(), String> {
    run(
        transport,
        host,
        true,
        &["rm", "-f", "/var/lib/rust-reality/deployment/pending"],
        "clear pending deployment record",
    )
}

fn prune(
    transport: &mut impl Transport,
    host: &Host,
    generations: &crate::deploy::snapshot::GenerationPointers,
) -> Result<(), String> {
    let paths = Paths::canonical();
    for (root, current, previous) in [
        (
            paths.releases.as_str(),
            generations.current_binary.as_deref(),
            generations.previous_binary.as_deref(),
        ),
        (
            paths.config_releases.as_str(),
            generations.current_config.as_deref(),
            generations.previous_config.as_deref(),
        ),
    ] {
        let keep: BTreeSet<&str> = [current, previous]
            .into_iter()
            .flatten()
            .filter_map(|path| path.rsplit('/').next())
            .collect();
        let entries = checked(
            transport,
            host,
            true,
            &strings(&[
                "find",
                root,
                "-mindepth",
                "1",
                "-maxdepth",
                "1",
                "-printf",
                "%f\\n",
            ]),
            "list release generations",
        )?;
        for entry in entries.lines().filter(|entry| !entry.is_empty()) {
            validate_release_id(entry)?;
            if !keep.contains(entry) {
                run(
                    transport,
                    host,
                    true,
                    &["rm", "-rf", "--", &format!("{root}/{entry}")],
                    "prune old release generation",
                )?;
            }
        }
    }
    Ok(())
}

fn safe_staging(path: &str) -> bool {
    path.starts_with("/tmp/rust-reality-deploy.")
        && !path.chars().any(char::is_whitespace)
        && !path.contains("..")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn run(
    transport: &mut impl Transport,
    host: &Host,
    privileged: bool,
    argv: &[&str],
    context: &str,
) -> Result<(), String> {
    checked(transport, host, privileged, &strings(argv), context).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::{
        host::{HostRole, Topology},
        plan::{DeploymentAction, plan_cutover, plan_stage},
        remote::Reply,
        snapshot::{GenerationPointers, Listener},
    };

    #[derive(Default)]
    struct FakeValidator {
        calls: usize,
    }

    impl CandidateValidator for FakeValidator {
        fn validate(&mut self, artifact: &ArtifactIdentity) -> Result<(), String> {
            artifact.validate()?;
            self.calls += 1;
            Ok(())
        }
    }

    struct FakeTransport {
        current: String,
        previous: String,
        config_current: String,
        config_previous: String,
        staging_counter: usize,
        commands: Vec<Vec<String>>,
        copies: Vec<String>,
        fail_candidate_start: bool,
        candidate_start_failed: bool,
        running_executable: String,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                current: "/opt/rust-reality/releases/r1".to_owned(),
                previous: "/opt/rust-reality/releases/r0".to_owned(),
                config_current: "/etc/rust-reality/releases/r1".to_owned(),
                config_previous: "/etc/rust-reality/releases/r0".to_owned(),
                staging_counter: 0,
                commands: Vec::new(),
                copies: Vec::new(),
                fail_candidate_start: false,
                candidate_start_failed: false,
                running_executable: "/opt/rust-reality/releases/r1/rust-reality".to_owned(),
            }
        }
    }

    impl Transport for FakeTransport {
        fn run(
            &mut self,
            _host: &Host,
            _privileged: bool,
            argv: &[String],
        ) -> Result<Reply, String> {
            self.commands.push(argv.to_vec());
            let joined = argv.join(" ");
            let mut code = Some(0);
            let stdout = if joined == "mktemp -d /tmp/rust-reality-deploy.XXXXXXXX" {
                self.staging_counter += 1;
                format!("/tmp/rust-reality-deploy.fake{}\n", self.staging_counter)
            } else if joined == "systemctl is-active rust-reality.service" {
                "active\n".to_owned()
            } else if joined == "systemctl show rust-reality.service -p MainPID --value" {
                "4242\n".to_owned()
            } else if joined == "readlink -f /proc/4242/exe" {
                format!("{}\n", self.running_executable)
            } else if joined.starts_with("sha256sum /opt/rust-reality/releases/r2")
                || joined.starts_with("sha256sum /tmp/rust-reality-deploy.")
            {
                format!("{}  file\n", "b".repeat(64))
            } else if joined.starts_with("sha256sum ") {
                format!("{}  file\n", "a".repeat(64))
            } else if joined.ends_with("rust-reality --version") {
                "rust-reality 1.9.0\n".to_owned()
            } else if joined == "ss -ltnH" {
                "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\n".to_owned()
            } else if joined == "systemctl show rust-reality.service -p NRestarts --value" {
                "0\n".to_owned()
            } else if joined == "readlink -f /opt/rust-reality/current" {
                format!("{}\n", self.current)
            } else if joined == "readlink -f /etc/rust-reality/current" {
                format!("{}\n", self.config_current)
            } else if joined == "readlink -f /opt/rust-reality/previous" {
                format!("{}\n", self.previous)
            } else if joined == "readlink -f /etc/rust-reality/previous" {
                format!("{}\n", self.config_previous)
            } else if argv.first().map(String::as_str) == Some("ln") {
                let target = argv[2].clone();
                let temporary = &argv[3];
                if temporary.starts_with("/opt/rust-reality/current") {
                    self.current = target;
                } else if temporary.starts_with("/etc/rust-reality/current") {
                    self.config_current = target;
                } else if temporary.starts_with("/opt/rust-reality/previous") {
                    self.previous = target;
                } else if temporary.starts_with("/etc/rust-reality/previous") {
                    self.config_previous = target;
                }
                String::new()
            } else if joined == "systemctl start rust-reality.service"
                && self.current.ends_with("/r2")
                && self.fail_candidate_start
                && !self.candidate_start_failed
            {
                self.candidate_start_failed = true;
                code = Some(1);
                String::new()
            } else if joined == "systemctl start rust-reality.service" {
                self.running_executable = format!("{}/rust-reality", self.current);
                String::new()
            } else {
                String::new()
            };
            Ok(Reply {
                code,
                stdout,
                stderr: String::new(),
            })
        }

        fn copy_to(&mut self, _host: &Host, _local: &Path, remote: &str) -> Result<(), String> {
            self.copies.push(remote.to_owned());
            Ok(())
        }
    }

    fn snapshot() -> HostSnapshot {
        HostSnapshot {
            alias: "rust-reality-vps".to_owned(),
            service_state: "active".to_owned(),
            pid: Some(4242),
            executable: Some("/opt/rust-reality/releases/r1/rust-reality".to_owned()),
            executable_sha256: Some("a".repeat(64)),
            version: Some("rust-reality 1.8.0".to_owned()),
            listeners: vec![
                Listener {
                    address: "0.0.0.0".to_owned(),
                    port: 22,
                },
                Listener {
                    address: "[::]".to_owned(),
                    port: 443,
                },
            ],
            ssh_22_present: true,
            service_443_present: true,
            restarts: Some(0),
            generations: Some(GenerationPointers {
                current_binary: Some("/opt/rust-reality/releases/r1".to_owned()),
                current_config: Some("/etc/rust-reality/releases/r1".to_owned()),
                previous_binary: Some("/opt/rust-reality/releases/r0".to_owned()),
                previous_config: Some("/etc/rust-reality/releases/r0".to_owned()),
            }),
        }
    }

    fn artifact() -> ArtifactIdentity {
        ArtifactIdentity {
            release_id: "r2".to_owned(),
            binary_path: "/build/rust-reality".to_owned(),
            config_path: "/build/config.json".to_owned(),
            binary_sha256: "b".repeat(64),
            version: "1.9.0".to_owned(),
            source_commit: Some("c".repeat(40)),
        }
    }

    #[test]
    fn fake_stage_validates_locally_copies_both_files_and_keeps_current() {
        let topology = Topology::canonical().unwrap();
        let host = topology.host(HostRole::Line);
        let before = snapshot();
        let artifact = artifact();
        let plan = plan_stage(&before, &artifact).unwrap();
        let mut transport = FakeTransport::new();
        let mut validator = FakeValidator::default();
        let report = execute(
            &mut transport,
            &mut validator,
            host,
            &plan,
            &before,
            Some(&artifact),
            None,
        )
        .unwrap();
        assert_eq!(validator.calls, 1);
        assert_eq!(transport.copies.len(), 2);
        assert_eq!(report.after.executable, before.executable);
        assert!(!transport.commands.iter().any(|argv| argv.first().map(String::as_str) == Some("systemctl") && argv.get(1).map(String::as_str) == Some("stop")));
    }

    #[test]
    fn fake_bootstrap_initializes_both_generations_without_restarting() {
        let topology = Topology::canonical().unwrap();
        let host = topology.host(HostRole::Line);
        let mut before = snapshot();
        before.generations = None;
        before.executable = Some("/usr/local/bin/rust-reality".to_owned());
        let plan = crate::deploy::plan::plan_bootstrap(
            &before,
            "baseline-1",
            "/usr/local/bin/rust-reality",
            "/etc/rust-reality/config.json",
        )
        .unwrap();
        let mut transport = FakeTransport::new();
        transport.running_executable = "/usr/local/bin/rust-reality".to_owned();
        let unit = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/rust-reality-vps.service");
        let report = execute(
            &mut transport,
            &mut FakeValidator::default(),
            host,
            &plan,
            &before,
            None,
            Some(&unit),
        )
        .unwrap();
        assert_eq!(
            report.after.executable.as_deref(),
            Some("/usr/local/bin/rust-reality")
        );
        assert_eq!(transport.current, "/opt/rust-reality/releases/baseline-1");
        assert_eq!(transport.previous, transport.current);
        assert!(!transport.commands.iter().any(|argv| {
            argv == &["systemctl".to_owned(), "stop".to_owned(), "rust-reality.service".to_owned()]
        }));
        assert!(
            transport
                .copies
                .iter()
                .any(|path| path.ends_with("/rust-reality.service"))
        );
    }

    #[test]
    fn fake_cutover_switches_both_pointer_pairs_and_records_pending() {
        let topology = Topology::canonical().unwrap();
        let host = topology.host(HostRole::Line);
        let before = snapshot();
        let artifact = artifact();
        let plan = plan_cutover(&before, &artifact).unwrap();
        assert!(plan.actions.iter().any(|action| matches!(action, DeploymentAction::RecordPending { .. })));
        let mut transport = FakeTransport::new();
        let report = execute(
            &mut transport,
            &mut FakeValidator::default(),
            host,
            &plan,
            &before,
            Some(&artifact),
            None,
        )
        .unwrap();
        assert_eq!(transport.current, "/opt/rust-reality/releases/r2");
        assert_eq!(transport.previous, "/opt/rust-reality/releases/r1");
        assert_eq!(report.after.executable.as_deref(), Some("/opt/rust-reality/releases/r2/rust-reality"));
        assert!(transport.copies.iter().any(|path| path.ends_with("/pending")));
        assert!(transport.commands.iter().all(|argv| {
            !matches!(argv.first().map(String::as_str), Some("sh" | "bash" | "python3"))
        }));
    }

    #[test]
    fn failed_cutover_start_restores_the_original_current_generation() {
        let topology = Topology::canonical().unwrap();
        let host = topology.host(HostRole::Line);
        let before = snapshot();
        let artifact = artifact();
        let plan = plan_cutover(&before, &artifact).unwrap();
        let mut transport = FakeTransport::new();
        transport.fail_candidate_start = true;
        let error = execute(
            &mut transport,
            &mut FakeValidator::default(),
            host,
            &plan,
            &before,
            Some(&artifact),
            None,
        )
        .unwrap_err();
        assert!(error.contains("rolled back"), "{error}");
        assert_eq!(transport.current, "/opt/rust-reality/releases/r1");
        assert_eq!(transport.config_current, "/etc/rust-reality/releases/r1");
    }

    #[test]
    fn a_new_public_listener_fails_postcondition() {
        let before = snapshot();
        let mut after = before.clone();
        after.listeners.push(Listener {
            address: "0.0.0.0".to_owned(),
            port: 8080,
        });
        let error = verify_snapshot(
            &before,
            &after,
            "/opt/rust-reality/releases/r1/rust-reality",
        )
        .unwrap_err();
        assert!(error.contains("introduced public listeners"), "{error}");
    }
}
