//! The typed deployment transaction: snapshots become plans, plans become
//! actions, actions are executed or replayed.
//!
//! The legacy `deploy-release-vps.sh` spread one transaction across four shell
//! subcommands (preflight/bootstrap/stage/cutover/rollback/promote) with the
//! rollback policy embedded in a remote `trap ERR`. This module owns the same
//! transaction as data: [`DeploymentPlan`] is a validated sequence of
//! [`DeploymentAction`]s derived from a [`super::snapshot::HostSnapshot`] and a
//! candidate [`ArtifactIdentity`], and the failure path is a constructed
//! [`RollbackPlan`] rather than a shell trap.
//!
//! Policy decisions live here; mechanism (SSH, scp, systemd) stays with the
//! executor. The plan is intentionally explicit about every remote mutation so
//! `cargo dev deploy plan` can show an operator exactly what would happen
//! before anything runs.

use std::fmt::Write as _;

use crate::perf::json_out::Json;

/// The remote directory layout a deployment maintains (release generations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `/opt/rust-reality/releases` — replaceable binary generations.
    pub releases: String,
    /// `/etc/rust-reality/releases` — replaceable config generations.
    pub config_releases: String,
    /// `/opt/rust-reality/current` — symlink to the active binary generation.
    pub current_binary: String,
    /// `/opt/rust-reality/previous` — symlink to the rollback binary generation.
    pub previous_binary: String,
    /// `/etc/rust-reality/current` — symlink to the active config generation.
    pub current_config: String,
    /// `/etc/rust-reality/previous` — symlink to the rollback config generation.
    pub previous_config: String,
    /// `/var/lib/rust-reality/deployment` — deployment state records.
    pub state: String,
}

impl Paths {
    /// The canonical layout the deployment doc documents.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            releases: "/opt/rust-reality/releases".to_owned(),
            config_releases: "/etc/rust-reality/releases".to_owned(),
            current_binary: "/opt/rust-reality/current".to_owned(),
            previous_binary: "/opt/rust-reality/previous".to_owned(),
            current_config: "/etc/rust-reality/current".to_owned(),
            previous_config: "/etc/rust-reality/previous".to_owned(),
            state: "/var/lib/rust-reality/deployment".to_owned(),
        }
    }
}

/// The exact identity a candidate binary/config pair must present.
///
/// Every field is checked before the executor touches the remote host: the
/// local file digests, the candidate's self-reported version, and the source
/// commit embedded in the binary. Identity is the anti-TOCTOU anchor — the
/// staged bytes are re-digested remotely and must match byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIdentity {
    /// Release generation id (`[A-Za-z0-9][A-Za-z0-9._-]{0,95}`).
    pub release_id: String,
    /// Local candidate binary path.
    pub binary_path: String,
    /// Local candidate config path.
    pub config_path: String,
    /// Expected lowercase SHA-256 of the candidate binary.
    pub binary_sha256: String,
    /// Expected `rust-reality X.Y.Z` version of the candidate binary.
    pub version: String,
    /// The 40-hex source commit the candidate binary embeds.
    pub source_commit: Option<String>,
}

impl ArtifactIdentity {
    /// Validates the identity's shape contracts.
    ///
    /// # Errors
    ///
    /// Returns every violated contract as one message.
    pub fn validate(&self) -> Result<(), String> {
        let mut failures = Vec::new();
        let id_ok = {
            let bytes = self.release_id.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 96
                && bytes[0].is_ascii_alphanumeric()
                && bytes[1..]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        };
        if !id_ok {
            failures.push("release_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,95}".to_owned());
        }
        if self.binary_sha256.len() != 64 || self.binary_sha256.bytes().any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase()) {
            failures.push("binary_sha256 must be 64 lowercase hex characters".to_owned());
        }
        let version_ok = {
            let parts: Vec<&str> = self.version.split(['.', '-']).collect();
            parts.len() >= 3
                && parts[..3].iter().all(|part| {
                    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                })
                && parts[2..]
                    .iter()
                    .all(|part| !part.is_empty())
                && self.version.bytes().next().is_some_and(|byte| byte.is_ascii_digit())
        };
        if !version_ok {
            failures.push("version must be a semantic version like 1.9.0".to_owned());
        }
        if !self.binary_path.starts_with('/') {
            failures.push("binary_path must be absolute".to_owned());
        }
        if !self.config_path.starts_with('/') {
            failures.push("config_path must be absolute".to_owned());
        }
        if let Some(commit) = &self.source_commit
            && (commit.len() != 40
                || commit
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase()))
        {
            failures.push("source_commit must be 40 lowercase hex characters".to_owned());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

/// One typed remote mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentAction {
    /// Create the release directories and install the staged candidate into
    /// them without touching CURRENT.
    Stage {
        /// Release generation directory name.
        release_id: String,
        /// Expected binary SHA-256; the executor re-digests the staged bytes.
        binary_sha256: String,
    },
    /// Point `previous` at the current generation, then atomically move
    /// `current` to the candidate generation (the cutover switch).
    SwitchCurrent {
        /// Release generation being cut over to.
        release_id: String,
    },
    /// Restart the systemd unit and wait for the executable identity and the
    /// 443 listener to come back.
    RestartService,
    /// Verify the running process's executable path and that 443 is listening.
    VerifyService {
        /// The binary path the running process must present.
        expected_binary: String,
    },
    /// Reject the cutover when a new public listener appeared.
    VerifyNoNewPublicListeners,
    /// Remove the `pending` marker after a successful promote.
    ClearPending,
    /// Restore the pending state file naming the rolled-back generation.
    RecordPending {
        /// The release id that is pending promote.
        release_id: String,
    },
    /// Write the durable record naming the accepted current generation.
    RecordPromoted {
        /// Release id that passed the canary and is now accepted.
        release_id: String,
    },
    /// Delete release generations other than CURRENT and PREVIOUS.
    PruneOldReleases,
}

impl DeploymentAction {
    /// A short human-readable verb for the action, for plan listings.
    #[must_use]
    pub fn verb(&self) -> &'static str {
        match self {
            Self::Stage { .. } => "stage",
            Self::SwitchCurrent { .. } => "switch-current",
            Self::RestartService => "restart-service",
            Self::VerifyService { .. } => "verify-service",
            Self::VerifyNoNewPublicListeners => "verify-no-new-public-listeners",
            Self::ClearPending => "clear-pending",
            Self::RecordPending { .. } => "record-pending",
            Self::RecordPromoted { .. } => "record-promoted",
            Self::PruneOldReleases => "prune-old-releases",
        }
    }

    /// The action as evidence JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        match self {
            Self::Stage { release_id, binary_sha256 } => Json::object([
                ("action", Json::string("stage")),
                ("releaseId", Json::string(release_id.clone())),
                ("binarySha256", Json::string(binary_sha256.clone())),
            ]),
            Self::SwitchCurrent { release_id } => Json::object([
                ("action", Json::string("switch-current")),
                ("releaseId", Json::string(release_id.clone())),
            ]),
            Self::RestartService => Json::object([("action", Json::string("restart-service"))]),
            Self::VerifyService { expected_binary } => Json::object([
                ("action", Json::string("verify-service")),
                ("expectedBinary", Json::string(expected_binary.clone())),
            ]),
            Self::VerifyNoNewPublicListeners => {
                Json::object([("action", Json::string("verify-no-new-public-listeners"))])
            }
            Self::ClearPending => Json::object([("action", Json::string("clear-pending"))]),
            Self::RecordPending { release_id } => Json::object([
                ("action", Json::string("record-pending")),
                ("releaseId", Json::string(release_id.clone())),
            ]),
            Self::RecordPromoted { release_id } => Json::object([
                ("action", Json::string("record-promoted")),
                ("releaseId", Json::string(release_id.clone())),
            ]),
            Self::PruneOldReleases => {
                Json::object([("action", Json::string("prune-old-releases"))])
            }
        }
    }
}

/// Which transaction a plan encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    /// Validate and install a candidate without touching CURRENT.
    Stage,
    /// Cut CURRENT over to a staged candidate with automatic rollback.
    Cutover,
    /// Restore CURRENT from PREVIOUS.
    Rollback,
    /// Confirm the current generation after a successful canary.
    Promote,
}

impl PlanKind {
    /// The lowercase kind name used in evidence.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Cutover => "cutover",
            Self::Rollback => "rollback",
            Self::Promote => "promote",
        }
    }
}

/// A validated deployment plan for one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentPlan {
    /// The transaction kind.
    pub kind: PlanKind,
    /// The SSH alias the plan targets.
    pub target: String,
    /// The ordered actions.
    pub actions: Vec<DeploymentAction>,
    /// Why the plan exists (the snapshot facts that motivated it).
    pub rationale: Vec<String>,
}

impl DeploymentPlan {
    /// Renders the plan as operator-readable JSON evidence.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("kind", Json::string(self.kind.name())),
            ("target", Json::string(self.target.clone())),
            (
                "actions",
                Json::Array(
                    self.actions
                        .iter()
                        .map(DeploymentAction::to_json)
                        .collect(),
                ),
            ),
            (
                "rationale",
                Json::Array(self.rationale.iter().map(|line| Json::string(line.clone())).collect()),
            ),
        ])
    }

    /// A one-line-per-action rendering for terminal display.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut text = String::new();
        let _ = writeln!(text, "plan {} -> {}", self.kind.name(), self.target);
        for (index, action) in self.actions.iter().enumerate() {
            let _ = writeln!(text, "  {:2}. {}", index + 1, action.verb());
        }
        text
    }
}

/// Plans the `stage` transaction from a snapshot and a candidate identity.
///
/// Staging is deliberately non-mutating on CURRENT: the actions create the
/// release directories, install the staged candidate, and verify its identity —
/// nothing else. The snapshot must show a healthy service; staging into a
/// broken deployment is refused because the operator would be planning a
/// cutover onto a node that cannot serve.
///
/// # Errors
///
/// Returns the identity validation failures, or a snapshot-state rejection.
pub fn plan_stage(
    snapshot: &super::snapshot::HostSnapshot,
    artifact: &ArtifactIdentity,
) -> Result<DeploymentPlan, String> {
    artifact.validate()?;
    let mut rationale = Vec::new();
    if !snapshot.service_healthy() {
        return Err(format!(
            "refusing to stage: {} is not healthy (state={}, 443={})",
            snapshot.alias, snapshot.service_state, snapshot.service_443_present
        ));
    }
    if let Some(sha) = &snapshot.executable_sha256 {
        rationale.push(format!("current executable sha256 {sha}"));
    }
    rationale.push(format!(
        "stage {} without changing CURRENT",
        artifact.release_id
    ));
    let paths = Paths::canonical();
    Ok(DeploymentPlan {
        kind: PlanKind::Stage,
        target: snapshot.alias.clone(),
        actions: vec![
            DeploymentAction::Stage {
                release_id: artifact.release_id.clone(),
                binary_sha256: artifact.binary_sha256.clone(),
            },
            DeploymentAction::VerifyService {
                expected_binary: format!(
                    "{}/{}/rust-reality",
                    paths.releases, artifact.release_id
                ),
            },
        ],
        rationale,
    })
}

/// Plans the `cutover` transaction: the CURRENT/PREVIOUS switch with the full
/// verification ladder, in the same order the shell trap enforced.
///
/// # Errors
///
/// Returns identity validation failures or snapshot-state rejections.
pub fn plan_cutover(
    snapshot: &super::snapshot::HostSnapshot,
    artifact: &ArtifactIdentity,
) -> Result<DeploymentPlan, String> {
    artifact.validate()?;
    if !snapshot.service_healthy() {
        return Err(format!(
            "refusing to cut over: {} is not healthy (state={}, 443={})",
            snapshot.alias, snapshot.service_state, snapshot.service_443_present
        ));
    }
    let Some(previous) = snapshot.generations.as_ref().map(|g| g.current_binary.clone()) else {
        return Err("refusing to cut over: no CURRENT/PREVIOUS generation pointers observed; run bootstrap-equivalent setup first".to_owned());
    };
    let Some(current_binary) = previous else {
        return Err("refusing to cut over: CURRENT pointer unresolved".to_owned());
    };
    let paths = Paths::canonical();
    let new_release = format!("{}/{}", paths.releases, artifact.release_id);
    let new_binary = format!("{new_release}/rust-reality");
    if current_binary == new_release {
        return Err(format!(
            "refusing to cut over: CURRENT already serves {new_binary}"
        ));
    }
    let rationale = vec![
        format!("CURRENT is {current_binary}"),
        format!("PREVIOUS will be {current_binary}"),
        format!("candidate {} ({})", artifact.release_id, artifact.binary_sha256),
    ];
    Ok(DeploymentPlan {
        kind: PlanKind::Cutover,
        target: snapshot.alias.clone(),
        actions: vec![
            // Snapshot the pre-cutover unexpected-public-listener set, then the
            // switch. The rollback is a *constructed* plan, not a shell trap.
            DeploymentAction::SwitchCurrent { release_id: artifact.release_id.clone() },
            DeploymentAction::RestartService,
            DeploymentAction::VerifyService { expected_binary: new_binary.clone() },
            DeploymentAction::VerifyNoNewPublicListeners,
            DeploymentAction::RecordPending { release_id: artifact.release_id.clone() },
        ],
        rationale,
    })
}

/// Plans the `rollback` transaction from a snapshot: CURRENT returns to
/// PREVIOUS, the service restarts, and health is verified before the pending
/// marker is cleared.
///
/// # Errors
///
/// Returns a rejection when the snapshot shows no usable PREVIOUS generation.
pub fn plan_rollback(snapshot: &super::snapshot::HostSnapshot) -> Result<DeploymentPlan, String> {
    let paths = Paths::canonical();
    let Some(generations) = &snapshot.generations else {
        return Err(format!(
            "refusing to roll back {}: no CURRENT/PREVIOUS generation pointers observed",
            snapshot.alias
        ));
    };
    let Some(previous_binary) = generations.previous_binary.clone() else {
        return Err(format!(
            "refusing to roll back {}: PREVIOUS is unresolved",
            snapshot.alias
        ));
    };
    if !previous_binary.starts_with(&format!("{}/", paths.releases)) {
        return Err(format!(
            "refusing to roll back: PREVIOUS {previous_binary} is outside the release root"
        ));
    }
    let rationale = vec![format!("restore CURRENT from PREVIOUS {previous_binary}")];
    Ok(DeploymentPlan {
        kind: PlanKind::Rollback,
        target: snapshot.alias.clone(),
        actions: vec![
            DeploymentAction::SwitchCurrent {
                release_id: release_id_of(&previous_binary),
            },
            DeploymentAction::RestartService,
            DeploymentAction::VerifyService { expected_binary: format!("{previous_binary}/rust-reality") },
            DeploymentAction::VerifyNoNewPublicListeners,
            DeploymentAction::ClearPending,
        ],
        rationale,
    })
}

/// Plans promotion after a successful application-level canary.
///
/// Promotion never restarts the service. It verifies that CURRENT and the live
/// executable still name the requested generation, records the accepted state,
/// clears the pending marker, and optionally prunes every generation other than
/// CURRENT/PREVIOUS.
///
/// # Errors
///
/// Returns a rejection when the snapshot is unhealthy or does not prove that the
/// requested release is the running CURRENT generation.
pub fn plan_promote(
    snapshot: &super::snapshot::HostSnapshot,
    release_id: &str,
    prune_old_releases: bool,
) -> Result<DeploymentPlan, String> {
    validate_release_id(release_id)?;
    if !snapshot.service_healthy() {
        return Err(format!(
            "refusing to promote: {} is not healthy (state={}, 443={})",
            snapshot.alias, snapshot.service_state, snapshot.service_443_present
        ));
    }
    let paths = Paths::canonical();
    let expected_release = format!("{}/{release_id}", paths.releases);
    let expected_config = format!("{}/{release_id}", paths.config_releases);
    let expected_binary = format!("{expected_release}/rust-reality");
    let Some(generations) = &snapshot.generations else {
        return Err("refusing to promote: generation pointers are absent".to_owned());
    };
    if generations.current_binary.as_deref() != Some(expected_release.as_str())
        || generations.current_config.as_deref() != Some(expected_config.as_str())
        || snapshot.executable.as_deref() != Some(expected_binary.as_str())
    {
        return Err(format!(
            "refusing to promote {release_id}: CURRENT/config/executable identity does not match"
        ));
    }
    let mut actions = vec![
        DeploymentAction::VerifyService {
            expected_binary,
        },
        DeploymentAction::RecordPromoted {
            release_id: release_id.to_owned(),
        },
        DeploymentAction::ClearPending,
    ];
    if prune_old_releases {
        actions.push(DeploymentAction::PruneOldReleases);
    }
    Ok(DeploymentPlan {
        kind: PlanKind::Promote,
        target: snapshot.alias.clone(),
        actions,
        rationale: vec![format!(
            "CURRENT {expected_release} passed the application canary"
        )],
    })
}

/// Validates the canonical release-generation id syntax.
///
/// # Errors
///
/// Returns the shared artifact-identity diagnostic when the id is unsafe.
pub fn validate_release_id(release_id: &str) -> Result<(), String> {
    ArtifactIdentity {
        release_id: release_id.to_owned(),
        binary_path: "/unused".to_owned(),
        config_path: "/unused".to_owned(),
        binary_sha256: "0".repeat(64),
        version: "0.0.0".to_owned(),
        source_commit: None,
    }
    .validate()
}

/// Extracts the release generation id from a release-root path.
fn release_id_of(release_dir: &str) -> String {
    release_dir
        .rsplit('/')
        .next()
        .unwrap_or(release_dir)
        .to_owned()
}

/// The rollback counterpart of any mutating plan: restore PREVIOUS, restart,
/// verify, and leave the pending marker intact for operator review.
///
/// A stage cannot fail into a broken service (it never switches CURRENT), so
/// its rollback is the empty plan; cutover and rollback-verify failures roll
/// back; promote failures also roll back because CURRENT is already the
/// candidate and the only safe state is the previous generation.
#[must_use]
pub fn rollback_for(plan: &DeploymentPlan) -> Option<DeploymentPlan> {
    match plan.kind {
        PlanKind::Cutover | PlanKind::Promote => Some(DeploymentPlan {
            kind: PlanKind::Rollback,
            target: plan.target.clone(),
            actions: vec![
                DeploymentAction::SwitchCurrent { release_id: String::from("PREVIOUS") },
                DeploymentAction::RestartService,
                DeploymentAction::VerifyService { expected_binary: String::from("PREVIOUS") },
                DeploymentAction::VerifyNoNewPublicListeners,
            ],
            rationale: vec![format!("automatic rollback of failed {}", plan.kind.name())],
        }),
        // A failed rollback is retried, not rolled back.
        PlanKind::Stage | PlanKind::Rollback => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::snapshot::{GenerationPointers, HostSnapshot, Listener};

    fn healthy_snapshot(alias: &str) -> HostSnapshot {
        HostSnapshot {
            alias: alias.to_owned(),
            service_state: "active".into(),
            pid: Some(4242),
            executable: Some("/opt/rust-reality/releases/r1/rust-reality".into()),
            executable_sha256: Some("a".repeat(64)),
            version: Some("rust-reality 1.8.0".into()),
            listeners: vec![
                Listener { address: "0.0.0.0".into(), port: 22 },
                Listener { address: "[::]".into(), port: 443 },
            ],
            ssh_22_present: true,
            service_443_present: true,
            restarts: Some(0),
            generations: Some(GenerationPointers {
                current_binary: Some("/opt/rust-reality/releases/r1".into()),
                current_config: Some("/etc/rust-reality/releases/r1".into()),
                previous_binary: Some("/opt/rust-reality/releases/r0".into()),
                previous_config: Some("/etc/rust-reality/releases/r0".into()),
            }),
        }
    }

    fn candidate() -> ArtifactIdentity {
        ArtifactIdentity {
            release_id: "r2".into(),
            binary_path: "/build/rust-reality".into(),
            config_path: "/build/config.json".into(),
            binary_sha256: "b".repeat(64),
            version: "1.9.0".into(),
            source_commit: Some("c".repeat(40)),
        }
    }

    #[test]
    fn artifact_identity_validates_shape_contracts() {
        assert!(candidate().validate().is_ok());
        let mut bad = candidate();
        bad.release_id = "-leading-dash".into();
        assert!(bad.validate().is_err());
        bad.release_id = "ok".into();
        bad.binary_sha256 = "XYZ".into();
        assert!(bad.validate().is_err());
        bad.binary_sha256 = "B".repeat(64);
        assert!(bad.validate().is_err(), "uppercase digests are rejected");
        bad.binary_sha256 = "b".repeat(64);
        bad.version = "not-a-version".into();
        assert!(bad.validate().is_err());
        bad.version = "1.9.0".into();
        bad.binary_path = "relative".into();
        assert!(bad.validate().is_err());
        bad.binary_path = "/build/rust-reality".into();
        bad.source_commit = Some("short".into());
        assert!(bad.validate().is_err());
        bad.source_commit = None;
        assert!(bad.validate().is_ok());
    }

    #[test]
    fn stage_plan_touches_nothing_but_the_release_directory() {
        let plan = plan_stage(&healthy_snapshot("line"), &candidate()).unwrap();
        assert_eq!(plan.kind, PlanKind::Stage);
        assert_eq!(plan.actions.len(), 2);
        assert!(matches!(plan.actions[0], DeploymentAction::Stage { .. }));
        assert!(plan.describe().contains("stage"));
    }

    #[test]
    fn stage_refuses_an_unhealthy_snapshot() {
        let mut broken = healthy_snapshot("line");
        broken.service_443_present = false;
        let error = plan_stage(&broken, &candidate()).unwrap_err();
        assert!(error.contains("not healthy"), "{error}");
    }

    #[test]
    fn cutover_plan_orders_switch_restart_verify_and_pending() {
        let plan = plan_cutover(&healthy_snapshot("line"), &candidate()).unwrap();
        assert_eq!(plan.kind, PlanKind::Cutover);
        let verbs: Vec<_> = plan.actions.iter().map(DeploymentAction::verb).collect();
        assert_eq!(
            verbs,
            ["switch-current", "restart-service", "verify-service",
             "verify-no-new-public-listeners", "record-pending"]
        );
        assert!(plan.rationale.iter().any(|line| line.contains("PREVIOUS will be")));
    }

    #[test]
    fn cutover_refuses_redeploying_the_running_generation() {
        let mut snapshot = healthy_snapshot("line");
        snapshot.generations.as_mut().unwrap().current_binary = Some("/opt/rust-reality/releases/r2".into());
        let error = plan_cutover(&snapshot, &candidate()).unwrap_err();
        assert!(error.contains("already serves"), "{error}");
    }

    #[test]
    fn cutover_requires_generation_pointers() {
        let mut snapshot = healthy_snapshot("line");
        snapshot.generations = None;
        let error = plan_cutover(&snapshot, &candidate()).unwrap_err();
        assert!(error.contains("generation pointers"), "{error}");
    }

    #[test]
    fn rollback_plan_restores_previous_and_clears_pending() {
        let plan = plan_rollback(&healthy_snapshot("line")).unwrap();
        let verbs: Vec<_> = plan.actions.iter().map(DeploymentAction::verb).collect();
        assert_eq!(
            verbs,
            ["switch-current", "restart-service", "verify-service",
             "verify-no-new-public-listeners", "clear-pending"]
        );
        assert!(plan.rationale[0].contains("releases/r0"));
    }

    #[test]
    fn rollback_refuses_when_previous_is_outside_the_release_root() {
        let mut snapshot = healthy_snapshot("line");
        snapshot.generations.as_mut().unwrap().previous_binary = Some("/usr/local/bin".into());
        let error = plan_rollback(&snapshot).unwrap_err();
        assert!(error.contains("outside the release root"), "{error}");
    }

    #[test]
    fn rollback_refuses_without_previous() {
        let mut snapshot = healthy_snapshot("line");
        snapshot.generations.as_mut().unwrap().previous_binary = None;
        assert!(plan_rollback(&snapshot).is_err());
    }

    #[test]
    fn rollback_construction_follows_the_plan_kind() {
        let stage = plan_stage(&healthy_snapshot("line"), &candidate()).unwrap();
        assert!(rollback_for(&stage).is_none(), "stage cannot break CURRENT");

        let cutover = plan_cutover(&healthy_snapshot("line"), &candidate()).unwrap();
        let rollback = rollback_for(&cutover).expect("cutover has a rollback");
        assert_eq!(rollback.kind, PlanKind::Rollback);
        assert!(rollback.rationale[0].contains("automatic rollback of failed cutover"));

        let rollback_plan = plan_rollback(&healthy_snapshot("line")).unwrap();
        assert!(rollback_for(&rollback_plan).is_none(), "a failed rollback is retried");
    }

    #[test]
    fn promote_requires_exact_current_identity_and_never_restarts() {
        let mut snapshot = healthy_snapshot("line");
        snapshot.generations.as_mut().unwrap().current_binary =
            Some("/opt/rust-reality/releases/r2".into());
        snapshot.generations.as_mut().unwrap().current_config =
            Some("/etc/rust-reality/releases/r2".into());
        snapshot.executable = Some("/opt/rust-reality/releases/r2/rust-reality".into());
        let plan = plan_promote(&snapshot, "r2", true).unwrap();
        let verbs: Vec<_> = plan.actions.iter().map(DeploymentAction::verb).collect();
        assert_eq!(
            verbs,
            [
                "verify-service",
                "record-promoted",
                "clear-pending",
                "prune-old-releases"
            ]
        );
        assert!(!verbs.contains(&"restart-service"));

        snapshot.executable = Some("/opt/rust-reality/releases/r1/rust-reality".into());
        assert!(plan_promote(&snapshot, "r2", false).is_err());
    }

    #[test]
    fn plan_json_is_renderable_evidence() {
        let plan = plan_cutover(&healthy_snapshot("line"), &candidate()).unwrap();
        let json = plan.to_json().to_compact_json();
        assert!(json.contains("\"kind\": \"cutover\""), "{json}");
        assert!(json.contains("\"actions\""), "{json}");
    }
}
