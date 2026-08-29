//! The paired baseline-versus-candidate suites.
//!
//! `benchmark-setup-rate.sh` and `benchmark-fallback-ab.sh` answer a narrower
//! question than the Xray comparator: not "how do we compare to Xray" but "did
//! *this change* make things worse". Both sides are rust-reality — a pinned
//! baseline ELF and the candidate — so the comparison is only as good as its
//! control of drift. That is why these harnesses block: each block measures both
//! sides twice in `A B B A` order, the block's statistic is the ratio of its two
//! medians, and the cell reports the median ratio with a seeded block bootstrap.
//!
//! Everything here follows from that. An unbalanced block is an error rather than
//! something to average over. Each slot gets fresh processes, fresh ports and a
//! fresh identity, so no state carries between measurements. The binaries are
//! re-hashed after every slot, because a build that changed mid-run would silently
//! attribute one side's numbers to the other's artifact.
//!
//! ## Attestation divergence, stated plainly
//!
//! `environment.json` keeps its schema, but two of its harness fields described
//! things that no longer exist. `harness.contract` was `benchmark-contract.sh` and
//! `harness.keeperHelper` was the dedicated keeper process that held the only lock
//! file descriptor. The native lock is an atomic lock *directory*
//! ([`crate::bench::host_lock`]) with no keeper at all, so both are recorded as
//! `null`. Emitting a hash for a file that is not there would be a false
//! attestation, and a null is a greppable signal that a run used the native
//! harness. `harness.entrypoint` now attests the `rr-dev` executable, which is the
//! equivalent input.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{
    bench::{
        aggregate, attest, attribution,
        config::{self, RealityIdentity},
        cover::{self, CoverMode, PoolSummary, ProfileSummary, Role},
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        origin_go, origin_tls,
        plan::{self, PortLayout, Slot},
        process::Child,
        slot::{self, Attribution},
        workload::{SampleRow, SetupRatePlan},
        workspace::Workspace,
    },
    hash,
    perf::json_out::Json,
    process::Tool,
};

/// Readiness deadline for a slot's server and client.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The two labels the paired harnesses alternate between.
pub const PAIRED_LABELS: [&str; 2] = ["baseline", "candidate"];

/// The `method` string the paired `environment.json` records.
const ENVIRONMENT_METHOD: &str = "balanced block ABBA";

/// Everything the paired setup-rate suite needs.
#[derive(Debug, Clone)]
pub struct SetupRateSuite {
    /// Repository root, used to build the Go origin and read repository state.
    pub repo: PathBuf,
    /// The pinned baseline ELF.
    pub baseline_bin: PathBuf,
    /// The candidate ELF under test.
    pub candidate_bin: PathBuf,
    /// The Xray binary, used only as the SOCKS client for both sides.
    pub xray_bin: PathBuf,
    /// The baseline's identity sidecar, binding its commit and digest.
    pub baseline_identity: Option<PathBuf>,
    /// The commit the sidecar must name, when the caller pins one.
    pub baseline_commit: Option<String>,
    /// Output directory; must not already exist.
    pub out_dir: PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// ABBA blocks, 3..=20.
    pub blocks: usize,
    /// Samples per concurrency level per slot.
    pub samples: usize,
    /// Connections per sample.
    pub connections: usize,
    /// Concurrency levels.
    pub concurrencies: Vec<usize>,
    /// Which label leads block one.
    pub abba_start: String,
    /// Cover mode for the baseline side.
    pub baseline_cover_mode: CoverMode,
    /// Cover mode for the candidate side.
    pub candidate_cover_mode: CoverMode,
    /// How the server's CPU is attributed.
    pub attribution: Attribution,
    /// One-leg netem delay in milliseconds, when the cover leg is shaped.
    pub cover_netem_rtt_ms: Option<u32>,
}

/// What a paired run produced.
#[derive(Debug)]
pub struct SuiteOutcome {
    /// The published output directory.
    pub out_dir: PathBuf,
    /// The `summary.json` document.
    pub summary_json: String,
    /// Number of slots measured.
    pub slot_count: usize,
}

/// Validates the paired setup-rate parameters, reproducing the script's guards.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(suite: &SetupRateSuite) -> Result<(), String> {
    if !(3..=20).contains(&suite.blocks) {
        return Err(format!("BLOCKS must be in 3..20, got {}", suite.blocks));
    }
    if suite.samples == 0 {
        return Err("SAMPLES must be positive".to_owned());
    }
    if suite.connections == 0 {
        return Err("CONNS must be positive".to_owned());
    }
    if !PAIRED_LABELS.contains(&suite.abba_start.as_str()) {
        return Err(format!(
            "ABBA_START must be baseline or candidate, got {}",
            suite.abba_start
        ));
    }
    if suite.concurrencies.is_empty() || suite.concurrencies.contains(&0) {
        return Err("every concurrency must be a positive integer".to_owned());
    }
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if let Some(rtt) = suite.cover_netem_rtt_ms
        && !(1..=2000).contains(&rtt)
    {
        return Err("COVER_NETEM_RTT_MS must be an integer in 1..2000".to_owned());
    }
    Ok(())
}

/// Refuses a port block that overlaps the kernel's ephemeral range.
///
/// The load driver's own outbound sockets come from that range. A benchmark port
/// that collides with one mid-run does not fail cleanly — it produces a slot that
/// cannot bind, or worse, one that binds to a socket the driver wanted.
///
/// # Errors
///
/// Returns a message when the range cannot be read or the block overlaps it.
pub fn check_ephemeral_range(base: u16, count: usize) -> Result<(), String> {
    let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .map_err(|error| format!("cannot verify the Linux ephemeral port range: {error}"))?;
    let mut fields = raw.split_whitespace();
    let (Some(low), Some(high)) = (fields.next(), fields.next()) else {
        return Err("invalid Linux ephemeral port range".to_owned());
    };
    let (Ok(low), Ok(high)) = (low.parse::<u32>(), high.parse::<u32>()) else {
        return Err("invalid Linux ephemeral port range".to_owned());
    };
    let last = u32::from(base) + u32::try_from(count).unwrap_or(u32::MAX) - 1;
    if last < low || u32::from(base) > high {
        return Ok(());
    }
    Err(format!(
        "benchmark port block {base}-{last} overlaps the Linux ephemeral range {low}-{high}"
    ))
}

/// The registered binaries and their attested identity.
struct PairedBinaries {
    baseline: Binary,
    candidate: Binary,
    xray: Binary,
    baseline_build_id: String,
    candidate_build_id: String,
    xray_build_id: String,
}

impl PairedBinaries {
    fn for_role(&self, role: Role) -> (&Binary, &str) {
        match role {
            Role::Baseline => (&self.baseline, &self.baseline_build_id),
            Role::Candidate => (&self.candidate, &self.candidate_build_id),
        }
    }
}

/// Registers and attests every binary the run measures.
fn register_binaries(suite: &SetupRateSuite) -> Result<PairedBinaries, String> {
    // The baseline is a pinned historical ELF; its provenance is the sidecar and
    // the build ID, never a commit it reports about itself.
    let baseline = identity::register("baseline", &suite.baseline_bin, "", Kind::Prebuilt)?;
    let candidate = identity::register("candidate", &suite.candidate_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let baseline_build_id = attest::build_id(&baseline.path)?;
    let candidate_build_id = attest::build_id(&candidate.path)?;
    let xray_build_id = attest::build_id(&xray.path)?;
    if let Some(sidecar) = &suite.baseline_identity {
        // The sidecar is the only way a prebuilt ELF whose source is no longer
        // checked out stays attributable, so a mismatch is fatal rather than
        // advisory. `--baseline-commit` pins which commit it must name.
        attest::verify_identity_sidecar(
            sidecar,
            suite.baseline_commit.as_deref(),
            &baseline.sha256,
        )?;
    }
    Ok(PairedBinaries {
        baseline,
        candidate,
        xray,
        baseline_build_id,
        candidate_build_id,
        xray_build_id,
    })
}

/// Runs the paired setup-rate suite end to end.
///
/// # Errors
///
/// Returns the first failure. Every resource is RAII-owned, so an error return
/// still stops the processes, removes the workspace, and releases the host lock.
pub fn run_setup_rate(suite: &SetupRateSuite) -> Result<SuiteOutcome, String> {
    validate(suite)?;
    for program in ["go", "openssl"] {
        if !Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    match suite.attribution {
        Attribution::Perf(_) if !Tool::exists("perf") => {
            return Err("MEASURE_MODE=perf requires perf".to_owned());
        }
        _ => {}
    }

    let binaries = register_binaries(suite)?;
    let repository = attest::repository_state(&suite.repo, attest::Dirtiness::IncludingUntracked)?;
    let lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("benchmark-setup-rate")?;

    let slot_count = suite.blocks * 4;
    let port_count = 2 + slot_count * 2;
    let port_base = crate::bench::workspace::reserve_block(port_count)?;
    check_ephemeral_range(port_base, port_count)?;
    let (plain_port, tls_port) = (port_base, port_base + 1);

    let origin_manifest = attest::snapshot_tree(&suite.repo.join(origin_go::SOURCE_RELATIVE))?;
    let _origins = start_origins(suite, &workspace, plain_port, tls_port)?;
    let cover_target = format!("127.0.0.1:{tls_port}");

    let slots = plan::abba_slots(
        PAIRED_LABELS,
        &suite.abba_start,
        suite.blocks,
        PortLayout::ServerAndSocksAfterTwoOrigins { base: port_base },
    )?;
    run.write_new("order.json", &plan::order_json(&slots).to_python_json())?;

    // The early environment copy, before the run has completed; the publication
    // renames the finished document over it.
    let environment = environment_json(
        suite,
        &binaries,
        &repository,
        &origin_manifest,
        &lock,
        port_base,
        port_count,
        &cover_target,
    );
    run.write_new("environment.json", &environment.to_python_json())?;

    let mut measured = Vec::with_capacity(slot_count);
    for entry in &slots {
        measured.push(measure_slot(
            suite,
            &binaries,
            &run,
            &workspace,
            entry,
            plain_port,
            &cover_target,
        )?);
    }

    // Re-hash every binary: a build that changed mid-run would attribute one
    // side's numbers to the other's artifact.
    for binary in [&binaries.baseline, &binaries.candidate, &binaries.xray] {
        let observed = hash::sha256_file(&binary.path)?;
        if observed != binary.sha256 {
            return Err(format!("{} binary changed during run", binary.label));
        }
    }

    let summary = summarise(suite, &measured)?;
    let summary_json = summary.to_python_json();
    run.write_new("summary.json", &summary_json)?;
    let raw: Vec<String> = measured
        .iter()
        .flat_map(|slot| slot.rows.iter())
        .map(|row| row.to_json(false).to_compact_json())
        .collect();
    run.write_jsonl("raw-samples.jsonl", &raw)?;
    run.publish(
        Publication::Environment,
        &environment.to_python_json(),
        &suite.run_id,
        "benchmark-setup-rate",
    )?;

    Ok(SuiteOutcome {
        out_dir: suite.out_dir.clone(),
        summary_json,
        slot_count,
    })
}

/// Builds the Go origin and starts both listeners, returning their RAII guards.
fn start_origins(
    suite: &SetupRateSuite,
    workspace: &Workspace,
    plain_port: u16,
    tls_port: u16,
) -> Result<(Child, Child), String> {
    let binary = origin_go::build(&suite.repo, workspace)?;
    origin_go::write_setup_payload(workspace.path())?;
    let (cert, key) = origin_tls::generate_self_signed(workspace.path())?;
    let plain_origin = origin_go::start(
        &binary,
        workspace,
        &origin_go::OriginPlan {
            label: "origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: plain_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
        },
    )?;
    let tls_origin = origin_go::start(
        &binary,
        workspace,
        &origin_go::OriginPlan {
            label: "origin-https".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: tls_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("https-put.jsonl"),
            tls: Some((cert, key)),
        },
    )?;
    Ok((plain_origin, tls_origin))
}

/// What one measured paired slot contributed.
struct MeasuredSlot {
    slot: Slot,
    task_clock_ms: Option<f64>,
    rows: Vec<SampleRow>,
    pool: Option<PoolSummary>,
    profile: Option<ProfileSummary>,
}

/// The role a slot's implementation label denotes.
fn role_of(label: &str) -> Role {
    if label == "baseline" {
        Role::Baseline
    } else {
        Role::Candidate
    }
}

/// Generates a slot's fresh REALITY identity and writes both configs.
#[expect(
    clippy::too_many_arguments,
    reason = "a slot's configuration inputs are exactly these"
)]
fn write_slot_configs(
    suite: &SetupRateSuite,
    workspace: &Workspace,
    slot_dir: &Path,
    name: &str,
    binary: &Binary,
    role: Role,
    server_port: u16,
    socks_port: u16,
    cover_target: &str,
) -> Result<(), String> {
    let rust_identity = crate::bench::suites::generate_rust_identity(
        workspace,
        &binary.path,
        server_port,
        cover_target,
        "localhost",
        Some(&slot_dir.join("generate.log")),
    )?;
    let mode = match role {
        Role::Baseline => suite.baseline_cover_mode,
        Role::Candidate => suite.candidate_cover_mode,
    };
    let server_config = cover::apply(
        &rust_identity.server_json,
        mode,
        role,
        suite.cover_netem_rtt_ms.is_some(),
    )?;
    let server_path = workspace.join(&format!("{name}.server.json"));
    std::fs::write(&server_path, &server_config)
        .map_err(|error| format!("could not write {}: {error}", server_path.display()))?;

    let reality = RealityIdentity {
        uuid: rust_identity.uuid.clone(),
        short_id: rust_identity.short_id.clone(),
        server_name: "localhost".to_owned(),
        target: cover_target.to_owned(),
    };
    let client_config =
        config::xray_client(&reality, server_port, socks_port, &rust_identity.public_key)
            .to_python_json();
    let client_path = workspace.join(&format!("{name}.client.json"));
    std::fs::write(&client_path, &client_config)
        .map_err(|error| format!("could not write {}: {error}", client_path.display()))
}

/// Launches a slot's rust server and its Xray SOCKS client, waiting for both.
fn launch_slot(
    suite: &SetupRateSuite,
    workspace: &Workspace,
    slot_dir: &Path,
    name: &str,
    binary: &Binary,
    server_port: u16,
    socks_port: u16,
) -> Result<(Child, Child), String> {
    let mut server = Child::spawn(
        format!("{name}-server"),
        &binary.path,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            workspace
                .join(&format!("{name}.server.json"))
                .display()
                .to_string(),
        ],
        workspace.path(),
        &[],
        &slot_dir.join("server.log"),
    )
    .map_err(|error| error.to_string())?;
    let mut client = Child::spawn(
        format!("{name}-client"),
        &suite.xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            workspace
                .join(&format!("{name}.client.json"))
                .display()
                .to_string(),
        ],
        workspace.path(),
        &[],
        &slot_dir.join("client.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    Ok((server, client))
}

/// Runs one paired slot: configure, launch, warm up, measure, record, tear down.
fn measure_slot(
    suite: &SetupRateSuite,
    binaries: &PairedBinaries,
    run: &RunDirectory,
    workspace: &Workspace,
    entry: &Slot,
    plain_port: u16,
    cover_target: &str,
) -> Result<MeasuredSlot, String> {
    let name = entry.directory_name();
    let slot_dir = run.slot_directory(&name)?;
    let role = role_of(&entry.implementation);
    let (binary, build_id) = binaries.for_role(role);
    let server_port = entry
        .server_port
        .ok_or_else(|| format!("{name} has no planned server port"))?;
    let socks_port = entry
        .socks_port
        .ok_or_else(|| format!("{name} has no planned SOCKS port"))?;

    write_slot_configs(
        suite, workspace, &slot_dir, &name, binary, role, server_port, socks_port, cover_target,
    )?;
    let (mut server, mut client) = launch_slot(
        suite,
        workspace,
        &slot_dir,
        &name,
        binary,
        server_port,
        socks_port,
    )?;
    let server_pid = server.pid();
    slot::verify_running_image(server_pid, &binary.sha256, &entry.implementation)?;

    let workload = SetupRatePlan {
        socks_port,
        origin_port: plain_port,
        connections: suite.connections,
        concurrencies: suite.concurrencies.clone(),
        samples: suite.samples,
        implementation: entry.implementation.clone(),
        block: entry.block,
        position: entry.position,
        // benchmark-setup-rate.sh works from the per-row percentiles, so the raw
        // latency vectors are not carried into its evidence.
        record_latencies: false,
    };
    slot::warm_up(&workload, workspace.path())?;

    let samples_path = slot_dir.join("samples.json");
    let perf_csv = slot_dir.join("perf.csv");
    slot::drive(
        &workload,
        &samples_path,
        suite.attribution,
        server_pid,
        &perf_csv,
        workspace.path(),
    )?;

    let task_clock_ms = match suite.attribution {
        Attribution::Wall => None,
        Attribution::Perf(_) => {
            let raw = std::fs::read_to_string(&perf_csv)
                .map_err(|error| format!("could not read {}: {error}", perf_csv.display()))?;
            let record = attribution::parse_csv(&raw, &attribution::REQUIRED_EVENTS)?;
            std::fs::write(slot_dir.join("perf.json"), record.to_json().to_python_json())
                .map_err(|error| format!("could not write the slot perf record: {error}"))?;
            Some(record.task_clock_milliseconds)
        }
    };

    let rows = crate::bench::ab_suites::read_rows(&samples_path)?;
    write_slot_identity(
        &slot_dir,
        entry,
        &binary.path,
        &binary.sha256,
        build_id,
        server_pid,
        server_port,
        socks_port,
    )?;

    client.terminate();
    server.terminate();

    // The cover counters only exist on a candidate slot under the shaped leg,
    // which is the only configuration that both emits and requires them.
    let (pool, profile) = collect_cover_counters(suite, &slot_dir, role)?;

    Ok(MeasuredSlot {
        slot: entry.clone(),
        task_clock_ms,
        rows,
        pool,
        profile,
    })
}

/// Extracts the cover counters a candidate slot under the shaped leg must report.
///
/// That is the only configuration that both emits and requires them: the shaped
/// leg raises the log level to `info`, and the whole point of shaping the cover
/// path is to observe whether pooling and pre-built profiles actually help.
fn collect_cover_counters(
    suite: &SetupRateSuite,
    slot_dir: &Path,
    role: Role,
) -> Result<(Option<PoolSummary>, Option<ProfileSummary>), String> {
    if role != Role::Candidate || suite.cover_netem_rtt_ms.is_none() {
        return Ok((None, None));
    }
    let log = std::fs::read_to_string(slot_dir.join("server.log"))
        .map_err(|error| format!("could not read the slot server log: {error}"))?;
    let pool = cover::extract_pool_summary(&log)?;
    std::fs::write(
        slot_dir.join("pool-summary.json"),
        pool_json(&pool).to_python_json(),
    )
    .map_err(|error| format!("could not write the pool summary: {error}"))?;
    let profile = if matches!(
        suite.candidate_cover_mode,
        CoverMode::Prebuilt | CoverMode::Default
    ) {
        let profile = cover::extract_profile_summary(&log)?;
        std::fs::write(
            slot_dir.join("profile-summary.json"),
            profile_json(&profile).to_python_json(),
        )
        .map_err(|error| format!("could not write the profile summary: {error}"))?;
        Some(profile)
    } else {
        None
    };
    Ok((Some(pool), profile))
}

fn pool_json(pool: &PoolSummary) -> Json {
    Json::object([
        ("pool_checkout_total", Json::Int(pool.checkout_total)),
        ("pool_checkout_hit", Json::Int(pool.checkout_hit)),
        ("pool_checkout_miss", Json::Int(pool.checkout_miss)),
        ("pool_cold_fallback", Json::Int(pool.cold_fallback)),
        ("pool_stale_discard", Json::Int(pool.stale_discard)),
        ("warmHitRatio", Json::Float(pool.warm_hit_ratio())),
    ])
}

fn profile_json(profile: &ProfileSummary) -> Json {
    Json::object([
        ("cover_profile_hit", Json::Int(profile.hit)),
        ("cover_profile_miss", Json::Int(profile.miss)),
        ("cover_profile_stale", Json::Int(profile.stale)),
        ("cover_profile_unstable", Json::Int(profile.unstable)),
        ("cover_profile_refresh", Json::Int(profile.refresh)),
        (
            "cover_profile_refresh_failure",
            Json::Int(profile.refresh_failure),
        ),
        (
            "cover_profile_disagreement",
            Json::Int(profile.disagreement),
        ),
        ("cover_profile_validated", Json::Int(profile.validated)),
        ("profileHitRatio", Json::Float(profile.profile_hit_ratio())),
    ])
}

/// Writes the paired slot's `identity.json`.
#[expect(
    clippy::too_many_arguments,
    reason = "these are exactly the fields the recorded identity carries"
)]
fn write_slot_identity(
    slot_dir: &Path,
    entry: &Slot,
    binary: &Path,
    sha256: &str,
    build_id: &str,
    server_pid: u32,
    server_port: u16,
    socks_port: u16,
) -> Result<(), String> {
    let document = Json::object([
        (
            "block",
            Json::Int(i64::try_from(entry.block).unwrap_or(i64::MAX)),
        ),
        (
            "position",
            Json::Int(i64::try_from(entry.position).unwrap_or(i64::MAX)),
        ),
        (
            "implementation",
            Json::string(entry.implementation.clone()),
        ),
        (
            "binary",
            Json::object([
                ("path", Json::string(binary.display().to_string())),
                ("sha256", Json::string(sha256)),
                ("buildId", Json::string(build_id)),
            ]),
        ),
        (
            "process",
            Json::object([("serverPid", Json::Int(i64::from(server_pid)))]),
        ),
        (
            "ports",
            Json::object([
                ("server", Json::Int(i64::from(server_port))),
                ("socks", Json::Int(i64::from(socks_port))),
            ]),
        ),
    ]);
    std::fs::write(slot_dir.join("identity.json"), document.to_python_json())
        .map_err(|error| format!("could not write the slot identity: {error}"))
}

/// Aggregates the paired slots into `summary.json` schema 3.
fn summarise(suite: &SetupRateSuite, measured: &[MeasuredSlot]) -> Result<Json, String> {
    let expected_slots = suite.blocks * 4;
    if measured.len() != expected_slots {
        return Err(format!(
            "missing ABBA slots: expected {expected_slots}, measured {}",
            measured.len()
        ));
    }
    let expected_rows = suite.samples * suite.concurrencies.len();
    for slot in measured {
        if slot.rows.len() != expected_rows {
            return Err(format!(
                "missing samples: {} has {} of {expected_rows}",
                slot.slot.directory_name(),
                slot.rows.len()
            ));
        }
        if slot
            .rows
            .iter()
            .any(|row| row.failed > 0 || row.connections != suite.connections)
        {
            return Err(format!(
                "failed setup sample: {}",
                slot.slot.directory_name()
            ));
        }
    }

    let mut cells: Vec<(String, Json)> = Vec::with_capacity(suite.concurrencies.len());
    for concurrency in &suite.concurrencies {
        let blocks = collect_blocks(suite, measured, |slot| {
            slot.rows
                .iter()
                .filter(|row| row.concurrency == *concurrency)
                .filter_map(SampleRow::connections_per_second)
                .collect()
        });
        let seed = aggregate::SETUP_RATE_CELL_SEED_BASE + u64::try_from(*concurrency).unwrap_or(0);
        let label = format!("setup-rate:c{concurrency}");
        // Two slots per side per block, each contributing `samples` rows.
        let cell = aggregate::paired_cell(&blocks, 2 * suite.samples, seed, &label)?;
        cells.push((
            concurrency.to_string(),
            aggregate::paired_cell_json(&cell, None),
        ));
    }

    let cpu = cpu_summary(suite, measured)?;
    let pools: Vec<PoolSummary> = measured.iter().filter_map(|s| s.pool.clone()).collect();
    let profiles: Vec<ProfileSummary> =
        measured.iter().filter_map(|s| s.profile.clone()).collect();
    let rows: usize = measured.iter().map(|slot| slot.rows.len()).sum();

    Ok(aggregate::summary_document(
        3,
        aggregate::PAIRED_METHOD,
        measured.len(),
        rows,
        [
            ("cells".to_owned(), Json::object(cells)),
            ("serverCpuPerConnection".to_owned(), cpu),
            ("coverPool".to_owned(), cover::aggregate_pool(&pools)),
            (
                "coverProfile".to_owned(),
                cover::aggregate_profile(&profiles),
            ),
        ],
    ))
}

/// Gathers per-block observations for both sides from a per-slot extractor.
fn collect_blocks(
    suite: &SetupRateSuite,
    measured: &[MeasuredSlot],
    extract: impl Fn(&MeasuredSlot) -> Vec<f64>,
) -> Vec<aggregate::BlockObservations> {
    (1..=suite.blocks)
        .map(|block| {
            let mut observations = aggregate::BlockObservations::default();
            for slot in measured.iter().filter(|slot| slot.slot.block == block) {
                let values = extract(slot);
                if slot.slot.implementation == "baseline" {
                    observations.baseline.extend(values);
                } else {
                    observations.candidate.extend(values);
                }
            }
            observations
        })
        .collect()
}

/// The per-connection CPU comparison, absent outside `perf` mode.
fn cpu_summary(suite: &SetupRateSuite, measured: &[MeasuredSlot]) -> Result<Json, String> {
    if matches!(suite.attribution, Attribution::Wall) {
        return Ok(Json::Null);
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "connection counts are small integers, exact in f64"
    )]
    let per_slot = (suite.samples * suite.concurrencies.len() * suite.connections) as f64;
    if per_slot <= 0.0 {
        return Err("a slot must measure at least one connection".to_owned());
    }
    let mut missing = None;
    let blocks = collect_blocks(suite, measured, |slot| {
        slot.task_clock_ms.map_or_else(Vec::new, |ms| vec![ms * 1000.0 / per_slot])
    });
    for slot in measured {
        if slot.task_clock_ms.is_none() {
            missing = Some(slot.slot.directory_name());
        }
    }
    if let Some(name) = missing {
        return Err(format!("{name} has no task-clock, so CPU cannot be attributed"));
    }
    // One perf record per slot, two slots per side per block.
    let cell = aggregate::paired_cell(
        &blocks,
        2,
        aggregate::SETUP_RATE_CPU_SEED,
        "setup-rate:cpu",
    )?;
    Ok(aggregate::paired_cell_json(
        &cell,
        Some("microsecondsPerConnection"),
    ))
}

/// Builds the paired `environment.json` (schema 2).
#[expect(
    clippy::too_many_arguments,
    reason = "these are exactly the fields the recorded environment carries"
)]
fn environment_json(
    suite: &SetupRateSuite,
    binaries: &PairedBinaries,
    repository: &attest::RepositoryState,
    origin_manifest: &attest::TreeManifest,
    lock: &HostLock,
    port_base: u16,
    port_count: usize,
    cover_target: &str,
) -> Json {
    let binary_json = |binary: &Binary, build_id: &str| {
        Json::object([
            ("path", Json::string(binary.path.display().to_string())),
            ("sha256", Json::string(binary.sha256.clone())),
            ("buildId", Json::string(build_id)),
        ])
    };
    Json::object([
        ("schemaVersion", Json::Int(2)),
        ("runId", Json::string(suite.run_id.clone())),
        (
            "repository",
            Json::object([
                ("head", Json::string(repository.head.clone())),
                ("dirty", Json::Bool(repository.dirty)),
            ]),
        ),
        ("method", Json::string(ENVIRONMENT_METHOD)),
        (
            "blocks",
            Json::Int(i64::try_from(suite.blocks).unwrap_or(i64::MAX)),
        ),
        (
            "samplesPerSlot",
            Json::Int(i64::try_from(suite.samples).unwrap_or(i64::MAX)),
        ),
        (
            "connectionsPerSample",
            Json::Int(i64::try_from(suite.connections).unwrap_or(i64::MAX)),
        ),
        (
            "concurrencies",
            Json::string(
                suite
                    .concurrencies
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
        ),
        (
            "measureMode",
            Json::string(match suite.attribution {
                Attribution::Wall => "wall",
                Attribution::Perf(_) => "perf",
            }),
        ),
        (
            "ports",
            Json::object([
                ("address", Json::string("127.0.0.1")),
                ("base", Json::Int(i64::from(port_base))),
                (
                    "count",
                    Json::Int(i64::try_from(port_count).unwrap_or(i64::MAX)),
                ),
            ]),
        ),
        ("coverNetwork", cover_network_json(suite, cover_target)),
        (
            "coverModes",
            Json::object([
                (
                    "baseline",
                    Json::string(suite.baseline_cover_mode.as_str()),
                ),
                (
                    "candidate",
                    Json::string(suite.candidate_cover_mode.as_str()),
                ),
            ]),
        ),
        (
            "baseline",
            binary_json(&binaries.baseline, &binaries.baseline_build_id),
        ),
        (
            "candidate",
            binary_json(&binaries.candidate, &binaries.candidate_build_id),
        ),
        ("xray", binary_json(&binaries.xray, &binaries.xray_build_id)),
        ("harness", harness_json(suite, origin_manifest)),
        ("hostExclusiveLock", lock_json(lock)),
    ])
}

/// The cover-network block: where the cover target lives and how it is shaped.
fn cover_network_json(suite: &SetupRateSuite, cover_target: &str) -> Json {
    Json::object([
        ("target", Json::string(cover_target)),
        (
            "netemRttMs",
            suite
                .cover_netem_rtt_ms
                .map_or(Json::Null, |rtt| Json::Int(i64::from(rtt))),
        ),
        (
            "model",
            Json::string(if suite.cover_netem_rtt_ms.is_some() {
                "one-leg-veth-netem"
            } else {
                "loopback"
            }),
        ),
    ])
}

/// The harness block: what produced the measurement, by content.
///
/// `contract` and `keeperHelper` are `null` because the shell contract and its
/// keeper process no longer exist; see the module note. A hash for an absent file
/// would be a false attestation.
fn harness_json(suite: &SetupRateSuite, origin_manifest: &attest::TreeManifest) -> Json {
    let entrypoint = std::env::current_exe().unwrap_or_default();
    let entrypoint_sha = hash::sha256_file(&entrypoint).unwrap_or_default();
    Json::object([
        (
            "entrypoint",
            Json::object([
                ("path", Json::string(entrypoint.display().to_string())),
                ("sha256", Json::string(entrypoint_sha)),
            ]),
        ),
        ("contract", Json::Null),
        ("keeperHelper", Json::Null),
        (
            "benchOrigin",
            Json::object([
                (
                    "path",
                    Json::string(
                        suite
                            .repo
                            .join(origin_go::SOURCE_RELATIVE)
                            .display()
                            .to_string(),
                    ),
                ),
                (
                    "manifestSha256",
                    Json::string(origin_manifest.sha256.clone()),
                ),
                (
                    "fileCount",
                    Json::Int(i64::try_from(origin_manifest.file_count).unwrap_or(i64::MAX)),
                ),
            ]),
        ),
    ])
}

/// The host-exclusive lock attestation.
///
/// The legacy shape carried keeper PID/starttime/exe fields describing a dedicated
/// process that held the only lock file descriptor. The native lock is an atomic
/// lock directory with no keeper, so those fields are absent rather than faked.
fn lock_json(lock: &HostLock) -> Json {
    Json::object([
        ("protocolVersion", Json::Int(1)),
        ("path", Json::string(lock.path().display().to_string())),
        ("deviceInode", Json::string(lock.device_inode())),
        ("mode", Json::string("lockDirectory")),
        ("required", Json::Bool(true)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite() -> SetupRateSuite {
        SetupRateSuite {
            repo: PathBuf::from("/repo"),
            baseline_bin: PathBuf::from("/bin/baseline"),
            candidate_bin: PathBuf::from("/bin/candidate"),
            xray_bin: PathBuf::from("/bin/xray"),
            baseline_identity: None,
            baseline_commit: None,
            out_dir: PathBuf::from("/out/run"),
            run_id: "setup-rate-1".to_owned(),
            blocks: 3,
            samples: 3,
            connections: 96,
            concurrencies: vec![1, 8, 32],
            abba_start: "baseline".to_owned(),
            baseline_cover_mode: CoverMode::Default,
            candidate_cover_mode: CoverMode::Default,
            attribution: Attribution::Perf(&attribution::REQUIRED_EVENTS),
            cover_netem_rtt_ms: None,
        }
    }

    #[test]
    fn the_script_guards_are_reproduced() {
        validate(&suite()).expect("the defaults are valid");

        // BLOCKS is 3..20 here, not 1..20: fewer than three blocks cannot be
        // bootstrapped at all.
        let mut bad = suite();
        bad.blocks = 2;
        assert!(validate(&bad).unwrap_err().contains("3..20"));
        bad.blocks = 21;
        assert!(validate(&bad).unwrap_err().contains("3..20"));

        let mut bad = suite();
        bad.samples = 0;
        assert!(validate(&bad).unwrap_err().contains("SAMPLES"));
        bad = suite();
        bad.connections = 0;
        assert!(validate(&bad).unwrap_err().contains("CONNS"));

        let mut bad = suite();
        bad.abba_start = "rust".to_owned();
        assert!(validate(&bad).unwrap_err().contains("baseline or candidate"));

        let mut bad = suite();
        bad.cover_netem_rtt_ms = Some(0);
        assert!(validate(&bad).unwrap_err().contains("1..2000"));
        bad.cover_netem_rtt_ms = Some(2001);
        assert!(validate(&bad).unwrap_err().contains("1..2000"));
        bad.cover_netem_rtt_ms = Some(50);
        assert!(validate(&bad).is_ok());

        let mut bad = suite();
        bad.run_id = "has/slash".to_owned();
        assert!(validate(&bad).unwrap_err().contains("RUN_ID"));
    }

    /// A block that overlaps the driver's own outbound source ports does not fail
    /// cleanly, so it is refused before anything binds.
    #[test]
    fn a_port_block_overlapping_the_ephemeral_range_is_refused() {
        let Ok(raw) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") else {
            return;
        };
        let mut fields = raw.split_whitespace();
        let low: u16 = fields.next().unwrap().parse().unwrap();
        let high: u16 = fields.next().unwrap().parse().unwrap();

        let error = check_ephemeral_range(low, 4).unwrap_err();
        assert!(error.contains("overlaps the Linux ephemeral range"), "{error}");
        // Straddling the lower edge from below also overlaps.
        assert!(check_ephemeral_range(low - 2, 8).is_err());
        // Entirely below and entirely above are both fine.
        check_ephemeral_range(low - 100, 8).expect("below the range");
        if high < u16::MAX - 100 {
            check_ephemeral_range(high + 1, 8).expect("above the range");
        }
    }

    fn measured(blocks: usize, samples: usize, with_perf: bool) -> Vec<MeasuredSlot> {
        let slots = plan::abba_slots(
            PAIRED_LABELS,
            "baseline",
            blocks,
            PortLayout::ServerAndSocksAfterTwoOrigins { base: 20_000 },
        )
        .unwrap();
        slots
            .into_iter()
            .map(|entry| {
                let candidate = entry.implementation == "candidate";
                let rows = (0..samples)
                    .map(|index| SampleRow {
                        block: entry.block,
                        position: entry.position,
                        implementation: entry.implementation.clone(),
                        concurrency: 1,
                        sample_index: index,
                        connections: 4,
                        failed: 0,
                        // The candidate is twice as fast.
                        wall_seconds: if candidate { 2.0 } else { 4.0 },
                        latencies_seconds: vec![0.01, 0.02, 0.03, 0.04],
                    })
                    .collect();
                MeasuredSlot {
                    slot: entry,
                    task_clock_ms: with_perf.then_some(if candidate { 100.0 } else { 200.0 }),
                    rows,
                    pool: None,
                    profile: None,
                }
            })
            .collect()
    }

    fn small_suite() -> SetupRateSuite {
        let mut suite = suite();
        suite.blocks = 3;
        suite.samples = 1;
        suite.connections = 4;
        suite.concurrencies = vec![1];
        suite
    }

    #[test]
    fn the_summary_is_schema_three_with_paired_cells_and_cpu() {
        let context = small_suite();
        let rendered = summarise(&context, &measured(3, 1, true))
            .unwrap()
            .to_python_json();
        assert!(rendered.contains("\"schemaVersion\": 3"));
        assert!(rendered.contains("block bootstrap"));
        assert!(rendered.contains("\"slotCount\": 12"));
        // The candidate is twice as fast, so the throughput ratio is 2.
        assert!(rendered.contains("\"medianCandidateVsBaseline\": 2.0"));
        assert!(rendered.contains("\"bootstrap95\""));
        // It also uses half the CPU per connection.
        assert!(rendered.contains("\"unit\": \"microsecondsPerConnection\""));
        // No shaped cover leg, so no cover counters were collected.
        assert!(rendered.contains("\"coverPool\": null"));
        assert!(rendered.contains("\"coverProfile\": null"));
    }

    #[test]
    fn wall_mode_records_a_null_cpu_summary() {
        let mut context = small_suite();
        context.attribution = Attribution::Wall;
        let rendered = summarise(&context, &measured(3, 1, false))
            .unwrap()
            .to_python_json();
        assert!(rendered.contains("\"serverCpuPerConnection\": null"));
    }

    #[test]
    fn a_short_or_failed_slot_is_refused() {
        let context = small_suite();

        let mut slots = measured(3, 1, true);
        slots.truncate(11);
        assert!(
            summarise(&context, &slots)
                .unwrap_err()
                .contains("missing ABBA slots")
        );

        let mut slots = measured(3, 1, true);
        slots[2].rows[0].failed = 1;
        assert!(
            summarise(&context, &slots)
                .unwrap_err()
                .contains("failed setup sample")
        );

        let mut slots = measured(3, 1, true);
        slots[4].rows.clear();
        assert!(
            summarise(&context, &slots)
                .unwrap_err()
                .contains("missing samples")
        );

        let mut slots = measured(3, 1, true);
        slots[0].task_clock_ms = None;
        assert!(
            summarise(&context, &slots)
                .unwrap_err()
                .contains("no task-clock")
        );
    }

    /// The environment keeps schema 2 and its field names, and says plainly that
    /// the shell contract and keeper no longer exist.
    #[test]
    fn the_environment_records_schema_two_and_the_native_attestation() {
        let binary = |label: &str| Binary {
            label: label.to_owned(),
            path: PathBuf::from(format!("/bin/{label}")),
            sha256: "a".repeat(64),
            identity: "{}".to_owned(),
        };
        let binaries = PairedBinaries {
            baseline: binary("baseline"),
            candidate: binary("candidate"),
            xray: binary("xray"),
            baseline_build_id: "b1".to_owned(),
            candidate_build_id: "b2".to_owned(),
            xray_build_id: "b3".to_owned(),
        };
        let repository = attest::RepositoryState {
            head: "c".repeat(40),
            dirty: false,
        };
        let manifest = attest::TreeManifest {
            sha256: "d".repeat(64),
            file_count: 2,
        };
        let lock_base = std::env::temp_dir().join(format!(
            "rr-paired-env-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let lock = HostLock::acquire(&lock_base).unwrap();

        let rendered = environment_json(
            &suite(),
            &binaries,
            &repository,
            &manifest,
            &lock,
            20_000,
            26,
            "127.0.0.1:8443",
        )
        .to_python_json();

        assert!(rendered.contains("\"schemaVersion\": 2"));
        assert!(rendered.contains("\"method\": \"balanced block ABBA\""));
        assert!(rendered.contains("\"concurrencies\": \"1 8 32\""));
        assert!(rendered.contains("\"measureMode\": \"perf\""));
        assert!(rendered.contains("\"model\": \"loopback\""));
        assert!(rendered.contains("\"netemRttMs\": null"));
        assert!(rendered.contains("\"buildId\": \"b1\""));
        assert!(rendered.contains("\"manifestSha256\""));
        assert!(rendered.contains("\"contract\": null"));
        assert!(rendered.contains("\"keeperHelper\": null"));
        assert!(rendered.contains("\"mode\": \"lockDirectory\""));

        let mut shaped = suite();
        shaped.cover_netem_rtt_ms = Some(50);
        shaped.candidate_cover_mode = CoverMode::Prebuilt;
        let rendered = environment_json(
            &shaped,
            &binaries,
            &repository,
            &manifest,
            &lock,
            20_000,
            26,
            "10.204.0.2:8443",
        )
        .to_python_json();
        assert!(rendered.contains("\"model\": \"one-leg-veth-netem\""));
        assert!(rendered.contains("\"netemRttMs\": 50"));
        assert!(rendered.contains("\"candidate\": \"prebuilt\""));
    }
}
