//! The balanced ABBA suites, as declarative variations on one lifecycle.
//!
//! This module holds the suites that compare two servers slot by slot. The first
//! is the Xray comparator, which `benchmark-setup-rate-xray.sh` existed to close a
//! specific gap: `benchmark-setup-rate.sh` only ever drives *rust* servers and uses
//! Xray solely as the SOCKS client, so it can say whether a candidate build is
//! faster than a baseline build but not whether either is faster than Xray. Here
//! both implementations serve the identical VLESS + REALITY + `xtls-rprx-vision`
//! shape against the same origins, the same unmodified Xray client drives both,
//! and the blocks interleave `rust/xray/xray/rust` so drift cannot favour a side.
//!
//! ## What varies, and what does not
//!
//! The lifecycle is shared and lives in [`crate::bench::plan`],
//! [`crate::bench::slot`], [`crate::bench::workload`], [`crate::bench::aggregate`],
//! [`crate::bench::evidence`] and [`crate::bench::attest`]. What a suite supplies
//! is data: which two labels compete, which binary serves each slot, how its
//! config is built, and what its `identity.json` records.
//!
//! ## Per-slot freshness
//!
//! Each rust slot generates a *fresh* REALITY identity, while every Xray slot
//! shares one pre-generated keypair. That asymmetry is inherited deliberately:
//! `xray x25519` is the comparator's own key-generation path and running it per
//! slot would charge its cost to one side of the comparison.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{
    bench::{
        aggregate, attribution,
        config::{self, RealityIdentity},
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        origin_go,
        origin_tls,
        plan::{self, PortLayout, Slot},
        process::Child,
        slot::{self, Attribution},
        workload::{SampleRow, SetupRatePlan},
        workspace::Workspace,
    },
    perf::json_out::Json,
    process::Tool,
};

/// Readiness deadline for a slot's server and client.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The two labels the comparator alternates between.
pub const COMPARATOR_LABELS: [&str; 2] = ["rust", "xray"];

/// Everything the Xray setup-rate comparator needs.
#[derive(Debug, Clone)]
pub struct ComparatorPlan {
    /// Repository root, used to build the Go origin.
    pub repo: PathBuf,
    /// The rust-reality binary under test.
    pub rust_bin: PathBuf,
    /// The Xray binary, serving one leg and driving both.
    pub xray_bin: PathBuf,
    /// Output directory; must not already exist.
    pub out_dir: PathBuf,
    /// Run identifier recorded in the completion marker.
    pub run_id: String,
    /// ABBA blocks, 1..=20.
    pub blocks: usize,
    /// Samples per concurrency level per slot.
    pub samples: usize,
    /// Connections per sample.
    pub connections: usize,
    /// Concurrency levels.
    pub concurrencies: Vec<usize>,
    /// Which label leads block one: `rust` or `xray`.
    pub abba_start: String,
    /// Whether server CPU is attributed with `perf`.
    pub attribution: Attribution,
}

/// What a comparator run produced.
#[derive(Debug)]
pub struct ComparatorOutcome {
    /// The published output directory.
    pub out_dir: PathBuf,
    /// The `summary.json` document.
    pub summary_json: String,
    /// Number of slots measured.
    pub slot_count: usize,
}

/// Validates the comparator parameters, reproducing the script's guards.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(plan: &ComparatorPlan) -> Result<(), String> {
    if !(1..=20).contains(&plan.blocks) {
        return Err(format!("BLOCKS must be in 1..20, got {}", plan.blocks));
    }
    if plan.samples == 0 || plan.connections == 0 {
        return Err("SAMPLES and CONNS must be positive integers".to_owned());
    }
    if !COMPARATOR_LABELS.contains(&plan.abba_start.as_str()) {
        return Err(format!(
            "ABBA_START must be rust or xray, got {}",
            plan.abba_start
        ));
    }
    if plan.concurrencies.is_empty() || plan.concurrencies.contains(&0) {
        return Err("every concurrency must be a positive integer".to_owned());
    }
    if plan.run_id.is_empty()
        || !plan
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID must be one safe path component".to_owned());
    }
    Ok(())
}

/// Runs the Xray setup-rate comparator end to end.
///
/// # Errors
///
/// Returns the first failure. Every resource is RAII-owned, so an error return
/// still stops the processes, removes the workspace, and releases the host lock.
pub fn run_setup_rate_xray(plan: &ComparatorPlan) -> Result<ComparatorOutcome, String> {
    validate(plan)?;
    for program in ["go", "openssl"] {
        if !Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    if matches!(plan.attribution, Attribution::Perf(_)) && !Tool::exists("perf") {
        return Err("MEASURE_MODE=perf requires perf".to_owned());
    }

    let rust = identity::register("rust-reality", &plan.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &plan.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&plan.out_dir)?;
    let workspace = Workspace::create("benchmark-setup-rate-xray")?;

    // Two origin ports plus a server/SOCKS pair per slot.
    let slot_count = plan.blocks * 4;
    let ports = crate::bench::workspace::reserve_ports(2 + slot_count * 2)?;
    let (plain_port, tls_port) = (ports[0], ports[1]);

    let _origins = start_origins(plan, &workspace, plain_port, tls_port)?;

    // One keypair for every Xray slot; see the module note on per-slot freshness.
    let xray_keys = crate::bench::suites::generate_xray_keys(&plan.xray_bin)?;

    let slots = plan::abba_slots(
        COMPARATOR_LABELS,
        &plan.abba_start,
        plan.blocks,
        PortLayout::Deferred,
    )?;
    run.write_new("order.json", &plan::order_json(&slots).to_python_json())?;

    let cover_target = format!("127.0.0.1:{tls_port}");
    let mut measured = Vec::with_capacity(slot_count);
    for (index, entry) in slots.iter().enumerate() {
        let server_port = ports[2 + index * 2];
        let socks_port = ports[3 + index * 2];
        let binary = if entry.implementation == "rust" {
            &rust.path
        } else {
            &xray.path
        };
        let expected_sha = if entry.implementation == "rust" {
            &rust.sha256
        } else {
            &xray.sha256
        };
        let outcome = measure_slot(
            plan,
            &SlotInputs {
                run: &run,
                workspace: &workspace,
                entry,
                ports: SlotPorts {
                    server: server_port,
                    socks: socks_port,
                    http: plain_port,
                },
                binary,
                expected_sha,
                cover_target: &cover_target,
                xray_keys: &xray_keys,
            },
        )?;
        measured.push(outcome);
    }

    let summary = summarise(plan, &measured)?;
    let summary_json = summary.to_python_json();
    run.write_new("summary.json", &summary_json)?;
    let raw: Vec<String> = measured
        .iter()
        .flat_map(|slot| slot.rows.iter())
        // The comparator strips the raw latency vector from the JSONL: it is
        // already summarised in the cells, and keeping it would multiply the file
        // size by the connection count.
        .map(|row| row.to_json(false).to_compact_json())
        .collect();
    run.write_jsonl("raw-samples.jsonl", &raw)?;

    let contract = contract_json(plan, &rust, &xray, plain_port, tls_port, slot_count);
    run.write_new("run-contract.json", &contract.to_python_json())?;
    run.publish(
        Publication::Contract,
        &contract.to_python_json(),
        &plan.run_id,
        "benchmark-setup-rate-xray",
    )?;

    Ok(ComparatorOutcome {
        out_dir: plan.out_dir.clone(),
        summary_json,
        slot_count,
    })
}

/// Builds the Go origin and starts both listeners, returning their RAII guards.
///
/// The plain listener is the workload's destination; the TLS listener is the
/// REALITY cover target every slot points at.
fn start_origins(
    plan: &ComparatorPlan,
    workspace: &Workspace,
    plain_port: u16,
    tls_port: u16,
) -> Result<(Child, Child), String> {
    let binary = origin_go::build(&plan.repo, workspace)?;
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

/// The three loopback ports one slot uses.
struct SlotPorts {
    server: u16,
    socks: u16,
    http: u16,
}

/// Everything one slot needs, gathered so the lifecycle reads as a sequence.
struct SlotInputs<'a> {
    run: &'a RunDirectory,
    workspace: &'a Workspace,
    entry: &'a Slot,
    ports: SlotPorts,
    binary: &'a Path,
    expected_sha: &'a str,
    cover_target: &'a str,
    xray_keys: &'a crate::bench::suites::XrayKeys,
}

/// What one measured slot contributed.
struct MeasuredSlot {
    slot: Slot,
    server_port: u16,
    socks_port: u16,
    server_pid: u32,
    task_clock_ms: Option<f64>,
    rows: Vec<SampleRow>,
}

/// Builds a slot's server config, client identity and the client's public key.
///
/// A rust slot generates a fresh REALITY identity; an Xray slot draws a fresh
/// client id and short id but shares the run's keypair.
fn slot_configuration(
    inputs: &SlotInputs<'_>,
) -> Result<(String, RealityIdentity, String), String> {
    let entry = inputs.entry;
    let cover_target = inputs.cover_target;
    let xray_keys = inputs.xray_keys;
    let ports = &inputs.ports;
    let workspace = inputs.workspace;
    let binary = inputs.binary;
    if entry.implementation == "rust" {
        let rust_identity = crate::bench::suites::generate_rust_identity(
            workspace,
            binary,
            ports.server,
            cover_target,
            "localhost",
            Some(&inputs.run.slot_directory(&entry.directory_name())?.join("generate.log")),
        )?;
        let reality = RealityIdentity {
            uuid: rust_identity.uuid.clone(),
            short_id: rust_identity.short_id.clone(),
            server_name: "localhost".to_owned(),
            target: cover_target.to_owned(),
        };
        Ok((
            rust_identity.server_json.clone(),
            reality,
            rust_identity.public_key.clone(),
        ))
    } else {
        let reality = RealityIdentity {
            uuid: random_uuid_v4()?,
            short_id: random_short_id()?,
            server_name: "localhost".to_owned(),
            target: cover_target.to_owned(),
        };
        let server = config::xray_server(&reality, ports.server, &xray_keys.private, true);
        Ok((server.to_python_json(), reality, xray_keys.public.clone()))
    }
}

/// Launches a slot's server and its Xray SOCKS client, waiting for both ports.
///
/// A rust server takes `serve --config`; an Xray server takes `run -config`. The
/// client is always Xray, which is the point of the comparison: both legs are
/// driven by the same unmodified client.
fn launch_slot(
    plan: &ComparatorPlan,
    inputs: &SlotInputs<'_>,
    name: &str,
    slot_dir: &Path,
    server_path: &Path,
    client_path: &Path,
) -> Result<(Child, Child), String> {
    let server_args = if inputs.entry.implementation == "rust" {
        vec![
            "serve".to_owned(),
            "--config".to_owned(),
            server_path.display().to_string(),
        ]
    } else {
        vec![
            "run".to_owned(),
            "-config".to_owned(),
            server_path.display().to_string(),
        ]
    };
    let mut server = Child::spawn(
        format!("{name}-server"),
        inputs.binary,
        &server_args,
        inputs.workspace.path(),
        &[],
        &slot_dir.join("server.log"),
    )
    .map_err(|error| error.to_string())?;
    let mut client = Child::spawn(
        format!("{name}-client"),
        &plan.xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_path.display().to_string(),
        ],
        inputs.workspace.path(),
        &[],
        &slot_dir.join("client.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(inputs.ports.server, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    client
        .wait_for_port(inputs.ports.socks, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    Ok((server, client))
}

/// Runs one slot: configure, launch, warm up, measure, record, tear down.
fn measure_slot(plan: &ComparatorPlan, inputs: &SlotInputs<'_>) -> Result<MeasuredSlot, String> {
    let SlotInputs {
        run,
        workspace,
        entry,
        ports,
        expected_sha,
        ..
    } = inputs;
    let name = entry.directory_name();
    let slot_dir = run.slot_directory(&name)?;
    let (server_config, client_identity, public_key) = slot_configuration(inputs)?;

    let server_path = workspace.join(&format!("{name}.server.json"));
    std::fs::write(&server_path, &server_config)
        .map_err(|error| format!("could not write {}: {error}", server_path.display()))?;
    let client_config =
        config::xray_client(&client_identity, ports.server, ports.socks, &public_key)
            .to_python_json();
    let client_path = workspace.join(&format!("{name}.client.json"));
    std::fs::write(&client_path, &client_config)
        .map_err(|error| format!("could not write {}: {error}", client_path.display()))?;

    // The comparator archives both configs beside the slot's evidence.
    std::fs::write(slot_dir.join("server-config.json"), &server_config)
        .map_err(|error| format!("could not archive the server config: {error}"))?;
    std::fs::write(slot_dir.join("client-config.json"), &client_config)
        .map_err(|error| format!("could not archive the client config: {error}"))?;

    let (mut server, mut client) = launch_slot(
        plan,
        inputs,
        &name,
        &slot_dir,
        &server_path,
        &client_path,
    )?;
    let server_pid = server.pid();
    slot::verify_running_image(server_pid, expected_sha, &entry.implementation)?;

    let workload = SetupRatePlan {
        socks_port: ports.socks,
        origin_port: ports.http,
        connections: plan.connections,
        concurrencies: plan.concurrencies.clone(),
        samples: plan.samples,
        implementation: entry.implementation.clone(),
        block: entry.block,
        position: entry.position,
        record_latencies: true,
    };
    slot::warm_up(&workload, workspace.path())?;

    let samples_path = slot_dir.join("samples.json");
    let perf_csv = slot_dir.join("perf.csv");
    slot::drive(
        &workload,
        &samples_path,
        plan.attribution,
        server_pid,
        &perf_csv,
        workspace.path(),
    )?;

    let task_clock_ms = match plan.attribution {
        Attribution::Wall => None,
        Attribution::Perf(_) => {
            let raw = std::fs::read_to_string(&perf_csv)
                .map_err(|error| format!("could not read {}: {error}", perf_csv.display()))?;
            Some(attribution::task_clock_only(&raw)?)
        }
    };

    let rows = read_rows(&samples_path)?;
    write_slot_identity(&slot_dir, entry, ports, server_pid, task_clock_ms)?;

    // Stop the client first, so the server sees clean closes rather than resets.
    client.terminate();
    server.terminate();

    Ok(MeasuredSlot {
        slot: (*entry).clone(),
        server_port: ports.server,
        socks_port: ports.socks,
        server_pid,
        task_clock_ms,
        rows,
    })
}

/// Writes the slot's `identity.json`.
///
/// `serverTaskClockMs` is explicitly `null` outside `perf` mode, so wall-mode
/// evidence can never be read as a CPU measurement of zero.
fn write_slot_identity(
    slot_dir: &Path,
    entry: &Slot,
    ports: &SlotPorts,
    server_pid: u32,
    task_clock_ms: Option<f64>,
) -> Result<(), String> {
    let document = Json::object([
        ("block", int(entry.block)),
        ("position", int(entry.position)),
        (
            "implementation",
            Json::string(entry.implementation.clone()),
        ),
        (
            "process",
            Json::object([("serverPid", Json::Int(i64::from(server_pid)))]),
        ),
        (
            "ports",
            Json::object([
                ("server", Json::Int(i64::from(ports.server))),
                ("socks", Json::Int(i64::from(ports.socks))),
            ]),
        ),
        (
            "serverTaskClockMs",
            task_clock_ms.map_or(Json::Null, Json::Float),
        ),
    ]);
    std::fs::write(slot_dir.join("identity.json"), document.to_python_json())
        .map_err(|error| format!("could not write the slot identity: {error}"))
}

/// Reads back the rows the workload child wrote.
pub(crate) fn read_rows(path: &Path) -> Result<Vec<SampleRow>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let value = crate::perf::json_in::parse(&raw)
        .map_err(|error| format!("{} is invalid JSON: {error}", path.display()))?;
    let crate::perf::json_in::Value::Array(items) = value else {
        return Err(format!("{} is not an array of rows", path.display()));
    };
    items.iter().map(row_from_json).collect()
}

fn row_from_json(value: &crate::perf::json_in::Value) -> Result<SampleRow, String> {
    use crate::perf::json_in::Value;
    let number = |name: &str| -> Result<f64, String> {
        match value.field("row", name) {
            Ok(Value::Number(text)) => text
                .parse::<f64>()
                .map_err(|error| format!("row.{name} is not a number: {error}")),
            _ => Err(format!("row.{name} is missing or not a number")),
        }
    };
    let count = |name: &str| -> Result<usize, String> {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "row counters are small non-negative integers"
        )]
        Ok(number(name)? as usize)
    };
    let latencies = match value.field("row", "latenciesSeconds") {
        Ok(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Number(text) => text
                    .parse::<f64>()
                    .map_err(|error| format!("a latency is not a number: {error}")),
                _ => Err("a latency is not a number".to_owned()),
            })
            .collect::<Result<Vec<f64>, String>>()?,
        _ => Vec::new(),
    };
    Ok(SampleRow {
        block: count("block")?,
        position: count("position")?,
        implementation: value
            .field("row", "implementation")
            .and_then(|field| field.as_str("row.implementation"))
            .map_err(|error| error.to_string())?
            .to_owned(),
        concurrency: count("concurrency")?,
        sample_index: count("sampleIndex")?,
        connections: count("connections")?,
        failed: count("failed")?,
        wall_seconds: number("wallSeconds")?,
        latencies_seconds: latencies,
    })
}

/// Aggregates the measured slots into the comparator's `summary.json`.
fn summarise(plan: &ComparatorPlan, measured: &[MeasuredSlot]) -> Result<Json, String> {
    let expected_slots = plan.blocks * 4;
    if measured.len() != expected_slots {
        return Err(format!(
            "missing ABBA slots: expected {expected_slots}, measured {}",
            measured.len()
        ));
    }
    let expected_rows = plan.samples * plan.concurrencies.len();
    for slot in measured {
        if slot.rows.len() != expected_rows {
            return Err(format!(
                "missing samples in {}: expected {expected_rows}, found {}",
                slot.slot.directory_name(),
                slot.rows.len()
            ));
        }
        if let Some(bad) = slot
            .rows
            .iter()
            .find(|row| row.failed > 0 || row.connections != plan.connections)
        {
            return Err(format!(
                "failed setup sample in {}: concurrency {} completed {} of {}",
                slot.slot.directory_name(),
                bad.concurrency,
                bad.connections,
                plan.connections
            ));
        }
    }

    let all_rows: Vec<&SampleRow> = measured.iter().flat_map(|slot| slot.rows.iter()).collect();
    let mut cells: Vec<(String, Json)> = Vec::with_capacity(plan.concurrencies.len());
    for concurrency in &plan.concurrencies {
        let mut entries: Vec<(String, Json)> = Vec::with_capacity(4);
        let mut medians = Vec::with_capacity(2);
        let mut p50s = Vec::with_capacity(2);
        for label in COMPARATOR_LABELS {
            let rows: Vec<&&SampleRow> = all_rows
                .iter()
                .filter(|row| row.implementation == label && row.concurrency == *concurrency)
                .collect();
            let rates: Vec<f64> = rows
                .iter()
                .filter_map(|row| row.connections_per_second())
                .collect();
            let latencies: Vec<f64> = rows
                .iter()
                .flat_map(|row| row.latencies_seconds.iter().copied())
                .collect();
            let pooled = aggregate::pooled_implementation(&rates, &latencies)?;
            medians.push(pooled.connections_per_second_median);
            p50s.push(pooled.p50_seconds);
            entries.push((label.to_owned(), pooled.to_json()));
        }
        if medians[1] == 0.0 || p50s[0] == 0.0 {
            return Err(format!(
                "concurrency {concurrency} produced a zero denominator, so the ratio is undefined"
            ));
        }
        entries.push((
            "rustVsXrayConnPerSecondRatio".to_owned(),
            Json::Float(medians[0] / medians[1]),
        ));
        entries.push((
            "xrayVsRustP50LatencyRatio".to_owned(),
            Json::Float(p50s[1] / p50s[0]),
        ));
        cells.push((concurrency.to_string(), Json::object(entries)));
    }

    let cpu = cpu_summary(plan, measured)?;
    Ok(aggregate::summary_document(
        1,
        aggregate::COMPARATOR_METHOD,
        measured.len(),
        all_rows.len(),
        [
            ("cells".to_owned(), Json::object(cells)),
            ("serverCpuPerConnection".to_owned(), cpu),
        ],
    ))
}

/// The per-connection CPU comparison, absent outside `perf` mode.
fn cpu_summary(plan: &ComparatorPlan, measured: &[MeasuredSlot]) -> Result<Json, String> {
    if matches!(plan.attribution, Attribution::Wall) {
        return Ok(Json::Null);
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "connection counts are small integers, exact in f64"
    )]
    let per_slot = (plan.samples * plan.concurrencies.len() * plan.connections) as f64;
    if per_slot <= 0.0 {
        return Err("a slot must measure at least one connection".to_owned());
    }
    let mut entries: Vec<(String, Json)> = Vec::with_capacity(3);
    let mut medians = Vec::with_capacity(2);
    for label in COMPARATOR_LABELS {
        let values: Vec<f64> = measured
            .iter()
            .filter(|slot| slot.slot.implementation == label)
            .map(|slot| {
                slot.task_clock_ms
                    .map(|ms| ms * 1000.0 / per_slot)
                    .ok_or_else(|| {
                        format!(
                            "{} has no task-clock, so CPU cannot be attributed",
                            slot.slot.directory_name()
                        )
                    })
            })
            .collect::<Result<Vec<f64>, String>>()?;
        let median = crate::perf::stats::median(&values).map_err(|error| error.to_string())?;
        medians.push(median);
        entries.push((
            label.to_owned(),
            Json::object([
                ("microsecondsPerConnectionMedian", Json::Float(median)),
                (
                    "slots",
                    Json::Int(i64::try_from(values.len()).unwrap_or(i64::MAX)),
                ),
            ]),
        ));
    }
    if medians[0] == 0.0 {
        return Err("rust reported zero CPU per connection, so the ratio is undefined".to_owned());
    }
    entries.push((
        "xrayVsRustCpuRatio".to_owned(),
        Json::Float(medians[1] / medians[0]),
    ));
    Ok(Json::object(entries))
}

/// The run contract this suite publishes and binds.
fn contract_json(
    plan: &ComparatorPlan,
    rust: &identity::Binary,
    xray: &identity::Binary,
    plain_port: u16,
    tls_port: u16,
    slot_count: usize,
) -> Json {
    let binary = |registered: &identity::Binary| {
        Json::object([
            ("path", Json::string(registered.path.display().to_string())),
            ("sha256", Json::string(registered.sha256.clone())),
        ])
    };
    Json::object([
        ("schemaVersion", Json::Int(1)),
        ("runId", Json::string(plan.run_id.clone())),
        ("phase", Json::string("complete")),
        ("outDir", Json::string(plan.out_dir.display().to_string())),
        ("blocks", int(plan.blocks)),
        ("slotCount", int(slot_count)),
        ("samplesPerSlot", int(plan.samples)),
        ("connectionsPerSample", int(plan.connections)),
        (
            "concurrencies",
            Json::string(
                plan.concurrencies
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
        ),
        ("abbaStart", Json::string(plan.abba_start.clone())),
        (
            "measureMode",
            Json::string(match plan.attribution {
                Attribution::Wall => "wall",
                Attribution::Perf(_) => "perf",
            }),
        ),
        (
            "origins",
            Json::object([
                ("http", Json::Int(i64::from(plain_port))),
                ("https", Json::Int(i64::from(tls_port))),
            ]),
        ),
        (
            "binaries",
            Json::object([("rust-reality", binary(rust)), ("xray", binary(xray))]),
        ),
    ])
}

fn int(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Draws a random RFC 4122 version-4 UUID from the system entropy source.
///
/// The comparator's Xray slots need a client id that no other run will reuse.
/// `/dev/urandom` avoids adding a dependency for sixteen bytes.
///
/// # Errors
///
/// Returns a message when the entropy source cannot be read.
pub fn random_uuid_v4() -> Result<String, String> {
    let mut bytes = random_bytes(16)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex_of(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// Draws a random REALITY short id: eight bytes as hex, as `openssl rand -hex 8`.
///
/// # Errors
///
/// Returns a message when the entropy source cannot be read.
pub fn random_short_id() -> Result<String, String> {
    Ok(hex_of(&random_bytes(8)?))
}

fn random_bytes(count: usize) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut source = std::fs::File::open("/dev/urandom")
        .map_err(|error| format!("could not open /dev/urandom: {error}"))?;
    let mut bytes = vec![0_u8; count];
    source
        .read_exact(&mut bytes)
        .map_err(|error| format!("could not read /dev/urandom: {error}"))?;
    Ok(bytes)
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ComparatorPlan {
        ComparatorPlan {
            repo: PathBuf::from("/repo"),
            rust_bin: PathBuf::from("/bin/rust-reality"),
            xray_bin: PathBuf::from("/bin/xray"),
            out_dir: PathBuf::from("/out/run"),
            run_id: "setup-rate-xray-1".to_owned(),
            blocks: 3,
            samples: 3,
            connections: 96,
            concurrencies: vec![1, 8, 32],
            abba_start: "rust".to_owned(),
            attribution: Attribution::Perf(&attribution::TASK_CLOCK_ONLY),
        }
    }

    #[test]
    fn the_script_guards_are_reproduced() {
        validate(&plan()).expect("the defaults are valid");

        let mut bad = plan();
        bad.blocks = 0;
        assert!(validate(&bad).unwrap_err().contains("BLOCKS"));
        bad.blocks = 21;
        assert!(validate(&bad).unwrap_err().contains("BLOCKS"));

        let mut bad = plan();
        bad.samples = 0;
        assert!(validate(&bad).unwrap_err().contains("positive"));
        bad = plan();
        bad.connections = 0;
        assert!(validate(&bad).unwrap_err().contains("positive"));

        let mut bad = plan();
        bad.abba_start = "baseline".to_owned();
        assert!(validate(&bad).unwrap_err().contains("rust or xray"));

        let mut bad = plan();
        bad.concurrencies = vec![];
        assert!(validate(&bad).is_err());
        bad.concurrencies = vec![1, 0];
        assert!(validate(&bad).is_err());

        let mut bad = plan();
        bad.run_id = "../escape".to_owned();
        assert!(validate(&bad).unwrap_err().contains("RUN_ID"));
        bad.run_id = String::new();
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn a_generated_uuid_is_version_four_and_unique() {
        let first = random_uuid_v4().unwrap();
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4', "version nibble");
        assert!(
            matches!(first.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "variant nibble in {first}"
        );
        assert_ne!(first, random_uuid_v4().unwrap());
    }

    #[test]
    fn a_short_id_is_sixteen_hex_digits() {
        let id = random_short_id().unwrap();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, random_short_id().unwrap());
    }

    /// The comparator's contract names the mode, so `wall` evidence can never be
    /// mistaken for a CPU claim.
    #[test]
    fn the_contract_records_the_measure_mode() {
        let rust = identity::Binary {
            label: "rust-reality".to_owned(),
            path: PathBuf::from("/bin/rust-reality"),
            sha256: "a".repeat(64),
            identity: "identity".to_owned(),
        };
        let xray = identity::Binary {
            label: "xray".to_owned(),
            path: PathBuf::from("/bin/xray"),
            sha256: "b".repeat(64),
            identity: "identity".to_owned(),
        };
        let rendered = contract_json(&plan(), &rust, &xray, 8080, 8443, 12).to_python_json();
        assert!(rendered.contains("\"measureMode\": \"perf\""));
        assert!(rendered.contains("\"schemaVersion\": 1"));
        assert!(rendered.contains("\"slotCount\": 12"));
        assert!(rendered.contains("\"concurrencies\": \"1 8 32\""));

        let mut wall = plan();
        wall.attribution = Attribution::Wall;
        let rendered = contract_json(&wall, &rust, &xray, 8080, 8443, 12).to_python_json();
        assert!(rendered.contains("\"measureMode\": \"wall\""));
    }

    fn row(implementation: &str, concurrency: usize, rate_scale: f64) -> SampleRow {
        SampleRow {
            block: 1,
            position: 1,
            implementation: implementation.to_owned(),
            concurrency,
            sample_index: 0,
            connections: 4,
            failed: 0,
            wall_seconds: 4.0 / rate_scale,
            latencies_seconds: vec![0.01, 0.02, 0.03, 0.04],
        }
    }

    fn measured_slots(attribution: Attribution) -> Vec<MeasuredSlot> {
        let slots = plan::abba_slots(COMPARATOR_LABELS, "rust", 1, PortLayout::Deferred).unwrap();
        slots
            .into_iter()
            .map(|entry| {
                let scale = if entry.implementation == "rust" {
                    2.0
                } else {
                    1.0
                };
                let rows = vec![row(&entry.implementation, 1, scale)];
                MeasuredSlot {
                    slot: entry,
                    server_port: 1,
                    socks_port: 2,
                    server_pid: 3,
                    task_clock_ms: match attribution {
                        Attribution::Wall => None,
                        Attribution::Perf(_) => Some(if scale > 1.0 { 100.0 } else { 200.0 }),
                    },
                    rows,
                }
            })
            .collect()
    }

    #[test]
    fn the_summary_reports_both_ratios_and_the_cpu_comparison() {
        let mut context = plan();
        context.blocks = 1;
        context.samples = 1;
        context.connections = 4;
        context.concurrencies = vec![1];
        let measured = measured_slots(context.attribution);
        let rendered = summarise(&context, &measured).unwrap().to_python_json();

        assert!(rendered.contains("\"schemaVersion\": 1"));
        assert!(rendered.contains("Xray serves one leg"));
        assert!(rendered.contains("\"slotCount\": 4"));
        // rust runs at twice the rate, so the ratio is 2.
        assert!(rendered.contains("\"rustVsXrayConnPerSecondRatio\": 2.0"));
        // Latencies are identical, so the p50 ratio is 1.
        assert!(rendered.contains("\"xrayVsRustP50LatencyRatio\": 1.0"));
        // Xray burns twice the CPU per connection.
        assert!(rendered.contains("\"xrayVsRustCpuRatio\": 2.0"));
        assert!(rendered.contains("\"serverCpuPerConnection\""));
    }

    /// Wall mode records no CPU claim at all, as `cpu_summary = None` did.
    #[test]
    fn wall_mode_records_a_null_cpu_summary() {
        let mut context = plan();
        context.blocks = 1;
        context.samples = 1;
        context.connections = 4;
        context.concurrencies = vec![1];
        context.attribution = Attribution::Wall;
        let measured = measured_slots(Attribution::Wall);
        let rendered = summarise(&context, &measured).unwrap().to_python_json();
        assert!(rendered.contains("\"serverCpuPerConnection\": null"));
    }

    #[test]
    fn a_short_or_failed_slot_is_refused() {
        let mut context = plan();
        context.blocks = 1;
        context.samples = 1;
        context.connections = 4;
        context.concurrencies = vec![1];

        let mut measured = measured_slots(context.attribution);
        measured.truncate(3);
        assert!(
            summarise(&context, &measured)
                .unwrap_err()
                .contains("missing ABBA slots")
        );

        let mut measured = measured_slots(context.attribution);
        measured[1].rows[0].failed = 1;
        assert!(
            summarise(&context, &measured)
                .unwrap_err()
                .contains("failed setup sample")
        );

        let mut measured = measured_slots(context.attribution);
        measured[2].rows.clear();
        assert!(
            summarise(&context, &measured)
                .unwrap_err()
                .contains("missing samples")
        );
    }

    /// A perf slot with no task-clock must not silently become a zero CPU claim.
    #[test]
    fn a_perf_slot_without_task_clock_is_refused() {
        let mut context = plan();
        context.blocks = 1;
        context.samples = 1;
        context.connections = 4;
        context.concurrencies = vec![1];
        let mut measured = measured_slots(context.attribution);
        measured[0].task_clock_ms = None;
        assert!(
            summarise(&context, &measured)
                .unwrap_err()
                .contains("no task-clock")
        );
    }
}
