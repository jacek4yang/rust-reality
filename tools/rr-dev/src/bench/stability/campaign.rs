//! Host-side execution of the fixed, owned three-VM stability campaign.

use super::{collect, fixture::Machines, guest, schema};
use crate::{
    bench::{
        config::{self, LandingLink, RealityIdentity},
        identity,
        no_ccs::{self, CertificatePlan},
        origin_go, soak,
        workspace::Workspace,
    },
    hash,
    process::Tool,
};
use clap::Args;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Inputs to the maintained local VM campaign.
#[derive(Args)]
pub struct Plan {
    /// Preserved, owned three-guest QEMU fixture directory.
    #[arg(long)]
    pub fixture: PathBuf,
    /// Fresh evidence directory; previous attempts are never overwritten.
    #[arg(long)]
    pub output: PathBuf,
    /// Frozen rust-reality release executable.
    #[arg(long)]
    pub candidate: PathBuf,
    /// Pinned stock-Xray executable.
    #[arg(long)]
    pub xray: PathBuf,
    /// Pinned OpenSSL executable for fresh private fixture certificates.
    #[arg(long)]
    pub openssl: PathBuf,
    /// Optional contract cell filter (repeatable). Empty runs every cell.
    ///
    /// Partial runs freeze identity and retain per-cell diagnosis but skip the
    /// full offline Pass evaluate — merge cell directories first (ADR 0042).
    #[arg(long = "cell")]
    pub cells: Vec<String>,
}

fn save(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write campaign receipt: {error}"))
}

fn private_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| error.to_string())
}

fn prepare(
    plan: &Plan,
    machines: &Machines,
    private: &Path,
    topology: &'static str,
) -> Result<(), String> {
    private_directory(private)?;
    no_ccs::build_certificate(
        &plan.openssl,
        private,
        &CertificatePlan {
            ca_subject: "/CN=rr-stability-fixture-ca".to_owned(),
            leaf_subject: "/CN=localhost".to_owned(),
            subject_alt_name: "DNS:localhost,IP:127.0.0.1,IP:192.0.2.2,IP:192.0.2.6".to_owned(),
            verify_hostname: Some("localhost".to_owned()),
        },
    )?;
    for size in [1, 4] {
        origin_go::write_pattern_payload(private, size)?;
    }
    let pair =
        rust_reality::crypto::generate_x25519_key_pair().map_err(|error| error.to_string())?;
    let (private_key, public_key) = pair.into_parts();
    let psk = soak::node_key(&plan.candidate)?;
    let workspace = Workspace::create("stability-config")?;
    for (role, landing_address) in [
        ("landing", "192.0.2.2"),
        ("line-a", "192.0.2.2"),
        ("line-b", "192.0.2.6"),
    ] {
        let directory = private.join(role);
        private_directory(&directory)?;
        let link = LandingLink {
            protocol: topology,
            address: landing_address.to_owned(),
            port: 9443,
            psk: psk.clone(),
            landing_public_key: (topology == "handoff").then(|| public_key.clone()),
        };
        let mut server: Value;
        if role == "landing" {
            server = serde_json::from_str(
                &config::rust_landing(
                    "0.0.0.0",
                    9443,
                    &link,
                    (topology == "handoff").then(|| private_key.expose()),
                )
                .to_python_json(),
            )
            .map_err(|error| error.to_string())?;
            server["log"]["level"] = json!("debug");
        } else {
            let target = format!("{landing_address}:8443");
            let generated = soak::generated_public_config(
                &soak::PublicNodeSpec::line(9444, &target, link),
                &workspace,
                role,
            )?;
            server = serde_json::from_str(&soak::patch_server_config(
                &generated.json,
                &workspace,
                role,
                true,
            )?)
            .map_err(|error| error.to_string())?;
            server["assets"]["cacheDirectory"] = json!(format!("{}/assets", guest::ROOT));
            let mut client: Value = serde_json::from_str(
                &config::xray_client(
                    &RealityIdentity {
                        uuid: generated.uuid,
                        short_id: generated.short_id,
                        server_name: "localhost".to_owned(),
                        target,
                    },
                    9444,
                    1080,
                    &generated.public_key,
                )
                .to_python_json(),
            )
            .map_err(|error| error.to_string())?;
            client["inbounds"][0]["listen"] = json!("0.0.0.0");
            save(&directory.join("xray.json"), &client)?;
            for (name, warm) in [("warm.json", true), ("cold.json", false)] {
                server["outbounds"]["landing-1"]["warmTcp"] = json!(warm);
                save(&directory.join(name), &server)?;
                soak::check_config(&plan.candidate, &directory.join(name))?;
            }
            server["outbounds"]["landing-1"]["warmTcp"] = json!(true);
        }
        save(&directory.join("server.json"), &server)?;
        soak::check_config(&plan.candidate, &directory.join("server.json"))?;
        stage_role(plan, machines, private, &directory, role)?;
    }
    Ok(())
}

fn stage_role(
    plan: &Plan,
    machines: &Machines,
    private: &Path,
    directory: &Path,
    role: &str,
) -> Result<(), String> {
    let harness = std::env::current_exe().map_err(|error| error.to_string())?;
    machines.prepare_inputs(role)?;
    for (path, name) in [
        (&plan.candidate, "rust-reality"),
        (&harness, "rr-dev"),
        (&private.join("ca.crt"), "ca.crt"),
        (&directory.join("server.json"), "server.json"),
    ] {
        machines.stage(role, path, name)?;
    }
    if role == "landing" {
        for name in ["server.crt", "server.key", "payload-1.bin", "payload-4.bin"] {
            machines.stage(role, &private.join(name), name)?;
        }
    } else {
        machines.stage(role, &plan.xray, "xray")?;
        for name in ["xray.json", "warm.json", "cold.json"] {
            machines.stage(role, &directory.join(name), name)?;
        }
    }
    machines
        .ssh(
            role,
            &[
                "chmod",
                "500",
                &format!("{}/rust-reality", guest::ROOT),
                &format!("{}/rr-dev", guest::ROOT),
            ],
        )?
        .run()
        .map_err(|error| error.to_string())?;
    if role != "landing" {
        machines
            .ssh(role, &["chmod", "500", &format!("{}/xray", guest::ROOT)])?
            .run()
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn wait_until(
    epoch: u64,
    helpers: &mut [(String, crate::process::RunningTool)],
) -> Result<(), String> {
    loop {
        for (role, helper) in helpers.iter_mut() {
            if !helper.is_running().map_err(|error| error.to_string())? {
                return Err(format!(
                    "{role}: guest helper exited before workload completion"
                ));
            }
        }
        let now = collect::unix_ms()?;
        if now >= epoch {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis((epoch - now).min(100)));
    }
}

fn checkpoint(
    root: &Path,
    cell_root: &Path,
    cell: &schema::Cell,
    name: &str,
    offset: u64,
    recovered: bool,
) -> Result<schema::Checkpoint, String> {
    let mut samples = Vec::new();
    let mut observed_ms = 0;
    for role in &cell.roles {
        let path = cell_root.join(&role.name).join(format!("{name}.json"));
        let raw = schema::parse_observation(&fs::read(&path).map_err(|error| error.to_string())?)?;
        observed_ms = observed_ms.max(
            raw.completed_unix_ms
                .checked_sub(cell.started_unix_ms)
                .ok_or("guest sample precedes workload epoch")?,
        );
        let normalize = if recovered {
            super::observation::normalize
        } else {
            super::observation::normalize_active
        };
        samples.push(normalize(
            &raw,
            &role.policy,
            &role.name,
            super::workload::artifact(root, &path)?,
        )?);
    }
    Ok(schema::Checkpoint {
        offset_ms: offset,
        observed_ms,
        samples,
    })
}

fn assemble_roles(
    root: &Path,
    cell_root: &Path,
    cell: &mut schema::Cell,
    constrained: bool,
    contract: &schema::Contract,
) -> Result<(), String> {
    for name in &contract.roles {
        let path = cell_root.join(name).join("cycle-0-0.json");
        let raw = schema::parse_observation(&fs::read(&path).map_err(|error| error.to_string())?)?;
        let policy = super::observation::startup_policy(&raw, 1)?;
        let sample = super::observation::normalize(
            &raw,
            &policy,
            name,
            super::workload::artifact(root, &path)?,
        )?;
        let ordinary_landing = name == "landing" && !constrained;
        let artifact =
            |file: &str| super::workload::artifact(root, &cell_root.join(name).join(file));
        cell.roles.push(schema::Role {
            name: name.clone(),
            process: sample.process,
            vcpus: if ordinary_landing { 2 } else { 1 },
            memory_limit_bytes: if ordinary_landing {
                2_147_483_648
            } else {
                1_073_741_824
            },
            swap_limit_bytes: 0,
            policy,
            startup: super::workload::artifact(
                root,
                &cell_root.join(name).join("startup-server.json"),
            )?,
            environment: [
                artifact("environment-before.json")?,
                artifact("environment-after.json")?,
            ],
            clocks: [
                super::workload::artifact(
                    root,
                    &cell_root.join(format!("{name}-clock-before.json")),
                )?,
                super::workload::artifact(
                    root,
                    &cell_root.join(format!("{name}-clock-after.json")),
                )?,
            ],
            terminal_status: artifact("terminal-status.json")?,
            server_logs: if name == "landing"
                && cell_root
                    .join(name)
                    .join("server-before-restart.log")
                    .is_file()
            {
                vec![
                    artifact("server-before-restart.log")?,
                    artifact("server.log")?,
                ]
            } else {
                vec![artifact("server.log")?]
            },
        });
    }
    Ok(())
}

fn assemble(
    root: &Path,
    cell_root: &Path,
    cell: &mut schema::Cell,
    constrained: bool,
    contract: &schema::Contract,
) -> Result<(), String> {
    assemble_roles(root, cell_root, cell, constrained, contract)?;
    for index in 0..cell.cycles.len() {
        let mut checkpoints = Vec::new();
        for offset in &contract.checkpoint_offsets_ms {
            checkpoints.push(checkpoint(
                root,
                cell_root,
                cell,
                &format!("cycle-{index}-{offset}"),
                *offset,
                Some(offset) == contract.checkpoint_offsets_ms.last(),
            )?);
        }
        cell.cycles[index].checkpoints = checkpoints;
    }
    let mut bindings: Vec<_> = cell
        .roles
        .iter()
        .map(|role| schema::ProcessBinding {
            role: role.name.clone(),
            identity: role.process.clone(),
        })
        .collect();
    for index in 0..cell.faults.len() {
        let name = &cell.faults[index].name;
        let mut checkpoints = Vec::new();
        for offset in &contract.fault_checkpoint_offsets_ms {
            checkpoints.push(checkpoint(
                root,
                cell_root,
                cell,
                &format!("fault-{name}-{offset}"),
                *offset,
                Some(offset) == contract.fault_checkpoint_offsets_ms.last(),
            )?);
        }
        cell.faults[index].before_processes = bindings;
        bindings = checkpoints
            .first()
            .ok_or("missing fault checkpoint")?
            .samples
            .iter()
            .map(|sample| schema::ProcessBinding {
                role: sample.role.clone(),
                identity: sample.process.clone(),
            })
            .collect();
        cell.faults[index].after_processes.clone_from(&bindings);
        cell.faults[index].checkpoints = checkpoints;
        for role in &cell.roles {
            for boundary in ["begin", "end"] {
                let artifact = super::workload::artifact(
                    root,
                    &cell_root.join(&role.name).join(format!(
                        "action-{}-{boundary}.json",
                        cell.faults[index].name
                    )),
                )?;
                cell.faults[index].actions.push(artifact);
            }
        }
    }
    for offset in contract.integrity_offsets() {
        cell.integrity_checkpoints.push(checkpoint(
            root,
            cell_root,
            cell,
            &format!("integrity-{offset}"),
            offset,
            Some(&offset) == contract.integrity_offsets().last(),
        )?);
    }
    for role in &cell.roles {
        let before = super::execution::parse_environment(
            &fs::read(root.join(&role.environment[0].path)).map_err(|error| error.to_string())?,
        )?;
        let after = super::execution::parse_environment(
            &fs::read(root.join(&role.environment[1].path)).map_err(|error| error.to_string())?,
        )?;
        cell.oom_kills += super::execution::environment_pair(&before, &after, role, cell)?;
        let counts = super::product_logs(root, cell, role, contract)?;
        cell.panics += counts.panics;
        cell.unexpected_rejections += counts.rejections;
    }
    cell.final_processes = checkpoint(root, cell_root, cell, "terminal", 0, true)?
        .samples
        .into_iter()
        .map(|sample| schema::ProcessBinding {
            role: sample.role,
            identity: sample.process,
        })
        .collect();
    Ok(())
}

fn workload(
    machines: &Machines,
    helpers: &mut [(String, crate::process::RunningTool)],
    driver: &super::workload::Driver<'_>,
    cell: &mut schema::Cell,
    contract: &schema::Contract,
) -> Result<(), String> {
    cycles(machines, helpers, driver, cell, contract)?;
    faults(machines, helpers, driver, cell, contract)?;
    wait_until(driver.epoch + contract.integrity_start() + 1000, helpers)?;
    let prefix = cell.name.replace('/', "-");
    for line in ["line-a", "line-b"] {
        for size in [1, 4] {
            for direction in &contract.directions {
                let id = format!("{prefix}-integrity-{line}-{size}-{direction}");
                cell.integrity.push(driver.integrity(
                    machines,
                    &id,
                    line,
                    machines.socks_port(line)?,
                    size,
                    direction,
                )?);
            }
        }
    }
    Ok(())
}

fn cycles(
    machines: &Machines,
    helpers: &mut [(String, crate::process::RunningTool)],
    driver: &super::workload::Driver<'_>,
    cell: &mut schema::Cell,
    contract: &schema::Contract,
) -> Result<(), String> {
    use super::workload::Batch;
    let ports = [
        machines.socks_port("line-a")?,
        machines.socks_port("line-b")?,
    ];
    let prefix = cell.name.replace('/', "-");
    for index in 0..contract.cycles {
        let start = index as u64 * contract.cycle_interval_ms;
        wait_until(driver.epoch + start + contract.load_start_ms, helpers)?;
        println!(
            "{}: cycle {}/{} concurrency {}",
            cell.name,
            index + 1,
            contract.cycles,
            contract.concurrency[index]
        );
        let id = format!("{prefix}-cycle-{index}");
        let batches: Vec<_> = ["line-a", "line-b"]
            .into_iter()
            .zip(ports)
            .map(|(line, port)| Batch {
                id: &id,
                line,
                socks_port: port,
                count: usize::try_from(contract.transfers_per_line).expect("bounded contract"),
                concurrency: usize::try_from(contract.concurrency[index])
                    .expect("bounded contract"),
                paced_wave: true,
                admission_deadline_ms: None,
            })
            .collect();
        let transfers = driver.batch(machines, &batches)?;
        cell.cycles.push(schema::Cycle {
            index,
            started_ms: start,
            concurrency: contract.concurrency[index],
            transfers,
            checkpoints: Vec::new(),
        });
        save(
            &driver.output.join(format!("cycle-{index}.json")),
            cell.cycles.last().expect("just inserted cycle"),
        )?;
    }
    Ok(())
}

// Keep continuity, impaired traffic and recovery together for each fixed fault.
#[allow(clippy::too_many_lines)]
fn faults(
    machines: &Machines,
    helpers: &mut [(String, crate::process::RunningTool)],
    driver: &super::workload::Driver<'_>,
    cell: &mut schema::Cell,
    contract: &schema::Contract,
) -> Result<(), String> {
    use super::workload::Batch;
    let ports = [
        machines.socks_port("line-a")?,
        machines.socks_port("line-b")?,
    ];
    let prefix = cell.name.replace('/', "-");
    let first = contract.cycles as u64 * contract.cycle_interval_ms;
    for (index, name) in contract.faults.iter().enumerate() {
        let start = first + index as u64 * contract.fault_interval_ms;
        let restored = start + contract.fault_duration(name);
        wait_until(driver.epoch + start - 1000, helpers)?;
        println!("{}: fault {}", cell.name, name);
        let id = format!("{prefix}-{name}");
        let mut during = Vec::new();
        let mut recovered = Vec::new();
        let mut expected_failures = Vec::new();
        let (affected, workload_result) = std::thread::scope(|scope| {
            let prefix_id = format!("{id}-prefix");
            let handle = scope.spawn(move || {
                driver.prefix(
                    &prefix_id,
                    ports[0],
                    if name.starts_with("rtt-") {
                        start + 1000
                    } else {
                        restored + 1000
                    },
                    name == "landing-restart",
                )
            });
            let execution = (|| {
                wait_until(
                    driver.epoch + start + if name.starts_with("rtt-") { 2500 } else { 1000 },
                    helpers,
                )?;
                if name != "landing-restart" {
                    let batches: Vec<_> = ["line-a", "line-b"]
                        .into_iter()
                        .zip(ports)
                        .filter(|(line, _)| name != "line-a-partition" || *line == "line-b")
                        .map(|(line, port)| Batch {
                            id: &id,
                            line,
                            socks_port: port,
                            count: usize::try_from(contract.transfers_per_line)
                                .expect("bounded contract"),
                            concurrency: usize::try_from(contract.fault_concurrency(name))
                                .expect("bounded contract"),
                            paced_wave: false,
                            admission_deadline_ms: Some(
                                contract.fault_admission_deadline_ms(name, restored),
                            ),
                        })
                        .collect();
                    during = driver.batch(machines, &batches)?;
                }
                // Do not overlap short-fault recovery admissions with the first
                // post-restore descriptor census (ADR 0043 / ADR 0046).
                wait_until(
                    driver.epoch + contract.recovery_ready_ms(name, start, restored),
                    helpers,
                )?;
                let recovery_id = format!("{id}-recovery");
                let batches: Vec<_> = ["line-a", "line-b"]
                    .into_iter()
                    .zip(ports)
                    .map(|(line, port)| Batch {
                        id: &recovery_id,
                        line,
                        socks_port: port,
                        count: usize::try_from(contract.transfers_per_line)
                            .expect("bounded contract"),
                        concurrency: usize::try_from(contract.fault_concurrency_per_line)
                            .expect("bounded contract"),
                        paced_wave: false,
                        admission_deadline_ms: None,
                    })
                    .collect();
                recovered = driver.batch(machines, &batches)?;
                Ok::<_, String>(())
            })();
            (
                handle
                    .join()
                    .map_err(|_| "prefix worker panicked".to_owned())
                    .and_then(|result| result),
                execution,
            )
        });
        workload_result?;
        let (affected_prefix, failure) = affected?;
        expected_failures.extend(failure);
        let first_admission_ms = recovered
            .iter()
            .map(|transfer| transfer.completed_ms)
            .min()
            .ok_or("missing recovery admission")?;
        cell.faults.push(schema::Fault {
            name: name.clone(),
            actions: Vec::new(),
            started_ms: start,
            restored_ms: restored,
            first_admission_ms,
            before_processes: Vec::new(),
            after_processes: Vec::new(),
            checkpoints: Vec::new(),
            during_transfers: during,
            recovery_transfers: recovered,
            affected_prefix,
            expected_failures,
            unexpected_failures: 0,
        });
        save(
            &driver.output.join(format!("fault-{name}.json")),
            cell.faults.last().expect("just inserted fault"),
        )?;
    }
    Ok(())
}

// Keep the primary attempt and every finalizer visibly in the same transaction.
#[allow(clippy::too_many_lines)]
fn run_cell(
    plan: &Plan,
    root: &Path,
    name: &str,
    sources: &[schema::Artifact; 2],
    identity: &schema::Identity,
    xray_sha256: &str,
) -> Result<schema::Cell, String> {
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let constrained = name.ends_with("/constrained");
    let topology = if name.starts_with("handoff/") {
        "handoff"
    } else {
        "nxr"
    };
    let cell_root = root.join(name.replace('/', "-"));
    let mut machines = Machines::start(&plan.fixture, &cell_root, constrained)?;
    let terminal_path = cell_root.join("cell-terminal.json");
    let mut cell = schema::Cell {
        name: name.to_owned(),
        started_unix_ms: 0,
        started: false,
        completed: false,
        roles: Vec::new(),
        final_processes: Vec::new(),
        cycles: Vec::new(),
        faults: Vec::new(),
        integrity: Vec::new(),
        integrity_checkpoints: Vec::new(),
        unexpected_exits: 0,
        panics: 0,
        oom_kills: 0,
        unexpected_rejections: 0,
        terminal: schema::Artifact {
            path: String::new(),
            sha256: String::new(),
        },
    };
    let mut helpers = Vec::new();
    let primary = (|| {
        let private = plan
            .fixture
            .canonicalize()
            .map_err(|error| error.to_string())?
            .join(format!(
                "private-{}-{}",
                name.replace('/', "-"),
                collect::unix_ms()?
            ));
        prepare(plan, &machines, &private, topology)?;
        for role in &contract.roles {
            machines.clock_probe(role, true)?;
        }
        let epoch = collect::unix_ms()?
            .checked_add(30000)
            .ok_or("workload epoch overflow")?;
        cell.started_unix_ms = epoch;
        cell.started = true;
        for role in ["landing", "line-a", "line-b"] {
            let boot = machines.verify_guest(role)?.to_owned();
            let args = [
                format!("{}/rr-dev", guest::ROOT),
                "bench".to_owned(),
                "stability-guest".to_owned(),
                "--role".to_owned(),
                role.to_owned(),
                "--started-unix-ms".to_owned(),
                epoch.to_string(),
                "--boot-id".to_owned(),
                boot,
                "--candidate-sha256".to_owned(),
                identity.candidate.sha256.clone(),
                "--evaluator-sha256".to_owned(),
                identity.evaluator.sha256.clone(),
                "--xray-sha256".to_owned(),
                xray_sha256.to_owned(),
            ];
            let tool = machines
                .ssh(role, &args.iter().map(String::as_str).collect::<Vec<_>>())?
                .timeout(Duration::from_mins(90))
                .capture_limit(2 * 1024 * 1024 * 1024)
                .log_output_only(
                    cell_root.join(format!("{role}-helper.stdout")),
                    cell_root.join(format!("{role}-helper.stderr")),
                )
                .spawn()
                .map_err(|error| error.to_string())?;
            helpers.push((role.to_owned(), tool));
        }
        let traffic = cell_root.join("traffic");
        fs::create_dir(&traffic).map_err(|error| error.to_string())?;
        let driver = super::workload::Driver {
            root,
            output: traffic,
            epoch,
            sources: sources.clone(),
            clock: (collect::unix_ms()?, Instant::now()),
            max_clock_drift_ms: contract.clock_max_drift_ms,
        };
        workload(&machines, &mut helpers, &driver, &mut cell, &contract)
    })();
    let mut finalization = Vec::new();
    if primary.is_err() {
        for (role, _) in &helpers {
            let result = machines.verify_guest(role).and_then(|_| {
                machines
                    .ssh(role, &["touch", &format!("{}/stop", guest::ROOT)])?
                    .run()
                    .map_err(|error| error.to_string())
                    .map(|_| ())
            });
            if let Err(error) = result {
                finalization.push(error);
            }
        }
    }
    for (role, mut helper) in helpers {
        let cleanup = Instant::now();
        if primary.is_err() {
            while helper.is_running().unwrap_or(false)
                && cleanup.elapsed() < Duration::from_secs(15)
            {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let waited = if primary.is_err() && helper.is_running().unwrap_or(true) {
            finalization.push(format!(
                "{role}: guest helper missed its cancellation/finalization deadline"
            ));
            helper.interrupt_and_wait(Duration::from_secs(2))
        } else {
            helper.wait()
        };
        if let Err(error) = waited.and_then(|result| {
            if result.success() {
                Ok(result)
            } else {
                Err(crate::process::ToolError::Failed {
                    command: format!("{role} guest helper"),
                    code: result.code,
                    stderr: result.stderr,
                })
            }
        }) {
            finalization.push(error.to_string());
        }
        if let Err(error) = machines.retrieve(&role, &cell_root.join(&role)) {
            finalization.push(error);
        }
    }
    for role in &contract.roles {
        if let Err(error) = machines.clock_probe(role, false) {
            finalization.push(error);
        }
    }
    if let Err(error) = machines.finalize() {
        finalization.push(error);
    }
    if let Err(error) = assemble(root, &cell_root, &mut cell, constrained, &contract) {
        finalization.push(error);
    }
    if let Err(error) = save(
        &terminal_path,
        &json!({"primary_error":primary.as_ref().err(),"finalization_errors":finalization}),
    ) {
        finalization.push(error);
    }
    match super::workload::artifact(root, &terminal_path) {
        Ok(artifact) => cell.terminal = artifact,
        Err(error) => finalization.push(error),
    }
    cell.completed = primary.is_ok() && finalization.is_empty();
    if let Err(error) = save(&cell_root.join("cell.json"), &cell) {
        finalization.push(error);
    }
    if let Err(error) = primary {
        finalization.insert(0, error);
    }
    if finalization.is_empty() {
        Ok(cell)
    } else {
        Err(format!(
            "{}: {}; raw evidence and partial cell retained",
            name,
            finalization.join("; ")
        ))
    }
}

/// Execute all four local VM cells and preserve an offline evidence bundle.
/// Required external/native checks remain NOT RUN until their receipts are bound.
///
/// # Errors
/// Stops on a demonstrated execution or evidence failure after finalization.
pub fn run(repo: &Path, plan: &Plan) -> Result<(), String> {
    fs::create_dir(&plan.output).map_err(|error| format!("fresh campaign directory: {error}"))?;
    let root = plan
        .output
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let _lock = super::qualification::CollectionLock::acquire(&root)?;
    let attempted = execute(repo, plan, &root);
    let written = save(
        &root.join("campaign-terminal.json"),
        &json!({"primary_error":attempted.as_ref().err(),"completed":attempted.is_ok()}),
    );
    match (attempted, written) {
        (Err(primary), Err(secondary)) => Err(format!(
            "{primary}; final evidence write also failed: {secondary}"
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

fn freeze(
    repo: &Path,
    plan: &Plan,
    root: &Path,
) -> Result<(schema::Identity, [schema::Artifact; 2], String), String> {
    let candidate = identity::register(
        "stability candidate",
        &plan.candidate,
        "",
        identity::Kind::Rust,
    )?;
    let xray = identity::register("stock Xray", &plan.xray, "", identity::Kind::Xray)?;
    let evaluator_sha256 = collect::running_image_digest()?;
    let openssl_sha256 = collect::file_digest(&plan.openssl)?;
    let source = identity::embedded_commit(&candidate.identity)?;
    if rust_reality::BUILD_COMMIT != source {
        return Err("build the frozen harness with RUST_REALITY_GIT_COMMIT set to the candidate source commit".to_owned());
    }
    let head = Tool::new("git")
        .args(["-C", &repo.display().to_string(), "rev-parse", "HEAD"])
        .run()
        .map_err(|error| error.to_string())?;
    let status = Tool::new("git")
        .args(["-C", &repo.display().to_string(), "status", "--porcelain"])
        .run()
        .map_err(|error| error.to_string())?;
    if head.stdout.trim() != source || !status.stdout.trim().is_empty() {
        return Err(
            "campaign requires a clean checkout at the candidate's embedded commit".to_owned(),
        );
    }
    if fs::read_to_string(repo.join("benchmarks/contracts/stability.json"))
        .map_err(|error| error.to_string())?
        != schema::CONTRACT
    {
        return Err("running harness contract differs from the source checkout".to_owned());
    }
    for (path, name) in [
        (&plan.candidate, "rust-reality"),
        (
            &std::env::current_exe().map_err(|error| error.to_string())?,
            "rr-dev",
        ),
        (&plan.xray, "xray"),
        (&plan.openssl, "openssl"),
    ] {
        fs::copy(path, root.join(name)).map_err(|error| error.to_string())?;
    }
    for (name, expected) in [
        ("rust-reality", &candidate.sha256),
        ("rr-dev", &evaluator_sha256),
        ("xray", &xray.sha256),
        ("openssl", &openssl_sha256),
    ] {
        if collect::file_digest(&root.join(name))? != *expected {
            return Err(format!("{name}: executable changed while freezing inputs"));
        }
    }
    Tool::new("git")
        .args([
            "-C".to_owned(),
            repo.display().to_string(),
            "archive".to_owned(),
            "--format=tar".to_owned(),
            format!("--output={}", root.join("source.tar").display()),
            source.clone(),
        ])
        .run()
        .map_err(|error| error.to_string())?;
    fs::write(root.join("contract.json"), schema::CONTRACT).map_err(|error| error.to_string())?;
    save(
        &root.join("workload.json"),
        &json!({"contract_sha256":hash::sha256_hex(schema::CONTRACT.as_bytes()),"cycle_first_wave":"4 MiB PUT at 256 KiB/s per transfer","cycle_remaining":"1 MiB GET","fault_count_per_line":100,"rtt_concurrency_per_line":4,"rtt_admission_drain_ms":12000,"rtt_duration_ms":90000,"fault_concurrency_per_line":4,"prefix_target":"LANDING 127.0.0.1:8081 echo","integrity":"1/4 MiB upload/download/concurrent bidirectional"}),
    )?;
    // Controller host_kernel is observational and runner-local. Matrix cell jobs
    // (ADR 0042) must share one identity-bound environment digest, so keep only
    // pinned tool digests here and retain the kernel string beside the freeze.
    save(
        &root.join("controller-host.json"),
        &json!({"host_kernel":Tool::new("uname").arg("-srm").run().map_err(|error| error.to_string())?.stdout}),
    )?;
    save(
        &root.join("environment.json"),
        &json!({"xray_sha256":xray.sha256,"xray_identity":xray.identity,"openssl_sha256":openssl_sha256}),
    )?;
    let art = |name: &str| super::workload::artifact(root, &root.join(name));
    let identity = schema::Identity {
        source_commit: source,
        source_archive: art("source.tar")?,
        candidate: art("rust-reality")?,
        evaluator: art("rr-dev")?,
        contract: art("contract.json")?,
        environment: art("environment.json")?,
        workload: art("workload.json")?,
    };
    let sources = [
        origin_go::write_pattern_payload(root, 1)?,
        origin_go::write_pattern_payload(root, 4)?,
    ]
    .map(|path| super::workload::artifact(root, &path));
    let [one, four] = sources;
    let sources = [one?, four?];
    Ok((identity, sources, xray.sha256))
}

fn execute(repo: &Path, plan: &Plan, root: &Path) -> Result<(), String> {
    let (identity, sources, xray_sha256) = freeze(repo, plan, root)?;
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let mut evidence = schema::Evidence {
        schema: "rr-stability-evidence/v1".to_owned(),
        identity,
        checks: Vec::new(),
        cells: Vec::new(),
    };
    save(&root.join("evidence.json"), &evidence)?;
    let selected = selected_cells(plan, &contract)?;
    let partial = selected.len() != contract.cells.len();
    write_cell_matrix_marker(root, &selected, partial, &evidence.identity.source_commit)?;
    let mut summary = Vec::new();
    let mut cell_errors = Vec::new();
    // Same-host cells stay sequential: ordinary hosted runners have one cell's
    // non-overlapping vCPU budget, plus process-global HostLock and fixed fixture
    // SSH/SOCKS/data ports. Hosted true parallelism is an Actions matrix of
    // `--cell` jobs merged by `stability-merge-cells` (ADR 0042). Aggregation
    // still records every attempted cell so INVALID names the failing cell/fault.
    for name in &selected {
        let result = run_cell(plan, root, name, &sources, &evidence.identity, &xray_sha256);
        let cell_root = root.join(name.replace('/', "-"));
        match result {
            Ok(cell) => {
                summary.push(json!({
                    "cell": name,
                    "result": "pass",
                    "faults": cell.faults.iter().map(|fault| &fault.name).collect::<Vec<_>>(),
                    "class_hint": null,
                }));
                evidence.cells.push(cell);
            }
            Err(error) => {
                let partial_cell = cell_root.join("cell.json");
                let mut failed_fault = None;
                if let Ok(bytes) = fs::read(&partial_cell)
                    && let Ok(cell) = serde_json::from_slice::<schema::Cell>(&bytes)
                {
                    failed_fault = cell.faults.last().map(|fault| fault.name.clone());
                    evidence.cells.push(cell);
                }
                let class = super::diagnosis::classify(&error);
                let diagnosis = json!({
                    "cell": name,
                    "result": "fail-closed",
                    "last_fault": failed_fault,
                    "error": error,
                    "class_hint": class.label(),
                });
                let _ = save(&cell_root.join("cell-diagnosis.json"), &diagnosis);
                summary.push(diagnosis.clone());
                cell_errors.push(format!("{name}: {error}"));
            }
        }
        save(&root.join("evidence.json"), &evidence)?;
        let _ = save(&root.join("cells-summary.json"), &summary);
    }
    if !cell_errors.is_empty() {
        let joined = cell_errors.join("; ");
        return Err(match save(&root.join("evidence.json"), &evidence) {
            Ok(()) => joined,
            Err(secondary) => format!("{joined}; evidence finalization also failed: {secondary}"),
        });
    }
    if partial {
        save(
            &root.join("campaign-selection.json"),
            &json!({
                "selected": selected,
                "contract_cells": contract.cells,
                "partial": true,
                "merge_required": true,
                "invocation": "cargo dev bench stability-merge-cells --output MERGED --cell-dir DIR...",
            }),
        )?;
        println!(
            "Partial VM campaign completed for {}; merge all contract cells before offline Pass evaluate.",
            selected.join(", ")
        );
        return Ok(());
    }
    let report = super::evaluate_path(&root.join("evidence.json"))?;
    save(&root.join("verdict.json"), &report)?;
    if matches!(
        report.verdict,
        super::evaluate::Verdict::Fail | super::evaluate::Verdict::Invalid
    ) {
        return Err(
            "VM evidence failed offline evaluation; verdict and raw files retained".to_owned(),
        );
    }
    println!(
        "VM campaign execution completed; aggregate qualification verdict {:?} (required check receipts must also be bound).",
        report.verdict
    );
    Ok(())
}

fn write_cell_matrix_marker(
    root: &Path,
    selected: &[String],
    partial: bool,
    source_commit: &str,
) -> Result<(), String> {
    // Marker for Actions matrix staging/merge (ADR 0042 / ADR 0046). Written by
    // the Rust campaign under the same privileges as the rest of the cell
    // output so a follow-up unprivileged step cannot PermissionError on
    // root-owned trees (Frozen 38016570647 secondary Class B).
    if !partial {
        return Ok(());
    }
    for name in selected {
        let slug = name.replace('/', "-");
        save(
            &root.join("cell-matrix.json"),
            &json!({
                "cell": name,
                "slug": slug,
                "source_commit": source_commit,
                "parallelism": "actions-matrix",
            }),
        )?;
    }
    Ok(())
}

fn selected_cells(plan: &Plan, contract: &schema::Contract) -> Result<Vec<String>, String> {
    if plan.cells.is_empty() {
        return Ok(contract.cells.clone());
    }
    let mut selected = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for name in &plan.cells {
        if !contract.cells.iter().any(|cell| cell == name) {
            return Err(format!(
                "unknown stability cell {name}; expected one of {}",
                contract.cells.join(", ")
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(format!("duplicate --cell {name}"));
        }
        selected.push(name.clone());
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_before_restart_retains_all_available_role_logs() {
        let workspace = Workspace::create("stability-partial-roles").unwrap();
        let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
        let mut cell: schema::Cell =
            serde_json::from_value(super::super::tests::fixture()["cells"][0].clone()).unwrap();
        cell.completed = false;
        cell.roles.clear();
        for role in &contract.roles {
            let directory = workspace.join(role);
            for phase in ["before", "after"] {
                fs::write(
                    workspace.join(&format!("{role}-clock-{phase}.json")),
                    b"retained clock receipt",
                )
                .unwrap();
            }
            fs::create_dir(&directory).unwrap();
            fs::write(
                directory.join("cycle-0-0.json"),
                include_bytes!("../../../../../fuzz/seeds/stability_evidence/seed_owned_unix.json"),
            )
            .unwrap();
            for name in [
                "startup-server.json",
                "environment-before.json",
                "environment-after.json",
                "terminal-status.json",
                "server.log",
            ] {
                fs::write(directory.join(name), b"retained raw evidence").unwrap();
            }
        }
        assemble_roles(
            workspace.path(),
            workspace.path(),
            &mut cell,
            false,
            &contract,
        )
        .unwrap();
        assert_eq!(cell.roles.len(), 3);
        assert!(cell.roles.iter().all(|role| role.server_logs.len() == 1));
        assert!(!cell.completed);
    }

    #[test]
    fn cell_filter_rejects_unknown_and_duplicates() {
        let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
        let plan = Plan {
            fixture: PathBuf::from("/fixture"),
            output: PathBuf::from("/out"),
            candidate: PathBuf::from("/candidate"),
            xray: PathBuf::from("/xray"),
            openssl: PathBuf::from("/openssl"),
            cells: vec!["missing/cell".into()],
        };
        assert!(
            selected_cells(&plan, &contract)
                .unwrap_err()
                .contains("unknown")
        );
        let plan = Plan {
            cells: vec!["handoff/ordinary".into(), "handoff/ordinary".into()],
            ..plan
        };
        assert!(
            selected_cells(&plan, &contract)
                .unwrap_err()
                .contains("duplicate")
        );
        let plan = Plan {
            cells: vec!["handoff/ordinary".into()],
            ..plan
        };
        assert_eq!(
            selected_cells(&plan, &contract).unwrap(),
            vec!["handoff/ordinary"]
        );
        let plan = Plan {
            cells: vec![],
            ..plan
        };
        assert_eq!(selected_cells(&plan, &contract).unwrap(), contract.cells);
    }

    #[test]
    fn failed_freeze_retains_primary_and_refuses_to_overwrite_the_attempt() {
        let workspace = Workspace::create("stability-freeze-failure").unwrap();
        let plan = Plan {
            fixture: workspace.join("absent-fixture"),
            output: workspace.join("attempt"),
            candidate: workspace.join("absent-candidate"),
            xray: workspace.join("absent-xray"),
            openssl: workspace.join("absent-openssl"),
            cells: Vec::new(),
        };
        let error = run(workspace.path(), &plan).unwrap_err();
        let terminal = plan.output.join("campaign-terminal.json");
        let original = fs::read(&terminal).unwrap();
        let value: Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(value["primary_error"], error);
        assert_eq!(value["completed"], false);
        assert!(
            run(workspace.path(), &plan)
                .unwrap_err()
                .contains("fresh campaign directory")
        );
        assert_eq!(fs::read(terminal).unwrap(), original);
    }
}
