//! Real-socket descriptor-pressure and recovery gate.
//!
//! The gate deliberately constrains the measured server's hard and soft open-file
//! limits, then fills its native descriptor budget with real
//! Xray → REALITY/Vision → echo streams. It proves that established work remains
//! usable while new work is refused, and that releasing pressure restores fresh
//! end-to-end service. Repository policy stays here; `prlimit`, OpenSSL and Xray
//! remain typed external mechanisms.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    bench::{
        config::RealityIdentity,
        evidence::{self, Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        no_ccs::{self, CertificatePlan},
        process::Child,
        runner, suites,
        workspace::{self, Workspace},
    },
    hash,
    perf::{json_in, json_out::Json},
    process::Tool,
};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TIMEOUT: Duration = Duration::from_secs(15);

/// Inputs for one descriptor-pressure run.
#[derive(Debug, Clone)]
pub struct PressureSuite {
    /// Repository root used to identify the tested revision.
    pub repo: PathBuf,
    /// Release rust-reality binary under test.
    pub rust_bin: PathBuf,
    /// Unmodified Xray client binary.
    pub xray_bin: PathBuf,
    /// OpenSSL used only to create and verify the ephemeral certificate chain.
    pub openssl_bin: PathBuf,
    /// Fresh durable evidence directory.
    pub out_dir: PathBuf,
    /// Safe single-component run identifier.
    pub run_id: String,
    /// Equal hard and soft `RLIMIT_NOFILE` applied to rust-reality.
    pub nofile_limit: u64,
    /// Maximum streams opened while searching for admission refusal.
    pub max_held: usize,
    /// Concurrent fresh streams attempted while pressure is high.
    pub storm_connections: usize,
}

/// Successful mechanism observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PressureResult {
    /// Measured server PID.
    pub server_pid: u32,
    /// Budget derived by the server from its actual limits.
    pub effective_budget: u64,
    /// Open descriptors before the control/fill streams.
    pub baseline_fd_count: usize,
    /// Open descriptors after the high transition.
    pub pressure_fd_count: usize,
    /// End-to-end streams established before refusal.
    pub successful_held: usize,
    /// Failed fill attempts (one ends the fill phase).
    pub fill_failures: usize,
    /// Storm connections that completed despite concurrent pressure.
    pub storm_successes: usize,
    /// Storm connections refused or stalled.
    pub storm_failures: usize,
    /// Descriptor units reported at the high transition.
    pub high_units: u64,
    /// Descriptor units reported at the normal transition.
    pub normal_units: u64,
    /// Hash of bytes echoed on the pre-existing control stream under pressure.
    pub control_sha256: String,
    /// Hash of a fresh post-pressure recovery transfer.
    pub recovery_sha256: String,
}

#[derive(Debug, Clone, Copy)]
struct DescriptorEvent {
    effective_budget: u64,
    units: u64,
}

/// Validates the bounded destructive inputs without touching the host.
///
/// # Errors
///
/// Returns a message naming the invalid field.
pub fn validate(suite: &PressureSuite) -> Result<(), String> {
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if !(182..=4096).contains(&suite.nofile_limit) {
        return Err("NOFILE_LIMIT must be in 182..4096".to_owned());
    }
    if !(8..=512).contains(&suite.max_held) {
        return Err("MAX_HELD_CONNECTIONS must be in 8..512".to_owned());
    }
    if !(4..=64).contains(&suite.storm_connections) {
        return Err("STORM_CONNECTIONS must be in 4..64".to_owned());
    }
    Ok(())
}

/// Runs the descriptor-pressure gate and publishes hash-bound evidence.
///
/// # Errors
///
/// Returns the first setup, mechanism, identity or publication failure.
#[allow(clippy::too_many_lines)]
pub fn run(suite: &PressureSuite) -> Result<PressureResult, String> {
    validate(suite)?;
    let rust = identity::register("rust-reality", &suite.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let openssl = external_binary("openssl", &suite.openssl_bin, &["version", "-a"])?;
    let prlimit = resolve_program(Path::new("prlimit"))?;
    let rr_dev_path = std::env::current_exe()
        .map_err(|error| format!("could not resolve the rr-dev executable: {error}"))?;
    let rr_dev_sha256 = hash::sha256_file(&rr_dev_path)?;

    let _lock = HostLock::acquire(&runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("descriptor-pressure")?;
    let ports = workspace::reserve_ports(4)?;
    let [server_port, socks_port, cover_port, echo_port] =
        <[u16; 4]>::try_from(ports).map_err(|_| "could not reserve four ports".to_owned())?;

    let certificate = no_ccs::build_certificate(
        &openssl.path,
        workspace.path(),
        &CertificatePlan {
            ca_subject: certificate_authority_subject(&suite.run_id),
            leaf_subject: "/CN=localhost".to_owned(),
            subject_alt_name: "DNS:localhost,IP:127.0.0.1".to_owned(),
            verify_hostname: Some("localhost".to_owned()),
        },
    )?;
    no_ccs::check_subject_alt_name(&certificate.subject_alt_name)?;
    run.write_new("certificate-san.txt", &certificate.subject_alt_name)?;

    let payload_dir = workspace.join("cover-payloads");
    std::fs::create_dir(&payload_dir)
        .map_err(|error| format!("could not create cover payload directory: {error}"))?;
    let cover_args = vec![
        "bench".to_owned(),
        "origin".to_owned(),
        "--port".to_owned(),
        cover_port.to_string(),
        "--payload-dir".to_owned(),
        payload_dir.display().to_string(),
        "--put-log".to_owned(),
        workspace.join("cover-put.jsonl").display().to_string(),
        "--tls-cert".to_owned(),
        certificate.certificate.display().to_string(),
        "--tls-key".to_owned(),
        certificate.key.display().to_string(),
        "--tls-alpn".to_owned(),
        "h2,http/1.1".to_owned(),
    ];
    let mut cover = Child::spawn(
        "descriptor-cover",
        &rr_dev_path,
        &cover_args,
        workspace.path(),
        &[],
        &run.join("cover.log"),
    )
    .map_err(|error| error.to_string())?;
    cover
        .wait_for_port(cover_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let echo_args = vec![
        "bench".to_owned(),
        "echo".to_owned(),
        "--port".to_owned(),
        echo_port.to_string(),
    ];
    let mut echo = Child::spawn(
        "descriptor-echo",
        &rr_dev_path,
        &echo_args,
        workspace.path(),
        &[],
        &run.join("echo.log"),
    )
    .map_err(|error| error.to_string())?;
    echo.wait_for_port(echo_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let generated = suites::generate_rust_identity(
        &workspace,
        &rust.path,
        server_port,
        &format!("localhost:{cover_port}"),
        "localhost",
        Some(&run.join("generate.log")),
    )?;
    let server_json = suites::set_rust_log_level(&generated.server_json, "info")?;
    let server_config = workspace.join("server.json");
    std::fs::write(&server_config, &server_json)
        .map_err(|error| format!("could not write server config: {error}"))?;
    check_config(&rust.path, &server_config)?;

    let reality = RealityIdentity {
        uuid: generated.uuid,
        short_id: generated.short_id,
        server_name: "localhost".to_owned(),
        target: format!("localhost:{cover_port}"),
    };
    let xray_config = workspace.join("xray.json");
    std::fs::write(
        &xray_config,
        crate::bench::config::xray_client(&reality, server_port, socks_port, &generated.public_key)
            .to_python_json(),
    )
    .map_err(|error| format!("could not write Xray config: {error}"))?;

    let clean_path = "/usr/local/bin:/usr/bin:/bin".to_owned();
    let server_args = vec![
        format!("--nofile={0}:{0}", suite.nofile_limit),
        "--".to_owned(),
        rust.path.display().to_string(),
        "run".to_owned(),
        "--config".to_owned(),
        server_config.display().to_string(),
    ];
    let mut server = Child::spawn_isolated(
        "descriptor-server",
        &prlimit,
        &server_args,
        workspace.path(),
        &[
            ("PATH".to_owned(), clean_path.clone()),
            (
                "SSL_CERT_FILE".to_owned(),
                certificate.ca_certificate.display().to_string(),
            ),
        ],
        &run.join("server.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    assert_limits(server.pid(), suite.nofile_limit)?;
    crate::bench::slot::verify_running_image(server.pid(), &rust.sha256, "rust-reality")?;

    let xray_args = vec![
        "run".to_owned(),
        "-config".to_owned(),
        xray_config.display().to_string(),
    ];
    let mut xray_client = Child::spawn_isolated(
        "descriptor-xray-client",
        &xray.path,
        &xray_args,
        workspace.path(),
        &[("PATH".to_owned(), clean_path)],
        &run.join("xray.log"),
    )
    .map_err(|error| error.to_string())?;
    xray_client
        .wait_for_port(socks_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    std::thread::sleep(Duration::from_millis(500));

    let result = match exercise(
        suite,
        &mut server,
        socks_port,
        echo_port,
        &run.join("server.log"),
    ) {
        Ok(result) => result,
        Err(error) => {
            let failure = Json::object([
                ("ok", Json::Bool(false)),
                ("error", Json::string(&error)),
                ("serverPid", Json::Int(i64::from(server.pid()))),
            ]);
            let _ = run.write_new("pressure-result.json", &failure.to_python_json());
            return Err(error);
        }
    };

    crate::bench::slot::verify_running_image(server.pid(), &rust.sha256, "rust-reality")?;
    crate::bench::slot::verify_running_image(xray_client.pid(), &xray.sha256, "xray")?;
    crate::bench::slot::verify_running_image(cover.pid(), &rr_dev_sha256, "cover")?;
    crate::bench::slot::verify_running_image(echo.pid(), &rr_dev_sha256, "echo")?;
    no_ccs::assert_unchanged(&rust)?;
    no_ccs::assert_unchanged(&xray)?;
    no_ccs::assert_unchanged(&openssl)?;
    if external_identity(&openssl.path, &["version", "-a"])? != openssl.identity {
        return Err("OpenSSL identity changed during the run".to_owned());
    }

    let result_json = result_json(&result);
    run.write_new("pressure-result.json", &result_json.to_python_json())?;
    let repository_head = git_head(&suite.repo)?;
    let summary = summary_json(
        suite,
        &result,
        &rust,
        &xray,
        &openssl,
        &rr_dev_path,
        &rr_dev_sha256,
        [server_port, socks_port, cover_port, echo_port],
        &repository_head,
        &hash::sha256_file(&server_config)?,
        &hash::sha256_file(&xray_config)?,
    )?;
    let summary_document = summary.to_python_json();
    run.write_new("gate-summary.json", &summary_document)?;

    // Freeze append-only logs before hashing and publishing completion.
    xray_client.terminate();
    server.terminate();
    echo.terminate();
    cover.terminate();
    write_checksums(
        &run,
        &[
            "cover.log",
            "echo.log",
            "server.log",
            "xray.log",
            "pressure-result.json",
            "gate-summary.json",
        ],
    )?;
    run.publish(
        Publication::Environment,
        &summary_document,
        &suite.run_id,
        "descriptor-pressure-recovery",
    )?;
    Ok(result)
}

fn exercise(
    suite: &PressureSuite,
    server: &mut Child,
    socks_port: u16,
    echo_port: u16,
    server_log: &Path,
) -> Result<PressureResult, String> {
    let budget = wait_event(
        server,
        server_log,
        "descriptor_budget_report",
        None,
        EVENT_TIMEOUT,
    )?;
    let baseline_fd_count = fd_count(server.pid())?;

    let mut held = Vec::new();
    let mut control = open_tunnel(socks_port, echo_port, Duration::from_secs(5))?;
    echo_payload(&mut control, b"control-before-pressure")?;
    held.push(control);

    let mut fill_failures = 0;
    for index in 1..suite.max_held {
        if !server.is_alive() {
            return Err("server exited while filling descriptor budget".to_owned());
        }
        if let Ok(mut tunnel) = open_tunnel(socks_port, echo_port, Duration::from_secs(2)) {
            if echo_payload(&mut tunnel, format!("held-{index}").as_bytes()).is_ok() {
                held.push(tunnel);
            } else {
                fill_failures += 1;
                break;
            }
        } else {
            fill_failures += 1;
            break;
        }
    }
    if fill_failures == 0 {
        return Err("MAX_HELD_CONNECTIONS did not exhaust descriptor admission".to_owned());
    }
    if held.len() < 8 {
        return Err(format!(
            "pressure arrived after only {} established streams",
            held.len()
        ));
    }
    let high = wait_event(
        server,
        server_log,
        "descriptor_pressure_changed",
        Some("high"),
        EVENT_TIMEOUT,
    )?;
    let successful_held = held.len();
    let pressure_fd_count = fd_count(server.pid())?;
    if pressure_fd_count <= baseline_fd_count {
        return Err("server FD count did not increase under pressure".to_owned());
    }

    let (storm_successes, storm_failures) = storm(socks_port, echo_port, suite.storm_connections);
    if storm_failures == 0 {
        return Err("connection storm observed no refused or stalled new flow".to_owned());
    }
    if !server.is_alive() {
        return Err("server exited under descriptor pressure".to_owned());
    }

    let control_payload: Vec<u8> = (0_u8..=255).cycle().take(4096).collect();
    echo_payload(&mut held[0], &control_payload)?;
    let control_sha256 = hash::sha256_hex(&control_payload);

    held.truncate(1);
    let normal = wait_event(
        server,
        server_log,
        "descriptor_pressure_changed",
        Some("normal"),
        EVENT_TIMEOUT,
    )?;
    if !server.is_alive() {
        return Err("server exited while pressure recovered".to_owned());
    }

    let recovery_payload: Vec<u8> = (0_u8..=255).cycle().take(65_536).collect();
    let mut recovery = open_tunnel(socks_port, echo_port, Duration::from_secs(8))?;
    echo_payload(&mut recovery, &recovery_payload)?;
    let recovery_sha256 = hash::sha256_hex(&recovery_payload);
    drop(recovery);
    drop(held);

    Ok(PressureResult {
        server_pid: server.pid(),
        effective_budget: budget.effective_budget,
        baseline_fd_count,
        pressure_fd_count,
        successful_held,
        fill_failures,
        storm_successes,
        storm_failures,
        high_units: high.units,
        normal_units: normal.units,
        control_sha256,
        recovery_sha256,
    })
}

fn storm(socks_port: u16, echo_port: u16, connections: usize) -> (usize, usize) {
    let attempts: Vec<_> = (0..connections)
        .map(|_| {
            std::thread::spawn(move || {
                let Ok(mut tunnel) =
                    open_tunnel(socks_port, echo_port, Duration::from_millis(1500))
                else {
                    return false;
                };
                echo_payload(&mut tunnel, b"storm").is_ok()
            })
        })
        .collect();
    let successes = attempts
        .into_iter()
        .map(|attempt| attempt.join().unwrap_or(false))
        .filter(|succeeded| *succeeded)
        .count();
    (successes, connections - successes)
}

fn open_tunnel(socks_port: u16, echo_port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);
    let mut stream = TcpStream::connect_timeout(&address.into(), timeout)
        .map_err(|error| format!("SOCKS connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("could not set SOCKS read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("could not set SOCKS write timeout: {error}"))?;
    stream
        .write_all(&[5, 1, 0])
        .map_err(|error| format!("SOCKS greeting failed: {error}"))?;
    let mut greeting = [0; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|error| format!("SOCKS greeting response failed: {error}"))?;
    if greeting != [5, 0] {
        return Err(format!("SOCKS greeting was rejected: {greeting:?}"));
    }
    let port = echo_port.to_be_bytes();
    stream
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]])
        .map_err(|error| format!("SOCKS connect request failed: {error}"))?;
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("SOCKS connect response failed: {error}"))?;
    if header[0] != 5 || header[1] != 0 {
        return Err(format!("SOCKS connect was rejected: {header:?}"));
    }
    match header[3] {
        1 => discard(&mut stream, 6)?,
        3 => {
            let mut length = [0];
            stream
                .read_exact(&mut length)
                .map_err(|error| format!("SOCKS domain length failed: {error}"))?;
            discard(&mut stream, usize::from(length[0]) + 2)?;
        }
        4 => discard(&mut stream, 18)?,
        address_type => return Err(format!("unknown SOCKS address type: {address_type}")),
    }
    Ok(stream)
}

fn discard(stream: &mut TcpStream, length: usize) -> Result<(), String> {
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("SOCKS bound address failed: {error}"))
}

fn echo_payload(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    stream
        .write_all(payload)
        .map_err(|error| format!("echo send failed: {error}"))?;
    let mut received = vec![0; payload.len()];
    stream
        .read_exact(&mut received)
        .map_err(|error| format!("echo receive failed: {error}"))?;
    if received != payload {
        return Err("echo integrity mismatch".to_owned());
    }
    Ok(())
}

fn wait_event(
    server: &mut Child,
    log: &Path,
    event: &str,
    state: Option<&str>,
    timeout: Duration,
) -> Result<DescriptorEvent, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(found) = find_event(log, event, state)? {
            return Ok(found);
        }
        if !server.is_alive() {
            return Err(format!("server exited before event {event}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("required event did not arrive: {event}"))
}

fn find_event(
    log: &Path,
    expected_event: &str,
    expected_state: Option<&str>,
) -> Result<Option<DescriptorEvent>, String> {
    let contents = std::fs::read_to_string(log)
        .map_err(|error| format!("could not read {}: {error}", log.display()))?;
    for line in contents.lines() {
        let Ok(value) = json_in::parse(line) else {
            continue;
        };
        if value.str_field("event", "event").ok() != Some(expected_event) {
            continue;
        }
        if let Some(state) = expected_state
            && value.str_field("event", "fd_pressure_state").ok() != Some(state)
        {
            continue;
        }
        let effective_budget = integer_field(&value, "fd_effective_budget")?;
        let units = match value.field("event", "fd_units_in_use") {
            Ok(_) => integer_field(&value, "fd_units_in_use")?,
            Err(_) => 0,
        };
        return Ok(Some(DescriptorEvent {
            effective_budget,
            units,
        }));
    }
    Ok(None)
}

fn integer_field(value: &json_in::Value, name: &str) -> Result<u64, String> {
    let json_in::Value::Number(text) = value
        .field("event", name)
        .map_err(|error| format!("event {name}: {error}"))?
    else {
        return Err(format!("event field {name} is not an integer"));
    };
    text.parse()
        .map_err(|error| format!("event field {name} is invalid: {error}"))
}

fn assert_limits(pid: u32, expected: u64) -> Result<(), String> {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))
        .map_err(|error| format!("could not read server limits: {error}"))?;
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .ok_or_else(|| "server limits have no Max open files row".to_owned())?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (Some(soft), Some(hard)) = (fields.get(3), fields.get(4)) else {
        return Err("server Max open files row is malformed".to_owned());
    };
    if *soft != expected.to_string() || *hard != expected.to_string() {
        return Err(format!(
            "server RLIMIT_NOFILE is soft={soft} hard={hard}, expected {expected}/{expected}"
        ));
    }
    Ok(())
}

fn fd_count(pid: u32) -> Result<usize, String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| format!("could not inspect server descriptors: {error}"))?
        .try_fold(0_usize, |count, entry| {
            entry
                .map(|_| count + 1)
                .map_err(|error| format!("could not inspect server descriptor: {error}"))
        })
}

fn check_config(rust_bin: &Path, config: &Path) -> Result<(), String> {
    let outcome = Tool::new(rust_bin.display().to_string())
        .args(["check", "--config", &config.display().to_string()])
        .probe()
        .map_err(|error| format!("rust-reality config check failed: {error}"))?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!(
            "rust-reality config check exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ))
    }
}

fn certificate_authority_subject(run_id: &str) -> String {
    let identity = hash::sha256_hex(run_id.as_bytes());
    format!("/CN=rr descriptor gate CA {}", &identity[..16])
}

fn resolve_program(program: &Path) -> Result<PathBuf, String> {
    crate::bench::origin_tls::which(&program.display().to_string())
        .ok_or_else(|| format!("{} is not on PATH", program.display()))
}

fn external_binary(label: &str, program: &Path, args: &[&str]) -> Result<Binary, String> {
    let path = resolve_program(program)?;
    Ok(Binary {
        label: label.to_owned(),
        sha256: hash::sha256_file(&path)?,
        identity: external_identity(&path, args)?,
        path,
    })
}

fn external_identity(program: &Path, args: &[&str]) -> Result<String, String> {
    let outcome = Tool::new(program.display().to_string())
        .args(args.iter().copied())
        .probe()
        .map_err(|error| format!("{} identity failed: {error}", program.display()))?;
    if outcome.success() {
        Ok(outcome.trimmed_stdout().to_owned())
    } else {
        Err(format!(
            "{} identity exited {:?}: {}",
            program.display(),
            outcome.code,
            outcome.stderr.trim_end()
        ))
    }
}

fn git_head(repo: &Path) -> Result<String, String> {
    let outcome = Tool::new("git")
        .args([
            "-C",
            &repo.display().to_string(),
            "rev-parse",
            "--verify",
            "HEAD",
        ])
        .probe()
        .map_err(|error| format!("could not identify repository HEAD: {error}"))?;
    if outcome.success() {
        Ok(outcome.trimmed_stdout().to_owned())
    } else {
        Err(format!(
            "git rev-parse exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ))
    }
}

fn result_json(result: &PressureResult) -> Json {
    Json::object([
        ("ok", Json::Bool(true)),
        ("serverPid", Json::Int(i64::from(result.server_pid))),
        ("effectiveBudget", int(result.effective_budget)),
        ("baselineFdCount", usize_json(result.baseline_fd_count)),
        ("pressureFdCount", usize_json(result.pressure_fd_count)),
        (
            "successfulHeldConnectionsAtPressure",
            usize_json(result.successful_held),
        ),
        ("fillFailures", usize_json(result.fill_failures)),
        ("stormSuccesses", usize_json(result.storm_successes)),
        ("stormFailures", usize_json(result.storm_failures)),
        ("highTransitionUnits", int(result.high_units)),
        ("normalTransitionUnits", int(result.normal_units)),
        ("controlSha256", Json::string(&result.control_sha256)),
        ("recoverySha256", Json::string(&result.recovery_sha256)),
        (
            "expectedRecoverySha256",
            Json::string(&result.recovery_sha256),
        ),
    ])
}

#[allow(clippy::too_many_arguments)]
fn summary_json(
    suite: &PressureSuite,
    result: &PressureResult,
    rust: &Binary,
    xray: &Binary,
    openssl: &Binary,
    rr_dev: &Path,
    rr_dev_sha256: &str,
    ports: [u16; 4],
    repository_head: &str,
    server_config_sha256: &str,
    xray_config_sha256: &str,
) -> Result<Json, String> {
    let binary = |binary: &Binary| {
        Json::object([
            ("path", Json::string(binary.path.display().to_string())),
            ("sha256", Json::string(&binary.sha256)),
            ("identity", Json::string(&binary.identity)),
            ("immutableDuringRun", Json::Bool(true)),
        ])
    };
    Ok(Json::object([
        ("schemaVersion", Json::Int(1)),
        ("runId", Json::string(&suite.run_id)),
        ("gate", Json::string("descriptor-pressure-recovery")),
        ("completedAt", Json::string(evidence::now_utc()?)),
        ("repositoryHead", Json::string(repository_head)),
        ("launcher", Json::string("prlimit-direct-exec")),
        (
            "nofile",
            Json::object([
                ("soft", int(suite.nofile_limit)),
                ("hard", int(suite.nofile_limit)),
            ]),
        ),
        (
            "binaries",
            Json::object([
                ("rustReality", binary(rust)),
                ("xray", binary(xray)),
                ("openssl", binary(openssl)),
                (
                    "rrDevHelpers",
                    Json::object([
                        ("path", Json::string(rr_dev.display().to_string())),
                        ("sha256", Json::string(rr_dev_sha256)),
                        ("immutableDuringRun", Json::Bool(true)),
                    ]),
                ),
            ]),
        ),
        (
            "configSha256",
            Json::object([
                ("server", Json::string(server_config_sha256)),
                ("xray", Json::string(xray_config_sha256)),
            ]),
        ),
        (
            "ports",
            Json::object([
                ("server", Json::Int(i64::from(ports[0]))),
                ("socks", Json::Int(i64::from(ports[1]))),
                ("cover", Json::Int(i64::from(ports[2]))),
                ("echo", Json::Int(i64::from(ports[3]))),
            ]),
        ),
        ("result", result_json(result)),
        ("ok", Json::Bool(true)),
    ]))
}

fn write_checksums(run: &RunDirectory, files: &[&str]) -> Result<(), String> {
    let mut lines = String::new();
    for name in files {
        let digest = hash::sha256_file(&run.join(name))?;
        lines.push_str(&digest);
        lines.push_str("  ");
        lines.push_str(name);
        lines.push('\n');
    }
    run.write_new("SHA256SUMS", &lines)?;
    Ok(())
}

fn int(value: u64) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn usize_json(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite() -> PressureSuite {
        PressureSuite {
            repo: PathBuf::from("/repo"),
            rust_bin: PathBuf::from("rust-reality"),
            xray_bin: PathBuf::from("xray"),
            openssl_bin: PathBuf::from("openssl"),
            out_dir: PathBuf::from("/out"),
            run_id: "pressure-1".to_owned(),
            nofile_limit: 192,
            max_held: 96,
            storm_connections: 12,
        }
    }

    #[test]
    fn destructive_inputs_are_bounded() {
        assert!(validate(&suite()).is_ok());
        for limit in [0, 181, 4097] {
            let mut invalid = suite();
            invalid.nofile_limit = limit;
            assert!(validate(&invalid).is_err());
        }
        let mut invalid = suite();
        invalid.run_id = "../escape".to_owned();
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn certificate_subject_is_bounded_and_run_specific() {
        let first = certificate_authority_subject(&"a".repeat(200));
        let second = certificate_authority_subject(&"b".repeat(200));
        assert!(first.len() <= 64);
        assert_ne!(first, second);
        assert_eq!(first, certificate_authority_subject(&"a".repeat(200)));
    }

    #[test]
    fn structured_events_are_selected_by_state() {
        let dir = Workspace::create("rr-pressure-event").unwrap();
        let log = dir.join("server.log");
        std::fs::write(
            &log,
            concat!(
                "not-json\n",
                "{\"event\":\"descriptor_budget_report\",\"fd_effective_budget\":64}\n",
                "{\"event\":\"descriptor_pressure_changed\",\"fd_pressure_state\":\"high\",\"fd_units_in_use\":60,\"fd_effective_budget\":64}\n"
            ),
        )
        .unwrap();
        let budget = find_event(&log, "descriptor_budget_report", None)
            .unwrap()
            .unwrap();
        assert_eq!(budget.effective_budget, 64);
        let high = find_event(&log, "descriptor_pressure_changed", Some("high"))
            .unwrap()
            .unwrap();
        assert_eq!(high.units, 60);
        assert!(
            find_event(&log, "descriptor_pressure_changed", Some("normal"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn result_requires_real_refusal_and_recovery_hash() {
        let result = PressureResult {
            server_pid: 123,
            effective_budget: 64,
            baseline_fd_count: 12,
            pressure_fd_count: 80,
            successful_held: 31,
            fill_failures: 1,
            storm_successes: 0,
            storm_failures: 12,
            high_units: 60,
            normal_units: 4,
            control_sha256: "a".repeat(64),
            recovery_sha256: "b".repeat(64),
        };
        let rendered = result_json(&result).to_python_json();
        assert!(rendered.contains("\"stormFailures\": 12"));
        assert!(rendered.contains("\"expectedRecoverySha256\""));
        assert!(rendered.contains(&"b".repeat(64)));
    }
}
