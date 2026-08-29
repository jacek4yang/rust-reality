//! Native machine-profile validation lifecycle.
//!
//! This is the typed owner of the cgroup-v2 profile harness. External Linux
//! mechanisms (`systemd-run`, `systemctl`, `setpriv`, Xray and OpenSSL) remain
//! separate programs invoked with explicit argv; topology, identity, sampling,
//! workload policy, aggregation and cleanup live in Rust.

#![allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the profile lifecycle keeps its explicit evidence contract in one typed module"
)]

use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    bench::{
        attest,
        config::{self, RealityIdentity},
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        origin, origin_tls,
        process::{Child, proc_starttime},
        profile_summary, profile_workload, suites,
        workspace::{self, Workspace},
    },
    hash,
    perf::{
        json_in::{self, Value},
        json_out::Json,
    },
    process::Tool,
};

/// A complete profile-validation request.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Repository root.
    pub repo: PathBuf,
    /// Exact rust-reality binary.
    pub rust_bin: PathBuf,
    /// Expected rust-reality SHA-256.
    pub rust_sha256: String,
    /// Full source commit embedded in the binary.
    pub expected_source_commit: String,
    /// Exact Xray binary.
    pub xray_bin: PathBuf,
    /// Expected Xray SHA-256.
    pub xray_sha256: String,
    /// New durable evidence directory.
    pub out_dir: PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// Persistent geo-asset cache.
    pub asset_cache_dir: PathBuf,
    /// Space-separated `name:cpu:memory` specifications.
    pub classes: String,
    /// Optional selected class.
    pub only: Option<String>,
    /// Whether to add the shared 1c1g comparison.
    pub standard_comparison: bool,
    /// Connections per churn sample.
    pub connections: usize,
    /// Churn samples per concurrency.
    pub churn_samples: usize,
    /// Download samples per concurrency.
    pub download_samples: usize,
    /// Download payload size in MiB.
    pub download_mib: u64,
    /// Hold time at each ladder level.
    pub hold_seconds: u64,
    /// Settle time before each ladder sample.
    pub settle_seconds: u64,
    /// Optional default ladder override.
    pub ladder_levels: Option<String>,
    /// Optional tuned ladder override.
    pub tuned_levels: Option<String>,
    /// Stop after immutable identity and host checks.
    pub identity_check_only: bool,
    /// Retain the ephemeral workspace.
    pub keep_work: bool,
}

/// Completed profile run information.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Durable evidence directory.
    pub out_dir: PathBuf,
    /// Number of measured classes.
    pub classes: usize,
    /// Aggregate verdict.
    pub passed: bool,
    /// Whether this was the explicit identity-only preflight.
    pub identity_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassSpec {
    name: String,
    cpu_percent: i64,
    memory_text: String,
    memory_bytes: i64,
    mode: &'static str,
}

#[derive(Debug)]
struct GeneratedConfig {
    nogeo: PathBuf,
    geo: PathBuf,
    tuned: PathBuf,
    identity: RealityIdentity,
    public_key: String,
}

#[derive(Debug)]
struct Scope {
    unit: String,
    control_group_name: String,
    cgroup: PathBuf,
    cpu_percent: i64,
    memory_text: String,
    memory_bytes: i64,
    server_pid: u32,
    server_starttime: String,
    server_sha256: String,
    runner: Child,
    stopped: bool,
    evidence: Json,
}

struct StartingScope {
    unit: String,
    runner: Option<Child>,
}

impl StartingScope {
    fn runner(&mut self) -> &mut Child {
        self.runner
            .as_mut()
            .expect("starting scope owns its runner")
    }

    fn finish(mut self) -> Child {
        self.runner.take().expect("starting scope owns its runner")
    }
}

impl Drop for StartingScope {
    fn drop(&mut self) {
        if let Some(runner) = self.runner.as_mut() {
            let _ = Tool::new("sudo")
                .args(["-n", "systemctl", "stop", &self.unit])
                .probe();
            runner.terminate();
        }
    }
}

impl Scope {
    fn start(
        class: &ClassSpec,
        run: &str,
        rust_bin: &Path,
        rust_sha256: &str,
        config: &Path,
        log: &Path,
        workspace: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<Self, String> {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let unit = format!(
            "rrprof-{}-{run}-{}-{suffix}.scope",
            class.name,
            std::process::id()
        );
        let load_state = systemctl_value(&unit, "LoadState").unwrap_or_default();
        if !load_state.is_empty() && load_state != "not-found" {
            return Err(format!(
                "refusing to reuse pre-existing scope {unit} (LoadState={load_state})"
            ));
        }
        let systemd_run = which("systemd-run")?;
        let args = vec![
            "-n".to_owned(),
            "systemd-run".to_owned(),
            "--scope".to_owned(),
            "--collect".to_owned(),
            "-q".to_owned(),
            format!("--unit={unit}"),
            "-p".to_owned(),
            format!("CPUQuota={}%", class.cpu_percent),
            "-p".to_owned(),
            format!("MemoryMax={}", class.memory_text),
            "-p".to_owned(),
            "MemorySwapMax=0".to_owned(),
            "--".to_owned(),
            "setpriv".to_owned(),
            format!("--reuid={uid}"),
            format!("--regid={gid}"),
            "--clear-groups".to_owned(),
            "env".to_owned(),
            "-i".to_owned(),
            "PATH=/usr/local/bin:/usr/bin:/bin".to_owned(),
            rust_bin.display().to_string(),
            "serve".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
        ];
        // `sudo` is the actual child; `systemd-run` is argv and never parsed by a
        // shell. Resolve it here as a prerequisite so a PATH surprise cannot be
        // misreported as a scope failure.
        let _ = systemd_run;
        let sudo = which("sudo")?;
        let runner = Child::spawn(
            format!("profile scope {unit}"),
            &sudo,
            &args,
            workspace,
            &[],
            log,
        )
        .map_err(|error| error.to_string())?;
        let mut starting = StartingScope {
            unit: unit.clone(),
            runner: Some(runner),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut control_group_name = String::new();
        let mut cgroup = PathBuf::new();
        let mut server_pid = None;
        while Instant::now() < deadline {
            if !starting.runner().is_alive() {
                return Err(format!(
                    "scope runner {unit} exited before the server appeared"
                ));
            }
            if let Ok(group) = systemctl_value(&unit, "ControlGroup")
                && !group.is_empty()
            {
                let path = PathBuf::from("/sys/fs/cgroup").join(group.trim_start_matches('/'));
                if path.is_dir() {
                    control_group_name = group;
                    cgroup = path;
                    server_pid = find_server_pid(&cgroup);
                    if server_pid.is_some() {
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let server_pid = server_pid.ok_or_else(|| format!("server did not appear in {unit}"))?;
        let server_starttime = proc_starttime(server_pid)
            .ok_or_else(|| format!("could not identify server PID {server_pid}"))?;
        let running_sha = attest::running_executable_sha256(server_pid)?;
        if running_sha != rust_sha256 {
            return Err(format!(
                "profile server image mismatch: expected {rust_sha256}, got {running_sha}"
            ));
        }
        let id = systemctl_value(&unit, "Id")?;
        let observed_group = systemctl_value(&unit, "ControlGroup")?;
        if id != unit || observed_group != control_group_name {
            return Err(format!(
                "scope {unit} failed exact unit/cgroup registration"
            ));
        }
        let evidence = verify_cgroup(
            &unit,
            &control_group_name,
            &cgroup,
            class.cpu_percent,
            class.memory_bytes,
            &class.memory_text,
        )?;
        let runner = starting.finish();
        Ok(Self {
            unit,
            control_group_name,
            cgroup,
            cpu_percent: class.cpu_percent,
            memory_text: class.memory_text.clone(),
            memory_bytes: class.memory_bytes,
            server_pid,
            server_starttime,
            server_sha256: rust_sha256.to_owned(),
            runner,
            stopped: false,
            evidence,
        })
    }

    fn is_server_alive(&self) -> bool {
        proc_starttime(self.server_pid).as_deref() == Some(self.server_starttime.as_str())
    }

    fn stop(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        let id = systemctl_value(&self.unit, "Id")?;
        let group = systemctl_value(&self.unit, "ControlGroup")?;
        if id != self.unit || group != self.control_group_name {
            return Err(format!(
                "refusing to stop {}: exact unit/cgroup identity changed",
                self.unit
            ));
        }
        let _ = verify_cgroup(
            &self.unit,
            &self.control_group_name,
            &self.cgroup,
            self.cpu_percent,
            self.memory_bytes,
            &self.memory_text,
        )?;
        if self.is_server_alive() {
            let current_sha = attest::running_executable_sha256(self.server_pid)?;
            if current_sha != self.server_sha256 {
                return Err(format!(
                    "refusing to stop {}: server image identity changed",
                    self.unit
                ));
            }
        }
        let outcome = Tool::new("sudo")
            .args(["-n", "systemctl", "stop", &self.unit])
            .probe()
            .map_err(|error| format!("could not stop {}: {error}", self.unit))?;
        if !outcome.success() {
            return Err(format!(
                "systemctl stop {} failed: {}",
                self.unit,
                outcome.stderr.trim()
            ));
        }
        for _ in 0..100 {
            if !self.is_server_alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if self.is_server_alive() {
            return Err(format!("server survived stopping scope {}", self.unit));
        }
        self.runner.terminate();
        self.stopped = true;
        Ok(())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = Tool::new("sudo")
                .args(["-n", "systemctl", "stop", &self.unit])
                .probe();
            self.runner.terminate();
        }
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn which(program: &str) -> Result<PathBuf, String> {
    std::env::split_paths(
        &std::env::var_os("PATH").ok_or_else(|| "PATH is unavailable".to_owned())?,
    )
    .map(|directory| directory.join(program))
    .find(|candidate| candidate.is_file())
    .ok_or_else(|| format!("required tool is unavailable: {program}"))
}

fn systemctl_value(unit: &str, property: &str) -> Result<String, String> {
    let outcome = Tool::new("systemctl")
        .args(["show", "-p", property, "--value", unit])
        .probe()
        .map_err(|error| format!("systemctl show {unit}: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "systemctl show {unit} {property} failed: {}",
            outcome.stderr.trim()
        ));
    }
    Ok(outcome.trimmed_stdout().to_owned())
}

fn find_server_pid(cgroup: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(cgroup.join("cgroup.procs")).ok()?;
    raw.lines().find_map(|line| {
        let pid = line.trim().parse::<u32>().ok()?;
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        (name.trim() == "rust-reality").then_some(pid)
    })
}

fn read_i64(path: &Path, label: &str) -> Result<i64, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {label} at {}: {error}", path.display()))?;
    raw.trim()
        .parse::<i64>()
        .map_err(|_| format!("{label} is not a finite integer: {}", raw.trim()))
}

fn verify_cgroup(
    unit: &str,
    control_group: &str,
    cgroup: &Path,
    cpu_percent: i64,
    memory_bytes: i64,
    memory_text: &str,
) -> Result<Json, String> {
    let cpu_max = std::fs::read_to_string(cgroup.join("cpu.max"))
        .map_err(|error| format!("could not read cpu.max for {unit}: {error}"))?;
    let mut cpu_fields = cpu_max.split_whitespace();
    let quota = cpu_fields
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("invalid or unbounded cpu.max for {unit}: {cpu_max}"))?;
    let period = cpu_fields
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("invalid cpu.max period for {unit}: {cpu_max}"))?;
    if cpu_fields.next().is_some() || quota * 100 != cpu_percent * period {
        return Err(format!(
            "cpu.max mismatch for {unit}: requested {cpu_percent}%, observed {}",
            cpu_max.trim()
        ));
    }
    let observed_memory = read_i64(&cgroup.join("memory.max"), "memory.max")?;
    let swap_max = read_i64(&cgroup.join("memory.swap.max"), "memory.swap.max")?;
    let swap_current = read_i64(&cgroup.join("memory.swap.current"), "memory.swap.current")?;
    if observed_memory != memory_bytes {
        return Err(format!(
            "memory.max mismatch for {unit}: requested {memory_bytes}, observed {observed_memory}"
        ));
    }
    if swap_max != 0 || swap_current != 0 {
        return Err(format!(
            "swap mismatch for {unit}: memory.swap.max={swap_max}, current={swap_current}"
        ));
    }
    Ok(Json::object([
        ("schemaVersion", Json::Int(1)),
        ("unit", Json::string(unit)),
        ("controlGroup", Json::string(control_group)),
        (
            "requested",
            Json::object([
                ("cpuQuotaPercent", Json::Int(cpu_percent)),
                ("memoryMax", Json::string(memory_text)),
                ("memoryMaxBytes", Json::Int(memory_bytes)),
                ("memorySwapMaxBytes", Json::Int(0)),
            ]),
        ),
        (
            "actual",
            Json::object([
                ("cpuMax", Json::string(cpu_max.trim())),
                ("cpuQuotaUs", Json::Int(quota)),
                ("cpuPeriodUs", Json::Int(period)),
                ("memoryMaxBytes", Json::Int(observed_memory)),
                ("memorySwapMaxBytes", Json::Int(swap_max)),
                ("memorySwapCurrentBytes", Json::Int(swap_current)),
            ]),
        ),
        ("matchesRequested", Json::Bool(true)),
    ]))
}

fn numeric_id(flag: &str) -> Result<u32, String> {
    let outcome = Tool::new("id")
        .arg(flag)
        .run()
        .map_err(|error| error.to_string())?;
    outcome
        .trimmed_stdout()
        .parse::<u32>()
        .map_err(|_| format!("id {flag} did not return a numeric id"))
}

fn wait_port(port: u16, timeout: Duration) -> Result<(), String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "port {port} did not become ready within {:.0}s",
        timeout.as_secs_f64()
    ))
}

fn parse_levels(raw: &str) -> Result<Vec<usize>, String> {
    let levels: Option<Vec<usize>> = raw
        .split([',', ' '])
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<usize>().ok().filter(|value| *value > 0))
        .collect();
    let levels = levels.ok_or_else(|| format!("invalid ladder levels: {raw}"))?;
    if levels.is_empty() || levels.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!(
            "ladder levels must be positive and strictly increasing: {raw}"
        ));
    }
    Ok(levels)
}

fn clean_command(program: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
        "CARGO_HTTP_PROXY",
    ] {
        command.env_remove(name);
    }
    command
}

fn write_new(path: &Path, contents: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn child_object<'a>(
    members: &'a mut BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a mut BTreeMap<String, Value>, String> {
    match members.get_mut(key) {
        Some(Value::Object(child)) => Ok(child),
        _ => Err(format!("generated config has no object field {key}")),
    }
}

fn first_inbound_mut(
    root: &mut BTreeMap<String, Value>,
) -> Result<&mut BTreeMap<String, Value>, String> {
    match root.get_mut("inbounds") {
        Some(Value::Array(inbounds)) => match inbounds.first_mut() {
            Some(Value::Object(inbound)) => Ok(inbound),
            _ => Err("generated config has no first inbound object".to_owned()),
        },
        _ => Err("generated config has no inbounds array".to_owned()),
    }
}

fn generated_identity(root: &BTreeMap<String, Value>) -> Result<(String, String), String> {
    let inbound = match root.get("inbounds") {
        Some(Value::Array(inbounds)) => inbounds.first(),
        _ => None,
    }
    .ok_or_else(|| "generated config has no first inbound".to_owned())?;
    let settings = inbound
        .field("inbound", "settings")
        .map_err(|error| error.to_string())?;
    let client = settings
        .field("settings", "clients")
        .and_then(|value| value.as_array("settings.clients"))
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated config has no client".to_owned())?;
    let uuid = client
        .str_field("client", "id")
        .map_err(|error| error.to_string())?
        .to_owned();
    let short_id = client
        .array_field("client", "shortIds")
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated client has no short id".to_owned())?
        .as_str("client.shortIds[0]")
        .map_err(|error| error.to_string())?
        .to_owned();
    Ok((uuid, short_id))
}

fn generate_configs(
    rust_bin: &Path,
    server_port: u16,
    tls_origin_port: u16,
    class: &ClassSpec,
    asset_cache: &Path,
    prefix: &Path,
) -> Result<GeneratedConfig, String> {
    let output = clean_command(rust_bin)
        .args([
            "config",
            "generate",
            "standalone",
            "--listen",
            "127.0.0.1",
            "--port",
            &server_port.to_string(),
            "--target",
            &format!("127.0.0.1:{tls_origin_port}"),
            "--server-name",
            "localhost",
        ])
        .output()
        .map_err(|error| format!("could not generate profile config: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "profile config generation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let raw = String::from_utf8(output.stdout)
        .map_err(|_| "generated profile config is not UTF-8".to_owned())?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let public_key = stderr
        .lines()
        .find_map(|line| line.strip_prefix("REALITY public key for the client: "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "config generator emitted no REALITY client public key".to_owned())?
        .to_owned();
    let Value::Object(mut root) = json_in::parse(&raw)
        .map_err(|error| format!("generated profile config is invalid JSON: {error}"))?
    else {
        return Err("generated profile config is not an object".to_owned());
    };
    let (uuid, short_id) = generated_identity(&root)?;
    let log = child_object(&mut root, "log")?;
    log.insert("level".to_owned(), Value::Str("info".to_owned()));
    let assets = child_object(&mut root, "assets")?;
    assets.insert(
        "cacheDirectory".to_owned(),
        Value::Str(asset_cache.display().to_string()),
    );
    assets.insert(
        "requestTimeoutSeconds".to_owned(),
        Value::Number("5".to_owned()),
    );
    let runtime = child_object(&mut root, "runtime")?;
    runtime.insert(
        "profile".to_owned(),
        Value::Str(
            if class.mode == "dedicated" {
                "dedicated"
            } else {
                "shared"
            }
            .to_owned(),
        ),
    );
    let nogeo_value = Value::Object(root.clone());
    let nogeo = prefix.with_extension("nogeo.json");
    write_new(&nogeo, &suites::render_compact(&nogeo_value))?;

    let routing = child_object(&mut root, "routing")?;
    routing.insert(
        "globalRules".to_owned(),
        Value::Array(vec![Value::Object(BTreeMap::from([
            ("name".to_owned(), Value::Str("geo-direct".to_owned())),
            ("outbound".to_owned(), Value::Str("direct".to_owned())),
            (
                "domain".to_owned(),
                Value::Array(vec![Value::Str("geosite:cn".to_owned())]),
            ),
            (
                "ip".to_owned(),
                Value::Array(vec![
                    Value::Str("geoip:cn".to_owned()),
                    Value::Str("geoip:private".to_owned()),
                ]),
            ),
        ]))]),
    );
    let geo_value = Value::Object(root.clone());
    let geo = prefix.with_extension("geo.json");
    write_new(&geo, &suites::render_compact(&geo_value))?;

    let advanced = child_object(&mut root, "advanced")?;
    let limits = child_object(advanced, "limits")?;
    let governor = child_object(limits, "resourceGovernor")?;
    governor.insert(
        "maxConnections".to_owned(),
        Value::Number("65536".to_owned()),
    );
    governor.insert("maxHandshakes".to_owned(), Value::Number("8192".to_owned()));
    governor.insert(
        "maxCryptoOperations".to_owned(),
        Value::Number("4096".to_owned()),
    );
    let barrier = child_object(limits, "directBarrier")?;
    barrier.insert(
        "maxConcurrent".to_owned(),
        Value::Number("65536".to_owned()),
    );
    barrier.insert("maxPerSecond".to_owned(), Value::Number("65536".to_owned()));
    let tuned_value = Value::Object(root);
    let tuned = prefix.with_extension("tuned.json");
    write_new(&tuned, &suites::render_compact(&tuned_value))?;
    for config in [&nogeo, &geo, &tuned] {
        let checked = clean_command(rust_bin)
            .args(["check", "--config", &config.display().to_string()])
            .output()
            .map_err(|error| format!("could not validate {}: {error}", config.display()))?;
        if !checked.status.success() {
            return Err(format!(
                "generated config {} failed validation: {}",
                config.display(),
                String::from_utf8_lossy(&checked.stderr).trim()
            ));
        }
    }
    Ok(GeneratedConfig {
        nogeo,
        geo,
        tuned,
        identity: RealityIdentity {
            uuid,
            short_id,
            server_name: "localhost".to_owned(),
            target: format!("127.0.0.1:{tls_origin_port}"),
        },
        public_key,
    })
}

fn write_xray_client(
    generated: &GeneratedConfig,
    server_port: u16,
    socks_port: u16,
    output: &Path,
) -> Result<(), String> {
    write_new(
        output,
        &config::xray_client(
            &generated.identity,
            server_port,
            socks_port,
            &generated.public_key,
        )
        .to_python_json(),
    )
}

fn append_row(path: &Path, row: &Json) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| format!("could not open {}: {error}", path.display()))?;
    writeln!(file, "{}", row.to_jq_json())
        .map_err(|error| format!("could not append {}: {error}", path.display()))
}

fn append_rows(path: &Path, rows: &[Json]) -> Result<(), String> {
    for row in rows {
        append_row(path, row)?;
    }
    Ok(())
}

fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Number(text) => text.parse::<i64>().map_or_else(
            |_| Json::Float(text.parse::<f64>().unwrap_or(f64::NAN)),
            Json::Int,
        ),
        Value::Str(text) => Json::string(text.clone()),
        Value::Array(values) => Json::Array(values.iter().map(value_to_json).collect()),
        Value::Object(values) => Json::object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(value))),
        ),
    }
}

fn last_event(log: &Path, event: &str) -> Option<Json> {
    let raw = std::fs::read_to_string(log).ok()?;
    raw.lines()
        .filter_map(|line| json_in::parse(line).ok())
        .fold(None, |found, row| {
            if row
                .optional("event")
                .and_then(|value| value.as_str("event").ok())
                == Some(event)
            {
                Some(value_to_json(&row))
            } else {
                found
            }
        })
}

fn merge_objects(parts: impl IntoIterator<Item = Json>) -> Json {
    let mut fields = BTreeMap::new();
    for part in parts {
        if let Json::Object(part_fields) = part {
            fields.extend(part_fields);
        }
    }
    Json::Object(fields)
}

fn startup_row(scope: &Scope, run: &str, log: &Path) -> Json {
    merge_objects([
        Json::object([
            ("cell", Json::string("startup")),
            ("run", Json::string(run)),
        ]),
        Json::object([
            (
                "machineReport",
                last_event(log, "machine_report").unwrap_or(Json::Null),
            ),
            (
                "descriptorBudgetReport",
                last_event(log, "descriptor_budget_report").unwrap_or(Json::Null),
            ),
            (
                "relayBackendReport",
                last_event(log, "relay_backend_report").unwrap_or(Json::Null),
            ),
            ("cgroupEvidence", scope.evidence.clone()),
            (
                "configurationPublished",
                Json::Bool(last_event(log, "configuration_published").is_some()),
            ),
        ]),
        Json::object([(
            "idle",
            profile_workload::sample_now(scope.server_pid, &scope.cgroup).to_json(),
        )]),
    ])
}

fn final_row(scope: &Scope, run: &str) -> Json {
    merge_objects([
        Json::object([
            ("cell", Json::string("cgroup_final")),
            ("run", Json::string(run)),
        ]),
        profile_workload::sample_now(scope.server_pid, &scope.cgroup).to_json(),
    ])
}

fn default_ladder_levels(class: &str) -> &'static str {
    if class == "4c8g" {
        "100,500,1000,2000,4000,8000,16000,20000"
    } else {
        "100,500,1000,2000,4000,8000"
    }
}

fn default_tuned_levels(class: &str) -> &'static str {
    match class {
        "1c1g" | "1c1g-standard" => "2000,4000,8000,12000,16000",
        "1c2g" | "2c2g" | "2c4g" | "4c4g" | "4c8g" => "2000,4000,8000,12000,16000,24000",
        _ => "2000,4000,8000,12000",
    }
}

fn launch_xray(
    xray: &Path,
    config: &Path,
    log: &Path,
    workspace: &Path,
    socks_port: u16,
) -> Result<Child, String> {
    let mut child = Child::spawn_isolated(
        "profile Xray client",
        xray,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            config.display().to_string(),
        ],
        workspace,
        &[],
        log,
    )
    .map_err(|error| error.to_string())?;
    child
        .wait_for_port(socks_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    Ok(child)
}

fn start_scope_and_wait(
    class: &ClassSpec,
    run: &str,
    rust_bin: &Path,
    rust_sha256: &str,
    config: &Path,
    log: &Path,
    workspace: &Path,
    uid: u32,
    gid: u32,
    port: u16,
) -> Result<Scope, String> {
    let scope = Scope::start(
        class,
        run,
        rust_bin,
        rust_sha256,
        config,
        log,
        workspace,
        uid,
        gid,
    )?;
    wait_port(port, Duration::from_mins(2))?;
    if !scope.is_server_alive() {
        return Err(format!(
            "profile server exited before port {port} was usable"
        ));
    }
    Ok(scope)
}

#[allow(clippy::too_many_arguments)]
fn run_class(
    plan: &Plan,
    class: &ClassSpec,
    rust_bin: &Path,
    rust_sha256: &str,
    xray_bin: &Path,
    asset_cache: &Path,
    workspace: &Path,
    output: &Path,
    http_port: u16,
    tls_origin_port: u16,
    uid: u32,
    gid: u32,
) -> Result<profile_summary::Outcome, String> {
    let class_dir = output.join(&class.name);
    std::fs::create_dir(&class_dir)
        .map_err(|error| format!("could not create {}: {error}", class_dir.display()))?;
    let cells = class_dir.join("cells.jsonl");
    write_new(&cells, "")?;
    let ports = workspace::reserve_ports(5)?;
    let [port_a, port_b, socks_b, port_c, socks_c] = ports.as_slice() else {
        return Err("could not reserve the profile class port set".to_owned());
    };

    let prefix_a = workspace.join(format!("{}-a", class.name));
    let config_a = generate_configs(
        rust_bin,
        *port_a,
        tls_origin_port,
        class,
        asset_cache,
        &prefix_a,
    )?;
    let log_a = class_dir.join("server-nogeo.log");
    let mut scope_a = start_scope_and_wait(
        class,
        "nogeo",
        rust_bin,
        rust_sha256,
        &config_a.nogeo,
        &log_a,
        workspace,
        uid,
        gid,
        *port_a,
    )?;
    let sampler_a = profile_workload::Sampler::start(
        scope_a.server_pid,
        scope_a.cgroup.clone(),
        class_dir.join("samples-nogeo.tsv"),
    )?;
    std::thread::sleep(Duration::from_secs(3));
    append_row(&cells, &startup_row(&scope_a, "nogeo", &log_a))?;
    sampler_a.stop()?;
    scope_a.stop()?;

    let prefix_b = workspace.join(format!("{}-b", class.name));
    let config_b = generate_configs(
        rust_bin,
        *port_b,
        tls_origin_port,
        class,
        asset_cache,
        &prefix_b,
    )?;
    let xray_b_config = workspace.join(format!("{}-b.xray.json", class.name));
    write_xray_client(&config_b, *port_b, *socks_b, &xray_b_config)?;
    let log_b = class_dir.join("server-geo.log");
    let mut scope_b = start_scope_and_wait(
        class,
        "geo",
        rust_bin,
        rust_sha256,
        &config_b.geo,
        &log_b,
        workspace,
        uid,
        gid,
        *port_b,
    )?;
    let mut xray_b = launch_xray(
        xray_bin,
        &xray_b_config,
        &class_dir.join("xray-client.log"),
        workspace,
        *socks_b,
    )?;
    profile_workload::sanity_probe(*socks_b, http_port)?;
    let sampler_b = profile_workload::Sampler::start(
        scope_b.server_pid,
        scope_b.cgroup.clone(),
        class_dir.join("samples-geo.tsv"),
    )?;
    std::thread::sleep(Duration::from_secs(3));
    append_row(&cells, &startup_row(&scope_b, "geo", &log_b))?;
    append_rows(
        &cells,
        &profile_workload::churn(
            *socks_b,
            http_port,
            scope_b.server_pid,
            &[8, 32],
            plan.connections,
            plan.churn_samples,
        ),
    )?;
    let curl = which("curl")?;
    let payload_bytes = plan
        .download_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "download payload size overflows u64".to_owned())?;
    let origin_url = format!(
        "http://127.0.0.1:{http_port}/payload-{}.bin",
        plan.download_mib
    );
    for concurrency in [1, 32] {
        let rows = profile_workload::download(
            &curl,
            *socks_b,
            &origin_url,
            payload_bytes,
            scope_b.server_pid,
            concurrency,
            plan.download_samples,
        )?;
        append_rows(&cells, &rows)?;
    }
    let ladder_levels = parse_levels(
        plan.ladder_levels
            .as_deref()
            .unwrap_or_else(|| default_ladder_levels(&class.name)),
    )?;
    append_rows(
        &cells,
        &profile_workload::ladder(
            *socks_b,
            http_port,
            scope_b.server_pid,
            &scope_b.server_starttime,
            &log_b,
            &scope_b.cgroup,
            &ladder_levels,
            Duration::from_secs(plan.settle_seconds),
            Duration::from_secs(plan.hold_seconds),
            None,
        ),
    )?;
    append_row(&cells, &final_row(&scope_b, "geo"))?;
    sampler_b.stop()?;
    scope_b.stop()?;
    xray_b.terminate();

    let prefix_c = workspace.join(format!("{}-c", class.name));
    let config_c = generate_configs(
        rust_bin,
        *port_c,
        tls_origin_port,
        class,
        asset_cache,
        &prefix_c,
    )?;
    let tuned_client_config = workspace.join(format!("{}-c.xray.json", class.name));
    write_xray_client(&config_c, *port_c, *socks_c, &tuned_client_config)?;
    let log_c = class_dir.join("server-tuned.log");
    let mut scope_c = start_scope_and_wait(
        class,
        "tuned",
        rust_bin,
        rust_sha256,
        &config_c.tuned,
        &log_c,
        workspace,
        uid,
        gid,
        *port_c,
    )?;
    let mut xray_c = launch_xray(
        xray_bin,
        &tuned_client_config,
        &class_dir.join("xray-client-tuned.log"),
        workspace,
        *socks_c,
    )?;
    let sampler_c = profile_workload::Sampler::start(
        scope_c.server_pid,
        scope_c.cgroup.clone(),
        class_dir.join("samples-tuned.tsv"),
    )?;
    std::thread::sleep(Duration::from_secs(2));
    append_row(&cells, &startup_row(&scope_c, "tuned", &log_c))?;
    let tuned_levels = parse_levels(
        plan.tuned_levels
            .as_deref()
            .unwrap_or_else(|| default_tuned_levels(&class.name)),
    )?;
    append_rows(
        &cells,
        &profile_workload::ladder(
            *socks_c,
            http_port,
            scope_c.server_pid,
            &scope_c.server_starttime,
            &log_c,
            &scope_c.cgroup,
            &tuned_levels,
            Duration::from_secs(plan.settle_seconds),
            Duration::from_secs(plan.hold_seconds),
            Some("tuned"),
        ),
    )?;
    append_row(&cells, &final_row(&scope_c, "tuned"))?;
    sampler_c.stop()?;
    scope_c.stop()?;
    xray_c.terminate();

    let request = profile_summary::Request {
        class_dir,
        class: class.name.clone(),
        resource_mode: class.mode.to_owned(),
        cpu_quota_percent: class.cpu_percent,
        memory_max: class.memory_text.clone(),
        memory_max_bytes: class.memory_bytes,
        memory_swap_max_bytes: 0,
    };
    let outcome = profile_summary::summarize(&request)?;
    profile_summary::write_summary(&request, &outcome)?;
    Ok(outcome)
}

fn host_preflight() -> Result<(), String> {
    for program in [
        "curl",
        "id",
        "openssl",
        "setpriv",
        "sudo",
        "systemctl",
        "systemd-run",
    ] {
        let _ = which(program)?;
    }
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        return Err("profile validation requires a unified cgroup-v2 hierarchy".to_owned());
    }
    let outcome = Tool::new("sudo")
        .args(["-n", "true"])
        .probe()
        .map_err(|error| format!("passwordless sudo preflight failed: {error}"))?;
    if !outcome.success() {
        return Err("passwordless sudo is required for systemd-run scopes".to_owned());
    }
    Ok(())
}

fn absolute_from_repo(repo: &Path, path: &Path) -> Result<PathBuf, String> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    };
    if joined.exists() {
        joined
            .canonicalize()
            .map_err(|error| format!("could not canonicalize {}: {error}", joined.display()))
    } else {
        Ok(joined)
    }
}

fn fetch_asset(cache: &Path, name: &str, url: &str) -> Result<PathBuf, String> {
    let path = cache.join(name);
    if path
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
    {
        return Ok(path);
    }
    let curl = which("curl")?;
    let outcome = Tool::new(curl.display().to_string())
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry",
            "3",
            "--output",
            &path.display().to_string(),
            url,
        ])
        .probe()
        .map_err(|error| format!("could not fetch {name}: {error}"))?;
    if !outcome.success() {
        let _ = std::fs::remove_file(&path);
        return Err(format!("could not fetch {name}: {}", outcome.stderr.trim()));
    }
    if !path
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
    {
        return Err(format!(
            "downloaded asset is empty or missing: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn prepare_assets(plan: &Plan) -> Result<(PathBuf, PathBuf, PathBuf, String, String), String> {
    let cache = absolute_from_repo(&plan.repo, &plan.asset_cache_dir)?;
    if cache.starts_with(&plan.out_dir) {
        return Err("--asset-cache-dir must be outside --out-dir".to_owned());
    }
    std::fs::create_dir_all(&cache)
        .map_err(|error| format!("could not create {}: {error}", cache.display()))?;
    let geoip = fetch_asset(
        &cache,
        "geoip.dat",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
    )?;
    let geosite = fetch_asset(
        &cache,
        "geosite.dat",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
    )?;
    let geoip_sha = hash::sha256_file(&geoip)?;
    let geosite_sha = hash::sha256_file(&geosite)?;
    Ok((cache, geoip, geosite, geoip_sha, geosite_sha))
}

fn command_line(program: &str, args: &[&str]) -> Result<String, String> {
    let outcome = Tool::new(program)
        .args(args.iter().copied())
        .run()
        .map_err(|error| error.to_string())?;
    Ok(outcome.trimmed_stdout().to_owned())
}

#[allow(clippy::too_many_arguments)]
fn environment_json(
    plan: &Plan,
    rust: &identity::Binary,
    xray: &identity::Binary,
    cache: &Path,
    geoip: &Path,
    geosite: &Path,
    geoip_sha: &str,
    geosite_sha: &str,
) -> Result<Json, String> {
    let harness_commit = command_line(
        "git",
        &["-C", &plan.repo.display().to_string(), "rev-parse", "HEAD"],
    )?;
    let kernel = command_line("uname", &["-r"])?;
    let logical_cpus = std::thread::available_parallelism().map_or(0, usize::from);
    let memory_mib = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|raw| {
            raw.lines().find_map(|line| {
                let value = line.strip_prefix("MemTotal:")?;
                value
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
                    .map(|kib| kib / 1024)
            })
        })
        .unwrap_or(0);
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    Ok(Json::object([
        ("commit", Json::string(plan.expected_source_commit.clone())),
        ("harnessCommit", Json::string(harness_commit)),
        ("binary", Json::string(rust.path.display().to_string())),
        ("binarySha256", Json::string(rust.sha256.clone())),
        (
            "binaryEmbeddedCommit",
            Json::string(plan.expected_source_commit.clone()),
        ),
        (
            "outputRoot",
            Json::string(plan.out_dir.display().to_string()),
        ),
        (
            "assetCacheDirectory",
            Json::string(cache.display().to_string()),
        ),
        (
            "geoAssets",
            Json::object([
                (
                    "geoip",
                    Json::object([
                        ("path", Json::string(geoip.display().to_string())),
                        ("sha256", Json::string(geoip_sha)),
                    ]),
                ),
                (
                    "geosite",
                    Json::object([
                        ("path", Json::string(geosite.display().to_string())),
                        ("sha256", Json::string(geosite_sha)),
                    ]),
                ),
            ]),
        ),
        ("xray", Json::string(xray.identity.clone())),
        ("xrayBinary", Json::string(xray.path.display().to_string())),
        ("xraySha256", Json::string(xray.sha256.clone())),
        ("kernel", Json::string(kernel)),
        (
            "host",
            Json::string(format!("{logical_cpus} CPUs, {memory_mib} MiB")),
        ),
        (
            "dateUtc",
            Json::string(crate::bench::evidence::utc_timestamp(
                i64::try_from(seconds).unwrap_or(i64::MAX),
            )),
        ),
        (
            "note",
            Json::string("server CPU via /proc/pid/stat utime+stime; native profile lifecycle"),
        ),
    ]))
}

fn contract_json(
    plan: &Plan,
    phase: &str,
    exit_code: Option<i64>,
    lock: &HostLock,
    rust: &identity::Binary,
    xray: &identity::Binary,
    error: Option<&str>,
) -> Json {
    Json::object([
        ("schemaVersion", Json::Int(1)),
        ("runId", Json::string(plan.run_id.clone())),
        ("collector", Json::string("profile-validation")),
        ("phase", Json::string(phase)),
        ("exitCode", exit_code.map_or(Json::Null, Json::Int)),
        ("error", error.map_or(Json::Null, Json::string)),
        (
            "hostExclusiveLock",
            Json::object([
                ("path", Json::string(lock.path().display().to_string())),
                ("deviceInode", Json::string(lock.device_inode())),
            ]),
        ),
        (
            "binaries",
            Json::object([
                (
                    "rust-reality",
                    Json::object([
                        ("path", Json::string(rust.path.display().to_string())),
                        ("sha256", Json::string(rust.sha256.clone())),
                        (
                            "sourceCommit",
                            Json::string(plan.expected_source_commit.clone()),
                        ),
                    ]),
                ),
                (
                    "xray",
                    Json::object([
                        ("path", Json::string(xray.path.display().to_string())),
                        ("sha256", Json::string(xray.sha256.clone())),
                        ("identity", Json::string(xray.identity.clone())),
                    ]),
                ),
            ]),
        ),
    ])
}

struct Measurement {
    class_rows: Vec<(PathBuf, profile_summary::Outcome)>,
    passed: bool,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn measure(
    plan: &Plan,
    rust: &identity::Binary,
    xray: &identity::Binary,
    classes: &[ClassSpec],
    run_dir: &RunDirectory,
    cache: &Path,
    geoip: &Path,
    geosite: &Path,
    geoip_sha: &str,
    geosite_sha: &str,
) -> Result<Measurement, String> {
    let mut workspace = Workspace::create("profile-validation")?;
    if plan.keep_work {
        workspace.keep();
    }
    let payload_bytes = plan
        .download_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "profile payload size overflows u64".to_owned())?;
    origin::write_payload(&workspace.join("payload.bin"), 256)?;
    origin::write_payload(
        &workspace
            .path()
            .join(format!("payload-{}.bin", plan.download_mib)),
        payload_bytes,
    )?;
    let (certificate, key) = origin_tls::generate_self_signed(workspace.path())?;
    let ports = workspace::reserve_ports(2)?;
    let [http_port, tls_port] = ports.as_slice() else {
        return Err("could not reserve profile origin ports".to_owned());
    };
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not identify rr-dev executable: {error}"))?;
    let mut plain_origin = Child::spawn_isolated(
        "profile HTTP origin",
        &executable,
        &[
            "bench".to_owned(),
            "origin".to_owned(),
            "--port".to_owned(),
            http_port.to_string(),
            "--payload-dir".to_owned(),
            workspace.path().display().to_string(),
            "--put-log".to_owned(),
            workspace.join("put.jsonl").display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join("origin.log"),
    )
    .map_err(|error| error.to_string())?;
    plain_origin
        .wait_for_port(*http_port, Duration::from_secs(10))
        .map_err(|error| error.to_string())?;
    let mut tls_origin = Child::spawn_isolated(
        "profile TLS origin",
        &executable,
        &[
            "bench".to_owned(),
            "origin".to_owned(),
            "--port".to_owned(),
            tls_port.to_string(),
            "--payload-dir".to_owned(),
            workspace.path().display().to_string(),
            "--put-log".to_owned(),
            workspace.join("tls-put.jsonl").display().to_string(),
            "--tls-cert".to_owned(),
            certificate.display().to_string(),
            "--tls-key".to_owned(),
            key.display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join("tls-origin.log"),
    )
    .map_err(|error| error.to_string())?;
    tls_origin
        .wait_for_port(*tls_port, Duration::from_secs(10))
        .map_err(|error| error.to_string())?;
    let uid = numeric_id("-u")?;
    let gid = numeric_id("-g")?;
    let environment = environment_json(
        plan,
        rust,
        xray,
        cache,
        geoip,
        geosite,
        geoip_sha,
        geosite_sha,
    )?;
    run_dir.write_new("environment.json", &environment.to_python_json())?;
    let mut class_rows = Vec::new();
    for class in classes {
        eprintln!(
            "== profile {} (CPUQuota={}% MemoryMax={} mode={})",
            class.name, class.cpu_percent, class.memory_text, class.mode
        );
        let outcome = run_class(
            plan,
            class,
            &rust.path,
            &rust.sha256,
            &xray.path,
            cache,
            workspace.path(),
            run_dir.path(),
            *http_port,
            *tls_port,
            uid,
            gid,
        )?;
        class_rows.push((
            run_dir.path().join(&class.name).join("summary.json"),
            outcome,
        ));
    }
    plain_origin.terminate();
    tls_origin.terminate();
    let (passed, aggregate) = profile_summary::aggregate(&class_rows);
    run_dir.write_new("summary.json", &aggregate.to_python_json())?;
    let parsed_environment = json_in::parse(&environment.to_python_json())?;
    run_dir.write_new(
        "SUMMARY.md",
        &profile_summary::cross_class_markdown(&class_rows, Some(&parsed_environment)),
    )?;
    Ok(Measurement { class_rows, passed })
}

fn memory_bytes(text: &str) -> Result<i64, String> {
    let (digits, multiplier) = if let Some(value) = text.strip_suffix("GiB") {
        (value, 1024_i64.pow(3))
    } else if let Some(value) = text.strip_suffix('G') {
        (value, 1024_i64.pow(3))
    } else if let Some(value) = text.strip_suffix("MiB") {
        (value, 1024_i64.pow(2))
    } else if let Some(value) = text.strip_suffix('M') {
        (value, 1024_i64.pow(2))
    } else if let Some(value) = text.strip_suffix("KiB") {
        (value, 1024)
    } else if let Some(value) = text.strip_suffix('K') {
        (value, 1024)
    } else {
        (text, 1)
    };
    let count = digits
        .parse::<i64>()
        .map_err(|_| format!("invalid finite memory maximum: {text}"))?;
    count
        .checked_mul(multiplier)
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("invalid finite memory maximum: {text}"))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        && name
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
}

fn parse_classes(plan: &Plan) -> Result<Vec<ClassSpec>, String> {
    let mut classes = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for raw in plan.classes.split_whitespace() {
        let mut fields = raw.split(':');
        let (Some(name), Some(cpu), Some(memory), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(format!(
                "invalid class specification (expected name:cpu:memory): {raw}"
            ));
        };
        if !valid_name(name) {
            return Err(format!("class output name is not a safe basename: {name}"));
        }
        let cpu_percent = cpu
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("invalid CPU quota percentage: {raw}"))?;
        let spec = ClassSpec {
            name: name.to_owned(),
            cpu_percent,
            memory_text: memory.to_owned(),
            memory_bytes: memory_bytes(memory)?,
            mode: "dedicated",
        };
        if plan.only.as_deref().is_none_or(|only| only == name) {
            if !names.insert(name.to_owned()) {
                return Err(format!("duplicate class output name: {name}"));
            }
            classes.push(spec);
        }
        if plan.standard_comparison
            && name == "1c1g"
            && plan
                .only
                .as_deref()
                .is_none_or(|only| only == "1c1g-standard")
        {
            if !names.insert("1c1g-standard".to_owned()) {
                return Err("duplicate class output name: 1c1g-standard".to_owned());
            }
            classes.push(ClassSpec {
                name: "1c1g-standard".to_owned(),
                cpu_percent,
                memory_text: memory.to_owned(),
                memory_bytes: memory_bytes(memory)?,
                mode: "standard",
            });
        }
    }
    if classes.is_empty() {
        return Err("no machine profile class was selected".to_owned());
    }
    Ok(classes)
}

fn embedded_commit(identity_json: &str) -> Result<String, String> {
    let value = json_in::parse(identity_json)
        .map_err(|error| format!("rust-reality identity JSON: {error}"))?;
    value
        .field("environment", "gitCommit")
        .and_then(|value| value.as_str("environment.gitCommit"))
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

/// Validates all static profile inputs before any external state is created.
///
/// # Errors
///
/// Returns a precise input diagnostic.
pub fn validate(plan: &Plan) -> Result<(), String> {
    if !valid_hex(&plan.rust_sha256, 64) {
        return Err("--rust-sha256 must be 64 lowercase hexadecimal characters".to_owned());
    }
    if !valid_hex(&plan.xray_sha256, 64) {
        return Err("--xray-sha256 must be 64 lowercase hexadecimal characters".to_owned());
    }
    if !valid_hex(&plan.expected_source_commit, 40) {
        return Err(
            "--expected-source-commit must be 40 lowercase hexadecimal characters".to_owned(),
        );
    }
    if plan.run_id.is_empty() {
        return Err("--run-id must not be empty".to_owned());
    }
    if !plan.out_dir.is_absolute() {
        return Err("--out-dir must be absolute".to_owned());
    }
    if plan.out_dir.symlink_metadata().is_ok() {
        return Err(format!(
            "--out-dir must not already exist: {}",
            plan.out_dir.display()
        ));
    }
    if plan.connections == 0
        || plan.churn_samples == 0
        || plan.download_samples == 0
        || plan.download_mib == 0
    {
        return Err("profile workload counts and payload size must be positive".to_owned());
    }
    let _ = parse_classes(plan)?;
    Ok(())
}

/// Runs the native profile harness.
///
/// # Errors
///
/// Returns a setup or measurement diagnostic. A completed aggregate gate is
/// returned even when its verdict is failure.
pub fn run(plan: &Plan) -> Result<Outcome, String> {
    validate(plan)?;
    host_preflight()?;
    let lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let rust = identity::register(
        "rust-reality",
        &plan.rust_bin,
        &plan.rust_sha256,
        Kind::Rust,
    )?;
    let xray = identity::register("xray", &plan.xray_bin, &plan.xray_sha256, Kind::Xray)?;
    let observed_commit = embedded_commit(&rust.identity)?;
    if observed_commit != plan.expected_source_commit {
        return Err(format!(
            "rust-reality embedded commit mismatch: expected {}, got {observed_commit}",
            plan.expected_source_commit
        ));
    }
    if plan.identity_check_only {
        return Ok(Outcome {
            out_dir: plan.out_dir.clone(),
            classes: 0,
            passed: true,
            identity_only: true,
        });
    }
    let classes = parse_classes(plan)?;
    let (cache, geoip, geosite, geoip_sha, geosite_sha) = prepare_assets(plan)?;
    let run_dir = RunDirectory::create(&plan.out_dir)?;
    run_dir.write_new(
        "run-contract.json",
        &contract_json(plan, "running", None, &lock, &rust, &xray, None).to_python_json(),
    )?;
    let measurement = match measure(
        plan,
        &rust,
        &xray,
        &classes,
        &run_dir,
        &cache,
        &geoip,
        &geosite,
        &geoip_sha,
        &geosite_sha,
    ) {
        Ok(measurement) => measurement,
        Err(error) => {
            let failed = contract_json(plan, "failed", Some(1), &lock, &rust, &xray, Some(&error));
            let _ = std::fs::write(run_dir.join("run-contract.json"), failed.to_python_json());
            return Err(error);
        }
    };
    let post_identity = (|| {
        let rust_after = hash::sha256_file(&rust.path)?;
        let xray_after = hash::sha256_file(&xray.path)?;
        let geoip_after = hash::sha256_file(&geoip)?;
        let geosite_after = hash::sha256_file(&geosite)?;
        if rust_after != rust.sha256 {
            return Err("rust-reality binary changed during profile validation".to_owned());
        }
        if xray_after != xray.sha256 {
            return Err("Xray binary changed during profile validation".to_owned());
        }
        if geoip_after != geoip_sha || geosite_after != geosite_sha {
            return Err("geo asset cache changed during profile validation".to_owned());
        }
        Ok(())
    })();
    if let Err(error) = post_identity {
        let failed = contract_json(plan, "failed", Some(1), &lock, &rust, &xray, Some(&error));
        let _ = std::fs::write(run_dir.join("run-contract.json"), failed.to_python_json());
        return Err(error);
    }
    if measurement.passed {
        run_dir.publish(
            Publication::Contract,
            &contract_json(plan, "complete", Some(0), &lock, &rust, &xray, None).to_python_json(),
            &plan.run_id,
            "profile-validation",
        )?;
    } else {
        let failed = contract_json(
            plan,
            "failed",
            Some(1),
            &lock,
            &rust,
            &xray,
            Some("one or more profile class gates failed"),
        );
        std::fs::write(run_dir.join("run-contract.json"), failed.to_python_json())
            .map_err(|error| format!("could not finalize failed profile contract: {error}"))?;
    }
    Ok(Outcome {
        out_dir: plan.out_dir.clone(),
        classes: measurement.class_rows.len(),
        passed: measurement.passed,
        identity_only: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            repo: PathBuf::from("/repo"),
            rust_bin: PathBuf::from("/rust"),
            rust_sha256: "a".repeat(64),
            expected_source_commit: "b".repeat(40),
            xray_bin: PathBuf::from("/xray"),
            xray_sha256: "c".repeat(64),
            out_dir: std::env::temp_dir().join(format!(
                "rr-profile-plan-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
            run_id: "profile-test".to_owned(),
            asset_cache_dir: PathBuf::from("cache"),
            classes: "1c1g:100:1G 2c4g:200:4G".to_owned(),
            only: None,
            standard_comparison: true,
            connections: 96,
            churn_samples: 3,
            download_samples: 2,
            download_mib: 512,
            hold_seconds: 8,
            settle_seconds: 3,
            ladder_levels: None,
            tuned_levels: None,
            identity_check_only: false,
            keep_work: false,
        }
    }

    #[test]
    fn class_parser_adds_the_standard_comparison_once() {
        let classes = parse_classes(&plan()).unwrap();
        assert_eq!(classes.len(), 3);
        assert_eq!(classes[1].name, "1c1g-standard");
        assert_eq!(classes[1].mode, "standard");
        assert_eq!(classes[2].memory_bytes, 4 * 1024_i64.pow(3));
    }

    #[test]
    fn only_selects_the_logical_comparison_name() {
        let mut plan = plan();
        plan.only = Some("1c1g-standard".to_owned());
        let classes = parse_classes(&plan).unwrap();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "1c1g-standard");
    }

    #[test]
    fn malformed_or_duplicate_classes_fail_before_a_run() {
        let mut plan = plan();
        plan.classes = "bad 1c1g:100:1G".to_owned();
        assert!(parse_classes(&plan).is_err());
        plan.classes = "1c1g:100:1G 1c1g:200:2G".to_owned();
        assert!(parse_classes(&plan).is_err());
    }
}
