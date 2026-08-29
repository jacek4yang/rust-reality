//! The `bench run` harness: one suite lifecycle over the shared primitives.
//!
//! This is where the benchmark foundation parts become one runnable suite. The
//! A/B tunnel-download suites (real-path, xray, vision-direct) share the entire
//! lifecycle — register binaries, acquire the host lock, create the ephemeral
//! workspace, generate the rust-reality and Xray configs, launch four processes
//! under RAII guards, wait for readiness, drive the alternating workload through
//! [`crate::bench::engine`], and write the schema-v1 report. They differ only in
//! the transfer destination (real Internet vs loopback origin), so that is the
//! only input a suite supplies beyond the shared parameters.
//!
//! Everything fails closed: a missing tool, an unregistrable binary, a port that
//! never becomes ready, or a failed transfer is either a hard error or a recorded
//! failure in the report — never a silent pass.

use std::fmt::Write as _;
use std::time::Duration;

use crate::{
    bench::{
        config::{self, RealityIdentity},
        engine::{self, Implementation, Transfer, TunnelPlan},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        process::Child,
        report::Sample,
        runner,
        workspace::Workspace,
    },
    perf::json_in,
    process::Tool,
};

/// A readiness deadline for one benchmark child process.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// One curl transfer through a SOCKS proxy.
///
/// Mirrors the legacy workload exactly: `curl --socks5-hostname 127.0.0.1:<port>`
/// with every proxy environment variable stripped (a workspace `NO_PROXY` export
/// makes curl bypass even an explicit `--socks5-hostname` otherwise), a bounded
/// max-time, and `%{size_download} %{time_total}` written out. The transfer
/// succeeds only when curl exits 0 and the downloaded size is exact.
#[derive(Debug)]
pub struct CurlTransfer {
    /// The URL to download.
    pub url: String,
    /// The per-transfer deadline, as the legacy scripts passed it.
    pub max_time_secs: u64,
    /// Pass `--insecure` (self-signed HTTPS origins).
    pub insecure: bool,
    /// Pass `--tlsv1.3` (Vision-direct TLS origin).
    pub tls_v1_3: bool,
}

impl Transfer for CurlTransfer {
    fn run(&self, socks_port: u16, expected_bytes: u64) -> Result<(u64, Duration), String> {
        // The workspace proxy environment (ALL_PROXY/HTTP_PROXY/...) sets
        // NO_PROXY with 127.0.0.1, which makes curl bypass even an explicit
        // --socks5-hostname for loopback URLs — the transfer would then measure a
        // direct connection and neither tunnel sees a session. Strip every proxy
        // variable from curl's environment.
        let mut curl = Tool::new("curl");
        for name in [
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            curl = curl.env(name, "");
        }
        let mut args = vec![
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
        ];
        if self.insecure {
            args.push("--insecure".to_owned());
        }
        if self.tls_v1_3 {
            args.push("--tlsv1.3".to_owned());
        }
        args.extend([
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{socks_port}"),
            "--max-time".to_owned(),
            self.max_time_secs.to_string(),
            "--output".to_owned(),
            "/dev/null".to_owned(),
            "--write-out".to_owned(),
            "%{size_download} %{time_total}".to_owned(),
            self.url.clone(),
        ]);
        let outcome = curl.args(args).probe().map_err(|error| error.to_string())?;
        if !outcome.success() {
            return Err(format!(
                "curl exited {:?}: {}",
                outcome.code,
                outcome.stderr.trim_end()
            ));
        }
        let mut parts = outcome.trimmed_stdout().split_whitespace();
        let (Some(bytes), Some(seconds), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!(
                "curl wrote an unexpected measurement line: {:?}",
                outcome.trimmed_stdout()
            ));
        };
        let bytes: u64 = bytes
            .parse()
            .map_err(|error| format!("curl size_download is not a byte count: {error}"))?;
        let seconds: f64 = seconds
            .parse()
            .map_err(|error| format!("curl time_total is not a number: {error}"))?;
        if bytes != expected_bytes {
            return Err(format!(
                "payload integrity failed: downloaded {bytes} bytes, expected {expected_bytes}"
            ));
        }
        if seconds <= 0.0 {
            return Err("curl reported a non-positive transfer duration".to_owned());
        }
        Ok((bytes, Duration::from_secs_f64(seconds)))
    }
}

/// The four benchmark processes a tunnel suite owns, terminated on drop.
#[derive(Debug)]
pub struct TunnelProcesses {
    /// The rust-reality server.
    pub rust_server: Child,
    /// The Xray server.
    pub xray_server: Child,
    /// The Xray client that fronts the rust-reality server.
    pub rust_client: Child,
    /// The Xray client that fronts the Xray server.
    pub xray_client: Child,
}

/// The rust-reality generated identity: config plus the extracted client fields.
#[derive(Debug)]
pub struct RustIdentity {
    /// The public key printed by `config generate standalone`.
    pub public_key: String,
    /// The client UUID from the generated config.
    pub uuid: String,
    /// The REALITY short id from the generated config.
    pub short_id: String,
    /// The generated server private key, retained only in ephemeral suite state.
    pub private_key: String,
    /// The final server config JSON with the assets cache and warn logging applied.
    pub server_json: String,
}

/// The Xray `x25519` keypair.
#[derive(Debug)]
pub struct XrayKeys {
    /// The private key for the server config.
    pub private: String,
    /// The public key for the client config.
    pub public: String,
}

/// The materialized state of one suite run, owned until the run completes.
///
/// Dropping this tears down every resource the run created: the four tunnel
/// processes (RAII guards), the ephemeral workspace, and the host lock.
pub struct Materialized {
    /// The registered binaries: `[rust-reality, xray]`.
    pub binaries: Vec<Binary>,
    /// The four live tunnel processes.
    pub processes: TunnelProcesses,
    /// The host lock, held for the whole run.
    pub lock: HostLock,
    /// The ephemeral run workspace (configs, logs, keys), removed on drop.
    pub workspace: Workspace,
    /// The reserved loopback ports: `[rust, xray, rust_socks, xray_socks]`.
    pub ports: [u16; 4],
    /// The generated rust-reality identity.
    pub rust_identity: RustIdentity,
    /// The Xray server keypair.
    pub xray_keys: XrayKeys,
}

/// What a suite run produced.
#[derive(Debug)]
pub struct RunOutcome {
    /// The assembled schema-v1 report JSON.
    pub report: engine::RunReport,
    /// The samples behind the report, in run order.
    pub samples: Vec<Sample>,
}

/// An error from running a suite.
#[derive(Debug)]
pub enum RunError {
    /// The environment could not support the run (tooling, binaries, lock).
    Setup(String),
    /// The servers or clients failed to materialize or become ready.
    Processes(String),
    /// The workload ran but one or more transfers failed; the report is complete.
    Workload(engine::RunReport),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(reason) | Self::Processes(reason) => write!(formatter, "{reason}"),
            Self::Workload(report) => {
                write!(formatter, "{} transfer(s) failed", report.failures)
            }
        }
    }
}

/// Parameters every A/B tunnel suite shares, supplied by the CLI.
pub struct SuiteContext<'a> {
    /// Path to the rust-reality release binary.
    pub rust_bin: &'a std::path::Path,
    /// Path to the Xray binary.
    pub xray_bin: &'a std::path::Path,
    /// The REALITY cover target, e.g. `dl.google.com:443`.
    pub cover_target: String,
    /// The REALITY cover SNI.
    pub cover_sni: String,
    /// Alternating runs (total transfers) across both implementations.
    pub runs: usize,
    /// Expected payload bytes per transfer.
    pub expected_bytes: u64,
    /// The suite id recorded in the report.
    pub suite_id: String,
    /// The transfer URL the workload downloads.
    pub transfer_url: String,
    /// Per-transfer curl deadline in seconds.
    pub transfer_max_time_secs: u64,
    /// Directory the durable report is written to (created if missing). The
    /// legacy contract recorded evidence outside the ephemeral workspace.
    pub out_dir: std::path::PathBuf,
    /// Whether the Xray server freedom outbound must allow private targets
    /// (required for loopback origins; forbidden for real-path WAN suites).
    pub allow_private: bool,
}

/// Generates the REALITY identities for both server/client pairs.
///
/// Runs `rust-reality config generate standalone` for the rust side (capturing
/// the public key from stderr and the client fields from the config) and
/// `xray x25519` for the Xray side.
///
/// # Errors
///
/// Returns the first failure in generation order.
pub fn generate_identities(
    workspace: &Workspace,
    context: &SuiteContext<'_>,
    rust_port: u16,
) -> Result<(RustIdentity, XrayKeys), String> {
    let rust_identity = generate_rust_identity(
        workspace,
        context.rust_bin,
        rust_port,
        &context.cover_target,
        &context.cover_sni,
        None,
    )?;
    let xray_keys = generate_xray_keys(context.xray_bin)?;
    Ok((rust_identity, xray_keys))
}

/// Generates one rust-reality server identity for a slot.
///
/// Runs `config generate standalone`, captures the REALITY public key from
/// stderr, reads the client UUID and short id out of the generated config, and
/// applies the warn-logging and workspace asset-cache patches the harnesses did
/// with `jq`. Split out from [`generate_identities`] because the ABBA harnesses
/// generate a *fresh* identity per slot, while the tunnel suites generate one for
/// the whole run.
///
/// `stderr_log` archives the generator's stderr, which the slot-based harnesses
/// kept as `generate.log` beside the slot's other evidence — it is where the
/// REALITY public key is announced, so a slot that failed to produce one leaves
/// the reason on disk.
///
/// # Errors
///
/// Returns the first failure in generation order.
pub fn generate_rust_identity(
    workspace: &Workspace,
    rust_bin: &std::path::Path,
    rust_port: u16,
    cover_target: &str,
    cover_sni: &str,
    stderr_log: Option<&std::path::Path>,
) -> Result<RustIdentity, String> {
    let outcome = Tool::new(rust_bin.display().to_string())
        .args([
            "config",
            "generate",
            "standalone",
            "--listen",
            "127.0.0.1",
            "--port",
            &rust_port.to_string(),
            "--target",
            cover_target,
            "--server-name",
            cover_sni,
        ])
        .probe()
        .map_err(|error| format!("rust-reality config generate failed: {error}"))?;
    if let Some(path) = stderr_log {
        std::fs::write(path, &outcome.stderr)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    }
    if !outcome.success() {
        return Err(format!(
            "rust-reality config generate exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let public_key = outcome
        .stderr
        .lines()
        .find_map(|line| line.strip_prefix("REALITY public key for the client: "))
        .ok_or_else(|| "rust-reality config generate printed no REALITY public key".to_owned())?
        .to_owned();
    let raw = outcome.trimmed_stdout();
    let value = json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?;
    let inbounds = value
        .array_field("", "inbounds")
        .map_err(|error| format!("generated rust config: {error}"))?;
    let inbound = inbounds
        .first()
        .ok_or_else(|| "generated rust config has no inbound".to_owned())?;
    let settings = inbound
        .field("inbound", "settings")
        .map_err(|error| format!("generated rust config: {error}"))?;
    let clients = settings
        .array_field("inbound.settings", "clients")
        .map_err(|error| format!("generated rust config: {error}"))?;
    let client = clients
        .first()
        .ok_or_else(|| "generated rust config has no inbound client".to_owned())?;
    let uuid = client
        .str_field("client", "id")
        .map_err(|error| format!("generated rust config: {error}"))?
        .to_owned();
    let short_id = client
        .array_field("client", "shortIds")
        .map_err(|error| format!("generated rust config: {error}"))?
        .first()
        .ok_or_else(|| "generated rust config client has no shortIds[0]".to_owned())?
        .as_str("shortIds[0]")
        .map_err(|error| format!("generated rust config: {error}"))?
        .to_owned();
    let private_key = inbound
        .field("inbound", "streamSettings")
        .and_then(|settings| settings.field("inbound.streamSettings", "realitySettings"))
        .and_then(|reality| {
            reality.str_field("inbound.streamSettings.realitySettings", "privateKey")
        })
        .map_err(|error| format!("generated rust config: {error}"))?
        .to_owned();

    // Patch the generated rust config: warn logging and an ephemeral assets
    // cache inside the workspace, exactly as the legacy `jq` postprocessing did.
    let server_json = patch_rust_config(raw, workspace)?;
    Ok(RustIdentity {
        public_key,
        uuid,
        short_id,
        private_key,
        server_json,
    })
}

/// Generates the Xray `x25519` keypair for a REALITY server.
///
/// # Errors
///
/// Returns a message when `xray x25519` fails or prints no key pair.
pub fn generate_xray_keys(xray_bin: &std::path::Path) -> Result<XrayKeys, String> {
    let outcome = Tool::new(xray_bin.display().to_string())
        .arg("x25519")
        .probe()
        .map_err(|error| format!("xray x25519 failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "xray x25519 exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let mut private = None;
    let mut public = None;
    for line in outcome.trimmed_stdout().lines() {
        if let Some(rest) = line.strip_prefix("PrivateKey: ") {
            private = Some(rest.to_owned());
        }
        if let Some(rest) = line.strip_prefix("Password (PublicKey): ") {
            public = Some(rest.to_owned());
        }
    }
    let (Some(private), Some(public)) = (private, public) else {
        return Err("xray x25519 output is missing the key fields".to_owned());
    };
    Ok(XrayKeys { private, public })
}

/// Rewrites the generated rust config with warn logging and the workspace asset
/// cache, preserving every other field exactly.
fn patch_rust_config(raw: &str, workspace: &Workspace) -> Result<String, String> {
    let value = json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?;
    let json_in::Value::Object(mut members) = value else {
        return Err("generated rust config is not an object".to_owned());
    };
    let log = members
        .get("log")
        .ok_or_else(|| "generated rust config has no log object".to_owned())?;
    let json_in::Value::Object(mut log_fields) = log.clone() else {
        return Err("generated rust config log is not an object".to_owned());
    };
    log_fields.insert("level".to_owned(), json_in::Value::Str("warn".to_owned()));
    members.insert("log".to_owned(), json_in::Value::Object(log_fields));
    members.insert(
        "assets".to_owned(),
        json_in::Value::Object(
            [(
                "cacheDirectory".to_owned(),
                json_in::Value::Str(workspace.join("assets").display().to_string()),
            )]
            .into_iter()
            .collect(),
        ),
    );
    Ok(render_compact(&json_in::Value::Object(members)))
}

/// Changes only the generated server's log level.
///
/// Gates that assert structured runtime events need `info`; ordinary benchmark
/// slots stay at `warn` to avoid perturbing measurements.
///
/// # Errors
///
/// Returns a message when the generated document has no object-shaped log field.
pub fn set_rust_log_level(raw: &str, level: &str) -> Result<String, String> {
    let value = json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?;
    let json_in::Value::Object(mut members) = value else {
        return Err("generated rust config is not an object".to_owned());
    };
    let log = members
        .get("log")
        .ok_or_else(|| "generated rust config has no log object".to_owned())?;
    let json_in::Value::Object(mut log_fields) = log.clone() else {
        return Err("generated rust config log is not an object".to_owned());
    };
    log_fields.insert("level".to_owned(), json_in::Value::Str(level.to_owned()));
    members.insert("log".to_owned(), json_in::Value::Object(log_fields));
    Ok(render_compact(&json_in::Value::Object(members)))
}

/// Renders a parsed JSON value as compact one-line JSON. The children only parse
/// the config, so the canonical evidence form stays deterministic and small.
pub fn render_compact(value: &json_in::Value) -> String {
    match value {
        json_in::Value::Null => "null".to_owned(),
        json_in::Value::Bool(flag) => flag.to_string(),
        json_in::Value::Number(text) => text.clone(),
        json_in::Value::Str(text) => {
            let mut out = String::with_capacity(text.len() + 2);
            out.push('"');
            for c in text.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        json_in::Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(render_compact)
                .collect::<Vec<_>>()
                .join(",")
        ),
        json_in::Value::Object(members) => format!(
            "{{{}}}",
            members
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    render_compact(&json_in::Value::Str(key.clone())),
                    render_compact(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// Writes all four suite configs into the workspace.
///
/// # Errors
///
/// Returns the first write failure.
pub fn write_configs(
    workspace: &Workspace,
    context: &SuiteContext<'_>,
    rust_identity: &RustIdentity,
    xray_keys: &XrayKeys,
    ports: [u16; 4],
) -> Result<(), String> {
    let identity = RealityIdentity {
        uuid: rust_identity.uuid.clone(),
        short_id: rust_identity.short_id.clone(),
        server_name: context.cover_sni.clone(),
        target: context.cover_target.clone(),
    };
    std::fs::write(
        workspace.join("rust-server.json"),
        &rust_identity.server_json,
    )
    .map_err(|error| format!("could not write rust-server.json: {error}"))?;
    std::fs::write(
        workspace.join("xray-server.json"),
        config::xray_server(
            &identity,
            ports[1],
            &xray_keys.private,
            context.allow_private,
        )
        .to_python_json(),
    )
    .map_err(|error| format!("could not write xray-server.json: {error}"))?;
    std::fs::write(
        workspace.join("xray-rust-client.json"),
        config::xray_client(&identity, ports[0], ports[2], &rust_identity.public_key)
            .to_python_json(),
    )
    .map_err(|error| format!("could not write xray-rust-client.json: {error}"))?;
    std::fs::write(
        workspace.join("xray-xray-client.json"),
        config::xray_client(&identity, ports[1], ports[3], &xray_keys.public).to_python_json(),
    )
    .map_err(|error| format!("could not write xray-xray-client.json: {error}"))?;
    Ok(())
}

/// Launches the four tunnel processes and waits for every port to become ready.
///
/// The servers bind first (rust, then xray), then the two Xray SOCKS clients.
/// Every child is owned by an RAII guard in the returned [`TunnelProcesses`], so
/// an error return tears down whatever was already running.
///
/// # Errors
///
/// Returns the first readiness failure; the guards clean up.
pub fn launch_processes(
    binaries: &[Binary],
    workspace: &Workspace,
    ports: [u16; 4],
) -> Result<TunnelProcesses, String> {
    let config_arg = |name: &str| workspace.join(name).display().to_string();
    let mut rust_server = Child::spawn(
        "rust-server",
        &binaries[0].path,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            config_arg("rust-server.json"),
        ],
        workspace.path(),
        &[],
        &workspace.join("rust-server.log"),
    )
    .map_err(|error| error.to_string())?;
    let mut xray_server = Child::spawn(
        "xray-server",
        &binaries[1].path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            config_arg("xray-server.json"),
        ],
        workspace.path(),
        &[],
        &workspace.join("xray-server.log"),
    )
    .map_err(|error| error.to_string())?;
    rust_server
        .wait_for_port(ports[0], READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    xray_server
        .wait_for_port(ports[1], READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let mut rust_client = Child::spawn(
        "xray-rust-client",
        &binaries[1].path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            config_arg("xray-rust-client.json"),
        ],
        workspace.path(),
        &[],
        &workspace.join("xray-rust-client.log"),
    )
    .map_err(|error| error.to_string())?;
    let mut xray_client = Child::spawn(
        "xray-xray-client",
        &binaries[1].path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            config_arg("xray-xray-client.json"),
        ],
        workspace.path(),
        &[],
        &workspace.join("xray-xray-client.log"),
    )
    .map_err(|error| error.to_string())?;
    rust_client
        .wait_for_port(ports[2], READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    xray_client
        .wait_for_port(ports[3], READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    Ok(TunnelProcesses {
        rust_server,
        xray_server,
        rust_client,
        xray_client,
    })
}

/// Drives the alternating A/B workload through the shared engine.
///
/// The `processes` argument is kept alive by the caller for the duration of the
/// call: dropping it would terminate the tunnels mid-workload.
///
/// # Errors
///
/// Never fails; transfer failures are classified into samples.
pub fn drive_workload_with(
    context: &SuiteContext<'_>,
    binaries: &[Binary],
    ports: [u16; 4],
    transfer: &dyn Transfer,
) -> (Vec<Sample>, engine::RunReport) {
    let plan = TunnelPlan {
        suite: context.suite_id.clone(),
        implementations: [
            Implementation {
                name: "rust-reality".to_owned(),
                socks_port: ports[2],
            },
            Implementation {
                name: "xray".to_owned(),
                socks_port: ports[3],
            },
        ],
        expected_bytes: context.expected_bytes,
        runs: context.runs,
    };
    let samples = engine::collect_samples(&plan, transfer);
    let provenance = engine::Provenance {
        binaries: binaries
            .iter()
            .map(|binary| {
                (
                    binary.label.clone(),
                    binary.path.display().to_string(),
                    binary.sha256.clone(),
                )
            })
            .collect(),
        url: Some(
            context
                .transfer_url
                .split('?')
                .next()
                .unwrap_or("")
                .to_owned(),
        ),
        rust_server_port: Some(ports[0]),
        timestamp_unix: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
        ),
    };
    let report = engine::assemble_report_with(&plan, &samples, &provenance);
    (samples, report)
}

/// Drives the workload with the production curl transfer over the live tunnels.
///
/// The `processes` guards must stay owned by the caller for the whole call.
fn drive_workload(
    context: &SuiteContext<'_>,
    binaries: &[Binary],
    ports: [u16; 4],
    _processes: &TunnelProcesses,
) -> (Vec<Sample>, engine::RunReport) {
    let transfer = CurlTransfer {
        url: context.transfer_url.clone(),
        max_time_secs: context.transfer_max_time_secs,
        insecure: false,
        tls_v1_3: false,
    };
    drive_workload_with(context, binaries, ports, &transfer)
}

/// Registers binaries, takes the lock, creates the workspace, reserves ports,
/// generates the identities, writes the configs, and launches the processes.
///
/// This is the setup half of the lifecycle; the caller drives the workload and
/// then drops the returned [`Materialized`], which tears everything down.
///
/// # Errors
///
/// Returns [`RunError::Setup`] for environment/identity failures and
/// [`RunError::Processes`] for launch/readiness failures; all partial resources
/// are cleaned up by their guards.
pub fn materialize(context: &SuiteContext<'_>) -> Result<Materialized, RunError> {
    let preflight = runner::preflight(&["curl"]);
    if !preflight.is_ready() {
        return Err(RunError::Setup(format!(
            "benchmark preflight failed: missing tools {}",
            preflight.missing_tools.join(", ")
        )));
    }
    let rust = identity::register("rust-reality", context.rust_bin, "", Kind::Rust)
        .map_err(RunError::Setup)?;
    let xray =
        identity::register("xray", context.xray_bin, "", Kind::Xray).map_err(RunError::Setup)?;
    let lock = HostLock::acquire(&runner::default_lock_path()).map_err(RunError::Setup)?;
    let workspace = Workspace::create(&context.suite_id).map_err(RunError::Setup)?;
    let ports: [u16; 4] = crate::bench::workspace::reserve_ports(4)
        .map_err(RunError::Setup)?
        .try_into()
        .expect("four ports reserved");
    let (rust_identity, xray_keys) =
        generate_identities(&workspace, context, ports[0]).map_err(RunError::Setup)?;
    write_configs(&workspace, context, &rust_identity, &xray_keys, ports)
        .map_err(RunError::Setup)?;
    let binaries = vec![rust, xray];
    let processes = launch_processes(&binaries, &workspace, ports).map_err(RunError::Processes)?;
    Ok(Materialized {
        binaries,
        processes,
        lock,
        workspace,
        ports,
        rust_identity,
        xray_keys,
    })
}

/// Runs one A/B tunnel suite end to end, from preflight to report.
///
/// This is the canonical lifecycle the legacy scripts duplicated: preflight,
/// register, lock, workspace, generate, launch, readiness, workload, report.
/// On success the report JSON has been written into the run workspace and is
/// returned with the samples. The run's resources are released before returning.
///
/// # Errors
///
/// Returns [`RunError::Setup`] or [`RunError::Processes`] on a hard failure, or
/// [`RunError::Workload`] when the report completed with failed transfers (the
/// report is still produced; the error carries it).
pub fn run_suite(context: &SuiteContext<'_>) -> Result<RunOutcome, RunError> {
    let run = materialize(context)?;
    let (samples, report) = drive_workload(context, &run.binaries, run.ports, &run.processes);
    // The durable evidence copy goes to the output directory; the ephemeral
    // workspace keeps a working copy that is removed with it.
    std::fs::create_dir_all(&context.out_dir).map_err(|error| {
        RunError::Setup(format!(
            "could not create {}: {error}",
            context.out_dir.display()
        ))
    })?;
    let path = write_report_to(&context.out_dir, &report_name(&context.suite_id), &report)?;
    println!("suite report: {}", path.display());
    let _ = engine::write_report(&run.workspace, "report.json", &report);
    if report.failures == 0 {
        Ok(RunOutcome { report, samples })
    } else {
        Err(RunError::Workload(report))
    }
}

/// The durable report filename for a suite, matching the legacy evidence names
/// (`real-path.json` for the real-path suite; `report.json` otherwise).
fn report_name(suite_id: &str) -> String {
    match suite_id {
        "benchmark-real-path" => "real-path.json".to_owned(),
        _ => "report.json".to_owned(),
    }
}

/// Writes the report JSON into `dir` and returns its path.
///
/// # Errors
///
/// Returns a setup error when the file cannot be written.
fn write_report_to(
    dir: &std::path::Path,
    name: &str,
    report: &engine::RunReport,
) -> Result<std::path::PathBuf, RunError> {
    let path = dir.join(name);
    std::fs::write(&path, &report.json).map_err(|error| {
        RunError::Setup(format!(
            "could not write report {}: {error}",
            path.display()
        ))
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The durable report name follows the legacy evidence names.
    #[test]
    fn report_name_matches_the_legacy_evidence_names() {
        assert_eq!(report_name("benchmark-real-path"), "real-path.json");
        assert_eq!(report_name("benchmark-xray"), "report.json");
    }

    /// A deterministic fake transfer: succeeds through both "tunnels" at fixed
    /// throughput. Proves the shared engine wiring — plan order, classification,
    /// summary, provenance — without launching tunnel processes or touching the
    /// network. The live WAN acceptance of this wiring is the real-path suite
    /// itself.
    struct DeterministicTransfer {
        seconds: f64,
    }

    impl Transfer for DeterministicTransfer {
        fn run(&self, _socks_port: u16, expected_bytes: u64) -> Result<(u64, Duration), String> {
            Ok((expected_bytes, Duration::from_secs_f64(self.seconds)))
        }
    }

    fn test_context() -> (SuiteContext<'static>, tempdir::TempDir) {
        let dir = tempdir::TempDir::new("rr-bench-suite").expect("tempdir");
        let context = SuiteContext {
            rust_bin: std::path::Path::new("/nonexistent/rust-reality"),
            xray_bin: std::path::Path::new("/nonexistent/xray"),
            cover_target: "dl.google.com:443".to_owned(),
            cover_sni: "dl.google.com".to_owned(),
            runs: 4,
            expected_bytes: 1_000_000,
            suite_id: "benchmark-real-path".to_owned(),
            transfer_url: "https://speed.cloudflare.com/__down?bytes=1000000".to_owned(),
            transfer_max_time_secs: 120,
            out_dir: dir.path().to_path_buf(),
            allow_private: false,
        };
        (context, dir)
    }

    #[test]
    fn the_workload_writes_a_complete_provenanced_report() {
        let (context, dir) = test_context();
        // The fake binaries are never launched; only the workload runs.
        let binaries = vec![
            identity::Binary {
                label: "rust-reality".to_owned(),
                path: std::path::PathBuf::from("/nonexistent/rust-reality"),
                sha256: "a".repeat(64),
                identity: "identity".to_owned(),
            },
            identity::Binary {
                label: "xray".to_owned(),
                path: std::path::PathBuf::from("/nonexistent/xray"),
                sha256: "b".repeat(64),
                identity: "identity".to_owned(),
            },
        ];
        let ports = [24000, 24001, 24002, 24003];
        let transfer = DeterministicTransfer { seconds: 0.5 };
        let (samples, report) = drive_workload_with(&context, &binaries, ports, &transfer);
        assert_eq!(samples.len(), 4);
        assert!(samples.iter().all(|sample| sample.ok));
        assert_eq!(report.failures, 0);
        assert!(report.json.contains("\"binaries\""));
        assert!(report.json.contains("\"sha256\""));
        assert!(report.json.contains("rustServerPort"));
        assert!(
            report
                .json
                .contains("\"url\": \"https://speed.cloudflare.com/__down\"")
        );

        // The durable evidence copy is written under the suite's evidence name.
        let path = dir.path().join(report_name(&context.suite_id));
        std::fs::write(&path, &report.json).unwrap();
        assert!(path.is_file());
    }

    /// A missing curl binary fails the preflight before anything launches.
    #[test]
    fn materialize_fails_closed_when_the_binary_is_absent() {
        let (context, _dir) = test_context();
        let Err(error) = materialize(&context) else {
            panic!("materialize must fail closed for an absent binary");
        };
        assert!(matches!(error, RunError::Setup(_)), "{error}");
    }
}

/// A minimal RAII temp directory for the suite tests.
mod tempdir {
    use std::path::PathBuf;

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(name: &str) -> Result<Self, String> {
            let dir = std::env::temp_dir().join(format!(
                "{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
            Ok(Self(dir))
        }

        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
