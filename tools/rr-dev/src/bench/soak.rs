//! Long-lived mixed-traffic soak and resource observations.
//!
//! A soak is one lifecycle with implementation-specific topology. Both sides use
//! the same native origins, workload mix, `/proc` sampler, failure accounting and
//! hash-bound publication. The Xray side is retained as a comparator mode; the
//! rust-reality side additionally owns its Handoff, NXR, SOCKS5 and reload gates.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    bench::{
        ab_suites,
        config::{self, RealityIdentity},
        evidence::{self, Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        no_ccs,
        origin_go::{self, OriginPlan},
        origin_tls,
        process::{Child, proc_starttime},
        runner, suites,
        workspace::{self, Workspace},
    },
    hash,
    perf::{json_in, json_out::Json},
    process::Tool,
};

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const PAYLOAD_MIB: u64 = 4;
const CHURN_CONNECTIONS: usize = 16;

/// Bounded shared soak inputs.
#[derive(Debug, Clone)]
pub struct SoakPlan {
    /// rust-reality binary used by the native multi-topology soak.
    pub rust_bin: PathBuf,
    /// Xray binary used as server/client for the comparator topology.
    pub xray_bin: PathBuf,
    /// OpenSSL used for the shaped Handoff cover certificate and server.
    pub openssl_bin: PathBuf,
    /// Fresh output directory.
    pub out_dir: PathBuf,
    /// Safe evidence identifier.
    pub run_id: String,
    /// Timed workload window.
    pub duration: Duration,
    /// Delay between completed rounds.
    pub round_sleep: Duration,
    /// Minimum rounds required even when the timed window is very short.
    pub minimum_rounds: usize,
    /// Interval between additional distributed correctness attempts.
    pub distributed_interval: Duration,
}

/// One process's sampled Linux resource state.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessResources {
    /// Process id.
    pub pid: u32,
    /// `/proc/<pid>/stat` start-time identity.
    pub starttime: String,
    /// Open descriptors.
    pub fds: u64,
    /// Resident memory in KiB.
    pub rss_kib: u64,
    /// Proportional resident memory in KiB when `smaps_rollup` is readable.
    pub pss_kib: Option<u64>,
    /// Process-lifetime high-water RSS in KiB.
    pub hwm_kib: u64,
    /// Kernel thread count.
    pub threads: u64,
}

/// One monotonic resource observation.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSnapshot {
    /// Phase label (`start`, `round-N`, or `end`).
    pub label: String,
    /// Seconds since this native run began.
    pub monotonic_seconds: f64,
    /// Stable process-name map.
    pub processes: BTreeMap<String, ProcessResources>,
}

/// Resource growth computed from a snapshot series.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSummary {
    /// End minus start descriptors.
    pub fd_growth: i64,
    /// Peak minus start descriptors.
    pub fd_peak_growth: i64,
    /// End minus start threads.
    pub thread_growth: i64,
    /// Peak minus start threads.
    pub thread_peak_growth: i64,
    /// End minus start RSS in MiB.
    pub rss_growth_mib: f64,
    /// HWM peak minus start HWM in MiB.
    pub rss_peak_growth_mib: f64,
    /// Sampled RSS peak minus start RSS in MiB.
    pub rss_sampled_peak_growth_mib: f64,
    /// Least-squares RSS slope over the second half of samples.
    pub rss_tail_slope_mib_per_hour: f64,
    /// Whether every snapshot exposed proportional-set size.
    pub pss_available: bool,
    /// End minus start PSS in MiB.
    pub pss_growth_mib: Option<f64>,
    /// Sampled PSS peak minus start in MiB.
    pub pss_peak_growth_mib: Option<f64>,
    /// PSS tail slope when available.
    pub pss_tail_slope_mib_per_hour: Option<f64>,
}

/// Successful Xray comparator observations.
#[derive(Debug, Clone)]
pub struct XraySoakOutcome {
    /// Completed mixed-traffic rounds.
    pub rounds: usize,
    /// Failed transfers or churn operations.
    pub transfer_failures: usize,
    /// Server resource growth.
    pub resources: ResourceSummary,
}

/// Successful native rust-reality soak observations.
#[derive(Debug, Clone)]
pub struct RustSoakOutcome {
    /// Completed mixed-traffic rounds.
    pub rounds: usize,
    /// Failed transfers or churn operations.
    pub transfer_failures: usize,
    /// Completed Handoff/NXR/SOCKS5 integrity attempts.
    pub distributed_attempts: usize,
    /// Aggregate resource growth across all six rust-reality processes.
    pub resources: ResourceSummary,
}

#[derive(Debug, Clone)]
pub(crate) struct GeneratedPublicConfig {
    pub(crate) public_key: String,
    pub(crate) uuid: String,
    pub(crate) short_id: String,
    pub(crate) json: String,
}

#[derive(Debug, Clone)]
struct DistributedSample {
    attempt: usize,
    trigger: &'static str,
    path: &'static str,
    success: bool,
    failure_class: Option<String>,
    bytes: u64,
    sha256: Option<String>,
    server_sequence: Option<i64>,
    output: String,
    monotonic_seconds: f64,
}

struct DistributedRun<'a> {
    run: &'a RunDirectory,
    started: Instant,
    http_origin_port: u16,
    socks_ports: [u16; 3],
    expected_sha256: String,
    handoff_log: PathBuf,
    attempts: usize,
    samples: Vec<DistributedSample>,
}

#[derive(Debug, Clone, Copy)]
struct NativePorts {
    standalone: u16,
    standalone_socks: u16,
    https_origin: u16,
    http_origin: u16,
    handoff_cover_upstream: u16,
    handoff_cover: u16,
    handoff_line: u16,
    handoff_landing: u16,
    handoff_socks: u16,
    nxr_line: u16,
    nxr_landing: u16,
    nxr_socks: u16,
    socks_line: u16,
    socks_upstream: u16,
    socks_client: u16,
}

impl NativePorts {
    fn reserve() -> Result<Self, String> {
        let ports = workspace::reserve_ports(15)?;
        let [
            standalone,
            standalone_socks,
            tls_origin_port,
            clear_origin_port,
            handoff_cover_upstream,
            handoff_cover,
            handoff_line,
            handoff_landing,
            handoff_socks,
            nxr_line,
            nxr_landing,
            nxr_socks,
            socks_line,
            socks_upstream,
            socks_client,
        ] = <[u16; 15]>::try_from(ports)
            .map_err(|_| "could not reserve the native soak port set".to_owned())?;
        Ok(Self {
            standalone,
            standalone_socks,
            https_origin: tls_origin_port,
            http_origin: clear_origin_port,
            handoff_cover_upstream,
            handoff_cover,
            handoff_line,
            handoff_landing,
            handoff_socks,
            nxr_line,
            nxr_landing,
            nxr_socks,
            socks_line,
            socks_upstream,
            socks_client,
        })
    }

    fn as_array(self) -> [u16; 15] {
        [
            self.standalone,
            self.standalone_socks,
            self.https_origin,
            self.http_origin,
            self.handoff_cover_upstream,
            self.handoff_cover,
            self.handoff_line,
            self.handoff_landing,
            self.handoff_socks,
            self.nxr_line,
            self.nxr_landing,
            self.nxr_socks,
            self.socks_line,
            self.socks_upstream,
            self.socks_client,
        ]
    }
}

struct NativeConfigs {
    standalone: PathBuf,
    standalone_client: PathBuf,
    handoff_line: PathBuf,
    handoff_landing: PathBuf,
    handoff_client: PathBuf,
    nxr_line: PathBuf,
    nxr_landing: PathBuf,
    nxr_client: PathBuf,
    socks_line: PathBuf,
    socks_client: PathBuf,
}

/// Validates the bounded native plan.
///
/// # Errors
///
/// Returns a message for unsafe evidence names or unbounded timings.
pub fn validate(plan: &SoakPlan) -> Result<(), String> {
    if plan.run_id.is_empty()
        || !plan
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if plan.duration.is_zero() || plan.duration > Duration::from_hours(12) {
        return Err("soak duration must be in 1..43200 seconds".to_owned());
    }
    if plan.round_sleep > Duration::from_mins(1) {
        return Err("soak round sleep must not exceed 60 seconds".to_owned());
    }
    if !(1..=100_000).contains(&plan.minimum_rounds) {
        return Err("soak minimum rounds must be in 1..100000".to_owned());
    }
    if plan.distributed_interval.is_zero() || plan.distributed_interval > Duration::from_mins(30) {
        return Err("distributed interval must be in 1..1800 seconds".to_owned());
    }
    let planned_attempts = 3 + plan
        .duration
        .as_secs()
        .saturating_sub(1)
        .checked_div(plan.distributed_interval.as_secs())
        .unwrap_or(0);
    if planned_attempts > 145 {
        return Err(format!(
            "distributed attempt count {planned_attempts} exceeds hard limit 145"
        ));
    }
    Ok(())
}

pub(crate) fn generated_public_config(
    rust_bin: &Path,
    args: Vec<String>,
    workspace: &Workspace,
    cache_label: &str,
) -> Result<GeneratedPublicConfig, String> {
    let outcome = Tool::new(rust_bin.display().to_string())
        .args(args)
        .probe()
        .map_err(|error| format!("rust-reality config generate failed: {error}"))?;
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
    let inbound = value
        .array_field("", "inbounds")
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated rust config has no inbound".to_owned())?;
    let client = inbound
        .field("inbounds[0]", "settings")
        .and_then(|settings| settings.array_field("inbounds[0].settings", "clients"))
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated rust config has no client".to_owned())?;
    let uuid = client
        .str_field("inbounds[0].settings.clients[0]", "id")
        .map_err(|error| error.to_string())?
        .to_owned();
    let short_id = client
        .array_field("inbounds[0].settings.clients[0]", "shortIds")
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated rust config client has no short id".to_owned())?
        .as_str("inbounds[0].settings.clients[0].shortIds[0]")
        .map_err(|error| error.to_string())?
        .to_owned();
    Ok(GeneratedPublicConfig {
        public_key,
        uuid,
        short_id,
        json: patch_server_config(raw, workspace, cache_label, false)?,
    })
}

pub(crate) fn patch_server_config(
    raw: &str,
    workspace: &Workspace,
    cache_label: &str,
    serial_cover: bool,
) -> Result<String, String> {
    use json_in::Value;
    let value = json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?;
    let Value::Object(mut root) = value else {
        return Err("generated rust config is not an object".to_owned());
    };
    let Some(Value::Object(log)) = root.get_mut("log") else {
        return Err("generated rust config has no log object".to_owned());
    };
    log.insert("level".to_owned(), Value::Str("debug".to_owned()));
    let Some(Value::Object(assets)) = root.get_mut("assets") else {
        return Err("generated rust config has no assets object".to_owned());
    };
    assets.insert(
        "cacheDirectory".to_owned(),
        Value::Str(workspace.join(cache_label).display().to_string()),
    );
    if serial_cover {
        let Some(Value::Array(inbounds)) = root.get_mut("inbounds") else {
            return Err("generated rust config has no inbounds array".to_owned());
        };
        let Some(Value::Object(inbound)) = inbounds.first_mut() else {
            return Err("generated rust config has no first inbound".to_owned());
        };
        let Some(Value::Object(stream)) = inbound.get_mut("streamSettings") else {
            return Err("generated rust config has no streamSettings".to_owned());
        };
        let Some(Value::Object(reality)) = stream.get_mut("realitySettings") else {
            return Err("generated rust config has no realitySettings".to_owned());
        };
        let Some(Value::Object(optimization)) = reality.get_mut("coverOptimization") else {
            return Err("generated rust config has no coverOptimization".to_owned());
        };
        optimization.insert("warmTcp".to_owned(), Value::Bool(false));
        optimization.insert("prebuiltProfiles".to_owned(), Value::Bool(false));
    }
    Ok(suites::render_compact(&Value::Object(root)))
}

pub(crate) fn patch_xray_socks_port(raw: &str, port: u16) -> Result<String, String> {
    use json_in::Value;
    let value = json_in::parse(raw)
        .map_err(|error| format!("generated Xray config is invalid JSON: {error}"))?;
    let Value::Object(mut root) = value else {
        return Err("generated Xray config is not an object".to_owned());
    };
    let Some(Value::Array(inbounds)) = root.get_mut("inbounds") else {
        return Err("generated Xray config has no inbounds array".to_owned());
    };
    let Some(Value::Object(inbound)) = inbounds.first_mut() else {
        return Err("generated Xray config has no first inbound".to_owned());
    };
    inbound.insert("port".to_owned(), Value::Number(port.to_string()));
    Ok(suites::render_compact(&Value::Object(root)))
}

pub(crate) fn patch_socks_outbound(raw: &str, upstream_port: u16) -> Result<String, String> {
    use json_in::Value;
    let value = json_in::parse(raw)
        .map_err(|error| format!("generated SOCKS line config is invalid JSON: {error}"))?;
    let Value::Object(mut root) = value else {
        return Err("generated SOCKS line config is not an object".to_owned());
    };
    let Some(Value::Array(outbounds)) = root.get_mut("outbounds") else {
        return Err("generated SOCKS line config has no outbounds array".to_owned());
    };
    outbounds.retain(
        |outbound| match outbound.str_field("outbounds[]", "protocol") {
            Ok(protocol) => protocol != "nxr",
            Err(_) => true,
        },
    );
    outbounds.push(Value::Object(
        [
            ("protocol".to_owned(), Value::Str("socks5".to_owned())),
            ("tag".to_owned(), Value::Str("via-socks".to_owned())),
            (
                "settings".to_owned(),
                Value::Object(
                    [
                        ("address".to_owned(), Value::Str("127.0.0.1".to_owned())),
                        ("port".to_owned(), Value::Number(upstream_port.to_string())),
                        ("warmTcp".to_owned(), Value::Bool(true)),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
        ]
        .into_iter()
        .collect(),
    ));
    let Some(Value::Object(routing)) = root.get_mut("routing") else {
        return Err("generated SOCKS line config has no routing object".to_owned());
    };
    let Some(Value::Array(users)) = routing.get_mut("users") else {
        return Err("generated SOCKS line config has no routing users".to_owned());
    };
    let Some(Value::Object(user)) = users.first_mut() else {
        return Err("generated SOCKS line config has no first routing user".to_owned());
    };
    user.insert(
        "defaultOutbound".to_owned(),
        Value::Str("via-socks".to_owned()),
    );
    Ok(suites::render_compact(&Value::Object(root)))
}

pub(crate) fn node_key(rust_bin: &Path) -> Result<String, String> {
    let outcome = Tool::new(rust_bin.display().to_string())
        .arg("node-keygen")
        .probe()
        .map_err(|error| format!("rust-reality node-keygen failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "rust-reality node-keygen exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    json_in::parse(outcome.trimmed_stdout())
        .map_err(|error| format!("node-keygen output is invalid JSON: {error}"))?
        .str_field("", "preSharedKey")
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

pub(crate) fn check_config(rust_bin: &Path, config: &Path) -> Result<(), String> {
    let outcome = Tool::new(rust_bin.display().to_string())
        .args(["check", "--config", &config.display().to_string()])
        .probe()
        .map_err(|error| format!("rust-reality check failed: {error}"))?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!(
            "rust-reality check rejected {}: {}",
            config.display(),
            outcome.stderr.trim_end()
        ))
    }
}

pub(crate) fn write_config(path: &Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents)
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

#[expect(
    clippy::too_many_lines,
    reason = "one transaction materializes and production-checks the four soak topologies"
)]
fn materialize_native_configs(
    plan: &SoakPlan,
    workspace: &Workspace,
    ports: NativePorts,
) -> Result<NativeConfigs, String> {
    let target = format!("127.0.0.1:{}", ports.https_origin);
    let standalone = generated_public_config(
        &plan.rust_bin,
        vec![
            "config".to_owned(),
            "generate".to_owned(),
            "standalone".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            ports.standalone.to_string(),
            "--target".to_owned(),
            target.clone(),
            "--server-name".to_owned(),
            "localhost".to_owned(),
        ],
        workspace,
        "assets-standalone",
    )?;
    let standalone_path = workspace.join("standalone.json");
    write_config(&standalone_path, &standalone.json)?;
    let standalone_client_path = workspace.join("standalone-client.json");
    write_config(
        &standalone_client_path,
        &config::xray_client(
            &RealityIdentity {
                uuid: standalone.uuid,
                short_id: standalone.short_id,
                server_name: "localhost".to_owned(),
                target: target.clone(),
            },
            ports.standalone,
            ports.standalone_socks,
            &standalone.public_key,
        )
        .to_python_json(),
    )?;

    let handoff_dir = workspace.join("handoff-generated");
    let handoff = Tool::new(plan.rust_bin.display().to_string())
        .args([
            "config",
            "generate",
            "handoff",
            "--listen",
            "127.0.0.1",
            "--port",
            &ports.handoff_line.to_string(),
            "--server-address",
            "127.0.0.1",
            "--target",
            &format!("localhost:{}", ports.handoff_cover),
            "--server-name",
            "localhost",
            "--landing-address",
            "127.0.0.1",
            "--landing-port",
            &ports.handoff_landing.to_string(),
            "--output-dir",
            &handoff_dir.display().to_string(),
        ])
        .probe()
        .map_err(|error| format!("handoff config generation failed: {error}"))?;
    if !handoff.success() {
        return Err(format!(
            "handoff config generation exited {:?}: {}",
            handoff.code,
            handoff.stderr.trim_end()
        ));
    }
    let handoff_line = handoff_dir.join("line.json");
    let handoff_landing = handoff_dir.join("landing.json");
    let handoff_client = handoff_dir.join("xray-client.json");
    write_config(
        &handoff_line,
        &patch_server_config(
            &std::fs::read_to_string(&handoff_line)
                .map_err(|error| format!("could not read handoff line config: {error}"))?,
            workspace,
            "assets-handoff-line",
            true,
        )?,
    )?;
    write_config(
        &handoff_landing,
        &patch_server_config(
            &std::fs::read_to_string(&handoff_landing)
                .map_err(|error| format!("could not read handoff landing config: {error}"))?,
            workspace,
            "assets-handoff-landing",
            false,
        )?,
    )?;
    write_config(
        &handoff_client,
        &patch_xray_socks_port(
            &std::fs::read_to_string(&handoff_client)
                .map_err(|error| format!("could not read handoff Xray config: {error}"))?,
            ports.handoff_socks,
        )?,
    )?;

    let nxr_key = node_key(&plan.rust_bin)?;
    let nxr_line_generated = generated_public_config(
        &plan.rust_bin,
        vec![
            "config".to_owned(),
            "generate".to_owned(),
            "line".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            ports.nxr_line.to_string(),
            "--target".to_owned(),
            target.clone(),
            "--server-name".to_owned(),
            "localhost".to_owned(),
            "--nxr-address".to_owned(),
            "127.0.0.1".to_owned(),
            "--nxr-port".to_owned(),
            ports.nxr_landing.to_string(),
            "--nxr-key".to_owned(),
            nxr_key.clone(),
        ],
        workspace,
        "assets-nxr-line",
    )?;
    let nxr_line = workspace.join("nxr-line.json");
    write_config(&nxr_line, &nxr_line_generated.json)?;
    let nxr_landing_outcome = Tool::new(plan.rust_bin.display().to_string())
        .args([
            "config",
            "generate",
            "landing",
            "--listen",
            "127.0.0.1",
            "--port",
            &ports.nxr_landing.to_string(),
            "--nxr-key",
            &nxr_key,
        ])
        .probe()
        .map_err(|error| format!("NXR landing config generation failed: {error}"))?;
    if !nxr_landing_outcome.success() {
        return Err(format!(
            "NXR landing config generation exited {:?}: {}",
            nxr_landing_outcome.code,
            nxr_landing_outcome.stderr.trim_end()
        ));
    }
    let nxr_landing = workspace.join("nxr-landing.json");
    write_config(
        &nxr_landing,
        &patch_server_config(
            nxr_landing_outcome.trimmed_stdout(),
            workspace,
            "assets-nxr-landing",
            false,
        )?,
    )?;
    let nxr_client = workspace.join("nxr-client.json");
    write_config(
        &nxr_client,
        &config::xray_client(
            &RealityIdentity {
                uuid: nxr_line_generated.uuid,
                short_id: nxr_line_generated.short_id,
                server_name: "localhost".to_owned(),
                target: target.clone(),
            },
            ports.nxr_line,
            ports.nxr_socks,
            &nxr_line_generated.public_key,
        )
        .to_python_json(),
    )?;

    let socks_generated = generated_public_config(
        &plan.rust_bin,
        vec![
            "config".to_owned(),
            "generate".to_owned(),
            "line".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            ports.socks_line.to_string(),
            "--target".to_owned(),
            target,
            "--server-name".to_owned(),
            "localhost".to_owned(),
            "--nxr-address".to_owned(),
            "127.0.0.1".to_owned(),
            "--nxr-port".to_owned(),
            "9".to_owned(),
            "--nxr-key".to_owned(),
            nxr_key,
        ],
        workspace,
        "assets-socks-line",
    )?;
    let socks_line = workspace.join("socks-line.json");
    write_config(
        &socks_line,
        &patch_socks_outbound(&socks_generated.json, ports.socks_upstream)?,
    )?;
    let socks_client = workspace.join("socks-client.json");
    write_config(
        &socks_client,
        &config::xray_client(
            &RealityIdentity {
                uuid: socks_generated.uuid,
                short_id: socks_generated.short_id,
                server_name: "localhost".to_owned(),
                target: format!("127.0.0.1:{}", ports.https_origin),
            },
            ports.socks_line,
            ports.socks_client,
            &socks_generated.public_key,
        )
        .to_python_json(),
    )?;

    for path in [
        &standalone_path,
        &handoff_line,
        &handoff_landing,
        &nxr_line,
        &nxr_landing,
        &socks_line,
    ] {
        check_config(&plan.rust_bin, path)?;
    }
    Ok(NativeConfigs {
        standalone: standalone_path,
        standalone_client: standalone_client_path,
        handoff_line,
        handoff_landing,
        handoff_client,
        nxr_line,
        nxr_landing,
        nxr_client,
        socks_line,
        socks_client,
    })
}

fn external_binary(label: &str, path: &Path, args: &[&str]) -> Result<Binary, String> {
    let resolved = if path.components().count() > 1 {
        path.to_path_buf()
    } else {
        origin_tls::which(&path.display().to_string())
            .ok_or_else(|| format!("{label} is unavailable: {}", path.display()))?
    };
    let canonical = std::fs::canonicalize(&resolved)
        .map_err(|error| format!("could not resolve {}: {error}", resolved.display()))?;
    let outcome = Tool::new(canonical.display().to_string())
        .args(args.iter().copied())
        .probe()
        .map_err(|error| format!("could not identify {label}: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "{label} identity exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let mut identity = outcome.stdout;
    identity.push_str(&outcome.stderr);
    Ok(Binary {
        label: label.to_owned(),
        sha256: hash::sha256_file(&canonical)?,
        path: canonical,
        identity: identity.trim().to_owned(),
    })
}

pub(crate) fn spawn_rust(
    label: &str,
    rust: &Binary,
    config: &Path,
    workspace: &Workspace,
    environment: &[(String, String)],
    log: &Path,
    port: u16,
) -> Result<Child, String> {
    let mut child = Child::spawn_isolated(
        label,
        &rust.path,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
        ],
        workspace.path(),
        environment,
        log,
    )
    .map_err(|error| error.to_string())?;
    child
        .wait_for_port(port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    Ok(child)
}

pub(crate) fn spawn_xray_client(
    label: &str,
    xray: &Binary,
    config: &Path,
    workspace: &Workspace,
    log: &Path,
    port: u16,
) -> Result<Child, String> {
    let mut child = Child::spawn_isolated(
        label,
        &xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            config.display().to_string(),
        ],
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        log,
    )
    .map_err(|error| error.to_string())?;
    child
        .wait_for_port(port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    Ok(child)
}

fn exact_processes(processes: &[(&str, u32)]) -> Result<Vec<(String, u32, String)>, String> {
    processes
        .iter()
        .map(|(name, pid)| {
            proc_starttime(*pid)
                .ok_or_else(|| format!("could not identify {name} process {pid}"))
                .map(|starttime| ((*name).to_owned(), *pid, starttime))
        })
        .collect()
}

impl DistributedRun<'_> {
    fn attempt(&mut self, trigger: &'static str) {
        self.attempts += 1;
        let attempt = self.attempts;
        let url = format!("http://127.0.0.1:{}/payload-1.bin", self.http_origin_port);
        for (path, socks_port) in [
            ("handoff-seq1", self.socks_ports[0]),
            ("nxr-byte-integrity", self.socks_ports[1]),
            ("socks5-byte-integrity", self.socks_ports[2]),
        ] {
            let relative = format!("distributed/{path}-{attempt:04}.bin");
            let output = self.run.join(&relative);
            let transfer = fetch(
                &url,
                Some(socks_port),
                false,
                &output,
                Some(&self.expected_sha256),
            );
            let bytes = output.metadata().map_or(0, |metadata| metadata.len());
            let sha256 = output
                .is_file()
                .then(|| hash::sha256_file(&output).ok())
                .flatten();
            let mut failure_class = transfer.err().map(|_| "transfer".to_owned());
            if failure_class.is_none() && bytes != 1_048_576 {
                failure_class = Some("size_mismatch".to_owned());
            }
            if failure_class.is_none() && sha256.as_deref() != Some(&self.expected_sha256) {
                failure_class = Some("sha256_mismatch".to_owned());
            }
            let server_sequence = if path == "handoff-seq1" {
                if let Ok(sequence) = wait_handoff_sequence(&self.handoff_log, attempt) {
                    Some(sequence)
                } else {
                    failure_class.get_or_insert_with(|| "server_sequence_missing".to_owned());
                    None
                }
            } else {
                None
            };
            if path == "handoff-seq1" && server_sequence.is_some_and(|sequence| sequence != 1) {
                failure_class = Some("server_sequence_mismatch".to_owned());
            }
            self.samples.push(DistributedSample {
                attempt,
                trigger,
                path,
                success: failure_class.is_none(),
                failure_class,
                bytes,
                sha256,
                server_sequence,
                output: relative,
                monotonic_seconds: self.started.elapsed().as_secs_f64(),
            });
        }
    }
}

impl DistributedSample {
    fn to_json(&self, expected_sha256: &str) -> Json {
        Json::object([
            ("attempt", usize_json(self.attempt)),
            ("trigger", Json::string(self.trigger)),
            ("path", Json::string(self.path)),
            ("success", Json::Bool(self.success)),
            (
                "failureClass",
                self.failure_class.as_ref().map_or(Json::Null, Json::string),
            ),
            ("bytes", int(self.bytes)),
            (
                "sha256",
                self.sha256.as_ref().map_or(Json::Null, Json::string),
            ),
            ("expectedBytes", int(1_048_576)),
            ("expectedSha256", Json::string(expected_sha256)),
            (
                "serverSequence",
                self.server_sequence.map_or(Json::Null, Json::Int),
            ),
            ("output", Json::string(&self.output)),
            ("monotonicSeconds", Json::Float(self.monotonic_seconds)),
        ])
    }
}

fn wait_handoff_sequence(log: &Path, expected_index: usize) -> Result<i64, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let sequences = text
            .lines()
            .filter_map(|line| json_in::parse(line).ok())
            .filter(|event| {
                event
                    .str_field("event", "event")
                    .is_ok_and(|name| name == "connection_completed")
            })
            .filter_map(|event| event.int_field("event", "handoff_server_sequence").ok())
            .collect::<Vec<_>>();
        if let Some(sequence) = sequences.get(expected_index.saturating_sub(1)) {
            return Ok(*sequence);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "missing Handoff completion {expected_index} in {}",
        log.display()
    ))
}

fn wait_for_generation(child: &mut Child, log: &Path, generation: i64) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let found = text
            .lines()
            .filter_map(|line| json_in::parse(line).ok())
            .any(|event| {
                event
                    .str_field("event", "event")
                    .is_ok_and(|name| name == "configuration_published")
                    && event
                        .int_field("event", "generation")
                        .is_ok_and(|observed| observed == generation)
            });
        if found {
            return Ok(());
        }
        if !child.is_alive() {
            return Err(format!("{} exited while waiting for reload", child.label()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "{} recorded no configuration generation {generation}",
        log.display()
    ))
}

fn reload_topology(processes: &mut [(&mut Child, &Path)]) -> Result<(), String> {
    for (child, _) in processes.iter_mut() {
        child.reload()?;
    }
    for (child, log) in processes.iter_mut() {
        wait_for_generation(child, log, 1)?;
    }
    Ok(())
}

fn wait_for_proxy_completion(
    proxy: &mut Child,
    log: &Path,
    expected_shaped: usize,
) -> Result<usize, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        for event in text.lines().filter_map(|line| json_in::parse(line).ok()) {
            if event
                .str_field("event", "event")
                .is_ok_and(|name| name == "proxy_complete")
            {
                let shaped = event
                    .int_field("event", "shaped")
                    .map_err(|error| error.to_string())?;
                let shaped = usize::try_from(shaped)
                    .map_err(|_| "shape proxy reported a negative count".to_owned())?;
                return if shaped == expected_shaped {
                    Ok(shaped)
                } else {
                    Err(format!(
                        "shape proxy completed {shaped} flights, expected {expected_shaped}"
                    ))
                };
            }
        }
        if !proxy.is_alive() {
            return Err("shape proxy exited without a completion event".to_owned());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("shape proxy did not publish completion".to_owned())
}

fn connection_rejections(log: &Path) -> Result<BTreeMap<String, usize>, String> {
    let text = std::fs::read_to_string(log)
        .map_err(|error| format!("could not read {}: {error}", log.display()))?;
    let mut reasons = BTreeMap::new();
    for event in text.lines().filter_map(|line| json_in::parse(line).ok()) {
        if event
            .str_field("event", "event")
            .is_ok_and(|name| name == "connection_rejected")
        {
            let reason = event
                .str_field("event", "reason")
                .unwrap_or("unclassified")
                .to_owned();
            *reasons.entry(reason).or_default() += 1;
        }
    }
    Ok(reasons)
}

fn validate_distributed(
    run: &DistributedRun<'_>,
    required_attempts: usize,
    shaped: usize,
    handoff_rejections: &BTreeMap<String, usize>,
    nxr_rejections: &BTreeMap<String, usize>,
) -> Result<(), String> {
    if run.attempts < required_attempts || run.samples.len() != run.attempts * 3 {
        return Err(format!(
            "distributed soak completed {} attempts/{} samples, requires {required_attempts} complete attempts",
            run.attempts,
            run.samples.len()
        ));
    }
    if let Some(sample) = run.samples.iter().find(|sample| !sample.success) {
        return Err(format!(
            "distributed {} attempt {} failed: {}",
            sample.path,
            sample.attempt,
            sample.failure_class.as_deref().unwrap_or("unclassified")
        ));
    }
    for trigger in ["start", "reload", "end"] {
        if run
            .samples
            .iter()
            .filter(|sample| sample.path == "handoff-seq1" && sample.trigger == trigger)
            .count()
            != 1
        {
            return Err(format!(
                "distributed soak did not record one {trigger} trigger"
            ));
        }
    }
    if shaped != run.attempts {
        return Err(format!(
            "shape proxy completed {shaped} flights for {} attempts",
            run.attempts
        ));
    }
    if !handoff_rejections.is_empty() || !nxr_rejections.is_empty() {
        return Err(format!(
            "landing rejected soak connections: handoff={handoff_rejections:?}, nxr={nxr_rejections:?}"
        ));
    }
    Ok(())
}

fn run_reload_phase(
    started: Instant,
    snapshots: &mut Vec<ResourceSnapshot>,
    identities: &[(String, u32, String)],
    distributed: &mut DistributedRun<'_>,
    processes: &mut [(&mut Child, &Path)],
) -> Result<(), String> {
    snapshots.push(capture_processes(
        "before-reload",
        started.elapsed(),
        identities,
    )?);
    reload_topology(processes)?;
    distributed.attempt("reload");
    snapshots.push(capture_processes(
        "after-reload",
        started.elapsed(),
        identities,
    )?);
    Ok(())
}

fn publish_final_downloads(run: &DistributedRun<'_>) -> Result<(), String> {
    for (path, destination) in [
        ("handoff-seq1", "handoff-download.bin"),
        ("nxr-byte-integrity", "nxr-download.bin"),
        ("socks5-byte-integrity", "socks-download.bin"),
    ] {
        let sample = run
            .samples
            .iter()
            .rev()
            .find(|sample| sample.path == path)
            .ok_or_else(|| format!("distributed soak has no {path} download"))?;
        std::fs::copy(run.run.join(&sample.output), run.run.join(destination))
            .map_err(|error| format!("could not publish final {path} download: {error}"))?;
    }
    Ok(())
}

fn distributed_summary_json(
    run: &DistributedRun<'_>,
    interval: Duration,
    required_attempts: usize,
    shaped: usize,
) -> Json {
    let path_summary = |path: &str, sequence: bool| {
        let samples = run
            .samples
            .iter()
            .filter(|sample| sample.path == path)
            .collect::<Vec<_>>();
        Json::object([
            ("attempts", usize_json(samples.len())),
            (
                "successes",
                usize_json(samples.iter().filter(|sample| sample.success).count()),
            ),
            (
                "failures",
                usize_json(samples.iter().filter(|sample| !sample.success).count()),
            ),
            (
                "allPayloadBytes",
                Json::Bool(samples.iter().all(|sample| sample.bytes == 1_048_576)),
            ),
            (
                "allPayloadSha256",
                Json::Bool(
                    samples
                        .iter()
                        .all(|sample| sample.sha256.as_deref() == Some(&run.expected_sha256)),
                ),
            ),
            (
                "allServerSequenceOne",
                if sequence {
                    Json::Bool(
                        samples
                            .iter()
                            .all(|sample| sample.server_sequence == Some(1)),
                    )
                } else {
                    Json::Null
                },
            ),
        ])
    };
    Json::object([
        ("schemaVersion", Json::Int(3)),
        ("payloadBytes", int(1_048_576)),
        ("payloadSha256", Json::string(&run.expected_sha256)),
        ("intervalSeconds", int(interval.as_secs())),
        ("attempts", usize_json(run.attempts)),
        ("requiredAttempts", usize_json(required_attempts)),
        (
            "reload",
            Json::object([
                (
                    "triggerAttempts",
                    usize_json(
                        run.samples
                            .iter()
                            .filter(|sample| {
                                sample.path == "handoff-seq1" && sample.trigger == "reload"
                            })
                            .count(),
                    ),
                ),
                ("expectedGeneration", Json::Int(1)),
            ]),
        ),
        ("handoffSeq1", path_summary("handoff-seq1", true)),
        (
            "nxrByteIntegrity",
            path_summary("nxr-byte-integrity", false),
        ),
        (
            "socks5ByteIntegrity",
            path_summary("socks5-byte-integrity", false),
        ),
        (
            "proxy",
            Json::object([
                ("shaped", usize_json(shaped)),
                (
                    "appendedWireLength",
                    usize_json(crate::bench::tls_shape::SHAPED_FIFTH_RECORD_BYTES),
                ),
            ]),
        ),
        ("ok", Json::Bool(true)),
    ])
}

fn ports_json(ports: NativePorts) -> Json {
    Json::object([
        ("standalone", Json::Int(i64::from(ports.standalone))),
        (
            "standaloneSocks",
            Json::Int(i64::from(ports.standalone_socks)),
        ),
        ("httpsOrigin", Json::Int(i64::from(ports.https_origin))),
        ("httpOrigin", Json::Int(i64::from(ports.http_origin))),
        (
            "handoffCoverUpstream",
            Json::Int(i64::from(ports.handoff_cover_upstream)),
        ),
        ("handoffCover", Json::Int(i64::from(ports.handoff_cover))),
        ("handoffLine", Json::Int(i64::from(ports.handoff_line))),
        (
            "handoffLanding",
            Json::Int(i64::from(ports.handoff_landing)),
        ),
        ("handoffSocks", Json::Int(i64::from(ports.handoff_socks))),
        ("nxrLine", Json::Int(i64::from(ports.nxr_line))),
        ("nxrLanding", Json::Int(i64::from(ports.nxr_landing))),
        ("nxrSocks", Json::Int(i64::from(ports.nxr_socks))),
        ("socksLine", Json::Int(i64::from(ports.socks_line))),
        ("socksUpstream", Json::Int(i64::from(ports.socks_upstream))),
        ("socksClient", Json::Int(i64::from(ports.socks_client))),
    ])
}

/// Runs the native standalone + Handoff + NXR + SOCKS5 soak topology.
///
/// # Errors
///
/// Returns the first identity, generation, process, integrity, reload, resource,
/// or publication failure. Every child and the workspace are RAII-owned.
#[allow(clippy::too_many_lines)]
pub fn run_rust(plan: &SoakPlan) -> Result<RustSoakOutcome, String> {
    validate(plan)?;
    let rust = identity::register("rust-reality", &plan.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &plan.xray_bin, "", Kind::Xray)?;
    let openssl = external_binary("openssl", &plan.openssl_bin, &["version", "-a"])?;
    let rr_dev = std::env::current_exe()
        .map_err(|error| format!("could not resolve the rr-dev executable: {error}"))?;
    let rr_dev_sha256 = hash::sha256_file(&rr_dev)?;
    let _lock = HostLock::acquire(&runner::default_lock_path())?;
    let run = RunDirectory::create(&plan.out_dir)?;
    std::fs::create_dir(run.join("distributed"))
        .map_err(|error| format!("could not create distributed evidence directory: {error}"))?;
    let workspace = Workspace::create("soak-rust")?;
    let ports = NativePorts::reserve()?;
    let mut resolved_plan = plan.clone();
    resolved_plan.rust_bin.clone_from(&rust.path);
    resolved_plan.xray_bin.clone_from(&xray.path);
    resolved_plan.openssl_bin.clone_from(&openssl.path);
    let configs = materialize_native_configs(&resolved_plan, &workspace, ports)?;

    let payload = origin_go::write_pattern_payload(workspace.path(), PAYLOAD_MIB)?;
    let payload_sha256 = hash::sha256_file(&payload)?;
    let distributed_payload = origin_go::write_pattern_payload(workspace.path(), 1)?;
    let distributed_payload_sha256 = hash::sha256_file(&distributed_payload)?;
    let certificate =
        no_ccs::build_cover_certificate(&openssl.path, workspace.path(), &plan.run_id)?;
    run.write_new(
        "handoff-cover-certificate-san.txt",
        &certificate.subject_alt_name,
    )?;

    let mut tls_origin = origin_go::start(
        &rr_dev,
        &workspace,
        &OriginPlan {
            label: "soak-origin-https".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: ports.https_origin,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("https-put.jsonl"),
            tls: Some((certificate.certificate.clone(), certificate.key.clone())),
            access_log: None,
            alpn: None,
        },
    )?;
    let mut clear_origin = origin_go::start(
        &rr_dev,
        &workspace,
        &OriginPlan {
            label: "soak-origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: ports.http_origin,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;

    let cover_log = run.join("handoff-cover-trace.log");
    let cover_args = vec![
        "s_server".to_owned(),
        "-accept".to_owned(),
        format!("127.0.0.1:{}", ports.handoff_cover_upstream),
        "-www".to_owned(),
        "-ign_eof".to_owned(),
        "-tls1_3".to_owned(),
        "-cert".to_owned(),
        certificate.certificate.display().to_string(),
        "-key".to_owned(),
        certificate.key.display().to_string(),
        "-alpn".to_owned(),
        "h2,http/1.1".to_owned(),
        "-trace".to_owned(),
        "-msg".to_owned(),
        "-state".to_owned(),
    ];
    let mut cover = Child::spawn_isolated(
        "soak-handoff-cover",
        &openssl.path,
        &cover_args,
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        &cover_log,
    )
    .map_err(|error| error.to_string())?;
    cover
        .wait_for_port(ports.handoff_cover_upstream, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let planned_attempts = usize::try_from(
        3 + plan
            .duration
            .as_secs()
            .saturating_sub(1)
            .checked_div(plan.distributed_interval.as_secs())
            .unwrap_or(0),
    )
    .map_err(|_| "distributed attempt count is unrepresentable".to_owned())?;
    let shape_log = run.join("handoff-cover-shape-proxy.log");
    let mut shape_proxy = Child::spawn_isolated(
        "soak-handoff-shape-proxy",
        &rr_dev,
        &[
            "bench".to_owned(),
            "shape-proxy".to_owned(),
            "--listen-port".to_owned(),
            ports.handoff_cover.to_string(),
            "--upstream-port".to_owned(),
            ports.handoff_cover_upstream.to_string(),
            "--max-shaped".to_owned(),
            planned_attempts.to_string(),
            "--max-accepted".to_owned(),
            (planned_attempts + 16).to_string(),
        ],
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        &shape_log,
    )
    .map_err(|error| error.to_string())?;
    shape_proxy
        .wait_for_port(ports.handoff_cover, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let clean_environment = [("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())];
    let handoff_environment = [
        ("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()),
        (
            "SSL_CERT_FILE".to_owned(),
            certificate.ca_certificate.display().to_string(),
        ),
    ];
    let handoff_landing_log = run.join("handoff-landing.log");
    let mut handoff_landing = spawn_rust(
        "soak-handoff-landing",
        &rust,
        &configs.handoff_landing,
        &workspace,
        &clean_environment,
        &handoff_landing_log,
        ports.handoff_landing,
    )?;
    let handoff_line_log = run.join("handoff-line.log");
    let mut handoff_line = spawn_rust(
        "soak-handoff-line",
        &rust,
        &configs.handoff_line,
        &workspace,
        &handoff_environment,
        &handoff_line_log,
        ports.handoff_line,
    )?;
    let mut handoff_xray = spawn_xray_client(
        "soak-handoff-xray",
        &xray,
        &configs.handoff_client,
        &workspace,
        &run.join("handoff-xray.log"),
        ports.handoff_socks,
    )?;

    let nxr_landing_log = run.join("nxr-landing.log");
    let mut nxr_landing = spawn_rust(
        "soak-nxr-landing",
        &rust,
        &configs.nxr_landing,
        &workspace,
        &clean_environment,
        &nxr_landing_log,
        ports.nxr_landing,
    )?;
    let nxr_line_log = run.join("nxr-line.log");
    let mut nxr_line = spawn_rust(
        "soak-nxr-line",
        &rust,
        &configs.nxr_line,
        &workspace,
        &clean_environment,
        &nxr_line_log,
        ports.nxr_line,
    )?;
    let mut nxr_xray = spawn_xray_client(
        "soak-nxr-xray",
        &xray,
        &configs.nxr_client,
        &workspace,
        &run.join("nxr-xray.log"),
        ports.nxr_socks,
    )?;

    let socks_upstream_log = run.join("socks-upstream.log");
    let mut socks_upstream = Child::spawn_isolated(
        "soak-socks-upstream",
        &rr_dev,
        &[
            "bench".to_owned(),
            "socks-server".to_owned(),
            "--port".to_owned(),
            ports.socks_upstream.to_string(),
        ],
        workspace.path(),
        &clean_environment,
        &socks_upstream_log,
    )
    .map_err(|error| error.to_string())?;
    socks_upstream
        .wait_for_port(ports.socks_upstream, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let socks_line_log = run.join("socks-line.log");
    let mut socks_line = spawn_rust(
        "soak-socks-line",
        &rust,
        &configs.socks_line,
        &workspace,
        &clean_environment,
        &socks_line_log,
        ports.socks_line,
    )?;
    let mut socks_xray = spawn_xray_client(
        "soak-socks-xray",
        &xray,
        &configs.socks_client,
        &workspace,
        &run.join("socks-xray.log"),
        ports.socks_client,
    )?;

    let standalone_log = run.join("standalone.log");
    let mut standalone = spawn_rust(
        "soak-standalone",
        &rust,
        &configs.standalone,
        &workspace,
        &clean_environment,
        &standalone_log,
        ports.standalone,
    )?;
    let mut standalone_xray = spawn_xray_client(
        "soak-standalone-xray",
        &xray,
        &configs.standalone_client,
        &workspace,
        &run.join("standalone-xray.log"),
        ports.standalone_socks,
    )?;

    let identities = exact_processes(&[
        ("standalone", standalone.pid()),
        ("handoff-line", handoff_line.pid()),
        ("handoff-landing", handoff_landing.pid()),
        ("nxr-line", nxr_line.pid()),
        ("nxr-landing", nxr_landing.pid()),
        ("socks-line", socks_line.pid()),
    ])?;
    let started = Instant::now();
    let mut distributed = DistributedRun {
        run: &run,
        started,
        http_origin_port: ports.http_origin,
        socks_ports: [ports.handoff_socks, ports.nxr_socks, ports.socks_client],
        expected_sha256: distributed_payload_sha256,
        handoff_log: handoff_line_log.clone(),
        attempts: 0,
        samples: Vec::with_capacity(planned_attempts * 3),
    };
    distributed.attempt("start");
    let mut snapshots = vec![capture_processes("start", started.elapsed(), &identities)?];
    let mut rounds = 0;
    let mut failures = 0;
    let reload_at = plan.duration.div_f64(2.0);
    let mut reload_triggered = false;
    let mut next_distributed = plan.distributed_interval;
    while started.elapsed() < plan.duration {
        if !reload_triggered && started.elapsed() >= reload_at {
            let mut reload_processes = [
                (&mut handoff_line, handoff_line_log.as_path()),
                (&mut handoff_landing, handoff_landing_log.as_path()),
                (&mut nxr_line, nxr_line_log.as_path()),
                (&mut nxr_landing, nxr_landing_log.as_path()),
                (&mut socks_line, socks_line_log.as_path()),
            ];
            run_reload_phase(
                started,
                &mut snapshots,
                &identities,
                &mut distributed,
                &mut reload_processes,
            )?;
            reload_triggered = true;
        }
        rounds += 1;
        failures += run_round(
            &workspace,
            rounds,
            ports.standalone_socks,
            ports.standalone,
            ports.https_origin,
            ports.http_origin,
            &payload_sha256,
        );
        while next_distributed < plan.duration && started.elapsed() >= next_distributed {
            distributed.attempt("interval");
            next_distributed += plan.distributed_interval;
        }
        snapshots.push(capture_processes(
            &format!("round-{rounds}"),
            started.elapsed(),
            &identities,
        )?);
        if started.elapsed() < plan.duration && !plan.round_sleep.is_zero() {
            std::thread::sleep(plan.round_sleep);
        }
    }
    if !reload_triggered {
        let mut reload_processes = [
            (&mut handoff_line, handoff_line_log.as_path()),
            (&mut handoff_landing, handoff_landing_log.as_path()),
            (&mut nxr_line, nxr_line_log.as_path()),
            (&mut nxr_landing, nxr_landing_log.as_path()),
            (&mut socks_line, socks_line_log.as_path()),
        ];
        run_reload_phase(
            started,
            &mut snapshots,
            &identities,
            &mut distributed,
            &mut reload_processes,
        )?;
    }
    while next_distributed < plan.duration && started.elapsed() >= next_distributed {
        distributed.attempt("interval");
        next_distributed += plan.distributed_interval;
    }
    distributed.attempt("end");
    publish_final_downloads(&distributed)?;
    std::thread::sleep(Duration::from_secs(5));
    snapshots.push(capture_processes("end", started.elapsed(), &identities)?);

    let shaped = wait_for_proxy_completion(&mut shape_proxy, &shape_log, distributed.attempts)?;
    let handoff_rejections = connection_rejections(&handoff_landing_log)?;
    let nxr_rejections = connection_rejections(&nxr_landing_log)?;
    validate_distributed(
        &distributed,
        planned_attempts,
        shaped,
        &handoff_rejections,
        &nxr_rejections,
    )?;
    if rounds < plan.minimum_rounds {
        return Err(format!(
            "soak completed {rounds} rounds, requires {}",
            plan.minimum_rounds
        ));
    }
    if failures != 0 {
        return Err(format!("soak observed {failures} transfer failure(s)"));
    }
    let resources = summarize_aggregate_resources(&snapshots)?;
    let resources_by_process = summarize_each_process(&snapshots)?;
    let slope_gate_applied = plan.duration >= Duration::from_mins(30);
    if !resources_within_limits(&resources, slope_gate_applied, true) {
        return Err(format!(
            "aggregate soak resources exceeded bounds: {resources:?}"
        ));
    }
    if let Some((name, summary)) = resources_by_process
        .iter()
        .find(|(_, summary)| !resources_within_limits(summary, slope_gate_applied, false))
    {
        return Err(format!(
            "{name} soak resources exceeded bounds: {summary:?}"
        ));
    }

    for (pid, label) in [
        (standalone.pid(), "standalone"),
        (handoff_line.pid(), "handoff line"),
        (handoff_landing.pid(), "handoff landing"),
        (nxr_line.pid(), "NXR line"),
        (nxr_landing.pid(), "NXR landing"),
        (socks_line.pid(), "SOCKS line"),
    ] {
        crate::bench::slot::verify_running_image(pid, &rust.sha256, label)?;
    }
    for (pid, label) in [
        (standalone_xray.pid(), "standalone Xray"),
        (handoff_xray.pid(), "handoff Xray"),
        (nxr_xray.pid(), "NXR Xray"),
        (socks_xray.pid(), "SOCKS Xray"),
    ] {
        crate::bench::slot::verify_running_image(pid, &xray.sha256, label)?;
    }
    for (pid, label) in [
        (tls_origin.pid(), "HTTPS origin"),
        (clear_origin.pid(), "HTTP origin"),
        (socks_upstream.pid(), "SOCKS5 upstream"),
    ] {
        crate::bench::slot::verify_running_image(pid, &rr_dev_sha256, label)?;
    }
    crate::bench::slot::verify_running_image(cover.pid(), &openssl.sha256, "OpenSSL cover")?;
    no_ccs::assert_unchanged(&rust)?;
    no_ccs::assert_unchanged(&xray)?;
    if hash::sha256_file(&openssl.path)? != openssl.sha256 {
        return Err("OpenSSL changed during the soak".to_owned());
    }
    if hash::sha256_file(&rr_dev)? != rr_dev_sha256 {
        return Err("rr-dev changed during the soak".to_owned());
    }

    let resource_rows = snapshots
        .iter()
        .map(|snapshot| snapshot_json(snapshot).to_compact_json())
        .collect::<Vec<_>>();
    run.write_jsonl("resources.jsonl", &resource_rows)?;
    let distributed_rows = distributed
        .samples
        .iter()
        .map(|sample| sample.to_json(&distributed.expected_sha256).to_jq_json())
        .collect::<Vec<_>>();
    run.write_jsonl("distributed-samples.jsonl", &distributed_rows)?;
    let distributed_json = distributed_summary_json(
        &distributed,
        plan.distributed_interval,
        planned_attempts,
        shaped,
    );
    run.write_new("distributed-gates.json", &distributed_json.to_python_json())?;
    let resource_by_process_json = Json::object(
        resources_by_process
            .iter()
            .map(|(name, summary)| (name.clone(), resource_summary_json(summary))),
    );
    let config_sha256 = Json::object([
        (
            "standalone",
            Json::string(hash::sha256_file(&configs.standalone)?),
        ),
        (
            "handoffLine",
            Json::string(hash::sha256_file(&configs.handoff_line)?),
        ),
        (
            "handoffLanding",
            Json::string(hash::sha256_file(&configs.handoff_landing)?),
        ),
        (
            "nxrLine",
            Json::string(hash::sha256_file(&configs.nxr_line)?),
        ),
        (
            "nxrLanding",
            Json::string(hash::sha256_file(&configs.nxr_landing)?),
        ),
        (
            "socksLine",
            Json::string(hash::sha256_file(&configs.socks_line)?),
        ),
    ]);
    let long_horizon_qualified = plan.duration == Duration::from_hours(12)
        && started.elapsed() >= Duration::from_hours(12)
        && resources.pss_available
        && slope_gate_applied
        && (Duration::from_mins(5)..=Duration::from_mins(30)).contains(&plan.distributed_interval)
        && distributed.attempts >= 25;
    let summary = Json::object([
        ("schemaVersion", Json::Int(3)),
        ("harness", Json::string("soak")),
        ("implementation", Json::string("rust-reality")),
        ("runId", Json::string(&plan.run_id)),
        ("completedAt", Json::string(evidence::now_utc()?)),
        ("durationSeconds", Json::Float(plan.duration.as_secs_f64())),
        (
            "elapsedSeconds",
            Json::Float(started.elapsed().as_secs_f64()),
        ),
        ("rounds", usize_json(rounds)),
        ("minimumRounds", usize_json(plan.minimum_rounds)),
        ("transferFailures", usize_json(failures)),
        ("payloadBytes", int(PAYLOAD_MIB * 1024 * 1024)),
        ("payloadSha256", Json::string(&payload_sha256)),
        (
            "binaries",
            Json::object([
                (
                    "rustReality",
                    Json::object([
                        ("path", Json::string(rust.path.display().to_string())),
                        ("sha256", Json::string(&rust.sha256)),
                        ("identity", Json::string(&rust.identity)),
                    ]),
                ),
                (
                    "xray",
                    Json::object([
                        ("path", Json::string(xray.path.display().to_string())),
                        ("sha256", Json::string(&xray.sha256)),
                        ("identity", Json::string(&xray.identity)),
                    ]),
                ),
                (
                    "openssl",
                    Json::object([
                        ("path", Json::string(openssl.path.display().to_string())),
                        ("sha256", Json::string(&openssl.sha256)),
                        ("identity", Json::string(&openssl.identity)),
                    ]),
                ),
                (
                    "rrDevHelpers",
                    Json::object([
                        ("path", Json::string(rr_dev.display().to_string())),
                        ("sha256", Json::string(&rr_dev_sha256)),
                    ]),
                ),
            ]),
        ),
        ("ports", ports_json(ports)),
        (
            "portBlock",
            Json::Array(
                ports
                    .as_array()
                    .into_iter()
                    .map(|port| Json::Int(i64::from(port)))
                    .collect(),
            ),
        ),
        ("configSha256", config_sha256),
        ("resources", resource_summary_json(&resources)),
        ("resourceAggregate", resource_summary_json(&resources)),
        ("resourceByProcess", resource_by_process_json),
        ("memoryTailSlopeGateApplied", Json::Bool(slope_gate_applied)),
        (
            "memorySlopeGateBasis",
            Json::object([
                (
                    "aggregate",
                    Json::string(if resources.pss_available {
                        "pss"
                    } else {
                        "rss-fallback"
                    }),
                ),
                ("perProcess", Json::string("rss")),
            ]),
        ),
        ("longHorizonQualified", Json::Bool(long_horizon_qualified)),
        ("distributedGates", distributed_json),
        ("ok", Json::Bool(true)),
    ]);
    let document = summary.to_python_json();
    run.write_new("soak-summary.json", &document)?;

    standalone_xray.terminate();
    socks_xray.terminate();
    nxr_xray.terminate();
    handoff_xray.terminate();
    standalone.terminate();
    socks_line.terminate();
    nxr_line.terminate();
    nxr_landing.terminate();
    handoff_line.terminate();
    handoff_landing.terminate();
    socks_upstream.terminate();
    shape_proxy.terminate();
    cover.terminate();
    clear_origin.terminate();
    tls_origin.terminate();
    copy_origin_log(&workspace, &run, "soak-origin-http", "origin-http.log")?;
    copy_origin_log(&workspace, &run, "soak-origin-https", "origin-https.log")?;
    run.publish(
        Publication::Environment,
        &document,
        &plan.run_id,
        "soak-rust-native",
    )?;
    Ok(RustSoakOutcome {
        rounds,
        transfer_failures: failures,
        distributed_attempts: distributed.attempts,
        resources,
    })
}

/// Runs the Xray comparator under the soak workload and publishes evidence.
///
/// # Errors
///
/// Returns the first identity, process, transfer, sampling or publication error.
#[allow(clippy::too_many_lines)]
pub fn run_xray(plan: &SoakPlan) -> Result<XraySoakOutcome, String> {
    validate(plan)?;
    let xray = identity::register("xray", &plan.xray_bin, "", Kind::Xray)?;
    let rr_dev =
        std::env::current_exe().map_err(|error| format!("could not resolve rr-dev: {error}"))?;
    let rr_dev_sha256 = hash::sha256_file(&rr_dev)?;
    let _lock = HostLock::acquire(&runner::default_lock_path())?;
    let run = RunDirectory::create(&plan.out_dir)?;
    let workspace = Workspace::create("soak-xray")?;
    let ports = workspace::reserve_ports(4)?;
    let [tls_origin_port, clear_origin_port, server_port, socks_port] =
        <[u16; 4]>::try_from(ports).map_err(|_| "could not reserve four ports".to_owned())?;

    let payload = origin_go::write_pattern_payload(workspace.path(), PAYLOAD_MIB)?;
    let payload_sha256 = hash::sha256_file(&payload)?;
    let (certificate, key) = origin_tls::generate_self_signed(workspace.path())?;
    let mut tls_origin = origin_go::start(
        &rr_dev,
        &workspace,
        &OriginPlan {
            label: "soak-origin-https".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: tls_origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("https-put.jsonl"),
            tls: Some((certificate, key)),
            access_log: None,
            alpn: None,
        },
    )?;
    let mut clear_origin = origin_go::start(
        &rr_dev,
        &workspace,
        &OriginPlan {
            label: "soak-origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: clear_origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;

    let identity = RealityIdentity {
        uuid: ab_suites::random_uuid_v4()?,
        short_id: ab_suites::random_short_id()?,
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{tls_origin_port}"),
    };
    let keys = suites::generate_xray_keys(&xray.path)?;
    let server_config = workspace.join("xray-server.json");
    let client_config = workspace.join("xray-client.json");
    std::fs::write(
        &server_config,
        config::xray_server(&identity, server_port, &keys.private, true).to_python_json(),
    )
    .map_err(|error| format!("could not write Xray server config: {error}"))?;
    std::fs::write(
        &client_config,
        config::xray_client(&identity, server_port, socks_port, &keys.public).to_python_json(),
    )
    .map_err(|error| format!("could not write Xray client config: {error}"))?;

    let mut server = Child::spawn_isolated(
        "soak-xray-server",
        &xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            server_config.display().to_string(),
        ],
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        &run.join("server.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let server_starttime = proc_starttime(server.pid())
        .ok_or_else(|| "could not capture Xray server start-time".to_owned())?;
    let mut client = Child::spawn_isolated(
        "soak-xray-client",
        &xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_config.display().to_string(),
        ],
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        &run.join("client.log"),
    )
    .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let started = Instant::now();
    let mut snapshots = vec![capture_snapshot(
        "start",
        started.elapsed(),
        "xray-server",
        &mut server,
        &server_starttime,
    )?];
    let mut rounds = 0;
    let mut failures = 0;
    while started.elapsed() < plan.duration {
        rounds += 1;
        failures += run_round(
            &workspace,
            rounds,
            socks_port,
            server_port,
            tls_origin_port,
            clear_origin_port,
            &payload_sha256,
        );
        snapshots.push(capture_snapshot(
            &format!("round-{rounds}"),
            started.elapsed(),
            "xray-server",
            &mut server,
            &server_starttime,
        )?);
        if started.elapsed() < plan.duration && !plan.round_sleep.is_zero() {
            std::thread::sleep(plan.round_sleep);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    snapshots.push(capture_snapshot(
        "end",
        started.elapsed(),
        "xray-server",
        &mut server,
        &server_starttime,
    )?);

    let resources = summarize_resources(&snapshots, "xray-server")?;
    let outcome = XraySoakOutcome {
        rounds,
        transfer_failures: failures,
        resources,
    };
    if rounds < plan.minimum_rounds {
        return Err(format!(
            "soak completed {rounds} rounds, requires {}",
            plan.minimum_rounds
        ));
    }
    if failures != 0 {
        return Err(format!("soak observed {failures} transfer failure(s)"));
    }
    crate::bench::slot::verify_running_image(server.pid(), &xray.sha256, "xray server")?;
    crate::bench::slot::verify_running_image(client.pid(), &xray.sha256, "xray client")?;
    crate::bench::slot::verify_running_image(tls_origin.pid(), &rr_dev_sha256, "HTTPS origin")?;
    crate::bench::slot::verify_running_image(clear_origin.pid(), &rr_dev_sha256, "HTTP origin")?;
    crate::bench::no_ccs::assert_unchanged(&xray)?;

    let rows: Vec<String> = snapshots
        .iter()
        .map(|snapshot| snapshot_json(snapshot).to_compact_json())
        .collect();
    run.write_jsonl("resources.jsonl", &rows)?;
    let summary = xray_summary_json(
        plan,
        &outcome,
        &snapshots,
        &xray,
        &rr_dev,
        &rr_dev_sha256,
        [tls_origin_port, clear_origin_port, server_port, socks_port],
        &payload_sha256,
        &hash::sha256_file(&server_config)?,
        &hash::sha256_file(&client_config)?,
    )?;
    let document = summary.to_python_json();
    run.write_new("xray-resource-summary.json", &document)?;

    client.terminate();
    server.terminate();
    clear_origin.terminate();
    tls_origin.terminate();
    copy_origin_log(&workspace, &run, "soak-origin-http", "origin-http.log")?;
    copy_origin_log(&workspace, &run, "soak-origin-https", "origin-https.log")?;
    run.publish(
        Publication::Environment,
        &document,
        &plan.run_id,
        "soak-xray-resources",
    )?;
    Ok(outcome)
}

fn run_round(
    workspace: &Workspace,
    round: usize,
    socks_port: u16,
    server_port: u16,
    tls_origin_port: u16,
    clear_origin_port: u16,
    expected_sha256: &str,
) -> usize {
    let mut failures = 0;
    for (name, url, socks, insecure) in [
        (
            "direct",
            format!("https://127.0.0.1:{tls_origin_port}/payload-{PAYLOAD_MIB}.bin"),
            Some(socks_port),
            true,
        ),
        (
            "framed",
            format!("http://127.0.0.1:{clear_origin_port}/payload-{PAYLOAD_MIB}.bin"),
            Some(socks_port),
            false,
        ),
        (
            "fallback",
            format!("https://127.0.0.1:{server_port}/payload-{PAYLOAD_MIB}.bin"),
            None,
            true,
        ),
    ] {
        let output = workspace.join(&format!("round-{round}-{name}.bin"));
        if fetch(&url, socks, insecure, &output, Some(expected_sha256)).is_err() {
            failures += 1;
        }
    }
    let fallback = format!("https://127.0.0.1:{server_port}/payload-{PAYLOAD_MIB}.bin");
    for _ in 0..CHURN_CONNECTIONS {
        if fetch_range(&fallback).is_err() {
            failures += 1;
        }
    }
    failures
}

fn fetch(
    url: &str,
    socks_port: Option<u16>,
    insecure: bool,
    output: &Path,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    let mut args = vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--max-time".to_owned(),
        "60".to_owned(),
        "--output".to_owned(),
        output.display().to_string(),
    ];
    if insecure {
        args.push("--insecure".to_owned());
    }
    if let Some(port) = socks_port {
        args.extend(["--socks5-hostname".to_owned(), format!("127.0.0.1:{port}")]);
    }
    args.push(url.to_owned());
    let outcome = clean_curl()
        .args(args)
        .probe()
        .map_err(|error| error.to_string())?;
    if !outcome.success() {
        return Err(format!(
            "curl exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    if let Some(expected) = expected_sha256 {
        let actual = hash::sha256_file(output)?;
        if actual != expected {
            return Err(format!(
                "payload SHA-256 mismatch: {actual}, expected {expected}"
            ));
        }
    }
    Ok(())
}

fn fetch_range(url: &str) -> Result<(), String> {
    let outcome = clean_curl()
        .args([
            "--silent",
            "--show-error",
            "--insecure",
            "--max-time",
            "5",
            "--output",
            "/dev/null",
            "--range",
            "0-1023",
            url,
        ])
        .probe()
        .map_err(|error| error.to_string())?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!("churn curl exited {:?}", outcome.code))
    }
}

fn clean_curl() -> Tool {
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
    curl
}

fn capture_snapshot(
    label: &str,
    elapsed: Duration,
    process_name: &str,
    child: &mut Child,
    expected_starttime: &str,
) -> Result<ResourceSnapshot, String> {
    if !child.is_alive() {
        return Err(format!("{process_name} exited before snapshot {label}"));
    }
    let resources = process_resources(child.pid(), expected_starttime)?;
    Ok(ResourceSnapshot {
        label: label.to_owned(),
        monotonic_seconds: elapsed.as_secs_f64(),
        processes: [(process_name.to_owned(), resources)].into_iter().collect(),
    })
}

/// Captures one exact-identity snapshot for every named process.
fn capture_processes(
    label: &str,
    elapsed: Duration,
    processes: &[(String, u32, String)],
) -> Result<ResourceSnapshot, String> {
    let resources = processes
        .iter()
        .map(|(name, pid, starttime)| {
            process_resources(*pid, starttime).map(|resources| (name.clone(), resources))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(ResourceSnapshot {
        label: label.to_owned(),
        monotonic_seconds: elapsed.as_secs_f64(),
        processes: resources,
    })
}

fn process_resources(pid: u32, expected_starttime: &str) -> Result<ProcessResources, String> {
    let observed = proc_starttime(pid).ok_or_else(|| format!("process {pid} exited"))?;
    if observed != expected_starttime {
        return Err(format!(
            "process {pid} identity changed: {expected_starttime} -> {observed}"
        ));
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("could not read process {pid} status: {error}"))?;
    let field = |name: &str| -> Result<u64, String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|tail| tail.trim_start_matches(':').split_whitespace().next())
            .ok_or_else(|| format!("process status has no {name}"))?
            .parse()
            .map_err(|error| format!("process status {name} is invalid: {error}"))
    };
    let pss_kib = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .ok()
        .and_then(|smaps| {
            smaps
                .lines()
                .find_map(|line| line.strip_prefix("Pss:"))
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|text| text.parse().ok())
        });
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| format!("could not inspect process {pid} descriptors: {error}"))?
        .count();
    Ok(ProcessResources {
        pid,
        starttime: observed,
        fds: u64::try_from(fds).unwrap_or(u64::MAX),
        rss_kib: field("VmRSS")?,
        pss_kib,
        hwm_kib: field("VmHWM").or_else(|_| field("VmRSS"))?,
        threads: field("Threads")?,
    })
}

/// Summarizes one stable named process across snapshots.
///
/// # Errors
///
/// Returns a message when fewer than two samples exist or the process set drifted.
pub fn summarize_resources(
    snapshots: &[ResourceSnapshot],
    process_name: &str,
) -> Result<ResourceSummary, String> {
    if snapshots.len() < 2 {
        return Err("resource summary needs at least start and end samples".to_owned());
    }
    let values: Vec<&ProcessResources> = snapshots
        .iter()
        .map(|snapshot| {
            snapshot
                .processes
                .get(process_name)
                .ok_or_else(|| format!("snapshot {} lacks {process_name}", snapshot.label))
        })
        .collect::<Result<_, _>>()?;
    let first = values[0];
    let last = values[values.len() - 1];
    let tail_offset = 1.max(values.len() / 2);
    let slope = linear_slope_per_hour(
        &snapshots[tail_offset..]
            .iter()
            .map(|snapshot| snapshot.monotonic_seconds)
            .collect::<Vec<_>>(),
        &values[tail_offset..]
            .iter()
            .map(|value| kib_to_mib(value.rss_kib))
            .collect::<Vec<_>>(),
    );
    let pss_values: Option<Vec<f64>> = values
        .iter()
        .map(|value| value.pss_kib.map(kib_to_mib))
        .collect();
    let pss_summary = pss_values.as_ref().map(|pss| {
        let tail_slope = linear_slope_per_hour(
            &snapshots[tail_offset..]
                .iter()
                .map(|snapshot| snapshot.monotonic_seconds)
                .collect::<Vec<_>>(),
            &pss[tail_offset..],
        );
        (
            pss[pss.len() - 1] - pss[0],
            pss.iter().copied().fold(f64::NEG_INFINITY, f64::max) - pss[0],
            tail_slope,
        )
    });
    Ok(ResourceSummary {
        fd_growth: difference(last.fds, first.fds),
        fd_peak_growth: difference(
            values.iter().map(|value| value.fds).max().unwrap_or(0),
            first.fds,
        ),
        thread_growth: difference(last.threads, first.threads),
        thread_peak_growth: difference(
            values.iter().map(|value| value.threads).max().unwrap_or(0),
            first.threads,
        ),
        rss_growth_mib: kib_to_mib(last.rss_kib) - kib_to_mib(first.rss_kib),
        rss_peak_growth_mib: kib_to_mib(
            values.iter().map(|value| value.hwm_kib).max().unwrap_or(0),
        ) - kib_to_mib(first.hwm_kib),
        rss_sampled_peak_growth_mib: kib_to_mib(
            values.iter().map(|value| value.rss_kib).max().unwrap_or(0),
        ) - kib_to_mib(first.rss_kib),
        rss_tail_slope_mib_per_hour: slope,
        pss_available: pss_summary.is_some(),
        pss_growth_mib: pss_summary.map(|summary| summary.0),
        pss_peak_growth_mib: pss_summary.map(|summary| summary.1),
        pss_tail_slope_mib_per_hour: pss_summary.map(|summary| summary.2),
    })
}

fn summarize_aggregate_resources(
    snapshots: &[ResourceSnapshot],
) -> Result<ResourceSummary, String> {
    let aggregate = snapshots
        .iter()
        .map(|snapshot| {
            let totals = totals(&snapshot.processes);
            ResourceSnapshot {
                label: snapshot.label.clone(),
                monotonic_seconds: snapshot.monotonic_seconds,
                processes: [(
                    "aggregate".to_owned(),
                    ProcessResources {
                        pid: 0,
                        starttime: "aggregate".to_owned(),
                        fds: totals.fds,
                        rss_kib: totals.rss_kib,
                        pss_kib: totals.pss_kib,
                        hwm_kib: totals.hwm_kib,
                        threads: totals.threads,
                    },
                )]
                .into_iter()
                .collect(),
            }
        })
        .collect::<Vec<_>>();
    summarize_resources(&aggregate, "aggregate")
}

fn summarize_each_process(
    snapshots: &[ResourceSnapshot],
) -> Result<BTreeMap<String, ResourceSummary>, String> {
    let first = snapshots
        .first()
        .ok_or_else(|| "resource summary needs at least one snapshot".to_owned())?;
    if snapshots
        .iter()
        .any(|snapshot| snapshot.processes.keys().ne(first.processes.keys()))
    {
        return Err("rust process set changed during soak".to_owned());
    }
    first
        .processes
        .keys()
        .map(|name| summarize_resources(snapshots, name).map(|summary| (name.clone(), summary)))
        .collect()
}

fn resources_within_limits(
    summary: &ResourceSummary,
    slope_gate_applied: bool,
    aggregate: bool,
) -> bool {
    let tail_slope = if aggregate {
        summary
            .pss_tail_slope_mib_per_hour
            .unwrap_or(summary.rss_tail_slope_mib_per_hour)
    } else {
        summary.rss_tail_slope_mib_per_hour
    };
    summary.fd_growth <= 32
        && summary.thread_growth <= 8
        && summary.rss_growth_mib <= 32.0
        && summary.fd_peak_growth <= 128
        && summary.thread_peak_growth <= 8
        && summary.rss_peak_growth_mib <= 64.0
        && (!slope_gate_applied || tail_slope <= 2.0)
}

fn linear_slope_per_hour(xs: &[f64], ys: &[f64]) -> f64 {
    if xs.len() < 2 || xs.len() != ys.len() {
        return 0.0;
    }
    let count = f64::from(u32::try_from(xs.len()).unwrap_or(u32::MAX));
    let x_mean = xs.iter().sum::<f64>() / count;
    let y_mean = ys.iter().sum::<f64>() / count;
    let denominator: f64 = xs.iter().map(|x| (x - x_mean).powi(2)).sum();
    if denominator == 0.0 {
        return 0.0;
    }
    3600.0
        * xs.iter()
            .zip(ys)
            .map(|(x, y)| (x - x_mean) * (y - y_mean))
            .sum::<f64>()
        / denominator
}

fn difference(after: u64, before: u64) -> i64 {
    i64::try_from(after).unwrap_or(i64::MAX) - i64::try_from(before).unwrap_or(i64::MAX)
}

fn kib_to_mib(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX)) / 1024.0
}

fn snapshot_json(snapshot: &ResourceSnapshot) -> Json {
    let processes: Vec<(String, Json)> = snapshot
        .processes
        .iter()
        .map(|(name, process)| (name.clone(), process_json(process)))
        .collect();
    let totals = totals(&snapshot.processes);
    Json::object([
        ("label", Json::string(&snapshot.label)),
        ("monotonicSeconds", Json::Float(snapshot.monotonic_seconds)),
        ("serverAlive", Json::Bool(true)),
        ("processes", Json::object(processes)),
        ("totals", totals_json(&totals)),
        ("fds", int(totals.fds)),
        ("vmRssKiB", int(totals.rss_kib)),
        ("vmPssKiB", totals.pss_kib.map_or(Json::Null, int)),
        ("vmHwmKiB", int(totals.hwm_kib)),
        ("threads", int(totals.threads)),
    ])
}

fn process_json(process: &ProcessResources) -> Json {
    Json::object([
        ("alive", Json::Bool(true)),
        ("pid", Json::Int(i64::from(process.pid))),
        ("pidStarttime", Json::string(&process.starttime)),
        ("fds", int(process.fds)),
        ("vmRssKiB", int(process.rss_kib)),
        ("vmPssKiB", process.pss_kib.map_or(Json::Null, int)),
        ("vmHwmKiB", int(process.hwm_kib)),
        ("threads", int(process.threads)),
    ])
}

fn resource_summary_json(summary: &ResourceSummary) -> Json {
    Json::object([
        ("fdGrowth", Json::Int(summary.fd_growth)),
        ("fdPeakGrowth", Json::Int(summary.fd_peak_growth)),
        ("threadGrowth", Json::Int(summary.thread_growth)),
        ("threadPeakGrowth", Json::Int(summary.thread_peak_growth)),
        ("rssGrowthMiB", Json::Float(summary.rss_growth_mib)),
        ("rssPeakGrowthMiB", Json::Float(summary.rss_peak_growth_mib)),
        (
            "rssTailSlopeMiBPerHour",
            Json::Float(summary.rss_tail_slope_mib_per_hour),
        ),
        (
            "rssSampledPeakGrowthMiB",
            Json::Float(summary.rss_sampled_peak_growth_mib),
        ),
        ("pssAvailable", Json::Bool(summary.pss_available)),
        (
            "pssGrowthMiB",
            summary.pss_growth_mib.map_or(Json::Null, Json::Float),
        ),
        (
            "pssSampledPeakGrowthMiB",
            summary.pss_peak_growth_mib.map_or(Json::Null, Json::Float),
        ),
        (
            "pssTailSlopeMiBPerHour",
            summary
                .pss_tail_slope_mib_per_hour
                .map_or(Json::Null, Json::Float),
        ),
    ])
}

#[derive(Default)]
struct Totals {
    fds: u64,
    rss_kib: u64,
    pss_kib: Option<u64>,
    hwm_kib: u64,
    threads: u64,
}

fn totals(processes: &BTreeMap<String, ProcessResources>) -> Totals {
    let mut totals = Totals {
        pss_kib: Some(0),
        ..Totals::default()
    };
    for process in processes.values() {
        totals.fds += process.fds;
        totals.rss_kib += process.rss_kib;
        totals.hwm_kib += process.hwm_kib;
        totals.threads += process.threads;
        totals.pss_kib = match (totals.pss_kib, process.pss_kib) {
            (Some(total), Some(value)) => Some(total + value),
            _ => None,
        };
    }
    totals
}

fn totals_json(totals: &Totals) -> Json {
    Json::object([
        ("fds", int(totals.fds)),
        ("vmRssKiB", int(totals.rss_kib)),
        ("vmPssKiB", totals.pss_kib.map_or(Json::Null, int)),
        ("vmHwmKiB", int(totals.hwm_kib)),
        ("threads", int(totals.threads)),
    ])
}

#[allow(clippy::too_many_arguments)]
fn xray_summary_json(
    plan: &SoakPlan,
    outcome: &XraySoakOutcome,
    snapshots: &[ResourceSnapshot],
    xray: &Binary,
    rr_dev: &Path,
    rr_dev_sha256: &str,
    ports: [u16; 4],
    payload_sha256: &str,
    server_config_sha256: &str,
    client_config_sha256: &str,
) -> Result<Json, String> {
    Ok(Json::object([
        ("schemaVersion", Json::Int(2)),
        ("harness", Json::string("soak")),
        ("implementation", Json::string("xray")),
        ("runId", Json::string(&plan.run_id)),
        ("completedAt", Json::string(evidence::now_utc()?)),
        ("durationSeconds", Json::Float(plan.duration.as_secs_f64())),
        ("rounds", usize_json(outcome.rounds)),
        ("minimumRounds", usize_json(plan.minimum_rounds)),
        ("transferFailures", usize_json(outcome.transfer_failures)),
        ("payloadBytes", int(PAYLOAD_MIB * 1024 * 1024)),
        ("payloadSha256", Json::string(payload_sha256)),
        (
            "xray",
            Json::object([
                ("path", Json::string(xray.path.display().to_string())),
                ("sha256", Json::string(&xray.sha256)),
                ("identity", Json::string(&xray.identity)),
            ]),
        ),
        (
            "nativeOrigins",
            Json::object([
                ("path", Json::string(rr_dev.display().to_string())),
                ("sha256", Json::string(rr_dev_sha256)),
            ]),
        ),
        (
            "configSha256",
            Json::object([
                ("server", Json::string(server_config_sha256)),
                ("client", Json::string(client_config_sha256)),
            ]),
        ),
        (
            "ports",
            Json::object([
                ("httpsOrigin", Json::Int(i64::from(ports[0]))),
                ("httpOrigin", Json::Int(i64::from(ports[1]))),
                ("server", Json::Int(i64::from(ports[2]))),
                ("socks", Json::Int(i64::from(ports[3]))),
            ]),
        ),
        ("resources", resource_summary_json(&outcome.resources)),
        (
            "snapshots",
            Json::Array(snapshots.iter().map(snapshot_json).collect()),
        ),
        ("ok", Json::Bool(true)),
    ]))
}

fn copy_origin_log(
    workspace: &Workspace,
    run: &RunDirectory,
    source_label: &str,
    destination: &str,
) -> Result<(), String> {
    let contents = std::fs::read_to_string(workspace.join(&format!("{source_label}.log")))
        .map_err(|error| format!("could not read native origin log: {error}"))?;
    run.write_new(destination, &contents)?;
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

    fn plan() -> SoakPlan {
        SoakPlan {
            rust_bin: PathBuf::from("rust-reality"),
            xray_bin: PathBuf::from("xray"),
            openssl_bin: PathBuf::from("openssl"),
            out_dir: PathBuf::from("/out"),
            run_id: "soak-1".to_owned(),
            duration: Duration::from_mins(1),
            round_sleep: Duration::from_secs(5),
            minimum_rounds: 1,
            distributed_interval: Duration::from_mins(30),
        }
    }

    fn process(fds: u64, rss: u64, hwm: u64, threads: u64) -> ProcessResources {
        ProcessResources {
            pid: 1,
            starttime: "10".to_owned(),
            fds,
            rss_kib: rss,
            pss_kib: Some(rss / 2),
            hwm_kib: hwm,
            threads,
        }
    }

    fn snapshot(seconds: f64, resources: ProcessResources) -> ResourceSnapshot {
        ResourceSnapshot {
            label: format!("at-{seconds}"),
            monotonic_seconds: seconds,
            processes: [("server".to_owned(), resources)].into_iter().collect(),
        }
    }

    #[test]
    fn timing_and_identity_inputs_are_bounded() {
        assert!(validate(&plan()).is_ok());
        let mut invalid = plan();
        invalid.run_id = "../escape".to_owned();
        assert!(validate(&invalid).is_err());
        invalid = plan();
        invalid.duration = Duration::ZERO;
        assert!(validate(&invalid).is_err());
        invalid = plan();
        invalid.duration = Duration::from_secs(43_201);
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn growth_and_tail_slope_follow_the_legacy_formulas() {
        let snapshots = [
            snapshot(0.0, process(10, 10_240, 10_240, 2)),
            snapshot(10.0, process(12, 11_264, 12_288, 3)),
            snapshot(20.0, process(11, 12_288, 13_312, 3)),
            snapshot(30.0, process(11, 13_312, 14_336, 3)),
        ];
        let summary = summarize_resources(&snapshots, "server").unwrap();
        assert_eq!(summary.fd_growth, 1);
        assert_eq!(summary.fd_peak_growth, 2);
        assert_eq!(summary.thread_growth, 1);
        assert!((summary.rss_growth_mib - 3.0).abs() < f64::EPSILON);
        assert!((summary.rss_peak_growth_mib - 4.0).abs() < f64::EPSILON);
        assert!((summary.rss_sampled_peak_growth_mib - 3.0).abs() < f64::EPSILON);
        assert!((summary.rss_tail_slope_mib_per_hour - 360.0).abs() < 0.001);
        assert!(summary.pss_available);
        assert!((summary.pss_growth_mib.unwrap() - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_changed_process_set_fails_closed() {
        let snapshots = [
            snapshot(0.0, process(1, 1, 1, 1)),
            ResourceSnapshot {
                label: "end".to_owned(),
                monotonic_seconds: 1.0,
                processes: BTreeMap::new(),
            },
        ];
        assert!(summarize_resources(&snapshots, "server").is_err());
        assert!(summarize_each_process(&snapshots).is_err());
    }

    #[test]
    fn aggregate_summary_uses_pss_without_double_counting_shared_pages() {
        let snapshots = [
            ResourceSnapshot {
                label: "start".to_owned(),
                monotonic_seconds: 0.0,
                processes: [
                    ("line".to_owned(), process(10, 10_240, 10_240, 2)),
                    ("landing".to_owned(), process(10, 10_240, 10_240, 2)),
                ]
                .into_iter()
                .collect(),
            },
            ResourceSnapshot {
                label: "end".to_owned(),
                monotonic_seconds: 10.0,
                processes: [
                    ("line".to_owned(), process(11, 12_288, 12_288, 2)),
                    ("landing".to_owned(), process(11, 12_288, 12_288, 2)),
                ]
                .into_iter()
                .collect(),
            },
        ];
        let summary = summarize_aggregate_resources(&snapshots).unwrap();
        assert_eq!(summary.fd_growth, 2);
        assert!((summary.rss_growth_mib - 4.0).abs() < f64::EPSILON);
        assert!((summary.pss_growth_mib.unwrap() - 2.0).abs() < f64::EPSILON);
        assert!(resources_within_limits(&summary, false, true));
    }
}
