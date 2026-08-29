//! Runnable TLS-shape suite over the native benchmark lifecycle.
//!
//! The suite captures one authenticated stock-Xray `ClientHello`, then replays
//! those exact bytes sequentially against the independent libssl reference,
//! rust-reality, and Xray.  The reference source is deliberately narrow and
//! dynamic; Rust owns its build identity, invocation, evidence, and cleanup.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    bench::{
        identity::Binary,
        no_ccs,
        process::Child,
        suites::{self, RustIdentity},
        workspace::Workspace,
    },
    hash,
    perf::{json_in, json_out::Json},
    process::{self, Tool},
};

/// Default reference behavior, matching the legacy harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceOptions {
    /// TLS 1.3 cipher-suite list.
    pub ciphersuites: String,
    /// OpenSSL group list.
    pub groups: String,
    /// Selected ALPN, empty to select none.
    pub alpn: String,
    /// Emit the TLS 1.3 middlebox compatibility CCS.
    pub middlebox: bool,
    /// Maximum send fragment, or zero for the OpenSSL default.
    pub max_fragment: u16,
    /// Split send fragment, or zero for the OpenSSL default.
    pub split_fragment: u16,
    /// Fixed TLS 1.3 record padding bytes.
    pub padding: u16,
    /// Apply `TCP_NODELAY` to the accepted reference socket.
    pub tcp_nodelay: bool,
}

impl Default for ReferenceOptions {
    fn default() -> Self {
        Self {
            ciphersuites: "TLS_AES_128_GCM_SHA256".to_owned(),
            groups: "X25519MLKEM768:X25519".to_owned(),
            alpn: "h2".to_owned(),
            middlebox: true,
            max_fragment: 0,
            split_fragment: 0,
            padding: 0,
            tcp_nodelay: false,
        }
    }
}

/// Inputs to one formal TLS-shape run.
#[derive(Debug, Clone)]
pub struct TlsShapeSuite {
    /// Repository checkout containing the candidate source and reference source.
    pub repo: PathBuf,
    /// Candidate rust-reality binary.
    pub rust_bin: PathBuf,
    /// Unmodified Xray binary.
    pub xray_bin: PathBuf,
    /// OpenSSL CLI whose installation identity must match the linked reference.
    pub openssl_bin: PathBuf,
    /// Fresh output directory outside the Git worktree.
    pub out_dir: PathBuf,
    /// Safe run identifier.
    pub run_id: String,
    /// Sequential samples, in `1..=10`.
    pub samples: usize,
    /// Dynamic reference controls.
    pub reference: ReferenceOptions,
}

/// A compiled, content-identified independent reference executable.
#[derive(Debug, Clone)]
struct ReferenceBinary {
    path: PathBuf,
    sha256: String,
    self_identity: String,
    source_sha256: String,
    compiler_path: PathBuf,
    compiler_sha256: String,
    compiler_identity: String,
    openssl_cli: Binary,
}

/// One implementation observation plus optional process-write instrumentation.
struct Measurement {
    flight: crate::bench::tls_shape::Flight,
    process_write: Option<Json>,
    packet_shape: PacketObservation,
}

#[derive(Debug, Clone)]
enum PacketCaptureCapability {
    Available {
        tcpdump: PathBuf,
        sudo: Option<PathBuf>,
        uid: String,
        gid: String,
    },
    Unavailable {
        reason: String,
    },
}

impl PacketCaptureCapability {
    fn to_json(&self) -> Json {
        match self {
            Self::Available { tcpdump, sudo, .. } => Json::object([
                (
                    "executor",
                    Json::string(if sudo.is_some() { "sudo" } else { "direct" }),
                ),
                ("status", Json::string("AVAILABLE")),
                ("tcpdumpPath", Json::string(tcpdump.display().to_string())),
            ]),
            Self::Unavailable { reason } => Json::object([
                ("reason", Json::string(reason.clone())),
                ("status", Json::string("UNAVAILABLE")),
            ]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacketEvent {
    payload_bytes: usize,
    flags: Option<String>,
}

#[derive(Debug, Clone)]
enum PacketObservation {
    Available {
        packets: Vec<PacketEvent>,
        total_bytes: usize,
        complete: bool,
        pcap_sha256: String,
    },
    Unavailable {
        reason: String,
    },
}

impl PacketObservation {
    fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    fn to_json(&self) -> Json {
        match self {
            Self::Available {
                packets,
                total_bytes,
                complete,
                pcap_sha256,
            } => Json::object([
                ("captureStatus", Json::string("AVAILABLE")),
                ("classification", Json::string("NETWORK_DEPENDENT")),
                ("complete", Json::Bool(*complete)),
                (
                    "packets",
                    Json::Array(
                        packets
                            .iter()
                            .map(|packet| {
                                Json::object([
                                    (
                                        "flags",
                                        packet.flags.as_ref().map_or(Json::Null, |flags| {
                                            Json::string(flags.clone())
                                        }),
                                    ),
                                    (
                                        "payloadBytes",
                                        Json::Int(
                                            i64::try_from(packet.payload_bytes).unwrap_or(i64::MAX),
                                        ),
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("pcapSha256", Json::string(pcap_sha256.clone())),
                (
                    "totalBytes",
                    Json::Int(i64::try_from(*total_bytes).unwrap_or(i64::MAX)),
                ),
            ]),
            Self::Unavailable { reason } => Json::object([
                ("captureStatus", Json::string("UNAVAILABLE")),
                ("reason", Json::string(reason.clone())),
            ]),
        }
    }
}

/// Immutable material shared by the sequential samples.
struct RunContext<'a> {
    suite: &'a TlsShapeSuite,
    workspace: &'a Workspace,
    run: &'a crate::bench::evidence::RunDirectory,
    reference: &'a ReferenceBinary,
    certificate: &'a no_ccs::CoverCertificate,
    rust: &'a Binary,
    xray: &'a Binary,
    rust_config: &'a Path,
    xray_server_config: &'a Path,
    client_hello: &'a [u8],
    strace: Option<&'a Path>,
    packet_capture: &'a PacketCaptureCapability,
    ports: [u16; 8],
}

/// Validates the purely structural suite inputs.
///
/// # Errors
///
/// Returns a diagnostic for an unsafe run id, invalid sample count, output
/// directory inside the checkout, or an out-of-range reference control.
pub fn validate(suite: &TlsShapeSuite) -> Result<(), String> {
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if !(1..=10).contains(&suite.samples) {
        return Err("TLS-shape samples must be in 1..=10".to_owned());
    }
    if suite.reference.ciphersuites.is_empty() || suite.reference.groups.is_empty() {
        return Err("TLS-shape ciphersuites and groups must be non-empty".to_owned());
    }
    if suite.reference.alpn.len() > 255 {
        return Err("TLS-shape ALPN exceeds 255 bytes".to_owned());
    }
    let repo = suite
        .repo
        .canonicalize()
        .map_err(|error| format!("could not canonicalize repository: {error}"))?;
    let output = absolute_without_existing(&suite.out_dir)?;
    if output.starts_with(&repo) {
        return Err("TLS-shape output directory must be outside the Git worktree".to_owned());
    }
    Ok(())
}

fn absolute_without_existing(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .map_err(|error| format!("could not resolve output directory: {error}"))
}

/// Builds the independent reference against the host's pinned libssl and binds
/// the resulting executable to its source, compiler, and linked OpenSSL identity.
fn build_reference(
    suite: &TlsShapeSuite,
    workspace: &Workspace,
) -> Result<ReferenceBinary, String> {
    let source = suite.repo.join("tools/reference/tls-shape-openssl.c");
    if !source.is_file() {
        return Err(format!(
            "TLS-shape reference source is missing: {}",
            source.display()
        ));
    }
    let source_sha256 = hash::sha256_file(&source)?;
    let cc = process::which("cc").ok_or_else(|| "cc is unavailable".to_owned())?;
    let compiler_sha256 = hash::sha256_file(&cc)?;
    let compiler = Tool::new(cc.display().to_string())
        .arg("--version")
        .run()
        .map_err(|error| format!("could not identify cc: {error}"))?;
    let compiler_identity = compiler
        .trimmed_stdout()
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    if compiler_identity.is_empty() {
        return Err("cc --version produced no identity".to_owned());
    }

    let cflags = pkg_config("--cflags")?;
    let libraries = pkg_config("--libs")?;
    let output = workspace.join("tls-shape-openssl-reference");
    let mut args = vec![
        "-std=c11".to_owned(),
        "-O2".to_owned(),
        "-g".to_owned(),
        "-fno-omit-frame-pointer".to_owned(),
        "-Wall".to_owned(),
        "-Wextra".to_owned(),
        "-Werror".to_owned(),
    ];
    args.extend(cflags);
    args.push(source.display().to_string());
    args.extend(["-o".to_owned(), output.display().to_string()]);
    args.extend(libraries);
    Tool::new(cc.display().to_string())
        .args(args)
        .run()
        .map_err(|error| format!("could not build TLS-shape reference: {error}"))?;
    let sha256 = hash::sha256_file(&output)?;
    let self_identity = Tool::new(output.display().to_string())
        .arg("--identity")
        .run()
        .map_err(|error| format!("could not identify TLS-shape reference: {error}"))?
        .stdout;
    validate_reference_identity(&self_identity)?;

    let openssl_path = process::which(&suite.openssl_bin.display().to_string())
        .ok_or_else(|| format!("{} is unavailable", suite.openssl_bin.display()))?;
    let openssl_identity = Tool::new(openssl_path.display().to_string())
        .args(["version", "-a"])
        .run()
        .map_err(|error| format!("could not identify OpenSSL: {error}"))?
        .stdout;
    no_ccs::check_openssl_version(&openssl_identity)?;
    let openssl_cli = Binary {
        label: "openssl-cli".to_owned(),
        sha256: hash::sha256_file(&openssl_path)?,
        path: openssl_path,
        identity: openssl_identity,
    };
    require_matching_openssl(&self_identity, &openssl_cli.identity)?;

    Ok(ReferenceBinary {
        path: output,
        sha256,
        self_identity,
        source_sha256,
        compiler_path: cc,
        compiler_sha256,
        compiler_identity,
        openssl_cli,
    })
}

fn pkg_config(flag: &str) -> Result<Vec<String>, String> {
    let output = Tool::new("pkg-config")
        .args([flag, "openssl"])
        .run()
        .map_err(|error| format!("pkg-config {flag} openssl failed: {error}"))?;
    Ok(output
        .trimmed_stdout()
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

fn validate_reference_identity(text: &str) -> Result<(), String> {
    let value = json_in::parse(text)
        .map_err(|error| format!("reference identity is invalid JSON: {error}"))?;
    if value
        .int_field("reference", "schemaVersion")
        .map_err(|error| error.to_string())?
        != 1
    {
        return Err("reference identity has an unsupported schemaVersion".to_owned());
    }
    let config = value
        .str_field("reference", "configPolicy")
        .map_err(|error| error.to_string())?;
    if config != "OPENSSL_INIT_NO_LOAD_CONFIG" {
        return Err(format!("reference config policy drifted: {config}"));
    }
    let providers = value
        .array_field("reference", "providerPolicy")
        .map_err(|error| error.to_string())?;
    if providers.len() != 1 || providers[0].as_str("providerPolicy[0]").ok() != Some("default") {
        return Err("reference provider policy must be exactly [default]".to_owned());
    }
    for field in ["compiler", "opensslCompileVersion", "opensslRuntimeVersion"] {
        if value
            .str_field("reference", field)
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err(format!("reference identity field {field} is empty"));
        }
    }
    Ok(())
}

fn require_matching_openssl(reference: &str, cli: &str) -> Result<(), String> {
    let value = json_in::parse(reference)?;
    let runtime = value
        .str_field("reference", "opensslRuntimeVersion")
        .map_err(|error| error.to_string())?;
    let cli_first = cli.lines().next().unwrap_or_default();
    let annotated = format!("{runtime} (Library: {runtime})");
    if runtime == cli_first || annotated == cli_first {
        Ok(())
    } else {
        Err(format!(
            "linked reference OpenSSL {runtime:?} differs from CLI {cli_first:?}"
        ))
    }
}

fn reference_args(
    options: &ReferenceOptions,
    port: u16,
    certificate: &no_ccs::CoverCertificate,
) -> Vec<String> {
    vec![
        port.to_string(),
        certificate.certificate.display().to_string(),
        certificate.key.display().to_string(),
        options.ciphersuites.clone(),
        options.groups.clone(),
        options.alpn.clone(),
        u8::from(options.middlebox).to_string(),
        options.max_fragment.to_string(),
        options.split_fragment.to_string(),
        options.padding.to_string(),
        u8::from(options.tcp_nodelay).to_string(),
    ]
}

fn serial_rust_config(generated: &RustIdentity, target: &str) -> Result<String, String> {
    use json_in::Value;
    let value = json_in::parse(&generated.server_json)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?;
    let Value::Object(mut root) = value else {
        return Err("generated rust config is not an object".to_owned());
    };
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
    reality.insert("target".to_owned(), Value::Str(target.to_owned()));
    let Some(Value::Object(optimization)) = reality.get_mut("coverOptimization") else {
        return Err("generated rust config has no coverOptimization".to_owned());
    };
    optimization.insert("warmTcp".to_owned(), Value::Bool(false));
    Ok(crate::bench::suites::render_compact(&Value::Object(root)))
}

fn record_delay_rust_config(generated: &RustIdentity, target: &str) -> Result<String, String> {
    use json_in::Value;
    let serial = serial_rust_config(generated, target)?;
    let value = json_in::parse(&serial)
        .map_err(|error| format!("record-delay rust config is invalid JSON: {error}"))?;
    let Value::Object(mut root) = value else {
        return Err("record-delay rust config is not an object".to_owned());
    };
    let Some(Value::Object(log)) = root.get_mut("log") else {
        return Err("record-delay rust config has no log object".to_owned());
    };
    log.insert("level".to_owned(), Value::Str("debug".to_owned()));
    Ok(crate::bench::suites::render_compact(&Value::Object(root)))
}

fn spawn_reference(
    reference: &ReferenceBinary,
    options: &ReferenceOptions,
    certificate: &no_ccs::CoverCertificate,
    port: u16,
    workspace: &Workspace,
    log: &Path,
) -> Result<Child, String> {
    Child::spawn(
        "tls-shape-openssl-reference",
        &reference.path,
        &reference_args(options, port, certificate),
        workspace.path(),
        &[],
        log,
    )
    .map_err(|error| error.to_string())
}

fn wait_for_log(child: &mut Child, log: &Path, marker: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::fs::read_to_string(log).is_ok_and(|text| text.contains(marker)) {
            return Ok(());
        }
        if !child.is_alive() {
            let text = std::fs::read_to_string(log).unwrap_or_default();
            return Err(format!(
                "{} exited before readiness marker {marker:?}: {}",
                child.label(),
                text.trim_end()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "{} did not emit readiness marker {marker:?} within 10s",
        child.label()
    ))
}

fn detect_packet_capture() -> PacketCaptureCapability {
    let Some(tcpdump) = process::which("tcpdump") else {
        return PacketCaptureCapability::Unavailable {
            reason: "tcpdump is not installed".to_owned(),
        };
    };
    let uid = Tool::new("id")
        .arg("-u")
        .run()
        .map(|outcome| outcome.trimmed_stdout().to_owned());
    let gid = Tool::new("id")
        .arg("-g")
        .run()
        .map(|outcome| outcome.trimmed_stdout().to_owned());
    let (Ok(uid), Ok(gid)) = (uid, gid) else {
        return PacketCaptureCapability::Unavailable {
            reason: "could not identify the capture owner".to_owned(),
        };
    };
    if uid == "0" {
        return PacketCaptureCapability::Available {
            tcpdump,
            sudo: None,
            uid,
            gid,
        };
    }
    let Some(sudo) = process::which("sudo") else {
        return PacketCaptureCapability::Unavailable {
            reason: "packet capture requires root and sudo is unavailable".to_owned(),
        };
    };
    if Tool::new(sudo.display().to_string())
        .args(["-n", "true"])
        .run()
        .is_err()
    {
        return PacketCaptureCapability::Unavailable {
            reason: "non-interactive packet-capture privilege is unavailable".to_owned(),
        };
    }
    PacketCaptureCapability::Available {
        tcpdump,
        sudo: Some(sudo),
        uid,
        gid,
    }
}

struct ActivePacketCapture {
    child: Child,
    parent_starttime: Option<String>,
    tcpdump: PathBuf,
    sudo: Option<PathBuf>,
    uid: String,
    gid: String,
    pcap: PathBuf,
    packets_text: PathBuf,
    port: u16,
}

enum PacketCapture {
    Active(Box<ActivePacketCapture>),
    Unavailable(String),
}

fn begin_packet_capture(context: &RunContext<'_>, stem: &str, port: u16) -> PacketCapture {
    let PacketCaptureCapability::Available {
        tcpdump,
        sudo,
        uid,
        gid,
    } = context.packet_capture
    else {
        let PacketCaptureCapability::Unavailable { reason } = context.packet_capture else {
            unreachable!()
        };
        return PacketCapture::Unavailable(reason.clone());
    };
    let pcap = context.run.join(&format!("{stem}.pcap"));
    let log = context.run.join(&format!("{stem}.tcpdump.log"));
    let packets_text = context.run.join(&format!("{stem}.packets.txt"));
    let capture_args = [
        "--immediate-mode".to_owned(),
        "-i".to_owned(),
        "lo".to_owned(),
        "-U".to_owned(),
        "-s".to_owned(),
        "0".to_owned(),
        "-w".to_owned(),
        pcap.display().to_string(),
        format!("tcp port {port}"),
    ];
    let (program, args) = if let Some(sudo) = sudo {
        let mut args = vec!["-n".to_owned(), tcpdump.display().to_string()];
        args.extend(capture_args);
        (sudo, args)
    } else {
        (tcpdump, capture_args.into())
    };
    let mut child = match Child::spawn(
        format!("tls-shape-tcpdump-{port}"),
        program,
        &args,
        context.workspace.path(),
        &[],
        &log,
    ) {
        Ok(child) => child,
        Err(error) => return PacketCapture::Unavailable(error.to_string()),
    };
    let parent_starttime = crate::bench::process::proc_starttime(child.pid());
    if let Err(error) = wait_for_log(&mut child, &log, "listening on") {
        child.terminate();
        let _ = normalize_capture(&pcap, sudo.as_ref(), uid, gid);
        return PacketCapture::Unavailable(error);
    }
    PacketCapture::Active(Box::new(ActivePacketCapture {
        child,
        parent_starttime,
        tcpdump: tcpdump.clone(),
        sudo: sudo.clone(),
        uid: uid.clone(),
        gid: gid.clone(),
        pcap,
        packets_text,
        port,
    }))
}

fn proc_children(pid: u32) -> Vec<(u32, Option<String>)> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|text| text.parse::<u32>().ok())
        .map(|child| (child, crate::bench::process::proc_starttime(child)))
        .collect()
}

fn signal_exact(
    pid: u32,
    starttime: Option<&str>,
    sudo: Option<&Path>,
) -> Result<(), String> {
    if starttime.is_some() && crate::bench::process::proc_starttime(pid).as_deref() != starttime {
        return Err(format!(
            "capture process {pid} identity changed before SIGINT"
        ));
    }
    let outcome = if let Some(sudo) = sudo {
        Tool::new(sudo.display().to_string()).args([
            "-n".to_owned(),
            "kill".to_owned(),
            "-INT".to_owned(),
            pid.to_string(),
        ])
    } else {
        Tool::new("kill").args(["-INT".to_owned(), pid.to_string()])
    }
    .run();
    outcome
        .map(|_| ())
        .map_err(|error| format!("could not interrupt capture process {pid}: {error}"))
}

fn normalize_capture(
    pcap: &Path,
    sudo: Option<&PathBuf>,
    uid: &str,
    gid: &str,
) -> Result<(), String> {
    if !pcap.exists() {
        return Err(format!("capture did not create {}", pcap.display()));
    }
    if let Some(sudo) = sudo {
        Tool::new(sudo.display().to_string())
            .args([
                "-n".to_owned(),
                "chown".to_owned(),
                "--".to_owned(),
                format!("{uid}:{gid}"),
                pcap.display().to_string(),
            ])
            .run()
            .map_err(|error| format!("could not normalize {} owner: {error}", pcap.display()))?;
    }
    Tool::new("chmod")
        .args(["600".to_owned(), pcap.display().to_string()])
        .run()
        .map(|_| ())
        .map_err(|error| format!("could not normalize {} mode: {error}", pcap.display()))
}

impl ActivePacketCapture {
    fn finish(mut self, expected_bytes: usize) -> Result<PacketObservation, String> {
        if self.sudo.is_some() {
            let children = proc_children(self.child.pid());
            if children.is_empty() {
                return Err("privileged tcpdump process had no observable child".to_owned());
            }
            for (pid, starttime) in children {
                signal_exact(pid, starttime.as_deref(), self.sudo.as_deref())?;
            }
        } else {
            signal_exact(self.child.pid(), self.parent_starttime.as_deref(), None)?;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && self.child.is_alive() {
            std::thread::sleep(Duration::from_millis(20));
        }
        self.child.terminate();
        normalize_capture(&self.pcap, self.sudo.as_ref(), &self.uid, &self.gid)?;
        let decoded = Tool::new(self.tcpdump.display().to_string())
            .args([
                "-nn".to_owned(),
                "-tt".to_owned(),
                "-r".to_owned(),
                self.pcap.display().to_string(),
            ])
            .run()
            .map_err(|error| format!("could not decode {}: {error}", self.pcap.display()))?
            .stdout;
        std::fs::write(&self.packets_text, &decoded).map_err(|error| {
            format!(
                "could not write decoded packet evidence {}: {error}",
                self.packets_text.display()
            )
        })?;
        Ok(parse_packet_shape(
            &decoded,
            self.port,
            expected_bytes,
            hash::sha256_file(&self.pcap)?,
        ))
    }
}

impl PacketCapture {
    fn finish(self, expected_bytes: usize) -> PacketObservation {
        match self {
            Self::Active(capture) => capture
                .finish(expected_bytes)
                .unwrap_or_else(PacketObservation::unavailable),
            Self::Unavailable(reason) => PacketObservation::unavailable(reason),
        }
    }
}

fn parse_packet_shape(
    text: &str,
    port: u16,
    expected_bytes: usize,
    pcap_sha256: String,
) -> PacketObservation {
    let source = format!(".{port} >");
    let all = text
        .lines()
        .filter(|line| line.contains(&source))
        .filter_map(|line| {
            let payload_bytes = line
                .rsplit_once("length ")?
                .1
                .trim()
                .parse::<usize>()
                .ok()?;
            if payload_bytes == 0 {
                return None;
            }
            let flags = line
                .split_once("Flags [")
                .and_then(|(_, rest)| rest.split_once(']'))
                .map(|(flags, _)| flags.to_owned());
            Some(PacketEvent {
                payload_bytes,
                flags,
            })
        })
        .collect::<Vec<_>>();
    let mut selected = Vec::new();
    let mut total_bytes = 0;
    for start in 0..all.len() {
        let mut candidate = Vec::new();
        let mut total = 0;
        for packet in &all[start..] {
            candidate.push(packet.clone());
            total += packet.payload_bytes;
            if total >= expected_bytes {
                break;
            }
        }
        if total == expected_bytes {
            selected = candidate;
            total_bytes = total;
            break;
        }
    }
    if selected.is_empty() {
        for packet in all {
            total_bytes += packet.payload_bytes;
            selected.push(packet);
            if total_bytes >= expected_bytes {
                break;
            }
        }
    }
    PacketObservation::Available {
        packets: selected,
        total_bytes,
        complete: total_bytes == expected_bytes,
        pcap_sha256,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "a measured process has exactly these identity and evidence inputs"
)]
fn spawn_measured(
    label: &str,
    program: &Path,
    args: &[String],
    env: &[(String, String)],
    workspace: &Workspace,
    log: &Path,
    strace: Option<&Path>,
    trace_prefix: &Path,
) -> Result<Child, String> {
    if let Some(strace) = strace {
        let mut traced_args = vec![
            "-ff".to_owned(),
            "-ttt".to_owned(),
            "-yy".to_owned(),
            "-s".to_owned(),
            "1".to_owned(),
            "-e".to_owned(),
            "trace=write,writev,sendto,sendmsg".to_owned(),
            "-o".to_owned(),
            trace_prefix.display().to_string(),
            program.display().to_string(),
        ];
        traced_args.extend_from_slice(args);
        return Child::spawn(label, strace, &traced_args, workspace.path(), env, log)
            .map_err(|error| error.to_string());
    }
    Child::spawn(label, program, args, workspace.path(), env, log)
        .map_err(|error| error.to_string())
}

fn parse_strace_shape(prefix: &Path, port: u16, expected_bytes: usize) -> Option<Json> {
    let parent = prefix.parent()?;
    let name = prefix.file_name()?.to_string_lossy();
    let mut paths = std::fs::read_dir(parent)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|candidate| candidate.to_string_lossy().starts_with(name.as_ref()))
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        return None;
    }
    let port_marker = format!(":{port}");
    let mut events = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path).ok()?;
        for line in text.lines() {
            if !line.contains("TCP:") || !line.contains(&port_marker) {
                continue;
            }
            let call = ["writev", "write", "sendto", "sendmsg"]
                .into_iter()
                .find(|name| line.contains(&format!("{name}(")))?;
            let timestamp = line.split_whitespace().next()?.parse::<f64>().ok()?;
            let result = line
                .rsplit_once("= ")?
                .1
                .split_whitespace()
                .next()?
                .parse::<i64>()
                .ok()?;
            if result > 0 {
                events.push((timestamp, call.to_owned(), usize::try_from(result).ok()?));
            }
        }
    }
    events.sort_by(|left, right| left.0.total_cmp(&right.0));
    let selected = select_write_window(&events, expected_bytes);
    let total = selected.iter().map(|event| event.2).sum::<usize>();
    Some(Json::object([
        ("complete", Json::Bool(total == expected_bytes)),
        (
            "sizes",
            Json::Array(
                selected
                    .iter()
                    .map(|event| Json::Int(i64::try_from(event.2).unwrap_or(i64::MAX)))
                    .collect(),
            ),
        ),
        (
            "syscalls",
            Json::Array(
                selected
                    .iter()
                    .map(|event| Json::string(event.1.clone()))
                    .collect(),
            ),
        ),
        (
            "totalBytes",
            Json::Int(i64::try_from(total).unwrap_or(i64::MAX)),
        ),
    ]))
}

fn select_write_window(
    events: &[(f64, String, usize)],
    expected_bytes: usize,
) -> Vec<&(f64, String, usize)> {
    for start in 0..events.len() {
        let mut selected = Vec::new();
        let mut total = 0;
        for event in &events[start..] {
            selected.push(event);
            total += event.2;
            if total >= expected_bytes {
                break;
            }
        }
        if total == expected_bytes {
            return selected;
        }
    }
    let mut selected = Vec::new();
    let mut total = 0;
    for event in events {
        selected.push(event);
        total += event.2;
        if total >= expected_bytes {
            break;
        }
    }
    selected
}

fn measurement_json(measurement: &Measurement, client_hello: &[u8]) -> Json {
    let Json::Object(mut members) = measurement.flight.to_json(client_hello) else {
        unreachable!("flight evidence is always an object")
    };
    members.insert(
        "processWriteShape".to_owned(),
        measurement.process_write.clone().unwrap_or(Json::Null),
    );
    members.insert("packetShape".to_owned(), measurement.packet_shape.to_json());
    members.insert(
        "timingMeasurement".to_owned(),
        Json::object([
            (
                "classification",
                Json::string(if measurement.process_write.is_some() {
                    "NOT_COMPARABLE"
                } else {
                    "EXPLORATORY"
                }),
            ),
            (
                "instrumentedByStrace",
                Json::Bool(measurement.process_write.is_some()),
            ),
        ]),
    );
    Json::Object(members)
}

fn packet_sequence_delta(reference: &[PacketEvent], candidate: &[PacketEvent]) -> Json {
    Json::Array(
        (0..reference.len().max(candidate.len()))
            .map(|position| {
                let left = reference.get(position).map(|packet| packet.payload_bytes);
                let right = candidate.get(position).map(|packet| packet.payload_bytes);
                Json::object([
                    (
                        "candidate",
                        right.map_or(Json::Null, |bytes| {
                            Json::Int(i64::try_from(bytes).unwrap_or(i64::MAX))
                        }),
                    ),
                    (
                        "delta",
                        left.zip(right).map_or(Json::Null, |(left, right)| {
                            Json::Int(
                                i64::try_from(right).unwrap_or(i64::MAX)
                                    - i64::try_from(left).unwrap_or(i64::MAX),
                            )
                        }),
                    ),
                    (
                        "position",
                        Json::Int(i64::try_from(position).unwrap_or(i64::MAX)),
                    ),
                    (
                        "reference",
                        left.map_or(Json::Null, |bytes| {
                            Json::Int(i64::try_from(bytes).unwrap_or(i64::MAX))
                        }),
                    ),
                ])
            })
            .collect(),
    )
}

fn comparison_json(reference: &Measurement, candidate: &Measurement) -> Json {
    let Json::Object(mut members) =
        crate::bench::tls_shape::compare(&reference.flight, &candidate.flight).to_json()
    else {
        unreachable!("shape comparison is always an object")
    };
    let (
        PacketObservation::Available {
            packets: reference_packets,
            complete: reference_complete,
            ..
        },
        PacketObservation::Available {
            packets: candidate_packets,
            complete: candidate_complete,
            ..
        },
    ) = (&reference.packet_shape, &candidate.packet_shape)
    else {
        members.insert("observedPacketShapeEqual".to_owned(), Json::Null);
        members.insert("packetCountDifference".to_owned(), Json::Null);
        members.insert("packetPayloadSizeDelta".to_owned(), Json::Null);
        members.insert(
            "packetShapeClassification".to_owned(),
            Json::string("UNAVAILABLE"),
        );
        return Json::Object(members);
    };
    {
        let comparable = *reference_complete && *candidate_complete;
        members.insert(
            "observedPacketShapeEqual".to_owned(),
            if comparable {
                Json::Bool(reference_packets == candidate_packets)
            } else {
                Json::Null
            },
        );
        members.insert(
            "packetCountDifference".to_owned(),
            if comparable {
                Json::Int(
                    i64::try_from(candidate_packets.len()).unwrap_or(i64::MAX)
                        - i64::try_from(reference_packets.len()).unwrap_or(i64::MAX),
                )
            } else {
                Json::Null
            },
        );
        members.insert(
            "packetPayloadSizeDelta".to_owned(),
            if comparable {
                packet_sequence_delta(reference_packets, candidate_packets)
            } else {
                Json::Null
            },
        );
        members.insert(
            "packetShapeClassification".to_owned(),
            Json::string(if comparable {
                "NETWORK_DEPENDENT"
            } else {
                "NOT_COMPARABLE"
            }),
        );
    }
    Json::Object(members)
}

fn run_reference_sample(context: &RunContext<'_>, sample: usize) -> Result<Measurement, String> {
    let port = context.ports[5];
    let stem = format!("samples/{sample:03}/reference");
    let log = context.run.join(&format!("{stem}.log"));
    let trace = context.run.join(&format!("{stem}.strace"));
    let capture = begin_packet_capture(context, &stem, port);
    let mut child = spawn_measured(
        "tls-shape-reference",
        &context.reference.path,
        &reference_args(&context.suite.reference, port, context.certificate),
        &[],
        context.workspace,
        &log,
        context.strace,
        &trace,
    )?;
    wait_for_log(&mut child, &log, "READY ")?;
    let flight = crate::bench::tls_shape::replay(port, context.client_hello)?;
    child.terminate();
    let process_write = context
        .strace
        .and_then(|_| parse_strace_shape(&trace, port, flight.wire.len()));
    let packet_shape = capture.finish(flight.wire.len());
    Ok(Measurement {
        flight,
        process_write,
        packet_shape,
    })
}

fn run_rust_sample(context: &RunContext<'_>, sample: usize) -> Result<Measurement, String> {
    let (cover_port, server_port) = (context.ports[0], context.ports[1]);
    let stem = format!("samples/{sample:03}/rust");
    let log = context.run.join(&format!("{stem}.log"));
    let trace = context.run.join(&format!("{stem}.strace"));
    let capture = begin_packet_capture(context, &stem, server_port);
    let mut server = spawn_measured(
        "tls-shape-rust-reality",
        &context.rust.path,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            context.rust_config.display().to_string(),
        ],
        &[(
            "SSL_CERT_FILE".to_owned(),
            context.certificate.ca_certificate.display().to_string(),
        )],
        context.workspace,
        &log,
        context.strace,
        &trace,
    )?;
    server
        .wait_for_port(server_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let cover_log = context.run.join(&format!("{stem}-cover.log"));
    let mut cover = spawn_reference(
        context.reference,
        &context.suite.reference,
        context.certificate,
        cover_port,
        context.workspace,
        &cover_log,
    )?;
    wait_for_log(&mut cover, &cover_log, "READY ")?;
    let flight = crate::bench::tls_shape::replay(server_port, context.client_hello)?;
    server.terminate();
    cover.terminate();
    let process_write = context
        .strace
        .and_then(|_| parse_strace_shape(&trace, server_port, flight.wire.len()));
    let packet_shape = capture.finish(flight.wire.len());
    Ok(Measurement {
        flight,
        process_write,
        packet_shape,
    })
}

fn run_xray_sample(context: &RunContext<'_>, sample: usize) -> Result<Measurement, String> {
    let (cover_port, server_port) = (context.ports[0], context.ports[6]);
    let stem = format!("samples/{sample:03}/xray");
    let log = context.run.join(&format!("{stem}.log"));
    let trace = context.run.join(&format!("{stem}.strace"));
    let capture = begin_packet_capture(context, &stem, server_port);
    let mut server = spawn_measured(
        "tls-shape-xray",
        &context.xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            context.xray_server_config.display().to_string(),
        ],
        &[],
        context.workspace,
        &log,
        context.strace,
        &trace,
    )?;
    server
        .wait_for_port(server_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let cover_log = context.run.join(&format!("{stem}-cover.log"));
    let mut cover = spawn_reference(
        context.reference,
        &context.suite.reference,
        context.certificate,
        cover_port,
        context.workspace,
        &cover_log,
    )?;
    wait_for_log(&mut cover, &cover_log, "READY ")?;
    let flight = crate::bench::tls_shape::replay(server_port, context.client_hello)?;
    server.terminate();
    cover.terminate();
    let process_write = context
        .strace
        .and_then(|_| parse_strace_shape(&trace, server_port, flight.wire.len()));
    let packet_shape = capture.finish(flight.wire.len());
    Ok(Measurement {
        flight,
        process_write,
        packet_shape,
    })
}

fn capture_stock_xray_hello(
    context: &RunContext<'_>,
    generated: &RustIdentity,
    xray_client_config: &Path,
    origin_port: u16,
    expected_payload_sha256: &str,
) -> Result<Vec<u8>, String> {
    let (cover_port, server_port, proxy_port, socks_port) = (
        context.ports[0],
        context.ports[1],
        context.ports[2],
        context.ports[3],
    );
    let mut server = Child::spawn(
        "tls-shape-capture-rust-reality",
        &context.rust.path,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            context.rust_config.display().to_string(),
        ],
        context.workspace.path(),
        &[(
            "SSL_CERT_FILE".to_owned(),
            context.certificate.ca_certificate.display().to_string(),
        )],
        &context.run.join("capture-rust.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;

    let cover_log = context.run.join("capture-cover.log");
    let mut cover = spawn_reference(
        context.reference,
        &context.suite.reference,
        context.certificate,
        cover_port,
        context.workspace,
        &cover_log,
    )?;
    wait_for_log(&mut cover, &cover_log, "READY ")?;

    let listener = std::net::TcpListener::bind(("127.0.0.1", proxy_port))
        .map_err(|error| format!("could not bind ClientHello capture proxy: {error}"))?;
    let capture = std::thread::spawn(move || {
        crate::bench::tls_shape::capture_one_from_listener(&listener, server_port)
    });
    let mut client = Child::spawn(
        "tls-shape-stock-xray-client",
        &context.xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            xray_client_config.display().to_string(),
        ],
        context.workspace.path(),
        &[],
        &context.run.join("capture-xray.log"),
    )
    .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;

    let downloaded = context.workspace.join("capture-download.bin");
    crate::bench::interop::fetch_payload(socks_port, origin_port, &downloaded)?;
    let observed = hash::sha256_file(&downloaded)?;
    if observed != expected_payload_sha256 {
        return Err("stock-Xray capture transfer changed payload bytes".to_owned());
    }
    client.terminate();
    server.terminate();
    cover.terminate();
    let hello = capture
        .join()
        .map_err(|_| "ClientHello capture thread panicked".to_owned())??;
    if generated.uuid.is_empty() || generated.short_id.is_empty() {
        return Err("captured ClientHello has no generated REALITY identity".to_owned());
    }
    Ok(hello)
}

fn run_production_reader_gate(suite: &TlsShapeSuite, rust: &Binary) -> Result<Json, String> {
    const TEST: &str = "protocol::reality::tls13::target_read::tests::tcp_record_delay_matrix_covers_fifth_probe_timing";
    let environment = json_in::parse(&rust.identity)
        .map_err(|error| format!("candidate identity is invalid JSON: {error}"))?;
    let candidate_commit = environment
        .str_field("environment", "gitCommit")
        .map_err(|error| error.to_string())?;
    let head = Tool::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&suite.repo)
        .run()
        .map_err(|error| format!("could not identify repository HEAD: {error}"))?;
    if head.trimmed_stdout() != candidate_commit {
        return Err(format!(
            "candidate source commit {candidate_commit} differs from repository HEAD {}",
            head.trimmed_stdout()
        ));
    }
    let outcome = Tool::new("cargo")
        .args(["test", "--lib", TEST, "--", "--exact", "--nocapture"])
        .current_dir(&suite.repo)
        .probe()
        .map_err(|error| format!("could not run production reader gate: {error}"))?;
    let success = outcome.success();
    let code = outcome.code;
    let mut output = outcome.stdout;
    output.push_str(&outcome.stderr);
    if !success
        || !output.contains(&format!("test {TEST} ... ok"))
        || !output.contains("test result: ok. 1 passed; 0 failed;")
    {
        return Err(format!(
            "production reader gate failed with {:?}: {}",
            code,
            output.trim_end()
        ));
    }
    Ok(Json::object([
        ("cargoExitCode", Json::Int(0)),
        ("candidateSourceCommit", Json::string(candidate_commit)),
        (
            "outputSha256",
            Json::string(hash::sha256_hex(output.as_bytes())),
        ),
        ("status", Json::string("PASS")),
        ("testName", Json::string(TEST)),
    ]))
}

fn write_measurement(
    context: &RunContext<'_>,
    sample: usize,
    label: &str,
    measurement: &Measurement,
) -> Result<Json, String> {
    let relative = format!("samples/{sample:03}/{label}");
    std::fs::write(
        context.run.join(&format!("{relative}.wire")),
        &measurement.flight.wire,
    )
    .map_err(|error| format!("could not write {relative}.wire: {error}"))?;
    let json = measurement_json(measurement, context.client_hello);
    context
        .run
        .write_new(&format!("{relative}.json"), &json.to_python_json())?;
    Ok(json)
}

fn find_event(path: &Path, event_name: &str) -> Result<json_in::Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let mut matches = Vec::new();
    for line in text.lines() {
        let Ok(value) = json_in::parse(line) else {
            continue;
        };
        if value
            .str_field("log", "event")
            .is_ok_and(|event| event == event_name)
        {
            matches.push(value);
        }
    }
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    Err(format!(
        "{} contains {} {event_name:?} events, expected exactly one",
        path.display(),
        matches.len()
    ))
}

fn json_value(value: &json_in::Value) -> Json {
    match value {
        json_in::Value::Null => Json::Null,
        json_in::Value::Bool(flag) => Json::Bool(*flag),
        json_in::Value::Number(text) => text.parse::<i64>().map_or(Json::Null, Json::Int),
        json_in::Value::Str(text) => Json::string(text.clone()),
        json_in::Value::Array(items) => Json::Array(items.iter().map(json_value).collect()),
        json_in::Value::Object(members) => Json::object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), json_value(value))),
        ),
    }
}

fn verify_delay_event(
    event: &json_in::Value,
    expected: &crate::bench::tls_shape::DelayCoverEvidence,
) -> Result<(), String> {
    let bool_field = |name| {
        event
            .field("cover_flight_selected", name)
            .and_then(|value| value.as_bool(&format!("cover_flight_selected.{name}")))
            .map_err(|error| error.to_string())
    };
    let int_field = |name| {
        event
            .int_field("cover_flight_selected", name)
            .map_err(|error| error.to_string())
    };
    if !bool_field("emit_ccs")? || !expected.emit_ccs {
        return Err("record-delay candidate did not select the expected CCS".to_owned());
    }
    if event
        .str_field("cover_flight_selected", "layout")
        .map_err(|error| error.to_string())?
        != "positional"
    {
        return Err("record-delay candidate did not select positional layout".to_owned());
    }
    let wire_lengths = event
        .array_field("cover_flight_selected", "wire_lens")
        .map_err(|error| error.to_string())?
        .iter()
        .map(|value| {
            value.as_int("wire_lens[]").and_then(|number| {
                usize::try_from(number).map_err(|_| json_in::FieldError {
                    path: "wire_lens[]".to_owned(),
                    expected: "a non-negative usize".to_owned(),
                })
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    if wire_lengths != expected.encrypted_wire_lengths {
        return Err(format!(
            "record-delay candidate wire lengths {wire_lengths:?} != {:?}",
            expected.encrypted_wire_lengths
        ));
    }
    // The candidate omits `nst_wire_len` entirely when no ticket is retained.
    let observed_nst = event
        .optional("nst_wire_len")
        .and_then(|value| match value {
            json_in::Value::Null => None,
            _ => usize::try_from(
                value
                    .as_int("nst_wire_len")
                    .map_err(|error| error.to_string())
                    .ok()?,
            )
            .ok(),
        });
    if observed_nst != expected.nst_wire_length
        || usize::try_from(int_field("retained_prefix_bytes")?).ok()
            != Some(expected.retained_prefix_bytes)
        || event
            .str_field("cover_flight_selected", "retained_prefix_sha256")
            .map_err(|error| error.to_string())?
            != expected.retained_prefix_sha256
    {
        return Err("record-delay candidate retained-prefix evidence differs".to_owned());
    }
    Ok(())
}

fn run_record_delay_e2e(
    context: &RunContext<'_>,
    generated: &RustIdentity,
    origin_port: u16,
    expected_payload_sha256: &str,
) -> Result<Json, String> {
    use crate::bench::{config::RealityIdentity, tls_shape::DelayProbeCase};
    let reality = RealityIdentity {
        uuid: generated.uuid.clone(),
        short_id: generated.short_id.clone(),
        server_name: "localhost".to_owned(),
        target: "record-delay-fixture".to_owned(),
    };
    let client_config = context.workspace.join("xray-record-delay.json");
    std::fs::write(
        &client_config,
        crate::bench::config::xray_client(
            &reality,
            context.ports[1],
            context.ports[3],
            &generated.public_key,
        )
        .to_python_json(),
    )
    .map_err(|error| format!("could not write record-delay Xray config: {error}"))?;
    let mut cases = Vec::new();
    for delay_ms in [0_u64, 20, 50, 100, 200] {
        for probe_case in [
            DelayProbeCase::AlreadyBuffered,
            DelayProbeCase::AbsentWouldBlock,
        ] {
            cases.push(run_record_delay_case(
                context,
                generated,
                &client_config,
                delay_ms,
                probe_case,
                origin_port,
                expected_payload_sha256,
            )?);
        }
    }
    Ok(Json::object([
        (
            "caseCount",
            Json::Int(i64::try_from(cases.len()).unwrap_or(i64::MAX)),
        ),
        (
            "classifications",
            Json::Array(vec![
                Json::string("absent-would-block"),
                Json::string("already-buffered"),
            ]),
        ),
        (
            "delaysMs",
            Json::Array(
                [0_i64, 20, 50, 100, 200]
                    .into_iter()
                    .map(Json::Int)
                    .collect(),
            ),
        ),
        ("cases", Json::Array(cases)),
        ("status", Json::string("PASS")),
    ]))
}

fn run_record_delay_case(
    context: &RunContext<'_>,
    generated: &RustIdentity,
    client_config: &Path,
    delay_ms: u64,
    probe_case: crate::bench::tls_shape::DelayProbeCase,
    origin_port: u16,
    expected_payload_sha256: &str,
) -> Result<Json, String> {
    let case_id = format!("delay-{delay_ms:03}-{}", probe_case.label());
    let case_dir = context.run.join(&format!("record-delay-e2e/{case_id}"));
    std::fs::create_dir_all(&case_dir)
        .map_err(|error| format!("could not create {case_id}: {error}"))?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("could not bind {case_id} cover: {error}"))?;
    let cover_port = listener
        .local_addr()
        .map_err(|error| format!("could not identify {case_id} cover: {error}"))?
        .port();
    let server_config = context.workspace.join(&format!("rust-{case_id}.json"));
    std::fs::write(
        &server_config,
        record_delay_rust_config(generated, &format!("127.0.0.1:{cover_port}"))?,
    )
    .map_err(|error| format!("could not write {case_id} server config: {error}"))?;
    let server_log = case_dir.join("candidate.log");
    let mut server = Child::spawn(
        format!("record-delay-rust-{case_id}"),
        &context.rust.path,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            server_config.display().to_string(),
        ],
        context.workspace.path(),
        &[],
        &server_log,
    )
    .map_err(|error| error.to_string())?;
    wait_for_log(&mut server, &server_log, "listener_started")?;
    let cover = std::thread::spawn(move || {
        crate::bench::tls_shape::serve_delayed_cover(&listener, delay_ms, probe_case)
    });
    let client_log = case_dir.join("xray.log");
    let mut client = Child::spawn(
        format!("record-delay-xray-{case_id}"),
        &context.xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_config.display().to_string(),
        ],
        context.workspace.path(),
        &[],
        &client_log,
    )
    .map_err(|error| error.to_string())?;
    client
        .wait_for_port(context.ports[3], Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let payload = case_dir.join("payload.bin");
    crate::bench::interop::fetch_payload(context.ports[3], origin_port, &payload)?;
    wait_for_log(&mut server, &server_log, "connection_completed")?;
    client.terminate();
    server.terminate();
    let fixture = cover
        .join()
        .map_err(|_| format!("{case_id} cover thread panicked"))??;
    let selected = find_event(&server_log, "cover_flight_selected")?;
    let completed = find_event(&server_log, "connection_completed")?;
    verify_delay_event(&selected, &fixture)?;
    if completed
        .int_field("connection_completed", "uplink_bytes")
        .map_err(|error| error.to_string())?
        <= 0
        || completed
            .int_field("connection_completed", "downlink_bytes")
            .map_err(|error| error.to_string())?
            <= 0
    {
        return Err(format!("{case_id} transferred no authenticated bytes"));
    }
    let payload_sha256 = hash::sha256_file(&payload)?;
    if payload_sha256 != expected_payload_sha256 {
        return Err(format!("{case_id} payload SHA-256 mismatch"));
    }
    Ok(Json::object([
        ("candidateConnectionCompleted", json_value(&completed)),
        ("candidateCoverFlightSelected", json_value(&selected)),
        (
            "candidateLogSha256",
            Json::string(hash::sha256_file(&server_log)?),
        ),
        ("case", Json::string(case_id)),
        ("fixture", fixture.to_json()),
        ("payloadSha256", Json::string(payload_sha256)),
        ("status", Json::string("PASS")),
    ]))
}

fn binary_json(binary: &Binary) -> Json {
    Json::object([
        ("identity", Json::string(binary.identity.clone())),
        ("path", Json::string(binary.path.display().to_string())),
        ("sha256", Json::string(binary.sha256.clone())),
    ])
}

fn reference_options_json(options: &ReferenceOptions) -> Json {
    Json::object([
        ("alpn", Json::string(options.alpn.clone())),
        ("ciphersuites", Json::string(options.ciphersuites.clone())),
        ("groups", Json::string(options.groups.clone())),
        ("maxFragment", Json::Int(i64::from(options.max_fragment))),
        ("middlebox", Json::Bool(options.middlebox)),
        ("padding", Json::Int(i64::from(options.padding))),
        (
            "splitFragment",
            Json::Int(i64::from(options.split_fragment)),
        ),
        ("tcpNodelay", Json::Bool(options.tcp_nodelay)),
        ("tlsVersion", Json::string("1.3-only")),
    ])
}

/// Runs stock-Xray capture and the three-way dynamic first-flight comparison.
///
/// # Errors
///
/// Returns the first identity, build, capture, replay, parsing, integrity, or
/// publication failure. Shape differences remain observations in a valid report.
#[expect(
    clippy::too_many_lines,
    reason = "the typed suite lifecycle is intentionally visible in execution order"
)]
pub fn run(suite: &TlsShapeSuite) -> Result<Json, String> {
    use crate::bench::{
        config::RealityIdentity,
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        origin_go,
    };

    validate(suite)?;
    for program in ["cargo", "cc", "curl", "go", "pkg-config"] {
        if !Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    let rust = identity::register("rust-reality", &suite.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("benchmark-tls-shape")?;
    let reference = build_reference(suite, &workspace)?;
    let base = crate::bench::workspace::reserve_block(8)?;
    let ports = std::array::from_fn(|offset| base + u16::try_from(offset).unwrap_or(0));
    let certificate = no_ccs::build_cover_certificate(
        &reference.openssl_cli.path,
        workspace.path(),
        &suite.run_id,
    )?;

    let generated = suites::generate_rust_identity(
        &workspace,
        &rust.path,
        ports[1],
        &format!("localhost:{}", ports[0]),
        "localhost",
        Some(&run.join("generate.log")),
    )?;
    let rust_config = workspace.join("rust.json");
    std::fs::write(
        &rust_config,
        serial_rust_config(&generated, &format!("localhost:{}", ports[0]))?,
    )
    .map_err(|error| format!("could not write rust TLS-shape config: {error}"))?;
    let reality = RealityIdentity {
        uuid: generated.uuid.clone(),
        short_id: generated.short_id.clone(),
        server_name: "localhost".to_owned(),
        target: format!("localhost:{}", ports[0]),
    };
    let xray_client_config = workspace.join("xray-client.json");
    std::fs::write(
        &xray_client_config,
        crate::bench::config::xray_client(&reality, ports[2], ports[3], &generated.public_key)
            .to_python_json(),
    )
    .map_err(|error| format!("could not write Xray client config: {error}"))?;
    let xray_server_config = workspace.join("xray-server.json");
    std::fs::write(
        &xray_server_config,
        crate::bench::config::xray_server(&reality, ports[6], &generated.private_key, false)
            .to_python_json(),
    )
    .map_err(|error| format!("could not write Xray server config: {error}"))?;

    let payload = origin_go::write_pattern_payload(workspace.path(), 1)?;
    let payload_sha256 = hash::sha256_file(&payload)?;
    let origin_binary = origin_go::build(&suite.repo, &workspace)?;
    let _origin = origin_go::start(
        &origin_binary,
        &workspace,
        &origin_go::OriginPlan {
            label: "tls-shape-origin".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: ports[4],
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("origin-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;
    let strace = process::which("strace");
    let packet_capture = detect_packet_capture();
    let empty_hello = [];
    let capture_context = RunContext {
        suite,
        workspace: &workspace,
        run: &run,
        reference: &reference,
        certificate: &certificate,
        rust: &rust,
        xray: &xray,
        rust_config: &rust_config,
        xray_server_config: &xray_server_config,
        client_hello: &empty_hello,
        strace: strace.as_deref(),
        packet_capture: &packet_capture,
        ports,
    };
    let client_hello = capture_stock_xray_hello(
        &capture_context,
        &generated,
        &xray_client_config,
        ports[4],
        &payload_sha256,
    )?;
    std::fs::write(run.join("clienthello.bin"), &client_hello)
        .map_err(|error| format!("could not persist captured ClientHello: {error}"))?;

    let context = RunContext {
        client_hello: &client_hello,
        ..capture_context
    };
    let record_delay_e2e = run_record_delay_e2e(&context, &generated, ports[4], &payload_sha256)?;
    let mut samples = Vec::new();
    for sample in 1..=suite.samples {
        std::fs::create_dir_all(run.join(&format!("samples/{sample:03}")))
            .map_err(|error| format!("could not create sample directory: {error}"))?;
        let reference_measurement = run_reference_sample(&context, sample)?;
        let rust_measurement = run_rust_sample(&context, sample)?;
        let xray_measurement = run_xray_sample(&context, sample)?;
        let reference_json =
            write_measurement(&context, sample, "reference", &reference_measurement)?;
        let rust_json = write_measurement(&context, sample, "rust", &rust_measurement)?;
        let xray_json = write_measurement(&context, sample, "xray", &xray_measurement)?;
        samples.push(Json::object([
            ("opensslReference", reference_json),
            ("rustReality", rust_json),
            (
                "sample",
                Json::Int(i64::try_from(sample).unwrap_or(i64::MAX)),
            ),
            ("status", Json::string("VALID")),
            (
                "comparisons",
                Json::object([
                    (
                        "rustRealityVsOpenSslReference",
                        comparison_json(&reference_measurement, &rust_measurement),
                    ),
                    (
                        "xrayVsOpenSslReference",
                        comparison_json(&reference_measurement, &xray_measurement),
                    ),
                ]),
            ),
            ("xray", xray_json),
        ]));
    }
    let reader_gate = run_production_reader_gate(suite, &rust)?;
    no_ccs::assert_unchanged(&rust)?;
    no_ccs::assert_unchanged(&xray)?;
    let summary = Json::object([
        (
            "clientHelloSha256",
            Json::string(hash::sha256_hex(&client_hello)),
        ),
        (
            "identity",
            Json::object([
                ("reference", reference_identity_json(&reference)),
                ("referenceOptions", reference_options_json(&suite.reference)),
                ("rustReality", binary_json(&rust)),
                (
                    "strace",
                    strace
                        .as_ref()
                        .map_or(Json::Null, |path| Json::string(path.display().to_string())),
                ),
                ("tcpdump", packet_capture.to_json()),
                ("xray", binary_json(&xray)),
            ]),
        ),
        ("invalidSampleCount", Json::Int(0)),
        ("performanceVerdict", Json::string("NOT_EVALUATED")),
        ("recordDelayCandidateE2e", record_delay_e2e),
        ("recordDelayProductionReaderTest", reader_gate),
        (
            "sampleCount",
            Json::Int(i64::try_from(suite.samples).unwrap_or(i64::MAX)),
        ),
        ("samples", Json::Array(samples)),
        ("schemaVersion", Json::Int(1)),
        ("status", Json::string("COMPLETE")),
    ]);
    let summary_text = summary.to_python_json();
    let summary_path = run.write_new("summary.json", &summary_text)?;
    let contract = Json::object([
        ("collector", Json::string("cargo-dev-bench-tls-shape")),
        ("phase", Json::string("complete")),
        ("runId", Json::string(suite.run_id.clone())),
        ("schemaVersion", Json::Int(1)),
        (
            "summary",
            Json::object([
                ("path", Json::string(summary_path.display().to_string())),
                ("sha256", Json::string(hash::sha256_file(&summary_path)?)),
            ]),
        ),
    ])
    .to_python_json();
    run.publish(
        Publication::Contract,
        &contract,
        &suite.run_id,
        "benchmark-tls-shape",
    )?;
    Ok(summary)
}

fn reference_identity_json(reference: &ReferenceBinary) -> Json {
    Json::object([
        (
            "compilerIdentity",
            Json::string(reference.compiler_identity.clone()),
        ),
        (
            "compilerPath",
            Json::string(reference.compiler_path.display().to_string()),
        ),
        (
            "compilerSha256",
            Json::string(reference.compiler_sha256.clone()),
        ),
        ("executableSha256", Json::string(reference.sha256.clone())),
        (
            "opensslCliIdentity",
            Json::string(reference.openssl_cli.identity.clone()),
        ),
        (
            "opensslCliPath",
            Json::string(reference.openssl_cli.path.display().to_string()),
        ),
        (
            "opensslCliSha256",
            Json::string(reference.openssl_cli.sha256.clone()),
        ),
        (
            "selfIdentity",
            Json::string(reference.self_identity.clone()),
        ),
        (
            "sourceSha256",
            Json::string(reference.source_sha256.clone()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED: &str = r#"{"assets":{"cacheDirectory":"/w"},"inbounds":[{"settings":{"clients":[{"id":"u","shortIds":["s"]}]},"streamSettings":{"realitySettings":{"privateKey":"p","target":"old:443","coverOptimization":{"enabled":true,"warmTcp":true,"prebuiltProfiles":true}}}}]}"#;

    fn identity() -> RustIdentity {
        RustIdentity {
            public_key: "public".to_owned(),
            uuid: "uuid".to_owned(),
            short_id: "short".to_owned(),
            private_key: "private".to_owned(),
            server_json: GENERATED.to_owned(),
        }
    }

    #[test]
    fn serial_reference_config_changes_only_target_and_pool_timing() {
        let rendered = serial_rust_config(&identity(), "127.0.0.1:9443").unwrap();
        assert!(rendered.contains(r#""target":"127.0.0.1:9443""#));
        assert!(rendered.contains(r#""warmTcp":false"#));
        assert!(rendered.contains(r#""enabled":true"#));
        assert!(rendered.contains(r#""prebuiltProfiles":true"#));
    }

    #[test]
    fn reference_argv_preserves_every_dynamic_control() {
        let options = ReferenceOptions {
            ciphersuites: "A:B".to_owned(),
            groups: "G:H".to_owned(),
            alpn: "h2".to_owned(),
            middlebox: false,
            max_fragment: 1024,
            split_fragment: 512,
            padding: 37,
            tcp_nodelay: true,
        };
        let certificate = no_ccs::CoverCertificate {
            ca_certificate: PathBuf::from("/w/ca"),
            certificate: PathBuf::from("/w/cert"),
            key: PathBuf::from("/w/key"),
            subject_alt_name: String::new(),
        };
        assert_eq!(
            reference_args(&options, 8443, &certificate),
            [
                "8443", "/w/cert", "/w/key", "A:B", "G:H", "h2", "0", "1024", "512", "37", "1"
            ]
        );
    }

    #[test]
    fn reference_identity_rejects_policy_drift() {
        let good = r#"{"schemaVersion":1,"compiler":"cc","opensslCompileVersion":"OpenSSL 3.5.6 7 Apr 2026","opensslRuntimeVersion":"OpenSSL 3.5.6 7 Apr 2026","configPolicy":"OPENSSL_INIT_NO_LOAD_CONFIG","providerPolicy":["default"]}"#;
        validate_reference_identity(good).unwrap();
        assert!(
            validate_reference_identity(&good.replace("NO_LOAD_CONFIG", "LOAD_CONFIG")).is_err()
        );
        assert!(validate_reference_identity(&good.replace("default", "legacy")).is_err());
    }

    #[test]
    fn openssl_cli_library_annotation_must_repeat_the_exact_runtime() {
        let reference = r#"{"opensslRuntimeVersion":"OpenSSL 3.5.6 7 Apr 2026"}"#;
        require_matching_openssl(
            reference,
            "OpenSSL 3.5.6 7 Apr 2026 (Library: OpenSSL 3.5.6 7 Apr 2026)\n",
        )
        .unwrap();
        assert!(
            require_matching_openssl(
                reference,
                "OpenSSL 3.5.6 7 Apr 2026 (Library: OpenSSL 3.5.5 10 Mar 2026)\n",
            )
            .is_err()
        );
    }
}
