//! The VLESS-encryption A/B.
//!
//! Unlike the rest of the family this compares Xray against *itself*: the same
//! build, the same REALITY transport, the same Vision flow, the same client and
//! the same origins, differing only in whether the inner VLESS layer is
//! `encryption: none` or VLESS Encryption. That is what makes the ratio
//! attributable to the encryption layer rather than to anything else.
//!
//! ## Two things that would otherwise bias the result
//!
//! Both paths are warmed before measurement, and for VLESS Encryption the warm-up
//! is what obtains the reusable ticket — so the measured setup path is its
//! intended 0-RTT mode rather than a first-contact handshake it would never do
//! twice in production. The report says so in its limitations, because it does
//! favour the encrypted side.
//!
//! And the measurement order is shuffled rather than run mode-by-mode, so a
//! machine that warms up or thermally throttles over the run cannot systematically
//! favour whichever mode went first. The shuffle is seeded and recorded, so the
//! order is reproducible evidence rather than an unrepeatable accident.

use crate::{
    perf::{bootstrap::PythonRandom, json_out::Json, stats},
    process::Tool,
};

/// The two modes under comparison.
pub const MODES: [&str; 2] = ["none", "vless-encryption"];

/// The shuffle seed the harness records, `"VLES"` as big-endian ASCII.
pub const ORDER_SEED: u64 = 0x0000_564C_4553;

/// The key material an Xray VLESS-Encryption pair needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKeys {
    /// The server's `decryption` string.
    pub decryption: String,
    /// The client's `encryption` string.
    pub encryption: String,
}

/// Extracts the `decryption`/`encryption` pair from `xray vlessenc` output.
///
/// The tool prints JSON-ish lines; the harness took the first of each with `sed`,
/// and this keeps that, because a later line describes a different profile.
///
/// # Errors
///
/// Returns a message when either field is absent.
pub fn parse_vlessenc(output: &str) -> Result<EncryptionKeys, String> {
    let first = |field: &str| -> Option<String> {
        let prefix = format!("\"{field}\": \"");
        output.lines().find_map(|line| {
            let rest = line.trim().strip_prefix(prefix.as_str())?;
            rest.strip_suffix('"').map(str::to_owned)
        })
    };
    let (Some(decryption), Some(encryption)) = (first("decryption"), first("encryption")) else {
        return Err("xray vlessenc output was not understood".to_owned());
    };
    Ok(EncryptionKeys {
        decryption,
        encryption,
    })
}

/// Runs `xray vlessenc` and parses its key pair.
///
/// # Errors
///
/// Returns a message when the tool fails or its output is not understood.
pub fn generate_encryption_keys(xray_bin: &std::path::Path) -> Result<EncryptionKeys, String> {
    let outcome = Tool::new(xray_bin.display().to_string())
        .arg("vlessenc")
        .probe()
        .map_err(|error| format!("xray vlessenc failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "xray vlessenc exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    parse_vlessenc(outcome.trimmed_stdout())
}

/// The measurement order: `samples` of each mode, shuffled and recorded.
#[must_use]
pub fn measurement_order(samples: usize) -> Vec<String> {
    let mut order: Vec<String> = (0..samples)
        .flat_map(|_| MODES.into_iter().map(str::to_owned))
        .collect();
    PythonRandom::seeded(ORDER_SEED).shuffle(&mut order);
    order
}

/// A process's accumulated CPU seconds, from `utime + stime` in `/proc`.
///
/// # Errors
///
/// Returns a message when the process is gone or its stat line is unreadable.
pub fn cpu_seconds(pid: u32) -> Result<f64, String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("could not read the CPU time of PID {pid}: {error}"))?;
    // The command name can contain spaces and parentheses, so fields are counted
    // from after the final ')'.
    let rest = raw
        .rfind(')')
        .and_then(|index| raw.get(index + 2..))
        .ok_or_else(|| format!("PID {pid} has a malformed stat line"))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let (Some(utime), Some(stime)) = (fields.get(11), fields.get(12)) else {
        return Err(format!("PID {pid} has a short stat line"));
    };
    let (Ok(utime), Ok(stime)) = (utime.parse::<f64>(), stime.parse::<f64>()) else {
        return Err(format!("PID {pid} has non-numeric CPU times"));
    };
    // USER_HZ is 100 on every Linux architecture Go and Rust support here.
    Ok((utime + stime) / 100.0)
}

/// One measured throughput or setup sample.
#[derive(Debug, Clone)]
pub struct ModeSample {
    /// Which mode produced it.
    pub mode: String,
    /// The measured values, by field name.
    pub values: Vec<(String, f64)>,
}

impl ModeSample {
    /// The value of one field, if present.
    #[must_use]
    pub fn value(&self, field: &str) -> Option<f64> {
        self.values
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| *value)
    }
}

/// Summarises one field across a mode's samples.
///
/// # Errors
///
/// Returns a message when the mode has no samples for the field.
pub fn summarise_field(samples: &[ModeSample], mode: &str, field: &str) -> Result<Json, String> {
    let values: Vec<f64> = samples
        .iter()
        .filter(|sample| sample.mode == mode)
        .filter_map(|sample| sample.value(field))
        .collect();
    if values.is_empty() {
        return Err(format!("{mode} has no {field} samples"));
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "sample counts here are small integers"
    )]
    let mean = stats::fsum(&values) / values.len() as f64;
    let median = stats::median(&values).map_err(|error| error.to_string())?;
    let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
    let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    Ok(Json::object([
        ("mean", Json::Float(mean)),
        ("p50", Json::Float(median)),
        ("minimum", Json::Float(minimum)),
        ("maximum", Json::Float(maximum)),
    ]))
}

/// Reads one summarised statistic back out of a rendered summary.
fn statistic(summary: &Json, mode: &str, field: &str, key: &str) -> Option<f64> {
    let Json::Object(modes) = summary else {
        return None;
    };
    let Json::Object(fields) = modes.get(mode)? else {
        return None;
    };
    let Json::Object(stats) = fields.get(field)? else {
        return None;
    };
    match stats.get(key)? {
        Json::Float(value) => Some(*value),
        _ => None,
    }
}

/// The three ratios the report records.
///
/// # Errors
///
/// Returns a message when a statistic is missing or its denominator is zero.
pub fn ratios_json(summary: &Json) -> Result<Json, String> {
    let ratio = |field: &str, key: &str| -> Result<f64, String> {
        let base = statistic(summary, "none", field, key)
            .ok_or_else(|| format!("none has no {field}.{key}"))?;
        let encrypted = statistic(summary, "vless-encryption", field, key)
            .ok_or_else(|| format!("vless-encryption has no {field}.{key}"))?;
        if base == 0.0 {
            return Err(format!("{field}.{key} for none is zero"));
        }
        Ok(encrypted / base)
    };
    Ok(Json::object([
        (
            "encryptedToNoneP50Throughput",
            Json::Float(ratio("throughputMiBPerSecond", "p50")?),
        ),
        (
            "encryptedToNoneMeanServerCpuPerGiB",
            Json::Float(ratio("serverCpuSecondsPerGiB", "mean")?),
        ),
        (
            "encryptedToNoneP50ConnectionsPerSecond",
            Json::Float(ratio("connectionsPerSecond", "p50")?),
        ),
    ]))
}

/// The limitations the report states about itself.
#[must_use]
pub fn limitations_json() -> Json {
    Json::Array(
        [
            "single-host loopback; results are host-specific, not universal",
            "both modes use the same Xray build, REALITY, Vision, client, and origins",
            "VLESS Encryption is measured after ticket warm-up, favoring its 0-RTT setup path",
            "server CPU excludes client-side encryption and the origin",
        ]
        .into_iter()
        .map(Json::string)
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_pair_is_taken_from_the_first_matching_lines() {
        let output = "\"decryption\": \"mlkem768x25519plus.native.0rtt.SEED\"\n\
                      \"encryption\": \"mlkem768x25519plus.native.0rtt.PUB\"\n\
                      \"decryption\": \"a-later-profile\"\n";
        let keys = parse_vlessenc(output).unwrap();
        assert_eq!(keys.decryption, "mlkem768x25519plus.native.0rtt.SEED");
        assert_eq!(keys.encryption, "mlkem768x25519plus.native.0rtt.PUB");
        assert!(parse_vlessenc("nothing useful").is_err());
        assert!(parse_vlessenc("\"decryption\": \"only-one\"").is_err());
    }

    /// The order is shuffled so a machine that warms up over the run cannot
    /// favour whichever mode went first, and seeded so it stays reproducible.
    #[test]
    fn the_measurement_order_is_shuffled_balanced_and_reproducible() {
        let order = measurement_order(5);
        assert_eq!(order.len(), 10);
        for mode in MODES {
            assert_eq!(order.iter().filter(|entry| *entry == mode).count(), 5);
        }
        assert_ne!(
            order,
            (0..5)
                .flat_map(|_| MODES.into_iter().map(str::to_owned))
                .collect::<Vec<String>>(),
            "an unshuffled order would run mode by mode"
        );
        assert_eq!(
            order,
            measurement_order(5),
            "the seed makes it reproducible"
        );
        assert_eq!(order[0], "vless-encryption");
    }

    #[test]
    fn cpu_time_is_read_for_a_live_process() {
        let seconds = cpu_seconds(std::process::id()).unwrap();
        assert!(seconds >= 0.0);
        assert!(cpu_seconds(u32::MAX).is_err());
    }

    fn sample(mode: &str, throughput: f64, cpu: f64, rate: f64) -> ModeSample {
        ModeSample {
            mode: mode.to_owned(),
            values: vec![
                ("throughputMiBPerSecond".to_owned(), throughput),
                ("serverCpuSecondsPerGiB".to_owned(), cpu),
                ("connectionsPerSecond".to_owned(), rate),
            ],
        }
    }

    #[test]
    fn a_field_summary_reports_mean_median_and_bounds() {
        let samples = vec![
            sample("none", 100.0, 1.0, 50.0),
            sample("none", 200.0, 3.0, 70.0),
            sample("vless-encryption", 80.0, 2.0, 40.0),
        ];
        let rendered = summarise_field(&samples, "none", "throughputMiBPerSecond")
            .unwrap()
            .to_python_json();
        assert!(rendered.contains("\"mean\": 150.0"));
        assert!(rendered.contains("\"p50\": 150.0"));
        assert!(rendered.contains("\"minimum\": 100.0"));
        assert!(rendered.contains("\"maximum\": 200.0"));
        assert!(summarise_field(&samples, "none", "absent").is_err());
        assert!(summarise_field(&samples, "missing-mode", "throughputMiBPerSecond").is_err());
    }

    #[test]
    fn the_ratios_compare_the_encrypted_mode_against_none() {
        let samples = vec![
            sample("none", 100.0, 1.0, 50.0),
            sample("vless-encryption", 80.0, 2.0, 40.0),
        ];
        let mut summary: Vec<(String, Json)> = Vec::new();
        for mode in MODES {
            let mut fields: Vec<(String, Json)> = Vec::new();
            for field in [
                "throughputMiBPerSecond",
                "serverCpuSecondsPerGiB",
                "connectionsPerSecond",
            ] {
                fields.push((
                    field.to_owned(),
                    summarise_field(&samples, mode, field).unwrap(),
                ));
            }
            summary.push((mode.to_owned(), Json::object(fields)));
        }
        let rendered = ratios_json(&Json::object(summary))
            .unwrap()
            .to_python_json();
        assert!(rendered.contains("\"encryptedToNoneP50Throughput\": 0.8"));
        assert!(rendered.contains("\"encryptedToNoneMeanServerCpuPerGiB\": 2.0"));
        assert!(rendered.contains("\"encryptedToNoneP50ConnectionsPerSecond\": 0.8"));
    }

    /// The warm-up favours the encrypted side, and the report has to say so.
    #[test]
    fn the_limitations_disclose_the_warm_up_bias() {
        let rendered = limitations_json().to_python_json();
        assert!(rendered.contains("favoring its 0-RTT setup path"));
        assert!(rendered.contains("server CPU excludes client-side encryption"));
    }
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Everything a VLESS-encryption run needs.
#[derive(Debug, Clone)]
pub struct VlessSuite {
    /// Repository root, for the Go origin.
    pub repo: std::path::PathBuf,
    /// The Xray binary; both modes are the same build.
    pub xray_bin: std::path::PathBuf,
    /// Output directory; must not already exist.
    pub out_dir: std::path::PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// Samples per mode.
    pub samples: usize,
    /// Concurrent transfers per throughput sample.
    pub concurrency: usize,
    /// Payload size in MiB per transfer.
    pub payload_mib: u64,
    /// Fresh connections per setup sample.
    pub setup_connections: usize,
    /// Concurrency for the setup sample.
    pub setup_concurrency: usize,
    /// The REALITY cover target.
    pub cover_target: String,
    /// The REALITY cover SNI.
    pub cover_sni: String,
}

/// Validates the VLESS parameters.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(suite: &VlessSuite) -> Result<(), String> {
    for (name, value) in [
        ("SAMPLES", suite.samples),
        ("CONCURRENCY", suite.concurrency),
        ("SETUP_CONNECTIONS", suite.setup_connections),
        ("SETUP_CONCURRENCY", suite.setup_concurrency),
    ] {
        if value == 0 {
            return Err(format!("{name} must be a positive integer"));
        }
    }
    if suite.payload_mib == 0 {
        return Err("PAYLOAD_MIB must be a positive integer".to_owned());
    }
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    Ok(())
}

/// Builds one mode's server config.
fn server_config(
    identity: &crate::bench::config::RealityIdentity,
    listen_port: u16,
    private_key: &str,
    decryption: &str,
) -> Json {
    Json::object([
        ("log", Json::object([("loglevel", Json::string("warning"))])),
        (
            "inbounds",
            Json::Array(vec![Json::object([
                ("listen", Json::string("127.0.0.1")),
                ("port", Json::Int(i64::from(listen_port))),
                ("protocol", Json::string("vless")),
                (
                    "settings",
                    Json::object([
                        (
                            "clients",
                            Json::Array(vec![Json::object([
                                ("id", Json::string(identity.uuid.clone())),
                                ("flow", Json::string("xtls-rprx-vision")),
                            ])]),
                        ),
                        ("decryption", Json::string(decryption)),
                    ]),
                ),
                (
                    "streamSettings",
                    Json::object([
                        ("network", Json::string("tcp")),
                        ("security", Json::string("reality")),
                        (
                            "realitySettings",
                            Json::object([
                                ("show", Json::Bool(false)),
                                ("target", Json::string(identity.target.clone())),
                                ("xver", Json::Int(0)),
                                (
                                    "serverNames",
                                    Json::Array(vec![Json::string(identity.server_name.clone())]),
                                ),
                                ("privateKey", Json::string(private_key.to_owned())),
                                (
                                    "shortIds",
                                    Json::Array(vec![Json::string(identity.short_id.clone())]),
                                ),
                            ]),
                        ),
                    ]),
                ),
            ])]),
        ),
        (
            "outbounds",
            Json::Array(vec![Json::object([
                ("tag", Json::string("direct")),
                ("protocol", Json::string("freedom")),
                (
                    "settings",
                    Json::object([(
                        "finalRules",
                        Json::Array(vec![Json::object([("action", Json::string("allow"))])]),
                    )]),
                ),
            ])]),
        ),
    ])
}

/// Builds one mode's client config, pinned to its `encryption` string.
fn client_config(
    identity: &crate::bench::config::RealityIdentity,
    server_port: u16,
    socks_port: u16,
    public_key: &str,
    encryption: &str,
) -> Json {
    Json::object([
        ("log", Json::object([("loglevel", Json::string("warning"))])),
        (
            "inbounds",
            Json::Array(vec![Json::object([
                ("listen", Json::string("127.0.0.1")),
                ("port", Json::Int(i64::from(socks_port))),
                ("protocol", Json::string("socks")),
                (
                    "settings",
                    Json::object([("auth", Json::string("noauth")), ("udp", Json::Bool(false))]),
                ),
            ])]),
        ),
        (
            "outbounds",
            Json::Array(vec![Json::object([
                ("protocol", Json::string("vless")),
                (
                    "settings",
                    Json::object([(
                        "vnext",
                        Json::Array(vec![Json::object([
                            ("address", Json::string("127.0.0.1")),
                            ("port", Json::Int(i64::from(server_port))),
                            (
                                "users",
                                Json::Array(vec![Json::object([
                                    ("id", Json::string(identity.uuid.clone())),
                                    ("encryption", Json::string(encryption)),
                                    ("flow", Json::string("xtls-rprx-vision")),
                                ])]),
                            ),
                        ])]),
                    )]),
                ),
                (
                    "streamSettings",
                    Json::object([
                        ("network", Json::string("tcp")),
                        ("security", Json::string("reality")),
                        (
                            "realitySettings",
                            Json::object([
                                ("fingerprint", Json::string("chrome")),
                                ("serverName", Json::string(identity.server_name.clone())),
                                ("publicKey", Json::string(public_key)),
                                ("shortId", Json::string(identity.short_id.clone())),
                                ("spiderX", Json::string("/")),
                            ]),
                        ),
                    ]),
                ),
            ])]),
        ),
    ])
}

/// One mode's running server and client, plus what the sampler needs.
struct ModeLeg {
    mode: &'static str,
    socks_port: u16,
    server_pid: u32,
    _server: crate::bench::process::Child,
    _client: crate::bench::process::Child,
}

/// Measures one throughput sample: `concurrency` transfers and the server CPU.
fn throughput_sample(
    leg: &ModeLeg,
    origin_port: u16,
    payload_mib: u64,
    concurrency: usize,
) -> Result<ModeSample, String> {
    let before = cpu_seconds(leg.server_pid)?;
    let started = std::time::Instant::now();
    let outcome = crate::bench::matrix::run_workload(
        crate::bench::matrix::Scenario::DirectDownload,
        crate::bench::matrix::Endpoints {
            socks: leg.socks_port,
            fallback: 0,
            http: origin_port,
            https: origin_port,
        },
        payload_mib,
        concurrency,
        std::path::Path::new("."),
    )?;
    let wall = started.elapsed().as_secs_f64();
    let cpu = cpu_seconds(leg.server_pid)? - before;
    if wall <= 0.0 {
        return Err("non-positive throughput wall time".to_owned());
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "request counts and payload sizes here are far below 2^53"
    )]
    let moved_mib = (payload_mib as f64) * (outcome.requests as f64);
    Ok(ModeSample {
        mode: leg.mode.to_owned(),
        values: vec![
            ("throughputMiBPerSecond".to_owned(), moved_mib / wall),
            (
                "serverCpuSecondsPerGiB".to_owned(),
                cpu / (moved_mib / 1024.0),
            ),
        ],
    })
}

/// Measures one setup sample: fresh connections and the server CPU they cost.
fn setup_sample(
    leg: &ModeLeg,
    origin_port: u16,
    connections: usize,
    concurrency: usize,
) -> Result<ModeSample, String> {
    let before = cpu_seconds(leg.server_pid)?;
    // No resolver is involved: this phase measures connection setup, and the
    // destination is loopback by address so nothing is ever looked up.
    let mut latencies = Vec::with_capacity(connections);
    let started = std::time::Instant::now();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut failed = 0_usize;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..concurrency.clamp(1, connections.max(1)))
            .map(|_| {
                let next = &next;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    let mut failures = 0_usize;
                    while next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < connections {
                        match crate::bench::workload::one_connection(leg.socks_port, origin_port) {
                            Some(elapsed) => mine.push(elapsed.as_secs_f64()),
                            None => failures += 1,
                        }
                    }
                    (mine, failures)
                })
            })
            .collect();
        for handle in handles {
            if let Ok((mine, failures)) = handle.join() {
                latencies.extend(mine);
                failed += failures;
            } else {
                failed += 1;
            }
        }
    });
    let wall = started.elapsed().as_secs_f64();
    let cpu = cpu_seconds(leg.server_pid)? - before;
    if failed > 0 || latencies.is_empty() || wall <= 0.0 {
        return Err(format!(
            "setup sample failed: {failed} of {connections} connections did not complete"
        ));
    }
    latencies.sort_unstable_by(f64::total_cmp);
    #[expect(
        clippy::cast_precision_loss,
        reason = "connection counts here are small integers"
    )]
    let count = latencies.len() as f64;
    let percentile =
        |fraction: f64| stats::nearest_rank(&latencies, fraction).unwrap_or(0.0) * 1000.0;
    Ok(ModeSample {
        mode: leg.mode.to_owned(),
        values: vec![
            ("connectionsPerSecond".to_owned(), count / wall),
            ("p50Milliseconds".to_owned(), percentile(0.50)),
            ("p95Milliseconds".to_owned(), percentile(0.95)),
            (
                "serverCpuMicrosecondsPerConnection".to_owned(),
                cpu * 1_000_000.0 / count,
            ),
        ],
    })
}

/// Writes both payloads and starts the TLS origin.
///
/// The setup phase fetches a tiny body so its cost is connection establishment
/// rather than transfer; the throughput phase fetches the large one.
fn start_origins(
    suite: &VlessSuite,
    workspace: &crate::bench::workspace::Workspace,
    plain_port: u16,
    tls_port: u16,
) -> Result<(crate::bench::process::Child, crate::bench::process::Child), String> {
    use crate::bench::{origin_go, origin_tls};
    origin_go::write_pattern_payload(workspace.path(), suite.payload_mib)?;
    std::fs::write(workspace.join("payload.bin"), vec![b'x'; 256])
        .map_err(|error| format!("could not write the setup payload: {error}"))?;
    let binary = origin_go::executable()?;
    let (cert, key) = origin_tls::generate_self_signed(workspace.path())?;
    let plain = origin_go::start(
        &binary,
        workspace,
        &origin_go::OriginPlan {
            label: "origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: plain_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;
    let secure = origin_go::start(
        &binary,
        workspace,
        &origin_go::OriginPlan {
            label: "origin-https".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: tls_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("https-put.jsonl"),
            tls: Some((cert, key)),
            access_log: None,
            alpn: None,
        },
    )?;
    Ok((plain, secure))
}

/// Starts one mode's server and client, sharing the run's identity and keypair.
///
/// Only the encryption layer may differ between the modes, so everything else --
/// UUID, short id, REALITY keypair, cover target -- is the same object.
#[expect(
    clippy::too_many_arguments,
    reason = "a mode's inputs are exactly these"
)]
fn start_mode(
    suite: &VlessSuite,
    workspace: &crate::bench::workspace::Workspace,
    identity: &crate::bench::config::RealityIdentity,
    keys: &crate::bench::suites::XrayKeys,
    encryption: &EncryptionKeys,
    mode: &'static str,
    server_port: u16,
    socks_port: u16,
) -> Result<ModeLeg, String> {
    use crate::bench::process::Child;
    let (decryption, client_encryption) = if mode == "none" {
        ("none".to_owned(), "none".to_owned())
    } else {
        (encryption.decryption.clone(), encryption.encryption.clone())
    };
    let server_path = workspace.join(&format!("server-{mode}.json"));
    std::fs::write(
        &server_path,
        server_config(identity, server_port, &keys.private, &decryption).to_python_json(),
    )
    .map_err(|error| format!("could not write {}: {error}", server_path.display()))?;
    let client_path = workspace.join(&format!("client-{mode}.json"));
    std::fs::write(
        &client_path,
        client_config(
            identity,
            server_port,
            socks_port,
            &keys.public,
            &client_encryption,
        )
        .to_python_json(),
    )
    .map_err(|error| format!("could not write {}: {error}", client_path.display()))?;

    let mut server = Child::spawn(
        format!("server-{mode}"),
        &suite.xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            server_path.display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join(&format!("server-{mode}.log")),
    )
    .map_err(|error| error.to_string())?;
    let server_pid = server.pid();
    let mut client = Child::spawn(
        format!("client-{mode}"),
        &suite.xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_path.display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join(&format!("client-{mode}.log")),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, std::time::Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, std::time::Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    Ok(ModeLeg {
        mode,
        socks_port,
        server_pid,
        _server: server,
        _client: client,
    })
}

/// Runs every sample in the shuffled order, throughput first then setup.
///
/// The order is shuffled rather than grouped by mode so a machine that drifts
/// over the run cannot systematically favour whichever mode went first.
fn measure_in_order(
    suite: &VlessSuite,
    legs: &[ModeLeg],
    plain_port: u16,
    tls_port: u16,
    order: &[String],
) -> Result<(Vec<ModeSample>, Vec<ModeSample>), String> {
    let leg_for = |mode: &str| {
        legs.iter()
            .find(|leg| leg.mode == mode)
            .ok_or_else(|| format!("{mode} has no leg"))
    };
    let mut throughput = Vec::with_capacity(order.len());
    for mode in order {
        throughput.push(throughput_sample(
            leg_for(mode)?,
            tls_port,
            suite.payload_mib,
            suite.concurrency,
        )?);
    }
    let mut setup = Vec::with_capacity(order.len());
    for mode in order {
        setup.push(setup_sample(
            leg_for(mode)?,
            plain_port,
            suite.setup_connections,
            suite.setup_concurrency,
        )?);
    }
    Ok((throughput, setup))
}

/// Summarises every field for both modes.
fn summarise_modes(throughput: &[ModeSample], setup: &[ModeSample]) -> Result<Json, String> {
    let mut summary: Vec<(String, Json)> = Vec::with_capacity(MODES.len());
    for mode in MODES {
        summary.push((
            mode.to_owned(),
            Json::object([
                (
                    "throughputMiBPerSecond",
                    summarise_field(throughput, mode, "throughputMiBPerSecond")?,
                ),
                (
                    "serverCpuSecondsPerGiB",
                    summarise_field(throughput, mode, "serverCpuSecondsPerGiB")?,
                ),
                (
                    "connectionsPerSecond",
                    summarise_field(setup, mode, "connectionsPerSecond")?,
                ),
                (
                    "setupP50Milliseconds",
                    summarise_field(setup, mode, "p50Milliseconds")?,
                ),
                (
                    "serverCpuMicrosecondsPerConnection",
                    summarise_field(setup, mode, "serverCpuMicrosecondsPerConnection")?,
                ),
            ]),
        ));
    }
    Ok(Json::object(summary))
}

/// The method block the report records.
fn method_json(suite: &VlessSuite, order: &[String]) -> Json {
    let count = |value: usize| Json::Int(i64::try_from(value).unwrap_or(i64::MAX));
    Json::object([
        ("outerTransport", Json::string("REALITY")),
        ("flow", Json::string("xtls-rprx-vision")),
        (
            "encryptedMode",
            Json::string("mlkem768x25519plus.native.0rtt after warm-up"),
        ),
        ("samplesPerMode", count(suite.samples)),
        ("concurrency", count(suite.concurrency)),
        (
            "payloadMiBPerRequest",
            Json::Int(i64::try_from(suite.payload_mib).unwrap_or(i64::MAX)),
        ),
        ("setupConnectionsPerSample", count(suite.setup_connections)),
        ("setupConcurrency", count(suite.setup_concurrency)),
        (
            "randomizedOrder",
            Json::Array(order.iter().cloned().map(Json::string).collect()),
        ),
    ])
}

/// Runs the VLESS-encryption A/B end to end.
///
/// # Errors
///
/// Returns the first failure; every resource is RAII-owned.
pub fn run(suite: &VlessSuite) -> Result<crate::bench::paired::SuiteOutcome, String> {
    use crate::bench::{
        config::RealityIdentity,
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        suites,
        workspace::Workspace,
    };

    validate(suite)?;
    for program in ["curl"] {
        if !Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("benchmark-vless-encryption")?;

    // A plain and a TLS origin, plus a server/SOCKS pair per mode. The
    // throughput phase needs TLS so Vision reaches Direct; the setup phase
    // speaks plain HTTP, because its cost must be connection establishment
    // rather than a second TLS handshake inside the tunnel.
    let port_base = crate::bench::workspace::reserve_block(6)?;
    let (plain_port, tls_port) = (port_base, port_base + 1);
    let _origins = start_origins(suite, &workspace, plain_port, tls_port)?;

    // One identity and one REALITY keypair, shared by both modes: only the
    // encryption layer may differ.
    let keys = suites::generate_xray_keys(&suite.xray_bin)?;
    let encryption = generate_encryption_keys(&suite.xray_bin)?;
    let identity = RealityIdentity {
        uuid: crate::bench::ab_suites::random_uuid_v4()?,
        short_id: crate::bench::ab_suites::random_short_id()?,
        server_name: suite.cover_sni.clone(),
        target: suite.cover_target.clone(),
    };

    let mut legs = Vec::with_capacity(2);
    for (index, mode) in MODES.into_iter().enumerate() {
        let offset = u16::try_from(index * 2).map_err(|_| "too many modes".to_owned())?;
        legs.push(start_mode(
            suite,
            &workspace,
            &identity,
            &keys,
            &encryption,
            mode,
            port_base + 2 + offset,
            port_base + 3 + offset,
        )?);
    }

    // Warm both paths. For VLESS Encryption this also obtains the reusable
    // ticket, so the measured setup path is its intended 0-RTT mode.
    for leg in &legs {
        throughput_sample(leg, tls_port, suite.payload_mib, 1)?;
        setup_sample(leg, plain_port, 1, 1)?;
    }

    let order = measurement_order(suite.samples);
    let (throughput, setup) = measure_in_order(suite, &legs, plain_port, tls_port, &order)?;

    let summary = summarise_modes(&throughput, &setup)?;
    let ratios = ratios_json(&summary)?;

    let report = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("harness", Json::string("benchmark-vless-encryption")),
        ("status", Json::string("COMPLETE")),
        ("performanceVerdict", Json::string("NOT_EVALUATED")),
        (
            "environment",
            Json::object([("xrayVersion", Json::string(xray.identity.clone()))]),
        ),
        ("method", method_json(suite, &order)),
        ("summary", summary),
        ("ratios", ratios),
        ("limitations", limitations_json()),
    ]);
    let summary_json = report.to_python_json();
    run.write_new("summary.json", &summary_json)?;
    run.publish(
        Publication::Environment,
        &summary_json,
        &suite.run_id,
        "benchmark-vless-encryption",
    )?;
    Ok(crate::bench::paired::SuiteOutcome {
        out_dir: suite.out_dir.clone(),
        summary_json,
        slot_count: order.len(),
    })
}
