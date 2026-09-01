//! `rr-dev` — the repository's development control plane.
//!
//! One typed entry point for repository policy that used to live scattered across
//! shell and Python programs. `rr-dev` orchestrates external tools; it does not
//! reimplement them, and it does not build shell command lines.
//!
//! Normal use is through the root cargo alias, so no one has to know where this
//! crate lives:
//!
//! ```text
//! cargo dev doctor
//! cargo dev check
//! cargo dev check --all
//! cargo dev repo check
//! ```

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand, ValueEnum};

mod bench;
mod check;
mod checks;
mod deploy;
mod docs;
mod doctor;
mod fuzz;
mod hash;
mod perf;
mod process;
mod release;
mod repo;

/// Development control plane for the rust-reality repository.
#[derive(Parser)]
#[command(name = "rr-dev", version, about, long_about = None)]
struct Cli {
    /// Repository root. Defaults to the checkout containing this crate.
    #[arg(long, global = true)]
    repo: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// A clap subcommand enum is a parsed command line, constructed once per process.
// Its variants are inherently uneven in size and boxing them would only obscure
// the derive.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Diagnose the development and measurement environment without changing it.
    Doctor,
    /// Run the repository quality gate.
    Check {
        /// Run every check CI enforces instead of the fast local subset.
        #[arg(long)]
        all: bool,
        /// Terminal result protocol.
        #[arg(long, value_enum, default_value_t)]
        output: check::OutputMode,
        /// Fresh local log directory; relative paths resolve from the repository root.
        #[arg(long)]
        log_dir: Option<PathBuf>,
    },
    /// Documentation tooling.
    Docs {
        #[command(subcommand)]
        command: DocsCommand,
    },
    /// Repository layout and ownership policy.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Release performance evaluation.
    Perf {
        #[command(subcommand)]
        command: PerfCommand,
    },
    /// Release engineering: tier matrix, build, package, smoke, aggregate.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Fuzzing: validate the target manifest and run deterministic smoke passes.
    Fuzz {
        #[command(subcommand)]
        command: FuzzCommand,
    },
    /// Configuration identity tooling.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Benchmarks: the typed measurement lifecycle and suite catalogue.
    Bench {
        #[command(subcommand)]
        command: BenchCommand,
    },
    /// Deployment engineering.
    Deploy {
        #[command(subcommand)]
        command: DeployCommand,
    },
}

#[derive(Subcommand)]
enum DeployCommand {
    /// Validate and render the active dual-VPS canary without contacting hosts.
    CanaryPlan {
        /// Shared canary identity, traffic and evidence inputs.
        #[command(flatten)]
        plan: CanaryArgs,
        /// New plan JSON path; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run the active dual-VPS canary (reloads LINE and restarts LANDING).
    CanaryRun {
        /// Shared canary identity, traffic and evidence inputs.
        #[command(flatten)]
        plan: CanaryArgs,
        /// Required acknowledgement of remote service mutation.
        #[arg(long)]
        mutate_remote: bool,
        /// Restore PREVIOUS on both hosts after any failure.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        rollback_on_failure: bool,
    },
    /// Inspect one deployment host without mutating it.
    Inspect {
        /// Fixed host role to inspect; address/user/proxy stay in OpenSSH config.
        #[arg(long, value_enum, default_value_t = DeployTarget::Line)]
        target: DeployTarget,
        /// New snapshot JSON path; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Derive a mutation plan from a recorded read-only snapshot.
    Plan {
        /// Transaction to plan.
        #[arg(value_enum)]
        operation: DeployPlanOperation,
        /// Fixed host role the recorded snapshot must describe.
        #[arg(long, value_enum, default_value_t = DeployTarget::Line)]
        target: DeployTarget,
        /// Snapshot JSON produced by `cargo dev deploy inspect`.
        #[arg(long)]
        snapshot: PathBuf,
        /// Release generation id (required except for rollback).
        #[arg(long)]
        release_id: Option<String>,
        /// Existing absolute remote executable to adopt (bootstrap).
        #[arg(long)]
        baseline_binary: Option<String>,
        /// Existing absolute remote config to adopt (bootstrap).
        #[arg(long)]
        baseline_config: Option<String>,
        /// Absolute local candidate binary path (stage/cutover).
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Absolute local candidate config path (stage/cutover).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Expected lowercase candidate SHA-256 (stage/cutover).
        #[arg(long)]
        expected_sha256: Option<String>,
        /// Expected semantic version (stage/cutover).
        #[arg(long)]
        expected_version: Option<String>,
        /// Optional exact lowercase source commit embedded in the candidate.
        #[arg(long)]
        source_commit: Option<String>,
        /// Include old-generation pruning in a promote plan.
        #[arg(long)]
        prune_old_releases: bool,
        /// New plan JSON path; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Execute a freshly inspected transaction against one fixed host.
    Apply {
        /// Transaction to execute.
        #[arg(value_enum)]
        operation: DeployPlanOperation,
        /// Fixed host role; address/user/proxy stay in OpenSSH config.
        #[arg(long, value_enum, default_value_t = DeployTarget::Line)]
        target: DeployTarget,
        /// Release generation id (required except for rollback).
        #[arg(long)]
        release_id: Option<String>,
        /// Existing absolute remote executable to adopt (bootstrap).
        #[arg(long)]
        baseline_binary: Option<String>,
        /// Existing absolute remote config to adopt (bootstrap).
        #[arg(long)]
        baseline_config: Option<String>,
        /// Absolute local candidate binary path (stage/cutover).
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Absolute local candidate config path (stage/cutover).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Expected lowercase candidate SHA-256 (stage/cutover).
        #[arg(long)]
        expected_sha256: Option<String>,
        /// Expected semantic version (stage/cutover).
        #[arg(long)]
        expected_version: Option<String>,
        /// Optional exact lowercase source commit embedded in the candidate.
        #[arg(long)]
        source_commit: Option<String>,
        /// Delete generations other than CURRENT/PREVIOUS after promote.
        #[arg(long)]
        prune_old_releases: bool,
        /// Required acknowledgement that this command mutates the remote host.
        #[arg(long)]
        mutate_remote: bool,
        /// New execution report path; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Evaluate a recorded dual-VPS release-canary report, fail-closed.
    ///
    /// Exit status is three-valued: 0 when the canary passes, 1 for a real
    /// failure, and 2 when the input was inadmissible.
    Canary {
        /// Path to the recorded canary report JSON.
        input: PathBuf,
        /// Optional path to write the verdict to; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate a recorded deployment netem Cartesian product, fail-closed.
    Netem {
        /// Path to profiles.jsonl.
        #[arg(long)]
        profiles: PathBuf,
        /// Path to pool-summaries.json.
        #[arg(long)]
        pool_summaries: PathBuf,
        /// Output report path (must not already exist).
        #[arg(long)]
        output: PathBuf,
        /// Space-separated RTT values in ms.
        #[arg(long)]
        rtts: String,
        /// Space-separated per-direction loss percents.
        #[arg(long)]
        losses: String,
        /// Space-separated concurrencies.
        #[arg(long)]
        concurrencies: String,
        /// Samples per concurrency.
        #[arg(long)]
        samples: i64,
        /// Connections per sample.
        #[arg(long)]
        connections: i64,
        /// Evaluate the controlled RTT mechanism (v1.7 ABBA cells).
        #[arg(long)]
        evaluate_performance: bool,
    },
}

/// Shared inputs for planning and running the active dual-VPS canary.
#[derive(Debug, Clone, Args)]
struct CanaryArgs {
    /// Exact stock Xray binary.
    #[arg(long)]
    xray_bin: PathBuf,
    /// Required lowercase Xray SHA-256.
    #[arg(long)]
    xray_sha256: String,
    /// Xray config containing the loopback SOCKS inbound.
    #[arg(long)]
    xray_config: PathBuf,
    /// Loopback SOCKS port.
    #[arg(long)]
    socks_port: u16,
    /// LINE public IPv4 used for LANDING firewall validation.
    #[arg(long)]
    line_public_ipv4: std::net::Ipv4Addr,
    /// Small URL used for active traffic.
    #[arg(long)]
    small_url: String,
    /// Exact one-MiB download URL.
    #[arg(long)]
    one_mib_url: String,
    /// Exact large download URL.
    #[arg(long)]
    large_url: String,
    /// Upload endpoint.
    #[arg(long)]
    upload_url: String,
    /// Local exact one-MiB reference payload.
    #[arg(long)]
    payload_one_mib: PathBuf,
    /// Local exact large reference payload.
    #[arg(long)]
    payload_large: PathBuf,
    /// New durable evidence directory the live run creates.
    #[arg(long)]
    out_dir: PathBuf,
    /// Full source commit of the candidate on both hosts.
    #[arg(long)]
    candidate_commit: String,
    /// Exact candidate SHA-256.
    #[arg(long)]
    candidate_sha256: String,
    /// Candidate ELF build id.
    #[arg(long)]
    candidate_build_id: String,
    /// Candidate product version.
    #[arg(long)]
    candidate_version: String,
    /// Candidate target triple.
    #[arg(long)]
    candidate_target: String,
    /// Candidate compiler identity.
    #[arg(long)]
    candidate_rustc: String,
    /// Active canary seconds.
    #[arg(long, default_value_t = 600)]
    duration_seconds: u64,
    /// Resource sample interval seconds.
    #[arg(long, default_value_t = 5)]
    sample_interval_seconds: u64,
}

/// One of the two fixed deployment roles.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum DeployTarget {
    /// Public LINE entry host.
    Line,
    /// Downstream LANDING host.
    Landing,
}

impl DeployTarget {
    const fn role(self) -> deploy::host::HostRole {
        match self {
            Self::Line => deploy::host::HostRole::Line,
            Self::Landing => deploy::host::HostRole::Landing,
        }
    }
}

/// A transaction that can be derived without contacting a live host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DeployPlanOperation {
    /// Adopt unmanaged remote files as the first protected generation.
    Bootstrap,
    /// Install a candidate generation without changing CURRENT.
    Stage,
    /// Atomically move CURRENT to an already staged generation.
    Cutover,
    /// Restore CURRENT from PREVIOUS.
    Rollback,
    /// Accept the current generation after a successful canary.
    Promote,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum BenchCommand {
    /// List the benchmark suites and the legacy scripts they supersede.
    List,
    /// Validate the benchmark environment (tools, host lock, workspace, ports).
    Environment,
    /// Drive one slot's connection-setup workload and write its samples.
    ///
    /// A suite runs this as a child process so `perf stat -- <workload>` bounds
    /// the measurement window exactly as `perf stat -- python3 driver.py` did.
    /// It is not normally invoked by hand.
    Workload {
        /// Loopback SOCKS5 port of the client fronting the server under test.
        #[arg(long)]
        socks_port: u16,
        /// Loopback port of the plain-HTTP origin to reach through the proxy.
        #[arg(long)]
        origin_port: u16,
        /// Connections per sample.
        #[arg(long)]
        connections: usize,
        /// Space-separated concurrency levels.
        #[arg(long)]
        concurrencies: String,
        /// Samples per concurrency level; `0` performs warm-up only.
        #[arg(long)]
        samples: usize,
        /// Implementation label recorded on every row.
        #[arg(long)]
        implementation: String,
        /// Block number.
        #[arg(long)]
        block: usize,
        /// Position within the block.
        #[arg(long)]
        position: usize,
        /// Record raw `latenciesSeconds` (the Xray comparator does).
        #[arg(long)]
        record_latencies: bool,
        /// Where to write `samples.json`; omitted for a warm-up-only run.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Drive one fallback slot's throughput set and write its samples.
    ///
    /// Run as a child so `perf stat -- <workload>` brackets exactly the window
    /// whose samples are recorded. Not normally invoked by hand.
    FallbackWorkload {
        /// The server listener to fetch through.
        #[arg(long)]
        server_port: u16,
        /// Payload size in MiB.
        #[arg(long)]
        payload_mib: u64,
        /// Space-separated concurrency levels.
        #[arg(long)]
        concurrencies: String,
        /// Samples per concurrency level; `0` performs warm-up only.
        #[arg(long)]
        samples: usize,
        /// Implementation label recorded on every row.
        #[arg(long)]
        implementation: String,
        /// Block number.
        #[arg(long)]
        block: usize,
        /// Position within the block.
        #[arg(long)]
        position: usize,
        /// Where to write `samples.json`; omitted for a warm-up-only run.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Internal TCP boundary for deterministic handoff cover-flight shaping.
    ///
    /// This is a separate process because a soak run must put the shaper between
    /// the measured LINE process and its OpenSSL cover. It is hidden from normal
    /// CLI help: operator policy remains `bench run --suite soak`.
    #[command(hide = true)]
    ShapeProxy {
        /// Loopback port accepting the measured client's TLS connection.
        #[arg(long)]
        listen_port: u16,
        /// Loopback OpenSSL cover port.
        #[arg(long)]
        upstream_port: u16,
        /// Number of valid flights to shape before exiting.
        #[arg(long, default_value_t = 1)]
        max_shaped: usize,
        /// Maximum accepted sockets, including readiness probes.
        #[arg(long, default_value_t = 8)]
        max_accepted: usize,
    },
    /// Loopback HTTP/1.1 and TLS 1.3 payload origin.
    ///
    /// A separate process so a wedged listener takes down nothing but itself;
    /// the harnesses own its lifetime through RAII children. Hidden from normal
    /// CLI help: operator policy remains the suite commands.
    #[command(hide = true)]
    Origin {
        /// Numeric listen address.
        #[arg(long, default_value = "127.0.0.1")]
        listen_address: String,
        /// Listen port; 0 binds an ephemeral port.
        #[arg(long)]
        port: u16,
        /// Directory holding the payload files.
        #[arg(long)]
        payload_dir: PathBuf,
        /// Path of the per-PUT JSONL log the origin appends to.
        #[arg(long)]
        put_log: PathBuf,
        /// Per-request JSONL log; leaving it unset also leaves hashing off.
        #[arg(long)]
        access_log: Option<PathBuf>,
        /// Instance name recorded in access-log rows.
        #[arg(long, default_value = "")]
        label: String,
        /// TLS 1.3-only PEM certificate; requires `--tls-key`.
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS 1.3-only PEM private key; requires `--tls-cert`.
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Comma-separated ALPN protocols the TLS listener offers.
        #[arg(long, default_value = "")]
        tls_alpn: String,
    },
    /// Internal process-owned TCP echo target for real socket gates.
    #[command(hide = true)]
    Echo {
        /// Loopback listen port.
        #[arg(long)]
        port: u16,
    },
    /// Internal TCP-only no-auth SOCKS5 upstream for outbound-pool gates.
    #[command(hide = true)]
    SocksServer {
        /// Numeric IPv4 listen address.
        #[arg(long, default_value = "127.0.0.1")]
        listen: std::net::Ipv4Addr,
        /// Listen port.
        #[arg(long)]
        port: u16,
        /// Rewrite every requested destination to this numeric socket.
        #[arg(long)]
        fixed_target: Option<std::net::SocketAddr>,
    },
    /// Internal deployment-suite acceptance entry point.
    #[command(hide = true)]
    Deployment {
        /// Exact rust-reality binary under test.
        #[arg(long, default_value = "target/release/rust-reality")]
        rust_bin: PathBuf,
        /// Exact stock Xray comparator binary.
        #[arg(long, default_value = "xray")]
        xray_bin: PathBuf,
        /// New durable evidence directory.
        #[arg(long)]
        out_dir: PathBuf,
        /// Stable evidence identity.
        #[arg(long)]
        run_id: String,
        /// Reviewed deployment program.
        #[arg(long, default_value = "smoke")]
        plan: String,
        /// Preserve the ephemeral workspace for diagnosis.
        #[arg(long)]
        keep_work: bool,
    },
    /// Validate bounded machine profiles under exact cgroup-v2 limits.
    Profiles {
        /// Path to the exact rust-reality release binary under test.
        #[arg(long, default_value = "target/release/rust-reality")]
        rust_bin: PathBuf,
        /// Expected lowercase SHA-256 of the rust-reality binary.
        #[arg(long)]
        rust_sha256: String,
        /// Full source commit embedded in the rust-reality binary.
        #[arg(long)]
        expected_source_commit: String,
        /// Path to the exact stock Xray client binary.
        #[arg(long)]
        xray_bin: PathBuf,
        /// Expected lowercase SHA-256 of the Xray binary.
        #[arg(long)]
        xray_sha256: String,
        /// New durable evidence directory; it must not already exist.
        #[arg(long)]
        out_dir: PathBuf,
        /// Stable run identifier written into the completion marker.
        #[arg(long)]
        run_id: String,
        /// Reusable directory containing geoip.dat and geosite.dat.
        #[arg(long, default_value = "benchmarks/profile-validation/.asset-cache")]
        asset_cache_dir: PathBuf,
        /// Space-separated `name:cpu-percent:memory` class specifications.
        #[arg(
            long,
            default_value = "1c1g:100:1G 1c2g:100:2G 2c2g:200:2G 2c4g:200:4G 4c4g:400:4G 4c8g:400:8G"
        )]
        classes: String,
        /// Run only this class name.
        #[arg(long)]
        only: Option<String>,
        /// Add the 1c1g standard/shared comparison.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        standard_comparison: bool,
        /// Fresh connections in each churn sample.
        #[arg(long, default_value_t = 96)]
        connections: usize,
        /// Churn samples at each concurrency.
        #[arg(long, default_value_t = 3)]
        churn_samples: usize,
        /// Download samples at each concurrency.
        #[arg(long, default_value_t = 2)]
        download_samples: usize,
        /// Download payload size in MiB.
        #[arg(long, default_value_t = 512)]
        download_mib: u64,
        /// Seconds to hold each connection-ladder level.
        #[arg(long, default_value_t = 8)]
        hold_seconds: u64,
        /// Seconds to settle before sampling each ladder level.
        #[arg(long, default_value_t = 3)]
        settle_seconds: u64,
        /// Optional comma-separated default-policy ladder levels.
        #[arg(long)]
        ladder_levels: Option<String>,
        /// Optional comma-separated tuned-policy ladder levels.
        #[arg(long)]
        tuned_levels: Option<String>,
        /// Verify identities and host prerequisites without producing evidence.
        #[arg(long)]
        identity_check_only: bool,
        /// Keep the ephemeral workspace after the run.
        #[arg(long)]
        keep_work: bool,
    },
    /// Run a benchmark or mechanism suite end to end.
    Run {
        /// Suite id (`cargo dev bench list` shows the catalogue).
        #[arg(long, default_value = "real-path")]
        suite: String,
        /// Path to the rust-reality release binary.
        #[arg(long, default_value = "target/release/rust-reality")]
        rust_bin: PathBuf,
        /// Path to the Xray binary.
        #[arg(long, default_value = "xray")]
        xray_bin: PathBuf,
        /// Alternating transfers across both implementations.
        #[arg(long, default_value_t = 20)]
        runs: usize,
        /// Expected payload bytes per transfer.
        #[arg(long, default_value_t = 5_000_000)]
        bytes: u64,
        /// The download URL (cloudflare speed endpoint by default).
        #[arg(long)]
        url: Option<String>,
        /// The REALITY cover target (`host:port`).
        #[arg(long, default_value = "dl.google.com:443")]
        cover_target: String,
        /// The REALITY cover SNI.
        #[arg(long, default_value = "dl.google.com")]
        cover_sni: String,
        /// Per-transfer curl deadline in seconds.
        #[arg(long, default_value_t = 300)]
        max_time: u64,
        /// Directory for the durable report (created; unique per run by default).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Samples per implementation (xray suite).
        #[arg(long, default_value_t = 9)]
        samples: usize,
        /// Concurrent transfers per sample (xray suite).
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Payload size in MiB (xray suite).
        #[arg(long, default_value_t = 64)]
        payload_mib: u64,
        /// Balanced ABBA blocks of four slots (setup-rate suites).
        #[arg(long, default_value_t = 3)]
        blocks: usize,
        /// Connections per sample (setup-rate suites).
        #[arg(long, default_value_t = 96)]
        connections: usize,
        /// Space-separated concurrency levels (setup-rate suites).
        #[arg(long, default_value = "1 8 32")]
        concurrencies: String,
        /// Which implementation leads block one; defaults to the suite's first
        /// label (`baseline` for the paired suites, `rust` for the comparator).
        #[arg(long, default_value = "")]
        abba_start: String,
        /// `perf` attributes server CPU, `strace` counts receive syscalls, and
        /// `wall` records rates only.
        #[arg(long, default_value = "perf")]
        measure_mode: String,
        /// Capture an identity-bound `perf record` from the benchmark-owned server.
        #[arg(long)]
        profile: bool,
        /// Hard maximum duration of a benchmark-owned profile.
        #[arg(long, default_value_t = 35)]
        profile_record_seconds: u64,
        /// `perf record` event for a benchmark-owned profile.
        #[arg(long, default_value = "cycles:u")]
        profile_event: String,
        /// Sampling frequency for a benchmark-owned profile.
        #[arg(long, default_value_t = 999)]
        profile_frequency: u32,
        /// Call-graph mode for a benchmark-owned profile.
        #[arg(long, default_value = "fp")]
        profile_call_graph: String,
        /// Run identifier recorded in the completion marker.
        #[arg(long)]
        run_id: Option<String>,
        /// Pinned baseline ELF (paired setup-rate / fallback suites).
        #[arg(long)]
        baseline_bin: Option<PathBuf>,
        /// Baseline identity sidecar binding its commit and digest.
        #[arg(long)]
        baseline_identity: Option<PathBuf>,
        /// The commit the baseline sidecar must name.
        #[arg(long)]
        baseline_commit: Option<String>,
        /// Cover mode for the baseline side.
        #[arg(long, default_value = "default")]
        baseline_cover_mode: String,
        /// Cover mode for the candidate side.
        #[arg(long, default_value = "default")]
        candidate_cover_mode: String,
        /// One-leg netem delay in ms; shapes only the TLS cover target.
        #[arg(long)]
        cover_netem_rtt_ms: Option<u32>,
        /// Payload size in MiB for the fallback suite.
        #[arg(long, default_value_t = 32)]
        payload_mib_fallback: u64,
        /// Pin the relay `splice` policy (fallback suite).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        relay_splice: bool,
        /// Pin the relay pipe-pool policy (fallback suite).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        relay_pipe_pool: bool,
        /// Pin the relay buffer size in KiB (fallback suite).
        #[arg(long, default_value_t = 32)]
        relay_buffer_kib: u32,
        /// Space-separated payload sizes in MiB (matrix suite).
        #[arg(long, default_value = "1 32 512")]
        payloads: String,
        /// Concurrencies for payloads below the large threshold (matrix suite).
        #[arg(long, default_value = "1 32")]
        large_concurrencies: String,
        /// The payload size at which the large plan takes over (matrix suite).
        #[arg(long, default_value_t = 512)]
        large_payload_mib: u64,
        /// Samples per implementation for large payloads (matrix suite).
        #[arg(long, default_value_t = 3)]
        samples_large: usize,
        /// Payload size in MiB for the end-to-end integrity run; 0 skips it.
        #[arg(long, default_value_t = 2048)]
        integrity_mib: u64,
        /// Comma- or space-separated cell include patterns (matrix suite).
        #[arg(long, default_value = "")]
        cells: String,
        /// Comma- or space-separated cell skip patterns (matrix suite).
        #[arg(long, default_value = "")]
        skip: String,
        /// Raise `fs.pipe-user-pages-soft` for the run and restore it after.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        manage_pipe_pages: bool,
        /// Warm rounds per implementation (dns suite).
        #[arg(long, default_value_t = 2)]
        warm_samples: usize,
        /// Connections in the burst phase (dns suite).
        #[arg(long, default_value_t = 32)]
        burst_conns: usize,
        /// Space-separated routing rule counts (routing suite).
        #[arg(long, default_value = "10 100 1000 10000")]
        rule_scales: String,
        /// Fresh connections per setup sample (vless-encryption suite).
        #[arg(long, default_value_t = 128)]
        setup_connections: usize,
        /// Concurrency for the setup sample (vless-encryption suite).
        #[arg(long, default_value_t = 8)]
        setup_concurrency: usize,
        /// A URL fetched through the tunnel to prove reachability (interop).
        #[arg(long)]
        internet_url: Option<String>,
        /// The pinned OpenSSL that serves the no-CCS cover target.
        #[arg(long, default_value = "openssl")]
        openssl_bin: PathBuf,
        /// Sequential TLS-shape samples per implementation.
        #[arg(long, default_value_t = 3)]
        tls_shape_samples: usize,
        /// TLS 1.3 reference cipher-suite list.
        #[arg(long, default_value = "TLS_AES_128_GCM_SHA256")]
        tls_ciphersuites: String,
        /// OpenSSL TLS group list for the dynamic reference.
        #[arg(long, default_value = "X25519MLKEM768:X25519")]
        tls_groups: String,
        /// ALPN selected by the dynamic reference; empty selects none.
        #[arg(long, default_value = "h2")]
        tls_alpn: String,
        /// Emit the TLS 1.3 middlebox compatibility CCS.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        tls_middlebox: bool,
        /// OpenSSL maximum send fragment; zero keeps its default.
        #[arg(long, default_value_t = 0)]
        tls_max_fragment: u16,
        /// OpenSSL split send fragment; zero keeps its default.
        #[arg(long, default_value_t = 0)]
        tls_split_fragment: u16,
        /// Fixed TLS 1.3 reference record padding bytes.
        #[arg(long, default_value_t = 0)]
        tls_padding: u16,
        /// Apply `TCP_NODELAY` to the accepted reference socket.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        tls_tcp_nodelay: bool,
        /// IPv6 validation phase digits.
        #[arg(long, default_value = "012345")]
        ipv6_phases: String,
        /// Host-global IPv6 address for the environmental phase.
        #[arg(long)]
        global_v6: Option<String>,
        /// Equal hard/soft open-file limit for the descriptor-pressure suite.
        #[arg(long, default_value_t = 192)]
        nofile_limit: u64,
        /// Maximum held streams attempted by the descriptor-pressure suite.
        #[arg(long, default_value_t = 96)]
        max_held_connections: usize,
        /// Concurrent admission attempts while descriptor pressure is high.
        #[arg(long, default_value_t = 12)]
        storm_connections: usize,
        /// Soak topology implementation (`rust` or the `xray` comparator).
        #[arg(long, default_value = "rust")]
        soak_implementation: String,
        /// Timed soak workload window in seconds.
        #[arg(long, default_value_t = 1800)]
        soak_seconds: u64,
        /// Delay between soak rounds in milliseconds.
        #[arg(long, default_value_t = 5000)]
        soak_round_sleep_ms: u64,
        /// Minimum completed soak workload rounds.
        #[arg(long, default_value_t = 1)]
        soak_min_rounds: usize,
        /// Interval between distributed soak integrity attempts.
        #[arg(long, default_value_t = 1800)]
        soak_distributed_interval_seconds: u64,
        /// Reviewed deployment program (deployment suite).
        #[arg(long, default_value = "smoke")]
        deployment_plan: String,
        /// Preserve the ephemeral deployment workspace for diagnosis.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        keep_work: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Emit a secret-free identity fingerprint for a deployment config.
    Fingerprint {
        /// Path to the config JSON.
        config: PathBuf,
        /// Optional path to write the fingerprint report to; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum FuzzCommand {
    /// Validate the fuzz manifest and print the (optionally sharded) target list.
    Targets {
        /// Shard index (0-based); requires --shard-count.
        #[arg(long)]
        shard_index: Option<usize>,
        /// Total shard count; requires --shard-index.
        #[arg(long)]
        shard_count: Option<usize>,
    },
    /// Run a deterministic short libFuzzer smoke pass over the targets.
    Smoke {
        /// Targets to smoke; all declared targets when omitted.
        targets: Vec<String>,
        /// Shard index (0-based) to smoke; requires --shard-count.
        #[arg(long)]
        shard_index: Option<usize>,
        /// Total shard count; requires --shard-index.
        #[arg(long)]
        shard_count: Option<usize>,
    },
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Print the release tier matrix.
    Matrix {
        /// Emit the GitHub Actions matrix JSON line for `$GITHUB_OUTPUT`.
        #[arg(long)]
        github_matrix: bool,
        /// List tier ids, space-separated.
        #[arg(long)]
        tiers: bool,
    },
    /// Verify a release tag's `SemVer`, version, annotation and commit identity.
    VerifyTag {
        /// The release tag, e.g. v1.8.0.
        tag: String,
        /// The mainline ref the tag commit must be reachable from.
        #[arg(default_value = "origin/main")]
        main_ref: String,
    },
    /// Build (and, unless --build-only, test) a tier.
    Build {
        /// The tier id.
        tier: String,
        /// Build without running the workspace test suite (required for
        /// non-runnable cross tiers).
        #[arg(long)]
        build_only: bool,
    },
    /// Package a built tier into a deterministic tarball and tier fragment.
    Package {
        /// The release tag.
        tag: String,
        /// The tier id.
        tier: String,
        /// Output directory.
        #[arg(default_value = "dist")]
        output: PathBuf,
    },
    /// Smoke-test a packaged tier by running its binary against a cover.
    Smoke {
        /// The release tag.
        tag: String,
        /// The tier id.
        tier: String,
        /// Directory containing the packaged assets.
        #[arg(default_value = "dist")]
        assets: PathBuf,
    },
    /// Aggregate the complete tier matrix into a manifest and SHA256SUMS.
    Aggregate {
        /// The release tag.
        tag: String,
        /// The dist directory containing every tier's tarball and fragment.
        #[arg(default_value = "dist")]
        dist: PathBuf,
    },
}

#[derive(Subcommand)]
enum PerfCommand {
    /// Evaluate recorded benchmark evidence and write a gate report.
    ///
    /// Exit status is three-valued and load-bearing: 0 when the gate passes, 1 for a
    /// real performance regression, and 2 when the evidence was inadmissible so no
    /// comparison happened. A failing gate and a broken harness need different
    /// operator responses, so the two are never collapsed.
    Evaluate {
        /// Absolute path to the evaluator manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Absolute path of the report to create. Must not already exist.
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture an identity-bound hotspot profile from the built-in benchmark or
    /// an already-running server.
    Hotspot {
        /// Process lifecycle used for the capture.
        #[arg(long, value_enum)]
        mode: HotspotMode,
        /// Exact rust-reality binary to archive and measure.
        #[arg(long)]
        binary: PathBuf,
        /// Required lowercase-hex SHA-256 of the binary.
        #[arg(long)]
        binary_sha256: String,
        /// Required source commit embedded in the binary.
        #[arg(long)]
        expected_source_commit: String,
        /// Existing rust-reality server PID for attach mode.
        #[arg(long)]
        pid: Option<u32>,
        /// New absolute evidence directory.
        #[arg(long)]
        out_dir: PathBuf,
        /// Stable run identifier written into the publication marker.
        #[arg(long)]
        run_id: String,
        /// Maximum seconds spent recording.
        #[arg(long, default_value_t = 35)]
        record_seconds: u64,
        /// Built-in benchmark case duration.
        #[arg(long, default_value_t = 10_000)]
        duration_ms: u64,
        /// Built-in benchmark warmup duration.
        #[arg(long, default_value_t = 1_000)]
        warmup_ms: u64,
        /// `perf record` event selector.
        #[arg(long, default_value = "cycles:u")]
        event: String,
        /// `perf record` sample frequency.
        #[arg(long, default_value_t = 999)]
        frequency: u32,
        /// `perf record --call-graph` value.
        #[arg(long, default_value = "fp")]
        call_graph: String,
    },
    /// Build one named commit into an identity-bound, read-only release artifact.
    ///
    /// Every other perf command consumes a binary that already carries its
    /// source commit, SHA-256 and Build ID; this is what produces one. The
    /// commit is embedded at build time and the built binary must report it
    /// back, so a forgotten `RUST_REALITY_GIT_COMMIT` fails here rather than
    /// inside a capture minutes later.
    Freeze {
        /// The 40-hex source commit to build, embed and verify.
        #[arg(long)]
        commit: String,
        /// New absolute evidence directory. Must not already exist.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Export one exact hotspot through DWARF, `IDALib`, LLVM and perf samples.
    HotspotBundle {
        /// Completed native `perf hotspot` run directory.
        #[arg(long)]
        run_dir: PathBuf,
        /// Safe name for the new `hotspots/LABEL` evidence directory.
        #[arg(long)]
        label: String,
        /// Perf DSO/file offset; the bundle normalizes it to a static ELF address.
        #[arg(long)]
        dso_offset: String,
        /// `IDALib` Python executable. Python is the external `IDALib` API boundary.
        #[arg(long)]
        idalib_python: PathBuf,
        /// Maximum seconds allowed for `IDALib` analysis.
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,
        /// Reviewed sub-1% unmapped-period threshold; zero is fail-closed default.
        #[arg(long, default_value_t = 0.0)]
        max_unmapped_period_percent: f64,
        /// Required explanation when allowing a non-zero unmapped-period threshold.
        #[arg(long)]
        unmapped_period_explanation: Option<String>,
    },
    /// Capture identity-bound perf-stat or perf-c2c environment evidence.
    ///
    /// The workload command follows `--` and its argv[0] must be the identified
    /// binary. Status is three-valued: PASS, UNAVAILABLE (perf refused for
    /// permission/capability reasons), or FAIL.
    Environment {
        /// Which perf tool to run.
        #[arg(long, value_enum)]
        tool: EnvironmentTool,
        /// Where to write the evidence JSON.
        #[arg(long)]
        output: PathBuf,
        /// The binary the workload must execute.
        #[arg(long)]
        binary: PathBuf,
        /// The expected lowercase-hex SHA-256 of that binary.
        #[arg(long)]
        binary_sha256: String,
        /// The workload command; everything after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum EnvironmentTool {
    /// `perf stat`.
    Stat,
    /// `perf c2c`.
    C2c,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum HotspotMode {
    /// Launch and own the built-in benchmark.
    BuiltIn,
    /// Attach to an existing exactly identified server.
    AttachServer,
}

#[derive(Subcommand)]
enum DocsCommand {
    /// Validate bilingual coverage, local links, stale wording and release headlines.
    Check,
}

#[derive(Subcommand)]
enum RepoCommand {
    /// Validate the tracked tree against repository-layout policy.
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let repo = cli.repo.unwrap_or_else(default_repo_root);

    match cli.command {
        Command::Doctor => run_doctor(),
        Command::Perf { command } => run_perf(&repo, command),
        Command::Release { command } => run_release(&repo, command),
        Command::Fuzz { command } => run_fuzz(&repo, command),
        Command::Config { command } => match command {
            ConfigCommand::Fingerprint { config, output } => {
                match checks::config_identity::report(&config) {
                    Ok(report) => {
                        let rendered = report.to_python_json();
                        if let Some(path) = output {
                            match std::fs::write(&path, &rendered) {
                                Ok(()) => ExitCode::SUCCESS,
                                Err(error) => {
                                    eprintln!("config fingerprint: {error}");
                                    ExitCode::FAILURE
                                }
                            }
                        } else {
                            print!("{rendered}");
                            ExitCode::SUCCESS
                        }
                    }
                    Err(error) => {
                        eprintln!("config fingerprint: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
        },
        Command::Bench { command } => run_bench(&repo, &command),
        Command::Deploy { command } => run_deploy(&repo, command),
        Command::Docs { command } => match command {
            DocsCommand::Check => {
                let report = docs::check(&repo);
                if report.is_clean() {
                    println!("{}", report.render());
                    ExitCode::SUCCESS
                } else {
                    eprint!("{}", report.render());
                    ExitCode::FAILURE
                }
            }
        },
        Command::Repo { command } => match command {
            RepoCommand::Check => {
                let report = repo::check(&repo);
                if report.is_clean() {
                    println!("{}", report.render());
                    ExitCode::SUCCESS
                } else {
                    eprint!("{}", report.render());
                    ExitCode::FAILURE
                }
            }
        },
        Command::Check {
            all,
            output,
            log_dir,
        } => {
            let scope = if all {
                check::Scope::All
            } else {
                check::Scope::Fast
            };
            if check::run(&repo, scope, output, log_dir.as_deref()) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Resolves the repository root from this crate's compile-time location.
///
/// `tools/rr-dev` sits two levels below the checkout root, so the tool works from
/// any current directory without an environment variable or a search heuristic.
fn default_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// Prints the environment diagnosis and fails only on a blocking finding.
///
/// A restricted capability, such as an installed `perf` whose PMU is blocked by
/// `perf_event_paranoid`, is reported prominently but is not an error: it is a
/// true fact about the host that the developer needs, not a broken setup.
fn run_doctor() -> ExitCode {
    let findings = doctor::diagnose();
    let mut blocking = Vec::new();
    let mut restricted = Vec::new();

    println!("{:<14} {:<9} {:<12} detail", "capability", "need", "status");
    println!("{}", "-".repeat(80).as_str());
    for finding in &findings {
        println!("{finding}");
        if finding.availability.is_blocking() {
            blocking.push(finding.name);
        } else if finding.availability == doctor::Availability::Restricted {
            restricted.push(finding.name);
        }
    }

    if !restricted.is_empty() {
        println!("\nrestricted: {}", restricted.join(", "));
        println!(
            "a restricted capability is present but limited by policy or kernel settings. \
             Record the affected questions as pending; do not estimate the numbers it \
             would have produced."
        );
    }

    if blocking.is_empty() {
        println!("\nthis host can build, test and check the repository");
        return ExitCode::SUCCESS;
    }
    eprintln!("\nmissing requirements: {}", blocking.join(", "));
    ExitCode::FAILURE
}

/// Dispatches a `cargo dev perf` subcommand.
#[allow(
    clippy::too_many_lines,
    reason = "each perf subcommand remains an explicit typed dispatch arm"
)]
fn run_perf(repo: &std::path::Path, command: PerfCommand) -> ExitCode {
    match command {
        PerfCommand::Evaluate { manifest, output } => {
            match perf::report::evaluate_to_file(&manifest, &output) {
                Ok(verdict) => {
                    println!("{}: {}", verdict.as_str(), output.display());
                    ExitCode::from(verdict.exit_code())
                }
                Err(error) => {
                    // An argument or write failure, distinct from inadmissible
                    // evidence: no report is produced at all.
                    eprintln!("perf evaluate: {error}");
                    ExitCode::from(2)
                }
            }
        }
        PerfCommand::Hotspot {
            mode,
            binary,
            binary_sha256,
            expected_source_commit,
            pid,
            out_dir,
            run_id,
            record_seconds,
            duration_ms,
            warmup_ms,
            event,
            frequency,
            call_graph,
        } => {
            let mode = match mode {
                HotspotMode::BuiltIn => perf::hotspot::Mode::BuiltIn,
                HotspotMode::AttachServer => perf::hotspot::Mode::AttachServer,
            };
            match perf::hotspot::run(&perf::hotspot::Plan {
                repo: repo.to_path_buf(),
                mode,
                binary,
                binary_sha256,
                expected_source_commit,
                server_pid: pid,
                out_dir,
                run_id,
                record_seconds,
                duration_ms,
                warmup_ms,
                event,
                frequency,
                call_graph,
            }) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("perf hotspot: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        PerfCommand::Freeze { commit, out_dir } => {
            match perf::freeze::run(&perf::freeze::Plan {
                repo: repo.to_path_buf(),
                commit,
                out_dir,
            }) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("perf freeze: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        PerfCommand::HotspotBundle {
            run_dir,
            label,
            dso_offset,
            idalib_python,
            timeout_seconds,
            max_unmapped_period_percent,
            unmapped_period_explanation,
        } => match perf::hotspot::bundle::run(&perf::hotspot::bundle::Plan {
            run_dir,
            label,
            dso_offset,
            idalib_python,
            timeout_seconds,
            max_unmapped_period_percent,
            unmapped_period_explanation,
        }) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("perf hotspot-bundle: {error}");
                ExitCode::FAILURE
            }
        },
        PerfCommand::Environment {
            tool,
            output,
            binary,
            binary_sha256,
            command,
        } => {
            let kind = match tool {
                EnvironmentTool::Stat => perf::environment::Kind::Stat,
                EnvironmentTool::C2c => perf::environment::Kind::C2c,
            };
            match perf::environment::capture(
                kind,
                &perf::environment::Options {
                    output: &output,
                    binary: &binary,
                    binary_sha256: &binary_sha256,
                    command: &command,
                },
            ) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("perf environment: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Dispatches a `cargo dev release` subcommand.
///
/// Each stage prints its own success line and maps a domain error onto a single
/// non-zero exit. Release stages are fail-closed: a stage that cannot prove its
/// invariant returns an error rather than a partial success.
fn run_release(repo: &std::path::Path, command: ReleaseCommand) -> ExitCode {
    let result = match command {
        ReleaseCommand::Matrix {
            github_matrix,
            tiers,
        } => {
            if github_matrix {
                println!("{}", release::matrix::github_matrix());
            } else if tiers {
                println!("{}", release::matrix::Tier::ids().join(" "));
            } else {
                for tier in &release::matrix::TIERS {
                    println!(
                        "{}\t{}\t{}\t{}",
                        tier.id, tier.target, tier.target_cpu, tier.runs_on
                    );
                }
            }
            Ok(String::new())
        }
        ReleaseCommand::VerifyTag { tag, main_ref } => {
            release::verify_tag::verify(repo, &tag, &main_ref)
        }
        ReleaseCommand::Build { tier, build_only } => {
            release::build::build(repo, &tier, build_only)
        }
        ReleaseCommand::Package { tag, tier, output } => {
            release::package::package(&release::package::Options {
                repo,
                tag: &tag,
                tier: &tier,
                output: &output,
                binary_override: std::env::var_os("RUST_REALITY_RELEASE_BIN").map(Into::into),
                cargo_features: std::env::var("RUST_REALITY_CARGO_FEATURES").ok(),
                measured_natively: std::env::var("RUST_REALITY_MEASURED_NATIVELY")
                    .ok()
                    .map(|value| value == "true"),
            })
            .map(|packaged| {
                format!(
                    "packaged {tier} -> {} (sha256 {}, fragment {})",
                    packaged.archive.display(),
                    packaged.sha256,
                    packaged.fragment.display()
                )
            })
        }
        ReleaseCommand::Smoke { tag, tier, assets } => {
            release::smoke::smoke(repo, &tag, &tier, &assets)
        }
        ReleaseCommand::Aggregate { tag, dist } => release::aggregate::aggregate(&dist, &tag),
    };

    match result {
        Ok(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatches a `cargo dev fuzz` subcommand.
///
/// `targets` prints the validated (optionally sharded) target list, one per line,
/// as the retired `fuzz-targets.py` did. `smoke` runs the deterministic libFuzzer
/// pass; with a shard it resolves that shard first, collapsing the shell pipeline
/// `security.yml` used into one invocation.
fn run_fuzz(repo: &std::path::Path, command: FuzzCommand) -> ExitCode {
    match command {
        FuzzCommand::Targets {
            shard_index,
            shard_count,
        } => {
            let names = match resolve_targets(repo, shard_index, shard_count) {
                Ok(names) => names,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            println!("{}", names.join("\n"));
            ExitCode::SUCCESS
        }
        FuzzCommand::Smoke {
            targets,
            shard_index,
            shard_count,
        } => {
            let selected = if shard_index.is_some() || shard_count.is_some() {
                if !targets.is_empty() {
                    eprintln!("fuzz smoke: pass either explicit targets or a shard, not both");
                    return ExitCode::FAILURE;
                }
                match resolve_targets(repo, shard_index, shard_count) {
                    Ok(names) => names,
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                targets
            };
            match fuzz::smoke::smoke(repo, &selected) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Resolves the full or sharded target list, requiring both shard arguments together.
fn resolve_targets(
    repo: &std::path::Path,
    shard_index: Option<usize>,
    shard_count: Option<usize>,
) -> Result<Vec<String>, String> {
    match (shard_index, shard_count) {
        (None, None) => fuzz::targets::all(repo).map_err(|error| error.to_string()),
        (Some(index), Some(count)) => {
            fuzz::targets::shard(repo, index, count).map_err(|error| error.to_string())
        }
        _ => Err("--shard-index and --shard-count must be supplied together".to_owned()),
    }
}

/// Dispatches a `cargo dev bench` subcommand.
///
/// `list` shows the suite catalogue and the legacy scripts each supersedes.
/// `environment` runs the typed preflight that every suite depends on: tool
/// availability, host-exclusive lock acquire/release, an ephemeral workspace and
/// loopback port reservation. It exits non-zero when the host cannot run a
/// benchmark, so it doubles as a CI-safe readiness probe.
#[allow(clippy::too_many_lines)]
fn run_bench(repo: &Path, command: &BenchCommand) -> ExitCode {
    match command {
        BenchCommand::ShapeProxy {
            listen_port,
            upstream_port,
            max_shaped,
            max_accepted,
        } => match bench::tls_shape::run_shape_proxy(
            *listen_port,
            *upstream_port,
            *max_shaped,
            *max_accepted,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench shape-proxy: {error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::Origin {
            listen_address,
            port,
            payload_dir,
            put_log,
            access_log,
            label,
            tls_cert,
            tls_key,
            tls_alpn,
        } => {
            let tls = match (tls_cert, tls_key) {
                (None, None) => None,
                (Some(cert), Some(key)) => {
                    let (certificate_pem, key_pem) = match (std::fs::read(cert), std::fs::read(key))
                    {
                        (Ok(certificate_pem), Ok(key_pem)) => (certificate_pem, key_pem),
                        (error, other) => {
                            let failed = match (error.is_err(), other.is_err()) {
                                (true, _) => error.unwrap_err(),
                                (_, true) => other.unwrap_err(),
                                _ => std::io::Error::other("unreadable TLS material"),
                            };
                            eprintln!("bench origin: could not read TLS material: {failed}");
                            return ExitCode::FAILURE;
                        }
                    };
                    let alpn = tls_alpn
                        .split(',')
                        .map(str::trim)
                        .filter(|protocol| !protocol.is_empty())
                        .map(str::to_owned)
                        .collect();
                    Some(bench::origin_server::TlsOptions {
                        certificate_pem,
                        key_pem,
                        alpn,
                    })
                }
                _ => {
                    eprintln!("bench origin: --tls-cert and --tls-key must be given together");
                    return ExitCode::from(2);
                }
            };
            let address = match listen_address.parse::<std::net::IpAddr>() {
                Ok(address) => address,
                Err(error) => {
                    eprintln!("bench origin: --listen-address must be numeric: {error}");
                    return ExitCode::from(2);
                }
            };
            if let Some(options) = tls.as_ref()
                && let Err(error) = bench::origin_server::tls_acceptor(options)
            {
                eprintln!("bench origin: {error}");
                return ExitCode::from(2);
            }
            let listener = match std::net::TcpListener::bind((address, *port)) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("bench origin: could not bind {address}:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Ok(address) = listener.local_addr() {
                println!("READY {address}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match bench::origin_server::serve_with_tls(
                &listener,
                payload_dir,
                Some(put_log),
                access_log.as_deref(),
                label,
                tls.as_ref(),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bench origin: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::Echo { port } => {
            let listener = match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, *port))
            {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("bench echo: could not bind 127.0.0.1:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Ok(address) = listener.local_addr() {
                println!("READY {address}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match bench::echo::serve(&listener) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bench echo: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::SocksServer {
            listen,
            port,
            fixed_target,
        } => {
            let listener = match std::net::TcpListener::bind((*listen, *port)) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("bench socks-server: could not bind {listen}:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Ok(address) = listener.local_addr() {
                println!("READY {address}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match bench::socks_server::serve_with_target(&listener, *fixed_target) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bench socks-server: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::Deployment {
            rust_bin,
            xray_bin,
            out_dir,
            run_id,
            plan,
            keep_work,
        } => {
            let kind = match bench::deployment::PlanKind::parse(plan) {
                Ok(kind) => kind,
                Err(error) => {
                    eprintln!("bench deployment: {error}");
                    return ExitCode::from(2);
                }
            };
            let run = bench::deployment::RunPlan {
                repo: repo.to_path_buf(),
                rust_bin: rust_bin.clone(),
                xray_bin: xray_bin.clone(),
                out_dir: out_dir.clone(),
                run_id: run_id.clone(),
                program: bench::deployment::Plan::reviewed(kind),
                keep_work: *keep_work,
            };
            match bench::deployment::run(&run) {
                Ok(outcome) => {
                    println!("summary: {}", outcome.summary_path.display());
                    println!("completion: {}", outcome.marker_path.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("bench deployment: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::Profiles {
            rust_bin,
            rust_sha256,
            expected_source_commit,
            xray_bin,
            xray_sha256,
            out_dir,
            run_id,
            asset_cache_dir,
            classes,
            only,
            standard_comparison,
            connections,
            churn_samples,
            download_samples,
            download_mib,
            hold_seconds,
            settle_seconds,
            ladder_levels,
            tuned_levels,
            identity_check_only,
            keep_work,
        } => run_bench_profiles(&bench::profiles::Plan {
            repo: repo.to_path_buf(),
            rust_bin: rust_bin.clone(),
            rust_sha256: rust_sha256.clone(),
            expected_source_commit: expected_source_commit.clone(),
            xray_bin: xray_bin.clone(),
            xray_sha256: xray_sha256.clone(),
            out_dir: out_dir.clone(),
            run_id: run_id.clone(),
            asset_cache_dir: asset_cache_dir.clone(),
            classes: classes.clone(),
            only: only.clone(),
            standard_comparison: *standard_comparison,
            connections: *connections,
            churn_samples: *churn_samples,
            download_samples: *download_samples,
            download_mib: *download_mib,
            hold_seconds: *hold_seconds,
            settle_seconds: *settle_seconds,
            ladder_levels: ladder_levels.clone(),
            tuned_levels: tuned_levels.clone(),
            identity_check_only: *identity_check_only,
            keep_work: *keep_work,
        }),
        BenchCommand::Workload {
            socks_port,
            origin_port,
            connections,
            concurrencies,
            samples,
            implementation,
            block,
            position,
            record_latencies,
            output,
        } => run_bench_workload(
            &bench::workload::SetupRatePlan {
                socks_port: *socks_port,
                origin_port: *origin_port,
                connections: *connections,
                concurrencies: concurrencies
                    .split_whitespace()
                    .filter_map(|word| word.parse().ok())
                    .collect(),
                samples: *samples,
                implementation: implementation.clone(),
                block: *block,
                position: *position,
                record_latencies: *record_latencies,
            },
            output.as_deref(),
        ),
        BenchCommand::FallbackWorkload {
            server_port,
            payload_mib,
            concurrencies,
            samples,
            implementation,
            block,
            position,
            output,
        } => run_bench_fallback_workload(
            &bench::throughput::ThroughputPlan {
                server_port: *server_port,
                payload_mib: *payload_mib,
                concurrencies: concurrencies
                    .split_whitespace()
                    .filter_map(|word| word.parse().ok())
                    .collect(),
                samples: *samples,
                implementation: implementation.clone(),
                block: *block,
                position: *position,
            },
            output.as_deref(),
        ),
        BenchCommand::List => {
            println!("{:<20} supersedes            summary", "suite");
            println!("{}", "-".repeat(80));
            for suite in &bench::runner::SUITES {
                println!(
                    "{:<20} {:<20}  {}",
                    suite.id, suite.supersedes, suite.summary
                );
            }
            ExitCode::SUCCESS
        }
        BenchCommand::Environment => {
            let report = bench::runner::preflight(&bench::runner::COMMON_TOOLS);
            println!("tools present : {}", report.present_tools.join(", "));
            if report.missing_tools.is_empty() {
                println!("tools missing : none");
            } else {
                println!("tools missing : {}", report.missing_tools.join(", "));
            }
            println!(
                "host lock     : {}",
                report.lock_identity.as_deref().map_or_else(
                    || if report.lock_ok { "ok" } else { "unavailable" }.to_owned(),
                    |identity| format!("ok (device:inode {identity})")
                )
            );
            println!(
                "workspace     : {}",
                if report.workspace_ok {
                    "ok"
                } else {
                    "unavailable"
                }
            );
            println!("ports reserved: {}", report.reserved_ports);
            if report.is_ready() {
                println!("\nthis host can run benchmarks");
                ExitCode::SUCCESS
            } else {
                eprintln!("\nthe benchmark environment is not ready");
                ExitCode::FAILURE
            }
        }
        BenchCommand::Run {
            suite,
            rust_bin,
            xray_bin,
            runs,
            bytes,
            url,
            cover_target,
            cover_sni,
            max_time,
            out_dir,
            samples,
            concurrency,
            payload_mib,
            blocks,
            connections,
            concurrencies,
            abba_start,
            measure_mode,
            profile,
            profile_record_seconds,
            profile_event,
            profile_frequency,
            profile_call_graph,
            run_id,
            baseline_bin,
            baseline_identity,
            baseline_commit,
            baseline_cover_mode,
            candidate_cover_mode,
            cover_netem_rtt_ms,
            payload_mib_fallback,
            relay_splice,
            relay_pipe_pool,
            relay_buffer_kib,
            payloads,
            large_concurrencies,
            large_payload_mib,
            samples_large,
            integrity_mib,
            cells,
            skip,
            manage_pipe_pages,
            warm_samples,
            burst_conns,
            rule_scales,
            setup_connections,
            setup_concurrency,
            internet_url,
            openssl_bin,
            tls_shape_samples,
            tls_ciphersuites,
            tls_groups,
            tls_alpn,
            tls_middlebox,
            tls_max_fragment,
            tls_split_fragment,
            tls_padding,
            tls_tcp_nodelay,
            ipv6_phases,
            global_v6,
            nofile_limit,
            max_held_connections,
            storm_connections,
            soak_implementation,
            soak_seconds,
            soak_round_sleep_ms,
            soak_min_rounds,
            soak_distributed_interval_seconds,
            deployment_plan,
            keep_work,
        } => {
            if *profile && !matches!(suite.as_str(), "setup-rate" | "vision-direct") {
                eprintln!(
                    "bench run: --profile is supported only for setup-rate and vision-direct"
                );
                return ExitCode::from(2);
            }
            let profile = profile.then(|| perf::hotspot::BenchmarkProfile {
                record_seconds: *profile_record_seconds,
                event: profile_event.clone(),
                frequency: *profile_frequency,
                call_graph: profile_call_graph.clone(),
            });
            if let Some(profile) = &profile
                && let Err(error) = perf::hotspot::validate_benchmark_profile(profile)
            {
                eprintln!("bench run: {error}");
                return ExitCode::from(2);
            }
            if suite == "tls-shape" {
                return run_bench_tls_shape(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *tls_shape_samples,
                    bench::tls_shape_suite::ReferenceOptions {
                        ciphersuites: tls_ciphersuites.clone(),
                        groups: tls_groups.clone(),
                        alpn: tls_alpn.clone(),
                        middlebox: *tls_middlebox,
                        max_fragment: *tls_max_fragment,
                        split_fragment: *tls_split_fragment,
                        padding: *tls_padding,
                        tcp_nodelay: *tls_tcp_nodelay,
                    },
                );
            }
            if suite == "ipv6" {
                return run_bench_ipv6(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    ipv6_phases,
                    global_v6.as_deref(),
                    *payload_mib,
                    internet_url.as_deref(),
                );
            }
            if suite == "no-ccs-interop" {
                return run_bench_no_ccs(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                );
            }
            if suite == "descriptor-pressure" {
                return run_bench_pressure(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *nofile_limit,
                    *max_held_connections,
                    *storm_connections,
                );
            }
            if suite == "soak" {
                if !matches!(soak_implementation.as_str(), "rust" | "xray") {
                    eprintln!("bench run soak: --soak-implementation must be rust or xray");
                    return ExitCode::from(2);
                }
                return run_bench_soak(
                    soak_implementation,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *soak_seconds,
                    *soak_round_sleep_ms,
                    *soak_min_rounds,
                    *soak_distributed_interval_seconds,
                );
            }
            if suite == "deployment" {
                let kind = match bench::deployment::PlanKind::parse(deployment_plan) {
                    Ok(kind) => kind,
                    Err(error) => {
                        eprintln!("bench run deployment: {error}");
                        return ExitCode::from(2);
                    }
                };
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs());
                let run_id = run_id.clone().unwrap_or_else(|| {
                    format!("deployment-{}-{stamp}-{}", kind.name(), std::process::id())
                });
                let out_dir = out_dir.clone().unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("benchmarks/evidence/releases")
                        .join(&run_id)
                });
                let run = bench::deployment::RunPlan {
                    repo: repo.to_path_buf(),
                    rust_bin: rust_bin.clone(),
                    xray_bin: xray_bin.clone(),
                    out_dir,
                    run_id,
                    program: bench::deployment::Plan::reviewed(kind),
                    keep_work: *keep_work,
                };
                return match bench::deployment::run(&run) {
                    Ok(outcome) => {
                        println!("summary: {}", outcome.summary_path.display());
                        println!("completion: {}", outcome.marker_path.display());
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("bench run deployment: {error}");
                        ExitCode::FAILURE
                    }
                };
            }
            if suite == "xray-interop" {
                return run_bench_interop(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    cover_target,
                    cover_sni,
                    internet_url.as_deref(),
                );
            }
            if suite == "vless-encryption" {
                return run_bench_vless(
                    repo,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *samples,
                    *concurrency,
                    *payload_mib,
                    *setup_connections,
                    *setup_concurrency,
                    cover_target,
                    cover_sni,
                );
            }
            if suite == "routing" {
                return run_bench_routing(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    rule_scales,
                    *blocks,
                    *samples,
                    *connections,
                    concurrencies,
                );
            }
            if suite == "dns" {
                return run_bench_dns(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *samples,
                    *warm_samples,
                    *connections,
                    concurrencies,
                    *burst_conns,
                );
            }
            if suite == "matrix" {
                return run_bench_matrix(
                    repo,
                    &MatrixArgs {
                        baseline_bin: baseline_bin.as_deref(),
                        final_bin: rust_bin,
                        xray_bin,
                        out_dir: out_dir.as_deref(),
                        run_id: run_id.as_deref(),
                        cover_target,
                        cover_sni,
                        payloads,
                        concurrencies,
                        large_concurrencies,
                        large_payload_mib: *large_payload_mib,
                        samples: *samples,
                        samples_large: *samples_large,
                        integrity_mib: *integrity_mib,
                        cells,
                        skip,
                        abba_start,
                        manage_pipe_pages: *manage_pipe_pages,
                    },
                );
            }
            if suite == "fallback" {
                return run_bench_fallback(
                    repo,
                    &FallbackArgs {
                        baseline_bin: baseline_bin.as_deref(),
                        candidate_bin: rust_bin,
                        baseline_identity: baseline_identity.as_deref(),
                        baseline_commit: baseline_commit.as_deref(),
                        out_dir: out_dir.as_deref(),
                        run_id: run_id.as_deref(),
                        blocks: *blocks,
                        samples: *samples,
                        concurrencies,
                        payload_mib: *payload_mib_fallback,
                        abba_start,
                        measure_mode,
                        relay_splice: *relay_splice,
                        relay_pipe_pool: *relay_pipe_pool,
                        relay_buffer_kib: *relay_buffer_kib,
                    },
                );
            }
            if suite == "setup-rate" {
                return run_bench_setup_rate(
                    repo,
                    &SetupRateArgs {
                        baseline_bin: baseline_bin.as_deref(),
                        candidate_bin: rust_bin,
                        xray_bin,
                        baseline_identity: baseline_identity.as_deref(),
                        baseline_commit: baseline_commit.as_deref(),
                        out_dir: out_dir.as_deref(),
                        run_id: run_id.as_deref(),
                        blocks: *blocks,
                        samples: *samples,
                        connections: *connections,
                        concurrencies,
                        abba_start,
                        baseline_cover_mode,
                        candidate_cover_mode,
                        measure_mode,
                        cover_netem_rtt_ms: *cover_netem_rtt_ms,
                        profile: profile.clone(),
                    },
                );
            }
            if suite == "setup-rate-xray" {
                return run_bench_setup_rate_xray(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *blocks,
                    *samples,
                    *connections,
                    concurrencies,
                    abba_start,
                    measure_mode,
                );
            }
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let out_dir = out_dir.clone().unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(format!(
                        "benchmarks/benchmark-real-path-{stamp}-{}",
                        std::process::id()
                    ))
            });
            let benchmark_run_id = run_id.clone().unwrap_or_else(|| {
                format!(
                    "benchmark-{}-{stamp}-{}",
                    suite.replace('_', "-"),
                    std::process::id()
                )
            });
            let context = bench::suites::SuiteContext {
                rust_bin,
                xray_bin,
                cover_target: cover_target.clone(),
                cover_sni: cover_sni.clone(),
                runs: *runs,
                expected_bytes: *bytes,
                suite_id: match suite.as_str() {
                    "xray" => "benchmark-xray".to_owned(),
                    "vision-direct" => "benchmark-vision-direct".to_owned(),
                    _ => "benchmark-real-path".to_owned(),
                },
                transfer_url: url.clone().unwrap_or_else(|| {
                    format!("https://speed.cloudflare.com/__down?bytes={bytes}")
                }),
                transfer_max_time_secs: *max_time,
                out_dir,
                allow_private: suite == "xray" || suite == "vision-direct",
            };
            match suite.as_str() {
                "real-path" => run_bench_run(&context),
                "xray" => run_bench_xray(
                    &context,
                    &bench::loopback::LoopbackPlan {
                        samples: *samples,
                        concurrency: *concurrency,
                        payload_mib: *payload_mib,
                        tls_origin: false,
                        harness: "benchmark-xray".to_owned(),
                        run_id: benchmark_run_id.clone(),
                        profile: None,
                    },
                ),
                "vision-direct" => run_bench_xray(
                    &context,
                    &bench::loopback::LoopbackPlan {
                        samples: *samples,
                        concurrency: *concurrency,
                        payload_mib: *payload_mib,
                        tls_origin: true,
                        harness: "benchmark-vision-direct".to_owned(),
                        run_id: benchmark_run_id,
                        profile: profile.clone(),
                    },
                ),
                other => {
                    eprintln!(
                        "bench run: unknown suite {other} (known: real-path, xray, vision-direct)"
                    );
                    ExitCode::from(2)
                }
            }
        }
    }
}

fn run_bench_profiles(plan: &bench::profiles::Plan) -> ExitCode {
    if let Err(error) = bench::profiles::validate(plan) {
        eprintln!("bench profiles: {error}");
        return ExitCode::from(2);
    }
    match bench::profiles::run(plan) {
        Ok(outcome) if outcome.identity_only => {
            println!("profile identity preflight: PASS");
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            println!(
                "profile validation: {} ({} classes) -> {}",
                if outcome.passed { "PASS" } else { "FAIL" },
                outcome.classes,
                outcome.out_dir.display()
            );
            if outcome.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("bench profiles: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives one fallback slot's throughput set as a child process.
fn run_bench_fallback_workload(
    plan: &bench::throughput::ThroughputPlan,
    output: Option<&std::path::Path>,
) -> ExitCode {
    if plan.concurrencies.is_empty() {
        eprintln!("bench fallback-workload: at least one concurrency level is required");
        return ExitCode::from(2);
    }
    if plan.samples == 0 {
        return match bench::throughput::warm_up(plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench fallback-workload: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let rows = match bench::throughput::run_slot(plan) {
        Ok(rows) => rows,
        Err(error) => {
            eprintln!("bench fallback-workload: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(output) = output else {
        eprintln!("bench fallback-workload: --output is required when samples are measured");
        return ExitCode::from(2);
    };
    match std::fs::write(output, bench::throughput::rows_json(&rows).to_python_json()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "bench fallback-workload: could not write {}: {error}",
                output.display()
            );
            ExitCode::FAILURE
        }
    }
}

/// Drives the DNS cold/warm/burst comparison.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_dns(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    samples: usize,
    warm_samples: usize,
    connections: usize,
    concurrencies: &str,
    burst_conns: usize,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-dns-comparison-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    // The DNS phases run at one concurrency; the first value is the one used.
    let concurrency = concurrencies
        .split_whitespace()
        .find_map(|word| word.parse().ok())
        .unwrap_or(8);
    let suite = bench::dns::DnsSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        samples,
        warm_samples,
        connections,
        concurrency,
        burst_connections: burst_conns,
    };
    if let Err(error) = bench::dns::validate(&suite) {
        eprintln!("bench run dns: {error}");
        return ExitCode::from(2);
    }
    match bench::dns::run(&suite) {
        Ok(outcome) => {
            println!("dns comparison complete: {}", outcome.out_dir.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run dns: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the routing-rule scaling comparison.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_routing(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    rule_scales: &str,
    blocks: usize,
    samples: usize,
    connections: usize,
    concurrencies: &str,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || {
            format!(
                "benchmark-routing-comparison-{stamp}-{}",
                std::process::id()
            )
        },
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::routing::RoutingSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        scales: rule_scales
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        blocks,
        samples,
        connections,
        concurrency: concurrencies
            .split_whitespace()
            .find_map(|word| word.parse().ok())
            .unwrap_or(8),
    };
    if let Err(error) = bench::routing::validate(&suite) {
        eprintln!("bench run routing: {error}");
        return ExitCode::from(2);
    }
    match bench::routing::run(&suite) {
        Ok(outcome) => {
            println!("routing comparison complete: {}", outcome.out_dir.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run routing: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the VLESS-encryption A/B.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_vless(
    repo: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    samples: usize,
    concurrency: usize,
    payload_mib: u64,
    setup_connections: usize,
    setup_concurrency: usize,
    cover_target: &str,
    cover_sni: &str,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-vless-encryption-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::vless::VlessSuite {
        repo: repo.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        samples,
        concurrency,
        payload_mib,
        setup_connections,
        setup_concurrency,
        cover_target: cover_target.to_owned(),
        cover_sni: cover_sni.to_owned(),
    };
    if let Err(error) = bench::vless::validate(&suite) {
        eprintln!("bench run vless-encryption: {error}");
        return ExitCode::from(2);
    }
    match bench::vless::run(&suite) {
        Ok(outcome) => {
            println!(
                "vless encryption comparison complete: {}",
                outcome.out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run vless-encryption: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the Xray interoperability gate.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the gate's command-line parameters, one per flag"
)]
fn run_bench_interop(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    cover_target: &str,
    cover_sni: &str,
    internet_url: Option<&str>,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("test-xray-interop-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::interop::InteropSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        cover_target: cover_target.to_owned(),
        cover_sni: cover_sni.to_owned(),
        internet_url: internet_url.map(str::to_owned),
    };
    if let Err(error) = bench::interop::validate(&suite) {
        eprintln!("bench run xray-interop: {error}");
        return ExitCode::from(2);
    }
    match bench::interop::run(&suite) {
        Ok(report) => {
            println!(
                "Xray interoperability: PASS ({} bytes, internet {})",
                report.local_bytes, report.internet
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run xray-interop: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the no-CCS interoperability gate.
fn run_bench_no_ccs(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("test-openssl-no-ccs-interop-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::no_ccs::NoCcsSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir,
        run_id,
    };
    match bench::no_ccs::run(&suite) {
        Ok(_) => {
            println!("no-CCS interoperability: PASS");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run no-ccs-interop: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the real-socket descriptor-pressure recovery gate.
#[expect(
    clippy::too_many_arguments,
    reason = "the bounded gate inputs are explicit command-line policy"
)]
fn run_bench_pressure(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    nofile_limit: u64,
    max_held: usize,
    storm_connections: usize,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("descriptor-pressure-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics/final")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::pressure::PressureSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        nofile_limit,
        max_held,
        storm_connections,
    };
    if let Err(error) = bench::pressure::validate(&suite) {
        eprintln!("bench run descriptor-pressure: {error}");
        return ExitCode::from(2);
    }
    match bench::pressure::run(&suite) {
        Ok(result) => {
            println!(
                "descriptor-pressure recovery: PASS ({} held, {} storm failures; {})",
                result.successful_held,
                result.storm_failures,
                out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run descriptor-pressure: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the selected side of the shared mixed-traffic soak lifecycle.
#[expect(
    clippy::too_many_arguments,
    reason = "the soak CLI fields map directly to the bounded native plan"
)]
fn run_bench_soak(
    implementation: &str,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    duration_seconds: u64,
    round_sleep_ms: u64,
    minimum_rounds: usize,
    distributed_interval_seconds: u64,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("soak-xray-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks/evidence/releases")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let plan = bench::soak::SoakPlan {
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        duration: std::time::Duration::from_secs(duration_seconds),
        round_sleep: std::time::Duration::from_millis(round_sleep_ms),
        minimum_rounds,
        distributed_interval: std::time::Duration::from_secs(distributed_interval_seconds),
    };
    if let Err(error) = bench::soak::validate(&plan) {
        eprintln!("bench run soak: {error}");
        return ExitCode::from(2);
    }
    if implementation == "rust" {
        match bench::soak::run_rust(&plan) {
            Ok(outcome) => {
                println!(
                    "rust-reality soak: PASS ({} rounds, {} distributed attempts, aggregate PSS/RSS growth {:.1} MiB; {})",
                    outcome.rounds,
                    outcome.distributed_attempts,
                    outcome
                        .resources
                        .pss_growth_mib
                        .unwrap_or(outcome.resources.rss_growth_mib),
                    out_dir.display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bench run soak: {error}");
                ExitCode::FAILURE
            }
        }
    } else {
        match bench::soak::run_xray(&plan) {
            Ok(outcome) => {
                println!(
                    "Xray soak: PASS ({} rounds, RSS growth {:.1} MiB; {})",
                    outcome.rounds,
                    outcome.resources.rss_growth_mib,
                    out_dir.display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bench run soak: {error}");
                ExitCode::FAILURE
            }
        }
    }
}

/// Drives the dynamic TLS first-flight shape suite.
#[expect(
    clippy::too_many_arguments,
    reason = "the suite's CLI inputs map one-for-one to these typed fields"
)]
fn run_bench_tls_shape(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    samples: usize,
    reference: bench::tls_shape_suite::ReferenceOptions,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-tls-shape-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            bench::workspace::cache_root()
                .join("evidence/tls-shape")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::tls_shape_suite::TlsShapeSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        samples,
        reference,
    };
    if let Err(error) = bench::tls_shape_suite::validate(&suite) {
        eprintln!("bench run tls-shape: {error}");
        return ExitCode::from(2);
    }
    match bench::tls_shape_suite::run(&suite) {
        Ok(_) => {
            println!("TLS shape: PASS ({})", out_dir.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run tls-shape: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the IPv6 end-to-end gate.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the IPv6 gate's command-line parameters"
)]
fn run_bench_ipv6(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    phases: &str,
    global_v6: Option<&str>,
    transfer_mib: u64,
    internet_url: Option<&str>,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("validate-ipv6-e2e-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::ipv6::Ipv6Suite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        phases: phases.to_owned(),
        global_ipv6: global_v6.map(str::to_owned),
        transfer_mib,
        internet_url: internet_url.unwrap_or("https://example.com/").to_owned(),
    };
    match bench::ipv6::run(&suite) {
        Ok(summary) => {
            println!(
                "IPv6 validation: PASS ({}; evidence {})",
                summary.to_python_json(),
                out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run ipv6: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The matrix suite's command-line inputs.
struct MatrixArgs<'a> {
    baseline_bin: Option<&'a Path>,
    final_bin: &'a Path,
    xray_bin: &'a Path,
    out_dir: Option<&'a Path>,
    run_id: Option<&'a str>,
    cover_target: &'a str,
    cover_sni: &'a str,
    payloads: &'a str,
    concurrencies: &'a str,
    large_concurrencies: &'a str,
    large_payload_mib: u64,
    samples: usize,
    samples_large: usize,
    integrity_mib: u64,
    cells: &'a str,
    skip: &'a str,
    abba_start: &'a str,
    manage_pipe_pages: bool,
}

/// Splits a comma- or space-separated pattern list.
fn pattern_list(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Drives the three-implementation matrix.
fn run_bench_matrix(repo: &Path, args: &MatrixArgs<'_>) -> ExitCode {
    let Some(baseline_bin) = args.baseline_bin else {
        eprintln!("bench run matrix: --baseline-bin is required");
        return ExitCode::from(2);
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = args.run_id.map_or_else(
        || format!("benchmark-matrix-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = args.out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let numbers = |raw: &str| -> Vec<usize> {
        raw.split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect()
    };
    let suite = bench::matrix::MatrixSuite {
        repo: repo.to_path_buf(),
        baseline_bin: baseline_bin.to_path_buf(),
        final_bin: args.final_bin.to_path_buf(),
        xray_bin: args.xray_bin.to_path_buf(),
        out_dir,
        run_id,
        cover_target: args.cover_target.to_owned(),
        cover_sni: args.cover_sni.to_owned(),
        plan: bench::matrix::CellPlan {
            payloads_mib: args
                .payloads
                .split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect(),
            concurrencies: numbers(args.concurrencies),
            large_concurrencies: numbers(args.large_concurrencies),
            large_payload_mib: args.large_payload_mib,
            include: pattern_list(args.cells),
            exclude: pattern_list(args.skip),
        },
        samples: args.samples,
        samples_large: args.samples_large,
        integrity_mib: args.integrity_mib,
        abba_start: if args.abba_start.is_empty() {
            "baseline".to_owned()
        } else {
            args.abba_start.to_owned()
        },
        manage_pipe_pages: args.manage_pipe_pages,
    };
    if let Err(error) = bench::matrix::validate(&suite) {
        eprintln!("bench run matrix: {error}");
        return ExitCode::from(2);
    }
    match bench::matrix::run(&suite) {
        Ok(outcome) => {
            println!(
                "matrix complete: {} samples, {} invalid -> {}",
                outcome.samples,
                outcome.invalid,
                outcome.out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run matrix: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The paired fallback suite's command-line inputs.
struct FallbackArgs<'a> {
    baseline_bin: Option<&'a Path>,
    candidate_bin: &'a Path,
    baseline_identity: Option<&'a Path>,
    baseline_commit: Option<&'a str>,
    out_dir: Option<&'a Path>,
    run_id: Option<&'a str>,
    blocks: usize,
    samples: usize,
    concurrencies: &'a str,
    payload_mib: u64,
    abba_start: &'a str,
    measure_mode: &'a str,
    relay_splice: bool,
    relay_pipe_pool: bool,
    relay_buffer_kib: u32,
}

/// Drives the paired fallback A/B suite.
fn run_bench_fallback(repo: &Path, args: &FallbackArgs<'_>) -> ExitCode {
    let Some(baseline_bin) = args.baseline_bin else {
        eprintln!("bench run fallback: --baseline-bin is required for a paired comparison");
        return ExitCode::from(2);
    };
    let attribution = match args.measure_mode {
        "perf" => bench::slot::Attribution::Perf(&bench::attribution::REQUIRED_EVENTS),
        "wall" => bench::slot::Attribution::Wall,
        other => {
            eprintln!("bench run fallback: MEASURE_MODE must be perf or wall, got {other}");
            return ExitCode::from(2);
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = args.run_id.map_or_else(
        || format!("benchmark-fallback-ab-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = args.out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::paired::FallbackSuite {
        repo: repo.to_path_buf(),
        baseline_bin: baseline_bin.to_path_buf(),
        candidate_bin: args.candidate_bin.to_path_buf(),
        baseline_identity: args.baseline_identity.map(Path::to_path_buf),
        baseline_commit: args.baseline_commit.map(str::to_owned),
        out_dir,
        run_id,
        blocks: args.blocks,
        samples: args.samples,
        concurrencies: args
            .concurrencies
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        payload_mib: args.payload_mib,
        abba_start: if args.abba_start.is_empty() {
            "baseline".to_owned()
        } else {
            args.abba_start.to_owned()
        },
        relay: bench::relay::RelayPolicy {
            splice: args.relay_splice,
            pipe_pool: args.relay_pipe_pool,
            buffer_kib: args.relay_buffer_kib,
        },
        attribution,
    };
    if let Err(error) = bench::paired::validate_fallback(&suite) {
        eprintln!("bench run fallback: {error}");
        return ExitCode::from(2);
    }
    match bench::paired::run_fallback(&suite) {
        Ok(outcome) => {
            println!(
                "fallback ABBA complete: {} ({} slots)",
                outcome.out_dir.display(),
                outcome.slot_count
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run fallback: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The paired setup-rate suite's command-line inputs.
struct SetupRateArgs<'a> {
    baseline_bin: Option<&'a Path>,
    candidate_bin: &'a Path,
    xray_bin: &'a Path,
    baseline_identity: Option<&'a Path>,
    baseline_commit: Option<&'a str>,
    out_dir: Option<&'a Path>,
    run_id: Option<&'a str>,
    blocks: usize,
    samples: usize,
    connections: usize,
    concurrencies: &'a str,
    abba_start: &'a str,
    baseline_cover_mode: &'a str,
    candidate_cover_mode: &'a str,
    measure_mode: &'a str,
    cover_netem_rtt_ms: Option<u32>,
    profile: Option<perf::hotspot::BenchmarkProfile>,
}

/// Drives the paired baseline-versus-candidate setup-rate suite.
fn run_bench_setup_rate(repo: &Path, args: &SetupRateArgs<'_>) -> ExitCode {
    let Some(baseline_bin) = args.baseline_bin else {
        eprintln!("bench run setup-rate: --baseline-bin is required for a paired comparison");
        return ExitCode::from(2);
    };
    let attribution = match args.measure_mode {
        "perf" => bench::slot::Attribution::Perf(&bench::attribution::REQUIRED_EVENTS),
        "wall" => bench::slot::Attribution::Wall,
        "strace" => bench::slot::Attribution::Strace,
        other => {
            eprintln!(
                "bench run setup-rate: MEASURE_MODE must be perf, strace or wall, got {other}"
            );
            return ExitCode::from(2);
        }
    };
    let (Ok(baseline_cover_mode), Ok(candidate_cover_mode)) = (
        bench::cover::CoverMode::parse(args.baseline_cover_mode),
        bench::cover::CoverMode::parse(args.candidate_cover_mode),
    ) else {
        eprintln!("bench run setup-rate: cover modes must be default, cold, warm or prebuilt");
        return ExitCode::from(2);
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = args.run_id.map_or_else(
        || format!("benchmark-setup-rate-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = args.out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::paired::SetupRateSuite {
        repo: repo.to_path_buf(),
        baseline_bin: baseline_bin.to_path_buf(),
        candidate_bin: args.candidate_bin.to_path_buf(),
        xray_bin: args.xray_bin.to_path_buf(),
        baseline_identity: args.baseline_identity.map(Path::to_path_buf),
        baseline_commit: args.baseline_commit.map(str::to_owned),
        out_dir,
        run_id,
        blocks: args.blocks,
        samples: args.samples,
        connections: args.connections,
        concurrencies: args
            .concurrencies
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        abba_start: if args.abba_start.is_empty() {
            "baseline".to_owned()
        } else {
            args.abba_start.to_owned()
        },
        baseline_cover_mode,
        candidate_cover_mode,
        attribution,
        cover_netem_rtt_ms: args.cover_netem_rtt_ms,
        profile: args.profile.clone(),
    };
    if let Err(error) = bench::paired::validate(&suite) {
        eprintln!("bench run setup-rate: {error}");
        return ExitCode::from(2);
    }
    match bench::paired::run_setup_rate(&suite) {
        Ok(outcome) => {
            println!(
                "setup ABBA complete: {} ({} slots)",
                outcome.out_dir.display(),
                outcome.slot_count
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run setup-rate: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the Xray setup-rate comparator.
///
/// Exit status follows the family contract: 0 when the run published, 1 when a
/// measurement failed, and 2 when the request itself was inadmissible.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_setup_rate_xray(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    blocks: usize,
    samples: usize,
    connections: usize,
    concurrencies: &str,
    abba_start: &str,
    measure_mode: &str,
) -> ExitCode {
    let attribution = match measure_mode {
        "perf" => bench::slot::Attribution::Perf(&bench::attribution::TASK_CLOCK_ONLY),
        "wall" => bench::slot::Attribution::Wall,
        other => {
            eprintln!("bench run: MEASURE_MODE must be perf or wall, got {other}");
            return ExitCode::from(2);
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-setup-rate-xray-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let plan = bench::ab_suites::ComparatorPlan {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        blocks,
        samples,
        connections,
        concurrencies: concurrencies
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        abba_start: if abba_start.is_empty() {
            "rust".to_owned()
        } else {
            abba_start.to_owned()
        },
        attribution,
    };
    if let Err(error) = bench::ab_suites::validate(&plan) {
        eprintln!("bench run setup-rate-xray: {error}");
        return ExitCode::from(2);
    }
    match bench::ab_suites::run_setup_rate_xray(&plan) {
        Ok(outcome) => {
            println!(
                "setup-rate xray comparison complete: {} ({} slots)",
                outcome.out_dir.display(),
                outcome.slot_count
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run setup-rate-xray: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives one slot's setup-rate workload as a child process.
///
/// With `samples == 0` this only warms the path up, exactly as the legacy driver
/// did; a warm-up failure is fatal because measuring a tunnel that never carried
/// traffic would record setup times for a path that does not work.
fn run_bench_workload(
    plan: &bench::workload::SetupRatePlan,
    output: Option<&std::path::Path>,
) -> ExitCode {
    if plan.concurrencies.is_empty() {
        eprintln!("bench workload: at least one concurrency level is required");
        return ExitCode::from(2);
    }
    if plan.samples == 0 {
        return match bench::workload::warm_up(plan.socks_port, plan.origin_port) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench workload: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let rows = match bench::workload::run_slot(plan) {
        Ok(rows) => rows,
        Err(error) => {
            eprintln!("bench workload: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(output) = output else {
        eprintln!("bench workload: --output is required when samples are measured");
        return ExitCode::from(2);
    };
    let document = bench::workload::rows_json(&rows, plan.record_latencies).to_python_json();
    match std::fs::write(output, document) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "bench workload: could not write {}: {error}",
                output.display()
            );
            ExitCode::FAILURE
        }
    }
}

/// Validates the `bench run` parameters and drives the real-path suite.
///
/// Exit codes mirror the legacy contract: 0 when every transfer succeeded, 1
/// when the report completed with failed transfers, 3 when direct egress is
/// unavailable (the gate is NOT RUN), and 2 on a hard setup/process error that
/// prevented a report.
fn run_bench_run(context: &bench::suites::SuiteContext<'_>) -> ExitCode {
    if context.runs == 0 || context.expected_bytes == 0 {
        eprintln!("bench run: runs and bytes must be positive");
        return ExitCode::from(2);
    }
    // The real-path gate requires direct Internet egress: the servers dial the
    // destination themselves. Probe with a tiny download and fail closed with
    // the legacy NOT RUN semantics.
    if let Err(error) = probe_egress() {
        eprintln!(
            "direct Internet egress to speed.cloudflare.com is unavailable; real-path gate NOT RUN ({error})"
        );
        return ExitCode::from(3);
    }
    match bench::suites::run_suite(context) {
        Ok(outcome) => {
            println!(
                "bench run: {} transfers, {} failures -> PASS",
                outcome.samples.len(),
                outcome.report.failures
            );
            ExitCode::SUCCESS
        }
        Err(bench::suites::RunError::Workload(report)) => {
            eprintln!(
                "bench run: {} transfer(s) failed; report records the details",
                report.failures
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("bench run: {error}");
            ExitCode::from(2)
        }
    }
}

/// Drives the loopback concurrent xray suite.
fn run_bench_xray(
    context: &bench::suites::SuiteContext<'_>,
    plan: &bench::loopback::LoopbackPlan,
) -> ExitCode {
    match bench::loopback::run_loopback(context, plan) {
        Ok(outcome) => {
            println!(
                "bench run xray: {} measurements -> PASS",
                outcome.measurements.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run xray: {error}");
            ExitCode::from(2)
        }
    }
}

/// Probes direct egress to the real-path speed endpoint.
///
/// # Errors
///
/// Returns the curl failure text when the probe fails.
fn probe_egress() -> Result<(), String> {
    let mut curl = process::Tool::new("curl");
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
    let outcome = curl
        .args([
            "--fail",
            "--silent",
            "--max-time",
            "30",
            "-o",
            "/dev/null",
            "https://speed.cloudflare.com/__down?bytes=100000",
        ])
        .probe()
        .map_err(|error| error.to_string())?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!("curl exited {:?}", outcome.code))
    }
}

/// Runs the netem Cartesian-product validator.
#[allow(clippy::too_many_arguments)]
fn run_deploy_netem(
    profiles: &Path,
    pool_summaries: &Path,
    output: &Path,
    rtts: &str,
    losses: &str,
    concurrencies: &str,
    samples: i64,
    connections: i64,
    evaluate_performance: bool,
) -> ExitCode {
    if output.exists() {
        eprintln!("deploy netem: output must not exist: {}", output.display());
        return ExitCode::from(2);
    }
    let args = match (
        deploy::netem::parse_i64_list(rtts),
        deploy::netem::parse_f64_list(losses),
        deploy::netem::parse_i64_list(concurrencies),
    ) {
        (Ok(rtts), Ok(losses), Ok(concurrencies)) => deploy::netem::NetemArgs {
            profiles: profiles.to_path_buf(),
            pool_summaries: pool_summaries.to_path_buf(),
            rtts,
            losses,
            concurrencies,
            samples,
            connections,
            evaluate_performance,
        },
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
            eprintln!("deploy netem: {error}");
            return ExitCode::from(2);
        }
    };
    match deploy::netem::validate(&args) {
        Ok(report) => {
            if let Err(error) = std::fs::write(output, &report.json) {
                eprintln!(
                    "deploy netem: could not write {}: {error}",
                    output.display()
                );
                return ExitCode::from(2);
            }
            print!("{}", report.json);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("deploy netem: {error}");
            ExitCode::from(2)
        }
    }
}

fn emit_deploy_json(output: Option<&Path>, json: &str) -> Result<(), String> {
    if let Some(path) = output {
        if path.exists() || path.is_symlink() {
            return Err(format!("output must not already exist: {}", path.display()));
        }
        std::fs::write(path, json)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    } else {
        print!("{json}");
    }
    Ok(())
}

fn run_deploy_inspect(target: DeployTarget, output: Option<&Path>) -> ExitCode {
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy inspect: {error}");
            return ExitCode::from(2);
        }
    };
    let host = topology.host(target.role());
    let mut transport = deploy::remote::SystemTransport;
    match deploy::snapshot::inspect(&mut transport, host) {
        Ok(snapshot) => {
            eprintln!("{}", snapshot.summary_line());
            let json = snapshot.to_json().to_python_json();
            if let Err(error) = emit_deploy_json(output, &json) {
                eprintln!("deploy inspect: {error}");
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("deploy inspect: {error}");
            ExitCode::FAILURE
        }
    }
}

fn build_canary_plan(arguments: CanaryArgs, rollback_on_failure: bool) -> deploy::canary_run::Plan {
    deploy::canary_run::Plan {
        candidate: deploy::canary_run::Candidate {
            commit: arguments.candidate_commit,
            sha256: arguments.candidate_sha256,
            build_id: arguments.candidate_build_id,
            version: arguments.candidate_version,
            target: arguments.candidate_target,
            rustc: arguments.candidate_rustc,
        },
        xray_bin: arguments.xray_bin,
        xray_sha256: arguments.xray_sha256,
        xray_config: arguments.xray_config,
        socks_port: arguments.socks_port,
        line_public_ipv4: arguments.line_public_ipv4,
        small_url: arguments.small_url,
        one_mib_url: arguments.one_mib_url,
        large_url: arguments.large_url,
        upload_url: arguments.upload_url,
        payload_one_mib: arguments.payload_one_mib,
        payload_large: arguments.payload_large,
        out_dir: arguments.out_dir,
        duration_seconds: arguments.duration_seconds,
        sample_interval_seconds: arguments.sample_interval_seconds,
        rollback_on_failure,
    }
}

fn run_canary_plan(arguments: CanaryArgs, output: Option<&Path>) -> ExitCode {
    let plan = build_canary_plan(arguments, true);
    if let Err(error) = plan.validate() {
        eprintln!("deploy canary-plan: {error}");
        return ExitCode::from(2);
    }
    let json = plan.to_json().to_python_json();
    if let Err(error) = emit_deploy_json(output, &json) {
        eprintln!("deploy canary-plan: {error}");
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_canary_live(
    arguments: CanaryArgs,
    mutate_remote: bool,
    rollback_on_failure: bool,
) -> ExitCode {
    if !mutate_remote {
        eprintln!(
            "deploy canary-run: LINE reload and LANDING restart require --mutate-remote; use `deploy canary-plan` for non-live validation"
        );
        return ExitCode::from(2);
    }
    let plan = build_canary_plan(arguments, rollback_on_failure);
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy canary-run: {error}");
            return ExitCode::from(2);
        }
    };
    match deploy::canary_run::run(&plan, &topology) {
        Ok(outcome) => {
            print!("{}", outcome.verdict);
            if outcome.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("deploy canary-run: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_deploy_plan(
    operation: DeployPlanOperation,
    target: DeployTarget,
    snapshot_path: &Path,
    release_id: Option<&str>,
    baseline_binary: Option<&str>,
    baseline_config: Option<&str>,
    binary: Option<&Path>,
    config: Option<&Path>,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
    source_commit: Option<&str>,
    prune_old_releases: bool,
    output: Option<&Path>,
) -> ExitCode {
    let text = match std::fs::read_to_string(snapshot_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "deploy plan: could not read {}: {error}",
                snapshot_path.display()
            );
            return ExitCode::from(2);
        }
    };
    let snapshot = match deploy::snapshot::from_json(&text) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("deploy plan: inadmissible snapshot: {error}");
            return ExitCode::from(2);
        }
    };
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy plan: {error}");
            return ExitCode::from(2);
        }
    };
    let expected_alias = topology.host(target.role()).alias();
    if snapshot.alias != expected_alias {
        eprintln!(
            "deploy plan: snapshot alias {:?} does not match target {:?}",
            snapshot.alias, expected_alias
        );
        return ExitCode::from(2);
    }

    let plan = match operation {
        DeployPlanOperation::Bootstrap => release_id
            .ok_or_else(|| "--release-id is required for bootstrap".to_owned())
            .and_then(|release_id| {
                let baseline_binary = baseline_binary
                    .ok_or_else(|| "--baseline-binary is required for bootstrap".to_owned())?;
                let baseline_config = baseline_config
                    .ok_or_else(|| "--baseline-config is required for bootstrap".to_owned())?;
                deploy::plan::plan_bootstrap(
                    &snapshot,
                    release_id,
                    baseline_binary,
                    baseline_config,
                )
            }),
        DeployPlanOperation::Stage => deploy_artifact(
            operation,
            release_id,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
        )
            .and_then(|artifact| deploy::plan::plan_stage(&snapshot, &artifact)),
        DeployPlanOperation::Cutover => deploy_artifact(
            operation,
            release_id,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
        )
            .and_then(|artifact| deploy::plan::plan_cutover(&snapshot, &artifact)),
        DeployPlanOperation::Rollback => deploy::plan::plan_rollback(&snapshot),
        DeployPlanOperation::Promote => release_id
            .ok_or_else(|| "--release-id is required for promote".to_owned())
            .and_then(|release_id| {
                deploy::plan::plan_promote(&snapshot, release_id, prune_old_releases)
            }),
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deploy plan: {error}");
            return ExitCode::from(2);
        }
    };
    eprint!("{}", plan.describe());
    if deploy::plan::rollback_for(&plan).is_some() {
        eprintln!("  rollback: constructed and required on execution failure");
    }
    let json = plan.to_json().to_python_json();
    if let Err(error) = emit_deploy_json(output, &json) {
        eprintln!("deploy plan: {error}");
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

#[allow(clippy::too_many_arguments)]
fn deploy_artifact(
    operation: DeployPlanOperation,
    release_id: Option<&str>,
    binary: Option<&Path>,
    config: Option<&Path>,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
    source_commit: Option<&str>,
) -> Result<deploy::plan::ArtifactIdentity, String> {
    let required = |value: Option<&str>, name: &str| {
        value
            .map(str::to_owned)
            .ok_or_else(|| format!("--{name} is required for {operation:?}"))
    };
    let path = |value: Option<&Path>, name: &str| {
        value
            .ok_or_else(|| format!("--{name} is required for {operation:?}"))?
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("--{name} must be valid UTF-8"))
    };
    Ok(deploy::plan::ArtifactIdentity {
        release_id: required(release_id, "release-id")?,
        binary_path: path(binary, "binary")?,
        config_path: path(config, "config")?,
        binary_sha256: required(expected_sha256, "expected-sha256")?,
        version: required(expected_version, "expected-version")?,
        source_commit: source_commit.map(str::to_owned),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_deploy_apply(
    repo: &Path,
    operation: DeployPlanOperation,
    target: DeployTarget,
    release_id: Option<&str>,
    baseline_binary: Option<&str>,
    baseline_config: Option<&str>,
    binary: Option<&Path>,
    config: Option<&Path>,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
    source_commit: Option<&str>,
    prune_old_releases: bool,
    mutate_remote: bool,
    output: Option<&Path>,
) -> ExitCode {
    if !mutate_remote {
        eprintln!(
            "deploy apply: remote mutation requires --mutate-remote; use `deploy plan` for a non-mutating transaction"
        );
        return ExitCode::from(2);
    }
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy apply: {error}");
            return ExitCode::from(2);
        }
    };
    let host = topology.host(target.role());
    let mut transport = deploy::remote::SystemTransport;
    let before = match deploy::snapshot::inspect(&mut transport, host) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("deploy apply: pre-mutation inspection failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let artifact = match operation {
        DeployPlanOperation::Stage | DeployPlanOperation::Cutover => match deploy_artifact(
            operation,
            release_id,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
        ) {
            Ok(artifact) => Some(artifact),
            Err(error) => {
                eprintln!("deploy apply: {error}");
                return ExitCode::from(2);
            }
        },
        DeployPlanOperation::Bootstrap
        | DeployPlanOperation::Rollback
        | DeployPlanOperation::Promote => None,
    };
    let plan = match operation {
        DeployPlanOperation::Bootstrap => release_id
            .ok_or_else(|| "--release-id is required for bootstrap".to_owned())
            .and_then(|release_id| {
                let baseline_binary = baseline_binary
                    .ok_or_else(|| "--baseline-binary is required for bootstrap".to_owned())?;
                let baseline_config = baseline_config
                    .ok_or_else(|| "--baseline-config is required for bootstrap".to_owned())?;
                deploy::plan::plan_bootstrap(
                    &before,
                    release_id,
                    baseline_binary,
                    baseline_config,
                )
            }),
        DeployPlanOperation::Stage => deploy::plan::plan_stage(
            &before,
            artifact.as_ref().expect("stage artifact was constructed"),
        ),
        DeployPlanOperation::Cutover => deploy::plan::plan_cutover(
            &before,
            artifact.as_ref().expect("cutover artifact was constructed"),
        ),
        DeployPlanOperation::Rollback => deploy::plan::plan_rollback(&before),
        DeployPlanOperation::Promote => release_id
            .ok_or_else(|| "--release-id is required for promote".to_owned())
            .and_then(|id| deploy::plan::plan_promote(&before, id, prune_old_releases)),
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deploy apply: {error}");
            return ExitCode::from(2);
        }
    };
    eprint!("{}", plan.describe());
    let mut validator = deploy::executor::SystemCandidateValidator;
    let unit_file = (operation == DeployPlanOperation::Bootstrap)
        .then(|| repo.join("deploy/rust-reality-vps.service"));
    match deploy::executor::execute(
        &mut transport,
        &mut validator,
        host,
        &plan,
        &before,
        artifact.as_ref(),
        unit_file.as_deref(),
    ) {
        Ok(report) => {
            let json = report.to_json().to_python_json();
            if let Err(error) = emit_deploy_json(output, &json) {
                eprintln!("deploy apply: transaction succeeded but evidence failed: {error}");
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("deploy apply: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatches a `cargo dev deploy` subcommand.
///
/// The canary evaluator is fail-closed and three-valued, mirroring
/// `cargo dev perf evaluate`: exit 0 on pass, 1 on a real canary failure, and 2
/// when the recorded report could not be admitted at all.
#[allow(clippy::too_many_lines)]
fn run_deploy(repo: &Path, command: DeployCommand) -> ExitCode {
    match command {
        DeployCommand::CanaryPlan { plan, output } => {
            run_canary_plan(plan, output.as_deref())
        }
        DeployCommand::CanaryRun {
            plan,
            mutate_remote,
            rollback_on_failure,
        } => run_canary_live(plan, mutate_remote, rollback_on_failure),
        DeployCommand::Inspect { target, output } => {
            run_deploy_inspect(target, output.as_deref())
        }
        DeployCommand::Plan {
            operation,
            target,
            snapshot,
            release_id,
            baseline_binary,
            baseline_config,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
            prune_old_releases,
            output,
        } => run_deploy_plan(
            operation,
            target,
            &snapshot,
            release_id.as_deref(),
            baseline_binary.as_deref(),
            baseline_config.as_deref(),
            binary.as_deref(),
            config.as_deref(),
            expected_sha256.as_deref(),
            expected_version.as_deref(),
            source_commit.as_deref(),
            prune_old_releases,
            output.as_deref(),
        ),
        DeployCommand::Apply {
            operation,
            target,
            release_id,
            baseline_binary,
            baseline_config,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
            prune_old_releases,
            mutate_remote,
            output,
        } => run_deploy_apply(
            repo,
            operation,
            target,
            release_id.as_deref(),
            baseline_binary.as_deref(),
            baseline_config.as_deref(),
            binary.as_deref(),
            config.as_deref(),
            expected_sha256.as_deref(),
            expected_version.as_deref(),
            source_commit.as_deref(),
            prune_old_releases,
            mutate_remote,
            output.as_deref(),
        ),
        DeployCommand::Netem {
            profiles,
            pool_summaries,
            output,
            rtts,
            losses,
            concurrencies,
            samples,
            connections,
            evaluate_performance,
        } => run_deploy_netem(
            &profiles,
            &pool_summaries,
            &output,
            &rtts,
            &losses,
            &concurrencies,
            samples,
            connections,
            evaluate_performance,
        ),
        DeployCommand::Canary { input, output } => match deploy::canary::evaluate_file(&input) {
            deploy::canary::Outcome::Evaluated { verdict, ok } => {
                if let Some(path) = output
                    && let Err(error) = std::fs::write(&path, &verdict)
                {
                    eprintln!("deploy canary: {error}");
                    return ExitCode::from(2);
                }
                print!("{verdict}");
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            deploy::canary::Outcome::Inadmissible(reason) => {
                eprintln!("canary evaluation failed: {reason}");
                ExitCode::from(2)
            }
        },
    }
}
