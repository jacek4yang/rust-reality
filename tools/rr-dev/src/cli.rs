//! Clap CLI surface for `rr-dev`.
//!
//! Argument and subcommand definitions live here so `main.rs` can own dispatch
//! and command execution without carrying ~1k lines of derive boilerplate.
//! Behavior and flag names are intentionally unchanged.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use super::{bench, check, deploy};

/// Development control plane for the rust-reality repository.
#[derive(Parser)]
#[command(name = "rr-dev", version, about, long_about = None)]
pub(crate) struct Cli {
    /// Repository root. Defaults to the checkout containing this crate.
    #[arg(long, global = true)]
    pub(crate) repo: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
// A clap subcommand enum is a parsed command line, constructed once per process.
// Its variants are inherently uneven in size and boxing them would only obscure
// the derive.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
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
    /// CI helpers (Actions shell parity; no repository Python scripts).
    Ci {
        #[command(subcommand)]
        command: CiCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum DeployCommand {
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
pub(crate) struct CanaryArgs {
    /// Native LINE inventory saved before candidate cutover.
    #[arg(long)]
    pub(crate) line_baseline: PathBuf,
    /// Native LANDING inventory saved before candidate cutover.
    #[arg(long)]
    pub(crate) landing_baseline: PathBuf,
    /// LANDING origin access JSONL with per-request SHA-256 receipts.
    #[arg(long)]
    pub(crate) origin_access_log: String,
    /// Separately staged rust-reality-canary-<name>.service on LINE.
    #[arg(long)]
    pub(crate) supplemental_line_service: Option<String>,
    /// Sole loopback listener of the supplemental service.
    #[arg(long)]
    pub(crate) supplemental_line_port: Option<u16>,
    /// Second SOCKS inbound in the Xray config, routed through public LINE.
    #[arg(long)]
    pub(crate) public_socks_port: Option<u16>,
    /// Reference download URL through unchanged public LINE.
    #[arg(long)]
    pub(crate) public_url: Option<String>,
    /// Independently retained bytes of the public-path reference download.
    #[arg(long)]
    pub(crate) public_payload: Option<PathBuf>,
    /// Exact stock Xray binary.
    #[arg(long)]
    pub(crate) xray_bin: PathBuf,
    /// Required lowercase Xray SHA-256.
    #[arg(long)]
    pub(crate) xray_sha256: String,
    /// Xray config containing the loopback SOCKS inbound.
    #[arg(long)]
    pub(crate) xray_config: PathBuf,
    /// Loopback SOCKS port.
    #[arg(long)]
    pub(crate) socks_port: u16,
    /// LINE public IPv4 used for LANDING firewall validation.
    #[arg(long)]
    pub(crate) line_public_ipv4: std::net::Ipv4Addr,
    /// Small URL used for active traffic.
    #[arg(long)]
    pub(crate) small_url: String,
    /// Exact one-MiB download URL.
    #[arg(long)]
    pub(crate) one_mib_url: String,
    /// Exact large download URL.
    #[arg(long)]
    pub(crate) large_url: String,
    /// Upload endpoint.
    #[arg(long)]
    pub(crate) upload_url: String,
    /// Local exact one-MiB reference payload.
    #[arg(long)]
    pub(crate) payload_one_mib: PathBuf,
    /// Local exact large reference payload.
    #[arg(long)]
    pub(crate) payload_large: PathBuf,
    /// New durable evidence directory the live run creates.
    #[arg(long)]
    pub(crate) out_dir: PathBuf,
    /// Full source commit of the candidate on both hosts.
    #[arg(long)]
    pub(crate) candidate_commit: String,
    /// Exact candidate SHA-256.
    #[arg(long)]
    pub(crate) candidate_sha256: String,
    /// Candidate ELF build id.
    #[arg(long)]
    pub(crate) candidate_build_id: String,
    /// Candidate product version.
    #[arg(long)]
    pub(crate) candidate_version: String,
    /// Candidate target triple.
    #[arg(long)]
    pub(crate) candidate_target: String,
    /// Candidate compiler identity.
    #[arg(long)]
    pub(crate) candidate_rustc: String,
    /// Active canary seconds.
    #[arg(long, default_value_t = 600)]
    pub(crate) duration_seconds: u64,
    /// Resource sample interval seconds.
    #[arg(long, default_value_t = 5)]
    pub(crate) sample_interval_seconds: u64,
}

/// One of the two fixed deployment roles.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum DeployTarget {
    /// Public LINE entry host.
    Line,
    /// Downstream LANDING host.
    Landing,
}

impl DeployTarget {
    pub(crate) const fn role(self) -> deploy::host::HostRole {
        match self {
            Self::Line => deploy::host::HostRole::Line,
            Self::Landing => deploy::host::HostRole::Landing,
        }
    }
}

/// A transaction that can be derived without contacting a live host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DeployPlanOperation {
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
pub(crate) enum BenchCommand {
    /// Execute the fixed stability workload in the owned local KVM fixture.
    StabilityRun(bench::stability::campaign::Plan),
    /// Prove NXR or Handoff UDP leaves the LANDING guest, not LINE.
    StabilityUdpGuest(bench::stability::udp_guest::Plan),
    /// Execute and retain a required check for an existing frozen campaign.
    StabilityCheck(bench::stability::qualification::Plan),
    /// Verify and bind one retained native package smoke receipt.
    StabilityBindPackage(bench::stability::package_bind::Plan),
    /// Owned-fixture child: execute the fixed guest campaign schedule.
    #[command(hide = true)]
    StabilityGuest(bench::stability::guest::Plan),
    /// Verify boot/identity of the owned KVM fixture, then stop those guests.
    /// This preflight does not run or pass candidate qualification.
    StabilityFixture {
        /// Preserved three-guest fixture directory supplied by the operator.
        #[arg(long)]
        fixture: PathBuf,
        /// Fresh directory for launch, boot, serial and final-identity receipts.
        #[arg(long)]
        output: PathBuf,
        /// Use the required 1-vCPU/1-GiB LANDING profile.
        #[arg(long)]
        constrained: bool,
    },
    /// Collect a raw, process-bound Linux observation inside an owned fixture.
    StabilityObserve {
        /// Exact local PID selected by the fixture controller.
        #[arg(long)]
        pid: u32,
        /// Full debug log of that process.
        #[arg(long)]
        log: PathBuf,
    },
    /// Evaluate a frozen stability evidence bundle offline.
    StabilityEvaluate {
        /// Strict evidence JSON; referenced objects are relative to its directory.
        #[arg(long)]
        evidence: PathBuf,
    },
    /// Minutes-scale single-fault stability reproduction (no four-cell QEMU).
    StabilityRepro(bench::stability::repro::Plan),
    /// Merge per-cell `stability-run --cell` outputs into one identity-bound bundle.
    StabilityMergeCells(bench::stability::merge::Plan),
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
        /// Balanced ABBA blocks of four slots (setup-rate suites). The default is
        /// the count below which the block bootstrap resolves nothing; lower it
        /// only for a characterization run whose numbers nothing will cite.
        #[arg(long, default_value_t = bench::aggregate::RESOLVING_BLOCKS)]
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
        /// `perf` attributes server CPU, `schedstat` attributes it without
        /// `perf` or `sudo`, `strace` counts receive syscalls, and `wall`
        /// records rates only.
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
pub(crate) enum ConfigCommand {
    /// Render the JSON Schema of the current configuration.
    ///
    /// Derived from the model types, so it cannot drift from what the binary
    /// accepts. Editors and CI consume it; the release attaches it as an
    /// asset. The running binary remains the final authority through
    /// `rust-reality check`.
    Schema {
        /// Optional path to write the schema to; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
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
pub(crate) enum FuzzCommand {
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
pub(crate) enum ReleaseCommand {
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
        /// Retain a secret-free execution receipt and bound artifacts in a fresh directory.
        #[arg(long)]
        receipt_dir: Option<PathBuf>,
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
pub(crate) enum PerfCommand {
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
    /// Capture an identity-bound hotspot profile from an already-running,
    /// exactly identified server.
    Hotspot {
        /// Exact rust-reality binary to archive and measure.
        #[arg(long)]
        binary: PathBuf,
        /// Required lowercase-hex SHA-256 of the binary.
        #[arg(long)]
        binary_sha256: String,
        /// Required source commit embedded in the binary.
        #[arg(long)]
        expected_source_commit: String,
        /// PID of the exactly identified rust-reality server to profile.
        #[arg(long)]
        pid: u32,
        /// New absolute evidence directory.
        #[arg(long)]
        out_dir: PathBuf,
        /// Stable run identifier written into the publication marker.
        #[arg(long)]
        run_id: String,
        /// Maximum seconds spent recording.
        #[arg(long, default_value_t = 35)]
        record_seconds: u64,
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
pub(crate) enum EnvironmentTool {
    /// `perf stat`.
    Stat,
    /// `perf c2c`.
    C2c,
}

#[derive(Clone, Copy, clap::ValueEnum, Subcommand)]
pub(crate) enum DocsCommand {
    /// Validate bilingual coverage, local links, stale wording and release headlines.
    Check,
}

#[derive(Subcommand)]
pub(crate) enum RepoCommand {
    /// Validate the tracked tree against repository-layout policy.
    Check,
}

#[derive(Subcommand)]
pub(crate) enum CiCommand {
    /// Run one Actions-style script with bash `-e`/`pipefail` (ADR 0044).
    GhaShell {
        /// Path to the temporary Actions `run` script (`{0}`).
        script: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_command_builds() {
        // Ensures the extracted clap graph still constructs (flag/type wiring).
        let _ = Cli::command();
    }
}
