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
//! ```

use std::{path::{Path, PathBuf}, process::ExitCode};

use clap::{Parser, Subcommand};

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
    },
    /// Documentation tooling.
    Docs {
        #[command(subcommand)]
        command: DocsCommand,
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
    /// Run a tunnel A/B suite end to end (`real-path`, `xray`, or `vision-direct`).
    Run {
        /// Suite id: `real-path`, `xray`, or `vision-direct`.
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

#[derive(Subcommand)]
enum DocsCommand {
    /// Validate bilingual coverage, local links, stale wording and release headlines.
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let repo = cli.repo.unwrap_or_else(default_repo_root);

    match cli.command {
        Command::Doctor => run_doctor(),
        Command::Perf { command } => run_perf(command),
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
        Command::Deploy { command } => run_deploy(command),
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
        Command::Check { all } => {
            let scope = if all {
                check::Scope::All
            } else {
                check::Scope::Fast
            };
            match check::run(&repo, scope) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("\ncheck failed: {error}");
                    ExitCode::FAILURE
                }
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
fn run_perf(command: PerfCommand) -> ExitCode {
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
        } => {
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
            let out_dir = out_dir.clone().unwrap_or_else(|| {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs());
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(format!(
                        "benchmarks/benchmark-real-path-{stamp}-{}",
                        std::process::id()
                    ))
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
        eprintln!(
            "bench run setup-rate: cover modes must be default, cold, warm or prebuilt"
        );
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
            eprintln!("bench workload: could not write {}: {error}", output.display());
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
                eprintln!("deploy netem: could not write {}: {error}", output.display());
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

/// Dispatches a `cargo dev deploy` subcommand.
///
/// The canary evaluator is fail-closed and three-valued, mirroring
/// `cargo dev perf evaluate`: exit 0 on pass, 1 on a real canary failure, and 2
/// when the recorded report could not be admitted at all.
fn run_deploy(command: DeployCommand) -> ExitCode {
    match command {
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
