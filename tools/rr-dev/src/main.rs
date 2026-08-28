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

use std::{path::PathBuf, process::ExitCode};

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
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum BenchCommand {
    /// List the benchmark suites and the legacy scripts they supersede.
    List,
    /// Validate the benchmark environment (tools, host lock, workspace, ports).
    Environment,
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
        Command::Bench { command } => run_bench(&command),
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
fn run_bench(command: &BenchCommand) -> ExitCode {
    match command {
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
        } => {
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

/// Dispatches a `cargo dev deploy` subcommand.
///
/// The canary evaluator is fail-closed and three-valued, mirroring
/// `cargo dev perf evaluate`: exit 0 on pass, 1 on a real canary failure, and 2
/// when the recorded report could not be admitted at all.
fn run_deploy(command: DeployCommand) -> ExitCode {
    match command {
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
