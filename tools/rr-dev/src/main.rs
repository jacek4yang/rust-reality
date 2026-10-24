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

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;

mod bench;
mod bench_cmd;
mod check;
mod checks;
mod ci;
mod cli;
mod deploy;
mod deploy_cmd;
mod docs;
mod doctor;
mod fuzz;
mod hash;
mod perf;
mod process;
mod release;
mod repo;

use cli::{
    CiCommand, Cli, Command, ConfigCommand, DocsCommand, EnvironmentTool, FuzzCommand, PerfCommand,
    ReleaseCommand, RepoCommand,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let repo = cli.repo.unwrap_or_else(default_repo_root);

    match cli.command {
        Command::Doctor => run_doctor(),
        Command::Perf { command } => run_perf(&repo, command),
        Command::Release { command } => run_release(&repo, command),
        Command::Fuzz { command } => run_fuzz(&repo, command),
        Command::Config { command } => match command {
            ConfigCommand::Schema { output } => match rust_reality::config::node::schema_json() {
                Ok(schema) => {
                    if let Some(path) = output {
                        match std::fs::write(&path, &schema) {
                            Ok(()) => ExitCode::SUCCESS,
                            Err(error) => {
                                eprintln!("config schema: {error}");
                                ExitCode::FAILURE
                            }
                        }
                    } else {
                        print!("{schema}");
                        ExitCode::SUCCESS
                    }
                }
                Err(error) => {
                    eprintln!("config schema: {error}");
                    ExitCode::FAILURE
                }
            },
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
        Command::Bench { command } => bench_cmd::run_bench(&repo, &command),
        Command::Deploy { command } => deploy_cmd::run_deploy(&repo, command),
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
        Command::Ci { command } => run_ci(command),
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

/// Dispatches a `cargo-dev ci` subcommand.
fn run_ci(command: CiCommand) -> ExitCode {
    match command {
        CiCommand::GhaShell { script } => match ci::run_gha_shell(&script) {
            Ok(status) => {
                let code = ci::shell_exit_code(status);
                ExitCode::from(u8::try_from(code).unwrap_or(1))
            }
            Err(error) => {
                eprintln!("ci gha-shell: {error}");
                ExitCode::FAILURE
            }
        },
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
            binary,
            binary_sha256,
            expected_source_commit,
            pid,
            out_dir,
            run_id,
            record_seconds,
            event,
            frequency,
            call_graph,
        } => {
            match perf::hotspot::run(&perf::hotspot::Plan {
                binary,
                binary_sha256,
                expected_source_commit,
                server_pid: pid,
                out_dir,
                run_id,
                record_seconds,
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
        ReleaseCommand::Smoke {
            tag,
            tier,
            assets,
            receipt_dir,
        } => release::smoke::smoke(repo, &tag, &tier, &assets, receipt_dir.as_deref()),
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
