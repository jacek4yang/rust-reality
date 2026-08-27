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

mod check;
mod docs;
mod doctor;
// The evaluator core lands before the evidence-loading layer that will call it, so
// nothing outside its own tests uses it yet. `expect` rather than `allow`: this
// becomes a hard error the moment `perf evaluate` is wired up, so the staging
// annotation cannot outlive the staging.
#[expect(
    dead_code,
    reason = "pure statistical core; the manifest/pairing layer and `perf evaluate` land next"
)]
mod perf;
mod process;

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
