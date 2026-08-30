//! Process entrypoint: parse the CLI, dispatch, and map errors to exit codes.
//!
//! All CLI model and behavior lives in the [`cli`](rust_reality::cli) module.

use std::{
    io::{self, Write},
    process::ExitCode,
};

use clap::Parser as _;
use rust_reality::cli::{Cli, CliError};

fn main() -> ExitCode {
    match rust_reality::cli::run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Configuration decode/validation failures render as complete
            // compiler-style diagnostics carrying their own `error:` header;
            // every other failure is a single-line message that needs the
            // prefix.
            match error {
                CliError::Config(source) if source.diagnostic().is_some() => {
                    let _ = writeln!(io::stderr().lock(), "{source}");
                }
                _ => {
                    let _ = writeln!(io::stderr().lock(), "error: {error}");
                }
            }
            ExitCode::FAILURE
        }
    }
}
