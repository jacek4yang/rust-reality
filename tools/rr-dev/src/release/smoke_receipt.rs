//! Collection and failure finalization for packaged executable smoke tests.
#![allow(missing_docs)]

use super::receipt::{Command, Image, Receipt};
use crate::{hash, process::Tool};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub struct Collector {
    pub receipt: Receipt,
    directory: Option<PathBuf>,
    archive: Option<PathBuf>,
    binary: Option<PathBuf>,
}

fn time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "package clock overflow".to_owned())
}

fn image(path: &str) -> Image {
    Image {
        path: path.to_owned(),
        before: None,
        after: None,
    }
}

impl Collector {
    pub fn new(
        tag: &str,
        tier: &str,
        archive: &str,
        runner: Vec<String>,
        assets: &Path,
        directory: Option<&Path>,
    ) -> Result<Self, String> {
        if let Some(directory) = directory {
            if let Some(parent) = directory.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::create_dir(directory)
                .map_err(|error| format!("create fresh package receipt directory: {error}"))?;
        }
        let mut collector = Self {
            receipt: Receipt {
                schema: "rr-package-execution/v1".to_owned(),
                source_commit: rust_reality::BUILD_COMMIT.to_owned(),
                tag: tag.to_owned(),
                tier: tier.to_owned(),
                assets_directory: assets
                    .canonicalize()
                    .unwrap_or_else(|_| assets.to_path_buf())
                    .display()
                    .to_string(),
                output_directory: directory
                    .map(|path| {
                        path.canonicalize()
                            .unwrap_or_else(|_| path.to_path_buf())
                            .display()
                            .to_string()
                    })
                    .unwrap_or_default(),
                archive: image(archive),
                binary: image("rust-reality"),
                harness: image("rr-dev"),
                host_architecture: String::new(),
                host_kernel: String::new(),
                host_boot_id: String::new(),
                host_cpuinfo_sha256: String::new(),
                runner,
                cover_target: String::new(),
                cover_server_name: String::new(),
                commands: Vec::new(),
                primary_error: None,
                finalization_errors: Vec::new(),
            },
            directory: directory.map(Path::to_path_buf),
            archive: None,
            binary: None,
        };
        if let Err(error) = collector.environment() {
            collector.receipt.finalization_errors.push(error);
        }
        Ok(collector)
    }

    fn environment(&mut self) -> Result<(), String> {
        Tool::new("uname")
            .arg("-m")
            .run()
            .map_err(|error| error.to_string())?
            .trimmed_stdout()
            .clone_into(&mut self.receipt.host_architecture);
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| error.to_string())?
            .trim()
            .clone_into(&mut self.receipt.host_kernel);
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?
            .trim()
            .clone_into(&mut self.receipt.host_boot_id);
        let cpuinfo = fs::read("/proc/cpuinfo").map_err(|error| error.to_string())?;
        self.receipt.host_cpuinfo_sha256 = hash::sha256_hex(&cpuinfo);
        // The digest subprocess must observe this process, never its own /proc/self.
        self.receipt.harness.before = Some(super::package::sha256_of(&PathBuf::from(format!(
            "/proc/{}/exe",
            std::process::id()
        )))?);
        if let Some(directory) = &self.directory {
            fs::write(directory.join("cpuinfo.txt"), cpuinfo).map_err(|error| error.to_string())?;
            fs::copy("/proc/self/exe", directory.join("rr-dev"))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub fn bind_archive(&mut self, archive: &Path) -> Result<PathBuf, String> {
        self.receipt.archive.before = Some(super::package::sha256_of(archive)?);
        let selected = self.directory.as_ref().map_or_else(
            || archive.to_path_buf(),
            |directory| directory.join(&self.receipt.archive.path),
        );
        if selected != archive {
            fs::copy(archive, &selected).map_err(|error| error.to_string())?;
        }
        self.archive = Some(selected.clone());
        Ok(selected)
    }

    pub fn retain_fragment(&self, assets: &Path, tier: &str) -> Result<(), String> {
        if let Some(directory) = &self.directory {
            let name = format!("{tier}.tier.json");
            fs::copy(assets.join(&name), directory.join(name))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub fn bind_binary(&mut self, binary: &Path) -> Result<PathBuf, String> {
        self.receipt.binary.before = Some(super::package::sha256_of(binary)?);
        let selected = self.directory.as_ref().map_or_else(
            || binary.to_path_buf(),
            |directory| directory.join("rust-reality"),
        );
        if selected != binary {
            fs::copy(binary, &selected).map_err(|error| error.to_string())?;
        }
        self.binary = Some(selected.clone());
        Ok(selected)
    }

    pub fn run(&mut self, binary: &Path, args: &[&str]) -> Result<String, String> {
        let mut tool = if let Some((program, rest)) = self.receipt.runner.split_first() {
            Tool::new(program)
                .args(rest.iter().cloned())
                .arg(binary.display().to_string())
        } else {
            Tool::new(binary.display().to_string())
        };
        tool = tool.args(args.iter().copied());
        let started = time()?;
        let mut pid = None;
        let mut start_ticks = None;
        let result = tool
            .spawn()
            .map_err(|error| error.to_string())
            .and_then(|child| {
                pid = child.pid();
                start_ticks = pid
                    .and_then(crate::bench::process::proc_starttime)
                    .and_then(|text| text.parse().ok());
                child.wait().map_err(|error| error.to_string())
            });
        let mut command = Command {
            argv: args.iter().map(|value| (*value).to_owned()).collect(),
            pid,
            start_ticks,
            started_unix_ms: started,
            completed_unix_ms: time()?,
            exit_code: None,
            stdout: None,
            stderr: None,
            stdout_sha256: None,
            stderr_sha256: None,
            error: result.as_ref().err().cloned(),
        };
        let secret = args.first() == Some(&"generate");
        if let Ok(outcome) = &result {
            command.exit_code = outcome.code;
            command.stdout_sha256 = Some(hash::sha256_hex(outcome.stdout.as_bytes()));
            command.stderr_sha256 = Some(hash::sha256_hex(outcome.stderr.as_bytes()));
            if !secret {
                command.stdout = Some(outcome.stdout.clone());
                command.stderr = Some(outcome.stderr.clone());
            }
        }
        self.receipt.commands.push(command);
        let outcome = result?;
        if !outcome.success() || pid.is_none() || start_ticks.is_none() {
            return Err(format!(
                "packaged command {args:?} failed or lacked process identity (exit {:?})",
                outcome.code
            ));
        }
        Ok(outcome.stdout)
    }

    pub fn finish<T>(mut self, attempted: Result<T, String>) -> Result<T, String> {
        self.receipt.primary_error = attempted.as_ref().err().cloned();
        let harness = PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        for (image, path) in [
            (&mut self.receipt.archive, self.archive.as_deref()),
            (&mut self.receipt.binary, self.binary.as_deref()),
            (&mut self.receipt.harness, Some(harness.as_path())),
        ] {
            match path
                .ok_or_else(|| format!("{} was not captured", image.path))
                .and_then(super::package::sha256_of)
            {
                Ok(digest) => {
                    image.after = Some(digest);
                    if image.after != image.before {
                        self.receipt
                            .finalization_errors
                            .push(format!("{} changed during smoke execution", image.path));
                    }
                }
                Err(error) => self.receipt.finalization_errors.push(error),
            }
        }
        let retained = if let Some(directory) = &self.directory {
            serde_json::to_vec_pretty(&self.receipt)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    fs::write(directory.join("receipt.json"), bytes)
                        .map_err(|error| error.to_string())
                })
        } else {
            Ok(())
        };
        let mut errors = self.receipt.primary_error.into_iter().collect::<Vec<_>>();
        errors.extend(self.receipt.finalization_errors);
        if let Err(error) = retained {
            errors.push(format!("package receipt finalization: {error}"));
        }
        if errors.is_empty() {
            attempted
        } else {
            Err(errors.join("; finalization: "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_output_is_redacted_and_finalization_preserves_the_primary_failure() {
        let work = super::super::package::tempdir("package-secret-receipt").unwrap();
        let directory = work.path().join("receipt");
        let archive = work.path().join("archive.tar.gz");
        fs::write(&archive, b"archive fixture").unwrap();
        let mut collector = Collector::new(
            "v2.0.1",
            "linux-x86_64-generic",
            "archive.tar.gz",
            Vec::new(),
            work.path(),
            Some(&directory),
        )
        .unwrap();
        collector.bind_archive(&archive).unwrap();
        let binary = collector.bind_binary(Path::new("/bin/echo")).unwrap();
        let generated = collector
            .run(Path::new("/bin/echo"), &["generate", "x25519", "--json"])
            .unwrap();
        assert_eq!(collector.receipt.commands[0].stdout, None);
        assert_eq!(collector.receipt.commands[0].stderr, None);
        assert_eq!(
            collector.receipt.commands[0].stdout_sha256,
            Some(hash::sha256_hex(generated.as_bytes()))
        );
        fs::write(&binary, b"changed binary").unwrap();
        let error = collector
            .finish::<()>(Err("original package failure".to_owned()))
            .unwrap_err();
        assert!(error.starts_with("original package failure; finalization:"));
        let receipt =
            super::super::receipt::parse(&fs::read(directory.join("receipt.json")).unwrap())
                .unwrap();
        assert_eq!(
            receipt.primary_error.as_deref(),
            Some("original package failure")
        );
        assert!(
            receipt
                .finalization_errors
                .iter()
                .any(|error| error.contains("rust-reality changed"))
        );
        assert!(receipt.commands[0].pid.is_some());
        assert!(receipt.commands[0].start_ticks.is_some());
        assert!(
            Collector::new(
                "v2.0.1",
                "linux-x86_64-generic",
                "archive.tar.gz",
                Vec::new(),
                work.path(),
                Some(&directory)
            )
            .is_err()
        );
    }
}
