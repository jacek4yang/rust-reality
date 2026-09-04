//! The deployment transport boundary.
//!
//! Deployment policy never opens a shell locally. Administrative operations are
//! represented as validated argv vectors and handed to OpenSSH. [`Transport`]
//! makes that boundary replaceable: production uses [`SystemTransport`], while
//! unit and recorded-parity tests provide deterministic replies without touching
//! a host.

use std::path::Path;

use crate::{
    deploy::host::{Host, redact_secrets},
    process::Tool,
};

/// The result of one administrative command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The remote command's exit status (`None` when terminated by signal).
    pub code: Option<i32>,
    /// Captured standard output, redacted before it crosses this boundary.
    pub stdout: String,
    /// Captured standard error, redacted before it crosses this boundary.
    pub stderr: String,
}

impl Reply {
    /// Whether the command exited successfully.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Returns trimmed standard output when the command succeeded.
    ///
    /// # Errors
    ///
    /// Returns a secret-free diagnostic for a non-zero or signalled command.
    pub fn checked_stdout(&self, context: &str) -> Result<&str, String> {
        if self.success() {
            Ok(self.stdout.trim())
        } else {
            Err(format!(
                "{context} failed with status {}{}",
                self.code
                    .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
                if self.stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", self.stderr.trim())
                }
            ))
        }
    }
}

/// Characters the remote login shell would act on rather than pass through.
///
/// `sshd` does not receive an argv. It joins the client's arguments with spaces
/// and hands the result to the remote login shell, which parses it a second
/// time. An element containing any of these is not the string the remote
/// program receives.
const REMOTE_SHELL_ACTIVE: &[char] = &[
    '\\', '\'', '"', '`', '$', ';', '&', '|', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?',
    '~', '#', '!',
];

/// Rejects an argv the remote login shell would rewrite before `exec`.
///
/// This boundary is the only place that knows a second parse happens, so it is
/// the only place that can turn silent corruption into a failure. A `find`
/// format of `%f\n`, written as the Rust literal `"%f\\n"`, arrives at the shell
/// unquoted, loses its backslash, and reaches `find` as `%fn` — a command that
/// succeeds while producing something the caller never asked for.
///
/// # Errors
///
/// Returns a diagnostic naming the offending element and character.
pub fn validate_remote_argv(argv: &[String]) -> Result<(), String> {
    let Some((program, _)) = argv.split_first() else {
        return Err("deployment transport received an empty argv".to_owned());
    };
    if program.is_empty() {
        return Err("deployment transport received an empty remote program".to_owned());
    }
    for (index, element) in argv.iter().enumerate() {
        if element.is_empty() {
            return Err(format!("remote argv element {index} is empty"));
        }
        if let Some(character) = element
            .chars()
            .find(|c| c.is_whitespace() || c.is_control() || REMOTE_SHELL_ACTIVE.contains(c))
        {
            return Err(format!(
                "remote argv element {index} contains {character:?}, which the remote login \
                 shell would reinterpret: {element:?}"
            ));
        }
    }
    Ok(())
}

/// Administrative operations required by the deployment executor.
pub trait Transport {
    /// Runs one command through the host's ordinary SSH identity.
    ///
    /// Validation lives here, in the provided method, so no implementation and
    /// no call site can reach a host with an argv the remote shell would
    /// rewrite. Implementations provide [`Transport::dispatch`].
    ///
    /// # Errors
    ///
    /// Returns the transport's own failure, or a rejected argv.
    fn run(&mut self, host: &Host, privileged: bool, argv: &[String]) -> Result<Reply, String> {
        validate_remote_argv(argv)?;
        self.dispatch(host, privileged, argv)
    }

    /// Executes an argv that [`Transport::run`] has already validated.
    ///
    /// # Errors
    ///
    /// Returns the transport's own failure.
    fn dispatch(&mut self, host: &Host, privileged: bool, argv: &[String])
    -> Result<Reply, String>;

    /// Copies one local file into a non-privileged remote staging path.
    ///
    /// # Errors
    ///
    /// Returns the transport's own failure, or an unsafe staging path.
    fn copy_to(&mut self, host: &Host, local: &Path, remote: &str) -> Result<(), String>;
}

/// The real OpenSSH transport.
#[derive(Debug, Default)]
pub struct SystemTransport;

impl SystemTransport {
    fn invoke(argv: &[String]) -> Result<Reply, String> {
        let Some((program, arguments)) = argv.split_first() else {
            return Err("deployment transport received an empty argv".to_owned());
        };
        let outcome = Tool::new(program)
            .args(arguments.iter().cloned())
            .probe()
            .map_err(|error| error.to_string())?;
        Ok(Reply {
            code: outcome.code,
            stdout: redact_secrets(&outcome.stdout),
            stderr: redact_secrets(&outcome.stderr),
        })
    }
}

impl Transport for SystemTransport {
    fn dispatch(
        &mut self,
        host: &Host,
        privileged: bool,
        argv: &[String],
    ) -> Result<Reply, String> {
        let command = if privileged {
            host.ssh_sudo_argv(argv)
        } else {
            host.ssh_argv(argv)
        };
        Self::invoke(&command)
    }

    fn copy_to(&mut self, host: &Host, local: &Path, remote: &str) -> Result<(), String> {
        if !remote.starts_with("/tmp/rust-reality-deploy.")
            || remote.chars().any(char::is_whitespace)
        {
            return Err(format!("refusing unsafe remote staging path {remote:?}"));
        }
        let target = format!("{}:{remote}", host.alias());
        let reply = Self::invoke(&[
            "scp".to_owned(),
            "-q".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "ConnectTimeout=10".to_owned(),
            local.display().to_string(),
            target,
        ])?;
        reply.checked_stdout("scp deployment artifact")?;
        Ok(())
    }
}

/// Runs an SSH command and requires success.
///
/// # Errors
///
/// Returns transport failures or the command's secret-free non-zero diagnostic.
pub fn checked(
    transport: &mut impl Transport,
    host: &Host,
    privileged: bool,
    argv: &[String],
    context: &str,
) -> Result<String, String> {
    transport
        .run(host, privileged, argv)?
        .checked_stdout(context)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::host::HostRole;

    #[test]
    fn failed_replies_are_contextual_and_secret_free() {
        let reply = Reply {
            code: Some(23),
            stdout: String::new(),
            stderr: "permission denied".to_owned(),
        };
        let error = reply.checked_stdout("inspect service").unwrap_err();
        assert!(error.contains("inspect service"), "{error}");
        assert!(error.contains("23"), "{error}");
    }

    #[test]
    fn system_copy_rejects_paths_outside_the_owned_staging_prefix() {
        let host = Host::new(HostRole::Line, "line", "rr.service").unwrap();
        let error = SystemTransport
            .copy_to(&host, Path::new("/tmp/candidate"), "/etc/passwd")
            .unwrap_err();
        assert!(error.contains("unsafe remote staging"), "{error}");
    }

    #[test]
    fn ordinary_administrative_argv_is_accepted() {
        for argv in [
            vec![
                "systemctl",
                "show",
                "rust-reality.service",
                "-p",
                "MainPID",
                "--value",
            ],
            vec![
                "find",
                "/opt/rust-reality/releases",
                "-mindepth",
                "1",
                "-maxdepth",
                "1",
            ],
            vec![
                "install",
                "-m",
                "0640",
                "-o",
                "root",
                "-g",
                "rust-reality",
                "/tmp/a",
                "/etc/b",
            ],
            vec![
                "journalctl",
                "-u",
                "rust-reality.service",
                "--since",
                "@1788495754",
            ],
            vec![
                "rm",
                "-rf",
                "--",
                "/opt/rust-reality/releases/v1.9.0-official",
            ],
        ] {
            let owned: Vec<String> = argv.iter().map(|value| (*value).to_owned()).collect();
            validate_remote_argv(&owned).expect("administrative argv should be accepted");
        }
    }

    #[test]
    fn a_backslash_escape_is_rejected_before_it_reaches_a_host() {
        let argv = [
            "find".to_owned(),
            "/proc/1/fd".to_owned(),
            "-printf".to_owned(),
            "%f\\n".to_owned(),
        ];
        let error = validate_remote_argv(&argv).unwrap_err();
        assert!(error.contains("element 3"), "{error}");
        assert!(error.contains("reinterpret"), "{error}");
    }

    #[test]
    fn shell_active_characters_and_blank_elements_are_rejected() {
        for element in [
            "a b",
            "$HOME",
            "one;two",
            "glob*",
            "quote'd",
            "`sub`",
            "new\nline",
            "",
        ] {
            let argv = ["echo".to_owned(), element.to_owned()];
            assert!(
                validate_remote_argv(&argv).is_err(),
                "{element:?} should be rejected"
            );
        }
        assert!(validate_remote_argv(&[]).is_err());
    }
}
