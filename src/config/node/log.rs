//! Logging destination and retention.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Where log events go and how much is kept.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogConfig {
    /// Lowest severity emitted. Absent means [`LogLevel::Info`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,
    /// Destination. Absent means [`LogOutput::Stderr`], which systemd captures
    /// into the journal without further configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<LogOutput>,
    /// Rotation and retention limits. Required by, and only meaningful for,
    /// [`LogOutput::File`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileLogConfig>,
}

impl LogConfig {
    /// The severity floor, applying the default.
    #[must_use]
    pub fn level(&self) -> LogLevel {
        self.level.unwrap_or_default()
    }

    /// The destination, applying the default.
    #[must_use]
    pub fn output(&self) -> LogOutput {
        self.output.unwrap_or_default()
    }
}

/// Emitted severities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Startup and fatal errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Normal operational messages.
    #[default]
    Info,
    /// Diagnostic messages. Never includes configuration values or keys.
    Debug,
}

impl LogLevel {
    /// The stable name used in configuration and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

/// Log destinations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Process standard error.
    #[default]
    Stderr,
    /// Standard error, formatted for capture by systemd-journald.
    Journald,
    /// A size-bounded rotating file set described by `log.file`.
    File,
    /// No sink: every event is dropped before any encoding or I/O.
    None,
}

impl LogOutput {
    /// The stable name used in configuration and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stderr => "stderr",
            Self::Journald => "journald",
            Self::File => "file",
            Self::None => "none",
        }
    }
}

/// Rotation and retention for file logging.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileLogConfig {
    /// Active log path.
    pub path: PathBuf,
    /// Rotate before one file exceeds this size. Absent means 64 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Largest number of active and rotated files. Absent means 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files: Option<u16>,
    /// Largest combined size across every retained file. Absent means the
    /// product of `maxBytes` and `maxFiles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_bytes: Option<u64>,
}

/// The default rotation size for one log file, in bytes.
pub const DEFAULT_LOG_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The default number of retained log files.
pub const DEFAULT_LOG_MAX_FILES: u16 = 8;

impl FileLogConfig {
    /// The per-file rotation size, applying the default.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.unwrap_or(DEFAULT_LOG_MAX_BYTES)
    }

    /// The retained file count, applying the default.
    #[must_use]
    pub fn max_files(&self) -> u16 {
        self.max_files.unwrap_or(DEFAULT_LOG_MAX_FILES)
    }

    /// The combined retention ceiling, applying the derived default.
    #[must_use]
    pub fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
            .unwrap_or_else(|| self.max_bytes().saturating_mul(u64::from(self.max_files())))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_MAX_FILES, FileLogConfig, LogConfig, LogLevel, LogOutput,
    };

    #[test]
    fn an_empty_log_block_logs_info_to_stderr() {
        let log: LogConfig = serde_json::from_str("{}").expect("log must decode");

        assert_eq!(log.level(), LogLevel::Info);
        assert_eq!(log.output(), LogOutput::Stderr);
        assert!(log.file.is_none());
    }

    #[test]
    fn file_retention_derives_the_total_from_the_per_file_bounds() {
        let file: FileLogConfig =
            serde_json::from_str(r#"{"path":"/var/log/rr.log"}"#).expect("file log must decode");

        assert_eq!(file.max_bytes(), DEFAULT_LOG_MAX_BYTES);
        assert_eq!(file.max_files(), DEFAULT_LOG_MAX_FILES);
        assert_eq!(
            file.max_total_bytes(),
            DEFAULT_LOG_MAX_BYTES * u64::from(DEFAULT_LOG_MAX_FILES)
        );

        let pinned: FileLogConfig =
            serde_json::from_str(r#"{"path":"/var/log/rr.log","maxBytes":1024,"maxFiles":4}"#)
                .expect("file log must decode");
        assert_eq!(pinned.max_total_bytes(), 4096);
    }

    #[test]
    fn an_explicit_total_wins_over_the_derived_one() {
        let file: FileLogConfig = serde_json::from_str(
            r#"{"path":"/var/log/rr.log","maxBytes":1024,"maxFiles":4,"maxTotalBytes":2048}"#,
        )
        .expect("file log must decode");

        assert_eq!(file.max_total_bytes(), 2048);
    }

    #[test]
    fn a_file_sink_requires_a_path() {
        assert!(serde_json::from_str::<FileLogConfig>(r#"{"maxBytes":1024}"#).is_err());
    }
}
