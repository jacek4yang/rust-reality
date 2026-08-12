use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::config::{FileLogConfig, LogConfig, LogLevel, LogOutput};

const MAX_MANAGED_ROTATIONS: u16 = 64;

/// A bounded admission resource whose exhaustion is safe to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionResource {
    /// Total accepted connections.
    Connections,
    /// Concurrent unauthenticated handshakes.
    Handshakes,
    /// Concurrent cover fallbacks.
    Fallbacks,
    /// Concurrent expensive cryptographic operations.
    CryptoOperations,
    /// Pending and committed replay entries.
    ReplayEntries,
    /// Direct outbound connection attempts.
    DirectConnections,
    /// Process file descriptors admitted against the derived budget.
    FileDescriptors,
}

/// A fixed rejection category that cannot carry credentials or packet contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Admission limit reached.
    ResourceLimit,
    /// Absolute deadline elapsed.
    Timeout,
    /// Authentication failed and fallback was unavailable.
    Authentication,
    /// Protocol input was malformed.
    Protocol,
    /// Selected route could not be completed.
    Outbound,
    /// The accepted socket could not be configured for proxy use.
    ///
    /// This is deliberately distinct from every listener-level category: a
    /// `TCP_NODELAY` failure affects one connection and must never be reported,
    /// or handled, as a listener failure.
    SocketConfiguration,
}

/// Structured operational events whose fields deliberately exclude secrets.
/// One backend's startup capability, with a fixed decline category.
///
/// Neither field can carry a target, an SNI value, or a payload: both are fixed
/// identifiers chosen from closed vocabularies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendStatus {
    /// The backend identifier.
    pub backend: &'static str,
    /// Whether the backend is usable.
    pub available: bool,
    /// The fixed decline category when the backend is unusable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LogEvent {
    /// Process startup began.
    ServerStarting,
    /// A complete validated configuration was published.
    ConfigurationPublished {
        /// Snapshot generation.
        generation: u64,
    },
    /// A listener became ready.
    ListenerStarted {
        /// Validated inbound tag.
        tag: String,
        /// Bound address.
        address: SocketAddr,
    },
    /// A connection was accepted. Emitted only at debug level.
    ConnectionAccepted {
        /// Remote address.
        peer: SocketAddr,
    },
    /// A connection completed. Emitted only at debug level.
    ConnectionClosed {
        /// Remote address.
        peer: SocketAddr,
    },
    /// A connection was rejected without logging raw input or credentials.
    ConnectionRejected {
        /// Remote address.
        peer: SocketAddr,
        /// Fixed safe category.
        reason: RejectionReason,
    },
    /// A bounded resource rejected additional work.
    AdmissionLimited {
        /// Resource category.
        resource: AdmissionResource,
    },
    /// A proposed configuration was rejected. The field is a validator-owned JSON path.
    ConfigurationRejected {
        /// Stable JSON path; never a value from the configuration.
        field: String,
    },
    /// A Handoff landing listener was published with a key-rotation window
    /// still open: retired keys remain accepted.
    ///
    /// Emitted once per listener per published generation (startup and every
    /// reload), never per connection. A lingering retired key silently voids
    /// the forward-secrecy bound promised by the threat model, so the open
    /// window must stay visible until the retired keys are dropped. Counts
    /// only — never key material.
    HandoffRotationWindowOpen {
        /// Validated inbound tag.
        tag: String,
        /// Retired pre-shared keys still accepted.
        previous_pre_shared_keys: usize,
        /// Retired static private keys still accepted.
        previous_private_keys: usize,
    },
    /// One stable capability line per relay backend, emitted once at startup.
    ///
    /// Static capability declines are reported here and never repeated per
    /// connection, so an unavailable backend is loud once rather than silent.
    RelayBackendReport {
        /// Every backend with its fixed availability and decline category.
        backends: Vec<BackendStatus>,
    },
    /// The derived descriptor budget, emitted exactly once at startup.
    ///
    /// Every field is a process-wide integer. None can carry a target, a peer,
    /// or any configuration value.
    DescriptorBudgetReport {
        /// Measured soft `RLIMIT_NOFILE`.
        fd_soft_limit: u64,
        /// Measured hard `RLIMIT_NOFILE`.
        fd_hard_limit: u64,
        /// Descriptors reserved for the process lifetime.
        fd_fixed_reserve: u64,
        /// Descriptors held back as safety headroom.
        fd_safety_headroom: u64,
        /// Units admissible for dynamic work.
        fd_effective_budget: u64,
        /// Whether the configured peak exceeds the derived budget.
        fd_clamped: bool,
        /// The soft limit that would avoid clamping.
        fd_recommended_soft_limit: u64,
    },
    /// A descriptor-pressure state transition.
    ///
    /// Emitted only when the state changes, never per accept, so a sustained
    /// pressure condition costs two log lines rather than one per connection.
    DescriptorPressureChanged {
        /// Fixed state identifier.
        fd_pressure_state: &'static str,
        /// Units reserved at the transition.
        fd_units_in_use: u64,
        /// Total admissible units.
        fd_effective_budget: u64,
    },
    /// The detected machine view and resource-mode decisions, emitted exactly
    /// once at startup when `runtime.resourceMode` is `dedicated`.
    ///
    /// Every field is a machine- or process-wide quantity from a closed
    /// shape. None can carry a target, a peer or a configuration value.
    MachineReport {
        /// The configured resource mode.
        resource_mode: &'static str,
        /// Measured soft `RLIMIT_NOFILE` before any raise.
        fd_soft_limit: u64,
        /// Measured hard `RLIMIT_NOFILE`.
        fd_hard_limit: u64,
        /// The effective soft limit after a dedicated-mode raise attempt.
        fd_effective_soft_limit: u64,
        /// Whether a soft-limit raise was attempted.
        fd_soft_raise_attempted: bool,
        /// Whether the raise took effect.
        fd_soft_limit_raised: bool,
        /// Measured soft `RLIMIT_MEMLOCK`.
        memlock_soft_limit: u64,
        /// Measured hard `RLIMIT_MEMLOCK`.
        memlock_hard_limit: u64,
        /// Logical CPUs visible to the process.
        available_cpus: usize,
        /// Cgroup v2 `cpu.max` quota in microseconds, when set.
        #[serde(skip_serializing_if = "Option::is_none")]
        cpu_quota_us: Option<u64>,
        /// Cgroup v2 `cpu.max` period in microseconds, when detected.
        #[serde(skip_serializing_if = "Option::is_none")]
        cpu_period_us: Option<u64>,
        /// Cgroup v2 `cpuset.cpus.effective`, when detected.
        #[serde(skip_serializing_if = "Option::is_none")]
        cpuset_effective: Option<String>,
        /// Memory quantity source: `cgroup_v2`, `proc_meminfo` or `unavailable`.
        memory_source: &'static str,
        /// Cgroup v2 `memory.current` at detection, when readable.
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_current: Option<u64>,
        /// Cgroup v2 `memory.high`, when set to a finite value.
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_high: Option<u64>,
        /// Cgroup v2 `memory.max`, when set to a finite value.
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_max: Option<u64>,
        /// The effective memory total used for budget derivation.
        memory_total: u64,
    },
    /// A combined resource-pressure state transition.
    ///
    /// Emitted only when the effective state changes, never per sample, so a
    /// sustained condition costs two log lines rather than one per second.
    /// The memory sampler switched measurement sources (e.g. cgroup file
    /// became unreadable and the monitor fell back to RSS).
    MemorySamplerChanged {
        /// The previous measurement source.
        from: &'static str,
        /// The source now in use.
        to: &'static str,
    },
    /// The effective resource-pressure state changed.
    ResourcePressureChanged {
        /// The effective state: the worst of the descriptor and memory
        /// dimensions.
        pressure_state: &'static str,
        /// The descriptor dimension at the transition.
        fd_pressure_state: &'static str,
        /// Sampled memory usage at the transition, when readable.
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_bytes_in_use: Option<u64>,
        /// The memory pressure-enter watermark in effect.
        memory_pressure_enter: u64,
        /// The memory critical-enter watermark in effect.
        memory_critical_enter: u64,
    },
    /// A recoverable listener accept error.
    ///
    /// The raw errno is included because diagnosing the incident this event
    /// exists for required exactly that number, and a errno carries no
    /// connection-specific information.
    AcceptErrorRecovered {
        /// Bound listener address.
        address: SocketAddr,
        /// Fixed error class.
        accept_error_class: &'static str,
        /// Raw operating-system error number, when the error carried one.
        #[serde(skip_serializing_if = "Option::is_none")]
        errno: Option<i32>,
        /// Backoff applied before the next accept attempt.
        accept_backoff_ms: u64,
    },
    /// Bounded per-connection completion counters. Emitted only at debug level.
    ConnectionCompleted {
        /// Session wall-clock duration.
        duration_ms: u64,
        /// Client bytes delivered to the destination.
        uplink_bytes: u64,
        /// Destination bytes delivered to the client.
        downlink_bytes: u64,
        /// Whether the uplink reached an authenticated Direct boundary.
        uplink_direct: bool,
        /// Whether the downlink reached an authenticated Direct boundary.
        downlink_direct: bool,
        /// The backend that ran the raw relay, when one did.
        #[serde(skip_serializing_if = "Option::is_none")]
        relay_backend: Option<&'static str>,
        /// Uplink bytes delivered before the uplink Direct boundary.
        uplink_direct_at_bytes: u64,
        /// Downlink bytes delivered before the downlink Direct boundary.
        downlink_direct_at_bytes: u64,
        /// The backend that moved the uplink's raw bytes, when direct.
        #[serde(skip_serializing_if = "Option::is_none")]
        uplink_backend: Option<&'static str>,
        /// The backend that moved the downlink's raw bytes, when direct.
        #[serde(skip_serializing_if = "Option::is_none")]
        downlink_backend: Option<&'static str>,
        /// Microseconds from the uplink boundary to its raw relay start.
        uplink_handoff_delay_us: u64,
        /// Microseconds from the downlink boundary to its raw relay start.
        downlink_handoff_delay_us: u64,
        /// Server application-record sequence exported to LANDING.
        ///
        /// Present only for a distributed Handoff session. This non-secret
        /// counter lets operators prove whether a cover-shaped fake ticket
        /// consumed sequence zero without exposing keys or packet contents.
        #[serde(skip_serializing_if = "Option::is_none")]
        handoff_server_sequence: Option<u64>,
        /// The raw-relay pipe capacity was downgraded by kernel pipe-page
        /// limits (skipped when false, so normal connections stay quiet).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        pipe_capacity_downgraded: bool,
    },
}

impl LogEvent {
    fn level(&self) -> LogLevel {
        match self {
            Self::ServerStarting
            | Self::ConfigurationPublished { .. }
            | Self::ListenerStarted { .. }
            | Self::RelayBackendReport { .. }
            | Self::DescriptorBudgetReport { .. }
            | Self::MachineReport { .. } => LogLevel::Info,
            Self::ConnectionAccepted { .. }
            | Self::ConnectionClosed { .. }
            | Self::ConnectionCompleted { .. } => LogLevel::Debug,
            Self::ConnectionRejected { .. }
            | Self::AdmissionLimited { .. }
            | Self::ConfigurationRejected { .. }
            | Self::HandoffRotationWindowOpen { .. }
            | Self::DescriptorPressureChanged { .. }
            | Self::ResourcePressureChanged { .. }
            | Self::MemorySamplerChanged { .. }
            | Self::AcceptErrorRecovered { .. } => LogLevel::Warn,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogRecord<'event> {
    timestamp_unix_ms: u128,
    level: LogLevel,
    #[serde(flatten)]
    event: &'event LogEvent,
}

/// Failure to initialize or write a configured log sink.
#[derive(Debug)]
pub enum LogWriteError {
    /// File or standard-error I/O failed.
    Io(io::Error),
    /// JSON event encoding failed.
    Encode(serde_json::Error),
    /// A previous writer panicked while holding the file sink lock.
    Unavailable,
    /// A single encoded event exceeds the configured per-file limit.
    EventTooLarge,
}

impl fmt::Display for LogWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("log sink I/O failed"),
            Self::Encode(_) => formatter.write_str("log event encoding failed"),
            Self::Unavailable => formatter.write_str("log sink is unavailable"),
            Self::EventTooLarge => formatter.write_str("encoded log event exceeds maxBytes"),
        }
    }
}

impl Error for LogWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Encode(source) => Some(source),
            Self::Unavailable | Self::EventTooLarge => None,
        }
    }
}

impl From<io::Error> for LogWriteError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<serde_json::Error> for LogWriteError {
    fn from(source: serde_json::Error) -> Self {
        Self::Encode(source)
    }
}

enum Sink {
    Stderr,
    File(Mutex<RotatingFile>),
}

/// Cloneable, level-filtered logger with a fixed secret-free event vocabulary.
#[derive(Clone)]
pub struct Logger {
    minimum_level: LogLevel,
    sink: Arc<Sink>,
}

impl Logger {
    /// Opens the configured sink and enforces existing file retention immediately.
    ///
    /// `journald` intentionally writes to standard error so systemd owns framing,
    /// metadata, rate limiting, and persistence policy.
    ///
    /// # Errors
    ///
    /// Returns an error if a file sink directory cannot be created, the active file
    /// cannot be opened, or existing rotations cannot be brought within bounds.
    pub fn new(config: &LogConfig) -> Result<Self, LogWriteError> {
        let sink = match (config.output, config.file.as_ref()) {
            (LogOutput::Stderr | LogOutput::Journald, _) => Sink::Stderr,
            (LogOutput::File, Some(file)) => Sink::File(Mutex::new(RotatingFile::open(file)?)),
            (LogOutput::File, None) => {
                return Err(LogWriteError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file log settings are missing",
                )));
            }
        };
        Ok(Self {
            minimum_level: config.level,
            sink: Arc::new(sink),
        })
    }

    /// Emits one structured event if its level passes the configured filter.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or sink I/O fails. Callers should avoid
    /// turning a log failure into a data-path panic.
    pub fn emit(&self, event: &LogEvent) -> Result<(), LogWriteError> {
        if level_rank(event.level()) > level_rank(self.minimum_level) {
            return Ok(());
        }

        let record = LogRecord {
            timestamp_unix_ms: unix_time_ms(),
            level: event.level(),
            event,
        };
        let mut encoded = serde_json::to_vec(&record)?;
        encoded.push(b'\n');
        match self.sink.as_ref() {
            Sink::Stderr => io::stderr().lock().write_all(&encoded).map_err(Into::into),
            Sink::File(file) => file
                .lock()
                .map_err(|_| LogWriteError::Unavailable)?
                .write(&encoded),
        }
    }
}

const fn level_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
    }
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

struct RotatingFile {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    max_bytes: u64,
    max_files: u16,
    max_total_bytes: u64,
}

impl RotatingFile {
    fn open(config: &FileLogConfig) -> Result<Self, LogWriteError> {
        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let file = open_append(&config.path)?;
        let bytes = file.metadata()?.len();
        let mut state = Self {
            path: config.path.clone(),
            file: Some(file),
            bytes,
            max_bytes: config.max_bytes,
            max_files: config.max_files,
            max_total_bytes: config.max_total_bytes,
        };
        state.remove_out_of_range_rotations()?;
        if state.bytes >= state.max_bytes {
            state.rotate()?;
        }
        state.prune_total()?;
        Ok(state)
    }

    fn write(&mut self, encoded: &[u8]) -> Result<(), LogWriteError> {
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| LogWriteError::EventTooLarge)?;
        if encoded_len > self.max_bytes {
            return Err(LogWriteError::EventTooLarge);
        }
        if self.bytes > 0 && self.bytes.saturating_add(encoded_len) > self.max_bytes {
            self.rotate()?;
        }
        self.file
            .as_mut()
            .ok_or(LogWriteError::Unavailable)?
            .write_all(encoded)?;
        self.bytes = self.bytes.saturating_add(encoded_len);
        self.prune_total()
    }

    fn rotate(&mut self) -> Result<(), LogWriteError> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        let rotation_count = self.max_files.saturating_sub(1);
        if rotation_count > 0 {
            let oldest = rotated_path(&self.path, rotation_count);
            remove_file_if_present(&oldest)?;
            for index in (1..rotation_count).rev() {
                let source = rotated_path(&self.path, index);
                let destination = rotated_path(&self.path, index + 1);
                rename_if_present(&source, &destination)?;
            }
            rename_if_present(&self.path, &rotated_path(&self.path, 1))?;
        } else {
            remove_file_if_present(&self.path)?;
        }
        self.file = Some(open_append(&self.path)?);
        self.bytes = 0;
        self.prune_total()
    }

    fn remove_out_of_range_rotations(&self) -> Result<(), LogWriteError> {
        for index in self.max_files..=MAX_MANAGED_ROTATIONS {
            remove_file_if_present(&rotated_path(&self.path, index))?;
        }
        Ok(())
    }

    fn prune_total(&self) -> Result<(), LogWriteError> {
        let mut rotations = Vec::new();
        let mut total = self.bytes;
        for index in 1..self.max_files {
            let path = rotated_path(&self.path, index);
            match fs::metadata(&path) {
                Ok(metadata) => {
                    total = total.saturating_add(metadata.len());
                    rotations.push((path, metadata.len()));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for (path, bytes) in rotations.into_iter().rev() {
            if total <= self.max_total_bytes {
                break;
            }
            remove_file_if_present(&path)?;
            total = total.saturating_sub(bytes);
        }
        Ok(())
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn rotated_path(path: &Path, index: u16) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn rename_if_present(source: &Path, destination: &Path) -> io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::config::{FileLogConfig, LogConfig, LogLevel, LogOutput};

    use super::{LogEvent, Logger};

    static TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn filters_debug_events_at_info_level() {
        let directory = test_directory();
        let path = directory.join("events.log");
        let logger = file_logger(&path, LogLevel::Info, 64 * 1024, 2, 128 * 1024);

        logger
            .emit(&LogEvent::ConnectionAccepted {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 12_345)),
            })
            .expect("filtered event must succeed");
        logger
            .emit(&LogEvent::ServerStarting)
            .expect("info event must be written");

        let contents = fs::read_to_string(&path).expect("active log must be readable");
        assert!(contents.contains("server_starting"));
        assert!(!contents.contains("connection_accepted"));
        cleanup(&directory);
    }

    #[test]
    fn enforces_file_count_and_total_byte_limits() {
        let directory = test_directory();
        let path = directory.join("events.log");
        let logger = file_logger(&path, LogLevel::Debug, 256, 3, 512);

        for port in 10_000..10_020 {
            logger
                .emit(&LogEvent::ConnectionAccepted {
                    peer: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                })
                .expect("event must be written");
        }

        let files: Vec<_> = fs::read_dir(&directory)
            .expect("log directory must be readable")
            .collect::<Result<_, _>>()
            .expect("directory entries must be readable");
        let total: u64 = files
            .iter()
            .map(|entry| entry.metadata().expect("metadata must be readable").len())
            .sum();
        assert!(files.len() <= 3);
        assert!(total <= 512);
        assert!(path.exists());
        cleanup(&directory);
    }

    fn file_logger(
        path: &Path,
        level: LogLevel,
        max_bytes: u64,
        max_files: u16,
        max_total_bytes: u64,
    ) -> Logger {
        Logger::new(&LogConfig {
            level,
            output: LogOutput::File,
            file: Some(FileLogConfig {
                path: path.to_path_buf(),
                max_bytes,
                max_files,
                max_total_bytes,
            }),
        })
        .expect("file logger must initialize")
    }

    fn test_directory() -> PathBuf {
        let sequence = TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rust-reality-log-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique test directory must be created");
        path
    }

    fn cleanup(directory: &Path) {
        fs::remove_dir_all(directory).expect("test directory must be removed");
    }
}
