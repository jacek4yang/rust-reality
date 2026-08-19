//! Bounded, host-local configuration autotuning.
//!
//! Autotuning deliberately changes only resource and relay policy. Listener
//! addresses, routing, credentials, timeouts, and logging remain operator
//! decisions. Every selected value is returned with the measurements that
//! produced it, so an automatically generated configuration is auditable.

use std::{
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    hint::black_box,
    io::{self, Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    benchmark::{BenchmarkError, BenchmarkOptions, BenchmarkReport, run_benchmarks},
    config::{Config, ConfigError, PolicyConfig, ResourceMode, validate_config},
    runtime::{
        machine::MachineReport,
        plan::{MachineCapabilities, Probes, SafetyLimits, StartupPlan},
    },
};

pub use crate::runtime::plan::NetworkProbe;

const MEBIBYTE: u64 = 1024 * 1024;
const STORAGE_BLOCK_BYTES: usize = 1024 * 1024;
const NETWORK_BLOCK_BYTES: usize = 64 * 1024;
const NETWORK_ROUND_TRIPS: usize = 128;

/// Bounds for one host-local autotuning pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutotuneOptions {
    /// Total measured duration assigned to each protocol benchmark case.
    pub benchmark_duration: Duration,
    /// Warm-up duration before each protocol benchmark case.
    pub benchmark_warmup: Duration,
    /// Bytes written and then read in the scratch-directory probe.
    pub storage_bytes: u64,
    /// Bytes sent in each direction through the loopback TCP probe.
    pub network_bytes: u64,
    /// Directory used for the temporary storage probe file.
    pub scratch_directory: PathBuf,
    /// Declare that the process owns the host or its cgroup.
    pub dedicated: bool,
}

impl Default for AutotuneOptions {
    fn default() -> Self {
        Self {
            benchmark_duration: Duration::from_millis(900),
            benchmark_warmup: Duration::from_millis(100),
            storage_bytes: 32 * MEBIBYTE,
            network_bytes: 32 * MEBIBYTE,
            scratch_directory: std::env::temp_dir(),
            dedicated: false,
        }
    }
}

/// A configuration and the complete evidence used to tune it.
#[derive(Debug)]
pub struct AutotunedConfig {
    config: Config,
    report: AutotuneReport,
}

impl AutotunedConfig {
    /// Returns the validated tuned configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the measurements and selected values.
    #[must_use]
    pub const fn report(&self) -> &AutotuneReport {
        &self.report
    }

    /// Separates the configuration and report for independent persistence.
    #[must_use]
    pub fn into_parts(self) -> (Config, AutotuneReport) {
        (self.config, self.report)
    }
}

/// Machine-readable evidence from one autotuning pass.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutotuneReport {
    /// Version of this report contract.
    pub schema_version: u8,
    /// Package version that made the decision.
    pub package_version: &'static str,
    /// Effective resource mode in the emitted configuration.
    pub resource_mode: &'static str,
    /// Kernel, cgroup, descriptor, CPU, and memory observations.
    pub machine: AutotuneMachine,
    /// In-process protocol hot-path measurements.
    pub protocol: BenchmarkReport,
    /// Sequential scratch-directory read/write measurements.
    pub storage: StorageProbe,
    /// TCP loopback latency and directional throughput measurements.
    pub network: NetworkProbe,
    /// The complete selected policy written to the output configuration.
    pub selected_policy: PolicyConfig,
}

/// Resource inputs used by the policy derivation.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutotuneMachine {
    /// Logical CPUs visible through process affinity.
    pub logical_cpus: usize,
    /// CPU count after applying a finite cgroup quota.
    pub effective_cpus: usize,
    /// Inherited soft descriptor limit.
    pub fd_soft_limit: u64,
    /// Inherited hard descriptor limit.
    pub fd_hard_limit: u64,
    /// Memory source selected by host detection.
    pub memory_source: &'static str,
    /// Effective memory ceiling, or zero when unavailable.
    pub memory_total_bytes: u64,
    /// Current cgroup memory usage when available.
    pub memory_current_bytes: Option<u64>,
    /// Finite cgroup CPU quota when available.
    pub cpu_quota_microseconds: Option<u64>,
    /// Cgroup CPU quota period when available.
    pub cpu_period_microseconds: Option<u64>,
}

impl AutotuneMachine {
    fn from_capabilities(capabilities: &MachineCapabilities) -> Self {
        Self {
            logical_cpus: capabilities.logical_cpus,
            effective_cpus: capabilities.effective_cpus,
            fd_soft_limit: capabilities.fd_soft_limit,
            fd_hard_limit: capabilities.fd_hard_limit,
            memory_source: capabilities.memory_source,
            memory_total_bytes: capabilities.memory_total_bytes,
            memory_current_bytes: capabilities.memory_current_bytes,
            cpu_quota_microseconds: capabilities.cpu_quota_microseconds,
            cpu_period_microseconds: capabilities.cpu_period_microseconds,
        }
    }
}

/// Sequential scratch-directory I/O result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProbe {
    /// Bytes transferred in each direction.
    pub bytes_per_direction: u64,
    /// Write throughput including `sync_data` completion.
    pub write_mebibytes_per_second: f64,
    /// Sequential read throughput.
    pub read_mebibytes_per_second: f64,
}

/// Autotuning failed without publishing a partial configuration.
#[derive(Debug)]
pub enum AutotuneError {
    /// Protocol benchmark setup or execution failed.
    Benchmark(BenchmarkError),
    /// A host-local I/O probe failed.
    Io {
        /// Stable operation label with no configuration secrets.
        operation: &'static str,
        /// Operating-system error.
        source: io::Error,
    },
    /// A probe worker panicked.
    WorkerPanic,
    /// Bounds were unusable.
    InvalidOptions(&'static str),
    /// The derived configuration violated a production invariant.
    Config(ConfigError),
}

impl fmt::Display for AutotuneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Benchmark(source) => source.fmt(formatter),
            Self::Io { operation, .. } => write!(formatter, "autotune {operation} probe failed"),
            Self::WorkerPanic => formatter.write_str("autotune loopback worker panicked"),
            Self::InvalidOptions(message) => {
                write!(formatter, "invalid autotune options: {message}")
            }
            Self::Config(source) => source.fmt(formatter),
        }
    }
}

impl Error for AutotuneError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Benchmark(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Config(source) => Some(source),
            Self::WorkerPanic | Self::InvalidOptions(_) => None,
        }
    }
}

impl From<BenchmarkError> for AutotuneError {
    fn from(source: BenchmarkError) -> Self {
        Self::Benchmark(source)
    }
}

impl From<ConfigError> for AutotuneError {
    fn from(source: ConfigError) -> Self {
        Self::Config(source)
    }
}

/// Runs bounded host-local probes and returns a validated tuned copy.
///
/// # Errors
///
/// Returns an error when an option is outside its safety bound, a benchmark
/// or I/O probe fails, or the derived policy does not validate. The input is
/// never modified.
pub fn autotune_config(
    source: &Config,
    options: &AutotuneOptions,
) -> Result<AutotunedConfig, AutotuneError> {
    validate_options(options)?;
    let machine_report = MachineReport::detect();
    let capabilities = MachineCapabilities::from_report(&machine_report);
    let machine = AutotuneMachine::from_capabilities(&capabilities);
    let protocol = run_benchmarks(BenchmarkOptions {
        duration: options.benchmark_duration,
        warmup: options.benchmark_warmup,
    })?;
    let storage = probe_storage(&options.scratch_directory, options.storage_bytes)?;
    let network = probe_loopback(options.network_bytes)?;

    let mut config = source.clone();
    // Normalize first so a programmatic (unloaded) source with a deprecated
    // `policy` alias still contributes its timeouts to the derivation.
    let _alias_used = config.normalize()?;
    if options.dedicated {
        config.runtime.resource_mode = Some(ResourceMode::Dedicated);
    }
    config.advanced.limits = derive_policy(
        &machine,
        &protocol,
        &network,
        config.inbounds.len(),
        config.runtime.resource_mode(),
        &config.advanced.limits,
    );
    validate_config(&config)?;
    let report = AutotuneReport {
        schema_version: 1,
        package_version: env!("CARGO_PKG_VERSION"),
        resource_mode: config.runtime.resource_mode().as_str(),
        machine,
        protocol,
        storage,
        network,
        selected_policy: config.advanced.limits.clone(),
    };
    Ok(AutotunedConfig { config, report })
}

fn validate_options(options: &AutotuneOptions) -> Result<(), AutotuneError> {
    if options.benchmark_duration < Duration::from_millis(90)
        || options.benchmark_duration > Duration::from_secs(30)
    {
        return Err(AutotuneError::InvalidOptions(
            "benchmark duration must be between 90ms and 30s",
        ));
    }
    if options.benchmark_warmup.is_zero() || options.benchmark_warmup > Duration::from_secs(10) {
        return Err(AutotuneError::InvalidOptions(
            "benchmark warmup must be between 1ms and 10s",
        ));
    }
    for (bytes, label) in [
        (options.storage_bytes, "storage bytes"),
        (options.network_bytes, "network bytes"),
    ] {
        if !(MEBIBYTE..=256 * MEBIBYTE).contains(&bytes) {
            return Err(AutotuneError::InvalidOptions(match label {
                "storage bytes" => "storage bytes must be between 1 MiB and 256 MiB",
                _ => "network bytes must be between 1 MiB and 256 MiB",
            }));
        }
    }
    Ok(())
}

/// Derives the tuned policy through the shared [`StartupPlan`] path.
///
/// The autotuner contributes its measured probes; serve startup calls
/// [`StartupPlan::derive`] directly with [`Probes::default`]. Both share the
/// exact formulas, so this shim only translates the report view into
/// capabilities and probe inputs.
fn derive_policy(
    machine: &AutotuneMachine,
    protocol: &BenchmarkReport,
    network: &NetworkProbe,
    listener_count: usize,
    resource_mode: ResourceMode,
    source_policy: &PolicyConfig,
) -> PolicyConfig {
    let slowest_operations_per_second = protocol
        .cases
        .iter()
        .map(|case| case.operations_per_second)
        .fold(f64::INFINITY, f64::min);
    let probes = Probes {
        protocol_ops_per_sec: slowest_operations_per_second
            .is_finite()
            .then_some(slowest_operations_per_second as u64),
        network: Some(network),
    };
    StartupPlan::derive(
        &capabilities_of(machine),
        &SafetyLimits::default(),
        resource_mode,
        listener_count,
        probes,
        source_policy,
    )
    .into_policy()
}

fn capabilities_of(machine: &AutotuneMachine) -> MachineCapabilities {
    MachineCapabilities {
        logical_cpus: machine.logical_cpus,
        effective_cpus: machine.effective_cpus,
        fd_soft_limit: machine.fd_soft_limit,
        fd_hard_limit: machine.fd_hard_limit,
        memory_source: machine.memory_source,
        memory_total_bytes: machine.memory_total_bytes,
        memory_current_bytes: machine.memory_current_bytes,
        cpu_quota_microseconds: machine.cpu_quota_microseconds,
        cpu_period_microseconds: machine.cpu_period_microseconds,
    }
}

fn probe_storage(directory: &Path, bytes: u64) -> Result<StorageProbe, AutotuneError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| AutotuneError::Io {
            operation: "storage clock",
            source: io::Error::other(source),
        })?
        .as_nanos();
    let path = directory.join(format!(
        ".rust-reality-autotune-{}-{timestamp}.tmp",
        std::process::id()
    ));
    let mut cleanup = ScratchFile::create(&path)?;
    let block = vec![0xa5; STORAGE_BLOCK_BYTES];

    let write_start = Instant::now();
    transfer_chunks(bytes, block.len(), |length| {
        cleanup.file.write_all(&block[..length])
    })
    .map_err(|source| AutotuneError::Io {
        operation: "storage write",
        source,
    })?;
    cleanup
        .file
        .sync_data()
        .map_err(|source| AutotuneError::Io {
            operation: "storage sync",
            source,
        })?;
    let write_elapsed = write_start.elapsed();

    cleanup
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|source| AutotuneError::Io {
            operation: "storage seek",
            source,
        })?;
    let mut read_block = vec![0_u8; STORAGE_BLOCK_BYTES];
    let read_start = Instant::now();
    transfer_chunks(bytes, read_block.len(), |length| {
        cleanup.file.read_exact(&mut read_block[..length])?;
        black_box(read_block[0]);
        Ok(())
    })
    .map_err(|source| AutotuneError::Io {
        operation: "storage read",
        source,
    })?;
    let read_elapsed = read_start.elapsed();

    Ok(StorageProbe {
        bytes_per_direction: bytes,
        write_mebibytes_per_second: throughput(bytes, write_elapsed),
        read_mebibytes_per_second: throughput(bytes, read_elapsed),
    })
}

struct ScratchFile {
    file: File,
    path: PathBuf,
}

impl ScratchFile {
    fn create(path: &Path) -> Result<Self, AutotuneError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| AutotuneError::Io {
                operation: "storage create",
                source,
            })?;
        Ok(Self {
            file,
            path: path.to_owned(),
        })
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn probe_loopback(bytes: u64) -> Result<NetworkProbe, AutotuneError> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|source| AutotuneError::Io {
            operation: "network bind",
            source,
        })?;
    let address = listener.local_addr().map_err(|source| AutotuneError::Io {
        operation: "network local address",
        source,
    })?;
    let worker = thread::spawn(move || loopback_server(listener, bytes));
    let client_result = loopback_client(address, bytes);
    let worker_result = worker.join().map_err(|_| AutotuneError::WorkerPanic)?;
    worker_result.map_err(|source| AutotuneError::Io {
        operation: "network server",
        source,
    })?;
    client_result
}

fn loopback_server(listener: TcpListener, bytes: u64) -> io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    configure_probe_stream(&stream)?;
    let mut byte = [0_u8; 1];
    for _ in 0..NETWORK_ROUND_TRIPS {
        stream.read_exact(&mut byte)?;
        stream.write_all(&byte)?;
    }
    receive_bytes(&mut stream, bytes)?;
    stream.write_all(&[0x5a])?;
    stream.read_exact(&mut byte)?;
    send_bytes(&mut stream, bytes)
}

fn loopback_client(
    address: std::net::SocketAddr,
    bytes: u64,
) -> Result<NetworkProbe, AutotuneError> {
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(|source| {
            AutotuneError::Io {
                operation: "network connect",
                source,
            }
        })?;
    configure_probe_stream(&stream).map_err(|source| AutotuneError::Io {
        operation: "network socket options",
        source,
    })?;

    let mut round_trips = Vec::with_capacity(NETWORK_ROUND_TRIPS);
    let mut reply = [0_u8; 1];
    for index in 0..NETWORK_ROUND_TRIPS {
        let start = Instant::now();
        stream
            .write_all(&[u8::try_from(index).unwrap_or(0)])
            .and_then(|()| stream.read_exact(&mut reply))
            .map_err(|source| AutotuneError::Io {
                operation: "network latency",
                source,
            })?;
        round_trips.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    round_trips.sort_by(f64::total_cmp);

    let upload_start = Instant::now();
    send_bytes(&mut stream, bytes).map_err(|source| AutotuneError::Io {
        operation: "network upload",
        source,
    })?;
    stream
        .read_exact(&mut reply)
        .map_err(|source| AutotuneError::Io {
            operation: "network upload acknowledgement",
            source,
        })?;
    let upload_elapsed = upload_start.elapsed();

    let download_start = Instant::now();
    stream
        .write_all(&[0xa5])
        .map_err(|source| AutotuneError::Io {
            operation: "network download start",
            source,
        })?;
    receive_bytes(&mut stream, bytes).map_err(|source| AutotuneError::Io {
        operation: "network download",
        source,
    })?;
    let download_elapsed = download_start.elapsed();

    Ok(NetworkProbe {
        round_trips: NETWORK_ROUND_TRIPS,
        p50_round_trip_microseconds: percentile(&round_trips, 50),
        p95_round_trip_microseconds: percentile(&round_trips, 95),
        upload_mebibytes_per_second: throughput(bytes, upload_elapsed),
        download_mebibytes_per_second: throughput(bytes, download_elapsed),
        bytes_per_direction: bytes,
    })
}

fn configure_probe_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))
}

fn send_bytes(stream: &mut TcpStream, bytes: u64) -> io::Result<()> {
    let block = [0x6d; NETWORK_BLOCK_BYTES];
    transfer_chunks(bytes, block.len(), |length| {
        stream.write_all(&block[..length])
    })
}

fn receive_bytes(stream: &mut TcpStream, bytes: u64) -> io::Result<()> {
    let mut block = [0_u8; NETWORK_BLOCK_BYTES];
    transfer_chunks(bytes, block.len(), |length| {
        stream.read_exact(&mut block[..length])
    })
}

fn transfer_chunks(
    bytes: u64,
    block_bytes: usize,
    mut operation: impl FnMut(usize) -> io::Result<()>,
) -> io::Result<()> {
    let mut remaining = bytes;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(block_bytes as u64)).unwrap_or(block_bytes);
        operation(length)?;
        remaining -= length as u64;
    }
    Ok(())
}

fn throughput(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 / MEBIBYTE as f64 / elapsed.as_secs_f64()
}

fn percentile(sorted: &[f64], percentile: usize) -> f64 {
    let index = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted[index]
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr as _, time::Duration};

    use super::{AutotuneMachine, NetworkProbe, derive_policy, probe_loopback, probe_storage};
    use crate::{
        benchmark::{BenchmarkOptions, run_benchmarks},
        config::{GenerateConfigInput, ResourceMode, generate_minimal_config, validate_config},
    };

    #[test]
    fn derived_policy_is_bounded_and_valid() {
        let generated = generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("0.0.0.0").expect("IP must parse"),
            port: 443,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate");
        let protocol = run_benchmarks(BenchmarkOptions {
            duration: Duration::from_millis(90),
            warmup: Duration::from_millis(1),
        })
        .expect("benchmark must run");
        let machine = AutotuneMachine {
            logical_cpus: 8,
            effective_cpus: 4,
            fd_soft_limit: 65_536,
            fd_hard_limit: 1_048_576,
            memory_source: "test",
            memory_total_bytes: 4 * 1024 * 1024 * 1024,
            memory_current_bytes: None,
            cpu_quota_microseconds: Some(400_000),
            cpu_period_microseconds: Some(100_000),
        };
        let network = NetworkProbe {
            round_trips: 128,
            p50_round_trip_microseconds: 10.0,
            p95_round_trip_microseconds: 20.0,
            upload_mebibytes_per_second: 2_000.0,
            download_mebibytes_per_second: 2_000.0,
            bytes_per_direction: 1024 * 1024,
        };
        let mut config = generated.config().clone();
        config.advanced.limits = derive_policy(
            &machine,
            &protocol,
            &network,
            config.inbounds.len(),
            ResourceMode::Standard,
            &config.advanced.limits,
        );
        validate_config(&config).expect("derived policy must validate");
        assert_eq!(config.advanced.limits.relay.buffer_bytes, 64 * 1024);
        assert_eq!(
            config.advanced.limits.resource_governor.max_connections,
            24_576
        );
        assert!(
            config.advanced.limits.relay.max_splice_relays
                <= config.advanced.limits.resource_governor.max_connections
        );
    }

    #[test]
    fn bounded_storage_and_loopback_probes_transfer_both_directions() {
        let directory =
            std::env::temp_dir().join(format!("rust-reality-autotune-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("test directory must be created");
        let storage = probe_storage(&directory, 1024 * 1024).expect("storage probe must run");
        let network = match probe_loopback(1024 * 1024) {
            Ok(network) => network,
            Err(super::AutotuneError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                std::fs::remove_dir_all(&directory).expect("test directory must be removed");
                return;
            }
            Err(error) => panic!("network probe must run: {error:?}"),
        };
        std::fs::remove_dir_all(&directory).expect("test directory must be removed");
        assert_eq!(storage.bytes_per_direction, 1024 * 1024);
        assert!(storage.write_mebibytes_per_second > 0.0);
        assert!(storage.read_mebibytes_per_second > 0.0);
        assert_eq!(network.bytes_per_direction, 1024 * 1024);
        assert!(network.upload_mebibytes_per_second > 0.0);
        assert!(network.download_mebibytes_per_second > 0.0);
        assert!(network.p95_round_trip_microseconds >= network.p50_round_trip_microseconds);
    }
}
