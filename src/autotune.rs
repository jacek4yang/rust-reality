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
    config::{
        Config, ConfigError, PolicyConfig, RelayPolicy, ResourceGovernorConfig, ResourceMode,
        validate_config,
    },
    runtime::machine::MachineReport,
};

const MEBIBYTE: u64 = 1024 * 1024;
const STORAGE_BLOCK_BYTES: usize = 1024 * 1024;
const NETWORK_BLOCK_BYTES: usize = 64 * 1024;
const NETWORK_ROUND_TRIPS: usize = 128;
const PIPE_PAIR_MEMORY_BYTES: u64 = 2 * 256 * 1024;
const MAX_PLANNED_FDS: u64 = 1_048_576;
const MAX_CONNECTIONS: u64 = 262_144;
const MAX_SPLICE_RELAYS: u64 = 8_192;
const MAX_POOLED_BUFFERS: u64 = 65_536;
/// Planning charge above the measured ~47 KiB idle-session footprint. The
/// margin covers allocator variation and per-session kernel state without
/// pretending that every byte is process RSS.
const PLANNED_CONNECTION_BYTES: u64 = 64 * 1024;

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
    fn from_report(report: &MachineReport) -> Self {
        Self {
            logical_cpus: report.available_cpus,
            effective_cpus: effective_cpu_count(report),
            fd_soft_limit: report.fd_soft_limit,
            fd_hard_limit: report.fd_hard_limit,
            memory_source: report.memory_source,
            memory_total_bytes: report.memory_total,
            memory_current_bytes: report.memory_current,
            cpu_quota_microseconds: report.cpu_quota_us,
            cpu_period_microseconds: report.cpu_period_us,
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

/// TCP loopback measurements of the local network stack.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProbe {
    /// Echo round trips in the latency sample.
    pub round_trips: usize,
    /// Median one-byte TCP round-trip latency.
    pub p50_round_trip_microseconds: f64,
    /// 95th percentile one-byte TCP round-trip latency.
    pub p95_round_trip_microseconds: f64,
    /// Client-to-server loopback throughput.
    pub upload_mebibytes_per_second: f64,
    /// Server-to-client loopback throughput.
    pub download_mebibytes_per_second: f64,
    /// Bytes transferred in each throughput direction.
    pub bytes_per_direction: u64,
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
    let machine = AutotuneMachine::from_report(&machine_report);
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

fn derive_policy(
    machine: &AutotuneMachine,
    protocol: &BenchmarkReport,
    network: &NetworkProbe,
    listener_count: usize,
    resource_mode: ResourceMode,
    source_policy: &PolicyConfig,
) -> PolicyConfig {
    let cpus = u64::try_from(machine.effective_cpus)
        .unwrap_or(u64::MAX)
        .max(1);
    let selected_limit = match resource_mode {
        ResourceMode::Standard => machine.fd_soft_limit,
        ResourceMode::Dedicated => machine.fd_hard_limit,
    }
    .min(MAX_PLANNED_FDS);
    let headroom_divisor = match resource_mode {
        ResourceMode::Standard => 16,
        ResourceMode::Dedicated => 10,
    };
    let headroom = (selected_limit / headroom_divisor).max(64);
    let listeners = u64::try_from(listener_count).unwrap_or(u64::MAX);
    let fixed = listeners.saturating_mul(2).saturating_add(3 + 1 + 16 + 32);
    let dynamic_fds = selected_limit
        .saturating_sub(headroom)
        .saturating_sub(fixed)
        .max(64);

    let relay_budget = relay_memory_budget(machine.memory_total_bytes);
    let desired_splice = cpus.saturating_mul(256).clamp(1, MAX_SPLICE_RELAYS);
    let memory_splice = (relay_budget / 2 / (2 * PIPE_PAIR_MEMORY_BYTES)).max(1);
    let max_splice_relays = desired_splice
        .min(dynamic_fds / 12)
        .min(memory_splice)
        .max(1);
    let max_pooled_pipes = max_splice_relays.saturating_mul(2);
    let accelerator_fds = max_splice_relays
        .saturating_mul(4)
        .saturating_add(max_pooled_pipes.saturating_mul(2));
    let fd_connection_limit = dynamic_fds
        .saturating_sub(accelerator_fds)
        .saturating_div(2);
    let memory_connection_limit =
        connection_memory_limit(machine.memory_total_bytes, resource_mode);
    let max_connections = fd_connection_limit
        .min(memory_connection_limit)
        .clamp(64, MAX_CONNECTIONS);

    let buffer_bytes = selected_buffer_bytes(network);
    let pipe_memory = max_pooled_pipes.saturating_mul(PIPE_PAIR_MEMORY_BYTES);
    let buffer_memory = relay_budget
        .saturating_sub(pipe_memory)
        .max(2 * buffer_bytes as u64);
    let max_pooled_buffers = (buffer_memory / buffer_bytes as u64)
        .clamp(2, MAX_POOLED_BUFFERS)
        .min(max_connections.saturating_mul(2));
    let relay_memory =
        pipe_memory.saturating_add(max_pooled_buffers.saturating_mul(buffer_bytes as u64));

    let slowest_operations_per_second = protocol
        .cases
        .iter()
        .map(|case| case.operations_per_second)
        .fold(f64::INFINITY, f64::min);
    let measured_setup_capacity = if slowest_operations_per_second.is_finite() {
        (slowest_operations_per_second / 1_000.0) as u64
    } else {
        0
    };
    let max_handshakes = cpus
        .saturating_mul(128)
        .max(measured_setup_capacity)
        .min(max_connections)
        .max(1);
    let max_crypto_operations = cpus.saturating_mul(32).min(max_handshakes).max(1);
    let max_fallbacks = max_connections.min(cpus.saturating_mul(128).max(64));
    let max_dns_lookups = max_connections.min(cpus.saturating_mul(32).max(16));
    let max_replay_entries = max_connections.saturating_mul(4).clamp(1_024, 1_000_000);
    let max_direct_concurrent = max_connections.min(cpus.saturating_mul(512).max(64));
    let max_direct_per_second = cpus
        .saturating_mul(2_048)
        .max(measured_setup_capacity.saturating_mul(4))
        .clamp(64, u64::from(u32::MAX));

    PolicyConfig {
        resource_governor: ResourceGovernorConfig {
            max_connections: to_u32(max_connections),
            max_handshakes: to_u32(max_handshakes),
            max_fallbacks: to_u32(max_fallbacks),
            max_crypto_operations: to_u32(max_crypto_operations),
            max_replay_entries: to_u32(max_replay_entries),
            max_dns_lookups: to_u32(max_dns_lookups),
            replay_retention_ms: source_policy.resource_governor.replay_retention_ms,
            client_hello_timeout_ms: source_policy.resource_governor.client_hello_timeout_ms,
            handshake_timeout_ms: source_policy.resource_governor.handshake_timeout_ms,
            connect_timeout_ms: source_policy.resource_governor.connect_timeout_ms,
            fallback_timeout_ms: source_policy.resource_governor.fallback_timeout_ms,
        },
        direct_barrier: crate::config::DirectBarrierConfig {
            max_concurrent: to_u32(max_direct_concurrent),
            max_per_second: to_u32(max_direct_per_second),
        },
        relay: RelayPolicy {
            buffer_bytes,
            max_pooled_buffers: usize::try_from(max_pooled_buffers).unwrap_or(65_536),
            max_splice_relays: to_u32(max_splice_relays.min(max_connections)),
            max_relay_memory_bytes: relay_memory,
            splice: cfg!(target_os = "linux"),
            pipe_pool: cfg!(target_os = "linux"),
            max_pooled_pipes: if cfg!(target_os = "linux") {
                to_u32(max_pooled_pipes)
            } else {
                0
            },
        },
    }
}

fn effective_cpu_count(report: &MachineReport) -> usize {
    let quota = report
        .cpu_quota_us
        .zip(report.cpu_period_us)
        .filter(|(_, period)| *period > 0)
        .map(|(quota, period)| quota.saturating_add(period - 1) / period)
        .and_then(|count| usize::try_from(count).ok());
    quota.map_or(report.available_cpus, |count| {
        report.available_cpus.min(count.max(1))
    })
}

fn relay_memory_budget(memory_total: u64) -> u64 {
    if memory_total == 0 {
        256 * MEBIBYTE
    } else {
        (memory_total / 8).clamp(16 * MEBIBYTE, 2 * 1024 * MEBIBYTE)
    }
}

fn connection_memory_limit(memory_total: u64, resource_mode: ResourceMode) -> u64 {
    if memory_total == 0 {
        return MAX_CONNECTIONS;
    }
    // Leave the rest for relay pools, crypto/asset state, the allocator,
    // kernel socket/pipe memory, and other processes in the same budget.
    let budget = match resource_mode {
        ResourceMode::Standard => memory_total.saturating_mul(3) / 8,
        ResourceMode::Dedicated => memory_total / 2,
    };
    (budget / PLANNED_CONNECTION_BYTES).max(64)
}

fn selected_buffer_bytes(network: &NetworkProbe) -> usize {
    let slower_direction = network
        .upload_mebibytes_per_second
        .min(network.download_mebibytes_per_second);
    if slower_direction >= 1_024.0 {
        64 * 1024
    } else if slower_direction >= 256.0 {
        32 * 1024
    } else {
        16 * 1024
    }
}

fn to_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
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

    use super::{
        AutotuneMachine, NetworkProbe, connection_memory_limit, derive_policy, effective_cpu_count,
        probe_loopback, probe_storage,
    };
    use crate::{
        benchmark::{BenchmarkOptions, run_benchmarks},
        config::{GenerateConfigInput, ResourceMode, generate_minimal_config, validate_config},
        runtime::machine::MachineReport,
    };

    #[test]
    fn cgroup_quota_reduces_the_effective_cpu_count() {
        let mut machine = MachineReport::conservative();
        machine.available_cpus = 16;
        machine.cpu_quota_us = Some(250_000);
        machine.cpu_period_us = Some(100_000);
        assert_eq!(effective_cpu_count(&machine), 3);
    }

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
    fn connection_memory_model_preserves_mode_specific_headroom() {
        let gibibyte = 1024 * 1024 * 1024;
        assert_eq!(
            connection_memory_limit(gibibyte, ResourceMode::Standard),
            6_144
        );
        assert_eq!(
            connection_memory_limit(gibibyte, ResourceMode::Dedicated),
            8_192
        );
        assert_eq!(
            connection_memory_limit(0, ResourceMode::Standard),
            super::MAX_CONNECTIONS
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
