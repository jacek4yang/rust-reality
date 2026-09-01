//! Reproducible, bounded in-process protocol benchmarks for release binaries.

use std::{
    error::Error,
    fmt,
    hint::black_box,
    net::Ipv4Addr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::protocol::{
    nxr::{NxrKey, encode_request},
    vless::{
        Address, Command, Destination, UserId, VERSION, VisionCommand, VisionDecoder, VisionPayload,
    },
};

const SAMPLE_COUNT: usize = 9;
const BATCH_OPERATIONS: u64 = 256;
const VISION_PAYLOAD_BYTES: usize = 8_000;

/// Bounded runtime settings for the built-in benchmark command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkOptions {
    /// Measured wall-clock time for each case.
    pub duration: Duration,
    /// Warm-up time before each measured case.
    pub warmup: Duration,
}

/// One machine-readable benchmark run.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkReport {
    /// Runtime and build facts required to interpret the measurements.
    pub environment: BenchmarkEnvironment,
    /// Independently measured protocol hot paths.
    pub cases: Vec<BenchmarkCase>,
}

/// Environment captured without invoking external programs.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkEnvironment {
    /// Unix timestamp at the beginning of the run.
    pub timestamp_unix_seconds: u64,
    /// Package version embedded in the executable.
    pub package_version: &'static str,
    /// Optional commit supplied by the release build environment.
    pub git_commit: &'static str,
    /// Rust compilation target operating system.
    pub operating_system: &'static str,
    /// Rust compilation target architecture.
    pub architecture: &'static str,
    /// Logical CPUs visible to this process.
    pub logical_cpus: usize,
    /// Whether compiler debug assertions are enabled.
    pub debug_assertions: bool,
    /// Number of independent timing samples per case.
    pub samples_per_case: usize,
    /// Requested measured milliseconds per case.
    pub duration_ms: u64,
    /// Requested warm-up milliseconds per case.
    pub warmup_ms: u64,
}

/// Summary statistics for one deterministic operation.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkCase {
    /// Stable operation identifier.
    pub name: &'static str,
    /// Logical input bytes processed by each operation.
    pub bytes_per_operation: u64,
    /// Total completed operations across all samples.
    pub operations: u64,
    /// Aggregate measured duration.
    pub elapsed_nanoseconds: u128,
    /// Aggregate arithmetic mean latency.
    pub mean_nanoseconds_per_operation: f64,
    /// Median per-sample latency.
    pub p50_nanoseconds_per_operation: f64,
    /// 95th-percentile per-sample latency.
    pub p95_nanoseconds_per_operation: f64,
    /// Aggregate operation rate.
    pub operations_per_second: f64,
    /// Logical input throughput; this is not network throughput.
    pub mebibytes_per_second: f64,
}

/// A built-in benchmark could not produce a trustworthy result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkError {
    /// The requested duration cannot produce independent samples.
    Duration,
    /// One deterministic benchmark fixture failed its protocol invariant.
    Fixture(&'static str),
    /// The platform clock moved or could not represent a timestamp.
    Clock,
    /// The process cannot determine its available parallelism.
    Parallelism,
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duration => formatter.write_str("benchmark duration is too short"),
            Self::Fixture(name) => write!(formatter, "benchmark fixture failed: {name}"),
            Self::Clock => {
                formatter.write_str("system clock is unavailable for benchmark metadata")
            }
            Self::Parallelism => formatter
                .write_str("available CPU parallelism is unavailable for benchmark metadata"),
        }
    }
}

impl Error for BenchmarkError {}

/// Runs deterministic protocol microbenchmarks and returns JSON-ready results.
///
/// This function never opens a socket and makes no Internet-performance claim.
/// Run it in an optimized binary on an otherwise idle host, then compare reports
/// from the same machine and operating conditions.
///
/// # Errors
///
/// Returns an error for an unusable duration, unavailable environment metadata,
/// or an internal fixture invariant failure.
pub fn run_benchmarks(options: BenchmarkOptions) -> Result<BenchmarkReport, BenchmarkError> {
    let sample_duration = options
        .duration
        .checked_div(u32::try_from(SAMPLE_COUNT).map_err(|_| BenchmarkError::Duration)?)
        .filter(|duration| !duration.is_zero())
        .ok_or(BenchmarkError::Duration)?;
    let environment = BenchmarkEnvironment {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BenchmarkError::Clock)?
            .as_secs(),
        package_version: env!("CARGO_PKG_VERSION"),
        git_commit: option_env!("RUST_REALITY_GIT_COMMIT").unwrap_or("unknown"),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism()
            .map_err(|_| BenchmarkError::Parallelism)?
            .get(),
        debug_assertions: cfg!(debug_assertions),
        samples_per_case: SAMPLE_COUNT,
        duration_ms: u64::try_from(options.duration.as_millis()).unwrap_or(u64::MAX),
        warmup_ms: u64::try_from(options.warmup.as_millis()).unwrap_or(u64::MAX),
    };

    let vless = vless_request();
    let mut vless_operation = || {
        let decoded = crate::protocol::vless::decode_request(black_box(vless.as_slice()))
            .map_err(|_| BenchmarkError::Fixture("VLESS decode"))?;
        black_box(decoded);
        Ok(())
    };
    let vless_case = measure(
        "vless.decode.ipv4",
        u64::try_from(vless.len()).map_err(|_| BenchmarkError::Fixture("VLESS length"))?,
        options.warmup,
        sample_duration,
        &mut vless_operation,
    )?;

    let vision_wire = vision_frame();
    let mut vision_output = Vec::with_capacity(VISION_PAYLOAD_BYTES);
    let mut vision_operation = || {
        vision_output.clear();
        let mut decoder = VisionDecoder::new(UserId::new([0x11; 16]));
        decoder
            .decode(black_box(&vision_wire), &mut vision_output)
            .map_err(|_| BenchmarkError::Fixture("Vision decode"))?;
        if vision_output.len() != VISION_PAYLOAD_BYTES {
            return Err(BenchmarkError::Fixture("Vision output length"));
        }
        black_box(vision_output.as_slice());
        Ok(())
    };
    let vision_case = measure(
        "vision.decode.8k",
        VISION_PAYLOAD_BYTES as u64,
        options.warmup,
        sample_duration,
        &mut vision_operation,
    )?;

    // The borrowed parser is what a real session runs; the owned one above is
    // the public convenience API. They are measured separately so a change to
    // either is visible on its own.
    let mut vless_borrowed_operation = || {
        let decoded = crate::protocol::vless::decode_request_ref(black_box(vless.as_slice()))
            .map_err(|_| BenchmarkError::Fixture("VLESS borrowed decode"))?;
        black_box(decoded);
        Ok(())
    };
    let vless_borrowed_case = measure(
        "vless.decode.ipv4.borrowed",
        u64::try_from(vless.len()).map_err(|_| BenchmarkError::Fixture("VLESS length"))?,
        options.warmup,
        sample_duration,
        &mut vless_borrowed_operation,
    )?;

    // Steady-state relay decoding: the opening frame leaves framed mode, after
    // which every record is payload verbatim and is borrowed rather than
    // staged. The case asserts the payload really is borrowed, so it cannot
    // silently degrade into the copying path it exists to distinguish from.
    let vision_record = vec![0x5a; VISION_PAYLOAD_BYTES];
    let mut vision_stage = Vec::with_capacity(VISION_PAYLOAD_BYTES);
    let mut vision_borrowed_decoder = VisionDecoder::new(UserId::new([0x11; 16]));
    vision_borrowed_decoder
        .decode_append(&vision_wire, &mut vision_stage)
        .map_err(|_| BenchmarkError::Fixture("Vision opening frame"))?;
    let mut vision_borrowed_operation = || {
        let (_, payload) = vision_borrowed_decoder
            .decode_borrowed_append(black_box(vision_record.as_slice()), &mut vision_stage)
            .map_err(|_| BenchmarkError::Fixture("Vision borrowed decode"))?;
        let VisionPayload::Borrowed(bytes) = payload else {
            return Err(BenchmarkError::Fixture(
                "Vision payload was staged, not borrowed",
            ));
        };
        if bytes.len() != VISION_PAYLOAD_BYTES {
            return Err(BenchmarkError::Fixture("Vision borrowed length"));
        }
        black_box(bytes);
        Ok(())
    };
    let vision_borrowed_case = measure(
        "vision.decode.8k.borrowed",
        VISION_PAYLOAD_BYTES as u64,
        options.warmup,
        sample_duration,
        &mut vision_borrowed_operation,
    )?;

    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
    let key = NxrKey::new([0x33; 32]);
    let mut nxr_output = Vec::with_capacity(crate::protocol::nxr::MAX_REQUEST_LEN);
    let mut nxr_operation = || {
        encode_request(
            &destination,
            black_box(1_785_761_600),
            black_box([0x44; 16]),
            &key,
            &mut nxr_output,
        )
        .map_err(|_| BenchmarkError::Fixture("NXR authentication encode"))?;
        black_box(nxr_output.as_slice());
        Ok(())
    };
    let nxr_case = measure(
        "nxr.auth.encode.domain",
        11,
        options.warmup,
        sample_duration,
        &mut nxr_operation,
    )?;

    Ok(BenchmarkReport {
        environment,
        cases: vec![
            vless_case,
            vless_borrowed_case,
            vision_case,
            vision_borrowed_case,
            nxr_case,
        ],
    })
}

fn measure(
    name: &'static str,
    bytes_per_operation: u64,
    warmup: Duration,
    sample_duration: Duration,
    operation: &mut impl FnMut() -> Result<(), BenchmarkError>,
) -> Result<BenchmarkCase, BenchmarkError> {
    run_for(warmup, operation)?;
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    let mut operations = 0_u64;
    let mut elapsed = Duration::ZERO;
    for _ in 0..SAMPLE_COUNT {
        let sample = run_for(sample_duration, operation)?;
        operations = operations.saturating_add(sample.operations);
        elapsed = elapsed.saturating_add(sample.elapsed);
        samples.push(sample.elapsed.as_secs_f64() * 1_000_000_000.0 / sample.operations as f64);
    }
    samples.sort_by(f64::total_cmp);
    if operations == 0 || elapsed.is_zero() {
        return Err(BenchmarkError::Duration);
    }
    let elapsed_seconds = elapsed.as_secs_f64();
    let operations_per_second = operations as f64 / elapsed_seconds;
    Ok(BenchmarkCase {
        name,
        bytes_per_operation,
        operations,
        elapsed_nanoseconds: elapsed.as_nanos(),
        mean_nanoseconds_per_operation: elapsed_seconds * 1_000_000_000.0 / operations as f64,
        p50_nanoseconds_per_operation: samples[SAMPLE_COUNT / 2],
        p95_nanoseconds_per_operation: samples[SAMPLE_COUNT - 1],
        operations_per_second,
        mebibytes_per_second: operations_per_second * bytes_per_operation as f64
            / (1024.0 * 1024.0),
    })
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    operations: u64,
    elapsed: Duration,
}

fn run_for(
    duration: Duration,
    operation: &mut impl FnMut() -> Result<(), BenchmarkError>,
) -> Result<Sample, BenchmarkError> {
    if duration.is_zero() {
        return Ok(Sample {
            operations: 0,
            elapsed: Duration::ZERO,
        });
    }
    let start = Instant::now();
    let mut operations = 0_u64;
    loop {
        for _ in 0..BATCH_OPERATIONS {
            operation()?;
        }
        operations = operations.saturating_add(BATCH_OPERATIONS);
        let elapsed = start.elapsed();
        if elapsed >= duration {
            return Ok(Sample {
                operations,
                elapsed,
            });
        }
    }
}

fn vless_request() -> Vec<u8> {
    let mut packet = Vec::with_capacity(26);
    packet.push(VERSION);
    packet.extend_from_slice(&[0x11; 16]);
    packet.push(0);
    packet.push(Command::Tcp.as_byte());
    packet.extend_from_slice(&443_u16.to_be_bytes());
    packet.push(1);
    packet.extend_from_slice(&Ipv4Addr::new(203, 0, 113, 10).octets());
    packet
}

fn vision_frame() -> Vec<u8> {
    let payload = [0x5a; VISION_PAYLOAD_BYTES];
    let mut wire = Vec::with_capacity(16 + 5 + payload.len());
    wire.extend_from_slice(&[0x11; 16]);
    wire.push(VisionCommand::Direct as u8);
    wire.extend_from_slice(&(VISION_PAYLOAD_BYTES as u16).to_be_bytes());
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(&payload);
    wire
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BenchmarkOptions, SAMPLE_COUNT, run_benchmarks};

    #[test]
    fn emits_finite_bounded_results_for_every_case() {
        let report = run_benchmarks(BenchmarkOptions {
            duration: Duration::from_millis(9),
            warmup: Duration::from_millis(1),
        })
        .expect("short benchmark must run");

        assert_eq!(report.environment.samples_per_case, SAMPLE_COUNT);
        // Named rather than counted: the borrowed cases are the ones a real
        // session executes, and dropping one would silently return the suite
        // to measuring only the owning convenience APIs.
        let names: Vec<&str> = report.cases.iter().map(|case| case.name).collect();
        assert_eq!(
            names,
            [
                "vless.decode.ipv4",
                "vless.decode.ipv4.borrowed",
                "vision.decode.8k",
                "vision.decode.8k.borrowed",
                "nxr.auth.encode.domain",
            ]
        );
        for case in report.cases {
            assert!(case.operations > 0);
            assert!(case.mean_nanoseconds_per_operation.is_finite());
            assert!(case.p50_nanoseconds_per_operation.is_finite());
            assert!(case.p95_nanoseconds_per_operation.is_finite());
            assert!(case.operations_per_second.is_finite());
            assert!(case.mebibytes_per_second.is_finite());
        }
    }
}
