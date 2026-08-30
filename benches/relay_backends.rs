//! A reproducible loopback relay benchmark that emits one JSON object per sample.
//!
//! Every sample is retained; nothing is averaged away and no fastest run is
//! selected. Implementation order is randomized per repetition from a recorded
//! seed so that ordering effects cannot favour one backend.
//!
//! The numbers this produces are loopback numbers on one host. They measure
//! relay engine cost, not Internet throughput, and must never be presented as a
//! general speed promise.
//!
//! Usage:
//!
//! ```text
//! cargo bench --bench relay_backends -- --samples 5 --seed 1 > benchmarks/relay.jsonl
//! ```

use std::{
    env, io,
    net::Ipv4Addr,
    process,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rust_reality::{
    config::RelayPolicy,
    transport::{BackendRequest, FdBudget, RelayBackend, RelayContext, TcpRelay},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Builder,
};

/// A deterministic order shuffler; benchmark ordering must be reproducible.
struct Lcg(u64);

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            let target = (self.next() >> 16) as usize % (index + 1);
            items.swap(index, target);
        }
    }
}

#[derive(Clone, Copy)]
struct Scenario {
    direction: &'static str,
    payload_bytes: usize,
    concurrency: usize,
    backend: Option<RelayBackend>,
}

impl Scenario {
    const fn requested(&self) -> &'static str {
        match self.backend {
            None => "automatic",
            Some(backend) => backend.as_str(),
        }
    }
}

fn policy(backend: Option<RelayBackend>) -> RelayPolicy {
    let buffer_kib = env::var("RR_BENCH_BUFFER_KIB")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32);
    RelayPolicy {
        buffer_bytes: buffer_kib * 1024,
        max_pooled_buffers: 512,
        max_splice_relays: 256,
        max_relay_memory_bytes: u64::MAX,
        splice: !matches!(backend, Some(RelayBackend::Buffered)),
        pipe_pool: true,
        max_pooled_pipes: 512,
    }
}

async fn pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let connect = TcpStream::connect(address);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    Ok((client?, accepted?.0))
}

/// Runs one flow and returns the bytes moved plus the backend that ran.
async fn one_flow(
    relay: &TcpRelay,
    scenario: Scenario,
    payload: &'static [u8],
) -> io::Result<(u64, &'static str)> {
    let (client, relay_inbound) = pair().await?;
    let (relay_outbound, target) = pair().await?;
    let context = scenario
        .backend
        .map_or_else(RelayContext::owned, |backend| {
            RelayContext::owned().with_request(BackendRequest::Explicit(backend))
        });
    let uplink = matches!(scenario.direction, "uplink" | "bidirectional");
    let downlink = matches!(scenario.direction, "downlink" | "bidirectional");

    let relaying = relay.relay_owned(relay_inbound, relay_outbound, context);
    let client_io = async move {
        let (mut reader, mut writer) = client.into_split();
        let send = async move {
            if uplink {
                writer.write_all(payload).await?;
            }
            writer.shutdown().await?;
            Ok::<_, io::Error>(())
        };
        let receive = async move {
            let mut sink = vec![0_u8; 64 * 1024];
            let mut total = 0_u64;
            loop {
                let read = reader.read(&mut sink).await?;
                if read == 0 {
                    break;
                }
                total += read as u64;
            }
            Ok::<_, io::Error>(total)
        };
        let (sent, received) = tokio::join!(send, receive);
        sent?;
        received
    };
    let target_io = async move {
        let (mut reader, mut writer) = target.into_split();
        let send = async move {
            if downlink {
                writer.write_all(payload).await?;
            }
            writer.shutdown().await?;
            Ok::<_, io::Error>(())
        };
        let receive = async move {
            let mut sink = vec![0_u8; 64 * 1024];
            let mut total = 0_u64;
            loop {
                let read = reader.read(&mut sink).await?;
                if read == 0 {
                    break;
                }
                total += read as u64;
            }
            Ok::<_, io::Error>(total)
        };
        let (sent, received) = tokio::join!(send, receive);
        sent?;
        received
    };

    let (outcome, client_bytes, target_bytes) = tokio::join!(relaying, client_io, target_io);
    let outcome = outcome?;
    let moved = client_bytes? + target_bytes?;
    Ok((moved, outcome.backend().as_str()))
}

fn main() {
    let buffer_kib = env::var("RR_BENCH_BUFFER_KIB")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32);
    eprintln!("buffer_bytes={} KiB", buffer_kib);
    let mut samples = 5_usize;
    let mut seed = 1_u64;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--samples" => samples = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(5),
            "--seed" => seed = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(1),
            // `cargo bench` passes its own flags; ignore anything unrecognized.
            _ => {}
        }
    }

    let payload_sizes = [1_usize << 20, 32 << 20];
    let concurrencies = [1_usize, 4, 32, 64];
    let backends: [Option<RelayBackend>; 3] = [
        Some(RelayBackend::Buffered),
        Some(RelayBackend::Splice),
        None,
    ];
    let mut scenarios = Vec::new();
    for direction in ["uplink", "downlink", "bidirectional"] {
        for payload_bytes in payload_sizes {
            for concurrency in concurrencies {
                for backend in backends {
                    scenarios.push(Scenario {
                        direction,
                        payload_bytes,
                        concurrency,
                        backend,
                    });
                }
            }
        }
        // 512 MiB only at low/medium and high concurrency: the decision-surface
        // edge cases, without multiplying the runtime beyond reason.
        for concurrency in [1_usize, 32] {
            for backend in backends {
                scenarios.push(Scenario {
                    direction,
                    payload_bytes: 512 << 20,
                    concurrency,
                    backend,
                });
            }
        }
    }

    let commit = env::var("RR_BENCH_COMMIT").unwrap_or_else(|_| "unknown".to_owned());
    let host = env::var("RR_BENCH_HOST").unwrap_or_else(|_| "unknown".to_owned());
    let cpu =
        read_first_line("/proc/cpuinfo", "model name").unwrap_or_else(|| "unknown".to_owned());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let rustc = option_env!("RUSTC_VERSION").unwrap_or("unknown");

    let workers = env::var("RR_BENCH_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2);
    eprintln!("workers={workers}");
    let runtime = Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("benchmark runtime must build");
    let mut shuffler = Lcg::new(seed);

    let payloads: Vec<&'static [u8]> = scenarios
        .iter()
        .map(|scenario| {
            Box::leak(vec![0x5a_u8; scenario.payload_bytes].into_boxed_slice()) as &'static [u8]
        })
        .collect();
    for sample_index in 0..samples {
        let mut order: Vec<usize> = (0..scenarios.len()).collect();
        shuffler.shuffle(&mut order);
        for position in order {
            let scenario = scenarios[position];
            let payload: &'static [u8] = payloads[position];
            let relay = TcpRelay::new(&policy(scenario.backend), FdBudget::new(65_536))
                .expect("relay must compile");

            let cpu_before = cpu_times();
            let cs_before = context_switches();
            let started = Instant::now();
            let selected = runtime.block_on(async {
                let mut flows = Vec::with_capacity(scenario.concurrency);
                for _ in 0..scenario.concurrency {
                    flows.push(one_flow(&relay, scenario, payload));
                }
                let mut moved = 0_u64;
                let mut selected = "unknown";
                for flow in flows {
                    let (bytes, backend) = flow.await.expect("benchmark flow must succeed");
                    moved += bytes;
                    selected = backend;
                }
                (moved, selected)
            });
            let elapsed = started.elapsed();
            let (moved, backend_selected) = selected;
            let (cpu_user_ns, cpu_system_ns) = cpu_before.elapsed(cpu_times());
            let context_switches =
                cs_before.map(|before| context_switches().unwrap_or(before).saturating_sub(before));

            println!(
                "{{\"commit\":\"{commit}\",\"timestamp\":{},\"host\":\"{host}\",\
                 \"cpu\":\"{}\",\"kernel\":\"{kernel}\",\"rustc\":\"{rustc}\",\
                 \"xrayVersion\":null,\"configuration\":\"loopback-relay\",\"seed\":{seed},\
                 \"sampleIndex\":{sample_index},\"direction\":\"{}\",\"payloadBytes\":{},\
                 \"concurrency\":{},\"backendRequested\":\"{}\",\"backendSelected\":\"{}\",\
                 \"durationNs\":{},\"throughputMiBps\":{:.3},\"bytesMoved\":{moved},\
                 \"cpuUserNs\":{cpu_user_ns},\"cpuSystemNs\":{cpu_system_ns},\
                 \"contextSwitches\":{},\"syscallCounts\":null,\"allocations\":null,\"peakRssBytes\":{},\
                 \"backendHitRate\":{:.3},\"verificationHash\":\"{}\"}}",
                unix_millis(),
                escape(&cpu),
                scenario.direction,
                scenario.payload_bytes,
                scenario.concurrency,
                scenario.requested(),
                backend_selected,
                elapsed.as_nanos(),
                throughput_mib(moved, elapsed),
                context_switches.map_or_else(|| "null".to_owned(), |value| value.to_string()),
                peak_rss_bytes(),
                f64::from(u8::from(
                    scenario.backend.is_none() || scenario.requested() == backend_selected
                )),
                verification_hash(moved, scenario.payload_bytes, scenario.concurrency),
            );
        }
    }
    process::exit(0);
}

#[derive(Clone, Copy)]
struct CpuSample {
    user_ns: u64,
    system_ns: u64,
}

impl CpuSample {
    fn elapsed(self, after: Self) -> (u64, u64) {
        (
            after.user_ns.saturating_sub(self.user_ns),
            after.system_ns.saturating_sub(self.system_ns),
        )
    }
}

/// Reads utime/stime from /proc/self/stat in 10 ms clock ticks (USER_HZ=100).
fn cpu_times() -> CpuSample {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let ticks: Vec<u64> = stat
        .rsplit(')')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .skip(11)
        .take(2)
        .filter_map(|field| field.parse().ok())
        .collect();
    let (user, system) = (
        ticks.first().copied().unwrap_or(0),
        ticks.get(1).copied().unwrap_or(0),
    );
    CpuSample {
        user_ns: user.saturating_mul(10_000_000),
        system_ns: system.saturating_mul(10_000_000),
    }
}

/// Reads voluntary + involuntary context switches from /proc/self/status.
fn context_switches() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut total = 0_u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("voluntary_ctxt_switches:") {
            total += rest.trim().parse::<u64>().ok()?;
        } else if let Some(rest) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            total += rest.trim().parse::<u64>().ok()?;
        }
    }
    Some(total)
}

fn throughput_mib(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    (bytes as f64) / seconds / (1024.0 * 1024.0)
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn peak_rss_bytes() -> u64 {
    read_first_line("/proc/self/status", "VmHWM")
        .and_then(|line| {
            line.split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
        })
        .map_or(0, |kilobytes| kilobytes.saturating_mul(1024))
}

fn read_first_line(path: &str, prefix: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let line = contents.lines().find(|line| line.starts_with(prefix))?;
    Some(
        line.split_once(':')
            .map_or(line, |(_, value)| value)
            .trim()
            .to_owned(),
    )
}

/// A cheap deterministic digest so a retained sample can be checked for
/// transcription errors without a hashing dependency.
fn verification_hash(bytes: u64, payload: usize, concurrency: usize) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for value in [bytes, payload as u64, concurrency as u64] {
        for byte in value.to_be_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

fn escape(value: &str) -> String {
    value.replace('"', "'")
}
