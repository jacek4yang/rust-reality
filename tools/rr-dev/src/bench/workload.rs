//! The connection-setup workload: what the setup-rate harnesses actually measure.
//!
//! Both setup-rate harnesses measure the cost of *establishing* a proxied
//! connection — accept through the first Vision transition — not the cost of
//! moving bytes. So each unit of work opens a fresh SOCKS5 connection to the
//! client, asks it to reach the loopback origin, sends one HTTP/1.0 request, and
//! stops as soon as the first body byte arrives. The payload is 256 bytes of `x`
//! precisely so that nothing about this measures throughput.
//!
//! Every step is checked, and a failure is counted rather than retried: a
//! connection that got a SOCKS reply but no `200`, or a `200` with no body, is not
//! a slow setup, it is a broken one, and the aggregators refuse a slot with any
//! failures.
//!
//! ## Why this is a separate process
//!
//! The originals invoked `perf stat ... -p <server_pid> -- python3 driver.py`. The
//! command after `--` is what bounds the measurement window: `perf` counts the
//! attached server for exactly as long as the driver runs. Keeping the driver in
//! process would mean inventing some other way to bracket the window, so the
//! driver stays a child process and this module is also reachable as
//! `cargo dev bench workload`.
//!
//! ## Row shape
//!
//! One row per (concurrency, sample). `benchmark-setup-rate-xray.sh` additionally
//! records `latenciesSeconds`, because it pools raw latencies across slots to get
//! its percentiles; `benchmark-setup-rate.sh` does not, because it works from the
//! per-row percentiles instead. That difference is carried by
//! [`SetupRatePlan::record_latencies`].

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::{bench::aggregate, perf::json_out::Json};

/// Per-connection deadline, as `socket.create_connection(..., timeout=30)` set.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on the response head, matching the driver's 65536-byte guard.
const MAX_HEAD_BYTES: usize = 65_536;

/// Warm-up connections a slot makes before it is measured.
const WARMUP_CONNECTIONS: usize = 3;

/// What one setup-rate slot measures.
#[derive(Debug, Clone)]
pub struct SetupRatePlan {
    /// Loopback SOCKS5 port of the Xray client fronting the server under test.
    pub socks_port: u16,
    /// Loopback port of the plain-HTTP origin the SOCKS client is asked to reach.
    pub origin_port: u16,
    /// Connections per sample.
    pub connections: usize,
    /// Concurrency levels, each measured `samples` times.
    pub concurrencies: Vec<usize>,
    /// Samples per concurrency level.
    pub samples: usize,
    /// The implementation label recorded on every row.
    pub implementation: String,
    /// The block this slot belongs to.
    pub block: usize,
    /// The position within the block.
    pub position: usize,
    /// Whether rows carry `latenciesSeconds` (the Xray comparator does).
    pub record_latencies: bool,
}

/// One measured (concurrency, sample) row.
#[derive(Debug, Clone)]
pub struct SampleRow {
    /// Block number.
    pub block: usize,
    /// Position within the block.
    pub position: usize,
    /// Implementation label.
    pub implementation: String,
    /// Concurrency level.
    pub concurrency: usize,
    /// Sample index within this concurrency level.
    pub sample_index: usize,
    /// Successful connections.
    pub connections: usize,
    /// Failed connections.
    pub failed: usize,
    /// Wall-clock seconds covering the whole sample.
    pub wall_seconds: f64,
    /// Successful setup latencies, ascending.
    pub latencies_seconds: Vec<f64>,
}

impl SampleRow {
    /// Connections per second, absent when nothing succeeded.
    #[must_use]
    pub fn connections_per_second(&self) -> Option<f64> {
        if self.latencies_seconds.is_empty() || self.wall_seconds <= 0.0 {
            return None;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "connection counts are small integers, exact in f64"
        )]
        let count = self.connections as f64;
        Some(count / self.wall_seconds)
    }

    /// Renders the row as the drivers wrote it.
    ///
    /// The rate and percentile fields are present only when at least one
    /// connection succeeded, exactly as the `if good:` guard did.
    #[must_use]
    pub fn to_json(&self, record_latencies: bool) -> Json {
        let mut fields: Vec<(String, Json)> = vec![
            ("block".to_owned(), int(self.block)),
            ("position".to_owned(), int(self.position)),
            (
                "implementation".to_owned(),
                Json::string(self.implementation.clone()),
            ),
            ("concurrency".to_owned(), int(self.concurrency)),
            ("sampleIndex".to_owned(), int(self.sample_index)),
            ("connections".to_owned(), int(self.connections)),
            ("failed".to_owned(), int(self.failed)),
            ("wallSeconds".to_owned(), Json::Float(self.wall_seconds)),
        ];
        if record_latencies {
            fields.push((
                "latenciesSeconds".to_owned(),
                Json::Array(
                    self.latencies_seconds
                        .iter()
                        .copied()
                        .map(Json::Float)
                        .collect(),
                ),
            ));
        }
        if let Some(rate) = self.connections_per_second() {
            fields.push(("connectionsPerSecond".to_owned(), Json::Float(rate)));
            let latencies = &self.latencies_seconds;
            // p50 is `good[len // 2]`, which is the floor rank at 0.5.
            for (name, fraction) in [("p50Seconds", 0.5), ("p95Seconds", 0.95), ("p99Seconds", 0.99)]
            {
                if let Ok(value) = aggregate::floor_percentile(latencies, fraction) {
                    fields.push((name.to_owned(), Json::Float(value)));
                }
            }
        }
        Json::object(fields)
    }
}

fn int(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Opens one proxied connection and times setup through the first body byte.
///
/// Returns `None` for any failure, which the caller counts. The steps are the
/// driver's, in order: SOCKS5 no-auth greeting, `CONNECT` to the origin by IPv4,
/// a ten-byte reply whose status byte must be zero, one HTTP/1.0 request, a `200`
/// status line, and a first body byte of `x`.
#[must_use]
pub fn one_connection(socks_port: u16, origin_port: u16) -> Option<Duration> {
    let started = Instant::now();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    let mut stream = TcpStream::connect_timeout(&address, CONNECTION_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT)).ok()?;

    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
    if read_exact(&mut stream, 2)? != [0x05, 0x00] {
        return None;
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    request.extend_from_slice(&origin_port.to_be_bytes());
    stream.write_all(&request).ok()?;
    let reply = read_exact(&mut stream, 10)?;
    if reply[1] != 0 {
        return None;
    }

    let get = format!(
        "GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
    );
    stream.write_all(get.as_bytes()).ok()?;

    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(index) = find_head_end(&response) {
            break index;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 || response.len() + read > MAX_HEAD_BYTES {
            return None;
        }
        response.extend_from_slice(&chunk[..read]);
    };
    let (head, body) = response.split_at(head_end);
    // The driver split the head on CRLF first, then on whitespace, so the carriage
    // return never reaches the status field.
    let first_line = head.split(|byte| *byte == b'\n').next()?;
    let status_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
    let mut status_fields = status_line
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty());
    let _version = status_fields.next()?;
    if status_fields.next()? != b"200" {
        return None;
    }

    // Skip the blank line, then wait for the first body byte.
    let mut first = body.get(4..).unwrap_or_default().first().copied();
    while first.is_none() {
        let mut single = [0_u8; 1];
        if stream.read(&mut single).ok()? == 0 {
            return None;
        }
        first = Some(single[0]);
    }
    if first != Some(b'x') {
        return None;
    }
    Some(started.elapsed())
}

/// Index of the `\r\n\r\n` that ends the response head.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
}

fn read_exact(stream: &mut TcpStream, count: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; count];
    stream.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

/// Runs one sample: `connections` connections across `concurrency` workers.
///
/// Mirrors `ThreadPoolExecutor(max_workers=concurrency).map(one, range(connections))`
/// — the pool size caps parallelism, it does not set the amount of work.
#[must_use]
pub fn run_sample(plan: &SetupRatePlan, concurrency: usize, sample_index: usize) -> SampleRow {
    let next = AtomicUsize::new(0);
    let started = Instant::now();
    let mut latencies: Vec<f64> = Vec::with_capacity(plan.connections);
    let mut failed = 0_usize;
    let workers = concurrency.clamp(1, plan.connections.max(1));
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let next = &next;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    let mut failures = 0_usize;
                    loop {
                        if next.fetch_add(1, Ordering::Relaxed) >= plan.connections {
                            break;
                        }
                        match one_connection(plan.socks_port, plan.origin_port) {
                            Some(elapsed) => mine.push(elapsed.as_secs_f64()),
                            None => failures += 1,
                        }
                    }
                    (mine, failures)
                })
            })
            .collect();
        for handle in handles {
            if let Ok((mine, failures)) = handle.join() {
                latencies.extend(mine);
                failed += failures;
            } else {
                failed += 1;
            }
        }
    });
    let wall_seconds = started.elapsed().as_secs_f64();
    latencies.sort_unstable_by(f64::total_cmp);
    SampleRow {
        block: plan.block,
        position: plan.position,
        implementation: plan.implementation.clone(),
        concurrency,
        sample_index,
        connections: latencies.len(),
        failed,
        wall_seconds,
        latencies_seconds: latencies,
    }
}

/// Makes the warm-up connections a slot performs before it is measured.
///
/// The originals ran the driver with `samples == 0` for this. A warm-up failure
/// is fatal: it means the tunnel never worked, so measuring it would record
/// setup times for a path that does not carry traffic.
///
/// # Errors
///
/// Returns a message when any warm-up connection fails.
pub fn warm_up(socks_port: u16, origin_port: u16) -> Result<(), String> {
    for attempt in 1..=WARMUP_CONNECTIONS {
        if one_connection(socks_port, origin_port).is_none() {
            return Err(format!(
                "warm-up failed on connection {attempt} through SOCKS port {socks_port}"
            ));
        }
    }
    Ok(())
}

/// Runs every (concurrency, sample) cell of one slot.
///
/// # Errors
///
/// Returns a message when the row count is short or any connection failed, which
/// is the drivers' `incomplete setup samples` refusal.
pub fn run_slot(plan: &SetupRatePlan) -> Result<Vec<SampleRow>, String> {
    let mut rows = Vec::with_capacity(plan.concurrencies.len() * plan.samples);
    for concurrency in &plan.concurrencies {
        for sample_index in 0..plan.samples {
            rows.push(run_sample(plan, *concurrency, sample_index));
        }
    }
    let expected = plan.samples * plan.concurrencies.len();
    if rows.len() != expected {
        return Err(format!(
            "incomplete setup samples: expected {expected} rows, produced {}",
            rows.len()
        ));
    }
    if let Some(bad) = rows
        .iter()
        .find(|row| row.failed > 0 || row.connections != plan.connections)
    {
        return Err(format!(
            "incomplete setup samples: concurrency {} sample {} completed {} of {} connections \
             with {} failure(s)",
            bad.concurrency, bad.sample_index, bad.connections, plan.connections, bad.failed
        ));
    }
    Ok(rows)
}

/// Renders a slot's rows as the drivers' `samples.json`.
#[must_use]
pub fn rows_json(rows: &[SampleRow], record_latencies: bool) -> Json {
    Json::Array(
        rows.iter()
            .map(|row| row.to_json(record_latencies))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A loopback stand-in for the Xray SOCKS client plus origin: it speaks just
    /// enough SOCKS5 and HTTP to be indistinguishable from the real path to the
    /// driver, so the protocol contract is testable without a tunnel.
    struct FakeSocks {
        port: u16,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeSocks {
        fn start(body: &'static [u8], status: &'static str) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop = std::sync::Arc::clone(&shutdown);
            let handle = std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(mut stream) = incoming else { break };
                    std::thread::spawn(move || {
                        let mut greeting = [0_u8; 3];
                        if stream.read_exact(&mut greeting).is_err() {
                            return;
                        }
                        if stream.write_all(&[0x05, 0x00]).is_err() {
                            return;
                        }
                        let mut connect = [0_u8; 10];
                        if stream.read_exact(&mut connect).is_err() {
                            return;
                        }
                        if stream.write_all(&[0x05, 0x00, 0, 1, 127, 0, 0, 1, 0, 0]).is_err() {
                            return;
                        }
                        let mut request = [0_u8; 1024];
                        let _ = stream.read(&mut request);
                        let head = format!("HTTP/1.0 {status}\r\nContent-Length: {}\r\n\r\n", body.len());
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body);
                        let _ = stream.flush();
                    });
                }
            });
            Self {
                port,
                shutdown,
                handle: Some(handle),
            }
        }
    }

    impl Drop for FakeSocks {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn plan(socks_port: u16, connections: usize) -> SetupRatePlan {
        SetupRatePlan {
            socks_port,
            origin_port: 9,
            connections,
            concurrencies: vec![1, 2],
            samples: 1,
            implementation: "rust".to_owned(),
            block: 1,
            position: 1,
            record_latencies: true,
        }
    }

    #[test]
    fn a_full_setup_handshake_is_timed_end_to_end() {
        let server = FakeSocks::start(b"xpayload", "200 OK");
        let elapsed = one_connection(server.port, 9).expect("the handshake completes");
        assert!(elapsed > Duration::ZERO);
    }

    /// The driver stops at the first body byte and requires it to be `x`, which is
    /// what proves the response really came from the benchmark origin.
    #[test]
    fn a_wrong_first_body_byte_is_a_failure_not_a_slow_setup() {
        let server = FakeSocks::start(b"ypayload", "200 OK");
        assert!(one_connection(server.port, 9).is_none());
    }

    #[test]
    fn a_non_200_status_is_a_failure() {
        let server = FakeSocks::start(b"xpayload", "503 Service Unavailable");
        assert!(one_connection(server.port, 9).is_none());
    }

    #[test]
    fn an_empty_body_is_a_failure() {
        let server = FakeSocks::start(b"", "200 OK");
        assert!(one_connection(server.port, 9).is_none());
    }

    #[test]
    fn a_closed_port_is_a_failure_rather_than_a_hang() {
        // Bind then drop, so the port is almost certainly unused.
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(one_connection(port, 9).is_none());
    }

    #[test]
    fn a_sample_runs_every_connection_across_the_worker_pool() {
        let server = FakeSocks::start(b"xpayload", "200 OK");
        let plan = plan(server.port, 8);
        let row = run_sample(&plan, 4, 0);
        assert_eq!(row.connections, 8, "the pool size caps parallelism, not work");
        assert_eq!(row.failed, 0);
        assert_eq!(row.latencies_seconds.len(), 8);
        assert!(row.wall_seconds > 0.0);
        assert!(row.connections_per_second().unwrap() > 0.0);
        // Latencies are stored ascending, as `sorted(...)` produced them.
        assert!(row.latencies_seconds.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn a_slot_produces_one_row_per_concurrency_and_sample() {
        let server = FakeSocks::start(b"xpayload", "200 OK");
        let mut plan = plan(server.port, 4);
        plan.samples = 2;
        let rows = run_slot(&plan).expect("every connection succeeds");
        assert_eq!(rows.len(), 4, "2 concurrencies x 2 samples");
        assert_eq!(rows[0].concurrency, 1);
        assert_eq!(rows[2].concurrency, 2);
        assert_eq!(rows[1].sample_index, 1);
    }

    /// A slot with any failed connection is refused; the aggregators would reject
    /// it anyway, and failing here names the cell.
    #[test]
    fn a_slot_with_failures_is_refused() {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let error = run_slot(&plan(port, 2)).unwrap_err();
        assert!(error.starts_with("incomplete setup samples:"), "{error}");
    }

    #[test]
    fn warm_up_failure_is_fatal() {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(warm_up(port, 9).is_err());
        let server = FakeSocks::start(b"xpayload", "200 OK");
        assert!(warm_up(server.port, 9).is_ok());
    }

    #[test]
    fn the_row_document_matches_the_driver_shape() {
        let row = SampleRow {
            block: 2,
            position: 3,
            implementation: "xray".to_owned(),
            concurrency: 8,
            sample_index: 1,
            connections: 4,
            failed: 0,
            wall_seconds: 0.5,
            latencies_seconds: vec![0.01, 0.02, 0.03, 0.04],
        };
        let rendered = row.to_json(true).to_python_json();
        assert!(rendered.contains("\"implementation\": \"xray\""));
        assert!(rendered.contains("\"connectionsPerSecond\": 8.0"));
        assert!(rendered.contains("\"latenciesSeconds\""));
        // int(4 * 0.5) = 2 -> the third smallest.
        assert!(rendered.contains("\"p50Seconds\": 0.03"));
        assert!(rendered.contains("\"p95Seconds\": 0.04"));

        // benchmark-setup-rate.sh omits the raw latencies.
        let rendered = row.to_json(false).to_python_json();
        assert!(!rendered.contains("latenciesSeconds"));
        assert!(rendered.contains("\"p99Seconds\""));
    }

    /// With nothing successful there is no rate and no percentile, exactly as the
    /// driver's `if good:` guard produced.
    #[test]
    fn a_row_with_no_successes_omits_the_rate_and_percentiles() {
        let row = SampleRow {
            block: 1,
            position: 1,
            implementation: "rust".to_owned(),
            concurrency: 1,
            sample_index: 0,
            connections: 0,
            failed: 4,
            wall_seconds: 0.25,
            latencies_seconds: Vec::new(),
        };
        let rendered = row.to_json(true).to_python_json();
        assert!(!rendered.contains("connectionsPerSecond"));
        assert!(!rendered.contains("p50Seconds"));
        assert!(rendered.contains("\"failed\": 4"));
        assert_eq!(row.connections_per_second(), None);
    }
}
