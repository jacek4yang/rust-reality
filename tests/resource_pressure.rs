//! Resource-pressure behavior of the production server.
//!
//! Two properties are exercised here that unit tests cannot reach:
//!
//! * a listener paused at `Critical` pressure keeps established sessions
//!   alive, pauses new setup, and resumes on the hysteresis exit — driven
//!   through the live pressure gauge rather than through real memory
//!   exhaustion, which no test may inflict on the host;
//! * the dedicated-mode soft-limit raise, which must run in a child process
//!   so the test runner's own `RLIMIT_NOFILE` is never touched.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rust_reality::{
    config::{
        DirectBarrierConfig, GenerateConfigInput, GenerateLandingConfigInput, ResourceMode,
        generate_landing_config, generate_minimal_config,
    },
    protocol::vless::{Address, Destination},
    runtime::{PressureGauge, ResourcePressure},
    server::{
        outbound::{OutboundConnectOutcome, OutboundRegistry},
        production::{ProductionServer, ProductionServerError},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time,
};

const CHILD_ENV: &str = "RR_PRESSURE_TEST_CHILD";
const LISTENER_START_ATTEMPTS: usize = 8;
const LISTENER_READY_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(31);
const START_ATTEMPT_STOP_TIMEOUT: Duration = Duration::from_secs(1);

type ServerTask = JoinHandle<Result<(), ProductionServerError>>;

struct RunningLandingServer {
    port: u16,
    gauge: PressureGauge,
    shutdown_sender: oneshot::Sender<()>,
    task: ServerTask,
}

impl RunningLandingServer {
    async fn shutdown(mut self) -> Result<(), String> {
        let _ = self.shutdown_sender.send(());
        await_server_stop(&mut self.task, SERVER_DRAIN_TIMEOUT, "graceful shutdown").await
    }
}

struct EchoTarget {
    destination: Destination,
    task: JoinHandle<()>,
}

impl EchoTarget {
    async fn shutdown(self) -> Result<(), String> {
        self.task.abort();
        match self.task.await {
            Err(error) if error.is_cancelled() => Ok(()),
            Ok(()) => Err("echo accept task exited before cancellation".to_owned()),
            Err(error) => Err(format!("echo accept task failed during cleanup: {error}")),
        }
    }
}

#[derive(Debug)]
enum ListenerStartFailure {
    AddressInUse(String),
    Fatal(String),
    TimedOut(String),
}

#[tokio::test(flavor = "current_thread")]
async fn a_critical_pause_keeps_established_traffic_and_resumes() {
    let key = BASE64_URL_SAFE_NO_PAD.encode([0x5a; 32]);
    let echo = spawn_echo_target().await;
    let destination = echo.destination.clone();
    let mut server = start_landing_server(&key, &destination, &[], &[], LISTENER_READY_TIMEOUT)
        .await
        .expect("landing listener must become ready");
    let port = server.port;
    let gauge = server.gauge.clone();
    assert_eq!(gauge.state(), ResourcePressure::Normal);
    let registry = landing_registry(port, &key);

    // The listener-ready probe above is deliberately outside this timer. This
    // five-second bound measures admission by an already-running server only.
    let established = connect_with_retry(
        &registry,
        &destination,
        Duration::from_secs(5),
        &mut server.task,
    )
    .await;
    let (mut established_stream, _permit) = established.into_parts();
    ping_pong_with_timeout(
        &mut established_stream,
        b"warmup",
        IO_TIMEOUT,
        "warmup exchange",
    )
    .await
    .expect("the session must be relaying before pressure begins");

    // Enter Critical: new setup must pause, the established session must not.
    // A probe can still complete its kernel handshake — pausing accept does
    // not stop SYN processing — but no byte may ever be relayed for it.
    gauge.set(ResourcePressure::Critical);
    let probe = time::timeout(
        Duration::from_secs(5),
        registry.connect("landing", &destination),
    )
    .await
    .expect("a kernel-level connect stays cheap under pressure")
    .expect("the probe dial must succeed");
    let OutboundConnectOutcome::Connected(probe) = probe else {
        panic!("a direct landing dial must connect");
    };
    let (mut probe_stream, _probe_permit) = probe.into_parts();
    let served = time::timeout(
        Duration::from_millis(400),
        ping_pong(&mut probe_stream, b"probe"),
    )
    .await;
    assert!(
        matches!(served, Err(_) | Ok(Err(_))),
        "no new session may be served while the listener is paused at critical"
    );
    ping_pong_with_timeout(
        &mut established_stream,
        b"still-alive",
        IO_TIMEOUT,
        "established-session exchange",
    )
    .await
    .expect("established traffic must continue through critical pressure");

    // The hysteresis exit resumes admission automatically.
    gauge.set(ResourcePressure::Normal);
    let resumed = connect_with_retry(
        &registry,
        &destination,
        Duration::from_secs(10),
        &mut server.task,
    )
    .await;
    let (mut resumed_stream, _permit) = resumed.into_parts();
    ping_pong_with_timeout(
        &mut resumed_stream,
        b"resumed",
        IO_TIMEOUT,
        "resumed exchange",
    )
    .await
    .expect("a resumed connection must serve traffic");

    // Close every session before shutdown so the graceful drain does not
    // wait out its timeout on still-open relays.
    drop(probe_stream);
    drop(established_stream);
    drop(resumed_stream);
    echo.shutdown()
        .await
        .expect("echo target must stop cleanly");
    server.shutdown().await.expect("server must stop cleanly");
}

fn landing_registry(port: u16, key: &str) -> Arc<OutboundRegistry> {
    Arc::new(OutboundRegistry::new(
        &[rust_reality::config::OutboundConfig::Nxr {
            tag: "landing".to_owned(),
            settings: rust_reality::config::NxrSettings {
                address: Ipv4Addr::LOCALHOST.to_string(),
                port,
                pre_shared_key: rust_reality::config::SecretString::new(key.to_owned()),
            },
        }],
        &DirectBarrierConfig::default(),
        Duration::from_secs(1),
        rust_reality::runtime::FdBudget::new(4_096),
    ))
}

/// Exercises both bounded recovery paths deterministically: the first candidate
/// is still reserved by this process, and the replacement server is deliberately
/// not scheduled for 300 ms. Startup must report the bind collision, choose a new
/// port, and wait for an actual TCP listener before returning.
#[tokio::test(flavor = "current_thread")]
async fn listener_ready_retries_an_occupied_port_and_delayed_server() {
    let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("the collision listener must bind");
    let occupied_port = occupied.local_addr().expect("collision address").port();
    let key = BASE64_URL_SAFE_NO_PAD.encode([0x6b; 32]);
    let echo = spawn_echo_target().await;

    let server = start_landing_server(
        &key,
        &echo.destination,
        &[occupied_port],
        &[Duration::from_millis(300), Duration::from_millis(300)],
        LISTENER_READY_TIMEOUT,
    )
    .await
    .expect("the replacement listener must become ready");
    assert_ne!(
        server.port, occupied_port,
        "an AddrInUse startup must rebuild on a fresh port"
    );

    drop(occupied);
    echo.shutdown()
        .await
        .expect("echo target must stop cleanly");
    server.shutdown().await.expect("server must stop cleanly");
}

async fn start_landing_server(
    key: &str,
    destination: &Destination,
    preferred_ports: &[u16],
    scheduling_delays: &[Duration],
    ready_timeout: Duration,
) -> Result<RunningLandingServer, String> {
    let mut last_retryable_failure = None;
    for attempt in 0..LISTENER_START_ATTEMPTS {
        let port = preferred_ports
            .get(attempt)
            .copied()
            .unwrap_or_else(unused_loopback_port);
        let config = generate_landing_config(GenerateLandingConfigInput {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            pre_shared_key: rust_reality::config::SecretString::new(key.to_owned()),
        })
        .expect("landing configuration must generate");
        let server = ProductionServer::from_config(&config).expect("server must compile");
        let gauge = server.pressure_gauge();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let scheduling_delay = scheduling_delays
            .get(attempt)
            .copied()
            .unwrap_or(Duration::ZERO);
        let mut task = tokio::spawn(async move {
            if !scheduling_delay.is_zero() {
                time::sleep(scheduling_delay).await;
            }
            server
                .run_until(async move {
                    shutdown_receiver
                        .await
                        .map_err(|_| io::Error::other("test shutdown sender dropped"))
                })
                .await
        });

        match wait_for_listener(port, key, destination, &mut task, ready_timeout).await {
            Ok(()) => {
                return Ok(RunningLandingServer {
                    port,
                    gauge,
                    shutdown_sender,
                    task,
                });
            }
            Err(ListenerStartFailure::AddressInUse(error)) => {
                last_retryable_failure = Some(error);
            }
            Err(ListenerStartFailure::TimedOut(error)) => {
                let cleanup = stop_start_attempt(shutdown_sender, &mut task).await;
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup_error) => format!("{error}; cleanup failed: {cleanup_error}"),
                });
            }
            Err(ListenerStartFailure::Fatal(error)) => {
                return Err(format!(
                    "landing listener failed before readiness on attempt {attempt}: {error}"
                ));
            }
        }
    }

    Err(format!(
        "landing listener exhausted {LISTENER_START_ATTEMPTS} address-in-use retries; last failure: {}",
        last_retryable_failure.as_deref().unwrap_or("unavailable")
    ))
}

async fn wait_for_listener(
    port: u16,
    key: &str,
    destination: &Destination,
    server_task: &mut ServerTask,
    within: Duration,
) -> Result<(), ListenerStartFailure> {
    let registry = landing_registry(port, key);
    let connect_until_ready = async {
        loop {
            let probe = time::timeout(Duration::from_millis(250), async {
                let outcome = registry
                    .connect("landing", destination)
                    .await
                    .map_err(|error| error.to_string())?;
                let OutboundConnectOutcome::Connected(connection) = outcome else {
                    return Err("readiness outbound was unexpectedly blackholed".to_owned());
                };
                let (mut stream, _permit) = connection.into_parts();
                ping_pong_with_timeout(
                    &mut stream,
                    b"listener-ready",
                    Duration::from_millis(200),
                    "listener readiness exchange",
                )
                .await
                .map_err(|error| error.to_string())
            })
            .await;
            if matches!(probe, Ok(Ok(()))) {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    };

    tokio::select! {
        outcome = server_task => match outcome {
            Ok(Err(error)) => {
                let detail = format!("{error} ({error:?})");
                if matches!(
                    &error,
                    ProductionServerError::Bind { source, .. }
                        if source.kind() == io::ErrorKind::AddrInUse
                ) {
                    Err(ListenerStartFailure::AddressInUse(detail))
                } else {
                    Err(ListenerStartFailure::Fatal(detail))
                }
            }
            Ok(Ok(())) => Err(ListenerStartFailure::Fatal(
                "server exited cleanly before listener readiness".to_owned(),
            )),
            Err(error) => Err(ListenerStartFailure::Fatal(format!(
                "server task failed before listener readiness: {error}"
            ))),
        },
        result = time::timeout(within, connect_until_ready) => match result {
            Ok(()) => Ok(()),
            Err(error) => Err(ListenerStartFailure::TimedOut(format!(
                "listener {port} was not reachable within {within:?}: {error}"
            ))),
        },
    }
}

async fn spawn_echo_target() -> EchoTarget {
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target must bind");
    let target_port = target.local_addr().expect("target address").port();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = target.accept() => {
                    let Ok((mut stream, _)) = accepted else {
                        continue;
                    };
                    connections.spawn(async move {
                        let mut buffer = [0_u8; 16_384];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => {
                                    if stream.write_all(&buffer[..read]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        panic!("echo connection task failed: {error}");
                    }
                }
            }
        }
    });
    EchoTarget {
        destination: Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_port),
        task,
    }
}

async fn stop_start_attempt(
    shutdown_sender: oneshot::Sender<()>,
    task: &mut ServerTask,
) -> Result<(), String> {
    let _ = shutdown_sender.send(());
    await_server_stop(task, START_ATTEMPT_STOP_TIMEOUT, "failed startup cleanup").await
}

async fn await_server_stop(
    task: &mut ServerTask,
    within: Duration,
    context: &str,
) -> Result<(), String> {
    match time::timeout(within, &mut *task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(format!("{context}: {error} ({error:?})")),
        Ok(Err(error)) => Err(format!("{context}: server task join failed: {error}")),
        Err(error) => {
            task.abort();
            let abort_result = task.await;
            Err(format!(
                "{context}: server did not stop within {within:?}: {error}; abort result: {abort_result:?}"
            ))
        }
    }
}

async fn connect_with_retry(
    registry: &OutboundRegistry,
    destination: &Destination,
    within: Duration,
    server_task: &mut ServerTask,
) -> rust_reality::server::outbound::OutboundConnection {
    let last_error = Arc::new(Mutex::new("no connection attempt completed".to_owned()));
    let connect_last_error = Arc::clone(&last_error);
    let connect = time::timeout(within, async move {
        loop {
            match registry.connect("landing", destination).await {
                Ok(OutboundConnectOutcome::Connected(connection)) => return connection,
                Ok(OutboundConnectOutcome::Blackholed) => {
                    *connect_last_error.lock().expect("last error lock") =
                        "outbound was unexpectedly blackholed".to_owned();
                    time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    *connect_last_error.lock().expect("last error lock") = error.to_string();
                    time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });

    tokio::select! {
        outcome = server_task => match outcome {
            Ok(Ok(())) => panic!("server exited cleanly while awaiting an admitted connection"),
            Ok(Err(error)) => panic!(
                "server failed while awaiting an admitted connection: {error} ({error:?})"
            ),
            Err(error) => panic!("server task failed while awaiting an admitted connection: {error}"),
        },
        result = connect => match result {
            Ok(connection) => connection,
            Err(error) => {
                let last_error = last_error.lock().expect("last error lock");
                panic!(
                    "listener did not admit the connection within {within:?}: {error}; last error: {last_error}"
                );
            }
        },
    }
}

async fn ping_pong(stream: &mut tokio::net::TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(payload).await?;
    let mut response = vec![0_u8; payload.len()];
    stream.read_exact(&mut response).await?;
    if response != payload {
        return Err(io::Error::other("the echo did not come back intact"));
    }
    Ok(())
}

async fn ping_pong_with_timeout(
    stream: &mut tokio::net::TcpStream,
    payload: &[u8],
    within: Duration,
    context: &str,
) -> io::Result<()> {
    match time::timeout(within, ping_pong(stream, payload)).await {
        Ok(result) => result,
        Err(error) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{context} exceeded {within:?}: {error}"),
        )),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn listener_ready_timeout_is_fail_closed_without_retrying() {
    let key = BASE64_URL_SAFE_NO_PAD.encode([0x7c; 32]);
    let echo = spawn_echo_target().await;
    let error = match start_landing_server(
        &key,
        &echo.destination,
        &[],
        &[Duration::from_millis(200), Duration::ZERO],
        Duration::from_millis(40),
    )
    .await
    {
        Ok(server) => {
            server
                .shutdown()
                .await
                .expect("unexpected server must still be cleaned up");
            panic!("one readiness timeout must fail instead of trying the viable second attempt");
        }
        Err(error) => error,
    };
    assert!(
        error.contains("was not reachable within"),
        "the readiness timeout must be preserved: {error}"
    );
    echo.shutdown()
        .await
        .expect("echo target must stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn server_shutdown_error_is_propagated() {
    let (shutdown_sender, _shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async {
        Err(ProductionServerError::Signal(io::Error::other(
            "injected shutdown failure",
        )))
    });
    let server = RunningLandingServer {
        port: 0,
        gauge: PressureGauge::new(),
        shutdown_sender,
        task,
    };
    let error = server
        .shutdown()
        .await
        .expect_err("a production server error must fail shutdown");
    assert!(
        error.contains("injected shutdown failure"),
        "the concrete production error must be retained: {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_echo_is_bounded() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("stalled target must bind");
    let address = listener.local_addr().expect("stalled target address");
    let target = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("stalled target accept");
        std::future::pending::<()>().await;
    });
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("stalled target connect");
    let error = ping_pong_with_timeout(
        &mut stream,
        b"will-stall",
        Duration::from_millis(40),
        "stalled echo",
    )
    .await
    .expect_err("a stalled echo must time out");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    target.abort();
    let result = target.await;
    assert!(
        matches!(result, Err(ref error) if error.is_cancelled()),
        "stalled target must be reaped after abort: {result:?}"
    );
}

/// Child entry point: runs the real setrlimit and a dedicated-mode compile.
///
/// The parent halves the child's soft limit before exec, so the raise has
/// visible work to do. Everything here is process-local to the child.
#[cfg(target_os = "linux")]
#[test]
fn dedicated_mode_raises_the_soft_limit_in_a_child_process() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let before = rr_linux::descriptor_limit().expect("limits must be readable");
        assert_eq!(before.soft, 256, "the parent must lower the soft limit");
        let target =
            rust_reality::runtime::machine::soft_limit_raise_target(before.soft, before.hard)
                .expect("a lower soft limit must plan a raise");
        let after = rr_linux::raise_descriptor_soft_limit(target).expect("raise must succeed");
        assert_eq!(
            after.soft, before.hard,
            "the dedicated mode raises the soft limit exactly to the hard limit"
        );

        let generated = generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("127.0.0.1").expect("address must parse"),
            port: 8_443,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate");
        let mut config = generated.config().clone();
        config.runtime.resource_mode = Some(ResourceMode::Dedicated);
        ProductionServer::from_config(&config)
            .expect("a dedicated server must compile against the raised limit");
        return;
    }

    let Ok(bash) = which_bash() else {
        eprintln!("bash is unavailable; skipping the child-process raise test");
        return;
    };
    let executable = std::env::current_exe().expect("test executable path");
    let output = std::process::Command::new(bash)
        .arg("-c")
        .arg(format!(
            "ulimit -Sn 256 && exec '{}' --exact --nocapture dedicated_mode_raises_the_soft_limit_in_a_child_process",
            executable.display()
        ))
        .env(CHILD_ENV, "1")
        .output()
        .expect("the child process must spawn");
    assert!(
        output.status.success(),
        "child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn which_bash() -> io::Result<std::path::PathBuf> {
    for candidate in ["/bin/bash", "/usr/bin/bash"] {
        let path = std::path::Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "bash not found"))
}

fn unused_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .unwrap_or_else(|error| panic!("reserve loopback port: {error}"))
}
