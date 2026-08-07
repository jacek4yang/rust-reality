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
    sync::Arc,
    time::Duration,
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rust_reality::{
    config::{
        DirectBarrierConfig, GenerateConfigInput, GenerateLandingConfigInput, ResourceMode,
        generate_landing_config, generate_minimal_config,
    },
    protocol::vless::{Address, Destination},
    runtime::ResourcePressure,
    server::{
        outbound::{OutboundConnectOutcome, OutboundRegistry},
        production::ProductionServer,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time,
};

const CHILD_ENV: &str = "RR_PRESSURE_TEST_CHILD";

#[tokio::test(flavor = "current_thread")]
async fn a_critical_pause_keeps_established_traffic_and_resumes() {
    let port = unused_loopback_port();
    let key = BASE64_URL_SAFE_NO_PAD.encode([0x5a; 32]);
    let config = generate_landing_config(GenerateLandingConfigInput {
        listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        pre_shared_key: rust_reality::config::SecretString::new(key.clone()),
    })
    .expect("landing configuration must generate");
    let server = ProductionServer::from_config(&config).expect("server must compile");
    let gauge = server.pressure_gauge();
    assert_eq!(gauge.state(), ResourcePressure::Normal);

    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_until(async move {
        shutdown_receiver
            .await
            .map_err(|_| io::Error::other("test shutdown sender dropped"))
    }));

    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target must bind");
    let target_port = target.local_addr().expect("target address").port();
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = target.accept().await else {
                continue;
            };
            tokio::spawn(async move {
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
    });

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_port);
    let registry = Arc::new(OutboundRegistry::new(
        &[rust_reality::config::OutboundConfig::Nxr {
            tag: "landing".to_owned(),
            settings: rust_reality::config::NxrSettings {
                address: Ipv4Addr::LOCALHOST.to_string(),
                port,
                pre_shared_key: rust_reality::config::SecretString::new(key),
            },
        }],
        &DirectBarrierConfig::default(),
        Duration::from_secs(1),
    ));

    // One established session before any pressure. The warmup exchange
    // matters: the NXR dial returns after writing the auth request, so only a
    // completed round trip proves the server authenticated and is relaying.
    let established = connect_with_retry(&registry, &destination, Duration::from_secs(5)).await;
    let (mut established_stream, _permit) = established.into_parts();
    ping_pong(&mut established_stream, b"warmup")
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
    ping_pong(&mut established_stream, b"still-alive")
        .await
        .expect("established traffic must continue through critical pressure");

    // The hysteresis exit resumes admission automatically.
    gauge.set(ResourcePressure::Normal);
    let resumed = connect_with_retry(&registry, &destination, Duration::from_secs(10)).await;
    let (mut resumed_stream, _permit) = resumed.into_parts();
    ping_pong(&mut resumed_stream, b"resumed")
        .await
        .expect("a resumed connection must serve traffic");

    // Close every session before shutdown so the graceful drain does not
    // wait out its timeout on still-open relays.
    drop(probe_stream);
    drop(established_stream);
    drop(resumed_stream);
    shutdown_sender.send(()).expect("shutdown must send");
    echo_task.abort();
    server_task
        .await
        .expect("server task must join")
        .expect("server must stop cleanly");
}

async fn connect_with_retry(
    registry: &OutboundRegistry,
    destination: &Destination,
    within: Duration,
) -> rust_reality::server::outbound::OutboundConnection {
    time::timeout(within, async {
        loop {
            match registry.connect("landing", destination).await {
                Ok(OutboundConnectOutcome::Connected(connection)) => break connection,
                Ok(OutboundConnectOutcome::Blackholed) | Err(_) => {
                    time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await
    .expect("the listener must admit the connection within the bound")
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
        config.runtime.resource_mode = ResourceMode::Dedicated;
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
