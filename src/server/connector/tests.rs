use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant as WallClock},
};

use tokio::{
    net::TcpListener,
    time::{self, Instant},
};

use super::{
    DestinationConnectError, DestinationConnector, connect_target, literal_socket_addr, race_with,
};
use crate::{
    config::node::network::{DialPolicy, NetworkConfig},
    network::DialTuning,
    network::{AddressFamily, ConnectionPlanner, NetworkEnvironment},
    protocol::vless::{Address, Destination},
    transport::FdBudget,
};

#[test]
fn classifies_numeric_literals_without_resolver() {
    assert_eq!(
        literal_socket_addr("127.0.0.1", 443),
        Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443))
    );
    assert_eq!(
        literal_socket_addr("::1", 8443),
        Some(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 8443))
    );
    // Real hostnames (and near-miss strings) must keep resolver behavior.
    assert_eq!(literal_socket_addr("localhost", 443), None);
    assert_eq!(literal_socket_addr("example.com", 443), None);
    assert_eq!(literal_socket_addr("127.0.0.1.", 443), None);
    assert_eq!(literal_socket_addr("256.0.0.1", 443), None);
}

#[tokio::test(flavor = "current_thread")]
async fn connects_to_domain_holding_ipv4_literal_without_resolver() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");

    let listener_addr = listener
        .local_addr()
        .expect("listener should have a local address");

    // A numeric string carried as a VLESS domain must connect directly.
    let destination = Destination::new(
        Address::Domain("127.0.0.1".to_owned()),
        listener_addr.port(),
    );

    let connector = DestinationConnector::new(Duration::from_secs(1));

    let stream = connector
        .connect(&destination)
        .await
        .expect("numeric literal domain should connect without resolution");

    let (_server_stream, peer_addr) = listener
        .accept()
        .await
        .expect("listener should accept connection");

    assert_eq!(
        stream
            .local_addr()
            .expect("client stream should have a local address"),
        peer_addr
    );
}

#[tokio::test(flavor = "current_thread")]
async fn connects_combined_numeric_target_without_resolver() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");

    let listener_addr = listener
        .local_addr()
        .expect("listener should have a local address");

    let stream = connect_target(&listener_addr.to_string())
        .await
        .expect("numeric host:port target should connect without resolution");

    let (_server_stream, peer_addr) = listener
        .accept()
        .await
        .expect("listener should accept connection");

    assert_eq!(
        stream
            .local_addr()
            .expect("client stream should have a local address"),
        peer_addr
    );
}

#[tokio::test(flavor = "current_thread")]
async fn connects_to_ipv4_destination() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");

    let listener_addr = listener
        .local_addr()
        .expect("listener should have a local address");

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), listener_addr.port());

    let connector = DestinationConnector::new(Duration::from_secs(1));

    let stream = connector
        .connect(&destination)
        .await
        .expect("IPv4 destination should connect");

    let (_server_stream, peer_addr) = listener
        .accept()
        .await
        .expect("listener should accept connection");

    assert_eq!(
        stream
            .peer_addr()
            .expect("client stream should have a peer"),
        listener_addr
    );

    assert_eq!(
        stream
            .local_addr()
            .expect("client stream should have a local address"),
        peer_addr
    );

    assert!(
        stream.nodelay().expect("read TCP_NODELAY"),
        "outbound proxy streams must disable Nagle"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn connects_to_numeric_ipv6_destination_without_dns() {
    let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
        .await
        .expect("IPv6 loopback listener should bind");
    let address = listener.local_addr().expect("read IPv6 listener address");
    let destination = Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), address.port());
    let connector = DestinationConnector::with_environment(
        Duration::from_secs(1),
        NetworkConfig {
            ip: Some(DialPolicy::Ipv6Only),
        },
        NetworkEnvironment::with_routes_and_primary(
            DialPolicy::Ipv6Only,
            false,
            true,
            AddressFamily::Ipv6,
        ),
    );
    let stream = connector
        .connect(&destination)
        .await
        .expect("numeric IPv6 destination should connect");
    let (_accepted, peer) = listener.accept().await.expect("accept IPv6 client");
    assert_eq!(stream.local_addr().expect("read local address"), peer);
}

fn test_planner(mode: DialPolicy, delay_ms: u64) -> ConnectionPlanner {
    let primary = if mode.prefers_ipv4() == Some(true) {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    };
    ConnectionPlanner::new(
        DialTuning {
            fallback_delay_ms: delay_ms,
            ..DialTuning::for_policy(mode)
        },
        NetworkEnvironment::with_routes_and_primary(mode, true, true, primary),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn preferred_family_failure_falls_back_and_updates_health() {
    let planner = test_planner(DialPolicy::PreferIpv6, 5);
    let addresses = vec![
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
    ];
    for _ in 0..2 {
        let (winner, permit) = race_with(
            planner.clone(),
            addresses.clone(),
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            None,
            |address| async move {
                if address.is_ipv6() {
                    Err(io::Error::from_raw_os_error(101))
                } else {
                    Ok(address)
                }
            },
        )
        .await
        .expect("alternate family should win");
        assert!(winner.is_ipv4());
        assert!(permit.is_none());
    }
    assert!(planner.plan(&addresses)[0].is_ipv4());
}

fn percentile(samples: &mut [Duration], percentile: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() - 1) * percentile / 100]
}

#[tokio::test(flavor = "current_thread")]
async fn missing_route_fallback_bypasses_the_normal_delay() {
    let addresses = vec![
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
    ];
    let mut samples = Vec::with_capacity(101);
    for _ in 0..101 {
        let started = WallClock::now();
        let (winner, _) = race_with(
            test_planner(DialPolicy::PreferIpv6, 250),
            addresses.clone(),
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            None,
            |address| async move {
                if address.is_ipv6() {
                    Err(io::Error::from_raw_os_error(101))
                } else {
                    Ok(address)
                }
            },
        )
        .await
        .expect("an immediate missing-route error should launch IPv4 at once");
        assert!(winner.is_ipv4());
        samples.push(started.elapsed());
    }
    let p50 = percentile(&mut samples, 50);
    let p95 = percentile(&mut samples, 95);
    let p99 = percentile(&mut samples, 99);
    eprintln!("missing-route fallback p50={p50:?} p95={p95:?} p99={p99:?}");
    assert!(p99 < Duration::from_millis(50));
}

#[tokio::test(flavor = "current_thread")]
async fn slow_preferred_family_falls_back_after_the_configured_delay() {
    let addresses = vec![
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
    ];
    let fallback_delay = Duration::from_millis(5);
    let mut samples = Vec::with_capacity(101);
    for _ in 0..101 {
        let started = WallClock::now();
        let (winner, _) = race_with(
            test_planner(DialPolicy::PreferIpv6, 5),
            addresses.clone(),
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            None,
            |address| async move {
                if address.is_ipv6() {
                    time::sleep(Duration::from_secs(1)).await;
                }
                Ok(address)
            },
        )
        .await
        .expect("the alternate family should win after the fallback delay");
        assert!(winner.is_ipv4());
        samples.push(started.elapsed());
    }
    let p50 = percentile(&mut samples, 50);
    let p95 = percentile(&mut samples, 95);
    let p99 = percentile(&mut samples, 99);
    eprintln!("slow-family fallback p50={p50:?} p95={p95:?} p99={p99:?}");
    assert!(p50 >= fallback_delay);
    assert!(p99 < Duration::from_millis(100));
}

#[tokio::test(flavor = "current_thread")]
async fn one_overall_deadline_bounds_every_attempt() {
    let timeout = Duration::from_millis(30);
    let started = Instant::now();
    let result = race_with(
        test_planner(DialPolicy::PreferIpv6, 5),
        vec![
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
        ],
        started + timeout,
        timeout,
        None,
        |address| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(address)
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(DestinationConnectError::TimedOut { timeout: observed }) if observed == timeout
    ));
    assert!(started.elapsed() < Duration::from_millis(150));
}

#[tokio::test(flavor = "current_thread")]
async fn single_family_candidates_never_spawn_a_race() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_active = Arc::clone(&active);
    let observed_maximum = Arc::clone(&maximum);
    let observed_calls = Arc::clone(&calls);
    let addresses = vec![
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 443),
    ];
    let (winner, _) = race_with(
        test_planner(DialPolicy::Ipv4Only, 1),
        addresses.clone(),
        Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
        None,
        move |address| {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::AcqRel);
                let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                maximum.fetch_max(current, Ordering::AcqRel);
                let _guard = ActiveAttempt(active);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(address)
            }
        },
    )
    .await
    .expect("first same-family candidate should win without a race");
    assert_eq!(winner, addresses[0]);
    assert_eq!(observed_calls.load(Ordering::Acquire), 1);
    assert_eq!(observed_maximum.load(Ordering::Acquire), 1);
    assert_eq!(observed_active.load(Ordering::Acquire), 0);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cancelling_a_pending_dial_returns_its_descriptor_reservation() {
    let budget = FdBudget::new(1);
    let entered = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&entered);
    let mut dial = Box::pin(race_with(
        test_planner(DialPolicy::Ipv4Only, 1),
        vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)],
        Instant::now() + Duration::from_secs(60),
        Duration::from_secs(60),
        Some(budget.clone()),
        move |_| {
            entered.fetch_add(1, Ordering::AcqRel);
            std::future::pending::<io::Result<SocketAddr>>()
        },
    ));
    // Poll the real dial path once, without advancing any timeout.
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(dial.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(observed.load(Ordering::Acquire), 1);
    assert_eq!(budget.in_use(), 1);
    drop(dial);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(budget.underflows(), 0);
    assert!(
        budget.try_acquire(1).is_some(),
        "cancellation must not starve later dials"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn failed_and_timed_out_dials_return_acquired_descriptor_permits() {
    let budget = FdBudget::new(1);
    // More attempts than capacity proves failures recycle the one permit.
    let addresses = vec![
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 443),
    ];
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let dial_budget = budget.clone();
    let failed = race_with(
        test_planner(DialPolicy::Ipv4Only, 1),
        addresses,
        Instant::now() + Duration::from_secs(60),
        Duration::from_secs(60),
        Some(budget.clone()),
        move |_| {
            calls.fetch_add(1, Ordering::AcqRel);
            assert_eq!(dial_budget.in_use(), 1, "acquire before attempting connect");
            std::future::ready(Err::<SocketAddr, _>(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            )))
        },
    )
    .await;
    assert!(matches!(failed, Err(DestinationConnectError::Io(_))));
    assert_eq!(observed.load(Ordering::Acquire), 2);
    assert_eq!(budget.in_use(), 0);
    let dial_budget = budget.clone();
    let timed_out = race_with(
        test_planner(DialPolicy::Ipv4Only, 1),
        vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)],
        Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
        Some(budget.clone()),
        move |_| {
            assert_eq!(dial_budget.in_use(), 1);
            std::future::pending::<io::Result<SocketAddr>>()
        },
    )
    .await;
    assert!(matches!(
        timed_out,
        Err(DestinationConnectError::TimedOut { .. })
    ));
    assert_eq!(budget.in_use(), 0);
    assert_eq!(budget.underflows(), 0);
    assert_eq!(budget.peak_in_use(), 1);
}

struct ActiveAttempt(Arc<AtomicUsize>);

impl Drop for ActiveAttempt {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn racing_cancels_tasks_and_releases_losing_fd_permits() {
    let active = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&active);
    let budget = FdBudget::new(2);
    let (winner, permit) = race_with(
        test_planner(DialPolicy::PreferIpv6, 5),
        vec![
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
        ],
        Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
        Some(budget.clone()),
        move |address| {
            let active = Arc::clone(&active);
            async move {
                active.fetch_add(1, Ordering::AcqRel);
                let _guard = ActiveAttempt(active);
                if address.is_ipv6() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(address)
            }
        },
    )
    .await
    .expect("IPv4 attempt should win the bounded race");
    assert!(winner.is_ipv4());
    assert_eq!(observed.load(Ordering::Acquire), 0, "loser task leaked");
    assert_eq!(budget.peak_in_use(), 2);
    assert_eq!(budget.in_use(), 1, "only winning permit should remain");
    drop(permit);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn resolves_and_connects_to_domain_destination() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");

    let listener_addr = listener
        .local_addr()
        .expect("listener should have a local address");

    let destination = Destination::new(
        Address::Domain("localhost".to_owned()),
        listener_addr.port(),
    );

    let connector = DestinationConnector::new(Duration::from_secs(5));

    let stream = connector
        .connect(&destination)
        .await
        .expect("localhost destination should resolve and connect");

    let (_server_stream, peer_addr) = listener
        .accept()
        .await
        .expect("listener should accept connection");

    assert_eq!(
        stream
            .local_addr()
            .expect("client stream should have a local address"),
        peer_addr
    );

    assert!(
        stream.nodelay().expect("read TCP_NODELAY"),
        "outbound proxy streams must disable Nagle"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn reuses_pre_resolved_address_without_second_dns_lookup() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let listener_addr = listener
        .local_addr()
        .expect("listener should have a local address");
    let destination = Destination::new(
        Address::Domain("must-not-resolve.invalid".to_owned()),
        listener_addr.port(),
    );
    let connector = DestinationConnector::new(Duration::from_secs(1));

    let stream = connector
        .connect_resolved(&destination, &[Ipv4Addr::LOCALHOST.into()])
        .await
        .expect("pre-resolved loopback must connect");
    let (_server_stream, peer_addr) = listener
        .accept()
        .await
        .expect("listener should accept connection");

    assert_eq!(
        stream
            .local_addr()
            .expect("client stream should have a local address"),
        peer_addr
    );
}
