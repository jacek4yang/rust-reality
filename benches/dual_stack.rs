//! Loopback setup and pure planning costs for autonomous dual-stack dialing.
//!
//! The connect cases include socket creation and kernel TCP setup. The fallback
//! case forces an IPv6 loopback refusal before IPv4 succeeds, without DNS or
//! public network access. Relay throughput remains covered by `relay_backends`.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::{
    config::{AddressFamilyPolicy, NetworkConfig},
    network::{AddressFamily, ConnectionPlanner, NetworkEnvironment},
    protocol::vless::{Address, Destination},
    server::connector::DestinationConnector,
};
use tokio::{net::TcpListener, runtime::Runtime, task::JoinHandle};

struct LoopbackFixture {
    runtime: Runtime,
    ipv4: SocketAddr,
    ipv6: SocketAddr,
    _acceptors: Vec<JoinHandle<()>>,
}

impl LoopbackFixture {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("benchmark runtime must build");
        let (ipv4_listener, ipv6_listener) = runtime.block_on(async {
            let ipv4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("IPv4 loopback must bind");
            let ipv6 = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
                .await
                .expect("IPv6 loopback must bind");
            (ipv4, ipv6)
        });
        let ipv4 = ipv4_listener.local_addr().expect("read IPv4 address");
        let ipv6 = ipv6_listener.local_addr().expect("read IPv6 address");
        let acceptors = vec![
            runtime.spawn(drain_connections(ipv4_listener)),
            runtime.spawn(drain_connections(ipv6_listener)),
        ];
        Self {
            runtime,
            ipv4,
            ipv6,
            _acceptors: acceptors,
        }
    }
}

async fn drain_connections(listener: TcpListener) {
    while let Ok((stream, _)) = listener.accept().await {
        drop(stream);
    }
}

fn connector(policy: AddressFamilyPolicy, environment: NetworkEnvironment) -> DestinationConnector {
    DestinationConnector::with_environment(
        Duration::from_secs(1),
        NetworkConfig {
            address_family: policy,
            fallback_delay_ms: 250,
            ..NetworkConfig::default()
        },
        environment,
    )
}

fn dual_stack_benchmarks(criterion: &mut Criterion) {
    let fixture = LoopbackFixture::new();
    let ipv4_connector = connector(AddressFamilyPolicy::Ipv4Only, NetworkEnvironment::detect());
    let ipv6_connector = connector(AddressFamilyPolicy::Ipv6Only, NetworkEnvironment::detect());

    let fallback_environment = NetworkEnvironment::detect();
    let fallback_connector = connector(AddressFamilyPolicy::Auto, fallback_environment.clone());
    let fallback_destination = Destination::new(
        Address::Domain("benchmark.invalid".to_owned()),
        fixture.ipv4.port(),
    );
    let fallback_addresses = [
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ];

    let mut setup = criterion.benchmark_group("network/connection_setup");
    setup.throughput(Throughput::Elements(1));
    setup.bench_function("numeric_ipv4", |bencher| {
        bencher.iter(|| {
            fixture.runtime.block_on(async {
                ipv4_connector
                    .connect_host("127.0.0.1", fixture.ipv4.port())
                    .await
                    .expect("IPv4 benchmark connect must succeed")
            })
        });
    });
    setup.bench_function("numeric_ipv6", |bencher| {
        bencher.iter(|| {
            fixture.runtime.block_on(async {
                ipv6_connector
                    .connect_host("::1", fixture.ipv6.port())
                    .await
                    .expect("IPv6 benchmark connect must succeed")
            })
        });
    });
    setup.bench_function("ipv6_refused_then_ipv4", |bencher| {
        bencher.iter(|| {
            // Force the planner to try the refused IPv6 endpoint first on
            // every sample; the succeeding IPv4 attempt clears its penalty.
            fallback_environment.record_timeout(AddressFamily::Ipv4, Duration::from_secs(60));
            fixture.runtime.block_on(async {
                fallback_connector
                    .connect_resolved(&fallback_destination, &fallback_addresses)
                    .await
                    .expect("IPv4 fallback must succeed")
            })
        });
    });
    setup.finish();

    let planner = ConnectionPlanner::new(NetworkConfig::default(), NetworkEnvironment::detect());
    let mixed = [
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443),
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 443),
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443),
    ];
    let mut planning = criterion.benchmark_group("network/planning");
    planning.throughput(Throughput::Elements(4));
    planning.bench_function("mixed_four_addresses", |bencher| {
        bencher.iter(|| planner.plan(std::hint::black_box(&mixed)));
    });
    planning.finish();
}

criterion_group!(benches, dual_stack_benchmarks);
criterion_main!(benches);
