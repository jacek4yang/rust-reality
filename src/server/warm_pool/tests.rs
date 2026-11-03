use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::WarmConnectionPolicy;
use std::{
    future::Future,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    task::{Context, Waker},
    time::Duration,
};

use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time};

use super::{AdaptiveTcpPool, WarmPoolAuthority};
use crate::{
    network::NetworkEnvironment,
    runtime::{PressureGauge, ResourcePressure},
    server::connector::DestinationConnector,
    transport::{FdBudget, FdPressure},
};

struct CoverFixture {
    target: Arc<str>,
    accepted: Arc<Mutex<Vec<tokio::net::TcpStream>>>,
    task: JoinHandle<()>,
}

impl CoverFixture {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover fixture must bind");
        let target: Arc<str> = Arc::from(
            listener
                .local_addr()
                .expect("cover address must exist")
                .to_string(),
        );
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let accepted_for_task = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accepted_for_task
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(stream);
            }
        });
        Self {
            target,
            accepted,
            task,
        }
    }

    fn accepted_count(&self) -> usize {
        self.accepted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

impl Drop for CoverFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn policy() -> WarmConnectionPolicy {
    WarmConnectionPolicy {
        min_ready: 2,
        max_ready: 8,
        max_connecting: 4,
        refill_batch: 4,
        idle_timeout_ms: 500,
        max_lifetime_ms: 1_000,
        shrink_delay_ms: 200,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn controller_retirement_before_notification_registration_is_immediate() {
    let policy = policy();
    let pressure = PressureGauge::new();
    pressure.set(ResourcePressure::Critical);
    let authority = WarmPoolAuthority::new(&policy, 1, pressure);
    let controller = AdaptiveTcpPool::new(
        Arc::from("127.0.0.1:1"),
        91,
        DestinationConnector::with_environment(
            Duration::from_millis(500),
            NetworkConfig::default(),
            NetworkEnvironment::detect(),
        ),
        FdBudget::new(64),
        authority,
        &policy,
    );
    controller.inner.lifecycle.store(
        super::LIFECYCLE_ACTIVE,
        std::sync::atomic::Ordering::Release,
    );
    let retired = Arc::downgrade(&controller.inner);
    let retiring_controller = controller.clone();
    *super::lock(&controller.inner.before_wait) = Some(Box::new(move || {
        assert!(retiring_controller.deactivate());
    }));
    let mut task = Box::pin(super::run_controller(Arc::clone(&controller.inner)));
    drop(controller);

    assert!(
        task.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready(),
        "retirement must not wait for the 30-second maintenance timer"
    );
    assert!(retired.upgrade().is_none());
}

fn pool(
    fixture: &CoverFixture,
    generation: u64,
    policy: &WarmConnectionPolicy,
    authority: WarmPoolAuthority,
    fd_budget: FdBudget,
) -> AdaptiveTcpPool {
    AdaptiveTcpPool::new(
        Arc::clone(&fixture.target),
        generation,
        DestinationConnector::with_environment(
            Duration::from_millis(500),
            NetworkConfig::default(),
            NetworkEnvironment::detect(),
        ),
        fd_budget,
        authority,
        policy,
    )
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("bounded condition must become true");
}

#[test]
fn process_authority_is_strict_and_raii() {
    let mut policy = policy();
    policy.max_ready = 2;
    policy.max_connecting = 1;
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let ready_a = authority.try_ready().expect("first ready permit");
    let ready_b = authority.try_ready().expect("second ready permit");
    assert!(authority.try_ready().is_none());
    let connecting = authority.try_connecting().expect("connecting permit");
    assert!(authority.try_connecting().is_none());
    assert_eq!(authority.counts(), (2, 1));
    drop((ready_a, ready_b, connecting));
    assert_eq!(authority.counts(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn warms_checks_out_and_proactively_refills_without_protocol_bytes() {
    let fixture = CoverFixture::start().await;
    let policy = policy();
    let fd_budget = FdBudget::new(64);
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = pool(&fixture, 7, &policy, authority.clone(), fd_budget.clone());
    assert!(pool.activate());
    assert!(!pool.activate());
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;
    wait_for(|| fixture.accepted_count() == policy.min_ready as usize).await;

    {
        let accepted = fixture
            .accepted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stream in accepted.iter() {
            let mut byte = [0_u8; 1];
            let error = stream
                .try_read(&mut byte)
                .expect_err("warming must not send TLS or protocol bytes");
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
    }

    let checkout = pool.checkout().expect("warm checkout must hit");
    assert_eq!(pool.snapshot().in_use, 1);
    drop(checkout);
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;
    let snapshot = pool.snapshot();
    assert_eq!(snapshot.generation, 7);
    assert_eq!(snapshot.checkout_hit, 1);
    assert_eq!(snapshot.checkout_miss, 0);
    assert_eq!(snapshot.in_use, 0);
    assert!(snapshot.refill >= u64::from(policy.min_ready + 1));

    pool.deactivate();
    wait_for(|| {
        pool.snapshot().ready == 0 && pool.snapshot().connecting == 0 && fd_budget.in_use() == 0
    })
    .await;
    assert_eq!(authority.counts(), (0, 0));
    assert_eq!(fd_budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn burst_growth_and_idle_shrink_are_bounded() {
    let fixture = CoverFixture::start().await;
    let mut policy = policy();
    policy.min_ready = 1;
    policy.shrink_delay_ms = 100;
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = pool(&fixture, 11, &policy, authority, FdBudget::new(64));
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == 1).await;

    for _ in 0..8 {
        drop(pool.checkout());
    }
    wait_for(|| pool.snapshot().target_ready > policy.min_ready).await;
    let grown = pool.snapshot();
    assert!(grown.target_ready <= policy.max_ready);
    assert!(grown.connecting <= policy.max_connecting);
    assert!(grown.checkout_miss > 0);
    wait_for(|| pool.snapshot().ready == pool.snapshot().target_ready).await;
    wait_for(|| pool.snapshot().target_ready == policy.min_ready).await;
    assert!(pool.snapshot().shrink > 0);

    pool.deactivate();
}

#[tokio::test(flavor = "current_thread")]
async fn low_watermark_coalesces_refill_without_waiting_for_exhaustion() {
    let fixture = CoverFixture::start().await;
    let mut policy = policy();
    policy.min_ready = 8;
    policy.max_ready = 8;
    policy.max_connecting = 8;
    policy.refill_batch = 8;
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = pool(&fixture, 12, &policy, authority, FdBudget::new(64));
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == 8).await;
    let initial_refills = pool.snapshot().refill;

    drop(pool.checkout());
    time::sleep(Duration::from_millis(20)).await;
    assert_eq!(pool.snapshot().ready, 7);
    assert_eq!(pool.snapshot().refill, initial_refills);

    drop(pool.checkout());
    wait_for(|| pool.snapshot().ready == 8).await;
    assert_eq!(pool.snapshot().refill, initial_refills + 2);
    pool.deactivate();
}

#[tokio::test(flavor = "current_thread")]
async fn hundreds_of_concurrent_checkouts_remain_bounded_and_single_owned() {
    let fixture = CoverFixture::start().await;
    let mut policy = policy();
    policy.min_ready = 32;
    policy.max_ready = 64;
    policy.max_connecting = 8;
    policy.refill_batch = 8;
    let fd_budget = FdBudget::new(256);
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = pool(&fixture, 15, &policy, authority.clone(), fd_budget.clone());
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..512 {
        let pool = pool.clone();
        tasks.spawn(async move { pool.checkout() });
    }
    let mut owned = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(checkout) = result.expect("checkout task must join") {
            owned.push(checkout);
        }
    }
    let snapshot = pool.snapshot();
    assert_eq!(snapshot.checkout_total, 512);
    assert_eq!(snapshot.checkout_hit + snapshot.checkout_miss, 512);
    assert_eq!(snapshot.in_use, owned.len() as u64);
    assert!(snapshot.ready <= policy.max_ready);
    assert!(snapshot.connecting <= policy.max_connecting);
    assert!(owned.len() <= policy.max_ready as usize);

    drop(owned);
    assert_eq!(pool.snapshot().in_use, 0);
    pool.deactivate();
    wait_for(|| fd_budget.in_use() == 0).await;
    assert_eq!(authority.counts(), (0, 0));
    assert_eq!(fd_budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn checkout_discards_a_peer_closed_idle_socket_and_recovers() {
    let fixture = CoverFixture::start().await;
    let mut policy = policy();
    policy.min_ready = 1;
    policy.max_ready = 1;
    policy.max_connecting = 1;
    policy.refill_batch = 1;
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = pool(&fixture, 13, &policy, authority, FdBudget::new(64));
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == 1 && fixture.accepted_count() == 1).await;

    let mut peer = fixture
        .accepted
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pop()
        .expect("fixture must own the peer half");
    peer.shutdown().await.expect("peer FIN must succeed");
    drop(peer);
    time::sleep(Duration::from_millis(10)).await;

    assert!(pool.checkout().is_none());
    assert_eq!(pool.snapshot().stale_discard, 1);
    wait_for(|| pool.snapshot().ready == 1 && fixture.accepted_count() == 1).await;
    pool.deactivate();
}

#[tokio::test(flavor = "current_thread")]
async fn pressure_reclaims_ready_state_before_checked_out_sessions() {
    let fixture = CoverFixture::start().await;
    let policy = policy();
    let pressure = PressureGauge::new();
    let authority = WarmPoolAuthority::new(&policy, 1, pressure.clone());
    let fd_budget = FdBudget::new(64);
    let pool = pool(&fixture, 16, &policy, authority.clone(), fd_budget.clone());
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;
    let active = pool.checkout().expect("one established session");
    assert_eq!(pool.snapshot().in_use, 1);

    pressure.set(ResourcePressure::Pressure);
    wait_for(|| pool.snapshot().ready == 0 && pool.snapshot().connecting == 0).await;
    assert_eq!(
        pool.snapshot().in_use,
        1,
        "checked out session must survive"
    );
    assert_eq!(authority.counts(), (0, 0));
    assert_eq!(fd_budget.in_use(), 1);

    drop(active);
    assert_eq!(pool.snapshot().in_use, 0);
    assert_eq!(fd_budget.in_use(), 0);
    pressure.set(ResourcePressure::Normal);
    pool.deactivate();
    assert_eq!(fd_budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn fd_pressure_reclaims_ready_permits_and_recovers() {
    let fixture = CoverFixture::start().await;
    let policy = policy();
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let fd_budget = FdBudget::new(64);
    let pool = pool(&fixture, 61, &policy, authority.clone(), fd_budget.clone());
    {
        let now = time::Instant::now();
        let later = now + Duration::from_secs(3);
        let mut state = super::lock(&pool.inner.state);
        state.backoff_until = Some(later);
        super::defer_pressure_refill(&mut state, now);
        assert_eq!(state.backoff_until, Some(later));
        assert_eq!(state.pressure_resume_at, Some(now + super::BASE_BACKOFF));
        // Success resets only network-failure backoff, not pressure.
        state.backoff_until = None;
        assert!(state.pressure_resume_at.is_some());
        state.pressure_resume_at = None;
    }
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;

    // External holders keep pressure above the low watermark even after
    // the pool sheds its own ready sockets. No async interleaving here.
    let mut held = Vec::new();
    while fd_budget.pressure() == FdPressure::Normal {
        held.push(fd_budget.try_acquire(1).expect("budget below capacity"));
    }
    assert_eq!(fd_budget.pressure(), FdPressure::High);
    wait_for(|| pool.snapshot().ready == 0 && pool.snapshot().connecting == 0).await;
    wait_for(|| authority.counts() == (0, 0)).await;
    assert_eq!(fd_budget.in_use(), held.len() as u64);

    drop(held);
    wait_for(|| fd_budget.pressure() == FdPressure::Normal).await;
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;
    pool.deactivate();
    wait_for(|| authority.counts() == (0, 0) && fd_budget.in_use() == 0).await;
    assert_eq!(fd_budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn fd_pressure_backoff_bounds_refill_churn() {
    let fixture = CoverFixture::start().await;
    let policy = policy();
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let budget = FdBudget::new(16);
    let pool = pool(&fixture, 62, &policy, authority.clone(), budget.clone());
    assert!(pool.activate());
    wait_for(|| pool.snapshot().ready == policy.min_ready).await;
    let initial = pool.snapshot().refill;
    let held = budget.try_acquire(13).expect("external pressure units");
    let began = time::Instant::now();
    time::sleep(Duration::from_millis(200)).await;
    let elapsed = began.elapsed();
    let refills = pool.snapshot().refill - initial;
    let limit = (elapsed.as_millis() / super::BASE_BACKOFF.as_millis() + 2)
        * u128::from(policy.refill_batch);
    eprintln!("pressure churn: {refills} refills in {elapsed:?}, limit {limit}");
    drop(held);
    pool.deactivate();
    wait_for(|| authority.counts() == (0, 0) && budget.in_use() == 0).await;
    assert_eq!(budget.underflows(), 0);
    assert!(
        u128::from(refills) <= limit,
        "pressure must not cause a refill storm"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn expiry_and_generation_shutdown_release_speculative_resources() {
    let fixture = CoverFixture::start().await;
    let mut policy = policy();
    policy.min_ready = 1;
    policy.idle_timeout_ms = 100;
    policy.max_lifetime_ms = 150;
    let authority = WarmPoolAuthority::new(&policy, 2, PressureGauge::new());
    let fd_budget = FdBudget::new(64);
    let old = pool(&fixture, 21, &policy, authority.clone(), fd_budget.clone());
    let new = pool(&fixture, 22, &policy, authority.clone(), fd_budget.clone());
    assert!(old.activate());
    assert!(new.activate());
    wait_for(|| old.snapshot().ready == 1 && new.snapshot().ready == 1).await;
    wait_for(|| old.snapshot().stale_discard > 0).await;

    old.deactivate();
    wait_for(|| old.snapshot().ready == 0 && old.snapshot().connecting == 0).await;
    wait_for(|| new.snapshot().ready == 1 && new.snapshot().connecting == 0).await;
    assert_eq!(old.snapshot().generation, 21);
    assert_eq!(new.snapshot().generation, 22);
    assert_eq!(new.snapshot().ready, 1);
    assert_eq!(authority.counts().0, 1);

    new.deactivate();
    wait_for(|| fd_budget.in_use() == 0).await;
    assert_eq!(authority.counts(), (0, 0));
    assert_eq!(fd_budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_refill_backs_off_and_recovers_when_cover_returns() {
    // Own the endpoint while it refuses connections. Releasing a port
    // probe lets another test (or an ephemeral connect) reuse the address.
    let probe = tokio::net::TcpSocket::new_v4().expect("cover socket must exist");
    probe
        .bind((Ipv4Addr::LOCALHOST, 0).into())
        .expect("cover endpoint must bind without listening");
    let address = probe.local_addr().expect("probe address must exist");
    assert!(TcpListener::bind(address).await.is_err());
    let mut policy = policy();
    policy.min_ready = 1;
    policy.max_connecting = 1;
    policy.refill_batch = 1;
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = AdaptiveTcpPool::new(
        Arc::from(address.to_string()),
        41,
        DestinationConnector::new(Duration::from_millis(100)),
        FdBudget::new(64),
        authority,
        &policy,
    );
    assert!(pool.activate());
    time::sleep(Duration::from_millis(350)).await;
    let failed = pool.snapshot();
    assert!(failed.connect_failure >= 1);
    assert_eq!(failed.connect_io, failed.connect_failure);
    assert_eq!(
        failed.connect_timeout + failed.connect_resource + failed.connect_policy,
        0
    );
    assert!(failed.failure_streak > 0);
    assert!(
        failed.refill <= 3,
        "exponential backoff must prevent a tight speculative dial loop"
    );

    let listener = probe
        .listen(128)
        .expect("owned cover endpoint must become a listener");
    let accept = tokio::spawn(async move { listener.accept().await });
    wait_for(|| pool.snapshot().ready == 1).await;
    let accepted = accept
        .await
        .expect("cover accept task must not panic")
        .expect("recovered cover must accept");
    let recovered = pool.snapshot();
    assert_eq!(recovered.ready, 1);
    assert_eq!(recovered.failure_streak, 0);
    assert_eq!(recovered.backoff_remaining_ms, 0);
    assert!(recovered.connect_io >= failed.connect_io);
    pool.deactivate();
    drop(accepted);
}

/// M1 — Listener unavailable while established sessions survive.
///
/// Closing only the listening socket (process still "alive", accepted FD
/// retained) refuses NEW dials with ECONNREFUSED while an already-accepted
/// session can still exchange bytes. This is the OS-level shape behind
/// hypothesis H1 / #253 "new fail, old may work", and discriminates from
/// full peer teardown (see sibling test).
#[tokio::test]
async fn listen_unavailable_established_survives_new_dials_refuse() {
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let addr = listener.local_addr().expect("listener address");
    let mut established = tokio::net::TcpStream::connect(addr)
        .await
        .expect("established dial");
    let (mut peer, _) = listener.accept().await.expect("accept established");
    // Drop listen only — analogue of bind flap / stop-listen without exit.
    drop(listener);

    established
        .write_all(b"ping")
        .await
        .expect("established write must succeed while peer FD lives");
    let mut buf = [0u8; 4];
    peer.read_exact(&mut buf)
        .await
        .expect("peer must still receive");
    assert_eq!(&buf, b"ping");

    let err = tokio::net::TcpStream::connect(addr)
        .await
        .expect_err("new dial must be refused while listener is down");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(
        err.raw_os_error(),
        Some(111),
        "Linux ECONNREFUSED errno must be 111"
    );
}

/// M2 — Full peer teardown (process-restart analogue) kills established.
///
/// Dropping the accepted peer FD (as process exit closes all FDs) makes
/// the established side observe FIN/RST; new dials also refuse while the
/// endpoint is down. Operators: if established sessions ALSO die when new
/// dials refuse, prefer M2 (restart/crash) over M1 (listen-only flap).
#[tokio::test]
async fn peer_teardown_terminates_established_and_new_dials_refuse() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let addr = listener.local_addr().expect("listener address");
    let established = tokio::net::TcpStream::connect(addr)
        .await
        .expect("established dial");
    let (peer, _) = listener.accept().await.expect("accept established");
    drop(listener);
    drop(peer); // process-exit analogue for this accepted socket

    // Wait for FIN/RST without a fixed sleep race: poll try_read until
    // closed/reset, or fall back to a write that must fail.
    let mut established = established;
    let deadline = time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut buf = [0u8; 8];
        match established.try_read(&mut buf) {
            Ok(0) => break,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if time::Instant::now() >= deadline {
                    let write = established.write_all(b"x").await;
                    assert!(
                        write.is_err(),
                        "established write must fail after peer teardown, got {write:?}"
                    );
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
            other => panic!("expected FIN/RST after peer teardown, got {other:?}"),
        }
    }

    let err = tokio::net::TcpStream::connect(addr)
        .await
        .expect_err("new dial must be refused while endpoint is down");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
}

#[test]
fn dial_failure_counts_are_bounded_typed_and_saturating() {
    use super::{DestinationConnectError, DialFailureCounts};
    use std::io;

    let mut counts = DialFailureCounts::default();
    for error in [
        DestinationConnectError::TimedOut {
            timeout: Duration::from_secs(1),
        },
        DestinationConnectError::Io(io::Error::from(io::ErrorKind::TimedOut)),
        DestinationConnectError::DescriptorBudget,
        DestinationConnectError::Allocation,
        DestinationConnectError::Io(io::Error::from(io::ErrorKind::OutOfMemory)),
        DestinationConnectError::NoAddressesForPolicy,
        DestinationConnectError::TooManyResolvedAddresses,
        DestinationConnectError::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "secret endpoint must not be retained",
        )),
    ] {
        counts.record(&error);
    }
    assert_eq!(
        (counts.timeout, counts.resource, counts.policy, counts.io),
        (2, 3, 2, 1)
    );
    counts.io = u64::MAX;
    counts.record(&DestinationConnectError::Io(io::Error::other("private")));
    assert_eq!(counts.io, u64::MAX);
}

#[test]
fn cancelled_unpolled_dials_release_permits_and_clear_gauges() {
    use futures_util::stream::FuturesUnordered;
    use std::sync::atomic::Ordering;

    let policy = policy();
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let pool = AdaptiveTcpPool::new(
        Arc::from("127.0.0.1:1"),
        97,
        DestinationConnector::new(Duration::from_millis(100)),
        FdBudget::new(64),
        authority.clone(),
        &policy,
    );
    // Own the permit before constructing a future that is never polled.
    let permit = authority
        .try_connecting()
        .expect("permit must be available");
    let mut dials: FuturesUnordered<super::DialFuture> = FuturesUnordered::new();
    dials.push(Box::pin(async move {
        let _permit = permit;
        std::future::pending::<super::DialOutcome>().await
    }));
    super::lock(&pool.inner.state).connecting = 1;
    pool.inner.metrics.connecting.store(1, Ordering::Release);
    assert_eq!(authority.counts(), (0, 1));
    for _ in 0..2 {
        super::cancel_speculative_dials(&pool.inner, &mut dials);
        assert!(dials.is_empty());
        assert_eq!(super::lock(&pool.inner.state).connecting, 0);
        assert_eq!(pool.inner.metrics.connecting.load(Ordering::Acquire), 0);
        assert_eq!(authority.counts(), (0, 0));
        assert_eq!(pool.snapshot().connect_failure, 0);
    }
}

#[test]
fn global_ready_saturation_defers_speculative_dials_until_capacity_returns() {
    use futures_util::stream::FuturesUnordered;
    use std::sync::atomic::Ordering;

    let mut policy = policy();
    policy.min_ready = 1;
    policy.max_ready = 1;
    policy.max_connecting = 1;
    policy.refill_batch = 1;
    // Startup authority can be shared by more warm outbounds after reload.
    let authority = WarmPoolAuthority::new(&policy, 1, PressureGauge::new());
    let occupied = authority
        .try_ready()
        .expect("existing pool owns ready capacity");
    let pool = AdaptiveTcpPool::new(
        Arc::from("127.0.0.1:1"),
        98,
        DestinationConnector::new(Duration::from_millis(100)),
        FdBudget::new(64),
        authority.clone(),
        &policy,
    );
    // Exercise scheduling without spawning a controller or polling network I/O.
    pool.inner
        .lifecycle
        .store(super::LIFECYCLE_ACTIVE, Ordering::Release);
    let mut dials: FuturesUnordered<super::DialFuture> = FuturesUnordered::new();
    for _ in 0..20 {
        super::reconcile(&pool.inner, &mut dials);
        assert!(
            dials.is_empty(),
            "full ready capacity must not cause pointless dials"
        );
    }
    assert_eq!(pool.snapshot().refill, 0);
    assert_eq!(authority.counts(), (1, 0));
    drop(occupied);
    super::reconcile(&pool.inner, &mut dials);
    assert_eq!(
        dials.len(),
        1,
        "normal reconciliation resumes after capacity returns"
    );
    assert_eq!(authority.counts(), (0, 1));
    super::cancel_speculative_dials(&pool.inner, &mut dials);
    pool.deactivate();
    assert_eq!(authority.counts(), (0, 0));
}
