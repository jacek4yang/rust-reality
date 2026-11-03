use std::{io, net::Ipv4Addr, os::fd::AsRawFd as _, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

use super::{
    DirectionalRelayContext, FdBudget, TcpRelay, TcpRelayConfig, classify_abort,
    is_write_stall_timeout_abort,
};
use crate::transport::{
    BackendRequest, DirectionalRelayOutcome, RelayBackend, RelayContext, RelayDirection,
};

async fn assert_cancelled_owned_relay_resets_drained_peers(splice: bool) {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(
        TcpRelayConfig {
            splice,
            pipe_pool: false,
            ..TcpRelayConfig::for_test()
        },
        budget.clone(),
    )
    .expect("relay policy");
    let (mut client, inbound) = tcp_pair().await;
    let (outbound, mut target) = tcp_pair().await;
    let task = tokio::spawn(async move {
        relay
            .relay_owned(inbound, outbound, RelayContext::owned())
            .await
    });
    // Drain both directions first: unread bytes must not accidentally
    // produce RST and mask a missing cancellation guard.
    time::timeout(Duration::from_secs(2), async {
        client.write_all(b"ping").await.expect("send request");
        let mut bytes = [0_u8; 4];
        target
            .read_exact(&mut bytes)
            .await
            .expect("receive request");
        assert_eq!(&bytes, b"ping");
        target.write_all(b"pong").await.expect("send response");
        client
            .read_exact(&mut bytes)
            .await
            .expect("receive response");
        assert_eq!(&bytes, b"pong");
    })
    .await
    .expect("bidirectional progress");
    if splice {
        assert_eq!(
            budget.in_use(),
            u64::from(crate::transport::UNITS_SPLICE_RELAY),
            "the splice case must exercise real pipe-backed transfer"
        );
    }
    task.abort();
    assert!(
        task.await
            .expect_err("task must be cancelled")
            .is_cancelled()
    );
    for mut peer in [client, target] {
        let error = time::timeout(Duration::from_secs(2), peer.read(&mut [0_u8; 1]))
            .await
            .expect("close must arrive")
            .expect_err("cancelling a live relay must reset, not deliver clean EOF");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }
    assert_eq!(budget.in_use(), 0, "cancellation returns all pipe permits");
    assert_eq!(budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_owned_buffered_relay_resets_drained_peers() {
    assert_cancelled_owned_relay_resets_drained_peers(false).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn cancelled_owned_splice_relay_resets_drained_peers() {
    assert_cancelled_owned_relay_resets_drained_peers(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_buffered_relay_preserves_half_close() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            buffer_bytes: 4 * 1024,
            max_pooled_buffers: 2,
            max_splice_relays: 0,
            splice: false,
            pipe_pool: true,
            max_pooled_pipes: 8,
        },
        FdBudget::new(4_096),
    )
    .expect("relay policy must compile");
    exercise_tcp_relay(relay).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn nonblocking_splice_relay_preserves_half_close() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 2,
            max_splice_relays: 1,
            splice: true,
            pipe_pool: true,
            max_pooled_pipes: 8,
        },
        FdBudget::new(4_096),
    )
    .expect("relay policy must compile");
    exercise_tcp_relay(relay).await;
}

async fn exercise_tcp_relay(relay: TcpRelay) {
    let (mut client, relay_inbound) = tcp_pair().await;
    let (relay_outbound, mut target) = tcp_pair().await;
    let operation = async {
        let relay_io = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
        let client_io = async {
            client.write_all(b"request").await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let target_io = async {
            let mut request = Vec::new();
            target.read_to_end(&mut request).await?;
            target.write_all(b"response").await?;
            target.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(relay_io, client_io, target_io)
    };
    let (stats, response, request) = time::timeout(Duration::from_secs(2), operation)
        .await
        .expect("relay must complete");
    let stats = stats.expect("relay must succeed");
    assert_eq!(request.expect("target I/O must succeed"), b"request");
    assert_eq!(response.expect("client I/O must succeed"), b"response");
    assert_eq!(stats.inbound_to_outbound(), 7);
    assert_eq!(stats.outbound_to_inbound(), 8);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_splice_relay_reserves_four_descriptor_units_before_creating_pipes() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    assert_eq!(budget.in_use(), 0);

    let (mut client, relay_inbound) = tcp_pair().await;
    let (relay_outbound, mut target) = tcp_pair().await;
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sampler = {
        let budget = budget.clone();
        let observed = std::sync::Arc::clone(&observed);
        async move {
            for _ in 0..512 {
                observed.fetch_max(budget.in_use(), std::sync::atomic::Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }
    };
    let exchange = async {
        let relay_io = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
        let client_io = async {
            client.write_all(b"request").await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let target_io = async {
            let mut request = Vec::new();
            target.read_to_end(&mut request).await?;
            target.write_all(b"response").await?;
            target.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(relay_io, client_io, target_io)
    };
    let (result, _sampled) = time::timeout(Duration::from_secs(5), async {
        tokio::join!(exchange, sampler)
    })
    .await
    .expect("relay must complete");
    result.0.expect("splice relay must succeed");

    assert_eq!(
        observed.load(std::sync::atomic::Ordering::Relaxed),
        u64::from(crate::transport::UNITS_SPLICE_RELAY),
        "a bidirectional splice relay uses two pipe pairs, all four accounted"
    );
    assert!(
        budget.in_use() <= u64::from(crate::transport::UNITS_SPLICE_RELAY),
        "after completion the pool may retain drained pipes within its keep count"
    );
    drop(relay);
    assert_eq!(
        budget.in_use(),
        0,
        "dropping the relay (and its pool) releases every pipe descriptor unit"
    );
    assert_eq!(budget.underflows(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn splice_declines_to_buffered_when_descriptors_are_exhausted() {
    // Three units cannot satisfy the four a splice relay requires, so the
    // backend must decline *before* `pipe2` and fall through.
    let budget = FdBudget::new(3);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    let (mut client, relay_inbound) = tcp_pair().await;
    let (relay_outbound, mut target) = tcp_pair().await;
    let exchange = async {
        let relay_io = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
        let client_io = async {
            client.write_all(b"request").await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let target_io = async {
            let mut request = Vec::new();
            target.read_to_end(&mut request).await?;
            target.write_all(b"response").await?;
            target.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(relay_io, client_io, target_io)
    };
    let (stats, response, request) = time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("relay must complete");
    let stats = stats.expect("the buffered backend must carry the connection");
    assert_eq!(request.expect("target I/O must succeed"), b"request");
    assert_eq!(response.expect("client I/O must succeed"), b"response");
    assert_eq!(stats.inbound_to_outbound(), 7);
    assert!(
        budget.in_use() <= u64::from(crate::transport::UNITS_SPLICE_DIRECTION),
        "a declined attempt may retain one drained pipe in the pool"
    );
    drop(relay);
    assert_eq!(
        budget.in_use(),
        0,
        "dropping the relay (and its pool) releases everything"
    );
    assert!(
        budget.denials() >= 1,
        "the decline must be recorded as a descriptor denial, not hidden"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn repeated_splice_relays_return_descriptor_units_to_baseline() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    for _ in 0..16 {
        let (mut client, relay_inbound) = tcp_pair().await;
        let (relay_outbound, mut target) = tcp_pair().await;
        let exchange = async {
            let relay_io = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
            let client_io = async {
                client.write_all(b"request").await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let target_io = async {
                let mut request = Vec::new();
                target.read_to_end(&mut request).await?;
                target.write_all(b"response").await?;
                target.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(relay_io, client_io, target_io)
        };
        let (stats, _, _) = time::timeout(Duration::from_secs(5), exchange)
            .await
            .expect("relay must complete");
        stats.expect("relay must succeed");
        assert!(
            budget.in_use() <= u64::from(crate::transport::UNITS_SPLICE_RELAY),
            "each cycle's pool retention stays within two pipe pairs"
        );
    }
    drop(relay);
    assert_eq!(
        budget.in_use(),
        0,
        "dropping the relay (and its pool) returns the counter to baseline"
    );
    assert_eq!(budget.underflows(), 0);
    assert!(budget.peak_in_use() <= u64::from(crate::transport::UNITS_SPLICE_RELAY));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_cancelled_splice_relay_releases_its_descriptor_units() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    let (_client, relay_inbound) = tcp_pair().await;
    let (relay_outbound, _target) = tcp_pair().await;
    // Neither peer sends or closes, so the relay parks with its pipes open.
    let cancelled = time::timeout(
        Duration::from_millis(50),
        relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned()),
    )
    .await;
    assert!(cancelled.is_err(), "the relay must still be running");
    assert_eq!(
        budget.in_use(),
        0,
        "cancellation must release pipe descriptors and their permit"
    );
    assert_eq!(budget.underflows(), 0);
}

#[cfg(target_os = "linux")]
fn splice_policy() -> TcpRelayConfig {
    TcpRelayConfig {
        buffer_bytes: 32 * 1024,
        max_pooled_buffers: 4,
        max_splice_relays: 8,
        splice: true,
        pipe_pool: true,
        max_pooled_pipes: 8,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_aborted_relay_resets_the_surviving_peer() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            splice: false,
            ..TcpRelayConfig::for_test()
        },
        FdBudget::new(4_096),
    )
    .expect("relay must build");
    let payload = vec![0x5a_u8; 256 * 1024];
    let (mut source_peer, relay_inbound) = tcp_pair().await;
    let (relay_outbound, mut sink_peer) = tcp_pair().await;
    let relaying = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
    let drive = async {
        time::timeout(Duration::from_secs(5), source_peer.write_all(&payload))
            .await
            .expect("source write must not stall")
            .expect("source write must succeed");
        // The sink receives part of the payload, then resets mid-transfer.
        let mut received = vec![0_u8; payload.len() / 2];
        time::timeout(Duration::from_secs(5), sink_peer.read_exact(&mut received))
            .await
            .expect("the first half must not stall")
            .expect("the first half must arrive");
        rr_linux::socket::abort_linger(&sink_peer).expect("abort linger must apply");
        drop(sink_peer);
    };
    let (relay_result, ()) = tokio::join!(relaying, drive);
    let _ignored = relay_result;

    let mut byte = [0_u8; 1];
    let mut attempts = 0_usize;
    let error = loop {
        match source_peer.try_read(&mut byte) {
            Ok(read) => panic!("the surviving peer must not read cleanly ({read})"),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break error,
            Err(_) if attempts < 200 => {
                attempts += 1;
                time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("expected ConnectionReset, got {error}"),
        }
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn an_aborted_splice_relay_resets_the_surviving_peer() {
    let relay =
        TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096)).expect("relay must build");
    let payload = vec![0x5a_u8; 256 * 1024];
    let (mut source_peer, relay_inbound) = tcp_pair().await;
    let (relay_outbound, mut sink_peer) = tcp_pair().await;
    let relaying = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
    let drive = async {
        time::timeout(Duration::from_secs(5), source_peer.write_all(&payload))
            .await
            .expect("source write must not stall")
            .expect("source write must succeed");
        let mut received = vec![0_u8; payload.len() / 2];
        time::timeout(Duration::from_secs(5), sink_peer.read_exact(&mut received))
            .await
            .expect("the first half must not stall")
            .expect("the first half must arrive");
        rr_linux::socket::abort_linger(&sink_peer).expect("abort linger must apply");
        drop(sink_peer);
    };
    let (relay_result, ()) = tokio::join!(relaying, drive);
    let _ignored = relay_result;

    let mut byte = [0_u8; 1];
    let mut attempts = 0_usize;
    let error = loop {
        match source_peer.try_read(&mut byte) {
            Ok(read) => panic!("the surviving peer must not read cleanly ({read})"),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break error,
            Err(_) if attempts < 200 => {
                attempts += 1;
                time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("expected ConnectionReset, got {error}"),
        }
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test(flavor = "current_thread")]
async fn a_graceful_relay_close_is_a_clean_eof_without_abort_marks() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            splice: false,
            ..TcpRelayConfig::for_test()
        },
        FdBudget::new(4_096),
    )
    .expect("relay must build");
    let payload = vec![0x5a_u8; 64 * 1024];
    let (mut source_peer, relay_inbound) = tcp_pair().await;
    let (relay_outbound, mut sink_peer) = tcp_pair().await;
    let relaying = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
    let source_io = async {
        source_peer.write_all(&payload).await?;
        source_peer.shutdown().await?;
        Ok::<_, io::Error>(())
    };
    let sink_io = async {
        let mut received = Vec::new();
        sink_peer.read_to_end(&mut received).await?;
        sink_peer.shutdown().await?;
        Ok::<_, io::Error>(received)
    };
    let (outcome, source_result, received) = tokio::join!(relaying, source_io, sink_io);
    outcome.expect("a graceful relay must succeed");
    source_result.expect("source I/O must succeed");
    assert_eq!(
        received.expect("sink I/O must succeed"),
        payload,
        "a graceful relay must deliver every byte"
    );
    let mut byte = [0_u8; 1];
    let read = source_peer
        .read(&mut byte)
        .await
        .expect("the post-close read must succeed");
    assert_eq!(read, 0, "a graceful close must read as a clean EOF");
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let client = TcpStream::connect(listener.local_addr().expect("address must exist"));
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(client, accept);
    (
        client.expect("client must connect"),
        accepted.expect("server must accept").0,
    )
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_pool_hit_reuses_the_same_pipe_without_syscalls() {
    let budget = FdBudget::new(4_096);
    let pool = super::PipePool::new(8, budget.clone());

    let first = pool.take().expect("first take must create a pipe");
    let first_read_fd = first.pair.read_fd().as_raw_fd();
    let baseline = budget.in_use();
    pool.give_back(first);
    let snapshot = pool.snapshot();
    assert_eq!(snapshot.misses, 1);
    assert_eq!(snapshot.hits, 0);

    let second = pool.take().expect("second take must be a pool hit");
    assert_eq!(
        second.pair.read_fd().as_raw_fd(),
        first_read_fd,
        "a pool hit must return the exact same pipe without pipe2"
    );
    assert_eq!(pool.snapshot().hits, 1);
    assert_eq!(budget.in_use(), baseline, "a hit acquires nothing new");
    drop(second);
}

#[cfg(target_os = "linux")]
#[test]
fn saturated_pipe_pool_reuses_bounded_storage_and_descriptor_permits() {
    const KEEP: usize = 8;
    let budget = FdBudget::new(16);
    let pool = super::PipePool::new(8, budget.clone());
    let mut retained_capacity = None;
    let mut retained_descriptors = None;
    for _ in 0..128 {
        let pipes: [_; KEEP] = std::array::from_fn(|_| pool.take().expect("bounded take"));
        assert_eq!(budget.in_use(), 16);
        assert!(pool.take().is_none(), "all descriptor permits are owned");
        for pipe in pipes {
            assert_eq!(
                rr_linux::socket::pending_input(pipe.pair.read_fd()).unwrap(),
                0
            );
            pool.give_back(pipe);
        }
        let free = super::lock_recover(&pool.free);
        assert_eq!(free.len(), KEEP);
        assert_eq!(budget.in_use(), 16, "retained pipes retain their permits");
        let mut descriptors: [_; KEEP] =
            std::array::from_fn(|index| free[index].pair.read_fd().as_raw_fd());
        descriptors.sort_unstable();
        assert_eq!(
            *retained_capacity.get_or_insert(free.capacity()),
            free.capacity()
        );
        assert_eq!(
            retained_descriptors.get_or_insert(descriptors),
            &descriptors
        );
    }
    let allocation = allocation_counter::measure(|| {
        for _ in 0..128 {
            let pipes: [_; KEEP] = std::array::from_fn(|_| pool.take().expect("warm take"));
            for pipe in pipes {
                pool.give_back(pipe);
            }
        }
    });
    assert_eq!(
        allocation.count_total, 0,
        "saturated reuse allocates nothing"
    );
    assert_eq!(allocation.bytes_current, 0);
    drop(pool);
    assert_eq!(budget.in_use(), 0, "pool retirement releases every permit");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_dirty_pipe_is_discarded_never_recycled() {
    let budget = FdBudget::new(4_096);
    let pool = super::PipePool::new(8, budget);
    let pipe = pool.take().expect("take must create a pipe");
    // Poison the pipe with an unread byte: it must never come back.
    rr_linux::pipe::write_nonblocking(pipe.pair.write_fd(), b"x").expect("poison write");
    pool.give_back(pipe);

    let snapshot = pool.snapshot();
    assert_eq!(snapshot.discards, 1);
    assert_eq!(snapshot.hits, 0, "nothing returned to the free list");
    let fresh = pool.take().expect("the discard forces a fresh pipe");
    assert_eq!(
        pool.snapshot().misses,
        2,
        "a dirty pipe must never be recycled into a session"
    );
    drop(fresh);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn the_pool_shrinks_past_its_keep_count_and_releases_units() {
    let budget = FdBudget::new(4_096);
    let pool = super::PipePool::new(1, budget.clone());
    let baseline = budget.in_use();

    let one = pool.take().expect("first pipe");
    let two = pool.take().expect("second pipe");
    let in_flight = budget.in_use();
    assert!(
        in_flight > baseline,
        "both pipes are accounted while in flight"
    );
    pool.give_back(one);
    assert_eq!(pool.snapshot().shrinks, 0, "the first return fits the keep");
    pool.give_back(two);
    assert_eq!(pool.snapshot().shrinks, 1, "the second return shrinks");
    assert_eq!(
        budget.in_use(),
        in_flight - u64::from(crate::transport::UNITS_SPLICE_DIRECTION),
        "the shrunk pipe releases its units"
    );
    drop(pool);
    assert_eq!(
        budget.in_use(),
        baseline,
        "draining the pool returns every descriptor unit"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn pooled_splice_relays_are_byte_exact_and_reuse_pipes() {
    let relay = TcpRelay::new(splice_policy(), FdBudget::new(4_096)).expect("relay must compile");
    let payload = vec![0x5a_u8; 64 * 1024];
    for round in 0..3 {
        let (outcome, received) = run_one_direction(
            &relay,
            RelayDirection::Downlink,
            BackendRequest::Explicit(RelayBackend::Splice),
            &payload,
        )
        .await;
        let outcome = outcome.expect("directional relay must succeed");
        assert_eq!(received, payload, "round {round} must be byte exact");
        assert_eq!(outcome.backend(), RelayBackend::Splice);
    }
    let stats = relay
        .pipe_pool_stats()
        .expect("the default policy enables the pool");
    assert!(
        stats.hits >= 2,
        "repeated relays must hit the pool, stats: {stats:?}"
    );
    assert_eq!(stats.discards, 0, "clean relays never discard pipes");
}

/// Drives one owned-half directional relay over loopback.
///
/// The receiver's `read_to_end` only terminates when the relay propagates
/// the source EOF as a destination write-side shutdown, so every test
/// through this helper also proves the half-close semantics.
async fn run_one_direction(
    relay: &TcpRelay,
    direction: RelayDirection,
    request: BackendRequest,
    payload: &[u8],
) -> (io::Result<DirectionalRelayOutcome>, Vec<u8>) {
    let (mut sender, relay_source) = tcp_pair().await;
    let (relay_sink, mut receiver) = tcp_pair().await;
    let (source_reader, _source_writer) = relay_source.into_split();
    let (_sink_reader, sink_writer) = relay_sink.into_split();
    let exchange = async {
        let relay_io = relay.relay_direction(
            source_reader,
            sink_writer,
            direction,
            DirectionalRelayContext::owned_direction().with_request(request),
        );
        let sender_io = async {
            sender.write_all(payload).await?;
            sender.shutdown().await?;
            Ok::<_, io::Error>(())
        };
        let receiver_io = async {
            let mut received = Vec::new();
            receiver.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(relay_io, sender_io, receiver_io)
    };
    let (outcome, sent, received) = time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("directional relay must complete");
    sent.expect("sender I/O must succeed");
    (outcome, received.expect("receiver I/O must succeed"))
}

fn directional_payload() -> Vec<u8> {
    (0..300_000_u32).map(|value| value as u8).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn directional_buffered_relay_is_byte_exact_in_both_directions() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            buffer_bytes: 4 * 1024,
            max_pooled_buffers: 2,
            max_splice_relays: 0,
            splice: false,
            pipe_pool: true,
            max_pooled_pipes: 8,
        },
        FdBudget::new(4_096),
    )
    .expect("relay policy must compile");
    let payload = directional_payload();

    for direction in [RelayDirection::Uplink, RelayDirection::Downlink] {
        let (outcome, received) =
            run_one_direction(&relay, direction, BackendRequest::Automatic, &payload).await;
        let outcome = outcome.expect("directional relay must succeed");
        assert_eq!(received, payload, "{direction} bytes must arrive in order");
        assert_eq!(
            outcome.bytes(),
            u64::try_from(payload.len()).unwrap_or(u64::MAX)
        );
        assert_eq!(outcome.backend(), RelayBackend::Buffered);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn directional_splice_relay_is_byte_exact_in_both_directions() {
    let relay =
        TcpRelay::new(splice_policy(), FdBudget::new(4_096)).expect("relay policy must compile");
    let payload = directional_payload();

    for direction in [RelayDirection::Uplink, RelayDirection::Downlink] {
        let (outcome, received) =
            run_one_direction(&relay, direction, BackendRequest::Automatic, &payload).await;
        let outcome = outcome.expect("directional splice relay must succeed");
        assert_eq!(received, payload, "{direction} bytes must arrive in order");
        assert_eq!(
            outcome.bytes(),
            u64::try_from(payload.len()).unwrap_or(u64::MAX)
        );
        assert_eq!(outcome.backend(), RelayBackend::Splice);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_directional_splice_relay_reserves_two_descriptor_units() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    assert_eq!(budget.in_use(), 0);

    let payload = directional_payload();
    let (outcome, received) = run_one_direction(
        &relay,
        RelayDirection::Uplink,
        BackendRequest::Automatic,
        &payload,
    )
    .await;
    let outcome = outcome.expect("directional splice relay must succeed");
    assert_eq!(outcome.backend(), RelayBackend::Splice);
    assert_eq!(received.len(), payload.len());
    assert_eq!(
        budget.peak_in_use(),
        u64::from(crate::transport::UNITS_SPLICE_DIRECTION),
        "one pipe pair is exactly two descriptor units"
    );
    assert!(
        budget.in_use() <= u64::from(crate::transport::UNITS_SPLICE_DIRECTION),
        "after completion the pool may retain the drained pipe within its keep count"
    );
    drop(relay);
    assert_eq!(
        budget.in_use(),
        0,
        "dropping the relay (and its pool) releases the pipe descriptors and permit"
    );
    assert_eq!(budget.underflows(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn repeated_directional_splice_relays_return_descriptor_units_to_baseline() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    for cycle in 0..8 {
        let (outcome, _) = run_one_direction(
            &relay,
            RelayDirection::Downlink,
            BackendRequest::Automatic,
            b"x",
        )
        .await;
        outcome.expect("directional relay must succeed");
        assert!(
            budget.in_use() <= u64::from(crate::transport::UNITS_SPLICE_DIRECTION),
            "cycle {cycle}: pool retention stays within one pipe pair"
        );
    }
    drop(relay);
    assert_eq!(
        budget.in_use(),
        0,
        "dropping the relay (and its pool) returns the counter to baseline"
    );
    assert_eq!(budget.underflows(), 0);
    assert!(budget.peak_in_use() <= u64::from(crate::transport::UNITS_SPLICE_DIRECTION));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn directional_splice_declines_to_buffered_with_bytes_intact() {
    // One unit cannot satisfy the two a directional splice relay requires,
    // so the backend must decline *before* `pipe2` and fall through.
    let budget = FdBudget::new(1);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    let payload = directional_payload();

    let (outcome, received) = run_one_direction(
        &relay,
        RelayDirection::Uplink,
        BackendRequest::Automatic,
        &payload,
    )
    .await;
    let outcome = outcome.expect("the buffered backend must carry the direction");
    assert_eq!(received, payload);
    assert_eq!(outcome.backend(), RelayBackend::Buffered);
    assert_eq!(
        outcome.bytes(),
        u64::try_from(payload.len()).unwrap_or(u64::MAX)
    );
    assert_eq!(budget.in_use(), 0);
    assert!(
        budget.denials() >= 1,
        "the decline must be recorded as a descriptor denial, not hidden"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn an_explicit_buffered_directional_request_bypasses_splice() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");
    let payload = directional_payload();

    let (outcome, received) = run_one_direction(
        &relay,
        RelayDirection::Uplink,
        BackendRequest::Explicit(RelayBackend::Buffered),
        &payload,
    )
    .await;
    let outcome = outcome.expect("explicit buffered direction must succeed");
    assert_eq!(received, payload);
    assert_eq!(outcome.backend(), RelayBackend::Buffered);
    assert_eq!(
        budget.peak_in_use(),
        0,
        "a buffered direction never reserves splice descriptors"
    );
}

/// Fills the destination's TCP buffers without draining them. This is a
/// genuine write stall, not a quiet source. Partial transfer must still
/// fail closed and release all backend resources.
async fn run_stalled_direction(
    relay: &TcpRelay,
    request: BackendRequest,
    write_stall: Duration,
) -> io::Error {
    let (mut sender, relay_source) = tcp_pair().await;
    let (relay_sink, _receiver) = tcp_pair().await;
    let (source_reader, _source_writer) = relay_source.into_split();
    let (_sink_reader, sink_writer) = relay_sink.into_split();
    sender
        .write_all(b"partial")
        .await
        .expect("the prefix must land");
    let outcome = time::timeout(Duration::from_secs(2), async {
        let mut flood = tokio::io::repeat(0x55);
        tokio::select! {
            result = relay.relay_direction(
                source_reader,
                sink_writer,
                RelayDirection::Uplink,
                DirectionalRelayContext::owned_direction()
                    .with_request(request)
                    .with_write_stall(write_stall),
            ) => result,
            result = tokio::io::copy(&mut flood, &mut sender) => {
                panic!("source must not finish before the write stall: {result:?}");
            }
        }
    })
    .await
    .expect("a stalled peer must end the relay well within two seconds");
    drop(sender);
    outcome.expect_err("a stalled peer must fail the relay")
}

/// Asserts that a mid-transfer write_stall abort reports `ConnectionAborted`
/// while preserving the original `TimedOut` as its payload.
fn assert_timeout_abort(error: &io::Error) {
    assert_eq!(
        error.kind(),
        io::ErrorKind::ConnectionAborted,
        "a timeout that truncated a live transfer is an abort, not a clean close"
    );
    let payload = error
        .get_ref()
        .and_then(|payload| payload.downcast_ref::<io::Error>())
        .expect("the abort must preserve the original error as its payload");
    assert_eq!(payload.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test(flavor = "current_thread")]
async fn a_quiet_direction_waits_for_real_fin() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            splice: false,
            ..TcpRelayConfig::for_test()
        },
        FdBudget::new(4_096),
    )
    .expect("relay must build");
    let (mut sender, relay_source) = tcp_pair().await;
    let (relay_sink, mut receiver) = tcp_pair().await;
    let (source_reader, _source_writer) = relay_source.into_split();
    let (_sink_reader, sink_writer) = relay_sink.into_split();
    let relaying = relay.relay_direction(
        source_reader,
        sink_writer,
        RelayDirection::Uplink,
        DirectionalRelayContext::owned_direction()
            .with_request(BackendRequest::Explicit(RelayBackend::Buffered))
            .with_write_stall(Duration::from_millis(10)),
    );
    tokio::pin!(relaying);
    assert!(
        time::timeout(Duration::from_millis(50), &mut relaying)
            .await
            .is_err(),
        "silence is not a FIN or an error"
    );
    sender.shutdown().await.expect("FIN");
    let outcome = time::timeout(Duration::from_secs(2), relaying)
        .await
        .expect("FIN must finish")
        .expect("clean FIN");
    assert_eq!(outcome.bytes(), 0);
    assert_eq!(receiver.read(&mut [0]).await.expect("EOF"), 0);
}

#[test]
fn only_a_rewrapped_timeout_is_a_write_stall_abort() {
    let abort = classify_abort(io::Error::new(io::ErrorKind::TimedOut, "idle"));
    assert!(is_write_stall_timeout_abort(&abort));
    assert!(!is_write_stall_timeout_abort(&io::Error::new(
        io::ErrorKind::TimedOut,
        "an untouched-ledger timeout stays clean"
    )));
    assert!(!is_write_stall_timeout_abort(&io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "a peer abort without a timeout payload"
    )));
    assert!(!is_write_stall_timeout_abort(&io::Error::other("boom")));
}

async fn asymmetric_pair(backend: RelayBackend) {
    let relay =
        TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096)).expect("relay must build");
    let (mut client, inbound) = tcp_pair().await;
    let (outbound, mut server) = tcp_pair().await;
    let context = RelayContext::owned()
        .with_request(BackendRequest::Explicit(backend))
        .with_write_stall(Duration::from_millis(20));
    let traffic = async {
        let mut byte = [0];
        client.write_all(b"Q").await.expect("request");
        server.read_exact(&mut byte).await.expect("request arrives");
        assert_eq!(byte, *b"Q");
        // SSE, reverse asymmetry, then alternating WebSocket-like messages.
        // Each phase exceeds several old direction-idle windows. Each
        // received byte synchronizes progress before advancing the phase.
        for phase in 0..3 {
            for tick in 0..8 {
                time::sleep(Duration::from_millis(15)).await;
                if phase == 1 || (phase == 2 && tick % 2 == 0) {
                    client.write_all(b"U").await.expect("uplink");
                    server.read_exact(&mut byte).await.expect("uplink arrives");
                    assert_eq!(byte, *b"U");
                } else {
                    server.write_all(b"D").await.expect("downlink");
                    client
                        .read_exact(&mut byte)
                        .await
                        .expect("downlink arrives");
                    assert_eq!(byte, *b"D");
                }
            }
        }
        // A FIN is different from silence; the opposite side still drains.
        client.shutdown().await.expect("uplink FIN");
        assert_eq!(server.read(&mut byte).await.expect("uplink EOF"), 0);
        time::sleep(Duration::from_millis(80)).await;
        server.write_all(b"T").await.expect("tail after FIN");
        client.read_exact(&mut byte).await.expect("tail arrives");
        assert_eq!(byte, *b"T");
        server.shutdown().await.expect("downlink FIN");
        assert_eq!(client.read(&mut byte).await.expect("downlink EOF"), 0);
    };
    let (outcome, ()) = time::timeout(Duration::from_secs(3), async {
        tokio::join!(relay.relay_owned(inbound, outbound, context), traffic)
    })
    .await
    .expect("asymmetric relay must finish");
    let outcome = outcome.expect("quiet direction must never abort its peer");
    assert_eq!(outcome.backend(), backend);
}

#[tokio::test(flavor = "current_thread")]
async fn buffered_asymmetry_and_half_close_preserve_both_directions() {
    asymmetric_pair(RelayBackend::Buffered).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn splice_asymmetry_and_half_close_preserve_both_directions() {
    asymmetric_pair(RelayBackend::Splice).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stalled_directional_buffered_relay_times_out_and_returns_its_permit() {
    let relay = TcpRelay::new(
        TcpRelayConfig {
            buffer_bytes: 4 * 1024,
            max_pooled_buffers: 2,
            max_splice_relays: 0,
            splice: false,
            pipe_pool: true,
            max_pooled_pipes: 8,
        },
        FdBudget::new(4_096),
    )
    .expect("relay policy must compile");

    let error = run_stalled_direction(
        &relay,
        BackendRequest::Explicit(RelayBackend::Buffered),
        Duration::from_millis(200),
    )
    .await;
    assert_timeout_abort(&error);
    assert_eq!(
        relay.buffers.inner.permits.available_permits(),
        2,
        "the stalled direction's buffer permit must return to the pool"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_stalled_directional_splice_relay_times_out_and_returns_its_units() {
    let budget = FdBudget::new(64);
    let relay = TcpRelay::new(splice_policy(), budget.clone()).expect("relay must compile");

    let error = run_stalled_direction(
        &relay,
        BackendRequest::Explicit(RelayBackend::Splice),
        Duration::from_millis(200),
    )
    .await;
    assert_timeout_abort(&error);
    assert!(
        budget.in_use() <= u64::from(crate::transport::UNITS_SPLICE_DIRECTION),
        "on the timeout path the drained pipe may be retained within the keep count"
    );
    drop(relay);
    assert_eq!(
        budget.in_use(),
        0,
        "dropping the relay (and its pool) releases everything on the timeout path"
    );
    assert_eq!(budget.underflows(), 0);
}

/// Drives one directional relay whose peer makes steady progress for
/// longer than three write_stall windows, then half-closes.
async fn run_active_direction(
    relay: &TcpRelay,
    request: BackendRequest,
    write_stall: Duration,
) -> (io::Result<DirectionalRelayOutcome>, Vec<u8>) {
    let (mut sender, relay_source) = tcp_pair().await;
    let (relay_sink, mut receiver) = tcp_pair().await;
    let (source_reader, _source_writer) = relay_source.into_split();
    let (_sink_reader, sink_writer) = relay_sink.into_split();
    let exchange = async {
        let relay_io = relay.relay_direction(
            source_reader,
            sink_writer,
            RelayDirection::Uplink,
            DirectionalRelayContext::owned_direction()
                .with_request(request)
                .with_write_stall(write_stall),
        );
        let sender_io = async {
            for chunk in 0..8_u8 {
                sender.write_all(&[chunk; 256]).await?;
                time::sleep(write_stall / 2).await;
            }
            sender.shutdown().await?;
            Ok::<_, io::Error>(())
        };
        let receiver_io = async {
            let mut received = Vec::new();
            receiver.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(relay_io, sender_io, receiver_io)
    };
    let (outcome, sent, received) = time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("an active directional relay must complete");
    sent.expect("sender I/O must succeed");
    (outcome, received.expect("receiver I/O must succeed"))
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn an_active_directional_relay_never_times_out_across_many_windows() {
    let relay = TcpRelay::new(splice_policy(), FdBudget::new(4_096)).expect("relay must compile");
    let write_stall = Duration::from_millis(200);
    let expected: Vec<u8> = (0..8_u8).flat_map(|chunk| [chunk; 256]).collect();

    for backend in [RelayBackend::Splice, RelayBackend::Buffered] {
        let (outcome, received) =
            run_active_direction(&relay, BackendRequest::Explicit(backend), write_stall).await;
        let outcome = outcome.expect("steady progress must never time out");
        assert_eq!(received, expected, "{backend} bytes must arrive in order");
        assert_eq!(
            outcome.bytes(),
            u64::try_from(expected.len()).unwrap_or(u64::MAX)
        );
        assert_eq!(outcome.backend(), backend);
        assert!(
            outcome.duration() > 3 * write_stall,
            "the transfer must span several write_stall windows"
        );
    }
}
