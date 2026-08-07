//! One conformance suite run against every relay backend available here.
//!
//! The same scenarios are executed for each backend so that a backend can never
//! be "supported" without demonstrating identical half-close, backpressure,
//! byte-accounting and cancellation behaviour. Backends that the running kernel,
//! capability set or configuration cannot provide are reported as skipped by
//! name; they are never reported as passing.

use std::{io, net::Ipv4Addr, time::Duration};

use rust_reality::{
    config::RelayPolicy,
    transport::{BackendRequest, RelayBackend, RelayContext, TcpRelay},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

const TIMEOUT: Duration = Duration::from_secs(20);

fn policy(backend: RelayBackend) -> RelayPolicy {
    RelayPolicy {
        buffer_bytes: 32 * 1024,
        max_pooled_buffers: 64,
        max_splice_relays: 16,
        max_sockhash_relays: 0,
        max_relay_memory_bytes: u64::MAX,
        max_pinned_memory_bytes: u64::MAX,
        splice: matches!(backend, RelayBackend::Splice),
        sockhash: false,
    }
}

/// Returns the backends this environment can actually exercise.
///
/// sockhash needs eBPF privileges this test environment cannot assume, so it
/// is listed as skipped rather than silently omitted.
fn exercisable() -> Vec<RelayBackend> {
    let mut backends = vec![RelayBackend::Buffered];
    if cfg!(target_os = "linux") {
        backends.push(RelayBackend::Splice);
    }
    backends
}

fn relay_for(backend: RelayBackend) -> TcpRelay {
    TcpRelay::new(
        &policy(backend),
        rust_reality::runtime::FdBudget::new(65_536),
    )
    .expect("relay policy must compile")
}

fn context(backend: RelayBackend) -> RelayContext {
    RelayContext::owned().with_request(BackendRequest::Explicit(backend))
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let connect = TcpStream::connect(listener.local_addr().expect("address must exist"));
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    (
        client.expect("client must connect"),
        accepted.expect("listener must accept").0,
    )
}

/// Runs one full-duplex transfer and returns what each peer observed.
async fn exchange(
    backend: RelayBackend,
    uplink: Vec<u8>,
    downlink: Vec<u8>,
) -> (u64, u64, Vec<u8>, Vec<u8>) {
    let relay = relay_for(backend);
    let (client, relay_inbound) = pair().await;
    let (relay_outbound, target) = pair().await;
    let expected_up = uplink.clone();
    let expected_down = downlink.clone();

    let run = async {
        let relaying = relay.relay_owned(relay_inbound, relay_outbound, context(backend));
        let client_io = async move {
            let (mut reader, mut writer) = client.into_split();
            let send = async move {
                writer.write_all(&uplink).await?;
                writer.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let receive = async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            let (sent, received) = tokio::join!(send, receive);
            sent?;
            received
        };
        let target_io = async move {
            let (mut reader, mut writer) = target.into_split();
            let send = async move {
                writer.write_all(&downlink).await?;
                writer.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let receive = async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            let (sent, received) = tokio::join!(send, receive);
            sent?;
            received
        };
        tokio::join!(relaying, client_io, target_io)
    };

    let (outcome, client_result, target_result) = time::timeout(TIMEOUT, run)
        .await
        .unwrap_or_else(|_| panic!("{backend} relay must not time out"));
    let outcome = outcome.unwrap_or_else(|error| panic!("{backend} relay failed: {error}"));
    let received_down = client_result.expect("client I/O must succeed");
    let received_up = target_result.expect("target I/O must succeed");

    assert_eq!(
        received_up, expected_up,
        "{backend} must deliver every uplink byte in order"
    );
    assert_eq!(
        received_down, expected_down,
        "{backend} must deliver every downlink byte in order"
    );
    assert_eq!(outcome.backend(), backend, "{backend} must not be replaced");
    (
        outcome.inbound_to_outbound(),
        outcome.outbound_to_inbound(),
        received_up,
        received_down,
    )
}

fn pattern(length: usize, salt: u8) -> Vec<u8> {
    (0..length)
        .map(|index| ((index as u64).wrapping_mul(31) as u8) ^ salt)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfers_a_single_byte_in_each_direction() {
    for backend in exercisable() {
        let (up, down, _, _) = exchange(backend, vec![0x41], vec![0x42]).await;
        assert_eq!(up, 1, "{backend} uplink count");
        assert_eq!(down, 1, "{backend} downlink count");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfers_more_than_every_internal_buffer() {
    // Larger than bufferBytes, the splice pipe capacity, and any pooled buffer.
    let size = 3 * 1024 * 1024;
    for backend in exercisable() {
        let (up, down, _, _) = exchange(backend, pattern(size, 0x11), pattern(size, 0x22)).await;
        assert_eq!(up as usize, size, "{backend} uplink count");
        assert_eq!(down as usize, size, "{backend} downlink count");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfers_uplink_only() {
    for backend in exercisable() {
        let (up, down, _, _) = exchange(backend, pattern(256 * 1024, 0x33), Vec::new()).await;
        assert_eq!(up as usize, 256 * 1024, "{backend} uplink count");
        assert_eq!(down, 0, "{backend} downlink count");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfers_downlink_only() {
    for backend in exercisable() {
        let (up, down, _, _) = exchange(backend, Vec::new(), pattern(256 * 1024, 0x44)).await;
        assert_eq!(up, 0, "{backend} uplink count");
        assert_eq!(down as usize, 256 * 1024, "{backend} downlink count");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preserves_reverse_flow_after_a_client_half_close() {
    for backend in exercisable() {
        let relay = relay_for(backend);
        let (mut client, relay_inbound) = pair().await;
        let (relay_outbound, mut target) = pair().await;

        let run = async {
            let relaying = relay.relay_owned(relay_inbound, relay_outbound, context(backend));
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
                // The target answers only after observing the client's EOF,
                // which proves the reverse direction survives a half-close.
                target.write_all(b"response").await?;
                target.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(relaying, client_io, target_io)
        };

        let (outcome, client_result, target_result) = time::timeout(TIMEOUT, run)
            .await
            .unwrap_or_else(|_| panic!("{backend} half-close must not time out"));
        let outcome = outcome.unwrap_or_else(|error| panic!("{backend} relay failed: {error}"));
        assert_eq!(target_result.expect("target I/O"), b"request");
        assert_eq!(client_result.expect("client I/O"), b"response");
        assert_eq!(outcome.inbound_to_outbound(), 7);
        assert_eq!(outcome.outbound_to_inbound(), 8);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applies_backpressure_when_the_reader_is_slow() {
    for backend in exercisable() {
        let relay = relay_for(backend);
        let (client, relay_inbound) = pair().await;
        let (relay_outbound, mut target) = pair().await;
        let payload = pattern(2 * 1024 * 1024, 0x55);
        let expected = payload.clone();

        let run = async {
            let relaying = relay.relay_owned(relay_inbound, relay_outbound, context(backend));
            let client_io = async move {
                let (mut reader, mut writer) = client.into_split();
                let send = async move {
                    writer.write_all(&payload).await?;
                    writer.shutdown().await?;
                    Ok::<_, io::Error>(())
                };
                let drain = async move {
                    let mut sink = Vec::new();
                    reader.read_to_end(&mut sink).await?;
                    Ok::<_, io::Error>(())
                };
                let (sent, drained) = tokio::join!(send, drain);
                sent?;
                drained
            };
            let target_io = async {
                // Deliberately slow: the relay must never buffer without bound.
                let mut received = Vec::new();
                let mut chunk = vec![0_u8; 16 * 1024];
                loop {
                    time::sleep(Duration::from_millis(1)).await;
                    let read = target.read(&mut chunk).await?;
                    if read == 0 {
                        break;
                    }
                    received.extend_from_slice(&chunk[..read]);
                }
                target.shutdown().await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(relaying, client_io, target_io)
        };

        let (outcome, client_result, target_result) = time::timeout(TIMEOUT, run)
            .await
            .unwrap_or_else(|_| panic!("{backend} backpressure must not time out"));
        outcome.unwrap_or_else(|error| panic!("{backend} relay failed: {error}"));
        client_result.expect("client I/O must succeed");
        assert_eq!(target_result.expect("target I/O must succeed"), expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abruptly_closed_peer_surfaces_instead_of_silently_truncating() {
    for backend in exercisable() {
        let relay = relay_for(backend);
        let (client, relay_inbound) = pair().await;
        let (relay_outbound, target) = pair().await;
        let payload = pattern(8 * 1024 * 1024, 0x66);
        let length = payload.len() as u64;

        let run = async {
            let relaying = relay.relay_owned(relay_inbound, relay_outbound, context(backend));
            let client_io = async move {
                let (mut reader, mut writer) = client.into_split();
                let send = async move {
                    // This write is expected to fail once the target vanishes.
                    let _ignored = writer.write_all(&payload).await;
                    let _ignored = writer.shutdown().await;
                };
                let drain = async move {
                    let mut sink = Vec::new();
                    let _ignored = reader.read_to_end(&mut sink).await;
                };
                tokio::join!(send, drain);
            };
            let target_io = async move {
                // Read a little, then vanish mid-transfer.
                let mut chunk = vec![0_u8; 4096];
                let mut target = target;
                let _ignored = target.read(&mut chunk).await;
                drop(target);
            };
            tokio::join!(relaying, client_io, target_io)
        };

        let (outcome, (), ()) = time::timeout(TIMEOUT, run)
            .await
            .unwrap_or_else(|_| panic!("{backend} abrupt close must not hang"));

        match outcome {
            Err(_) => {}
            Ok(outcome) => assert!(
                outcome.inbound_to_outbound() < length,
                "{backend} must not report bytes the peer never received"
            ),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_stops_the_relay_without_reporting_completion() {
    for backend in exercisable() {
        let relay = relay_for(backend);
        let (_client, relay_inbound) = pair().await;
        let (relay_outbound, _target) = pair().await;

        let cancelled = time::timeout(
            Duration::from_millis(50),
            relay.relay_owned(relay_inbound, relay_outbound, context(backend)),
        )
        .await;

        assert!(
            cancelled.is_err(),
            "{backend} must still be relaying when the deadline elapses"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_concurrent_flows_stay_byte_exact() {
    for backend in exercisable() {
        let mut flows = Vec::new();
        for index in 0..24_u8 {
            flows.push(tokio::spawn(async move {
                exchange(
                    backend,
                    pattern(64 * 1024, index),
                    pattern(64 * 1024, index ^ 0xff),
                )
                .await
            }));
        }
        for flow in flows {
            let (up, down, _, _) = flow.await.expect("concurrent flow must finish");
            assert_eq!(up as usize, 64 * 1024);
            assert_eq!(down as usize, 64 * 1024);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_request_for_an_unavailable_backend_falls_back_before_transfer() {
    let relay = relay_for(RelayBackend::Buffered);
    let (client, relay_inbound) = pair().await;
    let (relay_outbound, target) = pair().await;

    let run = async {
        let relaying = relay.relay_owned(
            relay_inbound,
            relay_outbound,
            RelayContext::owned().with_request(BackendRequest::Explicit(RelayBackend::Sockhash)),
        );
        let client_io = async move {
            let (mut reader, mut writer) = client.into_split();
            writer.write_all(b"probe").await?;
            writer.shutdown().await?;
            let mut sink = Vec::new();
            reader.read_to_end(&mut sink).await?;
            Ok::<_, io::Error>(())
        };
        let target_io = async move {
            let (mut reader, mut writer) = target.into_split();
            let mut request = Vec::new();
            reader.read_to_end(&mut request).await?;
            writer.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(relaying, client_io, target_io)
    };

    let (outcome, client_result, target_result) = time::timeout(TIMEOUT, run)
        .await
        .expect("fallback must not time out");
    let outcome = outcome.expect("an unavailable backend must fall back, not fail");
    client_result.expect("client I/O must succeed");
    assert_eq!(target_result.expect("target I/O must succeed"), b"probe");
    assert_ne!(
        outcome.backend(),
        RelayBackend::Sockhash,
        "an unavailable backend must never be reported as the one that ran"
    );
    assert_eq!(outcome.inbound_to_outbound(), 5);
}

#[test]
fn unexercisable_backends_are_reported_rather_than_ignored() {
    let skipped: Vec<RelayBackend> = RelayBackend::all()
        .iter()
        .copied()
        .filter(|backend| !exercisable().contains(backend))
        .collect();
    // The suite must never claim coverage it does not have. Printing the skipped
    // set keeps the gap visible in the captured test log.
    println!("relay backends not exercised in this environment: {skipped:?}");
    assert!(
        exercisable().contains(&RelayBackend::Buffered),
        "the portable backend must always be exercised"
    );
}
