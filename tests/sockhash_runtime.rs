//! Privileged `SOCKHASH` runtime gates: real traffic through the kernel
//! redirect, driven by `TcpRelay::relay_owned` itself.
//!
//! Every test is `#[ignore]`d by default so an unprivileged run neither fails
//! nor silently claims coverage it does not have. Run them explicitly:
//!
//! ```text
//! cargo test --test sockhash_runtime --no-run && sudo -n <binary> --ignored --test-threads=1 --nocapture
//! ```
//!
//! On a host where the gate is supposed to run, a refusal is a real result
//! rather than a skip: `armed_relay` fails the test when the controller could
//! not be constructed, and names the reported decline reason.

#![cfg(target_os = "linux")]

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use rust_reality::{
    config::RelayPolicy,
    runtime::FdBudget,
    transport::{BackendRequest, RelayBackend, RelayContext, RelayOutcome, TcpRelay},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time,
};

const TIMEOUT: Duration = Duration::from_secs(15);

/// Grace period for the spawned relay task to reach the arm before any peer
/// speaks.
///
/// The FIONREAD guard is doing its job when a peer that talks first gets
/// declined to splice: data already queued in the kernel cannot join the
/// redirect without reordering the stream. These gates exercise the *armed*
/// path, so every peer waits for the arm — which takes effect within
/// microseconds of the task being scheduled — before writing its first byte.
const ARM_SETTLE: Duration = Duration::from_millis(100);

fn policy(max_sockhash_relays: u32) -> RelayPolicy {
    RelayPolicy {
        buffer_bytes: 32 * 1024,
        max_pooled_buffers: 8,
        max_splice_relays: 8,
        max_sockhash_relays,
        max_relay_memory_bytes: u64::MAX,
        max_pinned_memory_bytes: u64::MAX,
        splice: true,
        pipe_pool: true,
        max_pooled_pipes: 8,
        sockhash: true,
    }
}

/// Builds a relay whose sockhash controller must be live.
///
/// These gates run under privilege; a host that cannot construct the
/// controller fails the gate loudly, with the exact decline reason, instead
/// of silently testing the splice fallback.
fn armed_relay(max_sockhash_relays: u32) -> TcpRelay {
    let relay = TcpRelay::new(&policy(max_sockhash_relays), FdBudget::new(65_536))
        .expect("relay policy must compile");
    let capability = relay.report().sockhash;
    assert!(
        capability.available,
        "this gate requires a live sockhash controller; the backend declined: {:?}",
        capability.decline_reason
    );
    relay
}

fn explicit_sockhash() -> RelayContext {
    RelayContext::owned().with_request(BackendRequest::Explicit(RelayBackend::Sockhash))
}

/// Starts one relayed pair: a client, the relay driving `relay_owned`, and
/// the target. The relay runs on a spawned task so the test can drive both
/// peers concurrently.
async fn relay_pair(
    relay: &TcpRelay,
    context: RelayContext,
) -> (TcpStream, TcpStream, JoinHandle<io::Result<RelayOutcome>>) {
    let inbound_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let inbound_addr = inbound_listener.local_addr().expect("address");
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let target_addr = target_listener.local_addr().expect("address");

    let client = TcpStream::connect(inbound_addr)
        .await
        .expect("client must connect");
    let (inbound, _) = inbound_listener.accept().await.expect("must accept");
    let outbound = TcpStream::connect(target_addr)
        .await
        .expect("relay must connect");
    let (target, _) = target_listener.accept().await.expect("must accept");

    let relay = relay.clone();
    let handle = tokio::spawn(async move { relay.relay_owned(inbound, outbound, context).await });
    (client, target, handle)
}

/// Runs one full-duplex exchange: both peers write their payload, half-close,
/// and read to EOF. Returns the relay outcome and what each peer received.
async fn full_exchange(
    relay: &TcpRelay,
    context: RelayContext,
    uplink: Vec<u8>,
    downlink: Vec<u8>,
) -> (RelayOutcome, Vec<u8>, Vec<u8>) {
    let (client, target, relaying) = relay_pair(relay, context).await;
    time::sleep(ARM_SETTLE).await;
    let expected_up = uplink.clone();
    let expected_down = downlink.clone();
    let run = async {
        let client_io = async move {
            let (mut reader, mut writer) = client.into_split();
            let send = async move {
                writer.write_all(&uplink).await?;
                writer.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let (sent, received) = tokio::join!(send, async {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            });
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
            let (sent, received) = tokio::join!(send, async {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            });
            sent?;
            received
        };
        tokio::join!(relaying, client_io, target_io)
    };
    let (outcome, client_result, target_result) = time::timeout(TIMEOUT, run)
        .await
        .expect("the armed relay must not time out");
    let outcome = outcome
        .expect("the relay task must not panic")
        .expect("the armed relay must succeed");
    (
        outcome,
        target_result.expect("target I/O must succeed"),
        client_result.expect("client I/O must succeed"),
    )
        .assert_bytes(expected_up, expected_down)
}

trait AssertBytes {
    fn assert_bytes(
        self,
        expected_up: Vec<u8>,
        expected_down: Vec<u8>,
    ) -> (RelayOutcome, Vec<u8>, Vec<u8>);
}

impl AssertBytes for (RelayOutcome, Vec<u8>, Vec<u8>) {
    fn assert_bytes(
        self,
        expected_up: Vec<u8>,
        expected_down: Vec<u8>,
    ) -> (RelayOutcome, Vec<u8>, Vec<u8>) {
        assert_eq!(
            self.1, expected_up,
            "the target must receive every uplink byte in order"
        );
        assert_eq!(
            self.2, expected_down,
            "the client must receive every downlink byte in order"
        );
        self
    }
}

fn pattern(length: usize, salt: u8) -> Vec<u8> {
    (0..length)
        .map(|index| ((index as u64).wrapping_mul(31) as u8) ^ salt)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn automatic_selection_arms_sockhash_and_reports_exact_counts() {
    let relay = armed_relay(4);
    let uplink = pattern(300_000, 0x11);
    let downlink = pattern(250_000, 0x22);
    let (outcome, _, _) = full_exchange(&relay, RelayContext::owned(), uplink, downlink).await;
    assert_eq!(
        outcome.backend(),
        RelayBackend::Sockhash,
        "the automatic order must prefer the verified sockhash backend"
    );
    assert_eq!(outcome.inbound_to_outbound(), 300_000);
    assert_eq!(outcome.outbound_to_inbound(), 250_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn a_large_payload_drains_before_the_synthesized_fin() {
    // The drain gate: the client dumps 3 MiB and half-closes immediately.
    // Redirect delivery is asynchronous, so the synthesized FIN must wait for
    // the drain barrier — a premature shutdown overtakes the backlog and the
    // target sees EOF with missing bytes (measured on kernel 6.12).
    let relay = armed_relay(4);
    let (mut client, mut target, relaying) = relay_pair(&relay, explicit_sockhash()).await;
    time::sleep(ARM_SETTLE).await;
    let payload = pattern(3 * 1024 * 1024, 0x33);
    let expected = payload.clone();
    let run = async {
        let client_io = async {
            client.write_all(&payload).await?;
            client.shutdown().await?;
            let mut received = Vec::new();
            client.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        let target_io = async {
            let mut received = Vec::new();
            target.read_to_end(&mut received).await?;
            target.write_all(b"ack").await?;
            target.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(relaying, client_io, target_io)
    };
    let (outcome, response, received) = time::timeout(TIMEOUT, run)
        .await
        .expect("the drain must complete");
    let outcome = outcome
        .expect("the relay task must not panic")
        .expect("the armed relay must succeed");
    assert_eq!(
        received.expect("target I/O must succeed"),
        expected,
        "every byte must drain before the target observes EOF"
    );
    assert_eq!(response.expect("client I/O must succeed"), b"ack");
    assert_eq!(outcome.backend(), RelayBackend::Sockhash);
    assert_eq!(outcome.inbound_to_outbound(), 3 * 1024 * 1024);
    assert_eq!(outcome.outbound_to_inbound(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn half_close_drains_and_the_reverse_direction_still_works() {
    // Strictly sequential half-close: the client sends and half-closes; the
    // target must receive every byte and then EOF; only then does the target
    // respond, and the reverse direction must work until its own FIN.
    let relay = armed_relay(4);
    let (mut client, mut target, relaying) = relay_pair(&relay, explicit_sockhash()).await;
    time::sleep(ARM_SETTLE).await;
    let uplink = pattern(512 * 1024, 0x44);
    let downlink = pattern(128 * 1024, 0x55);
    let expected_up = uplink.clone();
    let expected_down = downlink.clone();
    let run = async {
        let client_io = async {
            client.write_all(&uplink).await?;
            client.shutdown().await?;
            let mut received = Vec::new();
            client.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        let target_io = async {
            let mut received = Vec::new();
            target.read_to_end(&mut received).await?;
            target.write_all(&downlink).await?;
            target.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(relaying, client_io, target_io)
    };
    let (outcome, received_down, received_up) = time::timeout(TIMEOUT, run)
        .await
        .expect("the half-close exchange must complete");
    let outcome = outcome
        .expect("the relay task must not panic")
        .expect("the armed relay must succeed");
    assert_eq!(received_up.expect("target I/O must succeed"), expected_up);
    assert_eq!(
        received_down.expect("client I/O must succeed"),
        expected_down,
        "the reverse direction must work after the client's half-close"
    );
    assert_eq!(outcome.backend(), RelayBackend::Sockhash);
    assert_eq!(outcome.inbound_to_outbound(), 512 * 1024);
    assert_eq!(outcome.outbound_to_inbound(), 128 * 1024);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn a_reset_mid_session_aborts_and_releases_everything() {
    // One armed relay, admission bound exactly one. The client resets
    // mid-session (closing with unread redirected data); the relay must abort
    // the session, and a following connection must arm again — proving the
    // map entries and the admission were released on the error path.
    let relay = armed_relay(1);
    let (client, mut target, relaying) = relay_pair(&relay, explicit_sockhash()).await;
    time::sleep(ARM_SETTLE).await;
    target
        .write_all(&pattern(64 * 1024, 0x66))
        .await
        .expect("target write must land");
    // Let the redirect deliver into the client's receive queue, then drop the
    // client with that data unread: the kernel resets the connection.
    time::sleep(Duration::from_millis(300)).await;
    drop(client);

    let outcome = time::timeout(TIMEOUT, relaying)
        .await
        .expect("the reset must end the session")
        .expect("the relay task must not panic");
    assert!(
        outcome.is_err(),
        "a reset must abort the armed session, not report a clean completion"
    );
    drop(target);

    // Admission and both map entries must be back at baseline.
    let (outcome, _, _) = full_exchange(
        &relay,
        explicit_sockhash(),
        pattern(64 * 1024, 0x77),
        pattern(64 * 1024, 0x88),
    )
    .await;
    assert_eq!(
        outcome.backend(),
        RelayBackend::Sockhash,
        "a relay after the reset must arm again; admission and entries leaked otherwise"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn a_stalled_session_times_out_and_releases_everything() {
    // One armed relay, admission bound exactly one. Both peers exchange a few
    // bytes and then stall without ever closing: the progress-based liveness
    // must end the session with TimedOut, and a following connection must arm
    // again — proving the map entries and the admission were released.
    let relay = armed_relay(1);
    let context = explicit_sockhash().with_liveness(Duration::from_secs(1));
    let (mut client, mut target, relaying) = relay_pair(&relay, context).await;
    time::sleep(ARM_SETTLE).await;
    client
        .write_all(b"stalled")
        .await
        .expect("client write must land");
    let mut received = [0_u8; 7];
    target
        .read_exact(&mut received)
        .await
        .expect("the redirect must deliver the prefix");
    assert_eq!(&received, b"stalled");

    let outcome = time::timeout(Duration::from_secs(5), relaying)
        .await
        .expect("the idle liveness must end the session")
        .expect("the relay task must not panic");
    let error = outcome.expect_err("a stalled session must fail, not complete");
    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "the liveness policy must surface as TimedOut"
    );
    drop(client);
    drop(target);

    // Admission and both map entries must be back at baseline.
    let (outcome, _, _) = full_exchange(
        &relay,
        explicit_sockhash(),
        pattern(64 * 1024, 0xBB),
        pattern(64 * 1024, 0xCC),
    )
    .await;
    assert_eq!(
        outcome.backend(),
        RelayBackend::Sockhash,
        "a relay after the idle timeout must arm again; admission and entries leaked otherwise"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn map_exhaustion_falls_through_to_splice_before_any_byte() {
    // Admission bound one: the first connection parks armed and idle, the
    // second explicitly requests sockhash, must be declined with the bound
    // exhausted, and must complete byte-exact through splice — the decline
    // happens before any byte, so fall-through is safe.
    let relay = armed_relay(1);
    let (mut parked_client, mut parked_target, parked_relay) =
        relay_pair(&relay, explicit_sockhash()).await;
    // The arm happens synchronously at the start of `relay_owned`; give the
    // spawned task its scheduling slice.
    time::sleep(Duration::from_millis(300)).await;

    let (outcome, _, _) = full_exchange(
        &relay,
        explicit_sockhash(),
        pattern(96 * 1024, 0x99),
        pattern(96 * 1024, 0xAA),
    )
    .await;
    assert_eq!(
        outcome.backend(),
        RelayBackend::Splice,
        "an exhausted map must decline before any byte and fall through"
    );

    // Unpark the first connection: it must still be the armed sockhash relay.
    let run = async {
        let client_io = async {
            parked_client.write_all(b"first").await?;
            parked_client.shutdown().await?;
            let mut received = Vec::new();
            parked_client.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        let target_io = async {
            let mut received = Vec::new();
            parked_target.read_to_end(&mut received).await?;
            parked_target.write_all(b"one").await?;
            parked_target.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(parked_relay, client_io, target_io)
    };
    let (outcome, response, received) = time::timeout(TIMEOUT, run)
        .await
        .expect("the parked session must complete");
    let outcome = outcome
        .expect("the relay task must not panic")
        .expect("the armed relay must succeed");
    assert_eq!(received.expect("target I/O must succeed"), b"first");
    assert_eq!(response.expect("client I/O must succeed"), b"one");
    assert_eq!(outcome.backend(), RelayBackend::Sockhash);
    assert_eq!(outcome.inbound_to_outbound(), 5);
    assert_eq!(outcome.outbound_to_inbound(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn repeated_arm_disarm_cycles_return_to_baseline() {
    // Capacity is exactly four entries (two relays). Sixty-four sequential
    // cycles must all arm: a single leaked entry per cycle would exhaust the
    // map by the third cycle and flip the backend to splice.
    let relay = armed_relay(2);
    for cycle in 0..64 {
        let (outcome, _, _) = full_exchange(
            &relay,
            explicit_sockhash(),
            pattern(8 * 1024, cycle as u8),
            pattern(8 * 1024, (cycle as u8).wrapping_add(1)),
        )
        .await;
        assert_eq!(
            outcome.backend(),
            RelayBackend::Sockhash,
            "cycle {cycle} must arm; a leaked map entry would have exhausted the map by now"
        );
        assert_eq!(outcome.inbound_to_outbound(), 8 * 1024);
        assert_eq!(outcome.outbound_to_inbound(), 8 * 1024);
    }
}

/// Connects from a fixed local port with `SO_REUSEADDR`, so a tuple in
/// `TIME_WAIT` can be reused immediately after teardown.
fn connect_from(port: u16, target: SocketAddr) -> io::Result<TcpStream> {
    let socket = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        None,
    )?;
    rustix::net::sockopt::set_socket_reuseaddr(&socket, true)?;
    rustix::net::bind(&socket, &SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    rustix::net::connect(&socket, &target)?;
    let stream = std::net::TcpStream::from(socket);
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privilege to construct the SOCKHASH controller"]
async fn a_connection_tuple_is_reusable_after_teardown() {
    let relay = armed_relay(2);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let relay_addr = listener.local_addr().expect("address");
    // A currently-free port for the client's fixed identity.
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("probe bind")
        .local_addr()
        .expect("address")
        .port();

    for cycle in 0..2 {
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener must bind");
        let target_addr = target_listener.local_addr().expect("address");
        let client = connect_from(port, relay_addr).expect("reused-port connect");
        let (inbound, peer) = listener.accept().await.expect("must accept");
        assert_eq!(peer.port(), port, "the client must reuse its tuple");
        let outbound = TcpStream::connect(target_addr)
            .await
            .expect("relay must connect");
        let (mut target, _) = target_listener.accept().await.expect("must accept");

        let relay_clone = relay.clone();
        let mut client = client;
        let relaying = tokio::spawn(async move {
            relay_clone
                .relay_owned(inbound, outbound, explicit_sockhash())
                .await
        });
        time::sleep(ARM_SETTLE).await;
        let run = async {
            let client_io = async {
                client.write_all(b"reused").await?;
                client.shutdown().await?;
                let mut received = Vec::new();
                client.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            let target_io = async {
                let mut received = Vec::new();
                target.read_to_end(&mut received).await?;
                target.shutdown().await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(relaying, client_io, target_io)
        };
        let (outcome, response, received) = time::timeout(TIMEOUT, run)
            .await
            .expect("the reused-tuple exchange must complete");
        let outcome = outcome
            .expect("the relay task must not panic")
            .expect("the armed relay must succeed");
        assert_eq!(received.expect("target I/O must succeed"), b"reused");
        assert!(response.expect("client I/O must succeed").is_empty());
        assert_eq!(
            outcome.backend(),
            RelayBackend::Sockhash,
            "cycle {cycle}: the identical tuple must arm again after teardown"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires privilege to arm a SOCKHASH redirect"]
async fn the_redirect_consumes_fin_and_readiness_signals_it() {
    // Pins the empirics the production wait loop is built on, measured on
    // kernel 6.12:
    //
    // * a peer FIN is consumed by the receiving relay-side socket, which
    //   becomes readable with an empty userspace queue (CLOSE_WAIT);
    // * the FIN does not propagate: the peer socket stays ESTABLISHED and
    //   unreadable;
    // * redirect delivery is asynchronous: the sending socket's
    //   tcpi_bytes_acked converges to the payload after the FIN arrives;
    // * tcpi_bytes_received counts the payload plus one FIN sequence byte.
    use rr_linux::{
        socket::{pending_input, tcp_counters},
        sockhash::{
            FlowKey, attach_verdict_program, create_sockhash, load_with_verifier_log, map_delete,
            map_update,
        },
    };
    use std::os::fd::AsRawFd as _;
    use tokio::io::Interest;

    let map_fd = create_sockhash(16).expect("a privileged host must create a SOCKHASH");
    let prog_fd = load_with_verifier_log(map_fd).expect("the verdict program must load");
    attach_verdict_program(map_fd, prog_fd).expect("the program must attach");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (mut client, inbound) = (client.unwrap(), accepted.unwrap().0);
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let (outbound, accepted) =
        tokio::join!(TcpStream::connect(target_addr), target_listener.accept());
    let (outbound, _target) = (outbound.unwrap(), accepted.unwrap().0);

    let in_key = FlowKey::capture(inbound.local_addr().unwrap(), inbound.peer_addr().unwrap());
    let out_key = FlowKey::capture(
        outbound.local_addr().unwrap(),
        outbound.peer_addr().unwrap(),
    );
    let base_out = tcp_counters(outbound.as_raw_fd()).unwrap();
    map_update(map_fd, in_key, outbound.as_raw_fd()).unwrap();
    map_update(map_fd, out_key, inbound.as_raw_fd()).unwrap();

    let payload = vec![0xAB_u8; 65_536];
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();

    // The receiving relay socket must signal EOF through readiness.
    let eof = time::timeout(
        Duration::from_millis(500),
        inbound.async_io(Interest::READABLE, || {
            match pending_input(inbound.as_raw_fd()) {
                Ok(0) => Ok(()),
                Ok(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "still queued")),
                Err(error) => Err(error),
            }
        }),
    )
    .await;
    assert!(
        matches!(eof, Ok(Ok(()))),
        "a peer FIN must make the relay-side socket readable with an empty queue: {eof:?}"
    );
    let state = tcp_counters(inbound.as_raw_fd()).unwrap();
    assert_eq!(state.state, 8, "the receiving socket must be CLOSE_WAIT");
    assert_eq!(
        state.bytes_received, 65_537,
        "tcpi_bytes_received counts the payload plus the FIN sequence byte"
    );

    // The FIN must not propagate: the peer socket stays ESTABLISHED.
    let propagated = time::timeout(
        Duration::from_millis(200),
        outbound.async_io(Interest::READABLE, || Ok::<_, io::Error>(())),
    )
    .await;
    assert!(
        propagated.is_err(),
        "the redirect must not propagate the FIN to the peer socket"
    );
    assert_eq!(tcp_counters(outbound.as_raw_fd()).unwrap().state, 1);

    // Delivery is asynchronous but must converge without any userspace action.
    for _ in 0..100 {
        if tcp_counters(outbound.as_raw_fd()).unwrap().bytes_acked - base_out.bytes_acked >= 65_536
        {
            map_delete(map_fd, in_key).unwrap();
            map_delete(map_fd, out_key).unwrap();
            return;
        }
        time::sleep(Duration::from_millis(20)).await;
    }
    panic!("tcpi_bytes_acked must converge to the redirected payload");
}
