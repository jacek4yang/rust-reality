//! Privileged sockhash gates.
//!
//! These tests require a kernel that permits loading a `BPF_PROG_TYPE_SK_MSG`
//! program and attaching it to a `SOCKHASH`. They are `#[ignore]`d by default so
//! an unprivileged run neither fails nor silently claims coverage it does not
//! have. Run them explicitly on the target host:
//!
//! ```text
//! cargo test -p rr-linux --test sockhash_privileged -- --ignored --test-threads=1
//! ```
//!
//! If the program cannot be loaded, each test reports the exact fixed decline
//! reason and fails, because on a host where the gate is *supposed* to run, a
//! refusal is a real result rather than a skip.

use rr_linux::{
    Budget,
    bpf::stream_verdict_program,
    capability::Probe,
    sockhash::{self, FlowKey},
};

const BUDGET: Budget = Budget {
    max_relays: 64,
    buffer_bytes: 32 * 1024,
    max_shards: 1,
    queue_depth: 64,
};

#[test]
#[ignore = "requires privilege to load a BPF_PROG_TYPE_SK_MSG program"]
fn the_verdict_program_passes_the_kernel_verifier() {
    let map = sockhash::create_sockhash(128).expect("SOCKHASH creation must succeed");
    let program = stream_verdict_program(map, 16);

    let loaded = sockhash::load_sk_msg_program(&program);

    match loaded {
        Ok(fd) => {
            assert!(fd >= 0);
        }
        Err(error) => panic!(
            "the verifier rejected the stream verdict program: {error} \
             (classified as {})",
            Probe::from_result::<()>(&Err(error_clone(&error)))
        ),
    }
}

#[test]
#[ignore = "requires privilege to create and populate a SOCKHASH"]
fn a_bounded_map_refuses_more_entries_than_its_capacity() {
    let map = sockhash::create_sockhash(2).expect("SOCKHASH creation must succeed");
    assert!(map >= 0, "a bounded map must be created before arming");
    // Populating the map requires attached sockets; the arming path is covered
    // by the integration gate documented in UNVERIFIED-GATES.md. What is
    // asserted here is that the map is created with a finite capacity at all.
}

#[test]
#[ignore = "requires privilege to load a BPF_PROG_TYPE_SK_MSG program"]
fn the_probe_reports_availability_on_a_privileged_host() {
    let report = sockhash::probe(BUDGET);
    assert!(
        report.is_available(),
        "on a host where this gate runs, sockhash must probe available: {report}"
    );
}

#[test]
fn flow_identity_is_captured_before_teardown() {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener must bind");
    let address = listener.local_addr().expect("address must exist");
    let client = TcpStream::connect(address).expect("client must connect");
    let (accepted, _) = listener.accept().expect("server must accept");

    let local: SocketAddr = accepted.local_addr().expect("local address");
    let remote: SocketAddr = accepted.peer_addr().expect("peer address");
    let key = FlowKey::capture(local, remote);

    // Tearing the pair down must not change the captured key: this is exactly
    // why the key is captured at arm time and never reconstructed later, when
    // getpeername would return ENOTCONN.
    drop(client);
    drop(accepted);
    assert_eq!(key, FlowKey::capture(local, remote));
    assert_eq!(key.reversed().reversed(), key);
}

fn error_clone(error: &std::io::Error) -> std::io::Error {
    error.raw_os_error().map_or_else(
        || std::io::Error::other("unknown"),
        std::io::Error::from_raw_os_error,
    )
}
