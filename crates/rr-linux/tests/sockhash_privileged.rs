//! Privileged `SOCKHASH` gates.
//!
//! These tests require a kernel that permits loading a `BPF_PROG_TYPE_SK_SKB`
//! program and attaching it to a `SOCKHASH`. They are `#[ignore]`d by default so
//! an unprivileged run neither fails nor silently claims coverage it does not
//! have. Run them explicitly on the target host:
//!
//! ```text
//! cargo test -p rr-linux --test sockhash_privileged -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! If the program cannot be loaded, each test reports the errno *and the
//! bounded verifier log* and fails. On a host where the gate is supposed to
//! run, a refusal is a real result rather than a skip — and the log is the
//! diagnostic the merged implementation could not produce, because it requested
//! none.

use std::{
    io::{Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd as _,
    time::Duration,
};

use rr_linux::{
    Budget, DeclineReason, bpf,
    sockhash::{
        self, FlowKey, attach_verdict_program, create_sockhash, load_with_verifier_log, map_delete,
        map_update,
    },
};

const BUDGET: Budget = Budget {
    max_relays: 64,
    buffer_bytes: 32 * 1024,
    max_shards: 1,
    queue_depth: 64,
};

/// Loads the program, or fails with the kernel's own explanation.
fn load_or_report(map_fd: i32) -> i32 {
    match load_with_verifier_log(map_fd) {
        Ok(fd) => fd,
        Err(rejection) => panic!(
            "the verdict program must pass the verifier: {rejection}\n\
             --- bounded verifier log ---\n{log}",
            log = rejection.log
        ),
    }
}

#[test]
#[ignore = "requires privilege to load a BPF_PROG_TYPE_SK_SKB program"]
fn the_verdict_program_passes_the_kernel_verifier() {
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let prog_fd = load_or_report(map_fd);
    assert!(prog_fd >= 0);
}

#[test]
#[ignore = "requires privilege to load a BPF_PROG_TYPE_SK_SKB program"]
fn the_program_attaches_as_a_stream_verdict() {
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let prog_fd = load_or_report(map_fd);
    attach_verdict_program(map_fd, prog_fd)
        .expect("a loaded SK_SKB program must attach to its own SOCKHASH");
}

#[test]
#[ignore = "requires privilege to load a BPF_PROG_TYPE_SK_SKB program"]
fn a_helper_program_type_mismatch_is_a_verifier_rejection() {
    // The merged implementation paired helper 72 with an SK_MSG program. This
    // pins the inverse so the mismatch cannot return, and pins the fact that
    // the generic errno mapping cannot classify it correctly.
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let mut program = bpf::stream_verdict_program(map_fd);
    let call = program
        .iter_mut()
        .find(|insn| insn.imm == bpf::helper::SK_REDIRECT_HASH)
        .expect("the program must call the socket redirect helper");
    call.imm = bpf::helper::MSG_REDIRECT_HASH;

    let mut log = vec![0_u8; 8 * 1024];
    let error = sockhash::load_verdict_program_with_log(&program, Some(&mut log))
        .expect_err("an SK_MSG helper must not load in an SK_SKB program");
    let end = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
    let log = String::from_utf8_lossy(&log[..end]).into_owned();
    assert!(
        log.contains("cannot use helper"),
        "the verifier must name the helper mismatch; got: {log}"
    );
    // Measured on kernel 6.18: a helper/program-type mismatch is reported as
    // EINVAL, while a bad context offset is reported as EACCES. Both are
    // verifier rejections, and the generic errno mapping calls them
    // `missingOperation` and `blockedByLsm` respectively — neither of which is
    // true. That is why `BPF_PROG_LOAD` has its own classifier.
    let generic = DeclineReason::from_errno(&error);
    assert!(
        matches!(
            generic,
            DeclineReason::MissingOperation | DeclineReason::BlockedByLsm
        ),
        "the generic mapping misreads verifier rejections; got {generic:?}"
    );
    assert_ne!(
        generic,
        DeclineReason::VerifierRejected,
        "the generic mapping can never produce the correct category on its own"
    );
}

#[test]
#[ignore = "requires privilege to create and populate a SOCKHASH"]
fn both_directions_install_and_remove_for_ipv4() {
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let (client, accepted) = loopback_pair(Ipv4Addr::LOCALHOST.into());
    let key = FlowKey::capture(
        accepted.local_addr().expect("local address"),
        accepted.peer_addr().expect("peer address"),
    );
    map_update(map_fd, key, accepted.as_raw_fd()).expect("install the accepted direction");
    map_update(map_fd, key.reversed(), client.as_raw_fd()).expect("install the client direction");
    map_delete(map_fd, key).expect("remove the accepted direction");
    map_delete(map_fd, key.reversed()).expect("remove the client direction");
    map_delete(map_fd, key).expect("removing an absent entry must be idempotent for rollback");
}

#[test]
#[ignore = "requires privilege and a host with IPv6 loopback"]
fn both_directions_install_and_remove_for_ipv6() {
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let Some((client, accepted)) = try_loopback_pair(Ipv6Addr::LOCALHOST.into()) else {
        panic!("this gate requires IPv6 loopback and must not be silently skipped");
    };
    let key = FlowKey::capture(
        accepted.local_addr().expect("local address"),
        accepted.peer_addr().expect("peer address"),
    );
    assert_eq!(
        key.family,
        bpf::family::INET6.unsigned_abs(),
        "an IPv6 flow must carry AF_INET6 so its key cannot collide with a mapped IPv4 flow"
    );
    map_update(map_fd, key, accepted.as_raw_fd()).expect("install the accepted direction");
    map_update(map_fd, key.reversed(), client.as_raw_fd()).expect("install the client direction");
    map_delete(map_fd, key).expect("remove the accepted direction");
    map_delete(map_fd, key.reversed()).expect("remove the client direction");
}

#[test]
#[ignore = "requires privilege to arm a SOCKHASH redirect"]
fn an_armed_pair_redirects_production_bytes() {
    // The complete gate: a relayed pair armed in both directions, with a
    // byte-exact transfer proving the kernel actually moved the data rather
    // than the program merely loading.
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let prog_fd = load_or_report(map_fd);
    attach_verdict_program(map_fd, prog_fd).expect("attach the verdict program");

    let (mut client, server_side) = loopback_pair(Ipv4Addr::LOCALHOST.into());
    let (relay_side, mut target) = loopback_pair(Ipv4Addr::LOCALHOST.into());

    let inbound = FlowKey::capture(
        server_side.local_addr().expect("local address"),
        server_side.peer_addr().expect("peer address"),
    );
    let outbound = FlowKey::capture(
        relay_side.local_addr().expect("local address"),
        relay_side.peer_addr().expect("peer address"),
    );
    // The peer is registered under each socket's own key: the program describes
    // itself and the map names its partner. A key derived from one connection
    // can never name a socket belonging to the other.
    map_update(map_fd, inbound, relay_side.as_raw_fd()).expect("arm inbound -> outbound");
    map_update(map_fd, outbound, server_side.as_raw_fd()).expect("arm outbound -> inbound");

    let payload = b"redirected through the kernel";
    client.write_all(payload).expect("client write");
    client.flush().expect("client flush");

    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut received = vec![0_u8; payload.len()];
    if let Err(error) = target.read_exact(&mut received) {
        panic!(
            "an armed pair must redirect production bytes; the read failed with {error}. \
             This is the gate that proves the backend moves data."
        );
    }
    assert_eq!(
        received.as_slice(),
        payload,
        "the redirect must not truncate, reorder or duplicate"
    );

    // The reverse direction must work through the same armed pair.
    let downlink = b"and back again";
    target.write_all(downlink).expect("target write");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut back = vec![0_u8; downlink.len()];
    client
        .read_exact(&mut back)
        .expect("the downlink direction must redirect too");
    assert_eq!(back.as_slice(), downlink);

    map_delete(map_fd, inbound).expect("disarm inbound");
    map_delete(map_fd, outbound).expect("disarm outbound");
}

#[test]
#[ignore = "requires privilege to load a BPF_PROG_TYPE_SK_SKB program"]
fn an_unarmed_flow_is_delivered_to_userspace_rather_than_dropped() {
    let map_fd = create_sockhash(128).expect("a privileged host must create a SOCKHASH");
    let prog_fd = load_or_report(map_fd);
    attach_verdict_program(map_fd, prog_fd).expect("attach the verdict program");

    // Neither socket is in the map, so the verdict program never runs for
    // them. Delivery must be completely unaffected.
    let (mut client, mut accepted) = loopback_pair(Ipv4Addr::LOCALHOST.into());
    let payload = b"unarmed";
    client.write_all(payload).expect("client write");
    accepted
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut received = vec![0_u8; payload.len()];
    accepted
        .read_exact(&mut received)
        .expect("a flow that was never armed must reach userspace untouched");
    assert_eq!(received.as_slice(), payload);
}

#[test]
#[ignore = "requires privilege to create a SOCKHASH"]
fn the_probe_reports_availability_on_a_privileged_host() {
    let report = sockhash::probe(BUDGET);
    assert!(
        report.is_available(),
        "a privileged host must report the backend available; operations: {:?}",
        report.operations()
    );
}

#[test]
fn flow_identity_is_captured_before_teardown() {
    let (client, accepted) = loopback_pair(Ipv4Addr::LOCALHOST.into());
    let local = accepted.local_addr().expect("local address");
    let peer = accepted.peer_addr().expect("peer address");
    let key = FlowKey::capture(local, peer);
    drop(client);
    drop(accepted);
    assert_eq!(key, FlowKey::capture(local, peer));
    assert_eq!(key.reversed().reversed(), key);
    assert_ne!(key.reversed(), key);
}

#[test]
fn the_serialized_key_matches_the_layout_the_program_builds() {
    // The program writes the peer's key from its own context. Serializing a
    // captured key here must produce the same forty bytes, field for field.
    let local: SocketAddr = "192.0.2.1:443".parse().expect("address");
    let remote: SocketAddr = "198.51.100.7:51234".parse().expect("address");
    let bytes = FlowKey::capture(local, remote).to_bytes();

    assert_eq!(bytes.len(), 40, "every byte of the map key must be defined");
    assert_eq!(&bytes[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    assert_eq!(&bytes[12..16], &[192, 0, 2, 1]);
    assert_eq!(&bytes[16..26], &[0; 10]);
    assert_eq!(&bytes[26..28], &[0xff, 0xff]);
    assert_eq!(&bytes[28..32], &[198, 51, 100, 7]);
    assert_eq!(
        u32::from_ne_bytes(bytes[32..36].try_into().expect("four bytes")),
        443,
        "key[32..36] is the local port as a native-order u32"
    );
    let tail = u32::from_ne_bytes(bytes[36..40].try_into().expect("four bytes"));
    assert_eq!(tail & 0xffff, 51_234, "the low half is the remote port");
    assert_eq!(
        tail >> 16,
        bpf::family::INET.unsigned_abs(),
        "the high half is the address family"
    );
}

#[test]
fn a_mapped_ipv4_key_cannot_collide_with_a_native_ipv6_key() {
    let v4 = FlowKey::capture(
        "192.0.2.1:443".parse().expect("address"),
        "198.51.100.7:1024".parse().expect("address"),
    );
    let v6 = FlowKey::capture(
        "[::ffff:192.0.2.1]:443".parse().expect("address"),
        "[::ffff:198.51.100.7]:1024".parse().expect("address"),
    );
    assert_ne!(
        v4.to_bytes(),
        v6.to_bytes(),
        "the address family in the key tail is what keeps these distinct"
    );
}

fn loopback_pair(host: IpAddr) -> (TcpStream, TcpStream) {
    try_loopback_pair(host).expect("loopback must be available")
}

fn try_loopback_pair(host: IpAddr) -> Option<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((host, 0)).ok()?;
    let address = listener.local_addr().ok()?;
    let client = TcpStream::connect(address).ok()?;
    let (accepted, _) = listener.accept().ok()?;
    Some((client, accepted))
}
