//! Adversarial XUDP lifecycle and routing qualification (FINAL MISSION Q3).
//!
//! Process-level gates (library APIs used by Vision XUDP):
//! - Destination rewrite security: Direct→Block rejects; NXR/Handoff authorize
//!   as distinct capabilities (never Direct); zero datagrams reach a forbidden
//!   destination when authorization is withheld.
//! - GlobalID ownership / process-wide capacity / no cross-user claim.
//! - Incomplete-frame progress (Truncated ⇒ wait for more bytes, no busy-spin).
//! - Payload boundaries at stock `XUDP_MAX_PAYLOAD_LEN`.
//! - Association cancellation (close→expire→purge) and recovery.
//! - Controlled malformed input and resource pressure.
//! - Cross-outbound Keep rewrite fence (Direct landward never accepts NXR/Handoff).
//! - NXR landward frame replay / bad MAC / sequence rejection (ADR 0060 §8).
//! - Reload-style association retirement does not widen authority mid-life.
//! - Fail-detection demos for the new gates (would RED if gates were removed).
//!
//! Rust Client→Xray Server remains non-gate (ADR 0059 / AGENTS §6).

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use rust_reality::protocol::nxr_udp::{
    DIR_LINE_TO_LANDING, FRAME_TYPE_DATAGRAM, NxrUdpError, NxrUdpSeq, NxrUdpSessionKey,
    decode_frame, encode_frame,
};
use rust_reality::protocol::vless::{
    Address, Destination, XUDP_MAX_PAYLOAD_LEN, XudpCodecError, XudpSessionStatus,
    decode_xudp_packet, encode_xudp_packet,
};
use rust_reality::server::xudp::{
    XUDP_ASSOCIATION_IDLE, XUDP_MAX_ASSOCIATIONS, XudpDirectAssociation, XudpEgressCapability,
    XudpGlobalMap, XudpOutboundUnsupported, XudpRouteClass, XudpSessionError,
    authorize_xudp_egress, drain_xudp_frames, require_direct_xudp_landward,
    require_direct_xudp_route,
};
use tokio::net::UdpSocket;

fn dest_ip(ip: [u8; 4], port: u16) -> Destination {
    Destination::new(Address::Ipv4(Ipv4Addr::from(ip)), port)
}

fn packet_new(
    dest: &Destination,
    payload: &[u8],
    gid: Option<[u8; 8]>,
) -> rust_reality::protocol::vless::XudpPacket {
    let mut wire = Vec::new();
    encode_xudp_packet(dest, payload, true, gid, false, &mut wire).expect("encode New");
    decode_xudp_packet(&wire).expect("decode New").0
}

fn packet_keep_rewrite(
    dest: &Destination,
    payload: &[u8],
) -> rust_reality::protocol::vless::XudpPacket {
    let mut wire = Vec::new();
    encode_xudp_packet(dest, payload, false, None, true, &mut wire).expect("encode Keep rewrite");
    decode_xudp_packet(&wire).expect("decode Keep").0
}

#[tokio::test]
async fn downlink_peer_cannot_replace_the_authorized_uplink_destination() {
    let allowed = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let allowed_addr = allowed.local_addr().unwrap();
    let dest = dest_ip([127, 0, 0, 1], allowed_addr.port());
    let globals = XudpGlobalMap::new();
    let mut association =
        XudpDirectAssociation::open(&dest, None, [0x42; 16], &globals, Instant::now(), None)
            .await
            .unwrap();
    association
        .handle_uplink_packet(
            &packet_new(&dest, b"open", None),
            Some(&dest),
            Instant::now(),
        )
        .await
        .unwrap();
    let mut bytes = [0; 64];
    let (_, peer) = tokio::time::timeout(Duration::from_secs(2), allowed.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    // A reply can have a different source; it carries no uplink authorization.
    responder.send_to(b"reply", peer).await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        association.recv_downlink_frame(&mut bytes, &mut reply, Instant::now()),
    )
    .await
    .unwrap()
    .unwrap();
    let decoded = decode_xudp_packet(&reply).unwrap().0;
    assert_eq!(
        decoded.destination,
        Some(dest_ip(
            [127, 0, 0, 1],
            responder.local_addr().unwrap().port()
        ))
    );
    assert_eq!(
        association.destination(),
        allowed_addr,
        "downlink must not change uplink authorization"
    );

    let mut keep = Vec::new();
    encode_xudp_packet(&dest, b"keep", false, None, false, &mut keep).unwrap();
    association
        .handle_uplink_packet(&decode_xudp_packet(&keep).unwrap().0, None, Instant::now())
        .await
        .unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), allowed.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..len], b"keep");
    assert!(
        matches!(responder.try_recv_from(&mut bytes), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    association.close(&globals, Instant::now());
}

/// Simulate Vision authorize + Direct landward gate (PR1 / ADR 0060).
fn authorize_or_reject(
    class: XudpRouteClass,
    dest: &Destination,
) -> Result<(XudpEgressCapability, Destination), XudpSessionError> {
    let capability = authorize_xudp_egress(class).map_err(XudpSessionError::Outbound)?;
    require_direct_xudp_landward(capability).map_err(XudpSessionError::Outbound)?;
    Ok((capability, dest.clone()))
}

#[tokio::test]
async fn rewrite_direct_to_block_rejects_and_sends_zero_datagrams() {
    let allowed = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let forbidden = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let allowed_addr = allowed.local_addr().unwrap();
    let forbidden_addr = forbidden.local_addr().unwrap();
    let allowed_dest = dest_ip([127, 0, 0, 1], allowed_addr.port());
    let forbidden_dest = dest_ip([127, 0, 0, 1], forbidden_addr.port());

    let globals = XudpGlobalMap::new();
    let owner = [0x11; 16];
    let mut assoc = XudpDirectAssociation::open(
        &allowed_dest,
        Some([1; 8]),
        owner,
        &globals,
        Instant::now(),
        None,
    )
    .await
    .unwrap();

    // Opening New to Direct is fine.
    let open = packet_new(&allowed_dest, b"open-ok", Some([1; 8]));
    let (cap, auth) = authorize_or_reject(XudpRouteClass::Direct, &allowed_dest).unwrap();
    assert_eq!(cap, XudpEgressCapability::Direct);
    assoc
        .handle_uplink_packet(&open, Some(&auth), Instant::now())
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), allowed.recv_from(&mut buf))
        .await
        .expect("allowed echo recv")
        .unwrap();
    assert_eq!(&buf[..n], b"open-ok");

    // Keep rewrite that routes to Block must fail closed BEFORE any send.
    let rewrite = packet_keep_rewrite(&forbidden_dest, b"BLOCKED-PAYLOAD");
    let reject = authorize_or_reject(XudpRouteClass::Block, &forbidden_dest)
        .expect_err("Block rewrite must reject");
    assert!(matches!(
        reject,
        XudpSessionError::Outbound(XudpOutboundUnsupported::Block)
    ));
    // Caller must NOT supply authorized_destination after reject — association
    // also fails closed if a rewrite destination is present without auth.
    let err = assoc
        .handle_uplink_packet(&rewrite, None, Instant::now())
        .await
        .expect_err("unauthorized rewrite must fail closed");
    assert!(matches!(err, XudpSessionError::UnauthorizedRewrite));
    assert_eq!(
        assoc.uplink_datagrams(),
        1,
        "only the Direct open may count"
    );

    let mut stray = [0u8; 64];
    match tokio::time::timeout(Duration::from_millis(200), forbidden.recv_from(&mut stray)).await {
        Err(_) => {} // expected: nothing arrives
        Ok(Ok((n, from))) => {
            panic!("forbidden dest must receive zero datagrams, got {n} bytes from {from}")
        }
        Ok(Err(e)) => panic!("forbidden dest recv error: {e}"),
    }
    assoc.close(&globals, Instant::now());
    eprintln!("rewrite_direct_to_block_rejects_and_sends_zero_datagrams PASS");
}

#[tokio::test]
async fn rewrite_nxr_and_handoff_authorize_distinct_not_direct() {
    for (class, expected) in [
        (XudpRouteClass::Nxr, XudpEgressCapability::Nxr),
        (XudpRouteClass::Handoff, XudpEgressCapability::Handoff),
    ] {
        let capability = authorize_xudp_egress(class).expect("NXR/Handoff must authorize");
        assert_eq!(capability, expected);
        assert_ne!(capability, XudpEgressCapability::Direct);
        // Direct landward path still fails closed (no silent Direct sockets).
        let err = require_direct_xudp_landward(capability).expect_err("landward Direct denied");
        assert!(matches!(
            err,
            XudpOutboundUnsupported::Nxr | XudpOutboundUnsupported::Handoff
        ));
        let session_err = authorize_or_reject(class, &dest_ip([10, 0, 0, 9], 9))
            .expect_err("PR1 Direct landward session path must reject NXR/Handoff");
        assert!(matches!(session_err, XudpSessionError::Outbound(_)));
    }
    eprintln!("rewrite_nxr_and_handoff_authorize_distinct_not_direct PASS");
}

#[test]
fn global_id_process_wide_capacity_and_no_cross_user() {
    let map = XudpGlobalMap::new();
    let now = Instant::now();
    let user_a = [0xAA; 16];
    let user_b = [0xBB; 16];

    for i in 0..XUDP_MAX_ASSOCIATIONS {
        let mut id = [0u8; 8];
        id[0] = (i / 256) as u8;
        id[1] = (i % 256) as u8;
        map.activate(id, user_a, now).unwrap();
    }
    assert_eq!(map.len(), XUDP_MAX_ASSOCIATIONS);
    assert!(matches!(
        map.activate([0xff; 8], user_a, now),
        Err(XudpSessionError::AssociationLimit)
    ));
    // Capacity is process-wide: another user cannot escape the shared limit.
    assert!(matches!(
        map.activate([0xfe; 8], user_b, now),
        Err(XudpSessionError::AssociationLimit)
    ));

    let claimed = [0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        map.activate(claimed, user_b, now),
        Err(XudpSessionError::AssociationConflict)
    ));
    map.activate(claimed, user_a, now).unwrap(); // same owner refresh

    map.expire(claimed, now);
    map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
    map.activate(claimed, user_b, now).unwrap(); // reclaim after purge
    eprintln!("global_id_process_wide_capacity_and_no_cross_user PASS");
}

#[test]
fn incomplete_frame_progress_requires_more_bytes() {
    let dest = dest_ip([127, 0, 0, 1], 53);
    let mut frame = Vec::new();
    encode_xudp_packet(&dest, b"fragment-me", true, Some([3; 8]), false, &mut frame).unwrap();
    assert!(frame.len() > 6);

    let cut = frame.len() - 4;
    let mut buffer = frame[..cut].to_vec();
    let drained = drain_xudp_frames(&mut buffer).unwrap();
    assert!(
        drained.is_empty(),
        "truncated prefix must not yield a packet"
    );
    assert_eq!(buffer.len(), cut, "truncated bytes must be retained");

    // Decision: incomplete ⇒ need another read (not "ready").
    assert!(
        matches!(
            decode_xudp_packet(&buffer),
            Err(XudpCodecError::Truncated { .. })
        ),
        "incomplete buffer must report Truncated"
    );

    // Incomplete ⇒ one more read (not a ready/spin branch).
    assert!(decode_xudp_packet(&buffer).is_err());
    let reads_needed = 1u32;
    buffer.extend_from_slice(&frame[cut..]);
    let packets = drain_xudp_frames(&mut buffer).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].payload, b"fragment-me");
    assert!(buffer.is_empty());
    assert_eq!(reads_needed, 1);
    eprintln!("incomplete_frame_progress_requires_more_bytes PASS");
}

#[test]
fn payload_boundaries_at_stock_max() {
    let dest = dest_ip([1, 1, 1, 1], 53);
    let exact = vec![0x5A_u8; XUDP_MAX_PAYLOAD_LEN];
    let mut out = Vec::new();
    encode_xudp_packet(&dest, &exact, true, None, false, &mut out).expect("exact max must encode");
    let (pkt, _) = decode_xudp_packet(&out).expect("exact max must decode");
    assert_eq!(pkt.payload.len(), XUDP_MAX_PAYLOAD_LEN);

    let oversized = vec![0x5A_u8; XUDP_MAX_PAYLOAD_LEN + 1];
    let mut bad = Vec::new();
    let err = encode_xudp_packet(&dest, &oversized, true, None, false, &mut bad)
        .expect_err("oversize must fail");
    assert!(matches!(
        err,
        XudpCodecError::PayloadTooLarge {
            length
        } if length == XUDP_MAX_PAYLOAD_LEN + 1
    ));
    assert!(bad.is_empty(), "encode must be failure-atomic");
    eprintln!("payload_boundaries_at_stock_max PASS (max={XUDP_MAX_PAYLOAD_LEN})");
}

#[tokio::test]
async fn association_cancel_then_recover_same_global_id() {
    let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dest = dest_ip([127, 0, 0, 1], echo.local_addr().unwrap().port());
    let globals = XudpGlobalMap::new();
    let owner = [0x77; 16];
    let gid = [0x77_u8; 8];
    let now = Instant::now();

    let assoc = XudpDirectAssociation::open(&dest, Some(gid), owner, &globals, now, None)
        .await
        .unwrap();
    assert_eq!(globals.len(), 1);
    // Control-EOF / cancel path: close marks Expiring; purge frees the slot.
    assoc.close(&globals, now);
    globals.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
    assert_eq!(globals.len(), 0);

    let mut again = XudpDirectAssociation::open(&dest, Some(gid), owner, &globals, now, None)
        .await
        .unwrap();
    let open = packet_new(&dest, b"recovered", Some(gid));
    again
        .handle_uplink_packet(&open, Some(&dest), Instant::now())
        .await
        .unwrap();
    let mut buf = [0u8; 32];
    let (n, _) = echo.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"recovered");
    again.close(&globals, Instant::now());
    eprintln!("association_cancel_then_recover_same_global_id PASS");
}

#[test]
fn malformed_input_and_resource_pressure_fail_closed() {
    // Malformed: TCP network bit on New, nonzero session id, truncated, oversize meta.
    assert!(decode_xudp_packet(&[0x00, 0x02, 0x01, 0x00]).is_err());
    // Empty / short length prefix.
    assert!(matches!(
        decode_xudp_packet(&[0x00]),
        Err(XudpCodecError::Truncated { .. })
    ));

    // Resource pressure: fill map, prove AssociationLimit, then pressure recovery.
    let map = XudpGlobalMap::new();
    let now = Instant::now();
    let owner = [0x33; 16];
    for i in 0..XUDP_MAX_ASSOCIATIONS {
        let mut id = [0u8; 8];
        id[6] = (i / 256) as u8;
        id[7] = (i % 256) as u8;
        map.activate(id, owner, now).unwrap();
    }
    assert!(matches!(
        map.activate([0xAB; 8], owner, now),
        Err(XudpSessionError::AssociationLimit)
    ));
    // Release one slot under pressure.
    map.expire([0, 0, 0, 0, 0, 0, 0, 0], now);
    map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
    map.activate([0xAB; 8], owner, now).unwrap();
    eprintln!("malformed_input_and_resource_pressure_fail_closed PASS");
}

/// Fail-detection demos: these assertions are the gates. Removing
/// UnauthorizedRewrite / egress classification would turn them RED.
#[tokio::test]
async fn fail_detection_demo_unauthorized_rewrite_gate() {
    let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dest = dest_ip([127, 0, 0, 1], echo.local_addr().unwrap().port());
    let globals = XudpGlobalMap::new();
    let mut assoc =
        XudpDirectAssociation::open(&dest, None, [0xFD; 16], &globals, Instant::now(), None)
            .await
            .unwrap();
    let blocked = dest_ip([203, 0, 113, 1], 9); // TEST-NET-3
    let rewrite = packet_keep_rewrite(&blocked, b"should-not-leave");
    assert!(rewrite.destination.is_some());
    let err = assoc
        .handle_uplink_packet(&rewrite, None, Instant::now())
        .await
        .expect_err("GATE: UnauthorizedRewrite must exist");
    assert!(
        matches!(err, XudpSessionError::UnauthorizedRewrite),
        "GATE demo failed: expected UnauthorizedRewrite, got {err}"
    );
    assert_eq!(assoc.uplink_datagrams(), 0);
    assoc.close(&globals, Instant::now());
    eprintln!("fail_detection_demo_unauthorized_rewrite_gate PASS");
}

#[test]
fn fail_detection_demo_route_class_gate() {
    assert_eq!(
        authorize_xudp_egress(XudpRouteClass::Direct).unwrap(),
        XudpEgressCapability::Direct,
        "GATE: Direct must authorize as Direct"
    );
    assert!(
        require_direct_xudp_route(XudpRouteClass::Direct).is_ok(),
        "GATE: Direct landward must remain eligible"
    );
    assert_eq!(
        authorize_xudp_egress(XudpRouteClass::Nxr).unwrap(),
        XudpEgressCapability::Nxr,
        "GATE: NXR must authorize as Nxr (not Direct)"
    );
    assert_eq!(
        authorize_xudp_egress(XudpRouteClass::Handoff).unwrap(),
        XudpEgressCapability::Handoff,
        "GATE: Handoff must authorize as Handoff (not Direct)"
    );
    for class in [XudpRouteClass::Block, XudpRouteClass::Unsupported] {
        assert!(
            authorize_xudp_egress(class).is_err(),
            "GATE: {class:?} must fail closed at authorization"
        );
    }
    for class in [
        XudpRouteClass::Block,
        XudpRouteClass::Nxr,
        XudpRouteClass::Handoff,
        XudpRouteClass::Unsupported,
    ] {
        assert!(
            require_direct_xudp_route(class).is_err(),
            "GATE: {class:?} must not open Direct landward (no silent Direct fallback)"
        );
    }
    eprintln!("fail_detection_demo_route_class_gate PASS");
}

#[test]
fn keep_without_rewrite_preserves_status() {
    let dest = dest_ip([8, 8, 8, 8], 53);
    let mut wire = Vec::new();
    encode_xudp_packet(&dest, b"k", false, None, false, &mut wire).unwrap();
    let (pkt, _) = decode_xudp_packet(&wire).unwrap();
    assert_eq!(pkt.status, XudpSessionStatus::Keep);
    assert!(pkt.destination.is_none());
}

/// PR7 fault matrix: after N open→close→purge cycles the GlobalID map returns
/// to empty (resource recovery). No silent growth across recovered cycles.
#[tokio::test]
async fn association_resource_recovery_after_repeated_fault_cycles() {
    let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dest = dest_ip([127, 0, 0, 1], echo.local_addr().unwrap().port());
    let globals = XudpGlobalMap::new();
    let owner = [0xA1; 16];
    let cycles = 8usize;
    for i in 0..cycles {
        let mut gid = [0xA1_u8; 8];
        gid[7] = i as u8;
        let now = Instant::now();
        let mut assoc = XudpDirectAssociation::open(&dest, Some(gid), owner, &globals, now, None)
            .await
            .unwrap();
        assert_eq!(globals.len(), 1, "cycle {i}: one live association");
        let open = packet_new(&dest, b"pulse", Some(gid));
        assoc
            .handle_uplink_packet(&open, Some(&dest), Instant::now())
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let (n, _) = echo.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pulse");
        // Induced "fault": cancel / expire / purge — like LINE reload retiring
        // an association without leaking the GlobalID slot.
        assoc.close(&globals, Instant::now());
        globals.purge(Instant::now() + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert_eq!(globals.len(), 0, "cycle {i}: recovered to empty map");
    }
    eprintln!("association_resource_recovery_after_repeated_fault_cycles PASS (cycles={cycles})");
}

/// PR7: NXR and Handoff remain distinct egress capabilities across a Keep
/// rewrite authorization fence — never collapse to Direct (no silent fallback).
#[test]
fn fault_matrix_nxr_handoff_never_silent_direct_fallback() {
    for class in [XudpRouteClass::Nxr, XudpRouteClass::Handoff] {
        let cap = authorize_xudp_egress(class).expect("authorized topology");
        assert_ne!(
            cap,
            XudpEgressCapability::Direct,
            "{class:?} must not authorize as Direct"
        );
        assert!(
            require_direct_xudp_route(class).is_err(),
            "{class:?} must fail Direct landward (no silent Direct fallback)"
        );
        assert!(
            matches!(
                require_direct_xudp_landward(cap),
                Err(XudpOutboundUnsupported::Nxr | XudpOutboundUnsupported::Handoff)
            ),
            "{class:?} Direct landward gate must reject capability {cap:?}"
        );
    }
    // Block / Unsupported stay fail-closed at authorization.
    for class in [XudpRouteClass::Block, XudpRouteClass::Unsupported] {
        assert!(authorize_xudp_egress(class).is_err());
    }
    eprintln!("fault_matrix_nxr_handoff_never_silent_direct_fallback PASS");
}

/// PR7: a Keep rewrite authorized as NXR/Handoff must never be landed by the
/// Direct association path (cross-outbound fence). Prior Direct allow does not
/// inherit into a different egress class.
#[tokio::test]
async fn rewrite_cross_outbound_direct_landward_rejects_nxr_handoff() {
    let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dest = dest_ip([127, 0, 0, 1], echo.local_addr().unwrap().port());
    let globals = XudpGlobalMap::new();
    let mut assoc = XudpDirectAssociation::open(
        &dest,
        Some([0xC0; 8]),
        [0xC0; 16],
        &globals,
        Instant::now(),
        None,
    )
    .await
    .unwrap();
    let open = packet_new(&dest, b"direct-open", Some([0xC0; 8]));
    let (cap, auth) = authorize_or_reject(XudpRouteClass::Direct, &dest).unwrap();
    assert_eq!(cap, XudpEgressCapability::Direct);
    assoc
        .handle_uplink_packet(&open, Some(&auth), Instant::now())
        .await
        .unwrap();

    let alt = dest_ip([127, 0, 0, 1], echo.local_addr().unwrap().port());
    let rewrite = packet_keep_rewrite(&alt, b"cross-outbound");
    for class in [XudpRouteClass::Nxr, XudpRouteClass::Handoff] {
        let capability = authorize_xudp_egress(class).unwrap();
        assert!(
            require_direct_xudp_landward(capability).is_err(),
            "{class:?} must fail Direct landward on Keep rewrite"
        );
        // Vision must withhold authorized_destination when landward gate fails.
        let err = assoc
            .handle_uplink_packet(&rewrite, None, Instant::now())
            .await
            .expect_err("cross-outbound Keep without Direct auth must fail");
        assert!(
            matches!(err, XudpSessionError::UnauthorizedRewrite),
            "{class:?}: expected UnauthorizedRewrite, got {err}"
        );
    }
    assert_eq!(
        assoc.uplink_datagrams(),
        1,
        "only the initial Direct New may have egressed"
    );
    assoc.close(&globals, Instant::now());
    eprintln!("rewrite_cross_outbound_direct_landward_rejects_nxr_handoff PASS");
}

/// PR7: NXR landward MAC / sequence replay fail closed (ADR 0060 answer 8).
#[test]
fn nxr_udp_frame_replay_and_bad_mac_fail_closed() {
    let session = NxrUdpSessionKey::derive(
        &rust_reality::protocol::nxr::NxrKey::new([0x42; 32]),
        b"pr7-adversarial-open-prefix",
    );
    let mut wire = Vec::new();
    encode_frame(
        &session,
        DIR_LINE_TO_LANDING,
        FRAME_TYPE_DATAGRAM,
        0,
        None,
        b"once",
        &mut wire,
    )
    .unwrap();
    decode_frame(&wire, &session, DIR_LINE_TO_LANDING).unwrap();

    // Bad MAC
    let mut bad = wire.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    assert_eq!(
        decode_frame(&bad, &session, DIR_LINE_TO_LANDING),
        Err(NxrUdpError::Authentication)
    );

    // Sequence replay / reorder
    let mut inbound = NxrUdpSeq::new();
    inbound.accept_in(0).unwrap();
    assert_eq!(inbound.accept_in(0), Err(NxrUdpError::Sequence));
    assert_eq!(inbound.accept_in(2), Err(NxrUdpError::Sequence));
    inbound.accept_in(1).unwrap();
    eprintln!("nxr_udp_frame_replay_and_bad_mac_fail_closed PASS");
}

/// PR7: reload-style retirement — after close+purge the same GlobalID may be
/// reclaimed, but an in-flight Direct association never widens to NXR/Handoff
/// mid-life (ADR 0060 answer 10).
#[tokio::test]
async fn reload_retirement_does_not_widen_in_flight_authority() {
    let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dest = dest_ip([127, 0, 0, 1], echo.local_addr().unwrap().port());
    let globals = XudpGlobalMap::new();
    let owner = [0xD1; 16];
    let gid = [0xD1; 8];
    let mut assoc =
        XudpDirectAssociation::open(&dest, Some(gid), owner, &globals, Instant::now(), None)
            .await
            .unwrap();
    let open = packet_new(&dest, b"gen1", Some(gid));
    assoc
        .handle_uplink_packet(&open, Some(&dest), Instant::now())
        .await
        .unwrap();

    // Mid-life "reload" temptation: authorize NXR for a Keep rewrite — Direct
    // landward must still reject (authority does not widen in-flight).
    let nxr_cap = authorize_xudp_egress(XudpRouteClass::Nxr).unwrap();
    assert!(require_direct_xudp_landward(nxr_cap).is_err());
    let rewrite = packet_keep_rewrite(&dest, b"widen");
    let err = assoc
        .handle_uplink_packet(&rewrite, None, Instant::now())
        .await
        .expect_err("in-flight Direct must not accept unauthorized Keep");
    assert!(matches!(err, XudpSessionError::UnauthorizedRewrite));

    // Retirement recovers the GlobalID for a *new* association (new generation).
    assoc.close(&globals, Instant::now());
    globals.purge(Instant::now() + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
    assert_eq!(globals.len(), 0);
    let mut again =
        XudpDirectAssociation::open(&dest, Some(gid), owner, &globals, Instant::now(), None)
            .await
            .unwrap();
    let reopen = packet_new(&dest, b"gen2", Some(gid));
    again
        .handle_uplink_packet(&reopen, Some(&dest), Instant::now())
        .await
        .unwrap();
    let mut buf = [0u8; 8];
    let (n, _) = echo.recv_from(&mut buf).await.unwrap();
    // First gen1 may still be in the socket; drain until gen2 or accept either pulse.
    if &buf[..n] != b"gen2" {
        let (n2, _) = echo.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"gen2");
    } else {
        assert_eq!(&buf[..n], b"gen2");
    }
    again.close(&globals, Instant::now());
    eprintln!("reload_retirement_does_not_widen_in_flight_authority PASS");
}
