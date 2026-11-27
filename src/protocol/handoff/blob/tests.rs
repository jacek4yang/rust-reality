//! Codec-level tests for the sealed Handoff policy snapshot.
//!
//! The snapshot is LANDING's only copy of the LINE routing decision for a
//! Handoff XUDP session, so these tests pin two properties directly at the
//! codec boundary: every sealable matcher survives encode/decode with
//! identical authorization decisions, and every malformed or downgraded body
//! fails closed instead of widening authority.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::cursor::BlobCursor;
use super::policy::{decode_policy_snapshot, encode_policy_snapshot, encoded_policy_len};
use super::{encode_address, encode_bounded_bytes};
use crate::protocol::handoff::policy::{
    HANDOFF_POLICY_SNAPSHOT_VERSION, HANDOFF_POLICY_SNAPSHOT_VERSION_V1, MAX_POLICY_SNAPSHOT_LEN,
    MAX_SEALED_HANDOFF_RULES,
};
use crate::protocol::handoff::{
    HandoffError, HandoffPolicySnapshot, SealedDomainMatcher, SealedHandoffRouteRule,
    SealedIpNetwork, SealedPortRange,
};
use crate::protocol::vless::{Address, Destination};

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Destination {
    Destination::new(Address::Ipv4(Ipv4Addr::new(a, b, c, d)), port)
}

fn v6(address: &str, port: u16) -> Destination {
    Destination::new(Address::Ipv6(address.parse::<Ipv6Addr>().unwrap()), port)
}

fn domain(name: &str, port: u16) -> Destination {
    Destination::new(Address::Domain(name.into()), port)
}

fn ipv4_net(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> SealedIpNetwork {
    SealedIpNetwork::V4 {
        network: u32::from(Ipv4Addr::new(a, b, c, d)),
        prefix,
    }
}

fn ipv6_net(address: &str, prefix: u8) -> SealedIpNetwork {
    SealedIpNetwork::V6 {
        network: u128::from(address.parse::<Ipv6Addr>().unwrap()),
        prefix,
    }
}

/// Encoded snapshot body without its outer u32 length prefix.
fn body_of(policy: &HandoffPolicySnapshot) -> Vec<u8> {
    let mut framed = Vec::new();
    encode_policy_snapshot(policy, &mut framed).expect("encode");
    let length = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
    assert_eq!(length, framed.len() - 4);
    framed.split_off(4)
}

fn decode_body(body: &[u8]) -> Result<HandoffPolicySnapshot, HandoffError> {
    let mut framed = Vec::new();
    encode_bounded_bytes(body, &mut framed);
    let mut cursor = BlobCursor::new(&framed);
    let decoded = decode_policy_snapshot(&mut cursor);
    if decoded.is_ok() {
        assert_eq!(cursor.remaining(), 0, "decoder must consume the frame");
    }
    decoded
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    let mut hits = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(index, _)| index);
    let first = hits.next().expect("pattern present");
    assert!(hits.next().is_none(), "pattern must be unique");
    first
}

/// Every sealable matcher kind, both IP families with boundary prefixes, and
/// multiple port ranges, ordered deny-before-allow as LINE compiles them.
fn rich_policy(initial: Destination, default_allow: bool) -> HandoffPolicySnapshot {
    let rules = vec![
        SealedHandoffRouteRule {
            allow: false,
            domains: vec![SealedDomainMatcher::Keyword("blocked".into())],
            ips: Vec::new(),
            ports: Vec::new(),
        },
        SealedHandoffRouteRule {
            allow: false,
            domains: Vec::new(),
            ips: vec![
                ipv4_net(203, 0, 113, 7, 32),
                ipv6_net("2001:db8:dead::1", 128),
            ],
            ports: Vec::new(),
        },
        SealedHandoffRouteRule {
            allow: true,
            domains: vec![
                SealedDomainMatcher::Full("exact.example.test".into()),
                SealedDomainMatcher::Suffix("allowed.test".into()),
            ],
            ips: Vec::new(),
            ports: vec![
                SealedPortRange { start: 53, end: 53 },
                SealedPortRange {
                    start: 443,
                    end: 8443,
                },
            ],
        },
        SealedHandoffRouteRule {
            allow: true,
            domains: Vec::new(),
            ips: vec![ipv4_net(198, 51, 100, 0, 24), ipv6_net("2001:db8::", 64)],
            ports: vec![SealedPortRange {
                start: 1,
                end: u16::MAX,
            }],
        },
        SealedHandoffRouteRule {
            allow: false,
            domains: Vec::new(),
            ips: vec![ipv4_net(0, 0, 0, 0, 0), ipv6_net("::", 0)],
            ports: vec![SealedPortRange { start: 25, end: 25 }],
        },
    ];
    HandoffPolicySnapshot::xudp_with_sealed_rules(initial, rules, default_allow)
}

fn probes() -> Vec<Destination> {
    vec![
        domain("blocked.allowed.test", 443),
        domain("exact.example.test", 53),
        domain("sub.exact.example.test", 53),
        domain("www.allowed.test", 8443),
        domain("www.allowed.test", 8444),
        domain("notallowed.test", 443),
        v4(203, 0, 113, 7, 443),
        v4(203, 0, 113, 8, 443),
        v4(198, 51, 100, 255, 443),
        v4(198, 51, 101, 0, 443),
        v4(198, 51, 100, 1, 25),
        v4(192, 0, 2, 1, 25),
        v6("2001:db8:dead::1", 443),
        v6("2001:db8::ffff", 443),
        v6("2001:db8:0:1::1", 443),
        v6("2001:db8:0:1::1", 25),
        v6("fe80::1", 53),
    ]
}

#[test]
fn every_sealed_matcher_round_trips_with_identical_authorization() {
    for initial in [
        v4(10, 0, 0, 1, 443),
        v6("2001:db8::1", 443),
        domain("initial.test", 443),
    ] {
        for default_allow in [false, true] {
            let policy = rich_policy(initial.clone(), default_allow);
            assert!(policy.allow_destination_rewrites());
            let decoded = decode_body(&body_of(&policy)).expect("round trip");
            assert_eq!(decoded, policy);
            for probe in probes() {
                assert_eq!(
                    decoded.authorize_udp_destination(&probe),
                    policy.authorize_udp_destination(&probe),
                    "decision drift for {probe:?}"
                );
            }
        }
    }
    // Spot-check the decisions themselves so a symmetric bug cannot hide.
    let policy = decode_body(&body_of(&rich_policy(v4(10, 0, 0, 1, 443), false))).unwrap();
    let decide = |d: Destination| policy.authorize_udp_destination(&d).is_ok();
    assert!(
        !decide(domain("blocked.allowed.test", 443)),
        "keyword deny first"
    );
    assert!(decide(domain("exact.example.test", 53)));
    assert!(
        !decide(domain("sub.exact.example.test", 53)),
        "full is exact"
    );
    assert!(decide(domain("www.allowed.test", 8443)));
    assert!(!decide(domain("www.allowed.test", 8444)), "port range end");
    assert!(!decide(v4(203, 0, 113, 7, 443)), "/32 deny");
    assert!(decide(v4(198, 51, 100, 255, 443)), "/24 allow");
    assert!(!decide(v4(198, 51, 101, 0, 443)), "outside /24");
    assert!(!decide(v6("2001:db8:dead::1", 443)), "/128 deny");
    assert!(decide(v6("2001:db8::ffff", 443)), "/64 allow");
    assert!(!decide(v6("2001:db8:0:1::1", 443)), "outside /64");
    assert!(!decide(v4(192, 0, 2, 1, 25)), "/0 deny on port 25");
}

#[test]
fn out_of_range_prefixes_and_unknown_tags_fail_closed() {
    let initial = v4(10, 0, 0, 1, 443);
    let policy = HandoffPolicySnapshot::xudp_with_sealed_rules(
        initial,
        vec![SealedHandoffRouteRule {
            allow: true,
            domains: vec![SealedDomainMatcher::Suffix("ok.test".into())],
            ips: vec![ipv4_net(192, 0, 2, 0, 24), ipv6_net("2001:db8:1::", 48)],
            ports: vec![SealedPortRange {
                start: 1000,
                end: 2000,
            }],
        }],
        false,
    );
    let body = body_of(&policy);
    decode_body(&body).expect("unmodified body decodes");

    let v4_at = find(&body, &[4, 24, 192, 0, 2, 0]);
    let v6_at = find(&body, &[6, 48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let domain_at = find(&body, b"\x02\x07ok.test");
    let ports_at = find(&body, &[0x03, 0xe8, 0x07, 0xd0]);
    // IPv4 initial: version, two flags, 7-byte address, port, then rule count.
    assert_eq!(body[12], 1, "single rule; its allow flag follows at 13");
    let mutations: [(&str, usize, &[u8]); 12] = [
        ("IPv4 prefix above 32", v4_at + 1, &[33]),
        ("IPv6 prefix above 128", v6_at + 1, &[129]),
        ("unknown IP family", v4_at, &[5]),
        ("unknown domain matcher kind", domain_at, &[4]),
        ("non-ASCII domain byte", domain_at + 2, &[0xff]),
        // Valid UTF-8, so only the ASCII check can reject it.
        ("non-ASCII UTF-8 domain", domain_at + 2, &[0xc3, 0xa9]),
        ("port range start zero", ports_at, &[0, 0]),
        (
            "port range start above end",
            ports_at,
            &[0x07, 0xd0, 0x03, 0xe8],
        ),
        (
            "unknown snapshot version",
            0,
            &[HANDOFF_POLICY_SNAPSHOT_VERSION + 1],
        ),
        ("non-boolean rewrite flag", 1, &[2]),
        ("non-boolean default flag", 2, &[2]),
        ("non-boolean rule allow flag", 13, &[2]),
    ];
    for (name, index, bytes) in mutations {
        let mut mutated = body.clone();
        mutated[index..index + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            decode_body(&mutated),
            Err(HandoffError::State),
            "{name} must be rejected"
        );
    }
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(decode_body(&trailing), Err(HandoffError::State));
    for cut in 1..body.len() {
        assert_eq!(
            decode_body(&body[..cut]),
            Err(HandoffError::State),
            "truncation at {cut} must be rejected"
        );
    }
}

#[test]
fn rule_count_and_frame_length_caps_are_enforced() {
    let mut body = body_of(&HandoffPolicySnapshot::xudp_initial(v4(10, 0, 0, 1, 443)));
    assert_eq!(*body.last().unwrap(), 0, "rule count is the final byte");
    *body.last_mut().unwrap() = u8::try_from(MAX_SEALED_HANDOFF_RULES + 1).unwrap();
    assert_eq!(decode_body(&body), Err(HandoffError::State));

    let oversized = vec![HANDOFF_POLICY_SNAPSHOT_VERSION; MAX_POLICY_SNAPSHOT_LEN + 1];
    assert_eq!(decode_body(&oversized), Err(HandoffError::State));

    let too_many = HandoffPolicySnapshot::xudp_with_sealed_rules(
        v4(10, 0, 0, 1, 443),
        vec![
            SealedHandoffRouteRule {
                allow: true,
                domains: Vec::new(),
                ips: Vec::new(),
                ports: Vec::new(),
            };
            MAX_SEALED_HANDOFF_RULES + 1
        ],
        false,
    );
    let mut output = Vec::new();
    assert_eq!(
        encode_policy_snapshot(&too_many, &mut output),
        Err(HandoffError::Length),
        "encoder must refuse what the decoder would reject"
    );
}

#[test]
fn decoder_rule_cap_rejects_an_otherwise_well_formed_body() {
    // The cap must be what rejects the body, so every declared rule is
    // actually present and well formed.
    let empty_rule = SealedHandoffRouteRule {
        allow: false,
        domains: Vec::new(),
        ips: Vec::new(),
        ports: Vec::new(),
    };
    let at_cap = HandoffPolicySnapshot::xudp_with_sealed_rules(
        v4(10, 0, 0, 1, 443),
        vec![empty_rule; MAX_SEALED_HANDOFF_RULES],
        false,
    );
    let mut body = body_of(&at_cap);
    decode_body(&body).expect("a body at the rule cap decodes");
    // IPv4 initial: version, two flags, 7-byte address, port, then rule count.
    assert_eq!(usize::from(body[12]), MAX_SEALED_HANDOFF_RULES);
    body[12] += 1;
    body.extend_from_slice(&[0, 0, 0, 0]);
    assert!(body.len() <= MAX_POLICY_SNAPSHOT_LEN);
    assert_eq!(decode_body(&body), Err(HandoffError::State));
}

#[test]
fn encoder_refuses_bodies_above_the_frame_cap() {
    // Within the rule cap, long matchers can still exceed the frame the
    // decoder accepts; the encoder must refuse rather than seal it.
    let long = SealedHandoffRouteRule {
        allow: true,
        domains: vec![SealedDomainMatcher::Full("a".repeat(255))],
        ips: Vec::new(),
        ports: Vec::new(),
    };
    let oversized =
        HandoffPolicySnapshot::xudp_with_sealed_rules(v4(10, 0, 0, 1, 443), vec![long; 5], false);
    assert_eq!(encoded_policy_len(&oversized), Err(HandoffError::Length));
    let mut output = Vec::new();
    assert_eq!(
        encode_policy_snapshot(&oversized, &mut output),
        Err(HandoffError::Length)
    );
    assert!(output.is_empty(), "a refused snapshot writes nothing");
}

#[test]
fn legacy_v1_snapshot_never_gains_rewrite_authority() {
    let initial = domain("initial.test", 443);
    let mut v1 = vec![HANDOFF_POLICY_SNAPSHOT_VERSION_V1, 1];
    encode_address(&initial, &mut v1);
    v1.extend_from_slice(&initial.port().to_be_bytes());
    let decoded = decode_body(&v1).expect("v1 decodes");
    assert_eq!(
        decoded,
        HandoffPolicySnapshot::xudp_initial(initial.clone())
    );
    assert!(!decoded.allow_destination_rewrites());
    assert!(decoded.authorize_udp_destination(&initial).is_ok());
    assert!(
        decoded
            .authorize_udp_destination(&domain("other.test", 443))
            .is_err()
    );
    v1.push(0);
    assert_eq!(decode_body(&v1), Err(HandoffError::State));
}

#[test]
fn wire_rewrite_flag_disagreement_resolves_to_the_restrictive_view() {
    let initial = v4(10, 0, 0, 1, 443);
    let allowing = rich_policy(initial.clone(), true);
    let mut body = body_of(&allowing);
    assert_eq!(body[1], 1);
    body[1] = 0;
    let downgraded = decode_body(&body).expect("decodes");
    assert_eq!(
        downgraded,
        HandoffPolicySnapshot::xudp_initial(initial.clone())
    );
    assert!(
        downgraded
            .authorize_udp_destination(&v4(198, 51, 100, 1, 443))
            .is_err()
    );

    let deny_only = HandoffPolicySnapshot::xudp_with_sealed_rules(
        initial.clone(),
        vec![SealedHandoffRouteRule {
            allow: false,
            domains: Vec::new(),
            ips: vec![ipv4_net(198, 51, 100, 0, 24)],
            ports: Vec::new(),
        }],
        false,
    );
    assert!(!deny_only.allow_destination_rewrites());
    let mut body = body_of(&deny_only);
    assert_eq!(body[1], 0);
    body[1] = 1;
    let widened_claim = decode_body(&body).expect("decodes");
    assert!(
        !widened_claim.allow_destination_rewrites(),
        "a wire flag alone must not widen authority"
    );
    assert!(
        widened_claim
            .authorize_udp_destination(&v4(192, 0, 2, 1, 443))
            .is_err()
    );
}
