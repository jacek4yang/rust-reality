//! Sealed Handoff policy snapshot codec inside the continuation-state blob.

use super::super::HandoffError;
use super::super::policy::{
    HANDOFF_POLICY_SNAPSHOT_VERSION, HANDOFF_POLICY_SNAPSHOT_VERSION_V1, HandoffPolicySnapshot,
    MAX_POLICY_SNAPSHOT_LEN, MAX_SEALED_HANDOFF_RULES, SealedDomainMatcher, SealedHandoffRouteRule,
    SealedIpNetwork, SealedPortRange,
};
use super::{
    BlobCursor, decode_bounded_bytes, decode_destination, encode_address, encode_bounded_bytes,
};

pub(super) fn encoded_policy_len(policy: &HandoffPolicySnapshot) -> Result<usize, HandoffError> {
    let mut body = Vec::new();
    encode_policy_snapshot_body(policy, &mut body)?;
    body.len()
        .checked_add(4) // outer length prefix
        .filter(|_length| body.len() <= MAX_POLICY_SNAPSHOT_LEN)
        .ok_or(HandoffError::Length)
}

pub(super) fn encode_policy_snapshot(
    policy: &HandoffPolicySnapshot,
    output: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let mut body = Vec::new();
    encode_policy_snapshot_body(policy, &mut body)?;
    if body.len() > MAX_POLICY_SNAPSHOT_LEN {
        return Err(HandoffError::Length);
    }
    encode_bounded_bytes(&body, output);
    Ok(())
}

fn encode_policy_snapshot_body(
    policy: &HandoffPolicySnapshot,
    body: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    body.push(HANDOFF_POLICY_SNAPSHOT_VERSION);
    body.push(u8::from(policy.allow_destination_rewrites()));
    body.push(u8::from(policy.default_allow()));
    encode_address(policy.initial_destination(), body);
    body.extend_from_slice(&policy.initial_destination().port().to_be_bytes());
    let rule_count = u8::try_from(policy.sealed_rules().len()).map_err(|_| HandoffError::Length)?;
    if usize::from(rule_count) > MAX_SEALED_HANDOFF_RULES {
        return Err(HandoffError::Length);
    }
    body.push(rule_count);
    for rule in policy.sealed_rules() {
        encode_sealed_rule(rule, body)?;
    }
    Ok(())
}

fn encode_sealed_rule(
    rule: &SealedHandoffRouteRule,
    body: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    body.push(u8::from(rule.allow));
    let domain_count = u8::try_from(rule.domains.len()).map_err(|_| HandoffError::Length)?;
    body.push(domain_count);
    for domain in &rule.domains {
        encode_sealed_domain(domain, body)?;
    }
    let ip_count = u8::try_from(rule.ips.len()).map_err(|_| HandoffError::Length)?;
    body.push(ip_count);
    for ip in &rule.ips {
        encode_sealed_ip(*ip, body);
    }
    let port_count = u8::try_from(rule.ports.len()).map_err(|_| HandoffError::Length)?;
    body.push(port_count);
    for port in &rule.ports {
        body.extend_from_slice(&port.start.to_be_bytes());
        body.extend_from_slice(&port.end.to_be_bytes());
    }
    Ok(())
}

fn encode_sealed_domain(
    domain: &SealedDomainMatcher,
    body: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let (kind, value) = match domain {
        SealedDomainMatcher::Full(value) => (1_u8, value.as_str()),
        SealedDomainMatcher::Suffix(value) => (2_u8, value.as_str()),
        SealedDomainMatcher::Keyword(value) => (3_u8, value.as_str()),
    };
    if value.len() > 255 {
        return Err(HandoffError::Length);
    }
    body.push(kind);
    body.push(u8::try_from(value.len()).map_err(|_| HandoffError::Length)?);
    body.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_sealed_ip(network: SealedIpNetwork, body: &mut Vec<u8>) {
    match network {
        SealedIpNetwork::V4 { network, prefix } => {
            body.push(4);
            body.push(prefix);
            body.extend_from_slice(&network.to_be_bytes());
        }
        SealedIpNetwork::V6 { network, prefix } => {
            body.push(6);
            body.push(prefix);
            body.extend_from_slice(&network.to_be_bytes());
        }
    }
}

pub(super) fn decode_policy_snapshot(
    cursor: &mut BlobCursor<'_>,
) -> Result<HandoffPolicySnapshot, HandoffError> {
    let body = decode_bounded_bytes(cursor, MAX_POLICY_SNAPSHOT_LEN)?;
    let mut inner = BlobCursor::new(&body);
    let version = inner.u8()?;
    match version {
        HANDOFF_POLICY_SNAPSHOT_VERSION_V1 => {
            let allow_destination_rewrites = match inner.u8()? {
                0 => false,
                1 => true,
                _ => return Err(HandoffError::State),
            };
            let initial_destination = decode_destination(&mut inner)?;
            if inner.remaining() != 0 {
                return Err(HandoffError::State);
            }
            // Legacy v1 never carried compiled rules; ignore the rewrite flag and
            // keep initial-only semantics (no silent widen of authority).
            let _ = allow_destination_rewrites;
            Ok(HandoffPolicySnapshot::xudp_initial(initial_destination))
        }
        HANDOFF_POLICY_SNAPSHOT_VERSION => {
            let allow_destination_rewrites = match inner.u8()? {
                0 => false,
                1 => true,
                _ => return Err(HandoffError::State),
            };
            let default_allow = match inner.u8()? {
                0 => false,
                1 => true,
                _ => return Err(HandoffError::State),
            };
            let initial_destination = decode_destination(&mut inner)?;
            let rule_count = usize::from(inner.u8()?);
            if rule_count > MAX_SEALED_HANDOFF_RULES {
                return Err(HandoffError::State);
            }
            let mut rules = Vec::with_capacity(rule_count);
            for _ in 0..rule_count {
                rules.push(decode_sealed_rule(&mut inner)?);
            }
            if inner.remaining() != 0 {
                return Err(HandoffError::State);
            }
            let mut policy = HandoffPolicySnapshot::xudp_with_sealed_rules(
                initial_destination,
                rules,
                default_allow,
            );
            // Wire flag must agree with derived authority (no silent widen).
            if policy.allow_destination_rewrites() != allow_destination_rewrites {
                // Prefer fail-closed: force the more restrictive view.
                if !allow_destination_rewrites {
                    policy =
                        HandoffPolicySnapshot::xudp_initial(policy.initial_destination().clone());
                }
            }
            Ok(policy)
        }
        _ => Err(HandoffError::State),
    }
}

fn decode_sealed_rule(cursor: &mut BlobCursor<'_>) -> Result<SealedHandoffRouteRule, HandoffError> {
    let allow = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(HandoffError::State),
    };
    let domain_count = usize::from(cursor.u8()?);
    let mut domains = Vec::with_capacity(domain_count);
    for _ in 0..domain_count {
        domains.push(decode_sealed_domain(cursor)?);
    }
    let ip_count = usize::from(cursor.u8()?);
    let mut ips = Vec::with_capacity(ip_count);
    for _ in 0..ip_count {
        ips.push(decode_sealed_ip(cursor)?);
    }
    let port_count = usize::from(cursor.u8()?);
    let mut ports = Vec::with_capacity(port_count);
    for _ in 0..port_count {
        let start = cursor.u16()?;
        let end = cursor.u16()?;
        if start == 0 || start > end {
            return Err(HandoffError::State);
        }
        ports.push(SealedPortRange { start, end });
    }
    Ok(SealedHandoffRouteRule {
        allow,
        domains,
        ips,
        ports,
    })
}

fn decode_sealed_domain(cursor: &mut BlobCursor<'_>) -> Result<SealedDomainMatcher, HandoffError> {
    let kind = cursor.u8()?;
    let len = usize::from(cursor.u8()?);
    let bytes = cursor.take(len)?;
    if !bytes.is_ascii() {
        return Err(HandoffError::State);
    }
    let value = String::from_utf8(bytes.to_vec()).map_err(|_| HandoffError::State)?;
    match kind {
        1 => Ok(SealedDomainMatcher::Full(value)),
        2 => Ok(SealedDomainMatcher::Suffix(value)),
        3 => Ok(SealedDomainMatcher::Keyword(value)),
        _ => Err(HandoffError::State),
    }
}

fn decode_sealed_ip(cursor: &mut BlobCursor<'_>) -> Result<SealedIpNetwork, HandoffError> {
    match cursor.u8()? {
        4 => {
            let prefix = cursor.u8()?;
            if prefix > 32 {
                return Err(HandoffError::State);
            }
            let mut raw = [0_u8; 4];
            raw.copy_from_slice(cursor.take(4)?);
            Ok(SealedIpNetwork::V4 {
                network: u32::from_be_bytes(raw),
                prefix,
            })
        }
        6 => {
            let prefix = cursor.u8()?;
            if prefix > 128 {
                return Err(HandoffError::State);
            }
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(cursor.take(16)?);
            Ok(SealedIpNetwork::V6 {
                network: u128::from_be_bytes(raw),
                prefix,
            })
        }
        _ => Err(HandoffError::State),
    }
}
