//! Continuation-state blob encode/decode for Handoff.
//!
//! Kept in its own module so seal/open and the wire header stay readable while
//! the dense v3 blob codec (policy snapshot, destinations, traffic secrets)
//! lives beside the replay/keys/error surfaces.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::policy::{
    HANDOFF_POLICY_SNAPSHOT_VERSION, HANDOFF_POLICY_SNAPSHOT_VERSION_V1, HandoffPolicySnapshot,
    MAX_POLICY_SNAPSHOT_LEN, MAX_SEALED_HANDOFF_RULES, SealedDomainMatcher, SealedHandoffRouteRule,
    SealedIpNetwork, SealedPortRange, SessionKind,
};
use super::{
    ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, CONTINUATION_STATE_VERSION, ContinuationState,
    HandoffError, MAX_BLOB_LEN, MAX_DOMAIN_LEN, MAX_INBOUND_TAG_LEN, MAX_PENDING_CIPHERTEXT_LEN,
    MAX_PREFETCHED_PLAINTEXT_LEN, USER_ID_LEN,
};
use crate::protocol::reality::tls13::{CipherSuite, TrafficSecret};
use crate::protocol::vless::{Address, Destination};

pub(crate) fn encode_blob(
    state: &ContinuationState,
    output: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let address_length = bounded_address_length(state.destination())?;
    let policy_len = encoded_policy_len(state.policy())?;
    let inbound_len = state.inbound_tag().len();
    let total = 1_usize
        .checked_add(2)
        .and_then(|length| length.checked_add(2 * state.suite().hash().output_len()))
        .and_then(|length| length.checked_add(2 * 8))
        .and_then(|length| length.checked_add(1)) // key_update
        .and_then(|length| length.checked_add(1)) // session_kind
        .and_then(|length| length.checked_add(USER_ID_LEN))
        .and_then(|length| length.checked_add(1 + inbound_len)) // inbound tag
        .and_then(|length| length.checked_add(1 + 2 + address_length + 2))
        .and_then(|length| length.checked_add(4 + state.pending_ciphertext().len()))
        .and_then(|length| length.checked_add(4 + state.prefetched_plaintext().len()))
        .and_then(|length| length.checked_add(4 + policy_len))
        .filter(|length| *length <= MAX_BLOB_LEN)
        .ok_or(HandoffError::Length)?;
    output.clear();
    output
        .try_reserve_exact(total)
        .map_err(|_| HandoffError::Allocation)?;
    output.push(CONTINUATION_STATE_VERSION);
    output.extend_from_slice(&state.suite().wire_value().to_be_bytes());
    encode_traffic_secret(state.client_traffic_secret(), output);
    encode_traffic_secret(state.server_traffic_secret(), output);
    output.extend_from_slice(&state.client_sequence().to_be_bytes());
    output.extend_from_slice(&state.server_sequence().to_be_bytes());
    output.push(u8::from(state.key_update_response_pending()));
    output.push(state.session_kind().wire());
    output.extend_from_slice(state.user_id());
    encode_short_bytes(state.inbound_tag().as_bytes(), output)?;
    encode_address(state.destination(), output);
    output.extend_from_slice(&state.destination().port().to_be_bytes());
    encode_bounded_bytes(state.pending_ciphertext(), output);
    encode_bounded_bytes(state.prefetched_plaintext(), output);
    encode_policy_snapshot(state.policy(), output)?;
    Ok(())
}

fn encoded_policy_len(policy: &HandoffPolicySnapshot) -> Result<usize, HandoffError> {
    let mut body = Vec::new();
    encode_policy_snapshot_body(policy, &mut body)?;
    body.len()
        .checked_add(4) // outer length prefix
        .filter(|_length| body.len() <= MAX_POLICY_SNAPSHOT_LEN)
        .ok_or(HandoffError::Length)
}

fn encode_short_bytes(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), HandoffError> {
    if bytes.len() > MAX_INBOUND_TAG_LEN {
        return Err(HandoffError::State);
    }
    let length = u8::try_from(bytes.len()).map_err(|_| HandoffError::State)?;
    output.push(length);
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_policy_snapshot(
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

fn encode_address(destination: &Destination, output: &mut Vec<u8>) {
    match destination.address() {
        Address::Ipv4(address) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&4_u16.to_be_bytes());
            output.extend_from_slice(&address.octets());
        }
        Address::Domain(domain) => {
            output.push(ADDRESS_DOMAIN);
            let length = u16::try_from(domain.len()).unwrap_or(0);
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(address) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&16_u16.to_be_bytes());
            output.extend_from_slice(&address.octets());
        }
    }
}

fn encode_traffic_secret(secret: &TrafficSecret, output: &mut Vec<u8>) {
    output.extend_from_slice(secret.as_bytes());
}

fn encode_bounded_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

pub(crate) fn decode_blob(blob: &[u8]) -> Result<ContinuationState, HandoffError> {
    let mut cursor = BlobCursor::new(blob);
    let version = cursor.u8()?;
    // Reject legacy blobs explicitly: never reinterpret v1/v2 as v3 fields.
    if version != CONTINUATION_STATE_VERSION {
        return Err(HandoffError::State);
    }
    let suite = CipherSuite::from_wire(cursor.u16()?).ok_or(HandoffError::State)?;
    let client_traffic_secret = decode_traffic_secret(&mut cursor, suite)?;
    let server_traffic_secret = decode_traffic_secret(&mut cursor, suite)?;
    let client_sequence = cursor.u64()?;
    let server_sequence = cursor.u64()?;
    let key_update_response_pending = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(HandoffError::State),
    };
    let session_kind = SessionKind::from_wire(cursor.u8()?).ok_or(HandoffError::State)?;
    let user_id: [u8; USER_ID_LEN] = cursor
        .take(USER_ID_LEN)?
        .try_into()
        .map_err(|_| HandoffError::State)?;
    let inbound_tag = decode_short_string(&mut cursor)?;
    let destination = decode_destination(&mut cursor)?;
    let pending_ciphertext = decode_bounded_bytes(&mut cursor, MAX_PENDING_CIPHERTEXT_LEN)?;
    let prefetched_plaintext = decode_bounded_bytes(&mut cursor, MAX_PREFETCHED_PLAINTEXT_LEN)?;
    let policy = decode_policy_snapshot(&mut cursor)?;
    if cursor.remaining() != 0 {
        return Err(HandoffError::State);
    }
    ContinuationState::new(
        suite,
        client_traffic_secret,
        client_sequence,
        server_traffic_secret,
        server_sequence,
        key_update_response_pending,
        session_kind,
        user_id,
        inbound_tag,
        destination,
        pending_ciphertext,
        prefetched_plaintext,
        policy,
    )
}

fn decode_short_string(cursor: &mut BlobCursor<'_>) -> Result<String, HandoffError> {
    let length = usize::from(cursor.u8()?);
    if length > MAX_INBOUND_TAG_LEN {
        return Err(HandoffError::State);
    }
    let bytes = cursor.take(length)?;
    if !bytes.is_ascii() {
        return Err(HandoffError::State);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| HandoffError::State)
}

fn decode_policy_snapshot(
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

fn decode_traffic_secret(
    cursor: &mut BlobCursor<'_>,
    suite: CipherSuite,
) -> Result<TrafficSecret, HandoffError> {
    TrafficSecret::from_bytes(suite.hash(), cursor.take(suite.hash().output_len())?)
        .map_err(|_| HandoffError::State)
}

fn decode_destination(cursor: &mut BlobCursor<'_>) -> Result<Destination, HandoffError> {
    let address_type = cursor.u8()?;
    let address_len = usize::from(cursor.u16()?);
    let address = cursor.take(address_len)?;
    let parsed = match address_type {
        ADDRESS_IPV4 => {
            let bytes: [u8; 4] = address.try_into().map_err(|_| HandoffError::State)?;
            Address::Ipv4(Ipv4Addr::from(bytes))
        }
        ADDRESS_DOMAIN => {
            if address.is_empty() || address.len() > MAX_DOMAIN_LEN {
                return Err(HandoffError::State);
            }
            Address::Domain(
                std::str::from_utf8(address)
                    .map(str::to_owned)
                    .map_err(|_| HandoffError::State)?,
            )
        }
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = address.try_into().map_err(|_| HandoffError::State)?;
            Address::Ipv6(Ipv6Addr::from(bytes))
        }
        _ => return Err(HandoffError::State),
    };
    let port = cursor.u16()?;
    if port == 0 {
        return Err(HandoffError::State);
    }
    Ok(Destination::new(parsed, port))
}

fn decode_bounded_bytes(cursor: &mut BlobCursor<'_>, cap: usize) -> Result<Vec<u8>, HandoffError> {
    let length = usize::try_from(cursor.u32()?).map_err(|_| HandoffError::State)?;
    if length > cap {
        return Err(HandoffError::State);
    }
    let bytes = cursor.take(length)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| HandoffError::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn bounded_address_length(destination: &Destination) -> Result<usize, HandoffError> {
    match destination.address() {
        Address::Ipv4(_) => Ok(4),
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
                return Err(HandoffError::State);
            }
            Ok(domain.len())
        }
        Address::Ipv6(_) => Ok(16),
    }
}

struct BlobCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BlobCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HandoffError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HandoffError::State)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(HandoffError::State)?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, HandoffError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, HandoffError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, HandoffError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, HandoffError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }
}

/// Fuzz-target entry point for the continuation blob decoder: `blob` is
/// treated as already-decrypted plaintext, so the decoder's bounds checks
/// can be exercised without defeating the AEAD. Built only with the
/// `fuzzing` feature, which the `fuzz/` workspace enables on this crate.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_blob(blob: &[u8]) -> Result<ContinuationState, HandoffError> {
    decode_blob(blob)
}
