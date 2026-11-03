//! Packet codec, OPEN key schedule, and per-session AEAD channel.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInOut, Nonce, Tag, array::Array},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::super::{HandoffLandingKeys, HandoffPsk, HandoffReplayCache};
use super::window::ReplayWindow;
use crate::crypto::EphemeralX25519Key;
use crate::protocol::vless::XUDP_MAX_PAYLOAD_LEN;

/// Native UDP channel wire version.
pub const UDP_PROTOCOL_VERSION: u8 = 1;

/// Session identifier length (chosen by LINE, random).
pub const SESSION_ID_LEN: usize = 8;

/// Cleartext header: version, type, session id, counter.
pub const HEADER_LEN: usize = 2 + SESSION_ID_LEN + 8;

/// ChaCha20-Poly1305 tag length.
pub const TAG_LEN: usize = 16;

const OPEN_NONCE_LEN: usize = 16;
const X25519_LEN: usize = 32;
const USER_ID_LEN: usize = 16;
const OPEN_CLEAR_LEN: usize = 8 + OPEN_NONCE_LEN + X25519_LEN;

/// Truncated HMAC-SHA256 admission tag closing every OPEN.
const OPEN_FILTER_LEN: usize = 16;

/// Bytes of an OPEN covered by the admission tag.
const OPEN_SEALED_LEN: usize = HEADER_LEN + OPEN_CLEAR_LEN + USER_ID_LEN + TAG_LEN;

/// Exact OPEN packet length.
pub const OPEN_LEN: usize = OPEN_SEALED_LEN + OPEN_FILTER_LEN;

/// Largest application datagram the channel carries: the XUDP payload cap,
/// because every datagram enters or leaves through one XUDP frame on LINE.
pub const MAX_UDP_PAYLOAD_LEN: usize = XUDP_MAX_PAYLOAD_LEN;

/// Address family byte, address, and port preceding the datagram payload.
const MAX_ADDRESS_LEN: usize = 1 + 16 + 2;

/// Largest DATA plaintext (address metadata plus payload).
pub const MAX_DATA_PLAINTEXT_LEN: usize = MAX_ADDRESS_LEN + MAX_UDP_PAYLOAD_LEN;

/// FRAG plaintext prefix: u32 fragment id, u8 index, u8 count.
pub const FRAG_HEADER_LEN: usize = 6;

const ADDRESS_IPV4: u8 = 4;
const ADDRESS_IPV6: u8 = 6;

/// HKDF salt label; distinct from the TCP transfer label
/// `rust-reality/handoff/v1` so the two key schedules never collide.
const HKDF_LABEL: &[u8] = b"rust-reality/handoff-udp/v1";

/// HKDF salt of the PSK-only OPEN admission key. UDP sources are spoofable
/// and need no handshake, so LANDING rejects an OPEN that was not made by a
/// PSK holder before it burns a replay slot or performs any DH work.
const OPEN_FILTER_LABEL: &[u8] = b"rust-reality/handoff-udp/v1/open-filter";

type HmacSha256 = hmac::Hmac<Sha256>;

fn open_filter_mac(psk: &HandoffPsk) -> Result<HmacSha256, UdpPacketError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(OPEN_FILTER_LABEL), psk.as_bytes())
        .expand(&[], key.as_mut_slice())
        .map_err(|_| UdpPacketError::Crypto)?;
    <HmacSha256 as hmac::KeyInit>::new_from_slice(key.as_slice())
        .map_err(|_| UdpPacketError::Crypto)
}

fn open_filter_matches(psk: &HandoffPsk, packet: &[u8]) -> bool {
    let Ok(mut mac) = open_filter_mac(psk) else {
        return false;
    };
    hmac::Mac::update(&mut mac, &packet[..OPEN_SEALED_LEN]);
    hmac::Mac::verify_truncated_left(mac, &packet[OPEN_SEALED_LEN..OPEN_LEN]).is_ok()
}

/// One native channel packet type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    /// LINE→LANDING session open (ephemeral key share).
    Open = 1,
    /// LANDING→LINE open acknowledgement.
    OpenAck = 2,
    /// One whole datagram with its destination (uplink) or source (downlink).
    Data = 3,
    /// One fragment of a DATA plaintext.
    Frag = 4,
    /// Padded path MTU probe.
    Probe = 5,
    /// Probe acknowledgement.
    ProbeAck = 6,
    /// Session close.
    Close = 7,
}

impl PacketType {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Open),
            2 => Some(Self::OpenAck),
            3 => Some(Self::Data),
            4 => Some(Self::Frag),
            5 => Some(Self::Probe),
            6 => Some(Self::ProbeAck),
            7 => Some(Self::Close),
            _ => None,
        }
    }
}

/// Closed error vocabulary of the native channel. Receivers drop the packet
/// silently on every error; nothing is ever answered to an unauthenticated
/// sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpPacketError {
    /// A length is outside the fixed bounds.
    Length,
    /// Unsupported version.
    Version,
    /// Unknown or misplaced packet type.
    Type,
    /// OPEN timestamp outside the accepted clock window.
    TimeWindow,
    /// OPEN nonce or packet counter already seen, or too old.
    Replay,
    /// Key agreement or AEAD authentication failed.
    Authentication,
    /// Malformed or unsupported address metadata.
    Address,
    /// Wrong session id for this channel.
    Session,
    /// Send counter exhausted.
    Counter,
    /// Secure randomness unavailable.
    Random,
    /// A cryptographic primitive rejected an invariant.
    Crypto,
}

impl fmt::Display for UdpPacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Length => "handoff UDP packet length is invalid",
            Self::Version => "handoff UDP packet version is unsupported",
            Self::Type => "handoff UDP packet type is invalid",
            Self::TimeWindow => "handoff UDP open timestamp is outside policy",
            Self::Replay => "handoff UDP packet was replayed",
            Self::Authentication => "handoff UDP packet authentication failed",
            Self::Address => "handoff UDP datagram address is invalid",
            Self::Session => "handoff UDP session id does not match",
            Self::Counter => "handoff UDP send counter is exhausted",
            Self::Random => "handoff UDP randomness is unavailable",
            Self::Crypto => "handoff UDP cryptographic primitive failed",
        })
    }
}

impl std::error::Error for UdpPacketError {}

/// Parses the fixed cleartext header. Performs no authentication.
///
/// # Errors
///
/// Rejects short packets, unknown versions, and unknown types.
pub fn parse_header(
    packet: &[u8],
) -> Result<(PacketType, [u8; SESSION_ID_LEN], u64), UdpPacketError> {
    if packet.len() < HEADER_LEN + TAG_LEN {
        return Err(UdpPacketError::Length);
    }
    if packet[0] != UDP_PROTOCOL_VERSION {
        return Err(UdpPacketError::Version);
    }
    let packet_type = PacketType::from_wire(packet[1]).ok_or(UdpPacketError::Type)?;
    let mut session_id = [0_u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&packet[2..2 + SESSION_ID_LEN]);
    let mut counter = [0_u8; 8];
    counter.copy_from_slice(&packet[2 + SESSION_ID_LEN..HEADER_LEN]);
    Ok((packet_type, session_id, u64::from_be_bytes(counter)))
}

fn encode_header(
    packet_type: PacketType,
    session_id: &[u8; SESSION_ID_LEN],
    counter: u64,
) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    header[0] = UDP_PROTOCOL_VERSION;
    header[1] = packet_type as u8;
    header[2..2 + SESSION_ID_LEN].copy_from_slice(session_id);
    header[2 + SESSION_ID_LEN..].copy_from_slice(&counter.to_be_bytes());
    header
}

/// Authenticated OPEN contents, as LANDING sees them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOpen {
    /// LINE-chosen session id.
    pub session_id: [u8; SESSION_ID_LEN],
    /// Authenticated VLESS user the association belongs to (telemetry only).
    pub user_id: [u8; USER_ID_LEN],
}

struct DerivedKeys {
    open: Zeroizing<[u8; 32]>,
    line_to_landing: Zeroizing<[u8; 32]>,
    landing_to_line: Zeroizing<[u8; 32]>,
}

/// HKDF-Extract(salt = label || E_pub || S_pub, ikm = shared || PSK), then
/// HKDF-Expand over the OPEN cleartext (header, timestamp, nonce, E_pub)
/// followed by S_pub, yielding the OPEN key and both direction keys.
fn derive_keys(
    open_clear: &[u8; HEADER_LEN + OPEN_CLEAR_LEN],
    shared: &[u8; 32],
    psk: &HandoffPsk,
    landing_public: &[u8; 32],
) -> Result<DerivedKeys, UdpPacketError> {
    let ephemeral = &open_clear[HEADER_LEN + 8 + OPEN_NONCE_LEN..];
    let mut salt = [0_u8; HKDF_LABEL.len() + 2 * X25519_LEN];
    salt[..HKDF_LABEL.len()].copy_from_slice(HKDF_LABEL);
    salt[HKDF_LABEL.len()..HKDF_LABEL.len() + X25519_LEN].copy_from_slice(ephemeral);
    salt[HKDF_LABEL.len() + X25519_LEN..].copy_from_slice(landing_public);
    let mut ikm = Zeroizing::new([0_u8; 64]);
    ikm[..32].copy_from_slice(shared);
    ikm[32..].copy_from_slice(psk.as_bytes());
    let mut info = [0_u8; HEADER_LEN + OPEN_CLEAR_LEN + X25519_LEN];
    info[..HEADER_LEN + OPEN_CLEAR_LEN].copy_from_slice(open_clear);
    info[HEADER_LEN + OPEN_CLEAR_LEN..].copy_from_slice(landing_public);
    let mut okm = Zeroizing::new([0_u8; 96]);
    {
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), ikm.as_slice());
        let _prk = Zeroizing::new(prk);
        hkdf.expand(&info, okm.as_mut_slice())
            .map_err(|_| UdpPacketError::Crypto)?;
    }
    let mut keys = DerivedKeys {
        open: Zeroizing::new([0; 32]),
        line_to_landing: Zeroizing::new([0; 32]),
        landing_to_line: Zeroizing::new([0; 32]),
    };
    keys.open.copy_from_slice(&okm[..32]);
    keys.line_to_landing.copy_from_slice(&okm[32..64]);
    keys.landing_to_line.copy_from_slice(&okm[64..]);
    Ok(keys)
}

fn cipher(key: &[u8; 32]) -> Result<ChaCha20Poly1305, UdpPacketError> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| UdpPacketError::Crypto)
}

fn nonce_for(counter: u64) -> Nonce<ChaCha20Poly1305> {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    Array(nonce)
}

/// Seals one OPEN for a new session (LINE role) and returns the LINE end of
/// the channel. `output` receives the exact OPEN bytes, which the caller
/// retransmits unchanged until LANDING acknowledges.
///
/// # Errors
///
/// Rejects unavailable randomness, a non-contributory LANDING key, and AEAD
/// failure.
pub fn seal_open(
    psk: &HandoffPsk,
    landing_public: &[u8; 32],
    user_id: [u8; USER_ID_LEN],
    timestamp: u64,
    output: &mut Vec<u8>,
) -> Result<UdpChannel, UdpPacketError> {
    let mut session_id = [0_u8; SESSION_ID_LEN];
    crate::crypto::entropy::fill(&mut session_id).map_err(|_| UdpPacketError::Random)?;
    let mut open_nonce = [0_u8; OPEN_NONCE_LEN];
    crate::crypto::entropy::fill(&mut open_nonce).map_err(|_| UdpPacketError::Random)?;
    let ephemeral = EphemeralX25519Key::generate().map_err(|_| UdpPacketError::Random)?;
    let mut clear = [0_u8; HEADER_LEN + OPEN_CLEAR_LEN];
    clear[..HEADER_LEN].copy_from_slice(&encode_header(PacketType::Open, &session_id, 0));
    clear[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&timestamp.to_be_bytes());
    clear[HEADER_LEN + 8..HEADER_LEN + 8 + OPEN_NONCE_LEN].copy_from_slice(&open_nonce);
    clear[HEADER_LEN + 8 + OPEN_NONCE_LEN..].copy_from_slice(ephemeral.public_key());
    let shared = ephemeral
        .agree(landing_public)
        .ok_or(UdpPacketError::Authentication)?;
    let keys = derive_keys(&clear, &shared, psk, landing_public)?;
    let mut body = user_id;
    let tag = cipher(&keys.open)?
        .encrypt_inout_detached(&nonce_for(0), &clear, body.as_mut_slice().into())
        .map_err(|_| UdpPacketError::Crypto)?;
    output.clear();
    output.extend_from_slice(&clear);
    output.extend_from_slice(&body);
    output.extend_from_slice(&tag);
    let mut mac = open_filter_mac(psk)?;
    hmac::Mac::update(&mut mac, output);
    let filter = hmac::Mac::finalize(mac).into_bytes();
    output.extend_from_slice(&filter[..OPEN_FILTER_LEN]);
    UdpChannel::new(session_id, &keys.line_to_landing, &keys.landing_to_line)
}

/// Verifies one OPEN (LANDING role) and returns its contents with the
/// LANDING end of the channel.
///
/// Validation order: structure, timestamp window, the PSK-keyed admission
/// tag (constant time, per rotation PSK), one nonce reserve, then
/// per-candidate DH + HKDF + AEAD trials over the bounded rotation candidate
/// set. Unlike the TCP transfer, the replay reserve sits behind the
/// admission tag: a spoofed-source flood without the PSK can neither burn
/// replay capacity nor force DH work.
///
/// # Errors
///
/// Every failure maps to [`UdpPacketError`]; the caller drops silently.
pub fn accept_open(
    packet: &[u8],
    keys: &HandoffLandingKeys,
    replay: &HandoffReplayCache,
    now: u64,
    maximum_time_difference: u64,
) -> Result<(UdpOpen, UdpChannel), UdpPacketError> {
    if packet.len() != OPEN_LEN {
        return Err(UdpPacketError::Length);
    }
    let (packet_type, session_id, counter) = parse_header(packet)?;
    if packet_type != PacketType::Open || counter != 0 {
        return Err(UdpPacketError::Type);
    }
    let clear: [u8; HEADER_LEN + OPEN_CLEAR_LEN] = packet[..HEADER_LEN + OPEN_CLEAR_LEN]
        .try_into()
        .map_err(|_| UdpPacketError::Length)?;
    let mut timestamp = [0_u8; 8];
    timestamp.copy_from_slice(&clear[HEADER_LEN..HEADER_LEN + 8]);
    if u64::from_be_bytes(timestamp).abs_diff(now) > maximum_time_difference {
        return Err(UdpPacketError::TimeWindow);
    }
    let admitted: Vec<&HandoffPsk> = keys
        .candidates()
        .map(|(psk, _)| psk)
        .filter(|psk| open_filter_matches(psk, packet))
        .collect();
    if admitted.is_empty() {
        return Err(UdpPacketError::Authentication);
    }
    let mut open_nonce = [0_u8; OPEN_NONCE_LEN];
    open_nonce.copy_from_slice(&clear[HEADER_LEN + 8..HEADER_LEN + 8 + OPEN_NONCE_LEN]);
    replay
        .reserve(open_nonce)
        .map_err(|_| UdpPacketError::Replay)?;
    let mut ephemeral = [0_u8; X25519_LEN];
    ephemeral.copy_from_slice(&clear[HEADER_LEN + 8 + OPEN_NONCE_LEN..]);
    let body = &packet[HEADER_LEN + OPEN_CLEAR_LEN..HEADER_LEN + OPEN_CLEAR_LEN + USER_ID_LEN];
    let tag: [u8; TAG_LEN] = packet[OPEN_SEALED_LEN - TAG_LEN..OPEN_SEALED_LEN]
        .try_into()
        .map_err(|_| UdpPacketError::Length)?;
    let tag: Tag<ChaCha20Poly1305> = Array(tag);
    // Every candidate performs its own DH and derivation; nothing is shared
    // across trials (same rule as `open_transfer`).
    for (psk, secret) in keys.candidates() {
        if !admitted.iter().any(|admitted| std::ptr::eq(*admitted, psk)) {
            continue;
        }
        let Some(shared) = secret.agree(&ephemeral) else {
            continue;
        };
        let landing_public = secret.public_key();
        let derived = derive_keys(&clear, &shared, psk, &landing_public)?;
        let mut user_id = [0_u8; USER_ID_LEN];
        user_id.copy_from_slice(body);
        if cipher(&derived.open)?
            .decrypt_inout_detached(&nonce_for(0), &clear, user_id.as_mut_slice().into(), &tag)
            .is_ok()
        {
            let channel = UdpChannel::new(
                session_id,
                &derived.landing_to_line,
                &derived.line_to_landing,
            )?;
            return Ok((
                UdpOpen {
                    session_id,
                    user_id,
                },
                channel,
            ));
        }
    }
    Err(UdpPacketError::Authentication)
}

/// One authenticated end of a native UDP session.
///
/// Owns the send key and counter and the receive key and replay window.
/// `Debug` never reveals key material.
pub struct UdpChannel {
    session_id: [u8; SESSION_ID_LEN],
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_counter: u64,
    window: ReplayWindow,
}

impl fmt::Debug for UdpChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpChannel")
            .field("send_counter", &self.send_counter)
            .field("recv_highest", &self.window.highest())
            .finish_non_exhaustive()
    }
}

impl UdpChannel {
    fn new(
        session_id: [u8; SESSION_ID_LEN],
        send: &[u8; 32],
        recv: &[u8; 32],
    ) -> Result<Self, UdpPacketError> {
        Ok(Self {
            session_id,
            send: cipher(send)?,
            recv: cipher(recv)?,
            send_counter: 0,
            window: ReplayWindow::new(),
        })
    }

    /// This session's identifier.
    #[must_use]
    pub const fn session_id(&self) -> [u8; SESSION_ID_LEN] {
        self.session_id
    }

    /// Seals one packet. `output` is replaced by header, ciphertext, and tag.
    ///
    /// # Errors
    ///
    /// Rejects counter exhaustion and AEAD failure.
    pub fn seal(
        &mut self,
        packet_type: PacketType,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), UdpPacketError> {
        self.seal_padded(packet_type, plaintext, 0, output)
    }

    /// Seals one packet whose plaintext is `prefix` followed by zero padding,
    /// so the whole packet is `max(total_len, minimal)` bytes. Used by PMTU
    /// probes; padding is authenticated like any other plaintext.
    ///
    /// # Errors
    ///
    /// Rejects counter exhaustion and AEAD failure.
    pub fn seal_padded(
        &mut self,
        packet_type: PacketType,
        prefix: &[u8],
        total_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), UdpPacketError> {
        if packet_type == PacketType::Open {
            return Err(UdpPacketError::Type);
        }
        let counter = self
            .send_counter
            .checked_add(1)
            .ok_or(UdpPacketError::Counter)?;
        self.send_counter = counter;
        let header = encode_header(packet_type, &self.session_id, counter);
        let plain_len = prefix
            .len()
            .max(total_len.saturating_sub(HEADER_LEN + TAG_LEN));
        output.clear();
        output
            .try_reserve(HEADER_LEN + plain_len + TAG_LEN)
            .map_err(|_| UdpPacketError::Length)?;
        output.extend_from_slice(&header);
        output.extend_from_slice(prefix);
        output.resize(HEADER_LEN + plain_len, 0);
        let tag = self
            .send
            .encrypt_inout_detached(
                &nonce_for(counter),
                &header,
                output[HEADER_LEN..].as_mut().into(),
            )
            .map_err(|_| UdpPacketError::Crypto)?;
        output.extend_from_slice(&tag);
        Ok(())
    }

    /// Authenticates and decrypts one received packet into `plaintext`.
    ///
    /// The replay window is checked before and committed only after AEAD
    /// success, so forgeries never move it.
    ///
    /// # Errors
    ///
    /// Rejects malformed, foreign-session, replayed, and forged packets.
    pub fn open(
        &mut self,
        packet: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<PacketType, UdpPacketError> {
        let (packet_type, session_id, counter) = parse_header(packet)?;
        if packet_type == PacketType::Open {
            return Err(UdpPacketError::Type);
        }
        if session_id != self.session_id {
            return Err(UdpPacketError::Session);
        }
        if !self.window.check(counter) {
            return Err(UdpPacketError::Replay);
        }
        let header = &packet[..HEADER_LEN];
        let body_end = packet.len() - TAG_LEN;
        let tag: [u8; TAG_LEN] = packet[body_end..]
            .try_into()
            .map_err(|_| UdpPacketError::Length)?;
        let tag: Tag<ChaCha20Poly1305> = Array(tag);
        plaintext.clear();
        plaintext.extend_from_slice(&packet[HEADER_LEN..body_end]);
        if self
            .recv
            .decrypt_inout_detached(
                &nonce_for(counter),
                header,
                plaintext.as_mut_slice().into(),
                &tag,
            )
            .is_err()
        {
            plaintext.clear();
            return Err(UdpPacketError::Authentication);
        }
        if !self.window.commit(counter) {
            plaintext.clear();
            return Err(UdpPacketError::Replay);
        }
        Ok(packet_type)
    }
}

/// Encodes a DATA plaintext: address family, address, port, payload.
///
/// # Errors
///
/// Rejects port zero, unspecified addresses, and oversized payloads.
pub fn encode_data_plaintext(
    address: SocketAddr,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), UdpPacketError> {
    if payload.len() > MAX_UDP_PAYLOAD_LEN {
        return Err(UdpPacketError::Length);
    }
    if address.port() == 0 || address.ip().is_unspecified() {
        return Err(UdpPacketError::Address);
    }
    output.clear();
    match address.ip() {
        IpAddr::V4(ip) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

/// Decodes a DATA plaintext into its address and payload.
///
/// # Errors
///
/// Rejects unknown families, truncation, port zero, unspecified addresses,
/// and oversized payloads.
pub fn decode_data(plaintext: &[u8]) -> Result<(SocketAddr, &[u8]), UdpPacketError> {
    let (&family, rest) = plaintext.split_first().ok_or(UdpPacketError::Length)?;
    let (ip, rest) = match family {
        ADDRESS_IPV4 => {
            let octets: [u8; 4] = rest
                .get(..4)
                .ok_or(UdpPacketError::Length)?
                .try_into()
                .map_err(|_| UdpPacketError::Length)?;
            (IpAddr::V4(Ipv4Addr::from(octets)), &rest[4..])
        }
        ADDRESS_IPV6 => {
            let octets: [u8; 16] = rest
                .get(..16)
                .ok_or(UdpPacketError::Length)?
                .try_into()
                .map_err(|_| UdpPacketError::Length)?;
            (IpAddr::V6(Ipv6Addr::from(octets)), &rest[16..])
        }
        _ => return Err(UdpPacketError::Address),
    };
    let port: [u8; 2] = rest
        .get(..2)
        .ok_or(UdpPacketError::Length)?
        .try_into()
        .map_err(|_| UdpPacketError::Length)?;
    let port = u16::from_be_bytes(port);
    if port == 0 || ip.is_unspecified() {
        return Err(UdpPacketError::Address);
    }
    let payload = &rest[2..];
    if payload.len() > MAX_UDP_PAYLOAD_LEN {
        return Err(UdpPacketError::Length);
    }
    Ok((SocketAddr::new(ip, port), payload))
}
