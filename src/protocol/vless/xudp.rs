//! XUDP packet framing and Vision UDP/443 policy helpers.
//!
//! Authority: stock Xray-core v26.7.28 (`5ca6f4b7d4dc20a881d4330e498892697627ec0c`),
//! packages `common/xudp` and the Mux metadata layout used by `PacketWriter`.
//!
//! XUDP is **not** the config flow string `xtls-rprx-vision-udp443`. That flow is a
//! client policy that permits UDP/443 while still advertising wire flow
//! `xtls-rprx-vision`. XUDP is the VLESS Mux (`0x03`) carrier to `v1.mux.cool:666`
//! plus the datagram framing defined here.

use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::{Address, Command, Destination, VISION_FLOW};

/// Config-only Vision flow that permits UDP/443 under stock Xray policy.
///
/// On the wire the Addons flow is still [`VISION_FLOW`] (first 16 characters).
pub const VISION_FLOW_UDP443: &str = "xtls-rprx-vision-udp443";

/// Synthetic Mux destination host used by XUDP carriers (not written on the VLESS header).
pub const XUDP_MUX_HOST: &str = "v1.mux.cool";

/// Synthetic Mux destination port used by XUDP carriers.
pub const XUDP_MUX_PORT: u16 = 666;

/// Maximum Mux metadata length accepted by stock Xray (`common/mux/frame.go`).
pub const XUDP_MAX_META_LEN: usize = 512;

/// Stock Xray `common/buf.Size` (pinned v26.7.28 / current Xray-core releases).
pub const XRAY_BUF_SIZE: usize = 8 * 1024;

/// Soft upper bound matching Xray `PacketWriter` (`length + 666 > buf.Size` → skip).
/// We **reject** oversized payloads rather than silently dropping them.
pub const XUDP_MAX_PAYLOAD_LEN: usize = XRAY_BUF_SIZE - 666; // 7526

const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_DOMAIN: u8 = 0x02;
const ADDRESS_TYPE_IPV6: u8 = 0x03;

/// Mux session status byte used by XUDP frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum XudpSessionStatus {
    /// Opening frame for a UDP association (`SessionStatusNew`).
    New = 0x01,
    /// Continuation frame (`SessionStatusKeep`).
    Keep = 0x02,
    /// Association teardown (`SessionStatusEnd`).
    End = 0x03,
    /// Keep-alive / discard (`SessionStatusKeepAlive`).
    KeepAlive = 0x04,
}

impl XudpSessionStatus {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::New),
            0x02 => Some(Self::Keep),
            0x03 => Some(Self::End),
            0x04 => Some(Self::KeepAlive),
            _ => None,
        }
    }
}

/// Mux option bitmask. Only `Data` is required for XUDP datagrams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XudpOption(u8);

impl XudpOption {
    /// Frame carries an application payload length + bytes.
    pub const DATA: Self = Self(0x01);
    /// Frame reports an error (stock End frames may set this).
    pub const ERROR: Self = Self(0x02);

    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    pub const fn as_byte(self) -> u8 {
        self.0
    }

    pub const fn has_data(self) -> bool {
        self.0 & Self::DATA.0 != 0
    }
}

/// Target network byte inside XUDP metadata. Only UDP is accepted on this path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum XudpNetwork {
    Tcp = 0x01,
    Udp = 0x02,
}

impl XudpNetwork {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Eight-byte cone-NAT affinity key carried on New frames with data.
pub type XudpGlobalId = [u8; 8];

/// One decoded XUDP frame (metadata + optional payload).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XudpPacket {
    /// Mux session identifier. Stock XUDP writers use `0`.
    pub session_id: u16,
    pub status: XudpSessionStatus,
    pub option: XudpOption,
    /// Present on New frames and on Keep frames that rewrite the UDP destination.
    pub destination: Option<Destination>,
    /// Present on New+Data frames when the stock writer attaches a GlobalID.
    pub global_id: Option<XudpGlobalId>,
    /// Application datagram when `option` has Data and length > 0.
    pub payload: Vec<u8>,
}

/// Errors produced while encoding or decoding XUDP frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XudpCodecError {
    Truncated {
        field: &'static str,
    },
    MetaTooLarge {
        length: usize,
    },
    MetaTooSmall {
        length: usize,
    },
    UnknownStatus(u8),
    UnknownNetwork(u8),
    /// XUDP carrier accepts UDP network only (TCP Mux is a different path).
    TcpNetworkRejected,
    UnknownAddressType(u8),
    DomainTooLong {
        length: usize,
    },
    EmptyDomain,
    InvalidDomainUtf8,
    PayloadTooLarge {
        length: usize,
    },
    TrailingMetaBytes {
        remaining: usize,
    },
    SessionIdMustBeZero {
        session_id: u16,
    },
}

impl fmt::Display for XudpCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field } => write!(formatter, "XUDP frame truncated at {field}"),
            Self::MetaTooLarge { length } => {
                write!(
                    formatter,
                    "XUDP metadata length {length} exceeds {XUDP_MAX_META_LEN}"
                )
            }
            Self::MetaTooSmall { length } => {
                write!(
                    formatter,
                    "XUDP metadata length {length} is below the 4-byte minimum"
                )
            }
            Self::UnknownStatus(value) => write!(formatter, "unknown XUDP session status {value}"),
            Self::UnknownNetwork(value) => write!(formatter, "unknown XUDP network {value}"),
            Self::TcpNetworkRejected => {
                formatter.write_str("XUDP rejects TCP network type (UDP-only carrier)")
            }
            Self::UnknownAddressType(value) => {
                write!(formatter, "unknown XUDP address type {value}")
            }
            Self::DomainTooLong { length } => {
                write!(formatter, "XUDP domain length {length} exceeds 255")
            }
            Self::EmptyDomain => formatter.write_str("XUDP domain address is empty"),
            Self::InvalidDomainUtf8 => formatter.write_str("XUDP domain is not valid UTF-8"),
            Self::PayloadTooLarge { length } => {
                write!(
                    formatter,
                    "XUDP payload length {length} exceeds {XUDP_MAX_PAYLOAD_LEN}"
                )
            }
            Self::TrailingMetaBytes { remaining } => {
                write!(
                    formatter,
                    "XUDP metadata has {remaining} unexpected trailing bytes"
                )
            }
            Self::SessionIdMustBeZero { session_id } => {
                write!(
                    formatter,
                    "XUDP session id must be 0 (found {session_id}); non-zero is TCP Mux"
                )
            }
        }
    }
}

impl Error for XudpCodecError {}

/// Returns whether a **config** Vision flow string permits UDP/443.
///
/// Wire Addons must still carry [`VISION_FLOW`]. Matching stock Xray outbound:
/// only the `-udp443` suffix sets the allow bit, then the flow is truncated.
pub fn config_flow_allows_udp_443(config_flow: &str) -> bool {
    config_flow == VISION_FLOW_UDP443
}

/// Returns the wire Addons flow string for a config Vision flow.
///
/// `xtls-rprx-vision-udp443` → `xtls-rprx-vision`; other values pass through unchanged
/// for the caller to validate.
pub fn wire_vision_flow_from_config(config_flow: &str) -> &str {
    if config_flow == VISION_FLOW_UDP443 {
        VISION_FLOW
    } else {
        config_flow
    }
}

/// Stock Xray rejects plain `RequestCommandUDP` to port 443 unless `-udp443` is set.
pub fn vision_udp_command_allows_port(allow_udp_443: bool, port: u16) -> bool {
    allow_udp_443 || port != 443
}

/// Returns whether a Mux metadata **body** (bytes after `metaLen`) is XUDP.
///
/// Stock `isMuxAndNotXUDP` returns true (TCP Mux) unless session ID is `0,0` and
/// the network byte at body offset 4 is `2` (UDP). This helper is the XUDP side
/// of that peek and requires at least 5 body bytes.
pub fn meta_body_is_xudp(meta_body: &[u8]) -> bool {
    meta_body.len() >= 5
        && meta_body[0] == 0
        && meta_body[1] == 0
        && meta_body[4] == XudpNetwork::Udp as u8
}

/// Returns whether a full XUDP/Mux frame (starting at `metaLen`) peeks as XUDP.
pub fn frame_looks_like_xudp(frame: &[u8]) -> bool {
    if frame.len() < 2 {
        return false;
    }
    let meta_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if meta_len < 5 || frame.len() < 2 + meta_len {
        return false;
    }
    meta_body_is_xudp(&frame[2..2 + meta_len])
}

/// VLESS request is the Mux command used as the XUDP carrier.
pub const fn is_xudp_mux_command(command: Command) -> bool {
    matches!(command, Command::Mux)
}

/// Encode one XUDP datagram frame matching stock `PacketWriter` layout.
///
/// - `new_association`: status New with destination (and optional GlobalID).
/// - otherwise: status Keep; destination is embedded only when `rewrite_destination` is set.
pub fn encode_xudp_packet(
    destination: &Destination,
    payload: &[u8],
    new_association: bool,
    global_id: Option<XudpGlobalId>,
    rewrite_destination: bool,
    output: &mut Vec<u8>,
) -> Result<(), XudpCodecError> {
    if payload.len() > XUDP_MAX_PAYLOAD_LEN {
        return Err(XudpCodecError::PayloadTooLarge {
            length: payload.len(),
        });
    }
    let payload_len =
        u16::try_from(payload.len()).map_err(|_| XudpCodecError::PayloadTooLarge {
            length: payload.len(),
        })?;

    // Failure-atomic: stage into a scratch buffer and append only on success so
    // a MetaTooLarge / address error cannot leave a partial frame in `output`.
    let mut staged = Vec::with_capacity(2 + XUDP_MAX_META_LEN + 2 + payload.len());
    staged.extend_from_slice(&[0, 0]); // metaLen placeholder
    staged.extend_from_slice(&0_u16.to_be_bytes()); // session id 0

    if new_association {
        staged.push(XudpSessionStatus::New as u8);
        staged.push(XudpOption::DATA.as_byte());
        staged.push(XudpNetwork::Udp as u8);
        write_port_then_address(&mut staged, destination)?;
        if let Some(id) = global_id {
            staged.extend_from_slice(&id);
        }
    } else {
        staged.push(XudpSessionStatus::Keep as u8);
        staged.push(XudpOption::DATA.as_byte());
        if rewrite_destination {
            staged.push(XudpNetwork::Udp as u8);
            write_port_then_address(&mut staged, destination)?;
        }
    }

    let meta_len = staged.len() - 2;
    if meta_len > XUDP_MAX_META_LEN {
        return Err(XudpCodecError::MetaTooLarge { length: meta_len });
    }
    let meta_len_u16 = u16::try_from(meta_len).expect("meta_len fits u16 after bound check");
    staged[0..2].copy_from_slice(&meta_len_u16.to_be_bytes());
    staged.extend_from_slice(&payload_len.to_be_bytes());
    staged.extend_from_slice(payload);
    output.extend_from_slice(&staged);
    Ok(())
}

/// Decode one XUDP frame from `input`.
///
/// Returns `(packet, bytes_consumed)`. Rejects TCP network, unknown status, and
/// non-zero session IDs (those belong to TCP Mux, not XUDP).
pub fn decode_xudp_packet(input: &[u8]) -> Result<(XudpPacket, usize), XudpCodecError> {
    if input.len() < 2 {
        return Err(XudpCodecError::Truncated { field: "metaLen" });
    }
    let meta_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if meta_len < 4 {
        return Err(XudpCodecError::MetaTooSmall { length: meta_len });
    }
    if meta_len > XUDP_MAX_META_LEN {
        return Err(XudpCodecError::MetaTooLarge { length: meta_len });
    }
    let meta_end = 2 + meta_len;
    if input.len() < meta_end {
        return Err(XudpCodecError::Truncated { field: "metadata" });
    }
    let meta = &input[2..meta_end];

    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    if session_id != 0 {
        return Err(XudpCodecError::SessionIdMustBeZero { session_id });
    }
    let status =
        XudpSessionStatus::from_byte(meta[2]).ok_or(XudpCodecError::UnknownStatus(meta[2]))?;
    let option = XudpOption::from_byte(meta[3]);

    let mut cursor = 4;
    let mut destination = None;
    let mut global_id = None;

    match status {
        XudpSessionStatus::New => {
            if meta.len() < cursor + 1 {
                return Err(XudpCodecError::Truncated { field: "network" });
            }
            let network = XudpNetwork::from_byte(meta[cursor])
                .ok_or(XudpCodecError::UnknownNetwork(meta[cursor]))?;
            cursor += 1;
            if network == XudpNetwork::Tcp {
                return Err(XudpCodecError::TcpNetworkRejected);
            }
            let (dest, consumed) = read_port_then_address(&meta[cursor..])?;
            cursor += consumed;
            destination = Some(dest);
            // Stock attaches GlobalID when OptionData and remaining >= 8.
            if option.has_data() && meta.len() >= cursor + 8 {
                let mut id = [0_u8; 8];
                id.copy_from_slice(&meta[cursor..cursor + 8]);
                global_id = Some(id);
                cursor += 8;
            }
            if cursor != meta.len() {
                // Allow trailing padding only when no GlobalID was claimed and
                // remaining bytes are empty padding — stock may leave nothing.
                return Err(XudpCodecError::TrailingMetaBytes {
                    remaining: meta.len() - cursor,
                });
            }
        }
        XudpSessionStatus::Keep => {
            if meta.len() > cursor {
                if meta[cursor] == XudpNetwork::Udp as u8 {
                    cursor += 1;
                    let (dest, consumed) = read_port_then_address(&meta[cursor..])?;
                    cursor += consumed;
                    destination = Some(dest);
                } else if meta[cursor] == XudpNetwork::Tcp as u8 {
                    return Err(XudpCodecError::TcpNetworkRejected);
                } else {
                    return Err(XudpCodecError::UnknownNetwork(meta[cursor]));
                }
            }
            if cursor != meta.len() {
                return Err(XudpCodecError::TrailingMetaBytes {
                    remaining: meta.len() - cursor,
                });
            }
        }
        XudpSessionStatus::End | XudpSessionStatus::KeepAlive => {
            if cursor != meta.len() {
                // End/KeepAlive should be meta-only (4 bytes). Reject extras.
                return Err(XudpCodecError::TrailingMetaBytes {
                    remaining: meta.len() - cursor,
                });
            }
        }
    }

    let mut consumed = meta_end;
    let mut payload = Vec::new();
    if option.has_data() {
        if input.len() < consumed + 2 {
            return Err(XudpCodecError::Truncated {
                field: "payloadLen",
            });
        }
        let payload_len = u16::from_be_bytes([input[consumed], input[consumed + 1]]) as usize;
        consumed += 2;
        if payload_len > XUDP_MAX_PAYLOAD_LEN {
            return Err(XudpCodecError::PayloadTooLarge {
                length: payload_len,
            });
        }
        if input.len() < consumed + payload_len {
            return Err(XudpCodecError::Truncated { field: "payload" });
        }
        payload.extend_from_slice(&input[consumed..consumed + payload_len]);
        consumed += payload_len;
    }

    Ok((
        XudpPacket {
            session_id,
            status,
            option,
            destination,
            global_id,
            payload,
        },
        consumed,
    ))
}

/// Fuzz entry: decode must not panic.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_xudp_packet(input: &[u8]) {
    let _ = decode_xudp_packet(input);
}

fn write_port_then_address(
    output: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), XudpCodecError> {
    output.extend_from_slice(&destination.port().to_be_bytes());
    match destination.address() {
        Address::Ipv4(addr) => {
            output.push(ADDRESS_TYPE_IPV4);
            output.extend_from_slice(&addr.octets());
        }
        Address::Ipv6(addr) => {
            output.push(ADDRESS_TYPE_IPV6);
            output.extend_from_slice(&addr.octets());
        }
        Address::Domain(domain) => {
            if domain.is_empty() {
                return Err(XudpCodecError::EmptyDomain);
            }
            if domain.len() > 255 {
                return Err(XudpCodecError::DomainTooLong {
                    length: domain.len(),
                });
            }
            output.push(ADDRESS_TYPE_DOMAIN);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

fn read_port_then_address(input: &[u8]) -> Result<(Destination, usize), XudpCodecError> {
    if input.len() < 3 {
        return Err(XudpCodecError::Truncated {
            field: "port/address",
        });
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    let address_type = input[2];
    let mut cursor = 3;
    let address = match address_type {
        ADDRESS_TYPE_IPV4 => {
            if input.len() < cursor + 4 {
                return Err(XudpCodecError::Truncated { field: "ipv4" });
            }
            let mut octets = [0_u8; 4];
            octets.copy_from_slice(&input[cursor..cursor + 4]);
            cursor += 4;
            Address::Ipv4(Ipv4Addr::from(octets))
        }
        ADDRESS_TYPE_IPV6 => {
            if input.len() < cursor + 16 {
                return Err(XudpCodecError::Truncated { field: "ipv6" });
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&input[cursor..cursor + 16]);
            cursor += 16;
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        ADDRESS_TYPE_DOMAIN => {
            if input.len() < cursor + 1 {
                return Err(XudpCodecError::Truncated {
                    field: "domain length",
                });
            }
            let len = input[cursor] as usize;
            cursor += 1;
            if len == 0 {
                return Err(XudpCodecError::EmptyDomain);
            }
            if input.len() < cursor + len {
                return Err(XudpCodecError::Truncated { field: "domain" });
            }
            let domain = std::str::from_utf8(&input[cursor..cursor + len])
                .map_err(|_| XudpCodecError::InvalidDomainUtf8)?;
            cursor += len;
            Address::Domain(domain.to_owned())
        }
        unknown => return Err(XudpCodecError::UnknownAddressType(unknown)),
    };
    Ok((Destination::new(address, port), cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dest_dns() -> Destination {
        Destination::new(Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 53)
    }

    fn dest_https() -> Destination {
        Destination::new(Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 443)
    }

    #[test]
    fn config_udp443_policy_is_not_wire_flow() {
        assert!(config_flow_allows_udp_443(VISION_FLOW_UDP443));
        assert!(!config_flow_allows_udp_443(VISION_FLOW));
        assert_eq!(
            wire_vision_flow_from_config(VISION_FLOW_UDP443),
            VISION_FLOW
        );
        assert_eq!(wire_vision_flow_from_config(VISION_FLOW), VISION_FLOW);
    }

    #[test]
    fn vision_rejects_udp_443_without_policy() {
        assert!(!vision_udp_command_allows_port(false, 443));
        assert!(vision_udp_command_allows_port(true, 443));
        assert!(vision_udp_command_allows_port(false, 53));
    }

    #[test]
    fn golden_new_frame_without_global_id() {
        // Hand-built to match common/xudp PacketWriter for New+Data+UDP IPv4.
        // metaLen=12: sid(2)+status+opt+net+port(2)+type+ipv4(4)
        let expected: &[u8] = &[
            0x00, 0x0c, // metaLen
            0x00, 0x00, // session id
            0x01, // New
            0x01, // Data
            0x02, // UDP
            0x00, 0x35, // port 53
            0x01, // IPv4
            0x01, 0x01, 0x01, 0x01, // 1.1.1.1
            0x00, 0x02, // payload len
            b'h', b'i',
        ];
        let mut encoded = Vec::new();
        encode_xudp_packet(&dest_dns(), b"hi", true, None, false, &mut encoded).expect("encode");
        assert_eq!(encoded, expected);

        let (packet, consumed) = decode_xudp_packet(&encoded).expect("decode");
        assert_eq!(consumed, encoded.len());
        assert_eq!(packet.status, XudpSessionStatus::New);
        assert_eq!(packet.destination.as_ref(), Some(&dest_dns()));
        assert_eq!(packet.global_id, None);
        assert_eq!(packet.payload, b"hi");
    }

    #[test]
    fn golden_new_frame_with_global_id() {
        let global = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        // metaLen=20: sid(2)+st+opt+net+port(2)+type+ipv4(4)+gid(8)
        let expected: &[u8] = &[
            0x00, 0x14, // metaLen 20
            0x00, 0x00, // session id
            0x01, // New
            0x01, // Data
            0x02, // UDP
            0x01, 0xbb, // port 443
            0x01, // IPv4
            0x01, 0x01, 0x01, 0x01, // 1.1.1.1
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // GlobalID
            0x00, 0x01, // payload len
            b'x',
        ];
        let mut encoded = Vec::new();
        encode_xudp_packet(&dest_https(), b"x", true, Some(global), false, &mut encoded)
            .expect("encode");
        assert_eq!(encoded, expected);

        let (packet, _) = decode_xudp_packet(&encoded).expect("decode");
        assert_eq!(packet.global_id, Some(global));
        assert_eq!(packet.destination.as_ref(), Some(&dest_https()));
    }

    #[test]
    fn keep_frame_without_address_round_trips() {
        let mut encoded = Vec::new();
        encode_xudp_packet(&dest_dns(), b"abc", false, None, false, &mut encoded).expect("encode");
        // metaLen=4
        assert_eq!(&encoded[..6], &[0x00, 0x04, 0x00, 0x00, 0x02, 0x01]);
        let (packet, consumed) = decode_xudp_packet(&encoded).expect("decode");
        assert_eq!(consumed, encoded.len());
        assert_eq!(packet.status, XudpSessionStatus::Keep);
        assert_eq!(packet.destination, None);
        assert_eq!(packet.payload, b"abc");
    }

    #[test]
    fn keep_frame_with_address_rewrite() {
        let mut encoded = Vec::new();
        encode_xudp_packet(&dest_dns(), b"z", false, None, true, &mut encoded).expect("encode");
        let (packet, _) = decode_xudp_packet(&encoded).expect("decode");
        assert_eq!(packet.destination.as_ref(), Some(&dest_dns()));
    }

    #[test]
    fn rejects_tcp_network_on_new() {
        let frame: &[u8] = &[
            0x00, 0x0c, 0x00, 0x00, 0x01, 0x01, 0x01, // TCP network
            0x00, 0x50, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        assert_eq!(
            decode_xudp_packet(frame),
            Err(XudpCodecError::TcpNetworkRejected)
        );
    }

    #[test]
    fn rejects_nonzero_session_id() {
        let frame: &[u8] = &[0x00, 0x04, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00];
        assert_eq!(
            decode_xudp_packet(frame),
            Err(XudpCodecError::SessionIdMustBeZero { session_id: 1 })
        );
    }

    #[test]
    fn rejects_oversized_meta() {
        let mut frame = vec![0x02, 0x01]; // metaLen 513
        frame.extend(std::iter::repeat_n(0, 513));
        assert_eq!(
            decode_xudp_packet(&frame),
            Err(XudpCodecError::MetaTooLarge { length: 513 })
        );
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(
            decode_xudp_packet(&[0x00]),
            Err(XudpCodecError::Truncated { field: "metaLen" })
        );
    }

    #[test]
    fn meta_body_xudp_peek_matches_stock() {
        // session 0,0, status New, opt Data, network UDP
        assert!(meta_body_is_xudp(&[0, 0, 1, 1, 2]));
        // TCP network → not XUDP
        assert!(!meta_body_is_xudp(&[0, 0, 1, 1, 1]));
        // non-zero session → not XUDP
        assert!(!meta_body_is_xudp(&[0, 1, 1, 1, 2]));
        assert!(is_xudp_mux_command(Command::Mux));
        assert!(!is_xudp_mux_command(Command::Tcp));
    }

    #[test]
    fn constants_match_stock_names() {
        assert_eq!(XUDP_MUX_HOST, "v1.mux.cool");
        assert_eq!(XUDP_MUX_PORT, 666);
        assert_eq!(VISION_FLOW_UDP443, "xtls-rprx-vision-udp443");
        assert_eq!(VISION_FLOW.len(), 16);
        assert!(VISION_FLOW_UDP443.starts_with(VISION_FLOW));
        assert_eq!(XRAY_BUF_SIZE, 8 * 1024);
        assert_eq!(XUDP_MAX_PAYLOAD_LEN, XRAY_BUF_SIZE - 666);
        assert_eq!(XUDP_MAX_PAYLOAD_LEN, 7526);
    }

    #[test]
    fn rejects_payload_above_stock_buf_size_gate() {
        let oversized = vec![0_u8; XUDP_MAX_PAYLOAD_LEN + 1];
        let mut out = Vec::new();
        assert_eq!(
            encode_xudp_packet(&dest_dns(), &oversized, true, None, false, &mut out),
            Err(XudpCodecError::PayloadTooLarge {
                length: XUDP_MAX_PAYLOAD_LEN + 1
            })
        );
        assert!(out.is_empty(), "failed encode must not mutate output");
    }

    #[test]
    fn encode_is_failure_atomic_on_address_error() {
        // Domain longer than 255 fails inside staging; output must stay untouched.
        let domain = "a".repeat(256);
        let dest = Destination::new(Address::Domain(domain), 53);
        let mut out = vec![0xAA, 0xBB];
        let err = encode_xudp_packet(&dest, b"x", true, Some([1; 8]), false, &mut out)
            .expect_err("oversized domain must fail");
        assert!(matches!(err, XudpCodecError::DomainTooLong { .. }));
        assert_eq!(
            out,
            vec![0xAA, 0xBB],
            "failed encode must be failure-atomic"
        );
    }

    /// New+Data+UDP to 1.1.1.1:53 with `extra` appended to the metadata.
    fn new_meta(option: u8, extra: &[u8]) -> Vec<u8> {
        let mut meta = vec![0x00, 0x00, 0x01, option, 0x02, 0x00, 0x35, 0x01, 1, 1, 1, 1];
        meta.extend_from_slice(extra);
        meta
    }

    fn frame(meta: &[u8], payload: Option<&[u8]>) -> Vec<u8> {
        let mut out = u16::try_from(meta.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(meta);
        if let Some(payload) = payload {
            out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn rejects_metadata_shorter_than_the_fixed_header() {
        for length in 0..4_u8 {
            let mut input = vec![0x00, length];
            input.extend(std::iter::repeat_n(0, usize::from(length) + 4));
            assert_eq!(
                decode_xudp_packet(&input),
                Err(XudpCodecError::MetaTooSmall {
                    length: usize::from(length)
                })
            );
        }
    }

    #[test]
    fn rejects_trailing_metadata_for_every_status() {
        // New without the Data option never carries a GlobalID: 8 extra bytes are trailing.
        assert_eq!(
            decode_xudp_packet(&frame(&new_meta(0x00, &[7; 8]), None)),
            Err(XudpCodecError::TrailingMetaBytes { remaining: 8 })
        );
        // New with Data: GlobalID consumed, anything after it is trailing.
        assert_eq!(
            decode_xudp_packet(&frame(&new_meta(0x01, &[7; 9]), Some(b"x"))),
            Err(XudpCodecError::TrailingMetaBytes { remaining: 1 })
        );
        // Keep with an address rewrite followed by one extra byte.
        let keep = [
            0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35, 0x01, 1, 1, 1, 1, 0xEE,
        ];
        assert_eq!(
            decode_xudp_packet(&frame(&keep, Some(b"x"))),
            Err(XudpCodecError::TrailingMetaBytes { remaining: 1 })
        );
        // End and KeepAlive are header-only.
        for status in [0x03, 0x04] {
            assert_eq!(
                decode_xudp_packet(&frame(&[0x00, 0x00, status, 0x00, 0xEE], None)),
                Err(XudpCodecError::TrailingMetaBytes { remaining: 1 })
            );
        }
    }

    #[test]
    fn keep_rejects_tcp_and_unknown_networks_distinctly() {
        let keep_tcp = [0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x35, 0x01, 1, 1, 1, 1];
        assert_eq!(
            decode_xudp_packet(&frame(&keep_tcp, Some(b"x"))),
            Err(XudpCodecError::TcpNetworkRejected)
        );
        let keep_unknown = [0x00, 0x00, 0x02, 0x01, 0x03];
        assert_eq!(
            decode_xudp_packet(&frame(&keep_unknown, Some(b"x"))),
            Err(XudpCodecError::UnknownNetwork(0x03))
        );
    }

    #[test]
    fn header_only_frames_consume_no_payload_length() {
        // End and KeepAlive without the Data option stop at the metadata, so a
        // following frame in the same buffer is left untouched.
        for (status, expected) in [
            (0x03, XudpSessionStatus::End),
            (0x04, XudpSessionStatus::KeepAlive),
        ] {
            let mut input = frame(&[0x00, 0x00, status, 0x00], None);
            input.extend_from_slice(&[0x00, 0x04]);
            let (packet, consumed) = decode_xudp_packet(&input).expect("header-only frame");
            assert_eq!(packet.status, expected);
            assert_eq!(consumed, 6);
            assert!(packet.payload.is_empty());
        }
    }

    #[test]
    fn decoder_enforces_the_stock_payload_cap_exactly() {
        let at_cap = vec![0x5A; XUDP_MAX_PAYLOAD_LEN];
        let (packet, consumed) =
            decode_xudp_packet(&frame(&new_meta(0x01, &[]), Some(&at_cap))).expect("at cap");
        assert_eq!(packet.payload.len(), XUDP_MAX_PAYLOAD_LEN);
        assert_eq!(consumed, 2 + 12 + 2 + XUDP_MAX_PAYLOAD_LEN);

        let over = vec![0x5A; XUDP_MAX_PAYLOAD_LEN + 1];
        assert_eq!(
            decode_xudp_packet(&frame(&new_meta(0x01, &[]), Some(&over))),
            Err(XudpCodecError::PayloadTooLarge {
                length: XUDP_MAX_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn domain_addresses_must_be_non_empty_utf8() {
        let domain_meta = |domain: &[u8]| {
            let mut meta = vec![0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x35, 0x02];
            meta.push(u8::try_from(domain.len()).unwrap());
            meta.extend_from_slice(domain);
            meta
        };
        assert_eq!(
            decode_xudp_packet(&frame(&domain_meta(b""), None)),
            Err(XudpCodecError::EmptyDomain)
        );
        assert_eq!(
            decode_xudp_packet(&frame(&domain_meta(&[0xFF, 0xFE]), None)),
            Err(XudpCodecError::InvalidDomainUtf8)
        );
        let (packet, _) = decode_xudp_packet(&frame(&domain_meta(b"dns.test"), None)).unwrap();
        assert_eq!(
            packet.destination,
            Some(Destination::new(Address::Domain("dns.test".to_owned()), 53))
        );

        let mut out = vec![0xAA];
        let empty = Destination::new(Address::Domain(String::new()), 53);
        assert_eq!(
            encode_xudp_packet(&empty, b"x", true, None, false, &mut out),
            Err(XudpCodecError::EmptyDomain)
        );
        assert_eq!(out, vec![0xAA], "failed encode must be failure-atomic");
    }
}
