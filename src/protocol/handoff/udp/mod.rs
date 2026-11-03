//! Native LINE→LANDING UDP channel for Handoff XUDP traffic (ADR 0069).
//!
//! TCP Handoff transfers TLS ownership to LANDING (ADR 0031). XUDP does not:
//! LINE keeps decrypting REALITY + Vision + XUDP, performs every DNS,
//! GeoIP/GeoSite, routing, and authorization decision, and sends only
//! authorized datagrams to LANDING over this channel. LANDING authenticates
//! each datagram, forwards it to the destination LINE named, and returns
//! replies through the same channel. LANDING evaluates no routing rules.
//!
//! Wire layout (every packet is exactly one UDP datagram):
//!
//! ```text
//! header (AEAD associated data, 18 bytes):
//!   u8 version (=1) | u8 type | [8] session_id | u64 counter
//! OPEN (LINE→LANDING, counter 0):
//!   header | u64 unix_ts | [16] open_nonce | [32] E_pub
//!          | AEAD_open(user_id[16]) || [16] tag
//! every other type:
//!   header | AEAD_dir(plaintext) || [16] tag
//! ```
//!
//! The OPEN is the Handoff Noise_NK shape: an ephemeral X25519 share DH'd
//! against LANDING's static Handoff key, mixed with the Handoff pair PSK in
//! one HKDF-SHA256 chain under a label distinct from the TCP transfer
//! (`rust-reality/handoff-udp/v1`). The chain yields one OPEN key and one key
//! per direction. Data packets use ChaCha20-Poly1305 with a 96-bit nonce of
//! four zero bytes followed by the big-endian per-direction counter, and a
//! sliding replay window on receive. Retransmitted OPENs are byte-identical.
//!
//! Path MTU is discovered per session and per direction by padded,
//! authenticated PROBE packets ([`PmtuProber`], RFC 8899 style). Datagrams
//! larger than the current packetization limit are split into authenticated
//! FRAG packets and reassembled under strict bounds ([`Reassembler`]); the
//! channel never relies on IP fragmentation.

mod frag;
mod pmtu;
mod window;
mod wire;

pub use frag::{MAX_FRAGMENTS, Reassembler, ReassemblyLimits, split_fragments};
pub use pmtu::{
    BASE_PLPMTU, MAX_PLPMTU, MIN_PLPMTU, PmtuProbe, PmtuProber, PmtuTimers, plpmtu_from_ip_mtu,
};
pub use window::{REPLAY_WINDOW_BITS, ReplayWindow};
pub use wire::{
    FRAG_HEADER_LEN, HEADER_LEN, MAX_DATA_PLAINTEXT_LEN, MAX_UDP_PAYLOAD_LEN, OPEN_LEN, PacketType,
    SESSION_ID_LEN, TAG_LEN, UDP_PROTOCOL_VERSION, UdpChannel, UdpOpen, UdpPacketError,
    accept_open, decode_data, encode_data_plaintext, parse_header, seal_open,
};

#[cfg(test)]
mod tests;
