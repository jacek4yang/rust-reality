//! VLESS protocol codec: request header decode and read, client-side wire
//! operations, addons, response header encode and write, authenticated Vision
//! field validation, Vision padding, and XUDP framing.
//!
//! This module declares the submodules and re-exports their public surface;
//! the only items defined here are feature-gated fuzzing entry points.

mod addons;
mod client;
mod decode;
mod padding;
mod read;
mod response;
mod types;
mod validate;
mod vision;
mod xudp;

pub use addons::{Addons, AddonsDecodeError, VISION_FLOW};
pub(crate) use decode::decode_request_ref;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use decode::fuzz_decode_request_ref;
pub use decode::{DecodeError, DecodeRequest, decode_request};
pub use padding::{EntropyUnavailable, PaddingRng};
pub use read::{ReadError, ReadRequest, read_request};
pub use response::{
    ResponseEncodeError, ResponseWriteError, encode_response_header, write_response_header,
};
pub use types::{Address, Command, Destination, RequestHeader, UserId, VERSION};
pub(crate) use validate::validate_authenticated_vision_fields;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_validate_short_id_owner(
    request_user_id: UserId,
    authenticated_user_id: UserId,
) -> Result<(), RequestValidationError> {
    validate_authenticated_vision_fields(
        request_user_id,
        &[],
        Command::Tcp,
        true,
        authenticated_user_id,
    )
}
pub use validate::{
    RequestValidationError, UserRegistry, authorize_authenticated_vision_tcp,
    authorize_authenticated_vision_xudp,
};
pub use vision::{
    VISION_FRAME_SIZE, VisionCommand, VisionDecodeError, VisionDecoder, VisionEncodeError,
    VisionEncoder, VisionFramePlan, VisionMode, VisionPayload,
};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use xudp::fuzz_decode_xudp_packet;
pub use xudp::{
    VISION_FLOW_UDP443, XRAY_BUF_SIZE, XUDP_MAX_META_LEN, XUDP_MAX_PAYLOAD_LEN, XUDP_MUX_HOST,
    XUDP_MUX_PORT, XudpCodecError, XudpGlobalId, XudpNetwork, XudpOption, XudpPacket,
    XudpSessionStatus, config_flow_allows_udp_443, decode_xudp_packet, encode_xudp_packet,
    frame_looks_like_xudp, is_xudp_mux_command, meta_body_is_xudp, vision_udp_command_allows_port,
    wire_vision_flow_from_config,
};

pub use client::{
    DecodeResponse, RequestEncodeError, ResponseDecodeError, decode_response,
    encode_vision_tcp_request, encode_vision_xudp_request,
};
