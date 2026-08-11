mod addons;
mod decode;
mod padding;
mod read;
mod response;
mod types;
mod validate;
mod vision;

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
pub use validate::{RequestValidationError, UserRegistry, authorize_authenticated_vision_tcp};
pub use vision::{
    VISION_FRAME_SIZE, VisionCommand, VisionDecodeError, VisionDecoder, VisionEncodeError,
    VisionEncoder, VisionFramePlan, VisionMode, VisionPayload,
};
