//! Local SOCKS5 / HTTP CONNECT client that dials authenticated REALITY LINEs.
//!
//! The client role terminates no public REALITY identity. It accepts loopback
//! SOCKS5 CONNECT, UDP ASSOCIATE (via XUDP), and/or HTTP CONNECT, opens a LINE
//! (REALITY → VLESS → Vision) selected before any destination request (ADR 0032),
//! and relays bytes. After a LINE is committed there is no mid-session migration
//! and no request replay onto another LINE.

mod http_inbound;
mod line;
mod selection;
mod serve;
mod session;
mod socks5_inbound;
mod vision_io;
mod xudp;

pub use line::{AuthenticatedLine, Line, LineError};
pub use selection::{LineGroup, LinePool, SelectionPolicy};
pub use serve::{ClientRuntimeError, run_client};
pub use session::VisionTunnel;
pub use xudp::XudpTunnel;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use vision_io::fuzz_vision_response;
