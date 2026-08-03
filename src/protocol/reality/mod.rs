//! Bounded REALITY wire parsing and handshake state.

mod auth;
mod client_hello;
mod read;
mod replay;

pub use auth::{
    AuthKey, RealityAuthConfigError, RealityAuthError, RealityAuthResult, RealityAuthenticator,
};
pub use client_hello::{
    ClientHello, ClientHelloError, KeyShare, MAX_CLIENT_HELLO_BYTES, MLKEM768_ENCAP_KEY_LEN,
    SESSION_ID_LEN, SESSION_ID_OFFSET, X25519_GROUP, X25519_MLKEM768_GROUP,
    X25519_MLKEM768_SHARE_LEN,
};
pub use read::{
    ClientHelloRead, ClientHelloReadError, ClientHelloReadErrorKind, read_client_hello,
};
pub use replay::{ReplayCache, ReplayError, ReplayReservation};
