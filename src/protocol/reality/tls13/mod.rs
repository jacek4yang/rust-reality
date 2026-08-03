//! Minimal TLS 1.3 cryptographic state with explicit secret ownership.

mod application_io;
mod handshake;
mod handshake_read;
mod keys;
mod messages;
mod record;
mod record_read;
mod server_hello;
mod target_read;

pub use application_io::{
    ApplicationRecord, ApplicationWriteStats, TlsApplicationIo, TlsApplicationIoError,
    TlsApplicationReader, TlsApplicationWriter, bind_application_halves,
};
pub use handshake::{EstablishedTls, RealityHandshakeError, ServerFlight, build_server_flight};
pub use handshake_read::{ClientFinishedReadError, read_client_finished};
pub use keys::{
    ApplicationTrafficSecrets, CipherSuite, FinishedVerifyData, HashAlgorithm, Tls13KeySchedule,
    Tls13KeyScheduleError, TrafficKeys, TrafficSecret, TranscriptHash,
};
pub use messages::{
    CertificateIdentity, HandshakeMessageError, certificate_message, encrypted_extensions,
    finished_message,
};
pub use record::{
    ContentType, MAX_PLAINTEXT_LEN, OpenedRecord, Tls13RecordError, Tls13RecordLayer,
};
pub use record_read::{TlsRecordRead, TlsRecordReadError, TlsRecordReadErrorKind, read_tls_record};
pub use server_hello::{
    ServerHelloError, ServerHelloTemplate, change_cipher_spec_record, plaintext_handshake_record,
};
pub use target_read::{
    TargetServerHelloRead, TargetServerHelloReadError, TargetServerHelloReadErrorKind,
    read_target_server_hello,
};
