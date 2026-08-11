//! Minimal TLS 1.3 cryptographic state with explicit secret ownership.

#[cfg(test)]
mod allocation_gate;
mod application_io;
mod handshake;
mod handshake_read;
mod idle;
mod keys;
mod messages;
mod record;
mod record_read;
mod server_hello;
mod target_read;

pub(crate) use application_io::VectoredRead;
pub use application_io::{
    ApplicationRecord, ApplicationWriteStats, TlsApplicationIo, TlsApplicationIoError,
    TlsApplicationReader, TlsApplicationWriter, resume_application_halves,
};
pub(crate) use handshake::build_server_flight_with_shape;
pub use handshake::{
    EstablishedTls, ExportedTlsState, RealityHandshakeError, ServerFlight, build_server_flight,
};
pub use handshake_read::{ClientFinishedReadError, read_client_finished};
pub use idle::{IdleDeadline, IdleError};
pub use keys::{
    ApplicationTrafficSecrets, CipherSuite, FinishedVerifyData, HashAlgorithm, Tls13KeySchedule,
    Tls13KeyScheduleError, TrafficKeys, TrafficSecret, TranscriptHash,
};
pub use messages::{
    CertificateIdentity, HandshakeMessageError, certificate_message, encrypted_extensions,
    finished_message,
};
pub use record::{
    ContentType, ExportedRecordState, MAX_PLAINTEXT_LEN, OpenedRecord, Tls13RecordError,
    Tls13RecordLayer,
};
pub use record_read::{
    MAX_TLS_RECORD_WIRE_LEN, TlsRecordRead, TlsRecordReadError, TlsRecordReadErrorKind,
    read_tls_record, read_tls_record_into, record_storage,
};
pub(crate) use record_read::{MAX_TLS13_CIPHERTEXT_LEN, TLS_RECORD_HEADER_LEN, buffered_failure};
pub use server_hello::{
    ServerHelloError, ServerHelloTemplate, change_cipher_spec_record, plaintext_handshake_record,
};
pub(crate) use target_read::{
    CoverHandshakeRecordShape, TargetServerFlightRead, read_target_server_flight,
};
pub use target_read::{
    TargetServerHelloRead, TargetServerHelloReadError, TargetServerHelloReadErrorKind,
    read_target_server_hello,
};
