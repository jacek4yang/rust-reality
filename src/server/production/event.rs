//! The one place this subsystem writes to a log.
//!
//! Every emitter here is infallible from the caller's point of view: a sink
//! that cannot accept an event must never turn into a connection failure or a
//! failed reload. The debug emitter additionally refuses to *construct* an
//! event the sink would discard, which is what keeps per-connection evidence
//! free when debug is off.

use std::io::{self, Write as _};

use crate::{
    logging::{AdmissionResource, BackendStatus, LogEvent, Logger},
    runtime::{AdmissionDenied, AdmissionKind},
    transport::{BackendDeclineReason, BackendReport},
};

use super::{error::RuntimeUpdateError, store::RuntimeStore};

pub(super) fn emit(logger: &Logger, event: &LogEvent) {
    let _ignored = logger.emit(event);
}

/// Emits one debug-only event, constructing it only when debug evidence can
/// actually reach the configured sink.
///
/// Per-connection callers stay at zero cost when debug is disabled: no stats
/// accessors run and no event is allocated, whereas the warn-level rejections
/// stay eager because they are operator signal.
pub(super) fn emit_debug(logger: &Logger, event: impl FnOnce() -> LogEvent) {
    if logger.debug_enabled() {
        emit(logger, &event());
    }
}

pub(super) fn emit_rejected(
    runtime: &RuntimeStore,
    field: &'static str,
    error: Option<&RuntimeUpdateError>,
) {
    emit(
        &runtime.load().logger,
        &LogEvent::ConfigurationRejected {
            field: field.to_owned(),
        },
    );
    // The structured event stays a closed shape (a stable path, never
    // configuration content); the full compiler-style diagnostic goes to
    // stderr instead, where systemd captures it into the journal and an
    // interactive operator sees it directly.
    if let Some(error) = error {
        let _ignored = writeln!(
            io::stderr().lock(),
            "configuration {field} reload rejected:\n{error}"
        );
    }
}

pub(super) fn emit_admission(logger: &Logger, error: AdmissionDenied) {
    let resource = match error {
        AdmissionDenied::Limit(AdmissionKind::Connection)
        | AdmissionDenied::Pressure(AdmissionKind::Connection) => AdmissionResource::Connections,
        AdmissionDenied::Limit(AdmissionKind::PreAuthIdle)
        | AdmissionDenied::Pressure(AdmissionKind::PreAuthIdle) => {
            AdmissionResource::PreAuthIdleConnections
        }
        AdmissionDenied::Limit(AdmissionKind::Handshake)
        | AdmissionDenied::Pressure(AdmissionKind::Handshake) => AdmissionResource::Handshakes,
        AdmissionDenied::Limit(AdmissionKind::Fallback)
        | AdmissionDenied::Pressure(AdmissionKind::Fallback) => AdmissionResource::Fallbacks,
        AdmissionDenied::Limit(AdmissionKind::CryptoOperation)
        | AdmissionDenied::Pressure(AdmissionKind::CryptoOperation) => {
            AdmissionResource::CryptoOperations
        }
        AdmissionDenied::Limit(AdmissionKind::ReplayEntry)
        | AdmissionDenied::Pressure(AdmissionKind::ReplayEntry) => AdmissionResource::ReplayEntries,
        AdmissionDenied::Limit(AdmissionKind::DnsLookup)
        | AdmissionDenied::Pressure(AdmissionKind::DnsLookup) => AdmissionResource::Handshakes,
        AdmissionDenied::DirectConcurrency
        | AdmissionDenied::DirectRate
        | AdmissionDenied::DirectPressure => AdmissionResource::DirectConnections,
        AdmissionDenied::Unavailable => AdmissionResource::Connections,
    };
    emit(logger, &LogEvent::AdmissionLimited { resource });
}

/// Renders one stable capability line per backend for the startup report.
///
/// Static declines are emitted here exactly once. Nothing in this function can
/// fail, so an unavailable backend is reported rather than turned into a
/// startup error: a kernel without `splice` is a slower host, not a broken one.
pub(super) fn backend_statuses(report: &BackendReport) -> Vec<BackendStatus> {
    report
        .entries()
        .into_iter()
        .map(|(backend, capability)| BackendStatus {
            backend: backend.as_str(),
            available: capability.available,
            decline_reason: capability.decline_reason.map(BackendDeclineReason::as_str),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::config::node::log::{LogConfig, LogLevel, LogOutput};

    #[test]
    fn disabled_debug_skips_event_construction() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use crate::logging::{LogEvent, Logger};

        let constructed = AtomicU64::new(0);
        let attempt = |logger: &Logger| {
            super::emit_debug(logger, || {
                constructed.fetch_add(1, Ordering::Relaxed);
                LogEvent::ConnectionAccepted {
                    peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001)),
                }
            });
        };

        let info_logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Info),
            output: Some(LogOutput::Stderr),
            file: None,
        })
        .expect("stderr logger must initialize");
        attempt(&info_logger);
        assert_eq!(
            constructed.load(Ordering::Relaxed),
            0,
            "a disabled level must not even construct the event"
        );

        let none_logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Debug),
            output: Some(LogOutput::None),
            file: None,
        })
        .expect("none logger must initialize");
        attempt(&none_logger);
        assert_eq!(
            constructed.load(Ordering::Relaxed),
            0,
            "a none sink must report debug as disabled and skip construction"
        );

        let debug_logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Debug),
            output: Some(LogOutput::Stderr),
            file: None,
        })
        .expect("stderr logger must initialize");
        attempt(&debug_logger);
        assert_eq!(
            constructed.load(Ordering::Relaxed),
            1,
            "an enabled debug level must construct exactly one event"
        );
    }
}
