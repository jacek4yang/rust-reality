//! Secret-free structured events and bounded log sinks.

mod sink;

pub use sink::{
    AdmissionResource, BackendStatus, LogEvent, LogWriteError, Logger, RejectionReason,
};
