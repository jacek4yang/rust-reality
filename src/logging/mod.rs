//! Secret-free structured events and bounded log sinks.

mod sink;

pub use sink::{AdmissionResource, LogEvent, LogWriteError, Logger, RejectionReason};
