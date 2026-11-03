//! Secret-free structured events and bounded log sinks.

mod failure;
mod sink;

pub use failure::{FailureCause, FailureDetail, FailureStage};

pub use sink::{
    AdmissionResource, BackendStatus, HandoffUdpEndReason, LogEvent, LogWriteError, Logger,
    RejectionReason,
};
