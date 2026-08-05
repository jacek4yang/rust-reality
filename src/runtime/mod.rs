//! Runtime task supervision.

mod admission;
mod fd_budget;
mod fd_plan;

pub use admission::{
    AdmissionDenied, AdmissionKind, AdmissionPermit, DirectBarrier, DirectPermit, ResourceGovernor,
};
pub use fd_budget::{
    FdBudget, FdPermit, FdPressure, UNITS_CONNECTOR_CANDIDATE, UNITS_INBOUND_SOCKET,
    UNITS_OUTBOUND_SOCKET, UNITS_SPLICE_DIRECTION, UNITS_SPLICE_RELAY, UNITS_URING_SESSION,
};
pub use fd_plan::{FdBudgetError, FdBudgetPlan, FixedFdReserve, MINIMUM_DYNAMIC_UNITS};
pub mod connection;
