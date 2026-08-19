//! Runtime task supervision.

mod admission;
mod ceiling;
mod fd_budget;
mod fd_plan;
mod pressure;

pub use admission::{
    AdmissionDenied, AdmissionKind, AdmissionPermit, DirectBarrier, DirectPermit, ResourceGovernor,
};
pub use fd_budget::{
    FdBudget, FdPermit, FdPressure, UNITS_INBOUND_SOCKET, UNITS_OUTBOUND_SOCKET,
    UNITS_SPLICE_DIRECTION, UNITS_SPLICE_RELAY,
};
pub use fd_plan::{
    FdBudgetError, FdBudgetPlan, FdHeadroomPolicy, FixedFdReserve, MINIMUM_DYNAMIC_UNITS,
};
pub use pressure::{PressureGauge, ResourcePressure};
pub mod connection;
pub mod machine;
