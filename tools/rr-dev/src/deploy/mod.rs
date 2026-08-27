//! The deployment subsystem — typed deployment domain replacing the deploy scripts.
//!
//! The first migrated piece is the release-canary evaluator: a pure, fail-closed
//! function from a recorded canary report to a verdict, with no live-host
//! interaction. The remaining deployment stages (inspect/plan/canary-run/promote/
//! rollback) build on this evaluator and land later, so the safety-critical live
//! machinery is never migrated ahead of a tested evaluator.

pub mod canary;
