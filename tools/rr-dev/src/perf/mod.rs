//! Release performance evaluation.
//!
//! The typed replacement for `scripts/evaluate-release-performance.py`. Structure
//! follows the data rather than the original file layout:
//!
//! ```text
//! filesystem / CLI / JSON
//!         -> validated typed model
//!         -> pure evaluation functions      (stats, bootstrap)
//!         -> typed report
//!         -> text / JSON rendering
//! ```
//!
//! [`stats`] and [`bootstrap`] are pure: they read no files and spawn no
//! processes, which is what lets the gate's decisions be tested in isolation from
//! evidence plumbing.

pub mod bootstrap;
pub mod contract;
pub mod evaluator;
pub mod evidence;
pub mod json_out;
pub mod pairing;
pub mod stats;
