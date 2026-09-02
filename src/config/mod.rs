//! Strict JSON configuration: one current schema, parsed, validated, loaded.
//!
//! The pipeline is three steps with one type between each:
//!
//! ```text
//! bytes -> parse -> NodeConfig -> semantics -> ValidatedConfig
//! ```
//!
//! [`node`] owns the operator-facing model, [`parse`] the structural read,
//! [`semantics`] the cross-object rules, and [`mod@load`] the combination
//! every command uses. [`mod@format`] renders the inverse — the one canonical
//! form. The private `syntax` module holds the per-value rules the validator
//! applies, and `diagnostic` renders any failure against the source that
//! caused it.

mod diagnostic;
pub mod format;
pub mod load;
pub mod node;
pub mod parse;
mod secret;
pub mod semantics;
mod syntax;

pub use diagnostic::Diagnostic;
pub use format::canonical;
pub use load::{LoadError, load, load_bytes};
pub use node::{EntryConfig, LandingConfig, NodeConfig, Role};
pub use parse::{MAX_CONFIG_BYTES, ParseError};
pub use secret::SecretString;
pub use semantics::{SemanticError, ValidatedConfig};

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use load::fuzz_load;
