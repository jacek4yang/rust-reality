//! The canonical rendering of a configuration: the other half of loading.
//!
//! One function, because there is one canonical form. `rust-reality format`
//! writes it, the formatter's contract tests assert it, and `cargo dev docs
//! check` holds every documented example to it. If those three had their own
//! renderers, the documentation could drift from the binary while every test
//! still passed.

use crate::config::ValidatedConfig;

/// Renders a validated configuration in the canonical form.
///
/// Three properties, all of which the loader's contract tests pin:
///
/// - **Semantics-preserving.** The rendering goes through the typed model, so
///   it cannot emit a shape the parser would reject, and reparsing it yields
///   an equal configuration.
/// - **Nothing added, nothing dropped.** A field the operator wrote survives
///   even when it equals its default, because a written value is a decision
///   worth keeping visible. A field they omitted stays omitted — expanding
///   defaults is exactly the noise the command exists to avoid.
/// - **Declaration order.** Keys follow the order the model declares them,
///   which is the order the reference documents them. This is the property
///   `jq` cannot supply: it preserves arbitrary input order, and `jq -S`
///   sorts alphabetically, which scatters related fields apart.
///
/// # Panics
///
/// Panics only if the model itself cannot serialise, which would be a bug in
/// this crate rather than anything an operator can cause: every value reached
/// here already parsed from JSON and passed validation.
#[must_use]
pub fn canonical(config: &ValidatedConfig) -> String {
    let mut rendered = serde_json::to_string_pretty(config.node())
        .expect("a validated configuration is always serialisable");
    rendered.push('\n');
    rendered
}
