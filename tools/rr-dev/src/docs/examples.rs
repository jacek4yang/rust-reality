//! Holds every documented JSON example to the real parser.
//!
//! Documentation that shows a configuration is making a promise the reader
//! will test in about thirty seconds by pasting it into a file. Prose can go
//! stale quietly; a fenced example cannot be allowed to, because the reader
//! finds out by watching the server refuse to start.
//!
//! So every fenced block tagged `json` in `docs/` and both READMEs is
//! classified and checked here:
//!
//! - A **complete node configuration** must load through
//!   `rust_reality::config` — the same parse and the same validation
//!   `rust-reality check` performs — and it must already be byte-identical to
//!   `rust_reality::config::canonical`, so the page shows the form the
//!   project itself writes.
//! - A **fragment** is a section quoted on its own, or a sample of JSON this
//!   project *emits* rather than reads. It must still parse, which catches
//!   the trailing comma and the unbalanced brace.
//! - A block that parses as neither is a hard failure, with the advice to
//!   retag the fence if the text was never meant to be JSON.
//!
//! # Telling the three apart
//!
//! The classification has to be mechanical, and it is deliberately biased
//! toward *more* validation:
//!
//! 1. A block carrying a report key — `schemaVersion` from `explain --json`,
//!    or `configuration` from `doctor` — is output, not input. Those keys
//!    exist in no configuration, so if a report ever loses one the block
//!    stops being excluded and starts being validated as a configuration,
//!    which fails loudly rather than silently skipping.
//! 2. A block with fewer than [`FRAGMENT_KEY_LIMIT`] top-level keys is a
//!    teaching fragment — `{ "role": "entry" }` and the like.
//! 3. Everything else that declares `role` is a complete configuration.
//!
//! Rule 3 is what catches a page still showing a previous release's shape,
//! and rule 2 is bounded deliberately: an example large enough to look like a
//! real file is held to being one.
//!
//! The canonical check is deliberately byte-exact. Accepting "semantically
//! equal but formatted differently" would mean the documentation and the
//! `format` command disagree about what canonical means, and one of them
//! would be wrong.

use std::path::{Path, PathBuf};

use rust_reality::config::{canonical, load_bytes};

/// One fenced JSON block, with enough position to name it in a failure.
#[derive(Debug, Eq, PartialEq)]
pub struct Block {
    /// First line of the block's content, 1-indexed, as an editor counts.
    pub line: usize,
    /// The block's exact content, fences excluded.
    pub body: String,
}

/// Extracts every fenced block tagged `json` from Markdown.
///
/// Only the exact tag `json` is taken. A page that wants to show deliberately
/// incomplete JSON says so by tagging the fence something else, which is a
/// visible choice by the author rather than a silent exemption.
#[must_use]
pub fn json_blocks(markdown: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut open: Option<(usize, String)> = None;

    for (index, raw) in markdown.lines().enumerate() {
        let line = raw.trim_end();
        match &mut open {
            Some((_, body)) => {
                if line.trim_end() == "```" {
                    let (start, body) = open.take().expect("the block is open");
                    blocks.push(Block { line: start, body });
                } else {
                    body.push_str(raw);
                    body.push('\n');
                }
            }
            None => {
                if line == "```json" {
                    open = Some((index + 2, String::new()));
                }
            }
        }
    }

    blocks
}

/// What checking every documented example found.
///
/// The counts are reported even on success, because a check that silently
/// validates nothing is indistinguishable from a check that passes. If the
/// configurations count ever drops to zero, the documentation has stopped
/// showing configurations and the guard has stopped guarding.
#[derive(Debug, Default)]
pub struct Outcome {
    /// One entry per offending block.
    pub failures: Vec<String>,
    /// Complete node configurations parsed, validated, and found canonical.
    pub configurations: usize,
    /// Blocks that parse as JSON but declare no role.
    pub fragments: usize,
}

/// Checks every documented example under `repo`.
#[must_use]
pub fn check(repo: &Path, files: &[PathBuf]) -> Outcome {
    let mut outcome = Outcome::default();

    for path in files {
        let Ok(markdown) = std::fs::read_to_string(path) else {
            continue;
        };
        let relative = path.strip_prefix(repo).unwrap_or(path).display().to_string();

        for block in json_blocks(&markdown) {
            let complete = serde_json::from_str::<serde_json::Value>(&block.body)
                .is_ok_and(|value| is_configuration(&value));
            match check_block(&relative, block.line, &block.body) {
                Some(failure) => outcome.failures.push(failure),
                None if complete => outcome.configurations += 1,
                None => outcome.fragments += 1,
            }
        }
    }

    outcome
}

/// Top-level key count below which a role-declaring block is a fragment.
///
/// Four is the smallest complete configuration's key count minus one: every
/// role requires `role` and `listeners` plus at least two more, so nothing
/// deployable can sit under this and be mistaken for a teaching snippet.
const FRAGMENT_KEY_LIMIT: usize = 4;

/// Top-level keys that only appear in JSON this project *emits*.
const REPORT_KEYS: [&str; 2] = ["schemaVersion", "configuration"];

/// Checks one block, returning at most one failure.
fn check_block(path: &str, line: usize, body: &str) -> Option<String> {
    let at = format!("{path}:{line}");
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Some(format!(
            "{at}: fenced as a JSON block but does not parse as JSON. Fix it, \
             or retag the fence if it was never meant to be a JSON document."
        ));
    };

    if !is_configuration(&value) {
        return None;
    }

    // The diagnostic renders its own `path:line:column` against the block, so
    // the file is named here and the block's own coordinates come from it.
    let config = match load_bytes(Path::new(path), body.as_bytes()) {
        Ok(config) => config,
        Err(error) => {
            return Some(format!(
                "{at}: this example is a complete configuration, and it does \
                 not validate. Line numbers below are within the block.\n{error}"
            ));
        }
    };

    let expected = canonical(&config);
    if expected == body {
        return None;
    }

    Some(format!(
        "{at}: valid, but not in the canonical form the page should show. \
         `rust-reality format` would rewrite it{}.",
        first_difference(body, &expected)
            .map(|line| format!(" starting at line {line} of the block"))
            .unwrap_or_default()
    ))
}

/// Whether a parsed block is a complete node configuration.
fn is_configuration(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if REPORT_KEYS.iter().any(|key| object.contains_key(*key)) {
        return false;
    }
    object.contains_key("role") && object.len() >= FRAGMENT_KEY_LIMIT
}

/// The 1-indexed line within the block where the two renderings first differ.
fn first_difference(documented: &str, canonical: &str) -> Option<usize> {
    documented
        .lines()
        .zip(canonical.lines())
        .position(|(left, right)| left != right)
        .map(|index| index + 1)
        .or_else(|| {
            (documented.lines().count() != canonical.lines().count())
                .then(|| documented.lines().count().min(canonical.lines().count()) + 1)
        })
}

#[cfg(test)]
mod tests {
    use super::{Block, check_block, is_configuration, json_blocks};

    /// A complete, valid, canonical entry node, exactly as a page would show
    /// it. Written out rather than generated: this fixture is what proves the
    /// checker accepts a correct example, so it must not depend on the
    /// checker's own idea of correct.
    const CANONICAL_ENTRY: &str = r#"{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ]
    }
  ],
  "routing": {
    "default": "direct"
  }
}
"#;

    #[test]
    fn blocks_are_extracted_with_the_line_their_content_starts_on() {
        let markdown = "# Title\n\nProse.\n\n```json\n{ \"a\": 1 }\n```\n\nMore.\n";

        assert_eq!(
            json_blocks(markdown),
            vec![Block {
                line: 6,
                body: "{ \"a\": 1 }\n".to_owned(),
            }]
        );
    }

    #[test]
    fn only_an_exact_json_tag_is_taken() {
        // `jsonc`, `json5`, and untagged fences are how a page says "this is
        // not a JSON document". Taking them would make the escape hatch
        // useless, and taking an untagged fence would swallow every shell
        // transcript in the documentation.
        for fence in ["```jsonc", "```json5", "```", "```text", "```json title=x"] {
            let markdown = format!("{fence}\nnot json at all,\n```\n");
            assert!(
                json_blocks(&markdown).is_empty(),
                "{fence} must not be taken as a JSON example"
            );
        }
    }

    #[test]
    fn several_blocks_in_one_page_are_all_found() {
        let markdown = "```json\n1\n```\ntext\n```json\n2\n```\n";

        let blocks = json_blocks(markdown);

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].line, 2);
        assert_eq!(blocks[1].line, 6);
    }

    #[test]
    fn a_canonical_configuration_passes() {
        assert_eq!(check_block("page.md", 1, CANONICAL_ENTRY), None);
    }

    #[test]
    fn a_fragment_only_has_to_parse() {
        // A page quoting one section cannot be a whole configuration, and
        // demanding one would make sections undocumentable.
        assert_eq!(
            check_block("page.md", 1, "{ \"routing\": { \"default\": \"direct\" } }"),
            None
        );
    }

    #[test]
    fn a_block_that_is_not_json_is_reported_with_the_retag_advice() {
        let failure = check_block("page.md", 12, "{ \"a\": 1, }\n").expect("must fail");

        assert!(failure.starts_with("page.md:12: fenced as a JSON block"));
        assert!(
            failure.contains("retag the fence"),
            "the author needs to know the escape hatch exists: {failure}"
        );
    }

    #[test]
    fn a_configuration_that_does_not_validate_carries_the_real_diagnostic() {
        let broken = CANONICAL_ENTRY.replace(r#""default": "direct""#, r#""default": "nowhere""#);

        let failure = check_block("page.md", 1, &broken).expect("must fail");

        assert!(
            failure.contains("routing.default"),
            "the operator-facing diagnostic must survive into the failure: {failure}"
        );
    }

    #[test]
    fn output_samples_are_not_mistaken_for_configurations() {
        // `doctor` and `explain --json` both report a role, and `explain`
        // reports listeners too. Pages show them, and validating them as
        // input would be nonsense.
        for report in [
            r#"{ "configuration": "ok", "role": "entry", "routing": "ok", "cover": [] }"#,
            r#"{ "schemaVersion": 3, "role": "entry", "listeners": [], "routing": {} }"#,
        ] {
            let value: serde_json::Value = serde_json::from_str(report).expect("fixture parses");
            assert!(!is_configuration(&value), "must be a report: {report}");
            assert_eq!(check_block("page.md", 1, report), None);
        }
    }

    #[test]
    fn a_small_role_declaring_fragment_is_a_fragment() {
        // Pages introduce `role` on its own. Demanding a whole file there
        // would make the field undocumentable.
        assert_eq!(check_block("page.md", 1, r#"{ "role": "entry" }"#), None);
    }

    #[test]
    fn a_configuration_sized_block_is_held_to_being_one() {
        // Four top-level keys is enough to look like a real file, so a real
        // file missing required fields is caught rather than waved through.
        let incomplete = r#"{ "role": "entry", "reality": {}, "users": [], "routing": {} }"#;

        let failure = check_block("page.md", 1, incomplete).expect("must fail");

        assert!(
            failure.contains("complete configuration"),
            "the author needs to know why it was held to that standard: {failure}"
        );
        assert!(failure.contains("missing required field"), "{failure}");
    }

    #[test]
    fn a_previous_release_example_is_caught_as_an_invalid_configuration() {
        // The class this check exists for: a page still showing v1.8 shapes.
        // It parses as JSON, so only the real validator can catch it — and it
        // is caught only because it declares a role.
        let stale = r#"{
  "role": "entry",
  "inbounds": [{ "protocol": "vless", "port": 443 }],
  "outbounds": [{ "protocol": "direct", "tag": "direct" }],
  "routing": { "domainStrategy": "IPIfNonMatch" }
}
"#;

        let failure = check_block("docs/en/configuration.md", 40, stale).expect("must fail");

        assert!(failure.contains("inbounds"), "{failure}");
    }

    #[test]
    fn a_valid_but_uncanonical_example_names_the_line_that_differs() {
        // Two spaces of indent is what a hand-written example looks like
        // before anyone runs `format` on it.
        let compact = CANONICAL_ENTRY.replace(
            "  \"routing\": {\n    \"default\": \"direct\"\n  }",
            "  \"routing\": { \"default\": \"direct\" }",
        );

        let failure = check_block("page.md", 1, &compact).expect("must fail");

        assert!(failure.contains("canonical form"), "{failure}");
        assert!(
            failure.contains("starting at line"),
            "an author fixing this needs to know where to look: {failure}"
        );
    }

    #[test]
    fn the_canonical_form_the_checker_demands_is_the_one_format_writes() {
        // The whole point of calling the production crate rather than
        // reimplementing a formatter: these cannot drift.
        let config = rust_reality::config::load_bytes(
            std::path::Path::new("fixture.json"),
            CANONICAL_ENTRY.as_bytes(),
        )
        .expect("the fixture must load");

        assert_eq!(rust_reality::config::canonical(&config), CANONICAL_ENTRY);
    }
}
