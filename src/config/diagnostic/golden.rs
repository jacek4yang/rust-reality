//! Deterministic golden tests for the exact rendered diagnostics.
//!
//! Every expectation is the complete rendered block, so a rendering change is
//! a deliberate, reviewable event rather than something that drifts. Fixtures
//! are small hand-written documents with stable line positions; each one is
//! the shortest configuration that reaches the failure it is named for.

use std::path::Path;

use crate::config::{LoadError, load_bytes, node::fixture};

/// Loads `json` and returns the rendered diagnostic of the failure.
fn render_error(json: &str) -> String {
    render_error_at("config.json", json)
}

fn render_error_at(path: &str, json: &str) -> String {
    let error = load_bytes(Path::new(path), json.as_bytes()).expect_err("the fixture must fail");
    let rendered = error.to_string();
    assert!(
        !rendered.contains('\u{1b}'),
        "rendered diagnostics must stay plain text: {rendered:?}"
    );
    rendered
}

/// The minimal entry node, laid out one field per line so spans are stable.
const ENTRY: &str = r#"{
  "role": "entry",
  "listeners": [{ "port": 443 }],
  "reality": {
    "cover": "www.example.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    { "id": "11111111-1111-4111-8111-111111111111", "shortIds": ["0123456789abcdef"] }
  ],
  "routing": { "default": "direct" }
}"#;

/// Returns `ENTRY` with `find` replaced by `replace`.
fn entry_with(find: &str, replace: &str) -> String {
    assert!(ENTRY.contains(find), "fixture anchor `{find}` must exist");
    ENTRY.replace(find, replace)
}

#[test]
fn the_minimal_fixture_is_valid() {
    load_bytes(Path::new("config.json"), ENTRY.as_bytes())
        .expect("the golden fixture must itself be a valid configuration");
    load_bytes(Path::new("config.json"), fixture::entry_json().as_bytes())
        .expect("the shared fixture must be valid");
    load_bytes(Path::new("config.json"), fixture::landing_json().as_bytes())
        .expect("the shared landing fixture must be valid");
}

#[test]
fn golden_unknown_field() {
    let rendered = render_error(&entry_with(
        r#"  "routing": { "default": "direct" }"#,
        "  \"routing\": { \"default\": \"direct\" },\n  \"nonsense\": {}",
    ));

    assert!(
        rendered.starts_with("error: unknown field `nonsense`"),
        "{rendered}"
    );
    assert!(rendered.contains("config.json:12:3"), "{rendered}");
    assert!(rendered.contains("unknown field"), "{rendered}");
    assert!(
        rendered.contains("expected"),
        "the alternatives must be listed: {rendered}"
    );
}

/// A section this release removed gets a targeted error naming its
/// replacement, which is the one thing `AGENTS.md` §9 permits a removed name
/// to do.
#[test]
fn golden_removed_section() {
    let rendered = render_error(&entry_with(
        r#"  "routing": { "default": "direct" }"#,
        "  \"routing\": { \"default\": \"direct\" },\n  \"advanced\": {}",
    ));

    assert!(
        rendered.starts_with("error: field `advanced` was removed in v1.9"),
        "{rendered}"
    );
    assert!(rendered.contains("runtime.limits"), "{rendered}");
    assert!(rendered.contains("config.json:12:3"), "{rendered}");
}

#[test]
fn golden_unknown_field_suggests_a_near_miss() {
    let rendered = render_error(&entry_with(r#""listeners":"#, r#""listener":"#));

    assert!(rendered.contains("unknown field `listener`"), "{rendered}");
    assert!(
        rendered.contains("did you mean") && rendered.contains("listeners"),
        "a one-character typo must be suggested: {rendered}"
    );
}

#[test]
fn golden_missing_required_field() {
    let rendered = render_error(
        r#"{
  "role": "entry",
  "listeners": [{ "port": 443 }],
  "users": [],
  "routing": { "default": "direct" }
}"#,
    );

    assert!(
        rendered.starts_with("error: missing required field `reality`"),
        "{rendered}"
    );
    assert!(rendered.contains("config.json:"), "{rendered}");
}

#[test]
fn golden_missing_role_names_the_field_that_decides_the_shape() {
    let rendered = render_error(r#"{ "listeners": [{ "port": 443 }] }"#);

    assert!(rendered.contains("`role`"), "{rendered}");
    assert!(rendered.contains("missing"), "{rendered}");
}

#[test]
fn golden_unknown_role_lists_the_roles_that_exist() {
    let rendered = render_error(r#"{ "role": "line", "listeners": [] }"#);

    assert!(rendered.contains("entry"), "{rendered}");
    assert!(rendered.contains("landing"), "{rendered}");
    assert!(
        !rendered.contains("vless"),
        "removed vocabulary must not be offered: {rendered}"
    );
}

#[test]
fn golden_unknown_enum_value() {
    let rendered = render_error(&entry_with(
        r#"[{ "port": 443 }]"#,
        r#"[{ "port": 443, "ip": "ipv4" }]"#,
    ));

    assert!(rendered.contains("config.json:3:"), "{rendered}");
    assert!(
        rendered.contains("ipv4Only") && rendered.contains("dualStack"),
        "the accepted families must be listed: {rendered}"
    );
}

#[test]
fn golden_invalid_type() {
    let rendered = render_error(&entry_with(
        r#""listeners": [{ "port": 443 }]"#,
        r#""listeners": 443"#,
    ));

    assert!(rendered.starts_with("error: invalid type"), "{rendered}");
    assert!(rendered.contains("config.json:3:"), "{rendered}");
}

#[test]
fn golden_duplicate_field() {
    let rendered = render_error(&entry_with(
        r#"  "routing": { "default": "direct" }"#,
        "  \"routing\": { \"default\": \"direct\" },\n  \"routing\": { \"default\": \"block\" }",
    ));

    assert!(
        rendered.starts_with("error: duplicate field `routing`"),
        "{rendered}"
    );
    assert!(rendered.contains("defined more than once"), "{rendered}");
    assert!(rendered.contains("remove one"), "{rendered}");
}

#[test]
fn golden_duplicate_outbound_name() {
    let rendered = render_error(&entry_with(
        r#"  "routing": { "default": "direct" }"#,
        r#"  "outbounds": {
    "up": { "type": "nxr", "address": "10.0.0.2", "port": 7443,
            "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI" },
    "up": { "type": "nxr", "address": "10.0.0.3", "port": 7443,
            "psk": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM" }
  },
  "routing": { "default": "up" }"#,
    ));

    assert!(rendered.contains("duplicate name `up`"), "{rendered}");
    assert!(
        rendered.contains("rename one of them"),
        "the remedy must be stated: {rendered}"
    );
}

#[test]
fn golden_malformed_json() {
    let rendered = render_error(
        r#"{
  "role": "entry",
}"#,
    );

    assert!(rendered.starts_with("error: "), "{rendered}");
    assert!(rendered.contains("config.json:3:"), "{rendered}");
}

#[test]
fn golden_semantic_failure_points_at_the_offending_value() {
    let rendered = render_error(&entry_with(
        r#""default": "direct""#,
        r#""default": "nowhere""#,
    ));

    assert!(
        rendered.starts_with("error: invalid value for `routing.default`"),
        "{rendered}"
    );
    assert!(rendered.contains("config.json:11:"), "{rendered}");
    assert!(
        rendered.contains("nowhere"),
        "the excerpt must show what was written: {rendered}"
    );
    assert!(
        rendered.contains("direct") && rendered.contains("block"),
        "the known outbounds must be listed: {rendered}"
    );
}

#[test]
fn golden_secret_values_are_redacted_in_every_excerpt() {
    let secret = "ERERERERERERERERERERERERERERERERERERERERERE";
    // The failure is on the key's own line, so the excerpt underlines the
    // secret itself: exactly the case redaction exists for.
    let rendered = render_error(&entry_with(
        r#"    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE""#,
        r#"    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE", "nope": 1"#,
    ));

    assert!(
        !rendered.contains(secret),
        "key material must never reach a rendered diagnostic: {rendered}"
    );
    assert!(rendered.contains("REDACTED"), "{rendered}");
}

#[test]
fn golden_short_ids_are_redacted() {
    let rendered = render_error(&entry_with(
        r#""shortIds": ["0123456789abcdef"]"#,
        r#""shortIds": ["0123456789abcdef"], "policy": 7"#,
    ));

    assert!(
        !rendered.contains("0123456789abcdef"),
        "short IDs authenticate a user and must be redacted: {rendered}"
    );
}

#[test]
fn golden_landing_rejects_an_entry_section() {
    let rendered = render_error(
        r#"{
  "role": "landing",
  "listeners": [{ "port": 7443 }],
  "landing": { "protocol": "nxr", "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI" },
  "routing": { "default": "direct" }
}"#,
    );

    assert!(rendered.contains("unknown field `routing`"), "{rendered}");
    assert!(rendered.contains("config.json:5:3"), "{rendered}");
}

#[test]
fn golden_landing_protocol_variant_refines_the_path() {
    let rendered = render_error(
        r#"{
  "role": "landing",
  "listeners": [{ "port": 7443 }],
  "landing": {
    "protocol": "nxr",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
    "privateKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
  }
}"#,
    );

    assert!(
        rendered.contains("unknown field `privateKey`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("config.json:7:"),
        "the variant's own field must be located: {rendered}"
    );
}

#[test]
fn golden_outbound_variant_refines_the_path() {
    let rendered = render_error(&entry_with(
        r#"  "routing": { "default": "direct" }"#,
        r#"  "outbounds": {
    "up": {
      "type": "socks5",
      "address": "10.0.0.9",
      "port": 1080,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    }
  },
  "routing": { "default": "up" }"#,
    ));

    assert!(rendered.contains("unknown field `psk`"), "{rendered}");
    assert!(
        rendered.contains("config.json:16:"),
        "the offending line inside the variant must be located: {rendered}"
    );
}

#[test]
fn golden_reports_the_configured_path() {
    let rendered = render_error_at(
        "/etc/rust-reality/config.json",
        &entry_with(r#""role": "entry""#, r#""role": "entry", "nope": 1"#),
    );

    assert!(
        rendered.contains("/etc/rust-reality/config.json:2:"),
        "{rendered}"
    );
}

#[test]
fn a_missing_file_has_no_excerpt() {
    let error = crate::config::load(Path::new("/nonexistent/rust-reality/config.json"))
        .expect_err("a missing file must fail");

    assert!(matches!(error, LoadError::Parse(_)));
    assert!(error.diagnostic().is_none());
}
