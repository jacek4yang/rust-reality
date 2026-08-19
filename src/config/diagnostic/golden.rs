//! Deterministic golden tests for the exact rendered diagnostics.
//!
//! Every expectation is the complete rendered block; a rendering change is a
//! deliberate, reviewable event. Fixtures are small hand-written documents so
//! positions stay stable.

use std::path::Path;

use crate::config::test_config_json;
use crate::config::{ConfigLoadError, load_config};

/// Decodes `json` and returns the rendered diagnostic of the failure.
fn render_error(json: &str) -> String {
    render_error_at("config.json", json)
}

fn render_error_at(path: &str, json: &str) -> String {
    let error = crate::config::io::decode_config(Path::new(path), json.as_bytes())
        .expect_err("the fixture must fail");
    let rendered = error.to_string();
    assert!(
        !rendered.contains('\u{1b}'),
        "rendered diagnostics must stay plain text: {rendered:?}"
    );
    rendered
}

fn tweak(fixture: &serde_json::Value, path: &[&str], value: serde_json::Value) -> String {
    fn set(target: &mut serde_json::Value, path: &[&str], value: serde_json::Value) {
        if path.len() == 1 {
            if let Ok(index) = path[0].parse::<usize>() {
                target[index] = value;
            } else {
                target[path[0]] = value;
            }
            return;
        }
        if let Ok(index) = path[0].parse::<usize>() {
            set(&mut target[index], &path[1..], value);
        } else {
            set(&mut target[path[0]], &path[1..], value);
        }
    }
    let mut fixture = fixture.clone();
    set(&mut fixture, path, value);
    serde_json::to_string_pretty(&fixture).expect("fixture must encode")
}

fn base() -> serde_json::Value {
    serde_json::from_str(test_config_json()).expect("base fixture must parse")
}

#[test]
fn golden_syntax_error() {
    let rendered = render_error("{\n  \"inbounds\": @\n}\n");
    assert_eq!(
        rendered,
        concat!(
            "error: expected a JSON value\n",
            " --> config.json:2:15\n",
            "  |\n",
            "2 |   \"inbounds\": @\n",
            "  |               ^"
        )
    );
}

#[test]
fn golden_missing_comma() {
    let rendered = render_error(
        "{\n  \"inbounds\": []\n  \"outbounds\": [],\n  \"routing\": { \"users\": [] }\n}\n",
    );
    assert_eq!(
        rendered,
        concat!(
            "error: expected `,` or `}`\n",
            " --> config.json:3:3\n",
            "  |\n",
            "3 |   \"outbounds\": [],\n",
            "  |   ^"
        )
    );
}

#[test]
fn golden_unexpected_eof() {
    let rendered = render_error("{\n  \"inbounds\": [],\n  \"routing\": { \"users\": [");
    assert_eq!(
        rendered,
        concat!(
            "error: unexpected end of input\n",
            " --> config.json:3:25\n",
            "  |\n",
            "3 |   \"routing\": { \"users\": [\n",
            "  |                         ^\n",
            "  |\n",
            "  = help: the JSON document is incomplete"
        )
    );
}

#[test]
fn golden_unknown_field() {
    let rendered = render_error(&tweak(&base(), &["metrics"], serde_json::json!({})));
    assert_eq!(
        rendered,
        concat!(
            "error: unknown field `metrics`\n",
            "  --> config.json:55:3\n",
            "   |\n",
            "55 |   \"metrics\": {},\n",
            "   |   ^^^^^^^^^ unknown field\n",
            "   |\n",
            "   = expected: \"log\", \"assets\", \"dns\", \"network\", \"inbounds\", \"outbounds\", \"routing\", \"advanced\", or \"runtime\""
        )
    );
}

#[test]
fn golden_strong_typo_suggestion() {
    let rendered = render_error(&tweak(
        &base(),
        &["runtime"],
        serde_json::json!({ "profiel": "shared" }),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: unknown field `profiel`\n",
            "  --> config.json:98:5\n",
            "   |\n",
            "98 |     \"profiel\": \"shared\"\n",
            "   |     ^^^^^^^^^ unknown field\n",
            "   |\n",
            "   = expected: \"profile\", \"tuning\", or \"statusFile\"\n",
            "   = help: did you mean `profile`?"
        )
    );
}

#[test]
fn golden_weak_typo_has_no_suggestion() {
    let rendered = render_error(&tweak(
        &base(),
        &["runtime"],
        serde_json::json!({ "profeil": "shared" }),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: unknown field `profeil`\n",
            "  --> config.json:98:5\n",
            "   |\n",
            "98 |     \"profeil\": \"shared\"\n",
            "   |     ^^^^^^^^^ unknown field\n",
            "   |\n",
            "   = expected: \"profile\", \"tuning\", or \"statusFile\""
        )
    );
}

#[test]
fn golden_wrong_primitive_type() {
    let rendered = render_error(&tweak(
        &base(),
        &["inbounds", "0", "port"],
        serde_json::json!("443"),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: invalid type for `inbounds[0].port`\n",
            "  --> config.json:21:15\n",
            "   |\n",
            "21 |       \"port\": \"443\",\n",
            "   |               ^^^^^ expected u16\n",
            "   |\n",
            "   = actual value: \"443\""
        )
    );
}

#[test]
fn golden_invalid_enum() {
    let rendered = render_error(&tweak(
        &base(),
        &["runtime"],
        serde_json::json!({ "profile": "server" }),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: invalid value for `runtime.profile`\n",
            "  --> config.json:98:16\n",
            "   |\n",
            "98 |     \"profile\": \"server\"\n",
            "   |                ^^^^^^^^ expected \"auto\", \"shared\", or \"dedicated\"\n",
            "   |\n",
            "   = actual value: \"server\"\n",
            "   = help: use \"dedicated\" only when this process owns the bounded host or cgroup"
        )
    );
}

#[test]
fn golden_missing_required_field() {
    let mut fixture = base();
    fixture.as_object_mut().expect("object").remove("routing");
    let json = serde_json::to_string_pretty(&fixture).expect("fixture must encode");
    let rendered = render_error(&json);
    assert_eq!(
        rendered,
        concat!(
            "error: missing required field `routing`\n",
            " --> config.json:1:1\n",
            "  |\n",
            "1 | {\n",
            "  | ^ missing field `routing`"
        )
    );
}

#[test]
fn golden_range_error() {
    let rendered = render_error(&tweak(
        &base(),
        &["inbounds", "0", "port"],
        serde_json::json!(70000),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: invalid value for `inbounds[0].port`\n",
            "  --> config.json:21:15\n",
            "   |\n",
            "21 |       \"port\": 70000,\n",
            "   |               ^^^^^ expected u16\n",
            "   |\n",
            "   = actual value: 70000"
        )
    );
}

#[test]
fn golden_nested_semantic_conflict() {
    let rendered = render_error(&tweak(
        &base(),
        &["log"],
        serde_json::json!({
            "output": "stderr",
            "file": { "path": "/var/log/rr.log", "maxBytes": 65536, "maxFiles": 4, "maxTotalBytes": 262144 }
        }),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: invalid value for `log.file`\n",
            "  --> config.json:52:13\n",
            "   |\n",
            "52 |     \"file\": {\n",
            "   |             ^ is only allowed when log.output is file"
        )
    );
}

#[test]
fn golden_non_ascii_before_error() {
    let rendered = render_error(&tweak(
        &base(),
        &["log", "level"],
        serde_json::json!("infö"),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: invalid value for `log.level`\n",
            "  --> config.json:52:14\n",
            "   |\n",
            "52 |     \"level\": \"infö\",\n",
            "   |              ^^^^^^ expected \"error\", \"warn\", \"info\", or \"debug\"\n",
            "   |\n",
            "   = actual value: \"infö\""
        )
    );
}

#[test]
fn golden_tabs() {
    let rendered = render_error("{\n\t\"inbounds\": [],\n\t\"outbounds\": \"nope\"\n}\n");
    assert_eq!(
        rendered,
        concat!(
            "error: invalid type for `outbounds`\n",
            " --> config.json:3:18\n",
            "  |\n",
            "3 |     \"outbounds\": \"nope\"\n",
            "  |                  ^^^^^^ expected a sequence\n",
            "  |\n",
            "  = actual value: \"nope\""
        )
    );
}

#[test]
fn golden_very_long_line() {
    let padding = "x".repeat(400);
    let json = format!(
        "{{\"inbounds\": [], \"assets\": {{\"geoip\": \"{padding}\"}}, \"outbounds\": \"nope\"}}"
    );
    let rendered = render_error(&json);
    assert_eq!(
        rendered,
        concat!(
            "error: invalid type for `outbounds`\n",
            " --> config.json:1:456\n",
            "  |\n",
            "1 | ...xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}, \"outbounds\": \"nope\"}\n",
            "  |                                                                                                                            ^^^^^^ expected a sequence\n",
            "  |\n",
            "  = actual value: \"nope\""
        )
    );
}

#[test]
fn golden_eof_without_trailing_newline() {
    let rendered = render_error("{\n  \"inbounds\": [],\n  \"outbounds\": \"nope\"\n}");
    assert_eq!(
        rendered,
        concat!(
            "error: invalid type for `outbounds`\n",
            " --> config.json:3:16\n",
            "  |\n",
            "3 |   \"outbounds\": \"nope\"\n",
            "  |                ^^^^^^ expected a sequence\n",
            "  |\n",
            "  = actual value: \"nope\""
        )
    );
}

#[test]
fn golden_duplicate_key() {
    let rendered = render_error(
        "{\n  \"inbounds\": [],\n  \"outbounds\": [],\n  \"routing\": { \"users\": [] },\n  \"routing\": { \"users\": [] }\n}\n",
    );
    assert_eq!(
        rendered,
        concat!(
            "error: duplicate field `routing`\n",
            " --> config.json:5:3\n",
            "  |\n",
            "5 |   \"routing\": { \"users\": [] }\n",
            "  |   ^^^^^^^^^ field defined more than once\n",
            "  |\n",
            "  = help: remove one of the definitions"
        )
    );
}

#[test]
fn golden_secret_redaction() {
    let rendered = render_error(&tweak(
        &base(),
        &[
            "inbounds",
            "0",
            "streamSettings",
            "realitySettings",
            "privateKey",
        ],
        serde_json::json!("not-valid-base64!!!"),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: invalid value for `inbounds[0].streamSettings.realitySettings.privateKey`\n",
            "  --> config.json:40:25\n",
            "   |\n",
            "40 |           \"privateKey\": \"[REDACTED]\",\n",
            "   |                         ^^^^^^^^^^^^ must be URL-safe unpadded base64"
        )
    );
    assert!(
        !rendered.contains("not-valid-base64"),
        "the secret value must never appear: {rendered}"
    );
}

#[test]
fn golden_removed_policy() {
    let rendered = render_error(&tweak(
        &base(),
        &["policy"],
        serde_json::json!({ "relay": { "bufferBytes": 16384 } }),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: field `policy` was removed in v1.6\n",
            "  --> config.json:75:3\n",
            "   |\n",
            "75 |   \"policy\": {\n",
            "   |   ^^^^^^^^\n",
            "   |\n",
            "   = configuration path: policy\n",
            "   = help: move every value to the identically named `advanced.limits.*` fields"
        )
    );
}

#[test]
fn golden_removed_resource_mode() {
    let rendered = render_error(&tweak(
        &base(),
        &["runtime"],
        serde_json::json!({ "resourceMode": "dedicated" }),
    ));
    assert_eq!(
        rendered,
        concat!(
            "error: field `runtime.resourceMode` was removed in v1.6\n",
            "  --> config.json:98:5\n",
            "   |\n",
            "98 |     \"resourceMode\": \"dedicated\"\n",
            "   |     ^^^^^^^^^^^^^^\n",
            "   |\n",
            "   = configuration path: runtime.resourceMode\n",
            "   = help: use `runtime.profile` (\"auto\", \"shared\", or \"dedicated\")"
        )
    );
}

#[test]
fn golden_control_characters_are_never_emitted() {
    // A raw ESC byte inside a string is a syntax error; the excerpt must
    // still replace the control character rather than echo it.
    let rendered = render_error("{\n  \"inbounds\": [],\n  \"outbounds\": \"no\u{1b}pe\"\n}\n");
    assert_eq!(
        rendered,
        concat!(
            "error: unescaped control character in string\n",
            " --> config.json:3:19\n",
            "  |\n",
            "3 |   \"outbounds\": \"no�pe\"\n",
            "  |                   ^\n",
            "  |\n",
            "  = help: escape control characters as \\u00XX"
        )
    );

    // A JSON-escaped ESC is valid syntax but must never reach the terminal
    // through the actual-value note either.
    let rendered = render_error("{\n  \"inbounds\": [],\n  \"outbounds\": \"no\\u001bpe\"\n}\n");
    assert_eq!(
        rendered,
        concat!(
            "error: invalid type for `outbounds`\n",
            " --> config.json:3:16\n",
            "  |\n",
            "3 |   \"outbounds\": \"no\\u001bpe\"\n",
            "  |                ^^^^^^^^^^^^ expected a sequence\n",
            "  |\n",
            "  = actual value: \"no\\u001bpe\""
        )
    );
}

#[test]
fn golden_startup_error_through_load_config() {
    // The startup path (`check` and `serve` bootstrap) loads through
    // `load_config`; the pid-suffixed temp path is not golden-stable, so the
    // block around the variable file name is asserted instead.
    let path = std::env::temp_dir().join(format!(
        "rust-reality-golden-startup-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        "{\n  \"inbounds\": [],\n  \"outbounds\": \"nope\"\n}\n",
    )
    .expect("fixture must write");
    let error = load_config(&path).expect_err("the fixture must fail");
    let rendered = error.to_string();
    let _ignored = std::fs::remove_file(&path);
    assert!(matches!(error, ConfigLoadError::Decode { .. }));
    let (head, tail) = rendered
        .split_once(&path.display().to_string())
        .expect("the diagnostic must name the file");
    assert_eq!(head, "error: invalid type for `outbounds`\n --> ");
    assert_eq!(
        tail,
        concat!(
            ":3:16\n",
            "  |\n",
            "3 |   \"outbounds\": \"nope\"\n",
            "  |                ^^^^^^ expected a sequence\n",
            "  |\n",
            "  = actual value: \"nope\""
        )
    );
}

#[test]
fn golden_reload_error_display() {
    // Hot reload loads through the same `load_config`; the rendered
    // diagnostic travels through `RuntimeUpdateError` unchanged.
    let error = crate::config::io::decode_config(
        Path::new("reload.json"),
        "{\n  \"inbounds\": [],\n  \"outbounds\": \"nope\"\n}\n".as_bytes(),
    )
    .expect_err("the fixture must fail");
    let update = crate::server::production::RuntimeUpdateError::from(error);
    assert_eq!(
        update.to_string(),
        concat!(
            "error: invalid type for `outbounds`\n",
            " --> reload.json:3:16\n",
            "  |\n",
            "3 |   \"outbounds\": \"nope\"\n",
            "  |                ^^^^^^ expected a sequence\n",
            "  |\n",
            "  = actual value: \"nope\""
        )
    );
}

#[test]
fn golden_invalid_utf8_and_partial_spans_never_panic() {
    // Invalid UTF-8 forces lossy decoding; the tolerant scanner must keep
    // every span on a character boundary (regression: a multi-byte escape
    // byte once left the scanner mid-character).
    let bytes: &[u8] = b"[ {},[{\"u\\\xEC\x04";
    let error = crate::config::io::decode_config(Path::new("config.json"), bytes)
        .expect_err("the fixture must fail");
    let rendered = error.to_string();
    assert!(rendered.starts_with("error: "), "{rendered}");
    assert!(!rendered.contains('\u{1b}'), "{rendered:?}");
}
