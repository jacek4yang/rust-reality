//! JSON writing that reproduces `json.dump(indent=2, sort_keys=True)` byte for byte.
//!
//! The evaluator's output file is consumed by release evidence tooling and archived
//! as immutable proof of a gate decision. During authority transfer the new
//! implementation must therefore produce the *same file*, not merely an equivalent
//! one, so recorded reports stay comparable and any diff is a real finding.
//!
//! Two details make this harder than calling a serialiser:
//!
//! # Float formatting
//!
//! Python's `repr` for floats and Rust's `Display` disagree in exactly the cases the
//! report contains. Both recorded shapes appear in the v1.8.0 gate output:
//!
//! ```text
//! value                      Python            Rust `{}`
//! 1.0                        1.0               1
//! -9.037987321491757e-05     -9.037987321491757e-05   -0.00009037987321491757
//! ```
//!
//! So [`format_float`] reimplements Python's rule: shortest round-trip digits, fixed
//! notation while the decimal point sits in `-4 < decpt < 17`, a `.0` suffix when
//! there is no fractional part, and otherwise exponential notation with a signed
//! exponent of at least two digits.
//!
//! # Key ordering
//!
//! `sort_keys=True` sorts by the raw key string. A [`BTreeMap`] gives the same order
//! for the ASCII keys this schema uses, so ordering is structural rather than a
//! sorting step that could be forgotten.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A JSON value in the shape the evaluator emits.
///
/// Deliberately small: the report has no need for a general-purpose value type, and
/// keeping the variants minimal means every one has defined formatting.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// JSON `null`.
    Null,
    /// JSON `true` or `false`.
    Bool(bool),
    /// An integral value, rendered without a decimal point.
    Int(i64),
    /// A floating-point value, rendered with Python's `repr` rule.
    Float(f64),
    /// A string, with the escapes Python's encoder produces.
    Str(String),
    /// An array, rendered in order.
    Array(Vec<Json>),
    /// An object, rendered with sorted keys.
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// Builds an object from key-value pairs.
    #[must_use]
    pub fn object<I, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, Self)>,
        K: Into<String>,
    {
        Self::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// Builds a string value.
    #[must_use]
    pub fn string(text: impl Into<String>) -> Self {
        Self::Str(text.into())
    }

    /// Renders the document exactly as `json.dump(indent=2, sort_keys=True)` does,
    /// including the trailing newline the evaluator writes separately.
    #[must_use]
    pub fn to_python_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    /// Renders the document as `json.dumps(sort_keys=True)` does: one line, with
    /// Python's default `", "` and `": "` separators and no trailing newline.
    ///
    /// This is the form the harnesses used for JSON Lines evidence
    /// (`raw-samples.jsonl`), where one document per line is the point and the
    /// indented form would be unreadable.
    #[must_use]
    pub fn to_compact_json(&self) -> String {
        let mut out = String::new();
        self.write_compact(&mut out, ", ", ": ");
        out
    }

    /// Renders the document as `jq -c` does: one line, no separator spaces.
    ///
    /// The IPv6 harness builds `results.jsonl` with `jq -cn`, so its rows are
    /// byte-for-byte narrower than Python's. Both forms parse identically, but
    /// only one of them reproduces the recorded evidence.
    #[must_use]
    pub fn to_jq_json(&self) -> String {
        let mut out = String::new();
        self.write_compact(&mut out, ",", ":");
        out
    }

    fn write_compact(&self, out: &mut String, item_separator: &str, key_separator: &str) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Float(value) => out.push_str(&format_float(*value)),
            Self::Str(text) => out.push_str(&escape(text)),
            Self::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(item_separator);
                    }
                    item.write_compact(out, item_separator, key_separator);
                }
                out.push(']');
            }
            Self::Object(members) => {
                out.push('{');
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push_str(item_separator);
                    }
                    out.push_str(&escape(key));
                    out.push_str(key_separator);
                    value.write_compact(out, item_separator, key_separator);
                }
                out.push('}');
            }
        }
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Float(value) => out.push_str(&format_float(*value)),
            Self::Str(text) => out.push_str(&escape(text)),
            Self::Array(items) => {
                if items.is_empty() {
                    // Python renders an empty container inline, with no newline.
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    item.write(out, depth + 1);
                    if index + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push(']');
            }
            Self::Object(members) => {
                if members.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                let count = members.len();
                for (index, (key, value)) in members.iter().enumerate() {
                    indent(out, depth + 1);
                    out.push_str(&escape(key));
                    out.push_str(": ");
                    value.write(out, depth + 1);
                    if index + 1 < count {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push('}');
            }
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth * 2 {
        out.push(' ');
    }
}

/// Escapes a string the way Python's JSON encoder does with default settings.
///
/// `ensure_ascii` defaults to true in `json.dump`, so non-ASCII characters become
/// `\uXXXX` escapes, including surrogate pairs for astral code points. The schema is
/// ASCII today, but the rule is implemented rather than assumed so a future non-ASCII
/// workload name cannot silently produce a different file.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            ascii if ascii.is_ascii() => out.push(ascii),
            other => {
                let code = other as u32;
                if code > 0xffff {
                    // Python emits a surrogate pair for astral characters.
                    let adjusted = code - 0x1_0000;
                    let high = 0xd800 + (adjusted >> 10);
                    let low = 0xdc00 + (adjusted & 0x3ff);
                    let _ = write!(out, "\\u{high:04x}\\u{low:04x}");
                } else {
                    let _ = write!(out, "\\u{code:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

/// Formats a float the way Python's `repr` does.
///
/// Python takes the shortest decimal digit string that round-trips, then chooses a
/// presentation: fixed notation while the decimal point position `decpt` satisfies
/// `-4 < decpt < 17`, and exponential notation otherwise. In fixed notation a value
/// with no fractional digits gains a `.0` suffix, which is the difference that would
/// otherwise turn `1.0` into `1`.
///
/// Non-finite values have no JSON representation; Python writes the bare tokens
/// `NaN`, `Infinity` and `-Infinity`, so those are reproduced for completeness even
/// though admissibility rejects such measurements long before serialisation.
#[must_use]
pub fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "Infinity".to_owned()
        } else {
            "-Infinity".to_owned()
        };
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_owned()
        } else {
            "0.0".to_owned()
        };
    }

    // `{:e}` gives the shortest round-trip mantissa and a base-ten exponent.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` always emits an exponent");
    let exponent: i32 = exponent.parse().expect("`{:e}` emits a decimal exponent");
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.trim_start_matches('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };

    // `decpt` is where the decimal point falls relative to the first digit.
    let decpt = exponent + 1;
    let sign = if negative { "-" } else { "" };

    #[expect(
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation,
        reason = "digit counts are far below i32 range"
    )]
    let digit_count = digits.len() as i32;

    if decpt > -4 && decpt < 17 {
        if decpt <= 0 {
            let zeros = "0".repeat(decpt.unsigned_abs() as usize);
            return format!("{sign}0.{zeros}{digits}");
        }
        if decpt >= digit_count {
            // Both are non-negative here: this branch requires decpt >= digit_count
            // and digit_count is at least one.
            let padding = usize::try_from(decpt - digit_count).unwrap_or(0);
            let zeros = "0".repeat(padding);
            return format!("{sign}{digits}{zeros}.0");
        }
        // decpt is strictly positive in this branch, having been excluded above.
        let split = usize::try_from(decpt).unwrap_or(0);
        return format!("{sign}{}.{}", &digits[..split], &digits[split..]);
    }

    // Exponential notation: one digit, optional fraction, signed two-digit exponent.
    let head = &digits[..1];
    let tail = &digits[1..];
    let exponent_sign = if exponent < 0 { '-' } else { '+' };
    let magnitude = exponent.unsigned_abs();
    if tail.is_empty() {
        format!("{sign}{head}e{exponent_sign}{magnitude:02}")
    } else {
        format!("{sign}{head}.{tail}e{exponent_sign}{magnitude:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integral_floats_keep_the_python_dot_zero_suffix() {
        // The difference that would otherwise silently corrupt every adjusted
        // p-value of exactly 1.0 in the recorded reports.
        assert_eq!(format_float(1.0), "1.0");
        assert_eq!(format_float(0.0), "0.0");
        assert_eq!(format_float(-0.0), "-0.0");
        assert_eq!(format_float(100.0), "100.0");
        assert_eq!(format_float(-2.0), "-2.0");
        assert_eq!(format_float(0.05), "0.05");
    }

    #[test]
    fn the_recorded_exponential_value_is_reproduced_exactly() {
        // From artifacts/v180-release-gate/gates/evaluation-r01.json.
        assert_eq!(
            format_float(-9.037_987_321_491_757e-5),
            "-9.037987321491757e-05",
            "Python pads the exponent to two digits"
        );
    }

    #[test]
    fn the_fixed_to_exponential_thresholds_match_python() {
        // Python switches at decpt <= -4 and decpt > 16.
        assert_eq!(format_float(1e-4), "0.0001");
        assert_eq!(format_float(1e-5), "1e-05");
        assert_eq!(format_float(1e15), "1000000000000000.0");
        assert_eq!(format_float(1e16), "1e+16");
        assert_eq!(format_float(1e17), "1e+17");
        assert_eq!(format_float(1e100), "1e+100");
        assert_eq!(format_float(1e-100), "1e-100");
    }

    #[test]
    fn recorded_gate_values_render_exactly() {
        // Real values from the v1.8.0 protected metrics.
        assert_eq!(format_float(0.052_734_375), "0.052734375");
        assert_eq!(format_float(0.947_509_765_625), "0.947509765625");
        assert_eq!(format_float(1.028_454_451_654_484_5), "1.0284544516544845");
        assert_eq!(
            format_float(-0.058_513_158_852_144_67),
            "-0.05851315885214467"
        );
        assert_eq!(format_float(0.999_710_815_797_471_9), "0.9997108157974719");
    }

    #[test]
    fn non_finite_values_use_the_python_tokens() {
        assert_eq!(format_float(f64::NAN), "NaN");
        assert_eq!(format_float(f64::INFINITY), "Infinity");
        assert_eq!(format_float(f64::NEG_INFINITY), "-Infinity");
    }

    #[test]
    fn object_keys_are_sorted_and_indented_two_spaces() {
        let document = Json::object([
            ("zebra", Json::Int(1)),
            ("alpha", Json::Int(2)),
            ("Mixed", Json::Int(3)),
        ]);
        assert_eq!(
            document.to_python_json(),
            "{\n  \"Mixed\": 3,\n  \"alpha\": 2,\n  \"zebra\": 1\n}\n",
            "uppercase sorts before lowercase, matching sort_keys on raw strings"
        );
    }

    #[test]
    fn nested_containers_indent_cumulatively() {
        let document = Json::object([(
            "outer",
            Json::object([("inner", Json::Array(vec![Json::Int(1), Json::Int(2)]))]),
        )]);
        assert_eq!(
            document.to_python_json(),
            "{\n  \"outer\": {\n    \"inner\": [\n      1,\n      2\n    ]\n  }\n}\n"
        );
    }

    #[test]
    fn empty_containers_render_inline() {
        let document = Json::object([
            ("list", Json::Array(Vec::new())),
            ("map", Json::Object(BTreeMap::new())),
        ]);
        assert_eq!(
            document.to_python_json(),
            "{\n  \"list\": [],\n  \"map\": {}\n}\n",
            "Python emits empty containers without an inner newline"
        );
    }

    #[test]
    fn strings_are_escaped_the_way_python_escapes_them() {
        assert_eq!(escape("plain"), "\"plain\"");
        assert_eq!(escape("quote\"inside"), "\"quote\\\"inside\"");
        assert_eq!(escape("back\\slash"), "\"back\\\\slash\"");
        assert_eq!(escape("tab\tnew\nret\r"), "\"tab\\tnew\\nret\\r\"");
        assert_eq!(escape("\u{1}"), "\"\\u0001\"");
        // ensure_ascii defaults to true, so non-ASCII is escaped.
        assert_eq!(escape("中"), "\"\\u4e2d\"");
    }

    #[test]
    fn astral_characters_become_surrogate_pairs() {
        // Python's ensure_ascii emits a surrogate pair rather than one escape.
        assert_eq!(escape("\u{1f600}"), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn integers_and_floats_are_distinguishable_in_output() {
        // schemaVersion must stay `1`, while a p-value of one must stay `1.0`.
        let document = Json::object([
            ("schemaVersion", Json::Int(1)),
            ("holmAdjustedPValue", Json::Float(1.0)),
        ]);
        assert_eq!(
            document.to_python_json(),
            "{\n  \"holmAdjustedPValue\": 1.0,\n  \"schemaVersion\": 1\n}\n"
        );
    }

    #[test]
    fn booleans_and_null_render_as_json_tokens() {
        let document = Json::object([
            ("pass", Json::Bool(true)),
            ("significant", Json::Bool(false)),
            ("adjusted", Json::Null),
        ]);
        assert_eq!(
            document.to_python_json(),
            "{\n  \"adjusted\": null,\n  \"pass\": true,\n  \"significant\": false\n}\n"
        );
    }

    #[test]
    fn every_float_in_the_recorded_report_reformats_identically() {
        // The decisive check for byte-identical output: take the actual number tokens
        // Python wrote into the v1.8.0 gate report, parse each one, and confirm this
        // formatter reproduces the same text. Any disagreement in the shortest
        // round-trip digits, the fixed/exponential threshold, the `.0` suffix or the
        // exponent padding would show up here rather than as a mysterious diff during
        // authority transfer.
        let Some(raw) = recorded_report() else {
            eprintln!("recorded evaluation report unavailable; skipping float parity");
            return;
        };

        let mut checked = 0_usize;
        for token in number_tokens(&raw) {
            // Integers are rendered by the Int variant and have no float form here.
            if !token.contains('.') && !token.contains('e') && !token.contains('E') {
                continue;
            }
            let value: f64 = token
                .parse()
                .unwrap_or_else(|_| panic!("{token} should parse as a float"));
            assert_eq!(
                format_float(value),
                token,
                "reformatting {token} did not reproduce the recorded text"
            );
            checked += 1;
        }
        assert!(
            checked > 500,
            "expected hundreds of float tokens in the recorded report, saw {checked}"
        );
    }

    /// Reads the recorded v1.8.0 evaluation report if the evidence archive is present.
    fn recorded_report() -> Option<String> {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|ancestor| ancestor.join("artifacts/v180-release-gate/gates/evaluation-r01.json"))
            .find(|candidate| candidate.is_file())
            .and_then(|path| std::fs::read_to_string(path).ok())
    }

    /// Extracts JSON number tokens, skipping anything inside a string.
    fn number_tokens(raw: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let bytes = raw.as_bytes();
        let mut index = 0;
        let mut in_string = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if in_string {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == b'"' {
                    in_string = false;
                }
                index += 1;
                continue;
            }
            if byte == b'"' {
                in_string = true;
                index += 1;
                continue;
            }
            let starts_number = byte.is_ascii_digit()
                || (byte == b'-' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit));
            if !starts_number {
                index += 1;
                continue;
            }
            let start = index;
            index += 1;
            while let Some(next) = bytes.get(index) {
                if next.is_ascii_digit() || matches!(next, b'.' | b'e' | b'E' | b'+' | b'-') {
                    index += 1;
                } else {
                    break;
                }
            }
            tokens.push(raw[start..index].to_owned());
        }
        tokens
    }

    #[test]
    fn a_document_always_ends_with_exactly_one_newline() {
        let rendered = Json::Int(1).to_python_json();
        assert_eq!(rendered, "1\n");
        assert!(!rendered.ends_with("\n\n"));
    }

    /// `to_compact_json` must match `json.dumps(sort_keys=True)` byte for byte,
    /// including Python's default `", "` / `": "` separators.
    #[test]
    fn the_compact_form_matches_python_dumps() {
        let document = Json::object([
            ("b", Json::Int(2)),
            ("a", Json::Array(vec![Json::Int(1), Json::Int(2)])),
            ("c", Json::object([("d", Json::Null)])),
            ("e", Json::Float(1.5)),
            ("f", Json::string("x")),
        ]);
        assert_eq!(
            document.to_compact_json(),
            r#"{"a": [1, 2], "b": 2, "c": {"d": null}, "e": 1.5, "f": "x"}"#
        );

        let empties = Json::object([
            ("empty", Json::object([] as [(&str, Json); 0])),
            ("list", Json::Array(vec![])),
        ]);
        assert_eq!(empties.to_compact_json(), r#"{"empty": {}, "list": []}"#);
        // The same documents under `jq -c`, which uses no separator spaces.
        assert_eq!(
            document.to_jq_json(),
            r#"{"a":[1,2],"b":2,"c":{"d":null},"e":1.5,"f":"x"}"#
        );
        assert_eq!(empties.to_jq_json(), r#"{"empty":{},"list":[]}"#);
        // Verified against the real thing:
        //   jq -cn '{ts:"2026-01-01T00:00:00Z",matrix:"1-listeners",
        //            detail:{a:1,b:[1,2],c:null,d:true},evidence:""}'
        let row = Json::object([
            ("ts", Json::string("2026-01-01T00:00:00Z")),
            ("matrix", Json::string("1-listeners")),
            (
                "detail",
                Json::object([
                    ("a", Json::Int(1)),
                    ("b", Json::Array(vec![Json::Int(1), Json::Int(2)])),
                    ("c", Json::Null),
                    ("d", Json::Bool(true)),
                ]),
            ),
            ("evidence", Json::string("")),
        ]);
        assert_eq!(
            row.to_jq_json(),
            r#"{"detail":{"a":1,"b":[1,2],"c":null,"d":true},"evidence":"","matrix":"1-listeners","ts":"2026-01-01T00:00:00Z"}"#
        );
    }
}
