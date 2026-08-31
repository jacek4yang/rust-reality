//! JSON reading for evidence files, with fail-closed accessors.
//!
//! The evaluator's job is to refuse inadmissible evidence, so this parser is paired
//! with accessors that return a typed error naming the exact field path rather than
//! an `Option` a caller might unwrap carelessly. Every accessor that can fail says
//! which field it wanted and what it expected there, because those messages are the
//! evaluator's entire diagnostic surface when a gate rejects evidence.
//!
//! Numbers are retained as text so no precision is lost between reading a value and
//! writing it back out. The evaluator must reproduce recorded reports byte for byte,
//! and a parse-then-reformat round trip through `f64` would be the obvious place to
//! lose a digit.

use std::collections::{btree_map::Entry, BTreeMap};

/// Maximum number of recursively nested arrays and objects in one document.
///
/// Evidence schemas are shallow. A fixed ceiling keeps malformed inputs from
/// exhausting the control-plane thread's stack without constraining valid runs.
const MAX_NESTING_DEPTH: usize = 128;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// JSON `null`.
    Null,
    /// JSON `true` or `false`.
    Bool(bool),
    /// Any JSON number, kept as source text.
    Number(String),
    /// A JSON string with escapes resolved.
    Str(String),
    /// A JSON array.
    Array(Vec<Value>),
    /// A JSON object.
    Object(BTreeMap<String, Value>),
}

/// Why a field could not be read as required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// Dotted path to the field, for diagnostics.
    pub path: String,
    /// What the evaluator required there.
    pub expected: String,
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: expected {}", self.path, self.expected)
    }
}

impl std::error::Error for FieldError {}

type Field<T> = Result<T, FieldError>;

fn missing(path: &str, expected: &str) -> FieldError {
    FieldError {
        path: path.to_owned(),
        expected: expected.to_owned(),
    }
}

impl Value {
    /// Returns a member of this object, or an error naming the path.
    ///
    /// # Errors
    ///
    /// Fails when this is not an object or the member is absent.
    pub fn field(&self, path: &str, key: &str) -> Field<&Self> {
        let Self::Object(members) = self else {
            return Err(missing(path, "an object"));
        };
        members
            .get(key)
            .ok_or_else(|| missing(&format!("{path}.{key}"), "the field to be present"))
    }

    /// Returns a member if present, without failing when it is absent.
    #[must_use]
    pub fn optional(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members.get(key),
            _ => None,
        }
    }

    /// Reads this value as a string.
    ///
    /// # Errors
    ///
    /// Fails when the value is not a JSON string.
    pub fn as_str(&self, path: &str) -> Field<&str> {
        match self {
            Self::Str(text) => Ok(text),
            _ => Err(missing(path, "a string")),
        }
    }

    /// Reads this value as a boolean.
    ///
    /// # Errors
    ///
    /// Fails when the value is not a JSON boolean.
    pub fn as_bool(&self, path: &str) -> Field<bool> {
        match self {
            Self::Bool(flag) => Ok(*flag),
            _ => Err(missing(path, "a boolean")),
        }
    }

    /// Reads this value as a JSON integer.
    ///
    /// Rejects a value written with a decimal point or exponent even when it is
    /// mathematically integral, because Python distinguishes `int` from `float` and
    /// several evidence checks depend on `isinstance(value, int)`.
    ///
    /// # Errors
    ///
    /// Fails when the value is not an integral JSON number.
    pub fn as_int(&self, path: &str) -> Field<i64> {
        let Self::Number(text) = self else {
            return Err(missing(path, "an integer"));
        };
        if text.contains('.') || text.contains('e') || text.contains('E') {
            return Err(missing(path, "an integer, not a float"));
        }
        text.parse().map_err(|_| missing(path, "an integer"))
    }

    /// Reads this value as a floating-point number.
    ///
    /// Accepts both integral and fractional JSON numbers, matching Python's
    /// `isinstance(value, (int, float))` measurement rule.
    ///
    /// # Errors
    ///
    /// Fails when the value is not a JSON number.
    pub fn as_f64(&self, path: &str) -> Field<f64> {
        match self {
            Self::Number(text) => {
                let value: f64 = text
                    .parse()
                    .map_err(|_| missing(path, "a finite number"))?;
                if value.is_finite() {
                    Ok(value)
                } else {
                    Err(missing(path, "a finite number"))
                }
            }
            _ => Err(missing(path, "a number")),
        }
    }

    /// Reads this value as an array.
    ///
    /// # Errors
    ///
    /// Fails when the value is not a JSON array.
    pub fn as_array(&self, path: &str) -> Field<&[Self]> {
        match self {
            Self::Array(items) => Ok(items),
            _ => Err(missing(path, "an array")),
        }
    }

    /// Reads this value as an object.
    ///
    /// # Errors
    ///
    /// Fails when the value is not a JSON object.
    pub fn as_object(&self, path: &str) -> Field<&BTreeMap<String, Self>> {
        match self {
            Self::Object(members) => Ok(members),
            _ => Err(missing(path, "an object")),
        }
    }

    /// Reads a required string member.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent or not a string.
    pub fn str_field(&self, path: &str, key: &str) -> Field<&str> {
        self.field(path, key)?.as_str(&format!("{path}.{key}"))
    }

    /// Reads a required integer member.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent or not an integer.
    pub fn int_field(&self, path: &str, key: &str) -> Field<i64> {
        self.field(path, key)?.as_int(&format!("{path}.{key}"))
    }

    /// Reads a required array member.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent or not an array.
    pub fn array_field(&self, path: &str, key: &str) -> Field<&[Self]> {
        self.field(path, key)?.as_array(&format!("{path}.{key}"))
    }

    /// Requires a member to equal an exact string.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent, not a string, or a different string.
    pub fn require_str(&self, path: &str, key: &str, expected: &str) -> Field<()> {
        let observed = self.str_field(path, key)?;
        if observed == expected {
            return Ok(());
        }
        Err(missing(
            &format!("{path}.{key}"),
            &format!("exactly {expected:?}, found {observed:?}"),
        ))
    }

    /// Requires a member to equal an exact integer.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent, not an integer, or a different integer.
    pub fn require_int(&self, path: &str, key: &str, expected: i64) -> Field<()> {
        let observed = self.int_field(path, key)?;
        if observed == expected {
            return Ok(());
        }
        Err(missing(
            &format!("{path}.{key}"),
            &format!("exactly {expected}, found {observed}"),
        ))
    }

    /// Requires a member to equal an exact boolean.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent, not a boolean, or the wrong value.
    pub fn require_bool(&self, path: &str, key: &str, expected: bool) -> Field<()> {
        let observed = self.field(path, key)?.as_bool(&format!("{path}.{key}"))?;
        if observed == expected {
            return Ok(());
        }
        Err(missing(
            &format!("{path}.{key}"),
            &format!("exactly {expected}"),
        ))
    }

    /// Requires a member to be an empty array.
    ///
    /// Matrix evidence records `failures` as an empty **list** while paired evidence
    /// records the integer `0`. Keeping the two checks distinct is deliberate: a
    /// shared validator that accepted either would let real failures through in one
    /// of the two schemas.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent, not an array, or non-empty.
    pub fn require_empty_array(&self, path: &str, key: &str) -> Field<()> {
        let items = self.array_field(path, key)?;
        if items.is_empty() {
            return Ok(());
        }
        Err(missing(
            &format!("{path}.{key}"),
            &format!("an empty array, found {} entries", items.len()),
        ))
    }
}

/// Parses one JSON document.
///
/// # Errors
///
/// Returns a description of the first syntax problem encountered.
pub fn parse(text: &str) -> Result<Value, String> {
    let bytes = text.as_bytes();
    let mut cursor = 0;
    let value = parse_value(bytes, &mut cursor, 0)?;
    skip_whitespace(bytes, &mut cursor);
    if cursor != bytes.len() {
        return Err(format!("trailing input at byte {cursor}"));
    }
    Ok(value)
}

/// Parses JSON Lines, skipping blank lines, as the evaluator's `load_jsonl` does.
///
/// # Errors
///
/// Returns the offending line number and message for the first malformed row, and
/// rejects any row whose root is not an object.
pub fn parse_lines(text: &str) -> Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let value = parse(line).map_err(|error| format!("line {}: {error}", number + 1))?;
        if !matches!(value, Value::Object(_)) {
            return Err(format!("line {}: row is not an object", number + 1));
        }
        rows.push(value);
    }
    Ok(rows)
}

fn parse_value(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<Value, String> {
    skip_whitespace(bytes, cursor);
    match bytes.get(*cursor) {
        None => Err("unexpected end of input".to_owned()),
        Some(b'{') => parse_object(bytes, cursor, depth),
        Some(b'[') => parse_array(bytes, cursor, depth),
        Some(b'"') => parse_string(bytes, cursor).map(Value::Str),
        Some(b't') => literal(bytes, cursor, "true", Value::Bool(true)),
        Some(b'f') => literal(bytes, cursor, "false", Value::Bool(false)),
        Some(b'n') => literal(bytes, cursor, "null", Value::Null),
        Some(_) => parse_number(bytes, cursor),
    }
}

fn parse_object(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<Value, String> {
    if depth >= MAX_NESTING_DEPTH {
        return Err(format!("nesting depth exceeds {MAX_NESTING_DEPTH}"));
    }
    *cursor += 1;
    let mut members = BTreeMap::new();
    skip_whitespace(bytes, cursor);
    if bytes.get(*cursor) == Some(&b'}') {
        *cursor += 1;
        return Ok(Value::Object(members));
    }
    loop {
        skip_whitespace(bytes, cursor);
        let key_offset = *cursor;
        let key = parse_string(bytes, cursor)?;
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) != Some(&b':') {
            return Err(format!("expected ':' at byte {cursor}"));
        }
        *cursor += 1;
        let value = parse_value(bytes, cursor, depth + 1)?;
        match members.entry(key) {
            Entry::Vacant(member) => {
                member.insert(value);
            }
            Entry::Occupied(_) => {
                return Err(format!("duplicate object member at byte {key_offset}"));
            }
        }
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b'}') => {
                *cursor += 1;
                return Ok(Value::Object(members));
            }
            _ => return Err(format!("expected ',' or '}}' at byte {cursor}")),
        }
    }
}

fn parse_array(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<Value, String> {
    if depth >= MAX_NESTING_DEPTH {
        return Err(format!("nesting depth exceeds {MAX_NESTING_DEPTH}"));
    }
    *cursor += 1;
    let mut items = Vec::new();
    skip_whitespace(bytes, cursor);
    if bytes.get(*cursor) == Some(&b']') {
        *cursor += 1;
        return Ok(Value::Array(items));
    }
    loop {
        items.push(parse_value(bytes, cursor, depth + 1)?);
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b']') => {
                *cursor += 1;
                return Ok(Value::Array(items));
            }
            _ => return Err(format!("expected ',' or ']' at byte {cursor}")),
        }
    }
}

fn parse_string(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    if bytes.get(*cursor) != Some(&b'"') {
        return Err(format!("expected a string at byte {cursor}"));
    }
    *cursor += 1;
    let mut out = Vec::new();
    while let Some(&byte) = bytes.get(*cursor) {
        *cursor += 1;
        match byte {
            b'"' => return String::from_utf8(out).map_err(|error| error.to_string()),
            // RFC 8259 forbids unescaped U+0000..U+001F in JSON strings.
            0x00..=0x1f => {
                return Err(format!("unescaped control byte at byte {}", *cursor - 1));
            }
            b'\\' => {
                let escape = *bytes
                    .get(*cursor)
                    .ok_or_else(|| "unterminated escape".to_owned())?;
                *cursor += 1;
                match escape {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'u' => {
                        let character = parse_unicode_escape(bytes, cursor)?;
                        let mut buffer = [0_u8; 4];
                        out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                    }
                    other => return Err(format!("unknown escape \\{}", other as char)),
                }
            }
            other => out.push(other),
        }
    }
    Err("unterminated string".to_owned())
}

fn parse_unicode_escape(bytes: &[u8], cursor: &mut usize) -> Result<char, String> {
    let first = parse_hex_quad(bytes, cursor)?;
    let code = match first {
        0xd800..=0xdbff => {
            if bytes.get(*cursor..*cursor + 2) != Some(b"\\u") {
                return Err(format!(
                    "high surrogate at byte {} is not followed by a low surrogate",
                    *cursor - 4
                ));
            }
            *cursor += 2;
            let second = parse_hex_quad(bytes, cursor)?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(format!("invalid low surrogate at byte {}", *cursor - 4));
            }
            0x1_0000 + (u32::from(first) - 0xd800) * 0x400 + (u32::from(second) - 0xdc00)
        }
        0xdc00..=0xdfff => {
            return Err(format!("unpaired low surrogate at byte {}", *cursor - 4));
        }
        _ => u32::from(first),
    };
    char::from_u32(code).ok_or_else(|| format!("invalid Unicode scalar value {code:#x}"))
}

fn parse_hex_quad(bytes: &[u8], cursor: &mut usize) -> Result<u16, String> {
    let start = *cursor;
    let hex = bytes
        .get(start..start + 4)
        .ok_or_else(|| format!("truncated \\u escape at byte {start}"))?;
    let mut code = 0_u16;
    for &byte in hex {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a' + 10),
            b'A'..=b'F' => u16::from(byte - b'A' + 10),
            _ => return Err(format!("invalid hex digit at byte {}", *cursor)),
        };
        code = code * 16 + digit;
        *cursor += 1;
    }
    Ok(code)
}

fn parse_number(bytes: &[u8], cursor: &mut usize) -> Result<Value, String> {
    let start = *cursor;
    while let Some(byte) = bytes.get(*cursor) {
        if byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E') {
            *cursor += 1;
        } else {
            break;
        }
    }
    if start == *cursor {
        return Err(format!("expected a value at byte {start}"));
    }
    let text = std::str::from_utf8(&bytes[start..*cursor]).map_err(|error| error.to_string())?;
    if !is_json_number(text.as_bytes()) {
        return Err(format!("invalid number at byte {start}"));
    }
    Ok(Value::Number(text.to_owned()))
}

fn is_json_number(bytes: &[u8]) -> bool {
    let mut index = 0;
    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'0') => index += 1,
        Some(b'1'..=b'9') => {
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b'e' | b'E'))
    {
        index += 1;
        if bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            index += 1;
        }
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

fn literal(bytes: &[u8], cursor: &mut usize, word: &str, value: Value) -> Result<Value, String> {
    if bytes.get(*cursor..*cursor + word.len()) == Some(word.as_bytes()) {
        *cursor += word.len();
        return Ok(value);
    }
    Err(format!("expected `{word}` at byte {cursor}"))
}

fn skip_whitespace(bytes: &[u8], cursor: &mut usize) {
    while let Some(byte) = bytes.get(*cursor) {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            *cursor += 1;
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> Value {
        parse(text).expect("the fixture must parse")
    }

    #[test]
    fn integers_and_floats_are_distinguished_the_way_python_distinguishes_them() {
        let value = doc(r#"{"count": 12, "ratio": 1.5, "whole": 12.0}"#);
        assert_eq!(value.int_field("$", "count"), Ok(12));
        // Several evidence rules test isinstance(value, int); a float written with a
        // decimal point must not satisfy them even when mathematically integral.
        assert!(value.int_field("$", "whole").is_err());
        assert!(value.int_field("$", "ratio").is_err());
        // Both are acceptable as measurements.
        assert_eq!(
            value.field("$", "ratio").and_then(|v| v.as_f64("ratio")),
            Ok(1.5)
        );
        assert_eq!(
            value.field("$", "whole").and_then(|v| v.as_f64("whole")),
            Ok(12.0)
        );
    }

    #[test]
    fn number_text_is_retained_so_no_precision_is_lost() {
        let value = doc(r#"{"p": 0.052734375}"#);
        let Some(Value::Number(text)) = value.optional("p") else {
            panic!("expected a number");
        };
        assert_eq!(text, "0.052734375", "source text must survive parsing");
    }

    #[test]
    fn a_missing_field_names_its_path() {
        let value = doc(r#"{"present": 1}"#);
        let error = value.field("summary", "absent").expect_err("must fail");
        assert_eq!(error.path, "summary.absent");
    }

    #[test]
    fn the_two_failures_encodings_are_validated_separately() {
        // Paired evidence records the integer zero.
        let paired = doc(r#"{"failures": 0}"#);
        assert_eq!(paired.require_int("summary", "failures", 0), Ok(()));
        assert!(
            paired.require_empty_array("summary", "failures").is_err(),
            "the paired integer form must not satisfy the matrix array rule"
        );

        // Matrix evidence records an empty list.
        let matrix = doc(r#"{"failures": []}"#);
        assert_eq!(matrix.require_empty_array("summary", "failures"), Ok(()));
        assert!(
            matrix.require_int("summary", "failures", 0).is_err(),
            "the matrix array form must not satisfy the paired integer rule"
        );

        // A non-empty list is refused.
        let dirty = doc(r#"{"failures": ["timeout"]}"#);
        assert!(dirty.require_empty_array("summary", "failures").is_err());
    }

    #[test]
    fn exact_value_requirements_report_what_was_found() {
        let value = doc(r#"{"status": "PARTIAL", "schemaVersion": 2, "pinned": false}"#);
        let error = value
            .require_str("summary", "status", "COMPLETE")
            .expect_err("must fail");
        assert!(error.expected.contains("COMPLETE"), "{error}");
        assert!(error.expected.contains("PARTIAL"), "{error}");
        assert!(value.require_int("summary", "schemaVersion", 1).is_err());
        assert!(value.require_bool("summary", "pinned", true).is_err());
    }

    #[test]
    fn json_lines_skips_blanks_and_rejects_non_objects() {
        let rows = parse_lines("{\"a\":1}\n\n{\"a\":2}\n").expect("must parse");
        assert_eq!(rows.len(), 2);
        assert!(
            parse_lines("{\"a\":1}\n[1,2]\n").is_err(),
            "a row must be an object"
        );
        assert!(parse_lines("{\"a\":1}\nnot json\n").is_err());
    }

    #[test]
    fn malformed_documents_are_refused() {
        for bad in ["{", r#"{"a":}"#, r#"{"a":1}x"#, r#"{"a":"unterminated}"#] {
            assert!(parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn unescaped_control_bytes_inside_strings_are_refused() {
        assert!(parse("{\"x\":\"line\nfeed\"}").is_err());
        assert!(parse("{\"x\":\"nul\0byte\"}").is_err());
    }

    #[test]
    fn malformed_json_number_grammar_is_refused() {
        for bad in [
            r#"{"x":01}"#,
            r#"{"x":1.}"#,
            r#"{"x":1e}"#,
            r#"{"x":+1}"#,
            r#"{"x":-.1}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn valid_number_boundaries_are_retained_and_non_finite_f64_is_refused() {
        for good in ["0", "-0", "1.0", "1e0", "1E+9", "-2.5e-3"] {
            assert_eq!(parse(good), Ok(Value::Number(good.to_owned())));
        }
        let huge = doc(r#"{"x":1e9999}"#);
        assert!(huge.field("$", "x").unwrap().as_f64("$.x").is_err());
    }

    #[test]
    fn escapes_including_unicode_resolve() {
        let value = doc(r#"{"a":"line\nbreak \u4e2d \ud834\udd1e"}"#);
        assert_eq!(value.str_field("$", "a"), Ok("line\nbreak 中 𝄞"));
    }

    #[test]
    fn malformed_unicode_escapes_are_refused() {
        for bad in [
            r#"{"x":"\u12"}"#,
            r#"{"x":"\uzzzz"}"#,
            r#"{"x":"\ud834"}"#,
            r#"{"x":"\ud834\u0041"}"#,
            r#"{"x":"\udd1e"}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn only_rfc_8259_whitespace_is_accepted() {
        assert!(parse(" \t\r\nnull \t\r\n").is_ok());
        assert!(parse("\u{000b}null").is_err());
        assert!(parse("\u{000c}null").is_err());
    }

    #[test]
    fn duplicate_members_are_refused() {
        assert!(parse(r#"{"identity":"expected","identity":"stale"}"#).is_err());
    }

    #[test]
    fn malformed_container_separators_and_eof_are_refused() {
        for bad in [
            "[1,]",
            "[1,,2]",
            r#"{"x":1,}"#,
            r#"{"x":1,,"y":2}"#,
            r#"{"x" 1}"#,
            "[",
            r#"{"x":[1,2}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn nesting_depth_is_bounded() {
        let accepted = format!("{}0{}", "[".repeat(MAX_NESTING_DEPTH), "]".repeat(MAX_NESTING_DEPTH));
        assert!(parse(&accepted).is_ok());
        let refused = format!(
            "{}0{}",
            "[".repeat(MAX_NESTING_DEPTH + 1),
            "]".repeat(MAX_NESTING_DEPTH + 1)
        );
        assert!(parse(&refused).is_err());
    }

    #[test]
    fn accessors_refuse_the_wrong_shape_rather_than_coercing() {
        let value = doc(r#"{"list": [1], "text": "x", "num": 1}"#);
        assert!(value.array_field("$", "text").is_err());
        assert!(value.str_field("$", "list").is_err());
        assert!(value.int_field("$", "text").is_err());
        assert!(
            value
                .field("$", "num")
                .expect("present")
                .as_object("$.num")
                .is_err()
        );
    }
}
