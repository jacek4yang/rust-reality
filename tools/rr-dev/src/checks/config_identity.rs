//! Secret-free deployment identity fingerprints.
//!
//! Migrated from `config-identity-fingerprint.py` and its test. Deployment
//! identity comparison must never emit raw secrets (private keys, UUIDs, short
//! IDs): this walks a config document and, for each client-visible identity field,
//! records only `{present, sha256, kind, count}`. The whole document and the
//! identity-field set each get a SHA-256, so two configs can be compared for
//! identity drift by hash alone.
//!
//! The fingerprint hashes compact canonical JSON (sorted keys, no spaces),
//! matching the Python's `json.dumps(sort_keys=True, separators=(",", ":"))`, so a
//! recorded fingerprint stays comparable across the migration.

use std::{collections::BTreeMap, path::Path};

use crate::{
    hash::sha256_hex,
    perf::json_in::{self, Value},
    perf::json_out::Json,
};

/// The client-visible identity fields whose presence and hash are recorded.
const IDENTITY_FIELDS: [&str; 8] = [
    "clients",
    "flow",
    "listen",
    "port",
    "privateKey",
    "serverNames",
    "shortIds",
    "target",
];

/// One recorded identity field: present, its content hash, kind and count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Content SHA-256 over compact canonical JSON.
    pub sha256: String,
    /// The JSON kind: `dict`, `list`, `str`, `int`, `float`, `bool`, `NoneType`.
    pub kind: String,
    /// Element count for containers, else 1.
    pub count: usize,
}

/// Computes the SHA-256 of a value's compact canonical JSON.
#[must_use]
pub fn fingerprint(value: &Value) -> String {
    sha256_hex(compact_canonical(value).as_bytes())
}

/// Walks `value`, recording every client-visible identity field by dotted path.
///
/// A field is recorded when its key is in [`IDENTITY_FIELDS`]; the walk then
/// continues into the child so nested identity fields are captured too, matching
/// the Python's recursion.
pub fn visit(value: &Value, path: &str, result: &mut BTreeMap<String, Field>) {
    match value {
        Value::Object(members) => {
            for (key, child) in members {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if IDENTITY_FIELDS.contains(&key.as_str()) {
                    result.insert(
                        child_path.clone(),
                        Field {
                            sha256: fingerprint(child),
                            kind: kind_of(child),
                            count: count_of(child),
                        },
                    );
                }
                visit(child, &child_path, result);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                visit(child, &format!("{path}[{index}]"), result);
            }
        }
        _ => {}
    }
}

/// Produces the schema-v1 fingerprint report for a config document.
///
/// # Errors
///
/// Returns a message when the config file cannot be read or parsed.
pub fn report(config_path: &Path) -> Result<Json, String> {
    let text = std::fs::read_to_string(config_path)
        .map_err(|error| format!("{}: {error}", config_path.display()))?;
    let config = json_in::parse(&text).map_err(|error| format!("config is not JSON: {error}"))?;

    let mut fields: BTreeMap<String, Field> = BTreeMap::new();
    visit(&config, "", &mut fields);

    let identity_fields = Json::Object(
        fields
            .iter()
            .map(|(path, field)| {
                (
                    path.clone(),
                    Json::object([
                        ("present", Json::Bool(true)),
                        ("sha256", Json::string(field.sha256.clone())),
                        ("kind", Json::string(field.kind.clone())),
                        (
                            "count",
                            Json::Int(i64::try_from(field.count).unwrap_or(i64::MAX)),
                        ),
                    ]),
                )
            })
            .collect(),
    );
    let identity_set_sha256 = sha256_hex(fields_canonical(&fields).as_bytes());

    Ok(Json::object([
        ("schemaVersion", Json::Int(1)),
        ("configSha256", Json::string(fingerprint(&config))),
        ("identityFields", identity_fields),
        ("identitySetSha256", Json::string(identity_set_sha256)),
    ]))
}

/// The Python `type(value).__name__` for a JSON value.
fn kind_of(value: &Value) -> String {
    match value {
        Value::Object(_) => "dict",
        Value::Array(_) => "list",
        Value::Str(_) => "str",
        Value::Number(text) => {
            if text.contains('.') || text.contains('e') || text.contains('E') {
                "float"
            } else {
                "int"
            }
        }
        Value::Bool(_) => "bool",
        Value::Null => "NoneType",
    }
    .to_owned()
}

/// `len(child)` for containers, else 1, matching the Python.
fn count_of(value: &Value) -> usize {
    match value {
        Value::Object(members) => members.len(),
        Value::Array(items) => items.len(),
        _ => 1,
    }
}

/// Serialises a value as compact canonical JSON: sorted keys, no whitespace.
fn compact_canonical(value: &Value) -> String {
    let mut out = String::new();
    write_compact(value, &mut out);
    out
}

fn write_compact(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(text) => out.push_str(text),
        Value::Str(text) => out.push_str(&escape(text)),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            // BTreeMap iterates in sorted key order, matching sort_keys=True.
            out.push('{');
            for (index, (key, child)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&escape(key));
                out.push(':');
                write_compact(child, out);
            }
            out.push('}');
        }
    }
}

/// Serialises the recorded field map the way the Python hashes `fields`: a dict of
/// `{present, sha256, kind, count}` entries, compact and sorted.
fn fields_canonical(fields: &BTreeMap<String, Field>) -> String {
    let mut out = String::from("{");
    for (index, (path, field)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&escape(path));
        out.push_str(":{\"count\":");
        out.push_str(&field.count.to_string());
        out.push_str(",\"kind\":");
        out.push_str(&escape(&field.kind));
        out.push_str(",\"present\":true,\"sha256\":");
        out.push_str(&escape(&field.sha256));
        out.push('}');
    }
    out.push('}');
    out
}

/// Escapes a string as a compact JSON string literal.
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
            control if (control as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_fields_never_carry_raw_secrets() {
        let secret = "never-emit-this-private-value";
        let document = format!(
            r#"{{"inbounds":[{{"listen":{{"mode":"ipv4Only","ipv4":"0.0.0.0"}},"port":443,"settings":{{"clients":[{{"id":"{secret}","flow":"xtls-rprx-vision"}}]}},"streamSettings":{{"reality":{{"privateKey":"{secret}","shortIds":["{secret}"],"serverNames":["example.invalid"],"target":"example.invalid:443"}}}}}}]}}"#
        );
        let value = json_in::parse(&document).expect("fixture must parse");
        let mut fields = BTreeMap::new();
        visit(&value, "", &mut fields);

        assert!(!fields.is_empty(), "identity fields must be recorded");
        let encoded = format!("{fields:?}");
        assert!(
            !encoded.contains(secret),
            "no raw secret may survive: {encoded}"
        );
        for field in fields.values() {
            assert_eq!(field.sha256.len(), 64, "every field carries a full SHA-256");
        }
    }

    #[test]
    fn the_fingerprint_is_stable_and_key_order_independent() {
        let a = json_in::parse(r#"{"port":443,"flow":"x"}"#).unwrap();
        let b = json_in::parse(r#"{"flow":"x","port":443}"#).unwrap();
        assert_eq!(
            fingerprint(&a),
            fingerprint(&b),
            "sorted-key canonicalisation"
        );
    }

    #[test]
    fn a_present_field_records_kind_and_count() {
        let value = json_in::parse(r#"{"serverNames":["a.example","b.example"]}"#).unwrap();
        let mut fields = BTreeMap::new();
        visit(&value, "", &mut fields);
        let field = fields.get("serverNames").expect("serverNames recorded");
        assert_eq!(field.kind, "list");
        assert_eq!(field.count, 2);
    }
}
