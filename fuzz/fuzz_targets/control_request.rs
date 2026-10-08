#![no_main]

use arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::control::{
    decode_request,
    protocol::{MAX_REQUEST_ID_BYTES, OPERATIONS},
};
use serde_json::{Map, Value, json};

// Control protocol request decoder. Most inputs are generated envelopes close
// to the real grammar, so argument decoding and the cross-field rules are
// reached; one in eight is raw bytes for lexer-level rejects. Every value is
// synthetic: no real UUID, handle, or short ID.
//
// Invariants checked beyond "never panics":
// - an accepted request names an operation from the published capability
//   list and carries an `id` within the documented bound;
// - `expectedGeneration` is only ever accepted on a mutation;
// - a rejection never echoes the synthetic credential planted in the input.

const PLANTED: &str = "7e57c0de-0000-4000-8000-00000000f022";

fn text(u: &mut Unstructured<'_>, maximum: usize) -> Result<String> {
    let length = u.int_in_range(0..=maximum)?;
    let mut value = String::with_capacity(length);
    for _ in 0..length {
        value.push(char::from(*u.choose(b"abcdef0123456789_u-.")?));
    }
    Ok(value)
}

fn scalar(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0..=5_u8)? {
        0 => Value::Null,
        1 => json!(u.arbitrary::<bool>()?),
        2 => json!(u.arbitrary::<i64>()?),
        3 => json!(PLANTED),
        4 => json!(format!("u_{}", text(u, 34)?)),
        _ => json!(text(u, 20)?),
    })
}

fn arguments(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut args = Map::new();
    for _ in 0..u.int_in_range(0..=4_usize)? {
        let key = (*u.choose(&[
            "user", "id", "shortId", "shortIds", "label", "policy", "enabled", "retire", "bytes",
            "unknown",
        ])?)
        .to_owned();
        let value = if u.ratio(1, 4)? {
            json!([scalar(u)?, scalar(u)?])
        } else {
            scalar(u)?
        };
        args.insert(key, value);
    }
    Ok(Value::Object(args))
}

fn envelope(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let mut request = Map::new();
    if u.ratio(15, 16)? {
        request.insert("v".into(), json!(*u.choose(&[1_i64, 0, 2, -1])?));
    }
    if u.ratio(1, 2)? {
        let id = if u.ratio(7, 8)? {
            json!(text(u, 24)?)
        } else {
            json!("x".repeat(MAX_REQUEST_ID_BYTES + 1))
        };
        request.insert("id".into(), id);
    }
    if u.ratio(15, 16)? {
        let op = if u.ratio(7, 8)? {
            (*u.choose(OPERATIONS)?).to_owned()
        } else {
            text(u, 16)?
        };
        request.insert("op".into(), json!(op));
    }
    if u.ratio(3, 4)? {
        request.insert("args".into(), arguments(u)?);
    }
    if u.ratio(1, 4)? {
        request.insert("expectedGeneration".into(), scalar(u)?);
    }
    if u.ratio(1, 16)? {
        request.insert(text(u, 6)?, scalar(u)?);
    }
    let mut line = serde_json::to_vec(&Value::Object(request)).unwrap_or_default();
    if u.ratio(1, 8)? {
        let keep = u.int_in_range(0..=line.len())?;
        line.truncate(keep);
    }
    Ok(line)
}

fuzz_target!(|input: &[u8]| {
    let mut unstructured = Unstructured::new(input);
    let line = match unstructured.ratio(7, 8) {
        Ok(true) => match envelope(&mut unstructured) {
            Ok(line) => line,
            Err(_) => return,
        },
        _ => input.to_vec(),
    };
    match decode_request(&line) {
        Ok(request) => {
            assert!(OPERATIONS.contains(&request.operation.name()));
            assert!(
                request
                    .id
                    .as_ref()
                    .is_none_or(|id| id.len() <= MAX_REQUEST_ID_BYTES)
            );
            assert!(request.expected_generation.is_none() || request.operation.is_mutation());
        }
        Err(error) => {
            assert!(!error.message.contains(PLANTED));
        }
    }
});
