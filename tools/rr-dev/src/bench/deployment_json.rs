//! Shared JSON object helpers for deployment-suite config mutation.
//!
//! Kept separate from routing/topology/RTT section runners so config builders
//! can share exact parse/rebuild helpers without pulling section orchestration.

use std::collections::BTreeMap;

use crate::perf::json_in::{self, Value};

pub(super) fn root_object(raw: &str) -> Result<BTreeMap<String, Value>, String> {
    match json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?
    {
        Value::Object(root) => Ok(root),
        _ => Err("generated rust config is not an object".to_owned()),
    }
}

pub(super) fn first_client(root: &BTreeMap<String, Value>) -> Result<&Value, String> {
    root.get("inbounds")
        .ok_or_else(|| "generated config has no inbounds".to_owned())?
        .as_array("inbounds")
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated config has no first inbound".to_owned())?
        .field("inbounds[0]", "settings")
        .and_then(|settings| settings.array_field("inbounds[0].settings", "clients"))
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated config has no base client".to_owned())
}

pub(super) fn replace_clients(
    root: &mut BTreeMap<String, Value>,
    clients: Vec<Value>,
) -> Result<(), String> {
    let Some(Value::Array(inbounds)) = root.get_mut("inbounds") else {
        return Err("generated config has no inbounds array".to_owned());
    };
    let Some(Value::Object(inbound)) = inbounds.first_mut() else {
        return Err("generated config has no first inbound object".to_owned());
    };
    let Some(Value::Object(settings)) = inbound.get_mut("settings") else {
        return Err("generated config has no first inbound settings object".to_owned());
    };
    settings.insert("clients".to_owned(), Value::Array(clients));
    Ok(())
}

pub(super) fn object<K: Into<String>>(entries: impl IntoIterator<Item = (K, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

pub(super) fn string(value: impl Into<String>) -> Value {
    Value::Str(value.into())
}

pub(super) fn strings(values: impl IntoIterator<Item = impl Into<String>>) -> Value {
    Value::Array(
        values
            .into_iter()
            .map(|value| string(value.into()))
            .collect(),
    )
}

pub(super) fn number(value: u64) -> Value {
    Value::Number(value.to_string())
}
