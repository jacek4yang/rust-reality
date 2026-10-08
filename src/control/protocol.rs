//! Control protocol version 1: the wire shapes and the request decoder.
//!
//! Framing is one JSON object per line in each direction (UTF-8, `\n`
//! terminated, at most [`MAX_REQUEST_BYTES`] per request). A request is
//!
//! ```json
//! {"v":1,"id":"opaque","op":"users.list","args":{},"expectedGeneration":7}
//! ```
//!
//! - `v` (required) — the protocol version. Exactly the values in
//!   [`SUPPORTED_VERSIONS`] are accepted; anything else is answered with
//!   `unsupportedVersion` and the supported list, never silently reinterpreted.
//! - `id` (optional) — an opaque client string of at most
//!   [`MAX_REQUEST_ID_BYTES`] bytes, echoed back so a client can match
//!   responses.
//! - `op` (required) — the operation name; the closed set is [`Operation`].
//! - `args` (optional) — the operation's arguments. Unknown arguments are
//!   rejected.
//! - `expectedGeneration` (optional, mutations only) — compare-and-publish:
//!   the change is applied only if this is still the current generation.
//!
//! Every response is one line:
//!
//! ```json
//! {"v":1,"id":"opaque","ok":true,"generation":8,"result":{}}
//! {"v":1,"id":"opaque","ok":false,"generation":7,"error":{"code":"notFound","message":"..."}}
//! ```
//!
//! The decoder is strict and allocation-bounded by the line limit the server
//! enforces before calling it. It is a parser of untrusted (local) input and
//! is covered by the `control_request` fuzz target.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u64 = 1;

/// Every protocol version this build accepts.
pub const SUPPORTED_VERSIONS: &[u64] = &[PROTOCOL_VERSION];

/// Largest accepted request line, excluding the terminating newline.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Largest accepted client request `id`.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Largest accepted user `label` supplied through the control interface.
pub const MAX_LABEL_BYTES: usize = 128;

/// Largest number of short IDs one rotation may retire.
pub const MAX_RETIRE: usize = 16;

/// Entries a listing returns when the request names no `limit`.
pub const DEFAULT_PAGE_LIMIT: usize = 100;

/// Most entries one listing page may return.
pub const MAX_PAGE_LIMIT: usize = 1_000;

/// Encoded size a listing page stops growing at. A page holds whole
/// entries, at least one, so a response is bounded by this budget or, for a
/// single oversized entry, by the configuration size limit.
pub const MAX_PAGE_BYTES: usize = 256 * 1024;

/// A closed error vocabulary. Clients branch on the code, never on the
/// message, which is human-oriented and may change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// The line is not a well-formed request envelope.
    InvalidRequest,
    /// The request names a protocol version this build does not speak.
    UnsupportedVersion,
    /// The request names no known operation.
    UnknownOperation,
    /// The operation's arguments are malformed.
    InvalidArgument,
    /// The named user or short ID does not exist.
    NotFound,
    /// The change collides with existing state (a duplicate identity or a
    /// short ID owned by another user).
    Conflict,
    /// `expectedGeneration` is no longer the current generation.
    GenerationConflict,
    /// The resulting configuration fails semantic validation.
    ValidationFailed,
    /// The candidate validated but could not be compiled or published, or a
    /// file reload was rejected.
    UpdateFailed,
    /// The operation needs a configuration file this process was not started
    /// from.
    Unavailable,
    /// The request line exceeds [`MAX_REQUEST_BYTES`].
    RequestTooLarge,
    /// The control endpoint is at its connection or work limit.
    Busy,
    /// A listing `cursor` belongs to a generation that is no longer current;
    /// restart the listing without one.
    CursorExpired,
    /// An internal invariant failed; the live generation is unchanged.
    Internal,
}

/// One decoded request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// The client's opaque request identifier, echoed in the response.
    pub id: Option<String>,
    /// The requested operation.
    pub operation: Operation,
    /// The generation a mutation requires to still be current.
    pub expected_generation: Option<u64>,
}

/// The closed set of version-1 operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// `system.status`: build, protocol, role, generation, capabilities.
    SystemStatus,
    /// `generation.get`: the live generation and how it was produced.
    GenerationGet,
    /// `config.reload`: re-read the configuration file, exactly like `SIGHUP`.
    ConfigReload,
    /// `users.list`.
    UsersList(PageArgs),
    /// `users.get`.
    UsersGet(UserArgs),
    /// `users.create`.
    UsersCreate(CreateUserArgs),
    /// `users.setEnabled`.
    UsersSetEnabled(SetEnabledArgs),
    /// `users.delete`.
    UsersDelete(UserArgs),
    /// `shortIds.list`.
    ShortIdsList(ListShortIdsArgs),
    /// `shortIds.add`.
    ShortIdsAdd(ShortIdArgs),
    /// `shortIds.remove`.
    ShortIdsRemove(ShortIdArgs),
    /// `shortIds.rotate`.
    ShortIdsRotate(RotateArgs),
}

/// Every operation name, in documentation order. `system.status` reports
/// this list as the endpoint's capabilities.
pub const OPERATIONS: &[&str] = &[
    "system.status",
    "generation.get",
    "config.reload",
    "users.list",
    "users.get",
    "users.create",
    "users.setEnabled",
    "users.delete",
    "shortIds.list",
    "shortIds.add",
    "shortIds.remove",
    "shortIds.rotate",
];

impl Operation {
    /// The operation's wire name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::SystemStatus => "system.status",
            Self::GenerationGet => "generation.get",
            Self::ConfigReload => "config.reload",
            Self::UsersList(_) => "users.list",
            Self::UsersGet(_) => "users.get",
            Self::UsersCreate(_) => "users.create",
            Self::UsersSetEnabled(_) => "users.setEnabled",
            Self::UsersDelete(_) => "users.delete",
            Self::ShortIdsList(_) => "shortIds.list",
            Self::ShortIdsAdd(_) => "shortIds.add",
            Self::ShortIdsRemove(_) => "shortIds.remove",
            Self::ShortIdsRotate(_) => "shortIds.rotate",
        }
    }

    /// Whether the operation derives and publishes a new generation from the
    /// live one. `config.reload` publishes too, but from the file, so it does
    /// not take `expectedGeneration`.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::UsersCreate(_)
                | Self::UsersSetEnabled(_)
                | Self::UsersDelete(_)
                | Self::ShortIdsAdd(_)
                | Self::ShortIdsRemove(_)
                | Self::ShortIdsRotate(_)
        )
    }
}

/// Arguments naming one user by handle.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserArgs {
    /// The user's handle.
    pub user: String,
}

/// Arguments of `users.create`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateUserArgs {
    /// A caller-chosen UUID. Absent means the server generates one from the
    /// operating-system CSPRNG and returns it once in the response.
    #[serde(default)]
    pub id: Option<String>,
    /// Initial short IDs. Absent means one fresh 8-byte short ID.
    #[serde(default)]
    pub short_ids: Option<Vec<String>>,
    /// Non-secret operator label.
    #[serde(default)]
    pub label: Option<String>,
    /// Routing policy name.
    #[serde(default)]
    pub policy: Option<String>,
    /// Initial lifecycle state. Absent means enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Arguments of `users.setEnabled`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SetEnabledArgs {
    /// The user's handle.
    pub user: String,
    /// The new lifecycle state.
    pub enabled: bool,
}

/// Paging arguments of a listing.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageArgs {
    /// The `nextCursor` of the previous page. Absent starts at the first entry.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Most entries to return, 1 to [`MAX_PAGE_LIMIT`]. Absent means
    /// [`DEFAULT_PAGE_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Arguments of `shortIds.list`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListShortIdsArgs {
    /// Restrict the listing to one user's short IDs.
    #[serde(default)]
    pub user: Option<String>,
    /// The `nextCursor` of the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Most entries to return, 1 to [`MAX_PAGE_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Arguments naming one short ID of one user.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShortIdArgs {
    /// The owning user's handle.
    pub user: String,
    /// The short ID, 2 to 16 hexadecimal characters, an even count.
    pub short_id: String,
}

/// Arguments of `shortIds.rotate`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RotateArgs {
    /// The owning user's handle.
    pub user: String,
    /// Short IDs of this user to remove in the same generation. Absent or
    /// empty keeps every existing short ID (staged rotation).
    #[serde(default)]
    pub retire: Vec<String>,
    /// Width of the new short ID in bytes, 1 to 8. Absent means 8.
    #[serde(default)]
    pub bytes: Option<u8>,
}

/// A request that could not be decoded, with whatever `id` was recoverable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestError {
    /// The client's request identifier, when the envelope carried a valid one.
    pub id: Option<String>,
    /// The failure category.
    pub code: ErrorCode,
    /// A human-oriented explanation that never echoes argument values.
    pub message: String,
}

impl RequestError {
    fn new(id: Option<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id,
            code,
            message: message.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Envelope {
    v: u64,
    // Already recovered, bounded, and echoed before the envelope decodes; it
    // is declared so the strict envelope accepts it.
    #[serde(default, rename = "id")]
    _id: Option<String>,
    op: String,
    #[serde(default)]
    args: Option<Map<String, Value>>,
    #[serde(default)]
    expected_generation: Option<u64>,
}

/// Decodes one request line (without its newline).
///
/// # Errors
///
/// Returns a [`RequestError`] naming the failure category. The error's
/// message describes the rule that failed and never echoes the offending
/// value, which may be a credential.
pub fn decode_request(line: &[u8]) -> Result<Request, RequestError> {
    if line.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::new(
            None,
            ErrorCode::RequestTooLarge,
            format!("a request must not exceed {MAX_REQUEST_BYTES} bytes"),
        ));
    }
    let value: Value = serde_json::from_slice(line).map_err(|_| {
        RequestError::new(
            None,
            ErrorCode::InvalidRequest,
            "a request must be one JSON object on one line",
        )
    })?;
    let Value::Object(object) = value else {
        return Err(RequestError::new(
            None,
            ErrorCode::InvalidRequest,
            "a request must be a JSON object",
        ));
    };
    // Recover the id first, so every later failure can still be correlated.
    let id = match object.get("id") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) if id.len() <= MAX_REQUEST_ID_BYTES => Some(id.clone()),
        Some(_) => {
            return Err(RequestError::new(
                None,
                ErrorCode::InvalidRequest,
                format!("`id` must be a string of at most {MAX_REQUEST_ID_BYTES} bytes"),
            ));
        }
    };
    match object.get("v") {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(version) if SUPPORTED_VERSIONS.contains(&version) => {}
            _ => {
                return Err(RequestError::new(
                    id,
                    ErrorCode::UnsupportedVersion,
                    format!("supported protocol versions: {SUPPORTED_VERSIONS:?}"),
                ));
            }
        },
        _ => {
            return Err(RequestError::new(
                id,
                ErrorCode::InvalidRequest,
                "`v` must be the protocol version number",
            ));
        }
    }
    for field in ["args", "expectedGeneration"] {
        if object.get(field).is_some_and(Value::is_null) {
            return Err(RequestError::new(
                id,
                ErrorCode::InvalidRequest,
                format!("`{field}` must be omitted instead of null"),
            ));
        }
    }
    let envelope: Envelope = serde_json::from_value(Value::Object(object)).map_err(|_| {
        RequestError::new(
            id.clone(),
            ErrorCode::InvalidRequest,
            "a request has exactly `v`, `op`, and optionally `id`, `args`, and `expectedGeneration`",
        )
    })?;
    let args = Value::Object(envelope.args.unwrap_or_default());
    let operation = decode_operation(&envelope.op, args)
        .map_err(|(code, message)| RequestError::new(id.clone(), code, message))?;
    if envelope.expected_generation.is_some() && !operation.is_mutation() {
        return Err(RequestError::new(
            id,
            ErrorCode::InvalidRequest,
            format!(
                "`expectedGeneration` applies only to mutations, not `{}`",
                operation.name()
            ),
        ));
    }
    debug_assert!(SUPPORTED_VERSIONS.contains(&envelope.v));
    Ok(Request {
        id,
        operation,
        expected_generation: envelope.expected_generation,
    })
}

fn decode_operation(op: &str, args: Value) -> Result<Operation, (ErrorCode, String)> {
    fn typed<T: for<'de> Deserialize<'de>>(
        op: &str,
        args: Value,
    ) -> Result<T, (ErrorCode, String)> {
        serde_json::from_value(args).map_err(|_| {
            (
                ErrorCode::InvalidArgument,
                format!("the arguments of `{op}` are malformed or include an unknown field"),
            )
        })
    }
    fn none(op: &str, args: &Value) -> Result<(), (ErrorCode, String)> {
        match args {
            Value::Object(map) if map.is_empty() => Ok(()),
            _ => Err((
                ErrorCode::InvalidArgument,
                format!("`{op}` takes no arguments"),
            )),
        }
    }
    Ok(match op {
        "system.status" => none(op, &args).map(|()| Operation::SystemStatus)?,
        "generation.get" => none(op, &args).map(|()| Operation::GenerationGet)?,
        "config.reload" => none(op, &args).map(|()| Operation::ConfigReload)?,
        "users.list" => Operation::UsersList(typed(op, args)?),
        "users.get" => Operation::UsersGet(typed(op, args)?),
        "users.create" => Operation::UsersCreate(typed(op, args)?),
        "users.setEnabled" => Operation::UsersSetEnabled(typed(op, args)?),
        "users.delete" => Operation::UsersDelete(typed(op, args)?),
        "shortIds.list" => Operation::ShortIdsList(typed(op, args)?),
        "shortIds.add" => Operation::ShortIdsAdd(typed(op, args)?),
        "shortIds.remove" => Operation::ShortIdsRemove(typed(op, args)?),
        "shortIds.rotate" => Operation::ShortIdsRotate(typed(op, args)?),
        _ => {
            return Err((
                ErrorCode::UnknownOperation,
                "unknown operation; `system.status` lists the supported ones".to_owned(),
            ));
        }
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody<'a> {
    code: ErrorCode,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Response<'a> {
    v: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody<'a>>,
}

/// Encodes a success response line, newline included.
#[must_use]
pub fn encode_success(id: Option<&str>, generation: u64, result: &Value) -> Vec<u8> {
    encode(&Response {
        v: PROTOCOL_VERSION,
        id,
        ok: true,
        generation: Some(generation),
        result: Some(result),
        error: None,
    })
}

/// Encodes an error response line, newline included.
#[must_use]
pub fn encode_error(
    id: Option<&str>,
    generation: Option<u64>,
    code: ErrorCode,
    message: &str,
    path: Option<&str>,
) -> Vec<u8> {
    encode(&Response {
        v: PROTOCOL_VERSION,
        id,
        ok: false,
        generation,
        result: None,
        error: Some(ErrorBody {
            code,
            message,
            path,
        }),
    })
}

fn encode(response: &Response<'_>) -> Vec<u8> {
    // Serialising these shapes cannot fail: every key is a string and every
    // value is already a `serde_json::Value` or a primitive. Fall back to a
    // fixed line rather than panicking if that ever changes.
    let mut line = serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"v":1,"ok":false,"error":{"code":"internal","message":"response encoding failed"}}"#
            .to_vec()
    });
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        ErrorCode, MAX_REQUEST_BYTES, OPERATIONS, Operation, decode_request, encode_error,
        encode_success,
    };

    fn decode(value: &Value) -> Result<super::Request, super::RequestError> {
        decode_request(value.to_string().as_bytes())
    }

    #[test]
    fn decodes_every_operation_by_name() {
        let user = format!("u_{}", "0".repeat(32));
        let cases = [
            json!({"v":1,"op":"system.status"}),
            json!({"v":1,"op":"generation.get"}),
            json!({"v":1,"op":"config.reload"}),
            json!({"v":1,"op":"users.list"}),
            json!({"v":1,"op":"users.get","args":{"user":user}}),
            json!({"v":1,"op":"users.create","args":{}}),
            json!({"v":1,"op":"users.setEnabled","args":{"user":user,"enabled":false}}),
            json!({"v":1,"op":"users.delete","args":{"user":user}}),
            json!({"v":1,"op":"shortIds.list"}),
            json!({"v":1,"op":"shortIds.add","args":{"user":user,"shortId":"ab"}}),
            json!({"v":1,"op":"shortIds.remove","args":{"user":user,"shortId":"ab"}}),
            json!({"v":1,"op":"shortIds.rotate","args":{"user":user}}),
        ];
        assert_eq!(cases.len(), OPERATIONS.len());
        for (case, name) in cases.iter().zip(OPERATIONS) {
            let request = decode(case).unwrap_or_else(|error| panic!("{case}: {error:?}"));
            assert_eq!(request.operation.name(), *name);
        }
    }

    #[test]
    fn the_request_id_is_echoed_even_when_the_operation_fails() {
        let error = decode(&json!({"v":1,"id":"r-1","op":"users.nope"})).expect_err("unknown");
        assert_eq!(error.code, ErrorCode::UnknownOperation);
        assert_eq!(error.id.as_deref(), Some("r-1"));

        let error = decode(&json!({"v":9,"id":"r-2","op":"users.list"})).expect_err("version");
        assert_eq!(error.code, ErrorCode::UnsupportedVersion);
        assert_eq!(error.id.as_deref(), Some("r-2"));
    }

    #[test]
    fn the_envelope_is_strict() {
        for (value, code) in [
            (json!([]), ErrorCode::InvalidRequest),
            (json!({"op":"users.list"}), ErrorCode::InvalidRequest),
            (
                json!({"v":"1","op":"users.list"}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1.5,"op":"users.list"}),
                ErrorCode::UnsupportedVersion,
            ),
            (
                json!({"v":0,"op":"users.list"}),
                ErrorCode::UnsupportedVersion,
            ),
            (json!({"v":1}), ErrorCode::InvalidRequest),
            (
                json!({"v":1,"op":"users.list","extra":1}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.list","id":7}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.list","id":"x".repeat(129)}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.list","args":{"x":1}}),
                ErrorCode::InvalidArgument,
            ),
            (
                json!({"v":1,"op":"users.list","args":[]}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.get","args":{"user":"u","uuid":"x"}}),
                ErrorCode::InvalidArgument,
            ),
            (
                json!({"v":1,"op":"users.list","expectedGeneration":3}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.delete","args":{"user":"u"},"expectedGeneration":-1}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.list","args":null}),
                ErrorCode::InvalidRequest,
            ),
            (
                json!({"v":1,"op":"users.delete","args":{"user":"u"},"expectedGeneration":null}),
                ErrorCode::InvalidRequest,
            ),
        ] {
            let error = decode(&value).expect_err(&value.to_string());
            assert_eq!(error.code, code, "{value}");
        }
        assert_eq!(
            decode_request(b"{not json").expect_err("garbage").code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            decode_request(&vec![b' '; MAX_REQUEST_BYTES + 1])
                .expect_err("oversized")
                .code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn mutations_carry_an_expected_generation() {
        let request = decode(&json!({
            "v":1,"op":"users.delete","args":{"user":"u"},"expectedGeneration":4
        }))
        .expect("valid mutation");
        assert_eq!(request.expected_generation, Some(4));
        assert!(request.operation.is_mutation());
        assert!(!Operation::ConfigReload.is_mutation());
    }

    #[test]
    fn errors_never_echo_argument_values() {
        let secret = "11111111-1111-4111-8111-111111111111";
        let error = decode(&json!({
            "v":1,"op":"users.create","args":{"id":secret,"unknown":secret}
        }))
        .expect_err("unknown argument");
        assert!(!error.message.contains(secret), "{}", error.message);
    }

    #[test]
    fn responses_are_single_lines_with_a_closed_shape() {
        let success = encode_success(Some("a"), 3, &json!({"x":1}));
        assert_eq!(success.last(), Some(&b'\n'));
        assert_eq!(success.iter().filter(|byte| **byte == b'\n').count(), 1);
        let parsed: Value = serde_json::from_slice(&success).expect("json");
        assert_eq!(
            parsed,
            json!({"v":1,"id":"a","ok":true,"generation":3,"result":{"x":1}})
        );

        let failure = encode_error(None, Some(2), ErrorCode::GenerationConflict, "m\nx", None);
        assert_eq!(failure.iter().filter(|byte| **byte == b'\n').count(), 1);
        let parsed: Value = serde_json::from_slice(&failure).expect("json");
        assert_eq!(
            parsed,
            json!({"v":1,"ok":false,"generation":2,
                   "error":{"code":"generationConflict","message":"m\nx"}})
        );
    }
}
