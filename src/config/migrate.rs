//! v1.5 → v1.6 configuration migration.
//!
//! The migration loads a v1.5 configuration with the current strict loader
//! (unknown keys still fail), rewrites the retired v1.5 resource-policy
//! placement onto the v1.6 model, and emits a minimal v1.6-native document:
//!
//! - `runtime.resourceMode: standard` becomes `runtime.profile: "shared"`,
//!   `dedicated` becomes `"dedicated"`, and `resourceMode` is dropped.
//! - `policy.resourceGovernor.*`, `policy.directBarrier.*`, and
//!   `policy.relay.*` move to the identically named fields of
//!   `advanced.limits.*`.
//! - Any surviving pinned limit forces `runtime.tuning.mode: "fixed"`, which
//!   preserves v1.5 behavior byte-for-byte; without limits the `tuning`
//!   section is omitted and the defaults apply.
//! - Explicit values equal to the built-in default are reported
//!   `redundant — omitted` and dropped; an information-free `policy` object
//!   is reported `discarded`.
//!
//! Nothing is silently dropped and no security-sensitive value is guessed:
//! every translation, omission, and discard is reported through
//! [`Migration::notes`], and the generated document is re-validated with the
//! same validation `config check` runs before it is returned.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};

use super::{
    Config, ConfigLoadError, PolicyConfig, format_config,
    io::{decode_config, read_config_bytes},
};

/// Source model version accepted by the migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrateFrom {
    /// v1.5: top-level `policy` and `runtime.resourceMode` placement.
    V15,
    /// v1.6: rejects obsolete placement left over from an earlier run.
    V16,
}

impl MigrateFrom {
    /// Every accepted `--from` value, for CLI parsing and help.
    pub const VALUES: [&'static str; 2] = ["1.5", "1.6"];

    /// Parses a `--from` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "1.5" => Some(Self::V15),
            "1.6" => Some(Self::V16),
            _ => None,
        }
    }

    /// Returns the stable CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V15 => "1.5",
            Self::V16 => "1.6",
        }
    }
}

/// Category of one migration report line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationNoteKind {
    /// A v1.5 key was translated to its v1.6 replacement.
    Translated,
    /// An explicit value equaled the built-in default and was omitted.
    Redundant,
    /// A key carried no information and was dropped.
    Discarded,
    /// Behavioral context the operator should read.
    Context,
}

impl MigrationNoteKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Translated => "translated",
            Self::Redundant => "redundant",
            Self::Discarded => "discarded",
            Self::Context => "note",
        }
    }
}

/// One human-readable migration report line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationNote {
    kind: MigrationNoteKind,
    path: String,
    message: String,
}

impl MigrationNote {
    fn new(kind: MigrationNoteKind, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.into(),
            message: message.into(),
        }
    }

    /// Returns the category of this note.
    #[must_use]
    pub const fn kind(&self) -> MigrationNoteKind {
        self.kind
    }

    /// Returns the JSON path this note concerns, empty for context notes.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MigrationNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(formatter, "{}: {}", self.kind.as_str(), self.message)
        } else {
            write!(
                formatter,
                "{}: {}: {}",
                self.kind.as_str(),
                self.path,
                self.message
            )
        }
    }
}

/// The result of one successful migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Migration {
    json: String,
    notes: Vec<MigrationNote>,
}

impl Migration {
    /// Returns the migrated configuration as canonical pretty JSON.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }

    /// Returns every translation, omission, and discard, in report order.
    #[must_use]
    pub fn notes(&self) -> &[MigrationNote] {
        &self.notes
    }
}

/// An error produced while migrating a configuration.
#[derive(Debug)]
pub enum MigrateError {
    /// The source could not be read, decoded, or validated.
    Load(ConfigLoadError),
    /// `--from 1.6` was given a file that still uses the retired v1.5
    /// `policy` placement.
    ObsoletePolicy {
        /// Configuration path.
        path: PathBuf,
    },
    /// The migrated document could not be serialized.
    Encode(serde_json::Error),
    /// The migrated document failed the same validation `config check` runs.
    InvalidResult(ConfigLoadError),
    /// The migrated document was unstable or changed effective behavior.
    UnstableResult(&'static str),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(source) => source.fmt(formatter),
            Self::ObsoletePolicy { path } => write!(
                formatter,
                "configuration {} still uses the top-level \"policy\" object, which is \
                 obsolete in v1.6; move its values to \"advanced.limits\" \
                 (or migrate it with --from 1.5)",
                path.display()
            ),
            Self::Encode(_) => formatter.write_str("failed to encode the migrated configuration"),
            Self::InvalidResult(source) => write!(
                formatter,
                "the migrated configuration failed validation; no output was written: {source}"
            ),
            Self::UnstableResult(reason) => write!(
                formatter,
                "the migrated configuration failed its round-trip check; no output was \
                 written: {reason}"
            ),
        }
    }
}

impl Error for MigrateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Load(source) | Self::InvalidResult(source) => Some(source),
            Self::Encode(source) => Some(source),
            Self::ObsoletePolicy { .. } | Self::UnstableResult(_) => None,
        }
    }
}

impl From<ConfigLoadError> for MigrateError {
    fn from(source: ConfigLoadError) -> Self {
        Self::Load(source)
    }
}

/// Keys explicitly present in the source document, used to tell operator
/// intent apart from defaults the serializer fills in.
struct ExplicitKeys {
    policy_present: bool,
    /// `section.field` paths under the top-level `policy` object.
    policy: BTreeSet<String>,
    /// `section.field` paths under `advanced.limits`.
    limits: BTreeSet<String>,
    resource_mode: Option<String>,
    profile: bool,
    tuning: bool,
}

impl ExplicitKeys {
    fn scan(raw: &Value) -> Self {
        fn section_fields(object: Option<&Value>) -> BTreeSet<String> {
            let mut fields = BTreeSet::new();
            if let Some(object) = object.and_then(Value::as_object) {
                for (section, value) in object {
                    if let Some(section_object) = value.as_object() {
                        for field in section_object.keys() {
                            fields.insert(format!("{section}.{field}"));
                        }
                    }
                }
            }
            fields
        }

        let runtime = raw.get("runtime").and_then(Value::as_object);
        Self {
            policy_present: raw.get("policy").is_some(),
            policy: section_fields(raw.get("policy")),
            limits: section_fields(raw.pointer("/advanced/limits")),
            resource_mode: runtime
                .and_then(|runtime| runtime.get("resourceMode"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            profile: runtime.is_some_and(|runtime| runtime.contains_key("profile")),
            tuning: runtime.is_some_and(|runtime| runtime.contains_key("tuning")),
        }
    }
}

/// Migrates one configuration file to the v1.6 model.
///
/// The file is loaded with the strict v1.6 loader — unknown fields, invalid
/// values, and conflicting `policy`/`advanced.limits` placements fail exactly
/// as `config check` fails — then rewritten and re-validated. The source file
/// is never modified.
///
/// # Errors
///
/// Returns an error when the source cannot be loaded, when `--from 1.6`
/// input still uses the obsolete top-level `policy` object, or when the
/// generated document fails validation or the round-trip check.
pub fn migrate_config(
    from: MigrateFrom,
    path: impl AsRef<Path>,
) -> Result<Migration, MigrateError> {
    let path = path.as_ref();
    let bytes = read_config_bytes(path)?;
    migrate_config_bytes(from, path, &bytes)
}

/// Migrates one in-memory configuration document; `path` is used only for
/// error messages.
///
/// # Errors
///
/// Returns an error under the same conditions as [`migrate_config`].
pub fn migrate_config_bytes(
    from: MigrateFrom,
    path: &Path,
    bytes: &[u8],
) -> Result<Migration, MigrateError> {
    let raw: Value = serde_json::from_slice(bytes).map_err(|source| {
        MigrateError::Load(ConfigLoadError::Decode {
            path: path.to_owned(),
            source,
        })
    })?;
    if from == MigrateFrom::V16 && raw.get("policy").is_some() {
        return Err(MigrateError::ObsoletePolicy {
            path: path.to_owned(),
        });
    }
    let explicit = ExplicitKeys::scan(&raw);
    let (config, _) = decode_config(path, bytes)?;

    let mut document = serde_json::to_value(&config).map_err(MigrateError::Encode)?;
    if let Some(object) = document.as_object_mut() {
        // The alias never serializes; drop it defensively so the output is
        // always v1.6-native.
        object.remove("policy");
    }

    let mut notes = Vec::new();
    if from == MigrateFrom::V15
        && let Some(mode) = explicit.resource_mode.clone()
    {
        notes.push(translate_resource_mode(
            &mut document,
            &mode,
            explicit.profile,
        ));
    }
    let any_limit = rewrite_limits(&mut document, &explicit, &mut notes);
    if explicit.policy_present {
        notes.push(policy_disposition(&document, &explicit));
    }
    rewrite_tuning(&mut document, &explicit, from, any_limit, &mut notes);
    strip_default_runtime(&mut document, &explicit);

    let mut json = serde_json::to_string_pretty(&document).map_err(MigrateError::Encode)?;
    json.push('\n');
    validate_result(path, &json, &config)?;
    Ok(Migration { json, notes })
}

/// Maps `runtime.resourceMode` onto `runtime.profile` and drops the retired
/// key. Validation has already rejected a contradicting explicit `profile`,
/// so an explicit profile is left untouched.
fn translate_resource_mode(
    document: &mut Value,
    mode: &str,
    profile_explicit: bool,
) -> MigrationNote {
    let profile = match mode {
        "dedicated" => "dedicated",
        _ => "shared",
    };
    if let Some(runtime) = document.get_mut("runtime").and_then(Value::as_object_mut) {
        runtime.remove("resourceMode");
        if !profile_explicit {
            runtime.insert("profile".to_owned(), Value::String(profile.to_owned()));
        }
    }
    MigrationNote::new(
        MigrationNoteKind::Translated,
        "runtime.resourceMode",
        format!("\"{mode}\" became runtime.profile \"{profile}\"; resourceMode is retired in v1.6"),
    )
}

/// Returns whether `field` of `section` may be left out when the section
/// object is present. Fields without a serde default are required once their
/// object appears in the document, so a surviving section must keep them even
/// when they carry a default value.
fn field_omittable(section: &str, field: &str) -> bool {
    match section {
        "resourceGovernor" => matches!(field, "maxDnsLookups" | "replayRetentionMs"),
        "relay" => matches!(
            field,
            "maxSpliceRelays" | "maxRelayMemoryBytes" | "pipePool" | "maxPooledPipes"
        ),
        _ => false,
    }
}

/// Drops default-valued limit fields that the schema allows to be omitted,
/// reporting every one the operator wrote explicitly, and removes objects
/// left empty. A section with any surviving non-default field keeps its
/// schema-required default fields (reported as redundant but kept). Returns
/// whether any pinned limit survives.
fn rewrite_limits(
    document: &mut Value,
    explicit: &ExplicitKeys,
    notes: &mut Vec<MigrationNote>,
) -> bool {
    let defaults =
        serde_json::to_value(PolicyConfig::default()).unwrap_or_else(|_| Value::Object(Map::new()));
    let mut any_limit = false;
    let Some(limits) = document
        .pointer_mut("/advanced/limits")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };

    let mut empty_sections = Vec::new();
    for (section, value) in limits.iter_mut() {
        let Some(section_object) = value.as_object_mut() else {
            continue;
        };
        let default_section = defaults.get(section).cloned().unwrap_or(Value::Null);
        let section_has_limit = section_object.iter().any(|(field, value)| {
            *value != default_section.get(field).cloned().unwrap_or(Value::Null)
        });
        any_limit |= section_has_limit;
        section_object.retain(|field, value| {
            let is_default = *value == default_section.get(field).cloned().unwrap_or(Value::Null);
            if !is_default {
                return true;
            }
            let key = format!("{section}.{field}");
            let source_path = if explicit.policy.contains(&key) {
                Some(format!("policy.{key}"))
            } else if explicit.limits.contains(&key) {
                Some(format!("advanced.limits.{key}"))
            } else {
                None
            };
            let keep = section_has_limit && !field_omittable(section, field);
            if let Some(source_path) = source_path {
                let detail = if keep {
                    format!("equals the built-in default ({value}); kept because the field is required when its object is present")
                } else {
                    format!("equals the built-in default ({value}); omitted")
                };
                notes.push(MigrationNote::new(
                    MigrationNoteKind::Redundant,
                    source_path,
                    detail,
                ));
            }
            keep
        });
        if section_object.is_empty() {
            empty_sections.push(section.clone());
        }
    }
    for section in empty_sections {
        limits.remove(&section);
    }
    if limits.is_empty()
        && let Some(advanced) = document.get_mut("advanced").and_then(Value::as_object_mut)
    {
        advanced.remove("limits");
    }
    if document
        .get("advanced")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
        && let Some(object) = document.as_object_mut()
    {
        object.remove("advanced");
    }
    any_limit
}

/// Summarizes the fate of the retired top-level `policy` object.
fn policy_disposition(document: &Value, explicit: &ExplicitKeys) -> MigrationNote {
    let moved = explicit
        .policy
        .iter()
        .filter(|key| {
            let mut parts = key.split('.');
            let pointer = format!(
                "/advanced/limits/{}/{}",
                parts.next().unwrap_or_default(),
                parts.next().unwrap_or_default()
            );
            document.pointer(&pointer).is_some()
        })
        .count();
    let message = if moved == 0 {
        "the object held no non-default values".to_owned()
    } else {
        format!("{moved} value(s) moved to \"advanced.limits\"")
    };
    MigrationNote::new(
        MigrationNoteKind::Discarded,
        "policy",
        format!("{message}; the top-level key is retired in v1.6"),
    )
}

/// Applies the tuning-mode rule: surviving pinned limits force
/// `runtime.tuning.mode: "fixed"` (v1.5 behavior, byte-for-byte) unless the
/// source already set `tuning` explicitly; without limits the section is
/// omitted. `--from 1.6` input keeps its own tuning choice.
fn rewrite_tuning(
    document: &mut Value,
    explicit: &ExplicitKeys,
    from: MigrateFrom,
    any_limit: bool,
    notes: &mut Vec<MigrationNote>,
) {
    if explicit.tuning {
        return;
    }
    let Some(runtime) = document.get_mut("runtime").and_then(Value::as_object_mut) else {
        return;
    };
    if from == MigrateFrom::V15 && any_limit {
        let tuning = runtime
            .entry("tuning")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(tuning_object) = tuning.as_object_mut() {
            tuning_object.insert("mode".to_owned(), Value::String("fixed".to_owned()));
            if tuning_object.get("objective") == Some(&Value::String("balanced".to_owned())) {
                tuning_object.remove("objective");
            }
        }
        notes.push(MigrationNote::new(
            MigrationNoteKind::Context,
            "runtime.tuning.mode",
            "\"fixed\" keeps the pinned advanced.limits numbers exactly as v1.5 ran them; \
             \"startup\" and \"adaptive\" derive the numbers from the detected machine instead",
        ));
    } else {
        runtime.remove("tuning");
    }
}

/// Removes serializer-filled default noise from `runtime` and drops the
/// object when nothing explicit remains.
fn strip_default_runtime(document: &mut Value, explicit: &ExplicitKeys) {
    let Some(runtime) = document.get_mut("runtime").and_then(Value::as_object_mut) else {
        return;
    };
    if !explicit.profile
        && explicit.resource_mode.is_none()
        && runtime.get("profile") == Some(&Value::String("auto".to_owned()))
    {
        runtime.remove("profile");
    }
    let empty = runtime.is_empty();
    if empty && let Some(object) = document.as_object_mut() {
        object.remove("runtime");
    }
}

/// Re-runs the full `config check` validation on the generated document and
/// proves the migration preserved effective behavior: the parse must be
/// v1.6-native, serialize/parse stable, and carry the identical effective
/// limits and resource posture as the source.
fn validate_result(path: &Path, json: &str, source: &Config) -> Result<(), MigrateError> {
    let (parsed, report) =
        decode_config(path, json.as_bytes()).map_err(MigrateError::InvalidResult)?;
    if report.policy_alias_used {
        return Err(MigrateError::UnstableResult(
            "the output still uses the deprecated policy alias",
        ));
    }
    let formatted = format_config(&parsed).map_err(MigrateError::Encode)?;
    let (reparsed, _) =
        decode_config(path, formatted.as_bytes()).map_err(MigrateError::InvalidResult)?;
    if reparsed != parsed {
        return Err(MigrateError::UnstableResult(
            "serialize/parse round-trip changed the document",
        ));
    }
    if parsed.advanced.limits != source.advanced.limits {
        return Err(MigrateError::UnstableResult(
            "the effective resource and relay limits changed",
        ));
    }
    if let Some(mode) = source.runtime.resource_mode
        && parsed.runtime.profile.resource_mode() != Some(mode)
    {
        return Err(MigrateError::UnstableResult("the resource posture changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{MigrateError, MigrateFrom, MigrationNoteKind, migrate_config_bytes};
    use crate::config::test_config_json;

    fn migrate(from: MigrateFrom, json: &str) -> super::Migration {
        migrate_config_bytes(from, Path::new("test.json"), json.as_bytes())
            .expect("migration must succeed")
    }

    #[test]
    fn minimal_v15_config_migrates_to_itself() {
        let json = test_config_json().replace(",\n  \"policy\": {}\n}", "\n}");
        let migration = migrate(MigrateFrom::V15, &json);

        assert!(
            migration
                .notes()
                .iter()
                .all(|note| note.kind() != MigrationNoteKind::Redundant)
        );
        assert!(!migration.json().contains("\"policy\""));
        assert!(!migration.json().contains("\"advanced\""));
        assert!(!migration.json().contains("\"runtime\""));
    }

    #[test]
    fn an_information_free_policy_object_is_reported_discarded() {
        let migration = migrate(MigrateFrom::V15, test_config_json());

        assert!(!migration.json().contains("\"policy\""));
        assert!(!migration.json().contains("\"runtime\""));
        let discarded: Vec<_> = migration
            .notes()
            .iter()
            .filter(|note| note.kind() == MigrationNoteKind::Discarded)
            .collect();
        assert_eq!(discarded.len(), 1);
        assert_eq!(discarded[0].path(), "policy");
        assert!(discarded[0].message().contains("no non-default values"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = test_config_json().replace("\"policy\": {}", "\"policy\": {}, \"metrics\": {}");
        let error =
            migrate_config_bytes(MigrateFrom::V15, Path::new("unknown.json"), json.as_bytes())
                .expect_err("unknown fields must fail the migration");

        assert!(matches!(error, MigrateError::Load(_)));
    }

    #[test]
    fn from_v16_rejects_the_obsolete_policy_placement() {
        let error = migrate_config_bytes(
            MigrateFrom::V16,
            Path::new("obsolete.json"),
            test_config_json().as_bytes(),
        )
        .expect_err("a v1.6 re-run must name the new location");

        assert!(matches!(error, MigrateError::ObsoletePolicy { .. }));
        assert!(error.to_string().contains("advanced.limits"));
    }

    #[test]
    fn from_v16_canonicalizes_a_native_document_without_forcing_fixed() {
        let json = test_config_json().replace(
            ",\n  \"policy\": {}\n}",
            concat!(
                ",\n",
                "  \"advanced\": {\n",
                "    \"limits\": {\n",
                "      \"resourceGovernor\": {\n",
                "        \"maxConnections\": 2048,\n",
                "        \"maxHandshakes\": 1024,\n",
                "        \"maxFallbacks\": 512,\n",
                "        \"maxCryptoOperations\": 128,\n",
                "        \"maxReplayEntries\": 65536,\n",
                "        \"maxDnsLookups\": 64,\n",
                "        \"replayRetentionMs\": 120000,\n",
                "        \"clientHelloTimeoutMs\": 3000,\n",
                "        \"handshakeTimeoutMs\": 10000,\n",
                "        \"connectTimeoutMs\": 10000,\n",
                "        \"fallbackTimeoutMs\": 120000\n",
                "      }\n",
                "    }\n",
                "  }\n",
                "}",
            ),
        );
        let migration = migrate(MigrateFrom::V16, &json);

        assert!(migration.json().contains("\"maxConnections\": 2048"));
        assert!(
            !migration.json().contains("\"mode\": \"fixed\""),
            "a v1.6-native document keeps its own tuning choice: {}",
            migration.json()
        );
    }

    #[test]
    fn conflicting_policy_and_limits_fail_closed() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = serde_json::json!({
            "relay": { "bufferBytes": 16384, "maxPooledBuffers": 4096, "splice": true }
        });
        value["advanced"] = serde_json::json!({
            "limits": { "relay": { "bufferBytes": 65536, "maxPooledBuffers": 4096, "splice": true } }
        });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let error = migrate_config_bytes(MigrateFrom::V15, Path::new("conflict.json"), &json)
            .expect_err("contradictory numbers must fail closed");

        assert!(matches!(error, MigrateError::Load(_)));
    }
}
