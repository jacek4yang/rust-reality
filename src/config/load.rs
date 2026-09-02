//! Reading, parsing, and validating one configuration file.
//!
//! This is the single entry point every command uses. It exists so that
//! "read the configuration" means the same three steps everywhere — bounded
//! read, strict structural parse, semantic validation — and so that both
//! kinds of failure arrive as the same rendered diagnostic.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use super::{
    diagnostic::Diagnostic,
    parse::{self, ParseError},
    semantics::{self, SemanticError, ValidatedConfig},
};

/// A failure while loading a configuration.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read, or is not a well-formed node.
    Parse(ParseError),
    /// The node is well formed but does not describe a server that can run.
    Invalid {
        /// Source-oriented rendering of the failure.
        diagnostic: Box<Diagnostic>,
        /// Validation failure, kept as the programmatic cause.
        source: SemanticError,
    },
}

impl LoadError {
    /// The source-oriented diagnostic, when the failure carries one.
    #[must_use]
    pub fn diagnostic(&self) -> Option<&Diagnostic> {
        match self {
            Self::Parse(error) => error.diagnostic(),
            Self::Invalid { diagnostic, .. } => Some(diagnostic),
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => error.fmt(formatter),
            Self::Invalid { diagnostic, .. } => diagnostic.fmt(formatter),
        }
    }
}

impl Error for LoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Invalid { source, .. } => Some(source),
        }
    }
}

impl From<ParseError> for LoadError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

/// Reads, parses, and validates one configuration file.
///
/// # Errors
///
/// Returns an error when the file cannot be read, is not a well-formed node of
/// a known role, or fails semantic validation.
pub fn load(path: impl AsRef<Path>) -> Result<ValidatedConfig, LoadError> {
    let path = path.as_ref();
    let bytes = read_bounded(path)?;
    load_bytes(path, &bytes)
}

/// Parses and validates configuration bytes that have already been read.
///
/// `path` is used only to label diagnostics.
///
/// # Errors
///
/// Returns an error when the bytes are not a well-formed node of a known role
/// or fail semantic validation.
pub fn load_bytes(path: &Path, bytes: &[u8]) -> Result<ValidatedConfig, LoadError> {
    let node = parse::parse_bytes(path, bytes)?;
    semantics::validate(node).map_err(|source| {
        let text = String::from_utf8_lossy(bytes);
        LoadError::Invalid {
            diagnostic: Box::new(Diagnostic::validation(
                path,
                &text,
                source.path(),
                source.message(),
            )),
            source,
        }
    })
}

/// Reads one file, enforcing the same bound the parser does.
fn read_bounded(path: &Path) -> Result<Vec<u8>, LoadError> {
    // Delegating keeps one implementation of the size bound. `parse_file`
    // would read and parse in one step; here the bytes are needed afterwards
    // to render a semantic diagnostic against the original source.
    parse::read_bounded_for_load(path).map_err(LoadError::Parse)
}

/// The path a `LoadError::Parse` refers to, when it names one.
#[must_use]
pub fn errored_path(error: &LoadError) -> Option<&PathBuf> {
    match error {
        LoadError::Parse(ParseError::Io { path, .. } | ParseError::TooLarge { path, .. }) => {
            Some(path)
        }
        LoadError::Parse(ParseError::Decode { .. }) | LoadError::Invalid { .. } => None,
    }
}

/// Fuzz entry point: parses and validates raw configuration bytes.
///
/// Exercises the exact [`load`] path without touching the file system. Gated
/// behind the `fuzzing` feature, which only the `fuzz/` workspace enables;
/// never part of a production build.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_load(bytes: &[u8]) -> Result<ValidatedConfig, LoadError> {
    if bytes.len() > parse::MAX_CONFIG_BYTES {
        return Err(LoadError::Parse(ParseError::TooLarge {
            path: PathBuf::from("<fuzz>"),
            bytes: bytes.len() as u64,
        }));
    }
    load_bytes(Path::new("<fuzz>"), bytes)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    use super::{LoadError, load, load_bytes};

    fn key(seed: u8) -> String {
        BASE64_URL_SAFE_NO_PAD.encode([seed; 32])
    }

    fn valid() -> String {
        format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
  "users": [{{ "id": "11111111-1111-4111-8111-111111111111", "shortIds": ["ab"] }}],
  "routing": {{ "default": "direct" }}
}}"#,
            key(1)
        )
    }

    #[test]
    fn a_valid_configuration_loads() {
        let validated = load_bytes(Path::new("config.json"), valid().as_bytes())
            .expect("the configuration must load");

        assert_eq!(validated.role(), crate::config::node::Role::Entry);
    }

    #[test]
    fn a_structural_failure_renders_with_a_source_location() {
        let error = load_bytes(Path::new("config.json"), b"{ \"role\": \"entry\", }")
            .expect_err("malformed JSON must not load");

        assert!(matches!(error, LoadError::Parse(_)));
        let rendered = error.to_string();
        assert!(rendered.contains("config.json:"), "{rendered}");
    }

    #[test]
    fn a_semantic_failure_renders_against_the_offending_source_line() {
        let json = valid().replace(r#""default": "direct""#, r#""default": "nowhere""#);

        let error =
            load_bytes(Path::new("config.json"), json.as_bytes()).expect_err("must not load");

        let LoadError::Invalid { source, .. } = &error else {
            panic!("must be a semantic failure, got {error}");
        };
        assert_eq!(source.path(), "routing.default");
        let rendered = error.to_string();
        assert!(rendered.contains("config.json:"), "{rendered}");
        assert!(
            rendered.contains("nowhere"),
            "the excerpt must show the offending value: {rendered}"
        );
    }

    #[test]
    fn a_secret_is_never_echoed_into_a_diagnostic() {
        let secret = key(1);
        let json = valid().replace(r#""shortIds": ["ab"]"#, r#""shortIds": ["abc"]"#);

        let rendered = load_bytes(Path::new("config.json"), json.as_bytes())
            .expect_err("an odd-length short ID must not load")
            .to_string();

        assert!(
            !rendered.contains(&secret),
            "the private key must not appear in an unrelated diagnostic"
        );
    }

    use crate::config::canonical as format;

    #[test]
    fn formatting_is_idempotent_and_preserves_semantics() {
        let path = Path::new("config.json");
        let original = load_bytes(path, valid().as_bytes()).expect("the fixture must load");

        let once = format(&original);
        let reloaded = load_bytes(path, once.as_bytes()).expect("formatted output must reload");
        let twice = format(&reloaded);

        assert_eq!(once, twice, "formatting twice must be byte-identical");
        assert_eq!(
            original.node(),
            reloaded.node(),
            "formatting must not change what the configuration means"
        );
    }

    #[test]
    fn formatting_preserves_a_written_value_that_equals_its_default() {
        // The case presence tracking exists for: an operator who wrote a
        // default deliberately must still see it after formatting.
        let json = valid().replace(
            r#""listeners": [{ "port": 443 }]"#,
            r#""listeners": [{ "port": 443, "ip": "auto" }]"#,
        );
        let config =
            load_bytes(Path::new("config.json"), json.as_bytes()).expect("the fixture must load");

        let rendered = format(&config);

        assert!(
            rendered.contains(r#""ip": "auto""#),
            "an explicit default must survive: {rendered}"
        );
    }

    #[test]
    fn formatting_never_expands_a_default_the_operator_omitted() {
        let config = load_bytes(Path::new("config.json"), valid().as_bytes()).expect("must load");

        let rendered = format(&config);

        for absent in ["\"ip\"", "\"log\"", "\"runtime\"", "\"dns\"", "\"network\""] {
            assert!(
                !rendered.contains(absent),
                "{absent} was omitted and must stay omitted: {rendered}"
            );
        }
    }

    #[test]
    fn formatting_orders_keys_the_way_the_reference_documents_them() {
        // Schema declaration order, not alphabetical: `jq -S` would scatter
        // `reality` away from the identity it belongs to.
        let config = load_bytes(Path::new("config.json"), valid().as_bytes()).expect("must load");

        let rendered = format(&config);
        let position = |key: &str| {
            rendered
                .find(key)
                .unwrap_or_else(|| panic!("{key} must be rendered: {rendered}"))
        };

        assert!(position("\"role\"") < position("\"listeners\""));
        assert!(position("\"listeners\"") < position("\"reality\""));
        assert!(position("\"reality\"") < position("\"users\""));
        assert!(position("\"users\"") < position("\"routing\""));
    }

    #[test]
    fn a_missing_file_reports_its_path_and_carries_no_excerpt() {
        let error =
            load(Path::new("/nonexistent/rust-reality/config.json")).expect_err("must not load");

        assert!(error.diagnostic().is_none());
        assert!(error.to_string().contains("config.json"));
        assert_eq!(
            super::errored_path(&error).map(|path| path.to_string_lossy().into_owned()),
            Some("/nonexistent/rust-reality/config.json".to_owned())
        );
    }
}
