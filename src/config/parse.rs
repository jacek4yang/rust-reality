//! Reading one configuration file into a [`NodeConfig`].
//!
//! Parsing happens in two passes over the same bytes. The first reads `role`
//! and nothing else; the second deserializes the whole document directly into
//! the type that role selects.
//!
//! The alternative — one pass through a serde tagged enum — would cost the
//! diagnostics. Internal tagging buffers the document into an intermediate
//! value before dispatching, which loses the byte offsets the source map needs
//! and flattens the paths `serde_path_to_error` reports down to the root. A
//! second cheap pass on the cold configuration path is a good trade for an
//! error that can point at the offending line.
//!
//! This module is structural only: it decides that the document is a
//! well-formed node of a known role with no unknown fields. Whether the
//! resulting node makes sense — that its references resolve, its keys decode,
//! its topology is coherent — belongs to [`crate::config::semantics`].

use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::{
    diagnostic::Diagnostic,
    node::{EntryConfig, LandingConfig, NodeConfig, Role},
};

/// Largest accepted configuration file.
///
/// A configuration is written by a person; anything approaching this size is a
/// mistake, and refusing early keeps a malformed or hostile file from being
/// read into memory at all.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// A failure while reading a configuration file.
#[derive(Debug)]
pub enum ParseError {
    /// The file could not be opened or read.
    Io {
        /// Configuration path.
        path: PathBuf,
        /// Underlying failure.
        source: io::Error,
    },
    /// The file exceeds [`MAX_CONFIG_BYTES`].
    TooLarge {
        /// Configuration path.
        path: PathBuf,
        /// Observed size, or the bound plus one when the size is unknown.
        bytes: u64,
    },
    /// The bytes are not a well-formed node of a known role.
    Decode {
        /// Source-oriented rendering of the failure.
        diagnostic: Box<Diagnostic>,
        /// Parser failure, kept as the programmatic cause.
        source: serde_json::Error,
    },
}

impl ParseError {
    /// The source-oriented diagnostic, when the failure carries one.
    #[must_use]
    pub fn diagnostic(&self) -> Option<&Diagnostic> {
        match self {
            Self::Decode { diagnostic, .. } => Some(diagnostic),
            Self::Io { .. } | Self::TooLarge { .. } => None,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(
                formatter,
                "failed to read configuration {}: {source}",
                path.display()
            ),
            Self::TooLarge { path, bytes } => write!(
                formatter,
                "configuration {} is too large ({bytes} bytes; maximum {MAX_CONFIG_BYTES})",
                path.display()
            ),
            Self::Decode { diagnostic, .. } => diagnostic.fmt(formatter),
        }
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Decode { source, .. } => Some(source),
            Self::TooLarge { .. } => None,
        }
    }
}

/// Reads and structurally parses one configuration file.
///
/// # Errors
///
/// Returns an error when the file cannot be read, exceeds
/// [`MAX_CONFIG_BYTES`], is not valid JSON, states no known `role`, or carries
/// a field the selected role does not have.
pub fn parse_file(path: impl AsRef<Path>) -> Result<NodeConfig, ParseError> {
    let path = path.as_ref();
    let bytes = read_bounded(path)?;
    parse_bytes(path, &bytes)
}

/// Structurally parses configuration bytes that have already been read.
///
/// `path` is used only to label diagnostics.
///
/// # Errors
///
/// Returns an error when the bytes are not valid JSON, state no known `role`,
/// or carry a field the selected role does not have.
pub fn parse_bytes(path: &Path, bytes: &[u8]) -> Result<NodeConfig, ParseError> {
    // The source text backs every excerpt and span. Lossy decoding is safe:
    // offsets are clamped to character boundaries before use, and a valid
    // configuration is UTF-8 anyway.
    let text = String::from_utf8_lossy(bytes);

    let role = match role_of(bytes) {
        Ok(role) => role,
        Err(source) => return Err(decode_failure(path, &text, "", source)),
    };

    match role {
        Role::Entry => deserialize::<EntryConfig>(path, &text, bytes)
            .map(|entry| NodeConfig::Entry(Box::new(entry))),
        Role::Landing => deserialize::<LandingConfig>(path, &text, bytes)
            .map(|landing| NodeConfig::Landing(Box::new(landing))),
    }
}

/// Reads `role` and ignores everything else.
///
/// Unknown fields are deliberately tolerated here: this pass only chooses which
/// strict type the second pass uses, and rejecting an unknown field before the
/// role is known would report it against the wrong shape.
fn role_of(bytes: &[u8]) -> Result<Role, serde_json::Error> {
    #[derive(Deserialize)]
    struct RoleOnly {
        role: Role,
    }

    serde_json::from_slice::<RoleOnly>(bytes).map(|peek| peek.role)
}

/// Deserializes the whole document into one role's type, tracking field paths.
fn deserialize<'de, T>(path: &Path, text: &str, bytes: &'de [u8]) -> Result<T, ParseError>
where
    T: Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = match serde_path_to_error::deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(tracked) => {
            let field_path = tracked.path().to_string();
            let source = tracked.into_inner();
            return Err(decode_failure(path, text, &field_path, source));
        }
    };
    // Trailing content after a complete value is a malformed document, not a
    // second document.
    if let Err(source) = deserializer.end() {
        return Err(decode_failure(path, text, "", source));
    }
    Ok(value)
}

fn decode_failure(
    path: &Path,
    text: &str,
    field_path: &str,
    source: serde_json::Error,
) -> ParseError {
    ParseError::Decode {
        diagnostic: Box::new(Diagnostic::decode(path, text, field_path, &source)),
        source,
    }
}

/// Reads one file into memory, enforcing the hard size bound.
///
/// [`crate::config::load`] needs the bytes after parsing so a semantic failure
/// can be rendered against the original source, so the bound lives here and is
/// applied once.
///
/// # Errors
///
/// Returns an error when the file cannot be read or exceeds
/// [`MAX_CONFIG_BYTES`].
pub(super) fn read_bounded_for_load(path: &Path) -> Result<Vec<u8>, ParseError> {
    read_bounded(path)
}

/// Reads one file into memory, enforcing the hard size bound before and after
/// the read so a file that grows mid-read cannot slip past it.
fn read_bounded(path: &Path) -> Result<Vec<u8>, ParseError> {
    let file = File::open(path).map_err(|source| ParseError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ParseError::Io {
        path: path.to_owned(),
        source,
    })?;

    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ParseError::TooLarge {
            path: path.to_owned(),
            bytes: metadata.len(),
        });
    }

    let capacity = usize::try_from(metadata.len())
        .map_or(MAX_CONFIG_BYTES, |bytes| bytes.min(MAX_CONFIG_BYTES));
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ParseError::Io {
            path: path.to_owned(),
            source,
        })?;

    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ParseError::TooLarge {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
        });
    }

    Ok(bytes)
}

/// Fuzz entry point: structurally parses raw configuration bytes.
///
/// Exercises the exact [`parse_file`] decode path without touching the file
/// system. Gated behind the `fuzzing` feature, which only the `fuzz/`
/// workspace enables; never part of a production build.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse(bytes: &[u8]) -> Result<NodeConfig, ParseError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ParseError::TooLarge {
            path: PathBuf::from("<fuzz>"),
            bytes: bytes.len() as u64,
        });
    }
    parse_bytes(Path::new("<fuzz>"), bytes)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{MAX_CONFIG_BYTES, ParseError, parse_bytes, parse_file};
    use crate::config::node::Role;

    const ENTRY: &str = r#"{
      "role": "entry",
      "listeners": [{ "port": 443 }],
      "reality": { "cover": "www.example.com:443", "privateKey": "k" },
      "users": [{ "id": "11111111-1111-4111-8111-111111111111", "shortIds": ["ab"] }],
      "routing": { "default": "direct" }
    }"#;

    const LANDING: &str = r#"{
      "role": "landing",
      "listeners": [{ "port": 7443 }],
      "landing": { "protocol": "handoff", "psk": "k", "privateKey": "p" }
    }"#;

    fn parse(json: &str) -> Result<crate::config::node::NodeConfig, ParseError> {
        parse_bytes(Path::new("config.json"), json.as_bytes())
    }

    fn rendered_error(json: &str) -> String {
        parse(json).expect_err("must not parse").to_string()
    }

    #[test]
    fn both_roles_dispatch_to_their_own_shape() {
        assert_eq!(parse(ENTRY).expect("entry must parse").role(), Role::Entry);
        assert_eq!(
            parse(LANDING).expect("landing must parse").role(),
            Role::Landing
        );
    }

    #[test]
    fn a_missing_role_is_reported_as_a_missing_field() {
        let rendered = rendered_error(r#"{"listeners":[{"port":443}]}"#);

        assert!(
            rendered.contains("role"),
            "the error must name the field that decides the shape: {rendered}"
        );
    }

    #[test]
    fn an_unknown_role_lists_the_roles_that_exist() {
        let rendered = rendered_error(r#"{"role":"line","listeners":[]}"#);

        assert!(rendered.contains("entry"), "{rendered}");
        assert!(rendered.contains("landing"), "{rendered}");
    }

    #[test]
    fn an_unknown_field_is_reported_against_the_role_that_was_selected() {
        let rendered = rendered_error(
            r#"{"role":"landing","listeners":[{"port":7443}],
                "landing":{"protocol":"nxr","psk":"k"},
                "reality":{"cover":"a:443","privateKey":"k"}}"#,
        );

        assert!(
            rendered.contains("reality"),
            "a landing has no REALITY identity: {rendered}"
        );
        assert!(rendered.contains("unknown field"), "{rendered}");
    }

    #[test]
    fn a_diagnostic_points_at_a_line_and_column() {
        let error = parse(r#"{"role":"entry","listeners":"443"}"#).expect_err("must not parse");

        let diagnostic = error
            .diagnostic()
            .expect("a decode failure carries a diagnostic");
        let rendered = diagnostic.to_string();
        assert!(
            rendered.contains("config.json:"),
            "the diagnostic must locate the failure: {rendered}"
        );
    }

    #[test]
    fn a_repeated_outbound_name_is_rejected() {
        let rendered = rendered_error(
            r#"{"role":"entry","listeners":[{"port":443}],
                "reality":{"cover":"a:443","privateKey":"k"},
                "users":[{"id":"u","shortIds":["ab"]}],
                "outbounds":{
                  "landing-1":{"type":"nxr","address":"10.0.0.2","port":7443,"psk":"a"},
                  "landing-1":{"type":"nxr","address":"10.0.0.3","port":7443,"psk":"b"}},
                "routing":{"default":"landing-1"}}"#,
        );

        assert!(
            rendered.contains("landing-1"),
            "the ambiguous name must be reported: {rendered}"
        );
    }

    #[test]
    fn trailing_content_after_the_document_is_rejected() {
        assert!(parse(&format!("{ENTRY} {{}}")).is_err());
    }

    #[test]
    fn json_that_is_not_an_object_is_rejected() {
        for text in ["[]", "\"entry\"", "null", "7"] {
            assert!(parse(text).is_err(), "{text} is not a node");
        }
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-parse-bound-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).expect("temporary directory must be created");
        let path = directory.join("config.json");
        std::fs::write(&path, vec![b'a'; MAX_CONFIG_BYTES + 1]).expect("file must be written");

        let error = parse_file(&path).expect_err("an oversized file must be refused");

        assert!(matches!(error, ParseError::TooLarge { .. }));
        assert!(
            error.diagnostic().is_none(),
            "a file that was never parsed has no source diagnostic"
        );
        std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
    }

    #[test]
    fn a_missing_file_reports_the_path() {
        let error = parse_file(Path::new("/nonexistent/rust-reality/config.json"))
            .expect_err("a missing file must be refused");

        assert!(matches!(error, ParseError::Io { .. }));
        assert!(error.to_string().contains("config.json"));
    }
}
