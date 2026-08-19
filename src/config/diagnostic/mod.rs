//! Compiler-grade configuration diagnostics.
//!
//! Every configuration failure — malformed JSON, schema violations, and
//! semantic invariant failures — renders as one rustc-style block: severity
//! and title, `file:line:column`, the offending source line with a caret
//! span, the logical configuration path, expected versus actual, and a
//! trustworthy remediation hint. Raw serde wording never reaches the
//! operator, and secret values are redacted before any excerpt is built.
//!
//! Diagnostics are built only on the cold configuration-load path; the
//! network hot path never touches this module.

mod classify;
mod render;
mod source_map;

use std::{fmt, path::Path};

use classify::{Classified, SpanTarget};
use render::Excerpt;
use source_map::{SourceMap, Span};

use super::ConfigError;

/// One source-oriented configuration diagnostic.
///
/// The structured fields are prepared at construction; [`fmt::Display`]
/// renders the final plain-text block (no ANSI color).
#[derive(Debug)]
pub struct Diagnostic {
    severity: &'static str,
    title: String,
    file: String,
    excerpt: Option<Excerpt>,
    label: Option<String>,
    notes: Vec<String>,
}

impl Diagnostic {
    /// Builds the diagnostic for one `serde_json` decode failure at
    /// `serde_path` (the `serde_path_to_error` path, or empty at the root).
    pub(super) fn decode(
        path: &Path,
        text: &str,
        serde_path: &str,
        error: &serde_json::Error,
    ) -> Self {
        let map = SourceMap::scan(text);
        let serde_path = refine_tagged_enum_path(&map, text, serde_path, error);
        let classified = classify::classify(&serde_path, error);
        let span = resolve_span(&map, &classified, text, error);
        Self::assemble(path, &map, text, classified, span)
    }

    /// Builds the diagnostic for one semantic validation failure.
    pub(super) fn validation(path: &Path, text: &str, error: &ConfigError) -> Self {
        let map = SourceMap::scan(text);
        let span = map.lookup(error.path()).map(source_map::Node::value_span);
        let mut classified = Classified::plain(
            format!("invalid value for `{}`", error.path()),
            SpanTarget::None,
        );
        classified.label = Some(error.message().to_owned());
        Self::assemble(path, &map, text, classified, span)
    }

    fn assemble(
        path: &Path,
        map: &SourceMap,
        text: &str,
        classified: Classified,
        span: Option<Span>,
    ) -> Self {
        let excerpt = span.map(|span| render::build_excerpt(text, map, span));
        let mut notes = classified.notes.clone();
        if let Some(config_path) = &classified.config_path {
            notes.push(format!("configuration path: {config_path}"));
        }
        if classified.quote_actual
            && let Some(span) = span
        {
            notes.push(format!("actual value: {}", actual_value(text, map, span)));
        }
        if let Some(help) = &classified.help {
            notes.push(format!("help: {help}"));
        }
        Self {
            severity: "error",
            title: classified.title,
            file: path.display().to_string(),
            excerpt,
            label: classified.label,
            notes,
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&render::render(
            self.severity,
            &self.title,
            &self.file,
            self.excerpt.as_ref(),
            self.label.as_deref(),
            &self.notes,
        ))
    }
}

/// Resolves the classified span target against the scanned source.
fn resolve_span(
    map: &SourceMap,
    classified: &Classified,
    text: &str,
    error: &serde_json::Error,
) -> Option<Span> {
    match &classified.span {
        SpanTarget::SerdePosition => {
            let offset = serde_offset(text, error.line(), error.column());
            // serde points at the byte where parsing stalled, often the
            // whitespace before the offending token; snap to the token.
            let bytes = text.as_bytes();
            let mut offset = offset;
            while offset < text.len() && matches!(bytes[offset], b' ' | b'\t' | b'\r') {
                offset += 1;
            }
            Some(Span {
                start: offset,
                end: offset,
            })
        }
        SpanTarget::PathValue(path) => map.lookup(path).map(source_map::Node::value_span),
        SpanTarget::PathKey(path) => map
            .lookup(path)
            .map(|node| node.key_span().unwrap_or_else(|| node.value_span())),
        SpanTarget::DuplicateKey { parent, name } => map
            .lookup_member(parent, name)
            .map(|node| node.key_span().unwrap_or_else(|| node.value_span())),
        SpanTarget::None => None,
    }
}

/// Recovers the precise path inside internally tagged enum elements.
///
/// `serde` buffers the content of internally tagged enums (`inbounds[*]` and
/// `outbounds[*]` use `tag = "protocol"`), so `serde_path_to_error` reports
/// only the element path — `inbounds[0]` instead of
/// `inbounds[0].settings.clients[0].id`. When the reported path names exactly
/// one such element, its `protocol` tag selects the concrete variant type and
/// the source subtree is re-deserialized on the error path; if the same error
/// reappears with a deeper path, that path wins.
fn refine_tagged_enum_path(
    map: &SourceMap,
    text: &str,
    path: &str,
    error: &serde_json::Error,
) -> String {
    if error.classify() != serde_json::error::Category::Data {
        return path.to_owned();
    }
    let Some(array) = ["inbounds", "outbounds"]
        .into_iter()
        .find(|name| indexed_element(path, name))
    else {
        return path.to_owned();
    };
    let Some(element) = map.lookup(path) else {
        return path.to_owned();
    };
    let Some(protocol) = element.member("protocol").and_then(|node| {
        let span = node.content_span();
        text.get(span.start..span.end)
    }) else {
        return path.to_owned();
    };
    let element_span = element.value_span();
    let Some(element_text) = text.get(element_span.start..element_span.end) else {
        return path.to_owned();
    };
    let sub = match (array, protocol) {
        // The variant structs reject the `protocol` tag itself, so the
        // subtree is re-deserialized from a `Value` with the tag removed.
        ("inbounds", "vless") => repath_value::<super::VlessInboundConfig>(element_text, error),
        ("inbounds", "nxr") => repath_value::<super::NxrInboundConfig>(element_text, error),
        ("inbounds", "handoff") => repath_value::<super::HandoffInboundConfig>(element_text, error),
        ("outbounds", _) => refine_outbound_settings(text, element, protocol, error)
            .map(|sub| format!("settings.{sub}")),
        _ => None,
    };
    match sub {
        Some(sub) if !sub.is_empty() && sub != "." => format!("{path}.{sub}"),
        _ => {
            // The tag itself is the only enum-level value: when no variant
            // reproduced the error and it names an unknown variant, the
            // offending value is `protocol`.
            if classify::strip_location(error).starts_with("unknown variant `") {
                format!("{path}.protocol")
            } else {
                path.to_owned()
            }
        }
    }
}

/// Outbound variants carry no named per-variant struct, so refinement
/// re-deserializes the `settings` subtree against the tag's settings type.
fn refine_outbound_settings(
    text: &str,
    element: &source_map::Node,
    protocol: &str,
    error: &serde_json::Error,
) -> Option<String> {
    let span = element.member("settings")?.value_span();
    let subtree = text.get(span.start..span.end)?;
    match protocol {
        "blackhole" => repath::<super::BlackholeSettings>(subtree, error),
        "socks5" => repath::<super::Socks5Settings>(subtree, error),
        "nxr" => repath::<super::NxrSettings>(subtree, error),
        "handoff" => repath::<super::HandoffSettings>(subtree, error),
        _ => None,
    }
}

/// Returns whether `path` is exactly `name[<index>]`.
fn indexed_element(path: &str, name: &str) -> bool {
    let Some(rest) = path.strip_prefix(name) else {
        return false;
    };
    let Some(index) = rest
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return false;
    };
    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
}

/// Re-deserializes one subtree, returning the failing sub-path when the
/// identical error reappears deeper inside it.
fn repath<T: serde::de::DeserializeOwned>(
    subtree: &str,
    error: &serde_json::Error,
) -> Option<String> {
    let mut deserializer = serde_json::Deserializer::from_str(subtree);
    let tracked = serde_path_to_error::deserialize::<_, T>(&mut deserializer).err()?;
    // The subtree reports different line/column numbers; compare the
    // location-free messages to confirm it is the same failure.
    if classify::strip_location(tracked.inner()) == classify::strip_location(error) {
        Some(tracked.path().to_string())
    } else {
        None
    }
}

/// [`repath`] variant that drops the internally tagged `protocol` member
/// before re-deserializing against the concrete variant struct.
fn repath_value<T: serde::de::DeserializeOwned>(
    subtree: &str,
    error: &serde_json::Error,
) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(subtree).ok()?;
    value.as_object_mut()?.remove("protocol");
    let tracked = serde_path_to_error::deserialize::<_, T>(value).err()?;
    if classify::strip_location(tracked.inner()) == classify::strip_location(error) {
        Some(tracked.path().to_string())
    } else {
        None
    }
}

/// Converts serde's 1-based line and 1-based byte column into a byte offset,
/// clamped to the line so a lossy-decoded document can never panic.
fn serde_offset(text: &str, line: usize, column: usize) -> usize {
    let mut current = 1;
    let mut start = 0;
    for (index, ch) in text.char_indices() {
        if current == line {
            break;
        }
        if ch == '\n' {
            current += 1;
            start = index + 1;
        }
    }
    let end = text[start..]
        .find('\n')
        .map_or(text.len(), |newline| start + newline);
    // serde columns count bytes from the line start, 1-based.
    let offset = start + column.saturating_sub(1);
    // Never split a UTF-8 sequence when the source needed lossy decoding.
    let mut offset = offset.min(end);
    while offset > start && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// Quotes the actual source value for a note, redacted and length-bounded.
fn actual_value(text: &str, map: &SourceMap, span: Span) -> String {
    const MAX_ACTUAL: usize = 60;
    let redacted = map
        .redactions()
        .iter()
        .any(|secret| secret.start < span.end.max(span.start + 1) && span.start < secret.end);
    if redacted {
        return "[REDACTED]".to_owned();
    }
    let raw = &text[span.start..span.end.min(text.len())];
    if raw.chars().count() > MAX_ACTUAL {
        let truncated: String = raw.chars().take(MAX_ACTUAL).collect();
        format!("{truncated}...")
    } else {
        raw.to_owned()
    }
}
