//! Classification of `serde_json` failures into operator-facing diagnostics.
//!
//! Raw serde wording never reaches the operator: every message is mapped to a
//! fixed title here, and actual values are quoted from the source spans (with
//! redaction) instead of from serde's own text.

use serde_json::error::Category;

/// What the renderer should underline.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum SpanTarget {
    /// The byte position serde reported (line/column), used for syntax errors.
    SerdePosition,
    /// The value at this logical path.
    PathValue(String),
    /// The quoted key of the member at this logical path (unknown fields).
    PathKey(String),
    /// The last definition of `name` inside the object at this parent path.
    DuplicateKey { parent: String, name: String },
    /// No source span could be derived.
    None,
}

/// One classified failure, ready for span resolution and rendering.
#[derive(Debug)]
pub(super) struct Classified {
    pub title: String,
    pub label: Option<String>,
    pub config_path: Option<String>,
    pub help: Option<String>,
    pub notes: Vec<String>,
    pub span: SpanTarget,
    /// Whether the source span's value should be quoted as the actual value.
    pub quote_actual: bool,
}

impl Classified {
    pub(super) fn plain(title: impl Into<String>, span: SpanTarget) -> Self {
        Self {
            title: title.into(),
            label: None,
            config_path: None,
            help: None,
            notes: Vec::new(),
            span,
            quote_actual: false,
        }
    }
}

/// Classifies one `serde_json` error reported at `serde_path`.
pub(super) fn classify(serde_path: &str, error: &serde_json::Error) -> Classified {
    let message = strip_location(error);
    match error.classify() {
        Category::Data => classify_data(serde_path, &message),
        Category::Eof => {
            let mut classified =
                Classified::plain("unexpected end of input", SpanTarget::SerdePosition);
            classified.help = Some("the JSON document is incomplete".to_owned());
            classified
        }
        Category::Syntax | Category::Io => classify_syntax(&message),
    }
}

/// Removes the ` at line N column M` suffix serde appends to every message.
pub(super) fn strip_location(error: &serde_json::Error) -> String {
    let message = error.to_string();
    let suffix = format!(" at line {} column {}", error.line(), error.column());
    match message.strip_suffix(&suffix) {
        Some(stripped) => stripped.to_owned(),
        None => message,
    }
}

/// Extracts the backtick-quoted name following `prefix`.
fn quoted_after<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = message.strip_prefix(prefix)?;
    let end = rest.find('`')?;
    Some(&rest[..end])
}

/// Extracts everything after the last `, expected ` separator.
///
/// The expected text comes from the schema (type, field, and variant names),
/// never from configuration values, so it is safe to repeat.
fn expected_tail(message: &str) -> Option<&str> {
    message.rsplit_once(", expected ").map(|(_, tail)| tail)
}

/// Parses a serde expected-list tail (`one of `a`, `b`` / `` `a` or `b` `` /
/// `a map with a single element`) into display form. Returns the list joined
/// as `"a", "b", or "c"` when every item is backtick-quoted.
fn reformat_expected_list(tail: &str) -> Option<String> {
    let mut items = Vec::new();
    let mut rest = tail.strip_prefix("one of ").unwrap_or(tail);
    loop {
        rest = rest.strip_prefix('`')?;
        let end = rest.find('`')?;
        items.push(format!("\"{}\"", &rest[..end]));
        rest = &rest[end + 1..];
        if let Some(next) = rest.strip_prefix(", ") {
            rest = next;
        } else if let Some(next) = rest.strip_prefix(" or ") {
            rest = next;
        } else {
            break;
        }
    }
    if !rest.is_empty() || items.is_empty() {
        return None;
    }
    Some(join_items(&items))
}

/// Joins display items as `a`, `a or b`, `a, b, or c`.
fn join_items(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [first, second] => format!("{first} or {second}"),
        [rest @ .., last] => format!("{}, or {last}", rest.join(", ")),
    }
}

/// Field-specific remediation, added only where the right fix is not obvious
/// from the expected list alone.
fn path_help(path: &str) -> Option<&'static str> {
    match path {
        "runtime.profile" => {
            Some("use \"dedicated\" only when this process owns the bounded host or cgroup")
        }
        _ => None,
    }
}

/// Diagnostics for fields removed in v1.6, per AGENTS.md §7: recognizing a
/// removed field name solely to emit a targeted fatal error is acceptable.
/// Names a field the v1.9 configuration reset removed, so an operator holding
/// an older file learns what happened instead of reading "unknown field".
///
/// This recognises the name only to fail with a better message; nothing here
/// accepts, translates, or migrates an old value. `AGENTS.md` §9 permits
/// exactly that and nothing more.
fn removed_field(path: &str) -> Option<Classified> {
    let (title, help) = match path {
        "inbounds" => (
            "field `inbounds` was removed in v1.9",
            "a node now declares one `role` (\"entry\" or \"landing\") with its own              `listeners`; see the configuration guide",
        ),
        "advanced" => (
            "field `advanced` was removed in v1.9",
            "the few limits that remain configurable moved to `runtime.limits`;              everything else is derived from the machine",
        ),
        "policy" => (
            "field `policy` was removed in v1.6 and its replacement in v1.9",
            "the few limits that remain configurable live in `runtime.limits`",
        ),
        "routing.users" => (
            "field `routing.users` was removed in v1.9",
            "a user names its policy through `users[].policy`, and the policies              live in `routing.policies`",
        ),
        "routing.globalRules" => (
            "field `routing.globalRules` was removed in v1.9",
            "the global rule list is now `routing.rules`",
        ),
        _ => return None,
    };
    let mut classified = Classified::plain(title, SpanTarget::PathKey(path.to_owned()));
    classified.config_path = Some(path.to_owned());
    classified.help = Some(help.to_owned());
    Some(classified)
}

fn classify_data(path: &str, message: &str) -> Classified {
    if let Some(name) = quoted_after(message, "unknown field `") {
        if let Some(removed) = removed_field(path) {
            return removed;
        }
        let mut classified = Classified::plain(
            format!("unknown field `{name}`"),
            SpanTarget::PathKey(path.to_owned()),
        );
        classified.label = Some("unknown field".to_owned());
        if let Some(expected) = expected_tail(message)
            && let Some(list) = reformat_expected_list(expected)
        {
            classified.notes.push(format!("expected: {list}"));
            if let Some(suggestion) = suggest(name, expected) {
                classified.help = Some(format!("did you mean {suggestion}?"));
            }
        }
        return classified;
    }
    if let Some(name) = quoted_after(message, "missing field `") {
        let mut classified = Classified::plain(
            format!("missing required field `{name}`"),
            SpanTarget::PathValue(path.to_owned()),
        );
        classified.label = Some(format!("missing field `{name}`"));
        classified.config_path = non_root_path(path);
        return classified;
    }
    if let Some(name) = quoted_after(message, "duplicate field `") {
        let mut classified = Classified::plain(
            format!("duplicate field `{name}`"),
            SpanTarget::DuplicateKey {
                parent: path.to_owned(),
                name: name.to_owned(),
            },
        );
        classified.label = Some("field defined more than once".to_owned());
        classified.help = Some("remove one of the definitions".to_owned());
        return classified;
    }
    // A name-keyed section reports its own repeat, because a repeated map key
    // is not a struct field and serde has nothing to say about it. See
    // `config::node::named`.
    if let Some(name) = quoted_after(message, "duplicate name `") {
        let mut classified = Classified::plain(
            format!("duplicate name `{name}`"),
            SpanTarget::DuplicateKey {
                parent: path.to_owned(),
                name: name.to_owned(),
            },
        );
        classified.label = Some("name defined more than once".to_owned());
        classified.config_path = non_root_path(path);
        classified.help = Some("rename one of them: the name is how rules refer to it".to_owned());
        return classified;
    }
    if quoted_after(message, "unknown variant `").is_some() {
        let mut classified = Classified::plain(
            format!("invalid value for `{path}`"),
            SpanTarget::PathValue(path.to_owned()),
        );
        if let Some(expected) = expected_tail(message) {
            let list = reformat_expected_list(expected).unwrap_or_else(|| expected.to_owned());
            classified.label = Some(format!("expected {list}"));
        }
        classified.help = path_help(path).map(str::to_owned);
        classified.quote_actual = true;
        return classified;
    }
    if message.starts_with("invalid type: ") {
        let mut classified = Classified::plain(
            format!("invalid type for `{path}`"),
            SpanTarget::PathValue(path.to_owned()),
        );
        if let Some(expected) = expected_tail(message) {
            classified.label = Some(format!("expected {expected}"));
        }
        classified.quote_actual = true;
        return classified;
    }
    if message.starts_with("invalid value: ") || message.starts_with("invalid length: ") {
        let mut classified = Classified::plain(
            format!("invalid value for `{path}`"),
            SpanTarget::PathValue(path.to_owned()),
        );
        if let Some(expected) = expected_tail(message) {
            classified.label = Some(format!("expected {expected}"));
        }
        classified.quote_actual = true;
        return classified;
    }
    // Unknown data-error shapes degrade to path plus a fixed title; serde's
    // own message is never repeated because it may quote configuration values.
    Classified::plain(
        format!("invalid value for `{path}`"),
        SpanTarget::PathValue(path.to_owned()),
    )
}

/// Returns the path unless it names the document root.
fn non_root_path(path: &str) -> Option<String> {
    if path.is_empty() || path == "." || path == "?" {
        None
    } else {
        Some(path.to_owned())
    }
}

fn classify_syntax(message: &str) -> Classified {
    let title = if message == "expected value" {
        "expected a JSON value"
    } else if message == "expected `,` or `}`"
        || message == "expected `,` or `]`"
        || message == "expected `:`"
    {
        message
    } else if message == "expected ident" {
        "expected `true`, `false`, or `null`"
    } else if message == "key must be a string" {
        "object keys must be double-quoted strings"
    } else if message == "trailing comma" {
        "trailing comma is not allowed"
    } else if message == "trailing characters" {
        "trailing characters after the JSON document"
    } else if message == "invalid escape" {
        "invalid escape sequence in string"
    } else if message.starts_with("control character") {
        "unescaped control character in string"
    } else if message == "invalid unicode code point"
        || message.starts_with("lone leading surrogate")
        || message.starts_with("unexpected end of hex escape")
    {
        "invalid unicode escape in string"
    } else if message == "number out of range" {
        "number out of range"
    } else if message.starts_with("invalid number") {
        "invalid number"
    } else {
        "invalid JSON syntax"
    };
    let mut classified = Classified::plain(title, SpanTarget::SerdePosition);
    if title == "unescaped control character in string" {
        classified.help = Some("escape control characters as \\u00XX".to_owned());
    }
    classified
}

/// Suggests a field name for a typo, only when the match is unambiguously
/// strong: Damerau distance 1, or distance 2 in a name of at least 8 chars
/// (so `profiel` suggests `profile` but `profeil` does not).
fn suggest(name: &str, expected_tail: &str) -> Option<String> {
    let mut candidates: Vec<&str> = Vec::new();
    let mut rest = expected_tail
        .strip_prefix("one of ")
        .unwrap_or(expected_tail);
    while let Some(after) = rest.strip_prefix('`') {
        let end = after.find('`')?;
        candidates.push(&after[..end]);
        rest = &after[end + 1..];
        if let Some(next) = rest
            .strip_prefix(", ")
            .or_else(|| rest.strip_prefix(" or "))
        {
            rest = next;
        } else {
            break;
        }
    }
    let mut best: Option<(&str, usize)> = None;
    for candidate in candidates {
        let distance = damerau(name, candidate);
        let strong = distance == 1 || (distance == 2 && name.len().max(candidate.len()) >= 8);
        if strong && best.is_none_or(|(_, best_distance)| distance < best_distance) {
            best = Some((candidate, distance));
        } else if strong && best.is_some_and(|(_, best_distance)| distance == best_distance) {
            // Ambiguous: two equally close candidates, suggest neither.
            best = None;
            break;
        }
    }
    best.map(|(candidate, _)| format!("`{candidate}`"))
}

/// Optimal string alignment distance (Damerau-Levenshtein with each substring
/// edited at most once); enough for typo detection on short identifiers.
fn damerau(left: &str, right: &str) -> usize {
    let a: Vec<char> = left.chars().collect();
    let b: Vec<char> = right.chars().collect();
    let (rows, cols) = (a.len() + 1, b.len() + 1);
    let mut d = vec![vec![0usize; cols]; rows];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..rows {
        for j in 1..cols {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[rows - 1][cols - 1]
}

#[cfg(test)]
mod tests {
    use super::{damerau, reformat_expected_list, suggest};

    #[test]
    fn damerau_counts_transpositions_as_one_edit() {
        assert_eq!(damerau("profiel", "profile"), 1);
        assert_eq!(damerau("profeil", "profile"), 2);
        assert_eq!(damerau("profile", "profile"), 0);
        assert_eq!(damerau("xyz", "profile"), 7);
        assert_eq!(damerau("log", "logs"), 1);
    }

    #[test]
    fn suggests_only_strong_matches() {
        let tail = "one of `auto`, `shared`, `dedicated`";
        assert_eq!(
            suggest("profiel", "`profile` or `mode`"),
            Some("`profile`".to_owned()),
            "a transposition one edit away is a strong match"
        );
        assert_eq!(
            suggest("shaxed", "`shared` or `shaped`"),
            None,
            "two equally close matches are ambiguous and suggest nothing"
        );
        assert_eq!(suggest("profiel", tail), None);
        assert_eq!(suggest("sharred", tail), Some("`shared`".to_owned()));
        assert_eq!(
            suggest("profeil", "`profile` or `mode`"),
            None,
            "two edits in a short name is too weak to suggest"
        );
        assert_eq!(suggest("logg", "`log`"), Some("`log`".to_owned()));
    }

    #[test]
    fn reformats_expected_lists() {
        assert_eq!(
            reformat_expected_list("one of `auto`, `shared`, `dedicated`"),
            Some("\"auto\", \"shared\", or \"dedicated\"".to_owned())
        );
        assert_eq!(
            reformat_expected_list("`profile` or `mode`"),
            Some("\"profile\" or \"mode\"".to_owned())
        );
        assert_eq!(
            reformat_expected_list("u16"),
            None,
            "unquoted expectations are left verbatim"
        );
    }
}
