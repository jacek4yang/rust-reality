//! Documentation validation: the typed replacement for `scripts/check-docs.py`.
//!
//! Five independent policies, each learned from a real documentation defect:
//!
//! 1. **Required bilingual pairs.** Every operator-facing document must exist in
//!    both English and Chinese, so a translation cannot silently disappear.
//! 2. **Forbidden stale phrases.** Wording that was once published and later found
//!    wrong must never read as current behaviour again. `CHANGELOG.md` and the
//!    decision register are exempt, because there the historical wording is the
//!    point.
//! 3. **Release headline consistency.** The version and comparator identity quoted
//!    across six bilingual surfaces must come from one small data file that is
//!    itself checked against `Cargo.toml`, so a release cannot ship with one
//!    surface quoting stale numbers.
//! 4. **Local link resolution.** Every relative Markdown link must resolve to a
//!    file inside the repository.
//! 5. **Containment.** A link must not escape the repository root.
//!
//! One implementation difference from the Python original is deliberate and
//! documented at [`normalize`]: path resolution is *lexical* rather than
//! filesystem-based, because the check must be able to report a target that does
//! not exist, and `Path::canonicalize` fails on exactly those paths.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    path::{Component, Path, PathBuf},
};

/// Operator documents that must exist in both languages.
const REQUIRED_PAIRS: &[(&str, &str)] = &[
    ("README.md", "README.zh-CN.md"),
    ("SECURITY.md", "docs/zh-CN/security.md"),
    ("docs/en/index.md", "docs/zh-CN/index.md"),
    ("docs/en/getting-started.md", "docs/zh-CN/getting-started.md"),
    ("docs/en/cli.md", "docs/zh-CN/cli.md"),
    ("docs/en/configuration.md", "docs/zh-CN/configuration.md"),
    ("docs/en/deployment.md", "docs/zh-CN/deployment.md"),
    ("docs/en/architecture.md", "docs/zh-CN/architecture.md"),
    ("docs/en/protocol.md", "docs/zh-CN/protocol.md"),
    ("docs/en/performance.md", "docs/zh-CN/performance.md"),
    ("docs/en/benchmarks.md", "docs/zh-CN/benchmarks.md"),
    ("docs/en/threat-model.md", "docs/zh-CN/threat-model.md"),
    ("docs/en/tuning.md", "docs/zh-CN/tuning.md"),
    ("docs/en/release-process.md", "docs/zh-CN/release-process.md"),
];

/// Wording that must never read as current behaviour again.
///
/// Each entry was published once and later found wrong. The list stays short on
/// purpose: it is a drift guard, not a style checker.
const FORBIDDEN_PHRASES: &[&str] = &[
    // Inverted abort semantics: abort must read as RST/reset, never as a graceful
    // finish. Both languages.
    "indistinguishable from clean FIN",
    "不可区分",
    // Stale decision-register range; the register runs through D11.
    "D1–D9",
    // Pre-release positioning.
    "pre-1.0",
    "0.1.x",
];

/// Paths where historical wording is legitimate.
const FORBIDDEN_EXEMPT: &[&str] = &["CHANGELOG.md", "docs/adr/"];

/// The data file that owns current-release identity for documentation surfaces.
const HEADLINES: &str = "benchmarks/baselines/current-release-headlines.json";

/// Outcome of a documentation check.
#[derive(Debug, Default)]
pub struct Report {
    /// Every policy violation, in a stable order.
    pub failures: Vec<String>,
    /// How many Markdown files were considered.
    pub files: usize,
}

impl Report {
    /// Whether the documentation satisfies every policy.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// Renders the human-facing summary, matching the legacy output shape.
    #[must_use]
    pub fn render(&self) -> String {
        if self.is_clean() {
            return format!(
                "documentation links verified across {} Markdown files",
                self.files
            );
        }
        let mut text = String::from("documentation validation failed:\n");
        for failure in &self.failures {
            let _ = writeln!(text, "- {failure}");
        }
        text
    }
}

/// Runs every documentation policy against `repo`.
#[must_use]
pub fn check(repo: &Path) -> Report {
    let files = markdown_files(repo);
    let mut failures = Vec::new();

    for (english, chinese) in REQUIRED_PAIRS {
        for relative in [english, chinese] {
            if !repo.join(relative).is_file() {
                failures.push(format!("missing required document: {relative}"));
            }
        }
    }

    failures.extend(forbidden_phrase_failures(repo, &files));
    failures.extend(release_headline_failures(repo));
    failures.extend(link_failures(repo, &files));

    Report {
        failures,
        files: files.len(),
    }
}

/// Lists Markdown files: repository root plus everything under `docs/`.
#[must_use]
pub fn markdown_files(repo: &Path) -> Vec<PathBuf> {
    let mut found = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(repo) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && has_markdown_extension(&path) {
                found.insert(path);
            }
        }
    }
    collect_markdown(&repo.join("docs"), &mut found);
    found.into_iter().collect()
}

fn collect_markdown(directory: &Path, found: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown(&path, found);
        } else if path.is_file() && has_markdown_extension(&path) {
            found.insert(path);
        }
    }
}

fn has_markdown_extension(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
}

fn forbidden_phrase_failures(repo: &Path, files: &[PathBuf]) -> Vec<String> {
    let mut failures = Vec::new();
    for source in files {
        let relative = relative_display(repo, source);
        if FORBIDDEN_EXEMPT
            .iter()
            .any(|exempt| relative.starts_with(exempt))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(source) else {
            continue;
        };
        for phrase in FORBIDDEN_PHRASES {
            if text.contains(phrase) {
                failures.push(format!("{relative}: forbidden stale phrase: {phrase:?}"));
            }
        }
    }
    failures
}

fn link_failures(repo: &Path, files: &[PathBuf]) -> Vec<String> {
    let mut failures = Vec::new();
    for source in files {
        let Ok(text) = std::fs::read_to_string(source) else {
            continue;
        };
        let relative = relative_display(repo, source);
        let parent = source.parent().unwrap_or(repo);
        for raw in markdown_link_targets(&text) {
            let Some(target) = local_target(parent, &raw) else {
                continue;
            };
            if !target.starts_with(repo) {
                failures.push(format!("{relative}: local link escapes repository: {raw}"));
                continue;
            }
            if !target.exists() {
                failures.push(format!("{relative}: missing local link target: {raw}"));
            }
        }
    }
    failures
}

/// Extracts `](target)` payloads from inline Markdown links, skipping images.
///
/// Hand-scanned rather than regex-matched: the grammar needed here is one
/// character of lookbehind for the image `!`, which does not justify pulling a
/// regex engine into the tooling dependency graph.
#[must_use]
pub fn markdown_link_targets(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut targets = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            index += 1;
            continue;
        }
        // An image reference is `![alt](src)`; only inline links are validated.
        if index > 0 && bytes[index - 1] == b'!' {
            index += 1;
            continue;
        }
        let Some(close) = find_byte(bytes, index + 1, b']') else {
            break;
        };
        // The label must be non-empty and must not itself contain a `]`.
        if close == index + 1 || close + 1 >= bytes.len() || bytes[close + 1] != b'(' {
            index += 1;
            continue;
        }
        let Some(end) = find_byte(bytes, close + 2, b')') else {
            index = close + 1;
            continue;
        };
        if let Ok(target) = std::str::from_utf8(&bytes[close + 2..end]) {
            targets.push(target.to_owned());
        }
        index = end + 1;
    }
    targets
}

fn find_byte(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|byte| *byte == needle)
        .map(|offset| from + offset)
}

/// Resolves a link target to a repository path, or `None` when it is not local.
fn local_target(parent: &Path, raw: &str) -> Option<PathBuf> {
    let target = raw.trim().trim_start_matches('<').trim_end_matches('>');
    if target.is_empty() || target.starts_with('#') {
        return None;
    }
    for scheme in ["http://", "https://", "mailto:"] {
        if target.starts_with(scheme) {
            return None;
        }
    }
    let without_fragment = target.split_once('#').map_or(target, |(path, _)| path);
    if without_fragment.is_empty() {
        return None;
    }
    Some(normalize(&parent.join(percent_decode(without_fragment))))
}

/// Normalises `.` and `..` lexically, without touching the filesystem.
///
/// The Python original used `Path.resolve()`, which also resolves symlinks. That
/// difference is deliberate here: this check must be able to *report* a target
/// that does not exist, and `Path::canonicalize` — the direct equivalent — fails
/// on exactly those paths, which would turn a missing-link failure into an
/// internal error. Lexical normalisation gives the same answer for every link
/// shape the repository actually uses, and containment is then checked against
/// the repository root.
fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    normalized
}

/// Decodes `%XX` escapes, matching `urllib.parse.unquote` for link targets.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "both digits are hex, so the value fits in a byte"
                )]
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn relative_display(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Extracts the body between two headings, or `""` when the start is absent.
fn section(text: &str, start: &str, end: &str) -> String {
    let Some((_, body)) = text.split_once(start) else {
        return String::new();
    };
    body.split_once(end)
        .map_or_else(|| body.to_owned(), |(head, _)| head.to_owned())
}

/// Checks that every current-release surface quotes the same identity data.
fn release_headline_failures(repo: &Path) -> Vec<String> {
    let path = repo.join(HEADLINES);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => return vec![format!("{HEADLINES}: {error}")],
    };
    let data = match json::parse(&raw) {
        Ok(value) => value,
        Err(error) => return vec![format!("{HEADLINES}: {error}")],
    };

    let mut failures = Vec::new();
    if data.get("schemaVersion").and_then(json::Value::as_u64) != Some(1) {
        return vec!["current release headline schemaVersion must be 1".to_owned()];
    }
    let Some(release) = data.get("release").and_then(json::Value::as_str) else {
        return vec![format!("{HEADLINES}: release must be a string")];
    };

    let cargo_release = std::fs::read_to_string(repo.join("Cargo.toml"))
        .ok()
        .and_then(|cargo| cargo_version(&cargo));
    match &cargo_release {
        Some(version) if version == release => {}
        other => failures.push(format!(
            "current release mismatch: Cargo.toml={other:?}, headline data={release:?}"
        )),
    }

    let Some(comparator) = data.get("comparator") else {
        failures.push(format!("{HEADLINES}: comparator is required"));
        return failures;
    };
    let mut common = vec![release.to_owned()];
    for field in ["version", "commit", "goVersion", "binarySha256Abbreviated"] {
        match comparator.get(field).and_then(json::Value::as_str) {
            Some(value) => common.push(value.to_owned()),
            None => failures.push(format!("{HEADLINES}: comparator.{field} must be a string")),
        }
    }

    let mut table_values = Vec::new();
    for group in ["setup", "throughputRatios", "routing"] {
        let Some(object) = data.get(group) else {
            failures.push(format!("{HEADLINES}: {group} is required"));
            continue;
        };
        table_values.extend(object.leaf_strings());
    }
    let mut full = common.clone();
    full.extend(table_values);
    if let Some(headline) = data.get("headlineValues") {
        full.extend(headline.leaf_strings());
    } else {
        failures.push(format!("{HEADLINES}: headlineValues is required"));
    }

    failures.extend(surface_failures(
        repo,
        release,
        common.as_slice(),
        full.as_slice(),
    ));
    failures
}

/// Compares each documentation surface against the required identity values.
fn surface_failures(repo: &Path, release: &str, common: &[String], full: &[String]) -> Vec<String> {
    let mut failures = Vec::new();
    let surfaces: [(&str, String, String); 6] = [
        (
            "README.md",
            "## Performance vs Xray-core".to_owned(),
            "## Architecture".to_owned(),
        ),
        (
            "README.zh-CN.md",
            "## 与 Xray-core 的性能对比".to_owned(),
            "## 架构".to_owned(),
        ),
        (
            "docs/en/benchmarks.md",
            format!("## {release} release comparison evidence"),
            "## Historical README headline tables".to_owned(),
        ),
        (
            "docs/zh-CN/benchmarks.md",
            format!("## {release} 发布对比证据"),
            "## 历史 README 头条表格".to_owned(),
        ),
        (
            "docs/en/performance.md",
            format!("## {release} release evidence"),
            "## v1.5.1 release evidence".to_owned(),
        ),
        (
            "docs/zh-CN/performance.md",
            format!("## {release} 发布证据"),
            "## v1.5.1 发布证据".to_owned(),
        ),
    ];

    for (name, start, end) in surfaces {
        let Ok(text) = std::fs::read_to_string(repo.join(name)) else {
            failures.push(format!("{name}: unreadable"));
            continue;
        };
        let body = section(&text, &start, &end);
        if body.is_empty() {
            failures.push(format!(
                "{name}: missing current-release heading for {release}"
            ));
            continue;
        }
        let required: &[String] = if name.starts_with("README") {
            full
        } else {
            common
        };
        let missing: Vec<&String> = required
            .iter()
            .filter(|value| !body.contains(value.as_str()))
            .collect();
        if !missing.is_empty() {
            failures.push(format!("{name}: current-release data missing {missing:?}"));
        }
    }
    failures
}

/// Extracts the first top-level `version = "..."` from a manifest.
fn cargo_version(manifest: &str) -> Option<String> {
    manifest
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.split('"').next())
        .map(|version| format!("v{version}"))
}

/// A minimal JSON reader.
///
/// The headline data file is a small, repository-owned document with a checked
/// `schemaVersion`, so a full serde dependency in the tooling workspace would buy
/// nothing here. If a later slice needs real deserialisation this module is the
/// place to swap it.
mod json {
    use std::collections::BTreeMap;

    /// A parsed JSON value.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        /// JSON `null`.
        Null,
        /// JSON `true` or `false`.
        Bool(bool),
        /// Any JSON number, kept as text so no precision is lost.
        Number(String),
        /// A JSON string with escapes resolved.
        Str(String),
        /// A JSON array.
        Array(Vec<Value>),
        /// A JSON object.
        Object(BTreeMap<String, Value>),
    }

    impl Value {
        /// Returns the string body, if this is a string.
        #[must_use]
        pub fn as_str(&self) -> Option<&str> {
            if let Self::Str(text) = self {
                return Some(text);
            }
            None
        }

        /// Returns the value as an unsigned integer, if it parses as one.
        #[must_use]
        pub fn as_u64(&self) -> Option<u64> {
            if let Self::Number(text) = self {
                return text.parse().ok();
            }
            None
        }

        /// Looks up an object member.
        #[must_use]
        pub fn get(&self, key: &str) -> Option<&Self> {
            if let Self::Object(members) = self {
                return members.get(key);
            }
            None
        }

        /// Collects every string and number reachable from this value.
        ///
        /// Documentation surfaces quote these as literal text, so numbers are
        /// compared in their source form rather than reformatted.
        #[must_use]
        pub fn leaf_strings(&self) -> Vec<String> {
            let mut collected = Vec::new();
            self.walk(&mut collected);
            collected
        }

        fn walk(&self, out: &mut Vec<String>) {
            match self {
                Self::Str(text) | Self::Number(text) => out.push(text.clone()),
                Self::Array(items) => {
                    for item in items {
                        item.walk(out);
                    }
                }
                Self::Object(members) => {
                    for value in members.values() {
                        value.walk(out);
                    }
                }
                Self::Null | Self::Bool(_) => {}
            }
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
        let value = parse_value(bytes, &mut cursor)?;
        skip_whitespace(bytes, &mut cursor);
        if cursor != bytes.len() {
            return Err(format!("trailing input at byte {cursor}"));
        }
        Ok(value)
    }

    fn parse_value(bytes: &[u8], cursor: &mut usize) -> Result<Value, String> {
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            None => Err("unexpected end of input".to_owned()),
            Some(b'{') => parse_object(bytes, cursor),
            Some(b'[') => parse_array(bytes, cursor),
            Some(b'"') => parse_string(bytes, cursor).map(Value::Str),
            Some(b't') => literal(bytes, cursor, "true", Value::Bool(true)),
            Some(b'f') => literal(bytes, cursor, "false", Value::Bool(false)),
            Some(b'n') => literal(bytes, cursor, "null", Value::Null),
            Some(_) => parse_number(bytes, cursor),
        }
    }

    fn parse_object(bytes: &[u8], cursor: &mut usize) -> Result<Value, String> {
        *cursor += 1;
        let mut members = BTreeMap::new();
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) == Some(&b'}') {
            *cursor += 1;
            return Ok(Value::Object(members));
        }
        loop {
            skip_whitespace(bytes, cursor);
            let key = parse_string(bytes, cursor)?;
            skip_whitespace(bytes, cursor);
            if bytes.get(*cursor) != Some(&b':') {
                return Err(format!("expected ':' at byte {cursor}"));
            }
            *cursor += 1;
            let value = parse_value(bytes, cursor)?;
            members.insert(key, value);
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

    fn parse_array(bytes: &[u8], cursor: &mut usize) -> Result<Value, String> {
        *cursor += 1;
        let mut items = Vec::new();
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) == Some(&b']') {
            *cursor += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(parse_value(bytes, cursor)?);
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
                b'"' => {
                    return String::from_utf8(out).map_err(|error| error.to_string());
                }
                b'\\' => {
                    let escape = bytes
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
                            let hex = bytes
                                .get(*cursor..*cursor + 4)
                                .ok_or_else(|| "truncated \\u escape".to_owned())?;
                            let text =
                                std::str::from_utf8(hex).map_err(|error| error.to_string())?;
                            let code =
                                u32::from_str_radix(text, 16).map_err(|error| error.to_string())?;
                            *cursor += 4;
                            let character = char::from_u32(code)
                                .ok_or_else(|| format!("invalid code point {code}"))?;
                            let mut buffer = [0_u8; 4];
                            out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                        }
                        other => return Err(format!("unknown escape \\{}", *other as char)),
                    }
                }
                other => out.push(other),
            }
        }
        Err("unterminated string".to_owned())
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
        std::str::from_utf8(&bytes[start..*cursor])
            .map(|text| Value::Number(text.to_owned()))
            .map_err(|error| error.to_string())
    }

    fn literal(
        bytes: &[u8],
        cursor: &mut usize,
        word: &str,
        value: Value,
    ) -> Result<Value, String> {
        if bytes.get(*cursor..*cursor + word.len()) == Some(word.as_bytes()) {
            *cursor += word.len();
            return Ok(value);
        }
        Err(format!("expected `{word}` at byte {cursor}"))
    }

    fn skip_whitespace(bytes: &[u8], cursor: &mut usize) {
        while let Some(byte) = bytes.get(*cursor) {
            if byte.is_ascii_whitespace() {
                *cursor += 1;
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest sits below the repository root")
            .to_path_buf()
    }

    #[test]
    fn the_repository_documentation_passes_every_policy() {
        let report = check(&repo_root());
        assert!(
            report.is_clean(),
            "documentation policy must hold on main:\n{}",
            report.render()
        );
        assert!(
            report.files > 30,
            "discovery found too few files: {}",
            report.files
        );
    }

    #[test]
    fn discovery_matches_the_legacy_globs() {
        let repo = repo_root();
        let found = markdown_files(&repo);
        let root_count = std::fs::read_dir(&repo)
            .expect("root must be readable")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file() && has_markdown_extension(&entry.path()))
            .count();
        assert!(
            found.len() > root_count,
            "discovery must include docs/ as well as the repository root"
        );
        assert!(
            found.windows(2).all(|pair| pair[0] <= pair[1]),
            "output must be sorted for stable diagnostics"
        );
    }

    #[test]
    fn images_are_not_treated_as_links() {
        let targets = markdown_link_targets("![diagram](missing.png) and [text](real.md)");
        assert_eq!(targets, vec!["real.md".to_owned()]);
    }

    #[test]
    fn anchors_schemes_and_empty_targets_are_not_local_paths() {
        let parent = Path::new("/repo/docs");
        assert!(local_target(parent, "#section").is_none());
        assert!(local_target(parent, "https://example.test/a").is_none());
        assert!(local_target(parent, "http://example.test/a").is_none());
        assert!(local_target(parent, "mailto:someone@example.test").is_none());
        assert!(local_target(parent, "   ").is_none());
        assert!(local_target(parent, "#").is_none());
    }

    #[test]
    fn a_fragment_is_stripped_before_resolution() {
        let resolved = local_target(Path::new("/repo/docs"), "cli.md#usage")
            .expect("a path with a fragment is still local");
        assert_eq!(resolved, Path::new("/repo/docs/cli.md"));
    }

    #[test]
    fn angle_brackets_and_percent_escapes_are_decoded() {
        let resolved = local_target(Path::new("/repo/docs"), "<my%20file.md>")
            .expect("an escaped path is local");
        assert_eq!(resolved, Path::new("/repo/docs/my file.md"));
    }

    #[test]
    fn parent_traversal_is_normalized_without_touching_the_filesystem() {
        let resolved =
            local_target(Path::new("/repo/docs"), "../README.md").expect("a parent link is local");
        assert_eq!(resolved, Path::new("/repo/README.md"));
        // The decisive property: normalisation works for a path that cannot exist.
        let missing = local_target(Path::new("/repo/docs"), "../nope/../also-missing.md")
            .expect("a missing parent link still resolves");
        assert_eq!(missing, Path::new("/repo/also-missing.md"));
    }

    #[test]
    fn an_escaping_link_is_detected_by_containment() {
        let repo = Path::new("/repo");
        let escaped =
            local_target(Path::new("/repo/docs"), "../../outside.md").expect("the target resolves");
        assert!(
            !escaped.starts_with(repo),
            "a link leaving the repository must fail containment: {}",
            escaped.display()
        );
    }

    #[test]
    fn every_forbidden_phrase_is_still_absent_outside_the_exempt_paths() {
        let repo = repo_root();
        let files = markdown_files(&repo);
        assert!(
            forbidden_phrase_failures(&repo, &files).is_empty(),
            "a forbidden phrase reappeared"
        );
        // Guard the guard: the exemption must actually be reachable, otherwise
        // this policy silently stops covering the decision register.
        assert!(
            files
                .iter()
                .any(|path| { relative_display(&repo, path).starts_with("docs/adr/") }),
            "the exempt path no longer matches any file, so the exemption is stale"
        );
    }

    #[test]
    fn a_section_returns_empty_when_the_heading_is_absent() {
        assert_eq!(section("no headings here", "## Start", "## End"), "");
        assert_eq!(
            section("a ## Start body ## End c", "## Start", "## End"),
            " body "
        );
        // A missing end heading yields the remainder, matching the legacy split.
        assert_eq!(section("a ## Start body", "## Start", "## End"), " body");
    }

    #[test]
    fn the_cargo_version_is_read_as_a_v_prefixed_tag() {
        assert_eq!(
            cargo_version("[package]\nname = \"x\"\nversion = \"1.8.0\"\n"),
            Some("v1.8.0".to_owned())
        );
        assert_eq!(cargo_version("no version"), None);
    }

    #[test]
    fn the_headline_data_file_parses_and_matches_the_manifest() {
        assert!(
            release_headline_failures(&repo_root()).is_empty(),
            "release headline consistency must hold on main"
        );
    }

    #[test]
    fn json_parses_the_shapes_the_headline_file_uses() {
        let value = json::parse(
            r#"{"schemaVersion":1,"release":"v1.8.0","setup":{"a":["1.02","0.98"]},"n":null,"b":true}"#,
        )
        .expect("the document must parse");
        assert_eq!(
            value.get("schemaVersion").and_then(json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            value.get("release").and_then(json::Value::as_str),
            Some("v1.8.0")
        );
        let leaves = value.get("setup").expect("setup exists").leaf_strings();
        assert_eq!(leaves, vec!["1.02".to_owned(), "0.98".to_owned()]);
    }

    #[test]
    fn json_reports_malformed_input_instead_of_accepting_it() {
        assert!(json::parse("{").is_err());
        assert!(json::parse(r#"{"a":}"#).is_err());
        assert!(json::parse(r#"{"a":1}trailing"#).is_err());
        assert!(json::parse(r#"{"a":"unterminated}"#).is_err());
    }

    #[test]
    fn json_resolves_escapes_including_unicode() {
        let value = json::parse(r#"{"a":"line\nbreak \u4e2d tab\t"}"#).expect("must parse");
        assert_eq!(
            value.get("a").and_then(json::Value::as_str),
            Some("line\nbreak 中 tab\t")
        );
    }

    #[test]
    fn a_clean_report_renders_the_legacy_summary_line() {
        let report = Report {
            failures: Vec::new(),
            files: 39,
        };
        assert_eq!(
            report.render(),
            "documentation links verified across 39 Markdown files"
        );
    }

    #[test]
    fn a_failing_report_lists_every_failure() {
        let report = Report {
            failures: vec!["a: bad".to_owned(), "b: worse".to_owned()],
            files: 2,
        };
        let rendered = report.render();
        assert!(rendered.starts_with("documentation validation failed:"));
        assert!(rendered.contains("- a: bad"));
        assert!(rendered.contains("- b: worse"));
    }
}
