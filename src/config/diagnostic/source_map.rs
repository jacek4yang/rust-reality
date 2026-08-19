//! Best-effort mapping from logical configuration paths to JSON source spans.
//!
//! This is a small tolerant scanner, not a JSON parser: it only runs after
//! `serde_json` has already accepted or rejected the document, on the cold
//! error path, and it never validates. Its single job is to record where each
//! object member and array element lives so diagnostics can underline the
//! offending source, and to record which spans hold secret values so the
//! renderer can redact them.

/// One inclusive-exclusive byte range in the source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Span {
    pub start: usize,
    pub end: usize,
}

/// One scanned JSON value with its structural children.
#[derive(Debug)]
pub(super) struct Node {
    /// Span of the quoted key in the parent object, when this node is an
    /// object member.
    key: Option<Span>,
    /// Span of the whole value, quotes included for strings.
    value: Span,
    /// Span of the string content without quotes; equals `value` otherwise.
    content: Span,
    kind: NodeKind,
}

#[derive(Debug)]
enum NodeKind {
    Object(Vec<Member>),
    Array(Vec<Node>),
    Scalar,
}

#[derive(Debug)]
struct Member {
    name: String,
    node: Node,
}

impl Node {
    /// Returns the span of the quoted object key, when present.
    pub(super) fn key_span(&self) -> Option<Span> {
        self.key
    }

    /// Returns the span of the whole value.
    pub(super) fn value_span(&self) -> Span {
        self.value
    }

    /// Returns the span of the scalar content (unquoted for strings).
    pub(super) fn content_span(&self) -> Span {
        self.content
    }

    /// Returns the first member with `name`.
    pub(super) fn member(&self, name: &str) -> Option<&Node> {
        match &self.kind {
            NodeKind::Object(members) => members
                .iter()
                .find(|member| member.name == name)
                .map(|member| &member.node),
            NodeKind::Array(_) | NodeKind::Scalar => None,
        }
    }

    /// Returns the last member with `name` (the offending one for duplicates).
    fn last_member(&self, name: &str) -> Option<&Node> {
        match &self.kind {
            NodeKind::Object(members) => members
                .iter()
                .rev()
                .find(|member| member.name == name)
                .map(|member| &member.node),
            NodeKind::Array(_) | NodeKind::Scalar => None,
        }
    }
}

/// Member names whose values must never appear in rendered diagnostics.
///
/// UUIDs (`id`, `userIds`) and short IDs authenticate users; private keys,
/// pre-shared keys, and SOCKS5 credentials are key material.
fn is_secret_member(name: &str) -> bool {
    matches!(
        name,
        "id" | "userIds"
            | "shortIds"
            | "privateKey"
            | "previousPrivateKeys"
            | "preSharedKey"
            | "previousPreSharedKeys"
            | "username"
            | "password"
    )
}

/// A scanned document: the root value tree plus every secret byte range.
#[derive(Debug)]
pub(super) struct SourceMap {
    root: Node,
    redactions: Vec<Span>,
}

/// One parsed segment of a logical path such as `inbounds[0].settings`.
#[derive(Debug, Eq, PartialEq)]
enum Segment<'a> {
    Name(&'a str),
    Index(usize),
}

/// Splits a serde/validator path (`a.b[0].c`) into segments.
fn parse_path(path: &str) -> Vec<Segment<'_>> {
    let mut segments = Vec::new();
    for part in path.split('.') {
        let mut rest = part;
        while let Some(open) = rest.find('[') {
            let name = &rest[..open];
            if !name.is_empty() {
                segments.push(Segment::Name(name));
            }
            let Some(close) = rest[open..].find(']') else {
                break;
            };
            let index = &rest[open + 1..open + close];
            let Ok(index) = index.parse::<usize>() else {
                break;
            };
            segments.push(Segment::Index(index));
            rest = &rest[open + close + 1..];
        }
        if !rest.is_empty() && !rest.contains(']') {
            segments.push(Segment::Name(rest));
        }
    }
    segments
}

impl SourceMap {
    /// Scans `text`, tolerating malformed input by keeping a partial map.
    pub(super) fn scan(text: &str) -> Self {
        let mut scanner = Scanner {
            text,
            bytes: text.as_bytes(),
            pos: 0,
            redactions: Vec::new(),
        };
        let root = scanner.parse_value(0).unwrap_or(Node {
            key: None,
            value: Span {
                start: 0,
                end: text.len(),
            },
            content: Span {
                start: 0,
                end: text.len(),
            },
            kind: NodeKind::Scalar,
        });
        Self {
            root,
            redactions: scanner.redactions,
        }
    }

    /// Returns the node at `path`, when the scanned tree reaches it.
    pub(super) fn lookup(&self, path: &str) -> Option<&Node> {
        let mut node = &self.root;
        for segment in parse_path(path) {
            node = match (segment, &node.kind) {
                (Segment::Name(name), NodeKind::Object(_)) => node.last_member(name)?,
                (Segment::Index(index), NodeKind::Array(elements)) => elements.get(index)?,
                _ => return None,
            };
        }
        Some(node)
    }

    /// Returns the last member `name` of the object at `parent_path`.
    pub(super) fn lookup_member(&self, parent_path: &str, name: &str) -> Option<&Node> {
        self.lookup(parent_path)?.last_member(name)
    }

    /// Returns every byte range whose contents must be redacted on display.
    pub(super) fn redactions(&self) -> &[Span] {
        &self.redactions
    }
}

/// Recursion bound matching `serde_json`'s own recursion limit.
const MAX_DEPTH: usize = 128;

struct Scanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    redactions: Vec<Span>,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Option<Node> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_whitespace();
        let start = self.pos;
        let kind = match self.peek()? {
            b'{' => self.parse_object(depth)?,
            b'[' => self.parse_array(depth)?,
            b'"' => {
                let (_, content, _) = self.parse_string()?;
                return Some(Node {
                    key: None,
                    value: Span {
                        start,
                        end: self.pos,
                    },
                    content,
                    kind: NodeKind::Scalar,
                });
            }
            b't' => self.parse_literal(b"true")?,
            b'f' => self.parse_literal(b"false")?,
            b'n' => self.parse_literal(b"null")?,
            b'-' | b'0'..=b'9' => self.parse_number()?,
            _ => return None,
        };
        Some(Node {
            key: None,
            value: Span {
                start,
                end: self.pos,
            },
            content: Span {
                start,
                end: self.pos,
            },
            kind,
        })
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Option<NodeKind> {
        if self.bytes.len() - self.pos < literal.len()
            || &self.bytes[self.pos..self.pos + literal.len()] != literal
        {
            return None;
        }
        self.pos += literal.len();
        Some(NodeKind::Scalar)
    }

    fn parse_number(&mut self) -> Option<NodeKind> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.pos += 1;
        }
        Some(NodeKind::Scalar)
    }

    fn parse_object(&mut self, depth: usize) -> Option<NodeKind> {
        self.pos += 1; // '{'
        let mut members = Vec::new();
        loop {
            self.skip_whitespace();
            // Malformed tails (the scanner is tolerant by design) keep the
            // members collected so far instead of failing the whole object.
            match self.peek() {
                Some(b'}') => {
                    self.pos += 1;
                    return Some(NodeKind::Object(members));
                }
                Some(b'"') => {}
                _ => return Some(NodeKind::Object(members)),
            }
            let Some((key, _, name)) = self.parse_string() else {
                return Some(NodeKind::Object(members));
            };
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Some(NodeKind::Object(members));
            }
            self.pos += 1;
            let secret = is_secret_member(&name);
            let Some(mut node) = self.parse_value(depth + 1) else {
                return Some(NodeKind::Object(members));
            };
            node.key = Some(key);
            if secret {
                self.mark_secret(&node);
            }
            members.push(Member { name, node });
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Some(NodeKind::Object(members));
                }
                _ => return Some(NodeKind::Object(members)),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Option<NodeKind> {
        self.pos += 1; // '['
        let mut elements = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Some(NodeKind::Array(elements));
            }
            let Some(element) = self.parse_value(depth + 1) else {
                return Some(NodeKind::Array(elements));
            };
            elements.push(element);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Some(NodeKind::Array(elements));
                }
                _ => return Some(NodeKind::Array(elements)),
            }
        }
    }

    /// Records the secret contents of one value: the string content for
    /// scalars, each string element for arrays (short IDs, retired keys).
    fn mark_secret(&mut self, node: &Node) {
        match &node.kind {
            NodeKind::Scalar => {
                if self.text.is_char_boundary(node.content.start)
                    && self.text.is_char_boundary(node.content.end)
                    && node.content.start <= node.content.end
                {
                    self.redactions.push(node.content);
                }
            }
            NodeKind::Array(elements) => {
                for element in elements {
                    if matches!(element.kind, NodeKind::Scalar)
                        && element.content.start < element.content.end
                    {
                        self.redactions.push(element.content);
                    }
                }
            }
            NodeKind::Object(_) => {}
        }
    }

    /// Parses one string token, returning the full span, the content span,
    /// and the best-effort decoded value (member names only need ASCII keys).
    fn parse_string(&mut self) -> Option<(Span, Span, String)> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        let content_start = self.pos;
        let mut decoded = String::new();
        loop {
            match self.peek()? {
                b'"' => {
                    let content_end = self.pos;
                    self.pos += 1;
                    if decoded.is_empty() {
                        decoded = self.text.get(content_start..content_end)?.to_owned();
                    }
                    return Some((
                        Span {
                            start: content_start - 1,
                            end: self.pos,
                        },
                        Span {
                            start: content_start,
                            end: content_end,
                        },
                        decoded,
                    ));
                }
                b'\\' => {
                    if decoded.is_empty() {
                        decoded = self.text.get(content_start..self.pos)?.to_owned();
                    }
                    self.pos += 1;
                    self.parse_escape(&mut decoded)?;
                }
                0x00..=0x1F => return None,
                _ => {
                    // Multi-byte UTF-8 never contains ASCII specials; skip one char.
                    let ch = self.text.get(self.pos..)?.chars().next()?;
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_escape(&mut self, decoded: &mut String) -> Option<()> {
        let escaped = self.peek()?;
        // Valid JSON escapes are ASCII; anything else (including the lead
        // byte of a multi-byte character) fails here so `pos` never lands
        // inside a UTF-8 sequence.
        if !escaped.is_ascii() {
            return None;
        }
        self.pos += 1;
        match escaped {
            b'"' => decoded.push('"'),
            b'\\' => decoded.push('\\'),
            b'/' => decoded.push('/'),
            b'b' => decoded.push('\u{8}'),
            b'f' => decoded.push('\u{c}'),
            b'n' => decoded.push('\n'),
            b'r' => decoded.push('\r'),
            b't' => decoded.push('\t'),
            b'u' => {
                let first = self.parse_hex4()?;
                let scalar = if (0xD800..0xDC00).contains(&first) {
                    // Surrogate pair: a lone trail surrogate decodes to U+FFFD.
                    if self.peek() == Some(b'\\') && self.bytes.get(self.pos + 1) == Some(&b'u') {
                        self.pos += 2;
                        let second = self.parse_hex4()?;
                        if (0xDC00..0xE000).contains(&second) {
                            0x1_0000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                        } else {
                            0xFFFD
                        }
                    } else {
                        0xFFFD
                    }
                } else if (0xDC00..0xE000).contains(&first) {
                    0xFFFD
                } else {
                    first
                };
                decoded.push(char::from_u32(scalar).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
            _ => return None,
        }
        Some(())
    }

    fn parse_hex4(&mut self) -> Option<u32> {
        let digits = self.bytes.get(self.pos..self.pos + 4)?;
        let mut value = 0u32;
        for digit in digits {
            value = value * 16 + char::from(*digit).to_digit(16)?;
        }
        self.pos += 4;
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceMap, is_secret_member, parse_path};

    #[test]
    fn looks_up_nested_members_and_elements() {
        let map = SourceMap::scan(
            r#"{"inbounds": [{"settings": {"clients": [{"id": "abc"}]}}], "port": 443}"#,
        );
        let node = map
            .lookup("inbounds[0].settings.clients[0].id")
            .expect("nested path must resolve");
        assert_eq!(node.key_span().map(|span| span.start), Some(41));
        let port = map.lookup("port").expect("scalar member must resolve");
        assert_eq!(
            &r#"{"inbounds": [{"settings": {"clients": [{"id": "abc"}]}}], "port": 443}"#
                [port.value_span().start..port.value_span().end],
            "443"
        );
        assert!(map.lookup("inbounds[1]").is_none());
        assert!(map.lookup("missing").is_none());
    }

    #[test]
    fn duplicate_members_resolve_to_the_last_one() {
        let map = SourceMap::scan(r#"{"mode": "a", "mode": "b"}"#);
        let node = map.lookup("mode").expect("member must resolve");
        assert_eq!(
            &r#"{"mode": "a", "mode": "b"}"#[node.value_span().start..node.value_span().end],
            "\"b\""
        );
    }

    #[test]
    fn marks_secret_values_for_redaction() {
        let text = r#"{"id": "uuid-here", "shortIds": ["aa", "bb"], "name": "kept"}"#;
        let map = SourceMap::scan(text);
        let redacted: Vec<&str> = map
            .redactions()
            .iter()
            .map(|span| &text[span.start..span.end])
            .collect();
        assert_eq!(redacted, ["uuid-here", "aa", "bb"]);
        assert!(is_secret_member("password"));
        assert!(!is_secret_member("name"));
    }

    #[test]
    fn tolerates_truncated_documents() {
        let map = SourceMap::scan(r#"{"a": [1, "#);
        assert!(map.lookup("a").is_some());
        assert!(map.lookup("a[0]").is_some());
        assert!(map.lookup("a[1]").is_none());
    }

    #[test]
    fn parses_validator_and_serde_path_shapes() {
        let segments = parse_path("routing.globalRules[12].ip[0]");
        assert_eq!(segments.len(), 5);
        assert!(parse_path("").is_empty());
        assert!(parse_path("?").len() == 1);
    }
}
