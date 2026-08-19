//! Plain-text renderer for configuration diagnostics.
//!
//! One rustc-style rendering, readable without ANSI color on SSH sessions, CI
//! logs, systemd journals, and redirected files. All layout is deterministic:
//! tabs expand to four columns, long lines are windowed around the caret, and
//! secret spans are replaced with `[REDACTED]` before any display math.

use std::fmt::Write as _;

use super::source_map::{SourceMap, Span};

/// What one rendered source line is made of, before windowing.
#[derive(Debug)]
enum Cell {
    /// One source character; `\t` displays as four spaces.
    Char { src_start: usize, src_end: usize },
    /// One redacted secret byte range.
    Redacted { src_start: usize, src_end: usize },
}

const REDACTED: &str = "[REDACTED]";
/// Maximum display columns of one rendered source line.
const MAX_LINE_WIDTH: usize = 240;
/// Display columns kept before the caret when windowing long lines.
const WINDOW_MARGIN: usize = 120;

impl Cell {
    fn write(&self, output: &mut String, text: &str) {
        match self {
            Self::Char { src_start, src_end } => {
                let ch = &text[*src_start..*src_end];
                if ch == "\t" {
                    output.push_str("    ");
                } else {
                    push_sanitized(output, ch);
                }
            }
            Self::Redacted { .. } => output.push_str(REDACTED),
        }
    }

    fn display_width(&self, text: &str) -> usize {
        match self {
            Self::Char { src_start, src_end } => {
                if text[*src_start..*src_end] == *"\t" {
                    4
                } else {
                    1
                }
            }
            Self::Redacted { .. } => REDACTED.len(),
        }
    }

    fn src_start(&self) -> usize {
        match self {
            Self::Char { src_start, .. } | Self::Redacted { src_start, .. } => *src_start,
        }
    }

    fn src_end(&self) -> usize {
        match self {
            Self::Char { src_end, .. } | Self::Redacted { src_end, .. } => *src_end,
        }
    }
}

/// Appends one source character, replacing control characters (ESC among
/// them) with U+FFFD so hostile input can never inject terminal control
/// sequences into the rendered block.
fn push_sanitized(output: &mut String, ch: &str) {
    let mut chars = ch.chars();
    match chars.next() {
        Some(c) if c.is_control() => output.push(char::REPLACEMENT_CHARACTER),
        Some(c) => output.push(c),
        None => {}
    }
}

/// One located, fully prepared source excerpt.
#[derive(Debug)]
pub(super) struct Excerpt {
    pub line: usize,
    pub column: usize,
    pub text: String,
    pub caret_column: usize,
    pub caret_width: usize,
}

/// Finds the 1-based line number and the byte range of the line holding
/// `offset` (clamped to the document).
fn line_of(text: &str, offset: usize) -> (usize, usize, usize) {
    let offset = offset.min(text.len());
    let mut line = 1;
    let mut start = 0;
    for (index, ch) in text.char_indices() {
        if index >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            start = index + 1;
        }
    }
    let mut end = text[start..]
        .find('\n')
        .map_or(text.len(), |newline| start + newline);
    // A CR before LF belongs to neither the excerpt nor the column math.
    if end > start && text.as_bytes()[end - 1] == b'\r' {
        end -= 1;
    }
    (line, start, end)
}

/// Builds the display cells of one source line, applying redactions.
fn line_cells(text: &str, start: usize, end: usize, redactions: &[Span]) -> Vec<Cell> {
    let mut cells = Vec::new();
    let mut redactions: Vec<Span> = redactions
        .iter()
        .filter_map(|span| {
            let clipped = Span {
                start: span.start.max(start),
                end: span.end.min(end),
            };
            (clipped.start < clipped.end).then_some(clipped)
        })
        .collect();
    redactions.sort_by_key(|span| span.start);
    let mut cursor = start;
    for redaction in redactions {
        push_chars(text, cursor, redaction.start, &mut cells);
        cells.push(Cell::Redacted {
            src_start: redaction.start,
            src_end: redaction.end,
        });
        cursor = redaction.end;
    }
    push_chars(text, cursor, end, &mut cells);
    cells
}

fn push_chars(text: &str, start: usize, end: usize, cells: &mut Vec<Cell>) {
    let mut cursor = start;
    for ch in text[start..end].chars() {
        let next = cursor + ch.len_utf8();
        cells.push(Cell::Char {
            src_start: cursor,
            src_end: next,
        });
        cursor = next;
    }
}

/// Builds the excerpt for `span` (1-based line/column, windowed, redacted).
pub(super) fn build_excerpt(text: &str, map: &SourceMap, span: Span) -> Excerpt {
    let (line, line_start, line_end) = line_of(text, span.start);
    let cells = line_cells(text, line_start, line_end, map.redactions());

    // Display column of the caret within the fully rendered line (0-based):
    // every cell that ends at or before the span start.
    let mut column = 0;
    for cell in &cells {
        if cell.src_end() <= span.start {
            column += cell.display_width(text);
        } else {
            break;
        }
    }
    // Underline the cells overlapping the span, clamped to this line, at
    // least one caret wide.
    let span_end = span.end.min(line_end).max(span.start);
    let mut width = 0;
    for cell in &cells {
        if cell.src_start() >= span_end {
            break;
        }
        if cell.src_end() > span.start {
            width += cell.display_width(text);
        }
    }
    let width = width.max(1);

    // Window overly long lines around the caret.
    let total: usize = cells.iter().map(|cell| cell.display_width(text)).sum();
    let (window_start, window_end) = if total <= MAX_LINE_WIDTH {
        (0, total)
    } else {
        let start = column.saturating_sub(WINDOW_MARGIN);
        (start, (start + MAX_LINE_WIDTH).min(total))
    };
    let mut excerpt = String::new();
    if window_start > 0 {
        excerpt.push_str("...");
    }
    let prefix = excerpt.len();
    let mut caret_column = 0;
    let mut position = 0;
    for cell in &cells {
        let cell_width = cell.display_width(text);
        let next = position + cell_width;
        if next > window_start && position < window_end {
            if cell.src_end() <= span.start {
                caret_column += cell_width;
            }
            cell.write(&mut excerpt, text);
        }
        position = next;
        if position >= window_end {
            break;
        }
    }
    if window_end < total {
        excerpt.push_str("...");
    }
    Excerpt {
        line,
        column: column + 1,
        text: excerpt,
        caret_column: prefix + caret_column,
        caret_width: width,
    }
}

/// Renders one diagnostic block. Never emits ANSI control sequences.
pub(super) fn render(
    severity: &str,
    title: &str,
    file: &str,
    excerpt: Option<&Excerpt>,
    label: Option<&str>,
    notes: &[String],
) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "{severity}: {title}");
    let gutter = excerpt.map_or(1, |excerpt| excerpt.line.to_string().len());
    match excerpt {
        Some(excerpt) => {
            let _ = writeln!(
                output,
                "{:>gutter$}--> {file}:{}:{}",
                "", excerpt.line, excerpt.column
            );
            let _ = writeln!(output, "{:>gutter$} |", "");
            let _ = writeln!(output, "{:>gutter$} | {}", excerpt.line, excerpt.text);
            let _ = write!(
                output,
                "{:>gutter$} | {}{}",
                "",
                " ".repeat(excerpt.caret_column),
                "^".repeat(excerpt.caret_width)
            );
            if let Some(label) = label {
                let _ = write!(output, " {label}");
            }
            output.push('\n');
            if !notes.is_empty() {
                let _ = writeln!(output, "{:>gutter$} |", "");
            }
        }
        None => {
            let _ = writeln!(output, "{:>gutter$}--> {file}", "");
        }
    }
    for note in notes {
        let _ = writeln!(output, "{:>gutter$} = {note}", "");
    }
    // Display impls do not terminate the final line; callers add it.
    while output.ends_with('\n') {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{MAX_LINE_WIDTH, build_excerpt, render};
    use crate::config::diagnostic::source_map::{SourceMap, Span};

    fn excerpt_for(text: &str, start: usize, end: usize) -> super::Excerpt {
        build_excerpt(text, &SourceMap::scan(text), Span { start, end })
    }

    #[test]
    fn locates_lines_and_columns_by_character() {
        let text = "{\n  \"name\": \"héllo\"\n}\n";
        let start = text.find("héllo").expect("value must exist");
        let excerpt = excerpt_for(text, start, start + "héllo".len());
        assert_eq!(excerpt.line, 2);
        assert_eq!(excerpt.column, 12, "columns count characters, not bytes");
        assert_eq!(excerpt.caret_width, 5, "carets count characters, not bytes");
    }

    #[test]
    fn expands_tabs_in_excerpt_and_caret() {
        let text = "{\n\t\"a\": 1\n}\n";
        let start = text.find('1').expect("value must exist");
        let excerpt = excerpt_for(text, start, start + 1);
        assert_eq!(excerpt.text, "    \"a\": 1");
        assert_eq!(excerpt.column, 10);
        assert_eq!(excerpt.caret_column, 9);
    }

    #[test]
    fn windows_very_long_lines_around_the_caret() {
        let padding = "x".repeat(400);
        let text = format!("{{\"a\": \"{padding}ERROR{padding}\"}}");
        let start = text.find("ERROR").expect("marker must exist");
        let excerpt = excerpt_for(&text, start, start + 5);
        assert!(excerpt.text.starts_with("..."));
        assert!(excerpt.text.ends_with("..."));
        assert!(excerpt.text.len() <= MAX_LINE_WIDTH + 6);
        assert!(excerpt.text.contains("ERROR"));
        assert!(
            excerpt.column > MAX_LINE_WIDTH,
            "the header column is absolute"
        );
    }

    #[test]
    fn redacts_secret_spans() {
        let text = "{\n  \"privateKey\": \"secret-value-here\"\n}\n";
        let map = SourceMap::scan(text);
        let start = text.find("secret-value-here").expect("secret must exist");
        let excerpt = build_excerpt(
            text,
            &map,
            Span {
                start,
                end: start + 6,
            },
        );
        assert_eq!(excerpt.text, "  \"privateKey\": \"[REDACTED]\"");
        assert!(!excerpt.text.contains("secret"));
    }

    #[test]
    fn renders_the_rustc_shape_without_trailing_newline() {
        let text = "{\n  \"profile\": \"server\"\n}\n";
        let start = text.find("\"server\"").expect("value must exist");
        let excerpt = excerpt_for(text, start, start + 8);
        let rendered = render(
            "error",
            "invalid value for `runtime.profile`",
            "/etc/rust-reality/config.json",
            Some(&excerpt),
            Some("expected \"auto\", \"shared\", or \"dedicated\""),
            &[
                "configuration path: runtime.profile".to_owned(),
                "help: use \"dedicated\" only when this process owns the bounded host or cgroup"
                    .to_owned(),
            ],
        );
        let expected = concat!(
            "error: invalid value for `runtime.profile`\n",
            " --> /etc/rust-reality/config.json:2:14\n",
            "  |\n",
            "2 |   \"profile\": \"server\"\n",
            "  |              ^^^^^^^^ expected \"auto\", \"shared\", or \"dedicated\"\n",
            "  |\n",
            "  = configuration path: runtime.profile\n",
            "  = help: use \"dedicated\" only when this process owns the bounded host or cgroup"
        );
        assert_eq!(rendered, expected);
        assert!(!rendered.contains('\u{1b}'), "no ANSI escapes, ever");
    }
}
