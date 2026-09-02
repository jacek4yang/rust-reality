//! The three guards that decide whether a matrix sample means anything.
//!
//! A proxy benchmark can produce a beautiful number for the wrong reason, and the
//! matrix has been burned by all three of these:
//!
//! 1. **The origin choked, not the proxy.** The Go origin counts its own errors;
//!    if that counter moves during a cell, the origin was the bottleneck and every
//!    sample in the cell — for *every* implementation — is uninterpretable.
//! 2. **The upload never arrived.** An upload scenario's throughput is meaningless
//!    unless the origin actually received the bytes, so its per-`PUT` log is
//!    checked for both the request count and each byte count.
//! 3. **The tunnel was bypassed.** A curl that inherited the workspace proxy
//!    environment ignores `--socks5-hostname` for loopback URLs and measures a
//!    direct fetch. Stripping the variables is the first defence; counting the
//!    server's own `connection_accepted` events is the second, and it is the one
//!    that would catch a stripping bug.
//!
//! ## Reading files that are still being written
//!
//! The origin and the servers append while the run reads. [`LineTracker`] holds
//! back a trailing partial line rather than parsing half a record, and resumes
//! from its own offset so a cell sees only what happened during that cell.

use crate::{
    perf::json_in::{self, Value},
    process::Tool,
};

/// An incremental reader over an appended, line-oriented file.
#[derive(Debug)]
pub struct LineTracker {
    path: std::path::PathBuf,
    offset: u64,
}

impl LineTracker {
    /// Starts tracking `path` from its beginning.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
        }
    }

    /// Returns lines appended since the last call.
    ///
    /// A trailing partial line is held back: parsing half a record would either
    /// fail spuriously or, worse, succeed on a truncated one.
    pub fn new_lines(&mut self) -> Vec<String> {
        let Ok(data) = std::fs::read(&self.path) else {
            return Vec::new();
        };
        let start = usize::try_from(self.offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let fresh = &data[start..];
        let complete = match fresh.iter().rposition(|byte| *byte == b'\n') {
            Some(index) => &fresh[..=index],
            None => return Vec::new(),
        };
        self.offset += complete.len() as u64;
        String::from_utf8_lossy(complete)
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Discards everything appended so far, so the next read starts clean.
    pub fn drain(&mut self) {
        let _ = self.new_lines();
    }
}

/// The origin counters the saturation guard reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginStats {
    /// Requests the origin itself failed.
    pub errors: i64,
    /// GET requests served.
    pub gets: i64,
    /// PUT requests served.
    pub puts: i64,
}

/// Fetches `GET /__stats` from an origin.
///
/// The current matrix owns an embedded origin that always serves this endpoint,
/// so losing it means the saturation guard has lost its authority. Transport,
/// HTTP, syntax, shape, and counter failures therefore all fail closed.
///
/// # Errors
///
/// Returns a diagnostic when the endpoint cannot be fetched or does not contain
/// all three non-negative integer counters.
pub fn fetch_origin_stats(port: u16, scheme: &str) -> Result<OriginStats, String> {
    let mut curl = Tool::new("curl");
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        curl = curl.env(name, "");
    }
    let mut args = vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--max-time".to_owned(),
        "5".to_owned(),
    ];
    if scheme == "https" {
        args.push("--insecure".to_owned());
    }
    args.push(format!("{scheme}://127.0.0.1:{port}/__stats"));
    let outcome = curl
        .args(args)
        .run()
        .map_err(|error| format!("could not fetch {scheme} origin stats: {error}"))?;
    parse_origin_stats(outcome.trimmed_stdout())
}

fn parse_origin_stats(text: &str) -> Result<OriginStats, String> {
    let value = json_in::parse(text).map_err(|error| format!("invalid origin stats: {error}"))?;
    let counter = |name: &str| -> Result<i64, String> {
        let observed = value
            .int_field("origin stats", name)
            .map_err(|error| format!("invalid origin stats: {error}"))?;
        if observed < 0 {
            return Err(format!(
                "invalid origin stats: {name} counter is negative ({observed})"
            ));
        }
        Ok(observed)
    };
    Ok(OriginStats {
        errors: counter("errors")?,
        gets: counter("gets")?,
        puts: counter("puts")?,
    })
}

/// Whether the origin's own error counter moved between two snapshots.
///
/// A growing counter means the origin failed requests during the cell, so the
/// cell measured the origin rather than the proxy.
pub fn origin_error_delta(before: OriginStats, after: OriginStats) -> Result<Option<i64>, String> {
    for (name, before, after) in [
        ("errors", before.errors, after.errors),
        ("gets", before.gets, after.gets),
        ("puts", before.puts, after.puts),
    ] {
        if before < 0 || after < before {
            return Err(format!(
                "origin {name} counter moved backward from {before} to {after}"
            ));
        }
    }
    let delta = after
        .errors
        .checked_sub(before.errors)
        .ok_or_else(|| "origin errors counter delta overflowed".to_owned())?;
    Ok((delta > 0).then_some(delta))
}

/// The byte counts an origin logged for the `PUT`s of one sample.
#[must_use]
pub fn put_bytes(lines: &[String]) -> Vec<i64> {
    lines
        .iter()
        .filter_map(|line| {
            let value = json_in::parse(line).ok()?;
            match value.field("put", "bytes") {
                Ok(Value::Number(text)) => text.parse().ok(),
                _ => None,
            }
        })
        .collect()
}

/// Checks an upload scenario's origin-side byte log.
///
/// # Errors
///
/// Returns every problem found: a wrong `PUT` count, or any `PUT` whose byte
/// count differs from the payload.
pub fn verify_uploads(
    lines: &[String],
    expected_puts: usize,
    expected_bytes: i64,
    scheme: &str,
) -> Result<(), Vec<String>> {
    let observed = put_bytes(lines);
    let mut problems = Vec::new();
    if observed.len() != expected_puts {
        problems.push(format!(
            "{scheme} origin logged {} PUTs, expected {expected_puts}",
            observed.len()
        ));
    }
    for bytes in &observed {
        if *bytes != expected_bytes {
            problems.push(format!(
                "{scheme} origin received {bytes} != {expected_bytes} bytes"
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Counts `connection_accepted` events in a rust server's structured log.
#[must_use]
pub fn accepted_connections(lines: &[String]) -> usize {
    lines
        .iter()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| json_in::parse(line).ok())
        .filter(|value| {
            matches!(
                value.field("event", "event"),
                Ok(Value::Str(name)) if name == "connection_accepted"
            )
        })
        .count()
}

/// Checks that the server saw at least as many connections as curl opened.
///
/// Fewer accepted connections than requests means traffic reached the origin
/// without passing through the tunnel — the proxy environment leaking into curl
/// is the way this has actually happened.
///
/// # Errors
///
/// Returns the script's own diagnostic, which names the suspicion explicitly.
pub fn verify_not_bypassed(accepted: usize, expected: usize) -> Result<(), String> {
    if accepted >= expected {
        return Ok(());
    }
    Err(format!(
        "TUNNEL BYPASS SUSPECTED: only {accepted} connection_accepted events for {expected} \
         curl connections (proxy environment may have leaked into curl)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rr-guards-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn a_tracker_returns_only_what_is_new() {
        let path = scratch("incremental");
        std::fs::write(&path, "one\ntwo\n").unwrap();
        let mut tracker = LineTracker::new(&path);
        assert_eq!(tracker.new_lines(), ["one", "two"]);
        assert!(tracker.new_lines().is_empty());

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"three\n").unwrap();
        assert_eq!(tracker.new_lines(), ["three"]);
        let _ = std::fs::remove_file(&path);
    }

    /// Parsing half a record would either fail spuriously or succeed on a
    /// truncated one, so a trailing partial line waits for its newline.
    #[test]
    fn a_partial_final_line_is_held_back() {
        let path = scratch("partial");
        std::fs::write(&path, "{\"bytes\": 1}\n{\"byt").unwrap();
        let mut tracker = LineTracker::new(&path);
        assert_eq!(tracker.new_lines(), ["{\"bytes\": 1}"]);

        std::fs::write(&path, "{\"bytes\": 1}\n{\"bytes\": 2}\n").unwrap();
        assert_eq!(tracker.new_lines(), ["{\"bytes\": 2}"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_yields_nothing_rather_than_failing() {
        let mut tracker = LineTracker::new(scratch("absent"));
        assert!(tracker.new_lines().is_empty());
    }

    /// A growing error counter means the origin failed requests during the cell,
    /// so the cell measured the origin rather than the proxy.
    #[test]
    fn a_growing_origin_error_counter_is_detected() {
        let before = OriginStats {
            errors: 3,
            gets: 10,
            puts: 0,
        };
        let after = OriginStats {
            errors: 5,
            ..before
        };
        assert_eq!(origin_error_delta(before, after), Ok(Some(2)));
        assert_eq!(origin_error_delta(before, before), Ok(None));
    }

    #[test]
    fn an_origin_counter_reset_fails_closed() {
        let before = OriginStats {
            errors: 3,
            gets: 10,
            puts: 2,
        };
        for after in [
            OriginStats {
                errors: 2,
                ..before
            },
            OriginStats { gets: 9, ..before },
            OriginStats { puts: 1, ..before },
        ] {
            assert!(origin_error_delta(before, after).is_err());
        }
    }

    #[test]
    fn a_missing_origin_counter_is_not_rewritten_as_zero() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let body = "{\"gets\":1,\"puts\":2}\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });

        let observed = fetch_origin_stats(port, "http");
        server.join().unwrap();

        let error = observed.expect_err("a missing errors counter must fail closed");
        assert!(error.contains("errors"), "{error}");
    }

    #[test]
    fn origin_stats_require_non_negative_integer_counters() {
        let valid = parse_origin_stats(r#"{"errors":0,"gets":1,"puts":2}"#).unwrap();
        assert_eq!(valid.errors, 0);
        for invalid in [
            r#"{"gets":1,"puts":2}"#,
            r#"{"errors":0,"puts":2}"#,
            r#"{"errors":0,"gets":1}"#,
            r#"{"errors":"0","gets":1,"puts":2}"#,
            r#"{"errors":-1,"gets":1,"puts":2}"#,
        ] {
            assert!(parse_origin_stats(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn upload_accounting_checks_both_the_count_and_the_bytes() {
        let lines: Vec<String> = (0..4)
            .map(|_| r#"{"path": "/upload/32", "bytes": 33554432}"#.to_owned())
            .collect();
        verify_uploads(&lines, 4, 33_554_432, "https").expect("four exact PUTs");

        let problems = verify_uploads(&lines, 8, 33_554_432, "https").unwrap_err();
        assert!(problems[0].contains("logged 4 PUTs, expected 8"));

        let short = vec![r#"{"path": "/upload/32", "bytes": 1024}"#.to_owned()];
        let problems = verify_uploads(&short, 1, 33_554_432, "http").unwrap_err();
        assert!(problems[0].contains("received 1024 != 33554432 bytes"));

        // An upload scenario that logged nothing at all is the loudest failure.
        let problems = verify_uploads(&[], 4, 33_554_432, "https").unwrap_err();
        assert!(problems[0].contains("logged 0 PUTs"));
    }

    #[test]
    fn accepted_connections_counts_only_the_right_event() {
        let lines = vec![
            r#"{"event": "connection_accepted"}"#.to_owned(),
            r#"{"event": "connection_completed"}"#.to_owned(),
            r#"{"event": "connection_accepted"}"#.to_owned(),
            "not json at all".to_owned(),
            String::new(),
        ];
        assert_eq!(accepted_connections(&lines), 2);
    }

    #[test]
    fn a_bypassed_tunnel_is_named_explicitly() {
        verify_not_bypassed(4, 4).expect("every connection was accepted");
        verify_not_bypassed(5, 4).expect("more is fine; warm-up may linger");
        let error = verify_not_bypassed(1, 4).unwrap_err();
        assert!(error.starts_with("TUNNEL BYPASS SUSPECTED"), "{error}");
        assert!(error.contains("only 1 connection_accepted events for 4"));
    }
}
