//! IPv6 end-to-end validation.
//!
//! Six phases, each appending rows to `results.jsonl`: environment capture,
//! listener bind/accept modes, VLESS+REALITY+Vision sessions over IPv6, a
//! host-global address with real Internet egress, large byte-exact transfers,
//! and a resilience phase over shaped namespace links.
//!
//! ## Why every row carries a classification
//!
//! An IPv6 claim is only as strong as the network it was made on. A session
//! that works over `::1` says nothing about a session over a routed global
//! address, and neither says anything about ingress from another host. The
//! legacy harness therefore tagged every row `loopback`, `namespace`,
//! `host-global` or `external`, and refused to let a loopback pass stand in for
//! anything else. That honesty is the reason this evidence is worth keeping, so
//! the classification is part of the row type rather than a free-text note.
//!
//! ## Egress family attribution
//!
//! Several cases turn on *which address family the server dialled*, which the
//! server does not log. The harness proves it the only way available: two
//! origins bound to the same port, one on `127.0.0.1` and one on `::1`, each
//! labelling its own access-log rows. Whichever one served the request is the
//! family that was chosen.

use std::path::{Path, PathBuf};

use crate::perf::json_out::Json;

/// How far the network under a result actually reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Loopback only: `::1` and `127.0.0.1`.
    Loopback,
    /// Inside network namespaces joined by veth links.
    Namespace,
    /// A real global address on this host.
    HostGlobal,
    /// Ingress from a host we do not control.
    External,
}

impl Classification {
    /// The wire name recorded in `results.jsonl`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Namespace => "namespace",
            Self::HostGlobal => "host-global",
            Self::External => "external",
        }
    }
}

/// The outcome of one recorded case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The case ran and met its expectation.
    Pass,
    /// The case ran and did not.
    Fail,
    /// The case could not run here, with a recorded reason.
    Skip,
    /// The environment cannot supply the capability this observation needs.
    Unavailable,
}

impl Status {
    /// The wire name recorded in `results.jsonl`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Unavailable => "unavailable",
        }
    }

    /// Turns a boolean expectation into a status.
    #[must_use]
    pub const fn from_met(met: bool) -> Self {
        if met { Self::Pass } else { Self::Fail }
    }
}

/// One row of `results.jsonl`.
#[derive(Debug, Clone)]
pub struct Record {
    /// Phase name, e.g. `2-sessions`.
    pub matrix: String,
    /// Case name within the phase.
    pub case: String,
    /// How far this result reaches.
    pub classification: Classification,
    /// Whether the expectation was met.
    pub status: Status,
    /// Case-specific evidence.
    pub detail: Json,
    /// Relative path of a log supporting the row; empty when there is none.
    pub evidence: String,
}

impl Record {
    /// Renders the row in the legacy `results.jsonl` shape.
    #[must_use]
    pub fn to_json(&self, timestamp: &str) -> Json {
        Json::object([
            ("ts", Json::string(timestamp)),
            ("matrix", Json::string(&self.matrix)),
            ("case", Json::string(&self.case)),
            ("classification", Json::string(self.classification.as_str())),
            ("status", Json::string(self.status.as_str())),
            ("detail", self.detail.clone()),
            ("evidence", Json::string(&self.evidence)),
        ])
    }
}

/// Appends rows to `results.jsonl` and keeps a tally for the final gate.
#[derive(Debug)]
pub struct Results {
    /// Where rows are appended.
    path: PathBuf,
    /// Every row recorded so far.
    rows: Vec<Record>,
}

impl Results {
    /// Opens (creating) the results file.
    ///
    /// # Errors
    ///
    /// Returns a message when the file cannot be created.
    pub fn create(path: PathBuf) -> Result<Self, String> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("could not open {}: {error}", path.display()))?;
        Ok(Self {
            path,
            rows: Vec::new(),
        })
    }

    /// Appends one row.
    ///
    /// # Errors
    ///
    /// Returns a message when the row cannot be written.
    pub fn record(&mut self, record: Record) -> Result<(), String> {
        use std::io::Write as _;
        let timestamp = crate::bench::evidence::now_utc()?;
        let line = record.to_json(&timestamp).to_jq_json();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("could not open {}: {error}", self.path.display()))?;
        writeln!(file, "{line}")
            .map_err(|error| format!("could not append to {}: {error}", self.path.display()))?;
        self.rows.push(record);
        Ok(())
    }

    /// Every row recorded so far.
    #[must_use]
    pub fn rows(&self) -> &[Record] {
        &self.rows
    }

    /// The names of the cases that failed.
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|row| row.status == Status::Fail)
            .map(|row| format!("{}/{}", row.matrix, row.case))
            .collect()
    }

    /// A `pass/fail/skip` tally.
    #[must_use]
    pub fn tally(&self) -> [usize; 3] {
        let count = |wanted: Status| self.rows.iter().filter(|row| row.status == wanted).count();
        [
            count(Status::Pass),
            count(Status::Fail),
            count(Status::Skip),
        ]
    }

    /// Number of capability-dependent observations that were unavailable.
    #[must_use]
    pub fn unavailable(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.status == Status::Unavailable)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Listener modes
// ---------------------------------------------------------------------------

/// The four listener modes the server accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerMode {
    /// Bind whatever is available.
    Auto,
    /// Bind both families, failing if either is unavailable.
    DualStack,
    /// Bind IPv4 only.
    Ipv4Only,
    /// Bind IPv6 only.
    Ipv6Only,
}

impl ListenerMode {
    /// Every mode, in the order the phase exercises them.
    pub const ALL: [Self; 4] = [Self::Auto, Self::DualStack, Self::Ipv4Only, Self::Ipv6Only];

    /// The `listen.mode` value in the config.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::DualStack => "dualStack",
            Self::Ipv4Only => "ipv4Only",
            Self::Ipv6Only => "ipv6Only",
        }
    }

    /// Which families must both listen and accept, on a dual-stack loopback.
    ///
    /// `auto` is expected to bind both here precisely because both are
    /// available: the interesting `auto` cases are the ones where a family is
    /// missing, and those are exercised in a namespace instead.
    #[must_use]
    pub const fn expected_families(self) -> (bool, bool) {
        match self {
            Self::Auto | Self::DualStack => (true, true),
            Self::Ipv4Only => (true, false),
            Self::Ipv6Only => (false, true),
        }
    }
}

/// Reports whether `ss -lntH` output shows a listener on this address and port.
///
/// `ss` renders IPv6 addresses bracketed, and a bare substring search would let
/// port 8080 match 18080, so the needle is built and compared per column.
#[must_use]
pub fn listener_present(ss_output: &str, address: &str, port: u16) -> bool {
    let needle = if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    };
    ss_output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .any(|local| local == needle)
}

/// Counts addresses still failing Duplicate Address Detection.
///
/// A freshly added IPv6 address is `tentative` until DAD completes, and binding
/// a concrete tentative address fails `EADDRNOTAVAIL`. Starting a server before
/// DAD finishes produces a bind failure that looks exactly like a
/// misconfiguration, so the topology waits this out rather than racing it.
#[must_use]
pub fn tentative_addresses(ip_output: &str) -> usize {
    ip_output
        .lines()
        .filter(|line| line.contains("tentative"))
        .count()
}

// ---------------------------------------------------------------------------
// Egress family attribution
// ---------------------------------------------------------------------------

/// The distinct origin labels that served a `GET` in `rows`.
///
/// Returned sorted and comma-joined, matching the legacy `unique | join(",")`.
/// An empty result means no origin served a request, which is itself a failure
/// signal rather than an absence of evidence.
#[must_use]
pub fn egress_servers(rows: &str) -> String {
    let mut labels: Vec<String> = rows
        .lines()
        .filter_map(|line| crate::perf::json_in::parse(line).ok())
        .filter_map(|value| {
            let crate::perf::json_in::Value::Object(members) = value else {
                return None;
            };
            let method = members.get("method")?.as_str("method").ok()?;
            if method != "GET" {
                return None;
            }
            Some(members.get("server")?.as_str("server").ok()?.to_owned())
        })
        .collect();
    labels.sort_unstable();
    labels.dedup();
    labels.join(",")
}

/// Tracks how much of an access log has already been attributed.
///
/// Attribution is per case, so each case marks the log first and reads only the
/// rows that appear afterwards. Reading the whole file instead would credit
/// every later case with every earlier case's origins.
#[derive(Debug, Default)]
pub struct AccessLogMark {
    /// Bytes already consumed.
    offset: u64,
}

impl AccessLogMark {
    /// Moves the mark to the current end of `path`.
    ///
    /// # Errors
    ///
    /// Returns a message when the file cannot be inspected.
    pub fn mark(&mut self, path: &Path) -> Result<(), String> {
        self.offset = match std::fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(format!("could not stat {}: {error}", path.display())),
        };
        Ok(())
    }

    /// Reads everything appended since the mark.
    ///
    /// # Errors
    ///
    /// Returns a message when the file cannot be read.
    pub fn since(&self, path: &Path) -> Result<String, String> {
        use std::io::{Read as _, Seek as _};
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
            Err(error) => return Err(format!("could not open {}: {error}", path.display())),
        };
        file.seek(std::io::SeekFrom::Start(self.offset))
            .map_err(|error| format!("could not seek {}: {error}", path.display()))?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        Ok(text)
    }
}

// ---------------------------------------------------------------------------
// curl
// ---------------------------------------------------------------------------

/// What one `curl` transfer reported.
#[derive(Debug, Clone)]
pub struct Transfer {
    /// `curl`'s exit code; zero on success.
    pub code: i32,
    /// The HTTP status, when one was received.
    pub http_code: String,
    /// Wall time `curl` measured, in seconds.
    pub seconds: f64,
    /// SHA-256 of the body written, or `none`.
    pub sha256: String,
}

impl Transfer {
    /// Whether the transfer succeeded and matched `expected`.
    #[must_use]
    pub fn byte_exact(&self, expected: &str) -> bool {
        self.code == 0 && self.sha256 == expected
    }

    /// The `{http_code} {time_total}` pair the legacy rows record verbatim.
    #[must_use]
    pub fn curl_field(&self) -> String {
        format!("{} {}", self.http_code, self.seconds)
    }
}

/// Parses curl's `%{http_code} %{time_total}` write-out.
///
/// A failed transfer still prints a write-out, so a parse failure here means
/// something other than the transfer went wrong and must not be read as zero.
///
/// # Errors
///
/// Returns a message when the write-out is not the expected two fields.
pub fn parse_write_out(text: &str) -> Result<(String, f64), String> {
    let mut fields = text.split_whitespace();
    let (Some(code), Some(seconds)) = (fields.next(), fields.next()) else {
        return Err(format!("curl write-out is not two fields: {text:?}"));
    };
    let seconds = seconds
        .parse::<f64>()
        .map_err(|error| format!("curl reported an unparsable time {seconds:?}: {error}"))?;
    Ok((code.to_owned(), seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications_and_statuses_keep_their_wire_names() {
        // These strings are the evidence contract; renaming a variant must not
        // silently rename a recorded classification.
        assert_eq!(Classification::Loopback.as_str(), "loopback");
        assert_eq!(Classification::Namespace.as_str(), "namespace");
        assert_eq!(Classification::HostGlobal.as_str(), "host-global");
        assert_eq!(Classification::External.as_str(), "external");
        assert_eq!(Status::from_met(true).as_str(), "pass");
        assert_eq!(Status::from_met(false).as_str(), "fail");
        assert_eq!(Status::Skip.as_str(), "skip");
        assert_eq!(Status::Unavailable.as_str(), "unavailable");
    }

    #[test]
    fn a_row_renders_the_legacy_shape() {
        let record = Record {
            matrix: "2-sessions".to_owned(),
            case: "a-v6in-v6egress-literal".to_owned(),
            classification: Classification::Loopback,
            status: Status::Pass,
            detail: Json::object([("byteExact", Json::Bool(true))]),
            evidence: "run/x/x2.xray.log".to_owned(),
        };
        let rendered = record.to_json("2026-08-29T05:50:07Z").to_jq_json();
        assert_eq!(
            rendered,
            r#"{"case":"a-v6in-v6egress-literal","classification":"loopback","detail":{"byteExact":true},"evidence":"run/x/x2.xray.log","matrix":"2-sessions","status":"pass","ts":"2026-08-29T05:50:07Z"}"#
        );
    }

    #[test]
    fn listener_modes_expect_the_families_they_name() {
        assert_eq!(ListenerMode::Auto.expected_families(), (true, true));
        assert_eq!(ListenerMode::DualStack.expected_families(), (true, true));
        assert_eq!(ListenerMode::Ipv4Only.expected_families(), (true, false));
        assert_eq!(ListenerMode::Ipv6Only.expected_families(), (false, true));
        assert_eq!(ListenerMode::DualStack.as_str(), "dualStack");
    }

    /// Real `ss -lntH` output, including a port that shares a prefix.
    const SS: &str = "\
LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*
LISTEN 0      4096           [::1]:8080          [::]:*
LISTEN 0      4096       127.0.0.1:18080      0.0.0.0:*
LISTEN 0      511          0.0.0.0:80          0.0.0.0:*";

    #[test]
    fn a_listener_is_matched_by_column_not_by_substring() {
        assert!(listener_present(SS, "127.0.0.1", 8080));
        assert!(listener_present(SS, "::1", 8080));
        // 8080 must not match 18080, and 80 must not match 8080.
        assert!(!listener_present(SS, "127.0.0.1", 808));
        assert!(!listener_present(SS, "::1", 18080));
        assert!(listener_present(SS, "0.0.0.0", 80));
        assert!(!listener_present(SS, "127.0.0.1", 9999));
    }

    #[test]
    fn tentative_addresses_are_counted_for_the_dad_wait() {
        let output = "\
    inet6 2001:db8:a::1/64 scope global tentative
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link tentative";
        assert_eq!(tentative_addresses(output), 2);
        assert_eq!(tentative_addresses("inet6 ::1/128 scope host"), 0);
    }

    #[test]
    fn egress_attribution_reads_only_get_rows() {
        let rows = concat!(
            r#"{"server":"origin-v6","method":"GET","path":"/p.bin","bytes":4,"sha256":"a"}"#,
            "\n",
            r#"{"server":"origin-v4","method":"PUT","path":"/u","bytes":4,"sha256":"b"}"#,
            "\n",
            r#"{"server":"origin-v6","method":"GET","path":"/p.bin","bytes":4,"sha256":"a"}"#,
            "\n",
        );
        // The PUT row must not contribute: uploads and downloads can take
        // different families, and this attributes the download.
        assert_eq!(egress_servers(rows), "origin-v6");
        assert_eq!(egress_servers(""), "");
    }

    #[test]
    fn egress_attribution_reports_every_family_that_served() {
        let rows = concat!(
            r#"{"server":"origin-v4","method":"GET","path":"/p","bytes":1,"sha256":"a"}"#,
            "\n",
            r#"{"server":"origin-v6","method":"GET","path":"/p","bytes":1,"sha256":"a"}"#,
            "\n",
        );
        // A case that expects one family must see exactly that one, so a split
        // across both has to be visible rather than collapsed to the first.
        assert_eq!(egress_servers(rows), "origin-v4,origin-v6");
    }

    #[test]
    fn a_truncated_access_log_line_is_ignored_rather_than_fatal() {
        // The origin appends whole lines, but a read can still land mid-write.
        let rows = concat!(
            r#"{"server":"origin-v6","method":"GET","path":"/p","bytes":1,"sha256":"a"}"#,
            "\n",
            r#"{"server":"origin-v4","meth"#,
        );
        assert_eq!(egress_servers(rows), "origin-v6");
    }

    #[test]
    fn the_access_log_mark_reads_only_what_followed_it() {
        let dir = std::env::temp_dir().join(format!("rr-ipv6-mark-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.jsonl");
        std::fs::write(&path, "first\n").unwrap();
        let mut mark = AccessLogMark::default();
        mark.mark(&path).unwrap();
        assert_eq!(mark.since(&path).unwrap(), "");
        std::fs::write(&path, "first\nsecond\n").unwrap();
        assert_eq!(mark.since(&path).unwrap(), "second\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_mark_on_a_missing_log_starts_at_zero() {
        let mut mark = AccessLogMark::default();
        let missing = std::path::Path::new("/nonexistent/access.jsonl");
        mark.mark(missing).unwrap();
        assert_eq!(mark.since(missing).unwrap(), "");
    }

    #[test]
    fn curl_write_out_is_parsed_or_rejected() {
        assert_eq!(
            parse_write_out("200 0.123").unwrap(),
            ("200".to_owned(), 0.123)
        );
        // A failed transfer still writes out, with a zero status.
        assert_eq!(
            parse_write_out("000 5.001").unwrap(),
            ("000".to_owned(), 5.001)
        );
        assert!(parse_write_out("200").is_err());
        assert!(parse_write_out("200 fast").is_err());
    }

    #[test]
    fn a_transfer_is_byte_exact_only_when_curl_also_succeeded() {
        let ok = Transfer {
            code: 0,
            http_code: "200".to_owned(),
            seconds: 0.5,
            sha256: "abc".to_owned(),
        };
        assert!(ok.byte_exact("abc"));
        assert!(!ok.byte_exact("def"));
        assert_eq!(ok.curl_field(), "200 0.5");
        // A non-zero curl exit with a matching digest is still a failure: the
        // body may be complete but the session was not.
        let failed = Transfer { code: 28, ..ok };
        assert!(!failed.byte_exact("abc"));
    }

    #[test]
    fn the_tally_counts_each_status() {
        let dir = std::env::temp_dir().join(format!("rr-ipv6-tally-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut results = Results::create(dir.join("results.jsonl")).unwrap();
        for (case, status) in [
            ("a", Status::Pass),
            ("b", Status::Fail),
            ("c", Status::Skip),
            ("d", Status::Pass),
        ] {
            results
                .record(Record {
                    matrix: "1-listeners".to_owned(),
                    case: case.to_owned(),
                    classification: Classification::Loopback,
                    status,
                    detail: Json::Null,
                    evidence: String::new(),
                })
                .unwrap();
        }
        assert_eq!(results.tally(), [2, 1, 1]);
        assert_eq!(results.unavailable(), 0);
        assert_eq!(results.failures(), vec!["1-listeners/b".to_owned()]);
        let written = std::fs::read_to_string(dir.join("results.jsonl")).unwrap();
        assert_eq!(written.lines().count(), 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn global_discovery_ignores_tentative_and_loopback_addresses() {
        let output = concat!(
            "1: lo inet6 ::1/128 scope host\n",
            "2: eth0 inet6 2001:db8::bad/64 scope global tentative\n",
            "2: eth0 inet6 240e:391::47/64 scope global dynamic\n",
        );
        assert_eq!(
            discover_global_ipv6(output).as_deref(),
            Some("240e:391::47")
        );
        assert_eq!(
            discover_global_ipv6("1: lo inet6 ::1/128 scope host\n"),
            None
        );
    }

    #[test]
    fn access_integrity_reads_the_last_matching_method() {
        let rows = concat!(
            r#"{"server":"o","method":"GET","bytes":4,"sha256":"get"}"#,
            "\n",
            r#"{"server":"o","method":"PUT","bytes":8,"sha256":"first"}"#,
            "\n",
            r#"{"server":"o","method":"PUT","bytes":16,"sha256":"last"}"#,
            "\n",
        );
        assert_eq!(access_integrity(rows, "PUT"), Some((16, "last".to_owned())));
        assert_eq!(access_integrity(rows, "PATCH"), None);
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// One `socks -> vless` path through an Xray client.
///
/// The IPv6 phases need several paths at once — different inbound families,
/// different servers, different dial policies — and starting one Xray per path
/// would multiply the processes without changing what is measured. A single
/// client with per-inbound routing keeps the client constant across cases.
#[derive(Debug, Clone)]
pub struct Leg {
    /// SOCKS port this leg listens on.
    pub socks_port: u16,
    /// Address of the REALITY server, literal or bracketed-free IPv6.
    pub server_address: String,
    /// Port of the REALITY server.
    pub server_port: u16,
    /// REALITY public key.
    pub public_key: String,
    /// Client UUID.
    pub uuid: String,
    /// REALITY short id.
    pub short_id: String,
}

/// Builds a multi-leg Xray client configuration.
///
/// Each leg gets its own inbound tag and a routing rule binding that tag to its
/// own outbound, so a request's SOCKS port alone determines which server and
/// dial policy it exercises.
#[must_use]
pub fn xray_config(legs: &[Leg]) -> Json {
    let inbound_tag = |leg: &Leg| format!("s{}", leg.socks_port);
    let outbound_tag = |leg: &Leg| format!("v{}", leg.socks_port);
    Json::object([
        ("log", Json::object([("loglevel", Json::string("warning"))])),
        (
            "inbounds",
            Json::Array(
                legs.iter()
                    .map(|leg| {
                        Json::object([
                            ("tag", Json::string(inbound_tag(leg))),
                            ("listen", Json::string("127.0.0.1")),
                            ("port", Json::Int(i64::from(leg.socks_port))),
                            ("protocol", Json::string("socks")),
                            (
                                "settings",
                                Json::object([
                                    ("auth", Json::string("noauth")),
                                    ("udp", Json::Bool(false)),
                                ]),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "outbounds",
            Json::Array(
                legs.iter()
                    .map(|leg| {
                        Json::object([
                            ("tag", Json::string(outbound_tag(leg))),
                            ("protocol", Json::string("vless")),
                            (
                                "settings",
                                Json::object([(
                                    "vnext",
                                    Json::Array(vec![Json::object([
                                        ("address", Json::string(&leg.server_address)),
                                        ("port", Json::Int(i64::from(leg.server_port))),
                                        (
                                            "users",
                                            Json::Array(vec![Json::object([
                                                ("id", Json::string(&leg.uuid)),
                                                ("encryption", Json::string("none")),
                                                ("flow", Json::string("xtls-rprx-vision")),
                                            ])]),
                                        ),
                                    ])]),
                                )]),
                            ),
                            (
                                "streamSettings",
                                Json::object([
                                    ("network", Json::string("tcp")),
                                    ("security", Json::string("reality")),
                                    (
                                        "realitySettings",
                                        Json::object([
                                            ("fingerprint", Json::string("chrome")),
                                            ("serverName", Json::string(COVER_SNI)),
                                            ("publicKey", Json::string(&leg.public_key)),
                                            ("shortId", Json::string(&leg.short_id)),
                                            ("spiderX", Json::string("/")),
                                        ]),
                                    ),
                                ]),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "routing",
            Json::object([
                ("domainStrategy", Json::string("AsIs")),
                (
                    "rules",
                    Json::Array(
                        legs.iter()
                            .map(|leg| {
                                Json::object([
                                    ("type", Json::string("field")),
                                    (
                                        "inboundTag",
                                        Json::Array(vec![Json::string(inbound_tag(leg))]),
                                    ),
                                    ("outboundTag", Json::string(outbound_tag(leg))),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
        ),
    ])
}

/// The SNI every REALITY leg in this suite presents.
pub const COVER_SNI: &str = "cover.test";

/// How a server's listener and outbound dialling are configured.
#[derive(Debug, Clone)]
pub struct ServerPlan {
    /// Short name; also the config and log file stem.
    pub name: String,
    /// Inbound port.
    pub port: u16,
    /// `listen.mode`.
    pub mode: ListenerMode,
    /// `listen.ipv4`.
    pub ipv4: String,
    /// `listen.ipv6`.
    pub ipv6: String,
    /// Cover target, `host:port` with IPv6 bracketed.
    pub target: String,
    /// Extra `network.dial` members, merged over the generated defaults.
    pub dial: Vec<(String, Json)>,
}

impl ServerPlan {
    /// A loopback dual-stack plan, which most cases start from.
    #[must_use]
    pub fn dual_stack(name: &str, port: u16, target: &str) -> Self {
        Self {
            name: name.to_owned(),
            port,
            mode: ListenerMode::DualStack,
            ipv4: "127.0.0.1".to_owned(),
            ipv6: "::1".to_owned(),
            target: target.to_owned(),
            dial: Vec::new(),
        }
    }

    /// Sets `network.dial.mode`.
    #[must_use]
    pub fn dialling(mut self, mode: &str) -> Self {
        self.dial.push(("mode".to_owned(), Json::string(mode)));
        self
    }

    /// The `listen` object this plan describes.
    #[must_use]
    pub fn listen_json(&self) -> Json {
        Json::object([
            ("mode", Json::string(self.mode.as_str())),
            ("ipv4", Json::string(&self.ipv4)),
            ("ipv6", Json::string(&self.ipv6)),
        ])
    }
}

/// The generated credentials and config for one rust-reality server.
#[derive(Debug, Clone)]
pub struct MaterializedServer {
    /// Short name inherited from the plan.
    pub name: String,
    /// Inbound port inherited from the plan.
    pub port: u16,
    /// REALITY public key consumed by Xray.
    pub public_key: String,
    /// VLESS client UUID consumed by Xray.
    pub uuid: String,
    /// REALITY short id consumed by Xray.
    pub short_id: String,
    /// Path to the finished rust-reality config.
    pub config_path: PathBuf,
}

/// Generates and materializes one rust-reality server plan.
///
/// Generation remains delegated to the product CLI so the suite cannot invent a
/// second identity/configuration model. The typed patch below changes only the
/// listener, target, asset deadline and outbound dial policy exercised here.
///
/// # Errors
///
/// Returns a message when generation, structural patching or writing fails.
pub fn materialize_server(
    workspace: &crate::bench::workspace::Workspace,
    rust_bin: &Path,
    plan: &ServerPlan,
) -> Result<MaterializedServer, String> {
    let generated = crate::bench::suites::generate_rust_identity(
        workspace,
        rust_bin,
        plan.port,
        &plan.target,
        COVER_SNI,
        Some(&workspace.join(&format!("{}.generate.log", plan.name))),
    )?;
    let config = patch_server_config(
        &generated.server_json,
        plan,
        &workspace.join(&format!("assets-{}", plan.name)),
    )?;
    let config_path = workspace.join(&format!("{}.server.json", plan.name));
    std::fs::write(&config_path, config)
        .map_err(|error| format!("could not write {}: {error}", config_path.display()))?;
    Ok(MaterializedServer {
        name: plan.name.clone(),
        port: plan.port,
        public_key: generated.public_key,
        uuid: generated.uuid,
        short_id: generated.short_id,
        config_path,
    })
}

/// Applies an IPv6 server plan to a generated standalone config.
fn patch_server_config(raw: &str, plan: &ServerPlan, cache: &Path) -> Result<String, String> {
    use crate::perf::json_in::{self, Value};

    fn object(
        value: Value,
        path: &str,
    ) -> Result<std::collections::BTreeMap<String, Value>, String> {
        let Value::Object(members) = value else {
            return Err(format!("generated rust config {path} is not an object"));
        };
        Ok(members)
    }

    let value = json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?;
    let mut root = object(value, "root")?;
    let inbounds = root
        .remove("inbounds")
        .ok_or_else(|| "generated rust config has no inbounds".to_owned())?;
    let Value::Array(mut inbounds) = inbounds else {
        return Err("generated rust config inbounds is not an array".to_owned());
    };
    if inbounds.len() != 1 {
        return Err(format!(
            "generated rust config has {} inbounds, expected exactly one",
            inbounds.len()
        ));
    }
    let mut inbound = object(inbounds.remove(0), "inbounds[0]")?;
    inbound.insert(
        "listen".to_owned(),
        json_in::parse(&plan.listen_json().to_jq_json())
            .map_err(|error| format!("listener plan is invalid JSON: {error}"))?,
    );
    inbound.insert("port".to_owned(), Value::Number(plan.port.to_string()));

    let stream = inbound
        .remove("streamSettings")
        .ok_or_else(|| "generated rust config has no inbounds[0].streamSettings".to_owned())?;
    let mut stream = object(stream, "inbounds[0].streamSettings")?;
    let reality = stream.remove("realitySettings").ok_or_else(|| {
        "generated rust config has no inbounds[0].streamSettings.realitySettings".to_owned()
    })?;
    let mut reality = object(reality, "inbounds[0].streamSettings.realitySettings")?;
    reality.insert("target".to_owned(), Value::Str(plan.target.clone()));
    stream.insert("realitySettings".to_owned(), Value::Object(reality));
    inbound.insert("streamSettings".to_owned(), Value::Object(stream));
    root.insert(
        "inbounds".to_owned(),
        Value::Array(vec![Value::Object(inbound)]),
    );

    let mut assets = match root.remove("assets") {
        Some(value) => object(value, "assets")?,
        None => std::collections::BTreeMap::new(),
    };
    assets.insert(
        "cacheDirectory".to_owned(),
        Value::Str(cache.display().to_string()),
    );
    assets.insert(
        "requestTimeoutSeconds".to_owned(),
        Value::Number("5".to_owned()),
    );
    root.insert("assets".to_owned(), Value::Object(assets));

    let network = root
        .remove("network")
        .ok_or_else(|| "generated rust config has no network".to_owned())?;
    let mut network = object(network, "network")?;
    let dial = network
        .remove("dial")
        .ok_or_else(|| "generated rust config has no network.dial".to_owned())?;
    let mut dial = object(dial, "network.dial")?;
    for (name, value) in &plan.dial {
        let value = json_in::parse(&value.to_jq_json())
            .map_err(|error| format!("dial plan field {name} is invalid JSON: {error}"))?;
        dial.insert(name.clone(), value);
    }
    network.insert("dial".to_owned(), Value::Object(dial));
    root.insert("network".to_owned(), Value::Object(network));
    Ok(crate::bench::suites::render_compact(&Value::Object(root)))
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use crate::perf::json_in;

    const GENERATED: &str = r#"{
      "inbounds":[{"listen":"127.0.0.1","port":1,
        "streamSettings":{"realitySettings":{"target":"old.test:443","keep":true}}}],
      "assets":{"cacheDirectory":"old"},
      "network":{"dial":{"mode":"auto","routeRefreshSeconds":30}},
      "untouched":{"value":7}
    }"#;

    #[test]
    fn a_server_plan_patches_only_the_ipv6_runtime_fields() {
        let plan = ServerPlan::dual_stack("s", 62_001, "[::1]:8443").dialling("preferIpv6");
        let rendered = patch_server_config(GENERATED, &plan, Path::new("/run/assets-s")).unwrap();
        let value = json_in::parse(&rendered).unwrap();
        assert_eq!(
            value.int_field("root", "untouched").unwrap_err().path,
            "root.untouched"
        );
        let inbound = &value.array_field("root", "inbounds").unwrap()[0];
        assert_eq!(inbound.int_field("inbound", "port").unwrap(), 62_001);
        let listen = inbound.field("inbound", "listen").unwrap();
        assert_eq!(listen.str_field("listen", "mode").unwrap(), "dualStack");
        assert_eq!(listen.str_field("listen", "ipv4").unwrap(), "127.0.0.1");
        assert_eq!(listen.str_field("listen", "ipv6").unwrap(), "::1");
        let stream = inbound.field("inbound", "streamSettings").unwrap();
        let reality = stream.field("stream", "realitySettings").unwrap();
        assert_eq!(
            reality.str_field("reality", "target").unwrap(),
            "[::1]:8443"
        );
        assert!(
            reality
                .field("reality", "keep")
                .unwrap()
                .as_bool("keep")
                .unwrap()
        );
        let assets = value.field("root", "assets").unwrap();
        assert_eq!(
            assets.str_field("assets", "cacheDirectory").unwrap(),
            "/run/assets-s"
        );
        assert_eq!(
            assets.int_field("assets", "requestTimeoutSeconds").unwrap(),
            5
        );
        let dial = value
            .field("root", "network")
            .unwrap()
            .field("network", "dial")
            .unwrap();
        assert_eq!(dial.str_field("dial", "mode").unwrap(), "preferIpv6");
        assert_eq!(dial.int_field("dial", "routeRefreshSeconds").unwrap(), 30);
        assert_eq!(
            value
                .field("root", "untouched")
                .unwrap()
                .int_field("untouched", "value")
                .unwrap(),
            7
        );
    }

    #[test]
    fn config_shape_drift_fails_closed() {
        let plan = ServerPlan::dual_stack("s", 62_001, "[::1]:8443");
        let error = patch_server_config("{}", &plan, Path::new("/run/assets")).unwrap_err();
        assert!(error.contains("no inbounds"), "{error}");
        let error = patch_server_config(
            r#"{"inbounds":[],"network":{"dial":{}}}"#,
            &plan,
            Path::new("/run/assets"),
        )
        .unwrap_err();
        assert!(error.contains("expected exactly one"), "{error}");
    }
}

fn cover_certificate(
    suite: &Ipv6Suite,
    workspace: &crate::bench::workspace::Workspace,
) -> Result<crate::bench::no_ccs::CoverCertificate, String> {
    crate::bench::no_ccs::build_certificate(
        &suite.openssl_bin,
        workspace.path(),
        &crate::bench::no_ccs::CertificatePlan {
            ca_subject: format!("/CN=rust-reality IPv6 validation CA {}", suite.run_id),
            leaf_subject: format!("/CN={COVER_SNI}"),
            subject_alt_name: "DNS:cover.test,IP:127.0.0.1,IP:::1".to_owned(),
            verify_hostname: Some(COVER_SNI.to_owned()),
        },
    )
}

fn tool_capture(title: &str, program: &str, args: &[&str]) -> String {
    match crate::process::Tool::new(program)
        .args(args.iter().copied())
        .probe()
    {
        Ok(outcome) => format!("=== {title} ===\n{}{}", outcome.stdout, outcome.stderr),
        Err(error) => format!("=== {title} ===\nUNAVAILABLE: {error}\n"),
    }
}

fn phase0(
    suite: &Ipv6Suite,
    run: &crate::bench::evidence::RunDirectory,
    results: &mut Results,
) -> Result<(), String> {
    let mut environment = String::new();
    environment.push_str(&tool_capture("uname", "uname", &["-a"]));
    environment.push_str(&tool_capture(
        "rust-reality",
        &suite.rust_bin.display().to_string(),
        &["--version"],
    ));
    environment.push_str(&tool_capture(
        "xray",
        &suite.xray_bin.display().to_string(),
        &["version"],
    ));
    for (title, args) in [
        ("ip -6 addr", &["-6", "addr"][..]),
        ("ip -6 route", &["-6", "route"][..]),
        ("ip -6 rule", &["-6", "rule"][..]),
        ("ip -4 route", &["-4", "route"][..]),
    ] {
        environment.push_str(&tool_capture(title, "ip", args));
    }
    environment.push_str(&tool_capture(
        "sysctl",
        "sysctl",
        &[
            "net.ipv6.conf.all.disable_ipv6",
            "net.ipv6.conf.default.disable_ipv6",
            "net.ipv6.bindv6only",
            "net.ipv6.conf.all.forwarding",
            "net.ipv4.ip_forward",
        ],
    ));
    run.write_new("environment.txt", &environment)?;
    results.record(Record {
        matrix: "0-environment".to_owned(),
        case: "capture".to_owned(),
        classification: Classification::Loopback,
        status: Status::Pass,
        detail: Json::object([("path", Json::string("environment.txt"))]),
        evidence: "environment.txt".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// Inputs to the native IPv6 end-to-end gate.
#[derive(Debug, Clone)]
pub struct Ipv6Suite {
    /// Repository root, used to build the benchmark origin.
    pub repo: PathBuf,
    /// rust-reality binary under test.
    pub rust_bin: PathBuf,
    /// Unmodified Xray client binary.
    pub xray_bin: PathBuf,
    /// OpenSSL used only to create the ephemeral cover certificate.
    pub openssl_bin: PathBuf,
    /// Fresh durable evidence directory.
    pub out_dir: PathBuf,
    /// Safe run identifier.
    pub run_id: String,
    /// Selected phase digits, in execution order.
    pub phases: String,
    /// Explicit host-global IPv6 address, or automatic host discovery.
    pub global_ipv6: Option<String>,
    /// MiB transferred in each large-transfer direction.
    pub transfer_mib: u64,
    /// Public IPv6 URL used by phase 3.
    pub internet_url: String,
}

/// Validates the IPv6 gate's operator inputs.
///
/// # Errors
///
/// Returns a message when a value would make evidence ambiguous or unsafe.
pub fn validate(suite: &Ipv6Suite) -> Result<(), String> {
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if suite.phases.is_empty() || !suite.phases.chars().all(|phase| matches!(phase, '0'..='5')) {
        return Err("IPv6 phases must be a non-empty string containing only 0..5".to_owned());
    }
    if suite.transfer_mib == 0 {
        return Err("the IPv6 transfer size must be at least 1 MiB".to_owned());
    }
    if let Some(address) = &suite.global_ipv6 {
        let parsed = address
            .parse::<std::net::IpAddr>()
            .map_err(|error| format!("global IPv6 address {address:?} is invalid: {error}"))?;
        if !parsed.is_ipv6() {
            return Err("--global-v6 must be an IPv6 address".to_owned());
        }
    }
    Ok(())
}

/// Starts one materialized rust-reality server with the private cover CA.
fn start_server_raw(
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    server: &MaterializedServer,
    ca_certificate: &Path,
) -> Result<crate::bench::process::Child, String> {
    crate::bench::process::Child::spawn(
        format!("rust-{}", server.name),
        rust_bin,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            server.config_path.display().to_string(),
        ],
        workspace.path(),
        &[(
            "SSL_CERT_FILE".to_owned(),
            ca_certificate.display().to_string(),
        )],
        &run.join(&format!("{}.rust.log", server.name)),
    )
    .map_err(|error| error.to_string())
}

/// Returns whether an address accepts a TCP connection within a short deadline.
fn tcp_accepts(address: std::net::SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(500)).is_ok()
}

/// Waits for a child to exit, without ever signalling an unrelated PID.
fn exits_within(child: &mut crate::bench::process::Child, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !child.is_alive() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    !child.is_alive()
}

/// Reads the host TCP listener table.
fn socket_table() -> Result<String, String> {
    let outcome = crate::process::Tool::new("ss")
        .args(["-lntH"])
        .probe()
        .map_err(|error| format!("could not inspect TCP listeners: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "ss -lntH exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    Ok(outcome.stdout)
}

fn namespace_socket_table(namespace: &str) -> Result<String, String> {
    let outcome = crate::bench::ipv6_netns::command_in(
        namespace,
        Path::new("ss"),
        &["-lntH".to_owned()],
        &[],
    )?;
    if !outcome.success() {
        return Err(format!(
            "ss -lntH in {namespace} exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    Ok(outcome.stdout)
}

fn namespace_tcp_connected(namespace: &str, address: &str, port: u16) -> Result<bool, String> {
    let url = if address.contains(':') {
        format!("http://[{address}]:{port}/")
    } else {
        format!("http://{address}:{port}/")
    };
    let args = vec![
        "--silent".to_owned(),
        "--output".to_owned(),
        "/dev/null".to_owned(),
        "--connect-timeout".to_owned(),
        "1".to_owned(),
        "--max-time".to_owned(),
        "1".to_owned(),
        "--write-out".to_owned(),
        "%{time_connect}".to_owned(),
        url,
    ];
    let env = [
        ("ALL_PROXY".to_owned(), String::new()),
        ("all_proxy".to_owned(), String::new()),
        ("HTTP_PROXY".to_owned(), String::new()),
        ("http_proxy".to_owned(), String::new()),
        ("HTTPS_PROXY".to_owned(), String::new()),
        ("https_proxy".to_owned(), String::new()),
        ("NO_PROXY".to_owned(), String::new()),
        ("no_proxy".to_owned(), String::new()),
    ];
    let outcome = crate::bench::ipv6_netns::command_in(namespace, Path::new("curl"), &args, &env)?;
    Ok(outcome
        .trimmed_stdout()
        .parse::<f64>()
        .is_ok_and(|seconds| seconds > 0.0))
}

fn start_server_in_namespace(
    namespace: &str,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    server: &MaterializedServer,
    ca_certificate: &Path,
) -> Result<crate::bench::process::Child, String> {
    crate::bench::ipv6_netns::spawn_in(
        namespace,
        &format!("rust-{}", server.name),
        rust_bin,
        &[
            "serve".to_owned(),
            "--config".to_owned(),
            server.config_path.display().to_string(),
        ],
        workspace.path(),
        &[(
            "SSL_CERT_FILE".to_owned(),
            ca_certificate.display().to_string(),
        )],
        &run.join(&format!("{}.rust.log", server.name)),
    )
}

fn run_disabled_ipv6_listener_cases(
    run_id: &str,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    ca_certificate: &Path,
    ports: &[u16],
    results: &mut Results,
) -> Result<(), String> {
    if !crate::bench::ipv6_netns::sudo_available() {
        return results.record(Record {
            matrix: "1-listeners".to_owned(),
            case: "no-ipv6-ns".to_owned(),
            classification: Classification::Namespace,
            status: Status::Unavailable,
            detail: Json::object([("reason", Json::string("no passwordless sudo"))]),
            evidence: String::new(),
        });
    }

    let disabled = crate::bench::ipv6_netns::DisabledIpv6::create(run_id)?;
    let namespace = disabled.name().to_owned();
    let outcome = (|| {
        let ipv6_only_plan = ServerPlan {
            name: "l1-no6-v6only".to_owned(),
            port: ports[0],
            mode: ListenerMode::Ipv6Only,
            ipv4: "0.0.0.0".to_owned(),
            ipv6: "::1".to_owned(),
            target: "[::1]:1".to_owned(),
            dial: Vec::new(),
        };
        let ipv6_only = materialize_server(workspace, rust_bin, &ipv6_only_plan)?;
        let mut child = start_server_in_namespace(
            &namespace,
            workspace,
            run,
            rust_bin,
            &ipv6_only,
            ca_certificate,
        )?;
        let failed = exits_within(&mut child, std::time::Duration::from_secs(8));
        results.record(Record {
            matrix: "1-listeners".to_owned(),
            case: "no-ipv6-ns-ipv6only-fails".to_owned(),
            classification: Classification::Namespace,
            status: Status::from_met(failed),
            detail: Json::object([
                ("ns", Json::string("disable_ipv6=1")),
                (
                    "expect",
                    Json::string("EADDRNOTAVAIL on concrete ::1 is fatal"),
                ),
            ]),
            evidence: format!("{}.rust.log", ipv6_only.name),
        })?;
        child.terminate();

        let auto_plan = ServerPlan {
            name: "l1-no6-auto".to_owned(),
            port: ports[1],
            mode: ListenerMode::Auto,
            ipv4: "127.0.0.1".to_owned(),
            ipv6: "::".to_owned(),
            target: "[::1]:1".to_owned(),
            dial: Vec::new(),
        };
        let auto = materialize_server(workspace, rust_bin, &auto_plan)?;
        let mut child =
            start_server_in_namespace(&namespace, workspace, run, rust_bin, &auto, ca_certificate)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut served_ipv4 = false;
        while std::time::Instant::now() < deadline && child.is_alive() {
            let listening = namespace_socket_table(&namespace)
                .is_ok_and(|table| listener_present(&table, "127.0.0.1", auto.port));
            if listening && namespace_tcp_connected(&namespace, "127.0.0.1", auto.port)? {
                served_ipv4 = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        results.record(Record {
            matrix: "1-listeners".to_owned(),
            case: "no-ipv6-ns-auto-serves-v4".to_owned(),
            classification: Classification::Namespace,
            status: Status::from_met(served_ipv4),
            detail: Json::object([
                ("port", Json::Int(i64::from(auto.port))),
                (
                    "note",
                    Json::string(
                        "wildcard [::] bind remains optional in auto mode; IPv4 acceptance verified",
                    ),
                ),
            ]),
            evidence: format!("{}.rust.log", auto.name),
        })?;
        child.terminate();
        Ok(())
    })();
    drop(disabled);
    crate::bench::ipv6_netns::DisabledIpv6::verify_removed(&namespace)?;
    outcome
}

/// Records the non-privileged listener contract from phase 1.
#[allow(
    clippy::too_many_lines,
    reason = "the phase owns the run, workspace, identity, certificate and results"
)]
pub fn run_local_listener_phase(
    run_id: &str,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    ca_certificate: &Path,
    results: &mut Results,
) -> Result<(), String> {
    let ports = crate::bench::workspace::reserve_ports(8)?;
    for (index, mode) in ListenerMode::ALL.into_iter().enumerate() {
        let port = ports[index];
        let plan = ServerPlan {
            name: format!("l1-{}", mode.as_str()),
            port,
            mode,
            ipv4: "127.0.0.1".to_owned(),
            ipv6: "::1".to_owned(),
            target: "[::1]:1".to_owned(),
            dial: Vec::new(),
        };
        let materialized = materialize_server(workspace, rust_bin, &plan)?;
        let mut child = start_server_raw(workspace, run, rust_bin, &materialized, ca_certificate)?;
        let readiness = if mode == ListenerMode::Ipv4Only {
            std::net::SocketAddr::from(([127, 0, 0, 1], port))
        } else {
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))
        };
        child
            .wait_for_address(readiness, std::time::Duration::from_secs(10))
            .map_err(|error| error.to_string())?;
        let table = socket_table()?;
        let v4_listen = listener_present(&table, "127.0.0.1", port);
        let v6_listen = listener_present(&table, "::1", port);
        let v4_accept = tcp_accepts(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        let v6_accept = tcp_accepts(std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)));
        let expected = mode.expected_families();
        let met = (v4_listen && v4_accept, v6_listen && v6_accept) == expected;
        results.record(Record {
            matrix: "1-listeners".to_owned(),
            case: format!("mode-{}", mode.as_str()),
            classification: Classification::Loopback,
            status: Status::from_met(met),
            detail: Json::object([
                ("mode", Json::string(mode.as_str())),
                ("port", Json::Int(i64::from(port))),
                (
                    "v4Listen",
                    Json::string(if v4_listen { "present" } else { "absent" }),
                ),
                (
                    "v6Listen",
                    Json::string(if v6_listen { "present" } else { "absent" }),
                ),
                (
                    "v4Accept",
                    Json::string(if v4_accept { "accepted" } else { "refused" }),
                ),
                (
                    "v6Accept",
                    Json::string(if v6_accept { "accepted" } else { "refused" }),
                ),
                (
                    "expectV4",
                    Json::string(if expected.0 { "yes" } else { "no" }),
                ),
                (
                    "expectV6",
                    Json::string(if expected.1 { "yes" } else { "no" }),
                ),
            ]),
            evidence: format!("{}.rust.log", materialized.name),
        })?;
        child.terminate();
    }

    let bad_plan = ServerPlan {
        name: "l1-badaddr".to_owned(),
        port: ports[4],
        mode: ListenerMode::Auto,
        ipv4: "127.0.0.1".to_owned(),
        ipv6: "2001:db8::ffff".to_owned(),
        target: "[::1]:1".to_owned(),
        dial: Vec::new(),
    };
    let bad = materialize_server(workspace, rust_bin, &bad_plan)?;
    let mut child = start_server_raw(workspace, run, rust_bin, &bad, ca_certificate)?;
    let failed = exits_within(&mut child, std::time::Duration::from_secs(8));
    results.record(Record {
        matrix: "1-listeners".to_owned(),
        case: "auto-concrete-unassigned-v6-fatal".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(failed),
        detail: Json::object([(
            "expect",
            Json::string("serve exits non-zero: EADDRNOTAVAIL on a concrete address is fatal"),
        )]),
        evidence: format!("{}.rust.log", bad.name),
    })?;
    child.terminate();

    let owner_plan = ServerPlan {
        name: "l1-busy-a".to_owned(),
        port: ports[5],
        mode: ListenerMode::Ipv6Only,
        ipv4: "0.0.0.0".to_owned(),
        ipv6: "::1".to_owned(),
        target: "[::1]:1".to_owned(),
        dial: Vec::new(),
    };
    let owner = materialize_server(workspace, rust_bin, &owner_plan)?;
    let mut owner_child = start_server_raw(workspace, run, rust_bin, &owner, ca_certificate)?;
    owner_child
        .wait_for_address(
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], ports[5])),
            std::time::Duration::from_secs(10),
        )
        .map_err(|error| error.to_string())?;
    let contender_plan = ServerPlan {
        name: "l1-busy-b".to_owned(),
        port: ports[5],
        mode: ListenerMode::Auto,
        ipv4: "127.0.0.1".to_owned(),
        ipv6: "::1".to_owned(),
        target: "[::1]:1".to_owned(),
        dial: Vec::new(),
    };
    let contender = materialize_server(workspace, rust_bin, &contender_plan)?;
    let mut contender_child =
        start_server_raw(workspace, run, rust_bin, &contender, ca_certificate)?;
    let failed = exits_within(&mut contender_child, std::time::Duration::from_secs(8));
    results.record(Record {
        matrix: "1-listeners".to_owned(),
        case: "addr-in-use-fatal".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(failed),
        detail: Json::object([
            ("port", Json::Int(i64::from(ports[5]))),
            ("expect", Json::string("EADDRINUSE fatal even in auto mode")),
        ]),
        evidence: format!("{}.rust.log", contender.name),
    })?;
    contender_child.terminate();
    owner_child.terminate();
    run_disabled_ipv6_listener_cases(
        run_id,
        workspace,
        run,
        rust_bin,
        ca_certificate,
        &ports[6..8],
        results,
    )
}

/// A curl command with every ambient proxy variable cleared.
fn clean_curl() -> crate::process::Tool {
    let mut curl = crate::process::Tool::new("curl");
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
    curl
}

/// Runs one download through an Xray SOCKS listener.
fn download(
    socks_port: u16,
    url: &str,
    destination: &Path,
    max_time: u64,
) -> Result<Transfer, String> {
    let outcome = clean_curl()
        .args([
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{socks_port}"),
            "--max-time".to_owned(),
            max_time.to_string(),
            "--output".to_owned(),
            destination.display().to_string(),
            "--write-out".to_owned(),
            "%{http_code} %{time_total}".to_owned(),
            url.to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not run curl: {error}"))?;
    transfer_from_outcome(&outcome, destination)
}

/// Converts curl's process result and body file into typed transfer evidence.
fn transfer_from_outcome(
    outcome: &crate::process::Outcome,
    destination: &Path,
) -> Result<Transfer, String> {
    let (http_code, seconds) = match parse_write_out(outcome.trimmed_stdout()) {
        Ok(parsed) => parsed,
        Err(_) if !outcome.success() => ("000".to_owned(), outcome.elapsed.as_secs_f64()),
        Err(error) => return Err(error),
    };
    let sha256 = if destination.is_file() {
        crate::hash::sha256_file(destination)?
    } else {
        "none".to_owned()
    };
    Ok(Transfer {
        code: outcome.code.unwrap_or(-1),
        http_code,
        seconds,
        sha256,
    })
}

/// Renders the common per-transfer detail object.
fn transfer_detail(url: &str, transfer: &Transfer, expected: &str) -> Json {
    Json::object([
        ("url", Json::string(url)),
        ("curl", Json::string(transfer.curl_field())),
        ("rc", Json::Int(i64::from(transfer.code))),
        ("sha256", Json::string(&transfer.sha256)),
        ("expectSha256", Json::string(expected)),
        ("elapsedS", Json::Float(transfer.seconds)),
        ("byteExact", Json::Bool(transfer.byte_exact(expected))),
    ])
}

/// Starts an Xray client from a typed multi-leg plan.
fn start_xray(
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    xray_bin: &Path,
    name: &str,
    legs: &[Leg],
) -> Result<crate::bench::process::Child, String> {
    let path = workspace.join(&format!("{name}.xray.json"));
    std::fs::write(&path, xray_config(legs).to_python_json())
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    crate::bench::process::Child::spawn(
        format!("xray-{name}"),
        xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            path.display().to_string(),
        ],
        workspace.path(),
        &[],
        &run.join(&format!("{name}.xray.log")),
    )
    .map_err(|error| error.to_string())
}

/// Converts a materialized server into one Xray client leg.
fn leg(socks_port: u16, server_address: &str, server: &MaterializedServer) -> Leg {
    Leg {
        socks_port,
        server_address: server_address.to_owned(),
        server_port: server.port,
        public_key: server.public_key.clone(),
        uuid: server.uuid.clone(),
        short_id: server.short_id.clone(),
    }
}

/// Reads only the access-log rows appended after a pair of marks.
fn attributed_origins(
    mark4: &AccessLogMark,
    log4: &Path,
    mark6: &AccessLogMark,
    log6: &Path,
) -> Result<String, String> {
    let mut rows = mark4.since(log4)?;
    rows.push_str(&mark6.since(log6)?);
    Ok(egress_servers(&rows))
}

/// Runs a curl GET directly, with TLS verification disabled only for fallback
/// byte comparison against the intentionally private test certificate.
fn direct_fallback_fetch(url: &str, destination: &Path) -> Result<Transfer, String> {
    let outcome = clean_curl()
        .args([
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--insecure".to_owned(),
            "--http1.1".to_owned(),
            "--noproxy".to_owned(),
            "*".to_owned(),
            "--max-time".to_owned(),
            "10".to_owned(),
            "--output".to_owned(),
            destination.display().to_string(),
            "--write-out".to_owned(),
            "%{http_code} %{time_total}".to_owned(),
            url.to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not run fallback curl: {error}"))?;
    transfer_from_outcome(&outcome, destination)
}

/// Runs one direct IPv6 download with ambient proxies disabled.
fn direct_ipv6_fetch(url: &str, destination: &Path, max_time: u64) -> Result<Transfer, String> {
    let outcome = clean_curl()
        .args([
            "--ipv6".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--noproxy".to_owned(),
            "*".to_owned(),
            "--max-time".to_owned(),
            max_time.to_string(),
            "--output".to_owned(),
            destination.display().to_string(),
            "--write-out".to_owned(),
            "%{http_code} %{time_total}".to_owned(),
            url.to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not run direct IPv6 curl: {error}"))?;
    transfer_from_outcome(&outcome, destination)
}

/// Runs one PUT through an Xray SOCKS listener.
fn upload(socks_port: u16, url: &str, source: &Path, max_time: u64) -> Result<Transfer, String> {
    let outcome = clean_curl()
        .args([
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{socks_port}"),
            "--max-time".to_owned(),
            max_time.to_string(),
            "--upload-file".to_owned(),
            source.display().to_string(),
            "--output".to_owned(),
            "/dev/null".to_owned(),
            "--write-out".to_owned(),
            "%{http_code} %{time_total}".to_owned(),
            url.to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not run upload curl: {error}"))?;
    let (http_code, seconds) = match parse_write_out(outcome.trimmed_stdout()) {
        Ok(parsed) => parsed,
        Err(_) if !outcome.success() => ("000".to_owned(), outcome.elapsed.as_secs_f64()),
        Err(error) => return Err(error),
    };
    Ok(Transfer {
        code: outcome.code.unwrap_or(-1),
        http_code,
        seconds,
        sha256: crate::hash::sha256_file(source)?,
    })
}

/// The bytes and digest recorded by an origin access-log row.
fn access_integrity(rows: &str, method: &str) -> Option<(u64, String)> {
    rows.lines().rev().find_map(|line| {
        let value = crate::perf::json_in::parse(line).ok()?;
        if value.str_field("access", "method").ok()? != method {
            return None;
        }
        let bytes = value.int_field("access", "bytes").ok()?;
        let bytes = u64::try_from(bytes).ok()?;
        let digest = value.str_field("access", "sha256").ok()?.to_owned();
        Some((bytes, digest))
    })
}

/// Chooses the first non-tentative global address reported by `ip`.
#[must_use]
pub fn discover_global_ipv6(ip_output: &str) -> Option<String> {
    ip_output.lines().find_map(|line| {
        if line.contains(" tentative") || line.contains(" dadfailed") {
            return None;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let position = fields.iter().position(|field| *field == "inet6")?;
        let address = fields.get(position + 1)?.split('/').next()?;
        let parsed = address.parse::<std::net::Ipv6Addr>().ok()?;
        (!parsed.is_loopback() && !parsed.is_unspecified()).then(|| address.to_owned())
    })
}

/// Records phase 2: real Xray/VLESS/REALITY/Vision sessions across both
/// loopback families, including DNS policy, cover fallback and auth controls.
#[allow(
    clippy::too_many_lines,
    reason = "the phase owns the two binaries, origin, certificate and evidence"
)]
pub fn run_session_phase(
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    xray_bin: &Path,
    origin_bin: &Path,
    certificate: &crate::bench::no_ccs::CoverCertificate,
    results: &mut Results,
) -> Result<(), String> {
    let ports = crate::bench::workspace::reserve_ports(13)?;
    let cover_port = ports[0];
    let origin_port = ports[1];

    std::fs::write(
        workspace.join("cover.bin"),
        b"rust-reality ipv6 validation cover\n",
    )
    .map_err(|error| format!("could not write the cover body: {error}"))?;
    let _cover = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "cover-v6".to_owned(),
            listen_address: "::1".to_owned(),
            port: cover_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("cover-put.jsonl"),
            tls: Some((certificate.certificate.clone(), certificate.key.clone())),
            access_log: None,
            alpn: Some("h2,http/1.1".to_owned()),
        },
    )?;

    let payload = crate::bench::origin_go::write_pattern_payload(workspace.path(), 1)?;
    let expected = crate::hash::sha256_file(&payload)?;
    let log4 = workspace.join("origin-v4.access.jsonl");
    let log6 = workspace.join("origin-v6.access.jsonl");
    let _origin4 = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "origin-v4".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("origin-v4.put.jsonl"),
            tls: None,
            access_log: Some(log4.clone()),
            alpn: None,
        },
    )?;
    let _origin6 = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "origin-v6".to_owned(),
            listen_address: "::1".to_owned(),
            port: origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("origin-v6.put.jsonl"),
            tls: None,
            access_log: Some(log6.clone()),
            alpn: None,
        },
    )?;

    let cover_target = format!("[::1]:{cover_port}");
    let plans = [
        ServerPlan::dual_stack("s2auto", ports[2], &cover_target),
        ServerPlan::dual_stack("s2pref6", ports[3], &cover_target).dialling("preferIpv6"),
        ServerPlan::dual_stack("s2pref4", ports[4], &cover_target).dialling("preferIpv4"),
        ServerPlan::dual_stack("s2dial6", ports[5], &cover_target).dialling("ipv6Only"),
    ];
    let mut servers = Vec::new();
    let mut children = Vec::new();
    for plan in &plans {
        let server = materialize_server(workspace, rust_bin, plan)?;
        let child = start_server_raw(
            workspace,
            run,
            rust_bin,
            &server,
            &certificate.ca_certificate,
        )?;
        servers.push(server);
        children.push(child);
    }
    for (child, server) in children.iter_mut().zip(&servers) {
        child
            .wait_for_address(
                std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], server.port)),
                std::time::Duration::from_secs(15),
            )
            .map_err(|error| error.to_string())?;
    }

    let socks = &ports[6..11];
    let legs = [
        leg(socks[0], "::1", &servers[0]),
        leg(socks[1], "127.0.0.1", &servers[0]),
        leg(socks[2], "::1", &servers[1]),
        leg(socks[3], "::1", &servers[2]),
        leg(socks[4], "::1", &servers[3]),
    ];
    let mut xray = start_xray(workspace, run, xray_bin, "x2", &legs)?;
    for port in socks {
        xray.wait_for_port(*port, std::time::Duration::from_secs(15))
            .map_err(|error| error.to_string())?;
    }

    let downloads = workspace.join("phase2-downloads");
    std::fs::create_dir_all(&downloads)
        .map_err(|error| format!("could not create {}: {error}", downloads.display()))?;
    let url6 = format!("http://[::1]:{origin_port}/payload-1.bin");
    let url4 = format!("http://127.0.0.1:{origin_port}/payload-1.bin");
    let url_dns = format!("http://localhost:{origin_port}/payload-1.bin");

    let transfer = download(socks[0], &url6, &downloads.join("2a.bin"), 30)?;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "a-v6in-v6egress-literal".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(transfer.byte_exact(&expected)),
        detail: transfer_detail(&url6, &transfer, &expected),
        evidence: "x2.xray.log".to_owned(),
    })?;

    let mut mark4 = AccessLogMark::default();
    let mut mark6 = AccessLogMark::default();
    mark4.mark(&log4)?;
    mark6.mark(&log6)?;
    let transfer = download(socks[0], &url4, &downloads.join("2b.bin"), 30)?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let family = attributed_origins(&mark4, &log4, &mark6, &log6)?;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "b-v6in-v4egress".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(transfer.byte_exact(&expected) && family == "origin-v4"),
        detail: Json::object([
            ("transfer", transfer_detail(&url4, &transfer, &expected)),
            ("egressServer", Json::string(&family)),
        ]),
        evidence: "x2.xray.log".to_owned(),
    })?;

    mark4.mark(&log4)?;
    mark6.mark(&log6)?;
    let transfer = download(socks[1], &url6, &downloads.join("2c.bin"), 30)?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let family = attributed_origins(&mark4, &log4, &mark6, &log6)?;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "c-v4in-v6egress".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(transfer.byte_exact(&expected) && family == "origin-v6"),
        detail: Json::object([
            ("transfer", transfer_detail(&url6, &transfer, &expected)),
            ("egressServer", Json::string(&family)),
        ]),
        evidence: "x2.xray.log".to_owned(),
    })?;

    let transfer = download(socks[0], &url_dns, &downloads.join("2d.bin"), 30)?;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "d-mixed-a-aaaa".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(transfer.byte_exact(&expected)),
        detail: transfer_detail(&url_dns, &transfer, &expected),
        evidence: "x2.xray.log".to_owned(),
    })?;

    for (case, port, wanted, dial) in [
        ("e-dns-selected-v6", socks[2], "origin-v6", "preferIpv6"),
        (
            "e-dns-selected-v4-control",
            socks[3],
            "origin-v4",
            "preferIpv4",
        ),
    ] {
        mark4.mark(&log4)?;
        mark6.mark(&log6)?;
        let transfer = download(port, &url_dns, &downloads.join(format!("{case}.bin")), 30)?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        let family = attributed_origins(&mark4, &log4, &mark6, &log6)?;
        results.record(Record {
            matrix: "2-sessions".to_owned(),
            case: case.to_owned(),
            classification: Classification::Loopback,
            status: Status::from_met(transfer.byte_exact(&expected) && family == wanted),
            detail: Json::object([
                ("transfer", transfer_detail(&url_dns, &transfer, &expected)),
                ("egressServer", Json::string(&family)),
                ("dial", Json::string(dial)),
            ]),
            evidence: "x2.xray.log".to_owned(),
        })?;
    }

    let literal = download(socks[4], &url6, &downloads.join("2f.bin"), 30)?;
    let negative = download(socks[4], &url4, &downloads.join("2f-negative.bin"), 15)?;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "f-literal-v6-dial-ipv6only".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(literal.byte_exact(&expected) && negative.code != 0),
        detail: Json::object([
            ("literalV6", transfer_detail(&url6, &literal, &expected)),
            (
                "v4UnderIpv6OnlyDial",
                transfer_detail(&url4, &negative, &expected),
            ),
            (
                "note",
                Json::string("v4 destination under ipv6Only dial must fail (rc!=0)"),
            ),
        ]),
        evidence: "x2.xray.log".to_owned(),
    })?;

    let direct = direct_fallback_fetch(
        &format!("https://[::1]:{cover_port}/cover.bin"),
        &downloads.join("cover-direct.bin"),
    )?;
    let fallback = direct_fallback_fetch(
        &format!("https://[::1]:{}/cover.bin", servers[0].port),
        &downloads.join("cover-fallback.bin"),
    )?;
    let fallback_matches = direct.code == 0
        && fallback.code == 0
        && direct.sha256 != "none"
        && direct.sha256 == fallback.sha256;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "g-bracketed-v6-cover-fallback".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(fallback_matches),
        detail: Json::object([
            ("coverTarget", Json::string(&cover_target)),
            ("directSha256", Json::string(&direct.sha256)),
            ("fallbackSha256", Json::string(&fallback.sha256)),
            ("fallbackMatchesDirect", Json::Bool(fallback_matches)),
        ]),
        evidence: "s2auto.rust.log".to_owned(),
    })?;

    let mut bad_leg = leg(ports[11], "::1", &servers[0]);
    let replacement = if bad_leg.short_id.starts_with('0') {
        '1'
    } else {
        '0'
    };
    bad_leg
        .short_id
        .replace_range(..1, &replacement.to_string());
    let mut bad_xray = start_xray(workspace, run, xray_bin, "x2bad", &[bad_leg.clone()])?;
    bad_xray
        .wait_for_port(ports[11], std::time::Duration::from_secs(15))
        .map_err(|error| error.to_string())?;
    let rejected = download(ports[11], &url6, &downloads.join("2h-negative.bin"), 15)?;
    results.record(Record {
        matrix: "2-sessions".to_owned(),
        case: "h-negative-auth-control".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(rejected.code != 0),
        detail: Json::object([
            ("transfer", transfer_detail(&url6, &rejected, &expected)),
            ("wrongShortId", Json::string(&bad_leg.short_id)),
            (
                "expect",
                Json::string("fetch fails: REALITY auth rejects the session"),
            ),
        ]),
        evidence: "x2bad.xray.log".to_owned(),
    })?;
    Ok(())
}

/// Records phase 3 without letting absent public IPv6 invalidate local policy
/// proof. A configured-but-broken address is still a failure; automatic
/// discovery finding no address is an honest `unavailable` observation.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the phase owns both binaries, origin, certificate and results"
)]
pub fn run_global_phase(
    suite: &Ipv6Suite,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    xray_bin: &Path,
    origin_bin: &Path,
    certificate: &crate::bench::no_ccs::CoverCertificate,
    results: &mut Results,
) -> Result<(), String> {
    let discovered = if let Some(address) = &suite.global_ipv6 {
        Some(address.clone())
    } else {
        let outcome = crate::process::Tool::new("ip")
            .args(["-6", "-o", "addr", "show", "scope", "global"])
            .probe()
            .map_err(|error| format!("could not inspect global IPv6 addresses: {error}"))?;
        if outcome.success() {
            discover_global_ipv6(&outcome.stdout)
        } else {
            None
        }
    };
    let Some(address) = discovered else {
        for (case, classification, reason) in [
            (
                "bind-global-address",
                Classification::HostGlobal,
                "host has no non-tentative global IPv6 address",
            ),
            (
                "real-internet-v6-egress",
                Classification::HostGlobal,
                "host has no global IPv6 address for direct/proxied comparison",
            ),
            (
                "external-ingress",
                Classification::External,
                "no external IPv6 source under suite control",
            ),
        ] {
            results.record(Record {
                matrix: "3-global".to_owned(),
                case: case.to_owned(),
                classification,
                status: Status::Unavailable,
                detail: Json::object([("reason", Json::string(reason))]),
                evidence: String::new(),
            })?;
        }
        return Ok(());
    };

    let ports = crate::bench::workspace::reserve_ports(3)?;
    let cover_port = ports[0];
    std::fs::write(workspace.join("global-cover.bin"), b"global ipv6 cover\n")
        .map_err(|error| format!("could not write global cover body: {error}"))?;
    let _cover = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "cover-global".to_owned(),
            listen_address: "::1".to_owned(),
            port: cover_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("cover-global.put.jsonl"),
            tls: Some((certificate.certificate.clone(), certificate.key.clone())),
            access_log: None,
            alpn: Some("h2,http/1.1".to_owned()),
        },
    )?;
    let plan = ServerPlan {
        name: "s3glob".to_owned(),
        port: ports[1],
        mode: ListenerMode::Ipv6Only,
        ipv4: "0.0.0.0".to_owned(),
        ipv6: address.clone(),
        target: format!("[::1]:{cover_port}"),
        dial: vec![("mode".to_owned(), Json::string("ipv6Only"))],
    };
    let server = materialize_server(workspace, rust_bin, &plan)?;
    let mut server_child = start_server_raw(
        workspace,
        run,
        rust_bin,
        &server,
        &certificate.ca_certificate,
    )?;
    let listen_address = socket_address(&address, server.port)?;
    server_child
        .wait_for_address(listen_address, std::time::Duration::from_secs(15))
        .map_err(|error| error.to_string())?;
    let table = socket_table()?;
    let bound = listener_present(&table, &address, server.port)
        && std::net::TcpStream::connect_timeout(
            &listen_address,
            std::time::Duration::from_millis(500),
        )
        .is_ok();
    results.record(Record {
        matrix: "3-global".to_owned(),
        case: "bind-global-address".to_owned(),
        classification: Classification::HostGlobal,
        status: Status::from_met(bound),
        detail: Json::object([
            ("addr", Json::string(&address)),
            ("port", Json::Int(i64::from(server.port))),
        ]),
        evidence: "s3glob.rust.log".to_owned(),
    })?;

    let mut xray = start_xray(
        workspace,
        run,
        xray_bin,
        "x3",
        &[leg(ports[2], &address, &server)],
    )?;
    xray.wait_for_port(ports[2], std::time::Duration::from_secs(15))
        .map_err(|error| error.to_string())?;
    let direct = direct_ipv6_fetch(&suite.internet_url, &workspace.join("example.direct"), 20)?;
    let proxied = download(
        ports[2],
        &suite.internet_url,
        &workspace.join("example.proxied"),
        30,
    )?;
    let internet_status = if direct.code != 0 {
        Status::Unavailable
    } else {
        Status::from_met(proxied.code == 0 && direct.sha256 == proxied.sha256)
    };
    results.record(Record {
        matrix: "3-global".to_owned(),
        case: "real-internet-v6-egress".to_owned(),
        classification: Classification::HostGlobal,
        status: internet_status,
        detail: Json::object([
            (
                "direct",
                transfer_detail(&suite.internet_url, &direct, &direct.sha256),
            ),
            (
                "proxied",
                transfer_detail(&suite.internet_url, &proxied, &direct.sha256),
            ),
            (
                "byteExact",
                Json::Bool(
                    direct.code == 0 && proxied.code == 0 && direct.sha256 == proxied.sha256,
                ),
            ),
            (
                "note",
                Json::string("server dial ipv6Only forces real Internet AAAA egress"),
            ),
        ]),
        evidence: "x3.xray.log".to_owned(),
    })?;
    results.record(Record {
        matrix: "3-global".to_owned(),
        case: "external-ingress".to_owned(),
        classification: Classification::External,
        status: Status::Unavailable,
        detail: Json::object([(
            "reason",
            Json::string("no external IPv6 source under suite control"),
        )]),
        evidence: String::new(),
    })?;
    Ok(())
}

fn socket_address(address: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let ip = address
        .parse::<std::net::IpAddr>()
        .map_err(|error| format!("invalid numeric address {address:?}: {error}"))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

/// Records phase 4's upload, download and simultaneous full-duplex integrity.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the phase owns both binaries, origin, certificate and results"
)]
pub fn run_transfer_phase(
    suite: &Ipv6Suite,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    xray_bin: &Path,
    origin_bin: &Path,
    certificate: &crate::bench::no_ccs::CoverCertificate,
    results: &mut Results,
) -> Result<(), String> {
    let ports = crate::bench::workspace::reserve_ports(4)?;
    let cover_port = ports[0];
    let origin_port = ports[1];
    std::fs::write(workspace.join("transfer-cover.bin"), b"transfer cover\n")
        .map_err(|error| format!("could not write transfer cover body: {error}"))?;
    let _cover = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "cover-transfer".to_owned(),
            listen_address: "::1".to_owned(),
            port: cover_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("cover-transfer.put.jsonl"),
            tls: Some((certificate.certificate.clone(), certificate.key.clone())),
            access_log: None,
            alpn: Some("h2,http/1.1".to_owned()),
        },
    )?;
    let payload =
        crate::bench::origin_go::write_pattern_payload(workspace.path(), suite.transfer_mib)?;
    let expected = crate::hash::sha256_file(&payload)?;
    let expected_bytes = std::fs::metadata(&payload)
        .map_err(|error| format!("could not stat {}: {error}", payload.display()))?
        .len();
    let access_log = workspace.join("origin-transfer.access.jsonl");
    let _origin = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "origin-transfer-v6".to_owned(),
            listen_address: "::1".to_owned(),
            port: origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("origin-transfer.put.jsonl"),
            tls: None,
            access_log: Some(access_log.clone()),
            alpn: None,
        },
    )?;
    let plan = ServerPlan {
        name: "s4".to_owned(),
        port: ports[2],
        mode: ListenerMode::Ipv6Only,
        ipv4: "0.0.0.0".to_owned(),
        ipv6: "::1".to_owned(),
        target: format!("[::1]:{cover_port}"),
        dial: Vec::new(),
    };
    let server = materialize_server(workspace, rust_bin, &plan)?;
    let mut server_child = start_server_raw(
        workspace,
        run,
        rust_bin,
        &server,
        &certificate.ca_certificate,
    )?;
    server_child
        .wait_for_address(
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], server.port)),
            std::time::Duration::from_secs(15),
        )
        .map_err(|error| error.to_string())?;
    let mut xray = start_xray(
        workspace,
        run,
        xray_bin,
        "x4",
        &[leg(ports[3], "::1", &server)],
    )?;
    xray.wait_for_port(ports[3], std::time::Duration::from_secs(15))
        .map_err(|error| error.to_string())?;
    let payload_name = payload
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "transfer payload has no UTF-8 name".to_owned())?;
    let download_url = format!("http://[::1]:{origin_port}/{payload_name}");
    let upload_url = format!("http://[::1]:{origin_port}/up.received");

    let mut mark = AccessLogMark::default();
    mark.mark(&access_log)?;
    let sent = upload(ports[3], &upload_url, &payload, 600)?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let observed = access_integrity(&mark.since(&access_log)?, "PUT");
    let upload_ok = sent.code == 0
        && observed
            .as_ref()
            .is_some_and(|(bytes, digest)| *bytes == expected_bytes && digest == &expected);
    results.record(Record {
        matrix: "4-transfer".to_owned(),
        case: format!("upload-{}mib-v6", suite.transfer_mib),
        classification: Classification::Loopback,
        status: Status::from_met(upload_ok),
        detail: Json::object([
            ("curl", Json::string(sent.curl_field())),
            ("rc", Json::Int(i64::from(sent.code))),
            (
                "mib",
                Json::Int(i64::try_from(suite.transfer_mib).unwrap_or(i64::MAX)),
            ),
            ("expectSha256", Json::string(&expected)),
            (
                "gotSha256",
                Json::string(observed.as_ref().map_or("none", |row| row.1.as_str())),
            ),
            ("byteExact", Json::Bool(upload_ok)),
        ]),
        evidence: "x4.xray.log".to_owned(),
    })?;

    let received = download(
        ports[3],
        &download_url,
        &workspace.join("download-large.bin"),
        600,
    )?;
    results.record(Record {
        matrix: "4-transfer".to_owned(),
        case: format!("download-{}mib-v6", suite.transfer_mib),
        classification: Classification::Loopback,
        status: Status::from_met(received.byte_exact(&expected)),
        detail: transfer_detail(&download_url, &received, &expected),
        evidence: "x4.xray.log".to_owned(),
    })?;

    mark.mark(&access_log)?;
    let duplex_upload_url = format!("http://[::1]:{origin_port}/duplex.received");
    let duplex_download = workspace.join("download-duplex.bin");
    let (sent, received) = std::thread::scope(|scope| {
        let upload_job = scope.spawn(|| upload(ports[3], &duplex_upload_url, &payload, 600));
        let download_job = scope.spawn(|| download(ports[3], &download_url, &duplex_download, 600));
        let sent = upload_job
            .join()
            .map_err(|_| "full-duplex upload worker panicked".to_owned())??;
        let received = download_job
            .join()
            .map_err(|_| "full-duplex download worker panicked".to_owned())??;
        Ok::<_, String>((sent, received))
    })?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let observed = access_integrity(&mark.since(&access_log)?, "PUT");
    let upload_ok = sent.code == 0
        && observed
            .as_ref()
            .is_some_and(|(bytes, digest)| *bytes == expected_bytes && digest == &expected);
    let download_ok = received.byte_exact(&expected);
    results.record(Record {
        matrix: "4-transfer".to_owned(),
        case: format!("full-duplex-{}mib-v6", suite.transfer_mib),
        classification: Classification::Loopback,
        status: Status::from_met(upload_ok && download_ok),
        detail: Json::object([
            (
                "mib",
                Json::Int(i64::try_from(suite.transfer_mib).unwrap_or(i64::MAX)),
            ),
            ("concurrent", Json::Bool(true)),
            ("curlUpload", Json::string(sent.curl_field())),
            ("curlDownload", Json::string(received.curl_field())),
            (
                "upload",
                Json::object([
                    ("rc", Json::Int(i64::from(sent.code))),
                    ("byteExact", Json::Bool(upload_ok)),
                ]),
            ),
            (
                "download",
                Json::object([
                    ("rc", Json::Int(i64::from(received.code))),
                    ("byteExact", Json::Bool(download_ok)),
                ]),
            ),
        ]),
        evidence: "x4.xray.log".to_owned(),
    })?;
    Ok(())
}

fn wait_for_namespace_listener(
    namespace: &str,
    address: &str,
    port: u16,
    child: &mut crate::bench::process::Child,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if namespace_socket_table(namespace)
            .is_ok_and(|table| listener_present(&table, address, port))
        {
            return Ok(());
        }
        if !child.is_alive() {
            return Err(format!(
                "{} exited before {address}:{port} listened in {namespace}",
                child.label()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(format!(
        "{} did not listen on {address}:{port} in {namespace} within 15s",
        child.label()
    ))
}

fn start_origin_in_namespace(
    namespace: &str,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    binary: &Path,
    plan: &crate::bench::origin_go::OriginPlan,
) -> Result<crate::bench::process::Child, String> {
    let mut child = crate::bench::ipv6_netns::spawn_in(
        namespace,
        &plan.label,
        binary,
        &crate::bench::origin_go::listener_args(plan),
        workspace.path(),
        &[],
        &run.join(&format!("{}.log", plan.label)),
    )?;
    wait_for_namespace_listener(namespace, &plan.listen_address, plan.port, &mut child)?;
    Ok(child)
}

fn start_xray_in_namespace(
    namespace: &str,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    xray_bin: &Path,
    name: &str,
    legs: &[Leg],
) -> Result<crate::bench::process::Child, String> {
    let config = workspace.join(&format!("{name}.xray.json"));
    std::fs::write(&config, xray_config(legs).to_python_json())
        .map_err(|error| format!("could not write {}: {error}", config.display()))?;
    let mut child = crate::bench::ipv6_netns::spawn_in(
        namespace,
        &format!("xray-{name}"),
        xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            config.display().to_string(),
        ],
        workspace.path(),
        &[],
        &run.join(&format!("{name}.xray.log")),
    )?;
    for leg in legs {
        wait_for_namespace_listener(namespace, "127.0.0.1", leg.socks_port, &mut child)?;
    }
    Ok(child)
}

fn namespace_download(
    namespace: &str,
    socks_port: u16,
    url: &str,
    destination: &Path,
    max_time: u64,
) -> Result<Transfer, String> {
    let _ = std::fs::remove_file(destination);
    let args = vec![
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--socks5-hostname".to_owned(),
        format!("127.0.0.1:{socks_port}"),
        "--max-time".to_owned(),
        max_time.to_string(),
        "--output".to_owned(),
        destination.display().to_string(),
        "--write-out".to_owned(),
        "%{http_code} %{time_total}".to_owned(),
        url.to_owned(),
    ];
    let env = [
        ("ALL_PROXY".to_owned(), String::new()),
        ("all_proxy".to_owned(), String::new()),
        ("HTTP_PROXY".to_owned(), String::new()),
        ("http_proxy".to_owned(), String::new()),
        ("HTTPS_PROXY".to_owned(), String::new()),
        ("https_proxy".to_owned(), String::new()),
        ("NO_PROXY".to_owned(), String::new()),
        ("no_proxy".to_owned(), String::new()),
    ];
    let outcome = crate::bench::ipv6_netns::command_in(namespace, Path::new("curl"), &args, &env)?;
    transfer_from_outcome(&outcome, destination)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the resilience transaction owns three namespaces and every child in them"
)]
fn run_namespace_resilience(
    suite: &Ipv6Suite,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    xray_bin: &Path,
    origin_bin: &Path,
    certificate: &crate::bench::no_ccs::CoverCertificate,
    ports: &[u16],
    results: &mut Results,
) -> Result<(), String> {
    if !crate::bench::ipv6_netns::sudo_available() {
        return results.record(Record {
            matrix: "5-resilience".to_owned(),
            case: "netem-and-route-loss".to_owned(),
            classification: Classification::Namespace,
            status: Status::Unavailable,
            detail: Json::object([("reason", Json::string("no passwordless sudo"))]),
            evidence: String::new(),
        });
    }

    let mut topology = crate::bench::ipv6_netns::Topology::create(&suite.run_id)?;
    let names = topology.names().clone();
    let outcome = (|| {
        topology.wait_for_dad()?;
        let payload = crate::bench::origin_go::write_pattern_payload(workspace.path(), 1)?;
        let expected = crate::hash::sha256_file(&payload)?;
        let payload_name = payload
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "phase-5 payload has no UTF-8 name".to_owned())?;

        let cover_plan = crate::bench::origin_go::OriginPlan {
            label: "cover5".to_owned(),
            listen_address: "::1".to_owned(),
            port: ports[0],
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("cover5.put.jsonl"),
            tls: Some((certificate.certificate.clone(), certificate.key.clone())),
            access_log: None,
            alpn: Some("h2,http/1.1".to_owned()),
        };
        let mut cover = start_origin_in_namespace(
            &names.server_namespace,
            workspace,
            run,
            origin_bin,
            &cover_plan,
        )?;
        let origin_plan = crate::bench::origin_go::OriginPlan {
            label: "origin5-v6".to_owned(),
            listen_address: "2001:db8:b::1".to_owned(),
            port: ports[1],
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("origin5.put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        };
        let mut origin = start_origin_in_namespace(
            &names.origin_namespace,
            workspace,
            run,
            origin_bin,
            &origin_plan,
        )?;
        let server_plan = ServerPlan {
            name: "s5".to_owned(),
            port: ports[2],
            mode: ListenerMode::Ipv6Only,
            ipv4: "0.0.0.0".to_owned(),
            ipv6: "2001:db8:a::2".to_owned(),
            target: format!("[::1]:{}", ports[0]),
            dial: vec![
                ("mode".to_owned(), Json::string("auto")),
                ("routeRefreshSeconds".to_owned(), Json::Int(2)),
                ("hardFailurePenaltySeconds".to_owned(), Json::Int(3)),
            ],
        };
        let server = materialize_server(workspace, rust_bin, &server_plan)?;
        let mut server_child = start_server_in_namespace(
            &names.server_namespace,
            workspace,
            run,
            rust_bin,
            &server,
            &certificate.ca_certificate,
        )?;
        wait_for_namespace_listener(
            &names.server_namespace,
            "2001:db8:a::2",
            server.port,
            &mut server_child,
        )?;
        let mut xray = start_xray_in_namespace(
            &names.client_namespace,
            workspace,
            run,
            xray_bin,
            "x5",
            &[leg(ports[3], "2001:db8:a::2", &server)],
        )?;
        let url = format!("http://[2001:db8:b::1]:{}/{payload_name}", ports[1]);

        if crate::bench::ipv6_netns::tc_available() {
            topology.add_netem()?;
            let transfer = namespace_download(
                &names.client_namespace,
                ports[3],
                &url,
                &workspace.join("p5a.out"),
                120,
            );
            let removal = topology.remove_netem();
            removal?;
            let transfer = transfer?;
            results.record(Record {
                matrix: "5-resilience".to_owned(),
                case: "netem-100ms-1pct-session".to_owned(),
                classification: Classification::Namespace,
                status: Status::from_met(transfer.byte_exact(&expected)),
                detail: Json::object([
                    (
                        "netem",
                        Json::string("delay 100ms loss 1% (client-leg egress)"),
                    ),
                    ("curl", Json::string(transfer.curl_field())),
                    ("rc", Json::Int(i64::from(transfer.code))),
                    ("byteExact", Json::Bool(transfer.byte_exact(&expected))),
                ]),
                evidence: "x5.xray.log".to_owned(),
            })?;
        } else {
            results.record(Record {
                matrix: "5-resilience".to_owned(),
                case: "netem-100ms-1pct-session".to_owned(),
                classification: Classification::Namespace,
                status: Status::Unavailable,
                detail: Json::object([("reason", Json::string("tc unavailable"))]),
                evidence: String::new(),
            })?;
        }

        let baseline = namespace_download(
            &names.client_namespace,
            ports[3],
            &url,
            &workspace.join("p5b0.out"),
            60,
        )?;
        results.record(Record {
            matrix: "5-resilience".to_owned(),
            case: "route-loss-baseline".to_owned(),
            classification: Classification::Namespace,
            status: Status::from_met(baseline.byte_exact(&expected)),
            detail: transfer_detail(&url, &baseline, &expected),
            evidence: "x5.xray.log".to_owned(),
        })?;

        topology.remove_origin_route()?;
        let failed = namespace_download(
            &names.client_namespace,
            ports[3],
            &url,
            &workspace.join("p5b1.out"),
            30,
        );
        let restoration = topology.restore_origin_route();
        restoration?;
        let failed = failed?;
        results.record(Record {
            matrix: "5-resilience".to_owned(),
            case: "route-loss-fails-fast".to_owned(),
            classification: Classification::Namespace,
            status: Status::from_met(failed.code != 0),
            detail: Json::object([
                (
                    "expect",
                    Json::string("fetch fails while the egress route is deleted"),
                ),
                ("curl", Json::string(failed.curl_field())),
                ("rc", Json::Int(i64::from(failed.code))),
            ]),
            evidence: "s5.rust.log".to_owned(),
        })?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        let mut attempts = 0_i64;
        let mut recovered = None;
        while std::time::Instant::now() < deadline {
            attempts += 1;
            let transfer = namespace_download(
                &names.client_namespace,
                ports[3],
                &url,
                &workspace.join("p5b2.out"),
                30,
            )?;
            if transfer.byte_exact(&expected) {
                recovered = Some(transfer);
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        let server_alive = server_child.is_alive();
        results.record(Record {
            matrix: "5-resilience".to_owned(),
            case: "route-recovery-while-running".to_owned(),
            classification: Classification::Namespace,
            status: Status::from_met(recovered.is_some()),
            detail: Json::object([
                ("attempts", Json::Int(attempts)),
                (
                    "curl",
                    Json::string(
                        recovered
                            .as_ref()
                            .map_or_else(String::new, Transfer::curl_field),
                    ),
                ),
                (
                    "rc",
                    Json::Int(i64::from(recovered.as_ref().map_or(-1, |row| row.code))),
                ),
                (
                    "serverProcess",
                    Json::string(if server_alive { "alive" } else { "dead" }),
                ),
                (
                    "note",
                    Json::string("routeRefreshSeconds=2, hardFailurePenaltySeconds=3"),
                ),
            ]),
            evidence: "s5.rust.log".to_owned(),
        })?;
        results.record(Record {
            matrix: "5-resilience".to_owned(),
            case: "server-process-stability".to_owned(),
            classification: Classification::Namespace,
            status: Status::from_met(server_alive),
            detail: Json::object([("pid", Json::Int(i64::from(server_child.pid())))]),
            evidence: "s5.rust.log".to_owned(),
        })?;

        xray.terminate();
        server_child.terminate();
        origin.terminate();
        cover.terminate();
        Ok(())
    })();
    drop(topology);
    crate::bench::ipv6_netns::Topology::verify_removed(&names)?;
    outcome
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fallback case owns both implementations, two origins and evidence"
)]
fn run_fast_fallback(
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    xray_bin: &Path,
    origin_bin: &Path,
    certificate: &crate::bench::no_ccs::CoverCertificate,
    ports: &[u16],
    results: &mut Results,
) -> Result<(), String> {
    let _cover = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "cover5-fast".to_owned(),
            listen_address: "::1".to_owned(),
            port: ports[0],
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("cover5-fast.put.jsonl"),
            tls: Some((certificate.certificate.clone(), certificate.key.clone())),
            access_log: None,
            alpn: Some("h2,http/1.1".to_owned()),
        },
    )?;
    let payload = workspace.join("phase5-fast-payload.bin");
    let body: Vec<u8> = (0..=255_u8).cycle().take(256 * 1024).collect();
    std::fs::write(&payload, body)
        .map_err(|error| format!("could not write {}: {error}", payload.display()))?;
    let expected = crate::hash::sha256_file(&payload)?;
    let _origin = crate::bench::origin_go::start(
        origin_bin,
        workspace,
        &crate::bench::origin_go::OriginPlan {
            label: "origin5-v4only".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: ports[1],
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("origin5-fast.put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;
    let plan = ServerPlan::dual_stack("s5c", ports[2], &format!("[::1]:{}", ports[0]))
        .dialling("preferIpv6");
    let server = materialize_server(workspace, rust_bin, &plan)?;
    let mut server_child = start_server_raw(
        workspace,
        run,
        rust_bin,
        &server,
        &certificate.ca_certificate,
    )?;
    server_child
        .wait_for_address(
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], server.port)),
            std::time::Duration::from_secs(15),
        )
        .map_err(|error| error.to_string())?;
    let mut xray = start_xray(
        workspace,
        run,
        xray_bin,
        "x5c",
        &[leg(ports[3], "::1", &server)],
    )?;
    xray.wait_for_port(ports[3], std::time::Duration::from_secs(15))
        .map_err(|error| error.to_string())?;
    let url = format!("http://localhost:{}/phase5-fast-payload.bin", ports[1]);
    let transfer = download(ports[3], &url, &workspace.join("p5c.out"), 30)?;
    let met = transfer.byte_exact(&expected) && transfer.seconds < 3.0;
    results.record(Record {
        matrix: "5-resilience".to_owned(),
        case: "refused-v6-fast-fallback".to_owned(),
        classification: Classification::Loopback,
        status: Status::from_met(met),
        detail: Json::object([
            ("dial", Json::string("preferIpv6")),
            ("v6", Json::string("connection-refused")),
            ("curl", Json::string(transfer.curl_field())),
            ("rc", Json::Int(i64::from(transfer.code))),
            ("timeTotalS", Json::Float(transfer.seconds)),
            ("thresholdS", Json::Float(3.0)),
            ("byteExact", Json::Bool(transfer.byte_exact(&expected))),
        ]),
        evidence: "s5c.rust.log".to_owned(),
    })?;
    Ok(())
}

/// Records phase 5's owned-namespace netem/route-loss transaction and the
/// loopback immediate-family-failure control.
#[expect(
    clippy::too_many_arguments,
    reason = "the phase owns both binaries, origin, certificate and results"
)]
pub fn run_resilience_phase(
    suite: &Ipv6Suite,
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    xray_bin: &Path,
    origin_bin: &Path,
    certificate: &crate::bench::no_ccs::CoverCertificate,
    results: &mut Results,
) -> Result<(), String> {
    let ports = crate::bench::workspace::reserve_ports(8)?;
    run_namespace_resilience(
        suite,
        workspace,
        run,
        rust_bin,
        xray_bin,
        origin_bin,
        certificate,
        &ports[..4],
        results,
    )?;
    run_fast_fallback(
        workspace,
        run,
        rust_bin,
        xray_bin,
        origin_bin,
        certificate,
        &ports[4..8],
        results,
    )
}

/// Runs the native phases and publishes their evidence.
///
/// # Errors
///
/// Returns the first setup, runtime, integrity or publication failure.
#[allow(
    clippy::too_many_lines,
    reason = "the dispatcher keeps phase ownership and publication in one transaction"
)]
pub fn run(suite: &Ipv6Suite) -> Result<Json, String> {
    use crate::bench::{
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        workspace::Workspace,
    };

    validate(suite)?;
    for program in ["curl", "go", "ss"] {
        if !crate::process::Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    let rust = identity::register("rust-reality", &suite.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("validate-ipv6-e2e")?;
    let certificate = cover_certificate(suite, &workspace)?;
    run.write_new("certificate-san.txt", &certificate.subject_alt_name)?;
    let mut results = Results::create(run.join("results.jsonl"))?;
    let origin = if suite.phases.chars().any(|phase| matches!(phase, '2'..='5')) {
        Some(crate::bench::origin_go::build(&suite.repo, &workspace)?)
    } else {
        None
    };

    for phase in suite.phases.chars() {
        match phase {
            '0' => phase0(suite, &run, &mut results)?,
            '1' => run_local_listener_phase(
                &suite.run_id,
                &workspace,
                &run,
                &rust.path,
                &certificate.ca_certificate,
                &mut results,
            )?,
            '2' => run_session_phase(
                &workspace,
                &run,
                &rust.path,
                &xray.path,
                origin
                    .as_deref()
                    .ok_or_else(|| "phase 2 origin was not built".to_owned())?,
                &certificate,
                &mut results,
            )?,
            '3' => run_global_phase(
                suite,
                &workspace,
                &run,
                &rust.path,
                &xray.path,
                origin
                    .as_deref()
                    .ok_or_else(|| "phase 3 origin was not built".to_owned())?,
                &certificate,
                &mut results,
            )?,
            '4' => run_transfer_phase(
                suite,
                &workspace,
                &run,
                &rust.path,
                &xray.path,
                origin
                    .as_deref()
                    .ok_or_else(|| "phase 4 origin was not built".to_owned())?,
                &certificate,
                &mut results,
            )?,
            '5' => run_resilience_phase(
                suite,
                &workspace,
                &run,
                &rust.path,
                &xray.path,
                origin
                    .as_deref()
                    .ok_or_else(|| "phase 5 origin was not built".to_owned())?,
                &certificate,
                &mut results,
            )?,
            _ => unreachable!("validated phase digit"),
        }
    }
    let [passed, failed, skipped] = results.tally();
    let summary = Json::object([
        ("runId", Json::string(&suite.run_id)),
        ("phases", Json::string(&suite.phases)),
        ("pass", Json::Int(i64::try_from(passed).unwrap_or(i64::MAX))),
        ("fail", Json::Int(i64::try_from(failed).unwrap_or(i64::MAX))),
        (
            "skip",
            Json::Int(i64::try_from(skipped).unwrap_or(i64::MAX)),
        ),
        (
            "unavailable",
            Json::Int(i64::try_from(results.unavailable()).unwrap_or(i64::MAX)),
        ),
        (
            "failures",
            Json::Array(results.failures().iter().map(Json::string).collect()),
        ),
        (
            "binaries",
            Json::object([
                (
                    "rustReality",
                    Json::object([
                        ("path", Json::string(rust.path.display().to_string())),
                        ("sha256", Json::string(&rust.sha256)),
                        ("identity", Json::string(&rust.identity)),
                    ]),
                ),
                (
                    "xray",
                    Json::object([
                        ("path", Json::string(xray.path.display().to_string())),
                        ("sha256", Json::string(&xray.sha256)),
                        ("identity", Json::string(&xray.identity)),
                    ]),
                ),
            ]),
        ),
        ("complete", Json::Bool(failed == 0)),
    ]);
    let document = summary.to_python_json();
    run.write_new("summary.json", &document)?;
    if failed == 0 {
        run.publish(
            Publication::Environment,
            &document,
            &suite.run_id,
            "validate-ipv6-e2e",
        )?;
        Ok(summary)
    } else {
        Err(format!(
            "IPv6 validation failed: {}",
            results.failures().join(", ")
        ))
    }
}
