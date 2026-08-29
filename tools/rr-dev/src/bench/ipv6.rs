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
fn start_server(
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

/// Records the non-privileged listener contract from phase 1.
#[expect(
    clippy::too_many_arguments,
    reason = "the phase owns the run, workspace, identity, certificate and results"
)]
pub fn run_local_listener_phase(
    workspace: &crate::bench::workspace::Workspace,
    run: &crate::bench::evidence::RunDirectory,
    rust_bin: &Path,
    ca_certificate: &Path,
    results: &mut Results,
) -> Result<(), String> {
    let ports = crate::bench::workspace::reserve_ports(7)?;
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
        let mut child = start_server(workspace, run, rust_bin, &materialized, ca_certificate)?;
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
    let mut child = start_server(workspace, run, rust_bin, &bad, ca_certificate)?;
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
    let mut owner_child = start_server(workspace, run, rust_bin, &owner, ca_certificate)?;
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
    let mut contender_child = start_server(workspace, run, rust_bin, &contender, ca_certificate)?;
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
    Ok(())
}
