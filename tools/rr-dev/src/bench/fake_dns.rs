//! A deterministic loopback DNS server with counted queries.
//!
//! The DNS and routing comparisons need resolution to be *observable*: the whole
//! point is to distinguish a cache hit from an upstream query, and to prove that
//! thirty-two concurrent connections for one name coalesce into a single lookup.
//! A real resolver cannot answer that, so both harnesses point the implementations
//! at a fake one that counts every question it is asked.
//!
//! The behaviour is deliberate, not a convenience:
//!
//! * `A` gets one fixed answer with the configured TTL.
//! * `AAAA` gets a **NODATA answer carrying an SOA**, so the negative TTL is
//!   defined and a resolver with negative caching behaves as it would against a
//!   real dual-stack zone that has no `AAAA` records. Answering `NXDOMAIN`, or
//!   nothing at all, would change what the implementations do.
//! * An unparseable query is dropped rather than refused, mirroring the `Drop`
//!   scenario the production resolver tests use.
//!
//! ## No control port
//!
//! `scripts/dns-fake-server.py` served its counters over a loopback TCP control
//! port because the shell had no other way to reach them. Here the server is a
//! thread in the process that is running the benchmark, so [`FakeDns::counts`]
//! reads the shared state directly. The counters are the evidence; the port was
//! only ever the transport.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The `A` record type.
const TYPE_A: u16 = 1;

/// The `SOA` record type, used for the `AAAA` NODATA authority.
const TYPE_SOA: u16 = 6;

/// The `AAAA` record type.
const TYPE_AAAA: u16 = 28;

/// The `IN` class; anything else is dropped.
const CLASS_IN: u16 = 1;

/// One parsed question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The lowercased dotted name.
    pub name: String,
    /// The query type.
    pub qtype: u16,
    /// Offset just past the question, where an answer section begins.
    pub end: usize,
}

/// Parses the first question of a query, or `None` if it is malformed.
///
/// Compression pointers in a *question* are invalid, so a label whose length byte
/// has the top bits set is treated as malformed rather than followed.
#[must_use]
pub fn parse_question(packet: &[u8]) -> Option<Question> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount < 1 {
        return None;
    }
    let mut offset = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let length = *packet.get(offset)? as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        if length & 0xC0 != 0 || offset + 1 + length > packet.len() {
            return None;
        }
        let label = &packet[offset + 1..offset + 1 + length];
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += 1 + length;
    }
    if offset + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    if qclass != CLASS_IN {
        return None;
    }
    Some(Question {
        name: labels.join(".").to_lowercase(),
        qtype,
        end: offset + 4,
    })
}

/// The SOA record data used for an `AAAA` NODATA authority.
fn soa_rdata(minimum: u32) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(b"\x03ns1\x07invalid\x00");
    rdata.extend_from_slice(b"\x0ahostmaster\x07invalid\x00");
    for value in [1_u32, 60, 30, 604_800, minimum] {
        rdata.extend_from_slice(&value.to_be_bytes());
    }
    rdata
}

/// Builds the response to a parsed question.
#[must_use]
pub fn build_response(packet: &[u8], question: &Question, answer: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let ident = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // QR | RA, RCODE 0, with the request's RD copied back.
    let response_flags = 0x8180_u16 | (flags & 0x0100);
    let question_bytes = &packet[12..question.end];

    let mut out = Vec::with_capacity(64);
    let mut header = |an: u16, ns: u16| {
        out.extend_from_slice(&ident.to_be_bytes());
        out.extend_from_slice(&response_flags.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&an.to_be_bytes());
        out.extend_from_slice(&ns.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
    };
    match question.qtype {
        TYPE_A => {
            header(1, 0);
            out.extend_from_slice(question_bytes);
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&TYPE_A.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&4_u16.to_be_bytes());
            out.extend_from_slice(&answer.octets());
        }
        TYPE_AAAA => {
            let rdata = soa_rdata(ttl);
            header(0, 1);
            out.extend_from_slice(question_bytes);
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&TYPE_SOA.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            let length = u16::try_from(rdata.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&rdata);
        }
        // An unsupported type gets NODATA with no authority, so it is never cached.
        _ => {
            header(0, 0);
            out.extend_from_slice(question_bytes);
        }
    }
    out
}

/// A snapshot of what the resolver has been asked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// Total questions answered.
    pub total: u64,
    /// Questions per lowercased name.
    pub by_name: BTreeMap<String, u64>,
    /// Questions per type label (`A`, `AAAA`, or the numeric type).
    pub by_type: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct State {
    counts: Counts,
}

/// A running loopback DNS server, stopped on drop.
#[derive(Debug)]
pub struct FakeDns {
    port: u16,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeDns {
    /// Binds an ephemeral loopback UDP port and starts answering.
    ///
    /// # Errors
    ///
    /// Returns a message when the socket cannot be bound.
    pub fn start(answer: Ipv4Addr, ttl: u32) -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("could not bind the fake DNS socket: {error}"))?;
        let port = socket
            .local_addr()
            .map_err(|error| format!("could not read the fake DNS port: {error}"))?
            .port();
        // A read timeout is what lets the thread notice the stop flag; without it
        // a quiet resolver would block until the process exited.
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .map_err(|error| format!("could not set the fake DNS timeout: {error}"))?;

        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut buffer = [0_u8; 1500];
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                let packet = &buffer[..length];
                // A malformed query is dropped, never answered.
                let Some(question) = parse_question(packet) else {
                    continue;
                };
                if let Ok(mut state) = thread_state.lock() {
                    state.counts.total += 1;
                    *state
                        .counts
                        .by_name
                        .entry(question.name.clone())
                        .or_default() += 1;
                    let label = match question.qtype {
                        TYPE_A => "A".to_owned(),
                        TYPE_AAAA => "AAAA".to_owned(),
                        other => other.to_string(),
                    };
                    *state.counts.by_type.entry(label).or_default() += 1;
                }
                let response = build_response(packet, &question, answer, ttl);
                let _ = socket.send_to(&response, peer);
            }
        });
        Ok(Self {
            port,
            state,
            stop,
            handle: Some(handle),
        })
    }

    /// The loopback UDP port the resolver listens on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// A snapshot of the query counters.
    #[must_use]
    pub fn counts(&self) -> Counts {
        self.state
            .lock()
            .map(|state| state.counts.clone())
            .unwrap_or_default()
    }
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an `A` query for `name`, as a resolver would send it.
    fn query(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234_u16.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        for _ in 0..3 {
            packet.extend_from_slice(&0_u16.to_be_bytes());
        }
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&qclass.to_be_bytes());
        packet
    }

    #[test]
    fn a_question_is_parsed_and_lowercased() {
        let parsed = parse_question(&query("Cold-1.DnsBench", TYPE_A, CLASS_IN)).unwrap();
        assert_eq!(parsed.name, "cold-1.dnsbench");
        assert_eq!(parsed.qtype, TYPE_A);
    }

    /// A malformed or non-`IN` query is dropped, never answered — the resolver
    /// under test must see a timeout, not a response it can cache.
    #[test]
    fn malformed_and_non_internet_queries_are_rejected() {
        assert!(parse_question(&[]).is_none());
        assert!(parse_question(&[0; 11]).is_none());
        // qdcount 0.
        let mut empty = query("a.test", TYPE_A, CLASS_IN);
        empty[4] = 0;
        empty[5] = 0;
        assert!(parse_question(&empty).is_none());
        // CHAOS class.
        assert!(parse_question(&query("a.test", TYPE_A, 3)).is_none());
        // A compression pointer in a question is invalid.
        let mut pointer = query("a.test", TYPE_A, CLASS_IN);
        pointer[12] = 0xC0;
        assert!(parse_question(&pointer).is_none());
        // Truncated before the type/class.
        let truncated = &query("a.test", TYPE_A, CLASS_IN)[..14];
        assert!(parse_question(truncated).is_none());
    }

    #[test]
    fn an_a_query_is_answered_with_the_fixed_address() {
        let packet = query("warm.dnsbench", TYPE_A, CLASS_IN);
        let question = parse_question(&packet).unwrap();
        let response = build_response(&packet, &question, Ipv4Addr::LOCALHOST, 300);
        assert_eq!(&response[0..2], &packet[0..2], "the id is echoed");
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x8000, 0x8000);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1, "one answer");
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 1]);
        // TTL sits just before the two-byte rdlength and the four address bytes.
        let ttl_at = response.len() - 10;
        assert_eq!(
            u32::from_be_bytes([
                response[ttl_at],
                response[ttl_at + 1],
                response[ttl_at + 2],
                response[ttl_at + 3]
            ]),
            300
        );
    }

    /// AAAA must be NODATA *with* an SOA: the negative TTL is what makes a
    /// caching resolver behave as it would against a real zone with no AAAA.
    #[test]
    fn an_aaaa_query_is_nodata_with_an_soa_authority() {
        let packet = query("warm.dnsbench", TYPE_AAAA, CLASS_IN);
        let question = parse_question(&packet).unwrap();
        let response = build_response(&packet, &question, Ipv4Addr::LOCALHOST, 300);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0, "no answers");
        assert_eq!(
            u16::from_be_bytes([response[8], response[9]]),
            1,
            "one authority record"
        );
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x000F,
            0,
            "RCODE must be NOERROR, not NXDOMAIN"
        );
        assert!(
            response
                .windows(7)
                .any(|window| window == b"invalid"),
            "the SOA names the invalid zone"
        );
    }

    #[test]
    fn an_unsupported_type_gets_nodata_without_an_authority() {
        let packet = query("warm.dnsbench", 33, CLASS_IN);
        let question = parse_question(&packet).unwrap();
        let response = build_response(&packet, &question, Ipv4Addr::LOCALHOST, 300);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            u16::from_be_bytes([response[8], response[9]]),
            0,
            "nothing to cache negatively"
        );
    }

    /// The end-to-end contract: a real UDP round trip, counted by name and type.
    #[test]
    fn the_server_answers_and_counts_real_queries() {
        let server = FakeDns::start(Ipv4Addr::LOCALHOST, 300).unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        for (name, qtype) in [
            ("one.dnsbench", TYPE_A),
            ("one.dnsbench", TYPE_A),
            ("two.dnsbench", TYPE_AAAA),
        ] {
            let packet = query(name, qtype, CLASS_IN);
            client
                .send_to(&packet, (Ipv4Addr::LOCALHOST, server.port()))
                .unwrap();
            let mut buffer = [0_u8; 1500];
            let (length, _) = client.recv_from(&mut buffer).unwrap();
            assert!(length > 12, "a response arrived for {name}");
        }

        let counts = server.counts();
        assert_eq!(counts.total, 3);
        assert_eq!(counts.by_name.get("one.dnsbench"), Some(&2));
        assert_eq!(counts.by_name.get("two.dnsbench"), Some(&1));
        assert_eq!(counts.by_type.get("A"), Some(&2));
        assert_eq!(counts.by_type.get("AAAA"), Some(&1));
    }

    /// A dropped query must not be counted either: it never happened as far as
    /// the resolver under test is concerned.
    #[test]
    fn a_dropped_query_is_neither_answered_nor_counted() {
        let server = FakeDns::start(Ipv4Addr::LOCALHOST, 300).unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .unwrap();
        client
            .send_to(b"not a dns packet", (Ipv4Addr::LOCALHOST, server.port()))
            .unwrap();
        let mut buffer = [0_u8; 1500];
        assert!(client.recv_from(&mut buffer).is_err(), "no answer");
        assert_eq!(server.counts().total, 0);
    }
}
