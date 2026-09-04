//! Enforced `no_std`-readiness boundary for the canonical protocol core.
//!
//! ADR 0016 records the audit that found a coherent semantic layer inside
//! `src/protocol`: the modules that own the VLESS wire format, Vision framing,
//! the TLS 1.3 record layer and key schedule, REALITY `ClientHello` parsing,
//! and the NXR wire depend on nothing but bytes, `core`, `alloc`, and reviewed
//! `no_std` crypto. That audit compiled them against `core` and `alloc` alone.
//!
//! The ADR also decided not to extract them into a separate crate yet, because
//! nothing outside this binary consumes them and the move would publish 52
//! deliberately internal items. This file is what keeps that decision honest:
//! it enforces the property the crate boundary would have enforced, so the
//! layer cannot quietly acquire a runtime, a clock, or a configuration
//! dependency between now and the day extraction is worth doing.
//!
//! Only rules that hold across the whole listed set are asserted. This file
//! does **not** claim `src/protocol` as a whole is `no_std`-ready: the reader
//! modules are deliberately Tokio-driven, `reality/replay.rs` is a concurrent
//! cache with a clock, and `reality/auth.rs` deliberately compiles from
//! configuration. Those are the layering working as designed.

use std::{fs, path::PathBuf};

/// The modules ADR 0016 identified as the canonical `no_std + alloc` core.
///
/// This list is the subject of the audit, so it is written out rather than
/// discovered: a module joins it only when it has been shown to hold the
/// property, and the existence check below means a rename cannot silently
/// empty the suite.
const PROTOCOL_CORE: &[&str] = &[
    "src/protocol/nxr.rs",
    "src/protocol/reality/client_hello.rs",
    "src/protocol/reality/tls13/cover_profile.rs",
    "src/protocol/reality/tls13/keys.rs",
    "src/protocol/reality/tls13/messages.rs",
    "src/protocol/reality/tls13/record.rs",
    "src/protocol/reality/tls13/server_hello.rs",
    "src/protocol/vless/addons.rs",
    "src/protocol/vless/decode.rs",
    "src/protocol/vless/padding.rs",
    "src/protocol/vless/types.rs",
    "src/protocol/vless/vision.rs",
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strips `//` line comments so a rule name mentioned in prose is not a hit.
fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Reads every core module, failing loudly if the list has gone stale.
fn core_sources() -> Vec<(&'static str, String)> {
    let root = repository_root();
    PROTOCOL_CORE
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            let source = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "{relative} is listed as protocol core but cannot be read ({error}); \
                     update the list and ADR 0016 together rather than letting the rule lapse"
                )
            });
            (*relative, without_line_comments(&source))
        })
        .collect()
}

#[test]
fn the_protocol_core_list_is_not_vacuous() {
    let sources = core_sources();
    assert_eq!(
        sources.len(),
        PROTOCOL_CORE.len(),
        "every listed module must be readable"
    );
    assert!(
        sources.iter().all(|(_, code)| code.len() > 1_000),
        "a core module that shrank to nothing would make these rules pass for the wrong reason"
    );
}

#[test]
fn the_protocol_core_never_reaches_for_the_runtime_a_clock_or_configuration() {
    // These are the dependencies that would make the canonical semantics
    // untestable without a reactor and unusable outside this binary. Time and
    // I/O outcomes belong to callers; the core transforms bytes.
    let forbidden = [
        ("tokio::", "the codec must not depend on an async runtime"),
        ("async fn", "the codec must stay synchronous"),
        (".await", "the codec must stay synchronous"),
        ("crate::config", "the codec must not read configuration"),
        ("crate::runtime", "the codec must not depend on the runtime"),
        ("crate::transport", "the codec must not depend on transport"),
        ("crate::server", "the codec must not depend on the server"),
        ("Instant", "the codec must not read a clock"),
        ("SystemTime", "the codec must not read a clock"),
        ("TcpStream", "the codec must not name a socket"),
        ("TcpListener", "the codec must not name a socket"),
    ];

    let mut violations = Vec::new();
    for (relative, code) in core_sources() {
        for (token, reason) in forbidden {
            if code.contains(token) {
                violations.push(format!("{relative}: {token} ({reason})"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "protocol core reached outside its layer:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_protocol_core_uses_no_std_only_facility() {
    // The audit's finding was specific: every `std` path this layer uses has a
    // `core` or `alloc` equivalent, so the layer compiles against `core` and
    // `alloc` alone. This asserts the complement — the `std` facilities that
    // have no such equivalent — which stays honest as the code grows instead
    // of freezing today's exact import list.
    let forbidden = [
        ("std::collections", "no `core` or `alloc` equivalent hasher"),
        ("std::io", "I/O belongs to the Runtime Adapter"),
        ("std::fs", "the filesystem belongs to the Linux boundary"),
        ("std::os", "OS handles belong to the Linux boundary"),
        ("std::process", "not available without `std`"),
        ("std::env", "not available without `std`"),
        ("std::thread", "not available without `std`"),
        ("std::time::Instant", "not available without `std`"),
        ("std::time::SystemTime", "not available without `std`"),
        ("std::sync::Mutex", "not available without `std`"),
        ("std::sync::RwLock", "not available without `std`"),
        ("std::sync::OnceLock", "not available without `std`"),
        ("std::sync::LazyLock", "not available without `std`"),
        // A `std`-only dependency breaks the property just as surely as a
        // `std`-only path, and is easier to add by accident: the import reads
        // like any other crypto import. ADR 0016's audit specifically checked
        // that no crate in this layer's closure enables `std` — including
        // `ring`, which resolves without it.
        //
        // `aws-lc-rs` is the one that did, and C3b (ADR 0023) removed it from
        // the production graph entirely: X25519 now comes from `rr-crypto`,
        // which is `no_std` and `core`-only. The rule is kept because a
        // dev-dependency is still resolvable and an import here would still be
        // wrong — but the constraint it used to express is gone, and with it
        // the reason this binary carried two X25519 implementations. Nothing
        // now stops this layer from using `crypto::x25519` directly, which is
        // what makes collapsing the `x25519-dalek` call sites possible.
        (
            "aws_lc_rs",
            "aws-lc-rs requires `std`; this layer must compile against `core` + `alloc`",
        ),
    ];
    // `std::error::Error`, `std::fmt`, `std::str`, `std::net::Ipv6Addr`,
    // `std::ops::Range`, `std::iter` and `std::sync::Arc` are deliberately
    // absent from this list: each is a re-export of the `core` or `alloc` item
    // of the same name, so naming them through `std` costs a rename at
    // extraction time and nothing else.

    let mut violations = Vec::new();
    for (relative, code) in core_sources() {
        for (token, reason) in forbidden {
            if code.contains(token) {
                violations.push(format!("{relative}: {token} ({reason})"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "protocol core used a facility that has no `core`/`alloc` equivalent:\n{}",
        violations.join("\n")
    );
}
