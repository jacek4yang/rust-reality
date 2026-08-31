//! Enforced capability boundary between protocol/session semantics and the
//! concrete I/O backend.
//!
//! ADR 0008 gives Transport ownership of concrete TCP streams, buffered relay,
//! Linux `splice`, vectored I/O, half-close, cancellation, and descriptor
//! lifetime, and forbids it from redefining protocol semantics. The direction
//! this test protects is the other one: protocol and session semantics must not
//! reach *down* and choose or drive a transport backend.
//!
//! Only rules that are true of the current tree are asserted here. In
//! particular this file does **not** claim that protocol code never names a
//! socket or a descriptor: `src/protocol/reality/tls13` deliberately exposes a
//! raw descriptor so an authenticated session can hand ownership to a kernel
//! relay backend, and `CoverFlightIo` is deliberately implemented for the
//! concrete production `TcpStream`. Those are the boundary working as designed,
//! not leaks.

use std::{
    fs,
    path::{Path, PathBuf},
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
        for entry in entries {
            let entry = entry.expect("directory entry must be readable");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    assert!(
        !found.is_empty(),
        "no Rust sources found under {}",
        root.display()
    );
    found
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

#[test]
fn protocol_semantics_never_select_or_drive_a_transport_backend() {
    // Choosing between the buffered and splice backends, or invoking a relay at
    // all, is a Runtime Adapter decision. Protocol code that could name these
    // types could make a wire-format module depend on which zero-copy facility
    // the kernel happens to offer.
    let forbidden = [
        (
            "RelayBackend",
            "backend selection is not a protocol decision",
        ),
        ("TcpRelay", "protocol code must not drive a relay"),
        (
            "BackendRequest",
            "backend selection is not a protocol decision",
        ),
        ("RelayContext", "relay policy is not a protocol decision"),
        (
            "DirectionalRelayContext",
            "relay policy is not a protocol decision",
        ),
        ("crate::transport", "protocol must not depend on transport"),
        ("transport::", "protocol must not depend on transport"),
    ];

    let protocol = repository_root().join("src/protocol");
    let mut violations = Vec::new();
    for path in rust_sources(&protocol) {
        let source = fs::read_to_string(&path).expect("protocol source must be readable");
        let code = without_line_comments(&source);
        for (token, reason) in forbidden {
            if code.contains(token) {
                violations.push(format!("{}: {token} ({reason})", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "protocol/transport capability violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_session_engine_names_no_transport_capability() {
    // The pure engine is already forbidden from naming a socket by
    // `session_engine_boundary.rs`. This adds the capability vocabulary itself:
    // the engine decides *that* ownership crosses the raw boundary, never which
    // backend or policy carries it.
    let forbidden = [
        "RelayBackend",
        "TcpRelay",
        "BackendRequest",
        "RelayContext",
        "DirectionalRelayContext",
        "splice",
        "Splice",
    ];
    let engine = repository_root().join("crates/rr-session/src");
    let mut violations = Vec::new();
    for path in rust_sources(&engine) {
        let source = fs::read_to_string(&path).expect("engine source must be readable");
        let code = without_line_comments(&source);
        for token in forbidden {
            if code.contains(token) {
                violations.push(format!("{}: {token}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Session Engine named a transport capability:\n{}",
        violations.join("\n")
    );
}

#[test]
fn transport_never_depends_back_on_adapter_or_configuration() {
    // Dependency direction is Runtime Adapter -> Transport. In particular,
    // descriptor accounting for sockets and pipes is a concrete transport
    // mechanism; Transport must not import its permit type back from Runtime.
    // Serialized operator policy is translated at composition, so Transport
    // also cannot reach up into Configuration for its construction values.
    let transport = repository_root().join("src/transport");
    let mut violations = Vec::new();
    for path in rust_sources(&transport) {
        let source = fs::read_to_string(&path).expect("transport source must be readable");
        let code = without_line_comments(&source);
        for token in ["runtime::", "config::", "protocol::"] {
            if code.contains(token) {
                violations.push(format!("{}: {token}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Transport depends upward on Runtime Adapter or Configuration:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_directional_capability_cannot_be_asked_for_reset_as_eof() {
    // The two raw capabilities honour different options, so they take different
    // policy types. `DirectionalRelayContext` has no reset-as-EOF field at all,
    // which is what makes an unsupported request unrepresentable instead of
    // silently dropped. Checked as source text because the absence of a field
    // cannot be asserted at runtime.
    let backend = fs::read_to_string(repository_root().join("src/transport/backend.rs"))
        .expect("backend source must be readable");
    let directional_start = backend
        .find("pub struct DirectionalRelayContext")
        .expect("DirectionalRelayContext must exist");
    let directional_end = backend[directional_start..]
        .find("\n}")
        .expect("struct must terminate")
        + directional_start;
    let directional = &backend[directional_start..directional_end];
    assert!(
        !directional.contains("source_reset_is_eof"),
        "the directional capability must not accept reset-as-EOF, because its \
         backends do not implement it"
    );
    assert!(
        backend.contains("pub struct RelayContext")
            && backend[backend
                .find("pub struct RelayContext")
                .expect("RelayContext must exist")..]
                .contains("source_reset_is_eof"),
        "the bidirectional capability must still accept reset-as-EOF"
    );
}

#[test]
fn the_adapter_layer_is_the_only_caller_of_a_raw_capability() {
    // Anti-vacuity, and the positive statement of the boundary: raw relay entry
    // points are invoked from the server adapter layer, nowhere else.
    let root = repository_root().join("src");
    let mut callers = Vec::new();
    for path in rust_sources(&root) {
        let source = fs::read_to_string(&path).expect("source must be readable");
        let code = without_line_comments(&source);
        if code.contains(".relay_owned(") || code.contains(".relay_direction(") {
            callers.push(path);
        }
    }
    assert!(
        !callers.is_empty(),
        "no caller invokes a raw relay capability; the boundary tests would be vacuous"
    );
    for path in &callers {
        let relative = path
            .strip_prefix(repository_root())
            .expect("caller must live in the repository");
        let text = relative.to_string_lossy();
        assert!(
            text.starts_with("src/server/") || text.starts_with("src/transport/"),
            "{text} invokes a raw relay capability from outside the adapter or transport layer"
        );
    }
}

#[test]
fn root_reaches_linux_mechanisms_only_through_rr_linux() {
    let root = repository_root().join("src");
    let violations: Vec<_> = rust_sources(&root)
        .into_iter()
        .filter_map(|path| {
            let source = fs::read_to_string(&path).expect("source must be readable");
            let code = without_line_comments(&source);
            (code.contains("rustix::") || code.contains("libc::")).then_some(path)
        })
        .collect();
    assert!(
        violations.is_empty(),
        "root source directly names Linux syscall crates: {violations:?}"
    );

    let manifest = fs::read_to_string(repository_root().join("Cargo.toml"))
        .expect("root manifest must be readable");
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("rustix =")),
        "the root manifest must not directly depend on rustix"
    );
}
