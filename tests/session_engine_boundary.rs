//! Enforced layering between the Session Engine, the Runtime Adapter, and
//! Transport.
//!
//! ADR 0008 declares the dependency direction:
//!
//! ```text
//! Application -> Session Engine -> Runtime Adapter -> Transport -> Linux
//! ```
//!
//! Those rules were previously verified by hand for each staged PR. This test
//! makes them a permanent gate, so a later change cannot quietly pull Tokio, a
//! socket, a descriptor, a clock, or an allocator into the pure engine, and
//! cannot reintroduce a semantic call into the raw relay hot path.
//!
//! The checks read source text rather than types on purpose: the properties are
//! about which names a layer is *allowed to mention at all*, which is exactly
//! what a dependency boundary is, and several of them (no `std`, no `alloc`, no
//! `unsafe`) cannot be expressed as a trait bound.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Repository root, derived from this test file's location.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every `.rs` file under `root`, sorted for deterministic failure messages.
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
///
/// Block comments are not stripped; the crate does not use them for these names,
/// and a false positive here fails loudly rather than silently passing.
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
fn the_session_engine_names_no_runtime_or_os_facility() {
    // Each entry is (forbidden token, why the boundary forbids it).
    let forbidden = [
        (
            "tokio",
            "the Session Engine must not know which runtime drives it",
        ),
        ("std::", "pure session logic stays on core, not std"),
        ("use std", "pure session logic stays on core, not std"),
        (
            "extern crate std",
            "pure session logic stays on core, not std",
        ),
        (
            "alloc::",
            "no moved algorithm currently needs owned heap storage",
        ),
        (
            "extern crate alloc",
            "no moved algorithm currently needs owned heap storage",
        ),
        (
            "unsafe",
            "the engine is safe code; unsafe belongs to transport",
        ),
        ("RawFd", "descriptors are Runtime Adapter property"),
        ("AsRawFd", "descriptors are Runtime Adapter property"),
        ("TcpStream", "sockets are Transport property"),
        ("SocketAddr", "sockets are Transport property"),
        ("Instant", "clocks are Runtime Adapter property"),
        ("SystemTime", "clocks are Runtime Adapter property"),
        ("Duration", "timers are Runtime Adapter property"),
        (
            "core::sync",
            "synchronization stays outside the pure engine",
        ),
        ("AtomicU", "synchronization stays outside the pure engine"),
        ("Mutex", "synchronization stays outside the pure engine"),
        ("getrandom", "randomness is Runtime Adapter property"),
        ("tracing", "process-global logging is not an engine concern"),
        ("log::", "process-global logging is not an engine concern"),
        ("Box<", "the engine allocates nothing"),
        ("Vec<", "the engine allocates nothing"),
        ("String", "the engine allocates nothing"),
    ];

    let engine = repository_root().join("crates/rr-session/src");
    let mut violations = Vec::new();
    for path in rust_sources(&engine) {
        let source = fs::read_to_string(&path).expect("engine source must be readable");
        let code = without_line_comments(&source);
        for (token, reason) in forbidden {
            if code.contains(token) {
                violations.push(format!("{}: {token} ({reason})", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Session Engine boundary violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_session_engine_declares_no_dependencies() {
    let manifest = fs::read_to_string(repository_root().join("crates/rr-session/Cargo.toml"))
        .expect("engine manifest must be readable");
    for section in [
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
    ] {
        assert!(
            !manifest.contains(section),
            "the Session Engine must declare no {section}; it is the property that keeps \
             the pure layer fuzzable and portable"
        );
    }
    assert!(
        manifest.contains("unsafe_code = \"deny\""),
        "the Session Engine must keep denying unsafe code"
    );
}

#[test]
fn the_session_engine_is_declared_no_std() {
    let lib = fs::read_to_string(repository_root().join("crates/rr-session/src/lib.rs"))
        .expect("engine lib.rs must be readable");
    assert!(
        lib.contains("#![no_std]"),
        "the Session Engine must stay `no_std`"
    );
}

#[test]
fn the_raw_relay_hot_path_never_calls_the_session_engine() {
    // Permanent invariant: once authenticated session ownership has crossed the
    // raw relay boundary, the Session Engine must impose no per-chunk work. The
    // strongest cheap form of that is that Transport cannot even name the engine.
    let transport = repository_root().join("src/transport");
    let mut violations = Vec::new();
    for path in rust_sources(&transport) {
        let source = fs::read_to_string(&path).expect("transport source must be readable");
        let code = without_line_comments(&source);
        for token in ["rr_session", "rr-session"] {
            if code.contains(token) {
                violations.push(format!("{}: {token}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Transport must not name the Session Engine:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_runtime_adapter_is_the_only_layer_naming_both_sides() {
    // Sanity check that the boundary is actually load-bearing: the server
    // modules that drive Tokio are where engine values are consumed. If nothing
    // named the engine, the tests above would pass vacuously.
    let server = repository_root().join("src/server");
    let adapters: Vec<_> = rust_sources(&server)
        .into_iter()
        .filter(|path| {
            fs::read_to_string(path)
                .expect("server source must be readable")
                .contains("rr_session")
        })
        .collect();
    assert!(
        !adapters.is_empty(),
        "no Runtime Adapter module consumes the Session Engine; the boundary tests \
         would be vacuous"
    );
}
