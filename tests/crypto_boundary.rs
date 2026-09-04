//! Which production module is allowed to know which cryptographic provider.
//!
//! `src/crypto/` owns entropy and X25519. Everything else — hashing, HMAC,
//! HKDF, the record AEAD, Ed25519, ML-KEM — is still called directly from the
//! protocol module that needs it. That is the honest state of the tree, and
//! this test writes it down so it can only shrink.
//!
//! The value is not the rule itself; it is that the v2 crypto migration
//! (issue #225) becomes measurable. Each step deletes lines from
//! [`PROVIDERS`], a reviewer sees exactly which modules stopped naming a
//! vendor crate, and a module that quietly acquires a new provider import
//! fails here instead of arriving unnoticed.
//!
//! A crate whose list is **empty** is forbidden in production source
//! altogether — that is what a finished migration looks like, and it is why a
//! completed entry is emptied rather than removed.
//!
//! # What is scanned
//!
//! Every `.rs` file under `src/` and `crates/`, with `//` line comments
//! removed so prose does not count. Test and fuzz modules inside those files
//! are **not** excluded: "which files know about this crate" is the property
//! worth constraining, and a differential test that reaches for an oracle is
//! part of that answer. Entries whose only use is a test say so.
//!
//! This is a source-text scan, like `tests/protocol_core_boundary.rs`. It
//! cannot see a provider reached through a re-export that never spells the
//! crate name, and it is not a substitute for reading a diff.

use std::{collections::BTreeSet, fs, path::Path};

/// Every production file that names each provider crate, and why.
///
/// Sorted by path within each crate. Adding or removing a file here is a
/// deliberate architectural act; the test fails until the list matches.
const PROVIDERS: &[(&str, &[&str])] = &[
    // **Empty on purpose: forbidden in production source.** C3b removed it;
    // `rr-crypto` computes X25519 now. It survives as a dev-dependency, the
    // independent oracle `tests/x25519_differential.rs` compares against, and
    // `tests/` is outside this scan. A production file naming it again fails
    // here, which is the point of keeping the entry rather than deleting it.
    ("aws_lc_rs", &[]),
    // The default TLS 1.3 record AEAD, behind the `ring-aead` feature.
    // `ring` is also reached through `ureq -> rustls`, so removing this use
    // would not remove the crate.
    ("ring", &["src/protocol/reality/tls13/record.rs"]),
    // The RustCrypto AEADs. `record.rs` is the `--no-default-features`
    // provider and the equivalence oracle; `auth.rs` (AES-256-GCM, REALITY
    // session id) and `handoff.rs` (ChaCha20-Poly1305) use them
    // unconditionally and are not behind the feature switch.
    (
        "aes_gcm",
        &[
            "src/protocol/reality/auth.rs",
            "src/protocol/reality/tls13/record.rs",
        ],
    ),
    (
        "chacha20poly1305",
        &[
            "src/protocol/handoff.rs",
            "src/protocol/reality/tls13/record.rs",
        ],
    ),
    // ChaCha12 backs the Vision padding CSPRNG. Not an AEAD use.
    ("chacha20", &["src/protocol/vless/padding.rs"]),
    // Digest, MAC and KDF: the C2 migration surface. Eight, three and three
    // files in `src/` today.
    //
    // The two `crates/rr-crypto` entries are a different thing and do not
    // shrink with C2: they are a **dev-dependency**, used by
    // `vendored_upstream_matches_the_recorded_digests` to hash the vendored
    // upstream assembly against the digests the provenance record pins. They
    // are not in the production graph, which `cargo tree -e normal` shows.
    (
        "sha2",
        &[
            "crates/rr-crypto/src/x25519/aarch64.rs",
            "crates/rr-crypto/src/x25519/x86_64.rs",
            "src/protocol/handoff.rs",
            "src/protocol/nxr.rs",
            "src/protocol/reality/auth.rs",
            "src/protocol/reality/client_hello.rs",
            "src/protocol/reality/replay.rs",
            "src/protocol/reality/tls13/keys.rs",
            "src/protocol/reality/tls13/messages.rs",
            "src/server/production/connection.rs",
        ],
    ),
    (
        "hmac",
        &[
            "src/protocol/nxr.rs",
            "src/protocol/reality/tls13/keys.rs",
            "src/protocol/reality/tls13/messages.rs",
        ],
    ),
    (
        "hkdf",
        &[
            "src/protocol/handoff.rs",
            "src/protocol/reality/auth.rs",
            "src/protocol/reality/tls13/keys.rs",
        ],
    ),
    // The signature provider, used once per session for CertificateVerify.
    ("ed25519_dalek", &["src/protocol/reality/tls13/messages.rs"]),
    // C3c removed the last production call site: every remaining `src/` file
    // names `x25519_dalek` only from test code — the independent oracle the
    // in-file differential tests and `tests/x25519_differential.rs` compare
    // `rr-crypto` against. Keeping the oracle is deliberate; the entry is now
    // also the tripwire that keeps production from naming the crate again.
    // The scan does not distinguish test code on purpose: "which files know
    // about this crate" is the property worth constraining.
    (
        "x25519_dalek",
        &[
            "src/crypto/keygen.rs",
            "src/crypto/x25519.rs",
            "src/protocol/handoff.rs",
            "src/protocol/reality/auth.rs",
            "src/protocol/reality/tls13/handshake.rs",
        ],
    ),
    // Post-quantum KEM. Deliberately delegated in v2 (issue #225): the
    // implementation risk is disproportionate to the measured headroom.
    (
        "ml_kem",
        &[
            "src/protocol/reality/client_hello.rs",
            "src/protocol/reality/tls13/handshake.rs",
        ],
    ),
    // Constant-time comparison, one production use: the client Finished check.
    ("subtle", &["src/protocol/reality/tls13/handshake.rs"]),
];

/// Files permitted to reach the operating-system entropy source directly.
///
/// `crypto::entropy` is the single cryptographic source. The other two are
/// exceptions with stated reasons, and each is expected to disappear or stay
/// forever on its own merits rather than by neglect. C3c removed the third:
/// `protocol/handoff.rs` drew through `getrandom::SysRng` only because
/// `x25519_dalek::EphemeralSecret::random_from_rng` demanded an RNG object;
/// its migration onto `EphemeralX25519Key::generate` folded that draw back
/// into the owned source.
const ENTROPY_SITES: &[(&str, &str)] = &[
    (
        "src/crypto/entropy.rs",
        "the owner: every cryptographic draw in the program goes through it",
    ),
    (
        "src/assets/mod.rs",
        "not cryptographic: a uniqueness suffix for an atomic asset-cache write",
    ),
    (
        "src/runtime/adaptive.rs",
        "not cryptographic: a uniqueness suffix for an atomic status-file write",
    ),
];

/// Reads every production source file with `//` line comments removed.
fn production_sources() -> Vec<(String, String)> {
    let mut sources = Vec::new();
    for root in ["src", "crates"] {
        collect(Path::new(root), &mut sources);
    }
    assert!(
        sources.len() > 100,
        "the production tree should have far more than 100 source files; \
         found {} — the walk is broken, not the tree",
        sources.len()
    );
    sources
}

fn collect(directory: &Path, sources: &mut Vec<(String, String)>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} is not readable: {error}", directory.display()));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            // `target/` lives inside `crates/*/` after a build.
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let code = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} is not readable: {error}", path.display()));
            sources.push((
                path.to_string_lossy().replace('\\', "/"),
                without_line_comments(&code),
            ));
        }
    }
}

fn without_line_comments(code: &str) -> String {
    code.lines()
        .map(|line| match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `code` names `krate` as a path root, e.g. `sha2::Sha256`.
fn names_crate(code: &str, krate: &str) -> bool {
    let mut rest = code;
    while let Some(index) = rest.find(krate) {
        let (before, after) = rest.split_at(index);
        let preceded_by_word = before
            .chars()
            .last()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let followed_by_path = after[krate.len()..].trim_start().starts_with("::");
        if !preceded_by_word && followed_by_path {
            return true;
        }
        rest = &after[krate.len()..];
    }
    false
}

#[test]
fn every_provider_crate_is_named_exactly_where_the_list_says() {
    let sources = production_sources();
    let mut drift = Vec::new();

    for (krate, permitted) in PROVIDERS {
        let observed: BTreeSet<&str> = sources
            .iter()
            .filter(|(_, code)| names_crate(code, krate))
            .map(|(path, _)| path.as_str())
            .collect();
        let expected: BTreeSet<&str> = permitted.iter().copied().collect();

        for added in observed.difference(&expected) {
            drift.push(format!(
                "{added} now names `{krate}`; if that is intended, add it to \
                 PROVIDERS and say why in the comment above the entry"
            ));
        }
        for removed in expected.difference(&observed) {
            drift.push(format!(
                "{removed} no longer names `{krate}`; delete it from PROVIDERS \
                 — a migration that shrinks this list should show up here"
            ));
        }
    }

    assert!(
        drift.is_empty(),
        "the crypto provider boundary moved:\n{}",
        drift.join("\n")
    );
}

#[test]
fn the_operating_system_entropy_source_has_one_owner() {
    let sources = production_sources();
    let observed: BTreeSet<&str> = sources
        .iter()
        .filter(|(_, code)| names_crate(code, "getrandom"))
        .map(|(path, _)| path.as_str())
        .collect();
    let expected: BTreeSet<&str> = ENTROPY_SITES.iter().map(|(path, _)| *path).collect();

    assert_eq!(
        observed, expected,
        "a file reached the operating-system entropy source directly. \
         Cryptographic draws go through `crypto::entropy::fill`; if this one \
         genuinely cannot, add it to ENTROPY_SITES with the reason"
    );
}

#[test]
fn the_boundary_lists_are_not_vacuous() {
    let sources = production_sources();
    let known: BTreeSet<&str> = sources.iter().map(|(path, _)| path.as_str()).collect();

    let mut missing = Vec::new();
    for (krate, files) in PROVIDERS {
        // An empty list is the strongest form of the rule, not a vacuous one:
        // it says the crate must not appear in production source at all. That
        // is what a completed migration looks like, and deleting the entry
        // instead would silently stop checking.
        for file in *files {
            if !known.contains(file) {
                missing.push(format!(
                    "PROVIDERS names {file} for `{krate}`, which does not exist"
                ));
            }
        }
    }
    for (file, reason) in ENTROPY_SITES {
        assert!(
            !reason.is_empty(),
            "{file} is exempt from the entropy owner rule without a reason"
        );
        if !known.contains(file) {
            missing.push(format!("ENTROPY_SITES names {file}, which does not exist"));
        }
    }

    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn the_scanner_matches_a_path_root_and_not_a_substring() {
    assert!(names_crate("use sha2::Sha256;", "sha2"));
    assert!(names_crate("let x = ring::aead::AES_128_GCM;", "ring"));
    assert!(names_crate("fastcrypto :: x25519", "fastcrypto"));
    // A longer crate name that merely contains a shorter one must not match.
    assert!(!names_crate(
        "use chacha20poly1305::ChaCha20Poly1305;",
        "chacha20"
    ));
    // A field or method of the same name is not a crate path.
    assert!(!names_crate("self.ring.len()", "ring"));
    // Comments are removed before the scan, not by it.
    assert!(names_crate("// use sha2::Sha256;", "sha2"));
    assert!(!names_crate(
        &without_line_comments("// use sha2::Sha256;"),
        "sha2"
    ));
    assert_eq!(
        without_line_comments("use ring::aead; // and a note about sha2::"),
        "use ring::aead; "
    );
}
