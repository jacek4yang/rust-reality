//! Cross-provider comparison of the hash, MAC, KDF and signature primitives
//! this server performs per REALITY session, at their exact production shapes.
//!
//! The question this exists to answer is hardware-tier dependent. `sha2 0.11`
//! dispatches to SHA-NI for SHA-256 at runtime and to AVX2 for SHA-512/384;
//! `ring` and `aws-lc-rs` carry their own assembly. A host without SHA-NI
//! therefore measures a gap that a host with SHA-NI may not have, so the same
//! harness has to run on both CPU classes before a backend is chosen. That is
//! why this is a committed benchmark and not an ad-hoc script.
//!
//! Every operation is the shape the server actually performs:
//!
//! - the incremental TLS 1.3 transcript — six `update`s and four clone
//!   snapshots per handshake, as `build_server_flight_inner` drives it;
//! - HKDF-Extract and HKDF-Expand-Label at the key schedule's secret sizes;
//! - the REALITY authentication key derivation (20-byte salt, 32-byte IKM);
//! - the HMAC-SHA512 certificate binding over a 32-byte public key;
//! - the TLS Finished HMAC;
//! - the Ed25519 CertificateVerify signature over its 130/146-byte content.
//!
//! Providers are verified byte-identical before they are timed. A faster
//! wrong answer is not a result, and a provider that cannot reproduce the
//! current bytes cannot be adopted whatever it measures.
//!
//! Every sample is retained; nothing is averaged away and no fastest run is
//! selected. Provider order is reshuffled from a recorded seed on every
//! repetition, so a provider cannot win by running first or last.
//!
//! Usage:
//!
//! ```text
//! cargo bench --bench crypto_providers -- --repetitions 15 --seed 1
//! taskset -c 0-7 cargo bench --bench crypto_providers -- --label p-core
//! ```

use std::{
    env,
    hint::black_box,
    process,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac as _};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

/// The `KeyType` both ring-shaped HKDF APIs need to size an expansion.
struct OkmLen(usize);

impl ring::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl aws_lc_rs::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// A deterministic order shuffler; benchmark ordering must be reproducible.
struct Lcg(u64);

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            let target = usize::try_from(self.next() >> 16).unwrap_or(0) % (index + 1);
            items.swap(index, target);
        }
    }
}

/// Deterministic filler bytes, so every provider hashes the same input and a
/// rerun on another host hashes it again.
fn filler(len: usize, tag: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let mut state = u32::from(tag).wrapping_mul(2_654_435_761).wrapping_add(1);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push((state >> 24) as u8);
    }
    bytes
}

/// Which library computes one measured operation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Provider {
    /// `sha2` / `hmac` / `hkdf` / `ed25519-dalek`, the current production code.
    RustCrypto,
    /// `ring`, the current AEAD provider; resolves without `std`.
    Ring,
    /// `aws-lc-rs`, the current X25519 provider; requires `std`.
    AwsLcRs,
}

impl Provider {
    const fn id(self) -> &'static str {
        match self {
            Self::RustCrypto => "rustcrypto",
            Self::Ring => "ring",
            Self::AwsLcRs => "aws-lc-rs",
        }
    }
}

/// The message sizes of one server flight, in the order they are hashed.
///
/// `build_server_flight_inner` updates the running transcript six times and
/// finalises a clone four times. The two variants differ only in the key-share
/// sizes: the hybrid group carries a 1216-byte client share and a 1088-byte
/// server share, which is most of the difference in transcript volume.
struct FlightShape {
    id: &'static str,
    client_hello: usize,
    server_hello: usize,
    encrypted_extensions: usize,
    certificate: usize,
    certificate_verify: usize,
    finished: usize,
}

const FLIGHT_X25519: FlightShape = FlightShape {
    id: "x25519",
    client_hello: 517,
    server_hello: 122,
    encrypted_extensions: 6,
    certificate: 191,
    certificate_verify: 72,
    finished: 36,
};

const FLIGHT_HYBRID: FlightShape = FlightShape {
    id: "hybrid",
    client_hello: 1_741,
    server_hello: 1_178,
    encrypted_extensions: 6,
    certificate: 191,
    certificate_verify: 72,
    finished: 36,
};

/// The six handshake messages of one flight, as owned buffers.
struct FlightMessages {
    messages: Vec<Vec<u8>>,
    bytes: usize,
}

impl FlightMessages {
    fn build(shape: &FlightShape) -> Self {
        let sizes = [
            shape.client_hello,
            shape.server_hello,
            shape.encrypted_extensions,
            shape.certificate,
            shape.certificate_verify,
            shape.finished,
        ];
        let messages: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(index, len)| filler(*len, u8::try_from(index).unwrap_or(0)))
            .collect();
        let bytes = sizes.iter().sum();
        Self { messages, bytes }
    }
}

/// Which snapshot indices the flight finalises, by message count consumed.
///
/// Snapshots land after ServerHello (2 messages), after Certificate (4), after
/// CertificateVerify (5) and after Finished (6).
const SNAPSHOT_AFTER: [usize; 4] = [2, 4, 5, 6];

/// One provider's implementation of an operation, returning its exact output
/// bytes so the arms can be compared before any of them is timed.
type Arm = Box<dyn Fn() -> Vec<u8>>;

/// One measurable unit of work, closed over its inputs.
struct Operation {
    /// Operation identity, stable across hosts and reruns.
    id: String,
    /// Bytes of input the operation covers, for normalisation.
    input_bytes: usize,
    /// The providers that can compute it, and how.
    arms: Vec<(Provider, Arm)>,
}

impl Operation {
    fn new(id: impl Into<String>, input_bytes: usize) -> Self {
        Self {
            id: id.into(),
            input_bytes,
            arms: Vec::new(),
        }
    }

    fn arm(mut self, provider: Provider, run: impl Fn() -> Vec<u8> + 'static) -> Self {
        self.arms.push((provider, Box::new(run)));
        self
    }
}

/// Builds every operation with its production inputs.
#[expect(
    clippy::too_many_lines,
    reason = "one flat table of production shapes reads better than fragments \
              of it scattered across helpers; each entry is three lines"
)]
fn operations() -> Vec<Operation> {
    let mut operations = Vec::new();

    // One-shot digests at the two sizes the prior no-SHA-NI campaign measured,
    // retained so the two hardware tiers compare row for row.
    for len in [517_usize, 1_400] {
        let input = filler(len, 0x11);
        let (a, b, c) = (input.clone(), input.clone(), input);
        operations.push(
            Operation::new(format!("sha256-digest-{len}"), len)
                .arm(Provider::RustCrypto, move || Sha256::digest(&a).to_vec())
                .arm(Provider::Ring, move || {
                    ring::digest::digest(&ring::digest::SHA256, &b)
                        .as_ref()
                        .to_vec()
                })
                .arm(Provider::AwsLcRs, move || {
                    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &c)
                        .as_ref()
                        .to_vec()
                }),
        );

        let input = filler(len, 0x11);
        let (a, b, c) = (input.clone(), input.clone(), input);
        operations.push(
            Operation::new(format!("sha384-digest-{len}"), len)
                .arm(Provider::RustCrypto, move || Sha384::digest(&a).to_vec())
                .arm(Provider::Ring, move || {
                    ring::digest::digest(&ring::digest::SHA384, &b)
                        .as_ref()
                        .to_vec()
                })
                .arm(Provider::AwsLcRs, move || {
                    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, &c)
                        .as_ref()
                        .to_vec()
                }),
        );
    }

    // The production transcript: incremental updates with clone snapshots, not
    // a one-shot digest. This is what the key schedule actually costs.
    for shape in [&FLIGHT_X25519, &FLIGHT_HYBRID] {
        for (hash, name) in [(HashKind::Sha256, "sha256"), (HashKind::Sha384, "sha384")] {
            let flight = FlightMessages::build(shape);
            let a = flight.messages.clone();
            let b = flight.messages.clone();
            let c = flight.messages;
            operations.push(
                Operation::new(format!("transcript-{name}-{}", shape.id), flight.bytes)
                    .arm(Provider::RustCrypto, move || {
                        transcript_rustcrypto(hash, &a)
                    })
                    .arm(Provider::Ring, move || transcript_ring(hash, &b))
                    .arm(Provider::AwsLcRs, move || transcript_aws_lc(hash, &c)),
            );
        }
    }

    // HMAC-SHA512 certificate binding: 32-byte key over the 32-byte Ed25519
    // public key (`CertificateIdentity::forge_certificate`).
    let key = filler(32, 0x21);
    let message = filler(32, 0x22);
    let (ka, kb, kc) = (key.clone(), key.clone(), key);
    let (ma, mb, mc) = (message.clone(), message.clone(), message);
    operations.push(
        Operation::new("hmac-sha512-cert-binding", 32)
            .arm(Provider::RustCrypto, move || {
                let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&ka)
                    .expect("HMAC accepts any key length");
                mac.update(&ma);
                mac.finalize().into_bytes().to_vec()
            })
            .arm(Provider::Ring, move || {
                ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &kb), &mb)
                    .as_ref()
                    .to_vec()
            })
            .arm(Provider::AwsLcRs, move || {
                aws_lc_rs::hmac::sign(
                    &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA512, &kc),
                    &mc,
                )
                .as_ref()
                .to_vec()
            }),
    );

    // TLS Finished: HMAC over the transcript digest with the finished key.
    for (name, len) in [("sha256", 32_usize), ("sha384", 48)] {
        let key = filler(len, 0x31);
        let message = filler(len, 0x32);
        let (ka, kb, kc) = (key.clone(), key.clone(), key);
        let (ma, mb, mc) = (message.clone(), message.clone(), message);
        let (ring_alg, aws_alg) = if len == 32 {
            (ring::hmac::HMAC_SHA256, aws_lc_rs::hmac::HMAC_SHA256)
        } else {
            (ring::hmac::HMAC_SHA384, aws_lc_rs::hmac::HMAC_SHA384)
        };
        operations.push(
            Operation::new(format!("hmac-{name}-finished"), len)
                .arm(Provider::RustCrypto, move || {
                    if len == 32 {
                        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&ka)
                            .expect("HMAC accepts any key length");
                        mac.update(&ma);
                        mac.finalize().into_bytes().to_vec()
                    } else {
                        let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(&ka)
                            .expect("HMAC accepts any key length");
                        mac.update(&ma);
                        mac.finalize().into_bytes().to_vec()
                    }
                })
                .arm(Provider::Ring, move || {
                    ring::hmac::sign(&ring::hmac::Key::new(ring_alg, &kb), &mb)
                        .as_ref()
                        .to_vec()
                })
                .arm(Provider::AwsLcRs, move || {
                    aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_alg, &kc), &mc)
                        .as_ref()
                        .to_vec()
                }),
        );
    }

    // The REALITY authentication key: HKDF-SHA256 over a 20-byte salt (the
    // ClientHello random prefix) and the 32-byte X25519 shared secret,
    // expanded to 32 bytes under the `REALITY` info string.
    let salt = filler(20, 0x41);
    let ikm = filler(32, 0x42);
    let (sa, sb, sc) = (salt.clone(), salt.clone(), salt);
    let (ia, ib, ic) = (ikm.clone(), ikm.clone(), ikm);
    operations.push(
        Operation::new("hkdf-sha256-reality-auth", 32)
            .arm(Provider::RustCrypto, move || {
                let hkdf = Hkdf::<Sha256>::new(Some(&sa), &ia);
                let mut output = [0_u8; 32];
                hkdf.expand(b"REALITY", &mut output)
                    .expect("32 bytes is a valid HKDF length");
                output.to_vec()
            })
            .arm(Provider::Ring, move || {
                let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &sb).extract(&ib);
                let mut output = [0_u8; 32];
                prk.expand(&[b"REALITY"], OkmLen(32))
                    .expect("32 bytes is a valid HKDF length")
                    .fill(&mut output)
                    .expect("the output buffer matches the requested length");
                output.to_vec()
            })
            .arm(Provider::AwsLcRs, move || {
                let prk =
                    aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, &sc).extract(&ic);
                let mut output = [0_u8; 32];
                prk.expand(&[b"REALITY"], OkmLen(32))
                    .expect("32 bytes is a valid HKDF length")
                    .fill(&mut output)
                    .expect("the output buffer matches the requested length");
                output.to_vec()
            }),
    );

    // HKDF-Extract at both key-schedule sizes. ring and aws-lc-rs keep their
    // PRK opaque, so the comparable primitive is HMAC(salt, ikm) — which is
    // exactly what HKDF-Extract is, and what the key schedule would have to
    // call to keep storing a `Secret` as bytes.
    for (name, len) in [("sha256", 32_usize), ("sha384", 48)] {
        let salt = filler(len, 0x51);
        let ikm = filler(len, 0x52);
        let (sa, sb, sc) = (salt.clone(), salt.clone(), salt);
        let (ia, ib, ic) = (ikm.clone(), ikm.clone(), ikm);
        let (ring_alg, aws_alg) = if len == 32 {
            (ring::hmac::HMAC_SHA256, aws_lc_rs::hmac::HMAC_SHA256)
        } else {
            (ring::hmac::HMAC_SHA384, aws_lc_rs::hmac::HMAC_SHA384)
        };
        operations.push(
            Operation::new(format!("hkdf-extract-{name}"), len)
                .arm(Provider::RustCrypto, move || {
                    if len == 32 {
                        let (prk, _) = Hkdf::<Sha256>::extract(Some(&sa), &ia);
                        prk.to_vec()
                    } else {
                        let (prk, _) = Hkdf::<Sha384>::extract(Some(&sa), &ia);
                        prk.to_vec()
                    }
                })
                .arm(Provider::Ring, move || {
                    ring::hmac::sign(&ring::hmac::Key::new(ring_alg, &sb), &ib)
                        .as_ref()
                        .to_vec()
                })
                .arm(Provider::AwsLcRs, move || {
                    aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_alg, &sc), &ic)
                        .as_ref()
                        .to_vec()
                }),
        );
    }

    // HKDF-Expand-Label, the key schedule's per-derivation cost: a PRK, the
    // RFC 8446 encoded label, and one hash-length output.
    for (name, len) in [("sha256", 32_usize), ("sha384", 48)] {
        let prk = filler(len, 0x61);
        let info = expand_label_info(b"s ap traffic", &filler(len, 0x62), len);
        let (pa, pb, pc) = (prk.clone(), prk.clone(), prk);
        let (fa, fb, fc) = (info.clone(), info.clone(), info);
        let (ring_alg, aws_alg) = if len == 32 {
            (ring::hkdf::HKDF_SHA256, aws_lc_rs::hkdf::HKDF_SHA256)
        } else {
            (ring::hkdf::HKDF_SHA384, aws_lc_rs::hkdf::HKDF_SHA384)
        };
        operations.push(
            Operation::new(format!("hkdf-expand-label-{name}"), len)
                .arm(Provider::RustCrypto, move || {
                    let mut output = vec![0_u8; len];
                    if len == 32 {
                        Hkdf::<Sha256>::from_prk(&pa)
                            .expect("a hash-length PRK is valid")
                            .expand(&fa, &mut output)
                            .expect("one hash length is a valid HKDF length");
                    } else {
                        Hkdf::<Sha384>::from_prk(&pa)
                            .expect("a hash-length PRK is valid")
                            .expand(&fa, &mut output)
                            .expect("one hash length is a valid HKDF length");
                    }
                    output
                })
                .arm(Provider::Ring, move || {
                    let mut output = vec![0_u8; len];
                    ring::hkdf::Prk::new_less_safe(ring_alg, &pb)
                        .expand(&[&fb], OkmLen(len))
                        .expect("one hash length is a valid HKDF length")
                        .fill(&mut output)
                        .expect("the output buffer matches the requested length");
                    output
                })
                .arm(Provider::AwsLcRs, move || {
                    let mut output = vec![0_u8; len];
                    aws_lc_rs::hkdf::Prk::new_less_safe(aws_alg, &pc)
                        .expand(&[&fc], OkmLen(len))
                        .expect("one hash length is a valid HKDF length")
                        .fill(&mut output)
                        .expect("the output buffer matches the requested length");
                    output
                }),
        );
    }

    // Ed25519 CertificateVerify: 64 pad bytes, the 33-byte context string, a
    // separator, and the transcript hash. 130 bytes under a SHA-256 suite and
    // 146 under SHA-384.
    //
    // The signing key is built once, outside the timed closure, because
    // `CertificateIdentity` holds it for the process lifetime. Importing a key
    // per signature would measure a basepoint multiplication the server never
    // performs and would flatter whichever library imports fastest.
    let seed = filler(32, 0x71);
    for (name, hash_len) in [("sha256", 32_usize), ("sha384", 48)] {
        let mut content = vec![0x20_u8; 64];
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0);
        content.extend_from_slice(&filler(hash_len, 0x72));
        let signed_len = content.len();
        let (ca, cb, cc) = (content.clone(), content.clone(), content);

        let mut dalek_seed = [0_u8; 32];
        dalek_seed.copy_from_slice(&seed);
        let dalek_key = SigningKey::from_bytes(&dalek_seed);
        let ring_key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("32 bytes is a valid Ed25519 seed");
        let aws_key = aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("32 bytes is a valid Ed25519 seed");

        operations.push(
            Operation::new(format!("ed25519-sign-{name}-{signed_len}b"), signed_len)
                .arm(Provider::RustCrypto, move || {
                    dalek_key.sign(&ca).to_bytes().to_vec()
                })
                .arm(Provider::Ring, move || ring_key.sign(&cb).as_ref().to_vec())
                .arm(Provider::AwsLcRs, move || {
                    aws_key.sign(&cc).as_ref().to_vec()
                }),
        );
    }

    operations
}

/// Which digest a transcript operation runs.
#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Sha384,
}

/// The production transcript shape under `sha2`: one running state, updated
/// per message, finalised through a clone at each milestone.
fn transcript_rustcrypto(hash: HashKind, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut digests = Vec::new();
    match hash {
        HashKind::Sha256 => {
            let mut state = Sha256::new();
            for (index, message) in messages.iter().enumerate() {
                state.update(message);
                if SNAPSHOT_AFTER.contains(&(index + 1)) {
                    digests.extend_from_slice(&state.clone().finalize());
                }
            }
        }
        HashKind::Sha384 => {
            let mut state = Sha384::new();
            for (index, message) in messages.iter().enumerate() {
                state.update(message);
                if SNAPSHOT_AFTER.contains(&(index + 1)) {
                    digests.extend_from_slice(&state.clone().finalize());
                }
            }
        }
    }
    digests
}

/// The same shape under `ring::digest::Context`, which is `Clone`.
fn transcript_ring(hash: HashKind, messages: &[Vec<u8>]) -> Vec<u8> {
    let algorithm = match hash {
        HashKind::Sha256 => &ring::digest::SHA256,
        HashKind::Sha384 => &ring::digest::SHA384,
    };
    let mut state = ring::digest::Context::new(algorithm);
    let mut digests = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        state.update(message);
        if SNAPSHOT_AFTER.contains(&(index + 1)) {
            digests.extend_from_slice(state.clone().finish().as_ref());
        }
    }
    digests
}

/// The same shape under `aws_lc_rs::digest::Context`.
fn transcript_aws_lc(hash: HashKind, messages: &[Vec<u8>]) -> Vec<u8> {
    let algorithm = match hash {
        HashKind::Sha256 => &aws_lc_rs::digest::SHA256,
        HashKind::Sha384 => &aws_lc_rs::digest::SHA384,
    };
    let mut state = aws_lc_rs::digest::Context::new(algorithm);
    let mut digests = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        state.update(message);
        if SNAPSHOT_AFTER.contains(&(index + 1)) {
            digests.extend_from_slice(state.clone().finish().as_ref());
        }
    }
    digests
}

/// Encodes an RFC 8446 `HkdfLabel`, the info string every Expand-Label covers.
fn expand_label_info(label: &[u8], context: &[u8], output_len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&u16::try_from(output_len).unwrap_or(0).to_be_bytes());
    info.push(u8::try_from(6 + label.len()).unwrap_or(0));
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(u8::try_from(context.len()).unwrap_or(0));
    info.extend_from_slice(context);
    info
}

/// One timed repetition of one arm.
struct Sample {
    operation: String,
    provider: &'static str,
    repetition: usize,
    iterations: u64,
    elapsed_ns: u128,
}

impl Sample {
    fn ns_per_op(&self) -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "reporting precision; the counts here are far below 2^53"
        )]
        {
            self.elapsed_ns as f64 / self.iterations as f64
        }
    }
}

/// Chooses an iteration count whose batch runs for at least `target`, so the
/// clock's own cost cannot dominate a nanosecond-scale primitive.
fn calibrate(run: &dyn Fn() -> Vec<u8>, target: Duration) -> u64 {
    let mut iterations = 1_u64;
    loop {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(run());
        }
        let elapsed = start.elapsed();
        if elapsed >= target || iterations >= 1 << 26 {
            return iterations;
        }
        iterations = iterations.saturating_mul(4);
    }
}

fn main() {
    let mut repetitions = 15_usize;
    let mut seed = 1_u64;
    let mut label = String::from("default");
    let mut batch_ms = 20_u64;
    let mut filter: Option<String> = None;

    let arguments: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments.get(index + 1).cloned();
        match arguments[index].as_str() {
            "--repetitions" => repetitions = parse(value.as_deref(), repetitions),
            "--seed" => seed = parse(value.as_deref(), seed),
            "--batch-ms" => batch_ms = parse(value.as_deref(), batch_ms),
            "--label" => label = value.clone().unwrap_or(label),
            "--only" => filter = value.clone(),
            // `cargo bench` passes libtest flags this harness does not use.
            other if other.starts_with("--") => {
                index += 1;
                continue;
            }
            _ => {}
        }
        index += 2;
    }

    let mut operations = operations();
    if let Some(pattern) = filter.as_ref() {
        operations.retain(|operation| operation.id.contains(pattern.as_str()));
    }

    // Correctness gate: every comparable operation's arms must agree exactly.
    let mut verified = 0_usize;
    for operation in &operations {
        let mut expected: Option<Vec<u8>> = None;
        for (provider, run) in &operation.arms {
            let output = run();
            match expected.as_ref() {
                None => expected = Some(output),
                Some(reference) => {
                    assert_eq!(
                        reference,
                        &output,
                        "{} disagrees with the first provider on {}; a provider that \
                         cannot reproduce the current bytes is not a candidate",
                        provider.id(),
                        operation.id
                    );
                    verified += 1;
                }
            }
        }
    }

    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    println!(
        "{{\"schema\":\"crypto-provider-primitive/1\",\"kind\":\"run\",\"label\":\"{label}\",\
         \"seed\":{seed},\"repetitions\":{repetitions},\"batch_ms\":{batch_ms},\
         \"operations\":{},\"equivalence_checks\":{verified},\"started_unix\":{started}}}",
        operations.len()
    );

    let target = Duration::from_millis(batch_ms);
    let mut iterations = Vec::with_capacity(operations.len());
    for operation in &operations {
        let mut per_arm = Vec::with_capacity(operation.arms.len());
        for (_, run) in &operation.arms {
            per_arm.push(calibrate(run.as_ref(), target));
        }
        // One iteration count per operation, so every arm does the same amount
        // of bookkeeping and only the primitive differs.
        iterations.push(per_arm.into_iter().min().unwrap_or(1));
    }

    let mut order: Vec<(usize, usize)> = operations
        .iter()
        .enumerate()
        .flat_map(|(operation, entry)| (0..entry.arms.len()).map(move |arm| (operation, arm)))
        .collect();
    let mut shuffler = Lcg::new(seed);
    let mut samples = Vec::new();

    for repetition in 0..repetitions {
        shuffler.shuffle(&mut order);
        for (operation, arm) in &order {
            let entry = &operations[*operation];
            let count = iterations[*operation];
            let (provider, run) = &entry.arms[*arm];
            let start = Instant::now();
            for _ in 0..count {
                black_box(run());
            }
            let elapsed = start.elapsed().as_nanos();
            samples.push(Sample {
                operation: entry.id.clone(),
                provider: provider.id(),
                repetition,
                iterations: count,
                elapsed_ns: elapsed,
            });
        }
    }

    for sample in &samples {
        println!(
            "{{\"schema\":\"crypto-provider-primitive/1\",\"kind\":\"sample\",\
             \"label\":\"{label}\",\"op\":\"{}\",\"provider\":\"{}\",\"repetition\":{},\
             \"iterations\":{},\"elapsed_ns\":{},\"ns_per_op\":{:.4}}}",
            sample.operation,
            sample.provider,
            sample.repetition,
            sample.iterations,
            sample.elapsed_ns,
            sample.ns_per_op()
        );
    }

    for operation in &operations {
        for (provider, _) in &operation.arms {
            let mut values: Vec<f64> = samples
                .iter()
                .filter(|sample| {
                    sample.operation == operation.id && sample.provider == provider.id()
                })
                .map(Sample::ns_per_op)
                .collect();
            if values.is_empty() {
                continue;
            }
            values.sort_by(f64::total_cmp);
            let median = values[values.len() / 2];
            let minimum = values.first().copied().unwrap_or(f64::NAN);
            let maximum = values.last().copied().unwrap_or(f64::NAN);
            println!(
                "{{\"schema\":\"crypto-provider-primitive/1\",\"kind\":\"summary\",\
                 \"label\":\"{label}\",\"op\":\"{}\",\"provider\":\"{}\",\
                 \"input_bytes\":{},\"samples\":{},\"median_ns\":{median:.4},\
                 \"min_ns\":{minimum:.4},\"max_ns\":{maximum:.4},\"spread_pct\":{:.4}}}",
                operation.id,
                provider.id(),
                operation.input_bytes,
                values.len(),
                (maximum - minimum) / median * 100.0
            );
        }
    }

    if samples.is_empty() {
        eprintln!("no operation matched the filter; nothing was measured");
        process::exit(1);
    }
}

/// Parses one command-line value, keeping the default when it is absent.
fn parse<T: std::str::FromStr>(value: Option<&str>, default: T) -> T {
    value
        .and_then(|raw| raw.parse::<T>().ok())
        .unwrap_or(default)
}
