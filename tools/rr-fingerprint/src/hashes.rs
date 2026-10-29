//! Auxiliary TCP JA3/JA4 summaries, never a structural-equivalence verdict.
//! Algorithm references and their pinned revisions live in the testing guide.

use md5::Md5;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ClientHello, Cursor, DecodeError, Result, grease};

/// Lossy fingerprints alongside their complete unhashed inputs.
#[derive(Debug, Serialize)]
pub struct Fingerprints {
    /// JA3's ordered decimal fields, with GREASE excluded.
    pub ja3_raw: String,
    /// MD5 is required by JA3; it is not used as a security primitive.
    pub ja3: String,
    /// Sorted JA4 inputs, including the signature preference order.
    pub ja4_raw: String,
    /// TCP JA4. This decoder does not accept QUIC or DTLS captures.
    pub ja4: String,
}

fn decimal(values: impl IntoIterator<Item = u16>) -> String {
    values
        .into_iter()
        .filter(|v| !grease(*v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn hex(values: impl IntoIterator<Item = u16>) -> String {
    values
        .into_iter()
        .filter(|v| !grease(*v))
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn short_hash(input: &str) -> String {
    if input.is_empty() {
        "000000000000".to_owned()
    } else {
        Sha256::digest(input.as_bytes())
            .iter()
            .take(6)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn alpn_tag(first: &[u8]) -> String {
    match (first.first(), first.last()) {
        (Some(a), Some(b)) if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() => {
            format!("{}{}", char::from(*a), char::from(*b))
        }
        (Some(a), Some(b)) => format!("{:x}{:x}", a >> 4, b & 15),
        _ => "00".to_owned(),
    }
}

/// Summarize a decoded TCP hello, retaining the unhashed fingerprint inputs.
///
/// JA3 varies with Chrome's extension permutation. JA4 deliberately discards
/// ordering and many extension bodies; equal hashes cannot establish parity.
/// Malformed EC point-format vectors are rejected rather than truncated.
pub fn summarize(hello: &ClientHello) -> Result<Fingerprints> {
    let formats = if let Some(extension) = hello.extensions.iter().find(|e| e.kind == 11) {
        let mut r = Cursor(&extension.body);
        let values = r.short()?;
        r.end()?;
        if values.is_empty() {
            return Err(DecodeError("empty EC point formats"));
        }
        values.iter().map(|v| u16::from(*v)).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let ja3_raw = format!(
        "{},{},{},{},{}",
        hello.legacy_version,
        decimal(hello.cipher_suites.iter().copied()),
        decimal(hello.extensions.iter().map(|e| e.kind)),
        decimal(hello.groups.iter().flatten().copied()),
        decimal(formats),
    );
    let ja3 = Md5::digest(ja3_raw.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let version = hello
        .supported_versions
        .as_ref()
        .map_or(hello.legacy_version, |versions| {
            versions
                .iter()
                .copied()
                .filter(|v| !grease(*v))
                .max()
                .unwrap_or(0)
        });
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let mut ciphers: Vec<_> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !grease(*v))
        .collect();
    let mut extensions: Vec<_> = hello
        .extensions
        .iter()
        .map(|e| e.kind)
        .filter(|v| !grease(*v))
        .collect();
    let prefix = format!(
        "t{version}{}{:02}{:02}{}",
        if extensions.contains(&0) { 'd' } else { 'i' },
        ciphers.len().min(99),
        extensions.len().min(99),
        alpn_tag(
            hello
                .alpn
                .as_ref()
                .and_then(|v| v.first())
                .map_or(&[], Vec::as_slice)
        ),
    );
    ciphers.sort_unstable();
    extensions.retain(|v| !matches!(v, 0 | 16));
    extensions.sort_unstable();
    let ciphers = hex(ciphers);
    let mut extension_input = hex(extensions);
    let has_extensions = !extension_input.is_empty();
    let signatures = hex(hello.signature_algorithms.iter().flatten().copied());
    if !signatures.is_empty() {
        extension_input.push('_');
        extension_input.push_str(&signatures);
    }
    Ok(Fingerprints {
        ja3_raw,
        ja3,
        ja4_raw: format!("{prefix}_{ciphers}_{extension_input}"),
        ja4: format!(
            "{prefix}_{}_{}",
            short_hash(&ciphers),
            short_hash(if has_extensions { &extension_input } else { "" })
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Extension;

    fn example() -> ClientHello {
        ClientHello {
            records: vec![],
            legacy_version: 769,
            random: vec![],
            session_id: vec![],
            cipher_suites: vec![47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
            compression: vec![0],
            extensions: vec![
                Extension {
                    kind: 0,
                    body: vec![],
                },
                Extension {
                    kind: 10,
                    body: vec![],
                },
                Extension {
                    kind: 11,
                    body: vec![1, 0],
                },
            ],
            groups: Some(vec![23, 24, 25]),
            signature_algorithms: None,
            supported_versions: None,
            key_shares: None,
            alpn: None,
        }
    }

    #[test]
    fn published_ja3_example_and_grease_exclusion() {
        let mut hello = example();
        assert_eq!(
            summarize(&hello).unwrap().ja3,
            "ada70206e40642a3e4461f35503241d5"
        );
        hello.cipher_suites.insert(0, 0x1a1a);
        hello.extensions.push(Extension {
            kind: 0xfafa,
            body: vec![0],
        });
        hello.groups.as_mut().unwrap().push(0xaaaa);
        assert_eq!(
            summarize(&hello).unwrap().ja3,
            "ada70206e40642a3e4461f35503241d5"
        );
        hello.extensions[2].body.push(0);
        assert!(summarize(&hello).is_err());
    }

    #[test]
    fn published_ja4_example_and_order_loss() {
        let mut hello = example();
        hello.supported_versions = Some(vec![0x3a3a, 0x0304, 0x0303]);
        hello.cipher_suites = vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        hello.extensions = [
            0x001b, 0, 0x0033, 16, 0x4469, 0x0017, 0x002d, 0x000d, 5, 0x0023, 0x0012, 0x002b,
            0xff01, 11, 10, 0x0015,
        ]
        .map(|kind| Extension {
            kind,
            body: if kind == 11 { vec![1, 0] } else { vec![] },
        })
        .to_vec();
        hello.signature_algorithms = Some(vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]);
        hello.alpn = Some(vec![b"h2".to_vec()]);
        let first = summarize(&hello).unwrap();
        assert_eq!(first.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        hello.extensions.reverse();
        let shuffled = summarize(&hello).unwrap();
        assert_eq!(shuffled.ja4, first.ja4);
        assert_ne!(shuffled.ja3, first.ja3);
    }

    #[test]
    fn opaque_alpn_and_absent_inputs() {
        for (input, expected) in [
            (&b""[..], "00"),
            (b"h", "hh"),
            (b"http/1.1", "h1"),
            (&[0x30, 0xab, 0xcd, 0x31], "01"),
        ] {
            assert_eq!(alpn_tag(input), expected);
        }
        let mut hello = example();
        hello.extensions.clear();
        hello.cipher_suites.clear();
        assert_eq!(
            summarize(&hello).unwrap().ja4,
            "t10i000000_000000000000_000000000000"
        );
    }
}
