//! Independent, bounded comparison policy for the pinned native browser corpus.
use crate::{ClientHello, DecodeError, Result, grease};
fn normalize_word(value: &mut u16) {
    if grease(*value) {
        *value = 0x0a0a;
    }
}

/// Compare browser and candidate records without discarding capability or framing
/// differences. Chrome's middle extension permutation and ECH length choices are
/// validated separately; Firefox extension order remains exact.
pub fn compare(reference: &[u8], candidate: &[u8], chrome: bool) -> Result<()> {
    let a = normalized(crate::decode(reference)?, chrome)?;
    let b = normalized(crate::decode(candidate)?, chrome)?;
    if a != b {
        return Err(DecodeError("ClientHello structural mismatch"));
    }
    Ok(())
}

/// Check structural equivalence and observable fresh-handshake diversity.
/// This detects constant randomness or disabled shuffling, not RNG quality.
pub fn compare_corpus(reference: &[u8], candidates: &[&[u8]], chrome: bool) -> Result<()> {
    use std::collections::BTreeSet;
    if !(16..=256).contains(&candidates.len()) {
        return Err(DecodeError("corpus must contain 16..=256 fresh handshakes"));
    }
    let expected = normalized(crate::decode(reference)?, chrome)?;
    let mut randoms = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut exchanges = BTreeSet::new();
    let mut ech = BTreeSet::new();
    let mut orders = BTreeSet::new();
    let mut grease_suites = BTreeSet::new();
    for candidate in candidates {
        let hello = crate::decode(candidate)?;
        if normalized(hello.clone(), chrome)? != expected {
            return Err(DecodeError("ClientHello structural mismatch"));
        }
        if !randoms.insert(hello.random) || !sessions.insert(hello.session_id) {
            return Err(DecodeError(
                "repeated handshake random or session identifier",
            ));
        }
        for share in hello.key_shares.unwrap_or_default() {
            if !grease(share.group) && !exchanges.insert((share.group, share.exchange)) {
                return Err(DecodeError("repeated ephemeral key share"));
            }
        }
        for extension in &hello.extensions {
            if extension.kind == 65037 && !ech.insert(extension.body.clone()) {
                return Err(DecodeError("repeated ECH GREASE payload"));
            }
        }
        orders.insert(
            hello
                .extensions
                .iter()
                .map(|e| if grease(e.kind) { 0x0a0a } else { e.kind })
                .collect::<Vec<_>>(),
        );
        grease_suites.extend(hello.cipher_suites.into_iter().filter(|v| grease(*v)));
    }
    if chrome && (orders.len() < 2 || grease_suites.len() < 2) {
        return Err(DecodeError("Chrome extension or GREASE diversity missing"));
    }
    Ok(())
}

fn normalized(mut h: ClientHello, chrome: bool) -> Result<ClientHello> {
    if h.records.len() != 1
        || h.records[0].version != 0x0301
        || h.legacy_version != 0x0303
        || h.random.len() != 32
        || h.session_id.len() != 32
        || h.compression != [0]
    {
        return Err(DecodeError("browser record/version/session framing"));
    }
    h.random.fill(0);
    h.session_id.fill(0);
    let shares = h
        .key_shares
        .as_mut()
        .ok_or(DecodeError("missing key shares"))?;
    let expected: &[(u16, usize)] = if chrome {
        &[(0x0a0a, 1), (4588, 1216), (29, 32)]
    } else {
        &[(4588, 1216), (29, 32), (23, 65)]
    };
    if shares.len() != expected.len() {
        return Err(DecodeError("key share count"));
    }
    for (share, (group, length)) in shares.iter().zip(expected) {
        let actual = if grease(share.group) {
            0x0a0a
        } else {
            share.group
        };
        if actual != *group || share.exchange.len() != *length {
            return Err(DecodeError("key share group/order/length"));
        }
    }
    let hybrid = &shares[usize::from(chrome)].exchange;
    let standalone = &shares[usize::from(chrome) + 1].exchange;
    if (hybrid[1184..] == *standalone) == chrome {
        return Err(DecodeError("browser hybrid/standalone X25519 relationship"));
    }
    if !chrome && shares[2].exchange[0] != 4 {
        return Err(DecodeError("P-256 SEC1 encoding"));
    }
    if chrome {
        let groups = h.groups.as_ref().ok_or(DecodeError("missing groups"))?;
        if groups.first() != Some(&shares[0].group) || shares[0].exchange != [0] {
            return Err(DecodeError("GREASE key share relationship"));
        }
        if h.extensions.len() != 19
            || !grease(h.extensions[0].kind)
            || !h.extensions[0].body.is_empty()
            || !grease(h.extensions[18].kind)
            || h.extensions[18].body != [0]
            || h.extensions[0].kind == h.extensions[18].kind
        {
            return Err(DecodeError("GREASE extension placement/content"));
        }
        h.extensions[0].kind = 0x0a0a;
        h.extensions[18].kind = 0x1a1a;
    } else if h.extensions.len() != 17 {
        return Err(DecodeError("Firefox extension count"));
    }
    for s in shares.iter_mut() {
        normalize_word(&mut s.group);
        s.exchange.fill(0);
        if s.group == 23 {
            s.exchange[0] = 4;
        }
    }
    for values in [
        &mut h.cipher_suites,
        h.groups.as_mut().ok_or(DecodeError("groups"))?,
        h.signature_algorithms
            .as_mut()
            .ok_or(DecodeError("signatures"))?,
        h.supported_versions
            .as_mut()
            .ok_or(DecodeError("versions"))?,
    ] {
        values.iter_mut().for_each(normalize_word);
    }
    for e in &mut h.extensions {
        match e.kind {
            10 | 13 | 43 => {
                let offset = if e.kind == 43 { 1 } else { 2 };
                for pair in e.body[offset..].as_chunks_mut::<2>().0 {
                    let mut value = u16::from_be_bytes([pair[0], pair[1]]);
                    normalize_word(&mut value);
                    pair.copy_from_slice(&value.to_be_bytes());
                }
            }
            51 => {
                let mut body = vec![0, 0];
                for s in shares.iter() {
                    body.extend_from_slice(&s.group.to_be_bytes());
                    body.extend_from_slice(&(s.exchange.len() as u16).to_be_bytes());
                    body.extend_from_slice(&s.exchange);
                }
                let length = (body.len() - 2) as u16;
                body[..2].copy_from_slice(&length.to_be_bytes());
                e.body = body;
            }
            65037 => {
                let b = &e.body;
                if b.len() < 42
                    || b[..3] != [0, 0, 1]
                    || b[3] != 0
                    || !(b[4] == 1 || (!chrome && b[4] == 3))
                    || b[6..8] != [0, 32]
                {
                    return Err(DecodeError("ECH GREASE header"));
                }
                let payload = usize::from(u16::from_be_bytes([b[40], b[41]]));
                if b.len() != payload + 42
                    || (chrome && (!matches!(payload, 144 | 176 | 208 | 240) || b[39] & 128 != 0))
                {
                    return Err(DecodeError("ECH GREASE payload/enc"));
                }
                if !chrome && payload != 240 {
                    return Err(DecodeError("Firefox fixture ECH payload length"));
                }
                // Only Chrome has a randomized length. Preserve Firefox's exact
                // length, and all other record bytes/length contributions.
                if chrome {
                    h.records[0].length = h.records[0]
                        .length
                        .checked_sub(payload)
                        .ok_or(DecodeError("record length"))?;
                    e.body.truncate(42);
                }
                e.body.fill(0);
            }
            _ => {}
        }
    }
    if chrome {
        h.extensions[1..18].sort_by_key(|e| e.kind);
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../benchmarks/evidence/browser-clienthello/windows-20261029/{name}/sample-00.tls"))).unwrap()
    }

    fn extension_range(wire: &[u8], kind: u16) -> std::ops::Range<usize> {
        let word = |i: usize| usize::from(u16::from_be_bytes([wire[i], wire[i + 1]]));
        let mut offset = 5 + 4 + 2 + 32;
        offset += 1 + usize::from(wire[offset]);
        offset += 2 + word(offset);
        offset += 1 + usize::from(wire[offset]);
        offset += 2;
        while offset < wire.len() {
            let length = word(offset + 2);
            if word(offset) == usize::from(kind) {
                return offset + 4..offset + 4 + length;
            }
            offset += 4 + length;
        }
        panic!("missing fixture extension");
    }

    #[test]
    fn normalization_does_not_hide_capability_or_content_regressions() {
        for name in ["chrome", "firefox"] {
            let reference = fixture(name);
            for kind in [0, 10, 13, 16, 27, 43, 45] {
                let mut bad = reference.clone();
                let range = extension_range(&bad, kind);
                bad[range.end - 1] ^= 1;
                assert!(
                    compare(&reference, &bad, name == "chrome").is_err(),
                    "{name} extension {kind}"
                );
            }
            let mut bad = reference.clone();
            let range = extension_range(&bad, 65037);
            bad[range.start + 4] = 2;
            assert!(compare(&reference, &bad, name == "chrome").is_err());
            let mut bad = reference.clone();
            let range = extension_range(&bad, 51);
            bad[range.start + 2] ^= 1;
            assert!(compare(&reference, &bad, name == "chrome").is_err());
        }
        let reference = fixture("firefox");
        let mut bad = reference.clone();
        let range = extension_range(&bad, 0);
        let first = range.start - 4;
        // Swap SNI and the following empty extended-master-secret extension.
        bad[first..range.end + 4].rotate_left(range.end - first);
        assert!(compare(&reference, &bad, false).is_err());
    }

    #[test]
    fn stock_xray_captures_are_hashed_and_distinct_from_native_browsers() {
        for reference in ["xray-26.10.29", "xray-26.10.31"] {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../benchmarks/evidence/browser-clienthello")
                .join(reference);
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap())
                    .unwrap();
            let samples = manifest["samples"].as_array().unwrap();
            assert_eq!(samples.len(), 40);
            for sample in samples {
                let wire = std::fs::read(root.join(sample["file"].as_str().unwrap())).unwrap();
                assert_eq!(
                    Sha256::digest(&wire)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    sample["sha256"].as_str().unwrap()
                );
                crate::decode(&wire).unwrap();
                let name = sample["profile"].as_str().unwrap();
                assert!(compare(&fixture(name), &wire, name == "chrome").is_err());
            }
        }
    }

    #[test]
    fn frozen_native_samples_have_verified_hashes_and_consistent_structure() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/evidence/browser-clienthello/windows-20261029");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        for name in ["chrome", "firefox"] {
            let samples = manifest["profiles"][name]["samples"].as_array().unwrap();
            assert_eq!(samples.len(), 20);
            let reference = std::fs::read(root.join(samples[0]["file"].as_str().unwrap())).unwrap();
            let mut corpus = Vec::new();
            for sample in samples {
                let wire = std::fs::read(root.join(sample["file"].as_str().unwrap())).unwrap();
                assert_eq!(
                    Sha256::digest(&wire)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    sample["sha256"].as_str().unwrap()
                );
                compare(&reference, &wire, name == "chrome").unwrap();
                let mut bad = wire.clone();
                bad[2] ^= 1;
                assert!(compare(&reference, &bad, name == "chrome").is_err());
                corpus.push(wire);
            }
            let candidates: Vec<_> = corpus.iter().map(Vec::as_slice).collect();
            compare_corpus(&reference, &candidates, name == "chrome").unwrap();
            assert!(compare_corpus(&reference, &candidates[..15], name == "chrome").is_err());
            assert!(
                compare_corpus(&reference, &[reference.as_slice(); 16], name == "chrome").is_err()
            );
        }
    }
}
