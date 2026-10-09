//! Reconstruction of upload receipts from the origin's immutable log snapshots.

use super::schema::{Artifact, MAX_EVIDENCE_BYTES, UploadReceipt};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    server: String,
    method: String,
    path: String,
    client: std::net::IpAddr,
    bytes: u64,
    sha256: String,
}

/// Reconstruct a fresh PUT acknowledgement, including its byte offset, from
/// complete before/after snapshots. A claimed boundary is never trusted alone.
///
/// # Errors
/// Rejects malformed, truncated, rewritten, stale or duplicate log receipts.
pub fn verify_upload(before: &[u8], after: &[u8], receipt: &UploadReceipt) -> Result<(), String> {
    let observed = reconstruct_upload(
        before,
        after,
        &receipt.path,
        receipt.access_log_before.clone(),
        receipt.access_log_after.clone(),
    )?;
    if observed != *receipt {
        return Err("claimed upload receipt differs from the raw origin append".to_owned());
    }
    Ok(())
}

/// Build the canonical upload receipt from fresh origin-log bytes.
///
/// # Errors
/// Rejects incomplete, rewritten, stale, missing and duplicate requests.
pub fn reconstruct_upload(
    before: &[u8],
    after: &[u8],
    path: &str,
    access_log_before: Artifact,
    access_log_after: Artifact,
) -> Result<UploadReceipt, String> {
    if after.len() > MAX_EVIDENCE_BYTES
        || !after.starts_with(before)
        || (!before.is_empty() && !before.ends_with(b"\n"))
        || !after.ends_with(b"\n")
    {
        return Err("upload log snapshots do not prove the claimed append boundary".to_owned());
    }
    let text = std::str::from_utf8(after).map_err(|error| error.to_string())?;
    let mut offset = 0_u64;
    let mut matched = None;
    let boundary = u64::try_from(before.len()).map_err(|_| "origin log boundary overflow")?;
    for line in text.split_inclusive('\n') {
        let row: Access = serde_json::from_str(line)
            .map_err(|error| format!("invalid origin access row: {error}"))?;
        if row.server.is_empty()
            || !["GET", "PUT", "POST"].contains(&row.method.as_str())
            || !row.path.starts_with('/')
            || row.client.is_unspecified()
            || !super::evaluate::digest(&row.sha256, 64)
        {
            return Err("incomplete origin access row".to_owned());
        }
        if row.path == path && row.method == "PUT" {
            if offset < boundary || matched.is_some() {
                return Err("stale or duplicate upload receipt".to_owned());
            }
            matched = Some((offset, row.bytes, row.sha256));
        }
        offset += u64::try_from(line.len()).map_err(|_| "origin log offset overflow")?;
    }
    let (receipt_offset, bytes, sha256) = matched.ok_or("missing upload receipt")?;
    Ok(UploadReceipt {
        access_log_before,
        access_log_after,
        path: path.to_owned(),
        log_boundary: boundary,
        receipt_offset,
        appended_matches: 1,
        bytes,
        sha256,
    })
}

/// Validate the fixed IPv4 SOCKS reply used by the isolated echo-prefix probe.
///
/// # Errors
/// Rejects incomplete, rejected or substituted protocol responses.
pub fn ipv4_socks_reply(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() == 10 && bytes[..4] == [5, 0, 0, 1] {
        Ok(())
    } else {
        Err("invalid IPv4 SOCKS connect reply".to_owned())
    }
}
