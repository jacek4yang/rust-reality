//! Reconstruction of upload receipts from the origin's immutable log snapshots.

use super::schema::{MAX_EVIDENCE_BYTES, UploadReceipt};
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
    if after.len() > MAX_EVIDENCE_BYTES
        || !after.starts_with(before)
        || u64::try_from(before.len()).ok() != Some(receipt.log_boundary)
        || (!before.is_empty() && !before.ends_with(b"\n"))
        || !after.ends_with(b"\n")
    {
        return Err("upload log snapshots do not prove the claimed append boundary".to_owned());
    }
    let text = std::str::from_utf8(after).map_err(|error| error.to_string())?;
    let mut offset = 0_u64;
    let mut matches = 0_u64;
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
        if row.path == receipt.path && row.method == "PUT" {
            if offset < receipt.log_boundary
                || offset != receipt.receipt_offset
                || row.bytes != receipt.bytes
                || row.sha256 != receipt.sha256
            {
                return Err("stale or mismatched upload receipt".to_owned());
            }
            matches += 1;
        }
        offset += u64::try_from(line.len()).map_err(|_| "origin log offset overflow")?;
    }
    if matches != 1 || receipt.appended_matches != matches {
        return Err("missing or duplicate upload receipt".to_owned());
    }
    Ok(())
}
