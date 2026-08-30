//! ADR naming, metadata, numbering, and index consistency.

use std::{collections::BTreeMap, path::Path};

use super::{TrackedEntry, policy};

pub(super) fn failures(repo: &Path, entries: &[TrackedEntry]) -> Vec<String> {
    let mut failures = Vec::new();
    let mut adrs = Vec::new();
    let mut numbers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for entry in entries {
        let Some(filename) = entry.path.strip_prefix("docs/adr/") else {
            continue;
        };
        if filename == "README.md"
            || filename.contains('/')
            || !policy::valid_adr_filename(filename)
        {
            continue;
        }
        let number = &filename[..4];
        adrs.push(filename);
        numbers.entry(number).or_default().push(filename);
        match std::fs::read_to_string(repo.join(&entry.path)) {
            Ok(text) => failures.extend(metadata_failures(&entry.path, number, &text)),
            Err(error) => failures.push(format!("could not read {}: {error}", entry.path)),
        }
    }
    adrs.sort_unstable();

    for (number, files) in numbers {
        if files.len() > 1 {
            failures.push(format!(
                "ADR number {number} is reused by: {}",
                files.join(", ")
            ));
        }
    }

    match std::fs::read_to_string(repo.join("docs/adr/README.md")) {
        Ok(index) => {
            let indexed = index_targets(&index);
            if indexed != adrs {
                failures.push(format!(
                    "ADR index targets must exactly match numbered ADRs in order: expected {adrs:?}, found {indexed:?}"
                ));
            }
        }
        Err(error) => failures.push(format!("could not read docs/adr/README.md: {error}")),
    }
    failures
}

fn metadata_failures(path: &str, number: &str, text: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let heading = text.lines().find(|line| !line.trim().is_empty());
    if heading.is_none_or(|line| !line.starts_with('#') || !line.contains(number)) {
        failures.push(format!("ADR heading must identify {number}: {path}"));
    }

    let status = status(text);
    if status.as_deref().is_none_or(|value| {
        let lowered = value.to_ascii_lowercase();
        !["accepted", "rejected", "superseded"]
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
    }) {
        failures.push(format!(
            "ADR must carry Accepted, Rejected, or Superseded status metadata: {path}"
        ));
    }
    failures
}

fn status(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().take(24).collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim().trim_start_matches('-').trim();
        if trimmed.len() >= "Status:".len()
            && trimmed[.."Status:".len()].eq_ignore_ascii_case("Status:")
        {
            let value = trimmed["Status:".len()..].trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
        if trimmed.eq_ignore_ascii_case("## Status") {
            return lines[index + 1..]
                .iter()
                .map(|next| next.trim())
                .find(|next| !next.is_empty())
                .map(str::to_owned);
        }
    }
    None
}

fn index_targets(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| {
            let row = line.trim().strip_prefix("| [")?;
            let (number, target) = row.split_once("](")?;
            if number.len() != 4 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let (target, _) = target.split_once(')')?;
            Some(target)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_parser_requires_exact_ordered_targets() {
        let index =
            "| [0001](0001-one.md) | one | Accepted |\n| [0002](0002-two.md) | two | Rejected |\n";
        assert_eq!(index_targets(index), ["0001-one.md", "0002-two.md"]);
    }

    #[test]
    fn metadata_accepts_both_canonical_status_shapes() {
        assert!(
            metadata_failures(
                "docs/adr/0001-one.md",
                "0001",
                "# ADR 0001: One\n\n- Status: Accepted\n"
            )
            .is_empty()
        );
        assert!(
            metadata_failures(
                "docs/adr/0002-two.md",
                "0002",
                "# ADR 0002: Two\n\n## Status\n\nRejected on measurement\n"
            )
            .is_empty()
        );
        assert!(
            !metadata_failures(
                "docs/adr/0003-three.md",
                "0003",
                "# Decision without number\n\nStatus: Pending\n"
            )
            .is_empty()
        );
    }
}
