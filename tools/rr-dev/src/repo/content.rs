//! Bounded tracked content, onboarding graph, and machine-path hygiene.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::Path,
};

use super::{TrackedEntry, policy};

/// Required local-link edges in the two onboarding graphs.
///
/// General link validity remains a docs-check responsibility. These edges prove
/// that each entrypoint actually routes a new contributor to the next owner.
const ONBOARDING_LINKS: &[(&str, &str)] = &[
    ("README.md", "CONTRIBUTING.md"),
    ("README.md", "docs/en/index.md"),
    ("README.zh-CN.md", "CONTRIBUTING.md"),
    ("README.zh-CN.md", "docs/zh-CN/index.md"),
    ("CONTRIBUTING.md", "docs/en/index.md"),
    ("CONTRIBUTING.md", "docs/en/architecture.md"),
    (
        "CONTRIBUTING.md",
        "docs/en/development/repository-layout.md",
    ),
    (
        "CONTRIBUTING.md",
        "docs/en/development/development-workflow.md",
    ),
    ("CONTRIBUTING.md", "docs/en/development/testing.md"),
    ("AGENTS.md", "docs/en/architecture.md"),
    ("AGENTS.md", "docs/en/development/repository-layout.md"),
    ("AGENTS.md", "docs/en/development/development-workflow.md"),
    ("AGENTS.md", "docs/en/development/testing.md"),
    ("AGENTS.md", "docs/adr/README.md"),
];

/// The largest normalized tracked object is 425,921 bytes. The next binary
/// boundary leaves reviewable headroom while rejecting accidental raw captures.
const MAX_TRACKED_FILE_BYTES: u64 = 512 * 1024;

/// Exact oversized-object exceptions, each with a durable rationale.
///
/// There are intentionally no current exceptions. A future valid large fixture
/// or evidence object can be admitted by one narrow, reviewable path entry.
const OVERSIZED_FILE_EXCEPTIONS: &[(&str, &str)] = &[];

pub(super) fn failures(repo: &Path, entries: &[TrackedEntry]) -> Vec<String> {
    let mut failures = tracked_file_failures(repo, entries);
    failures.extend(onboarding_failures(repo));
    failures.extend(machine_path_failures(repo, entries));
    failures
}

fn tracked_file_failures(repo: &Path, entries: &[TrackedEntry]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in entries {
        let absolute = repo.join(&entry.path);
        let metadata = match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) => {
                failures.push(format!(
                    "tracked path is unavailable: {}: {error}",
                    entry.path
                ));
                continue;
            }
        };
        if metadata.len() > MAX_TRACKED_FILE_BYTES && oversized_exception(&entry.path).is_none() {
            failures.push(format!(
                "tracked object exceeds {MAX_TRACKED_FILE_BYTES} bytes without an exception: {} ({} bytes)",
                entry.path,
                metadata.len()
            ));
        }

        if policy::is_archived_script_evidence(&entry.path) {
            let expected = entry.path.split('/').nth(4).unwrap_or("");
            match crate::hash::sha256_file(&absolute) {
                Ok(actual) if actual == expected => {}
                Ok(actual) => failures.push(format!(
                    "archived shell/Python evidence digest mismatch: {} (path {expected}, content {actual})",
                    entry.path
                )),
                Err(error) => failures.push(format!(
                    "could not hash archived shell/Python evidence {}: {error}",
                    entry.path
                )),
            }
        }

        if !policy::is_archived_script_evidence(&entry.path)
            && !policy::is_script_path(&entry.path)
            && has_script_shebang(&absolute)
        {
            failures.push(format!(
                "active repository-owned shell/Python shebang: {}",
                entry.path
            ));
        }
    }

    for (path, rationale) in OVERSIZED_FILE_EXCEPTIONS {
        if rationale.trim().is_empty() {
            failures.push(format!(
                "oversized-file exception lacks a rationale: {path}"
            ));
        }
        if !entries.iter().any(|entry| entry.path == *path) {
            failures.push(format!("stale oversized-file exception: {path}"));
        }
    }
    failures
}

fn oversized_exception(path: &str) -> Option<&'static str> {
    OVERSIZED_FILE_EXCEPTIONS
        .iter()
        .find(|(candidate, _)| *candidate == path)
        .map(|(_, rationale)| *rationale)
}

fn has_script_shebang(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut prefix = Vec::new();
    if file.take(256).read_to_end(&mut prefix).is_err() {
        return false;
    }
    let first = prefix.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    is_script_shebang(first)
}

fn is_script_shebang(line: &[u8]) -> bool {
    let lowered = String::from_utf8_lossy(line).to_ascii_lowercase();
    let Some(command) = lowered.strip_prefix("#!") else {
        return false;
    };
    command.split_whitespace().any(|word| {
        let interpreter = word.rsplit('/').next().unwrap_or(word);
        matches!(interpreter, "bash" | "dash" | "sh" | "zsh") || interpreter.starts_with("python")
    })
}

fn onboarding_failures(repo: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let mut sources: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (source, _) in ONBOARDING_LINKS {
        if sources.contains_key(source) {
            continue;
        }
        match std::fs::read_to_string(repo.join(source)) {
            Ok(text) => {
                let links = crate::docs::markdown_link_targets(&text)
                    .into_iter()
                    .map(|target| {
                        target
                            .trim()
                            .trim_start_matches('<')
                            .trim_end_matches('>')
                            .split('#')
                            .next()
                            .unwrap_or("")
                            .to_owned()
                    })
                    .collect();
                sources.insert(source, links);
            }
            Err(error) => failures.push(format!(
                "could not read onboarding source {source}: {error}"
            )),
        }
    }
    for (source, target) in ONBOARDING_LINKS {
        if sources
            .get(source)
            .is_some_and(|targets| targets.contains(*target))
        {
            continue;
        }
        failures.push(format!(
            "onboarding graph is missing link {source} -> {target}"
        ));
    }
    failures
}

fn machine_path_failures(repo: &Path, entries: &[TrackedEntry]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in entries.iter().filter(|entry| is_policy_text(&entry.path)) {
        let Ok(text) = std::fs::read_to_string(repo.join(&entry.path)) else {
            failures.push(format!(
                "could not read policy/documentation text: {}",
                entry.path
            ));
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if contains_private_machine_path(line) {
                failures.push(format!(
                    "private machine path in policy/documentation: {}:{}",
                    entry.path,
                    index + 1
                ));
            }
        }
    }
    failures
}

fn is_policy_text(path: &str) -> bool {
    if path.starts_with("docs/") || (!path.contains('/') && has_markdown_extension(path)) {
        return true;
    }
    let in_policy_directory = [".cargo/", ".config/", ".github/"]
        .iter()
        .any(|prefix| path.starts_with(prefix));
    let text_extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            ["md", "toml", "yaml", "yml"]
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        });
    in_policy_directory && text_extension
}

fn has_markdown_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "md")
}

fn contains_private_machine_path(line: &str) -> bool {
    if [
        "~/.ssh/",
        "$HOME/.ssh/",
        "${HOME}/.ssh/",
        "%USERPROFILE%\\.ssh\\",
    ]
    .iter()
    .any(|fragment| line.contains(fragment))
    {
        return true;
    }
    if ["/home/", "/Users/"]
        .iter()
        .any(|prefix| contains_literal_home(line, prefix))
    {
        return true;
    }

    let lowered = line.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(found) = lowered[offset..].find(":\\users\\") {
        let marker = offset + found;
        if marker > 0 && lowered.as_bytes()[marker - 1].is_ascii_alphabetic() {
            let rest = &line[marker + ":\\users\\".len()..];
            if literal_user_component(rest).is_some_and(|user| !is_placeholder_user(user)) {
                return true;
            }
        }
        offset = marker + 1;
    }
    false
}

fn contains_literal_home(line: &str, prefix: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = line[offset..].find(prefix) {
        let rest = &line[offset + found + prefix.len()..];
        if literal_user_component(rest).is_some_and(|user| !is_placeholder_user(user)) {
            return true;
        }
        offset += found + prefix.len();
    }
    false
}

fn literal_user_component(text: &str) -> Option<&str> {
    let length = text
        .char_indices()
        .take_while(|(_, character)| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | '$' | '{' | '}' | '<' | '>')
        })
        .last()
        .map_or(0, |(index, character)| index + character.len_utf8());
    (length > 0).then(|| &text[..length])
}

fn is_placeholder_user(user: &str) -> bool {
    let normalized = user
        .trim_matches(['<', '>', '$', '{', '}'])
        .to_ascii_lowercase();
    ["example", "home", "user", "username"].contains(&normalized.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_machine_paths_are_narrowly_detected() {
        assert!(contains_private_machine_path(
            "cache = /home/jacek/private/ida"
        ));
        assert!(contains_private_machine_path(
            r"cache = C:\Users\jacek\private"
        ));
        assert!(contains_private_machine_path("use ~/.ssh/config"));
        assert!(!contains_private_machine_path(
            "example = /home/<user>/checkout"
        ));
        assert!(!contains_private_machine_path(
            "state = /var/lib/rust-reality"
        ));
    }

    #[test]
    fn shell_and_python_shebangs_are_detected_without_extensions() {
        assert!(is_script_shebang(b"#!/bin/sh"));
        assert!(is_script_shebang(b"#!/usr/bin/env bash"));
        assert!(is_script_shebang(b"#!/usr/bin/env python3 -I"));
        assert!(!is_script_shebang(b"#!/usr/bin/perl"));
        assert!(!is_script_shebang(b"ordinary text"));
    }
}
