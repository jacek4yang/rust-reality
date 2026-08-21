#!/usr/bin/env python3
"""Validate local Markdown links and required bilingual operator documents."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
REQUIRED_PAIRS = (
    ("README.md", "README.zh-CN.md"),
    ("SECURITY.md", "SECURITY.zh-CN.md"),
    ("docs/index.md", "docs/index.zh-CN.md"),
    ("docs/getting-started.md", "docs/getting-started.zh-CN.md"),
    ("docs/cli.md", "docs/cli.zh-CN.md"),
    ("docs/configuration.md", "docs/configuration.zh-CN.md"),
    ("docs/deployment.md", "docs/deployment.zh-CN.md"),
    ("docs/architecture.md", "docs/architecture.zh-CN.md"),
    ("docs/protocol.md", "docs/protocol.zh-CN.md"),
    ("docs/performance.md", "docs/performance.zh-CN.md"),
    ("docs/benchmarks.md", "docs/benchmarks.zh-CN.md"),
    ("docs/threat-model.md", "docs/threat-model.zh-CN.md"),
    ("docs/tuning.md", "docs/tuning.zh-CN.md"),
)

# Stable drift invariants learned from release documentation defects. Each is
# a phrase that was once published and later found wrong; keep the list small
# and only for statements that must never read as current behavior again.
FORBIDDEN_PHRASES = (
    # Inverted abort semantics: abort must read as RST/reset, never as a
    # graceful finish. (Both languages.)
    "indistinguishable from clean FIN",
    "不可区分",
    # Stale decision-register range; the register runs through D11.
    "D1–D9",
    # Pre-release positioning.
    "pre-1.0",
    "0.1.x",
)

# Files where historical wording is legitimate (version history and ADRs).
FORBIDDEN_EXEMPT = ("CHANGELOG.md", "docs/decisions/")

RELEASE_HEADLINES = ROOT / "machine-readable/current-release-headlines.json"


def section(text: str, start: str, end: str | None) -> str:
    try:
        body = text.split(start, 1)[1]
    except IndexError:
        return ""
    return body.split(end, 1)[0] if end and end in body else body


def release_headline_failures() -> list[str]:
    """Keep current bilingual release surfaces tied to one small data file."""
    try:
        data = json.loads(RELEASE_HEADLINES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{RELEASE_HEADLINES.relative_to(ROOT)}: {error}"]

    if data.get("schemaVersion") != 1:
        return ["current release headline schemaVersion must be 1"]

    cargo = ROOT.joinpath("Cargo.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version = "([^"]+)"', cargo, re.MULTILINE)
    cargo_release = f"v{version_match.group(1)}" if version_match else None
    release = data.get("release")
    failures: list[str] = []
    if cargo_release != release:
        failures.append(
            f"current release mismatch: Cargo.toml={cargo_release!r}, headline data={release!r}"
        )

    documents = {
        "README.md": section(
            ROOT.joinpath("README.md").read_text(encoding="utf-8"),
            "## Performance vs Xray-core",
            "## Architecture",
        ),
        "README.zh-CN.md": section(
            ROOT.joinpath("README.zh-CN.md").read_text(encoding="utf-8"),
            "## 与 Xray-core 的性能对比",
            "## 架构",
        ),
        "docs/benchmarks.md": section(
            ROOT.joinpath("docs/benchmarks.md").read_text(encoding="utf-8"),
            f"## {release} release comparison evidence",
            "## Historical README headline tables",
        ),
        "docs/benchmarks.zh-CN.md": section(
            ROOT.joinpath("docs/benchmarks.zh-CN.md").read_text(encoding="utf-8"),
            f"## {release} 发布对比证据",
            "## 历史 README 头条表格",
        ),
        "docs/performance.md": section(
            ROOT.joinpath("docs/performance.md").read_text(encoding="utf-8"),
            f"## {release} release evidence",
            "## v1.5.1 release evidence",
        ),
        "docs/performance.zh-CN.md": section(
            ROOT.joinpath("docs/performance.zh-CN.md").read_text(encoding="utf-8"),
            f"## {release} 发布证据",
            "## v1.5.1 发布证据",
        ),
    }

    comparator = data["comparator"]
    common = [
        release,
        comparator["version"],
        comparator["commit"],
        comparator["goVersion"],
        comparator["binarySha256Abbreviated"],
    ]
    table_values = [
        value
        for group in (data["setup"], data["throughputRatios"], data["routing"])
        for row in group.values()
        for value in (row if isinstance(row, list) else [row])
    ]
    full_values = common + table_values + data["headlineValues"]
    for name, body in documents.items():
        if not body:
            failures.append(f"{name}: missing current-release heading for {release}")
            continue
        required = full_values if name.startswith("README") else common
        missing = [value for value in required if value not in body]
        if missing:
            failures.append(f"{name}: current-release data missing {missing!r}")
    return failures


def forbidden_phrase_failures() -> list[str]:
    failures: list[str] = []
    for source in markdown_files():
        relative = str(source.relative_to(ROOT))
        if relative.startswith(FORBIDDEN_EXEMPT):
            continue
        text = source.read_text(encoding="utf-8")
        for phrase in FORBIDDEN_PHRASES:
            if phrase in text:
                failures.append(f"{relative}: forbidden stale phrase: {phrase!r}")
    return failures


def markdown_files() -> list[Path]:
    roots = [*ROOT.glob("*.md"), *ROOT.joinpath("docs").rglob("*.md")]
    return sorted(path for path in roots if path.is_file())


def local_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().strip("<>")
    if not target or target.startswith("#"):
        return None
    if target.startswith(("http://", "https://", "mailto:")):
        return None
    path_text = unquote(target.split("#", 1)[0])
    if not path_text:
        return None
    return (source.parent / path_text).resolve()


def main() -> int:
    failures: list[str] = []
    for english, chinese in REQUIRED_PAIRS:
        for relative in (english, chinese):
            if not ROOT.joinpath(relative).is_file():
                failures.append(f"missing required document: {relative}")

    failures.extend(forbidden_phrase_failures())
    failures.extend(release_headline_failures())
    for source in markdown_files():
        text = source.read_text(encoding="utf-8")
        for match in LINK.finditer(text):
            target = local_target(source, match.group(1))
            if target is None:
                continue
            try:
                target.relative_to(ROOT)
            except ValueError:
                failures.append(
                    f"{source.relative_to(ROOT)}: local link escapes repository: {match.group(1)}"
                )
                continue
            if not target.exists():
                failures.append(
                    f"{source.relative_to(ROOT)}: missing local link target: {match.group(1)}"
                )

    if failures:
        print("documentation validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"documentation links verified across {len(markdown_files())} Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
