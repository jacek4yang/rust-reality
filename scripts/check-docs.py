#!/usr/bin/env python3
"""Validate local Markdown links and required bilingual operator documents."""

from __future__ import annotations

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
)


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
