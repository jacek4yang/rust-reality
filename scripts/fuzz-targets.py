#!/usr/bin/env python3
"""List and validate the cargo-fuzz targets declared by fuzz/Cargo.toml."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fuzz/Cargo.toml"


def targets() -> list[str]:
    with MANIFEST.open("rb") as source:
        manifest = tomllib.load(source)

    failures: list[str] = []
    names: list[str] = []
    for entry in manifest.get("bin", []):
        name = entry.get("name")
        path = entry.get("path")
        if not isinstance(name, str) or not name:
            failures.append("every [[bin]] needs a non-empty string name")
            continue
        if name in names:
            failures.append(f"duplicate fuzz target name: {name}")
        names.append(name)
        if not isinstance(path, str) or not ROOT.joinpath("fuzz", path).is_file():
            failures.append(f"{name}: missing fuzz target source: {path!r}")

    declared_paths = {
        Path(entry["path"]).name
        for entry in manifest.get("bin", [])
        if isinstance(entry.get("path"), str)
    }
    source_paths = {path.name for path in ROOT.joinpath("fuzz/fuzz_targets").glob("*.rs")}
    for path in sorted(source_paths - declared_paths):
        failures.append(f"undeclared fuzz target source: fuzz/fuzz_targets/{path}")
    if not names:
        failures.append("fuzz/Cargo.toml declares no [[bin]] targets")
    if failures:
        raise ValueError("; ".join(failures))
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int)
    args = parser.parse_args()
    if (args.shard_index is None) != (args.shard_count is None):
        parser.error("--shard-index and --shard-count must be supplied together")
    try:
        selected = targets()
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"fuzz target validation failed: {error}", file=sys.stderr)
        return 1
    if args.shard_count is not None:
        if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
            parser.error("shard count must be positive and index must be within the count")
        selected = selected[args.shard_index :: args.shard_count]
        if not selected:
            parser.error("selected shard is empty")
    print("\n".join(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
