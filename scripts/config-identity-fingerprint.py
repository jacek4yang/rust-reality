#!/usr/bin/env python3
"""Emit secret-free fingerprints for client-visible deployment identity."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


IDENTITY_FIELDS = {
    "clients",
    "flow",
    "listen",
    "port",
    "privateKey",
    "serverNames",
    "shortIds",
    "target",
}


def fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def visit(value: Any, path: str, result: dict[str, dict[str, Any]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            if key in IDENTITY_FIELDS:
                result[child_path] = {
                    "present": True,
                    "sha256": fingerprint(child),
                    "kind": type(child).__name__,
                    "count": len(child) if isinstance(child, (dict, list)) else 1,
                }
            visit(child, child_path, result)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            visit(child, f"{path}[{index}]", result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    with arguments.config.open(encoding="utf-8") as handle:
        config = json.load(handle)
    fields: dict[str, dict[str, Any]] = {}
    visit(config, "", fields)
    result = {
        "schemaVersion": 1,
        "configSha256": fingerprint(config),
        "identityFields": dict(sorted(fields.items())),
        "identitySetSha256": fingerprint(fields),
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
