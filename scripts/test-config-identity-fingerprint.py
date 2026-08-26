#!/usr/bin/env python3
"""Prove deployment identity reports contain hashes, never raw values."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "config_identity_fingerprint", ROOT / "scripts/config-identity-fingerprint.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

secret = "never-emit-this-private-value"
document = {
    "inbounds": [
        {
            "listen": {"mode": "ipv4Only", "ipv4": "0.0.0.0"},
            "port": 443,
            "settings": {"clients": [{"id": secret, "flow": "xtls-rprx-vision"}]},
            "streamSettings": {
                "reality": {
                    "privateKey": secret,
                    "shortIds": [secret],
                    "serverNames": ["example.invalid"],
                    "target": "example.invalid:443",
                }
            },
        }
    ]
}
fields: dict = {}
MODULE.visit(document, "", fields)
encoded = str(fields)
assert secret not in encoded
assert fields
assert all(set(value) == {"present", "sha256", "kind", "count"} for value in fields.values())
print("config identity fingerprint tests passed")
