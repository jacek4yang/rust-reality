#!/usr/bin/env python3
"""HTTP origin for transfer validation: byte-exact GET and PUT.

GET /<name>  serves files from --directory.
PUT /<name>  stores the request body into --directory for hash comparison.

Binds one explicit address (IPv4 or IPv6). Every instance logs each request
line to stderr as JSON so tests can prove which address family served it.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import ipaddress
import json
import socket
import sys
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    directory: Path
    label: str

    def _log(self, method: str, path: str, detail: dict[str, object]) -> None:
        row = {
            "server": self.label,
            "method": method,
            "path": path,
            "client": self.client_address[0],
            **detail,
        }
        print(json.dumps(row), file=sys.stderr, flush=True)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        name = self.path.lstrip("/")
        source = self.directory / name
        if not source.is_file():
            self.send_error(404)
            return
        data = source.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        self._log("GET", self.path, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def do_PUT(self) -> None:  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length", "0"))
        name = self.path.lstrip("/") or "upload.bin"
        target = self.directory / name
        remaining = length
        digest = hashlib.sha256()
        with target.open("wb") as output:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self._log("PUT", self.path, {"bytes": length, "sha256": digest.hexdigest()})

    def log_message(self, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()

    family = (
        socket.AF_INET6
        if ipaddress.ip_address(args.bind).version == 6
        else socket.AF_INET
    )

    class Server(http.server.ThreadingHTTPServer):
        address_family = family
        daemon_threads = True

    Handler.directory = Path(args.directory)
    Handler.label = args.label
    server = Server((args.bind, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
