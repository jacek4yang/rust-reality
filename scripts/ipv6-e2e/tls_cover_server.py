#!/usr/bin/env python3
"""Minimal TLS 1.3 cover server for REALITY fallback validation.

Binds one explicit address (IPv4 or IPv6) and answers every request with a
fixed HTTP response so fallback byte flow can be verified end to end.
"""

from __future__ import annotations

import argparse
import http.server
import ipaddress
import socket
import ssl

BODY = b"rust-reality ipv6 validation cover\n"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True, help="address to bind, e.g. ::1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--alpn", default="h2,http/1.1",
                        help="comma-separated ALPN protocols; empty disables ALPN")
    args = parser.parse_args()

    family = (
        socket.AF_INET6
        if ipaddress.ip_address(args.bind).version == 6
        else socket.AF_INET
    )

    class Server(http.server.ThreadingHTTPServer):
        address_family = family
        daemon_threads = True

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    if args.alpn:
        context.set_alpn_protocols(args.alpn.split(","))

    server = Server((args.bind, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
