#!/usr/bin/env python3
"""Minimal toy HTTP target used to prove the VulnForge adapter boundary.

This is deliberately not a CVE: it exists so the factory can build, start,
health-check, and stop a second target using only adapter/config changes.
"""
from __future__ import annotations

import json
import os
import resource
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = os.environ.get("TOY_VERSION", "0.1.0")


def rss_bytes() -> int:
    # ru_maxrss is KiB on Linux.
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send(200, b"ok")
        elif self.path == "/stats":
            payload = {
                "toy_version": VERSION,
                "process_count": 1,
                "erlang_memory": {"total": rss_bytes()},
                "top_processes": [{"memory": rss_bytes()}],
            }
            self._send(
                200,
                json.dumps(payload).encode(),
                "application/json",
            )
        else:
            self._send(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/echo":
            self._send(404, b"not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        received = 0
        while received < length:
            chunk = self.rfile.read(min(65536, length - received))
            if not chunk:
                break
            received += len(chunk)
        self._send(200, json.dumps({"received_bytes": received}).encode(), "application/json")

    def log_message(self, fmt: str, *args) -> None:
        # Keep container logs quiet during adapter contract tests.
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 4000), Handler)
    print(f"toy target {VERSION} listening on 0.0.0.0:4000", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
