"""Local dashboard CLI command."""
from __future__ import annotations

import argparse
import sys

from ..config import FactoryConfig
from ..paths import Paths


def _cmd_ui(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    from ..ui.server import create_server

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "error: the UI only binds to loopback addresses "
            "(127.0.0.1, localhost, or ::1)",
            file=sys.stderr,
        )
        return 2
    try:
        server = create_server(
            cfg,
            paths,
            host=args.host,
            port=args.port,
            read_only=args.read_only,
        )
    except OSError as exc:
        print(f"error: could not start UI: {exc}", file=sys.stderr)
        return 1

    host, port = server.server_address[:2]
    display_host = f"[{host}]" if ":" in str(host) else str(host)
    url = f"http://{display_host}:{port}/"
    print(f"VulnForge UI: {url}")
    print("Press Ctrl-C to stop.")
    if not args.no_open:
        import threading
        import webbrowser

        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0
