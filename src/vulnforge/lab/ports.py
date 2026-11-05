"""Loopback port allocation for lab targets."""
from __future__ import annotations

import socket


def allocate_ports(count: int, host: str = "127.0.0.1") -> list[int]:
    """Allocate ``count`` distinct free TCP ports on ``host``.

    Sockets are held open until all ports are chosen, which prevents returning
    the same ephemeral port twice within one allocation. There is still an
    unavoidable race between allocation and `docker compose up`; the
    orchestrator treats a bind failure as a start error rather than silently
    reusing a port.
    """
    if count < 1:
        raise ValueError("count must be positive")
    sockets: list[socket.socket] = []
    ports: list[int] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            sockets.append(sock)
            ports.append(int(sock.getsockname()[1]))
    finally:
        for sock in sockets:
            sock.close()
    if len(set(ports)) != len(ports):
        raise RuntimeError(f"allocator returned duplicate ports: {ports}")
    return ports
