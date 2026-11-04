#!/usr/bin/env python3
"""
thresholds.py

Defensive detection logic, independent of any specific PoC script, meant
to run against a live Bandit deployment's own telemetry/metrics (adapt the
`sample()` function to your actual metrics source -- Prometheus, an
internal telemetry sink, etc.). Ships with the lab's /admin/stats shape as
the reference implementation so it's testable end-to-end against the lab.

Detection philosophy (see report Section 7): behavioral thresholds and
protocol invariants, not literal payload/signature matching. Every rule
below answers "is this connection's resource consumption inconsistent
with its declared/observed request size", which generalizes across all
four amplification-family CVEs (111101, 116078, 108525, 105659/115269)
rather than hard-coding "chunk == 1 byte".

Rules
-----
1. per_connection_frame_rate: sustained tiny-frame/tiny-chunk rate far
   above what a legitimate client needs to deliver its payload.
2. memory_per_connection_outlier: a single connection's attributable
   memory delta is a statistical outlier vs. the rest of the pool.
3. body_duration_vs_size: a request body taking far longer to arrive than
   its size and the configured rate would suggest (trickle attacks like
   CVE-2026-105659 / 115269).
4. unbounded_process_growth: BEAM process count or top-process memory
   growing monotonically across polling intervals with no corresponding
   request completion -- a generic "something is accumulating" signal
   that doesn't need the specific CVE to be known in advance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean, pstdev


@dataclass
class ConnectionSample:
    conn_id: str
    frames_or_chunks: int
    bytes_total: int
    duration_s: float
    attributable_memory_bytes: int


@dataclass
class Verdict:
    rule: str
    triggered: bool
    detail: str


@dataclass
class ProcessGrowthSample:
    """One poll of a live node, used by the time-series growth rule."""

    process_count: int
    top_process_memory_bytes: int
    completed_requests: int


DEFAULTS = dict(
    max_frame_rate_per_sec=200,       # legit clients rarely need >200 tiny writes/sec
    min_bytes_per_frame_ok=64,        # frames/chunks averaging under this are suspicious at volume
    memory_outlier_stdevs=3.0,
    max_body_duration_per_kb_s=0.5,   # >0.5s per KB implies a trickle well below any real network floor
    min_process_growth_samples=3,
    min_process_growth=10,            # new BEAM processes across the window
    min_idle_growth_bytes=1_000_000,  # 1 MiB of top-process growth with no request progress
)


def rule_frame_rate(sample: ConnectionSample, cfg=DEFAULTS) -> Verdict:
    if sample.duration_s <= 0:
        return Verdict("per_connection_frame_rate", False, "duration too small to rate")
    rate = sample.frames_or_chunks / sample.duration_s
    avg_frame_bytes = sample.bytes_total / max(sample.frames_or_chunks, 1)
    triggered = rate > cfg["max_frame_rate_per_sec"] and avg_frame_bytes < cfg["min_bytes_per_frame_ok"]
    return Verdict(
        "per_connection_frame_rate",
        triggered,
        f"rate={rate:.1f}/s avg_frame_bytes={avg_frame_bytes:.1f}B "
        f"(thresholds: >{cfg['max_frame_rate_per_sec']}/s and <{cfg['min_bytes_per_frame_ok']}B avg)",
    )


def rule_memory_outlier(sample: ConnectionSample, pool: list[ConnectionSample], cfg=DEFAULTS) -> Verdict:
    others = [c.attributable_memory_bytes for c in pool if c.conn_id != sample.conn_id]
    if len(others) < 5:
        return Verdict("memory_per_connection_outlier", False, "insufficient pool for baseline")
    mu, sigma = mean(others), pstdev(others) or 1
    z = (sample.attributable_memory_bytes - mu) / sigma
    triggered = z > cfg["memory_outlier_stdevs"]
    return Verdict(
        "memory_per_connection_outlier",
        triggered,
        f"z={z:.2f} (memory={sample.attributable_memory_bytes}B, pool mean={mu:.0f}B, stdev={sigma:.0f}B)",
    )


def rule_body_duration(sample: ConnectionSample, cfg=DEFAULTS) -> Verdict:
    kb = max(sample.bytes_total, 1) / 1024
    per_kb = sample.duration_s / kb
    triggered = per_kb > cfg["max_body_duration_per_kb_s"] and sample.bytes_total > 0
    return Verdict(
        "body_duration_vs_size",
        triggered,
        f"{per_kb:.3f}s/KB over {kb:.2f}KB (threshold {cfg['max_body_duration_per_kb_s']}s/KB)",
    )


def rule_unbounded_process_growth(history: list[ProcessGrowthSample],
                                  cfg=DEFAULTS) -> Verdict:
    """
    Detect monotonic BEAM process/memory growth without completed-request
    progress. This is the generic "something is accumulating" signal that
    works even when the specific CVE is not known in advance.
    """
    if len(history) < cfg["min_process_growth_samples"]:
        return Verdict(
            "unbounded_process_growth",
            False,
            f"only {len(history)} samples; need >= {cfg['min_process_growth_samples']}",
        )

    process_counts = [s.process_count for s in history]
    top_memory = [s.top_process_memory_bytes for s in history]
    completed = [s.completed_requests for s in history]

    process_growth = process_counts[-1] - process_counts[0]
    memory_growth = top_memory[-1] - top_memory[0]
    no_request_progress = completed[-1] == completed[0]

    process_rising = all(b >= a for a, b in zip(process_counts, process_counts[1:]))
    memory_rising = all(b >= a for a, b in zip(top_memory, top_memory[1:]))

    triggered = no_request_progress and (
        (process_growth >= cfg["min_process_growth"] and process_rising)
        or (memory_growth >= cfg["min_idle_growth_bytes"] and memory_rising)
    )

    return Verdict(
        "unbounded_process_growth",
        triggered,
        f"process_count {process_counts[0]}->{process_counts[-1]} "
        f"(+{process_growth}), top_process_memory +{memory_growth}B, "
        f"completed_requests {completed[0]}->{completed[-1]} "
        f"(thresholds: +{cfg['min_process_growth']} procs or "
        f"+{cfg['min_idle_growth_bytes']}B with no request progress)",
    )


def evaluate(sample: ConnectionSample, pool: list[ConnectionSample],
             history: list[ProcessGrowthSample] | None = None) -> list[Verdict]:
    verdicts = [
        rule_frame_rate(sample),
        rule_memory_outlier(sample, pool),
        rule_body_duration(sample),
    ]
    if history is not None:
        verdicts.append(rule_unbounded_process_growth(history))
    return verdicts


if __name__ == "__main__":
    # Self-test with synthetic data: one attacker-shaped connection among
    # nine normal ones.
    import random

    random.seed(0)
    pool = [
        ConnectionSample(f"normal-{i}", frames_or_chunks=20, bytes_total=50_000,
                          duration_s=0.8, attributable_memory_bytes=random.randint(40_000, 60_000))
        for i in range(9)
    ]
    attacker = ConnectionSample("attacker-1", frames_or_chunks=20_000, bytes_total=20_000,
                                 duration_s=30.0, attributable_memory_bytes=8_000_000)
    pool.append(attacker)

    # Time-series signal: processes and top-process memory rise while no
    # requests complete.
    history = [
        ProcessGrowthSample(process_count=120 + i * 40,
                            top_process_memory_bytes=2_000_000 + i * 1_500_000,
                            completed_requests=500)
        for i in range(5)
    ]

    for v in evaluate(attacker, pool, history):
        flag = "TRIGGERED" if v.triggered else "ok"
        print(f"[{flag:>10}] {v.rule}: {v.detail}")
