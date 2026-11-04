"""Behavioral detection rules.

These rules answer "is this connection's resource consumption inconsistent
with its declared/observed request size" instead of matching a specific
payload. They are used by the offline M4 detector against captured probe
evidence and telemetry.
"""
from __future__ import annotations

from dataclasses import dataclass
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
    max_frame_rate_per_sec=200,
    min_bytes_per_frame_ok=64,
    memory_outlier_stdevs=3.0,
    max_body_duration_per_kb_s=0.5,
    min_process_growth_samples=3,
    min_process_growth=10,
    min_idle_growth_bytes=1_000_000,
)


def rule_frame_rate(sample: ConnectionSample, cfg=DEFAULTS) -> Verdict:
    if sample.duration_s <= 0:
        return Verdict("per_connection_frame_rate", False, "duration too small to rate")
    rate = sample.frames_or_chunks / sample.duration_s
    avg_frame_bytes = sample.bytes_total / max(sample.frames_or_chunks, 1)
    triggered = (
        rate > cfg["max_frame_rate_per_sec"]
        and avg_frame_bytes < cfg["min_bytes_per_frame_ok"]
    )
    return Verdict(
        "per_connection_frame_rate",
        triggered,
        f"rate={rate:.1f}/s avg_frame_bytes={avg_frame_bytes:.1f}B "
        f"(thresholds: >{cfg['max_frame_rate_per_sec']}/s and "
        f"<{cfg['min_bytes_per_frame_ok']}B avg)",
    )


def rule_memory_outlier(
    sample: ConnectionSample, pool: list[ConnectionSample], cfg=DEFAULTS
) -> Verdict:
    others = [
        connection.attributable_memory_bytes
        for connection in pool
        if connection.conn_id != sample.conn_id
    ]
    if len(others) < 5:
        return Verdict(
            "memory_per_connection_outlier",
            False,
            "insufficient pool for baseline",
        )
    mu, sigma = mean(others), pstdev(others) or 1
    z = (sample.attributable_memory_bytes - mu) / sigma
    triggered = z > cfg["memory_outlier_stdevs"]
    return Verdict(
        "memory_per_connection_outlier",
        triggered,
        f"z={z:.2f} (memory={sample.attributable_memory_bytes}B, "
        f"pool mean={mu:.0f}B, stdev={sigma:.0f}B)",
    )


def rule_body_duration(sample: ConnectionSample, cfg=DEFAULTS) -> Verdict:
    kb = max(sample.bytes_total, 1) / 1024
    per_kb = sample.duration_s / kb
    triggered = (
        per_kb > cfg["max_body_duration_per_kb_s"] and sample.bytes_total > 0
    )
    return Verdict(
        "body_duration_vs_size",
        triggered,
        f"{per_kb:.3f}s/KB over {kb:.2f}KB "
        f"(threshold {cfg['max_body_duration_per_kb_s']}s/KB)",
    )


def rule_unbounded_process_growth(
    history: list[ProcessGrowthSample], cfg=DEFAULTS
) -> Verdict:
    if len(history) < cfg["min_process_growth_samples"]:
        return Verdict(
            "unbounded_process_growth",
            False,
            f"only {len(history)} samples; need >= "
            f"{cfg['min_process_growth_samples']}",
        )

    process_counts = [sample.process_count for sample in history]
    top_memory = [sample.top_process_memory_bytes for sample in history]
    completed = [sample.completed_requests for sample in history]

    process_growth = process_counts[-1] - process_counts[0]
    memory_growth = top_memory[-1] - top_memory[0]
    no_request_progress = completed[-1] == completed[0]

    process_rising = all(
        b >= a for a, b in zip(process_counts, process_counts[1:])
    )
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


def evaluate(
    sample: ConnectionSample,
    pool: list[ConnectionSample],
    history: list[ProcessGrowthSample] | None = None,
) -> list[Verdict]:
    verdicts = [
        rule_frame_rate(sample),
        rule_memory_outlier(sample, pool),
        rule_body_duration(sample),
    ]
    if history is not None:
        verdicts.append(rule_unbounded_process_growth(history))
    return verdicts
