#!/usr/bin/env python3
"""Detection-rule self-test.

The rules now live in ``vulnforge.detect.rules`` so the M4 detector can reuse
them. This script keeps the original synthetic self-test.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.detect.rules import (  # noqa: E402
    ConnectionSample,
    ProcessGrowthSample,
    evaluate,
)


def main() -> None:
    random.seed(0)
    pool = [
        ConnectionSample(
            f"normal-{index}",
            frames_or_chunks=20,
            bytes_total=50_000,
            duration_s=0.8,
            attributable_memory_bytes=random.randint(40_000, 60_000),
        )
        for index in range(9)
    ]
    attacker = ConnectionSample(
        "attacker-1",
        frames_or_chunks=20_000,
        bytes_total=20_000,
        duration_s=30.0,
        attributable_memory_bytes=8_000_000,
    )
    pool.append(attacker)

    history = [
        ProcessGrowthSample(
            process_count=120 + index * 40,
            top_process_memory_bytes=2_000_000 + index * 1_500_000,
            completed_requests=500,
        )
        for index in range(5)
    ]

    for verdict in evaluate(attacker, pool, history):
        flag = "TRIGGERED" if verdict.triggered else "ok"
        print(f"[{flag:>10}] {verdict.rule}: {verdict.detail}")


if __name__ == "__main__":
    main()
