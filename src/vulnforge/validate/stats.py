"""Summary statistics for validation runs."""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass


@dataclass(frozen=True)
class Summary:
    count: int
    median: float
    mean: float
    minimum: float
    maximum: float
    stdev: float
    cv: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "median": self.median,
            "mean": self.mean,
            "min": self.minimum,
            "max": self.maximum,
            "stdev": self.stdev,
            "cv": self.cv,
        }


def summarize(values: list[float]) -> Summary:
    if not values:
        return Summary(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    mean = statistics.fmean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    cv = (stdev / mean) if mean != 0 else 0.0
    return Summary(
        count=len(values),
        median=float(statistics.median(values)),
        mean=float(mean),
        minimum=float(min(values)),
        maximum=float(max(values)),
        stdev=float(stdev),
        cv=float(cv),
    )


def json_safe_number(value: float) -> float | None:
    if not math.isfinite(value):
        return None
    return float(value)
