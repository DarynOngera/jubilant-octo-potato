"""Behavioral detection over captured evidence."""

from .rules import (
    ConnectionSample,
    ProcessGrowthSample,
    Verdict,
    evaluate,
)
from .runner import evaluate_package, run_detection

__all__ = [
    "ConnectionSample",
    "ProcessGrowthSample",
    "Verdict",
    "evaluate",
    "evaluate_package",
    "run_detection",
]
