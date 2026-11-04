"""Pure statistics and verdict-logic tests (no Docker)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.validate import decide_verdict, summarize  # noqa: E402
from vulnforge.validate.stats import json_safe_number  # noqa: E402


class StatsTests(unittest.TestCase):
    def test_summarize(self):
        summary = summarize([1.0, 2.0, 3.0])
        self.assertEqual(summary.count, 3)
        self.assertEqual(summary.median, 2.0)
        self.assertEqual(summary.minimum, 1.0)
        self.assertEqual(summary.maximum, 3.0)
        self.assertGreater(summary.stdev, 0)
        self.assertGreater(summary.cv, 0)

    def test_empty_summary(self):
        summary = summarize([])
        self.assertEqual(summary.count, 0)
        self.assertEqual(summary.median, 0.0)

    def test_json_safe_number(self):
        self.assertEqual(json_safe_number(1.5), 1.5)
        self.assertIsNone(json_safe_number(float("inf")))
        self.assertIsNone(json_safe_number(float("nan")))


class VerdictTests(unittest.TestCase):
    ABS = {
        "mode": "absolute",
        "vulnerable_min": 3.0,
        "patched_max": 1.5,
        "min_samples": 3,
        "max_cv": 0.35,
    }
    REL = {
        "mode": "relative",
        "vulnerable_min": 1_000_000,
        "patched_max": 10_000_000,
        "min_samples": 3,
        "max_cv": 0.35,
        "min_ratio": 2.0,
    }

    def test_absolute_confirmed(self):
        result = decide_verdict([4.0, 5.0, 6.0], [0.6, 0.7, 0.8], self.ABS)
        self.assertEqual(result["verdict"], "CONFIRMED")

    def test_absolute_patched_fail(self):
        result = decide_verdict([4.0, 5.0, 6.0], [2.0, 2.1, 2.2], self.ABS)
        self.assertEqual(result["verdict"], "FAIL")

    def test_absolute_overlapping_ranges_inconclusive(self):
        result = decide_verdict([1.0, 5.0, 6.0], [1.4, 1.45, 1.5], self.ABS)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("overlap", result["reason"])

    def test_absolute_low_vulnerable_inconclusive(self):
        result = decide_verdict([1.0, 1.1, 1.2], [0.2, 0.3, 0.4], self.ABS)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_patched_variance_guard(self):
        result = decide_verdict([4.0, 5.0, 6.0], [0.1, 1.0, 2.0], self.ABS)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("coefficient of variation", result["reason"])

    def test_not_enough_samples(self):
        result = decide_verdict([5.0], [0.5], self.ABS)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("need >=", result["reason"])

    def test_relative_confirmed(self):
        result = decide_verdict(
            [4_000_000, 4_200_000, 3_800_000],
            [1_500_000, 1_600_000, 1_400_000],
            self.REL,
        )
        self.assertEqual(result["verdict"], "CONFIRMED")
        self.assertGreater(result["ratio"], 2.0)

    def test_relative_below_threshold_inconclusive(self):
        result = decide_verdict(
            [3_784_120, 3_900_000, 3_700_000],
            [1_946_896, 2_000_000, 1_900_000],
            self.REL,
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertLess(result["ratio"], 2.0)

    def test_relative_sanity_floor(self):
        result = decide_verdict(
            [100, 100, 100],
            [10, 10, 10],
            self.REL,
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("sanity floor", result["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
