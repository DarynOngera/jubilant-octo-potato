"""Data-driven prioritizer tests."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from triage.prioritizer import (  # noqa: E402
    MATRIX_PATH,
    build_matrix,
    exploitability_tier,
    load_config,
    load_scores,
    score_priority,
    validate_scores,
)


class PrioritizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.weights, cls.tiers = load_config()
        cls.scores = load_scores()
        cls.advisories = json.loads(
            (REPO_ROOT / "data" / "advisories.json").read_text()
        )["advisories"]
        cls.matrix = json.loads(MATRIX_PATH.read_text())

    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(self.weights.values()), 1.0)

    def test_tiers_are_descending(self):
        thresholds = [self.tiers[name]["threshold"] for name in ("E4", "E3", "E2", "E1")]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))

    def test_every_advisory_is_scored(self):
        validate_scores(self.scores, self.advisories)
        self.assertEqual(len(self.scores), len(self.advisories))

    def test_matrix_is_deterministic(self):
        generated = build_matrix(
            self.advisories, self.scores, self.weights, self.tiers
        )
        self.assertEqual(generated, self.matrix)

    def test_priority_and_tier_match_matrix(self):
        by_cve = {row["cve"]: row for row in self.matrix}
        for cve, score in self.scores.items():
            row = by_cve[cve]
            self.assertEqual(
                row["priority_P"], score_priority(score, self.weights), cve
            )
            self.assertEqual(
                row["exploit_tier"],
                exploitability_tier(score["exploitability"], self.tiers),
                cve,
            )

    def test_matrix_order_is_deterministic(self):
        ordered = [(row["priority_P"], row["cve"]) for row in self.matrix]
        self.assertEqual(
            ordered,
            sorted(ordered, key=lambda item: (-item[0], item[1])),
        )

    def test_check_mode_passes(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "triage" / "prioritizer.py"), "--check"],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK:", result.stdout)

    def test_missing_score_is_rejected(self):
        with self.assertRaises(SystemExit):
            validate_scores({}, self.advisories)

    def test_unknown_score_is_rejected(self):
        bad = dict(self.scores)
        bad["CVE-2099-999999"] = {
            "impact": 1,
            "exploitability": 1,
            "reachability": 1,
            "detectability": 1,
            "notes": "unknown",
        }
        with self.assertRaises(SystemExit):
            validate_scores(bad, self.advisories)

    def test_packaged_exploitability_matches_global_scores(self):
        for cve, score in self.scores.items():
            path = REPO_ROOT / "vulnerabilities" / cve / "analysis" / "exploitability.json"
            if not path.is_file():
                continue
            data = json.loads(path.read_text())
            self.assertEqual(data["impact_I"], score["impact"], cve)
            self.assertEqual(data["exploit_E"], score["exploitability"], cve)
            self.assertEqual(data["reach_R"], score["reachability"], cve)
            self.assertEqual(data["detect_D"], score["detectability"], cve)
            self.assertEqual(
                data["priority_P"], score_priority(score, self.weights), cve
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
