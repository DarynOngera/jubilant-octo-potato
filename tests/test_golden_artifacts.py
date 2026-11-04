"""Golden baselines for the pre-factory Bandit pipeline."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = Path(__file__).resolve().parent / "golden"


class GoldenArtifactsTests(unittest.TestCase):
    def _assert_json_equal(self, actual_path: Path, golden_path: Path) -> None:
        self.assertTrue(actual_path.exists(), f"missing generated artifact: {actual_path}")
        self.assertEqual(
            json.loads(actual_path.read_text()),
            json.loads(golden_path.read_text()),
            f"{actual_path.name} drifted from {golden_path.name}",
        )

    def test_version_cve_map(self):
        self._assert_json_equal(
            REPO_ROOT / "data" / "version-cve-map.json",
            GOLDEN / "version-cve-map.json",
        )

    def test_lab_checkpoints(self):
        self._assert_json_equal(
            REPO_ROOT / "data" / "lab-checkpoints.json",
            GOLDEN / "lab-checkpoints.json",
        )

    def test_vulnerability_matrix(self):
        self._assert_json_equal(
            REPO_ROOT / "data" / "vulnerability-matrix.json",
            GOLDEN / "vulnerability-matrix.json",
        )

    def test_report_sections(self):
        text = (REPO_ROOT / "reports" / "technical-report.md").read_text()
        current = [line.rstrip() for line in text.splitlines() if line.startswith("## ")]
        expected = [
            line.rstrip()
            for line in (GOLDEN / "technical-report.sections.txt").read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(current, expected)

    def test_catalog_shape(self):
        data = json.loads((REPO_ROOT / "data" / "advisories.json").read_text())
        advisories = data["advisories"]
        self.assertEqual(len(advisories), 24)
        for advisory in advisories:
            for field in ("cve", "title", "affected", "fixed_in", "track", "references"):
                self.assertIn(field, advisory, advisory.get("cve"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
