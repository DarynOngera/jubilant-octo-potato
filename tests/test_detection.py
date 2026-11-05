"""Detection-runner tests against committed evidence."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.detect import evaluate_package  # noqa: E402
from vulnforge.packages import find_package  # noqa: E402
from vulnforge.schema import validate_instance  # noqa: E402


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = load_config(REPO_ROOT).paths()

    def _rules(self, result, role):
        return {rule["id"]: rule for rule in result["targets"][role]["rules"]}

    def test_116078_memory_outlier_discriminates(self):
        pkg = find_package(self.paths, "CVE-2026-116078")
        result = evaluate_package(pkg)
        self.assertEqual(result["result"], "TRIGGERED")
        vulnerable = self._rules(result, "vulnerable")
        patched = self._rules(result, "patched")
        self.assertTrue(vulnerable["memory_per_connection_outlier"]["triggered"])
        self.assertFalse(patched["memory_per_connection_outlier"]["triggered"])

    def test_116078_detection_evidence_schema(self):
        pkg = find_package(self.paths, "CVE-2026-116078")
        import json

        data = json.loads((pkg.root / "detection" / "evidence.json").read_text())
        self.assertEqual(
            validate_instance(data, self.paths.schemas, "detection"), []
        )

    def test_111101_is_not_claimed_as_triggered(self):
        pkg = find_package(self.paths, "CVE-2026-111101")
        result = evaluate_package(pkg)
        self.assertNotEqual(result["result"], "TRIGGERED")
        self.assertIn(result["result"], {"INCONCLUSIVE", "NOT_TRIGGERED"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
