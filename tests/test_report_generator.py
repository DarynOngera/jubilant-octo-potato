"""Per-CVE report generator tests."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.packages import load_package  # noqa: E402
from vulnforge.report import write_package_report  # noqa: E402


class ReportGeneratorTests(unittest.TestCase):
    def test_116078_report_contains_validation_and_detection(self):
        real = load_config(REPO_ROOT).paths()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "CVE-2026-116078"
            shutil.copytree(real.packages / "CVE-2026-116078", target)
            pkg = load_package(target, real.schemas)
            report_path, json_path = write_package_report(pkg)
            text = report_path.read_text()
            self.assertIn("## 3. Validation result", text)
            self.assertIn("CONFIRMED", text)
            self.assertIn("## 4. Detection", text)
            self.assertIn("memory_per_connection_outlier", text)
            self.assertIn("## 6. Evidence and provenance", text)
            self.assertTrue(json_path.is_file())

    def test_inconclusive_report_does_not_claim_success(self):
        real = load_config(REPO_ROOT).paths()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "CVE-2026-111101"
            shutil.copytree(real.packages / "CVE-2026-111101", target)
            pkg = load_package(target, real.schemas)
            report_path, _ = write_package_report(pkg)
            text = report_path.read_text()
            self.assertIn("INCONCLUSIVE", text)
            self.assertIn("not a confirmed exploit", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
