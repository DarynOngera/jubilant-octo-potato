"""Package artifact contract tests."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.contract import missing_artifacts, required_artifacts  # noqa: E402
from vulnforge.packages import load_package  # noqa: E402


class PackageContractTests(unittest.TestCase):
    def test_validated_requires_evidence_and_report(self):
        required = required_artifacts("validated")
        self.assertIn("evidence/validation.json", required)
        self.assertIn("detection/evidence.json", required)
        self.assertIn("report.json", required)

    def test_draft_does_not_require_evidence(self):
        required = required_artifacts("draft")
        self.assertNotIn("evidence/validation.json", required)
        self.assertIn("poc/manifest.json", required)

    def test_missing_artifacts_are_reported_for_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{}")
            missing = missing_artifacts(root, "validated")
        self.assertNotIn("package.json", missing)
        self.assertIn("evidence/validation.json", missing)

    def test_loader_rejects_validated_package_without_report(self):
        paths = load_config(REPO_ROOT).paths()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "CVE-2026-116078"
            shutil.copytree(paths.packages / "CVE-2026-116078", target)
            (target / "report.json").unlink()
            pkg = load_package(target, paths.schemas)
        self.assertTrue(
            any("report.json" in error for error in pkg.errors), pkg.errors
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
