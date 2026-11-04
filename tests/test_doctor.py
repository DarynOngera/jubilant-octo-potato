"""Doctor and clean tests."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.doctor import clean_runtime, run_doctor  # noqa: E402
from vulnforge.paths import Paths  # noqa: E402


class DoctorTests(unittest.TestCase):
    def test_core_checks_pass(self):
        paths = load_config(REPO_ROOT).paths()
        checks = {check.name: check for check in run_doctor(paths)}
        for name in ("python", "config/vulnforge.yaml", "schemas", "packages", "lab limits"):
            self.assertTrue(checks[name].ok, checks[name])

    def test_clean_removes_runtime_state_only(self):
        real = load_config(REPO_ROOT).paths()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_file = root / ".vulnforge" / "labs" / "CVE-2026-116078" / "compose.yaml"
            runtime_file.parent.mkdir(parents=True)
            runtime_file.write_text("name: demo\n")
            paths = Paths(
                root=root,
                packages=real.packages,
                data=real.data,
                evidence=real.evidence,
                reports=real.reports,
                config=real.config,
                schemas=real.schemas,
            )
            dry = clean_runtime(paths, dry_run=True)
            self.assertTrue(runtime_file.is_file())
            self.assertIn(runtime_file, dry)
            clean_runtime(paths, dry_run=False)
            self.assertFalse((root / ".vulnforge").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
