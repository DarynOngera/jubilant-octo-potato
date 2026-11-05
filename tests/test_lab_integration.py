"""Gated Docker integration test for the M2 lab lifecycle.

Run explicitly:

    VULNFORGE_DOCKER=1 .venv/bin/python -m unittest tests.test_lab_integration -v

It builds and starts the real CVE-2026-116078 lab, checks health/versions, and
stops it in a finally block. It is skipped by default so unit/CI runs do not
require a Docker daemon or network access.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.lab import LabOrchestrator  # noqa: E402
from vulnforge.packages import find_package, validate_package  # noqa: E402
from vulnforge.targets.loader import load_adapter  # noqa: E402

CVE = "CVE-2026-116078"


@unittest.skipUnless(
    os.environ.get("VULNFORGE_DOCKER") == "1",
    "set VULNFORGE_DOCKER=1 to run Docker integration tests",
)
class LabIntegrationTests(unittest.TestCase):
    def test_build_start_status_stop(self):
        cfg = load_config(REPO_ROOT)
        paths = cfg.paths()
        pkg = find_package(paths, CVE)
        self.assertEqual(validate_package(pkg, paths), [])

        adapter = load_adapter(cfg, pkg.manifest.target)
        orchestrator = LabOrchestrator(cfg, paths, adapter)
        try:
            runtime, provenance_path = orchestrator.start(pkg)
            self.assertTrue(provenance_path.is_file())
            self.assertEqual(set(runtime.services), {"vulnerable", "patched"})

            status = orchestrator.status(pkg)
            self.assertTrue(status["running"])
            self.assertEqual(
                status["services"]["vulnerable"]["reported_version"], "1.14.0"
            )
            self.assertEqual(
                status["services"]["patched"]["reported_version"], "1.14.1"
            )
            for service in status["services"].values():
                self.assertTrue(service["healthy"])
        finally:
            orchestrator.stop(pkg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
