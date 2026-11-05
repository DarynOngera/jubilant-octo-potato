"""Probe protocol/loader tests (no Docker)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.packages import find_package  # noqa: E402
from vulnforge.probe import (  # noqa: E402
    ProbeBudgetError,
    ProbeResult,
    ProbeTarget,
    enforce_loopback,
    load_probe,
    validate_payload_budget,
)


class ProbeProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = load_config(REPO_ROOT).paths()

    def test_116078_probe_loads(self):
        pkg = find_package(self.paths, "CVE-2026-116078")
        assert pkg.probe is not None
        probe = load_probe(pkg.root, pkg.probe)
        self.assertTrue(callable(probe))

    def test_111101_probe_loads(self):
        pkg = find_package(self.paths, "CVE-2026-111101")
        assert pkg.probe is not None
        probe = load_probe(pkg.root, pkg.probe)
        self.assertTrue(callable(probe))

    def test_probe_result_wraps_legacy_dict(self):
        result = ProbeResult.from_mapping(
            {
                "target": "interim",
                "amplification_factor": 4.2,
                "delta_1byte_frames_bytes": 1000,
                "nested": {"ok": True},
            }
        )
        self.assertEqual(result.metrics["amplification_factor"], 4.2)
        self.assertEqual(result.metrics["delta_1byte_frames_bytes"], 1000.0)
        self.assertEqual(result.observations["target"], "interim")
        self.assertTrue(result.observations["nested"]["ok"])

    def test_target_host_and_port(self):
        target = ProbeTarget(
            name="interim",
            base_url="http://127.0.0.1:4120",
            admin_url="http://127.0.0.1:4121",
        )
        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 4120)

    def test_non_loopback_target_refused(self):
        target = ProbeTarget(
            name="prod-bandit",
            base_url="http://example.com:4000",
            admin_url="http://example.com:4001",
        )
        with self.assertRaises(ProbeBudgetError):
            enforce_loopback(target)

    def test_payload_budget_refuses_oversized_run(self):
        with self.assertRaises(ProbeBudgetError):
            validate_payload_budget(10**12)


if __name__ == "__main__":
    unittest.main(verbosity=2)
