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
    MeasurementSpec,
    ProbeBudgetError,
    ProbeResult,
    ProbeTarget,
    enforce_loopback,
    load_probe,
    read_beam_stats,
    read_toy_stats,
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

    def test_beam_measurement_reader(self):
        sample = read_beam_stats(
            {
                "erlang_memory": {"total": 1234},
                "process_count": 7,
                "top_processes": [{"memory": 900}, {"memory": 1000}],
                "run_queue": 2,
            }
        )
        assert sample is not None
        self.assertEqual(sample.total, 1234)
        self.assertEqual(sample.process_count, 7)
        self.assertEqual(sample.top_process_memory, 1000)
        self.assertEqual(sample.run_queue, 2)
        self.assertIsNone(read_beam_stats({"erlang_memory": {}}))

    def test_toy_measurement_reader(self):
        sample = read_toy_stats(
            {
                "memory_bytes": 4321,
                "process_count": 1,
                "top_process_memory_bytes": 4321,
            }
        )
        assert sample is not None
        self.assertEqual(sample.total, 4321)
        self.assertEqual(sample.process_count, 1)
        self.assertEqual(sample.top_process_memory, 4321)
        self.assertIsNone(read_toy_stats({"erlang_memory": {"total": 1}}))

    def test_target_carries_measurement_spec(self):
        target = ProbeTarget(
            name="toy",
            base_url="http://127.0.0.1:4000",
            admin_url="http://127.0.0.1:4000",
            measurement=MeasurementSpec(stats_path="/metrics", gc_path=None),
        )
        self.assertEqual(target.measurement.stats_path, "/metrics")
        self.assertIsNone(target.measurement.gc_path)
        self.assertEqual(target.measurement_base_url, target.admin_url)
        self.assertFalse(target.admin_gc())

        single = ProbeTarget(
            name="toy",
            base_url="http://127.0.0.1:4000",
            admin_url="http://127.0.0.1:4001",
            measurement=MeasurementSpec(use_app_listener=True),
        )
        self.assertEqual(single.measurement_base_url, single.base_url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
