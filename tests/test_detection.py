"""Detection-runner tests against committed evidence."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.detect import ConnectionSample, evaluate_package  # noqa: E402
from vulnforge.detect.rules import DEFAULTS, rule_memory_outlier  # noqa: E402
from vulnforge.detect.runner import _config_from_spec  # noqa: E402
from vulnforge.packages import find_package, load_package  # noqa: E402
from vulnforge.schema import validate_instance  # noqa: E402


def _pool(mean_bytes: int, stdev_bytes: int) -> list[ConnectionSample]:
    """Six distinct samples whose population mean/stdev are exact."""
    values = [mean_bytes - stdev_bytes, mean_bytes + stdev_bytes] * 3
    return [
        ConnectionSample(
            conn_id=f"benign-{index}",
            frames_or_chunks=2,
            bytes_total=1_000,
            duration_s=0.1,
            attributable_memory_bytes=value,
        )
        for index, value in enumerate(values)
    ]


def _sample(memory_bytes: int) -> ConnectionSample:
    return ConnectionSample(
        conn_id="attack",
        frames_or_chunks=10_000,
        bytes_total=100_000,
        duration_s=10.0,
        attributable_memory_bytes=memory_bytes,
    )


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

    def test_memory_outlier_ignores_small_high_z_connection(self):
        # z ~= 3.4 but only 620 KB: the patched-target regression condition.
        verdict = rule_memory_outlier(
            _sample(620_000), _pool(mean_bytes=280_000, stdev_bytes=100_000)
        )
        self.assertFalse(verdict.triggered)
        self.assertIn("floor=3000000B", verdict.detail)

    def test_memory_outlier_triggers_on_large_connection(self):
        # z ~= 26 and 5.3 MB: well above both conditions.
        verdict = rule_memory_outlier(
            _sample(5_300_000), _pool(mean_bytes=2_700_000, stdev_bytes=100_000)
        )
        self.assertTrue(verdict.triggered)
        self.assertIn("floor=3000000B", verdict.detail)

    def test_memory_outlier_ignores_below_floor_connection(self):
        # z ~= 10 but only 2 MB: outlier without the required magnitude.
        verdict = rule_memory_outlier(
            _sample(2_000_000), _pool(mean_bytes=1_000_000, stdev_bytes=100_000)
        )
        self.assertFalse(verdict.triggered)

    def test_spec_thresholds_resolve_to_config(self):
        spec = {
            "rules": [
                {
                    "id": "memory_per_connection_outlier",
                    "threshold": {"stdevs": 4.5, "min_attack_bytes": 9_000_000},
                },
                {
                    "id": "per_connection_frame_rate",
                    "threshold": {
                        "chunks_per_second_min": 123,
                        "avg_chunk_bytes_max": 7,
                    },
                },
                {
                    "id": "body_duration_vs_size",
                    "threshold": {"seconds_per_kb_max": 0.25},
                },
                {
                    "id": "unbounded_process_growth",
                    "threshold": {
                        "min_process_growth": 2,
                        "min_idle_growth_bytes": 3,
                        "min_samples": 4,
                    },
                },
            ]
        }
        cfg = _config_from_spec(spec)
        self.assertEqual(cfg["memory_outlier_stdevs"], 4.5)
        self.assertEqual(cfg["memory_outlier_floor_bytes"], 9_000_000)
        self.assertEqual(cfg["max_frame_rate_per_sec"], 123)
        self.assertEqual(cfg["min_bytes_per_frame_ok"], 7)
        self.assertEqual(cfg["max_body_duration_per_kb_s"], 0.25)
        self.assertEqual(cfg["min_process_growth"], 2)
        self.assertEqual(cfg["min_idle_growth_bytes"], 3)
        self.assertEqual(cfg["min_process_growth_samples"], 4)

    def test_spec_thresholds_fall_back_to_defaults(self):
        self.assertEqual(_config_from_spec({}), dict(DEFAULTS))
        self.assertEqual(
            _config_from_spec(
                {
                    "rules": [
                        {"id": "unknown_rule", "threshold": {"stdevs": 99}},
                        {
                            "id": "memory_per_connection_outlier",
                            "threshold": {"unknown_key": 99},
                        },
                    ]
                }
            ),
            dict(DEFAULTS),
        )

    def test_spec_thresholds_drive_evaluate_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "CVE-2026-116078"
            shutil.copytree(self.paths.packages / "CVE-2026-116078", target)
            spec_path = target / "detection" / "spec.json"
            spec = json.loads(spec_path.read_text())
            memory_rule = next(
                rule
                for rule in spec["rules"]
                if rule["id"] == "memory_per_connection_outlier"
            )
            pkg = load_package(target, self.paths.schemas)

            # Lowering the floor to zero must expose the patched z > 3 runs.
            memory_rule["threshold"]["min_attack_bytes"] = 0
            spec_path.write_text(json.dumps(spec))
            result = evaluate_package(pkg)
            self.assertTrue(
                self._rules(result, "patched")["memory_per_connection_outlier"][
                    "triggered"
                ]
            )

            # Raising it above every vulnerable run must suppress the rule.
            memory_rule["threshold"]["min_attack_bytes"] = 9_000_000
            spec_path.write_text(json.dumps(spec))
            result = evaluate_package(pkg)
            self.assertFalse(
                self._rules(result, "vulnerable")["memory_per_connection_outlier"][
                    "triggered"
                ]
            )

    def test_116078_detection_evidence_schema(self):
        pkg = find_package(self.paths, "CVE-2026-116078")
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
