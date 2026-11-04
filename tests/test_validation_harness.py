"""End-to-end harness tests with a fake probe/runtime (no Docker)."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.lab.models import LabRuntime, ServicePlan  # noqa: E402
from vulnforge.packages import load_package  # noqa: E402
from vulnforge.paths import Paths  # noqa: E402
from vulnforge.probe import ProbeResult  # noqa: E402
from vulnforge.schema import validate_instance  # noqa: E402
from vulnforge.validate.harness import run_validation  # noqa: E402


def _runtime(cve: str, root: Path, versions: dict[str, str], names: dict[str, str]) -> LabRuntime:
    services = {}
    for role in ("vulnerable", "patched"):
        services[role] = ServicePlan(
            role=role,
            name=names[role],
            version=versions[role],
            image_tag=f"fake/{cve}-{role}:latest",
            container_name=f"fake-{cve}-{role}",
            build_args={},
            labels={},
            base_url=f"http://127.0.0.1:{4000 + len(role)}",
            admin_url=f"http://127.0.0.1:{4100 + len(role)}",
            app_port=4000 + len(role),
            admin_port=4100 + len(role),
        )
    return LabRuntime(
        cve=cve,
        target="bandit",
        lab_id=f"fake-{cve}",
        network="fake",
        compose_path=root / "compose.yaml",
        runtime_path=root / "runtime.json",
        services=services,
        created_at="2026-11-04T00:00:00Z",
    )


class HarnessTests(unittest.TestCase):
    def _paths(self, root: Path) -> Paths:
        real = load_config(REPO_ROOT).paths()
        return Paths(
            root=root,
            packages=root / "vulnerabilities",
            data=real.data,
            evidence=real.evidence,
            reports=real.reports,
            config=real.config,
            schemas=real.schemas,
        )

    def _copy_package(self, tmp_root: Path, cve: str) -> Path:
        real = load_config(REPO_ROOT).paths()
        target = tmp_root / "vulnerabilities" / cve
        shutil.copytree(real.packages / cve, target)
        return target

    def test_absolute_confirmation_writes_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg_dir = self._copy_package(root, "CVE-2026-116078")
            paths = self._paths(root)
            pkg = load_package(pkg_dir, paths.schemas)
            runtime = _runtime(
                pkg.cve,
                root,
                {"vulnerable": "1.14.0", "patched": "1.14.1"},
                {"vulnerable": "interim", "patched": "patched"},
            )

            def fake_probe(target, **kwargs):
                value = 8_000_000.0 if target.name == "interim" else 500_000.0
                return ProbeResult(
                    metrics={
                        "attack_memory_delta": value,
                        "amplification_factor": 8.0 if value > 1_000_000 else 0.7,
                    },
                    observations={"telemetry": {"attack": [], "control": []}},
                    raw={"target": target.name},
                )

            with mock.patch(
                "vulnforge.validate.harness._image_digests",
                return_value={"vulnerable": {"id": "sha256:v"}, "patched": {"id": "sha256:p"}},
            ):
                result = run_validation(
                    pkg,
                    load_config(REPO_ROOT),
                    paths,
                    probe=fake_probe,
                    runtime=runtime,
                    runs=3,
                    capture_logs=False,
                )

            validation = result["validation"]
            self.assertEqual(validation["verdict"], "CONFIRMED")
            self.assertEqual(
                validate_instance(validation, paths.schemas, "validation"), []
            )
            self.assertTrue(result["validation_path"].is_file())
            self.assertTrue(result["execution_path"].is_file())
            self.assertEqual(
                len(list((pkg_dir / "evidence" / "runs").glob("*.json"))), 6
            )
            self.assertEqual(
                len(list((pkg_dir / "evidence" / "telemetry").glob("*.json"))), 6
            )
            manifest = json.loads((pkg_dir / "package.json").read_text())
            self.assertEqual(manifest["status"], "validated")
            self.assertEqual(manifest["validation"]["last_verdict"], "CONFIRMED")

            execution = json.loads(result["execution_path"].read_text())
            self.assertEqual(
                validate_instance(execution, paths.schemas, "evidence"), []
            )
            self.assertTrue(execution["artifacts"])
            for artifact in execution["artifacts"]:
                path = pkg_dir / artifact["path"]
                self.assertTrue(path.is_file(), artifact["path"])
                import hashlib

                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(digest, artifact["sha256"])

    def test_relative_below_threshold_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg_dir = self._copy_package(root, "CVE-2026-111101")
            paths = self._paths(root)
            pkg = load_package(pkg_dir, paths.schemas)
            runtime = _runtime(
                pkg.cve,
                root,
                {"vulnerable": "1.13.1", "patched": "1.14.0"},
                {"vulnerable": "vulnerable", "patched": "interim"},
            )

            def fake_probe(target, **kwargs):
                value = 4_000_000.0 if target.name == "vulnerable" else 2_100_000.0
                return ProbeResult(
                    metrics={
                        "attack_memory_delta": value,
                        "control_memory_delta": 1000.0,
                    },
                    observations={"telemetry": {"attack": [], "control": []}},
                    raw={"target": target.name},
                )

            with mock.patch(
                "vulnforge.validate.harness._image_digests",
                return_value={"vulnerable": {"id": "sha256:v"}, "patched": {"id": "sha256:p"}},
            ):
                result = run_validation(
                    pkg,
                    load_config(REPO_ROOT),
                    paths,
                    probe=fake_probe,
                    runtime=runtime,
                    runs=3,
                    capture_logs=False,
                )

            validation = result["validation"]
            self.assertEqual(validation["verdict"], "INCONCLUSIVE")
            self.assertEqual(
                validate_instance(validation, paths.schemas, "validation"), []
            )
            self.assertIn("below the pre-registered", validation["reason"])
            manifest = json.loads((pkg_dir / "package.json").read_text())
            self.assertEqual(manifest["status"], "inconclusive")
            self.assertEqual(manifest["validation"]["last_verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
