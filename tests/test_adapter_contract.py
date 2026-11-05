"""Adapter-boundary tests (non-Docker + gated toy lab)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import FactoryConfig, TargetConfig, load_config  # noqa: E402
from vulnforge.lab import LabOrchestrator  # noqa: E402
from vulnforge.models import (  # noqa: E402
    LabSpec,
    LabTarget,
    Package,
    PackageManifest,
)
from vulnforge.paths import Paths  # noqa: E402
from vulnforge.targets.loader import load_adapter  # noqa: E402
from vulnforge.targets.toy import ToyAdapter  # noqa: E402


class AdapterBoundaryTests(unittest.TestCase):
    def test_toy_adapter_loads_from_config(self):
        cfg = FactoryConfig(
            root=REPO_ROOT,
            targets={
                "toy": TargetConfig(
                    name="toy",
                    adapter="vulnforge.targets.toy:ToyAdapter",
                    app_dir="targets/toy",
                )
            },
        )
        adapter = load_adapter(cfg, "toy")
        self.assertIsInstance(adapter, ToyAdapter)
        self.assertEqual(adapter.repo_root, REPO_ROOT.resolve())
        self.assertIsNone(adapter.lockfile("0.1.0"))
        self.assertEqual(adapter.version_from_stats({"toy_version": "0.1.0"}), "0.1.0")
        measurement = adapter.measurement()
        self.assertIsNone(measurement.gc_path)
        self.assertTrue(measurement.use_app_listener)
        sample = measurement.reader({"memory_bytes": 123, "process_count": 1})
        assert sample is not None
        self.assertEqual(sample.total, 123)
        self.assertEqual(adapter.intelligence().name, "toy")
        self.assertIsNone(adapter.intelligence().osv_package)

    def test_core_has_no_bandit_imports(self):
        core = [
            REPO_ROOT / "src" / "vulnforge" / "lab",
            REPO_ROOT / "src" / "vulnforge" / "probe",
            REPO_ROOT / "src" / "vulnforge" / "validate",
            REPO_ROOT / "src" / "vulnforge" / "targets" / "base.py",
        ]
        offenders = []
        for path in core:
            files = [path] if path.is_file() else path.rglob("*.py")
            for file in files:
                text = file.read_text(errors="replace").lower()
                if "bandit" in text:
                    offenders.append(str(file.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [])


@unittest.skipUnless(
    os.environ.get("VULNFORGE_DOCKER") == "1",
    "set VULNFORGE_DOCKER=1 to run the toy adapter Docker test",
)
class ToyAdapterDockerTests(unittest.TestCase):
    def test_build_start_status_stop(self):
        real = load_config(REPO_ROOT).paths()
        cfg = FactoryConfig(
            root=REPO_ROOT,
            targets={
                "toy": TargetConfig(
                    name="toy",
                    adapter="vulnforge.targets.toy:ToyAdapter",
                    app_dir="targets/toy",
                )
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = Paths(
                root=root,
                packages=real.packages,
                data=real.data,
                evidence=real.evidence,
                reports=real.reports,
                config=real.config,
                schemas=real.schemas,
            )
            manifest = PackageManifest(
                cve="CVE-2026-990001",
                target="toy",
                status="draft",
                versions={
                    "vulnerable": "0.1.0",
                    "patched": "0.1.1",
                    "first_fixed": "0.1.1",
                    "affected": [{"introduced": "0.1.0", "fixed": "0.1.1"}],
                },
                paths={},
            )
            lab = LabSpec(
                cve=manifest.cve,
                target="toy",
                app="targets/toy",
                versions={"vulnerable": "0.1.0", "patched": "0.1.1"},
                targets=[
                    LabTarget(
                        role="vulnerable",
                        name="toy-vulnerable",
                        version="0.1.0",
                        base_url="http://127.0.0.1:1",
                        admin_url="http://127.0.0.1:2",
                    ),
                    LabTarget(
                        role="patched",
                        name="toy-patched",
                        version="0.1.1",
                        base_url="http://127.0.0.1:3",
                        admin_url="http://127.0.0.1:4",
                    ),
                ],
                limits={
                    "mem_limit_mb": 256,
                    "cpus": 0.5,
                    "pids_limit": 128,
                    "max_duration_seconds": 60,
                    "max_request_bytes_total": 1_000_000,
                },
            )
            pkg = Package(root=root, manifest=manifest, lab=lab)
            adapter = load_adapter(cfg, "toy")
            orchestrator = LabOrchestrator(cfg, paths, adapter)
            try:
                runtime, provenance_path = orchestrator.start(pkg)
                self.assertEqual(
                    set(runtime.services), {"vulnerable", "patched"}
                )
                self.assertTrue(provenance_path.is_file())
                status = orchestrator.status(pkg)
                self.assertTrue(status["running"])
                self.assertEqual(
                    status["services"]["vulnerable"]["reported_version"], "0.1.0"
                )
                self.assertEqual(
                    status["services"]["patched"]["reported_version"], "0.1.1"
                )
            finally:
                orchestrator.stop(pkg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
