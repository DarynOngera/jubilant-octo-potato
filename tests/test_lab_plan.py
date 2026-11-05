"""Lab planning/rendering tests that do not require Docker."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import FactoryConfig, TargetConfig, load_config  # noqa: E402
from vulnforge.lab import LabOrchestrator, allocate_ports  # noqa: E402
from vulnforge.lab import provenance as provenance_mod  # noqa: E402
from vulnforge.packages import find_package  # noqa: E402
from vulnforge.paths import Paths  # noqa: E402
from vulnforge.schema import validate_instance  # noqa: E402
from vulnforge.targets.bandit import BanditAdapter  # noqa: E402
from vulnforge.targets.loader import load_adapter  # noqa: E402

CVE = "CVE-2026-116078"


class LabPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real_paths = load_config(REPO_ROOT).paths()
        cls.package = find_package(cls.real_paths, CVE)
        cls.cfg = FactoryConfig(
            root=REPO_ROOT,
            targets={
                "bandit": TargetConfig(
                    name="bandit",
                    adapter="vulnforge.targets.bandit:BanditAdapter",
                    app_dir="lab/app",
                    limits="config/lab-limits.yaml",
                )
            },
        )
        cls.adapter = BanditAdapter(REPO_ROOT)
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.paths = Paths(
            root=root,
            packages=cls.real_paths.packages,
            data=cls.real_paths.data,
            evidence=cls.real_paths.evidence,
            reports=cls.real_paths.reports,
            config=cls.real_paths.config,
            schemas=cls.real_paths.schemas,
        )
        cls.orch = LabOrchestrator(cls.cfg, cls.paths, cls.adapter)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_adapter_loads_from_config(self):
        adapter = load_adapter(self.cfg, "bandit")
        self.assertIsInstance(adapter, BanditAdapter)

    def test_port_allocation_is_distinct(self):
        ports = allocate_ports(8)
        self.assertEqual(len(ports), 8)
        self.assertEqual(len(set(ports)), 8)

    def test_plan_uses_dynamic_loopback_ports(self):
        plan = self.orch.plan(self.package)
        self.assertEqual(set(plan.services), {"vulnerable", "patched"})
        self.assertEqual(plan.services["vulnerable"].version, "1.14.0")
        self.assertEqual(plan.services["patched"].version, "1.14.1")
        for service in plan.services.values():
            self.assertIn("127.0.0.1", service.base_url)
            self.assertIn("127.0.0.1", service.admin_url)
            self.assertNotEqual(service.app_port, service.admin_port)
            self.assertIn("cve-2026-116078", service.image_tag)
        self.assertEqual(
            len({s.app_port for s in plan.services.values()}),
            len(plan.services),
        )
        self.assertTrue(str(plan.compose_path).startswith(str(self.paths.root)))

    def test_compose_rendering_has_isolation_and_budget_controls(self):
        plan = self.orch.plan(self.package)
        compose_path = self.orch.render_compose(self.package, plan)
        document = yaml.safe_load(compose_path.read_text())
        self.assertEqual(document["name"], "vulnforge-cve-2026-116078")
        self.assertFalse(document["networks"]["labnet"]["internal"])
        for role in ("vulnerable", "patched"):
            service = document["services"][role]
            self.assertEqual(service["environment"]["ERL_AFLAGS"], "+Q 262144")
            self.assertEqual(service["mem_limit"], "512m")
            self.assertTrue(service["read_only"])
            self.assertIn("ALL", service["cap_drop"])
            self.assertEqual(service["restart"], "no")
            self.assertTrue(
                any(port.startswith("127.0.0.1:") for port in service["ports"])
            )
            self.assertEqual(service["build"]["context"], str(self.adapter.app_dir))

    def test_provenance_records_hashes_and_image_metadata(self):
        plan = self.orch.plan(self.package)
        fake_image = {
            "Id": "sha256:deadbeef",
            "RepoDigests": ["vulnforge/bandit@sha256:deadbeef"],
            "Created": "2026-11-04T00:00:00Z",
            "Architecture": "amd64",
            "Os": "linux",
            "Size": 1234,
            "Config": {"Labels": {"com.vulnforge.cve": CVE}},
        }
        with mock.patch(
            "vulnforge.lab.docker.image_inspect", return_value=fake_image
        ):
            data = provenance_mod.build_provenance(
                self.cfg, self.adapter, self.package, plan
            )
        self.assertEqual(data["cve"], CVE)
        self.assertIn("1.14.0", data["build"]["lockfiles"])
        self.assertIn("1.14.1", data["build"]["lockfiles"])
        self.assertEqual(data["build"]["dockerfile"]["path"], "lab/app/Dockerfile")
        self.assertEqual(data["images"]["vulnerable"]["id"], "sha256:deadbeef")
        self.assertEqual(
            validate_instance(data, self.real_paths.schemas, "provenance"),
            [],
        )

    def test_bandit_intelligence_coordinates(self):
        intelligence = self.adapter.intelligence()
        self.assertEqual(intelligence.osv_package, {"name": "bandit", "ecosystem": "Hex"})
        self.assertEqual(intelligence.github_repo, "mtrudel/bandit")

    def test_image_tags_include_cve_role_and_version(self):
        self.assertEqual(
            self.adapter.image_tag(CVE, "vulnerable", "1.14.0"),
            "vulnforge/bandit:cve-2026-116078-vulnerable-1.14.0",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
