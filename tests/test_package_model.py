"""Package model and cross-file validation tests (M1)."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.models import LabSpec, Package, PackageManifest  # noqa: E402
from vulnforge.packages import (  # noqa: E402
    check_package_consistency,
    discover_package_dirs,
    find_package,
    load_package,
    load_packages,
    package_path,
    validate_against_catalog,
    validate_package,
)

CVE = "CVE-2026-116078"
ALL_CVES = ["CVE-2026-111101", "CVE-2026-116078"]


class PackageModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = load_config(REPO_ROOT)
        cls.paths = cls.cfg.paths()

    def test_package_is_discovered(self):
        dirs = discover_package_dirs(self.paths)
        self.assertTrue(set(ALL_CVES).issubset({path.name for path in dirs}))

    def test_package_loads_and_validates(self):
        pkg = find_package(self.paths, CVE)
        self.assertTrue(pkg.is_valid, pkg.errors)
        self.assertEqual(validate_package(pkg, self.paths), [])

    def test_versions_are_last_vulnerable_and_first_fixed(self):
        pkg = find_package(self.paths, CVE)
        self.assertIsNotNone(pkg.manifest)
        assert pkg.manifest is not None
        self.assertEqual(pkg.manifest.vulnerable_version, "1.14.0")
        self.assertEqual(pkg.manifest.patched_version, "1.14.1")
        self.assertEqual(pkg.manifest.first_fixed, "1.14.1")
        self.assertNotEqual(
            pkg.manifest.vulnerable_version, pkg.manifest.patched_version
        )

    def test_lab_and_probe_roles_agree(self):
        pkg = find_package(self.paths, CVE)
        assert pkg.lab is not None and pkg.probe is not None
        for role in ("vulnerable", "patched"):
            target = pkg.lab.target_by_role(role)
            self.assertIsNotNone(target, role)
            self.assertEqual(pkg.probe.targets[role], target.name)

    def test_probe_entrypoint_exists(self):
        pkg = find_package(self.paths, CVE)
        assert pkg.probe is not None
        self.assertTrue(pkg.probe.module_path(pkg.root).is_file())

    def test_advisory_is_in_sync_with_catalog(self):
        pkg = find_package(self.paths, CVE)
        self.assertEqual(validate_against_catalog(pkg, self.paths), [])

    def test_evidence_artifact_hashes_match(self):
        pkg = find_package(self.paths, CVE)
        evidence = json.loads((pkg.root / "evidence" / "execution.json").read_text())
        self.assertTrue(evidence["artifacts"])
        for artifact in evidence["artifacts"]:
            path = pkg.root / artifact["path"]
            self.assertTrue(path.is_file(), artifact["path"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, artifact["sha256"], artifact["path"])

    def test_catalog_drift_is_detected(self):
        pkg = find_package(self.paths, CVE)
        assert pkg.advisory is not None
        drifted = Package(
            root=pkg.root,
            manifest=pkg.manifest,
            advisory=dataclasses.replace(pkg.advisory, title="drifted title"),
            lab=pkg.lab,
            probe=pkg.probe,
            errors=[],
        )
        errors = validate_against_catalog(drifted, self.paths)
        self.assertTrue(any("title" in error for error in errors), errors)

    def test_patched_must_equal_first_fixed(self):
        pkg = find_package(self.paths, CVE)
        assert pkg.manifest is not None
        versions = dict(pkg.manifest.versions)
        versions["patched"] = "1.14.2"
        modified = Package(
            root=pkg.root,
            manifest=dataclasses.replace(pkg.manifest, versions=versions),
            advisory=pkg.advisory,
            lab=pkg.lab,
            probe=pkg.probe,
            errors=[],
        )
        check_package_consistency(modified)
        self.assertTrue(
            any("patched == first_fixed" in error for error in modified.errors),
            modified.errors,
        )

    def test_vulnerable_version_must_be_affected(self):
        pkg = find_package(self.paths, CVE)
        assert pkg.advisory is not None
        advisory = dataclasses.replace(
            pkg.advisory,
            affected=">= 1.14.1 and < 1.15.0",
            affected_ranges=[],
        )
        modified = Package(
            root=pkg.root,
            manifest=pkg.manifest,
            advisory=advisory,
            lab=pkg.lab,
            probe=pkg.probe,
            errors=[],
        )
        check_package_consistency(modified)
        self.assertTrue(
            any("is not in the advisory affected range" in error for error in modified.errors),
            modified.errors,
        )

    def test_package_path_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(Exception, "escapes package root"):
                package_path(root, "../outside.json")

    def test_validated_status_requires_confirmed_verdict(self):
        pkg = find_package(self.paths, CVE)
        assert pkg.manifest is not None
        validation = dict(pkg.manifest.validation)
        validation["last_verdict"] = "INCONCLUSIVE"
        modified = Package(
            root=pkg.root,
            manifest=dataclasses.replace(
                pkg.manifest, status="validated", validation=validation
            ),
            advisory=pkg.advisory,
            lab=pkg.lab,
            probe=pkg.probe,
            errors=[],
        )
        check_package_consistency(modified)
        self.assertTrue(
            any("requires last_verdict 'CONFIRMED'" in error for error in modified.errors),
            modified.errors,
        )

    def test_adapter_alias_is_accepted_as_target(self):
        manifest = PackageManifest.from_dict(
            {
                "schema_version": "1.0",
                "cve": CVE,
                "adapter": "bandit",
                "status": "draft",
                "versions": {
                    "vulnerable": "1.14.0",
                    "patched": "1.14.1",
                    "first_fixed": "1.14.1",
                    "affected": [">= 0.3.1 and < 1.14.1"],
                },
                "paths": {},
            }
        )
        self.assertEqual(manifest.target, "bandit")
        self.assertEqual(manifest.adapter_name, "bandit")

        lab = LabSpec.from_dict(
            {
                "schema_version": "1.0",
                "cve": CVE,
                "adapter": "bandit",
                "app": "lab/app",
                "versions": {"vulnerable": "1.14.0", "patched": "1.14.1"},
                "targets": [
                    {
                        "role": "vulnerable",
                        "name": "interim",
                        "version": "1.14.0",
                        "base_url": "http://127.0.0.1:4000",
                        "admin_url": "http://127.0.0.1:4001",
                    },
                    {
                        "role": "patched",
                        "name": "patched",
                        "version": "1.14.1",
                        "base_url": "http://127.0.0.1:4010",
                        "admin_url": "http://127.0.0.1:4011",
                    },
                ],
                "limits": {
                    "mem_limit_mb": 512,
                    "cpus": 1.0,
                    "pids_limit": 512,
                    "max_duration_seconds": 120,
                    "max_request_bytes_total": 268435456,
                },
            }
        )
        self.assertEqual(lab.target, "bandit")
        self.assertEqual(lab.adapter_name, "bandit")

    def test_missing_manifest_reports_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = load_package(Path(tmp), self.paths.schemas)
        self.assertIsNone(pkg.manifest)
        self.assertTrue(any("package.json not found" in e for e in pkg.errors), pkg.errors)

    def test_all_packages_load(self):
        packages = load_packages(self.paths)
        self.assertTrue(set(ALL_CVES).issubset({pkg.cve for pkg in packages}))

    def test_111101_uses_first_fixed_pair(self):
        pkg = find_package(self.paths, "CVE-2026-111101")
        self.assertTrue(pkg.is_valid, pkg.errors)
        assert pkg.manifest is not None and pkg.probe is not None
        self.assertEqual(pkg.manifest.vulnerable_version, "1.13.1")
        self.assertEqual(pkg.manifest.patched_version, "1.14.0")
        self.assertEqual(pkg.manifest.first_fixed, "1.14.0")
        self.assertIn(pkg.manifest.status, {"poc-implemented", "inconclusive"})
        self.assertEqual(pkg.probe.thresholds.get("mode"), "relative")


if __name__ == "__main__":
    unittest.main(verbosity=2)
