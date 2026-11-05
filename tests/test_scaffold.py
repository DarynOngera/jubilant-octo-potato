"""Package scaffold tests (no Docker)."""
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
from vulnforge.packages import load_package, validate_package  # noqa: E402
from vulnforge.paths import Paths  # noqa: E402
from vulnforge.scaffold import scaffold_package  # noqa: E402

CVE = "CVE-2026-39803"


class ScaffoldTests(unittest.TestCase):
    def _paths(self, root: Path, real: Paths) -> Paths:
        data = root / "data"
        config = root / "config"
        triage = root / "triage"
        data.mkdir(parents=True)
        config.mkdir(parents=True)
        triage.mkdir(parents=True)
        shutil.copy(real.data / "advisories.json", data / "advisories.json")
        shutil.copy(
            real.data / "vulnerability-matrix.json",
            data / "vulnerability-matrix.json",
        )
        shutil.copy(
            real.config / "lab-limits.yaml", config / "lab-limits.yaml"
        )
        shutil.copy(
            real.root / "triage" / "version_resolver.py",
            triage / "version_resolver.py",
        )
        return Paths(
            root=root,
            packages=root / "vulnerabilities",
            data=data,
            evidence=root / "evidence",
            reports=root / "reports",
            config=config,
            schemas=real.schemas,
        )

    def test_scaffold_creates_valid_draft_package(self):
        real = load_config(REPO_ROOT).paths()
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp), real)
            created = scaffold_package(load_config(REPO_ROOT), paths, CVE)

            self.assertTrue((paths.packages / CVE / "package.json").is_file())
            self.assertTrue(
                (paths.packages / CVE / "poc" / "exploit.py").is_file()
            )
            self.assertGreater(len(created), 10)

            pkg = load_package(paths.packages / CVE, paths.schemas)
            self.assertEqual(validate_package(pkg, paths), [], pkg.errors)
            manifest = json.loads(
                (paths.packages / CVE / "package.json").read_text()
            )
            self.assertEqual(manifest["status"], "draft")
            self.assertEqual(manifest["versions"]["vulnerable"], "1.11.0")
            self.assertEqual(manifest["versions"]["patched"], "1.11.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
