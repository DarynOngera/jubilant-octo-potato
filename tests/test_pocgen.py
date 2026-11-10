"""CVE-driven PoC build tests."""
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
from vulnforge.models import Advisory, LabSpec, Package, PackageManifest  # noqa: E402
from vulnforge.pocgen import build_poc  # noqa: E402


class PocBuildTests(unittest.TestCase):
    def test_builds_http2_probe_from_matching_cve(self):
        with tempfile.TemporaryDirectory() as tmp:
            packages = Path(tmp)
            reference = packages / "CVE-2026-116078"
            shutil.copytree(
                REPO_ROOT / "vulnerabilities" / "CVE-2026-116078", reference
            )
            target = packages / "CVE-2099-0001"
            shutil.copytree(reference, target)

            for relative in ("package.json", "advisory.json", "lab/lab.json", "poc/manifest.json"):
                path = target / relative
                path.write_text(path.read_text().replace("CVE-2026-116078", "CVE-2099-0001"))
            (target / "poc" / "exploit.py").write_text(
                'def run(target, **kwargs):\n'
                '    raise NotImplementedError("implement the package probe for this CVE")\n'
            )

            cfg = load_config(REPO_ROOT)
            from vulnforge.packages import load_package

            package = load_package(target, cfg.paths().schemas)
            self.assertTrue(package.manifest is not None)
            result = build_poc(package)

            self.assertEqual(result["profile"], "bandit-http2-one-byte-data")
            generated = (target / "poc" / "exploit.py").read_text()
            self.assertIn('CVE = "CVE-2099-0001"', generated)
            proposal = json.loads((target / "poc" / "proposal.json").read_text())
            self.assertEqual(proposal["source"]["reference_cve"], "CVE-2026-116078")
            manifest = json.loads((target / "package.json").read_text())
            self.assertEqual(manifest["status"], "poc-implemented")

    def test_refuses_hand_authored_probe(self):
        package = Package(
            root=REPO_ROOT / "vulnerabilities" / "CVE-2026-116078",
            manifest=PackageManifest.from_dict(
                json.loads((REPO_ROOT / "vulnerabilities" / "CVE-2026-116078" / "package.json").read_text())
            ),
            advisory=Advisory.from_dict(
                json.loads((REPO_ROOT / "vulnerabilities" / "CVE-2026-116078" / "advisory.json").read_text())
            ),
            lab=LabSpec.from_dict(
                json.loads((REPO_ROOT / "vulnerabilities" / "CVE-2026-116078" / "lab" / "lab.json").read_text())
            ),
        )
        with self.assertRaisesRegex(Exception, "refusing to replace"):
            build_poc(package)


if __name__ == "__main__":
    unittest.main(verbosity=2)
