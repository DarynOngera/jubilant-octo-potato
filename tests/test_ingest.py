"""OSV ingestion/merge tests using a cached fixture."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "osv_bandit.json"
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.ingest import ingest_bandit  # noqa: E402
from vulnforge.ingest.osv import load_snapshot, normalize_osv  # noqa: E402
from vulnforge.ingest.proposal import load_catalog, merge_advisories  # noqa: E402
from vulnforge.paths import Paths  # noqa: E402


class IngestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = load_config(REPO_ROOT).paths()
        cls.records = load_snapshot(FIXTURE)
        cls.normalized = normalize_osv(cls.records)

    def test_normalize_skips_records_without_cve(self):
        self.assertEqual(len(self.records), 3)
        self.assertEqual(len(self.normalized), 2)
        self.assertEqual(
            [item["cve"] for item in self.normalized],
            ["CVE-2026-116078", "CVE-2026-900001"],
        )

    def test_normalize_range_and_commits(self):
        item = next(
            item for item in self.normalized if item["cve"] == "CVE-2026-116078"
        )
        self.assertEqual(item["fixed_in"], "1.14.1")
        self.assertIn(">= 0.3.1 and < 1.14.1", item["affected_ranges"])
        self.assertIn("327bb02ff84171237e1aeff787930debd16155ee", item["commits"])

    def test_merge_preserves_existing_metadata(self):
        catalog = load_catalog(self.real.data / "advisories.json")
        merged, changes = merge_advisories(catalog, self.normalized)
        self.assertIn("CVE-2026-900001", changes["added"])
        self.assertTrue(any(item["cve"] == "CVE-2026-116078" for item in changes["changed"]))
        by_cve = {row["cve"]: row for row in merged}
        self.assertEqual(by_cve["CVE-2026-116078"]["track"], "http2_resource_exhaustion")
        self.assertEqual(by_cve["CVE-2026-116078"]["cvss_score"], 8.7)
        self.assertEqual(by_cve["CVE-2026-900001"]["track"], "unclassified")

    def _temp_paths(self, root: Path) -> Paths:
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.real.data / "advisories.json", data / "advisories.json")
        return Paths(
            root=root,
            packages=self.real.packages,
            data=data,
            evidence=self.real.evidence,
            reports=self.real.reports,
            config=self.real.config,
            schemas=self.real.schemas,
        )

    def test_offline_refresh_is_deterministic_and_apply_sticks(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._temp_paths(Path(tmp))
            first = ingest_bandit(paths, offline=True, raw_path=FIXTURE)
            first_diff = Path(first["diff"]).read_text()
            second = ingest_bandit(paths, offline=True, raw_path=FIXTURE)
            self.assertEqual(first_diff, Path(second["diff"]).read_text())

            applied = ingest_bandit(paths, offline=True, raw_path=FIXTURE, apply=True)
            self.assertTrue(applied["applied"])
            after = ingest_bandit(paths, offline=True, raw_path=FIXTURE)
            self.assertEqual(after["changes"]["added"], [])
            self.assertEqual(after["changes"]["changed"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
