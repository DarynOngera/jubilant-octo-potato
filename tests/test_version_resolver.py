#!/usr/bin/env python3
"""Unit tests for triage/version_resolver.py.

Run directly:
    python3 tests/test_version_resolver.py
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "triage"))

from version_resolver import (  # noqa: E402
    KNOWN_VERSIONS,
    exposure_summary,
    parse_ranges,
    ranges_for_advisory,
    resolve_all,
    suggested_checkpoints,
    version_in_range,
)


class RangeParsingTests(unittest.TestCase):
    def test_single_range(self):
        ranges = parse_ranges(">= 0.1.0 and < 1.14.0")
        self.assertEqual(len(ranges), 1)
        self.assertTrue(version_in_range("0.1.0", ">= 0.1.0 and < 1.14.0"))
        self.assertTrue(version_in_range("1.13.9", ">= 0.1.0 and < 1.14.0"))
        self.assertFalse(version_in_range("1.14.0", ">= 0.1.0 and < 1.14.0"))

    def test_nested_multi_range_is_a_union(self):
        affected = ">= 1.6.1 and < 1.11.1 >= 1.6.0 and < 1.11.1"
        self.assertEqual(len(parse_ranges(affected)), 2)
        # 1.6.0 is only covered by the second (broader) range.
        self.assertTrue(version_in_range("1.6.0", affected))
        self.assertTrue(version_in_range("1.6.1", affected))
        self.assertTrue(version_in_range("1.11.0", affected))
        self.assertFalse(version_in_range("1.11.1", affected))

    def test_disjoint_multi_range(self):
        affected = ">= 1.0.0 and < 1.2.0, >= 2.0.0 and < 2.1.0"
        self.assertEqual(len(parse_ranges(affected)), 2)
        self.assertTrue(version_in_range("1.1.0", affected))
        self.assertFalse(version_in_range("1.5.0", affected))
        self.assertTrue(version_in_range("2.0.5", affected))
        self.assertFalse(version_in_range("2.1.0", affected))

    def test_single_upper_bound(self):
        affected = "< 1.11.0"
        self.assertTrue(version_in_range("1.10.4", affected))
        self.assertFalse(version_in_range("1.11.0", affected))

    def test_exact_pin(self):
        affected = "= 1.0.0"
        self.assertTrue(version_in_range("1.0.0", affected))
        self.assertFalse(version_in_range("1.0.1", affected))

    def test_prerelease_boundary(self):
        affected = ">= 1.0.0-pre.7 and < 1.14.0"
        self.assertFalse(version_in_range("1.0.0-pre.6", affected))
        self.assertTrue(version_in_range("1.0.0-pre.7", affected))
        self.assertTrue(version_in_range("1.0.0", affected))
        self.assertFalse(version_in_range("1.14.0", affected))

    def test_html_entities(self):
        affected = "&gt;= 0.3.1 and &lt; 1.14.1"
        self.assertTrue(version_in_range("0.3.2", affected))
        self.assertFalse(version_in_range("1.14.1", affected))

    def test_list_of_ranges(self):
        affected = [">= 1.0.0 and < 1.2.0", ">= 2.0.0 and < 2.1.0"]
        self.assertTrue(version_in_range("1.1.0", affected))
        self.assertTrue(version_in_range("2.0.5", affected))
        self.assertFalse(version_in_range("1.5.0", affected))

    def test_osv_style_affected_ranges(self):
        advisory = {
            "cve": "CVE-TEST-0001",
            "affected_ranges": [
                {"introduced": "1.0.0", "fixed": "1.2.0"},
                {"introduced": "2.0.0", "fixed": "2.1.0"},
            ],
        }
        self.assertTrue(version_in_range("1.1.0", advisory))
        self.assertTrue(version_in_range("2.0.5", advisory))
        self.assertFalse(version_in_range("1.5.0", advisory))
        self.assertFalse(version_in_range("2.1.0", advisory))

    def test_unparseable_range_raises(self):
        with self.assertRaises(ValueError):
            parse_ranges("not-a-version-range")


class CurrentDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads((REPO_ROOT / "data" / "advisories.json").read_text())
        cls.advisories = data["advisories"]
        cls.exposure = resolve_all(cls.advisories)

    def test_every_known_version_has_a_list(self):
        self.assertEqual(set(self.exposure), set(KNOWN_VERSIONS))
        for cves in self.exposure.values():
            self.assertEqual(cves, sorted(set(cves)))

    def test_latest_release_is_clean(self):
        self.assertEqual(self.exposure["1.14.1"], [])

    def test_multi_range_advisories_are_recorded_and_parsed(self):
        # These four advisories list more than one affected range on the Hex
        # page (backported/nested ranges). The checked-in data keeps the
        # broadest as the scalar `affected` for older consumers and the full
        # list in `affected_ranges` for the resolver.
        multi = {
            a["cve"]: a for a in self.advisories if a.get("affected_ranges")
        }
        self.assertEqual(set(multi), {
            "CVE-2026-39804",
            "CVE-2026-39805",
            "CVE-2026-39806",
            "CVE-2026-42788",
        })
        for cve, adv in multi.items():
            self.assertGreater(len(adv["affected_ranges"]), 1, cve)
            self.assertEqual(len(ranges_for_advisory(adv)), len(adv["affected_ranges"]), cve)

        # The union of 39806's ranges starts at 1.6.0 and excludes 1.11.1.
        adv = multi["CVE-2026-39806"]
        self.assertTrue(version_in_range("1.6.0", adv))
        self.assertFalse(version_in_range("1.11.1", adv))
        self.assertIn("CVE-2026-39806", self.exposure["1.10.4"])

    def test_interim_is_only_exposed_to_116078(self):
        self.assertEqual(self.exposure["1.14.0"], ["CVE-2026-116078"])

    def test_vulnerable_lab_version_is_not_uniformly_vulnerable(self):
        # 1.13.1 is exposed to several later advisories but already patched
        # for older ones. This is the coverage gap the report calls out.
        self.assertIn("CVE-2026-111101", self.exposure["1.13.1"])
        self.assertNotIn("CVE-2026-39803", self.exposure["1.13.1"])

    def test_checkpoints_are_deduplicated_and_expose_counts(self):
        checkpoints = suggested_checkpoints(self.advisories, self.exposure)
        versions = [cp["version"] for cp in checkpoints]
        self.assertEqual(len(versions), len(set(versions)))
        for cp in checkpoints:
            self.assertEqual(cp["vulnerable_count"], len(cp["vulnerable_cves"]))
            self.assertEqual(cp["vulnerable_cves"], self.exposure[cp["version"]])

        one_eleven = next(cp for cp in checkpoints if cp["version"] == "1.11.0")
        self.assertIn("first-patched", one_eleven["roles"])
        self.assertIn("last-vulnerable", one_eleven["roles"])
        self.assertEqual(len(one_eleven["fixes_boundaries"]), 2)

    def test_exposure_bands_cover_every_version(self):
        bands = exposure_summary(self.exposure)
        covered = []
        for band in bands:
            cursor = KNOWN_VERSIONS.index(band["start"])
            end = KNOWN_VERSIONS.index(band["end"])
            covered.extend(KNOWN_VERSIONS[cursor:end + 1])
            self.assertEqual(band["count"], len(band["cves"]))
        self.assertEqual(covered, KNOWN_VERSIONS)

    def test_unknown_fix_boundary_fails_loudly(self):
        with self.assertRaises(ValueError):
            suggested_checkpoints([
                {"cve": "CVE-TEST-0002", "fixed_in": "9.9.9", "affected": "< 9.9.9"}
            ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
