"""CLI tests for the M1 VulnForge surface."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.cli import main  # noqa: E402

CVE = "CVE-2026-116078"


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(["--root", str(REPO_ROOT), *args])
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_status_lists_package(self):
        code, out, _ = run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn(CVE, out)
        self.assertIn("1.14.0 -> 1.14.1", out)

    def test_status_json(self):
        code, out, _ = run_cli("status", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual([item["cve"] for item in payload], ["CVE-2026-111101", "CVE-2026-116078"])
        self.assertTrue(all(item["valid"] for item in payload))

    def test_package_list(self):
        code, out, _ = run_cli("package", "list")
        self.assertEqual(code, 0)
        self.assertIn(CVE, out)

    def test_package_show(self):
        code, out, _ = run_cli("package", "show", CVE)
        self.assertEqual(code, 0)
        self.assertIn("1.14.0", out)
        self.assertIn("1.14.1", out)
        self.assertIn("verdict:", out)

    def test_package_show_unknown(self):
        code, _, err = run_cli("package", "show", "CVE-2026-000000")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_package_validate(self):
        code, out, _ = run_cli("package", "validate", CVE)
        self.assertEqual(code, 0)
        self.assertIn(f"OK   {CVE}", out)

    def test_package_validate_111101(self):
        code, out, _ = run_cli("package", "validate", "CVE-2026-111101")
        self.assertEqual(code, 0)
        self.assertIn("OK   CVE-2026-111101", out)

    def test_package_validate_all_json(self):
        code, out, _ = run_cli("package", "validate", "--all", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(
            [item["cve"] for item in payload],
            ["CVE-2026-111101", "CVE-2026-116078"],
        )
        self.assertTrue(all(item["ok"] for item in payload))
        self.assertTrue(all(item["errors"] == [] for item in payload))

    # `detect` is covered read-only in tests/test_detection.py via
    # evaluate_package(); running the CLI here rewrites tracked evidence files.

    def test_triage_check(self):
        code, out, _ = run_cli("triage", "--check")
        self.assertEqual(code, 0)
        self.assertIn("OK:", out)

    def test_validate_without_runtime_is_helpful(self):
        code, _, err = run_cli("validate", "CVE-2026-111101")
        self.assertEqual(code, 2)
        self.assertIn("lab start CVE-2026-111101", err)

    def test_poc_without_runtime_is_helpful(self):
        code, _, err = run_cli("poc", "run", "CVE-2026-111101")
        self.assertEqual(code, 2)
        self.assertIn("lab start CVE-2026-111101", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
