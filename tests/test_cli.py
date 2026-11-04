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
        self.assertIn("CONFIRMED", out)

    def test_status_json(self):
        code, out, _ = run_cli("status", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual([item["cve"] for item in payload], [CVE])
        self.assertTrue(payload[0]["valid"])

    def test_package_list(self):
        code, out, _ = run_cli("package", "list")
        self.assertEqual(code, 0)
        self.assertIn(CVE, out)

    def test_package_show(self):
        code, out, _ = run_cli("package", "show", CVE)
        self.assertEqual(code, 0)
        self.assertIn("1.14.0", out)
        self.assertIn("1.14.1", out)
        self.assertIn("CONFIRMED", out)

    def test_package_show_unknown(self):
        code, _, err = run_cli("package", "show", "CVE-2026-000000")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_package_validate(self):
        code, out, _ = run_cli("package", "validate", CVE)
        self.assertEqual(code, 0)
        self.assertIn(f"OK   {CVE}", out)

    def test_package_validate_all_json(self):
        code, out, _ = run_cli("package", "validate", "--all", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload[0]["cve"], CVE)
        self.assertTrue(payload[0]["ok"])
        self.assertEqual(payload[0]["errors"], [])

    def test_planned_commands_are_explicit(self):
        code, _, err = run_cli("validate", CVE)
        self.assertEqual(code, 2)
        self.assertIn("not implemented", err)
        self.assertIn("M3", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
