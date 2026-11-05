"""JSON Schema sanity tests for the VulnForge contracts."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.schema import SCHEMA_FILES, load_schema, validate_instance  # noqa: E402

SCHEMAS = REPO_ROOT / "schemas"
PACKAGES = [
    REPO_ROOT / "vulnerabilities" / "CVE-2026-116078",
    REPO_ROOT / "vulnerabilities" / "CVE-2026-111101",
]


class SchemaTests(unittest.TestCase):
    def test_every_schema_file_is_valid(self):
        for name in SCHEMA_FILES:
            with self.subTest(schema=name):
                load_schema(SCHEMAS, name)

    def test_package_files_match_their_schemas(self):
        for package in PACKAGES:
            checks = [
                ("advisory", package / "advisory.json"),
                ("package", package / "package.json"),
                ("lab", package / "lab" / "lab.json"),
                ("probe", package / "poc" / "manifest.json"),
                ("exploitability", package / "analysis" / "exploitability.json"),
                ("detection-spec", package / "detection" / "spec.json"),
                ("detection", package / "detection" / "evidence.json"),
                ("evidence", package / "evidence" / "execution.json"),
                ("provenance", package / "lab" / "provenance.json"),
            ]
            for schema_name, path in checks:
                with self.subTest(package=package.name, path=path.name):
                    data = json.loads(path.read_text())
                    self.assertEqual(
                        validate_instance(
                            data, SCHEMAS, schema_name, label=path.name
                        ),
                        [],
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
