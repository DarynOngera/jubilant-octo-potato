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
PACKAGE = REPO_ROOT / "vulnerabilities" / "CVE-2026-116078"


class SchemaTests(unittest.TestCase):
    def test_every_schema_file_is_valid(self):
        for name in SCHEMA_FILES:
            with self.subTest(schema=name):
                load_schema(SCHEMAS, name)

    def test_package_files_match_their_schemas(self):
        checks = [
            ("advisory", PACKAGE / "advisory.json"),
            ("package", PACKAGE / "package.json"),
            ("lab", PACKAGE / "lab" / "lab.json"),
            ("probe", PACKAGE / "poc" / "manifest.json"),
            ("exploitability", PACKAGE / "analysis" / "exploitability.json"),
            ("detection-spec", PACKAGE / "detection" / "spec.json"),
            ("evidence", PACKAGE / "evidence" / "execution.json"),
        ]
        for schema_name, path in checks:
            with self.subTest(path=path.name):
                data = json.loads(path.read_text())
                self.assertEqual(
                    validate_instance(
                        data, SCHEMAS, schema_name, label=path.name
                    ),
                    [],
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
