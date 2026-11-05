"""Commit-analysis tests without network access."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.ingest.github import analyze_package, changed_files  # noqa: E402
from vulnforge.packages import load_package  # noqa: E402

PATCH = """diff --git a/lib/bandit/http2/stream.ex b/lib/bandit/http2/stream.ex
--- a/lib/bandit/http2/stream.ex
+++ b/lib/bandit/http2/stream.ex
@@ -1,1 +1,1 @@
-old
+new
diff --git a/test/bandit/http2/protocol_test.exs b/test/bandit/http2/protocol_test.exs
--- a/test/bandit/http2/protocol_test.exs
+++ b/test/bandit/http2/protocol_test.exs
"""


class AnalysisTests(unittest.TestCase):
    def test_changed_files(self):
        self.assertEqual(
            changed_files(PATCH),
            [
                "lib/bandit/http2/stream.ex",
                "test/bandit/http2/protocol_test.exs",
            ],
        )

    def test_analyze_generates_scaffold_without_touching_human_analysis(self):
        real = load_config(REPO_ROOT).paths()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "CVE-2026-116078"
            shutil.copytree(real.packages / "CVE-2026-116078", target)
            pkg = load_package(target, real.schemas)
            patch_file = Path(tmp) / "fake.patch"
            patch_file.write_text(PATCH)

            with mock.patch(
                "vulnforge.ingest.github.fetch_patch", return_value=patch_file
            ):
                result = analyze_package(pkg, refresh=True)

            self.assertTrue((target / "analysis" / "root-cause.generated.md").is_file())
            self.assertTrue((target / "analysis" / "root-cause.md").is_file())
            self.assertIn("lib/bandit/http2/stream.ex", result["changed_files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
