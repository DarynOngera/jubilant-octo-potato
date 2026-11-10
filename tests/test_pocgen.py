"""CVE-driven PoC build tests.

The build path is exercised from a genuinely fresh scaffold in an isolated
workspace, matching the acceptance criteria in
docs/cve-driven-poc-engine.md.
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.cli import main  # noqa: E402
from vulnforge.config import load_config  # noqa: E402
from vulnforge.errors import PackageError  # noqa: E402
from vulnforge.packages import load_package, validate_package  # noqa: E402
from vulnforge.paths import Paths  # noqa: E402
from vulnforge.pocgen import build_poc  # noqa: E402
from vulnforge.pocgen.builder import GENERATED_MARKER  # noqa: E402
from vulnforge.scaffold import scaffold_package  # noqa: E402

REFERENCE_CVE = "CVE-2026-116078"
SYNTHETIC_CVE = "CVE-2099-0001"


def _workspace(root: Path, *, cve: str = SYNTHETIC_CVE, track: str | None = None) -> Paths:
    """Create an isolated workspace whose catalog holds one synthetic CVE.

    The workspace layout mirrors the repository so both the API and the CLI
    (``--root``) work against it.
    """
    real = load_config(REPO_ROOT).paths()
    root.mkdir(parents=True, exist_ok=True)

    data = root / "data"
    data.mkdir()
    shutil.copy(real.data / "vulnerability-matrix.json", data / "vulnerability-matrix.json")
    catalog = json.loads((real.data / "advisories.json").read_text())
    row = dict(
        next(r for r in catalog["advisories"] if r["cve"] == REFERENCE_CVE)
    )
    row["cve"] = cve
    if track is not None:
        row["track"] = track
    catalog["advisories"] = [row]
    (data / "advisories.json").write_text(json.dumps(catalog, indent=2) + "\n")

    for name in ("config", "schemas", "triage"):
        shutil.copytree(real.root / name, root / name)
    shutil.copy(real.root / "pyproject.toml", root / "pyproject.toml")

    (root / "vulnerabilities").mkdir()
    return Paths.from_root(root)


def _scaffold(paths: Paths, cve: str = SYNTHETIC_CVE) -> None:
    scaffold_package(load_config(REPO_ROOT), paths, cve)


def _add_reference(paths: Paths) -> None:
    """Place the reviewed reference package next to the scaffold."""
    shutil.copytree(
        REPO_ROOT / "vulnerabilities" / REFERENCE_CVE,
        paths.packages / REFERENCE_CVE,
        ignore=shutil.ignore_patterns("__pycache__"),
    )


def _load(paths: Paths, cve: str):
    return load_package(paths.packages / cve, paths.schemas)


def _run_cli(root: Path, *args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(["--root", str(root), *args])
    return code, stdout.getvalue(), stderr.getvalue()


class PocBuildTests(unittest.TestCase):
    def _built_fixture(self, root: Path) -> Paths:
        paths = _workspace(root)
        _scaffold(paths)
        _add_reference(paths)
        package = _load(paths, SYNTHETIC_CVE)
        self.assertEqual(validate_package(package, paths), [], package.errors)
        return paths

    def test_builds_probe_from_fresh_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            package = _load(paths, SYNTHETIC_CVE)
            result = build_poc(package)

            self.assertEqual(result["status"], "built")
            self.assertEqual(result["profile"], "bandit-http2-one-byte-data")

            generated = (paths.packages / SYNTHETIC_CVE / "poc" / "exploit.py").read_text()
            self.assertIn(
                GENERATED_MARKER.format(
                    profile="bandit-http2-one-byte-data", reference=REFERENCE_CVE
                ),
                generated.splitlines(),
            )
            self.assertIn(f'CVE = "{SYNTHETIC_CVE}"', generated)
            # The reference CVE survives only inside the provenance marker.
            marker = GENERATED_MARKER.format(
                profile="bandit-http2-one-byte-data", reference=REFERENCE_CVE
            )
            self.assertEqual(generated.count(REFERENCE_CVE), 1)
            self.assertIn(marker, generated.splitlines())
            for contract_call in (
                "enforce_loopback(",
                "validate_payload_budget(",
                "validate_duration_budget(",
                "admin_gc(",
                "MemorySampler(",
                "runtime.json",
            ):
                self.assertIn(contract_call, generated)

            manifest = json.loads(
                (paths.packages / SYNTHETIC_CVE / "poc" / "manifest.json").read_text()
            )
            self.assertEqual(manifest["cve"], SYNTHETIC_CVE)
            self.assertEqual(manifest["entrypoint"], "poc.exploit:run")
            self.assertEqual(
                manifest["targets"], {"vulnerable": "vulnerable", "patched": "patched"}
            )
            self.assertEqual(manifest["kwargs"], {"n_frames": 100000, "pace_ms": 0})
            self.assertEqual(manifest["metric"], "attack_memory_delta")
            self.assertEqual(manifest["thresholds"]["vulnerable_min"], 3000000)
            self.assertEqual(manifest["runs"], 3)

            proposal = json.loads(
                (paths.packages / SYNTHETIC_CVE / "poc" / "proposal.json").read_text()
            )
            self.assertEqual(proposal["cve"], SYNTHETIC_CVE)
            self.assertEqual(proposal["profile"], "bandit-http2-one-byte-data")
            self.assertEqual(proposal["status"], "built")
            self.assertTrue(proposal["generator_version"])
            self.assertEqual(proposal["source"]["reference_cve"], REFERENCE_CVE)
            self.assertEqual(proposal["source"]["track"], "http2_resource_exhaustion")
            self.assertEqual(proposal["source"]["adapter"], "bandit")
            self.assertEqual(
                proposal["source"]["versions"],
                {"vulnerable": "1.14.0", "patched": "1.14.1"},
            )
            self.assertIn("attack_memory_delta", proposal["probe"]["predicate"])
            self.assertIn("3000000", proposal["probe"]["predicate"])
            self.assertIn("run ranges must not overlap", proposal["probe"]["predicate"])
            self.assertEqual(proposal["patch_analysis"], [])

            package_manifest = json.loads(
                (paths.packages / SYNTHETIC_CVE / "package.json").read_text()
            )
            self.assertEqual(package_manifest["status"], "poc-implemented")
            self.assertEqual(
                package_manifest["validation"]["predicate"],
                proposal["probe"]["predicate"],
            )

            reloaded = _load(paths, SYNTHETIC_CVE)
            self.assertEqual(validate_package(reloaded, paths), [], reloaded.errors)

    def test_build_is_idempotent_for_unchanged_generated_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            first = build_poc(_load(paths, SYNTHETIC_CVE))
            self.assertEqual(first["status"], "built")

            proposal_path = paths.packages / SYNTHETIC_CVE / "poc" / "proposal.json"
            before = {
                "exploit": (paths.packages / SYNTHETIC_CVE / "poc" / "exploit.py").read_text(),
                "manifest": (paths.packages / SYNTHETIC_CVE / "poc" / "manifest.json").read_text(),
                "proposal": proposal_path.read_text(),
                "package": (paths.packages / SYNTHETIC_CVE / "package.json").read_text(),
            }
            second = build_poc(_load(paths, SYNTHETIC_CVE))
            self.assertEqual(second["status"], "unchanged")
            self.assertEqual(
                (paths.packages / SYNTHETIC_CVE / "poc" / "exploit.py").read_text(),
                before["exploit"],
            )
            self.assertEqual(
                (paths.packages / SYNTHETIC_CVE / "poc" / "manifest.json").read_text(),
                before["manifest"],
            )
            self.assertEqual(proposal_path.read_text(), before["proposal"])
            self.assertEqual(
                (paths.packages / SYNTHETIC_CVE / "package.json").read_text(),
                before["package"],
            )

    def test_refuses_modified_generated_probe_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            build_poc(_load(paths, SYNTHETIC_CVE))
            exploit_path = paths.packages / SYNTHETIC_CVE / "poc" / "exploit.py"
            exploit_path.write_text(
                exploit_path.read_text() + "\n# researcher tweak\n"
            )

            with self.assertRaisesRegex(PackageError, "pass --force to regenerate"):
                build_poc(_load(paths, SYNTHETIC_CVE))

            forced = build_poc(_load(paths, SYNTHETIC_CVE), force=True)
            self.assertEqual(forced["status"], "built")
            self.assertNotIn("# researcher tweak", exploit_path.read_text())

    def test_refuses_generated_probe_from_a_different_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            build_poc(_load(paths, SYNTHETIC_CVE))
            exploit_path = paths.packages / SYNTHETIC_CVE / "poc" / "exploit.py"
            lines = exploit_path.read_text().splitlines(keepends=True)
            lines[1] = (
                GENERATED_MARKER.format(
                    profile="bandit-http1-one-byte-chunks", reference="CVE-2026-111101"
                )
                + "\n"
            )
            exploit_path.write_text("".join(lines))

            with self.assertRaisesRegex(
                PackageError, "generated by profile 'bandit-http1-one-byte-chunks'"
            ):
                build_poc(_load(paths, SYNTHETIC_CVE))

    def test_refuses_hand_authored_probe(self):
        package = load_package(
            REPO_ROOT / "vulnerabilities" / REFERENCE_CVE,
            load_config(REPO_ROOT).paths().schemas,
        )
        with self.assertRaisesRegex(PackageError, "refusing to replace"):
            build_poc(package)

    def test_does_not_downgrade_a_validated_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            package_path = paths.packages / SYNTHETIC_CVE / "package.json"
            manifest = json.loads(package_path.read_text())
            manifest["status"] = "validated"
            package_path.write_text(json.dumps(manifest, indent=2) + "\n")

            result = build_poc(_load(paths, SYNTHETIC_CVE))
            self.assertEqual(result["status"], "built")
            self.assertEqual(
                json.loads(package_path.read_text())["status"], "validated"
            )

    def test_unsupported_cve_reports_required_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _workspace(Path(tmp), cve="CVE-2026-105659")
            # CVE-2026-105659 exists in the real catalog; rebuild its package
            # from the repo so the fixture stays honest.
            shutil.rmtree(paths.packages / "CVE-2026-105659", ignore_errors=True)
            shutil.copytree(
                REPO_ROOT / "vulnerabilities" / "CVE-2026-105659",
                paths.packages / "CVE-2026-105659",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            package = _load(paths, "CVE-2026-105659")

            with self.assertRaisesRegex(
                PackageError,
                r"does not match a supported CVE-driven PoC profile",
            ) as raised:
                build_poc(package)
            self.assertIn(
                "Required capability: Bandit HTTP/2 profile", str(raised.exception)
            )
            self.assertIn("bandit-http2-one-byte-data", str(raised.exception))

            # The package stays a draft and gains no PoC artifacts.
            self.assertFalse(
                (paths.packages / "CVE-2026-105659" / "poc" / "proposal.json").is_file()
            )
            self.assertTrue(
                (paths.packages / "CVE-2026-105659" / "poc" / "exploit.py")
                .read_text()
                .__contains__("NotImplementedError")
            )

    def test_unsupported_track_names_its_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _workspace(Path(tmp), track="websocket_exhaustion")
            _scaffold(paths)
            package = _load(paths, SYNTHETIC_CVE)

            with self.assertRaisesRegex(
                PackageError, "Required capability: Bandit WebSocket profile"
            ):
                build_poc(package)

    def test_non_bandit_adapter_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            for relative in ("package.json", "lab/lab.json"):
                path = paths.packages / SYNTHETIC_CVE / relative
                path.write_text(path.read_text().replace('"bandit"', '"toy"'))
            package = _load(paths, SYNTHETIC_CVE)

            with self.assertRaisesRegex(
                PackageError, "no CVE-driven PoC profile is available for adapter"
            ):
                build_poc(package)

    def test_missing_probe_manifest_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            (paths.packages / SYNTHETIC_CVE / "poc" / "manifest.json").unlink()
            package = _load(paths, SYNTHETIC_CVE)

            with self.assertRaisesRegex(PackageError, "has no poc/manifest.json"):
                build_poc(package)

    def test_missing_reference_package_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _workspace(Path(tmp))
            _scaffold(paths)
            package = _load(paths, SYNTHETIC_CVE)

            with self.assertRaisesRegex(
                PackageError, "missing its reviewed reference package"
            ):
                build_poc(package)

    def test_reference_package_cannot_rebuild_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _workspace(Path(tmp), cve=REFERENCE_CVE)
            _scaffold(paths, REFERENCE_CVE)
            package = _load(paths, REFERENCE_CVE)

            with self.assertRaisesRegex(PackageError, "cannot rebuild itself"):
                build_poc(package)

    def test_proposal_is_schema_validated_by_the_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._built_fixture(Path(tmp))
            build_poc(_load(paths, SYNTHETIC_CVE))

            proposal_path = paths.packages / SYNTHETIC_CVE / "poc" / "proposal.json"
            proposal = json.loads(proposal_path.read_text())
            del proposal["generator_version"]
            proposal_path.write_text(json.dumps(proposal, indent=2) + "\n")

            errors = _load(paths, SYNTHETIC_CVE).errors
            self.assertTrue(
                any("poc/proposal.json" in error for error in errors), errors
            )


class PocBuildCliTests(unittest.TestCase):
    def test_cli_build_from_fresh_scaffold_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = _workspace(root)
            _scaffold(paths)
            _add_reference(paths)

            code, out, err = _run_cli(root, "poc", "build", SYNTHETIC_CVE)
            self.assertEqual(code, 0, err)
            self.assertIn("Built PoC", out)
            self.assertIn("bandit-http2-one-byte-data", out)

            code, out, err = _run_cli(root, "poc", "build", SYNTHETIC_CVE)
            self.assertEqual(code, 0, err)
            self.assertIn("already matches profile", out)

    def test_cli_build_refuses_generated_probe_changes_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = _workspace(root)
            _scaffold(paths)
            _add_reference(paths)

            code, _, err = _run_cli(root, "poc", "build", SYNTHETIC_CVE)
            self.assertEqual(code, 0, err)

            exploit_path = paths.packages / SYNTHETIC_CVE / "poc" / "exploit.py"
            exploit_path.write_text(exploit_path.read_text() + "\n# tweak\n")

            code, _, err = _run_cli(root, "poc", "build", SYNTHETIC_CVE)
            self.assertEqual(code, 1)
            self.assertIn("pass --force to regenerate", err)

            code, out, err = _run_cli(root, "poc", "build", "--force", SYNTHETIC_CVE)
            self.assertEqual(code, 0, err)
            self.assertIn("Built PoC", out)
            self.assertNotIn("# tweak", exploit_path.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
