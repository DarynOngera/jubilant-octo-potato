"""Triage orchestration over the existing resolver/prioritizer scripts."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from ..errors import VulnForgeError
from ..ingest.proposal import merge_advisories
from ..paths import Paths


def overlay_package_advisories(paths: Paths) -> list[str]:
    """Overlay packaged advisories onto the global catalog.

    The catalog remains the source of truth for un-packaged advisories; this
    is an explicit, reviewable overlay for CVEs that have a package.
    """
    catalog_path = paths.data / "advisories.json"
    catalog = json.loads(catalog_path.read_text()).get("advisories", [])
    packaged = []
    for path in sorted(paths.packages.glob("*/advisory.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise VulnForgeError(f"invalid package advisory {path}: {exc}") from exc
        if isinstance(data, dict) and data.get("cve"):
            packaged.append(data)
    if not packaged:
        return []
    merged, _changes = merge_advisories(catalog, packaged)
    catalog_path.write_text(json.dumps({"advisories": merged}, indent=2) + "\n")
    return sorted(str(item["cve"]) for item in packaged)


def _run(paths: Paths, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(paths.root),
        text=True,
        capture_output=True,
    )


def run_triage(
    paths: Paths,
    *,
    check: bool = False,
    from_packages: bool = False,
) -> dict[str, Any]:
    overlaid: list[str] = []
    if from_packages and not check:
        overlaid = overlay_package_advisories(paths)

    resolver = paths.root / "triage" / "version_resolver.py"
    prioritizer = paths.root / "triage" / "prioritizer.py"
    if check:
        resolver_result = _run(paths, [str(resolver), "--check"])
        prioritizer_result = _run(paths, [str(prioritizer), "--check"])
        return {
            "check": True,
            "returncode": max(
                resolver_result.returncode, prioritizer_result.returncode
            ),
            "stdout": resolver_result.stdout + prioritizer_result.stdout,
            "stderr": resolver_result.stderr + prioritizer_result.stderr,
        }

    resolver_result = _run(paths, [str(resolver)])
    if resolver_result.returncode != 0:
        raise VulnForgeError(
            f"version resolver failed ({resolver_result.returncode}): "
            f"{resolver_result.stderr.strip()}"
        )
    prioritizer_result = _run(
        paths,
        [
            str(prioritizer),
            "--csv",
            str(paths.root / "reports" / "vulnerability-matrix.csv"),
        ],
    )
    if prioritizer_result.returncode != 0:
        raise VulnForgeError(
            f"prioritizer failed ({prioritizer_result.returncode}): "
            f"{prioritizer_result.stderr.strip()}"
        )
    return {
        "check": False,
        "overlaid": overlaid,
        "resolver": resolver_result.stdout,
        "prioritizer": prioritizer_result.stdout,
    }
