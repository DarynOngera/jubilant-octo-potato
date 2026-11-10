"""Single source of truth for the package artifact contract.

The documentation, the loader, and the CLI all need to agree on what makes a
package complete.  This module is the authoritative list.  Keep
``docs/package-lifecycle.md`` and the package-authoring docs in sync with it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

ANALYSIS_FILES = (
    "root-cause.md",
    "exploitability.json",
    "attack-surface.md",
)

DETECTION_FILES = ("spec.json",)

# Files every package has regardless of status.
BASE_FILES = (
    "package.json",
    "advisory.json",
    "lab/lab.json",
    "poc/manifest.json",
    "detection/spec.json",
    "analysis/root-cause.md",
    "analysis/exploitability.json",
    "analysis/attack-surface.md",
)

BASE_DIRS = ("tests",)

# Files that only exist after the given lifecycle stage.
LAB_FILES = ("lab/provenance.json",)
EVIDENCE_FILES = (
    "evidence/execution.json",
    "evidence/validation.json",
    "detection/evidence.json",
    "report.md",
    "report.json",
)
EVIDENCE_DIRS = (
    "evidence/runs",
    "evidence/telemetry",
    "evidence/logs",
)

STATUS_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "draft": BASE_FILES + BASE_DIRS,
    "lab-ready": BASE_FILES + BASE_DIRS + LAB_FILES,
    "poc-implemented": BASE_FILES + BASE_DIRS,
    "validated": BASE_FILES + BASE_DIRS + LAB_FILES + EVIDENCE_FILES + EVIDENCE_DIRS,
    "inconclusive": BASE_FILES + BASE_DIRS + LAB_FILES + EVIDENCE_FILES + EVIDENCE_DIRS,
    "retired": BASE_FILES + BASE_DIRS,
}

VALID_STATUSES = tuple(STATUS_ARTIFACTS)


def required_artifacts(status: str) -> tuple[str, ...]:
    """Return the artifact paths required for ``status``.

    Unknown statuses fall back to the base set so a new schema value does not
    accidentally make every package invalid; the package schema still rejects
    unknown statuses.
    """
    return STATUS_ARTIFACTS.get(status, BASE_FILES + BASE_DIRS)


def _resolve_manifest_path(relative: str, paths: Mapping[str, str] | None) -> str:
    """Translate a canonical contract path through ``package.json:paths``."""
    if not paths:
        return relative

    analysis = paths.get("analysis", "analysis")
    detection = paths.get("detection", "detection")
    evidence = paths.get("evidence", "evidence")
    lab = paths.get("lab", "lab/lab.json")
    lab_dir = str(Path(lab).parent)
    poc = paths.get("poc", "poc/manifest.json")
    report = paths.get("report", "report.md")

    exact = {
        "advisory.json": paths.get("advisory", "advisory.json"),
        "lab/lab.json": lab,
        "lab/compose.yaml": f"{lab_dir}/compose.yaml",
        "lab/provenance.json": f"{lab_dir}/provenance.json",
        "poc/manifest.json": poc,
        "analysis/root-cause.md": f"{analysis}/root-cause.md",
        "analysis/exploitability.json": f"{analysis}/exploitability.json",
        "analysis/attack-surface.md": f"{analysis}/attack-surface.md",
        "detection/spec.json": f"{detection}/spec.json",
        "detection/evidence.json": f"{detection}/evidence.json",
        "evidence/execution.json": f"{evidence}/execution.json",
        "evidence/validation.json": f"{evidence}/validation.json",
        "evidence/runs": f"{evidence}/runs",
        "evidence/telemetry": f"{evidence}/telemetry",
        "evidence/logs": f"{evidence}/logs",
        "tests": paths.get("tests", "tests"),
        "report.md": report,
        "report.json": str(Path(report).with_suffix(".json")),
    }
    return exact.get(relative, relative)


def missing_artifacts(
    package_root: Path,
    status: str,
    paths: Mapping[str, str] | None = None,
) -> list[str]:
    """Return required artifact paths absent from ``package_root``."""
    missing: list[str] = []
    for relative in required_artifacts(status):
        resolved = _resolve_manifest_path(relative, paths)
        if not (package_root / resolved).exists():
            missing.append(resolved)
    return sorted(missing)
